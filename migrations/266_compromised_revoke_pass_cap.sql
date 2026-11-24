-- 266: migration 214's COMPROMISED revoke,
-- `public.epigraph_revoke_passkey_compromised(passkey, reason)`, re-stated so
-- that one transaction can LOWER its pass cap (backlog 51fe91bf), which makes
-- the cap's refusal reachable by a test.
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 214's revoke locks every passkey of the person and walks the anchor
-- lineage, repeating until every walked passkey is locked. If a walk still
-- reaches a passkey its locks do not hold after 32 passes, it refuses
-- SQLSTATE 40001 and revokes nothing. That refusal is the safety exit of a
-- security revoke, and it had no test: a lineage still growing after 32
-- passes needs 32 completions, each committed during a different pass's
-- lock wait, which no deterministic arrangement produces. A regression in
-- the exit (a partial revoke committed, an audit row written, or a loop
-- without bound) would go unseen until an attack-time race.
--
-- ===================================================================
-- 2. THE CHANGE
-- ===================================================================
--
-- `CREATE OR REPLACE` of the one function, same signature and result
-- columns, 214's body with one change: the cap is read once, before any
-- lock, from the setting `epigraph.compromised_revoke_max_passes`, and
-- used only when it is one or two digits with a value from 1 to 31.
-- Anything else (unset, empty, non-numeric, 0, negative, 32 or more) leaves
-- 214's 32. The 40001 refusal itself (message, nothing revoked, no audit
-- row) is 214's; its HINT now names the setting.
--
-- Why a setting and not a defaulted argument: an argument changes the
-- function's identity (`(uuid, text)`), which the grants, the definer
-- register in `crates/epigraph-cli/src/bin/tenancy_backfill.rs` and the
-- callers name; and a two-argument call next to a three-argument one with a
-- default is ambiguous.
--
-- THE GUARD is the clamp: the setting can only LOWER the cap. A lower cap
-- can only turn a revoke whose lineage grew during its lock wait into a
-- 40001 refusal with nothing revoked (loud, run again); it can never make
-- the revoke revoke less, skip a lock, or loop longer than 214's. A revoke
-- whose first walk is already locked (every revoke without a completion in
-- flight) exits before the cap is checked, so even a cap of 1 does not
-- refuse it. Only `epigraph_maintenance` may call the function, and it sets
-- the value for its own transaction (`SET LOCAL` or `set_config(.., true)`).
-- An operator foot-gun remains: a value set on the role or the database
-- (`ALTER ROLE .. SET`) applies to every revoke; clear it with
-- `ALTER ROLE epigraph_maintenance RESET epigraph.compromised_revoke_max_passes`
-- (or `ALTER DATABASE .. RESET ..`). No code sets it outside the tests.
--
-- `CREATE OR REPLACE` keeps 200's owner (`epigraph_maintenance`) and grants
-- (EXECUTE revoked from PUBLIC and `epigraph_app`, granted to
-- `epigraph_maintenance`), so nothing is re-owned or re-granted, and the
-- function stays registered at 200 in `tenancy_backfill.rs`. Path pinned to
-- `pg_catalog, pg_temp`, every built-in qualified, as 214's.
--
-- PRECONDITION: the body in place must be 214's (md5 of `prosrc`
-- `645f997359d64646702e3db2f86ed7ca`), so that this file never silently
-- discards another migration's re-statement; over any other body it raises
-- 55000 and changes nothing. A later re-statement starts from this body.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- No binary depends on it, and no binary sets the setting: with it unset
-- the revoke behaves exactly as 214's. Apply it whenever.
--
-- UNDO: `docs/runbooks/266-undo.sql` restores 214's body; run it BEFORE
-- `214-undo.sql` (which refuses over any body but 214's or 200's).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
                       'public.epigraph_revoke_passkey_compromised(uuid, text)');
    IF v_found IS DISTINCT FROM '645f997359d64646702e3db2f86ed7ca' THEN
        RAISE EXCEPTION '266: public.epigraph_revoke_passkey_compromised(uuid, text) is not '
                        'the body 266 re-states (214''s, md5 '
                        '645f997359d64646702e3db2f86ed7ca); found md5 %. Another migration '
                        're-bodied it, or 214 is not applied; nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

-- The COMPROMISED revoke: the passkey and every passkey whose anchor lineage
-- passes through it, under READ COMMITTED only, locked to a fixpoint, the
-- pass cap lowerable for one transaction.
CREATE OR REPLACE FUNCTION public.epigraph_revoke_passkey_compromised(p_id uuid, p_reason text)
RETURNS TABLE (revoked_id uuid, lineage_depth integer, revoked_now boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_person uuid;
    v_ids    uuid[];
    v_depths integer[];
    v_hit    uuid[];
    v_locked uuid[] := '{}';
    v_pass   integer := 0;
    v_cap    integer := 32;
    v_set    text;
BEGIN
    -- READ COMMITTED only: the walk must read a snapshot taken AFTER the lock
    -- wait below, which only a per-statement snapshot is.
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'epigraph_revoke_passkey_compromised: runs only under READ COMMITTED '
                        '(this transaction is %): an older snapshot would miss a passkey '
                        'enrolled during its lock wait; nothing was revoked',
                        pg_catalog.current_setting('transaction_isolation')
            USING ERRCODE = '25000',
                  HINT = 'Run it under READ COMMITTED (the default).';
    END IF;
    IF p_id IS NULL OR p_reason IS NULL OR pg_catalog.length(pg_catalog.btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_revoke_passkey_compromised: the passkey and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    -- 266: a transaction may LOWER the pass cap (1 to 31), never raise it;
    -- any other value, a typo included, leaves 32. Nested, so the cast runs
    -- only on one or two digits (AND does not fix an evaluation order).
    v_set := pg_catalog.current_setting('epigraph.compromised_revoke_max_passes', true);
    IF v_set ~ '^[0-9]{1,2}$' THEN
        IF v_set::integer BETWEEN 1 AND 31 THEN
            v_cap := v_set::integer;
        END IF;
    END IF;
    SELECT k.person_agent_id INTO v_person
      FROM public.person_authenticators k WHERE k.id = p_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV04: no passkey %', p_id
            USING ERRCODE = 'ELV04';
    END IF;
    -- Lock every passkey of the person, then walk, and repeat until every
    -- passkey the walk reached is locked (a fixpoint). The lock is the one
    -- the UPDATE takes anyway, and it conflicts with (b)'s FOR SHARE: a
    -- completion in flight on an act one of them confirmed is waited for,
    -- and the walk, a later statement with a later snapshot, then sees the
    -- passkey it recorded; a completion that starts later on a locked
    -- passkey's act waits for this transaction and is refused (ELV04, its
    -- confirmer revoked). A passkey recorded DURING the wait is not in the
    -- lock's snapshot, so the walk can reach a passkey the lock does not
    -- hold, whose own act could still take a completion before the UPDATE:
    -- the next pass locks it (waiting for such a completion) and walks
    -- again. Every pass that does not end the loop locks at least one more
    -- passkey of the person.
    LOOP
        v_pass := v_pass + 1;
        v_locked := v_locked || ARRAY(
            SELECT k.id FROM public.person_authenticators k
             WHERE k.person_agent_id = v_person ORDER BY k.id FOR NO KEY UPDATE);
        -- The walk, down the acts each passkey confirmed: through revoked
        -- passkeys too, the same person's only, never round a cycle.
        WITH RECURSIVE down (id, depth, path) AS (
            SELECT p_id, 0, ARRAY[p_id]
            UNION ALL
            SELECT k.id, down.depth + 1, down.path || k.id
              FROM down
              JOIN public.pending_admin_acts a ON a.authenticator_id = down.id
              JOIN public.passkey_enrollments en
                ON en.act_id = a.id AND en.created_via = 'confirmed_act'
              JOIN public.person_authenticators k ON k.enrollment_id = en.id
             WHERE k.person_agent_id = v_person
               AND NOT (k.id = ANY (down.path))
        )
        SELECT pg_catalog.array_agg(w.id ORDER BY w.depth, w.id),
               pg_catalog.array_agg(w.depth ORDER BY w.depth, w.id)
          INTO v_ids, v_depths
          FROM (SELECT DISTINCT ON (down.id) down.id, down.depth
                  FROM down ORDER BY down.id, down.depth) w;
        EXIT WHEN v_ids <@ v_locked;
        IF v_pass >= v_cap THEN
            RAISE EXCEPTION 'epigraph_revoke_passkey_compromised: passkey % kept gaining '
                            'lineage passkeys while it was being locked (% passes); nothing '
                            'was revoked', p_id, v_pass
                USING ERRCODE = '40001',
                      HINT = 'Run it again, with epigraph.compromised_revoke_max_passes '
                             'unset (a lower value refuses sooner).';
        END IF;
    END LOOP;
    -- One statement: (c)'s per-row cascade then finds nothing of the walk
    -- still live, and the audit reads the mode.
    PERFORM pg_catalog.set_config('epigraph.passkey_revoke_mode', 'compromised', true);
    WITH hit AS (
        UPDATE public.person_authenticators k
           SET revoked_at = pg_catalog.now(), revoked_by = session_user::text,
               revoked_reason = CASE WHEN k.id = p_id THEN p_reason
                                     ELSE 'compromised anchor ' || p_id::text || ' (lineage): '
                                          || p_reason END
         WHERE k.id = ANY (v_ids) AND k.revoked_at IS NULL
        RETURNING k.id)
    SELECT pg_catalog.array_agg(hit.id) INTO v_hit FROM hit;
    PERFORM pg_catalog.set_config('epigraph.passkey_revoke_mode', '', true);
    RETURN QUERY
        SELECT w.id, w.depth, w.id = ANY (COALESCE(v_hit, '{}'::uuid[]))
          FROM ROWS FROM (pg_catalog.unnest(v_ids), pg_catalog.unnest(v_depths))
               WITH ORDINALITY AS w(id, depth, n)
         ORDER BY w.n;
END $$;
