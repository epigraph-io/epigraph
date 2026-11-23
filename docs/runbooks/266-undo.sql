-- ===================================================================
-- 266-undo.sql: take migration 266 (the compromised revoke's pass cap,
-- lowerable for one transaction) back out, in ONE transaction, on the
-- migration (superuser) DSN.
--
-- READ FIRST: no binary depends on 266, so nothing needs rolling back
-- first. Run this BEFORE `214-undo.sql` when taking 214 out as well (that
-- one refuses over any body but 214's or 200's).
--
-- WHAT IT DOES: re-states 214's body of
-- `public.epigraph_revoke_passkey_compromised(uuid, text)` byte for byte.
-- `CREATE OR REPLACE` keeps its owner and grants. From then on the
-- `epigraph.compromised_revoke_max_passes` setting is ignored and the cap is
-- 32 passes again, so the 40001 refusal is unreachable by a test.
--
-- PRECONDITION: the body in place must be 266's (md5 of `prosrc`
-- `84600a74b4b2f80264ba917682b58841`) or already 214's
-- (`645f997359d64646702e3db2f86ed7ca`, a second run); over any other body it
-- raises 55000 and changes nothing (a later migration re-bodied it: undo that
-- one first).
--
-- WHAT IT LEAVES: every passkey and revoke as it stands, and 266's
-- `_sqlx_migrations` row. Re-introducing the change is a NEW migration,
-- never a re-run of 266. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
                       'public.epigraph_revoke_passkey_compromised(uuid, text)');
    IF v_found IS NULL OR v_found NOT IN ('84600a74b4b2f80264ba917682b58841',
                                          '645f997359d64646702e3db2f86ed7ca') THEN
        RAISE EXCEPTION '266-undo: public.epigraph_revoke_passkey_compromised(uuid, text) is '
                        'neither 266''s body nor 214''s; found md5 %. Nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- 214's body, byte for byte (CREATE OR REPLACE keeps owner and grants).
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
        IF v_pass >= 32 THEN
            RAISE EXCEPTION 'epigraph_revoke_passkey_compromised: passkey % kept gaining '
                            'lineage passkeys while it was being locked (% passes); nothing '
                            'was revoked', p_id, v_pass
                USING ERRCODE = '40001',
                      HINT = 'Run it again.';
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

COMMIT;
