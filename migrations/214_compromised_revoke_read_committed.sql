-- 214: migration 200's COMPROMISED revoke,
-- `public.epigraph_revoke_passkey_compromised(passkey, reason)`, re-stated to
-- run only under READ COMMITTED (backlog c77931a7) and to lock every passkey
-- it walks before it revokes (backlog 2deb56fa).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 200's revoke first locks every passkey of the person (`FOR NO KEY UPDATE`,
-- which 200's insert guard's `FOR SHARE` conflicts with), so that an
-- enrollment completing on one of their acts is waited for, and then walks
-- the anchor lineage in a LATER statement, which sees the passkey that
-- completed. That holds only under READ COMMITTED, where each statement
-- takes a new snapshot. Under REPEATABLE READ or SERIALIZABLE the walk reads
-- the transaction's snapshot, taken before the wait: it misses the passkey
-- that completed meanwhile, the revoke commits, and that passkey (attested,
-- so no lost-revoke cascade reaches it) stays live. SERIALIZABLE does not
-- save it: no serialization failure is raised and the revoke commits.
-- Measured on a fresh database (`pending_admin_acts.rs`'s
-- `the_compromised_revoke_runs_only_under_read_committed` against 200's
-- body): READ COMMITTED reaches 3 passkeys, REPEATABLE READ and
-- SERIALIZABLE reach 2 and commit. 166 guards its lock-then-read definers
-- the same way (`<> 'read committed'`). 123, 130 and 148 refuse only
-- REPEATABLE READ and let SERIALIZABLE through, which is NOT enough here
-- (SERIALIZABLE misses the passkey too, as measured above); do not copy
-- their guard onto this function. 200's had no guard at all.
-- Minor while the maintenance role runs READ COMMITTED (the default); major
-- if that ever changes.
--
-- Under READ COMMITTED a second gap remains. The person-wide lock reads the
-- passkeys in ITS snapshot, so a passkey N recorded during its wait (its
-- completion held a share lock the revoke waited for) is not locked, though
-- the walk after the wait reaches it. Between that walk and the UPDATE, a
-- completion on an act N confirmed takes (b)'s share lock on N unhindered
-- and commits; the UPDATE then waits for it on N, revokes N, and leaves N's
-- new passkey live if it is attested (the lost cascade (c) reaches only
-- `none` ones). The window is sub-millisecond, but it is a window on the
-- one revoke meant to leave nothing of a stolen device's lineage live.
-- Arranged deterministically in `pending_admin_acts.rs`'s
-- `a_passkey_enrolled_during_the_lock_wait_is_locked_before_the_walk_ends`.
--
-- 200's header (d) and docs/deploy.md say, without condition, that a
-- completion in flight "is waited for and then walked". 200 is applied and
-- is never edited; this header is the correction, and deploy.md is updated
-- with it.
--
-- ===================================================================
-- 2. THE CHANGE
-- ===================================================================
--
-- `CREATE OR REPLACE` of the one function, same signature, same result
-- columns, the same walk, UPDATE, audit mode and result rows as 200's, with
-- two changes:
--
-- (a) First, `transaction_isolation` other than `read committed` is
--     refused, SQLSTATE 25000 (invalid_transaction_state), before any lock
--     is taken or any row read, nothing revoked.
--
-- (b) The lock and the walk repeat until every passkey the walk reached is
--     locked (a fixpoint): each pass locks every passkey of the person
--     visible to it (`FOR NO KEY UPDATE`, in id order, as 200's single pass
--     did) and walks again. A pass that walks a passkey not yet locked is
--     followed by one that locks it, waiting for any completion holding it,
--     and so sees that completion's passkey. When the loop ends, every
--     walked passkey is locked, so no completion on any of their acts can
--     commit before this transaction, and one that tries is refused ELV04
--     once it does. A pass that does not end the loop locks at least one
--     more passkey; after 32 passes (a person whose lineage keeps growing
--     while it is being locked; not expected) the call is refused 40001,
--     nothing revoked, to be run again.
--
-- Every other refusal is 200's (22004 a blank reason, ELV04 an unknown
-- passkey).
--
-- `CREATE OR REPLACE` keeps 200's owner (`epigraph_maintenance`) and grants
-- (EXECUTE revoked from PUBLIC and `epigraph_app`, granted to
-- `epigraph_maintenance`), so nothing is re-owned or re-granted here, and
-- the function stays registered at 200 in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- (`DEFERRED_DEFINER_FUNCTIONS` and the grant register). Path pinned to
-- 172's `pg_catalog, pg_temp`, every built-in qualified, as 200's.
--
-- PRECONDITION: the body in place must be 200's (md5 of `prosrc`
-- `0dfedeb8a0dc722a743fe2299baae704`), so that this file never silently
-- discards another migration's re-statement; over any other body it raises
-- 55000 and changes nothing. A later re-statement starts from this body.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- No binary depends on it: `epigraph-operator revoke-passkey --compromised`
-- calls the function in a transaction at the connection's default
-- isolation, READ COMMITTED unless the maintenance DSN, the role or the
-- database sets another, in which case the revoke is now refused (loud)
-- instead of missing a passkey (silent). Apply it whenever.
--
-- UNDO: `docs/runbooks/214-undo.sql` restores 200's body; run it BEFORE
-- `200-undo.sql` (which drops the function whatever its body).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
                       'public.epigraph_revoke_passkey_compromised(uuid, text)');
    IF v_found IS DISTINCT FROM '0dfedeb8a0dc722a743fe2299baae704' THEN
        RAISE EXCEPTION '214: public.epigraph_revoke_passkey_compromised(uuid, text) is not '
                        'the body 214 re-states (200''s, md5 '
                        '0dfedeb8a0dc722a743fe2299baae704); found md5 %. Another migration '
                        're-bodied it, or 200 is not applied; nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

-- The COMPROMISED revoke: the passkey and every passkey whose anchor lineage
-- passes through it, under READ COMMITTED only, locked to a fixpoint.
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
