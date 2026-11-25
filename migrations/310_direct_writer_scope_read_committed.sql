-- 310: the DIRECT-membership arm of the claims-path writer scope admits a
-- write only under READ COMMITTED (backlog e39af056).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 256 made 165's role-DERIVED arm of `epigraph_require_writer_scope` admit
-- only under READ COMMITTED and recorded the residual: 122's DIRECT arm
-- (`epigraph_operator_writes_group(v_human, p_group)`, a live writer/admin
-- row of the writing principal's human in `group_memberships`) reads through
-- the same snapshot. Under REPEATABLE READ or SERIALIZABLE that snapshot is
-- the transaction's FIRST, so a membership revoked, or demoted to reader, by
-- another session after it (committed) still reads as a live writer row, and
-- the human (or its linked agent) keeps writing into the group until its
-- transaction ends. SERIALIZABLE does not save it: the revoke writes no row
-- the claim INSERT reads for update, so no serialization failure is raised.
-- The same snapshot also serves the arm's other reads (`epigraph_human_of`:
-- the human registration and the operator link), so a level rule covers
-- every read of the arm where a locked re-read of the one membership row
-- would not. Measured on a fresh database
-- (`direct_writer_scope_read_committed.rs`): on 256's body such a writer,
-- whose membership is revoked mid-transaction, writes; on 310's it is
-- refused.
--
-- Low while the request path runs READ COMMITTED (the default; no
-- application write path sets another level, and every REPEATABLE READ
-- writer in the tree runs on the maintenance DSN, which the exemption
-- relieves).
--
-- The CUSTODIAN half of the backlog item is not a write admission at this
-- head: 123 re-bodied `epigraph_operator_scope_exempt()` to
-- `epigraph_bypass()` alone (operator ruling OQ-1 (b)), so holding
-- role:platform-custodian relieves nothing here, live or ended, at any
-- level; no later migration re-states the exemption. The tests pin that
-- under all three levels with the assignment ended mid-transaction.
--
-- ===================================================================
-- 2. THE CHANGE
-- ===================================================================
--
-- `CREATE OR REPLACE` of the one function, same signature, STABLE, same
-- search path (`public, pg_temp`, pg_temp last), 256's body with one delta in
-- the direct arm:
--
--   * an unbound principal (`v_human IS NULL`) returns as before, at any
--     level (the bound-author checks refuse it elsewhere);
--   * the direct arm ADMITS only when `transaction_isolation` is
--     `read committed`, and then returns before the derived arm is
--     evaluated, as before;
--   * under any other level, when the direct arm would have admitted (by the
--     transaction's snapshot), the write is refused OPL02 with its own
--     message ("a write through a direct membership is admitted only under
--     READ COMMITTED"), AFTER the exemption: a privileged session
--     (`epigraph_operator_scope_exempt`, i.e. `epigraph_bypass()`) is
--     exempt at any level, as before. The derived arm is not evaluated in
--     that case (the write is refused either way).
--
-- The level decides, not the old snapshot, with 166/256's
-- `<> 'read committed'` form. 256's derived-arm refusal and both of 122's
-- OPL02 refusals are verbatim. Everything that calls the function (the
-- claims trigger, 153's lineage check, 185, 206, 207) gets the change
-- through it; none is re-stated.
--
-- `CREATE OR REPLACE` keeps 166's owner (`epigraph_maintenance`), ACL and
-- the function's registration at 122 in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs`; nothing is re-owned or
-- re-granted. A later re-statement starts from this body and keeps every
-- fragment `schema_contract.rs::migration_165_derived_arms_survive_at_head`
-- pins (310's included).
--
-- PRECONDITION: the body in place must be 256's (md5 of `prosrc`
-- `9693498b3365ddfa8f97d4ead83b2ee6`); over any other body this file raises
-- 55000 and changes nothing, so it never silently discards another
-- migration's re-statement.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- No binary depends on it; apply it whenever. Before applying, measure that
-- no login that writes claims on the application role runs at another
-- default level (`default_transaction_isolation` set on the database or the
-- role in `pg_db_role_setting`): such a write by a bound principal is
-- refused OPL02 after 310 (loud) instead of outliving a revoke (silent).
--
-- UNDO: `docs/runbooks/310-undo.sql` restores 256's body; run it BEFORE
-- `256-undo.sql`.
-- **Applied to throwaway databases only, NOT to any deployed database.**
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_require_writer_scope(uuid, uuid)');
    IF v_found IS DISTINCT FROM '9693498b3365ddfa8f97d4ead83b2ee6' THEN
        RAISE EXCEPTION '310: public.epigraph_require_writer_scope(uuid, uuid) is not the body '
                        '310 re-states (256''s, md5 9693498b3365ddfa8f97d4ead83b2ee6); found '
                        'md5 %. Another migration re-bodied it, or 256 is not applied; nothing '
                        'was changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

-- The claims-path writer scope as 256 left it (122's body, 123's HINT, 165's
-- derived arm, 166's ROL01 line, 256's READ COMMITTED condition on the
-- derived arm); delta: 310's READ COMMITTED condition on the direct arm and
-- its refusal.
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human   uuid;
    v_direct  boolean;
    v_derived boolean;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    -- 166: ROL01, the agent the claims trigger checks here (the author, or
    -- the stamped writer when that is someone else).
    PERFORM public.epigraph_require_role_holder(p_agent);
    v_human := public.epigraph_human_of(p_agent, false);
    IF v_human IS NULL THEN
        RETURN;
    END IF;
    -- 122's direct arm; 310: it admits only under READ COMMITTED. Under
    -- REPEATABLE READ or SERIALIZABLE it reads the transaction's first
    -- snapshot, so a membership revoked or demoted (and committed) since
    -- would still read as a live writer row; the level, not the old
    -- snapshot, decides (256's rule for the derived arm).
    v_direct := public.epigraph_operator_writes_group(v_human, p_group);
    IF v_direct AND current_setting('transaction_isolation') = 'read committed' THEN
        RETURN;
    END IF;
    -- 165: the principal's own derived membership, by the viewer's rule, at
    -- this statement's clock (a transaction opened in the window does not
    -- keep writing past its end). Not evaluated when the direct arm already
    -- decided (310: that write is refused below either way).
    v_derived := NOT v_direct
                 AND EXISTS (SELECT 1
                               FROM public.epigraph_role_derived_memberships(p_agent, clock_timestamp()) d
                              WHERE d.group_id = p_group AND d.role = 'writer');
    -- 256: and only under READ COMMITTED. Under REPEATABLE READ or
    -- SERIALIZABLE the derivation reads the transaction's first snapshot, so
    -- an assignment or binding ended (and committed) since would still read
    -- as live; the level, not the old snapshot, decides (166's ROL01 rule).
    IF v_derived AND current_setting('transaction_isolation') = 'read committed' THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_direct THEN
        RAISE EXCEPTION 'OPL02: principal % reaches group % through a direct membership of '
                        'operator %, and a write through a direct membership is admitted only '
                        'under READ COMMITTED (this transaction is %): an older snapshot would '
                        'still see a membership revoked since', p_agent, p_group, v_human,
                        current_setting('transaction_isolation')
            USING ERRCODE = 'OPL02',
                  HINT = 'Nothing was written. Write under READ COMMITTED (the default).';
    END IF;
    IF v_derived THEN
        RAISE EXCEPTION 'OPL02: principal % reaches group % only through a role binding, and a '
                        'write through a role binding is admitted only under READ COMMITTED '
                        '(this transaction is %): an older snapshot would still see an '
                        'assignment or binding ended since', p_agent, p_group,
                        current_setting('transaction_isolation')
            USING ERRCODE = 'OPL02',
                  HINT = 'Nothing was written. Write under READ COMMITTED (the default).';
    END IF;
    IF v_human = p_agent THEN
        RAISE EXCEPTION 'OPL02: human operator % holds no writer/admin membership in group %; '
                        'a human writes only where it writes', p_agent, p_group
            USING ERRCODE = 'OPL02',
                  HINT = 'Write into a group you write (your personal group is the default). '
                         'A custodial revision is made on the maintenance DSN with '
                         'epigraph-operator custodial-supersede.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_human, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. No application '
                     'session crosses humans, a custodian''s included.';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) FROM PUBLIC;
