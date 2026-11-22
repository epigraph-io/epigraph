-- 256: the role-DERIVED arm of the claims-path writer scope admits a write
-- only under READ COMMITTED (backlog a8cabb45).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 165 added a DERIVED arm to `epigraph_require_writer_scope` (OPL02, armed
-- only): the writing principal writes a group its role binding names, while
-- its role assignment and the binding are live. 165 evaluates the arm at
-- `clock_timestamp()`, so an elapsed `valid_to` stops a transaction opened
-- inside the window at its next statement. Its header records the residual:
-- under REPEATABLE READ or SERIALIZABLE the arm reads `role_assignments`
-- and `group_role_bindings` through the transaction's FIRST snapshot, so an
-- assignment or a binding ENDED by another session after that snapshot (an
-- UPDATE setting the end, committed) still reads as live, and the writer
-- keeps writing into the role's group until its transaction ends.
-- SERIALIZABLE does not save it: the end writes no row the write reads for
-- update, so no serialization failure is raised. The ruling for role-bound
-- authority is that every write after the end is refused.
--
-- 166 closed it for AGENTS only: an agent that could be attached writes
-- only under READ COMMITTED (ROL01, checked before this arm). A human was
-- left at any level, so a human role holder writing through its binding in
-- a long REPEATABLE READ / SERIALIZABLE transaction (an operator tool, a
-- bulk job) is the remaining case. Measured on a fresh database
-- (`derived_writer_scope_read_committed.rs`): on 166's body such a holder,
-- whose assignment is ended mid-transaction, writes; on 256's it is refused.
-- Low while the request path runs READ COMMITTED (the default; no
-- application write path sets another level).
--
-- ===================================================================
-- 2. THE CHANGE
-- ===================================================================
--
-- `CREATE OR REPLACE` of the one function, same signature, STABLE, same
-- search path (`public, pg_temp`), 166's body with one delta in the derived
-- arm:
--
--   * the arm ADMITS only when `transaction_isolation` is `read committed`;
--   * under any other level, when the arm would have admitted (by the
--     transaction's snapshot), the write is refused OPL02 with its own
--     message ("a write through a role binding is admitted only under READ
--     COMMITTED"), AFTER the exemption: a privileged session
--     (`epigraph_operator_scope_exempt`, i.e. `epigraph_bypass()`) is
--     exempt at any level, as before.
--
-- The level decides, not the old snapshot, exactly as 166's ROL01 does and
-- with 166/214's `<> 'read committed'` form (123/130/148's REPEATABLE-READ-
-- only guard would let SERIALIZABLE through, which misses the end too).
-- 122's DIRECT arm (`epigraph_operator_writes_group`) is checked first and
-- is unchanged: a holder writes its own groups at any level. The two OPL02
-- refusals that follow are 166's, verbatim. Everything that calls the
-- function (the claims trigger, 153's lineage check, 185, 206, 207) gets the
-- change through it; none is re-stated.
--
-- NOT CHANGED: the derivation `epigraph_role_derived_memberships` (195's
-- body) and the viewer's read set `epigraph_live_memberships` (235's body);
-- the READ side resolves per request at READ COMMITTED.
--
-- Residual (not this file): 122's DIRECT arm reads `group_memberships`
-- through the same snapshot, so a direct membership revoked after a
-- REPEATABLE READ / SERIALIZABLE transaction's snapshot is still seen by it.
--
-- `CREATE OR REPLACE` keeps 166's owner (`epigraph_maintenance`), ACL and
-- the function's registration at 122 in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs`; nothing is re-owned or
-- re-granted. A later re-statement starts from this body and keeps every
-- fragment `schema_contract.rs::migration_165_derived_arms_survive_at_head`
-- pins.
--
-- PRECONDITION: the body in place must be 166's (md5 of `prosrc`
-- `a7c9d5d196c1d45022df6f91e263bf14`); over any other body this file raises
-- 55000 and changes nothing, so it never silently discards another
-- migration's re-statement.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- No binary depends on it; apply it whenever. Before applying, measure that
-- no login that writes as a HUMAN principal on the application role runs at
-- another default level (`default_transaction_isolation` set on the
-- database or the role in `pg_db_role_setting`): such a write through a
-- role binding is refused OPL02 after 256 (loud) instead of outliving an
-- end (silent).
--
-- UNDO: `docs/runbooks/256-undo.sql` restores 166's body; run it BEFORE
-- `166-undo.sql`.
-- **Applied to throwaway databases only, NOT to any deployed database.**
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_require_writer_scope(uuid, uuid)');
    IF v_found IS DISTINCT FROM 'a7c9d5d196c1d45022df6f91e263bf14' THEN
        RAISE EXCEPTION '256: public.epigraph_require_writer_scope(uuid, uuid) is not the body '
                        '256 re-states (166''s, md5 a7c9d5d196c1d45022df6f91e263bf14); found '
                        'md5 %. Another migration re-bodied it, or 166 is not applied; nothing '
                        'was changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

-- The claims-path writer scope as 166 left it (122's body, 123's HINT, 165's
-- derived arm, 166's ROL01 line); delta: 256's READ COMMITTED condition on
-- the derived arm and its refusal.
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human   uuid;
    v_derived boolean;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    -- 166: ROL01, the agent the claims trigger checks here (the author, or
    -- the stamped writer when that is someone else).
    PERFORM public.epigraph_require_role_holder(p_agent);
    v_human := public.epigraph_human_of(p_agent, false);
    IF v_human IS NULL OR public.epigraph_operator_writes_group(v_human, p_group) THEN
        RETURN;
    END IF;
    -- 165: the principal's own derived membership, by the viewer's rule, at
    -- this statement's clock (a transaction opened in the window does not
    -- keep writing past its end).
    v_derived := EXISTS (SELECT 1
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
