-- ===================================================================
-- 310-undo.sql: take migration 310 (the direct-membership writer arm admits
-- only under READ COMMITTED) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST: no binary depends on 310, so nothing needs rolling back
-- first. Run this BEFORE `256-undo.sql` when taking 256 out as well (that
-- one refuses any body but 256's or 166's).
--
-- WHAT IT DOES: re-states 256's body of
-- `public.epigraph_require_writer_scope(uuid, uuid)` byte for byte.
-- `CREATE OR REPLACE` keeps its owner and grants. From then on a bound
-- principal under REPEATABLE READ or SERIALIZABLE writes through its human's
-- direct membership again, and keeps writing after that membership is
-- revoked or demoted by another session, until its transaction ends (310's
-- header).
--
-- PRECONDITION: the body in place must be 310's (md5 of `prosrc`
-- `513b346945eeff4d760c558b7d43075f`) or already 256's
-- (`9693498b3365ddfa8f97d4ead83b2ee6`, a second run); over any other body it
-- raises 55000 and changes nothing (a later migration re-bodied it: undo
-- that one first).
--
-- WHAT IT LEAVES: 310's `_sqlx_migrations` row. Re-introducing the change
-- is a NEW migration, never a re-run of 310. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_require_writer_scope(uuid, uuid)');
    IF v_found IS NULL OR v_found NOT IN ('513b346945eeff4d760c558b7d43075f',
                                          '9693498b3365ddfa8f97d4ead83b2ee6') THEN
        RAISE EXCEPTION '310-undo: public.epigraph_require_writer_scope(uuid, uuid) is neither '
                        '310''s body nor 256''s; found md5 %. Nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- 256's body, byte for byte (CREATE OR REPLACE keeps owner and grants).
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

COMMIT;
