-- ===================================================================
-- 256-undo.sql: take migration 256 (the role-derived writer arm admits only
-- under READ COMMITTED) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST: no binary depends on 256, so nothing needs rolling back
-- first. Run this BEFORE `166-undo.sql` when taking 166 out as well (that
-- one restores 165's body over whatever body is in place).
--
-- WHAT IT DOES: re-states 166's body of
-- `public.epigraph_require_writer_scope(uuid, uuid)` byte for byte.
-- `CREATE OR REPLACE` keeps its owner and grants. From then on a human role
-- holder under REPEATABLE READ or SERIALIZABLE writes through its role
-- binding again, and keeps writing after its assignment or the binding is
-- ended by another session, until its transaction ends (256's header).
--
-- PRECONDITION: the body in place must be 256's (md5 of `prosrc`
-- `9693498b3365ddfa8f97d4ead83b2ee6`) or already 166's
-- (`a7c9d5d196c1d45022df6f91e263bf14`, a second run); over any other body it
-- raises 55000 and changes nothing (a later migration re-bodied it: undo
-- that one first).
--
-- WHAT IT LEAVES: 256's `_sqlx_migrations` row. Re-introducing the change
-- is a NEW migration, never a re-run of 256. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_require_writer_scope(uuid, uuid)');
    IF v_found IS NULL OR v_found NOT IN ('9693498b3365ddfa8f97d4ead83b2ee6',
                                          'a7c9d5d196c1d45022df6f91e263bf14') THEN
        RAISE EXCEPTION '256-undo: public.epigraph_require_writer_scope(uuid, uuid) is neither '
                        '256''s body nor 166''s; found md5 %. Nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- 166's body, byte for byte (CREATE OR REPLACE keeps owner and grants).
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human uuid;
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
    IF EXISTS (SELECT 1
                 FROM public.epigraph_role_derived_memberships(p_agent, clock_timestamp()) d
                WHERE d.group_id = p_group AND d.role = 'writer') THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
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
