-- 105: `epigraph_ensure_personal_group` never revives, never promotes.
--
-- ===================================================================
-- THE DEFECT (backlog F2, `af7c58d9`; the root of F1, #493 and the #498
-- `system_agent_write_authority` finding)
--
-- Migration 077 created this function with a membership statement of
--
--     ON CONFLICT (group_id, agent_id, epoch)
--     DO UPDATE SET revoked_at = NULL, role = 'admin'
--
-- so EVERY call for an agent that already had a row in its personal group
-- restored that row to a live admin: a deliberate revocation was reversed, and a
-- deliberate demotion to `reader` was reversed. On its own that is a privilege
-- change hidden inside a provisioning helper. It became a live defect through
-- the callers: a read on an UNSTAMPED `epigraph_app` connection cannot see the
-- agent's personal group (`groups_tenancy` hides it), reports "no group", and
-- calls this function to mint one. MEASURED three times on the real binary as
-- `epigraph_app`: PR-09's `EpiGraphMcpFull::agent_id` (per HTTP session, +4
-- claims committed under the revived membership), `recall_audit_owner_group`
-- (#493, on every recall), and `system_agent_write_authority` (#498, +3 claims).
-- Each was patched at its caller; this file removes the thing they all reached.
--
-- ===================================================================
-- THE CONTRACT, AFTER THIS FILE
--
-- For the (personal group, agent) pair, across EVERY epoch:
--
--   * a LIVE row exists       -> return the group; write nothing. The row's role
--                                is kept, whatever it is.
--   * only REVOKED rows exist -> RAISE SQLSTATE 'RVK01'. A distinguishable
--                                refusal, never a silent success and never a
--                                revival. Reversing a revocation is an operator
--                                action (restore the row explicitly).
--   * no row of any state     -> first-time provisioning, exactly as before: the
--                                group (if absent) and one live epoch-0 `admin`
--                                row.
--
-- Signature and return shape are unchanged (`(uuid) RETURNS uuid`), so no caller
-- has to change to keep compiling; each caller's handling of the refusal is its
-- own decision and is made in the same commit.
--
-- WHY A RAISE AND NOT A NULL RETURN. 077's sibling
-- `epigraph_provision_oauth_agent` refuses by returning NULL, and the Rust side
-- has to remember to map it. A NULL here would be a silent success for every
-- raw-SQL caller (`scripts/e2e/probe-workflow.sh` binds the result straight into
-- a fixture). A RAISE aborts the caller's statement, and its SQLSTATE lets the
-- Rust layer name it: `epigraph-db/src/errors.rs` maps 'RVK01' to
-- `DbError::MembershipRevoked`.
--
-- WHY 'RVK01'. SQLSTATE classes beginning 0-4 or A-H are reserved to the
-- standard; PostgreSQL's own implementation-defined classes are 53-58, F0, HV,
-- P0 and XX. Class 'RV' collides with none of them, so no server-raised error
-- can ever be mistaken for this refusal.
--
-- WHY "ANY EPOCH". The old targeted conflict only looked at epoch 0. A personal
-- group has one member at one epoch in practice, but a revoked row at any epoch
-- is the same operator decision, and an INSERT at epoch 0 beside it would be a
-- revival spelled differently.
--
-- ===================================================================
-- THE LIVE PATH WRITES NOTHING
--
-- 077 upserted `groups` (`ON CONFLICT (did_key) DO UPDATE SET updated_at =
-- now()`) on every call, so even an already-provisioned agent took a row lock on
-- its group and bumped `updated_at` — on what is, for most callers, a read path.
-- The group is now read first; the upsert runs only when the group is absent.
--
-- ===================================================================
-- CONCURRENCY
--
-- Two first-time callers can both read "no row" and both reach the INSERT. The
-- membership INSERT is untargeted `ON CONFLICT DO NOTHING`: the second waits on
-- the first's uniqueness check (the composite `(group_id, agent_id, epoch)`
-- UNIQUE, or the partial `group_memberships_one_live` index), then inserts
-- nothing. `NOT FOUND` then re-reads under a new READ COMMITTED snapshot and
-- returns the group if the concurrent row is live. If it is not live — a revoke
-- raced the provisioning — the refusal is raised, which is the correct answer
-- for a row that is revoked by the time this call can see it.
--
-- Untargeted, deliberately, and safe here where 077's comment says it was not:
-- 077 needed the targeted conflict because an untargeted DO NOTHING "silently
-- no-ops" against a revoked row and returned success. That silent case is now
-- handled BEFORE the INSERT (the revoked-rows RAISE) and AFTER it (the re-read),
-- so a no-op insert can no longer be mistaken for provisioning.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_ensure_personal_group(p_agent uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_did   text := 'did:epigraph:personal:' || p_agent::text;
    v_group uuid;
BEGIN
    SELECT g.id INTO v_group FROM public.groups g WHERE g.did_key = v_did;

    IF v_group IS NOT NULL THEN
        -- A live row: keep it exactly as it is, role included. No write.
        IF EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group
                      AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL) THEN
            RETURN v_group;
        END IF;

        -- Only revoked rows, at any epoch: refuse.
        IF EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group
                      AND m.agent_id = p_agent) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'RVK01',
                MESSAGE = format(
                    'agent %s holds only REVOKED membership(s) of its personal group %s; '
                    'epigraph_ensure_personal_group does not restore a revoked membership',
                    p_agent, v_group),
                HINT = 'Reversing a revocation is an operator action: restore the '
                       'group_memberships row explicitly if the revocation was a mistake.';
        END IF;
    ELSE
        INSERT INTO public.groups (display_name, did_key, public_key, kind,
                                   created_by_agent_id)
        VALUES ('personal:' || p_agent::text, v_did, ''::bytea, 'personal', p_agent)
        ON CONFLICT (did_key) DO UPDATE SET updated_at = now()
        RETURNING id INTO v_group;
    END IF;

    -- No row of any state: first-time provisioning.
    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                          epoch, role)
    VALUES (v_group, p_agent, ''::bytea, 0, 'admin')
    ON CONFLICT DO NOTHING;
    IF FOUND THEN
        RETURN v_group;
    END IF;

    -- A concurrent caller inserted first. Re-read under a new snapshot.
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group
                  AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL) THEN
        RETURN v_group;
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = 'RVK01',
        MESSAGE = format(
            'agent %s holds only REVOKED membership(s) of its personal group %s; '
            'epigraph_ensure_personal_group does not restore a revoked membership',
            p_agent, v_group),
        HINT = 'Reversing a revocation is an operator action: restore the '
               'group_memberships row explicitly if the revocation was a mistake.';
END $$;

-- `CREATE OR REPLACE` keeps the function's owner and ACL, so 077's
-- `epigraph_maintenance` ownership and `epigraph_app` EXECUTE grant survive.
-- Re-stated anyway, in 077's own conditional form, so this file does not depend
-- on the history of whichever database it lands on.
REVOKE EXECUTE ON FUNCTION public.epigraph_ensure_personal_group(uuid) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_ensure_personal_group(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_ensure_personal_group(uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- UNDO: re-run 077's `CREATE OR REPLACE FUNCTION
-- public.epigraph_ensure_personal_group` body. That restores the revival, which
-- is the defect this file removes; no rows are created or changed here, so there
-- is nothing to un-create.
