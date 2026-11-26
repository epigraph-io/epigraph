-- Undo migration 315 (role_edges_team_only): restore 130's body of
-- epigraph_role_assignments_audit, and drop the binding re-own trigger and the owner rule.
-- Run on a maintenance connection, AFTER rolling back every binary built with 315 (none
-- calls these functions directly; the triggers do). The backfilled owners are NOT reversed:
-- the projection edges stay team-only (re-publishing them is exactly what the operator's
-- ruling forbids). New projections written after this undo are public again, as under 130.
-- CREATE OR REPLACE keeps the owner and ACL. Idempotent.
DROP TRIGGER IF EXISTS group_role_bindings_reown_role_edges ON public.group_role_bindings;
DROP FUNCTION IF EXISTS public.epigraph_group_role_bindings_reown_role_edges();

CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node uuid;
    v_act  uuid;
BEGIN
    SELECT r.role_node_id INTO v_node FROM public.platform_roles r WHERE r.key = NEW.role;
    IF TG_OP = 'INSERT' THEN
        -- Section 5: the projection, holder -> role node, in the edge's own
        -- validity columns. A structural (agent -> agent) edge: 120 owns it
        -- by the world group, public.
        INSERT INTO public.edges (source_id, source_type, target_id, target_type, relationship,
                                  properties, valid_from, valid_to, visibility, owner_group_id)
        VALUES (NEW.holder_person_id, 'agent', v_node, 'agent', 'OCCUPIES',
                jsonb_build_object('assignment_id', NEW.id::text, 'role', NEW.role,
                                   'source', 'role_assignments', 'projection', true),
                NEW.valid_from, NEW.valid_to, 'public',
                '00000000-0000-0000-0000-000000000000'::uuid);
        v_act := NEW.grant_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_granted', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by,
                                   'granted_via', NEW.granted_via, 'reason', NEW.reason,
                                   'migrated', NEW.granted_via = 'migration 123',
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- The projection closes at the end (or keeps an earlier valid_to).
        -- An assignment ended before it began keeps a one-microsecond window
        -- marked never_effective: `temporal_ordering` requires
        -- valid_to > valid_from.
        UPDATE public.edges e
           SET valid_to = CASE
                            WHEN LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                                 <= NEW.valid_from
                            THEN NEW.valid_from + interval '1 microsecond'
                            ELSE LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                          END,
               properties = e.properties
                   || jsonb_build_object('ended_at', NEW.revoked_at,
                                         'never_effective', NEW.revoked_at <= NEW.valid_from)
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.source_id = NEW.holder_person_id
           AND e.properties @> jsonb_build_object('assignment_id', NEW.id::text);
        -- Section 6: the end of the holder's LAST un-ended custodian
        -- assignment is mirrored into a live legacy `instance_admins` row, so a
        -- rollback to 083's body cannot resurrect an authority ended here.
        IF NEW.role = 'role:platform-custodian'
           AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                            WHERE ra.holder_person_id = NEW.holder_person_id
                              AND ra.role = 'role:platform-custodian'
                              AND ra.revoked_at IS NULL AND ra.id <> NEW.id) THEN
            UPDATE public.instance_admins SET revoked_at = now()
             WHERE agent_id = NEW.holder_person_id AND revoked_at IS NULL;
        END IF;
        v_act := NEW.revoke_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_ended', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoked_reason', NEW.revoked_reason,
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    END IF;
    RETURN NULL;
END $$;

DROP FUNCTION IF EXISTS public.epigraph_role_edge_owner(text, uuid);
