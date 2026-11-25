-- 296: a role projection edge is written only by maintenance (human-identity
-- visibility spec docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 7 row K1 and section 15 R1; security review of migration 292,
-- finding 2).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 292 owns each projection edge by the role's bound team (or the holder's
-- personal group). `edges` row security admits an UPDATE or DELETE by any
-- writer of the owning group (117's `edges_update_owner`, 120's
-- `edges_delete_owner`), so a writer of that team could
--   * widen the edge to `public` (only the owner columns are frozen, by 260's
--     `edges_owner_immutable`; `visibility` is not), republishing exactly what
--     the operator's ruling hides;
--   * strip or rewrite the marker, the role or the window;
--   * delete it, removing the holder from the governance graph.
-- And any edge writer could put the marker on a row of its own (INSERT, or an
-- UPDATE that adds it), dressing an ordinary edge as a projection.
--
-- ===================================================================
-- 2. THE GUARD
-- ===================================================================
--
-- `epigraph_role_projection_edges_guard()`, SECURITY INVOKER on 271's
-- `pg_catalog, pg_temp` path, every name qualified, admits a write only when
-- `public.epigraph_bypass()` (the SESSION is a maintenance member) or
-- `public.epigraph_definer_bypass()` (the CURRENT frame is a maintenance-owned
-- definer: the audit trigger's projection INSERT and end UPDATE, 295's re-own,
-- the tenancy re-meet); anything else is refused OCC05 (42501). It must be an
-- INVOKER: as a definer its frame would itself be the owner and admit
-- everyone. Three triggers on `edges`, each keyed on the marker by a WHEN
-- clause, so no other edge write runs any code:
--   * `edges_role_projection_guard_insert`  BEFORE INSERT, NEW carries it;
--   * `edges_role_projection_guard_update`  BEFORE UPDATE, OLD or NEW carries it;
--   * `edges_role_projection_guard_delete`  BEFORE DELETE, OLD carries it.
-- The marker is the audit trigger's (123, 130, 292):
-- `properties @> {"source": "role_assignments", "projection": true}`.
--
-- The legitimate writers all run as maintenance: `epigraph_grant_role` /
-- `epigraph_end_role_assignment` and the `role_assignments` audit trigger
-- (maintenance-owned definers, EXECUTE maintenance only), the
-- `group_role_bindings` writes (maintenance policies) and their re-own
-- trigger, the operator CLI (maintenance DSN), and every edge re-meet
-- definer (maintenance-owned). None runs on the application role.
--
-- UNDO: `docs/runbooks/296-undo.sql` (drops the three triggers and the guard).
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_role_projection_edges_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_id uuid;
BEGIN
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'INSERT' THEN
        v_id := NEW.id;
    ELSE
        v_id := OLD.id;
    END IF;
    RAISE EXCEPTION 'OCC05: a role projection edge (the role_assignments audit trigger''s '
                    'marker) is written only by a maintenance session or a maintenance-owned '
                    'definer; this % was refused and nothing was changed', TG_OP
        USING ERRCODE = '42501', DETAIL = COALESCE(v_id::text, '');
END $$;
REVOKE ALL ON FUNCTION public.epigraph_role_projection_edges_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS edges_role_projection_guard_insert ON public.edges;
CREATE TRIGGER edges_role_projection_guard_insert
    BEFORE INSERT ON public.edges
    FOR EACH ROW
    WHEN (NEW.properties @> '{"source": "role_assignments", "projection": true}'::jsonb)
    EXECUTE FUNCTION public.epigraph_role_projection_edges_guard();

DROP TRIGGER IF EXISTS edges_role_projection_guard_update ON public.edges;
CREATE TRIGGER edges_role_projection_guard_update
    BEFORE UPDATE ON public.edges
    FOR EACH ROW
    WHEN (OLD.properties @> '{"source": "role_assignments", "projection": true}'::jsonb
          OR NEW.properties @> '{"source": "role_assignments", "projection": true}'::jsonb)
    EXECUTE FUNCTION public.epigraph_role_projection_edges_guard();

DROP TRIGGER IF EXISTS edges_role_projection_guard_delete ON public.edges;
CREATE TRIGGER edges_role_projection_guard_delete
    BEFORE DELETE ON public.edges
    FOR EACH ROW
    WHEN (OLD.properties @> '{"source": "role_assignments", "projection": true}'::jsonb)
    EXECUTE FUNCTION public.epigraph_role_projection_edges_guard();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_projection_edges_guard() '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 296 guard '
                     'stays owned by the migration runner.';
    END IF;
END $$;
