-- Undo migration 295 (role_edges_genuine_projections_only): restore 292's body of
-- epigraph_group_role_bindings_reown_role_edges (every edge of the relationship with a
-- matching `properties.role`, forged rows included) and drop the genuine-projection re-own.
-- Run on a maintenance connection, in reverse order (296's undo first when it was applied),
-- AFTER rolling back every binary built with 295 (none calls these functions; the trigger does).
-- Nothing the reconcile pass moved is reversed: it only ever re-owned genuine projections into
-- their team-only owner. CREATE OR REPLACE keeps the owner and ACL. Idempotent.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_reown_role_edges()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NOT (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) THEN
        RETURN NULL;
    END IF;
    WITH o AS (
        SELECT e.id, public.epigraph_role_edge_owner(NEW.role, e.source_id) AS g
          FROM public.edges e
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.properties ->> 'role' = NEW.role
    )
    UPDATE public.edges e
       SET visibility = 'group', owner_group_id = o.g, co_owner_group_id = NULL,
           declared_owner_group_id = o.g, declared_co_owner_group_id = NULL
      FROM o
     WHERE e.id = o.id
       AND (e.visibility, e.owner_group_id, e.co_owner_group_id,
            e.declared_owner_group_id, e.declared_co_owner_group_id)
           IS DISTINCT FROM ('group'::varchar, o.g, NULL::uuid, o.g, NULL::uuid);
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_group_role_bindings_reown_role_edges() FROM PUBLIC;

DROP FUNCTION IF EXISTS public.epigraph_reown_role_projection_edges(text);
