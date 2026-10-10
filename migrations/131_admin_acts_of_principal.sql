-- Migration 131: a person reads their OWN admin acts (elevation plan EL-12b,
-- `GET /api/v1/admin/acts?mine`).
--
-- Migration 130's `pending_admin_acts` admits no application-role read (its
-- row policies admit only a privileged session and a maintenance-owned
-- definer frame), so the API cannot show a proposer the acts it proposed:
-- which are waiting for the passkey, which were confirmed, refused, executed
-- or let expire. This adds one PRINCIPAL-BOUND reader:
--
--   `epigraph_admin_acts_of_principal(p_limit)`: the acts whose proposer is
--   the SESSION PRINCIPAL (`epigraph_principal_id()`), newest first, at most
--   `p_limit` (1..200; NULL reads as 50). An unstamped connection has no
--   principal and reads nothing. No caller-supplied id: an act is listed only
--   to the person who proposed it.
--
-- WHAT IT RETURNS: what the proposer already saw or decided (the kind, the
-- canonical args and their digest, the target, the reason, the elevation it
-- was proposed under, the times) and each step's outcome (asserted,
-- confirmed or refused and why, consumed). NEVER the ceremony's stored
-- challenge state or the assertion evidence (the offline verifier reads
-- those on the maintenance DSN), nor which login consumed the act or what the
-- execution produced.
--
-- WHAT IT DOES NOT CHANGE: no table, no policy, no earlier body. The
-- application role gets EXECUTE on this one function.
--
-- UNDO: `docs/runbooks/131-undo.sql` (drops the function), BEFORE 130-undo:
-- the body reads 130's table, and a `LANGUAGE sql` body records no
-- dependency, so 130-undo would otherwise leave this function behind,
-- pointing at a table that no longer exists. Roll back first every binary
-- that calls it (the API's act list).

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_admin_acts_of_principal(p_limit integer)
RETURNS TABLE (id uuid, kind text, args jsonb, args_digest bytea, target_type text,
               target_id uuid, reason text, elevation_id uuid, proposed_at timestamptz,
               expires_at timestamptz, asserted_at timestamptz, outcome text, refusal text,
               consumed_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT a.id, a.kind, a.args, a.args_digest, a.target_type, a.target_id, a.reason,
           a.elevation_id, a.proposed_at, a.expires_at, a.asserted_at, a.outcome, a.refusal,
           a.consumed_at
      FROM public.pending_admin_acts a
     WHERE a.proposed_by = public.epigraph_principal_id()
     ORDER BY a.proposed_at DESC, a.id
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_admin_acts_of_principal(integer) FROM PUBLIC;

-- OWNERSHIP AND GRANTS (guarded, as every such block since 060 is). Owned by
-- the maintenance role: under any other owner the table's definer-frame
-- policy admits no row, and the list reads empty.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_admin_acts_of_principal(integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_acts_of_principal(integer) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_admin_acts_of_principal(integer) '
                'TO epigraph_app';
    END IF;
END $$;
