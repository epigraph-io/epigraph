-- 287: the name an UNNAMED human is shown under is the placeholder a nameless
-- OAuth service principal carries, `oauth:<client row id>` (operator ruling C7;
-- spec docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 5 and 16.C7).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 274's rule hides an unnamed human's name, and the surfaces showed
-- `display_name: null` in its place. But `ensure_for_client` names every
-- non-human OAuth principal `oauth:<client row id>`, never null, so a null
-- name on an `oauth-principal` agent marked exactly the hidden humans, and
-- `GET /api/v1/agents?label=oauth-principal` listed them. The operator ruled
-- (C7): redact an unnamed human's name to that placeholder, not null, so it
-- reads byte for byte as a nameless service principal on every surface.
--
-- ===================================================================
-- 2. THE FUNCTION
-- ===================================================================
--
--   epigraph_unnamed_agent_name(p_agent uuid) RETURNS text
--
-- `'oauth:' || <id of the agent's EARLIEST linked oauth_clients row>`
-- (`created_at`, then `id`), or NULL when no client is linked. The earliest
-- linked client is the provisioning one: `ensure_for_client` derives a
-- principal's key from the client it is minted for and links that client in
-- the same transaction, and `set_agent_id` links an unlinked client only to
-- the row derived from it (or, for an `agent` client, to the real signer it
-- names), so any other client linked to the row was inserted after it. That
-- matters: the placeholder is publicly checkable, `public_key =
-- blake3::derive_key("epigraph-oauth-client", <uuid in the name>)`, for a
-- service principal; a human shown under any other client's id would fail the
-- check (pinned by
-- `human_identity_visibility.rs::an_unnamed_humans_placeholder_is_its_provisioning_clients`).
--
-- It is the ONE spelling of the placeholder in SQL; the Rust side
-- (`agent_disclosure.rs`) only ever calls it, in the ELSE of the disclosure
-- decision (`CASE WHEN named THEN display_name ELSE
-- epigraph_unnamed_agent_name(id) END`), so it runs only for an unnamed
-- human, and for the matcher's placeholder candidates.
--
-- SHAPE. SECURITY INVOKER, `LANGUAGE sql STABLE`, every name qualified, no
-- pinned path (not a trigger: 271's ratchet admits it; the body names no
-- unqualified type, relation or function). It reads only `oauth_clients`,
-- which carries no row policy and which the application and maintenance roles
-- already SELECT (070; spec 16.C13), so as an invoker it widens nothing.
-- Owner `epigraph_maintenance` (who may replace it); EXECUTE revoked from
-- PUBLIC and granted to `epigraph_app` (every request surface that names an
-- agent calls it).
--
-- UNDO: `docs/runbooks/287-undo.sql` (drop it, AFTER rolling back the
-- binaries that call it).
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_unnamed_agent_name(p_agent uuid)
RETURNS pg_catalog.text
LANGUAGE sql STABLE SECURITY INVOKER AS $$
    SELECT 'oauth:' OPERATOR(pg_catalog.||) c.id::pg_catalog.text
      FROM public.oauth_clients c
     WHERE c.agent_id OPERATOR(pg_catalog.=) p_agent
     ORDER BY c.created_at, c.id
     LIMIT 1
$$;
REVOKE ALL ON FUNCTION public.epigraph_unnamed_agent_name(uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_unnamed_agent_name(uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 287 placeholder '
                     'name stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unnamed_agent_name(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
