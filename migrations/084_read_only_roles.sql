-- Read-only and admin roles for provenance-safe database access.
--
-- Three roles:
--   epigraph       — full write, used ONLY by the API server (existing)
--   epigraph_ro    — read-only, default for scripts, CLI, AI agents
--   epigraph_admin — write access for one-off migrations/backfills (explicit opt-in)
--
-- All graph mutations should flow through the API to preserve provenance
-- (audit trails, reasoning traces, signature verification).

-- ── Read-only role ──────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_ro') THEN
        CREATE ROLE epigraph_ro WITH LOGIN PASSWORD 'epigraph_ro';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE epigraph TO epigraph_ro;
GRANT USAGE ON SCHEMA public TO epigraph_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO epigraph_ro;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO epigraph_ro;

-- Future tables automatically get SELECT for epigraph_ro
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO epigraph_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO epigraph_ro;

-- ── Admin role (for migrations/backfills that can't use API yet) ────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_admin') THEN
        CREATE ROLE epigraph_admin WITH LOGIN PASSWORD 'epigraph_admin';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE epigraph TO epigraph_admin;
GRANT USAGE ON SCHEMA public TO epigraph_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO epigraph_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO epigraph_admin;

-- Future tables automatically get full DML for epigraph_admin
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO epigraph_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO epigraph_admin;

-- Note: epigraph_admin intentionally does NOT get CREATE/DROP/ALTER.
-- Schema changes (DDL) remain exclusive to the epigraph superuser
-- and are applied only via sqlx migrate.
