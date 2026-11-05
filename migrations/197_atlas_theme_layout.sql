-- 197_atlas_theme_layout.sql
-- Atlas P3a (backlog f9b4a488, 2b5bd83e, 4321ae80; owner ruling A1, claim 7b8f47a7).
-- Shared theme/region layout per layout run, computed ONLY from public current
-- claims and public in-force edges by the operator CLI `atlas_layout` on the
-- maintenance DSN. No claim_id column and no FK to claims, on purpose: these
-- are aggregates of public rows, outside tenancy_coverage.rs's generators A/B.
-- A run is served only while atlas_layout_runs.visibility_epoch equals
-- atlas_layout_epoch.n; the definer trigger below bumps n in the same
-- transaction that turns any public claim or edge non-public, so no aggregate
-- outlives the publicity of a row it counted.
-- Undo (only after rolling back a binary that serves /graph/themes/layout):
--   DROP TRIGGER claims_atlas_layout_narrowed ON public.claims;
--   DROP TRIGGER edges_atlas_layout_narrowed ON public.edges;
--   DROP FUNCTION public.epigraph_atlas_layout_narrowed();
--   DROP TABLE public.atlas_layout_theme_links, public.atlas_layout_themes,
--              public.atlas_layout_regions, public.atlas_layout_runs,
--              public.atlas_layout_epoch;
SET LOCAL lock_timeout = '3s';

CREATE TABLE public.atlas_layout_epoch (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    n         bigint  NOT NULL DEFAULT 0 CHECK (n >= 0)
);
INSERT INTO public.atlas_layout_epoch DEFAULT VALUES;

CREATE TABLE public.atlas_layout_runs (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    completed_at        timestamptz NOT NULL DEFAULT now(),
    -- e.g. 'pca2-ward-v1'
    algo                text NOT NULL CHECK (length(algo) BETWEEN 1 AND 64),
    -- k, k_range, silhouette, min_public_members
    params              jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- informational; NO FK (the clustering retention sweep deletes runs)
    cluster_run_id      uuid,
    -- atlas_layout_epoch.n in the build snapshot
    visibility_epoch    bigint  NOT NULL CHECK (visibility_epoch >= 0),
    -- placed themes
    theme_count         integer NOT NULL CHECK (theme_count >= 0),
    region_count        integer NOT NULL CHECK (region_count BETWEEN 0 AND 200),
    public_claim_count  bigint  NOT NULL CHECK (public_claim_count >= 0),
    public_link_count   bigint  NOT NULL CHECK (public_link_count >= 0),
    -- SHA-256 hex of the sorted placed theme ids
    theme_set_digest    text    NOT NULL CHECK (theme_set_digest ~ '^[0-9a-f]{64}$')
);
CREATE INDEX atlas_layout_runs_completed_idx
    ON public.atlas_layout_runs (completed_at DESC, id DESC);

CREATE TABLE public.atlas_layout_regions (
    id                  uuid NOT NULL PRIMARY KEY,
    run_id              uuid NOT NULL REFERENCES public.atlas_layout_runs(id) ON DELETE CASCADE,
    ordinal             integer NOT NULL CHECK (ordinal BETWEEN 0 AND 199),
    label               text NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
    x                   double precision NOT NULL,
    y                   double precision NOT NULL,
    r                   double precision NOT NULL CHECK (r > 0),
    -- L2-normalised mean of member PUBLIC centroids
    centroid            public.vector(1536) NOT NULL,
    UNIQUE (run_id, ordinal),
    -- composite FK target
    UNIQUE (run_id, id)
);

CREATE TABLE public.atlas_layout_themes (
    run_id              uuid NOT NULL REFERENCES public.atlas_layout_runs(id) ON DELETE CASCADE,
    theme_id            uuid NOT NULL REFERENCES public.claim_themes(id) ON DELETE CASCADE,
    region_id           uuid NOT NULL,
    -- shared order; cursors carry this, never a count
    rank_in_region      integer NOT NULL CHECK (rank_in_region >= 0),
    x                   double precision NOT NULL,
    y                   double precision NOT NULL,
    -- build input; never served
    public_member_count bigint NOT NULL CHECK (public_member_count > 0),
    PRIMARY KEY (run_id, theme_id),
    UNIQUE (run_id, region_id, rank_in_region),
    FOREIGN KEY (run_id, region_id)
        REFERENCES public.atlas_layout_regions(run_id, id) ON DELETE CASCADE
);

CREATE TABLE public.atlas_layout_theme_links (
    run_id       uuid NOT NULL,
    theme_a      uuid NOT NULL,
    theme_b      uuid NOT NULL,
    relationship text NOT NULL CHECK (length(relationship) BETWEEN 1 AND 100
                                      AND relationship = lower(relationship)),
    link_count   bigint NOT NULL CHECK (link_count > 0),
    PRIMARY KEY (run_id, theme_a, theme_b, relationship),
    CHECK (theme_a < theme_b),
    FOREIGN KEY (run_id, theme_a)
        REFERENCES public.atlas_layout_themes(run_id, theme_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, theme_b)
        REFERENCES public.atlas_layout_themes(run_id, theme_id) ON DELETE CASCADE
);
CREATE INDEX atlas_layout_theme_links_b_idx
    ON public.atlas_layout_theme_links (run_id, theme_b);

-- The narrowing bump. Row-level AFTER UPDATE with a WHEN clause and NO column
-- list: a column-list trigger fires only when the column is a SET target, and
-- 070's BEFORE trigger on edges rewrites visibility when source_id/target_id
-- is repointed (viewer_fixture.rs, seed_edge_owned_by), which a column list
-- would miss. The WHEN is evaluated without calling the function, so ordinary
-- updates (truth_value recomputes, is_current flips) queue nothing.
CREATE OR REPLACE FUNCTION public.epigraph_atlas_layout_narrowed()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE public.atlas_layout_epoch SET n = n + 1 WHERE singleton;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_layout_narrowed() FROM PUBLIC;

CREATE TRIGGER claims_atlas_layout_narrowed AFTER UPDATE ON public.claims
    FOR EACH ROW
    WHEN (OLD.visibility = 'public' AND NEW.visibility IS DISTINCT FROM 'public')
    EXECUTE FUNCTION public.epigraph_atlas_layout_narrowed();
CREATE TRIGGER edges_atlas_layout_narrowed AFTER UPDATE ON public.edges
    FOR EACH ROW
    WHEN (OLD.visibility = 'public' AND NEW.visibility IS DISTINCT FROM 'public')
    EXECUTE FUNCTION public.epigraph_atlas_layout_narrowed();

-- Privileges. 077's ALTER DEFAULT PRIVILEGES FOR ROLE epigraph grants
-- SELECT, INSERT, UPDATE, DELETE on every new table to epigraph_app
-- (077_rls_policies.sql); 070's maintenance grant covered only the tables
-- that existed then. So both halves are explicit.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.atlas_layout_epoch, '
                'public.atlas_layout_runs, public.atlas_layout_regions, '
                'public.atlas_layout_themes, public.atlas_layout_theme_links FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.atlas_layout_epoch, public.atlas_layout_runs, '
                'public.atlas_layout_regions, public.atlas_layout_themes, '
                'public.atlas_layout_theme_links TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.atlas_layout_runs, '
                'public.atlas_layout_regions, public.atlas_layout_themes, '
                'public.atlas_layout_theme_links TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, UPDATE ON public.atlas_layout_epoch TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_atlas_layout_narrowed() OWNER TO epigraph_maintenance';
    END IF;
END $$;
