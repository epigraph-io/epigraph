-- 210_atlas_team_layout.sql
-- Atlas W2 (backlog 77f4bf09, epic 8fa0282d): per-team Atlas layout storage
-- and its staleness epoch, beside migration 197's public-only atlas_layout_*
-- tables (design docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-
-- subgraph-view-design.md, sections 2, 5 and 7).
--
-- ===================================================================
-- 0. THE MAPS
-- ===================================================================
--
-- A map is `(owner_group_id, visibility)`:
--   * a TEAM map is ('group', T), T a group of kind 'team' or 'community'
--     (206's definition of a TEAM); it is built from T's claims plus public
--     claims and read by T's members;
--   * the PUBLIC map is ('public', world group), built from public claims only
--     and readable by every session, an unstamped one included (rule A1 of the
--     2026-11-04 Atlas design). The world group is the owner 077 already gives
--     instance-wide rows (frames, contexts, perspectives, communities).
--
-- Three tables, each with 062's tier-A shape (section 3):
--
--   atlas_map_epochs  one staleness counter per map (created on first bump)
--   atlas_map_runs    one nightly build of one map; UNFINISHED until the
--                     builder stamps finished_at, and readers take finished
--                     runs only, so a half-written run is never served
--   atlas_map_levels  one jsonb level document per (run, hierarchy, group id):
--                     the primary key makes a level one index probe. The
--                     payload's JSON schema is owned and versioned by W10a
--                     (backlog 8921ce49); this table indexes only the key
--                     columns and keeps `schema_version` beside the document.
--
-- No claim_id column and no FK to claims (the documents are built from claims
-- by the nightly), so tenancy_coverage.rs's generators do not reach these
-- tables; they carry the tenancy columns because a team map's documents are
-- that team's private data, and the standard `<table>_tenancy` policy is what
-- keeps them from a non-member.
--
-- ===================================================================
-- 1. STALENESS: WHICH EPOCH BUMPS
-- ===================================================================
--
-- A map's READABLE SET is what its builder may draw:
--   * team T:     claims ('group', T), plus every public claim;
--   * public map: every public claim.
-- Each half has its own epoch: T's row tracks the ('group', T) claims and the
-- world row tracks the public claims. A team run records both epochs in its
-- build snapshot and is CURRENT only while both are unchanged; a public run
-- records the world epoch in both columns.
--
-- A claim's SIGNATURE is 'public' or ('group', owner). The trigger in section
-- 4 bumps, once per statement, every map key of the OLD and the NEW signature
-- of each claim whose signature changed (world for 'public', the owner for
-- 'group'), keeping only world and team/community groups (a personal or seed
-- group has no map). Hence:
--   * ('group', A) -> ('group', B)          bumps A and B, nobody else;
--   * ('group', P) -> ('group', A), P personal: bumps A only;
--   * ('group', A) -> ('group', P), P personal: bumps A only;
--   * publicize, ('group', B) -> 'public':  bumps B and the public map
--     (B's private half lost the claim; the public half gained it, which also
--     stales every team map through its public epoch);
--   * narrowing, 'public' -> ('group', A):  bumps the public map and A;
--   * re-owning a PUBLIC claim (owner A -> B, still public): bumps nothing,
--     because no readable set changed;
--   * any UPDATE that changes no tenancy:   bumps nothing (the firing gate).
--
-- NOT bumped, on purpose:
--   * a claim INSERT or DELETE. A new claim appears on the next nightly
--     (design section 2, "Freshness"); bumping on every insert would leave
--     every map permanently stale.
--   * edges and evidence. Their tenancy follows their claims through 070's
--     claims_propagate_tenancy in the same statement, whose claim keys bump
--     here. A direct re-tenancy of an edge alone is a residual the nightly
--     picks up.
--   * co-owners. Claims have none; an edge's co_owner_group_id (072) NARROWS
--     reading to the intersection of two groups, it never grants it.
--
-- 197's `atlas_layout_epoch` and its two narrowing triggers are untouched.
--
-- ===================================================================
-- 2. COST
-- ===================================================================
--
-- Statement level with transition tables, beside 070's claims_propagate_tenancy,
-- which already makes every claims UPDATE capture OLD and NEW transition rows;
-- PostgreSQL shares those tuplestores between the triggers of one table and
-- event, so this trigger adds one scan of them. The firing gate is that scan:
-- an UPDATE that moves no tenancy returns before anything privileged runs.
-- A bulk move of N claims between K maps writes K epoch rows, once each,
-- in key order (a stable lock order between two concurrent bulk moves).
--
-- Undo (only after rolling back a binary that reads these tables):
--   DROP TRIGGER claims_atlas_map_stale ON public.claims;
--   DROP FUNCTION public.epigraph_atlas_map_stale();
--   DROP TABLE public.atlas_map_levels, public.atlas_map_runs,
--              public.atlas_map_epochs;
--   DROP FUNCTION public.epigraph_atlas_map_visibility_guard();
--   and remove the three names from docs/runbooks/079-undo.sql's array.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 3. TABLES (062's tier-A shape on each)
-- ===================================================================
CREATE TABLE public.atlas_map_epochs (
    owner_group_id  uuid NOT NULL PRIMARY KEY,
    visibility      character varying(16) NOT NULL,
    n               bigint NOT NULL CHECK (n >= 0),
    CONSTRAINT atlas_map_epochs_visibility_check
        CHECK (visibility IN ('public', 'group')),
    CONSTRAINT atlas_map_epochs_owner_group_fkey
        FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT atlas_map_epochs_group_needs_real_group CHECK (
        visibility <> 'group'
        OR owner_group_id NOT IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid)),
    -- The public map is the world group's, and only it.
    CONSTRAINT atlas_map_epochs_public_is_world CHECK (
        (visibility = 'public')
        = (owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid))
);

CREATE TABLE public.atlas_map_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_group_id  uuid NOT NULL,
    visibility      character varying(16) NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- NULL while the builder writes levels; readers take finished runs only.
    finished_at     timestamptz,
    algo            text NOT NULL CHECK (length(algo) BETWEEN 1 AND 64),
    params          jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- atlas_map_epochs.n of this map and of the public map in the build
    -- snapshot (0 when the row did not exist yet).
    map_epoch       bigint NOT NULL CHECK (map_epoch >= 0),
    public_epoch    bigint NOT NULL CHECK (public_epoch >= 0),
    level_count     integer CHECK (level_count >= 0),
    CONSTRAINT atlas_map_runs_visibility_check
        CHECK (visibility IN ('public', 'group')),
    CONSTRAINT atlas_map_runs_owner_group_fkey
        FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT atlas_map_runs_group_needs_real_group CHECK (
        visibility <> 'group'
        OR owner_group_id NOT IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid)),
    CONSTRAINT atlas_map_runs_public_is_world CHECK (
        (visibility = 'public')
        = (owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT atlas_map_runs_finished_has_count
        CHECK ((finished_at IS NULL) = (level_count IS NULL)),
    -- composite FK target: a level carries its run's tenancy, exactly
    UNIQUE (id, owner_group_id, visibility)
);
-- The serving read: the latest FINISHED run of one map.
CREATE INDEX atlas_map_runs_latest_idx
    ON public.atlas_map_runs (owner_group_id, visibility, finished_at DESC, id DESC)
    WHERE finished_at IS NOT NULL;

CREATE TABLE public.atlas_map_levels (
    run_id          uuid NOT NULL,
    owner_group_id  uuid NOT NULL,
    visibility      character varying(16) NOT NULL,
    hierarchy       text NOT NULL CHECK (hierarchy IN ('meaning', 'links')),
    -- the W4/W5 group this document describes (stable across nights)
    group_id        uuid NOT NULL,
    -- NULL exactly at level 0, a group directly under its theme
    parent_group_id uuid,
    theme_id        uuid NOT NULL REFERENCES public.claim_themes(id) ON DELETE CASCADE,
    level           integer NOT NULL CHECK (level BETWEEN 0 AND 64),
    -- the version of W10a's payload schema this document follows
    schema_version  integer NOT NULL CHECK (schema_version > 0),
    payload         jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    PRIMARY KEY (run_id, hierarchy, group_id),
    CONSTRAINT atlas_map_levels_parent_iff_nested
        CHECK ((parent_group_id IS NULL) = (level = 0)),
    CONSTRAINT atlas_map_levels_not_own_parent
        CHECK (parent_group_id IS DISTINCT FROM group_id),
    CONSTRAINT atlas_map_levels_run_fkey
        FOREIGN KEY (run_id, owner_group_id, visibility)
        REFERENCES public.atlas_map_runs(id, owner_group_id, visibility) ON DELETE CASCADE,
    CONSTRAINT atlas_map_levels_visibility_check
        CHECK (visibility IN ('public', 'group')),
    CONSTRAINT atlas_map_levels_owner_group_fkey
        FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT atlas_map_levels_group_needs_real_group CHECK (
        visibility <> 'group'
        OR owner_group_id NOT IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid))
);
-- A theme's top groups in one hierarchy of one run.
CREATE INDEX atlas_map_levels_theme_roots_idx
    ON public.atlas_map_levels (run_id, hierarchy, theme_id)
    WHERE level = 0;

-- ===================================================================
-- 3a. Declared, never defaulted (074), and immutable tenancy (115, 183)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_atlas_map_visibility_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: an UPDATE of % changes visibility; '
                    'only a maintenance session re-tenants an Atlas map row', TG_TABLE_NAME
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_map_visibility_guard() FROM PUBLIC;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['atlas_map_epochs', 'atlas_map_runs', 'atlas_map_levels'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON public.%I '
                       'FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy()',
                       t || '_require_tenancy', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF owner_group_id ON public.%I '
                       'FOR EACH ROW WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id) '
                       'EXECUTE FUNCTION public.epigraph_owner_immutable_guard()',
                       t || '_owner_immutable', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF visibility ON public.%I '
                       'FOR EACH ROW WHEN (OLD.visibility IS DISTINCT FROM NEW.visibility) '
                       'EXECUTE FUNCTION public.epigraph_atlas_map_visibility_guard()',
                       t || '_visibility_immutable', t);
    END LOOP;
END $$;

-- ===================================================================
-- 3b. Row security: the standard `<table>_tenancy` policy (077's tier-A
--     form), ENABLEd and FORCEd, plus 115's restrictive owner-scoped DELETE.
-- ===================================================================
-- READ: public, or owned by a group in the session's read set. A team map's
-- rows are ('group', T), so a non-member reads none of them; the public map's
-- rows are 'public', so an unstamped session reads them (A1).
-- WRITE: the application role holds SELECT only (section 6); the nightly
-- writes on the maintenance connection and the trigger below writes the
-- epochs as a maintenance-owned definer, both through the bypass arms. The
-- WITH CHECK is 077's all the same, so a grant added later cannot write a row
-- into a group the session does not write.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['atlas_map_epochs', 'atlas_map_runs', 'atlas_map_levels'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I FOR ALL TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR visibility = 'public'
                    OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_tenancy', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I AS RESTRICTIVE FOR DELETE TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_delete_owner', t);
    END LOOP;
END $$;

-- ===================================================================
-- 4. THE STALENESS TRIGGER (section 1)
-- ===================================================================
-- SECURITY DEFINER on 172's path, every public object qualified, EXECUTE
-- revoked from PUBLIC, owned by epigraph_maintenance (section 6), so the
-- upsert passes atlas_map_epochs' FORCEd policy through the definer bypass
-- whoever ran the claims UPDATE. The transition tables are ephemeral named
-- relations and resolve whatever the search_path.
CREATE OR REPLACE FUNCTION public.epigraph_atlas_map_stale()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- The firing gate: no claim's signature changed, nothing to do.
    IF NOT EXISTS (
        SELECT 1 FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.visibility::text,
                CASE WHEN ch.visibility::text = 'public' THEN NULL ELSE ch.owner_group_id END)
               IS DISTINCT FROM
               (p.visibility::text,
                CASE WHEN p.visibility::text = 'public' THEN NULL ELSE p.owner_group_id END))
    THEN RETURN NULL; END IF;

    WITH moved AS (
        SELECT p.visibility::text AS ov, p.owner_group_id AS og,
               ch.visibility::text AS nv, ch.owner_group_id AS ng
          FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.visibility::text,
                CASE WHEN ch.visibility::text = 'public' THEN NULL ELSE ch.owner_group_id END)
               IS DISTINCT FROM
               (p.visibility::text,
                CASE WHEN p.visibility::text = 'public' THEN NULL ELSE p.owner_group_id END)
    ), keys AS (
        SELECT CASE WHEN ov = 'public'
                    THEN '00000000-0000-0000-0000-000000000000'::uuid ELSE og END AS k
          FROM moved
        UNION
        SELECT CASE WHEN nv = 'public'
                    THEN '00000000-0000-0000-0000-000000000000'::uuid ELSE ng END
          FROM moved
    )
    INSERT INTO public.atlas_map_epochs AS e (owner_group_id, visibility, n)
    SELECT k.k,
           CASE WHEN k.k = '00000000-0000-0000-0000-000000000000'::uuid
                THEN 'public' ELSE 'group' END,
           1
      FROM keys k
      JOIN public.groups g ON g.id = k.k
     WHERE g.kind IN ('world', 'team', 'community')
     ORDER BY k.k
    ON CONFLICT (owner_group_id) DO UPDATE SET n = e.n + 1;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_map_stale() FROM PUBLIC;

CREATE TRIGGER claims_atlas_map_stale AFTER UPDATE
    ON public.claims REFERENCING OLD TABLE AS prev NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_atlas_map_stale();

-- ===================================================================
-- 5. Comments
-- ===================================================================
COMMENT ON TABLE public.atlas_map_epochs IS
    'Migration 210 (Atlas W2): one staleness counter per Atlas map; bumped once per '
    'statement by claims_atlas_map_stale when a claim enters or leaves the map''s half of '
    'the readable set. (world, public) is the public map.';
COMMENT ON TABLE public.atlas_map_runs IS
    'Migration 210 (Atlas W2): one nightly build of one Atlas map; served only once '
    'finished_at is set, and current only while map_epoch and public_epoch still equal '
    'atlas_map_epochs.';
COMMENT ON TABLE public.atlas_map_levels IS
    'Migration 210 (Atlas W2): one level document per (run, hierarchy, group). The payload '
    'schema is versioned by schema_version (Atlas W10a).';

-- ===================================================================
-- 6. OWNERSHIP AND GRANTS
-- ===================================================================
-- 077's ALTER DEFAULT PRIVILEGES grants epigraph_app SELECT, INSERT, UPDATE,
-- DELETE on every new table; the application only reads these, so the writes
-- are revoked (197's form).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.atlas_map_epochs, '
                'public.atlas_map_runs, public.atlas_map_levels FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.atlas_map_epochs, public.atlas_map_runs, '
                'public.atlas_map_levels TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.atlas_map_runs, '
                'public.atlas_map_levels TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.atlas_map_epochs '
                'TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_atlas_map_stale() OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; '
                     'epigraph_atlas_map_stale stays owned by the migration runner.';
    END IF;
END $$;
