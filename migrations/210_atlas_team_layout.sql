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
--   atlas_map_epochs  the two staleness counters of one map (created on its
--                     first bump; section 1)
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
-- 1. STALENESS: TWO COUNTERS, WHICH ROWS BUMP THEM
-- ===================================================================
--
-- A map's READABLE SET is what its builder may draw:
--   * team T:     rows ('group', T), plus every public row;
--   * public map: every public row.
-- The rows are claims and the two kinds the map draws beside them, edges and
-- evidence. Each half has its own epoch row: T's row tracks the ('group', T)
-- rows and the world row tracks the public rows. A team run records both
-- rows in its build snapshot; a public run records the world row twice.
--
-- Each epoch row holds TWO counters, because an arrival and a departure ask
-- different things of a stored map:
--   n       bumps when a row ENTERS OR LEAVES the half. A run whose recorded n
--           still matches is CURRENT: nothing moved since the build.
--   left_n  bumps only when a row LEAVES the half for somewhere not public. A
--           run whose recorded left_n still matches holds NO row its viewers
--           have lost: an arrival only leaves the map incomplete (as an INSERT
--           does, which bumps nothing), a departure may leave it holding a row
--           a viewer can no longer read. What a route does with either is the
--           route's decision (Atlas W10); left_n lets it refuse only the
--           second without darkening every map on every share-with-team.
--   left_n counts tenancy departures only: a DELETE bumps neither counter.
--
-- A row's SIGNATURE is 'public', or ('group', owner[, co-owner]): edges carry
-- 072's co_owner_group_id, which narrows reading to members of both groups.
-- Its KEYS are world for 'public', else the owner and the co-owner. When a
-- row's signature changes:
--   * n      bumps every key of the OLD and the NEW signature;
--   * left_n bumps every key of the OLD signature, unless the new visibility
--            is public (a widening to public removes nobody's read).
-- Whole signatures are compared, not key sets: a ('group', G) edge that gains
-- a co-owner C keeps G among its keys, but G's members who are not in C have
-- lost it, so it is a departure from G. Only world and team/community groups
-- have epoch rows (a personal or seed group has no map). Hence, for claims:
--   * ('group', A) -> ('group', B)          n: A, B      left_n: A
--   * ('group', P) -> ('group', A), P personal: n: A      left_n: none
--   * ('group', A) -> ('group', P), P personal: n: A      left_n: A
--   * publicize, ('group', B) -> 'public':  n: B, public  left_n: none
--     (no map loses a row; every team map gains one through its public half)
--   * narrowing, 'public' -> ('group', A):  n: public, A  left_n: public
--     (every map loses the row through its public half)
--   * re-owning a PUBLIC row (owner A -> B, still public): nothing, because no
--     readable set changed;
--   * any UPDATE that changes no signature: nothing (the firing gate).
-- An edge or evidence row re-tenanted directly (an operator's hide-evidence,
-- a narrowed edge between two public claims, a co-owner change) bumps by the
-- same rule; when it moves through 070's claims cascade its keys are mostly
-- the claim's, which already bumped in this transaction (section 2).
--
-- NOT bumped, on purpose: a claim, edge or evidence INSERT or DELETE. A new
-- row appears on the next nightly (design section 2, "Freshness"); bumping
-- on every insert would leave every map permanently stale.
--
-- 197's `atlas_layout_epoch` and its two narrowing triggers are untouched.
--
-- ===================================================================
-- 2. AT MOST ONCE PER MAP PER TRANSACTION, AND COST
-- ===================================================================
--
-- A build only needs the counter to DIFFER from its snapshot, and another
-- transaction's bumps are invisible to a snapshot until it commits, so one
-- bump per counter per map per transaction is enough. Each counter keeps the
-- xid8 of the transaction that last bumped it (n_xact, left_xact; 194's
-- pg_current_xact_id() precedent): a bump whose transaction already bumped
-- that counter is skipped. This
--   * makes 070's cascade harmless: the claims statement bumps first
--     (claims_atlas_map_stale sorts before claims_propagate_tenancy, and AFTER
--     triggers fire by name), and the evidence and edge rows the cascade
--     re-tenants then find their keys already bumped;
--   * keeps a bulk move at one bump per map, however many statements or rows;
--   * keeps an arrival and a later departure in one transaction apart, each
--     counter on its own marker, so the departure still bumps left_n;
--   * is unforgeable: only the maintenance-owned definers below write the
--     epochs (the application role holds SELECT only), unlike a GUC marker a
--     session holding the DSN could pre-set;
--   * survives ROLLBACK TO SAVEPOINT: the rolled-back bump's row version goes
--     with it, and the version left has the earlier marker.
-- Nothing on this path RAISEs: an exception here would fail the claims,
-- edges or evidence UPDATE that fired it.
--
-- claims: statement level with transition tables, beside 070's
-- claims_propagate_tenancy, which already makes every claims UPDATE capture
-- OLD and NEW transition rows (PostgreSQL shares those tuplestores between
-- the triggers of one table and event), so this adds one scan of them and
-- returns when no signature changed.
-- edges, evidence: row level with a WHEN on the signature and no column list
-- (197's edges shape), so an ordinary UPDATE queues nothing and captures no
-- transition table; a bulk re-tenancy makes one guarded upsert per row, a
-- no-op after the first per map.
-- Upserts run in key order within one statement. Two transactions bumping
-- the same maps in different statement orders can still deadlock (one is
-- aborted and retried), and a map's epoch row stays locked until the bumping
-- transaction commits.
--
-- Undo: docs/runbooks/210-undo.sql (only after rolling back every binary
-- that reads these tables).
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 3. TABLES (062's tier-A shape on each)
-- ===================================================================
CREATE TABLE public.atlas_map_epochs (
    owner_group_id  uuid NOT NULL PRIMARY KEY,
    visibility      character varying(16) NOT NULL,
    -- section 1: any arrival or departure / departures only
    n               bigint NOT NULL CHECK (n >= 0),
    left_n          bigint NOT NULL CHECK (left_n >= 0),
    -- section 2: the transaction that last bumped each counter
    n_xact          xid8 NOT NULL,
    left_xact       xid8,
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
    -- atlas_map_epochs.n and .left_n of this map and of the public map in the
    -- build snapshot (0 when the row did not exist yet).
    map_epoch       bigint NOT NULL CHECK (map_epoch >= 0),
    public_epoch    bigint NOT NULL CHECK (public_epoch >= 0),
    map_left_epoch  bigint NOT NULL CHECK (map_left_epoch >= 0),
    public_left_epoch bigint NOT NULL CHECK (public_left_epoch >= 0),
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
-- 4. THE STALENESS TRIGGERS (sections 1 and 2)
-- ===================================================================
-- All three functions are SECURITY DEFINER on 172's path, every public object
-- qualified, EXECUTE revoked from PUBLIC, owned by epigraph_maintenance
-- (section 6), so the upsert passes atlas_map_epochs' FORCEd policy through
-- the definer bypass whoever ran the UPDATE. Transition tables are ephemeral
-- named relations and resolve whatever the search_path.

-- The bump: n for every key in `changed_keys`, left_n for every key in
-- `left_keys` (a subset of `changed_keys`), each at most once per
-- transaction, for world and team/community groups only, in key order.
CREATE OR REPLACE FUNCTION public.epigraph_atlas_map_bump(changed_keys uuid[], left_keys uuid[])
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cur xid8 := pg_catalog.pg_current_xact_id();
BEGIN
    INSERT INTO public.atlas_map_epochs AS e
           (owner_group_id, visibility, n, left_n, n_xact, left_xact)
    SELECT k.k,
           CASE WHEN k.k = '00000000-0000-0000-0000-000000000000'::uuid
                THEN 'public' ELSE 'group' END,
           1,
           CASE WHEN k.k = ANY (left_keys) THEN 1 ELSE 0 END,
           cur,
           CASE WHEN k.k = ANY (left_keys) THEN cur END
      FROM (SELECT DISTINCT u AS k
              FROM pg_catalog.unnest(changed_keys || left_keys) AS u
             WHERE u IS NOT NULL) k
      JOIN public.groups g ON g.id = k.k
     WHERE g.kind IN ('world', 'team', 'community')
     ORDER BY k.k
    ON CONFLICT (owner_group_id) DO UPDATE
       SET n         = CASE WHEN e.n_xact = cur THEN e.n ELSE e.n + 1 END,
           n_xact    = cur,
           left_n    = CASE WHEN EXCLUDED.left_n > 0 AND e.left_xact IS DISTINCT FROM cur
                            THEN e.left_n + 1 ELSE e.left_n END,
           left_xact = CASE WHEN EXCLUDED.left_n > 0 THEN cur ELSE e.left_xact END
     WHERE e.n_xact IS DISTINCT FROM cur
        OR (EXCLUDED.left_n > 0 AND e.left_xact IS DISTINCT FROM cur);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_map_bump(uuid[], uuid[]) FROM PUBLIC;

-- claims: once per statement, over the shared transition tables.
CREATE OR REPLACE FUNCTION public.epigraph_atlas_map_stale()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    changed_keys uuid[];
    left_keys    uuid[];
BEGIN
    -- One scan: the old and new key of every claim whose signature changed
    -- (a claim's signature is its key: world for public, else its owner).
    SELECT pg_catalog.array_agg(DISTINCT m.ok) || pg_catalog.array_agg(DISTINCT m.nk),
           pg_catalog.array_agg(DISTINCT m.ok) FILTER (WHERE m.nv <> 'public')
      INTO changed_keys, left_keys
      FROM (SELECT CASE WHEN p.visibility::text = 'public'
                        THEN '00000000-0000-0000-0000-000000000000'::uuid
                        ELSE p.owner_group_id END AS ok,
                   CASE WHEN ch.visibility::text = 'public'
                        THEN '00000000-0000-0000-0000-000000000000'::uuid
                        ELSE ch.owner_group_id END AS nk,
                   ch.visibility::text AS nv
              FROM changed ch JOIN prev p ON p.id = ch.id) m
     WHERE m.ok IS DISTINCT FROM m.nk;
    -- The firing gate: no claim's signature changed, nothing to do.
    IF changed_keys IS NULL THEN RETURN NULL; END IF;
    PERFORM public.epigraph_atlas_map_bump(changed_keys,
                                           COALESCE(left_keys, '{}'::uuid[]));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_map_stale() FROM PUBLIC;

CREATE TRIGGER claims_atlas_map_stale AFTER UPDATE
    ON public.claims REFERENCING OLD TABLE AS prev NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_atlas_map_stale();

-- edges and evidence: per row, queued only by the WHEN below. Only edges
-- carry a co-owner.
CREATE OR REPLACE FUNCTION public.epigraph_atlas_map_stale_row()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    old_co   uuid;
    new_co   uuid;
    old_keys uuid[];
    new_keys uuid[];
BEGIN
    IF TG_TABLE_NAME = 'edges' THEN
        old_co := OLD.co_owner_group_id;
        new_co := NEW.co_owner_group_id;
    END IF;
    old_keys := CASE WHEN OLD.visibility::text = 'public'
                     THEN ARRAY['00000000-0000-0000-0000-000000000000'::uuid]
                     ELSE ARRAY[OLD.owner_group_id, old_co] END;
    new_keys := CASE WHEN NEW.visibility::text = 'public'
                     THEN ARRAY['00000000-0000-0000-0000-000000000000'::uuid]
                     ELSE ARRAY[NEW.owner_group_id, new_co] END;
    PERFORM public.epigraph_atlas_map_bump(
        old_keys || new_keys,
        CASE WHEN NEW.visibility::text = 'public' THEN '{}'::uuid[] ELSE old_keys END);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_atlas_map_stale_row() FROM PUBLIC;

-- The WHENs compare whole signatures; an owner change of a public row is none.
CREATE TRIGGER edges_atlas_map_stale AFTER UPDATE ON public.edges
    FOR EACH ROW
    WHEN ((OLD.visibility::text,
           CASE WHEN OLD.visibility::text = 'public' THEN NULL ELSE OLD.owner_group_id END,
           CASE WHEN OLD.visibility::text = 'public' THEN NULL ELSE OLD.co_owner_group_id END)
          IS DISTINCT FROM
          (NEW.visibility::text,
           CASE WHEN NEW.visibility::text = 'public' THEN NULL ELSE NEW.owner_group_id END,
           CASE WHEN NEW.visibility::text = 'public' THEN NULL ELSE NEW.co_owner_group_id END))
    EXECUTE FUNCTION public.epigraph_atlas_map_stale_row();
CREATE TRIGGER evidence_atlas_map_stale AFTER UPDATE ON public.evidence
    FOR EACH ROW
    WHEN ((OLD.visibility::text,
           CASE WHEN OLD.visibility::text = 'public' THEN NULL ELSE OLD.owner_group_id END)
          IS DISTINCT FROM
          (NEW.visibility::text,
           CASE WHEN NEW.visibility::text = 'public' THEN NULL ELSE NEW.owner_group_id END))
    EXECUTE FUNCTION public.epigraph_atlas_map_stale_row();

-- ===================================================================
-- 5. Comments
-- ===================================================================
COMMENT ON TABLE public.atlas_map_epochs IS
    'Migration 210 (Atlas W2): the staleness counters of one Atlas map, bumped at most once '
    'per transaction by the *_atlas_map_stale triggers on claims, edges and evidence: n when '
    'a row enters or leaves the map''s half of the readable set, left_n when one leaves it '
    'for somewhere not public. (world, public) is the public map.';
COMMENT ON TABLE public.atlas_map_runs IS
    'Migration 210 (Atlas W2): one nightly build of one Atlas map; served only once '
    'finished_at is set; current only while map_epoch and public_epoch still equal '
    'atlas_map_epochs.n, and holding no departed row while map_left_epoch and '
    'public_left_epoch still equal atlas_map_epochs.left_n.';
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
        EXECUTE 'ALTER FUNCTION public.epigraph_atlas_map_bump(uuid[], uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_atlas_map_stale() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_atlas_map_stale_row() '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; '
                     'the epigraph_atlas_map_* functions stay owned by the migration runner.';
    END IF;
END $$;
