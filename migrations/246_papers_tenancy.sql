-- 246: a `papers` row carries the tenancy of the ingest that wrote it
-- (backlog 34864fb5, parts 1, 4, 5, 8 and 9 for papers; the design is option 2
-- of docs/tenancy/papers-tenancy-followup.md).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `papers` (001) had no owner group and no row security. A `team` or
-- `private` document ingest scoped the CLAIMS it created, but its `papers`
-- row (document key, title, journal) was readable by every session, and
-- `epigraph_node_tenancy` counted a paper endpoint as ('public', world), so
-- the `authored` edges onto it, its `processed_by` stamp and its `asserts`
-- edges onto already-public claims were world-readable too. Anyone could
-- learn that a confidential document existed, what it was called, who wrote
-- it and which agent ingested it (`check_already_ingested`, `query_paper`,
-- `GET /api/v1/papers`, `get_neighborhood` from an author agent).
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `owner_group_id uuid` and `visibility varchar(16)`, 183's tier-A shape
--      (the same CHECK, FK and group-needs-real-group constraints), NOT NULL
--      with NO default (074: tenancy is declared, never defaulted), and
--      074's `epigraph_root_require_tenancy()` as `papers_require_tenancy`.
--   2. The backfill: every existing row becomes ('public', world), which is
--      what every reader saw before this file. Nothing becomes private.
--   3. ONE ROW PER DOCUMENT PER SCOPE. The two unique constraints on `doi`
--      (001's `papers_doi_key` and `papers_doi_unique`) are replaced by one
--      unique index on (doi, scope), where the scope of a PUBLIC row is the
--      world group whoever owns it and the scope of a GROUP row is its owner
--      group. So every public ingest of a document still converges on one
--      public row (how two sources corroborate; a public ingest behaves as
--      before), while two teams' private ingests of one document get one row
--      each, and neither can see, or collide with, the other's.
--   4. Tenancy is immutable to an ordinary session: 115's
--      `epigraph_owner_immutable_guard` on `owner_group_id` and the same rule
--      for `visibility` (`epigraph_papers_visibility_guard`). Widening a
--      private paper (publicize / share, with dedup against the target scope)
--      is a follow-up; until then only a maintenance session re-tenants a row.
--   5. Row security, ENABLEd and FORCEd, in 183's shape: READ public or a
--      group in the read set; INSERT a group the session writes; UPDATE a
--      readable row into a readable row (the fill-only title/journal upsert);
--      no application DELETE (plus 115's restrictive owner-writer rule); and
--      126-style elevated write refusals.
--   6. `epigraph_node_tenancy` gains a `paper` arm, so `authored`,
--      `processed_by` and `asserts` edges take the meet with a paper's own
--      row instead of ('public', world): a group paper's edges are group
--      edges. `epigraph_propagate_tenancy` meets a paper endpoint with its own
--      row too (as 219 did for workflows), so re-tenanting a claim never
--      re-meets a group paper's `asserts` edge as if the paper were public.
--
-- No edge is re-met here: every paper is public after the backfill, which is
-- what the oracle answered for it before, so no stored edge's meet changes.
--
-- NOT changed (follow-ups of 34864fb5): author agents stay public identity
-- rows (an author's NAME stays readable; only the `authored` edge onto a
-- group paper is scoped); widening a paper on publicize/share and merging it
-- into the target scope's row; the narrowing guard; the `doi:` label a
-- non-public ingest adds to a converged public claim.
--
-- ===================================================================
-- 2. DEPLOY AND UNDO
-- ===================================================================
--
-- Apply as the maintenance role or a superuser. DEPLOY ORDER: migrate and
-- roll out the 246 binary TOGETHER. A pre-246 binary on a 246 database writes
-- `papers` without declaring its tenancy, which `papers_require_tenancy`
-- refuses (23502): its document ingest and `POST /api/v1/papers` fail until
-- the new binary is out. A 246 binary on a pre-246 database names columns
-- that do not exist yet.
--
-- Undo (roll every 246 binary back first): `docs/runbooks/246-undo.sql`. It
-- refuses, changing nothing, while any paper is group-private (a pre-246
-- schema has nowhere to keep that and would publish it) or while one document
-- key has more than one row (001's `UNIQUE (doi)` cannot be restored over
-- them), and unless both re-stated functions still hold 246's bodies.
--
-- Re-stating a shared body: 219 re-stated `epigraph_node_tenancy` and
-- `epigraph_propagate_tenancy` last. The GUARD below refuses to apply unless
-- both still hold 219's bodies (md5 of `prosrc`), so a re-statement that
-- landed before this file fails loudly instead of being silently reverted.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- GUARD: re-state only the bodies this file was written against (219's)
-- ===================================================================
DO $$
DECLARE v_node text; v_prop text;
BEGIN
    SELECT md5(p.prosrc) INTO v_node FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure;
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_propagate_tenancy()'::regprocedure;
    IF v_node IS DISTINCT FROM 'd08bf867256ced915ba54f65cf620de7'
       OR v_prop IS DISTINCT FROM 'd48f242f2756ae9679d97d111dfda925' THEN
        RAISE EXCEPTION '246: epigraph_node_tenancy (prosrc md5 %) or epigraph_propagate_tenancy '
                        '(prosrc md5 %) is not the body 246 builds on (219''s). A migration '
                        'before 246 re-stated it; re-stating it here would revert that change. '
                        'Re-state the MERGED body in the later migration',
                        v_node, v_prop
              USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 1. Columns (nullable until the backfill has filled them)
-- ===================================================================
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT column_name, data_type
               FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'papers'
                AND column_name IN ('owner_group_id', 'visibility')
    LOOP
        RAISE EXCEPTION
            'public.papers.% already exists (data_type=%). Reconcile by hand, then re-run.',
            r.column_name, r.data_type;
    END LOOP;
END $$;

ALTER TABLE public.papers
    ADD COLUMN owner_group_id uuid,
    ADD COLUMN visibility character varying(16);

-- ===================================================================
-- 2. Backfill: what every reader saw before this file
-- ===================================================================
UPDATE public.papers
   SET visibility = 'public',
       owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid;

ALTER TABLE public.papers
    ALTER COLUMN owner_group_id SET NOT NULL,
    ALTER COLUMN visibility SET NOT NULL;

ALTER TABLE public.papers
    ADD CONSTRAINT papers_visibility_check
        CHECK (visibility IN ('public', 'group')),
    ADD CONSTRAINT papers_owner_group_fkey
        FOREIGN KEY (owner_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT,
    ADD CONSTRAINT papers_group_needs_real_group CHECK (
        visibility <> 'group'
        OR owner_group_id NOT IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid));

CREATE INDEX papers_group_owner_idx
    ON public.papers (owner_group_id) WHERE visibility = 'group';

-- ===================================================================
-- 3. One row per document per scope
-- ===================================================================
-- The writers' `ON CONFLICT` names this exact expression
-- (`PaperRepository::get_or_create`); keep the two in step.
ALTER TABLE public.papers DROP CONSTRAINT IF EXISTS papers_doi_key;
ALTER TABLE public.papers DROP CONSTRAINT IF EXISTS papers_doi_unique;
CREATE UNIQUE INDEX papers_document_key_scope_key ON public.papers (
    doi,
    (CASE WHEN visibility = 'public'
          THEN '00000000-0000-0000-0000-000000000000'::uuid
          ELSE owner_group_id END));
-- The lookup by key alone (`WHERE doi = ANY(...)`) keeps an index.
CREATE INDEX papers_doi_idx ON public.papers (doi);

-- ===================================================================
-- 4. Declared, never defaulted; immutable to an ordinary session
-- ===================================================================
DROP TRIGGER IF EXISTS papers_require_tenancy ON public.papers;
CREATE TRIGGER papers_require_tenancy BEFORE INSERT ON public.papers
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_root_require_tenancy();

DROP TRIGGER IF EXISTS papers_owner_immutable ON public.papers;
CREATE TRIGGER papers_owner_immutable BEFORE UPDATE OF owner_group_id ON public.papers
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id)
    EXECUTE FUNCTION public.epigraph_owner_immutable_guard();

CREATE OR REPLACE FUNCTION public.epigraph_papers_visibility_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: an UPDATE of papers changes visibility; '
                    'only a maintenance session re-tenants a paper row'
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_papers_visibility_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS papers_visibility_immutable ON public.papers;
CREATE TRIGGER papers_visibility_immutable BEFORE UPDATE OF visibility ON public.papers
    FOR EACH ROW
    WHEN (OLD.visibility IS DISTINCT FROM NEW.visibility)
    EXECUTE FUNCTION public.epigraph_papers_visibility_guard();

-- ===================================================================
-- 5. Row security
-- ===================================================================
ALTER TABLE public.papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.papers FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS papers_read ON public.papers;
CREATE POLICY papers_read ON public.papers FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

DROP POLICY IF EXISTS papers_insert ON public.papers;
CREATE POLICY papers_insert ON public.papers FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

DROP POLICY IF EXISTS papers_update ON public.papers;
CREATE POLICY papers_update ON public.papers FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]));

DROP POLICY IF EXISTS papers_delete_owner ON public.papers;
CREATE POLICY papers_delete_owner ON public.papers AS RESTRICTIVE FOR DELETE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- Elevated sessions (126's census): write refusal, no read arm, as 183.
DROP POLICY IF EXISTS papers_elevated_no_insert ON public.papers;
CREATE POLICY papers_elevated_no_insert ON public.papers
    AS RESTRICTIVE FOR INSERT TO epigraph_app
    WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS papers_elevated_no_update ON public.papers;
CREATE POLICY papers_elevated_no_update ON public.papers
    AS RESTRICTIVE FOR UPDATE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));
DROP POLICY IF EXISTS papers_elevated_no_delete ON public.papers;
CREATE POLICY papers_elevated_no_delete ON public.papers
    AS RESTRICTIVE FOR DELETE TO epigraph_app
    USING (NOT (SELECT public.epigraph_is_elevated()));

-- ===================================================================
-- 6. THE ORACLE: 219's body plus the paper arm
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_node_tenancy(p_id uuid, p_type text)
RETURNS TABLE (g uuid, v character varying(16))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_type = 'claim' THEN
        RETURN QUERY SELECT c.owner_group_id, c.visibility FROM public.claims c WHERE c.id = p_id;
    ELSIF p_type = 'evidence' THEN
        RETURN QUERY SELECT e.owner_group_id, e.visibility FROM public.evidence e WHERE e.id = p_id;
    ELSIF p_type = 'workflow' THEN
        -- 219: a plan's row carries its tenancy since 183.
        RETURN QUERY SELECT w.owner_group_id, w.visibility FROM public.workflows w WHERE w.id = p_id;
    ELSIF p_type = 'paper' THEN
        -- 246: a paper's row carries its ingest's tenancy.
        RETURN QUERY SELECT p.owner_group_id, p.visibility FROM public.papers p WHERE p.id = p_id;
    END IF;
    -- An edge pointing at a frame/agent/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

-- ===================================================================
-- 7. ARM (d): 219's epigraph_propagate_tenancy plus the paper joins
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint; pin_skip text;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
        writer_tables text[] := ARRAY['evidence','mass_functions','reasoning_traces'];
BEGIN
    -- The firing gate. MUST stay ahead of the assertion below.
    IF NOT EXISTS (
        SELECT 1 FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.owner_group_id, ch.visibility)
               IS DISTINCT FROM (p.owner_group_id, p.visibility))
    THEN RETURN NULL; END IF;

    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: propagation requires a maintenance-role '
                        'owner; refusing to run RLS-filtered' USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY derived LOOP
        -- 110: a PINNED evidence row is left to the statement after the loop.
        -- (An IF, not a conditional expression: `tenancy_triggers.rs` counts
        -- this body's conditional expressions to pin the edges meet at three.)
        IF t = 'evidence' THEN
            pin_skip := ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
                        ' WHERE vp.evidence_id = d.id)';
        ELSE
            pin_skip := '';
        END IF;
        -- 114: a WRITER-OWNED row is left to the statement after the loop.
        IF t = ANY (writer_tables) THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        -- 168 (R-CH1): an OUTSIDER's challenge is the challenger's, and it
        -- never follows the claim, so it is not in `writer_tables` and the
        -- narrowing statement after the loop does not re-own it either.
        IF t = 'challenges' THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip;
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- 110: PINNED evidence. Never widened, owner never changed.
    SELECT count(*) INTO expected
      FROM public.evidence d
      JOIN changed ch ON ch.id = d.claim_id
      JOIN public.evidence_visibility_pins vp ON vp.evidence_id = d.id
     WHERE d.visibility IS DISTINCT FROM 'group'::character varying(16);
    IF expected > 0 THEN
        UPDATE public.evidence d
           SET visibility = 'group'::character varying(16)
          FROM changed ch, public.evidence_visibility_pins vp
         WHERE ch.id = d.claim_id
           AND vp.evidence_id = d.id
           AND d.visibility IS DISTINCT FROM 'group'::character varying(16);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to pinned evidence updated % '
                            'of % rows (RLS filtered?)', actual, expected;
        END IF;
    END IF;
    -- 114: WRITER-OWNED rows. While the claim stays public they are left
    -- alone: their owner is the writer's whoever the claim moves to, and their
    -- visibility is already the claim's (or narrower, for pinned evidence).
    -- When the claim NARROWS to non-public they become the claim's: owner and
    -- visibility follow the claim and the flag is cleared (review finding W5).
    -- Keeping the writer as owner there would leave rows about a private claim
    -- readable by the writer's group and hidden from the claim's own owner,
    -- which is sequestering evidence from the one party who now holds the
    -- claim; privatization's seal already encrypts every evidence row of the
    -- claim with the claim group's key, the writer's included. Pinned evidence
    -- is re-owned too (its visibility is 'group' either way, set above).
    -- Issued only when a count finds a row to change.
    FOREACH t IN ARRAY writer_tables LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE d.writer_owned
               AND ch.visibility IS DISTINCT FROM ''public''', t)
          INTO expected;
        IF expected > 0 THEN
            EXECUTE format(
              'UPDATE %I d SET owner_group_id = ch.owner_group_id,
                               visibility     = ch.visibility,
                               writer_owned   = false
                 FROM changed ch
                WHERE ch.id = d.claim_id
                  AND d.writer_owned
                  AND ch.visibility IS DISTINCT FROM ''public''', t);
            GET DIAGNOSTICS actual = ROW_COUNT;
            IF actual <> expected THEN
                RAISE EXCEPTION 'epigraph tenancy: propagation to writer-owned % updated % '
                                'of % rows (RLS filtered?)', t, actual, expected;
            END IF;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    -- 218: a fragment of a changed claim takes the MOST RESTRICTIVE of the
    -- CHANGED claims that cite it (group before public, a real owner before a
    -- sentinel, then the lowest owner id); it never moves to a claim this
    -- statement did not change. When that winner is public, a group fragment
    -- that another group-private claim still cites is left as it is (owner
    -- and visibility): publicizing one citer no longer makes the fragment
    -- public, and does not hand it to the other citer's group either.
    UPDATE public.harvester_fragments f
       SET owner_group_id = w.owner_group_id, visibility = w.visibility
      FROM (SELECT DISTINCT ON (p.fragment_id)
                   p.fragment_id, ch.owner_group_id, ch.visibility
              FROM public.harvester_claim_provenance p
              JOIN changed ch ON ch.id = p.claim_id
             ORDER BY p.fragment_id,
                      (ch.visibility = 'group') DESC,
                      (ch.owner_group_id IN (
                         '00000000-0000-0000-0000-000000000000'::uuid,
                         '00000000-0000-0000-0000-00000000dead'::uuid)) ASC,
                      ch.owner_group_id ASC) w
     WHERE f.id = w.fragment_id
       AND NOT (w.visibility = 'public'
                AND f.visibility = 'group'
                AND EXISTS (SELECT 1
                              FROM public.harvester_claim_provenance p2
                              JOIN public.claims c2 ON c2.id = p2.claim_id
                             WHERE p2.fragment_id = f.id
                               AND c2.visibility = 'group'))
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (w.owner_group_id, w.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
    -- 219: a `workflow` endpoint is met with its OWN row (183's columns), as
    -- `epigraph_node_tenancy` now meets it.
    -- 246: so is a `paper` endpoint (246's columns).
    UPDATE public.edges e
       SET owner_group_id    = m.g,
           visibility        = m.v,
           co_owner_group_id = m.co
      FROM (
        SELECT DISTINCT e2.id,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN s.v = 'public' THEN t.g
                    WHEN t.v = 'public' THEN s.g
                    ELSE s.g END AS g,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN 'public'::character varying(16)
                    ELSE 'group'::character varying(16) END AS v,
               CASE WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g
                         THEN t.g
                    ELSE NULL END AS co
          FROM (SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.source_id = ch.id AND x.source_type = 'claim'
                UNION
                SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.target_id = ch.id AND x.target_type = 'claim') e2
          LEFT JOIN public.claims   sc ON e2.source_type = 'claim'    AND sc.id = e2.source_id
          LEFT JOIN public.evidence se ON e2.source_type = 'evidence' AND se.id = e2.source_id
          LEFT JOIN public.workflows sw ON e2.source_type = 'workflow' AND sw.id = e2.source_id
          LEFT JOIN public.papers    sp ON e2.source_type = 'paper'    AND sp.id = e2.source_id
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          LEFT JOIN public.workflows tw ON e2.target_type = 'workflow' AND tw.id = e2.target_id
          LEFT JOIN public.papers    tp ON e2.target_type = 'paper'    AND tp.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id, sw.owner_group_id, sp.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility, sw.visibility, sp.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id, tw.owner_group_id, tp.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility, tw.visibility, tp.visibility,
                            'public'::character varying(16)) AS v) t
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND m.v = 'group'
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;

-- ===================================================================
-- 8. OWNERSHIP (CREATE OR REPLACE keeps it; re-set regardless, as 219 does)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;
