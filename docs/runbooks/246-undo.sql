-- ===================================================================
-- 246-undo.sql: take migration 246 (a `papers` row carries the tenancy of the
-- ingest that wrote it) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- READ FIRST: ROLL THE BINARIES BACK BEFORE THIS RUNS. A 246 binary writes
-- `papers.visibility` and `papers.owner_group_id` and names 246's unique index
-- in its `ON CONFLICT`; after this undo every document ingest and
-- `POST /api/v1/papers` it serves fails (42703 / 42P10).
--
-- WHAT IT DOES:
--   * REFUSES, changing nothing, unless both re-stated functions hold 246's
--     bodies (or already hold 219's, a second run): a later migration that
--     re-stated either one would otherwise be reverted. Undo that one first.
--   * REFUSES, changing nothing, while any paper is group-private: a pre-246
--     schema has nowhere to keep that, and dropping the columns would publish
--     the row to every reader. Re-tenant or delete those rows first, as a
--     maintenance act of its own.
--   * REFUSES, changing nothing, while one document key has more than one row
--     (a public row beside a group's copy, or two groups' copies): 001's
--     `UNIQUE (doi)` cannot be restored over them. Merging them is a
--     maintenance act of its own (re-point their edges first).
--   * re-states 219's `epigraph_node_tenancy(uuid, text)` and
--     `epigraph_propagate_tenancy()` byte for byte (`CREATE OR REPLACE` keeps
--     their owner and ACL; never DROP them);
--   * drops 246's policies, triggers, guard function, indexes, constraints and
--     columns, puts back 001's two `UNIQUE (doi)` constraints, and turns row
--     security on `papers` off again.
--
-- WHAT IT LEAVES: 246's `_sqlx_migrations` row, and every edge as it stands
-- (all of them public while every paper is, which the refusals above ensure).
-- Re-introducing any of it is a NEW migration, never a re-run of 246.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- The session must read every paper (row security is FORCEd on it).
DO $$
BEGIN
    IF NOT (public.epigraph_bypass()
            OR COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
                          WHERE rolname = current_user), false)) THEN
        RAISE EXCEPTION '246-undo: run as the maintenance role or a superuser; the refusals '
                        'below must see every group''s papers'
              USING ERRCODE = '42501';
    END IF;
END $$;

-- The body guard: md5(prosrc) of 246's bodies, or of 219's (already undone).
DO $$
DECLARE v_node text; v_prop text;
BEGIN
    SELECT md5(p.prosrc) INTO v_node FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure;
    SELECT md5(p.prosrc) INTO v_prop FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_propagate_tenancy()'::regprocedure;
    IF (v_node, v_prop) IS DISTINCT FROM ('25a0585c8da9141741a55e2f2f72259c',
                                          '4882fdda50140fc2ae0968de3526bcb5')
       AND (v_node, v_prop) IS DISTINCT FROM ('d08bf867256ced915ba54f65cf620de7',
                                              'd48f242f2756ae9679d97d111dfda925') THEN
        RAISE EXCEPTION '246-undo: epigraph_node_tenancy (prosrc md5 %) or '
                        'epigraph_propagate_tenancy (prosrc md5 %) is neither 246''s body nor '
                        '219''s: a later migration re-stated it. Undo that migration first; '
                        'nothing was changed', v_node, v_prop
              USING ERRCODE = '55000';
    END IF;
END $$;

-- The data guards (only while 246's columns exist; a second run skips them).
DO $$
DECLARE n_group bigint; n_dup bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'papers'
                  AND column_name = 'visibility') THEN
        EXECUTE 'SELECT count(*) FROM public.papers WHERE visibility = ''group'''
           INTO n_group;
        IF n_group > 0 THEN
            RAISE EXCEPTION '246-undo: % group-private paper row(s); a pre-246 schema would '
                            'publish them. Nothing was changed', n_group
                  USING ERRCODE = '55000';
        END IF;
    END IF;
    SELECT count(*) INTO n_dup
      FROM (SELECT doi FROM public.papers GROUP BY doi HAVING count(*) > 1) d;
    IF n_dup > 0 THEN
        RAISE EXCEPTION '246-undo: % document key(s) hold more than one paper row; 001''s '
                        'UNIQUE (doi) cannot be restored. Nothing was changed', n_dup
              USING ERRCODE = '55000';
    END IF;
END $$;

-- 219's oracle, byte for byte.
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
    END IF;
    -- An edge pointing at a frame/agent/paper/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

-- 219's propagation, byte for byte.
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
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          LEFT JOIN public.workflows tw ON e2.target_type = 'workflow' AND tw.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id, sw.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility, sw.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id, tw.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility, tw.visibility,
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

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_node_tenancy(uuid, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- Row security, policies, triggers, guard function.
DROP POLICY IF EXISTS papers_read ON public.papers;
DROP POLICY IF EXISTS papers_insert ON public.papers;
DROP POLICY IF EXISTS papers_update ON public.papers;
DROP POLICY IF EXISTS papers_delete_owner ON public.papers;
DROP POLICY IF EXISTS papers_elevated_no_insert ON public.papers;
DROP POLICY IF EXISTS papers_elevated_no_update ON public.papers;
DROP POLICY IF EXISTS papers_elevated_no_delete ON public.papers;
ALTER TABLE public.papers NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.papers DISABLE ROW LEVEL SECURITY;

DROP TRIGGER IF EXISTS papers_require_tenancy ON public.papers;
DROP TRIGGER IF EXISTS papers_owner_immutable ON public.papers;
DROP TRIGGER IF EXISTS papers_visibility_immutable ON public.papers;
DROP FUNCTION IF EXISTS public.epigraph_papers_visibility_guard();

-- Keys, indexes, constraints, columns.
DROP INDEX IF EXISTS public.papers_document_key_scope_key;
DROP INDEX IF EXISTS public.papers_doi_idx;
DROP INDEX IF EXISTS public.papers_group_owner_idx;
ALTER TABLE public.papers
    DROP CONSTRAINT IF EXISTS papers_visibility_check,
    DROP CONSTRAINT IF EXISTS papers_owner_group_fkey,
    DROP CONSTRAINT IF EXISTS papers_group_needs_real_group;
ALTER TABLE public.papers
    DROP COLUMN IF EXISTS owner_group_id,
    DROP COLUMN IF EXISTS visibility;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.papers'::regclass AND conname = 'papers_doi_key') THEN
        ALTER TABLE public.papers ADD CONSTRAINT papers_doi_key UNIQUE (doi);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.papers'::regclass AND conname = 'papers_doi_unique') THEN
        ALTER TABLE public.papers ADD CONSTRAINT papers_doi_unique UNIQUE (doi);
    END IF;
END $$;

COMMIT;
