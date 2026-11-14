-- 218: a harvester fragment cited by several claims takes the MOST RESTRICTIVE
-- of them; the application role loses UPDATE on harvester_claim_provenance.
-- (backlog 73ea4d4d, 77fbf3f9, 0bf301fd)
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `harvester_fragments` has no `claim_id`. It reaches its claims through
-- `harvester_claim_provenance (claim_id, fragment_id)`, and one fragment may be
-- cited by several claims. Three writers copy a citing claim's
-- `(owner_group_id, visibility)` onto the fragment, and each picked a citing
-- claim ARBITRARILY when there were several:
--
--   * 089/115's `epigraph_inherit_fragment_tenancy_stmt()` (AFTER INSERT on
--     provenance): `UPDATE harvester_fragments f ... FROM newprov n JOIN
--     claims c`. With two provenance rows for one fragment in one statement,
--     `UPDATE ... FROM` applies ONE of the joined rows, chosen by plan order.
--   * `epigraph-tenancy-backfill`'s `backfill_harvester_fragments`: the same
--     `UPDATE ... FROM` shape over the whole provenance table.
--   * 168's `epigraph_propagate_tenancy()` (arm (d), AFTER UPDATE on claims):
--     a fragment of a claim whose tenancy changed takes THAT claim's tuple,
--     whatever its other citers are. So publicizing claim A made a fragment
--     public although group-private claim B also cites it: B's source text
--     became world-readable. And moving A to another group moved a fragment B
--     (still in the old group) cites away from B's group.
--
-- The operator decided the rule on 2026-09-22 (finding F-089-A in
-- docs/tenancy/progress.json): MOST RESTRICTIVE WINS.
--
-- ===================================================================
-- 1. THE RULE, ONE ORDER IN THREE PLACES
-- ===================================================================
--
-- Among a fragment's citing claims, the winner is the first by:
--
--   1. `visibility = 'group'` before `'public'` (the restrictive direction;
--      062's CHECKs make these the only two values);
--   2. arm (d) only: a claim of THIS statement's `changed` set before one it
--      did not change. At equal visibility the act that moved the claim keeps
--      168's meaning: a share, a re-own or a regroup still carries the
--      fragment with the claim (the operator tools' `reown-claims`,
--      `regroup-claims` and `restrict-claims` model the cascade that way);
--   3. a real owner before a sentinel (world `...0000`, seed `...dead`): a
--      sentinel owns nothing (062's `*_group_needs_real_group`), so it never
--      beats a real group at equal visibility;
--   4. arm (d) only: the fragment's CURRENT owner before another group (two
--      groups are incomparable, so a fragment no changed claim decides stays
--      with a citer's group it already has rather than moving on a uuid);
--   5. `owner_group_id ASC`: a deterministic tie-break, so the result does not
--      depend on plan or insert order.
--
-- Keys 2 and 4 are left out of the provenance trigger and the backfill: there
-- is no `changed` set, and the target is always a sentinel, so a current-owner
-- key would decide nothing.
--
-- The rank is over EVERY citing claim in `harvester_claim_provenance`, not
-- only the rows of the statement that fired: at AFTER STATEMENT time the
-- table already holds them.
--
-- WHERE EACH WRITER MAY MOVE A FRAGMENT IS UNCHANGED:
--
--   * the provenance trigger and the backfill still stamp ONLY a
--     sentinel-owned fragment (089's target predicate), and still exclude a
--     world-owned citing claim (089's source predicate), and the trigger still
--     runs only for an `epigraph_bypass()` session (115 section 9);
--   * arm (d) still re-stamps every fragment of a changed claim (a claim's own
--     tenancy change is authoritative), now to the winner over all its citers.
--     The result differs from 168's only where another citer is MORE
--     restrictive than the changed claim's new tuple (a publicize, or a claim
--     moved to a sentinel), or where several changed claims disagree.
--
-- WHAT IS NOT DONE HERE, AND WHY. A fragment ALREADY owned by a real group
-- with `visibility = 'public'` is not narrowed when a group-private claim later
-- cites it, by the trigger or by the backfill. Doing so would contradict the
-- operator tools' node rule: `restrict-claims` and `regroup-claims`
-- (`crates/epigraph-cli/src/operator/restrict.rs`, "Nodes stay"; `regroup.rs`
-- `fragment_moves`) deliberately leave a shared fragment on its tuple unless
-- EVERY claim citing it ends in the target, and a backfill that narrowed it
-- would undo an audited, census-checked run. Which rule governs that shape is
-- an operator question, recorded on F-089-A and F-089-C in
-- docs/tenancy/progress.json. Arm (d) does not collide with the node rule:
-- when the moved claim's new tuple is `group`, key 2 below makes it win, so arm
-- (d) writes exactly the tuple 168 wrote, and the tools still put a kept node
-- back afterwards.
--
-- ===================================================================
-- 2. THE TRUST MODEL OF THE STAMP (backlog 0bf301fd, finding F-089-F)
-- ===================================================================
--
-- The stamp copies tenancy from a claim the WRITER of the provenance row
-- names, and nothing constrains which claims it may name. The operator
-- ACCEPTED that on 2026-09-22: the harvester ingest path is TRUSTED to name
-- any citing claim. Since 115 the stamp runs only for a privileged session
-- (`epigraph_bypass()`), so the writer that can name a claim to it is the
-- harvester on a maintenance or superuser DSN, nothing else. The consequence
-- is an INTEGRITY and AVAILABILITY one (a wrong citation can make a fragment
-- private to the wrong group, or hide it from a public claim's readers), not a
-- DISCLOSURE one: a sentinel-owned fragment is necessarily public (062), and
-- a stamp moves it only public->public or public->group, so it never becomes
-- MORE readable. docs/tenancy.md states the same.
--
-- ===================================================================
-- 3. NO UPDATE ON harvester_claim_provenance FOR epigraph_app (77fbf3f9)
-- ===================================================================
--
-- 089's stamp is AFTER INSERT only, so an UPDATE that re-points an existing
-- provenance row's `fragment_id` or `claim_id` stamps nothing (finding
-- F-089-E), and `epigraph_app` held UPDATE on the table (077's grant on all
-- tables; 118's revocations do not name it). No writer in this tree updates
-- this table: its only Rust references are reads, and arm (d) re-stamps the
-- rows' own tenancy as a maintenance-owned definer, under
-- `epigraph_maintenance`'s own UPDATE (070). The external harvester that
-- writes it is outside this tree; the README's deploy note asks the operator
-- to confirm it only INSERTs on an application DSN.
-- So the application role loses UPDATE outright, which closes the path
-- without a second trigger and moves none of the four pinned trigger counts.
-- A table-level REVOKE also removes any column-level UPDATE grant. INSERT,
-- SELECT and DELETE are kept (the harvest path and 115's owner-scoped DELETE
-- use them). `epigraph_maintenance` keeps UPDATE; it is not a writer that
-- re-points a link either, and the operator tools that run on it only
-- re-stamp the rows' tenancy.
--
-- ===================================================================
-- 4. WHAT IT DOES NOT DO
-- ===================================================================
--
-- It moves no existing row, and NO TOOL RE-STAMPS a fragment the old rule
-- already gave a real owner: such a row is no longer sentinel-owned, so
-- neither this stamp nor `epigraph-tenancy-backfill run --entity
-- harvester-fragments` (sentinel-owned rows only) reaches it. It changes only
-- when one of its claims moves (arm (d)). The one shape that matters is a
-- `public` fragment owned by a real group with a group-private citer, and it
-- is ONGOING, not only historical: a group-private link inserted in a later
-- statement than the first public one still leaves the fragment public,
-- because the stamp's target is sentinel-only. Whether to narrow that shape
-- waits on the node-rule question in section 1. Counting it on a deployed
-- database is operator work.
--
-- `CREATE OR REPLACE` of both bodies (same signatures) keeps their owner and
-- ACL; part D below re-asserts the owner anyway, as 089, 114, 122 and 168 do.
-- Undo: docs/runbooks/218-undo.sql (restores 115's and 168's bodies byte for
-- byte and re-grants UPDATE to `epigraph_app`; it RE-OPENS both defects).
-- Idempotent: a re-run of this file changes nothing.
-- ===================================================================
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- A. THE PROVENANCE STAMP: 115's body, the winner over every citer
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    -- `session_user`, not `current_user`: inside this definer the latter is
    -- the maintenance owner. Only a session that could itself write a
    -- sentinel-owned fragment stamps one (115 section 9).
    IF NOT public.epigraph_bypass() THEN
        RETURN NULL;
    END IF;
    -- 218: the MOST RESTRICTIVE citing claim wins (group before public, a
    -- real owner before the seed sentinel, then the lowest owner id), ranked
    -- over every provenance row of the fragment, not only this statement's.
    -- The ingest path is trusted to name any citing claim (finding F-089-F,
    -- accepted): a stamp only ever moves a sentinel-owned, hence public,
    -- fragment to public or group, never to something more readable.
    UPDATE public.harvester_fragments f
       SET owner_group_id = w.owner_group_id,
           visibility     = w.visibility
      FROM (SELECT DISTINCT ON (p.fragment_id)
                   p.fragment_id, c.owner_group_id, c.visibility
              FROM public.harvester_claim_provenance p
              JOIN public.claims c ON c.id = p.claim_id
             WHERE p.fragment_id IN (SELECT n.fragment_id FROM newprov n)
               AND c.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
             ORDER BY p.fragment_id,
                      (c.visibility = 'group') DESC,
                      (c.owner_group_id = '00000000-0000-0000-0000-00000000dead'::uuid) ASC,
                      c.owner_group_id ASC) w
     WHERE f.id = w.fragment_id
       AND f.owner_group_id IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid)
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (w.owner_group_id, w.visibility);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() FROM PUBLIC;

-- ===================================================================
-- B. ARM (d): epigraph_propagate_tenancy (168's body; only the
--     harvester_fragments statement changes)
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
    -- 218: a fragment of a changed claim takes the MOST RESTRICTIVE of ALL
    -- its citing claims as they stand after this statement: group before
    -- public. At equal visibility the changed claim decides, as in 168 (a
    -- share, re-own or regroup still carries the fragment with the claim);
    -- then a real owner before a sentinel, the fragment's current owner, and
    -- the lowest owner id. Publicizing one citer no longer makes a fragment
    -- public while another citer is group-private.
    UPDATE public.harvester_fragments f
       SET owner_group_id = w.owner_group_id, visibility = w.visibility
      FROM (SELECT DISTINCT ON (p.fragment_id)
                   p.fragment_id, c.owner_group_id, c.visibility
              FROM public.harvester_claim_provenance p
              JOIN public.claims c ON c.id = p.claim_id
              JOIN public.harvester_fragments f0 ON f0.id = p.fragment_id
             WHERE p.fragment_id IN (SELECT p0.fragment_id
                                       FROM public.harvester_claim_provenance p0
                                       JOIN changed ch ON ch.id = p0.claim_id)
             ORDER BY p.fragment_id,
                      (c.visibility = 'group') DESC,
                      (c.id IN (SELECT ch2.id FROM changed ch2)) DESC,
                      (c.owner_group_id IN (
                         '00000000-0000-0000-0000-000000000000'::uuid,
                         '00000000-0000-0000-0000-00000000dead'::uuid)) ASC,
                      (c.owner_group_id = f0.owner_group_id) DESC,
                      c.owner_group_id ASC) w
     WHERE f.id = w.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (w.owner_group_id, w.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
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
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility,
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
-- C. NO UPDATE ON harvester_claim_provenance FOR THE APPLICATION ROLE
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE ON public.harvester_claim_provenance FROM epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- D. OWNERSHIP (CREATE OR REPLACE keeps it; re-set regardless, guarded on
--    the role as 089 and 168 guard it)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;
