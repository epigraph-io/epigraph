-- 110: evidence visibility pins — the kernel guard that keeps a HIDDEN
-- evidence row hidden (operator directive 2026-09-23, Amendment 2, B-H2).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `epigraph-operator hide-evidence` makes selected evidence rows
-- `visibility = 'group'`, owned by the operator's personal group, while their
-- claim stays as it is. Two trigger arms undo that on ordinary writes:
--
--   * 070 arm (c), `epigraph_inherit_tenancy_stmt`, fires AFTER every INSERT
--     into a claim-derived table and re-syncs EVERY row of that table for the
--     inserted rows' claims to the claim's (owner, visibility). The next
--     evidence INSERT for a public claim therefore re-publishes every hidden
--     evidence row of that claim.
--   * 072 arm (d), `epigraph_propagate_tenancy`, fires AFTER a claims UPDATE
--     whose (owner_group_id, visibility) changed and copies the claim's pair
--     onto every derived row. The next re-own or declassification of the claim
--     re-publishes them.
--
-- Measured (`epigraph-db/tests/evidence_visibility_pins.rs` with either body
-- below left at 072's / 070's text): both re-publish the hidden row, arm (c)
-- to `('public', world)` at the next evidence INSERT and arm (d) to
-- `(new owner, 'public')` at the next re-own. So a hide without this guard
-- does not hold, and `hide-evidence --apply` refuses on a schema that lacks it
-- (`epigraph_cli::operator::hide::guard_status` reads the catalog).
--
-- ===================================================================
-- 1. THE MECHANISM: A DEFINER-ONLY SIDE TABLE, NOT A COLUMN
-- ===================================================================
--
-- `evidence_visibility_pins(evidence_id PK -> evidence ON DELETE CASCADE)`.
-- A row here PINS that evidence row: propagation never widens it.
--
-- Why not a `visibility_pinned boolean` on `evidence`: `epigraph_app` holds a
-- TABLE-level UPDATE on `evidence` (077's blanket grant), and a column-level
-- REVOKE does not subtract from a table-level grant, so any app session that
-- may update an evidence row could clear its own pin. A separate table can be
-- made writable by the maintenance role alone:
--
--   * ENABLE + FORCE row security (so the table owner is bound too);
--   * SELECT admits `epigraph_bypass()` (a maintenance session) or
--     `epigraph_definer_bypass()` (the two trigger bodies below, which run as
--     their owner `epigraph_maintenance`);
--   * INSERT and DELETE admit `epigraph_bypass()` only — the operator CLI on a
--     maintenance DSN; NO UPDATE policy (a pin is written and removed, never
--     edited), so UPDATE default-denies under FORCE;
--   * REVOKE ALL from PUBLIC and from `epigraph_app` (077's ALTER DEFAULT
--     PRIVILEGES would otherwise have granted it full DML on creation); GRANT
--     SELECT back to `epigraph_app`, as 107 does for `operator_links`, so an app
--     statement that names the table reads nothing rather than raising 42501 —
--     the SELECT policy admits no app session;
--   * GRANT SELECT, INSERT, DELETE to `epigraph_maintenance`.
--
-- ===================================================================
-- 2. WHAT A PIN MEANS TO THE TWO ARMS
-- ===================================================================
--
-- Arm (d) `epigraph_propagate_tenancy`, on a claim owner/visibility change:
--
--   * UNPINNED rows: exactly 072's statements. The generic per-table loop is
--     unchanged for sixteen of the seventeen derived tables; for `evidence` the
--     SAME count and UPDATE carry one extra conjunct, `AND NOT EXISTS (pin)`,
--     so an unpinned evidence row is selected and written exactly as before.
--     The `derived text[] := ARRAY[...]` literal is byte-for-byte 072's:
--     `epigraph_cli::operator::tables::parse_derived_array` reads it.
--   * PINNED evidence rows: a separate statement sets `visibility = 'group'`
--     if anything had made it otherwise, and NEVER touches `owner_group_id`.
--     A pinned row keeps the owner the hide gave it (the operator's personal
--     group) whatever happens to its claim. It keeps 070's assertion shape:
--     the rows updated must equal the rows counted, or the statement raises
--     (an RLS-filtered definer would otherwise no-op).
--
--     WHY THE OWNER DOES NOT FOLLOW THE CLAIM. The first form of this file (the
--     B-H2 design as first written) let the pinned owner follow the claim
--     except onto world/seed, so the row "stays readable by the claim's new
--     owning group". Review measured what that means: the `visibility` column
--     stayed 'group' while the set of READERS changed. After a claim moved to
--     another group the operator read 0 of its hidden rows and the new owner
--     read 1; after `epigraph-tenancy-backfill`'s world -> author's-personal-group
--     shape, a RETIRED author's personal group (whose key 107 treats as
--     possibly exposed) read the hidden content, and `reown-reverse` could
--     only HOLD. That is a widening in everything but the column name, and it
--     contradicts "pinned rows are never widened on later claim owner or
--     visibility changes". So the owner is fixed at the hide, and only an
--     explicit unhide (`reown-reverse` on the hide manifest) moves it.
--
-- Arm (c) `epigraph_inherit_tenancy_stmt`, on a derived-row INSERT: for
-- `evidence` the re-sync UPDATE excludes pinned rows (same extra conjunct), so
-- inserting new evidence for a claim does not touch its hidden rows. A pinned
-- row cannot be the inserted row (the pin's key references an existing
-- evidence row). Every other table's statement is unchanged.
--
-- Neither body gains a new write target, a new caller or a new privilege.
-- Both keep 072/070's SECURITY DEFINER, `SET search_path`, EXECUTE revoked from
-- PUBLIC, and owner `epigraph_maintenance` (re-asserted in the guarded block of
-- section 4, as every such block since 060 is; CREATE OR REPLACE keeps the
-- owner and ACL on an upgraded database, and the ALTER makes a fresh install
-- identical).
--
-- ===================================================================
-- 3. WHAT THIS DOES NOT DO
-- ===================================================================
--
--   * It is not a read control. Readability is `evidence_tenancy`'s; a pin only
--     stops propagation from widening the row. Production's orphan PERMISSIVE
--     `evidence_privacy` policy (in no migration; USING effectively TRUE) is
--     OR'ed with `evidence_tenancy`, so while it exists a hidden row is still
--     readable by every app session. The hide tool detects it and refuses
--     without `--accept-unenforced-hide`. Any BYPASSRLS or superuser connection
--     reads every row regardless.
--   * It is forward-only: content emitted before a row was hidden (events,
--     caches, exports, search results) is not retracted.
--   * It pins `evidence` only. Other derived tables keep 070/072 semantics.
--
-- Undo: `DROP TABLE public.evidence_visibility_pins` AFTER restoring both
-- function bodies to 072's `epigraph_propagate_tenancy` and 070's
-- `epigraph_inherit_tenancy_stmt` (the bodies reference the table, so the
-- DROP must come second). `reown-reverse` on each hide manifest first, so no
-- row is left `group` without its pin.

-- ===================================================================
-- 1. THE TABLE
-- ===================================================================
CREATE TABLE IF NOT EXISTS public.evidence_visibility_pins (
    evidence_id uuid PRIMARY KEY REFERENCES public.evidence(id) ON DELETE CASCADE,
    pinned_at   timestamptz NOT NULL DEFAULT now(),
    -- The operator on whose authority the row was hidden. A record, not a
    -- key: no FK, so the pin never blocks an agent row's lifecycle.
    pinned_by   uuid NOT NULL,
    reason      text NOT NULL,
    CONSTRAINT evidence_visibility_pins_reason_nonempty CHECK (length(btrim(reason)) > 0)
);

ALTER TABLE public.evidence_visibility_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_visibility_pins FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS evidence_visibility_pins_definer_read ON public.evidence_visibility_pins;
CREATE POLICY evidence_visibility_pins_definer_read ON public.evidence_visibility_pins
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

DROP POLICY IF EXISTS evidence_visibility_pins_maintenance_insert ON public.evidence_visibility_pins;
CREATE POLICY evidence_visibility_pins_maintenance_insert ON public.evidence_visibility_pins
    FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));

DROP POLICY IF EXISTS evidence_visibility_pins_maintenance_delete ON public.evidence_visibility_pins;
CREATE POLICY evidence_visibility_pins_maintenance_delete ON public.evidence_visibility_pins
    FOR DELETE TO PUBLIC
    USING ((SELECT public.epigraph_bypass()));

REVOKE ALL ON public.evidence_visibility_pins FROM PUBLIC;

-- ===================================================================
-- 2. ARM (d): epigraph_propagate_tenancy, pin-aware
-- ===================================================================
-- 072's body, with two changes only: the `evidence` iteration of the loop
-- appends `pin_skip`, and the PINNED statement follows the loop. Everything
-- else, the derived[] literal included, is 072's text.
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
        -- Empty for every other table, so their statements are 072's exactly.
        -- (An IF, not a conditional expression: `tenancy_triggers.rs` counts
        -- this body's conditional expressions to pin the edges meet at three.)
        IF t = 'evidence' THEN
            pin_skip := ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
                        ' WHERE vp.evidence_id = d.id)';
        ELSE
            pin_skip := '';
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
    -- 110: PINNED evidence. Never widened: visibility is forced to 'group' and
    -- the owner is NEVER changed, so the set of readers is the one the hide
    -- chose whatever happens to the claim (header, section 2). Same
    -- count/update assertion as the loop.
    --
    -- The UPDATE runs only when the count finds a pinned row to change, so a
    -- claim change with nothing pinned issues exactly 072's statements: ONE
    -- UPDATE against `evidence` per claims statement, which
    -- `tenancy_triggers.rs::propagation_is_one_pass_per_statement_not_one_per_row`
    -- pins (a statement-level trigger on `evidence` fires on a zero-row UPDATE
    -- too, so an unconditional second UPDATE would be observable).
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
    -- Harvester fragments hang off provenance, not off claim_id.
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints -- `edges` is the only two-parent relation here, which is
    -- why the 17 derived tables above can legitimately copy their single parent
    -- and this one cannot. See the header for the three CASE expressions, the
    -- two guards and why the co-owner CASE must collapse to NULL.
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
          FROM public.edges e2
          JOIN changed ch
            ON ((e2.source_id = ch.id AND e2.source_type = 'claim')
             OR (e2.target_id = ch.id AND e2.target_type = 'claim'))
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.source_id, e2.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.target_id, e2.target_type) t
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;

-- ===================================================================
-- 3. ARM (c): epigraph_inherit_tenancy_stmt, pin-aware
-- ===================================================================
-- 070's body, with one change: for `evidence` the re-sync UPDATE excludes
-- pinned rows. Its two long comments are 070's and still true of every other
-- table; the exception is stated where it applies.
CREATE OR REPLACE FUNCTION public.epigraph_inherit_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE n_orphan bigint;
BEGIN
    -- ===============================================================
    -- THIS ARM IS INTENTIONALLY UNCONDITIONAL -- IT HAS NO NO-WIDENING GATE,
    -- UNLIKE ARMS (b) AND (d) AND UNLIKE 071's SHIM. STATED EXPLICITLY BECAUSE
    -- THE SURROUNDING COMMENTS ASSERT THE OPPOSITE PRINCIPLE THREE TIMES.
    --
    -- Arms (b) and (d) honour an EXPLICIT, STRICTER declaration because an edge
    -- has two parents and a tenancy of its own to defend. A claim-DERIVED row
    -- does not: `evidence`, `triples`, `claim_versions` and the rest are a
    -- projection of their parent claim's content, so "a derived row always
    -- equals its parent" IS the invariant, in both directions. A derived row
    -- STRICTER than its parent is not a privacy win -- it is a row nobody can
    -- read attached to a claim everybody can.
    --
    -- The `IS DISTINCT FROM` below is an IDEMPOTENCE guard, not a direction
    -- guard, and must not be misread as one.
    --
    -- CONSEQUENCE FOR PR-16. Migration 074 adds explicit owner_group_id
    -- bindings at the INSERT sites. A caller that declares a derived row
    -- stricter than its parent will have the declaration overwritten HERE,
    -- silently, by a trigger that predates the call site.
    -- `each_of_the_eight_section_2_4_tables_inherits_from_its_claim` pins this
    -- behaviour so PR-16 cannot come to rely on the opposite by accident.
    --
    -- THE ONE EXCEPTION (110): an `evidence` row an operator explicitly HID is
    -- PINNED in `evidence_visibility_pins`, and this re-sync skips it. That is
    -- the stricter declaration the paragraph above says a derived row cannot
    -- have; it exists only by a maintenance-role write, never by an INSERT.
    -- ===============================================================
    -- NO epigraph_definer_bypass() ASSERTION HERE, DELIBERATELY, AND THIS IS THE
    -- ONE PLACE THIS FILE DIVERGES FROM ARM (d)'s SHAPE. Arm (d) fires only on
    -- a maintenance-driven UPDATE of claims. Arm (c) fires on EVERY ORDINARY
    -- APPLICATION INSERT of evidence/triples/entity_mentions/..., on the app
    -- pool. A 42501 here would break every ingest until PR-15 gives background
    -- writers a maintenance DSN. The function is still re-owned to
    -- epigraph_maintenance below so its UPDATE is not RLS-filtered at PR-17.
    EXECUTE format(
      'UPDATE %I t SET owner_group_id = c.owner_group_id, visibility = c.visibility
         FROM public.claims c
        WHERE c.id = t.claim_id
          AND t.claim_id IN (SELECT n.claim_id FROM newrows n WHERE n.claim_id IS NOT NULL)
          AND (t.owner_group_id, t.visibility)
              IS DISTINCT FROM (c.owner_group_id, c.visibility)', TG_TABLE_NAME)
      || CASE WHEN TG_TABLE_NAME = 'evidence' THEN
             ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
             ' WHERE vp.evidence_id = t.id)'
         ELSE '' END;
    -- Unresolvable parent => RAISE, never a default.
    EXECUTE 'SELECT count(*) FROM newrows n
              WHERE n.claim_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM public.claims c WHERE c.id = n.claim_id)'
      INTO n_orphan;
    IF n_orphan > 0 THEN
        RAISE EXCEPTION 'epigraph tenancy: % row(s) in % reference a nonexistent '
                        'parent claim', n_orphan, TG_TABLE_NAME
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_inherit_tenancy_stmt() FROM PUBLIC;

-- ===================================================================
-- 4. OWNERSHIP AND GRANTS
-- ===================================================================
-- Guarded, as every such block since 060 is: the roles exist in a deployed
-- cluster and not in every throwaway.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_inherit_tenancy_stmt() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON public.evidence_visibility_pins '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE ALL ON public.evidence_visibility_pins FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.evidence_visibility_pins TO epigraph_app';
    END IF;
END $$;
