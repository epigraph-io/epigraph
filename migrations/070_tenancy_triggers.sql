-- 070_tenancy_triggers.sql -- write-side stamping (TRANSITION form, statement-level)
-- PR-12 of the multi-user tenancy series. Plan §3 calls this file "066"; the
-- authoritative table in migrations/README.md pins it at 070, and 067's own
-- (applied, checksum-frozen) comment already names "migration 070" as the file
-- that creates these trigger bodies. 066 is PR-04's idx_claims_world_owned.
--
-- WHAT THIS FILE IS FOR. Thirteen production `INSERT INTO claims` statements
-- exist (plan §4.6) plus ~160 in tests. Patching them by hand is exactly the
-- opt-in discipline that produced 7-of-85 MCP coverage, so inheritance is
-- stamped by the DATABASE and covers write paths that do not exist yet.
--
-- THIS IS THE TRANSITION FORM. 062's DEFAULTs are still present, so
-- NEW.visibility is never NULL and "undeclared" reads as "still equals the
-- world default". Migration 074 (PR-16) CREATE OR REPLACEs these same
-- functions with the final IS NULL-keyed, RAISE-terminated versions in the
-- same migration that drops those defaults. Arm (a) below WARNS AND COUNTS; it
-- does not raise. Do not read it as the enforcement point.
--
-- Idempotent (CREATE OR REPLACE FUNCTION; DROP TRIGGER IF EXISTS before every
-- CREATE TRIGGER), because sqlx records no row for a failed migration and a
-- lock_timeout abort must be recoverable by re-running the file.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. THE OWNERSHIP PRE-REQUISITE, AND WHY IT IS FIRST.
--
-- epigraph_definer_bypass() (067) is pg_has_role(CURRENT_USER, ...), and
-- inside a SECURITY DEFINER frame current_user is the FUNCTION OWNER. Arm (d)
-- refuses to run unless it returns true, so the owner of these functions must
-- be a member of epigraph_maintenance or every propagation raises 42501.
--
-- 067 also did `REVOKE EXECUTE ON FUNCTION epigraph_definer_bypass() FROM
-- PUBLIC`, so only the CREATING role retains EXECUTE. Re-owning arm (d) to
-- epigraph_maintenance without this GRANT produces
--   ERROR: permission denied for function epigraph_definer_bypass
-- on the first backfill batch. VERIFIED on a throwaway database: OWNER TO
-- without the GRANT fails; with the GRANT, a call made under `SET ROLE
-- epigraph_app` returns true, and the same function re-owned to epigraph_app
-- returns false. The assertion is therefore MEANINGFUL and not vacuous under a
-- superuser test connection -- what is vacuous is only the *caller's* role.
--
-- Guarded on role existence exactly the way 067 guards its EXISTS: on managed
-- PostgreSQL, 060's CREATE ROLE only NOTICEs on insufficient_privilege, and a
-- hard failure here would turn a missing role into a permanent deploy outage
-- (a failed migration records no row, so the next restart re-runs it).
-- ===================================================================
-- AND THE TABLE PRIVILEGES, WHICH ARE NOT OPTIONAL EITHER. Migration 060 says
-- in its own words "(060 itself issues no GRANT.)" -- epigraph_maintenance is a
-- bare `CREATE ROLE ... NOLOGIN` with NO table privileges whatsoever. Re-owning
-- a SECURITY DEFINER body to it therefore makes that body run as a role that
-- cannot read or write anything, and the first thing to fail is arm (a):
--   ERROR: permission denied for table tenancy_undeclared_writes
-- (measured, on the first behavioural probe of this file).
--
-- SELECT/INSERT/UPDATE, deliberately NOT DELETE or TRUNCATE. The tenancy
-- maintenance role stamps and reads; it never destroys. Schema-wide rather than
-- table-by-table because the same role is what PR-15 points the backfill's
-- MAINTENANCE_DATABASE_URL at, and that touches all 25 tier-A tables plus the
-- three bookkeeping tables.
--
-- NOTE FOR A LATER MIGRATION: `ON ALL TABLES IN SCHEMA public` binds the tables
-- that exist NOW. A migration that adds a tier-A table must re-issue this grant.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_definer_bypass() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT USAGE ON SCHEMA public TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- (a) A successor claim INHERITS its predecessor's tenancy.
--
-- ClaimRepository::supersede inserts a new UUID and carries labels forward but
-- NOT ownership, so superseding a private claim silently DECLASSIFIES it.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    -- TRANSITION FORM. While 062's DEFAULTs exist, "undeclared" reads as "still
    -- the world default". Migration 074 replaces this whole function.
    IF NEW.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       THEN RETURN NEW; END IF;

    IF NEW.supersedes IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.supersedes;
        IF FOUND THEN NEW.owner_group_id := g; NEW.visibility := v; RETURN NEW; END IF;
    END IF;

    -- evolve_step inserts a successor WITHOUT setting supersedes -- it links via
    -- step_lineage_id plus an edge.
    IF NEW.step_lineage_id IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c
         WHERE c.step_lineage_id = NEW.step_lineage_id AND c.id <> NEW.id
         ORDER BY c.created_at DESC LIMIT 1;
        IF FOUND THEN NEW.owner_group_id := g; NEW.visibility := v; RETURN NEW; END IF;
    END IF;

    -- THE DEPLOY-ORDERING INSTRUMENT (ops F10). An undeclared write that
    -- silently inherits the default is exactly what migration 074 will start
    -- REJECTING. Count it, loudly, so plan §9.2's week-11b gate has a number to
    -- be flat. (§9.2 has no row labelled "W11"; the gate is week 11b.)
    INSERT INTO public.tenancy_undeclared_writes (table_name, day, n, last_seen)
    VALUES (TG_TABLE_NAME, current_date, 1, now())
    ON CONFLICT (table_name, day)
      DO UPDATE SET n = tenancy_undeclared_writes.n + 1, last_seen = now();
    RAISE WARNING 'epigraph tenancy: undeclared INSERT INTO % (id=%). This will '
                  'raise 23502 after migration 074. See docs/tenancy.md.',
                  TG_TABLE_NAME, NEW.id;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_tenancy() FROM PUBLIC;
DROP TRIGGER IF EXISTS claims_require_tenancy ON public.claims;
CREATE TRIGGER claims_require_tenancy BEFORE INSERT ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_require_tenancy();

-- ===================================================================
-- (b) An edge is stamped with the MEET of its endpoints. Migration 072 (PR-13)
--     relaxes the cross-group RAISE to a co-ownership stamp once
--     co_owner_group_id exists; until then it raises, because silently picking
--     one side leaks the other.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_node_tenancy(p_id uuid, p_type text)
RETURNS TABLE (g uuid, v character varying(16))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_type = 'claim' THEN
        RETURN QUERY SELECT c.owner_group_id, c.visibility FROM public.claims c WHERE c.id = p_id;
    ELSIF p_type = 'evidence' THEN
        RETURN QUERY SELECT e.owner_group_id, e.visibility FROM public.evidence e WHERE e.id = p_id;
    END IF;
    -- An edge pointing at a frame/agent/paper/task has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
-- ops F18. This is a directly callable oracle returning any claim's
-- (owner_group_id, visibility).
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
BEGIN
    SELECT g, v INTO sg, sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type);
    SELECT g, v INTO tg, tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type);

    -- ===============================================================
    -- THIS ARM NEVER WIDENS EITHER -- CORRECTION TO THE PLAN.
    --
    -- Plan §3/066 makes this arm UNCONDITIONAL: it assigns the endpoint meet
    -- over whatever the writer bound. Unlike arm (a), it has no "still equals
    -- the world default" gate. The consequence is that an edge EXPLICITLY
    -- declared ('group', G) between two PUBLIC endpoints is silently rewritten
    -- to ('public', world) -- a declared-private row made public by a trigger.
    --
    -- MEASURED. `epigraph-api/tests/structural_features_authz.rs::
    -- owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part` seeds
    -- exactly that edge and asserts a stranger cannot count it. With the plan's
    -- unconditional form the stranger saw 2 edges where it must see 1:
    --   "a group-private EDGE must not appear in a stranger's edge counts even
    --    though both its endpoints are public claims"
    --
    -- The meet is still the DERIVATION for an undeclared edge, so the plan's
    -- "edges need no call-site edits" property is preserved intact -- an edge
    -- inserted on 062's defaults is still stamped from its endpoints. What
    -- changes is only that an EXPLICIT, STRICTER declaration is honoured, which
    -- is the same no-widening rule migration 071's shim applies and the same
    -- shape as arm (a)'s transition gate.
    -- ===============================================================
    IF NEW.visibility = 'group'
       AND NEW.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       AND NOT (sv = 'group' OR tv = 'group') THEN
        -- Explicitly declared private, endpoints both public: the meet would
        -- WIDEN it. Keep the declaration.
        RETURN NEW;
    END IF;

    IF sv = 'public' AND tv = 'public' THEN
        NEW.owner_group_id := '00000000-0000-0000-0000-000000000000'::uuid;
        NEW.visibility := 'public';
    ELSIF sv = 'public' THEN NEW.owner_group_id := tg; NEW.visibility := 'group';
    ELSIF tv = 'public' THEN NEW.owner_group_id := sg; NEW.visibility := 'group';
    ELSIF sg = tg      THEN NEW.owner_group_id := sg; NEW.visibility := 'group';
    ELSE
        -- ===============================================================
        -- THE CROSS-GROUP RAISE IS EFFECTIVELY UNCONDITIONAL, AND PR-12 IS
        -- WHAT MAKES IT REACHABLE. STATED HERE SO IT IS NOT DISCOVERED IN
        -- PRODUCTION.
        --
        -- For PERSONAL groups one principal can never be a live member of two
        -- distinct ones, so `sg = ANY(session_groups) AND tg = ANY(...)` is
        -- unsatisfiable and this arm always raises. The satisfiable case
        -- (sg = tg) was already taken by the branch above.
        --
        -- MEASURED on a throwaway database: an edge between claim(group G1) and
        -- claim(group G2) with no session GUC set raises here. It is NOT
        -- reachable from this binary's own backfill output -- `backfill_claims`
        -- writes visibility='public' with a personal owner_group_id, so the
        -- `sv='public' AND tv='public'` branch above takes it. It becomes
        -- reachable once migration 071's transcription makes two claims with
        -- DIFFERENT owners genuinely ('group', G), at which point a cross-owner
        -- link_epistemic / link_hierarchical / decomposition edge hard-fails.
        --
        -- PR-13's migration 072 CREATE OR REPLACEs this body with the
        -- co_owner_group_id form and closes the window. Shipping the RAISE
        -- first is the fail-CLOSED order: silently picking one side leaks the
        -- other, which is the disclosure this whole file exists to prevent.
        --
        -- ERRCODE 23514 (check_violation) rather than plpgsql's P0001 default,
        -- so the API/MCP layer can map it to a 4xx instead of surfacing a bare
        -- 500. The mapping itself is PR-13's to add alongside 072.
        -- ===============================================================
        IF NOT (sg = ANY (public.epigraph_session_groups())
            AND tg = ANY (public.epigraph_session_groups())) THEN
            RAISE EXCEPTION 'epigraph tenancy: edge spans groups % and %; writer '
                            'is not a member of both', sg, tg
                USING ERRCODE = '23514';
        END IF;
        NEW.owner_group_id := sg; NEW.visibility := 'group';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_tenancy() FROM PUBLIC;   -- ops F18
DROP TRIGGER IF EXISTS edges_tenancy ON public.edges;
CREATE TRIGGER edges_tenancy BEFORE INSERT OR UPDATE OF source_id, target_id
    ON public.edges FOR EACH ROW EXECUTE FUNCTION public.epigraph_edges_tenancy();

-- ===================================================================
-- (c) Claim-derived rows inherit from their parent claim. Fails CLOSED.
--
-- STATIC, PER-TABLE, STATEMENT-LEVEL (ops F17). The parent column is `claim_id`
-- on every table in the set.
--
-- NAMING, RECONCILED. 067's frozen comment calls this function
-- `epigraph_inherit_tenancy`; plan §3/066's SQL body defines
-- `epigraph_inherit_tenancy_stmt`. 067 is applied and its checksum frozen, so
-- its prose cannot be corrected. This file uses the plan's spelling, because
-- the `_stmt` suffix carries the fact that distinguishes it from the row-level
-- form the previous plan revision shipped. Read 067's comment against this file.
--
-- ===================================================================
-- THE ctid PREDICATE IS GONE. THIS IS THE SHARPEST CORRECTION IN THIS PR.
--
-- Plan §3/066 restricts the UPDATE to the inserted rows with
--     AND t.ctid = ANY (SELECT ctid FROM newrows)
-- A TRANSITION TABLE HAS NO ctid. It is a tuplestore, not a heap relation, and
-- `SELECT n.ctid FROM newrows n` is a hard error:
--     ERROR: column n.ctid does not exist
--
-- The plan's form is UNQUALIFIED, and that is what makes this dangerous rather
-- than merely wrong. Inside an UPDATE that has already bound the aliases `t`
-- and `c`, a bare `ctid` in the subquery does not fail to resolve -- it resolves
-- OUTWARD, to `t.ctid`. The predicate degenerates to `t.ctid = ANY (SELECT
-- t.ctid ...)`, a TAUTOLOGY over the whole base table.
--
-- MEASURED, because the failure is invisible in the values it produces: a
-- statement trigger on a 4-row table inserting 2 rows reported the predicate
-- matching 4 rows, not 2; on the preceding 2-row insert it reported 2. It
-- tracks the TABLE SIZE, not the statement. So the plan's arm (c) re-stamps
-- EVERY ROW OF THE TABLE ON EVERY INSERT -- correct output, O(table) cost, on
-- the highest-volume write path in the system (one 5,017-claim ingest inserts
-- 18,400 triples and 22,119 entity_mentions). It would never have produced a
-- wrong answer and never have failed a test; it would only have got slower.
--
-- An earlier probe of mine "confirmed" the ctid form matched 3 of 3 rows. It
-- was a false positive for exactly this reason: the base table had 3 rows.
--
-- THE REPLACEMENT joins on `claim_id`, the same key arm (d) uses. It is
-- narrower than the tautology (only the touched claims' rows, not the table)
-- and it is what the `IS DISTINCT FROM` guard was always doing the real work
-- for: a sibling row that already carries its parent's tenancy is not written.
-- ===================================================================
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_inherit_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
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
              IS DISTINCT FROM (c.owner_group_id, c.visibility)', TG_TABLE_NAME);
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

-- THE TRIGGER SET IS A LITERAL ARRAY, NOT A CATALOG LOOP -- CORRECTION TO THE
-- PLAN. Plan §3/066 says "one trigger per member of the generated set that
-- carries claim_id". Measured against this schema, 21 relations carry a
-- claim_id column and a naive loop over them ABORTS THIS MIGRATION:
--
--   * alternative_set and alt_set_decisions are VIEWS. PostgreSQL rejects a
--     statement-level AFTER INSERT trigger on a view (a view accepts only
--     INSTEAD OF row triggers), so the CREATE TRIGGER errors out.
--   * claim_encryption and claim_version_encryption carry claim_id but have NO
--     owner_group_id / visibility columns -- they are tenancy_exempt, keyed on
--     group_id + epoch by migration 060. The UPDATE would name columns that do
--     not exist.
--
-- The correct set is 062's tier_a array INTERSECTED WITH "has a claim_id
-- column", which is these 17 -- identical to arm (d)'s `derived` array below,
-- and that identity is the point: (c) stamps on INSERT, (d) re-stamps the same
-- 17 on UPDATE. `evidence` IS INCLUDED: evidence.claim_id is NOT NULL, and
-- evidence.raw_content plus evidence.embedding are a full second copy of
-- claim-derived text WITH ITS OWN ANN VECTOR. A draft that omitted it stamped
-- EVIDENCE OF A GROUP-PRIVATE CLAIM AS WORLD/PUBLIC.
--
-- recall_events is tier_a but has NO claim_id (it is keyed on the QUERYING
-- agent), so it correctly gets no (c) trigger. harvester_fragments has no
-- claim_id either -- it hangs off harvester_claim_provenance; see arm (d) and
-- the backfill's explicit arm for it.
DO $$
DECLARE t text;
        inheritors text[] := ARRAY[
          'evidence','triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','challenges','reasoning_traces',
          'experiment_triples','experiment_entity_mentions','claim_clusters',
          'claim_cluster_membership','claim_neighborhood_membership',
          'claim_signature_revocations'];
BEGIN
    FOREACH t IN ARRAY inheritors LOOP
        -- Defensive: skip a table that is somehow absent or shapeless rather
        -- than aborting the whole migration on a partially-migrated database.
        IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r')
        THEN
            EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                           t || '_inherit_tenancy', t);
            EXECUTE format(
              'CREATE TRIGGER %I AFTER INSERT ON public.%I
                 REFERENCING NEW TABLE AS newrows
                 FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_inherit_tenancy_stmt()',
              t || '_inherit_tenancy', t);
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- (d) A visibility change on a claim propagates to its children in the SAME tx.
--
-- STATEMENT-LEVEL, not FOR EACH ROW (ops F11): the row form issued ten UPDATEs
-- per claim. EVERY arm carries IS DISTINCT FROM -- idempotence is what makes a
-- kill -9 recoverable, so it is load-bearing, not hygiene. ROW_COUNT IS CHECKED
-- (sec F10): without it a silently RLS-filtered UPDATE would make propagation
-- work for a first privatization and fail silently for every re-privatization.
--
-- PR-13's migration 072 CREATE OR REPLACEs THIS FUNCTION, BY THIS NAME, with
-- the three-CASE co-ownership meet, and PR-13's acceptance reads pg_proc.prosrc
-- for it. The name and the zero-argument trigger signature are a downstream
-- contract, not a preference.
--
-- ===================================================================
-- CORRECTION TO THE PLAN -- ITS TRIGGER DEFINITION IS NOT CREATABLE.
--
-- Plan §3/066 specifies:
--     CREATE TRIGGER claims_propagate_tenancy AFTER UPDATE OF owner_group_id,
--       visibility ON public.claims REFERENCING NEW TABLE AS changed
--       FOR EACH STATEMENT ...
-- PostgreSQL rejects that outright:
--     ERROR: transition tables cannot be specified for triggers with column lists
-- A column list (`UPDATE OF ...`) and a transition table (`REFERENCING`) are
-- mutually exclusive, so this trigger could never have been created and the
-- migration would have aborted on the last statement of the file. Measured, not
-- reasoned: it is the error the first application of this file produced.
--
-- THE FIX, AND WHY IT IS NOT JUST "DROP THE COLUMN LIST". Without the column
-- list the trigger fires on EVERY UPDATE of `claims` -- embedding backfills,
-- label edits, last_match_scan stamps -- and each firing would run 2 statements
-- x 17 derived tables plus two more, ~36 statements, on a path that changed no
-- tenancy at all. Worse, the epigraph_definer_bypass() assertion would then
-- raise 42501 on ordinary application UPDATEs if a deploy had not re-owned this
-- function, converting a backfill-only failure into a total write outage.
--
-- So the column list is replaced by an OLD TABLE comparison AS THE FIRST
-- STATEMENT, ahead of the assertion. One scan of two tuplestores restores
-- exactly the firing condition `UPDATE OF owner_group_id, visibility` was
-- reaching for -- and is in fact STRICTER, because a column list fires on a
-- write of the same value, while this fires only on a real change.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
BEGIN
    -- The firing gate. MUST stay ahead of the assertion below: an UPDATE that
    -- changes no tenancy is none of this trigger's business, and must not be
    -- made to depend on the maintenance role.
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
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t)
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- ===============================================================
    -- Edges are the MEET of their (possibly changed) endpoints. Migration 072
    -- REPLACES this body with the three-CASE co-ownership form.
    --
    -- THIS RECOMPUTES THE MEET FROM BOTH ENDPOINTS -- CORRECTION TO AN EARLIER
    -- REVISION OF THIS FILE, WHICH COPIED ONE SIDE.
    --
    -- The earlier form was
    --     UPDATE public.edges e SET owner_group_id = ch.owner_group_id,
    --            visibility = ch.visibility FROM changed ch WHERE ...
    -- which never reads the OTHER endpoint. MEASURED twice on a throwaway
    -- database, in rolled-back transactions:
    --
    --   (1) WIDENING. Claims A and B both ('group', G); edge A->B correctly
    --       stamped group/G by arm (b). Declassifying A alone rewrote the edge
    --       to ('public', world) while B was still group-private -- a public
    --       edge attesting that a private claim exists and stands in a named
    --       relationship. That is exactly the structural leak arm (b) exists
    --       to close, reached through the UPDATE door.
    --   (2) ARBITRARY SIDE. One statement privatizing A and B into DIFFERENT
    --       personal groups made the edge take whichever join row Postgres
    --       matched first. Arm (b) RAISEs on that configuration at INSERT; the
    --       UPDATE path silently picked a winner.
    --
    -- `edges` is the ONLY two-parent relation here, which is why the 17 derived
    -- tables and harvester_fragments above can legitimately copy their single
    -- parent and this one cannot.
    --
    -- WHY THIS DOES NOT RAISE THE WAY ARM (b) DOES. Arm (d) fires on EVERY
    -- claims UPDATE, including this series' own backfill. An exception here
    -- would be a total write outage on any privatization that happens to touch
    -- a cross-group edge. `m.g IS NULL` (the both-private-different-groups
    -- case) therefore LEAVES THE EDGE UNCHANGED: stale-but-still-private is
    -- fail-closed, and 072 resolves it properly with co_owner_group_id.
    --
    -- AND IT NEVER WIDENS, for arm (b)'s reason and measured by the same test:
    -- `structural_features_authz.rs::seed_corpus` seeds an edge EXPLICITLY
    -- declared ('group', G) between two PUBLIC claims, then stamps ownership
    -- rows over those claims -- which fires this arm. Without the guard the
    -- meet re-widened that edge to ('public', world) and the stranger counted
    -- it. A declassification that should widen an edge is migration 074's
    -- (PR-16) business, alongside its claims_block_widening trigger.
    -- ===============================================================
    UPDATE public.edges e
       SET owner_group_id = m.g, visibility = m.v
      FROM (
        SELECT DISTINCT e2.id,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN s.v = 'public' THEN t.g
                    WHEN t.v = 'public' THEN s.g
                    WHEN s.g = t.g      THEN s.g
                    ELSE NULL END AS g,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN 'public'::character varying(16)
                    ELSE 'group'::character varying(16) END AS v
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
       AND (e.owner_group_id, e.visibility) IS DISTINCT FROM (m.g, m.v);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;  -- ops F18
DROP TRIGGER IF EXISTS claims_propagate_tenancy ON public.claims;
CREATE TRIGGER claims_propagate_tenancy AFTER UPDATE
    ON public.claims REFERENCING OLD TABLE AS prev NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_propagate_tenancy();

-- ===================================================================
-- RE-OWN THE SECURITY DEFINER BODIES TO epigraph_maintenance.
--
-- Arm (d) REQUIRES it (see section 0). Arms (a), (b) and (c) do not assert on
-- epigraph_definer_bypass(), but they all read or write through their own
-- tables' policies while running as the function owner, so at PR-17 an
-- app-owned body would be RLS-filtered. Arm (b) is the sharpest case: a
-- filtered read of `claims` returns NOT FOUND, epigraph_node_tenancy then
-- yields its ('public', world) fallback, and a private endpoint would be
-- stamped PUBLIC. That is a LEAK, not an error, so ownership is a security
-- control here and not tidiness.
--
-- CREATE OR REPLACE preserves ownership, so a re-run of this file is a no-op.
--
-- ===================================================================
-- THE GUARD BELOW SILENTLY NO-OPS IF THE ROLE IS ABSENT, AND THAT IS WHY
-- `epigraph-tenancy-backfill verify` NOW ASSERTS THE OUTCOME.
--
-- The role is not guaranteed: migration 060 creates it inside a DO block that
-- catches insufficient_privilege and only RAISE NOTICEs, precisely because a
-- managed PostgreSQL migration role may lack CREATEROLE. On such a cluster 070
-- applies SUCCESSFULLY, these functions stay app-owned, and at PR-17 arm (b)'s
-- filtered read of `claims` returns NOT FOUND -> epigraph_node_tenancy's
-- ('public', world) fallback -> a private endpoint stamped PUBLIC. A leak, with
-- no error and no signal. 071's shim has the loud twin: an app-owned body makes
-- epigraph_definer_bypass() false and every `ownership` write raises 42501.
--
-- A hard failure HERE is still wrong -- a failed migration records no row, so
-- the next restart re-runs it and a missing role becomes a permanent deploy
-- outage. The check therefore lives where it can be acted on: `verify`, whose
-- exit code is the documented week-11c pre-flight, fails if any of the six
-- SECURITY DEFINER bodies is not owned by epigraph_maintenance.
-- ===================================================================
DO $$
DECLARE f text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_claims_require_tenancy()',
            'public.epigraph_node_tenancy(uuid, text)',
            'public.epigraph_edges_tenancy()',
            'public.epigraph_inherit_tenancy_stmt()',
            'public.epigraph_propagate_tenancy()'] LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO epigraph_maintenance', f);
        END LOOP;
    END IF;
END $$;
