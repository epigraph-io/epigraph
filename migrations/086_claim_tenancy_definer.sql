-- 086_claim_tenancy_definer.sql
-- PR-24. `migrations/README.md` is authoritative for the number: it reserves
-- 086-090 as remaining headroom (085 was claimed by PR-10 on 2026-09-03, 091 is
-- taken by PR #411). Verified free on disk before writing; the on-disk order is
-- 079 -> 085 -> 091 and `set_ignore_missing(true)` tolerates the gaps. The
-- README's reservation table is updated in this same commit — 086 claimed
-- 2026-09-06, headroom narrowed to 087-090 — the way 085's row records PR-10's
-- claim, so the next shard cannot re-take it.
--
-- No `-- no-transaction` header, deliberately. Nothing here is `CONCURRENTLY`,
-- and `crates/epigraph-db/tests/tenancy_migration_shape.rs::
-- no_transaction_files_contain_exactly_one_statement` asserts the count of
-- `-- no-transaction` files equals `INDEX_MIGRATIONS.len()` EXACTLY, so copying
-- that header from a neighbouring index migration fails an exact-count
-- assertion that reads as unrelated. `SET LOCAL lock_timeout` mirrors 077.
--
-- ===================================================================
-- WHAT THIS REPAIRS
--
-- `crates/epigraph-db/src/repos/claim.rs::ClaimRepository::hidden_claim_ids`
-- answers "which of these caller-named ids name a claims row that this viewer
-- may NOT read". It is the read-side suppression control for two surfaces:
-- `epigraph-api`'s `routes/events.rs::retain_visible_events` (the in-process
-- ring-buffer half of `GET /api/v1/events`) and
-- `routes/webhooks.rs::agent_may_receive` (webhook fan-out).
--
-- It computes a set difference between an EXISTENCE arm and a VIEWER-FILTERED
-- arm. That is only informative while the two arms have DIFFERENT authority.
-- Both arms read `claims` directly, so once migration 079's FORCE posture is
-- live on an application role BOTH arms are filtered by `claims_tenancy`, and
-- the difference collapses. Recorded as
-- `F-PR23-existence-probe-collapses-under-force` in `docs/tenancy/progress.json`
-- and closed by this migration. It is LATENT TODAY — every environment's DSN is
-- still the owning superuser, for whom no policy applies — and it is armed by
-- plan 9.2 step 11d, which this discharges one precondition of. Step 11d is
-- still NOT runnable: `D-PR17-request-path-never-stamps-session-gucs` remains
-- open.
--
-- ===================================================================
-- BOTH ARMS MOVE INTO THE FRAME, NOT JUST THE EXISTENCE ARM
--
-- The finding's prescribed repair says "route the existence arm through a
-- SECURITY DEFINER helper". MEASURED on the throwaway at head 91 with FORCE
-- live, that repairs three of the four acceptance properties and breaks the
-- fourth, in the OTHER direction. Every cell below was measured, on a fixture of
-- one public claim, one claim private to group g, and one uuid naming no row;
-- `priv` means the private id was reported hidden, `{}` means nothing was:
--
--   session        GUC          viewer       today       arm-1-only   this file
--   -------------  -----------  -----------  ----------  -----------  ---------
--   owner          -            stranger []  priv        priv         priv
--   epigraph_app   '' (empty)   stranger []  {} <-- BUG  priv         priv
--   epigraph_app   '' (empty)   member  [g]  {}          priv <-- BUG {}
--   epigraph_app   g            member  [g]  {}          {}           {}
--   epigraph_app   g            stranger []  priv (!)    priv         priv
--
-- Row 1 is the calibration: the fixture CAN detect a hidden id. Row 2 is the
-- reported defect. Row 5 is why a coherent-GUC test alone proves nothing — with
-- the GUC carrying the owning group and a STRANGER viewer, TODAY's unrepaired
-- statement already returns the right answer, for a reason that has nothing to
-- do with the viewer. An acceptance test written that way passes on the broken
-- tree.
--
-- Row 3 is the shape BOTH production call sites actually have: they take a raw
-- `&sqlx::PgPool` as a parameter, sourced from `state.db_pool` or the webhook
-- dispatcher handoff, and nothing stamps the session GUCs on it. With the
-- existence arm alone in the frame, the viewer-filtered arm is still narrowed by
-- the policy to `visibility = 'public'` whatever `$V` binds, so a group-private
-- claim the viewer IS entitled to read comes back reported hidden and its
-- delivery is dropped. Silent, 200-shaped, and visible only in a tracing target.
--
-- So the function returns the two TENANCY COLUMNS as well as the id, and
-- `hidden_claim_ids` keeps its `Viewer::splice` marker over the function's
-- output instead of over `claims`. Both arms are then evaluated inside the
-- definer frame and the ONLY filter left is the viewer's own predicate — which
-- is the authority the function's signature promises, and which is independent
-- of whether the connection is stamped, unstamped, or incoherently stamped.
-- A `Bypass` viewer keeps working through the existing mechanism: `splice`
-- renders it to a bare separator, the two arms coincide, and the difference is
-- empty. Nothing hand-rolls that branch.
--
-- ===================================================================
-- THE RESIDUAL, STATED PLAINLY RATHER THAN LEFT IMPLICIT
--
-- This is the second definer helper in the tree that is PARAMETERISED rather
-- than bound to the calling principal, after `epigraph_live_memberships` (077),
-- and the same accepted obligation applies:
-- `D-PR17-live-memberships-is-parameterised-not-principal-bound`. It cannot be
-- principal-bound: its callers ask "classify these N ids", where the ids are
-- extracted blind from an arbitrary event payload precisely so that no key
-- allowlist can be escaped by the next emitter.
--
-- IT RETURNS MORE THAN IDS, AND THAT IS A DEVIATION FROM THE FINDING'S OWN
-- PRESCRIPTION ("a SECURITY DEFINER helper returning ids only and no content").
-- What it adds is `visibility` and `owner_group_id` — the two columns the policy
-- itself keys on — and nothing else: no content, no agent, no labels, no
-- timestamps, no truth value, no attribution. The deviation is argued, not
-- waved through:
--
--   * The DECIDING argument is (b) below, not (a). The alternative that keeps
--     the ids-only shape is a definer that takes the caller's group array and
--     computes the difference internally.
--     (a) DISCLOSURE — no reduction, and an earlier draft of this header
--         overclaimed here. That alternative would disclose the owning group by
--         PROBING (vary the group array, watch the answer change). The shape
--         shipped below discloses `owner_group_id` DIRECTLY, in its result set.
--         That is equal to or greater than what probing yields, so this is not a
--         disclosure win and must not be written as one. It is accepted for the
--         same reason 077's `epigraph_live_memberships` is accepted — see THE
--         RESIDUAL above — and bounded by the next three bullets.
--     (b) CORRECTNESS — decisive, and measured. Putting the group array inside
--         the frame lets a caller UNDER-suppress by passing a group it is not
--         in, because the array is then a definer parameter rather than the
--         `Viewer`'s own predicate. Arm 2's `$V` here comes from the `Viewer`
--         object, through the same `splice` mechanism the repo-layer lint
--         checks, so there is no such parameter to vary.
--   * Enumeration is impossible in either shape: the body is `= ANY(p_ids)`, so
--     a caller learns nothing about ids it does not already possess, and v4
--     uuids are not guessable.
--   * Scoped to its CALLER, `hidden_claim_ids` discloses strictly less than the
--     read it guards: the callers already hold the whole event payload and the
--     probe only decides whether to SUPPRESS it. That is a property of the
--     caller, NOT of the function — the function is executable by anything
--     running as `epigraph_app`, which is why the next bullet and the ACL pin in
--     `crates/epigraph-db/tests/schema_contract.rs` matter.
--   * `EXECUTE` is revoked from PUBLIC and granted only to `epigraph_app`, and
--     that ACL is pinned in the catalog by
--     `schema_contract.rs::migration_086_read_definer_is_revoked_from_public`,
--     including `proacl IS NOT NULL` — because a later `CREATE OR REPLACE` of
--     this body silently restores the DEFAULT ACL, which is EXECUTE to PUBLIC.
--
-- ===================================================================
-- THE GUARDED `OWNER TO` IS THE MECHANISM, NOT HARDENING
--
-- A SECURITY DEFINER frame is not an RLS exemption in itself. This body reads
-- `claims`, which is FORCEd; what admits the read is `claims_tenancy`'s
-- `OR (SELECT public.epigraph_definer_bypass())` disjunct, and
-- `epigraph_definer_bypass()` (067) is `pg_has_role(current_user,
-- 'epigraph_maintenance', 'MEMBER')` — `current_user` inside the frame being the
-- FUNCTION OWNER. So the `ALTER FUNCTION ... OWNER TO epigraph_maintenance`
-- below is load-bearing, together with `epigraph_maintenance`'s `SELECT` on
-- `claims` and its `EXECUTE` on `epigraph_definer_bypass()`.
--
-- The guard is a real hazard and not a formality: 060 creates the roles inside a
-- `DO` block that catches `insufficient_privilege` and only `RAISE NOTICE`s, so
-- on a cluster where the role is absent this `ALTER` silently no-ops, ownership
-- stays with the migration runner, and the frame then bypasses only because that
-- role happens to be a superuser. That fails SAFE but with more authority than
-- intended, and it is invisible in `_sqlx_migrations`.
--
-- THE INSTRUMENT FOR THAT IS WIRED IN THIS SAME COMMIT.
-- `verify`'s exit code is the documented week-11c deploy pre-flight, and its
-- whole purpose is catching a silently no-opped `OWNER TO`. This function is
-- registered with it in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`.
-- Without that edit the one gate built to catch this failure would have been
-- blind to precisely the function whose silent no-op reintroduces the collapse.
--
-- THAT INSTRUMENT IS LOAD-BEARING, NOT BELT-AND-BRACES, and the reason is the
-- failure DIRECTION. A no-opped `OWNER TO` does not make this control
-- conservative. Both arms of `hidden_claim_ids`' set difference draw from ONE
-- call to this function, so a frame that lost its authority shrinks BOTH arms
-- together: a public row survives in both, the difference empties, and the
-- callers read empty as "nothing is hidden" and DELIVER. That is the original
-- collapse reached by another route. `verify` is what stands behind it.
-- (A missing `EXECUTE` grant is the one genuinely fail-CLOSED sub-case; see
-- below.) This is stated the same way in
-- `crates/epigraph-db/tests/locked_decisions.rs`' D1 bullet.
--
-- It is registered on the DEFERRED list rather than on the unconditional
-- `DEFINER_FUNCTIONS`, and that distinction is deliberate. Plan 9.2 runs
-- `verify` at step 11c, BEFORE applying 070/071/072 — 077/078/079 land at 11d
-- and this file later still — so on a correctly sequenced deploy 086 is not yet
-- applied when the pre-flight runs. An unconditional entry would report
-- "does not exist" and block a working deploy, which is the same class of error
-- that check's own comment refuses to commit for its role predicate. So the
-- entry is skipped, with an explicit stderr NOTE (unchecked, not passing),
-- exactly while the FUNCTION IS ABSENT FROM `pg_proc` — the object, not the
-- `_sqlx_migrations` row, because a database can hold the function without the
-- row (a version row deleted to clear a checksum mismatch, a dump/restore, a
-- baselined database) and a bookkeeping gate would skip the check there and
-- still exit 0.
--
-- A MISSING `GRANT EXECUTE` fails CLOSED rather than open — `42501` on the first
-- call, which `routes/webhooks.rs::agent_may_receive` maps to "suppress" and
-- `routes/events.rs::retain_visible_events` maps to a 500 — but "fails loudly"
-- describes the log line and not the operator experience: the visible symptom is
-- every webhook delivery silently stopping and `GET /api/v1/events` 500ing, i.e.
-- a total outage of both surfaces this file exists to protect. The grant is
-- therefore pinned in the catalog too, by
-- `crates/epigraph-db/tests/schema_contract.rs::migration_086_read_definer_is_revoked_from_public`,
-- alongside the REVOKE. It is NOT added to `verify_definer_ownership`, whose six
-- other entries have different grant expectations. Note also that
-- `crates/epigraph-db/tests/viewer_fixture.rs::grant_app_privileges` grants
-- schema, tables and sequences and NOT functions, so the grant below is the only
-- thing that makes the app role able to call this at all.
--
-- ===================================================================
-- ORDERING: THIS MIGRATION MUST APPLY BEFORE THE CODE THAT CALLS IT
--
-- `ClaimRepository::hidden_claim_ids` calls this function UNCONDITIONALLY, with
-- no fallback, so a binary carrying that change on a database that has not
-- applied 086 raises `42883` on every call — the same fail-closed outage as the
-- missing grant. That is an accepted class in this tree, not a new one:
-- `repos/group_membership.rs::list_live_for_agent` calls 077's
-- `epigraph_live_memberships` exactly the same way. It is stated here because
-- this file creates an ASYMMETRY that could be misread: the `verify` entry above
-- is deliberately tolerant of a pre-086 database, and that tolerance is about
-- the PRE-FLIGHT only. It does not make the api binary tolerant of one.
-- `server.rs::should_migrate_on_boot` is opt-in, so the ordering is enforced by
-- running `epigraph-migrate` before the new binary serves traffic.
--
-- ===================================================================
-- ON 077'S `42804` NOTE — CORRECTED, CONCLUSION KEPT
--
-- 077 says a `character varying(20)` vs `RETURNS TABLE (... role text)`
-- mismatch raises `42804 structure of query does not match function result type`
-- "at CALL time, not at CREATE time". MEASURED on PG 16.13: for a
-- `LANGUAGE sql` body — which is what 077 uses and what this file uses — an
-- arity or incompatible-type mismatch is caught at CREATE (`42P13`), and
-- `character varying(n)` -> `text` is binary-coercible and accepted at both.
-- `42804` on `RETURN QUERY` is a PL/pgSQL failure mode. `m.role::text` is
-- therefore harmless but not load-bearing, and neither is the `::text` below
-- (`claims.visibility` is `character varying(16)`); it is written explicitly
-- anyway so the declared type cannot silently start depending on the column's.
--
-- 077's operational conclusion survives for a stronger reason: what applying a
-- migration cannot detect is SILENT, not an error. A no-opped `OWNER TO`, or
-- `epigraph_maintenance` losing `SELECT` on `claims`, makes this function return
-- FEWER rows with no error at all — straight back to the collapse. So it is
-- exercised BY BEING CALLED, on a real `epigraph_app` session under FORCE, with
-- an owner-connection calibration arm, in
-- `crates/epigraph-db/tests/rls_enforcement.rs`.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_claim_tenancy_by_ids(p_ids uuid[])
RETURNS TABLE (id uuid, visibility text, owner_group_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT c.id, c.visibility::text, c.owner_group_id
      FROM public.claims c
     WHERE c.id = ANY(p_ids)
$$;

COMMENT ON FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) IS
    'Tenancy label (id, visibility, owner_group_id) for caller-named claim ids. '
    'Never content. Backs ClaimRepository::hidden_claim_ids, whose set '
    'difference is uninformative when both of its arms are filtered by the same '
    'policy. Owner must satisfy epigraph_definer_bypass(); see migration 086.';

REVOKE EXECUTE ON FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_claim_tenancy_by_ids(uuid[]) TO epigraph_app';
    END IF;
END $$;
