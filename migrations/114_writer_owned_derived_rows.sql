-- 114: writer-owned derived rows on public claims (operator decision
-- 2026-09-26, batch W-own).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- An agent that attaches evidence, a DS mass function or a reasoning trace to
-- a PUBLIC claim it does not own was refused on the application role:
--
--   * 074's `epigraph_derived_require_tenancy` (BEFORE INSERT) stamps the row
--     with the CLAIM's `(owner_group_id, visibility)`;
--   * 077's `<table>_tenancy` WITH CHECK then asks whether that owner is in
--     the session's `epigraph_writable_groups()`;
--   * most public claims are owned by the WORLD group,
--     which is memberless by design (`locked_decisions.rs::
--     d2_world_and_seed_remain_memberless`), so it is in nobody's writable
--     set, and every such attachment raised 42501.
--
-- Measured on a rehearsal database at head as the application role, stamped
-- as a writer with its own personal group: `update_with_evidence` refused on
-- "evidence", `submit_ds_evidence` refused on "claim_frames", and
-- `link_epistemic` returned `belief_wired: false` ("edge auto-wire failed:
-- assign_claim ... claim_frames"): belief mass that was silently never
-- recorded.
--
-- The operator's rule: a row an agent ATTACHES to a public claim it cannot
-- write is owned by the WRITER's group and stays PUBLIC; ownership of the
-- claim is not needed to attach. Changing the claim ROW (content, labels,
-- truth_value) stays with the claim's owner (or an admin, 111).
--
-- ===================================================================
-- 1. WHICH ROWS BECOME WRITER-OWNED, AND WHICH DO NOT
-- ===================================================================
--
-- PER-WRITER rows, whose key includes the writer: `evidence` (one row per
-- submission), `mass_functions` (unique per claim, frame, SOURCE AGENT and
-- perspective) and `reasoning_traces` (one row per trace). These three gain a
-- `writer_owned boolean NOT NULL DEFAULT false` column and a BEFORE INSERT
-- trigger, `<table>_attach_writer`, that decides the owner (section 2).
--
-- PER-CLAIM aggregates, keyed on the claim alone: `claim_frames` (PRIMARY KEY
-- (claim_id, frame_id)) and the DS cache columns on the `claims` row itself
-- (belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing,
-- belief_frame_id, classification). There is one row per claim, so a
-- writer-owned copy is impossible without a schema change, and a row owned by
-- whoever attached FIRST would take the claim's own frame assignment out of
-- its owner's hands (the owner could no longer change `hypothesis_index` on
-- its own claim: the row's owner is not in the owner's writable set). So these
-- stay owned by the CLAIM's group and a non-owner reaches them only through
-- the audited SECURITY DEFINER functions of section 5, which:
--
--   * never write `truth_value`, `labels`, `content` or any other claim
--     column: the owner's truth is the owner's;
--   * write the DS cache that Dempster-Shafer combination across ALL writers'
--     mass functions produced. Combination across writers is the intended
--     semantics; the cache is recomputable from the stored mass functions at
--     any time (`recompute_beliefs`), and every such write is audited.
--
-- KNOWN LIMITATION, NOT CLOSED HERE (review finding W8): the combination treats
-- every stored BBA as an independent source. One writer that submits N
-- differently-worded pieces of evidence (each `update_with_evidence` keys its
-- BBA by a fresh evidence id), or wires N edges from claims it authored, is
-- combined as N sources, and can on its own move a public claim's CACHED
-- belief (belief / plausibility / pignistic_prob, and the classification
-- derived from them) arbitrarily close to 0 or 1. It cannot move `truth_value`,
-- labels or content, and every cache write is attributed in `security_events`.
-- Bounding one writer's weight needs a per-writer reduction (e.g. averaging
-- each writer group's writer-owned BBAs into one before Dempster's rule)
-- applied at EVERY combine site that reads stored BBAs -- the engine
-- recompute, `ds_auto`, the belief/assess/hypothesis routes and the read-side
-- belief queries -- or reads and writes would disagree. That is its own change.
--
-- WHY THE DEFINER TAKES THE CACHE VALUES FROM THE CALLER rather than computing
-- them: the combination runs in Rust (`epigraph_ds::combination`, with the
-- per-frame reliability discount read from `calibration.toml` on disk and the
-- monotonicity clamp in `ds_auto`), and none of that is reachable from SQL.
-- This does not lower the trust bar: the writable set every RLS policy trusts
-- is itself a plain `set_config` the application issues
-- (`epigraph-db/src/pool.rs::SET_SESSION_GUCS`), so the application code is
-- already the party trusted to compute a claim's tenancy context. What the
-- definer adds is a boundary on WHAT a non-owner may change (the cache
-- columns only, only on a public claim it can read and cannot write, only
-- with a principal to attribute it to) and a permanent record of who did.
--
-- NOT CHANGED: every other derived table (`triples`, `entity_mentions`,
-- `claim_versions`, `challenges`, the cluster tables, ...). `challenges` is
-- deliberately out: a challenge is resolved by an UPDATE from the claim's
-- owner, which a challenger-owned row would refuse.
--
-- ===================================================================
-- 2. THE OWNER RULE (`epigraph_attach_writer_owner`, BEFORE INSERT ROW)
-- ===================================================================
--
-- SECURITY INVOKER, deliberately: its one read of `claims` is the session's
-- own RLS-filtered read, so "the session can see this claim" is asked of the
-- policy itself rather than re-derived.
--
--   (a) `writer_owned` is FORCED to false first: a caller can never declare
--       it. Only arm (e) below sets it.
--   (b) A privileged session (superuser, BYPASSRLS, `epigraph_bypass()`, or a
--       definer frame owned by `epigraph_maintenance`) is left exactly as
--       before: the row inherits the claim's tenancy through 074 and 070.
--   (c) A claim the session cannot see (RLS) or that does not exist: left to
--       074's trigger, i.e. exactly as before.
--   (d) A claim whose owning group is in the session's writable set: left as
--       before (the row inherits the claim's owner).
--   (e) A PUBLIC claim the session can see but not write: the row is owned by
--       the writer's default write group (`epigraph_writer_group()`), with
--       `visibility = 'public'` and `writer_owned = true`. Decided on the claim
--       row LOCKED `FOR NO KEY UPDATE` (`epigraph_lock_public_claim_for_attach`,
--       a definer that locks and returns a PUBLIC claim only), so an attach and
--       a privatization of the same claim serialise: whichever commits second
--       sees the other (review finding W6). A claim privatized or re-owned to a
--       writable group while the attach waited falls back to 074 and 077.
--   (f) A group-private claim the session can read but not write: left as
--       before, so 077's WITH CHECK refuses it. Writer-owned rows exist only
--       on public claims.
--
-- `epigraph_writer_group()` is the write-path owner rule of
-- `ClaimRepository::default_decl_for_author` (#503) applied to the session
-- principal (`epigraph.principal_id`): the acting operator's personal group
-- (`epigraph_operator_actor`, 107) when the principal is a live operated
-- agent, else the principal's own personal group; and ONLY when that group is
-- in the session's writable set, so the row still has to pass 077's WITH
-- CHECK on its own terms. It never mints (unlike
-- `epigraph_ensure_personal_group`): a principal with neither group writable
-- gets NULL, the row is left to 074, and 077 refuses it exactly as before. An
-- unstamped session (no principal) is therefore unchanged.
--
-- Trigger ORDER: row triggers of one kind fire in name order, and
-- `<table>_attach_writer` sorts before `<table>_require_tenancy`, whose first
-- arm returns a fully declared row untouched. Every BEFORE trigger runs before
-- the policy's WITH CHECK.
--
-- This file does NOT replace `epigraph_derived_require_tenancy`: migration 113
-- (the R2 seed escape, not yet applied everywhere) replaces that body, and
-- sqlx applies a lower unapplied version after a higher one, so a second
-- replacement here would silently revert whichever of the two landed first.
--
-- ===================================================================
-- 3. THE TWO PROPAGATION ARMS
-- ===================================================================
--
-- Both keep their SECURITY DEFINER, `SET search_path`, EXECUTE revoked from
-- PUBLIC and owner `epigraph_maintenance`, and 110's pin handling unchanged.
--
-- Arm (c) `epigraph_inherit_tenancy_stmt` (AFTER INSERT STATEMENT on every
-- derived table) re-syncs every row of the inserted rows' claims to the
-- claim's tenancy. Left alone it would re-stamp a writer-owned row to the
-- claim's (world) owner at the NEXT insert on that claim. For the three
-- writer tables it now skips `writer_owned` rows, exactly as 110 skips pinned
-- evidence. A writer-owned row exists only on a public claim (arm (e) creates
-- it public, arm (d) below un-flags it when the claim narrows), so there is
-- nothing to re-sync.
--
-- Arm (d) `epigraph_propagate_tenancy` (AFTER UPDATE STATEMENT on claims) on a
-- claim owner/visibility change:
--
--   * rows that are not writer-owned: exactly 110's statements (one extra
--     `AND NOT d.writer_owned` conjunct on the three writer tables' loop
--     iterations only). The `derived text[]` literal is byte-for-byte 072's,
--     because `epigraph_cli::operator::tables::parse_derived_array` reads it.
--   * writer-owned rows, while the claim stays PUBLIC: untouched. Their owner
--     is the writer's whoever the claim moves to, and they are already public
--     (or 'group', for pinned evidence, which 110's statement keeps).
--   * writer-owned rows, when the claim NARROWS to non-public (review finding
--     W5, a deliberate decision): they become the CLAIM's -- owner and
--     visibility follow the claim, `writer_owned` is cleared, pinned evidence
--     included. The alternative, keeping the writer as owner and narrowing only
--     the visibility, leaves rows about a private claim readable by the
--     writer's group (an operator's other agents included) and invisible to,
--     and undeletable by, the claim's own owner: disjoint, not narrower, and
--     sequestering evidence from the one party that now holds the claim.
--     Privatization's seal already encrypts every evidence row of a sealed
--     claim with the claim group's key, the writer's included, so the writer
--     loses the plaintext either way. The writer stays recorded as the row's
--     author (`evidence.signer_id`, `mass_functions.source_agent_id`); on
--     re-publication the rows follow the claim as claim-owned rows.
--   The writer-owned UPDATE runs only when a count finds a row to change, so a
--   claim change with no writer-owned row issues exactly 110's statements
--   (`tenancy_triggers.rs::propagation_is_one_pass_per_statement_not_one_per_row`
--   observes the number of UPDATEs on `evidence`).
--
-- ===================================================================
-- 4. THE OWNER GUARD (`epigraph_writer_owner_guard`, BEFORE UPDATE ROW)
-- ===================================================================
--
-- 077's policies admit an UPDATE whose OLD row is public (USING) and whose
-- NEW owner is writable (WITH CHECK), so any application session could move
-- ANY public evidence / mass function / trace row into its own group: an
-- ownership steal that was harmless while every row copied its claim (the
-- next arm-(c) re-sync put it back) and is not once arm (c) stops re-syncing
-- writer-owned rows. The guard refuses (42501) a change of `owner_group_id` or
-- `writer_owned`, and a change of `claim_id` or `visibility` on a writer-owned
-- row, from any session that is not privileged in the sense of section 2(b)
-- (review finding W7): a writer-owned row's parent and visibility track a claim
-- that is not the writer's, so the writer may not re-point it at another claim
-- (a private one included) or widen it past its claim. The dedup BBA move
-- (section 5b) is the one sanctioned claim_id change, and runs as a definer. The propagation arms, the operator CLI (hide-evidence,
-- reown) and privatization all run as `epigraph_maintenance` and are
-- unaffected. SECURITY INVOKER, so `current_user` is the role that issued the
-- UPDATE (or the maintenance owner of the definer that did).
--
-- DELETE policy: tracked separately.
--
-- ===================================================================
-- 5. THE AGGREGATE DEFINERS
-- ===================================================================
--
-- `epigraph_foreign_claim_frame(claim, frame, hypothesis_index)`: inserts the
-- claim's frame assignment OWNED BY THE CLAIM's group (never the writer's) if
-- it does not exist, and never changes an existing one; returns the
-- effective hypothesis_index.
-- `epigraph_foreign_belief_cache(claim, belief, plausibility, mass_on_empty,
-- pignistic_prob, mass_on_missing, belief_frame_id)`,
-- `epigraph_foreign_claim_classification(claim, classification,
-- belief_frame_id)` and `epigraph_foreign_belief_clear(claim)`: the three
-- writes of the DS cache. The cache carries ONE frame's combination
-- (`claims.belief_frame_id`); a non-owner refreshes it only on THAT frame and
-- never re-points it to another frame -- one it created, say, holding only its
-- own BBA -- which would replace the claim's cross-writer combination on the
-- writer's own authority. It SEEDS a cache only when every cache column is
-- NULL, and only on the canonical `binary_truth` frame: an older cache with no
-- recorded frame is "frame unknown", not "no cache" (review finding W1). A
-- refused write is a no-op returning 0, not an error: the writer's BBA is
-- stored regardless, and which frame carries the belief stays the owner's
-- decision. The clear refuses unless the cache's frame is recorded and no
-- mass function is left on the claim on any frame.
--
-- The claim-frame definer refuses (FA07, 22023) to CREATE a `binary_truth`
-- assignment at any hypothesis_index but 0 (TRUE): that index is what every
-- reader takes as the claim's own truth, and on a world claim nobody could
-- correct a non-owner's FALSE binding afterwards (review finding W2).
--
-- Each first calls `epigraph_foreign_aggregate_target(claim)`, which refuses:
--   * FA01 (42501) no session principal: nothing to attribute the write to;
--   * FA02 (P0002) "claim not found" when the claim does not exist OR the
--     session cannot read it, with the SAME text in both cases, so this is no
--     existence oracle for a private claim;
--   * FA03 (22023) a claim the session CAN write: the ordinary RLS path is the
--     one to use, and the repo layer takes it (this is defensive);
--   * FA04 (42501) a group-private claim the session can read but not write,
--     with the text 077's WITH CHECK gives, so the refusal is what it was;
--   * FA06 (42501) a principal with no writable group of its own
--     (`epigraph_writer_group()` is NULL), which the attach trigger would not
--     let attach a row either (review finding W13); 077's text again.
-- and then appends one `security_events` row (`event_type =
-- 'claims.foreign_aggregate_write'`, `agent_id` = the session principal, the
-- claim, its owning group, the action and the values before and after), in
-- the same transaction as the write. `security_events` is the channel 111
-- uses for the other cross-owner claim write (`claims.admin_write`), and is
-- append-only and immutable since 082. The claim-frame write is audited only
-- when it inserted a row, and the cache write only when a value changed.
--
-- Callers: `FrameRepository::assign_claim`,
-- `MassFunctionRepository::{update_claim_belief, update_claim_classification,
-- clear_claim_belief}`. Each takes the ordinary statement unchanged unless the
-- session is not privileged AND can read the claim AND it is public AND its
-- owner is not writable (the "foreign public" case), in which case the SAME
-- statement calls the definer instead. So an owner's, an admin's and a
-- maintenance session's write is byte-for-byte what it was.
--
-- Ownership and grants: every function here is owned by
-- `epigraph_maintenance` (so `epigraph_definer_bypass()` is true in the
-- definers), EXECUTE revoked from PUBLIC; the four aggregate definers, the
-- attach lock (5 / 2(e)), the dedup move (5b) and `epigraph_writer_group()`
-- are granted to `epigraph_app` and `epigraph_maintenance`; the legacy re-own
-- (5c) to `epigraph_maintenance` only; the target check and the audit writer
-- to nobody (only the definers, as their owner, call them). Guarded, as every
-- such block since 060 is.
--
-- RUNBOOK, before the agents move to the application role: run
-- `SELECT public.epigraph_reown_legacy_writer_bbas(<batch>)` as a maintenance
-- login until it returns 0 (section 5c). Without it, an agent that re-submits a
-- BBA it stored while its server ran privileged is refused (077 on the legacy
-- claim-owned row its upsert conflicts with).
--
-- DEPLOY ORDER: apply 114 BEFORE any binary built with it serves. The repo
-- layer's aggregate writes (`FrameRepository::assign_claim`,
-- `MassFunctionRepository::{update_claim_belief, update_claim_classification,
-- clear_claim_belief}`) call `epigraph_session_is_privileged_writer()` on EVERY
-- call, the owner's and a superuser's included, so such a binary against a
-- database below 114 fails every DS wiring with "function ... does not exist".
-- A binary built WITHOUT 114 against a database at 114 is unaffected (its
-- statements are the ones 114 leaves in place for every non-foreign session).
--
-- Undo: DROP the six triggers and thirteen functions this file creates, restore
-- 110's two arm bodies, then DROP COLUMN writer_owned on the three tables
-- (after `reown`-ing any writer-owned row whose writer should not keep it).
-- Checked before claiming: no `origin/*` ref carries a `114`; 111/112 (H-b)
-- and 113 (R2) are taken and none of them replaces a function this file does.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE MARKER COLUMN
-- ===================================================================
ALTER TABLE public.evidence
    ADD COLUMN IF NOT EXISTS writer_owned boolean NOT NULL DEFAULT false;
ALTER TABLE public.mass_functions
    ADD COLUMN IF NOT EXISTS writer_owned boolean NOT NULL DEFAULT false;
ALTER TABLE public.reasoning_traces
    ADD COLUMN IF NOT EXISTS writer_owned boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.evidence.writer_owned IS
    'Migration 114: true when this row was attached to a PUBLIC claim its writer could not write, '
    'so it is owned by the writer''s group, not the claim''s. Set only by <table>_attach_writer.';
COMMENT ON COLUMN public.mass_functions.writer_owned IS
    'Migration 114: see evidence.writer_owned.';
COMMENT ON COLUMN public.reasoning_traces.writer_owned IS
    'Migration 114: see evidence.writer_owned.';

-- ===================================================================
-- 2. THE WRITER'S GROUP, AND THE OWNER RULE
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_writer_group() RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE p uuid := public.epigraph_principal_id();
        w uuid[] := public.epigraph_writable_groups();
        g uuid;
BEGIN
    IF p IS NULL THEN RETURN NULL; END IF;
    -- #503's rule, in #503's order: the acting operator's personal group ...
    SELECT a.operator_group_id INTO g FROM public.epigraph_operator_actor(p) a;
    IF g IS NOT NULL AND g = ANY (w) THEN RETURN g; END IF;
    -- ... else the principal's own personal group. Read, never minted.
    SELECT gr.id INTO g
      FROM public.groups gr
      JOIN public.group_memberships m
        ON m.group_id = gr.id AND m.agent_id = p
       AND m.revoked_at IS NULL AND m.role IN ('admin', 'writer')
     WHERE gr.did_key = 'did:epigraph:personal:' || p::text
       AND gr.kind = 'personal'
       AND gr.created_by_agent_id = p;
    IF g IS NOT NULL AND g = ANY (w) THEN RETURN g; END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writer_group() FROM PUBLIC;

-- Section 2(b): the sessions that are left exactly as they were. Invoker, so
-- `current_user` is the caller (or the maintenance owner of a calling definer).
CREATE OR REPLACE FUNCTION public.epigraph_session_is_privileged_writer() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = public, pg_temp AS $$
DECLARE priv boolean;
BEGIN
    SELECT r.rolsuper OR r.rolbypassrls INTO priv
      FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
    IF COALESCE(priv, false) THEN RETURN true; END IF;
    IF public.epigraph_bypass() THEN RETURN true; END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        IF pg_catalog.pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER') THEN
            RETURN true;
        END IF;
    END IF;
    RETURN false;
END $$;

-- Section 2(e)'s row lock (review finding W6). Without it an attach racing a
-- privatization could commit a PUBLIC writer-owned row onto a claim that had
-- just become private: the privatizing UPDATE's arm (d) cannot see the attach's
-- uncommitted row, and arm (c) skips writer-owned rows, so nothing repairs it.
-- `FOR NO KEY UPDATE`, not `FOR SHARE`: two non-owners attaching to the same
-- claim would each hold SHARE and then each UPDATE the claim's cache through
-- the belief-cache definer, which deadlocks; NO KEY UPDATE serialises them
-- instead, and still does not conflict with the KEY SHARE an ordinary foreign
-- key check takes. A definer, so the lock does not depend on the session's
-- UPDATE policy; it returns (and locks) a PUBLIC claim only, so it is no oracle
-- for a private one. Re-evaluated on the locked version, so a claim privatized
-- while we waited comes back as no row.
CREATE OR REPLACE FUNCTION public.epigraph_lock_public_claim_for_attach(p_claim uuid)
RETURNS TABLE (o_owner uuid, o_vis character varying(16))
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT c.owner_group_id, c.visibility
      FROM public.claims c
     WHERE c.id = p_claim AND c.visibility = 'public'
       FOR NO KEY UPDATE
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_lock_public_claim_for_attach(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_attach_writer_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16); w uuid;
BEGIN
    -- (a) Never caller-declared.
    NEW.writer_owned := false;
    IF NEW.claim_id IS NULL THEN RETURN NEW; END IF;
    -- (b) Privileged: unchanged.
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    -- (c) The session's own RLS-filtered read.
    SELECT c.owner_group_id, c.visibility INTO g, v
      FROM public.claims c WHERE c.id = NEW.claim_id;
    IF NOT FOUND THEN RETURN NEW; END IF;
    -- (d) The claim is the session's to write: inherit, as before.
    IF g = ANY (public.epigraph_writable_groups()) THEN RETURN NEW; END IF;
    -- (f) Private and not writable: refused by 077 as before.
    IF v IS DISTINCT FROM 'public' THEN RETURN NEW; END IF;
    -- (e) Public, readable, not writable: the writer's row.
    w := public.epigraph_writer_group();
    IF w IS NULL THEN RETURN NEW; END IF;
    -- ... decided on the LOCKED claim row (W6). Privatized or re-owned to a
    -- writable group while we waited: left to 074, and 077 decides, as before.
    SELECT l.o_owner, l.o_vis INTO g, v
      FROM public.epigraph_lock_public_claim_for_attach(NEW.claim_id) l;
    IF NOT FOUND OR g = ANY (public.epigraph_writable_groups()) THEN RETURN NEW; END IF;
    NEW.owner_group_id := w;
    NEW.visibility     := 'public';
    NEW.writer_owned   := true;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_attach_writer_owner() FROM PUBLIC;

-- ===================================================================
-- 4. THE OWNER GUARD
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_writer_owner_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_session_is_privileged_writer() THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'epigraph tenancy: %.% changes owner_group_id or writer_owned, or the '
                    'claim_id or visibility of a writer-owned row; only a maintenance session '
                    're-owns a derived row or moves a writer-owned one', TG_TABLE_NAME, OLD.id
        USING ERRCODE = '42501';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_writer_owner_guard() FROM PUBLIC;

DO $$
DECLARE t text;
        writer_tables text[] := ARRAY['evidence','mass_functions','reasoning_traces'];
BEGIN
    FOREACH t IN ARRAY writer_tables LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', t || '_attach_writer', t);
        EXECUTE format(
          'CREATE TRIGGER %I BEFORE INSERT ON public.%I
             FOR EACH ROW EXECUTE FUNCTION public.epigraph_attach_writer_owner()',
          t || '_attach_writer', t);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', t || '_writer_owner_guard', t);
        EXECUTE format(
          'CREATE TRIGGER %I BEFORE UPDATE OF owner_group_id, writer_owned, claim_id, visibility
             ON public.%I
             FOR EACH ROW
             WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
                   OR OLD.writer_owned IS DISTINCT FROM NEW.writer_owned
                   OR (OLD.writer_owned
                       AND (OLD.claim_id IS DISTINCT FROM NEW.claim_id
                            OR OLD.visibility IS DISTINCT FROM NEW.visibility)))
             EXECUTE FUNCTION public.epigraph_writer_owner_guard()',
          t || '_writer_owner_guard', t);
    END LOOP;
END $$;

-- ===================================================================
-- 3a. ARM (d): epigraph_propagate_tenancy, writer-aware
-- ===================================================================
-- 110's body, with two changes only: the three writer tables' loop iterations
-- append `AND NOT d.writer_owned`, and the WRITER-OWNED statement follows the
-- pinned one. Everything else, the derived[] literal included, is 110's text.
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
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header; unchanged since).
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
-- 3b. ARM (c): epigraph_inherit_tenancy_stmt, writer-aware
-- ===================================================================
-- 110's body, with one change: for the three writer tables the re-sync
-- UPDATE excludes writer-owned rows, as it already excludes pinned evidence.
CREATE OR REPLACE FUNCTION public.epigraph_inherit_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE n_orphan bigint;
BEGIN
    -- ===============================================================
    -- THIS ARM IS INTENTIONALLY UNCONDITIONAL -- IT HAS NO NO-WIDENING GATE.
    -- A claim-DERIVED row is a projection of its parent claim, so "a derived
    -- row always equals its parent" IS the invariant (070's comment, in full
    -- in 110). The `IS DISTINCT FROM` below is an IDEMPOTENCE guard, not a
    -- direction guard.
    --
    -- THE TWO EXCEPTIONS:
    --   * 110: an `evidence` row an operator explicitly HID is PINNED in
    --     `evidence_visibility_pins`, and this re-sync skips it.
    --   * 114: an `evidence`, `mass_functions` or `reasoning_traces` row a
    --     writer ATTACHED to a public claim it could not write is
    --     `writer_owned`: it is the writer's, not a projection of the claim's
    --     owner, and this re-sync skips it. Only `<table>_attach_writer` sets
    --     the flag, and only a maintenance session can change it.
    -- ===============================================================
    -- NO epigraph_definer_bypass() ASSERTION HERE, DELIBERATELY (070): arm (c)
    -- fires on every ordinary application INSERT.
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
         ELSE '' END
      || CASE WHEN TG_TABLE_NAME IN ('evidence', 'mass_functions', 'reasoning_traces') THEN
             ' AND NOT t.writer_owned'
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
-- 5. THE AGGREGATE DEFINERS
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_foreign_aggregate_target(p_claim uuid)
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_owner uuid; v_vis character varying(16);
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'FA01: a non-owner write to a claim''s aggregate needs a session '
            'principal (epigraph.principal_id) to attribute it to; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    SELECT c.owner_group_id, c.visibility INTO v_owner, v_vis
      FROM public.claims c WHERE c.id = p_claim;
    -- Not found and not readable give the SAME answer: no existence oracle.
    IF NOT FOUND OR NOT (v_vis = 'public'
                         OR v_owner = ANY (public.epigraph_session_groups())) THEN
        RAISE EXCEPTION 'FA02: claim % not found', p_claim USING ERRCODE = 'P0002';
    END IF;
    IF v_owner = ANY (public.epigraph_writable_groups()) THEN
        RAISE EXCEPTION 'FA03: claim % is writable by this session; the ordinary write '
            'applies, not the non-owner aggregate path', p_claim USING ERRCODE = '22023';
    END IF;
    IF v_vis IS DISTINCT FROM 'public' THEN
        RAISE EXCEPTION 'new row violates row-level security policy for table "claims"'
            USING ERRCODE = '42501',
                  DETAIL = 'FA04: a non-owner may attach only to a PUBLIC claim';
    END IF;
    -- The attach trigger's own precondition (section 2(e)): a principal with no
    -- group of its own to write (a read-only principal) attaches nothing, so it
    -- writes no aggregate either. Same text as 077's refusal, as before 114.
    IF public.epigraph_writer_group() IS NULL THEN
        RAISE EXCEPTION 'new row violates row-level security policy for table "claims"'
            USING ERRCODE = '42501',
                  DETAIL = 'FA06: a non-owner write needs a writable group of the writer''s own';
    END IF;
    RETURN v_owner;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_foreign_aggregate_target(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_aggregate_audit(
    p_claim uuid, p_owner uuid, p_action text, p_before jsonb, p_after jsonb)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('claims.foreign_aggregate_write',
            public.epigraph_principal_id(),
            true,
            jsonb_build_object(
                'action',         p_action,
                'claim_id',       p_claim,
                'owner_group_id', p_owner,
                'writer_agent_id', public.epigraph_principal_id(),
                'writable_group_ids', to_jsonb(public.epigraph_writable_groups()),
                'before',         p_before,
                'after',          p_after,
                'migration',      114));
$$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_foreign_aggregate_audit(uuid, uuid, text, jsonb, jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_claim_frame(
    p_claim uuid, p_frame uuid, p_hypothesis_index integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_owner uuid := public.epigraph_foreign_aggregate_target(p_claim);
        v_n bigint; v_idx integer;
BEGIN
    -- The canonical `binary_truth` frame's index is what every reader takes as
    -- the claim's OWN truth (`edge_factor::resolve_hypothesis_index`,
    -- `belief_query::get_belief`; `ds_auto` is hard-wired to index 0 there).
    -- A non-owner may create that assignment only at 0 (TRUE): binding a world
    -- claim to FALSE would be permanent, because no member of the world group
    -- exists to correct it (review finding W2). `frames.name` is UNIQUE
    -- (`frames_name_key`), so the name cannot be spoofed by a second frame.
    IF COALESCE(p_hypothesis_index, 0) <> 0
       AND NOT EXISTS (SELECT 1 FROM public.claim_frames cf
                        WHERE cf.claim_id = p_claim AND cf.frame_id = p_frame)
       AND EXISTS (SELECT 1 FROM public.frames f
                    WHERE f.id = p_frame AND f.name = 'binary_truth') THEN
        RAISE EXCEPTION 'FA07: a non-owner may assign claim % to binary_truth only at '
            'hypothesis_index 0 (TRUE), not %; nothing was written', p_claim, p_hypothesis_index
            USING ERRCODE = '22023';
    END IF;
    -- Owned by the CLAIM's group: the frame assignment is the claim's, and an
    -- existing one is never changed from here.
    INSERT INTO public.claim_frames (claim_id, frame_id, hypothesis_index,
                                     owner_group_id, visibility)
    VALUES (p_claim, p_frame, p_hypothesis_index, v_owner, 'public')
    ON CONFLICT (claim_id, frame_id) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    SELECT cf.hypothesis_index INTO v_idx
      FROM public.claim_frames cf WHERE cf.claim_id = p_claim AND cf.frame_id = p_frame;
    IF v_n > 0 THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_claim, v_owner, 'claim_frame_attach', NULL,
            jsonb_build_object('frame_id', p_frame, 'hypothesis_index', v_idx));
    END IF;
    RETURN v_idx;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_foreign_claim_frame(uuid, uuid, integer) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_belief_cache(
    p_claim uuid, p_belief double precision, p_plausibility double precision,
    p_mass_on_empty double precision, p_pignistic_prob double precision,
    p_mass_on_missing double precision, p_belief_frame_id uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_owner uuid := public.epigraph_foreign_aggregate_target(p_claim);
        v_before jsonb; v_after jsonb; v_frame uuid; v_cached boolean;
BEGIN
    -- The cache carries ONE frame's combination (`belief_frame_id`). A non-owner
    -- may refresh it on THAT frame (every writer's BBAs there, recombined), or
    -- SEED it when the claim has no cache at all; it may NOT re-point it to
    -- another frame -- e.g. one it just created, holding only its own BBA --
    -- which would replace the claim's cross-writer combination on its own
    -- authority. Which frame carries a claim's belief is the owner's decision.
    -- A refused write is a no-op (0), not an error: the BBA is stored either way.
    --
    -- A cache with NO frame recorded (written before `belief_frame_id` existed:
    -- the common shape among older claims) is "frame unknown", never "no cache":
    -- treating it as seedable would let one non-owner BBA overwrite it and then
    -- own the frame (review finding W1). So a seed needs every cache column NULL,
    -- and it lands only on the canonical `binary_truth` frame, the designated
    -- summary frame; a non-owner cannot make a frame of its own choosing the one
    -- that carries a claim's belief. Backfilling `belief_frame_id` for older
    -- caches is a maintenance recompute, not this path.
    SELECT c.belief_frame_id,
           (c.belief IS NOT NULL OR c.plausibility IS NOT NULL
            OR c.pignistic_prob IS NOT NULL OR c.classification IS NOT NULL)
      INTO v_frame, v_cached
      FROM public.claims c WHERE c.id = p_claim;
    IF v_frame IS NULL THEN
        IF v_cached THEN RETURN 0; END IF;
        IF NOT EXISTS (SELECT 1 FROM public.frames f
                        WHERE f.id = p_belief_frame_id AND f.name = 'binary_truth') THEN
            RETURN 0;
        END IF;
    ELSIF v_frame IS DISTINCT FROM p_belief_frame_id THEN
        RETURN 0;
    END IF;
    -- A cached triple no mass function can represent is refused rather than
    -- stored: Bel <= BetP <= Pl (the `claims_*_bounds` checks bound each value
    -- to [0, 1] but do not order them).
    IF p_belief IS NOT NULL AND p_plausibility IS NOT NULL AND p_pignistic_prob IS NOT NULL
       AND NOT (p_belief <= p_pignistic_prob + 1e-9
                AND p_pignistic_prob <= p_plausibility + 1e-9) THEN
        RAISE EXCEPTION 'FA05: belief % / pignistic % / plausibility % is not an ordered '
            'DS triple; nothing was written', p_belief, p_pignistic_prob, p_plausibility
            USING ERRCODE = '22023';
    END IF;
    SELECT jsonb_build_object('belief', c.belief, 'plausibility', c.plausibility,
                              'pignistic_prob', c.pignistic_prob,
                              'mass_on_empty', c.mass_on_empty,
                              'mass_on_missing', c.mass_on_missing,
                              'belief_frame_id', c.belief_frame_id)
      INTO v_before FROM public.claims c WHERE c.id = p_claim;
    v_after := jsonb_build_object('belief', p_belief, 'plausibility', p_plausibility,
                                  'pignistic_prob', p_pignistic_prob,
                                  'mass_on_empty', p_mass_on_empty,
                                  'mass_on_missing', p_mass_on_missing,
                                  'belief_frame_id', p_belief_frame_id);
    UPDATE public.claims
       SET belief = p_belief, plausibility = p_plausibility, mass_on_empty = p_mass_on_empty,
           pignistic_prob = p_pignistic_prob, mass_on_missing = p_mass_on_missing,
           belief_frame_id = p_belief_frame_id, updated_at = now()
     WHERE id = p_claim;
    IF v_before IS DISTINCT FROM v_after THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_claim, v_owner, 'belief_cache', v_before, v_after);
    END IF;
    RETURN 1;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_foreign_belief_cache(
    uuid, double precision, double precision, double precision, double precision,
    double precision, uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_claim_classification(
    p_claim uuid, p_classification text, p_belief_frame_id uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_owner uuid := public.epigraph_foreign_aggregate_target(p_claim);
        v_before text; v_frame uuid;
BEGIN
    -- The verdict on the combination of `p_belief_frame_id`: written only when
    -- that is the frame the claim's cache carries (the belief-cache definer's
    -- rule), so a non-owner cannot relabel a claim from another frame.
    SELECT c.classification, c.belief_frame_id INTO v_before, v_frame
      FROM public.claims c WHERE c.id = p_claim;
    IF v_frame IS DISTINCT FROM p_belief_frame_id THEN
        RETURN 0;
    END IF;
    UPDATE public.claims SET classification = p_classification, updated_at = now()
     WHERE id = p_claim;
    IF v_before IS DISTINCT FROM p_classification THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_claim, v_owner, 'classification',
            jsonb_build_object('classification', v_before),
            jsonb_build_object('classification', p_classification));
    END IF;
    RETURN 1;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_foreign_claim_classification(uuid, text, uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_foreign_belief_clear(p_claim uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_owner uuid := public.epigraph_foreign_aggregate_target(p_claim);
        v_before jsonb; v_n bigint; v_frame uuid;
BEGIN
    -- Clears a cache only when no mass function is left on the claim on ANY
    -- frame (the retraction cascade's own precondition, re-checked here so a
    -- direct call cannot wipe a backed cache), and only a cache whose frame is
    -- recorded: an older frameless cache is "frame unknown" (see the
    -- belief-cache definer) and is left to a maintenance recompute.
    SELECT c.belief_frame_id INTO v_frame FROM public.claims c WHERE c.id = p_claim;
    IF v_frame IS NULL
       OR EXISTS (SELECT 1 FROM public.mass_functions m WHERE m.claim_id = p_claim) THEN
        RETURN 0;
    END IF;
    SELECT jsonb_build_object('belief', c.belief, 'plausibility', c.plausibility,
                              'pignistic_prob', c.pignistic_prob,
                              'classification', c.classification)
      INTO v_before FROM public.claims c WHERE c.id = p_claim;
    -- `MassFunctionRepository::clear_claim_belief`'s statement: only clears a
    -- cache that exists.
    UPDATE public.claims
       SET belief = NULL, plausibility = NULL, mass_on_empty = NULL,
           pignistic_prob = NULL, mass_on_missing = NULL,
           classification = NULL, updated_at = now()
     WHERE id = p_claim
       AND (belief IS NOT NULL OR plausibility IS NOT NULL
            OR pignistic_prob IS NOT NULL OR classification IS NOT NULL);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_claim, v_owner, 'belief_clear', v_before, NULL);
    END IF;
    RETURN v_n::integer;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_foreign_belief_clear(uuid) FROM PUBLIC;

-- ===================================================================
-- 5b. THE DEDUP BBA MOVE (review finding W4(b))
-- ===================================================================
-- `ClaimRepository::mark_duplicate_with_repair_conn` moves the edge-keyed BBAs
-- of the edges it re-targeted from the duplicate onto the canonical claim. As a
-- plain UPDATE that fails on the application role in three ways once rows can
-- be writer-owned: another writer's writer-owned BBA on the duplicate is not
-- the caller's to UPDATE (077), the owner guard refuses a writer-owned row's
-- `claim_id` change (section 4), and a moved row left claim-owned-but-unflagged
-- on a canonical the caller cannot write is re-stamped to that claim's owner by
-- the next arm-(c) insert, after which its own source agent can no longer
-- replace it. This definer does the move for a non-privileged session, bounded
-- to what a dedup may move:
--   * the session must be able to WRITE the duplicate, and the duplicate must
--     already be marked a duplicate of the canonical (`supersedes`), i.e. the
--     caller is inside a dedup it was allowed to make (FA08 otherwise);
--   * only BBAs keyed by an edge that now targets the canonical claim move;
--   * the canonical must be readable (FA02 otherwise, same text as missing);
--     if the session cannot write it, it must be public (FA04 otherwise).
-- Ownership of the moved rows, by where they land:
--   * a PUBLIC canonical the session cannot write: every moved row is
--     writer-owned and public, its owner kept (the writer's for a writer-owned
--     row, the duplicate's owner -- the deduplicating session's own group --
--     for the rest);
--   * a PUBLIC canonical the session can write: a writer-owned row keeps its
--     owner and flag, every other row takes the canonical's owner (a projection
--     of the claim, as arm (c) would make it);
--   * a non-public canonical (writable): every moved row becomes the claim's,
--     flag cleared (section 3, arm (d)'s narrowing rule).
-- Audited (`dedup_bba_move`) when the canonical is not the session's to write.
CREATE OR REPLACE FUNCTION public.epigraph_dedup_move_bbas(
    p_dup uuid, p_canonical uuid, p_perspectives uuid[])
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_w uuid[] := public.epigraph_writable_groups();
        v_dup_owner uuid; v_dup_sup uuid;
        v_c_owner uuid; v_c_vis character varying(16);
        v_c_writable boolean; v_n bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'FA01: a non-owner write to a claim''s aggregate needs a session '
            'principal (epigraph.principal_id) to attribute it to; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    SELECT c.owner_group_id, c.supersedes INTO v_dup_owner, v_dup_sup
      FROM public.claims c WHERE c.id = p_dup;
    IF NOT FOUND OR NOT (v_dup_owner = ANY (v_w)) OR v_dup_sup IS DISTINCT FROM p_canonical THEN
        RAISE EXCEPTION 'FA08: claim % is not a duplicate of % that this session may move '
            'BBAs from; nothing was written', p_dup, p_canonical USING ERRCODE = '42501';
    END IF;
    SELECT c.owner_group_id, c.visibility INTO v_c_owner, v_c_vis
      FROM public.claims c WHERE c.id = p_canonical;
    IF NOT FOUND OR NOT (v_c_vis = 'public'
                         OR v_c_owner = ANY (public.epigraph_session_groups())) THEN
        RAISE EXCEPTION 'FA02: claim % not found', p_canonical USING ERRCODE = 'P0002';
    END IF;
    v_c_writable := v_c_owner = ANY (v_w);
    IF NOT v_c_writable AND v_c_vis IS DISTINCT FROM 'public' THEN
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'FA04: a non-owner may attach only to a PUBLIC claim';
    END IF;

    UPDATE public.mass_functions mf
       SET claim_id       = p_canonical,
           owner_group_id = CASE
                              WHEN NOT v_c_writable THEN mf.owner_group_id
                              WHEN v_c_vis = 'public' AND mf.writer_owned THEN mf.owner_group_id
                              ELSE v_c_owner END,
           visibility     = v_c_vis,
           writer_owned   = CASE
                              WHEN v_c_vis IS DISTINCT FROM 'public' THEN false
                              WHEN NOT v_c_writable THEN true
                              ELSE mf.writer_owned END
     WHERE mf.claim_id = p_dup
       AND mf.perspective_id = ANY (p_perspectives)
       AND EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = mf.perspective_id
                      AND e.target_id = p_canonical AND e.target_type = 'claim');
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 AND NOT v_c_writable THEN
        PERFORM public.epigraph_foreign_aggregate_audit(
            p_canonical, v_c_owner, 'dedup_bba_move',
            jsonb_build_object('from_claim_id', p_dup),
            jsonb_build_object('moved', v_n));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) FROM PUBLIC;

-- ===================================================================
-- 5c. LEGACY BBAs: RE-OWN TO THEIR SOURCE AGENT (review finding W3)
-- ===================================================================
-- A BBA stored before this file by a privileged session on a public claim is
-- owned by the claim's group (typically the world group) and not flagged. Its
-- own source agent, once on the application role, cannot REPLACE it:
-- `MassFunctionRepository::store_with_perspective` upserts on (claim, frame,
-- source agent, perspective), the ON CONFLICT DO UPDATE lands on that legacy
-- row, and 077's WITH CHECK refuses its owner. This re-owns such rows to what
-- section 2(e) would have made them: owned by the source agent's operator's
-- personal group (the `operator_links` record, retired links included:
-- `epigraph_operator_of_author`, the "whose are this author's rows?" read), else
-- by the agent's own personal group; public; `writer_owned = true`. Only rows
-- that are still a projection of a PUBLIC claim whose owning group the source
-- agent holds no live writer/admin membership in. A row whose agent has neither
-- group stays as it is.
--
-- MAINTENANCE ONLY (EXECUTE granted to `epigraph_maintenance` alone), and NOT
-- run by this migration: privileged servers keep writing claim-owned BBAs until
-- the agents move to the application role, so it is run IMMEDIATELY BEFORE that
-- move (and may be re-run: it is idempotent). `p_limit` bounds one call, for a
-- large table under a short lock_timeout; NULL means all. Returns the number of
-- rows re-owned and writes one `security_events` row per call that changed any.
CREATE OR REPLACE FUNCTION public.epigraph_reown_legacy_writer_bbas(p_limit integer DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_n bigint;
BEGIN
    WITH base AS (
        SELECT mf.id, c.owner_group_id AS c_owner,
               COALESCE(
                 (SELECT o.operator_group_id
                    FROM public.epigraph_operator_of_author(mf.source_agent_id) o
                   ORDER BY o.retired, o.operator_id LIMIT 1),
                 (SELECT g.id FROM public.groups g
                   WHERE g.did_key = 'did:epigraph:personal:' || mf.source_agent_id::text
                     AND g.kind = 'personal'
                     AND g.created_by_agent_id = mf.source_agent_id)) AS w
          FROM public.mass_functions mf
          JOIN public.claims c ON c.id = mf.claim_id
         WHERE NOT mf.writer_owned
           AND mf.source_agent_id IS NOT NULL
           AND c.visibility = 'public'
           AND mf.visibility = 'public'
           AND mf.owner_group_id = c.owner_group_id
           AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                            WHERE m.group_id = c.owner_group_id
                              AND m.agent_id = mf.source_agent_id
                              AND m.revoked_at IS NULL
                              AND m.role IN ('admin', 'writer'))
    ), cand AS (
        SELECT b.id, b.w FROM base b
         WHERE b.w IS NOT NULL AND b.w <> b.c_owner
         ORDER BY b.id
         LIMIT p_limit
    )
    UPDATE public.mass_functions mf
       SET owner_group_id = cand.w, writer_owned = true
      FROM cand
     WHERE mf.id = cand.id;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('derived.legacy_writer_reown', NULL, true,
                jsonb_build_object('table', 'mass_functions', 'rows', v_n,
                                   'limit', p_limit, 'migration', 114));
    END IF;
    RETURN v_n;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_reown_legacy_writer_bbas(integer) FROM PUBLIC;

-- ===================================================================
-- 6. OWNERSHIP AND GRANTS
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_inherit_tenancy_stmt() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_writer_group() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_session_is_privileged_writer() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_attach_writer_owner() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_writer_owner_guard() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_aggregate_target(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_aggregate_audit(uuid, uuid, text, jsonb, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_claim_frame(uuid, uuid, integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_belief_cache(uuid, double precision, '
                'double precision, double precision, double precision, double precision, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_claim_classification(uuid, text, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_foreign_belief_clear(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_lock_public_claim_for_attach(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_reown_legacy_writer_bbas(integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lock_public_claim_for_attach(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_reown_legacy_writer_bbas(integer) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_writer_group() TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_claim_frame(uuid, uuid, integer) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_belief_cache(uuid, '
                'double precision, double precision, double precision, double precision, '
                'double precision, uuid) TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_claim_classification(uuid, text, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_belief_clear(uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_writer_group() TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_claim_frame(uuid, uuid, integer) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_belief_cache(uuid, '
                'double precision, double precision, double precision, double precision, '
                'double precision, uuid) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_claim_classification(uuid, text, uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_foreign_belief_clear(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_lock_public_claim_for_attach(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_dedup_move_bbas(uuid, uuid, uuid[]) '
                'TO epigraph_app';
    END IF;
END $$;
