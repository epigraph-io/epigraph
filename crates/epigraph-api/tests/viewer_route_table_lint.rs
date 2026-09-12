//! Source lint implementing PR-07 acceptance criterion #1:
//! *"no handler that returns claim content lacks a `ViewerExtractor`
//! (route-table test)"*.
//!
//! # Why this file exists
//!
//! PR-07 originally cited `public_router_allowlist.rs` as the verification for
//! that criterion. It is not: that test asserts public-vs-protected router
//! *membership* and makes no assertion whatsoever about `ViewerExtractor`
//! presence on handlers. The criterion was asserted only in prose — and it was
//! false, with two live counterexamples in `belief.rs` (`claims_by_belief`,
//! which had no `ViewerExtractor` at all, and `frame_claims_sorted`, which held
//! one and never filtered on it). Both are fixed; this file is the ratchet that
//! stops the class recurring.
//!
//! # Why a source lint and not a runtime route-table walk
//!
//! axum erases handler signatures into boxed `Handler` impls at registration
//! time, so a `Router` cannot be asked at runtime which extractors a handler
//! declared. The property is only visible in the source. That makes this a
//! grep with a spine rather than an integration test, and it is deliberately
//! written to fail loudly with the offending file, line and snippet rather than
//! to report a bare count.
//!
//! # What it actually checks
//!
//! **The real invariant is not "a handler mentions `ViewerExtractor`" — that is
//! trivially satisfiable and was satisfied by `frame_claims_sorted` while it
//! leaked.** The invariant is that no claim-content read happens in the route
//! layer at all. Content reads live in `crates/epigraph-db/src/repos/`, where
//! the `/* {VISIBILITY:...} */` marker convention applies and
//! `Viewer::splice`'s missing-marker panic can enforce it. A handler cannot
//! splice a predicate into SQL it does not own.
//!
//! So: **no `sqlx::query*` call in `crates/epigraph-api/src/routes/` may select
//! claim content**, except for the sites on the dated exemption list below.
//! Checking the structural property (where the SQL lives) rather than the
//! syntactic one (does the word `ViewerExtractor` appear) is what makes this
//! lint catch the defect that motivated it.
//!
//! # Two ways this lint was blind, and how it is measured now
//!
//! The first revision of this file **could not have caught `frame_claims_sorted`
//! either**, despite the paragraph above claiming that is what it is for. Two
//! independent holes, both closed in PR-07's follow-up:
//!
//! 1. **It scanned only FORWARD from the `sqlx::query*` token**, over a fixed
//!    2500-byte window. `frame_claims_sorted`'s shape is
//!    `let query = format!(…); … sqlx::query_as(&query)` — the SQL literal sits
//!    ABOVE the call, so the window never saw it. Replayed against
//!    `origin/integration/tenancy` the old algorithm scored `belief.rs: 1`,
//!    counting the one inline literal and missing the `format!` one. The hole
//!    was still live in PR-07's own tree: `routes/search.rs` builds `full_sql`
//!    with `format!` and calls `sqlx::query(&full_sql)`, and the old lint
//!    measured `search.rs: 0`.
//!
//!    [`resolved_region`] now resolves `sqlx::query*(&ident)` back to the
//!    `let <ident> = …` binding above it and scans that too.
//!    [`a_format_built_statement_is_counted`] pins the fix.
//!
//! 2. **`reads_claim_content` recognised one table and one column** — `claims`
//!    plus a bare `content` token — so it could not see reads of `evidence`,
//!    `challenges.explanation`, `claim_versions.content`, `claims.properties`
//!    or `claims.embedding`. PR-07's own acceptance criteria cover all of
//!    those: embeddings are treated as approximately invertible to content,
//!    and challenge `explanation`s are criterion #3's subject. It now
//!    recognises the `tier_a` projections.
//!
//! # And the fixed window is gone
//!
//! The 2500-byte forward window also **over**-counted: it swept up whatever
//! statement happened to follow. `conventions.rs`'s `SELECT labels FROM claims`
//! was charged as a content read because the handler's `content: claim.content`
//! response field sat eleven lines below it, and `reasoning.rs` was charged 2
//! for an in-file `#[cfg(test)]` INSERT fixture. Those are false positives, and
//! a debt register full of them is not a register — it is noise that makes the
//! real entries unreviewable, which is the same failure the entries' own
//! justification had.
//!
//! [`arg_region`] replaces the window with the call's balanced-paren argument
//! region, skipping string literals so SQL parens cannot unbalance it. The
//! region is therefore exactly the statement, and every entry below was
//! hand-checked against its source line.
//!
//! # The numbers below were RE-BASELINED, not raised
//!
//! Widening the predicate and fixing the scan is a redefinition of the
//! measurement, not a regression in the tree. The counts were re-derived under
//! the new measurement on **2026-09-02**; the ratchet is monotone from that
//! baseline forward. Fixing the newly-surfaced sites is PR-12/PR-14/PR-16 work.

mod lint_text;

use lint_text::strip_comments;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Counted `tier_a` reads that are **`#[cfg(test)]` read-backs**, not handler
/// reads. As measured on **2026-09-04**.
///
/// # This register replaces `COMPENSATED_INLINE_READS`, and PR-14 is why
///
/// The old constant was `[("claims.rs", 3), ("edges.rs", 4)]`, justified as
/// "inline `tier_a` reads whose second line of defence is the per-row
/// `check_content_access` pass". **PR-14 deleted `check_content_access`**, so
/// that justification could not survive this commit in any form: there is no
/// compensating control left to name.
///
/// The previous revision of this doc was explicit that it had never actually
/// checked the claim it was making — *"this comment asserts only that the file
/// CONTAINS `check_content_access` calls — NOT that the call sits on the return
/// path of the specific counted statement. Establishing that per site is
/// PR-14's job, and claiming it here without checking is how the previous
/// version of this paragraph went wrong."* That determination is now done, and
/// it found something better than expected on both files.
///
/// **`edges.rs` 4 → 0.** All four statements moved into the repo layer, where
/// they carry a marker and are spliced with a `Viewer`:
/// `get_evidence`'s evidence projection and `evidence_by_relationship`'s
/// edge⋈evidence join became `EvidenceRepository::detail_by_id` and
/// `::by_relationship_for_claim`; `claim_provenance`'s `SELECT id, content,
/// trace_id FROM claims` became `ClaimRepository::get_by_id`; and
/// `build_evidence_chains`'s evidence lookup now reuses `detail_by_id`. Three
/// of those four were **genuinely uncompensated in the old sense too** — their
/// rows came from raw viewerless SQL and `check_content_access` was the only
/// control on them — which is why deleting the pass without moving them would
/// have shipped a disclosure rather than a cleanup. The file leaves the
/// register entirely rather than moving between halves.
///
/// Read "4 → 0" as **all four COUNTED statements**, which is the only thing
/// this lint measures. `measure_inline_claim_content_reads` matches the
/// `tier_a` *claim-content* column set and nothing else, so three inline reads
/// survive in `edges.rs::claim_provenance` that it has never counted and still
/// does not: two `SELECT target_id FROM edges …` projections (edge columns) and
/// one `SELECT id, reasoning_type, confidence FROM reasoning_traces WHERE id =
/// $1`. `reasoning_traces` IS a tier_a table (062 lists it; 070 carries it), and
/// `ReasoningTraceRepository::get_by_id(pool, viewer, id)` is the filtered form —
/// but it returns a parsed `Methodology` enum where the handler formats a raw
/// `reasoning_type` string, so swapping it changes a response field and can turn
/// an unrecognised value into a 500. That is a behaviour change, not a move, and
/// PR-14 does not make it: the read is pre-existing, the deleted pass never
/// covered it, and it is filed as `D-PR16-claim-provenance-trace-read-unfiltered`
/// in `docs/tenancy/progress.json`. Stated here because a security ratchet whose
/// prose over-claims its own measurement is how the previous revision of this
/// file went wrong.
///
/// **`claims.rs` 3 → 3, but they are not what the register said they were.**
/// The three counted statements are at `claims.rs` lines 2193, 2241 and 2668,
/// and every one of them is inside `#[cfg(all(test, feature = "db"))] mod
/// db_tests` (which spans 2025..EOF). They are `SELECT properties FROM claims
/// WHERE id = $1` read-backs that assert a write landed. They were never
/// handler reads, so they were never "compensated" by a runtime pass — and they
/// are not a disclosure surface at all. `measure_inline_claim_content_reads`
/// does not exclude `#[cfg(test)]` (unlike
/// `epigraph-mcp/tests/no_inline_sql_in_tools.rs`, which counts test and
/// production sites in separate columns), so they must stay registered
/// SOMEWHERE or the exact-set assertion fails on a correct tree. This constant
/// is that somewhere, named for what they actually are.
///
/// The count is asserted exactly, so this ratchet stays monotone: adding a new
/// inline `tier_a` read fails the build, and removing one fails it too until
/// the number here is lowered. Do not raise it.
const TEST_ONLY_INLINE_READS: &[(&str, usize)] = &[("claims.rs", 3)];

/// The register entries with **no filter and, since PR-14, no post-pass
/// anywhere in the tree**.
///
/// Thirteen handler sites across eight files read `tier_a` claim content inline
/// in the route layer with no `Viewer` spliced into the statement. Before PR-14
/// the register carried the sentence *"Deadline **PR-12**, not PR-14: these
/// become live disclosure the moment ownership is transcribed into the tenancy
/// columns, with nothing behind them."* That prediction is not stale — it has
/// come true, and PR-14 is the commit that removes any ambiguity about it:
///
/// * PR-12 landed the transcription, so the condition the sentence named is
///   satisfied for every row the backfill has reached.
/// * `docs/deploy.md` now makes running `epigraph-tenancy-backfill` to
///   completion a **prerequisite** of shipping this release, so the condition is
///   satisfied for the rest by the time it deploys.
/// * PR-14 deleted `check_content_access`, the pass these sites were once
///   (wrongly — see the note on [`TEST_ONLY_INLINE_READS`]) believed to sit
///   behind. There is now nothing behind them at all.
///
/// So this is a live-disclosure register, not a latent one, and the deadline it
/// carries is **overdue since PR-12** rather than pending. PR-14 does not
/// discharge it: the plan's *Files* line scopes this PR to deleting redaction,
/// and converting thirteen handlers in eight unrelated files is a different
/// change with a different blast radius. The owner is recorded on
/// `open_findings::F-inline-claim-content-reads` in
/// `docs/tenancy/progress.json` (proposed: PR-16, which already owns the
/// write-side predicate for the same files).
///
/// This list is a debt register, not a permission slip. Every entry is a
/// handler. Do not add to it — move the statement into
/// `crates/epigraph-db/src/repos/`, mark it, and splice a `Viewer`.
const UNCOMPENSATED_INLINE_READS: &[(&str, usize)] = &[
    ("clusters.rs", 2),
    ("conflicts.rs", 1),
    // `cross_source.rs` was 1 until PR-09 and is now 0, so it is gone from the
    // register entirely. The site was `SELECT id, content FROM claims WHERE id
    // = ANY($1)` in `list_candidates`, hydrating excerpts for the candidate
    // queue; it is now
    // `ClaimRepository::contents_by_ids(&state.db_pool, &viewer, ..)`. PR-09
    // also removed the file's other unfiltered read — the `CORROBORATES` edge
    // scan in `get_cross_source_matches`, which this lint never counted because
    // it projects edge columns, not `tier_a` content — into
    // `MatchCandidateRepo::corroborates_edges_for_claim`. Both were byte-for-byte
    // duplicates of SQL in `epigraph-mcp/src/tools/matching.rs`; there is now
    // one copy, in the repo layer, filtered.
    ("embeddings.rs", 1),
    ("hypothesis.rs", 1),
    ("policies.rs", 2),
    ("political.rs", 1),
    // `search.rs`'s remaining site is the `format!`-built `full_sql` the old
    // forward-only scan could not see. Its in-code comment argues it is not a
    // live leak — the ids come from the viewer-filtered
    // `ClaimThemeRepository::claims_in_themes_at_dim_since`, which splices
    // `{VISIBILITY:c}` onto the joined `claims` (PR-29 re-pointed the route at
    // that repo method directly; it previously named the engine wrapper
    // `candidates_in_themes_at_dim`, whose body was the same call) — and that
    // derivation looks sound. It is
    // registered anyway: the argument is a caller-side invariant with nothing
    // enforcing it, which is precisely the kind of reasoning this register
    // exists to keep visible rather than to accept silently.
    ("search.rs", 1),
    ("workflows.rs", 4),
];

/// Fail-open scope-check sites: `if let Some(..) = auth_ctx { check_scopes(..) }`
/// with no `else`, which performs no authorization at all when `AuthContext` is
/// absent. Originally measured on **2026-09-02**.
///
/// The plan's §4.13 puts this at 39; the verbatim idiom counted 37 in the tree
/// after PR-07 converted `crud.rs::get_theme_embeddings` (see the PR-07 entry in
/// `docs/tenancy/progress.json` for the full reconciliation). PR-10 removed
/// `webhooks.rs`'s 2 and PR-18a removed `audit.rs`'s 1, leaving **34
/// occurrences of the idiom** across 7 files. The remainder are predominantly
/// **write** paths and were assigned to PR-16.
///
/// # THIS REGISTER COUNTS SCOPE CHECKS ONLY (PR-16, delivered as 16b)
///
/// It used to count every occurrence of the `if let` LINE, and its doc comment
/// claimed to be measuring `if let Some(..) = auth_ctx { check_scopes(..) }`.
/// Those are not the same set. Classifying all 34 blocks by BODY shows **24
/// contain a scope call** (`check_scopes(` or `has_scope(`) and **10 contain
/// only `record_provenance(`** — no authorization of any kind.
///
/// That made a security ratchet walkable DOWNWARD by deleting a provenance
/// call: a diff that removes an audit-trail write, fixing zero authorization,
/// would have read as an improvement here. A register that can be satisfied by
/// deleting something unrelated to the control it names is the same defect
/// class this whole lint exists to catch — it looks like a control and gates
/// nothing.
///
/// The fix is ADDITIVE, not a needle rewrite: the 10 provenance blocks move to
/// [`AUTH_OPTIONAL_PROVENANCE_SITES`], the historical total is preserved by
/// [`the_registers_sum_to_the_verbatim_idiom`], and a conversion that
/// touches both kinds of block in one handler now decrements two different
/// constants instead of one ambiguous one.
///
/// # The "34" above is the PRE-WIDENING population and is no longer the total
///
/// Both paragraphs above were written when the scanner recognised ONE spelling
/// of the idiom. It now recognises four (see [`AUTH_CTX_NEEDLES`]), and the
/// population is **35**: 24 scope + 10 provenance + 1
/// [`AUTH_OPTIONAL_WRITE_SITES`]. The 24 and the 10 survive unchanged — the
/// extra block is `agents.rs::create_agent`'s OAuth-client arm, which the old
/// needle could not see. **The tree did not change**; the scanner's vision did,
/// and the two are recorded separately on purpose. The 34 is left in place
/// rather than overwritten because the argument those paragraphs make is about
/// the SPLIT, and rewriting the number would erase the evidence that the split
/// was lossless when it was made.
///
/// Asserted exactly for the same monotonicity reason as above.
const FAIL_OPEN_SCOPE_SITES: &[(&str, usize)] = &[
    ("agent_keys.rs", 3),
    // 1 → 2 when the needle set widened from one spelling to four. NOT a new
    // site and NOT a regression: `create_agent`'s `agents:write` check is
    // written `if let Some(axum::Extension(ref auth)) = &auth_ctx` — the same
    // idiom with a trailing `&` on the scrutinee — and the single-spelling
    // needle could not see it. The block was always here; the register could
    // not count it.
    ("agents.rs", 2),
    // `("audit.rs", 1)` REMOVED by PR-18a, on the PR-10 precedent recorded
    // below: `query_security_events` now takes the prescribed
    // `let Some(..) = auth_ctx else { return Err(ApiError::Unauthorized ..) }`
    // shape and checks `audit:read` unconditionally, so the file measures 0.
    // Removed rather than set to `0` for the reason the PR-10 note gives — the
    // register is compared as a whole `BTreeMap` and a `0` row would never match.
    //
    // PR-18a is a schema shard and did not set out to convert a handler. It
    // converted this one because migration 083 recreates `security_events_read`,
    // the sole per-principal narrowing on the table this route reads, and a
    // fail-open scope check on the caller-facing end of a policy being widened in
    // the same commit is not a debt worth carrying forward one more PR.
    ("claims.rs", 1),
    // 7 before PR-16/16b. `update_evidence` moved its `raw_content` UPDATE into
    // `EvidenceRepository::update_raw_content` behind the write-side predicate,
    // and took the prescribed
    // `let Some(..) = auth_ctx else { return Err(ApiError::Unauthorized ..) }`
    // shape on the way. Its `record_provenance` block is a SEPARATE `if let`
    // and is deliberately untouched — it is still counted, in the other
    // register, where the count stays 4.
    ("crud.rs", 6),
    ("edges.rs", 5),
    ("papers.rs", 1),
    ("tasks.rs", 6),
    // `("webhooks.rs", 2)` REMOVED by PR-10, which converted both sites in
    // `delete_webhook` to the prescribed
    // `auth_ctx.ok_or(ApiError::Unauthorized { .. })?` shape and made the scope
    // check unconditional. Removed rather than set to `0`: this constant is
    // compared as a whole `BTreeMap` against `measure_fail_open_scope_sites`,
    // which only inserts a key when its count is non-zero, so a `0` row is a
    // key the measurement can never produce and the assertion would fail on a
    // correct fix.
];

/// The other half of the 34: `if let Some(..) = auth_ctx { record_provenance(..) }`
/// blocks that contain NO scope call.
///
/// **These are not fail-open authorization.** They are auth-OPTIONAL provenance:
/// the handler writes an audit-trail row when it has an `AuthContext` and skips
/// it when it does not. The residual is a missing audit record, not an
/// unauthorized write — a real gap, but a different one, and it is not fixed by
/// the `let Some(..) else { return Err(Unauthorized) }` shape
/// [`FAIL_OPEN_SCOPE_SITES`]'s failure message prescribes.
///
/// Registered separately rather than dropped, because the shape IS worth
/// watching: a handler whose only use of `auth_ctx` is optional provenance has
/// no authorization at all, and finding a NEW one is usually the sign of a new
/// unauthenticated write path. It is a debt register, not a permission slip.
const AUTH_OPTIONAL_PROVENANCE_SITES: &[(&str, usize)] = &[
    ("agents.rs", 1),
    ("claims.rs", 1),
    ("crud.rs", 4),
    ("edges.rs", 4),
];

/// The third shape: `if let Some(..) = auth_ctx { .. Repository::.. }` blocks
/// that neither check a scope nor record provenance.
///
/// # This register arrived with a wider needle, not with a new handler
///
/// It is empty against the single-spelling needle and has one entry against the
/// four-spelling set, and **the tree did not change**. The entry is
/// `agents.rs::create_agent`'s OAuth-client auto-provisioning arm, spelled
/// `if let Some(axum::Extension(auth)) = &auth_ctx` — no `ref`, trailing `&` —
/// which the old needle could not see. `AuthCtxBlock::Unclassified`'s own doc
/// already said a block fitting neither register "must be classified
/// deliberately rather than fall into either register by default"; widening the
/// needle produced exactly that case, so this is the deliberate classification.
///
/// # What the shape means, and what it is NOT
///
/// It is not a fail-open scope check: no authorization happens in the block
/// either way. It is not auth-optional provenance: no audit row is written. It
/// is an effect that occurs only when a principal is present and silently does
/// not occur when one is absent. Worth its own register because a NEW entry is
/// usually a persistence path that has quietly become conditional on
/// authentication.
///
/// # The `create_agent` entry, and its compensating control
///
/// `create_agent` declares no `ViewerExtractor`, so the route-level statement
/// that its `agents:write` check is unconditional does not come from the
/// handler's signature. It comes from the router: `POST /agents` and
/// `POST /api/v1/agents` are registered on the `protected` router in
/// `routes/mod.rs::create_router`, which is layered with `bearer_auth_middleware`
/// — a total function that either injects an `AuthContext` or returns
/// `Unauthorized`. The two-route public allowlist does not include them, and
/// `public_router_allowlist.rs` pins that over both router variants. So on this
/// route `auth_ctx` is always `Some` when the handler runs.
///
/// That control is ROUTER-LEVEL and order-independent. An earlier revision of
/// this register stated it here only, while
/// [`fail_open_scope_check_sites_do_not_increase`]'s failure message — the text
/// a contributor actually reads when a row reddens — still attributed the safety
/// to "a `ViewerExtractor` earlier in the same signature 401s first", which makes
/// an authz control depend on axum parameter ORDER. Measured against the router
/// table that is a weaker claim than the tree supports, and believing it a
/// contributor could "fix" a row by reordering extractors and change nothing.
/// **That message now carries the router-level statement itself**; this
/// paragraph is the cross-reference, not the only copy. Two doc comments under
/// `src/routes/` still carry the superseded framing — they are pre-existing and
/// out of this batch's scope, recorded so the correction is not later assumed
/// complete.
///
/// # The classifier's authorization predicate is a two-spelling allowlist
///
/// [`classify_auth_ctx_block`] recognises only `check_scopes(` and `has_scope(`.
/// A block that spells its check some third way AND reaches the repo layer files
/// HERE rather than in [`AuthCtxBlock::Unclassified`] — that is, under a heading
/// that says no authorization happens in the block either way. It still errs
/// safe, because this register is an exact set and a new entry reddens the
/// build; but a NEW row must be read for an authorization call the classifier
/// does not recognise before it is accepted as benign.
const AUTH_OPTIONAL_WRITE_SITES: &[(&str, usize)] = &[("agents.rs", 1)];

/// `UPDATE`/`DELETE` statements against a tenancy-scoped table, issued from a
/// route handler.
///
/// # Why this is its own register and not a row in the write-gate lint
///
/// The remedy here is never "add a marker". A handler does not own its SQL, so
/// it **cannot** carry a `/* {WRITABLE:<alias>} */` marker no matter how many
/// extractors it declares — the same structural argument
/// [`UNCOMPENSATED_INLINE_READS`] makes for reads, and the reason that register
/// checks WHERE the SQL lives rather than whether the word `ViewerExtractor`
/// appears. Every row here must first MOVE to `crates/epigraph-db/src/repos/`;
/// only then can it be gated. `crates/epigraph-db/tests/write_gate_lint.rs`
/// picks it up on the other side.
///
/// # crud.rs is absent, and that is this PR's decrement
///
/// It measured 1 — `update_evidence`'s inline
/// `UPDATE evidence SET raw_content = $2 WHERE id = $1`, whose own comment read
/// `no repo method exists yet`. PR-16 (delivered as 16b) moved it to
/// `EvidenceRepository::update_raw_content` behind the write predicate, so the
/// file measures 0. Removed rather than set to `0` for the reason the PR-10 note
/// on [`FAIL_OPEN_SCOPE_SITES`] gives: the register is compared as a whole
/// `BTreeMap` and a `0` row is a key the measurement can never produce.
///
/// # KNOWN UNDER-MEASUREMENT, stated rather than hidden
///
/// [`sqlx_call_offsets`] requires INVOCATION syntax — `sqlx::query(` — so
/// `sqlx::query!` MACRO writes are not counted. `submit.rs` has one
/// (`UPDATE claims SET trace_id = …`), which is why its count here is 4 and a
/// plain grep of the file finds 5. The exclusion is inherited from the read-side
/// scan, where it is what keeps prose out of the count, and it is left in place
/// rather than special-cased: a macro write is unspliceable by construction and
/// belongs in `write_gate_lint.rs::MACRO_WRITE_SITES`, whose remedy is a
/// different mechanism. [`the_route_write_scanner_is_not_vacuous`] pins this
/// behaviour so it stays a known limit rather than becoming an accident.
///
/// Everything else is debt. Do not add to it.
const ROUTE_LAYER_WRITES: &[(&str, usize)] = &[
    ("assess.rs", 1),
    ("belief.rs", 1),
    ("claims.rs", 4),
    ("computation.rs", 2),
    ("conventions.rs", 2),
    ("hypothesis.rs", 2),
    ("policies.rs", 4),
    ("rag.rs", 2),
    ("reasoning.rs", 2),
    ("revoke_signature.rs", 1),
    // 4, not 5: the fifth is a `sqlx::query!` macro — see the note above.
    ("submit.rs", 4),
    ("workflows.rs", 4),
];

/// Tenancy-scoped tables whose route-layer writes this lint counts.
///
/// Duplicated from `write_gate_lint.rs::WRITE_GATED_TABLES` because an
/// integration test in one crate cannot import one in another.
///
/// **NOTHING CROSS-CHECKS THE TWO COPIES.** An earlier revision of this comment
/// claimed they were "cross-checked by that file's subset assertion against
/// `TIER_A`". That was false twice over: the assertion in question reads only
/// the *other* file's copy — it lives in the `epigraph-db` test binary and
/// cannot see this constant at all, which is the very reason the constant is
/// duplicated — and at the time the claim was written the two lists were not
/// even equal. This copy carried 8 tables; the other carried 10.
///
/// The claim was worse than the divergence it papered over. A divergent register
/// under-measures; a comment asserting a machine check that does not exist stops
/// the next reader from looking, which is the same failure this whole PR exists
/// to reject — a control that reads like a control and checks nothing.
///
/// The two lists are now equal by hand, and `claim_versions` /
/// `harvester_fragments` are carried here even though
/// `grep -rnE '(UPDATE|DELETE FROM) (public\.)?(claim_versions|harvester_fragments)'`
/// over `src/routes/` currently returns nothing. They are a no-op today and
/// correct the day a handler writes one. **Keep them equal by hand, and expect
/// no test to tell you when you have not.**
const WRITE_GATED_TABLES: &[&str] = &[
    "challenges",
    "claim_versions",
    "claims",
    "edges",
    "evidence",
    "frames",
    "harvester_fragments",
    "mass_functions",
    "perspectives",
    "recall_events",
];

/// Does `region` issue an `UPDATE`/`DELETE` against a scoped table?
///
/// The trailing-character check is load-bearing: `crud.rs` writes
/// `UPDATE edges_staging`, a staging table that carries no tenancy columns at
/// all, and a prefix match would charge it as `edges` — inflating a security
/// register with a row no conversion can remove, and hiding this PR's actual
/// decrement behind it.
fn writes_scoped_table(region: &str) -> bool {
    for table in WRITE_GATED_TABLES {
        for verb in [
            format!("UPDATE {table}"),
            format!("UPDATE public.{table}"),
            format!("DELETE FROM {table}"),
            format!("DELETE FROM public.{table}"),
        ] {
            let mut from = 0usize;
            while let Some(rel) = region[from..].find(&verb) {
                let at = from + rel;
                from = at + verb.len();
                let tail = region[at + verb.len()..].chars().next();
                if tail.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                return true;
            }
        }
    }
    false
}

fn measure_route_layer_writes() -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let mut n = 0usize;
        for at in sqlx_call_offsets(&src) {
            if writes_scoped_table(&resolved_region(&src, at)) {
                n += 1;
            }
        }
        if n > 0 {
            counts.insert(name, n);
        }
    }
    counts
}

fn routes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

/// Every file under `src/routes/`, as `(file name, **comment-stripped** source)`.
///
/// # Why the source is stripped, and what it cost
///
/// Every scanner in this file — the two `auth_ctx` registers, the verbatim
/// idiom total, [`measure_route_layer_writes`] and
/// [`measure_inline_claim_content_reads`] — is a substring search, and all of
/// them read their source through here. Unstripped, they could not tell a site
/// from a doc comment QUOTING one. That is not hypothetical: PR-10 fixed both
/// `webhooks.rs` fail-open sites, documented the idiom it had removed in
/// `delete_webhook`'s doc comment, and the ratchet went red with
/// `webhooks.rs: expected 0, found 1 [REGRESSION]`. The workaround was to
/// misspell the idiom in prose. A lint that a comment can break teaches
/// contributors not to name the thing they are documenting, which is the
/// opposite of what these registers are for.
///
/// **Stripping moved no number here.** Measured over `src/routes/` before the
/// change: the verbatim total (33), both register `BTreeMap`s, the
/// `Unclassified` count (0), `ROUTE_LAYER_WRITES` and the inline-read map are
/// byte-identical stripped and unstripped. So this closes a hazard without
/// re-baselining a ratchet — the two are different events and conflating them
/// is how a ratchet stops meaning anything.
///
/// The direction that would be dangerous is the other one: a stripper that ate
/// real code would lower every register at once and stay lowered silently. See
/// `lint_text::strip_comments` for why that argument has to be made per caller
/// rather than inherited.
fn route_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(routes_dir()).expect("read routes dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        let body = strip_comments(&std::fs::read_to_string(&path).expect("read route file"));
        out.push((name, body));
    }
    out.sort();
    assert!(
        out.len() > 40,
        "expected the routes directory to hold the whole HTTP surface, found {} files — \
         the lint is probably looking in the wrong place and would pass vacuously",
        out.len()
    );
    out
}

/// Byte offsets of every `sqlx::query`/`query_as`/`query_scalar` **invocation**.
///
/// The tail after `sqlx::query` must open a call — `(`, or a turbofish that
/// eventually does. Requiring invocation syntax is what keeps prose out of the
/// count: `// Row types for sqlx::query_as` in `graph_query_utils.rs` is a bare
/// mention, and an early version of this lint charged it as a violation because
/// the 2500-byte window downstream of it swept up a doc comment that quotes the
/// very SQL this PR deleted.
fn sqlx_call_offsets(src: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find("sqlx::query") {
        let at = from + rel;
        from = at + "sqlx::query".len();

        // Skip the `_as` / `_scalar` suffix, then any turbofish, then require `(`.
        let mut tail = &src[from..];
        for suffix in ["_as", "_scalar"] {
            if let Some(rest) = tail.strip_prefix(suffix) {
                tail = rest;
                break;
            }
        }
        let tail = tail.trim_start();
        let opens_call = if let Some(rest) = tail.strip_prefix("::<") {
            // Turbofish: find its close, then require `(`.
            rest.find('>')
                .is_some_and(|gt| rest[gt + 1..].trim_start().starts_with('('))
        } else {
            tail.starts_with('(')
        };
        if opens_call {
            out.push(at);
        }
    }
    out
}

/// The balanced-paren argument region of the `sqlx::query*` call at `at`.
///
/// This replaces the old fixed 2500-byte forward window, which both
/// over-counted (it swept up whatever statement followed) and under-counted
/// (see [`resolved_region`]). String literals — normal and raw — are skipped so
/// that parentheses inside the SQL text cannot unbalance the depth count.
fn arg_region(src: &str, at: usize) -> &str {
    let b = src.as_bytes();
    let Some(open) = src[at..].find('(').map(|i| at + i) else {
        return &src[at..];
    };
    let n = src.len();
    let mut j = open + 1;
    let mut depth = 1usize;
    while j < n && depth > 0 {
        // Raw string: r"…", r#"…"#, r##"…"##
        if b[j] == b'r' && j + 1 < n && (b[j + 1] == b'#' || b[j + 1] == b'"') {
            let mut k = j + 1;
            let mut hashes = 0usize;
            while k < n && b[k] == b'#' {
                hashes += 1;
                k += 1;
            }
            if k < n && b[k] == b'"' {
                let mut term = String::from('"');
                for _ in 0..hashes {
                    term.push('#');
                }
                j = match src[k + 1..].find(&term) {
                    Some(e) => k + 1 + e + term.len(),
                    None => n,
                };
                continue;
            }
        }
        match b[j] {
            b'"' => {
                let mut k = j + 1;
                while k < n {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        break;
                    }
                    k += 1;
                }
                j = k + 1;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    // Clamp to a char boundary: route files contain non-ASCII in comments.
    let mut e = j.min(n);
    while e > open && !src.is_char_boundary(e) {
        e -= 1;
    }
    &src[open..e]
}

/// Extract `ident` from an argument region shaped `(&ident` / `(&ident,`.
fn borrowed_ident(region: &str) -> Option<&str> {
    let rest = region.strip_prefix('(')?.trim_start();
    let rest = rest.strip_prefix('&')?.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let ident = &rest[..end];
    let tail = rest[end..].trim_start();
    if tail.starts_with(',') || tail.starts_with(')') {
        Some(ident)
    } else {
        None
    }
}

/// The region to scan for one `sqlx::query*` call.
///
/// [`arg_region`] plus — when the sole SQL argument is a borrowed local, i.e.
/// `sqlx::query(&sql)` — the text of the `let <ident> = …` binding that built
/// it. That is the `frame_claims_sorted` shape: `let query = format!(…);` above
/// the call, invisible to any forward-only scan.
fn resolved_region(src: &str, at: usize) -> String {
    let region = arg_region(src, at);
    let Some(ident) = borrowed_ident(region) else {
        return region.to_string();
    };

    // The LAST `let <ident>` before the call: with two functions each binding
    // `sql`, the one in scope is the nearer one.
    let head = &src[..at];
    let mut best: Option<usize> = None;
    let mut from = 0usize;
    while let Some(rel) = head[from..].find("let ") {
        let pos = from + rel;
        from = pos + 4;
        let after = head[pos + 4..].trim_start();
        let after = after.strip_prefix("mut ").map_or(after, str::trim_start);
        if let Some(rest) = after.strip_prefix(ident) {
            if !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                best = Some(pos);
            }
        }
    }
    match best {
        Some(pos) => format!("{}{region}", &src[pos..at]),
        None => region.to_string(),
    }
}

/// `tier_a` tables whose projections this lint treats as claim content.
///
/// Migration 062 puts all four in its `tier_a` array, so all four carry
/// `visibility`/`owner_group_id` and all four are filterable today.
const CONTENT_TABLES: &[&str] = &["claims", "evidence", "challenges", "claim_versions"];

/// Column names that carry, or are approximately invertible to, claim content.
///
/// `explanation` is `challenges`' content column and is acceptance criterion
/// #3's subject; `embedding` is included because PR-07's own acceptance
/// criteria treat a raw vector as approximately invertible to the text it
/// encodes (that is why `/themes/:id/embeddings` returns none); `properties`
/// carries free-text payloads (`hypothesis_status`, `scope_limitations`,
/// evidence captions) and was the field `hypothesis_status` leaked alongside
/// `content`.
const CONTENT_COLUMNS: &[&str] = &["content", "explanation", "properties", "embedding"];

/// Does this region read `tier_a` content?
///
/// Deliberately over-approximate on the SQL side (any of [`CONTENT_TABLES`] in
/// a FROM/JOIN plus any of [`CONTENT_COLUMNS`] as a bare token) and precise on
/// the scan side. A false positive here costs one register entry; a false
/// negative costs a leak.
fn reads_claim_content(region: &str) -> bool {
    let low = region.to_ascii_lowercase();
    let touches = CONTENT_TABLES
        .iter()
        .any(|t| low.contains(&format!("from {t}")) || low.contains(&format!("join {t}")));
    if !touches {
        return false;
    }
    low.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| CONTENT_COLUMNS.contains(&tok))
}

fn measure_inline_claim_content_reads() -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let mut n = 0usize;
        for at in sqlx_call_offsets(&src) {
            if reads_claim_content(&resolved_region(&src, at)) {
                n += 1;
            }
        }
        if n > 0 {
            counts.insert(name, n);
        }
    }
    counts
}

/// Every spelling of the optional-`AuthContext` idiom, shared by all registers
/// so they cannot drift to different definitions of "the site".
///
/// # This was ONE spelling, and the ratchet was monotone only against it
///
/// The single needle was `if let Some(axum::Extension(ref auth)) = auth_ctx`.
/// `routes/agents.rs::create_agent` writes the same idiom two ways that needle
/// misses — with a trailing `&` on the scrutinee, and without the `ref` — so a
/// site could be introduced, or an existing one re-spelled, and the register
/// would not move. A ratchet that tracks a transcription rather than a shape is
/// walkable by a rename.
///
/// # Every needle must stay anchored on `if let`, and that is not a style rule
///
/// `src/routes/` holds roughly fifty occurrences of the bare substring
/// `Some(axum::Extension(`, and about eighteen of them are the PRESCRIBED FIXED
/// SHAPE these registers exist to push handlers towards:
/// `let Some(axum::Extension(ref auth)) = auth_ctx else { return Err(ApiError::Unauthorized { .. }) }`.
/// Widening to the bare substring would charge the correct shape into a
/// fail-open register, so a conversion would make the number go UP. The `if let`
/// prefix is what distinguishes "the block is skipped when auth is absent" from
/// "the request is refused when auth is absent".
///
/// # The four spellings are pairwise non-overlapping, so counting is sound
///
/// No needle here is a substring of another — `= auth_ctx` is not a substring of
/// `= &auth_ctx`, and `(auth))` is not a substring of `(ref auth))` — so
/// [`measure_verbatim_auth_ctx_idiom`] can sum `matches().count()` across the set
/// without double-charging one site. A FIFTH spelling added later must preserve
/// that property or the total silently over-counts.
const AUTH_CTX_NEEDLES: &[&str] = &[
    "if let Some(axum::Extension(ref auth)) = auth_ctx",
    "if let Some(axum::Extension(ref auth)) = &auth_ctx",
    "if let Some(axum::Extension(auth)) = auth_ctx",
    "if let Some(axum::Extension(auth)) = &auth_ctx",
];

/// The brace-balanced block starting at the first `{` at or after `from`.
///
/// String literals (normal and raw) and line comments are skipped, so a brace
/// inside SQL text or inside a comment cannot unbalance the depth count — the
/// same care [`arg_region`] takes with parentheses, for the same reason.
///
/// Returns the remainder of the source when the block never closes, which makes
/// an unbalanced file over-count rather than silently classify as `Other`.
fn balanced_block(src: &str, from: usize) -> &str {
    let b = src.as_bytes();
    let n = src.len();
    let Some(start) = src[from..].find('{').map(|i| from + i) else {
        return &src[from..];
    };
    let mut j = start;
    let mut depth = 0usize;
    while j < n {
        // Raw string: r"…", r#"…"#, r##"…"##
        if b[j] == b'r' && j + 1 < n && (b[j + 1] == b'#' || b[j + 1] == b'"') {
            let mut k = j + 1;
            let mut hashes = 0usize;
            while k < n && b[k] == b'#' {
                hashes += 1;
                k += 1;
            }
            if k < n && b[k] == b'"' {
                let mut term = String::from('"');
                for _ in 0..hashes {
                    term.push('#');
                }
                j = match src[k + 1..].find(&term) {
                    Some(e) => k + 1 + e + term.len(),
                    None => n,
                };
                continue;
            }
        }
        match b[j] {
            b'"' => {
                let mut k = j + 1;
                while k < n {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        break;
                    }
                    k += 1;
                }
                j = k + 1;
                continue;
            }
            b'\'' if j + 2 < n && b[j + 2] == b'\'' => {
                // A char literal such as `'{'`. Skip it wholesale.
                j += 3;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let mut e = j + 1;
                    while e < n && !src.is_char_boundary(e) {
                        e += 1;
                    }
                    return &src[start..e];
                }
            }
            _ => {}
        }
        j += 1;
    }
    &src[start..]
}

/// What one `if let Some(..) = auth_ctx { .. }` block actually does.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum AuthCtxBlock {
    /// The block calls `check_scopes(` or `has_scope(` — a real authorization
    /// decision, skipped entirely when `AuthContext` is absent.
    ScopeCheck,
    /// The block calls `record_provenance(` and performs no scope check — an
    /// audit-trail write, not authorization.
    ProvenanceOnly,
    /// The block reaches the repo layer and performs neither a scope check nor a
    /// provenance write: **auth-optional persistence**. Something is written
    /// when an `AuthContext` is present and silently not written when it is
    /// absent.
    ///
    /// This category was introduced by the needle widening, not by a change to
    /// any handler. It exists because the widening surfaced a block that fits
    /// neither of the other two and [`AuthCtxBlock::Unclassified`] must stay
    /// empty to keep working as a sentinel.
    AuthOptionalWrite,
    /// None of the above. **Deliberately kept empty**: a block that binds the
    /// principal and then neither authorizes, nor audits, nor persists is a
    /// shape no register describes, and is most often what is left behind when
    /// the body of a check is deleted. A new one must be classified
    /// deliberately rather than fall into a register by default.
    Unclassified,
}

/// Classify every occurrence of an [`AUTH_CTX_NEEDLES`] spelling by its block
/// body.
///
/// The order of the arms is the priority order, and it is load-bearing. A block
/// containing BOTH a scope call and a provenance call is a
/// [`AuthCtxBlock::ScopeCheck`]: the authorization is the property worth
/// tracking, and charging it to the provenance register would let a real
/// fail-open hide behind an audit write. By the same argument a block that
/// checks a scope AND persists is a `ScopeCheck` — it is not auth-optional at
/// all, because the scope check refuses before the write.
///
/// [`AuthCtxBlock::AuthOptionalWrite`] is keyed on a repo-layer call
/// (`Repository::`) rather than on "uses the principal for something". That is
/// deliberate: a predicate as loose as "mentions `auth.`" would swallow a block
/// whose only use of the principal is a `tracing::debug!` field, and with it the
/// `Unclassified` sentinel. Requiring a persistence call keeps the third
/// category about an EFFECT that does or does not happen.
fn classify_auth_ctx_block(block: &str) -> AuthCtxBlock {
    if block.contains("check_scopes(") || block.contains("has_scope(") {
        AuthCtxBlock::ScopeCheck
    } else if block.contains("record_provenance(") {
        AuthCtxBlock::ProvenanceOnly
    } else if block.contains("Repository::") {
        AuthCtxBlock::AuthOptionalWrite
    } else {
        AuthCtxBlock::Unclassified
    }
}

/// Per-file counts of `auth_ctx` blocks matching `kind`, over every spelling in
/// [`AUTH_CTX_NEEDLES`].
fn measure_auth_ctx_sites(kind: AuthCtxBlock) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let mut n = 0usize;
        for needle in AUTH_CTX_NEEDLES {
            let mut from = 0usize;
            while let Some(rel) = src[from..].find(needle) {
                let at = from + rel;
                from = at + needle.len();
                if classify_auth_ctx_block(balanced_block(&src, at)) == kind {
                    n += 1;
                }
            }
        }
        if n > 0 {
            counts.insert(name, n);
        }
    }
    counts
}

fn measure_fail_open_scope_sites() -> BTreeMap<String, usize> {
    measure_auth_ctx_sites(AuthCtxBlock::ScopeCheck)
}

fn measure_auth_optional_provenance_sites() -> BTreeMap<String, usize> {
    measure_auth_ctx_sites(AuthCtxBlock::ProvenanceOnly)
}

fn measure_auth_optional_write_sites() -> BTreeMap<String, usize> {
    measure_auth_ctx_sites(AuthCtxBlock::AuthOptionalWrite)
}

/// Total occurrences of the idiom in every spelling, unclassified.
///
/// This is what [`measure_fail_open_scope_sites`] counted before PR-16/16b split
/// the register, and it is preserved so the split can be proved lossless.
/// Summing across [`AUTH_CTX_NEEDLES`] is sound because no needle is a substring
/// of another — see that constant's doc.
fn measure_verbatim_auth_ctx_idiom() -> usize {
    route_files()
        .iter()
        .map(|(_, src)| {
            AUTH_CTX_NEEDLES
                .iter()
                .map(|n| src.matches(n).count())
                .sum::<usize>()
        })
        .sum()
}

/// The binder-agnostic substring every spelling of the idiom must contain.
///
/// [`AUTH_CTX_NEEDLES`] cannot be widened to this — it would charge the
/// PRESCRIBED refusal shapes into a fail-open register — but it is exactly the
/// right population to take a CENSUS over. See
/// [`every_auth_ctx_occurrence_has_a_recognised_shape`].
const AUTH_CTX_BARE: &str = "Some(axum::Extension(";

/// Byte offsets of every [`AUTH_CTX_BARE`] occurrence.
fn auth_ctx_offsets(src: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(AUTH_CTX_BARE) {
        let at = from + rel;
        out.push(at);
        from = at + AUTH_CTX_BARE.len();
    }
    out
}

/// A bounded, char-boundary-safe forward window. Route files carry non-ASCII in
/// their box-drawing section comments, so a naive slice can panic.
fn window_after(src: &str, from: usize, len: usize) -> &str {
    let mut e = (from + len).min(src.len());
    while e > from && !src.is_char_boundary(e) {
        e -= 1;
    }
    &src[from..e]
}

/// The SYNTACTIC shape an [`AUTH_CTX_BARE`] occurrence sits in, decided without
/// consulting [`AUTH_CTX_NEEDLES`] at all.
///
/// Independence from the needle set is the whole point: it is what lets
/// [`every_auth_ctx_occurrence_has_a_recognised_shape`] compare a shape-derived
/// count against a needle-derived one and catch a spelling the needles miss.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum AuthCtxShape {
    /// `if let Some(axum::Extension(..)) = auth_ctx { .. }` — the conditional
    /// shape the three registers measure. Every occurrence of this shape MUST
    /// be found by [`AUTH_CTX_NEEDLES`] or a fail-open is invisible to all
    /// three.
    IfLet,
    /// `let Some(axum::Extension(..)) = auth_ctx else { return Err(..) }` — the
    /// prescribed refusal these registers push handlers towards.
    LetElse,
    /// `match auth_ctx { Some(axum::Extension(..)) => .., None => .. }` whose
    /// arms include a `return Err(`. Equivalent in effect to `LetElse`: the
    /// request is refused when the principal is absent.
    MatchArmRefusing,
    /// Anything else — including a `match` arm whose sibling `None` arm does
    /// NOT refuse, which is a fail-open written as a `match` and is exactly as
    /// invisible to the three registers as an unenumerated `if let` binder.
    /// **Must stay empty**, for the same reason
    /// [`AuthCtxBlock::Unclassified`] must.
    Unknown,
}

/// Classify one [`AUTH_CTX_BARE`] occurrence by the syntax around it.
///
/// The prefix tests are ordered longest-first because `"if let"` and
/// `"while let"` both end with `"let"`; reversing them would file every `if let`
/// site as a prescribed refusal and empty the fail-open registers silently.
fn classify_auth_ctx_shape(src: &str, at: usize) -> AuthCtxShape {
    let before = src[..at].trim_end();
    if before.ends_with("if let") {
        return AuthCtxShape::IfLet;
    }
    if before.ends_with("while let") {
        // Not a shape this tree uses. Routed to `Unknown` deliberately rather
        // than to `LetElse` by the trailing-`let` test below.
        return AuthCtxShape::Unknown;
    }
    // `at + AUTH_CTX_BARE.len() - 1` is the `(` that opens `Extension(`, but
    // `arg_region` wants the OUTER one: `at + 4` is the `(` of `Some(`, and it
    // is the first `(` at or after `at`, so the region it returns starts there.
    let end = at + 4 + arg_region(src, at).len();
    if before.ends_with("let") {
        return if window_after(src, end, 200)
            .split('{')
            .next()
            .unwrap_or("")
            .contains("else")
        {
            AuthCtxShape::LetElse
        } else {
            // `let Some(..) = ..;` with no `else` is not a refusal. Whatever it
            // is, it is not a shape any register describes.
            AuthCtxShape::Unknown
        };
    }
    if window_after(src, end, 8).trim_start().starts_with("=>") {
        // A `match` arm. It is a refusal only if the match as a whole refuses —
        // a `None => None` arm is a fail-open wearing a different syntax, and
        // classifying every match arm as a refusal would be precisely the
        // "control that reports safety it does not check" defect.
        let Some(m) = src[..at].rfind("match ") else {
            return AuthCtxShape::Unknown;
        };
        if at - m > 200 {
            return AuthCtxShape::Unknown;
        }
        let arms = balanced_block(src, m);
        if arms.contains("None") && arms.contains("return Err(") {
            return AuthCtxShape::MatchArmRefusing;
        }
        return AuthCtxShape::Unknown;
    }
    AuthCtxShape::Unknown
}

fn expected(list: &[(&str, usize)]) -> BTreeMap<String, usize> {
    list.iter().map(|(f, n)| ((*f).to_string(), *n)).collect()
}

/// Report the exact per-file delta, so a failure names the file to look at
/// rather than only a total that moved.
fn diff_report(actual: &BTreeMap<String, usize>, want: &BTreeMap<String, usize>) -> String {
    let mut lines = Vec::new();
    let mut files: Vec<&String> = actual.keys().chain(want.keys()).collect();
    files.sort();
    files.dedup();
    for f in files {
        let a = actual.get(f).copied().unwrap_or(0);
        let w = want.get(f).copied().unwrap_or(0);
        if a != w {
            let verdict = if a > w { "REGRESSION" } else { "improved" };
            lines.push(format!("  {f}: expected {w}, found {a}  [{verdict}]"));
        }
    }
    lines.join("\n")
}

#[test]
fn no_new_inline_claim_content_reads_in_the_route_layer() {
    let actual = measure_inline_claim_content_reads();
    let mut want = expected(TEST_ONLY_INLINE_READS);
    want.extend(expected(UNCOMPENSATED_INLINE_READS));
    assert_eq!(
        actual,
        want,
        "\n\nPR-07 acceptance #1 ratchet failed.\n{}\n\n\
         A `sqlx::query*` call in crates/epigraph-api/src/routes/ selects \
         `tier_a` content (claims / evidence / challenges / claim_versions, \
         projecting content / explanation / properties / embedding). Route \
         handlers cannot carry a `/* {{VISIBILITY:...}} */` marker, so such a \
         read is unfilterable by a `Viewer` no matter how many extractors the \
         handler declares — `frame_claims_sorted` held a viewer and leaked \
         anyway, which is why this lint checks WHERE the SQL lives rather than \
         whether the word `ViewerExtractor` appears.\n\n\
         Fix: move the statement into crates/epigraph-db/src/repos/, add the \
         marker, and call `viewer.splice`. If you have genuinely removed a \
         site, LOWER the number in TEST_ONLY_INLINE_READS or \
         UNCOMPENSATED_INLINE_READS. Never raise it.\n",
        diff_report(&actual, &want)
    );
}

/// The two registers must not both claim the same file.
///
/// A file cannot have its counted statements be simultaneously test-only and
/// unfiltered-production, and a stray duplicate would silently drop one of the
/// two counts when the maps are merged — turning the ratchet's exact-count
/// assertion into an under-count.
#[test]
fn the_two_registers_are_disjoint() {
    for (f, _) in TEST_ONLY_INLINE_READS {
        assert!(
            !UNCOMPENSATED_INLINE_READS.iter().any(|(g, _)| g == f),
            "{f} appears in both registers"
        );
    }
}

/// **The self-test for the blind spot that made the first revision of this file
/// unable to catch the defect it was written for.**
///
/// `frame_claims_sorted`'s shape was `let query = format!(…); … sqlx::query_as(&query)`:
/// the SQL literal ABOVE the call, invisible to a forward-only scan. Without
/// this test nothing stops that hole reopening — a future refactor of
/// [`resolved_region`] would go green against the current tree and quietly stop
/// measuring the very shape the module doc claims it catches.
///
/// The fixture is a synthetic source string rather than a real file, so the
/// test cannot be made to pass by editing the routes directory.
#[test]
fn a_format_built_statement_is_counted() {
    let forward = r#"
        let rows = sqlx::query_as("SELECT c.content FROM claims c WHERE c.id = $1")
            .bind(id).fetch_all(pool).await?;
    "#;
    assert_eq!(
        sqlx_call_offsets(forward).len(),
        1,
        "the inline form must still be recognised as a call"
    );
    assert!(
        reads_claim_content(&resolved_region(forward, sqlx_call_offsets(forward)[0])),
        "an inline literal must still be counted"
    );

    let deferred = r#"
        let query = format!("SELECT c.content FROM claims c ORDER BY {sort}");
        let rows = sqlx::query_as(&query).bind(id).fetch_all(pool).await?;
    "#;
    let offsets = sqlx_call_offsets(deferred);
    assert_eq!(offsets.len(), 1, "the deferred form is still one call");
    assert!(
        reads_claim_content(&resolved_region(deferred, offsets[0])),
        "a `let sql = format!(..); sqlx::query_as(&sql)` statement MUST be \
         counted — this is the `frame_claims_sorted` shape, and a forward-only \
         scan scores it clean. If this assertion is failing, the lint has \
         regressed to measuring less than its own doc comment claims."
    );

    // …and the argument region must not bleed into the NEXT statement: this is
    // the over-counting half, which charged `conventions.rs` for a
    // `SELECT labels FROM claims` because a `content:` response field followed.
    let bleed = r#"
        let labels = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(id).fetch_one(pool).await?;
        Ok(Json(Response { content: claim.content }))
    "#;
    let offsets = sqlx_call_offsets(bleed);
    assert_eq!(offsets.len(), 1);
    assert!(
        !reads_claim_content(&resolved_region(bleed, offsets[0])),
        "a non-content statement must not be charged because a later line \
         mentions `content`"
    );

    // A raw string carrying unbalanced-looking SQL parens must not derail the
    // region scan.
    let raw =
        "let rows = sqlx::query_as(r#\"SELECT c.content FROM claims c WHERE (a > 1)\"#).bind(x);";
    let offsets = sqlx_call_offsets(raw);
    assert_eq!(offsets.len(), 1);
    assert!(reads_claim_content(&resolved_region(raw, offsets[0])));
}

#[test]
fn fail_open_scope_check_sites_do_not_increase() {
    let actual = measure_fail_open_scope_sites();
    let want = expected(FAIL_OPEN_SCOPE_SITES);
    assert_eq!(
        actual,
        want,
        "\n\nFail-open scope-check ratchet failed.\n{}\n\n\
         `if let Some(axum::Extension(ref auth)) = auth_ctx {{ check_scopes(..) }}` \
         performs NO authorization when `AuthContext` is absent. Where it is \
         currently harmless, that is because the ROUTE is registered on the \
         `protected` router in `routes/mod.rs::create_router`, which is layered \
         with `bearer_auth_middleware` — a total function whose every arm either \
         injects an `AuthContext` or returns `Unauthorized`, and whose two-route \
         public allowlist `public_router_allowlist.rs` pins over both router \
         variants. That control is router-level and ORDER-INDEPENDENT.\n\n\
         So reordering axum extractors changes NOTHING here, and moving a route \
         off `protected` changes everything. Do not read this register as a \
         parameter-order problem.\n\n\
         Fix: `let auth = auth_ctx.ok_or(ApiError::Unauthorized {{ .. }})?.0;` \
         then check scopes unconditionally (see \
         `crud.rs::get_theme_embeddings`). Then LOWER the number here.\n",
        diff_report(&actual, &want)
    );
}

#[test]
fn route_layer_writes_to_scoped_tables_do_not_increase() {
    let actual = measure_route_layer_writes();
    let want = expected(ROUTE_LAYER_WRITES);
    assert_eq!(
        actual,
        want,
        "\n\nRoute-layer write ratchet failed.\n{}\n\n\
         A `sqlx::query*` call in crates/epigraph-api/src/routes/ issues an \
         `UPDATE`/`DELETE` against a tenancy-scoped table. A handler cannot \
         carry a `/* {{WRITABLE:...}} */` marker — it does not own the SQL — so \
         such a write is ungateable by a `Viewer` no matter what the handler's \
         signature declares.\n\n\
         Fix: move the statement into crates/epigraph-db/src/repos/, add the \
         marker, call `viewer.splice_write(..)`, and bind \
         `viewer.writable_bind()`. See `crud.rs::update_evidence` → \
         `EvidenceRepository::update_raw_content`. Then LOWER the number here. \
         Never raise it.\n",
        diff_report(&actual, &want)
    );
}

/// **The self-test for the route-write scanner**, over synthetic source.
///
/// Without it, a refactor of [`writes_scoped_table`] could go green against the
/// current tree while quietly measuring nothing — the failure this whole PR
/// exists to avoid, reproduced inside its own ratchet. The fixtures are strings,
/// so this cannot be satisfied by editing the routes directory.
#[test]
fn the_route_write_scanner_is_not_vacuous() {
    let inline = r#"sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1").bind(id);"#;
    let offsets = sqlx_call_offsets(inline);
    assert_eq!(offsets.len(), 1);
    assert!(
        writes_scoped_table(&resolved_region(inline, offsets[0])),
        "an inline scoped-table UPDATE must be counted"
    );

    // The `frame_claims_sorted` shape on the write side: statement built above
    // the call. A forward-only scan scores it clean.
    let deferred = r#"
        let sql = format!("DELETE FROM claims WHERE id = ANY($1) {extra}");
        let _ = sqlx::query(&sql).bind(ids).execute(pool).await;
    "#;
    let offsets = sqlx_call_offsets(deferred);
    assert_eq!(offsets.len(), 1);
    assert!(
        writes_scoped_table(&resolved_region(deferred, offsets[0])),
        "a `let sql = format!(..); sqlx::query(&sql)` write MUST be counted"
    );

    // `edges_staging` carries no tenancy columns. Charging it as `edges` would
    // inflate the register with a row no conversion can remove — and would have
    // hidden this PR's crud.rs decrement behind it.
    let staging = r#"sqlx::query("UPDATE edges_staging SET state = 'done' WHERE id = $1");"#;
    let offsets = sqlx_call_offsets(staging);
    assert_eq!(offsets.len(), 1);
    assert!(
        !writes_scoped_table(&resolved_region(staging, offsets[0])),
        "`UPDATE edges_staging` must not be charged as `UPDATE edges`"
    );

    // A READ on a scoped table is not a write.
    let read = r#"sqlx::query_as("SELECT id FROM claims WHERE id = $1").bind(id);"#;
    let offsets = sqlx_call_offsets(read);
    assert!(!writes_scoped_table(&resolved_region(read, offsets[0])));

    // The documented under-measurement: a macro write is not an invocation the
    // offset scan recognises. Asserted so the limit is a decision on record
    // rather than a surprise the next reader has to rediscover.
    let macro_write = "sqlx::query!(\"UPDATE claims SET trace_id = $1 WHERE id = $2\", t, id);";
    assert!(
        sqlx_call_offsets(macro_write).is_empty(),
        "`sqlx::query!` is deliberately outside this scan — see the \
         ROUTE_LAYER_WRITES doc comment. If this now returns a site, the \
         register is under-stated and submit.rs must go 4 → 5."
    );
}

/// `crud.rs` must not grow an inline scoped-table write again.
///
/// A targeted guard beside the count, on the precedent of
/// [`the_two_handlers_pr07_fixed_stay_fixed`]: a revert of PR-16's conversion
/// should fail by NAME and not only by a total moving, because the total can be
/// held constant by an unrelated deletion elsewhere in the file.
///
/// # The window is self-sizing, and it has to be
///
/// An earlier revision took a FIXED 2600-byte window. That number covered the
/// handler with 94 bytes to spare — the next `\npub async fn ` (the
/// `#[cfg(not(feature = "db"))]` stub of the same name) began 2506 bytes in — so
/// the `!window.contains("UPDATE evidence")` assertion was as strong as it read,
/// but only by that margin, and in the wrong direction on both sides: 95 bytes
/// of new code inside the handler would have pushed the tail of the function out
/// of the window and let an inline `UPDATE evidence` return unseen, while the
/// bytes it DID cover past the handler belonged to a neighbouring function.
/// A guard whose correctness depends on a hand-tuned byte count silently stops
/// guarding the day someone adds a line. The window now ends where the next
/// item begins.
#[test]
fn update_evidence_routes_through_the_gated_repo_fn() {
    let src = std::fs::read_to_string(routes_dir().join("crud.rs")).expect("read crud.rs");
    let at = src
        .find("pub async fn update_evidence")
        .expect("update_evidence handler still exists");
    // From the handler to the start of the next top-level item, whatever its
    // length. `\npub ` is the item boundary in this file; falling back to EOF
    // keeps the last handler in the file covered rather than empty.
    let head = at + "pub async fn update_evidence".len();
    let rest = &src[head..];
    // The EARLIEST boundary of either spelling, not the first one tried: the
    // `#[cfg(not(feature = "db"))]` stub of this same handler is introduced by
    // its attribute, so keying only on `\npub ` would pull that attribute line
    // into the window.
    let end = [rest.find("\npub "), rest.find("\n#[cfg(")]
        .into_iter()
        .flatten()
        .min()
        .map_or(src.len(), |rel| head + rel);
    let window = &src[at..end];
    assert!(
        window.len() > 400,
        "the self-sized window collapsed to {} bytes — the item-boundary search \
         matched inside the handler instead of after it, and every assertion \
         below would pass vacuously",
        window.len()
    );

    assert!(
        window.contains("EvidenceRepository::update_raw_content"),
        "update_evidence no longer routes through the write-gated repo fn; \
         holding a Viewer and issuing the UPDATE inline is the exact fail-open \
         PR-16 (delivered as 16b) fixed"
    );
    assert!(
        !window.contains("UPDATE evidence"),
        "update_evidence has an inline `UPDATE evidence` again"
    );
    assert!(
        window.contains("ViewerExtractor"),
        "update_evidence lost its ViewerExtractor, so the repo call cannot be \
         supplying a real write authority"
    );
}

#[test]
fn auth_optional_provenance_sites_do_not_increase() {
    let actual = measure_auth_optional_provenance_sites();
    let want = expected(AUTH_OPTIONAL_PROVENANCE_SITES);
    assert_eq!(
        actual,
        want,
        "\n\nAuth-optional provenance ratchet failed.\n{}\n\n\
         `if let Some(axum::Extension(ref auth)) = auth_ctx {{ record_provenance(..) }}` \
         writes an audit-trail row when an `AuthContext` is present and silently \
         writes nothing when it is not. That is NOT a fail-open scope check — \
         there is no scope check in the block at all — which is why it is \
         counted here and not in FAIL_OPEN_SCOPE_SITES.\n\n\
         A NEW entry usually means a new write path that performs no \
         authorization whatsoever, so read it as that before reading it as an \
         audit gap.\n",
        diff_report(&actual, &want)
    );
}

/// The split of the old single register must be LOSSLESS.
///
/// Before PR-16/16b, `FAIL_OPEN_SCOPE_SITES` counted every occurrence of
/// an [`AUTH_CTX_NEEDLES`] spelling regardless of what the block did. This asserts that the
/// two registers still account for exactly those occurrences and nothing else,
/// so the split cannot have quietly dropped a site — the failure mode that would
/// turn a security ratchet into a smaller number that means less.
///
/// The `Unclassified` assertion is the sharp half: a block that neither checks a
/// scope, nor records provenance, nor persists anything is a shape no register
/// describes, and it must be classified deliberately in a diff rather than
/// vanish from every total.
///
/// **The sum is over THREE registers since the needle widened.** It was two, and
/// the third was added rather than relaxing `unclassified == 0` to `== 1` —
/// which would have turned the sentinel off to accommodate the one case it
/// correctly caught.
#[test]
fn the_registers_sum_to_the_verbatim_idiom() {
    let scope: usize = measure_fail_open_scope_sites().values().sum();
    let prov: usize = measure_auth_optional_provenance_sites().values().sum();
    let write: usize = measure_auth_optional_write_sites().values().sum();
    let unclassified: usize = measure_auth_ctx_sites(AuthCtxBlock::Unclassified)
        .values()
        .sum();
    let verbatim = measure_verbatim_auth_ctx_idiom();

    assert_eq!(
        unclassified, 0,
        "an `if let Some(..) = auth_ctx {{ .. }}` block calls none of \
         `check_scopes(`/`has_scope(`, `record_provenance(`, or a \
         `Repository::` method. It binds the principal and then does nothing \
         with it that any register describes — which is what a deleted check \
         leaves behind. Decide which register it belongs in and say so, rather \
         than leaving it where no ratchet watches it."
    );
    assert_eq!(
        scope + prov + write,
        verbatim,
        "the registers no longer account for every occurrence of the \
         idiom ({scope} scope + {prov} provenance + {write} auth-optional write \
         != {verbatim} verbatim). The split of the pre-16b register must stay \
         lossless: a site that falls out of every total is a site nothing \
         watches."
    );
    assert_eq!(
        scope + prov + write,
        expected(FAIL_OPEN_SCOPE_SITES).values().sum::<usize>()
            + expected(AUTH_OPTIONAL_PROVENANCE_SITES)
                .values()
                .sum::<usize>()
            + expected(AUTH_OPTIONAL_WRITE_SITES).values().sum::<usize>(),
        "the registers disagree with the measurement; the three per-register \
         ratchets above will name the file"
    );
}

/// The third register is a ratchet like the other two.
#[test]
fn auth_optional_write_sites_do_not_increase() {
    let actual = measure_auth_optional_write_sites();
    let want = expected(AUTH_OPTIONAL_WRITE_SITES);
    assert_eq!(
        actual,
        want,
        "\n\nAuth-optional write ratchet failed.\n{}\n\n\
         An `if let Some(..) = auth_ctx {{ .. Repository::.. }}` block with no \
         scope check and no provenance call performs a persistence step only \
         when an `AuthContext` is present, and silently skips it otherwise.\n\n\
         A NEW entry usually means a write path that has quietly become \
         conditional on authentication without anyone deciding that it should \
         be. Read it as that first.\n",
        diff_report(&actual, &want)
    );
}

/// **The self-test for the classifier, over synthetic source.**
///
/// The register split is only worth anything if the classifier actually reads
/// the BLOCK. A classifier that read the `if let` line alone would put every
/// site in one bucket and the sum test above would still pass — the exact
/// "looks like a control, measures nothing" failure the split was written to
/// remove.
///
/// The fixtures are synthetic strings, so this test cannot be made to pass by
/// editing the routes directory.
#[test]
fn the_auth_ctx_classifier_is_not_vacuous() {
    let scope = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            if !auth.has_scope("evidence:write") {
                return Err(ApiError::Forbidden { reason: "nope".to_string() });
            }
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(scope, 0)),
        AuthCtxBlock::ScopeCheck
    );

    let prov = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            let hash = blake3::hash(id.as_bytes());
            if let Err(e) = record_provenance(&pool, auth, "evidence", id).await {
                tracing::warn!(error = %e, "failed");
            }
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(prov, 0)),
        AuthCtxBlock::ProvenanceOnly
    );

    // A block doing BOTH is a scope check, not a provenance site: charging it to
    // the provenance register would let a real fail-open hide behind an audit
    // write.
    let both = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            check_scopes(auth, &["claims:write"])?;
            record_provenance(&pool, auth, "claims", id).await.ok();
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(both, 0)),
        AuthCtxBlock::ScopeCheck
    );

    // Auth-optional persistence: a repo call with no scope check and no
    // provenance write. This is the third category, and the fixture is
    // synthetic so it cannot be satisfied by editing the routes directory.
    let auth_optional_write = r#"
        if let Some(axum::Extension(auth)) = &auth_ctx {
            if let Err(e) = OAuthClientRepository::create(&state.db_pool, Some(auth.client_id)).await {
                tracing::warn!(error = %e, "failed");
            }
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(auth_optional_write, 0)),
        AuthCtxBlock::AuthOptionalWrite
    );

    // A scope check WINS over a repo call in the same block: the handler is not
    // auth-optional at all when the check refuses first. Without this arm the
    // priority order could be reversed and a real fail-open would be filed as a
    // benign auth-optional write.
    let scope_and_write = r#"
        if let Some(axum::Extension(ref auth)) = &auth_ctx {
            check_scopes(auth, &["agents:write"])?;
            AgentRepository::create_or_get(&state.db_pool, &agent).await?;
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(scope_and_write, 0)),
        AuthCtxBlock::ScopeCheck,
        "a block that checks a scope AND persists is a scope check; filing it \
         as an auth-optional write would move a real fail-open into a register \
         that does not claim to watch authorization"
    );

    // Neither: must NOT silently land in a register. Note this block DOES read
    // the principal (`auth.agent_id`) — it is here to pin that "uses the
    // principal" is not the third category's predicate, because a predicate
    // that loose would empty the Unclassified sentinel.
    let neither = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            tracing::debug!(agent = %auth.agent_id, "hello");
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(neither, 0)),
        AuthCtxBlock::Unclassified
    );

    // The block scanner must not stop at a brace inside a string literal, nor
    // run past the block's own close into a following scope check. Both errors
    // would misclassify a real site.
    let braces_in_sql = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            record_provenance(&pool, auth, "{not a block}", id).await.ok();
        }
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            check_scopes(auth, &["claims:write"])?;
        }
    "#;
    let first = balanced_block(braces_in_sql, 0);
    assert_eq!(
        classify_auth_ctx_block(first),
        AuthCtxBlock::ProvenanceOnly,
        "a brace inside a string literal must not close the block early, and \
         the region must not bleed into the NEXT `if let` — this fixture is \
         built so either error flips the verdict to ScopeCheck"
    );
    assert!(
        !first.contains("check_scopes("),
        "the block region bled into the following statement"
    );

    // A nested block must not close the outer one.
    let nested = r#"
        if let Some(axum::Extension(ref auth)) = auth_ctx {
            if request.raw_content.is_none() {
                return Err(ApiError::ValidationError { field: "x".to_string() });
            }
            check_scopes(auth, &["evidence:write"])?;
        }
    "#;
    assert_eq!(
        classify_auth_ctx_block(balanced_block(nested, 0)),
        AuthCtxBlock::ScopeCheck,
        "a nested `{{ }}` must not terminate the outer block before the scope \
         call is reached"
    );
}

/// **The self-test for the needle SET**, over synthetic source.
///
/// [`the_auth_ctx_classifier_is_not_vacuous`] hands the classifier a block
/// directly and so proves nothing about which blocks are FOUND. Widening from
/// one spelling to four is entirely a change to the finding step, so without
/// this the widening ships unproven in the direction that matters: three of the
/// four needles could be typos and every register would still be green.
///
/// The fixtures are synthetic strings and cannot be satisfied by editing the
/// routes directory.
#[test]
fn the_needle_set_finds_every_spelling_and_nothing_prescribed() {
    // 1. Each spelling is found, exactly once, by exactly one needle.
    let fixtures = [
        "if let Some(axum::Extension(ref auth)) = auth_ctx {",
        "if let Some(axum::Extension(ref auth)) = &auth_ctx {",
        "if let Some(axum::Extension(auth)) = auth_ctx {",
        "if let Some(axum::Extension(auth)) = &auth_ctx {",
    ];
    for fixture in fixtures {
        let hits: usize = AUTH_CTX_NEEDLES
            .iter()
            .map(|n| fixture.matches(n).count())
            .sum();
        assert_eq!(
            hits, 1,
            "the spelling `{fixture}` is matched {hits} times by the needle \
             set; it must be matched exactly once or the totals are wrong"
        );
    }

    // 2. No needle is a substring of another, which is what makes summing
    //    `matches().count()` across the set sound rather than double-charging.
    for a in AUTH_CTX_NEEDLES {
        for b in AUTH_CTX_NEEDLES {
            if a != b {
                assert!(
                    !a.contains(b),
                    "needle `{b}` is a substring of `{a}`; the verbatim total \
                     would count one site twice"
                );
            }
        }
    }

    // 3. THE PRESCRIBED SHAPE MUST NOT BE CHARGED. This is the failure mode a
    //    careless widening produces: `let Some(..) = auth_ctx else { return
    //    Err(Unauthorized) }` is the FIX these registers push handlers towards,
    //    and matching it would make a conversion increase the count.
    let prescribed = r#"
        let Some(axum::Extension(ref auth)) = auth_ctx else {
            return Err(ApiError::Unauthorized { reason: "auth required".into() });
        };
        check_scopes(auth, &["claims:write"])?;
    "#;
    for n in AUTH_CTX_NEEDLES {
        assert!(
            !prescribed.contains(n),
            "needle `{n}` matches the PRESCRIBED `let .. else` shape. A handler \
             that adopts the fix would make a fail-open register go UP."
        );
    }
}

/// **The COMPLETENESS assertion for the needle set.**
///
/// # What [`the_needle_set_finds_every_spelling_and_nothing_prescribed`] does
/// not prove
///
/// That test proves the four needles are SOUND — each matches its own spelling
/// once, none is a substring of another, none charges the prescribed shape. It
/// proves nothing about whether four is ALL of them, and
/// [`measure_verbatim_auth_ctx_idiom`] defines the "verbatim total" as the
/// needle sum, so [`the_registers_sum_to_the_verbatim_idiom`] is tautological
/// with respect to coverage: a fifth spelling contributes zero to both sides.
///
/// Every needle hard-codes the binder name as `auth`, and this tree already
/// uses others — `routes/claims.rs::create_claim` binds `ctx`, and two handlers
/// bind `a` in a `match` arm. Both alternative binders are therefore idiomatic
/// here, not hypothetical, and their conditional variants would be invisible to
/// all three registers, to the lossless sum, and to the `unclassified == 0`
/// sentinel (which only sees blocks the needles already found).
///
/// This batch exists to remove selectors narrower than the rule they claim to
/// enforce. Leaving one in the file it rewrote would be the same defect.
///
/// # How the census closes it
///
/// [`classify_auth_ctx_shape`] decides each occurrence's shape from the
/// SURROUNDING SYNTAX and never consults [`AUTH_CTX_NEEDLES`]. So
/// `if_let == verbatim` compares two independent measurements of the same set,
/// and a fifth `if let` spelling breaks it by name.
///
/// # The residual: this census is binder-agnostic but PATH-SENSITIVE
///
/// [`AUTH_CTX_BARE`] pins the fully-pathed `axum::Extension`. A handler that
/// imported the type — `if let Some(Extension(ref auth)) = auth_ctx` — or wrote
/// `axum::extract::Extension` would be outside the POPULATION, and so invisible
/// to the needles, to all three registers, to the lossless sum, AND to this
/// census. That is the same structural hole one level up, and stating it is the
/// point: `routes/webhooks.rs` already establishes the bare spelling as a form
/// written in this tree.
///
/// Measured over `src/routes/`: exactly one occurrence of either alternative
/// spelling exists, and it is a doc comment, which [`route_files`] strips. So the
/// population is complete on today's tree over one path prefix, and the residual
/// is recorded rather than denied. Adding the alternatives to the offset scan is
/// the fix if one is ever written; it would not move a register today.
///
/// # Why the totals are floors and not pins
///
/// The critic that prompted this asked for `total` pinned at its measured
/// value. It is deliberately NOT: `LetElse` and `MatchArmRefusing` are the
/// CORRECT shapes, so a new correctly-written handler — or a conversion of an
/// existing fail-open — raises them, and an exact pin would redden the build
/// for the fix. That is the same "a conversion makes the number go UP" trap
/// [`AUTH_CTX_NEEDLES`]' doc rejects for the needle set itself. The load-bearing
/// half is the EQUATION: `Unknown == 0` with a named remainder, plus
/// `if_let == verbatim`. The floors are floors, well under the measurement, and
/// exist only so a scanner that stops matching fails instead of passing over an
/// empty set.
#[test]
fn every_auth_ctx_occurrence_has_a_recognised_shape() {
    let (mut if_let, mut let_else, mut match_arm) = (0usize, 0usize, 0usize);
    let mut unknown: Vec<String> = Vec::new();
    let mut total = 0usize;

    for (name, src) in route_files() {
        for at in auth_ctx_offsets(&src) {
            total += 1;
            match classify_auth_ctx_shape(&src, at) {
                AuthCtxShape::IfLet => if_let += 1,
                AuthCtxShape::LetElse => let_else += 1,
                AuthCtxShape::MatchArmRefusing => match_arm += 1,
                AuthCtxShape::Unknown => {
                    let line = src[..at].matches('\n').count() + 1;
                    unknown.push(format!("  {name}:{line}"));
                }
            }
        }
    }

    assert!(
        unknown.is_empty(),
        "\n\nAn occurrence of `{AUTH_CTX_BARE}` sits in a shape no register \
         describes:\n{}\n\n\
         The recognised shapes are `if let` (measured by the three registers), \
         `let .. else {{ return Err(..) }}`, and a `match` whose arms refuse. \
         Anything else — notably a `match` arm whose sibling `None` arm does \
         NOT refuse — is a fail-open that no ratchet in this file watches. \
         Classify it deliberately rather than leaving it outside every total.\n",
        unknown.join("\n")
    );

    assert_eq!(
        if_let,
        measure_verbatim_auth_ctx_idiom(),
        "\n\nAUTH_CTX_NEEDLES is INCOMPLETE. {if_let} occurrences of \
         `{AUTH_CTX_BARE}` are in the conditional `if let` shape, but the needle \
         set finds only {}. The difference is a conditional binding of the \
         principal that FAIL_OPEN_SCOPE_SITES, AUTH_OPTIONAL_PROVENANCE_SITES \
         and AUTH_OPTIONAL_WRITE_SITES are all blind to — every needle \
         hard-codes the binder name `auth`, and a different binder (this tree \
         already uses `ctx` and `a` elsewhere) contributes zero to every \
         register AND to the lossless sum.\n\n\
         Fix: add the missing spelling to AUTH_CTX_NEEDLES, keeping the \
         pairwise non-substring property that test asserts, and re-baseline the \
         register the new site belongs to — as a VISION change, not a tree \
         change.\n",
        measure_verbatim_auth_ctx_idiom()
    );

    // Non-vacuity. Deliberately well under the measurements (53 / 16 / 2 at the
    // time of writing) so that a correct conversion can move them upward
    // without touching this test.
    assert!(
        total >= 40,
        "only {total} `{AUTH_CTX_BARE}` occurrences found under src/routes/; \
         the census is probably scanning the wrong text"
    );
    assert!(
        let_else >= 12,
        "only {let_else} prescribed `let .. else` refusals found; this shape is \
         the fix the registers push towards and the scanner has stopped seeing it"
    );
    assert!(
        match_arm >= 1,
        "the refusing-`match` shape is no longer recognised; if the last one was \
         converted, say so here rather than deleting the floor"
    );
}

/// **The self-test for the shape classifier**, over synthetic source.
///
/// Without it the census ships with no proof it matches anything — a scanner
/// asserting an equation between two counts that are both zero. The fixtures are
/// strings, so this cannot be satisfied by editing the routes directory.
#[test]
fn the_auth_ctx_shape_classifier_is_not_vacuous() {
    let one = |s: &str| {
        let offs = auth_ctx_offsets(s);
        assert_eq!(offs.len(), 1, "fixture must hold exactly one occurrence");
        classify_auth_ctx_shape(s, offs[0])
    };

    // THE CASE THE CENSUS EXISTS FOR: the conditional shape with a binder the
    // needle set does not enumerate. The classifier must see it AND the needles
    // must not — that pair is what makes the equation fire.
    let alien = "    if let Some(axum::Extension(ctx)) = &auth_ctx {\n        \
                 AgentRepository::create(&pool).await.ok();\n    }\n";
    assert_eq!(one(alien), AuthCtxShape::IfLet);
    assert_eq!(
        AUTH_CTX_NEEDLES
            .iter()
            .map(|n| alien.matches(n).count())
            .sum::<usize>(),
        0,
        "if the needle set ever matches this fixture the census assertion is \
         satisfied trivially and proves nothing; pick a binder it does not \
         enumerate"
    );

    let enumerated = "    if let Some(axum::Extension(ref auth)) = auth_ctx {\n    }\n";
    assert_eq!(one(enumerated), AuthCtxShape::IfLet);

    let let_else = "    let Some(axum::Extension(ctx)) = &auth_ctx else {\n        \
                    return Err(ApiError::Unauthorized { reason: \"x\".into() });\n    };\n";
    assert_eq!(one(let_else), AuthCtxShape::LetElse);

    let refusing_match = "    let auth = match auth_ctx {\n        \
                          Some(axum::Extension(ref a)) => a.clone(),\n        \
                          None => {\n            \
                          return Err(ApiError::Unauthorized { reason: \"x\".into() });\n        \
                          }\n    };\n";
    assert_eq!(one(refusing_match), AuthCtxShape::MatchArmRefusing);

    // A `match` that does NOT refuse is a fail-open in different syntax. Filing
    // it as a refusal is the failure this arm pins.
    let fail_open_match = "    let auth = match auth_ctx {\n        \
                           Some(axum::Extension(ref a)) => Some(a.clone()),\n        \
                           None => None,\n    };\n";
    assert_eq!(
        one(fail_open_match),
        AuthCtxShape::Unknown,
        "a `match` whose `None` arm yields instead of refusing must NOT be \
         counted as a prescribed refusal"
    );

    // `let` with no `else` is not a refusal either.
    let no_else = "    let Some(axum::Extension(ctx)) = auth_ctx;\n";
    assert_eq!(one(no_else), AuthCtxShape::Unknown);

    // A construction, not a pattern.
    let construction = "    let ext = Some(axum::Extension(auth.clone()));\n";
    assert_eq!(one(construction), AuthCtxShape::Unknown);

    // `while let` ends with `let`; the prefix order must not file it as a
    // prescribed refusal.
    let while_let = "    while let Some(axum::Extension(a)) = queue.pop() {\n    }\n";
    assert_eq!(one(while_let), AuthCtxShape::Unknown);
}

#[test]
fn the_two_handlers_pr07_fixed_stay_fixed() {
    // Targeted regression guards for the two named counterexamples, so a
    // revert is caught by name rather than only by a count moving.
    let src = std::fs::read_to_string(routes_dir().join("belief.rs")).expect("read belief.rs");

    let by_belief = src
        .find("pub async fn claims_by_belief")
        .expect("claims_by_belief handler still exists");
    let window = &src[by_belief..(by_belief + 900).min(src.len())];
    assert!(
        window.contains("ViewerExtractor"),
        "claims_by_belief lost its ViewerExtractor; it is a paginated, \
         content-returning corpus scan and was PR-07's live counterexample to \
         acceptance criterion #1"
    );

    let frame_sorted = src
        .find("pub async fn frame_claims_sorted")
        .expect("frame_claims_sorted handler still exists");
    let window = &src[frame_sorted..(frame_sorted + 3000).min(src.len())];
    assert!(
        window.contains("ClaimRepository::frame_claims_sorted"),
        "frame_claims_sorted no longer routes through the viewer-spliced repo \
         function; holding a Viewer and building the content query inline is the \
         exact fail-open PR-07 fixed"
    );
    assert!(
        !window.contains("JOIN claims c ON c.id = cf.claim_id"),
        "frame_claims_sorted has an inline claims join again"
    );
}
