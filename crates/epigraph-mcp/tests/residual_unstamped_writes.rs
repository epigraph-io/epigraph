//! Source ratchet: the `epigraph-mcp` tool layer's REMAINING unstamped writes
//! are enumerated here, and the list may only shrink.
//!
//! # Why this file exists, in the reviewer's words
//!
//! > "Nothing in the repository pins that the converted tools CALL
//! > `begin_author_stamped_tx`. `no_unscoped_pool.rs` excludes `epigraph-mcp` by
//! > its own documented design, the new epigraph-db arms test the repository
//! > functions rather than the tools, and every epigraph-mcp test runs as a
//! > BYPASSRLS superuser — so a future edit reverting any tool to `&server.pool`
//! > would compile and pass the entire suite."
//!
//! That is correct, and it is stated in `no_unscoped_pool.rs`'s own Known-limits
//! section: **"`epigraph-mcp` … is the *other* per-principal serving surface,
//! live in production … It needs its own lint and its own workstream. A green run
//! HERE means 'no unexempted `epigraph-api` handler reaches the raw pool through
//! `AppState`', not 'no unscoped read exists in the workspace'."** This is that
//! lint. It scans `AppState`'s counterpart — `server.pool` — instead.
//!
//! # Why a REGISTER OF WHAT REMAINS rather than a list of what was converted
//!
//! A list of converted sites rots the wrong way: it stays green when a tool is
//! reverted and nobody edits it. The register below is the complement — every
//! write-shaped `server.pool` the tool layer still has — so a reverted conversion
//! ADDS an entry the scan does not expect and the test fails. Shrinking it
//! requires editing this file, which is the point: the residual stays measured
//! in-repo instead of in a commit message that the next reader will not find.
//!
//! # THE TRAP THIS SCANNER HAD TO AVOID
//!
//! `src/maintenance.rs` records it as a measured failure: `no_hybrid_bypass_spend.rs`
//! "matches the FIELD-ACCESS SPELLING over comment-stripped source, and a STRING
//! LITERAL is not stripped. MEASURED — an earlier revision of this sentence
//! spelled it out and turned this function, whose whole purpose is to make the
//! hybrid unreachable, into the lint's only reported offender." The write-path
//! branch added several doc comments in `tools/claims.rs` and `tools/ds.rs` that
//! discuss `&server.pool` in prose, so a scanner that did not strip comments would
//! report the documentation as the defect. [`strip_comments`] does, and
//! [`the_scanner_strips_comments_and_would_otherwise_report_the_docs`] is the
//! calibration that proves it rather than asserting it.
//!
//! # What this lint does NOT see, stated so its green is not over-read
//!
//! It matches the literal `server.pool` AND, since Unit E, any
//! `let alias = &server.pool;` binding within the function that makes it (see
//! `alias_regions`). Before that it could not see a write reached through a
//! binding — `tools/ingestion.rs`'s whole document walk was that shape — and the
//! broadening surfaced nine more alias-bound sites, now registered below. It
//! still cannot see a pool passed through a FUNCTION PARAMETER or a struct
//! field other than `server.pool`, and it only counts callees whose name
//! carries a WRITE_TOKEN. It is also purely syntactic: it says which call sites
//! take the unstamped pool, never whether the statement they run would be
//! refused.
//!
//! # The axis it pins, and the axis it does not
//!
//! VERIFIED that it pins the first: reverting `challenge_claim`'s converted call
//! site from `&mut *tx` back to `&server.pool` makes
//! [`the_tool_layers_unstamped_writes_are_exactly_the_registered_set`] FAIL, naming
//! the exact new tuple `("tools/challenges.rs", "ChallengeRepository::create", 1)`;
//! restoring it returns the file to 6/6. So the reviewer's concern that "a future
//! edit reverting any tool to `&server.pool` would compile and pass the entire
//! suite" is answered — measured, not asserted. That is also why no
//! `server_without_scoped(...)` arms were added per converted tool: they would
//! catch the same revert this scan already catches, at six times the surface.
//!
//! IT DOES NOT PIN THE SECOND: a site can be stamped, and stamped from the WRONG
//! AUTHOR. That is invisible to a syntactic scan — the call reads `&mut *tx`
//! either way — and it is the axis on which a conversion actually fails, because
//! every tier-A `WITH CHECK` asks about the ROW's `owner_group_id` rather than the
//! caller's identity. `scripts/e2e/probe-workflow.sh` is currently the only
//! instrument for it: it reaches the real `epigraph_app` role (`rolbypassrls =
//! false`), seeds the SAME claim in the server agent's own group and in a foreign
//! one, and reports which writes land. A green run HERE means "no tool-layer write
//! takes the unstamped pool except the registered ones" — never "the converted
//! tools stamp from the right viewer".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ===========================================================================
// THE REGISTER.
//
// `(file, callee, occurrences, why it is still unstamped)`. Measured on
// 2026-09-23, at the tip of the MCP write-path conversion. Entries leave this
// list when the site is converted; an entry that ARRIVES is a regression.
// ===========================================================================
const RESIDUAL_UNSTAMPED_WRITES: &[(&str, &str, usize, &str)] = &[
    (
        "tools/claims.rs",
        "ClaimRepository::update_labels",
        1,
        "`resolve_backlog_item`'s step 3, the `resolved` label PATCH on the ORIGINAL backlog \
         claim. RE-MEASURED a second time, and the previous correction was itself wrong: it said \
         this was the `update_labels` TOOL, but the only `ClaimRepository::update_labels(&server.pool` \
         in this file is inside `resolve_backlog_item`, and the `update_labels` tool SUCCEEDS on a \
         cleanly-migrated schema as `epigraph_app` (`scripts/e2e/probe-tools.sh` CONFIG A: \
         `labelled=1`). A tier-A `UPDATE claims` on a claim that is frequently ANOTHER agent's, \
         so its stamp is an ownership question, not a mechanical conversion. Not in E1/E2.",
    ),
    (
        "tools/claims.rs",
        "EdgeRepository::create_if_not_exists",
        1,
        "`resolve_backlog_item`'s `basis -justifies-> resolution` edge. RE-MEASURED: this entry \
         previously read \"`update_with_evidence`'s CHALLENGED/SUPPORTED verb-edge\", and there \
         is no such call site — `update_with_evidence` emits no verb-edge, and neither \
         `CHALLENGED` nor `SUPPORTED` appears anywhere in this file. An inherited description \
         that names the wrong tool sends the next reader to convert the wrong line, so it is \
         corrected here rather than carried. `edges` carries an orphan `edges_privacy` policy, so \
         it lands in production and is refused on a clean migrate. Not in E1/E2: \
         `resolve_backlog_item` is its own tool with its own population and its own ownership \
         question (the basis claims are frequently another agent's).",
    ),
    (
        "tools/claims.rs",
        "server.pool.begin",
        1,
        "`patch_claim`. ATOMIC but unstamped. Invisible to an argument-shaped scan — it takes no \
         `&server.pool` ARGUMENT — which is how it escaped the inherited inventory. Its fix is a \
         REPOSITORY SIGNATURE change: `patch_claim_atomic_conn` takes `&mut sqlx::Transaction`, \
         which `ScopedTx` is not, so the parameter has to become a connection and an \
         `epigraph-api` caller moves with it.",
    ),
    (
        "tools/dedup_sweep.rs",
        "server.pool.acquire",
        1,
        "`sweep_semantic_duplicates`, one of the three MAINTENANCE tools. Hard-gated off by \
         `maintenance.rs::maintenance_tools_run_on_the_maintenance_connection() == false`, which \
         is checked before the pool is even consulted, so this line is unreachable. Converting \
         the three tools' query plumbing is PR-17. \
         REGISTERED UNDER `server.pool.acquire` RATHER THAN THE CASCADE CALLEE, and that rename \
         is the point: the engine signature moved to `&mut PgConnection`, so the call no longer \
         NAMES a pool and an argument-shaped scan stops seeing it. Keeping the site measured \
         needed `acquire` in WRITE_TOKENS — see the note there.",
    ),
    (
        "tools/ds.rs",
        "FrameRepository::create",
        1,
        "`create_frame`. `frames` is one of migration 077 §2b's four instance-wide REGISTRIES, \
         whose `WITH CHECK` carries a STATIC widening arm for `TenancyDecl::instance_wide()`, so \
         this write is admitted unstamped. Registered as a known-unstamped site rather than a \
         known-refused one.",
    ),
    (
        "tools/ds.rs",
        "FrameRepository::create_refinement",
        1,
        "`create_frame`'s refinement arm. Same static registry arm as `FrameRepository::create` \
         above; same reason it is admitted.",
    ),
    (
        "tools/embeddings.rs",
        "ClaimRepository::store_embedding",
        1,
        "`backfill_embeddings`, the second of the three MAINTENANCE tools, and the ONE remaining \
         unstamped `UPDATE claims SET embedding` in this crate — `McpEmbedder`'s store is now \
         routed through a declared `StorePath`. Unreachable for the same gate reason as \
         `dedup_sweep`; it converts with PR-17 onto the maintenance connection, not onto a \
         stamped one, because a backfill is not authored by anyone.",
    ),
    (
        "tools/events.rs",
        "EventRepository::insert",
        1,
        "`publish_event`. `events` is not a claim-derived tier-A table and takes no \
         `owner_group_id`, so there is no `WITH CHECK` for a stamp to satisfy. Registered because \
         the inherited inventory listed it and a reader deserves to know why it is not a defect.",
    ),
    (
        "tools/ingestion.rs",
        "PaperRepository::get_or_create",
        3,
        "The `papers` upsert, three times: `ensure_paper_node` (synchronous, before the detached \
         task is spawned), and the walk-opening call in `do_ingest_document` and \
         `do_ingest_document_spine` (the last two reached through `let pool = &server.pool`, which \
         this scan now follows). `papers` has NO row-level security \
         (`relrowsecurity = false`, measured at head 101), so these are admitted unstamped by \
         construction, and `ensure_paper_node` has already created the row before the walk's \
         call runs. The rest of both walks runs on ONE transaction stamped from the ingesting \
         agent (Unit E); reverting any of those statements to `pool` adds an entry here.",
    ),
    (
        "tools/ingestion.rs",
        "server.pool.begin",
        1,
        "`begin_ingest_tx`'s PRIVILEGED arm: a plain transaction, taken ONLY when the server has \
         no `ScopedPool` AND was built with `EpiGraphMcpFull::on_a_privileged_pool(reason)`. Its \
         one caller is the operator `ingest-document` CLI, which runs on `MaintenancePool` \
         (BYPASSRLS) where there is no tenancy context to stamp. A server on an ordinary pool \
         with neither never reaches it — it gets `begin_author_stamped_tx`'s refusal.",
    ),
    (
        "tools/cdst_maintenance.rs",
        "server.pool.acquire",
        1,
        "`recompute_beliefs`, one of the three MAINTENANCE tools, reached through `let pool = \
         &server.pool` — invisible to this scan until it followed bindings. Hard-gated off like \
         `dedup_sweep.rs` above, and its target is the maintenance connection, not a stamped one: \
         a bulk recompute is authored by nobody. PR-17.",
    ),
    (
        "tools/edge_mutation.rs",
        "EdgeRepository::update_valid_to_and_properties",
        1,
        "`patch_edge`, through `let pool = &server.pool`. An `UPDATE edges`; for an edge between \
         two PUBLIC claims the `edges_tenancy` trigger makes it world-owned public, which \
         `edges_tenancy`'s WITH CHECK admits unstamped — MEASURED, `scripts/e2e/probe-unit-e.sh` \
         CONFIG A REGISTER arm: `patch_edge isError:false`, `patched=1`. A group-owned edge is \
         refused loudly (one statement). Not in E1/E2; converts with an owner-of-the-edge stamp.",
    ),
    (
        "tools/edge_mutation.rs",
        "EdgeRepository::retract_by_id",
        1,
        "`delete_edge`'s retraction (`valid_to = now()`), through `let pool = &server.pool`. \
         Invisible until `retract` joined WRITE_TOKENS. Same world-owned-public argument as \
         `patch_edge`; MEASURED on CONFIG A: `delete_edge isError:false`, `in_force=0`.",
    ),
    (
        "tools/edge_mutation.rs",
        "EventRepository::publish_or_log",
        3,
        "`patch_edge` / `delete_edge`'s best-effort audit events. `events` has no row-level \
         security, and each is a single auto-committing statement outside any transaction, so \
         the swallowed failure is genuinely fire-and-forget here.",
    ),
    (
        "tools/link_alternative.rs",
        "EdgeRepository::create_symmetric_if_absent_returning",
        1,
        "`link_alternative`'s `alternative_of` edge, through `let pool = &server.pool`. Between \
         two PUBLIC claims the edge is world-owned public and admitted unstamped — MEASURED, \
         CONFIG A REGISTER arm: `isError:false`, `alternative_of=1`, owner \
         `00000000-…/public`. Between group-private claims it is refused loudly. Not in E1/E2.",
    ),
    (
        "tools/link_epistemic.rs",
        "EdgeRepository::create_if_not_exists",
        1,
        "`link_epistemic`'s edge INSERT, through `let pool = &server.pool`. Its BELIEF WIRING is \
         stamped (E2: `belief_wired: true` on CONFIG A); the edge itself is world-owned public \
         between public claims and admitted unstamped — MEASURED, `probe-unit-e.sh` \
         `supports_edges=1`. A private endpoint makes it a group-owned edge and a loud refusal \
         BEFORE any belief is wired.",
    ),
    (
        "tools/link_epistemic.rs",
        "EdgeRepository::create_symmetric_if_absent_oriented",
        1,
        "`link_epistemic`'s symmetric-relationship arm (`contradicts` and kin). Same edge-INSERT \
         argument as its `create_if_not_exists` entry.",
    ),
    (
        "tools/link_epistemic.rs",
        "EventRepository::publish_or_log",
        1,
        "`link_epistemic`'s best-effort `edge.added` event: `events` has no row-level security, \
         and it is emitted outside the stamped DS transaction.",
    ),
    (
        "tools/link_hierarchical.rs",
        "EdgeRepository::create_if_not_exists",
        1,
        "`link_hierarchical`'s structural edge, through `let pool = &server.pool`. World-owned \
         public between public claims, admitted unstamped — MEASURED, CONFIG A REGISTER arm: \
         `isError:false`, `decomposes_to=1`. Not in E1/E2.",
    ),
    (
        "tools/matching.rs",
        "EdgeRepository::create_symmetric_if_absent",
        1,
        "`decide_match_candidate`'s SAME_AS edge. `edges`, so an orphan `edges_privacy` policy \
         admits it in production and a clean migrate refuses it. Not in D1-D5; filed here so the \
         set is complete rather than the set the brief happened to enumerate.",
    ),
    (
        "tools/perspectives.rs",
        "EdgeRepository::create",
        1,
        "`create_perspective`'s provenance edge. Same `edges` position as `matching.rs`: admitted \
         in production by the orphan `edges_privacy` policy, refused on a clean migrate.",
    ),
    (
        "tools/perspectives.rs",
        "PerspectiveRepository::create",
        1,
        "`create_perspective`. `perspectives` is another of the four instance-wide registries, so \
         the static `instance_wide()` arm admits it unstamped.",
    ),
    (
        "tools/perspectives.rs",
        "PerspectiveRepository::set_source_reliability",
        1,
        "`set_source_reliability`. Same registry table as above; an UPDATE rather than an INSERT, \
         and the static arm covers it for the same reason.",
    ),
    (
        "tools/supersede.rs",
        "ClaimRepository::supersede",
        1,
        "`supersede_claim`. Tier-A `claims` UPDATE plus the embedding null in the same repo \
         transaction. Unconverted because the cascade below shares its pool and splitting them \
         would half-supersede a tree.",
    ),
    (
        "tools/supersede.rs",
        "server.pool.acquire",
        2,
        "`supersede_claim`'s and `mark_duplicate`'s retraction cascades, one acquire each. STILL \
         UNSTAMPED, and it is a design decision rather than a missing conversion: the cascade \
         walks DOWNSTREAM claims, whose owner groups are arbitrary, so no single viewer's \
         writable set covers its target population and stamping it from `server.agent_id()` \
         would refuse some rows while looking converted. Which authority a retraction cascade \
         carries across group boundaries is a tenancy-model question, not a mechanical \
         conversion. \
         REGISTERED UNDER `server.pool.acquire` for the same reason as `dedup_sweep.rs` above: \
         the engine now takes `&mut PgConnection`, so the cascade call names no pool and only \
         the acquire is visible to this scan.",
    ),
    (
        "tools/workflow_ingest.rs",
        "WorkflowRepository::set_goal_embedding",
        2,
        "`ingest_workflow` and `improve_workflow_hierarchy`, one call each. Writes `workflows`, \
         which is MEASURED `relrowsecurity = false` with no policy at migration head 101 — so \
         unlike the `claims` embed this one is not refused, and converting it would be cohesion \
         rather than a fix. Kept unstamped deliberately; see `visibility_lint.rs`'s \
         `workflow.rs::set_truth_value` entry for the same argument.",
    ),
    (
        "tools/workflows.rs",
        "BehavioralExecutionRepository::create",
        1,
        "`report_workflow_outcome`. `behavioral_executions` is not claim-derived and carries no \
         `owner_group_id`, so there is no `WITH CHECK` for a stamp to satisfy.",
    ),
    (
        "tools/workflows.rs",
        "WorkflowRepository::set_goal_embedding",
        1,
        "`store_workflow`'s goal embedding. Same `relrowsecurity = false` argument as the two in \
         `workflow_ingest.rs`.",
    ),
];

/// Call sites the write-name heuristic matches but which do not WRITE through
/// `server.pool` — the pool is passed as a read connection.
///
/// One entry today. Kept as a register rather than a smarter heuristic because a
/// heuristic that excluded it by shape would also start excluding real writes,
/// and this lint's value is that its false-positive set is written down.
const NOT_ACTUALLY_A_POOL_WRITE: &[(&str, &str, &str)] = &[
    (
        "tools/claims.rs",
        "server.pool.acquire",
        "`submit_claim`'s novelty-gate preamble: a READ-ONLY content-hash existence probe \
         (`ClaimRepository::find_by_content_hash_and_agent`) that runs before any write, so that \
         an exact resubmit takes the unchanged dedup path. Matched only because `acquire` had to \
         join WRITE_TOKENS to keep the three cascade sites visible; nothing is written on this \
         connection.",
    ),
    (
        "tools/memory.rs",
        "server.pool.acquire",
        "`memorize`'s novelty-gate preamble. The same read-only content-hash probe as \
         `tools/claims.rs` above, matched for the same WRITE_TOKENS reason. The write half of \
         `memorize` runs on `begin_author_stamped_tx`.",
    ),
    (
    "claim_helper.rs",
    "store_embedding_author_stamped",
    "The `&server.pool` here is the helper's READ pool: it resolves the author's viewer through \
     `epigraph_live_memberships` (SECURITY DEFINER) before the stamp exists. The WRITE inside that \
     helper runs on `ScopedPool::begin_as`, which is the whole point of it.",
)];

/// Tokens that make a callee name write-shaped. Deliberately broad: a name this
/// misses is a site this lint cannot see, and the inherited inventory's own
/// Counting note records that a NARROW pattern "silently misses `set_*`,
/// `deprecate_*`, `insert` and `delete_step`".
///
/// # `acquire` is here, and it is a DELIBERATE BROADENING — this register may grow
///
/// The monotone-decreasing rule is about the SITES, not about what the scanner can
/// see. When `epigraph-engine`'s belief chain moved from `&PgPool` to
/// `&mut PgConnection`, three unconverted sites stopped naming a pool
/// (`supersede.rs` twice, `dedup_sweep.rs` once) and would have LEFT this
/// register while still reaching an unstamped connection — the register going
/// blind on exactly what it exists to track. `acquire` keeps them visible, at the
/// cost of naming the acquire rather than the write it feeds; each affected entry
/// says so.
///
/// It also matches read-only dedup probes, which is why
/// `NOT_ACTUALLY_A_POOL_WRITE` gained two entries rather than the heuristic being
/// narrowed: the false-positive set of this lint is WRITTEN DOWN, and that is the
/// property that makes broadening it safe rather than noisy.
///
/// # `consolidate` is here because this scanner could not see that write at all
///
/// `ClaimRepository::consolidate(&server.pool, …)` inserts a claim, rewrites
/// edges and retires N sources, and its name matched none of the tokens above —
/// so `consolidate_claims` was refused on every cleanly-migrated schema without
/// ever appearing in this register. Unit E converted it onto
/// `begin_author_stamped_tx`; the token is what makes reverting that conversion
/// a failure here rather than a silent return to the blind spot.
const WRITE_TOKENS: &[&str] = &[
    "consolidate",
    "retract",
    "acquire",
    "create",
    "insert",
    "update",
    "set_",
    "store",
    "delete",
    "deprecate",
    "assign",
    "upsert",
    "mark",
    "patch",
    "begin",
    "publish",
    "record",
    "supersede",
];

/// Remove `//` line comments and (nestable) `/* */` block comments.
///
/// See the module header: without this the branch's own documentation of the
/// defect becomes the lint's only reported offender, which is a measured failure
/// mode in this repository and not a hypothetical one.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// The identifier path heading the call expression that `idx` sits inside:
/// walk back to the nearest UNMATCHED `(`, then take the path before it.
fn callee_before(text: &[char], idx: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut j = idx;
    loop {
        if j == 0 {
            return None;
        }
        j -= 1;
        match text[j] {
            ')' => depth += 1,
            '(' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let end = j;
    let mut k = j;
    while k > 0 && (text[k - 1].is_alphanumeric() || text[k - 1] == '_' || text[k - 1] == ':') {
        k -= 1;
    }
    let name: String = text[k..end].iter().collect();
    let name = name.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Keep at most the last two `::` segments, so the register does not break when
/// a caller changes `epigraph_db::ClaimRepository::x` to `ClaimRepository::x`.
fn normalize(name: &str) -> String {
    let parts: Vec<&str> = name.split("::").collect();
    if parts.len() <= 2 {
        name.to_string()
    } else {
        parts[parts.len() - 2..].join("::")
    }
}

fn mcp_src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Byte ranges of `stripped` in which `alias` names `server.pool`: from each
/// `let alias = &server.pool;` (or `= server.pool.clone();`) binding to the end
/// of the enclosing function — approximated as the next line that opens an item
/// at column 0 or 4 (`fn`, `pub fn`, `async fn`, `pub async fn`, `pub(crate)`),
/// which is how every function in this crate is laid out.
///
/// # Why aliases are followed at all
///
/// The scan below keys on the literal `server.pool`. A write reached through a
/// binding — `let pool = &server.pool;` … `EdgeRepository::create(pool, …)` —
/// was therefore INVISIBLE to this register, and `do_ingest_document` /
/// `do_ingest_document_spine` wrote their whole walk that way. Unit E converted
/// both onto a stamped transaction; following the binding is what makes a
/// revert of either (`&mut tx` back to `pool`) fail here instead of vanishing.
/// The broadening surfaced the other alias-bound writes in the crate, which are
/// registered with their reasons rather than filtered out.
fn alias_regions(stripped: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (pos, _) in stripped.match_indices("let ") {
        let rest = &stripped[pos + 4..];
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        let bound = after
            .strip_prefix('=')
            .map(str::trim_start)
            .is_some_and(|rhs| {
                rhs.starts_with("&server.pool;") || rhs.starts_with("server.pool.clone();")
            });
        if !bound {
            continue;
        }
        let start = pos;
        let mut end = stripped.len();
        for marker in [
            "\nfn ",
            "\npub fn ",
            "\nasync fn ",
            "\npub async fn ",
            "\npub(crate) async fn ",
            "\n    fn ",
            "\n    pub fn ",
            "\n    async fn ",
            "\n    pub async fn ",
        ] {
            if let Some(off) = stripped[start..].find(marker) {
                end = end.min(start + off);
            }
        }
        out.push((name, start, end));
    }
    out
}

/// `(relative file, normalized callee) -> occurrences`, over comment-stripped
/// source under `crates/epigraph-mcp/src`.
fn scan() -> BTreeMap<(String, String), usize> {
    let root = mcp_src_root();
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for path in rust_files(&root) {
        let rel = path
            .strip_prefix(&root)
            .expect("strip prefix")
            .to_string_lossy()
            .replace('\\', "/");
        let stripped = strip_comments(&std::fs::read_to_string(&path).expect("read source"));
        let chars: Vec<char> = stripped.chars().collect();
        let needle: Vec<char> = "server.pool".chars().collect();
        let mut i = 0;
        while i + needle.len() <= chars.len() {
            if chars[i..i + needle.len()] == needle[..] {
                let after: String = chars[i + needle.len()..]
                    .iter()
                    .take(48)
                    .collect::<String>();
                let name = if after.starts_with('.') {
                    // `server.pool.begin()` — a method ON the pool.
                    after
                        .trim_start_matches('.')
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .filter(|s| !s.is_empty())
                        .map(|m| format!("server.pool.{m}"))
                } else {
                    callee_before(&chars, i)
                };
                if let Some(name) = name {
                    let norm = normalize(&name);
                    let short = norm.rsplit("::").next().unwrap_or(&norm).to_string();
                    if WRITE_TOKENS.iter().any(|t| short.contains(t)) {
                        *found.entry((rel.clone(), norm)).or_insert(0) += 1;
                    }
                }
                i += needle.len();
            } else {
                i += 1;
            }
        }

        // Writes reached through a `let alias = &server.pool;` binding. See
        // `alias_regions`.
        for (alias, bstart, bend) in alias_regions(&stripped) {
            let cstart = stripped[..bstart].chars().count();
            let cend = stripped[..bend].chars().count();
            let a: Vec<char> = alias.chars().collect();
            let is_ident = |c: char| c.is_alphanumeric() || c == '_';
            // Skip the binding's own `let alias` token.
            let mut i = cstart + 4 + a.len();
            while i + a.len() <= cend {
                let hit = chars[i..i + a.len()] == a[..]
                    && (i == 0 || !(is_ident(chars[i - 1]) || chars[i - 1] == '.'))
                    && !chars.get(i + a.len()).is_some_and(|c| is_ident(*c));
                if !hit {
                    i += 1;
                    continue;
                }
                let after: String = chars[i + a.len()..].iter().take(48).collect();
                let name = if after.starts_with('.') {
                    after
                        .trim_start_matches('.')
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .filter(|s| !s.is_empty())
                        .map(|m| format!("server.pool.{m}"))
                } else {
                    callee_before(&chars, i)
                };
                if let Some(name) = name {
                    let norm = normalize(&name);
                    let short = norm.rsplit("::").next().unwrap_or(&norm).to_string();
                    if WRITE_TOKENS.iter().any(|t| short.contains(t)) {
                        *found.entry((rel.clone(), norm)).or_insert(0) += 1;
                    }
                }
                i += a.len();
            }
        }
    }
    // Drop the registered false positives.
    for (file, callee, _) in NOT_ACTUALLY_A_POOL_WRITE {
        found.remove(&((*file).to_string(), (*callee).to_string()));
    }
    found
}

/// **The ratchet.** The measured residual must be EXACTLY the register.
///
/// A new entry means a write-shaped call reached `server.pool` that nobody
/// recorded — the "a future edit reverting a tool to `&server.pool` would compile
/// and pass the entire suite" hole. A missing entry means a site was converted and
/// the register has to shrink, which is a one-line edit and is the direction this
/// list is supposed to move.
#[test]
fn the_tool_layers_unstamped_writes_are_exactly_the_registered_set() {
    let measured: Vec<(String, String, usize)> =
        scan().into_iter().map(|((f, c), n)| (f, c, n)).collect();
    let mut registered: Vec<(String, String, usize)> = RESIDUAL_UNSTAMPED_WRITES
        .iter()
        .map(|(f, c, n, _)| ((*f).to_string(), (*c).to_string(), *n))
        .collect();
    registered.sort();

    assert_eq!(
        measured, registered,
        "\nThe set of write-shaped `server.pool` call sites under crates/epigraph-mcp/src has \
         changed.\n\
         * An entry on the LEFT that is not on the RIGHT is a NEW unstamped write — either \
           convert it (`claim_helper::begin_author_stamped_tx`) or add it to \
           RESIDUAL_UNSTAMPED_WRITES with a reason.\n\
         * An entry on the RIGHT that is not on the LEFT means a site was converted or renamed; \
           delete its register entry.\n"
    );
}

/// Every register entry must carry a real reason, not a placeholder. Mirrors
/// `visibility_lint.rs`'s length assertion on `EXECUTOR_WITHOUT_VIEWER`.
#[test]
fn every_registered_residual_states_why_it_is_still_unstamped() {
    for (file, callee, _, reason) in RESIDUAL_UNSTAMPED_WRITES {
        assert!(
            reason.len() > 80,
            "{file}::{callee} needs a reason a reader can act on, got {} chars: {reason}",
            reason.len()
        );
    }
    for (file, callee, reason) in NOT_ACTUALLY_A_POOL_WRITE {
        assert!(
            reason.len() > 80,
            "{file}::{callee} needs a reason a reader can act on, got {} chars",
            reason.len()
        );
    }
}

/// **Calibration for the comment trap.** A scanner that did not strip comments
/// would report this branch's own documentation as the offender — the measured
/// failure `maintenance.rs` records for `no_hybrid_bypass_spend.rs`. Asserted on
/// a fixture rather than on the tree, so it keeps testing the stripper even after
/// every doc mentioning `server.pool` is edited away.
#[test]
fn the_scanner_strips_comments_and_would_otherwise_report_the_docs() {
    let fixture = "\
        /// The previous fallback, `EvidenceRepository::create(&server.pool, …)`,\n\
        /// is refused on a clean schema.\n\
        /* block: EdgeRepository::create(&server.pool) */\n\
        fn f() { let _ = real_call(&server.pool); } // trailing: Foo::create(&server.pool)\n";
    let stripped = strip_comments(fixture);
    assert_eq!(
        stripped.matches("server.pool").count(),
        1,
        "exactly the one real occurrence must survive; got: {stripped}"
    );
    assert!(
        !stripped.contains("EvidenceRepository"),
        "doc-comment prose must not reach the matcher: {stripped}"
    );
}

/// A scanner that matched nothing would satisfy the ratchet above vacuously.
#[test]
fn the_scanner_is_not_vacuous() {
    let measured = scan();
    assert!(
        measured.len() >= 16,
        "the residual scan found only {} sites; the tool layer had 27 when this lint was written \
         and 18 after the ingest-executor and DS-substrate conversions, so a collapse below 16 \
         means the matcher broke rather than that the surface was converted. LOWERED FROM 20 \
         DELIBERATELY: the register fell 24 -> 18 in one change (five D2 sites converted, three \
         cascade sites re-keyed onto `server.pool.acquire`), so a floor of 20 would have failed \
         on a correct shrink. A floor is a matcher-broke tripwire, not a second ratchet — the \
         exact-equality assertion above is the ratchet.",
        measured.len()
    );
    assert!(
        measured.contains_key(&(
            "tools/claims.rs".to_string(),
            "server.pool.begin".to_string()
        )),
        "the `patch_claim` site is the one the argument-shaped inventory could not see; if the \
         scan stops finding it, the method-call arm of the matcher is broken"
    );
}

// ===========================================================================
// THE EMBEDDER'S STORE PATH MUST BE DECLARED IN PRODUCTION SOURCE.
//
// `McpEmbedder`'s default is `StorePath::Undeclared`, which refuses. That is
// safe-by-default, but it means a production embedder built without a
// declaration would stop embedding SILENTLY (the refusal is warned, never
// returned — CLAUDE.md's best-effort embedding policy). So the declaration is
// ratcheted here: every `McpEmbedder::new(` in non-test source must be followed
// immediately by `.with_scoped_pool(` or `.on_a_privileged_pool(`.
//
// Test fixtures are exempt as a class, not individually: ~46 of them build
// `McpEmbedder::new(pool, None)` — mock mode, no API key — so `generate` refuses
// before any store is attempted and the store path is unreachable. Registering
// them one by one would be noise that hides the two entries that matter.
// ===========================================================================

/// Production `McpEmbedder::new(` sites that declare no store path. Empty, and
/// an addition needs a reason that survives the question "so what embeds those
/// claims?".
const PRODUCTION_EMBEDDERS_WITHOUT_A_STORE_PATH: &[(&str, &str)] = &[];

fn workspace_crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

/// Offset of the last `#[cfg(test)]` in the file; everything after it is treated
/// as test code. Crude, and deliberately so: the alternative is parsing Rust, and
/// the property only needs to distinguish "a binary's wiring" from "a `mod tests`
/// fixture".
/// Given text starting at `McpEmbedder::new`, return what follows its
/// balanced argument list (trimmed), or `""` if the parens never close.
fn skip_balanced_args(tail: &str) -> String {
    let chars: Vec<char> = tail.chars().collect();
    let Some(open) = chars.iter().position(|c| *c == '(') else {
        return String::new();
    };
    let mut depth = 0usize;
    for (i, c) in chars.iter().enumerate().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return chars[i + 1..]
                        .iter()
                        .collect::<String>()
                        .trim_start()
                        .to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

fn production_prefix(stripped: &str) -> &str {
    match stripped.rfind("#[cfg(test)]") {
        Some(i) => &stripped[..i],
        None => stripped,
    }
}

#[test]
fn every_production_embedder_declares_a_store_path() {
    let root = workspace_crates_root();
    let mut bare: Vec<(String, String)> = Vec::new();
    for krate in std::fs::read_dir(&root).expect("read crates/") {
        let src = krate.expect("crate dir").path().join("src");
        if !src.is_dir() {
            continue;
        }
        for path in rust_files(&src) {
            let stripped = strip_comments(&std::fs::read_to_string(&path).expect("read source"));
            let prod = production_prefix(&stripped);
            let rel = path
                .strip_prefix(&root)
                .expect("strip prefix")
                .to_string_lossy()
                .replace('\\', "/");
            for (idx, _) in prod.match_indices("McpEmbedder::new") {
                let tail: String = prod[idx..].chars().take(400).collect();
                // Skip past the constructor's own argument list. BALANCED, not
                // `find(')')`: the first close paren in
                // `McpEmbedder::new(pool.clone(), key)` belongs to `clone()`, and
                // a naive `find` reported both correctly-declared production
                // sites as bare — measured on the first run of this lint.
                let after_args = skip_balanced_args(&tail);
                let declared = after_args.starts_with(".with_scoped_pool(")
                    || after_args.starts_with(".on_a_privileged_pool(");
                if !declared {
                    bare.push((rel.clone(), after_args.chars().take(40).collect()));
                }
            }
        }
    }
    bare.sort();
    let registered: Vec<(String, String)> = PRODUCTION_EMBEDDERS_WITHOUT_A_STORE_PATH
        .iter()
        .map(|(f, t)| ((*f).to_string(), (*t).to_string()))
        .collect();
    assert_eq!(
        bare, registered,
        "\nA production `McpEmbedder` was constructed without declaring a StorePath. Its stores \
         will be REFUSED and the refusal is warned rather than returned, so every claim that path \
         writes would land `embedding = NULL` with no error reaching any caller. Call \
         `.with_scoped_pool(..)` (an ordinary application pool) or `.on_a_privileged_pool(reason)` \
         (a MaintenancePool).\n"
    );
}

/// Non-vacuity for the arm above: the two production sites must be FOUND, or the
/// scan is passing because it looked at nothing.
#[test]
fn the_production_embedder_scan_sees_the_two_known_sites() {
    let root = workspace_crates_root();
    let mut declared = 0usize;
    for rel in [
        "epigraph-mcp/src/main.rs",
        "epigraph-cli/src/bin/ingest_document.rs",
    ] {
        let stripped = strip_comments(&std::fs::read_to_string(root.join(rel)).expect("read"));
        let prod = production_prefix(&stripped);
        assert!(
            prod.contains("McpEmbedder::new"),
            "{rel} no longer constructs an McpEmbedder; the ratchet above is now watching a \
             surface that moved"
        );
        assert!(
            prod.contains(".with_scoped_pool(") || prod.contains(".on_a_privileged_pool("),
            "{rel} constructs an McpEmbedder with no declared StorePath"
        );
        declared += 1;
    }
    assert_eq!(declared, 2);
}

// ===========================================================================
// THE EXECUTOR ENTRY POINTS MUST BE CALLED ON A STAMPED TRANSACTION.
//
// # Why this arm had to exist the moment the register shrank
//
// The scan above matches the literal `server.pool`. Four entries left the
// register in this change — `store_workflow`'s, `ingest_workflow`'s and
// `improve_workflow_hierarchy`'s executor calls, and `delete_step` — and every
// one of them left by ceasing to NAME a pool at all: the call now reads
// `execute_workflow_ingest_plan(&mut tx, …)`. A revert to `&server.pool` would
// re-add an entry and be caught, but a revert to
// `&mut pool.acquire().await?` would NOT: it names no pool, so the scan sees
// nothing and the ratchet passes over a site that is unstamped again.
//
// That is the "coverage quietly ends" failure the register's own header warns
// about, in the direction shrinking creates. This arm closes it by pinning the
// ARGUMENT rather than the absence of a pool: every production call to an
// `epigraph-ingest-executor` entry point must pass `&mut tx`, and every file
// that makes one must also contain the helper that produces that `tx`.
//
// It covers `epigraph-api` as well as `epigraph-mcp`, because both surfaces call
// the same executor and the HTTP twin was converted in the same change.
//
// THE HOLE IN AN ARGUMENT-SPELLING SCAN, and how much of it is closed.
// MEASURED, by writing the adversarial revert and running this arm against it:
// `let mut tx = server.pool.acquire().await?;` followed by the unchanged
// `add_step(&mut tx, …)` is unstamped and still spelled `&mut tx`, so the
// spelling check alone passes it. The second assertion below is what catches it:
// a file is required to CALL the stamp helper at least once per stamped executor
// call it makes, so a `tx` that did not come from the helper leaves the counts
// short. It is not airtight — one helper call and two executor calls in the same
// function would satisfy it — but it is the difference between "a rename defeats
// this" and "you have to work at it".
//
// WHAT IT STILL DOES NOT PIN, stated so the next reader does not over-trust it:
// that the `tx` came from the SYSTEM agent's viewer rather than some other one.
// A stamped-from-the-wrong-author transaction is spelled `&mut tx` too. That
// axis remains `scripts/e2e/probe-workflow.sh`'s, exactly as the header above
// says for the first ratchet.
// ===========================================================================

/// The executor entry points whose first argument decides whether the ingest is
/// stamped. Named rather than pattern-matched: a new entry point should be a
/// deliberate addition here, not silently uncovered.
const EXECUTOR_ENTRY_POINTS: &[&str] = &[
    "execute_workflow_ingest_plan(",
    "epigraph_ingest_executor::add_step(",
    "epigraph_ingest_executor::delete_step(",
];

/// **The executor-call register**: `(file, total calls, calls that pass `&mut
/// tx`, why the remainder does not)`.
///
/// A full register rather than a per-file exemption, and the difference is
/// load-bearing. An exemption keyed on the FILE would have covered
/// `workflow_ingest.rs` entirely — and that file holds both the unstamped test
/// fixture AND the production entry point every workflow ingest goes through, so
/// the production call could revert to a pool and this ratchet would still pass.
/// Pinning the COUNTS means the fixture stays exempt and the production call
/// does not.
const EXECUTOR_CALL_REGISTER: &[(&str, usize, usize, &str)] = &[
    (
        "epigraph-api/src/routes/workflows.rs",
        4,
        4,
        "The HTTP twin: `POST /api/v1/workflows` and `POST /api/v1/workflows/ingest` (one \
         `execute_workflow_ingest_plan` each) plus `POST /workflows/steps` and \
         `/workflows/steps/delete`. All four stamp through this module's own \
         `begin_system_ingest_stamped_tx`; none is exempt.",
    ),
    (
        "epigraph-mcp/src/tools/step_ops.rs",
        2,
        2,
        "`add_step` and `delete_step`, both stamped. Neither has a fixture variant — the \
         executor's own `#[sqlx::test]` suite calls `epigraph_ingest_executor::add_step` \
         directly rather than through this module.",
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        2,
        1,
        "TWO calls, ONE stamped, and that asymmetry is the point. The stamped one is \
         `execute_workflow_ingest_with_inserted`, which every production ingest \
         (`store_workflow`, `ingest_workflow`, `improve_workflow_hierarchy`) routes through. The \
         unstamped one is `do_ingest_workflow_via_pool`, a fixture for `#[sqlx::test]` — which \
         connects as `epigraph`, a BYPASSRLS superuser that owns every protected table, so a \
         stamp there is inert. If the production call reverts to a pool this count reads 2/0 and \
         the ratchet fails, which a file-level exemption would not have caught.",
    ),
];

/// The helper each production caller must use to obtain its `tx`. One NAME, two
/// definitions: `epigraph-mcp`'s lives in `claim_helper.rs` and `epigraph-api`'s
/// in `routes/workflows.rs`, with the same semantics and the same stamp.
const STAMP_HELPER_NAME: &str = "begin_system_ingest_stamped_tx";

/// Spellings that count as "this file names the stamp helper at all".
const STAMP_HELPERS: &[&str] = &[
    "claim_helper::begin_system_ingest_stamped_tx",
    "begin_system_ingest_stamped_tx",
];

/// `(relative file, total executor calls, calls passing `&mut tx`)`.
fn executor_callers() -> Vec<(String, usize, usize)> {
    let root = workspace_crates_root();
    let mut out = Vec::new();
    for krate in ["epigraph-mcp", "epigraph-api"] {
        let src = root.join(krate).join("src");
        for path in rust_files(&src) {
            let rel = format!(
                "{krate}/src/{}",
                path.strip_prefix(&src)
                    .expect("strip prefix")
                    .to_string_lossy()
                    .replace('\\', "/")
            );
            let stripped = strip_comments(&std::fs::read_to_string(&path).expect("read source"));
            let prod = production_prefix(&stripped);
            let mut total = 0usize;
            let mut stamped = 0usize;
            for entry in EXECUTOR_ENTRY_POINTS {
                for (idx, _) in prod.match_indices(entry) {
                    total += 1;
                    // The first argument, whitespace-insensitively.
                    let rest: String = prod[idx + entry.len()..]
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .take(8)
                        .collect();
                    if rest.starts_with("&muttx") {
                        stamped += 1;
                    }
                }
            }
            if total > 0 {
                out.push((rel, total, stamped));
            }
        }
    }
    out.sort();
    out
}

/// **The second ratchet.** The measured executor-call shape must be EXACTLY the
/// register.
#[test]
fn every_production_executor_call_takes_a_stamped_transaction() {
    let measured = executor_callers();
    assert!(
        !measured.is_empty(),
        "no executor entry-point call was found in epigraph-mcp or epigraph-api production \
         source; the names in EXECUTOR_ENTRY_POINTS have moved and this ratchet is watching \
         nothing"
    );

    let mut registered: Vec<(String, usize, usize)> = EXECUTOR_CALL_REGISTER
        .iter()
        .map(|(f, total, stamped, _)| ((*f).to_string(), *total, *stamped))
        .collect();
    registered.sort();

    assert_eq!(
        measured, registered,
        "\nThe shape of epigraph-ingest-executor calls in production source has changed.\n\
         Each tuple is (file, total calls, calls passing `&mut tx`).\n\
         * A file whose STAMPED count dropped has an executor call back on an unstamped \
           connection: the rows it writes are owned by the workflow-ingest-system agent's \
           personal group, and migration 077's claims_tenancy WITH CHECK refuses them on a \
           cleanly-migrated schema. Convert it (`begin_system_ingest_stamped_tx`).\n\
         * A file whose TOTAL changed gained or lost a call site; update \
           EXECUTOR_CALL_REGISTER with a reason.\n"
    );
}

/// Every register entry carries a reason, and every file that makes a stamped
/// call still contains the helper that produces the `tx`.
#[test]
fn the_executor_call_register_states_why_and_still_names_a_stamp_helper() {
    let root = workspace_crates_root();
    for (rel, total, stamped, reason) in EXECUTOR_CALL_REGISTER {
        assert!(
            reason.len() > 80,
            "{rel} needs a reason a reader can act on, got {} chars",
            reason.len()
        );
        assert!(
            stamped <= total,
            "{rel}: {stamped} stamped of {total} total is not a coherent count"
        );
        if *stamped == 0 {
            continue;
        }
        let stripped = strip_comments(&std::fs::read_to_string(root.join(rel)).expect("read"));
        let prod = production_prefix(&stripped);
        assert!(
            STAMP_HELPERS.iter().any(|h| prod.contains(h)),
            "{rel} is registered as making {stamped} stamped executor call(s), but its \
             production source no longer names a stamp helper at all — so whatever `tx` those \
             calls receive is not coming from the system agent's viewer"
        );

        // AT LEAST ONE HELPER CALL PER STAMPED EXECUTOR CALL. This is what
        // closes the rename hole described in the header: `let mut tx =
        // server.pool.acquire().await?` keeps the `&mut tx` spelling and is
        // unstamped, but it does not add a helper call, so the count falls
        // short. Counted over the BARE NAME minus its `fn` declarations: the
        // HTTP surface defines its own helper in the same file it calls it from,
        // and a `(`-anchored pattern misses that definition's generic parameter
        // list (`begin_system_ingest_stamped_tx<'s>(`) while an unanchored one
        // counts it. Subtracting the declarations handles both spellings.
        let helper_calls: usize = prod
            .matches(STAMP_HELPER_NAME)
            .count()
            .saturating_sub(prod.matches(&format!("fn {STAMP_HELPER_NAME}")).count());
        assert!(
            helper_calls >= *stamped,
            "{rel} makes {stamped} executor call(s) spelled `&mut tx` but calls a stamp helper \
             only {helper_calls} time(s). A `tx` that did not come from \
             `begin_system_ingest_stamped_tx` is not stamped from the workflow-ingest-system \
             agent's viewer, however it is spelled — and `let mut tx = \
             server.pool.acquire().await?` is the exact revert this counts against."
        );
    }
}
