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
//! It matches the literal `server.pool`, so it cannot see a write that reaches
//! the pool through a `pool` BINDING — `tools/ingestion.rs`'s
//! `ReasoningTraceRepository::create(pool, …)` / `EvidenceRepository::create(pool, …)`
//! inside the detached background task are exactly that shape, and they are why
//! the branch's inherited inventory undercounted. Those live in the brief's D4,
//! not here. It is also purely syntactic: it says which call sites take the
//! unstamped pool, never whether the statement they run would be refused.

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
        "`update_with_evidence`'s label merge. Reached only AFTER the DS wiring below, which is \
         itself unconverted and refuses first on a clean schema, so this line does not execute \
         on either configuration today. Converts with D2.",
    ),
    (
        "tools/claims.rs",
        "ClaimRepository::update_truth_value",
        1,
        "`submit_claim`'s post-DS truth write, on the `was_created` branch. Same D2 ordering \
         constraint as the label merge: `ds_auto` is pool-bound and post-commit, and the value \
         written is derived from its result.",
    ),
    (
        "tools/claims.rs",
        "EvidenceRepository::create",
        1,
        "`update_with_evidence`'s evidence INSERT. Stamped in an earlier revision of this branch \
         and DELIBERATELY REVERTED: migration 046's FK from `mass_functions.evidence_id` forces \
         it to commit before the (unconverted) DS wiring can reference it, so stamping it traded \
         a clean CONFIG-A refusal for a committed orphan, and `Evidence::new` + a no-`ON CONFLICT` \
         INSERT makes agent retries accumulate rows. Converts with D2, in the commit that can put \
         evidence -> BBA -> truth -> labels in one unit.",
    ),
    (
        "tools/claims.rs",
        "ds_auto::auto_wire_ds_update",
        1,
        "`update_with_evidence`'s DS wiring. Writes `claim_frames` + `mass_functions`, neither of \
         which has an orphan `*_privacy` policy, so it is refused in PRODUCTION as well as on a \
         clean migrate — this is why `mass_functions` stopped growing. D2. Gated on `was_created` \
         asymmetrically ON PURPOSE: re-running it double-counts mass.",
    ),
    (
        "tools/claims.rs",
        "EdgeRepository::create_if_not_exists",
        1,
        "`update_with_evidence`'s CHALLENGED/SUPPORTED verb-edge. `edges` carries an orphan \
         `edges_privacy` policy, so it lands in production and is refused on a clean migrate. \
         Belongs with the rest of this tool's conversion rather than alone.",
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
        "retraction_cascade::mark_duplicate_with_cascade",
        1,
        "`sweep_semantic_duplicates`, one of the three MAINTENANCE tools. Hard-gated off by \
         `maintenance.rs::maintenance_tools_run_on_the_maintenance_connection() == false`, which \
         is checked before the pool is even consulted, so this line is unreachable. Converting \
         the three tools' query plumbing is PR-17.",
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
        1,
        "`ingest_document`'s paper upsert. The whole ingest path is pool-bound and its writes run \
         in a DETACHED background task where a refusal reaches no caller — the brief's D4, whose \
         first obligation is to make that task's outcome observable at all.",
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
        "tools/step_ops.rs",
        "epigraph_ingest_executor::delete_step",
        1,
        "`delete_step`. Deletes a step claim and rewrites the workflow's step list; `claims` is \
         tier-A, so it is admitted in production by the orphan `claims_privacy` policy and \
         refused on a clean migrate. Its sibling `add_step` no longer appears here: its embed now \
         goes through the declared `StorePath`.",
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
        "retraction_cascade::cascade_after_supersede",
        1,
        "`supersede_claim`'s cascade, in `epigraph-engine` and pool-bound. Converting it is the \
         same executor-generic widening D2 needs for `edge_factor`, so the two travel together.",
    ),
    (
        "tools/supersede.rs",
        "retraction_cascade::mark_duplicate_with_cascade",
        1,
        "`mark_duplicate`'s cascade. Same pool-bound engine machinery as `cascade_after_supersede`.",
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
        "tools/workflow_ingest.rs",
        "execute_workflow_ingest_with_inserted",
        1,
        "`ingest_workflow`'s executor call. Inserts step claims authored by \
         `get_or_create_system_agent`, so a conversion has to stamp the SYSTEM agent's viewer, \
         not the MCP server's — the same trap the embedder's author lookup exists to avoid. D5.",
    ),
    (
        "tools/workflow_ingest.rs",
        "improve_workflow_hierarchy_with_inserted",
        1,
        "`improve_workflow_hierarchy`'s executor call. Same shape and same system-agent \
         authorship as `execute_workflow_ingest_with_inserted`.",
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
    (
        "tools/workflows.rs",
        "workflow_ingest::execute_workflow_ingest_with_inserted",
        1,
        "`store_workflow`'s executor call, via the shared helper. Same system-agent authorship.",
    ),
    (
        "tools/workflows.rs",
        "ds_auto::auto_wire_ds_update",
        1,
        "`report_workflow_outcome`'s DS wiring. Writes `claim_frames` + `mass_functions`, so it \
         is refused on BOTH configurations exactly as `update_with_evidence`'s is. D2.",
    ),
];

/// Call sites the write-name heuristic matches but which do not WRITE through
/// `server.pool` — the pool is passed as a read connection.
///
/// One entry today. Kept as a register rather than a smarter heuristic because a
/// heuristic that excluded it by shape would also start excluding real writes,
/// and this lint's value is that its false-positive set is written down.
const NOT_ACTUALLY_A_POOL_WRITE: &[(&str, &str, &str)] = &[(
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
const WRITE_TOKENS: &[&str] = &[
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
        measured.len() >= 20,
        "the residual scan found only {} sites; the tool layer had 27 at the time this lint was \
         written, so a collapse this large means the matcher broke rather than that the surface \
         was converted",
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
