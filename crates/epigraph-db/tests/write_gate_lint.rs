//! **The write-gate ratchet** (PR-16, delivered as 16b) — the replacement for
//! the three write-gate test files PR-14 deleted.
//!
//! # Why this file exists
//!
//! PR-14 deleted `write_gate_call_sites.rs`, `write_gate_denies_at_the_route.rs`
//! and `write_gate_denies_at_the_tool.rs` because their subject — the four
//! ownership routes and tools they pinned — ceased to exist. Nothing has pinned
//! the gated write set in either direction since. This file re-establishes that
//! pin over the surface the write-side predicate actually covers.
//!
//! # The property, and the one that is NOT claimed
//!
//! **Claimed:** a repo function that issues an `UPDATE` or `DELETE` against a
//! tenancy-scoped table either splices the write predicate or is named in a
//! register below with a reason. The registers are EXACT SETS keyed on
//! `(file, fn)`, on the `visibility_lint.rs` idiom, deliberately not a
//! `HIGH_WATER` integer: an exact set forces a new exemption to be a visible
//! diff naming the function, where an integer lets a regression hide behind an
//! unrelated deletion in the same file.
//!
//! **Not claimed:** that a write cannot happen without a `Viewer` at all. A repo
//! function that takes no `&Viewer` and issues an `UPDATE` is caught by this
//! lint (the scan is keyed on the SQL, not on the signature). Two populations
//! are not:
//!
//! * **`INSERT`.** `INSERT ... VALUES` has no `WHERE` clause for a marker to be
//!   spliced into; insert-side authority can only come from a `WITH CHECK`-shaped
//!   control on the new row, which is a different mechanism and a different
//!   shard.
//! * **Scoped writes issued from outside `src/repos/` and outside
//!   `epigraph-api/src/routes/`.** This is stated in the PRESENT tense on
//!   purpose. An earlier revision of this paragraph said "a NEW write issued
//!   from outside `src/repos/` is not caught", which reads as a future risk.
//!   It is not: **12 such writes exist today**, and neither register here nor
//!   `ROUTE_LAYER_WRITES` measures any of them. Measured over the scoped tables
//!   in [`WRITE_GATED_TABLES`]:
//!
//!   | crate | scoped writes | reachability |
//!   |---|---|---|
//!   | `epigraph-ingest-executor` | 3 (`claims` ×2, `edges` ×1) | **request-reachable over BOTH transports** |
//!   | `epigraph-embeddings` | 2 (`claims.embedding`) | background |
//!   | `epigraph-cli` | 7 (`claims`, `edges`, `harvester_fragments`) | operator binaries |
//!
//!   The same revision named "the MCP write tools in particular" as the
//!   uncovered surface. That was the WRONG POPULATION and it mattered: the MCP
//!   write tools overwhelmingly call the repo layer and are therefore covered
//!   TRANSITIVELY by [`UNGATED_REPO_WRITES`] — measured, `epigraph-mcp` issues
//!   **zero** scoped writes of its own, as does `epigraph-jobs`. The genuinely
//!   uncovered crate was unnamed. `epigraph-ingest-executor` contains **no
//!   occurrence of `Viewer` at all**, and its writes take a caller-supplied
//!   lineage identifier, select a row from it, and update that row with no
//!   tenancy predicate.
//!
//!   None of this is introduced here and none of it is closed here. It is
//!   written down in the present tense with a measured count so that a future
//!   shard which walks [`UNGATED_REPO_WRITES`] and `ROUTE_LAYER_WRITES` to zero
//!   cannot conclude from that alone that the write side is gated. A third
//!   register keyed on `(crate, file, fn)` is the natural next deliverable;
//!   unmeasured debt is the debt no shard ever finds.
//!
//! # Why three registers and not one total
//!
//! The three carry different remedies, and merging them would let a genuinely
//! hard case be mistaken for negligence:
//!
//! * [`UNGATED_REPO_WRITES`] — an ordinary `sqlx::query(..)` statement. The fix
//!   is to add a `/* {WRITABLE:<alias>} */` marker and call `splice_write`.
//!   These are the conversion shards.
//! * [`MACRO_WRITE_SITES`] — a `sqlx::query!`-family MACRO. **Unspliceable by
//!   construction**: the macro needs a compile-time literal of fixed arity, so
//!   no runtime-built string can reach it. The fix is a static fragment with a
//!   bypass flag, the same shape the four read-side macro sites use, and this PR
//!   does not build it. Filing these beside the ordinary sites would read as
//!   "someone forgot a marker", which is false.
//! * `ROUTE_LAYER_WRITES`, in `epigraph-api/tests/viewer_route_table_lint.rs` —
//!   an `UPDATE`/`DELETE` in a route handler. The fix is always the same and is
//!   never "add a marker here": a handler does not own its SQL and cannot carry
//!   a marker, so the statement must MOVE to `src/repos/` first.
//!
//! # Known drift risk, stated rather than mitigated
//!
//! [`WRITE_GATED_TABLES`] is a constant, and it is a STRICT SUBSET of `TIER_A`
//! (10 of 25) rather than a copy of it. The 15 it omits are omitted because they
//! have no `UPDATE`/`DELETE` in `src/repos/` today — that was MEASURED over the
//! current repos directory, not assumed — so listing them would add rows that
//! can never move. It is a present-tense subset, not merely a future risk, and
//! the two facts have different consequences:
//!
//! * **Today:** every scoped table written from `src/repos/` is named here. A
//!   write on an omitted table would be measured by nothing.
//! * **Tomorrow:** a migration that gives a table `owner_group_id`/`visibility`,
//!   or a repo function that starts writing one of the 15, produces writes that
//!   land in NO register and that this lint silently does not measure.
//!
//! [`the_write_gated_table_set_is_a_subset_of_tier_a`] catches only the INVERSE
//! error — a table named here that is not scoped. It cannot catch either case
//! above, because the authoritative list lives in a migration and not in Rust.
//! When a table gains tenancy columns, or gains its first repo-layer write, add
//! it here in the same PR.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Tenancy-scoped tables whose `UPDATE`/`DELETE` statements this lint watches.
///
/// A subset of `tenancy_migration_shape.rs`'s `TIER_A` — the tables that carry
/// both `owner_group_id` and `visibility` AND have an `UPDATE`/`DELETE` in
/// `src/repos/`. The subset relation is asserted, so a typo here is a test
/// failure rather than a silently-unwatched table.
///
/// **DERIVED BY MEASUREMENT, NOT CHOSEN.** The second condition was evaluated
/// against the repos directory rather than assumed, and that measurement found
/// two tables an eyeball pass had missed: `privatization.rs` writes
/// `public.claim_versions` (in `seal_claims_conn` and `unseal_claims_conn`) and
/// `public.harvester_fragments` (in `seal_claims_conn`). Both are schema-
/// qualified, which is why the offset scan accepts the `public.` prefix.
///
/// Adding them changed NO register row, because both functions were already
/// named in [`UNGATED_REPO_WRITES`] on the strength of their `claims` writes —
/// the registers key on `(file, fn)`, not on the table. So nothing was unwatched
/// in practice; the constant was simply narrower than the property it claimed to
/// measure, and a later PR that split those functions apart would have opened a
/// real hole.
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

/// Repo functions issuing an ungated `UPDATE`/`DELETE` on a scoped table via an
/// ordinary (spliceable) `sqlx::query(..)` call.
///
/// **A debt register, not a permission slip.** Every row is a write that
/// constrains which rows it touches by id alone. Conversion shards walk this set
/// down one reviewable PR at a time, exactly as the read side's conversion
/// shards walked `visibility_lint.rs` down; do not add to it.
///
/// The reason strings are as public as the diff. They describe the code, never
/// the deployment.
const UNGATED_REPO_WRITES: &[(&str, &str)] = &[
    // ── caller-supplied id, no viewer in the signature ──────────────────────
    // The conversion shards. Each takes an id from its caller and constrains on
    // nothing else, so plumbing a `&Viewer` in is real work at every one of them
    // — none of these functions has a viewer parameter today.
    ("challenge.rs::update_state", "caller-supplied id"),
    ("claim.rs::batch_update_truth_values", "caller-supplied ids"),
    ("claim.rs::evolve_step", "caller-supplied id"),
    (
        "claim.rs::mark_duplicate_with_repair_conn",
        "caller-supplied ids (the body moved here from `mark_duplicate_with_repair`, which now delegates; not a new write)",
    ),
    ("claim.rs::merge_properties", "caller-supplied id"),
    ("claim.rs::patch_claim_atomic_conn", "caller-supplied id"),
    ("claim.rs::supersede_conn", "caller-supplied id"),
    ("claim.rs::update_trace_id_conn", "caller-supplied id"),
    ("claim.rs::update_truth_value_conn", "caller-supplied id"),
    ("edge.rs::retract", "caller-supplied id"),
    ("frame.rs::set_property", "caller-supplied id"),
    ("perspective.rs::set_reliability_map", "caller-supplied id"),
    ("semantic_link.rs::retract", "caller-supplied ids"),
    // ── derived-row writes keyed on a claim the caller named ────────────────
    // The row written is not the row the caller identified: these update a
    // belief/classification/mass row derived from a claim id. Gating them wants
    // the predicate on the PARENT claim, which is a join this fragment shape
    // does not express — a design question, not a missed marker.
    (
        "mass_function.rs::clear_claim_belief",
        "derived from claim id",
    ),
    (
        "mass_function.rs::delete_for_claim",
        "derived from claim id",
    ),
    (
        "mass_function.rs::delete_for_perspective",
        "derived from perspective id",
    ),
    (
        "mass_function.rs::update_claim_belief",
        "derived from claim id",
    ),
    (
        "mass_function.rs::update_claim_classification",
        "derived from claim id",
    ),
    // ── maintenance / corpus-wide, unreachable from a request ───────────────
    // These run under a bypass viewer or a maintenance connection by
    // construction. A write predicate would render `" "` for every one of them,
    // so converting them changes no behaviour — they are registered so that a
    // future REQUEST-reachable caller is a visible diff here rather than a
    // silent widening.
    // MEASURED CORRECTION, and the reason it is written here rather than left
    // to the grouping above: `claim.rs::store_embedding` IS request-reachable.
    // `PUT /api/v1/claims/:id` calls it with a caller-supplied vector, gated by
    // `claims:write` plus owner-or-admin rather than by a write predicate. It is
    // still listed — converting it is conversion-tail work, not this register's
    // business — but the enclosing "unreachable from a request" sentence was
    // never true of this entry, and a register that overstates its own contents
    // is the thing this file exists to prevent.
    (
        "claim.rs::store_embedding",
        "embedding backfill corpus-wide AND PUT /claims/:id; statement refuses sealed rows",
    ),
    ("claim_theme.rs::assign_claim", "clustering, corpus-wide"),
    (
        "claim_theme.rs::assign_unthemed_batch",
        "clustering, corpus-wide",
    ),
    ("claim_theme.rs::bulk_assign", "clustering, corpus-wide"),
    ("claim_theme.rs::delete_all_conn", "clustering, corpus-wide"),
    ("claim_theme.rs::unassign_claim", "clustering, corpus-wide"),
    (
        "evidence.rs::store_embedding",
        "embedding backfill, corpus-wide",
    ),
    ("match_candidate.rs::retire", "dedup sweep, corpus-wide"),
    // ── privatization: selection must be unfiltered to be correct ───────────
    // Filtering these would silently skip the rows they exist to find, which is
    // the argument `SystemReason::PrivatizationSelection` already records. They
    // are listed so the argument is re-read whenever the set changes, not
    // because a marker is missing.
    (
        "privatization.rs::recompute_boundary_meet_conn",
        "privatization apply",
    ),
    (
        "privatization.rs::restore_claims_conn",
        "privatization apply",
    ),
    (
        "privatization.rs::restrict_claims_conn",
        "privatization apply",
    ),
    ("privatization.rs::seal_claims_conn", "privatization apply"),
    (
        "privatization.rs::unseal_claims_conn",
        "privatization apply",
    ),
];

/// Repo functions whose scoped-table write is inside a `sqlx::query!`-family
/// MACRO.
///
/// Separate from [`UNGATED_REPO_WRITES`] because the remedy is different in
/// kind, not in effort: `splice_write` returns a runtime `String` and the macro
/// requires a compile-time literal of fixed arity, so **no marker can ever reach
/// these statements**. They need the static-fragment-plus-bypass-flag shape the
/// read side uses at its four macro sites, extended to a writable array. This PR
/// does not build that shape.
const MACRO_WRITE_SITES: &[(&str, &str)] = &[
    (
        "claim.rs::delete",
        "sqlx::query! — takes &PgPool, no route reaches it",
    ),
    (
        "claim.rs::set_properties_conn",
        "sqlx::query! (body moved from `set_properties`, which now delegates; not a new write)",
    ),
    ("claim.rs::update_trace_id", "sqlx::query!"),
    ("claim.rs::update_truth_value", "sqlx::query!"),
    ("edge.rs::retract_between", "sqlx::query!"),
    ("edge.rs::retract_by_id", "sqlx::query!"),
    ("edge.rs::update_valid_to_and_properties", "sqlx::query!"),
    // Also carries a `VISIBILITY-EXEMPT:` comment and a row in
    // `visibility_lint.rs::EXPECTED_EXEMPTIONS`. Both stay. The read-side
    // register records that this fn takes a `&Viewer` and does not spend it;
    // this one records WHY it cannot be spliced. They are two different facts
    // about the same function, and moving the row rather than adding one would
    // have forced an edit to a read-side lint as collateral of a write-side PR.
    ("evidence.rs::delete", "sqlx::query!"),
    ("recall_event.rs::prune_older_than", "sqlx::query!"),
];

fn repos_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repos")
}

/// Every `.rs` under `src/repos/`, with `#[cfg(test)]` modules truncated away.
///
/// Test modules are excluded because a fixture's `DELETE FROM claims` is
/// cleanup, not a production write path, and charging it would put rows in a
/// security register that no conversion shard can ever remove.
fn repo_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repos_dir()).expect("read repos dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        let body = std::fs::read_to_string(&path).expect("read repo file");
        out.push((name, strip_test_modules(&body)));
    }
    out.sort();
    assert!(
        out.len() > 30,
        "expected the repos directory to hold the whole SQL surface, found {} \
         files — the lint is looking in the wrong place and would pass vacuously",
        out.len()
    );
    out
}

/// Truncate the source at its first `#[cfg(test)]`.
///
/// Blunt on purpose. A repo file's test module is conventionally last, and the
/// alternative — tracking module nesting — would be a second parser to get
/// wrong. If a file ever puts production code after its tests, this lint
/// under-measures it, which is why [`the_write_scanner_is_not_vacuous`] pins the
/// behaviour rather than leaving it implied.
fn strip_test_modules(src: &str) -> String {
    match src.find("#[cfg(test)]") {
        Some(at) => src[..at].to_string(),
        None => src.to_string(),
    }
}

/// The balanced region starting at `src[start]`, which must be `open`.
///
/// Skips string literals (normal and raw) and line comments, so braces or
/// parens inside SQL text cannot unbalance the count. Same shape as
/// `visibility_lint.rs::balanced`, and duplicated rather than shared because an
/// integration test cannot import another integration test.
fn balanced(src: &str, start: usize, open: u8, close: u8) -> &str {
    let b = src.as_bytes();
    let n = src.len();
    let mut j = start;
    let mut depth = 0usize;
    while j < n {
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
                j += 3;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            c if c == open => depth += 1,
            c if c == close => {
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

struct RepoFn {
    name: String,
    body: String,
}

/// Every `fn` declaration in `src`, with its body.
///
/// The `fn NAME<generics>(params) {` shape, requiring nothing but whitespace
/// between the name and `(`. That requirement is what keeps PROSE out of the
/// scan: `a future write fn that lets a caller assign …` in a doc comment has
/// non-whitespace between `that` and the next `(`, so it is not a declaration.
fn fns_in(src: &str) -> Vec<RepoFn> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find("fn ") {
        let at = from + rel;
        from = at + 3;

        if at > 0 {
            let prev = src.as_bytes()[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }

        // Not inside a comment. `claim.rs` documents a repo method with a
        // rustdoc example whose hidden line is
        // `/// # async fn example(pool: &sqlx::PgPool) -> … {`, and that is a
        // doc fixture, not a write path — charging it would put a row in a
        // security register that no conversion shard could ever remove. Checking
        // the line prefix also excludes commented-out code, which is the same
        // class of false positive.
        let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
        if src[line_start..at].contains("//") {
            continue;
        }

        let after = &src[at + 3..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        if name_end == 0 {
            continue;
        }
        let name = after[..name_end].to_string();

        let mut cursor = at + 3 + name_end;
        if src[cursor..].trim_start().starts_with('<') {
            let lt = src[cursor..].find('<').expect("just matched") + cursor;
            cursor = lt + balanced(src, lt, b'<', b'>').len();
        }
        let Some(paren_rel) = src[cursor..].find('(') else {
            continue;
        };
        let paren = cursor + paren_rel;
        if !src[cursor..paren].trim().is_empty() {
            continue;
        }
        let params = balanced(src, paren, b'(', b')');
        let Some(brace_rel) = src[paren + params.len()..].find('{') else {
            continue;
        };
        let brace = paren + params.len() + brace_rel;
        out.push(RepoFn {
            name,
            body: balanced(src, brace, b'{', b'}').to_string(),
        });
    }
    out
}

/// Byte offsets in `body` of an `UPDATE <t>` / `DELETE FROM <t>` naming a
/// [`WRITE_GATED_TABLES`] table.
///
/// The optional `public.` qualifier is accepted because `privatization.rs`
/// writes schema-qualified. Matching on the STATEMENT rather than on the
/// function signature is deliberate: a new write fn that takes no `&Viewer` at
/// all is exactly the case a signature-keyed lint would miss, and it is the case
/// most likely to be a genuine fail-open.
fn scoped_write_offsets(body: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for table in WRITE_GATED_TABLES {
        for verb in [
            format!("UPDATE {table}"),
            format!("UPDATE public.{table}"),
            format!("DELETE FROM {table}"),
            format!("DELETE FROM public.{table}"),
        ] {
            let mut from = 0usize;
            while let Some(rel) = body[from..].find(&verb) {
                let at = from + rel;
                from = at + verb.len();
                // `UPDATE claims` must not match `UPDATE claims_history`.
                let tail = body[at + verb.len()..].chars().next();
                if tail.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                out.push(at);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Is the statement at `at` inside a `sqlx::query!`-family MACRO invocation?
///
/// Keyed on the nearest preceding `sqlx::query` and whether the offset falls
/// inside its balanced argument region, so a function containing BOTH a macro
/// and an ordinary call is classified per-statement rather than per-function.
fn inside_query_macro(body: &str, at: usize) -> bool {
    let mut best: Option<usize> = None;
    let mut from = 0usize;
    while let Some(rel) = body[from..].find("sqlx::query") {
        let pos = from + rel;
        from = pos + "sqlx::query".len();
        if pos < at {
            best = Some(pos);
        } else {
            break;
        }
    }
    let Some(pos) = best else { return false };
    let mut tail = &body[pos + "sqlx::query".len()..];
    for suffix in ["_as", "_scalar"] {
        if let Some(rest) = tail.strip_prefix(suffix) {
            tail = rest;
            break;
        }
    }
    if !tail.starts_with('!') {
        return false;
    }
    let Some(open_rel) = body[pos..].find('(') else {
        return false;
    };
    let open = pos + open_rel;
    at < open + balanced(body, open, b'(', b')').len()
}

/// Every scoped-table write in `src/repos/` that does not splice the write
/// predicate, split by whether it CAN be spliced.
///
/// A function is cleared by containing `.splice_write(`, on the same argument
/// `visibility_lint.rs::SPENT_MARKERS` makes for reads: requiring the mechanism
/// rather than the accessor is what keeps the check about the QUERY rather than
/// about the call.
///
/// # The granularity hole this clearing has, and the guard that closes it
///
/// Clearing is per-FUNCTION while [`inside_query_macro`] classifies
/// per-STATEMENT, and that asymmetry is a live hole rather than a stylistic
/// one. A function with two scoped writes that gates ONE of them contains
/// `.splice_write(`, is skipped entirely, and drops out of `actual` — so the
/// conversion shard that half-converted it MUST delete its register row to keep
/// `assert_eq!` green, and the write it did not gate then exists in no register
/// at all, with a green suite. That is a ratchet a shard can punch a hole in,
/// which is this PR's own failure mode relocated one level down.
///
/// It has a named victim already. `privatization.rs::seal_claims_conn` writes
/// `claims`, `public.claim_versions` and `public.harvester_fragments` — three
/// scoped writes, one register row — and is exactly the shape that would go
/// silent on partial conversion.
///
/// **The real fix is per-statement classification**, deciding for each offset
/// whether that statement's own `sqlx::query(..)` argument derives from a
/// `.splice_write(` result. That needs data-flow this lint does not do and is
/// not attempted here. What IS done is to make partial conversion LOUD instead
/// of silent: a cleared function must have as many `.splice_write(` calls as it
/// has scoped-write offsets, and [`partial_conversion_report`] names the
/// function when it does not. That is a weaker property than per-statement
/// gating and it is stated as such — it cannot tell you WHICH write was left
/// ungated, only that one was.
fn measure_ungated_writes() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut ordinary = BTreeMap::new();
    let mut macros = BTreeMap::new();
    for (file, src) in repo_files() {
        for f in fns_in(&src) {
            if f.body.contains(".splice_write(") {
                continue;
            }
            let offsets = scoped_write_offsets(&f.body);
            if offsets.is_empty() {
                continue;
            }
            let key = format!("{file}::{}", f.name);
            if offsets.iter().all(|&at| inside_query_macro(&f.body, at)) {
                macros.insert(key, String::new());
            } else {
                ordinary.insert(key, String::new());
            }
        }
    }
    (ordinary, macros)
}

/// Functions that spliced SOME of their scoped writes but not all of them.
///
/// The companion to [`measure_ungated_writes`]'s per-function clearing, and the
/// only thing standing between a half-converted function and silence. Returns
/// one line per offender, empty when there is none.
///
/// Counting `.splice_write(` calls against scoped-write offsets is a COUNT
/// heuristic, not a pairing: it cannot prove the marker that was spliced belongs
/// to the statement that carries it. It catches the case that actually occurs —
/// a shard converts one write in a function and leaves its siblings — and it
/// would not catch a function that spliced twice into one statement and left
/// another bare. Stated so the next reader does not over-trust it.
fn partial_conversion_report() -> Vec<String> {
    repo_files()
        .into_iter()
        .flat_map(|(file, src)| partial_conversions_in(&file, &src))
        .collect()
}

/// [`partial_conversion_report`] over ONE source string.
///
/// Split out so the property can be exercised on synthetic sources that do not
/// exist in `src/repos/` — see
/// [`the_partial_conversion_guard_is_not_vacuous`]. A guard whose only evidence
/// is that the current tree happens to satisfy it is indistinguishable from a
/// guard that always returns empty, and this one is satisfied vacuously today:
/// exactly one function in `src/repos/` splices a write predicate and it has
/// exactly one scoped write.
fn partial_conversions_in(file: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in fns_in(src) {
        let spliced = f.body.matches(".splice_write(").count();
        if spliced == 0 {
            continue;
        }
        let writes = scoped_write_offsets(&f.body).len();
        if writes > spliced {
            out.push(format!(
                "{file}::{} splices {spliced} write predicate(s) but issues {writes} \
                 scoped write(s). measure_ungated_writes() clears this function WHOLE, so \
                 the {} unspliced write(s) are measured by NOTHING. Either splice them too, \
                 or split the function so the ungated half keeps a register row.",
                f.name,
                writes - spliced
            ));
        }
    }
    out
}

/// A function may not be cleared by gating only some of its scoped writes.
///
/// Without this, the conversion shards have a legal move that reduces coverage
/// while every assertion in this file stays green: gate one write of two, watch
/// the function vanish from `actual`, and delete its `UNGATED_REPO_WRITES` row
/// to restore the `assert_eq!`. See [`measure_ungated_writes`] for why the
/// stronger per-statement property is not asserted instead.
#[test]
fn a_partially_converted_function_is_not_silently_cleared() {
    let offenders = partial_conversion_report();
    assert!(
        offenders.is_empty(),
        "{} function(s) splice the write predicate for only some of their scoped \
         writes, and are therefore cleared whole by a lint that measures neither \
         half:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

/// The partial-conversion guard must FIRE on the shape it exists to catch.
///
/// [`a_partially_converted_function_is_not_silently_cleared`] passes vacuously
/// on the current tree — one splicing function, one scoped write — so on its own
/// it is evidence of nothing. These three synthetic sources are the actual
/// proof: the half-converted shape is reported, and neither the fully-converted
/// nor the fully-ungated shape is.
#[test]
fn the_partial_conversion_guard_is_not_vacuous() {
    // 1. HALF-CONVERTED — one marker, two scoped writes. This is the exact move
    //    a conversion shard makes, and the one that would otherwise delete a
    //    register row and take an unmeasured write with it.
    let half = r#"
        pub async fn seal(pool: &PgPool, v: &Viewer, id: Uuid) -> Result<(), DbError> {
            let sql = v.splice_write("UPDATE claims AS c SET sealed = true WHERE c.id = $1 /* {WRITABLE:c} */", 2);
            sqlx::query(&sql).bind(id).bind(v.writable_bind().unwrap()).execute(pool).await?;
            sqlx::query("UPDATE public.claim_versions SET sealed = true WHERE claim_id = $1")
                .bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    let hits = partial_conversions_in("synthetic.rs", half);
    assert_eq!(
        hits.len(),
        1,
        "a function splicing 1 of its 2 scoped writes must be reported, or a \
         conversion shard can delete its register row and silently drop the \
         other write: {hits:?}"
    );
    assert!(
        hits[0].contains("seal") && hits[0].contains("splices 1") && hits[0].contains("issues 2"),
        "the report must name the function and both counts: {}",
        hits[0]
    );

    // 2. FULLY CONVERTED — two markers, two scoped writes. Must NOT fire, or
    //    the guard would block the very conversions it exists to protect.
    let whole = r#"
        pub async fn seal(pool: &PgPool, v: &Viewer, id: Uuid) -> Result<(), DbError> {
            let a = v.splice_write("UPDATE claims AS c SET sealed = true WHERE c.id = $1 /* {WRITABLE:c} */", 2);
            sqlx::query(&a).bind(id).execute(pool).await?;
            let b = v.splice_write("UPDATE claim_versions AS cv SET sealed = true WHERE cv.claim_id = $1 /* {WRITABLE:cv} */", 2);
            sqlx::query(&b).bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    assert!(
        partial_conversions_in("synthetic.rs", whole).is_empty(),
        "a fully converted function must not be reported"
    );

    // 3. FULLY UNGATED — no marker at all. Must NOT fire here either: this
    //    function is caught by UNGATED_REPO_WRITES, and reporting it twice
    //    would make the two registers disagree about the same site.
    let none = r#"
        pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
            sqlx::query("UPDATE claims SET sealed = true WHERE id = $1").bind(id).execute(pool).await?;
            sqlx::query("UPDATE evidence SET raw_content = '' WHERE id = $1").bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    assert!(
        partial_conversions_in("synthetic.rs", none).is_empty(),
        "an entirely ungated function belongs to UNGATED_REPO_WRITES, not here"
    );
}

fn expected(list: &[(&str, &str)]) -> BTreeMap<String, String> {
    list.iter()
        .map(|(k, _)| ((*k).to_string(), String::new()))
        .collect()
}

/// Name the exact rows that moved, so a failure is actionable without rerunning
/// anything by hand.
fn diff_report(actual: &BTreeMap<String, String>, want: &BTreeMap<String, String>) -> String {
    let mut lines = Vec::new();
    for k in actual.keys() {
        if !want.contains_key(k) {
            lines.push(format!("  + {k}   [NEW — an ungated write appeared]"));
        }
    }
    for k in want.keys() {
        if !actual.contains_key(k) {
            lines.push(format!(
                "  - {k}   [gone — if you converted it, DELETE this row]"
            ));
        }
    }
    lines.sort();
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// the non-vacuity self-test, written BEFORE the registers it calibrates
// ---------------------------------------------------------------------------

/// **The self-test for the scanner.**
///
/// `visibility_lint.rs` documents that its own first revision could not catch
/// the defect it was written for, and PR-14 deleted a write-gate lint once
/// already. A ratchet that goes green by measuring NOTHING is the same failure
/// as a gate with no call sites — it is the failure this PR exists to avoid,
/// reproduced inside the thing built to prevent it.
///
/// The fixtures are synthetic source strings, so this test cannot be made to
/// pass by editing the repos directory.
#[test]
fn the_write_scanner_is_not_vacuous() {
    // 1. An ordinary ungated UPDATE on a scoped table IS counted.
    let ungated = r#"
        pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
            sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
                .bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    let f = &fns_in(ungated)[0];
    assert_eq!(f.name, "touch");
    assert_eq!(
        scoped_write_offsets(&f.body).len(),
        1,
        "an unguarded UPDATE on a scoped table must be seen"
    );
    assert!(!f.body.contains(".splice_write("));

    // 2. The SAME statement, marked and spliced, is NOT counted.
    let gated = r#"
        pub async fn touch(pool: &PgPool, viewer: &Viewer, id: Uuid) -> Result<(), DbError> {
            let sql = viewer.splice_write(
                "UPDATE evidence AS e SET raw_content = $2 WHERE e.id = $1 /* {WRITABLE:e} */", 3);
            sqlx::query(&sql).bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    assert!(
        fns_in(gated)[0].body.contains(".splice_write("),
        "the converted form must be recognised as gated — if this fails the \
         lint charges every converted site forever and the ratchet can never \
         go down"
    );

    // 3. A `format!`-built UPDATE is STILL counted. The scan is keyed on the
    //    SQL text, not on the call, so deferring the statement into a local
    //    does not launder it — this is the `frame_claims_sorted` shape that
    //    defeated the read lint's first revision.
    let deferred = r#"
        pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
            let sql = format!("UPDATE claims SET content = $2 WHERE id = $1 {extra}");
            sqlx::query(&sql).bind(id).execute(pool).await?;
            Ok(())
        }
    "#;
    assert_eq!(scoped_write_offsets(&fns_in(deferred)[0].body).len(), 1);

    // 4. A write on an UNSCOPED table is not counted: `tasks` carries neither
    //    `owner_group_id` nor `visibility`, so there is nothing to gate on and
    //    charging it would inflate a security register with rows no conversion
    //    can ever remove.
    let unscoped = r#"
        pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), DbError> {
            sqlx::query("UPDATE tasks SET state = 'done' WHERE id = $1").execute(pool).await?;
            Ok(())
        }
    "#;
    assert!(scoped_write_offsets(&fns_in(unscoped)[0].body).is_empty());

    // 5. A table whose name merely STARTS with a scoped table's name is not
    //    counted.
    let prefixed = r#"
        pub async fn touch(pool: &PgPool) -> Result<(), DbError> {
            sqlx::query("UPDATE claims_history SET x = 1").execute(pool).await?;
            Ok(())
        }
    "#;
    assert!(
        scoped_write_offsets(&fns_in(prefixed)[0].body).is_empty(),
        "`UPDATE claims_history` must not be charged as `UPDATE claims`"
    );

    // 6. Bare PROSE is not a declaration and not a write.
    //    A rustdoc example's hidden `fn` line is the live case: `claim.rs`
    //    carries one, and before the comment check it entered the register as
    //    `claim.rs::example` — a row no conversion could ever remove.
    let prose = r#"
        /// A future write fn that lets a caller assign `owner_group_id` is not
        /// made safe by this marker, and an `UPDATE claims` in a doc comment is
        /// not a write site.
        ///
        /// ```
        /// # async fn example(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        /// sqlx::query("UPDATE claims SET content = 'x'").execute(pool).await?;
        /// # Ok(()) }
        /// ```
        pub async fn documented(pool: &PgPool) -> Result<(), DbError> { Ok(()) }
    "#;
    let declared = fns_in(prose);
    let names: Vec<&str> = declared.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["documented"],
        "prose in a doc comment must not be scanned as a declaration"
    );

    // 7. The macro/ordinary split is per-STATEMENT, not per-function.
    // Outer `r##` so the fixture can carry a nested `r#"…"#` — which it must:
    // the tree's macro sites write their SQL in raw strings, and the scanner has
    // to survive one.
    let macro_site = r##"
        pub async fn wipe(pool: &PgPool, id: Uuid) -> Result<bool, DbError> {
            let r = sqlx::query!(r#"DELETE FROM evidence WHERE id = $1"#, id)
                .execute(pool).await?;
            Ok(r.rows_affected() > 0)
        }
    "##;
    let body = &fns_in(macro_site)[0].body;
    let offsets = scoped_write_offsets(body);
    assert_eq!(offsets.len(), 1);
    assert!(
        inside_query_macro(body, offsets[0]),
        "a `sqlx::query!` write must be classified as unspliceable, or the \
         register will demand a marker that cannot physically be added"
    );
    let ordinary_site = r#"
        pub async fn wipe(pool: &PgPool, id: Uuid) -> Result<bool, DbError> {
            let r = sqlx::query("DELETE FROM evidence WHERE id = $1").bind(id)
                .execute(pool).await?;
            Ok(r.rows_affected() > 0)
        }
    "#;
    let body = &fns_in(ordinary_site)[0].body;
    assert!(
        !inside_query_macro(body, scoped_write_offsets(body)[0]),
        "an ordinary `sqlx::query(..)` write must NOT be excused as a macro \
         site — that would let any conversion be dodged by misclassification"
    );

    // 8. A `#[cfg(test)]` fixture's cleanup is not a production write path.
    let with_tests =
        "pub async fn real(p: &PgPool) { sqlx::query(\"UPDATE claims SET x = 1\"); }\n\
                      #[cfg(test)]\n\
                      mod tests { fn t() { sqlx::query(\"DELETE FROM claims\"); } }";
    let stripped = strip_test_modules(with_tests);
    assert!(stripped.contains("UPDATE claims"));
    assert!(
        !stripped.contains("DELETE FROM claims"),
        "a test module's cleanup must not enter a security register"
    );
}

// ---------------------------------------------------------------------------
// the ratchets
// ---------------------------------------------------------------------------

#[test]
fn ungated_repo_writes_do_not_increase() {
    let (actual, _) = measure_ungated_writes();
    let want = expected(UNGATED_REPO_WRITES);
    assert_eq!(
        actual,
        want,
        "\n\nWrite-gate ratchet failed.\n{}\n\n\
         A repo function issues an `UPDATE`/`DELETE` against a tenancy-scoped \
         table and does not splice the write predicate, so the only thing \
         constraining which row it touches is the id the caller supplied.\n\n\
         Fix: add `/* {{WRITABLE:<alias>}} */` to the statement, wrap it in \
         `viewer.splice_write(..)`, and bind `viewer.writable_bind()` — NOT \
         `group_bind()`; the read set is not write authority. Then DELETE the \
         row here. Never add one.\n",
        diff_report(&actual, &want)
    );
}

#[test]
fn macro_write_sites_do_not_increase() {
    let (_, actual) = measure_ungated_writes();
    let want = expected(MACRO_WRITE_SITES);
    assert_eq!(
        actual,
        want,
        "\n\nUnspliceable-write register changed.\n{}\n\n\
         A scoped-table `UPDATE`/`DELETE` inside a `sqlx::query!`-family macro \
         cannot take a spliced literal — the macro needs a compile-time literal \
         of fixed arity. These are NOT missed markers and must not be filed \
         beside sites that are.\n\n\
         A NEW row means a new unspliceable write path was added; prefer the \
         ordinary `sqlx::query(..)` form so the marker mechanism can reach it.\n",
        diff_report(&actual, &want)
    );
}

/// The two write registers must not both claim the same function.
///
/// A function's write cannot be simultaneously spliceable and unspliceable, and
/// a stray duplicate would let one register's row silently excuse the other's.
#[test]
fn the_two_write_registers_are_disjoint() {
    for (k, _) in UNGATED_REPO_WRITES {
        assert!(
            !MACRO_WRITE_SITES.iter().any(|(m, _)| m == k),
            "{k} appears in both write registers"
        );
    }
}

/// Every table this lint watches must actually carry tenancy columns.
///
/// Parsed out of `tenancy_migration_shape.rs`'s `TIER_A` literal rather than
/// re-listed, so the two cannot drift into two different ideas of "scoped". This
/// catches a typo or a table that loses its tenancy columns; it CANNOT catch a
/// newly-scoped table that nobody added here — see the module docs.
#[test]
fn the_write_gated_table_set_is_a_subset_of_tier_a() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tenancy_migration_shape.rs");
    let src = std::fs::read_to_string(&path).expect("read tenancy_migration_shape.rs");
    let at = src
        .find("const TIER_A")
        .expect("TIER_A still exists in tenancy_migration_shape.rs");
    // `= &[` and not the first `[`: the TYPE is `&[&str]`, whose bracket comes
    // first and balances to `[&str]` — a literal with no strings in it, which
    // would parse as an empty TIER_A and make this check pass vacuously. The
    // non-vacuity assertion below is what caught that.
    let eq = src[at..].find("= &[").expect("TIER_A is a slice literal") + at;
    let open = eq + "= &".len();
    let literal = balanced(&src, open, b'[', b']');

    let tier_a: Vec<&str> = literal
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert!(
        tier_a.len() > 20,
        "parsed only {} TIER_A entries — the literal's shape changed and this \
         check would pass vacuously",
        tier_a.len()
    );

    for t in WRITE_GATED_TABLES {
        assert!(
            tier_a.contains(t),
            "`{t}` is in WRITE_GATED_TABLES but not in TIER_A. Either it is a \
             typo, or it lost its tenancy columns and every row this lint \
             charges against it is now noise."
        );
    }
}
