//! Source lint: a repo function that takes a `&Viewer` and runs SQL must
//! actually spend it.
//!
//! # Why this file exists — and why its absence was itself the defect
//!
//! `crates/epigraph-db/src/visibility.rs` cites this file three times as the
//! mechanism that stops the lint and the repo layer drifting to two spellings
//! of "this query is filtered". `repos/lineage.rs` cites it seven times,
//! `repos/claim.rs` twice ("visibility_lint.rs — which checks that a marker is
//! present, not where"), and `docs/tenancy/FINAL-PLAN.md` lists it as PR-06's
//! gate.
//!
//! **It did not exist.** That is the same defect PR-07's own commit message
//! indicts in acceptance criterion #1: a verification cited in prose, never
//! written. It is written here.
//!
//! # The gap it closes
//!
//! `Viewer::splice`'s missing-marker panic is the primary control, and it is
//! a good one — but it only fires if `splice` is CALLED. A repo function that
//! takes a `&Viewer`, never calls `splice`, and runs its own `sqlx::query` is
//! caught by nothing. That is exactly how `belief.rs::frame_claims_sorted`
//! evaded every control PR-06 shipped: it held a viewer, built its statement
//! with `format!`, and never spliced.
//!
//! `frame_claims_sorted` lived in the route layer, where
//! `crates/epigraph-api/tests/viewer_route_table_lint.rs` now watches for it.
//! This file is the repo-layer half of the same property.
//!
//! # What it checks
//!
//! For every `fn` under `crates/epigraph-db/src/repos/` whose parameter list
//! mentions `Viewer`: if the body runs SQL (`sqlx::query…`), the body must
//! contain at least one of
//!
//! * `.splice(` — the marker path,
//! * the literal `visibility = 'public'` — the static three-bind spelling the
//!   `sqlx::query!` macro sites use, which `visibility.rs`'s module doc names
//!   as the accepted equivalent (the macro needs a compile-time literal of
//!   fixed arity and so cannot be spliced), or
//! * a `VISIBILITY-EXEMPT:` comment carrying a reason.
//!
//! The third of those is a convention the repo layer already used in a dozen
//! places before this file existed — as a `-- VISIBILITY-EXEMPT:` line inside
//! the SQL literal. Nothing read it. An exemption convention with no ratchet
//! behind it is a comment style, not a control, so
//! [`the_exemption_set_is_exactly_what_was_reviewed`] pins the exact set.
//!
//! # What it checks since PR-13: WHICH fragment, not only that there is one
//!
//! `edges` has two owning groups as of migration 072, so it takes a different
//! predicate — [`epigraph_db::visibility::Viewer::edge_predicate_fragment`],
//! spelled `/* {EDGE_VISIBILITY:<alias>} */`. Every check above is satisfied by
//! an `edges` read that uses the SINGLE-OWNER predicate: it spends its viewer,
//! it contains `visibility = 'public'`, it calls `.splice(`. It just shows a
//! cross-group edge to a principal in only one of its two owning groups.
//!
//! [`every_edges_marker_uses_the_edge_spelling_and_no_others_do`] closes that
//! by resolving each marker's alias to the table it names and requiring the two
//! to agree — in both directions, since the edge fragment names a column no
//! other table has. It is a textual approximation of a SQL parser and is
//! calibrated by [`the_edge_marker_scanner_is_not_vacuous`], because a scanner
//! that resolved every alias to `None` would be silently vacuous.
//!
//! # What it deliberately does NOT check
//!
//! **Where** the marker sits. A marker in the wrong clause — inside a `LEFT
//! JOIN`'s ON versus its WHERE, say — is a semantic question this lint cannot
//! answer, and pretending otherwise would be the same over-claim that got the
//! previous citations into trouble. `repos/claim.rs::count_all_evidence_for_claim`
//! carries a comment explaining its placement for that reason. What this lint
//! guarantees is the weaker but checkable property: **a viewer parameter is
//! never silently ignored**.
//!
//! It also cannot see a function that delegates its SQL to another function —
//! those have no `sqlx::query` in their own body and are correctly skipped,
//! because the callee is itself subject to this lint.

use std::path::{Path, PathBuf};

/// Every viewer-taking repo function carrying a `VISIBILITY-EXEMPT:` marker,
/// as measured on **2026-09-02**.
///
/// The marker convention already existed in the tree — `claim.rs`, `edge.rs`,
/// `frame.rs`, `claim_theme.rs`, `mass_function.rs` and `triple.rs` all use it,
/// mostly as a `-- VISIBILITY-EXEMPT:` comment inside the SQL literal. What did
/// not exist was anything that READ it. An exemption convention with no ratchet
/// behind it is a comment style, not a control: nothing stopped a leak being
/// annotated rather than fixed.
///
/// Three categories, all reviewed:
///
/// * **Corpus-wide maintenance enumerators** — `find_claims_needing_embeddings`,
///   `list_claim_ids`, the three `claim_theme` centroid functions. A `Scoped`
///   viewer here is not safer, it is WRONG: the enumerator would silently skip
///   every other tenant's rows, leaving them unembedded or their beliefs stale
///   forever, and report success. A theme centroid computed per-viewer would
///   give each tenant a different value for the same row.
/// * **Corpus cardinality** — `triple.rs::index_counts`, three scalars used for
///   index health.
/// * **Write paths PR-16 owns** — `evidence.rs::delete`,
///   `semantic_link.rs::retract`.
///
/// The set is asserted exactly, not just counted, so a NEW exemption is a
/// visible diff naming the function. That matters more than the total: an
/// exemption appearing on a READ path is almost always a leak being annotated.
const EXPECTED_EXEMPTIONS: &[(&str, &str)] = &[
    ("claim.rs", "find_claims_needing_embeddings"),
    ("claim_theme.rs", "assign_unthemed_batch"),
    ("claim_theme.rs", "recompute_all_centroids"),
    ("claim_theme.rs", "recompute_centroid_for_theme"),
    // PR-09. `agents` is not in migration 062's `tier_a` array — it has
    // `profile_visibility` and `default_group_id`, no `owner_group_id` — so
    // there is nothing to filter on. Corpus cardinality, same category as
    // `triple.rs::index_counts`; one scalar leaves the function.
    ("corpus_stats.rs", "agent_count"),
    ("evidence.rs", "delete"),
    ("mass_function.rs", "list_claim_ids"),
    ("semantic_link.rs", "retract"),
    ("triple.rs", "index_counts"),
];

/// The one spelling of an accepted exemption, kept next to the accepted
/// spellings of a filter so all of them are read together.
const EXEMPT_MARKER: &str = "VISIBILITY-EXEMPT:";

/// The three ways a body can legitimately spend its viewer.
///
/// `.splice(` is the READ marker path. `.splice_write(` is the WRITE marker path
/// (PR-16, delivered as 16b). `visibility = 'public'` is the leading disjunct of
/// the static three-bind form the four `sqlx::query!` macro sites use — those
/// cannot take a spliced literal, because the macro needs a compile-time literal
/// of fixed arity, so they carry the predicate verbatim.
///
/// # Why `.splice_write(` belongs here, and why this is not a weakening
///
/// This lint's rule is that a viewer-taking fn running SQL must be shown to put
/// a PREDICATE in the query — see the `group_bind()` paragraph below, which is
/// the whole reason the list names query text and mechanisms rather than
/// accessors. `Viewer::splice_write` is a predicate-installing mechanism by
/// exactly the same construction `Viewer::splice` is: it panics when its input
/// carries no `/* {WRITABLE:<alias>} */` marker, so it cannot return a string
/// that lacks a predicate. Without this entry the lint reports a CORRECTLY GATED
/// write as an unspent viewer — which it did, on
/// `evidence.rs::update_raw_content`, the first site converted — and the only
/// ways to silence it would be to annotate a gated function
/// `VISIBILITY-EXEMPT:` or to stop taking a `&Viewer`. Both are worse than the
/// false positive.
///
/// **THE LIMIT THIS ENTRY INHERITS, STATED PLAINLY.** These markers are matched
/// by a SUBSTRING SCAN OVER THE FUNCTION BODY. The scan establishes that a
/// predicate-installing mechanism was *called*; it does NOT establish that the
/// string it returned is the one that reaches `sqlx::query`. A body that splices
/// into an unused local and then executes a separately `format!`-built statement
/// passes this check — which is the `frame_claims_sorted` shape named below.
/// That limit is not new and `.splice_write(` does not widen it: `.splice(` has
/// always had it, and closing it would need data-flow analysis this lint does
/// not do. The write side is covered from the other direction by
/// `write_gate_lint.rs::UNGATED_REPO_WRITES`, which keys on the SQL TEXT of the
/// `UPDATE`/`DELETE` rather than on the call, so a spliced-but-unused local
/// leaves the real statement visible there.
///
/// **THE GRANULARITY CONSEQUENCE, WHICH IS A SEPARATE LIMIT.** The scan clears a
/// function whole. One `.splice_write(` anywhere in a body therefore spends the
/// viewer for EVERY statement in that body — so a repo fn that splices its
/// `UPDATE` and leaves an adjacent `SELECT` ungated is cleared HERE, by this
/// list, on the strength of the write it did gate. The substring limit above is
/// about whether the spliced string reaches `sqlx::query`; this one is about
/// which statements a single spent marker is allowed to speak for, and adding
/// `.splice_write(` widens the set of bodies in which the second limit can
/// bite. `write_gate_lint.rs::a_partially_converted_function_is_not_silently_cleared`
/// closes the mirror-image hole on the write side; nothing closes this one on
/// the read side today, and per-statement classification is the fix for both.
///
/// Note the two are NOT interchangeable, and nothing here suggests they are:
/// `splice` panics on a write marker and `splice_write` panics on a read one,
/// because they bind different arrays. This list records that both are
/// predicate-installing mechanisms, not that either fits anywhere.
///
/// **`group_bind()` / `bypass_bind()` / `writable_bind()` are deliberately NOT
/// on this list**, even though an earlier draft accepted the first two. Binding
/// a group array proves the caller supplied a parameter; it does not prove the
/// SQL has a predicate that reads it. A `frame_claims_sorted`-shaped fail-open —
/// `format!` the statement, omit the predicate, bind the array anyway — would
/// pass a lint keyed on the accessor and fail this one. Requiring the predicate
/// TEXT is what makes this check about the query rather than about the call.
const SPENT_MARKERS: &[&str] = &[".splice(", ".splice_write(", "visibility = 'public'"];

fn repos_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repos")
}

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
        out.push((
            name,
            std::fs::read_to_string(&path).expect("read repo file"),
        ));
    }
    out.sort();
    assert!(
        out.len() > 30,
        "expected the repos directory to hold the whole SQL surface, found {} \
         files — the lint is probably looking in the wrong place and would pass \
         vacuously",
        out.len()
    );
    out
}

/// The balanced region starting at `src[start]`, which must be `open`.
///
/// Skips string literals (normal and raw) and line comments, so braces or
/// parens inside SQL text cannot unbalance the count.
fn balanced(src: &str, start: usize, open: u8, close: u8) -> &str {
    let b = src.as_bytes();
    debug_assert_eq!(b[start], open);
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
                // A char literal such as `'{'`. Skip it wholesale so its
                // contents cannot move the depth.
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

struct ViewerFn {
    file: String,
    line: usize,
    name: String,
    /// The generic parameter list between the name and `(`, empty when there is
    /// none. Captured separately from [`Self::params`] because a bound written
    /// `fn f<'e, E: sqlx::PgExecutor<'e>>(executor: E, …)` puts the executor
    /// TYPE here and only the binding `executor: E` in the parameter list, so a
    /// check keyed on `params` alone cannot see it.
    generics: String,
    params: String,
    body: String,
}

/// Every `fn` under `src/repos/` whose parameter list mentions `Viewer`.
fn viewer_taking_fns() -> Vec<ViewerFn> {
    repo_fns()
        .into_iter()
        .filter(|f| f.params.contains("Viewer"))
        .collect()
}

/// Every `fn` under `src/repos/`, with its parameter list and body.
fn repo_fns() -> Vec<ViewerFn> {
    let mut out = Vec::new();
    for (file, src) in repo_files() {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("fn ") {
            let at = from + rel;
            from = at + 3;

            // `fn` must be a whole token.
            if at > 0 {
                let prev = src.as_bytes()[at - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }

            let after = &src[at + 3..];
            let name_end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            if name_end == 0 {
                continue;
            }
            let name = after[..name_end].to_string();

            // Skip an optional generic list, then require the parameter list.
            let mut cursor = at + 3 + name_end;
            let rest = src[cursor..].trim_start();
            let mut generics = String::new();
            if rest.starts_with('<') {
                let lt = src[cursor..].find('<').expect("just matched") + cursor;
                let g = balanced(&src, lt, b'<', b'>');
                cursor = lt + g.len();
                generics = g.to_string();
            }
            let Some(paren_rel) = src[cursor..].find('(') else {
                continue;
            };
            let paren = cursor + paren_rel;
            // Anything other than whitespace between the name and `(` means
            // this is not a declaration we can read.
            if !src[cursor..paren].trim().is_empty() {
                continue;
            }
            let params = balanced(&src, paren, b'(', b')');
            let Some(brace_rel) = src[paren + params.len()..].find('{') else {
                continue;
            };
            let brace = paren + params.len() + brace_rel;
            let body = balanced(&src, brace, b'{', b'}').to_string();

            out.push(ViewerFn {
                file: file.clone(),
                line: src[..at].matches('\n').count() + 1,
                name,
                generics,
                params: params.to_string(),
                body,
            });
        }
    }
    out
}

/// A viewer parameter must never be silently ignored by a function that runs
/// SQL.
#[test]
fn every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer() {
    let fns = viewer_taking_fns();
    assert!(
        fns.len() > 100,
        "found only {} viewer-taking repo fns — PR-06 converted ~190, so the \
         scanner is not matching declarations and this lint would pass \
         vacuously",
        fns.len()
    );

    let mut offenders = Vec::new();
    for f in &fns {
        if !f.body.contains("sqlx::query") && !f.body.contains("sqlx::raw_sql") {
            // Delegating wrapper: the callee is subject to this same lint.
            continue;
        }
        let spends = SPENT_MARKERS.iter().any(|m| f.body.contains(m));
        let exempt = f.body.contains(EXEMPT_MARKER);
        if !spends && !exempt {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese repo functions take a `&Viewer`, run SQL, and never spend \
         it:\n{}\n\n\
         A read that accepts read authority and ignores it is a fail-open that \
         compiles, passes every \"a stranger cannot read\" test (it returns \
         MORE, not less), and is invisible in a diff. `Viewer::splice`'s \
         missing-marker panic cannot catch this class, because it only fires \
         when `splice` is called at all — which is precisely how \
         `belief.rs::frame_claims_sorted` leaked.\n\n\
         Fix: add `/* {{VISIBILITY:<alias>}} */` to the SQL and wrap it in \
         `viewer.splice(..)`; or, at a `sqlx::query!` macro site, write the \
         static form `AND ($N::bool OR visibility = 'public' OR owner_group_id \
         = ANY($M::uuid[]))` and bind `viewer.bypass_bind()` / \
         `viewer.group_bind()`. If the function is a write path PR-16 owns, add \
         a `{EXEMPT_MARKER}` comment WITH A REASON and raise the count in \
         EXPECTED_EXEMPTIONS.\n",
        offenders.join("\n")
    );
}

/// The exemption list is a ratchet, not a category.
///
/// Without this, `VISIBILITY-EXEMPT:` would be a comment anyone can type to
/// silence the lint above. Asserting the exact set makes every new exemption a
/// visible diff in review.
#[test]
fn the_exemption_set_is_exactly_what_was_reviewed() {
    let mut actual: Vec<(String, String)> = viewer_taking_fns()
        .into_iter()
        .filter(|f| f.body.contains(EXEMPT_MARKER))
        .map(|f| (f.file, f.name))
        .collect();
    actual.sort();

    let mut want: Vec<(String, String)> = EXPECTED_EXEMPTIONS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        actual, want,
        "\n\nThe `{EXEMPT_MARKER}` set changed. Every current entry is either a \
         corpus-wide maintenance enumerator (where a Scoped viewer would be \
         WRONG, not safer), a corpus-cardinality scalar, or a write path PR-16 \
         owns. A new exemption on a READ path is almost certainly a leak being \
         annotated rather than fixed.\n"
    );
}

/// Repo functions that take a `&mut PgConnection` and NO `Viewer`, each with
/// the reason. Asserted as an exact set, in both directions, by
/// [`every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`].
///
/// Keyed on `(file, fn)` the same way [`EXPECTED_EXEMPTIONS`] is, so a new
/// entry is a visible diff naming the function.
///
/// # The last eleven entries arrived with a selector change, not a tree change
///
/// The block at the end of this array, under its own banner comment, is the
/// register the widened selector produced. Those eleven functions were in the
/// tree before and are unchanged by it; what changed is that the lint can now
/// see them. Read them as a first review, not as a regression — and read the
/// count `43 → 54` the same way.
const CONN_WITHOUT_VIEWER: &[(&str, &str, &str)] = &[
    (
        "claim.rs",
        "update_labels_conn",
        "WRITE. Label mutation on a claim the caller has already fetched under a viewer predicate \
         on the same connection; under migration 077 the claims_tenancy WITH CHECK (keyed on \
         epigraph_writable_groups()) is what authorises the row, not a read predicate. The \
         write-side gate is 16b's, not this lint's.",
    ),
    (
        "claim.rs",
        "update_trace_id_conn",
        "WRITE. Same argument as update_labels_conn: an UPDATE on an already-fetched claim, \
         authorised by claims_tenancy's WITH CHECK rather than by a spliced read predicate.",
    ),
    (
        "claim.rs",
        "update_truth_value_conn",
        "WRITE. Same argument as update_labels_conn: an UPDATE on an already-fetched claim, \
         authorised by claims_tenancy's WITH CHECK rather than by a spliced read predicate.",
    ),
    (
        "claim_encryption.rs",
        "get_by_claim_id_conn",
        "READ, and the only exempt read that touches a tenanted table — so it is the one to \
         re-check. Its two callers (routes/claims.rs::get_claim and the batch sibling) both run it \
         on the SAME transaction immediately after ClaimRepository::get_by_id_conn(&mut tx, \
         &viewer, id) has already resolved the parent claim under the viewer predicate, so the \
         authority decision has been made one statement earlier on the same connection. \
         claim_encryption is additionally in migration 077's `enc` protected array, so RLS \
         backstops it from step 11d onward. A shard that ever calls this WITHOUT the preceding \
         gated fetch must give it a Viewer instead of inheriting this entry.",
    ),
    (
        "claim_encryption.rs",
        "insert_conn",
        "WRITE. Writes the encryption row for a claim created in the same transaction; the row's \
         tenancy is the parent claim's, established by the INSERT that precedes it.",
    ),
    (
        "event.rs",
        "publish_or_log_conn",
        "WRITE, append-only. Publishes an event row inside the caller's transaction and returns \
         only the new id. The read side of `events` is where tenancy is enforced \
         (EventRepository::list, and hidden_claim_ids for the Rust-callable half); an append has \
         no rows to filter.",
    ),
    (
        "group_key_epoch.rs",
        "create_epoch_conn",
        "WRITE. Creates a key epoch for a group inside the membership/rotation transaction that \
         has already authorised the group. group_key_epochs carries its own policy in migration \
         077 (section 8), which is what gates the row once step 11d lands.",
    ),
    (
        "group_membership.rs",
        "get_member_role_conn",
        "READ of `group_memberships`, which carries neither `visibility` nor `owner_group_id` — it \
         is not in migration 062's tier_a array and schema_contract.rs pins its eight columns — so \
         there is no predicate a Viewer could be spent on. It answers the authorization question \
         itself (is this principal an admin of THIS group) for POST /groups/:id/rotate, on the \
         same ScopedPool::begin_as transaction that performs the rotation, so the decision and \
         the write cannot be taken on different connections. Its tenancy backstop is migration \
         077 section 7's group_memberships_tenancy policy, which selects on the CONNECTION.",
    ),
    (
        "group_key_epoch.rs",
        "rotate_conn",
        "Two READs with nothing to filter on. The `group_memberships` read is the live roster the \
         rotation locks FOR UPDATE, and that table carries neither `visibility` nor \
         `owner_group_id` — it is not in migration 062's tier_a array — so there is no predicate \
         a Viewer could be spent on; narrowing it to a viewer's own memberships would break the \
         very contract the function enforces, which is that the submission covers EVERY live \
         member. The `groups` read is `properties->>'kms_key_ref'` on the one group the caller \
         has already been authorised as an admin of, on this same stamped transaction. Its \
         tenancy backstop is migration 077 section 7's group_memberships_tenancy policy and the \
         groups_tenancy policy, both of which select on the CONNECTION.",
    ),
    (
        "oauth_client.rs",
        "get_by_id_conn",
        "READ, but of a table with NO tenancy at all. `oauth_clients` has neither `visibility` nor \
         `owner_group_id`, is in none of migration 077's protected arrays, and 077 states in its \
         own comment that it deliberately gets NO policy and is NOT in 079's array — because a \
         policy there would make the token mint's `UPDATE oauth_clients SET agent_id` match zero \
         rows. There is nothing for a Viewer to filter on; adding one would be decoration.",
    ),
    (
        "privatization.rs",
        "load_plan_conn",
        "READ of `privatization_plans`, which has NO tenancy column at all — no `visibility`, no \
         `owner_group_id` — so there is no predicate to splice and a `Viewer` parameter could not \
         be spent. Its tenancy is migration 087's `privatization_plans_read` policy (instance \
         admin AND group admin of the plan's target group), which selects on the CONNECTION, so \
         this must be given a STAMPED app connection; on a maintenance connection \
         `epigraph_bypass()` is true and the policy admits every row. The projected columns carry \
         no entity ids.",
    ),
    (
        "privatization.rs",
        "list_plans_conn",
        "READ of `privatization_plans`, same absent-tenancy-column argument as `load_plan_conn`. \
         It is the one of the three that does NOT rely on 087's policy alone: FINAL-PLAN §6.6's \
         conjunction is spliced into its `WHERE` from the same session helpers the policy uses, so \
         two independent filters bind. That predicate is written by hand rather than by \
         `Viewer::splice`, because a `Viewer` filters on row columns this table does not have.",
    ),
    (
        "privatization.rs",
        "load_plan_items_conn",
        "READ of `privatization_plan_items`, which likewise has no `visibility` and no \
         `owner_group_id`; migration 087's `privatization_plan_items_read` resolves the target \
         group THROUGH the plan row. Its projection DOES carry entity ids, and 087's policy is not \
         the same property as being able to read each selected claim — so its caller must re-render \
         them through `visible_previews`, which takes the actor's viewer. A future widening of this \
         statement into a join on `claims` would be a viewer-less read of tenanted content and must \
         take a `&Viewer` instead of inheriting this entry.",
    ),
    // ---- PR-18 (18c): the apply/revert state machine. --------------------
    //
    // Nineteen entries at once, and the shape of the argument is the same for
    // all of them, so it is stated here rather than nineteen times: NONE of
    // `privatization_plans`, `privatization_plan_items` or `privatization_audit`
    // has a `visibility` column or an `owner_group_id`, so there is no predicate
    // for a `Viewer` to splice and a `Viewer` parameter could not be spent. Their
    // tenancy is migrations 083/087/088's policies, which select on the
    // CONNECTION. Each entry below says which connection it must be given and
    // what goes wrong on the other one, because that — not a viewer — is the
    // control.
    (
        "privatization.rs",
        "load_plan_for_update_conn",
        "READ of `privatization_plans` with `FOR UPDATE`, for the job handler's re-validation. \
         MUST be the maintenance connection: on a stamped app connection 087's SELECT policy \
         hides a plan the session does not administer, and a job handler has no session principal \
         at all, so it would read `None` for every plan and abort legitimate work. The row lock is \
         the point — the six conditions must be checked against a row nothing can move before the \
         state flip.",
    ),
    (
        "privatization.rs",
        "transition_plan_conn",
        "WRITE. The plan state machine (approve / dispatch / cursor / finish), authorised by \
         migration 088's bypass-only UPDATE policy and by 080's `pp_four_eyes` CHECK and 081's \
         approver guard, which bind the maintenance connection too. There is nothing to filter: \
         every arm names one plan by primary key and returns a row COUNT, never a row.",
    ),
    (
        "privatization.rs",
        "frozen_digest_conn",
        "READ of `privatization_plan_items`, projecting `(kind, entity_id)` into a BLAKE3 digest \
         and returning 32 bytes. The entity ids never leave the function, which is why this is not \
         the disclosure `load_plan_items_conn` is fenced against. Maintenance connection: the \
         digest must describe the WHOLE frozen set, and a policy-filtered subset would hash to \
         something else and refuse every apply.",
    ),
    (
        "privatization.rs",
        "is_live_group_admin_conn",
        "READ of `group_memberships`, which carries no `visibility` column. MUST be the \
         maintenance connection: migration 077's policy narrows that table to what the session can \
         see, and this asks about the APPROVER rather than about the session, so on an app \
         connection an authorised approver reads as revoked. Returns a boolean and no rows.",
    ),
    (
        "privatization.rs",
        "begin_batch_conn",
        "Neither read nor write: `SET LOCAL lock_timeout`, `SET LOCAL statement_timeout` and the \
         one global `pg_advisory_xact_lock` every privatization batch serialises on (ops F12). It \
         touches no table, so there is no tenancy to filter; it takes a connection because a \
         `SET LOCAL` and an advisory lock are properties of a transaction rather than of a pool.",
    ),
    (
        "privatization.rs",
        "next_batch_conn",
        "READ of `privatization_plan_items` with `FOR UPDATE`, one batch of work. Its projection \
         DOES carry entity ids, and the reason that is not a disclosure is that its ONLY caller is \
         a job handler with no requesting principal, whose use of those ids is to write them into \
         `claims` and `privatization_audit`. Maintenance connection: a filtered batch would leave \
         items pending while the plan advanced to `applied`.",
    ),
    (
        "privatization.rs",
        "mark_items_conn",
        "WRITE of `privatization_plan_items.state`, authorised by migration 088's bypass-only \
         UPDATE policy. Takes the ids the batch has just processed and returns a row count; there \
         is no read whose result reaches a caller.",
    ),
    (
        "privatization.rs",
        "restrict_claims_conn",
        "WRITE of `claims.visibility` and `claims.owner_group_id` — the whole of `restrict` mode. \
         This is a tenanted table, and it takes no `Viewer` because a viewer predicate on a \
         privatization UPDATE would narrow it to what somebody can already see, which is the \
         opposite of the operation. The authorisation is FINAL-PLAN §6.5.5's re-validation in the \
         job handler; the D4 admin surface is what §0.1 grants this write to.",
    ),
    (
        "privatization.rs",
        "restore_claims_conn",
        "WRITE of `claims.visibility` and `claims.owner_group_id`, restoring the values the freeze \
         captured. Same argument as `restrict_claims_conn` and one addition: it sets \
         `epigraph.allow_declassify` for the transaction, which migration 074's own comment names \
         'the admin declassification surface'. It restores a value the database recorded rather \
         than one a caller supplied, and the sealed arm of that guard has no override and is not \
         reachable from here.",
    ),
    (
        "privatization.rs",
        "recompute_boundary_meet_conn",
        "WRITE of `edges` tenancy — the endpoint meet (§6.5.3), re-run after a batch. `edges` is \
         tenanted and takes no `Viewer` for `restrict_claims_conn`'s reason: the meet is computed \
         FROM the endpoints' stored tenancy through `epigraph_node_tenancy`, so a viewer-narrowed \
         read of the endpoints would compute a meet from rows it could see and stamp the rest \
         wrong.",
    ),
    (
        "privatization.rs",
        "sealed_item_count_conn",
        "READ of `claim_encryption` joined to `privatization_plan_items`, returning a COUNT and no \
         ids. It answers ops-F13's question — may this plan be reverted — and the count is the \
         number the 409 carries. Maintenance connection, because a filtered count would report \
         zero sealed items to a caller who cannot read them and permit a revert that then fails \
         `42501` mid-batch.",
    ),
    (
        "privatization.rs",
        "shared_fragment_count_conn",
        "READ of `harvester_claim_provenance` joined to `privatization_plan_items`, returning a \
         COUNT of FRAGMENT IDS and enumerating none of them — no claim id, no fragment id and no \
         text crosses the boundary. It is the magnitude behind the seal preview's unconditional \
         `unrecoverable` sentence, which already tells the operator that a shared fragment is \
         blanked for the claims outside the plan too. Maintenance connection, and that is the \
         point of the entry: the claims that make a fragment SHARED are by definition outside \
         this plan, so they are exactly the rows the actor may have no right to see. A filtered \
         count would report zero sharing to an operator whose seal shares plenty, understating \
         the very loss the sentence exists to disclose. What the actor is told is one integer \
         keyed on the EXISTENCE of rows outside the plan — which is a different shape from \
         `sealed_item_count_conn`, and is stated rather than borrowed: that one counts rows \
         INSIDE the plan. The argument for this entry is its own. The caller has already \
         passed `require_instance_admin_for_group` for the target group, and the preview it \
         feeds already returns several bypass-derived aggregates over the same unfiltered \
         closure (`authors_losing_own_claims`, `boundary_edge_counts`, `not_visible_to_actor`), \
         so one more integer grants no capability the route did not already grant. Note the \
         limit plainly: a plan built one claim at a time makes this count a per-fragment \
         existence signal, which is the reason the entry needs the admin gate above it rather \
         than the analogy.",
    ),
    (
        "privatization.rs",
        "item_state_counts_conn",
        "READ of `privatization_plan_items`, GROUPed to `state -> count`. Serves `GET /plans/:id`'s \
         live-progress block, so it MUST be given the actor's STAMPED app connection: 087's policy \
         is what makes it a histogram of a plan the caller administers. It returns counts and no \
         entity ids either way, which is why a policy-filtered result is the right answer here and \
         a wrong one for `frozen_digest_conn` two entries up.",
    ),
    (
        "privatization.rs",
        "record_plan_audit_conn",
        "WRITE, append-only. `privatization_audit` is append-only by three independent controls \
         (082's trigger, its REVOKE, and the absence of an UPDATE or DELETE policy), so there is \
         nothing here that can rewrite history. An append has no rows to filter.",
    ),
    (
        "privatization.rs",
        "record_item_audit_conn",
        "WRITE, append-only, set-based. Reads `privatization_plan_items` and `claims` INSIDE the \
         INSERT so the audit row describes the rows at the end of the batch transaction rather \
         than what Rust believed at the start of it. Maintenance connection: a filtered read there \
         would silently write fewer audit rows than items processed.",
    ),
    (
        "privatization.rs",
        "load_audit_conn",
        "READ of `privatization_audit`, serving `GET /admin/privatization/audit`. MUST be the \
         actor's STAMPED app connection. Its tenancy is migration 083's `privatization_audit_read`, \
         which admits plan-level rows to an instance admin and entity-level rows only where the \
         caller administers the plan's target group — resolved through a sub-select over \
         `privatization_plans` that 087's policy filters in turn. Two policies deep, both \
         properties of the connection; on the maintenance connection this is the instance-wide \
         read FINAL-PLAN §6.5.8 argues against.",
    ),
    // NOTE: `create_followup_drift_plan_conn` was in this list and is NOT any
    // more. It now takes the bypass `&Viewer` so it can COMPUTE the follow-up
    // plan's `authors_losing_count` instead of asserting zero, which puts it
    // under `every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer`
    // instead — the stronger of the two lints. Removing it here is the exact
    // half of that change; this register is exact in both directions.
    (
        "privatization.rs",
        "enqueue_job_conn",
        "WRITE of `jobs`, on the connection that flipped the plan, so the state change and the \
         enqueue commit together. `jobs` has no `visibility` column; migration 077's `jobs_app` \
         policy is what gates it, and its `WITH CHECK` refuses `privatization_*` job types from the \
         app role. Returns the new job id and reads nothing.",
    ),
    (
        "privatization.rs",
        "applied_entity_ids_conn",
        "READ of `privatization_plan_items`, projecting the entity ids of items in \
         `state='applied'` as the drift rescan's seed set. This is the one function in the module \
         that hands a bare id list to a caller without an actor's viewer in sight; it is sound \
         because its single caller is a JOB HANDLER with no requesting principal, and the ids' only \
         destinations are `drift_ids`, a follow-up plan's frozen items and `privatization_audit` — \
         three FORCE-protected tables read back through a policy. Never a response body.",
    ),
    (
        "privatization.rs",
        "active_epoch_conn",
        "READ of `group_key_epochs`, returning ONE integer and no ids. That table carries neither \
         `visibility` nor `owner_group_id` — it is keyed on `group_id` and is not in migration \
         062's tier_a array — so there is no predicate a Viewer could be spent on. Its tenancy \
         backstop is migration 077 section 8's group_key_epochs policy, which selects on the \
         CONNECTION. The group whose epoch it resolves is the plan's own `target_group_id`, which \
         the caller has already been authorised against under FINAL-PLAN §6.6.",
    ),
    (
        "privatization.rs",
        "plan_contains_conn",
        "READ of `privatization_plan_items`, projecting the INTERSECTION of a caller-supplied id \
         list with a plan's frozen set — so it returns only ids the caller already named, and can \
         disclose nothing the caller did not already hold. It is the check that a seal-commit \
         names only claims an operator actually approved. `privatization_plan_items` has no \
         `visibility` column; migration 087's read policy on the plan tables selects on the \
         CONNECTION, and the caller has already been authorised for this plan under §6.6.",
    ),
    (
        "privatization.rs",
        "record_seal_audit_conn",
        "WRITE, append-only, of `privatization_audit`, and the first writer of that table's \
         `before_sealed` / `after_sealed` columns. It appends one row per entity inside the same \
         transaction as the seal or unseal it attests to; there is no read whose result could \
         widen. `privatization_audit` carries no `visibility` column and is gated on the READ side \
         by migration 082's `privatization_audit_read` policy.",
    ),
    (
        "privatization.rs",
        "seal_tcb_shape_conn",
        "READ of `claim_versions` and `evidence`, projecting IDS ONLY and no content. It answers \
         the completeness question for FINAL-PLAN §6.5.6 — which rows a seal-commit must cover — \
         and a viewer-filtered answer is the failure it exists to prevent: a shape narrowed to what \
         the actor can read would declare a commit complete while a version row the actor cannot \
         see keeps its plaintext. Its only caller has already been authorised under §6.6 for the \
         plan whose frozen item set bounds the id list, and the ids reach a refusal message, never \
         a content projection.",
    ),
    (
        "privatization.rs",
        "seal_claims_conn",
        "WRITE, and the whole §6.5.4 mutation: it writes the three encryption tables and empties \
         `claims`, `claim_versions`, `evidence` and `harvester_fragments` of plaintext. Every one \
         of those tables is in migration 077's protected set, so the `WITH CHECK` on the \
         maintenance connection is the control, not a read predicate. It is bounded to the ids its \
         own first statement inserted, which is what makes the set that gains a ciphertext row and \
         the set that loses its plaintext the same set.",
    ),
    (
        "privatization.rs",
        "unseal_manifest_page_conn",
        "READ of `claim_encryption`, `claim_version_encryption` and `evidence_encryption`, which \
         carry `group_id` but no `visibility`, and whose projection is CIPHERTEXT bound to a key \
         the server does not hold. There is no plaintext for a predicate to protect. Their tenancy \
         backstop is migration 077's `enc` policy loop, which selects on the CONNECTION; the \
         authority for knowing WHICH claims are sealed is §6.6's, checked in the route.",
    ),
    (
        "privatization.rs",
        "unseal_claims_conn",
        "WRITE, and the widest one in this module: it writes CLIENT-SUPPLIED plaintext into \
         `claims`, `claim_versions` and `evidence`. The maintenance connection is why it can write \
         at all, so 077's `WITH CHECK` is not the constraint on WHAT it writes and must not be \
         cited as one. What bounds it is, in order: the caller proves every claim id is a frozen \
         item of the plan whose target group §6.6 authorised the actor over; the head UPDATE \
         additionally requires a `claim_encryption` row bound to THAT group, so a claim sealed \
         under another group's key is unreachable; the version and evidence UPDATEs carry the \
         parent claim id through the `unnest` and match on it, so a row id is addressable only \
         through the claim it belongs to; and the ciphertext DELETEs are keyed on what was \
         restored, so an incomplete commit strands a ciphertext row rather than destroying the \
         only remaining copy of a plaintext. The server cannot check the plaintext it is handed — \
         it holds no key — so these predicates are the whole of the protection.",
    ),
    (
        "privatization.rs",
        "unseal_tcb_shape_conn",
        "READ of `claim_encryption`, `claim_version_encryption` and `evidence_encryption`, \
         projecting IDS ONLY and no ciphertext, for claim ids the caller already named and only \
         where the row is bound to the plan's target group. It answers the unseal-side cover \
         question — which ciphertext rows a commit must account for — for a caller that has \
         already passed §6.6 and plan membership. A scoped viewer has no predicate to contribute: \
         there is no plaintext here and the group binding is an explicit argument rather than a \
         viewer-derived one.",
    ),
    (
        "privatization.rs",
        "stale_epoch_seal_count_conn",
        "READ of the three encryption tables and `group_key_epochs`, returning ONE integer and no \
         ids. It answers §6.7 point 3's completion question — are any of this group's ciphertext \
         rows still bound to a retired epoch — for a JOB HANDLER that has no requesting principal. \
         A count narrowed to a viewer's own groups would answer zero for the operator who most \
         needs the real number.",
    ),
    (
        "privatization.rs",
        "clear_reseal_required_conn",
        "WRITE of one column on one `groups` row, and the ONLY writer of `reseal_required_at` back \
         to NULL. `groups` carries no `visibility`; migration 077 section 7's groups_tenancy policy \
         is its control and selects on the CONNECTION. Its single caller is the reseal job handler, \
         which calls it only after `stale_epoch_seal_count_conn` has returned zero on the same \
         transaction.",
    ),
    (
        "security_event.rs",
        "log_conn",
        "WRITE, append-only, of `security_events`. The connection is a parameter so the event and \
         the plan state flip it attests to commit in ONE transaction: FINAL-PLAN §6.5.5's sixth \
         re-validation condition compares the two, and an event written on a separate pool \
         connection can commit while the flip rolls back. No `RETURNING`, because PostgreSQL \
         applies the SELECT policy to a `RETURNING` projection and an event about another \
         principal would be refused while the identical bare INSERT succeeds.",
    ),
    (
        "security_event.rs",
        "correlation_is_attributed_to_conn",
        "READ of `security_events`, returning a BOOLEAN and no rows. It is the machine form of \
         FINAL-PLAN §6.5.5's sixth condition. MUST be the maintenance connection: migration 077's \
         `security_events_read` is keyed on the session principal and a job handler has none, so on \
         an app connection it answers `false` for every correlation id and the handler refuses \
         every plan. It fails CLOSED in both directions — a missing row and a wrong agent are the \
         same answer.",
    ),
    (
        "provenance.rs",
        "append_conn",
        "WRITE, append-only, into `provenance_log`. It records who authorised a write that the \
         caller has already performed in the same transaction; there is no read whose result could \
         widen.",
    ),
    // ---------------------------------------------------------------------
    // Surfaced by the SIGNATURE selector, not by any change to these
    // functions. Every entry below already existed and already took a
    // `&mut PgConnection` without a `Viewer`; the previous name-suffix rule
    // simply did not look at them. Each was read individually for this
    // register.
    // ---------------------------------------------------------------------
    (
        "agent.rs",
        "ensure_for_client",
        "WRITE, plus the two lookups it needs. Locks one `oauth_clients` row `FOR UPDATE`, may \
         adopt an existing `agents` row by public key, and links the two. Neither table is \
         tenancy-partitioned: `oauth_clients` has no `visibility` and no `owner_group_id` at all, \
         and `agents` is deliberately `USING (true)` under migration 077 because authorship has to \
         render on a public claim. The PII on `agents.properties` is narrowed by the repo-layer \
         projection in `public_profile`, which this function does not use and does not return.",
    ),
    (
        "agent.rs",
        "ensure_personal_group",
        "WRITE, idempotent, of one `groups` row via `epigraph_ensure_personal_group`. `groups` \
         carries no `visibility`; migration 077 section 7's groups_tenancy policy is its control \
         and selects on the CONNECTION. It resolves a NAMED agent's own personal group and returns \
         only that group's id — the agent id is the caller's input, so no row the caller did not \
         already name can come back.",
    ),
    (
        "agent.rs",
        "operator_actor",
        "READ through migration 107's `epigraph_operator_actor` SECURITY DEFINER function, not of \
         a table. It must answer on an UNSTAMPED epigraph_app session (brief constraint 4: a \
         viewer-gated read there is blind and turns read-then-mint into re-mint), so a Viewer \
         would be the wrong control. It returns only (operator agent id, operator personal group \
         id) for the NAMED agent — the operator relationship is public through the OPERATED_BY \
         edge (agent endpoints stamp ('public', world) in 070/072) and a personal group's id \
         derives from the public `did:epigraph:personal:<agent>` key; 107 section 5 records the \
         one liveness bit it adds.",
    ),
    (
        "agent.rs",
        "operator_of_author",
        "READ through migration 107's `epigraph_operator_of_author` SECURITY DEFINER function; \
         same reason as `operator_actor`. It returns only (operator agent id, operator personal \
         group id, retired) for the NAMED agent.",
    ),
    (
        "agent.rs",
        "operates_agents",
        "READ through migration 107's `epigraph_operates_agents` SECURITY DEFINER function; \
         same reason as `operator_actor`. It returns one boolean for the NAMED agent (does any \
         link name it as operator), used only to REFUSE an HTTP listener's signer.",
    ),
    (
        "agent.rs",
        "link_operator",
        "WRITE through migration 107's `epigraph_link_operator` SECURITY DEFINER function, which \
         is EXECUTE-able by epigraph_maintenance only; the CONNECTION's privilege is the \
         authorisation (an epigraph_app connection gets 42501), so there is nothing for a Viewer \
         to filter. Returns only the outcome of the named (agent, operator) link.",
    ),
    (
        "agent.rs",
        "link_retired_agent",
        "WRITE through migration 107's `epigraph_link_retired_agent` SECURITY DEFINER function, \
         EXECUTE-able by epigraph_maintenance only, exactly as `link_operator`: the CONNECTION's \
         privilege is the authorisation, so there is nothing for a Viewer to filter. Returns only \
         the outcome of the named (agent, operator) retired link.",
    ),
    (
        "agent.rs",
        "public_key_if_signer",
        "READ of `agents`, projecting `public_key` for one id already held by the caller, and only \
         where `key_kind = 'ed25519'`. `agents` is deliberately not tenancy-partitioned — \
         migration 077's policy on it is `USING (true)` with its own `VISIBILITY-EXEMPT` marker, \
         because authorship must render on a public claim. The `key_kind` filter is itself the \
         narrowing this function exists for: it is what signature verification calls so that a \
         derived OAuth placeholder's bytes can never be mistaken for a signer's key.",
    ),
    (
        "claim.rs",
        "default_decl_for_author",
        "Runs NO SQL of its own. It wraps `personal_group_of` — registered immediately below, and \
         subject to this same lint — in a `TenancyDecl` for a named agent. Registered rather than \
         skipped: this lint has no delegating-wrapper exception today, and adding one would widen \
         what it cannot see in the same change that widens what it can. A register row is a \
         visible diff; a new skip rule is not.",
    ),
    (
        "claim.rs",
        "personal_group_of",
        "READ of `groups` by the deterministic `did:epigraph:personal:<agent_uuid>` key, falling \
         back to `AgentRepository::ensure_personal_group` when absent. `groups` carries no \
         `visibility` column; migration 077 section 7's groups_tenancy policy is its control and \
         selects on the CONNECTION. The agent id is the caller's own input and one group id is the \
         entire result, so there is no set a predicate could narrow.",
    ),
    (
        "claim.rs",
        "create_with_tx",
        "WRITE path into `claims` (LEGACY content-hash dedup), plus the dedup SELECT that is part \
         of the mutation. Migration 077's `WITH CHECK` rather than a read predicate is the \
         control, exactly as for the `*_conn` writes above. The dedup read already carries its own \
         `VISIBILITY-EXEMPT` marker in the SQL; note that marker is INERT for \
         `the_exemption_set_is_exactly_what_was_reviewed`, which inspects only viewer-taking \
         functions, and this one takes no viewer.",
    ),
    (
        "claim.rs",
        "create_strict",
        "WRITE into `claims`, a single INSERT with an explicit `visibility` and `owner_group_id` \
         supplied by the caller's `TenancyDecl`. It is the D1-compliant creation path: ownership \
         is a required argument rather than a column default, and migration 077's `WITH CHECK` is \
         what refuses a declaration the writer may not make. `RETURNING` projects back only the \
         row this statement just inserted.",
    ),
    (
        "instance_admin.rs",
        "privatization_authority",
        "READ of `group_memberships` and `groups`, returning four scalars and no ids. It MUST run \
         unfiltered on the maintenance connection and its own doc says why: a count of a target \
         group's other live admins narrowed to what the CALLER can see would report zero for a \
         caller who cannot see the roster, and refuse — a fail-closed wrong answer that is \
         indistinguishable from the true one. A viewer predicate here would corrupt the \
         authorisation decision rather than protect it.",
    ),
    (
        "oauth_client.rs",
        "set_agent_id",
        "WRITE of one column, write-once. `oauth_clients` has no tenancy at all — neither \
         `visibility` nor `owner_group_id` — the same absent-column argument as `get_by_id_conn` \
         above. The `AND agent_id IS NULL` guard is the control that matters here: it makes the \
         link unrebindable, so a re-mint or a raced first-mint can never transfer the ownership \
         and membership decisions made under the old identity.",
    ),
    (
        "privatization.rs",
        "create_previewed_plan",
        "WRITE of one `privatization_plans` row in the `previewed` state. `privatization_plans` \
         has NO tenancy column at all — no `visibility`, no `owner_group_id` — the same argument \
         `load_plan_conn` above makes for reads of it. Migration 087's policies plus the guard \
         that `RAISE`s (which the route maps to 403) are the control on who may create one.",
    ),
    (
        "privatization.rs",
        "freeze_into",
        "WRITE into `privatization_plan_items`, whose `INSERT ... SELECT` joins `claims` to record \
         each item's prior state. It belongs to the SELECTION pass, which this module's own docs \
         require to run UNFILTERED under a bypass viewer: a selection narrowed to what the actor \
         can see would silently omit exactly the rows privatization exists to catch and then \
         report success. Nothing crosses to the caller — the return value is the row COUNT, and \
         ids and content are re-filtered under the actor's own viewer by `visible_previews`.",
    ),
];

/// A connection-taking repo fn must spend a viewer, or say in writing why it
/// has none.
///
/// # Why this rule exists at all
///
/// [`every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer`] inspects only
/// functions whose PARAMETER LIST mentions `Viewer`. A connection-taking
/// function that simply omits the `Viewer` parameter is therefore invisible to
/// it — and PR-23 made `*_conn` siblings the standard conversion shape for the
/// sites `epigraph-db/tests/no_unscoped_pool.rs` registers. Without this
/// rule, a sibling written without a viewer would pass BOTH controls: this file
/// would not inspect it, and the ratchet would count its call site as converted
/// because the `.db_pool` access is gone. The two together would certify
/// "converted" for a read that filters on nothing.
///
/// # The selector is the SIGNATURE, and was the NAME until this change
///
/// The rule used to be "the name ends `_conn` **and** the parameter list
/// mentions `PgConnection`". The name half was the hole, and PR-18 fell in it:
/// its third slice shipped `load_plan`, `list_plans` and `load_plan_items`
/// viewer-less and connection-taking, registered nowhere, purely because of what
/// they were called — and they were RENAMED to earn their registration rather
/// than the lint being widened. Renaming to satisfy a lint is not a fix; it
/// teaches the next author that the control is a spelling convention.
///
/// PR-18's own doc recorded the widening — "parameter list mentions
/// `PgConnection`" — as a deferred follow-up, on the grounds that it changes
/// this lint's contract across the whole repo layer and a route slice should not
/// make that decision alone. This change IS that follow-up, so the reason for
/// deferring no longer applies.
///
/// **The cost was real and is paid in [`CONN_WITHOUT_VIEWER`], not hidden.** The
/// widening surfaced **eleven** previously-unreviewed functions and the register
/// went 43 → 54. None of them changed; the scanner's vision did. Each was read
/// individually and carries its own reason naming the table.
///
/// # Measured, by this test's own rule, at the time of the widening
///
/// Eighty-one repo fns take a `PgConnection` in their parameter list: 27 take a
/// `Viewer` and the 54 below are enumerated with reasons. Fifty-two functions
/// have a name ending `_conn`, which is why a bare grep disagrees with the
/// register in both directions — it catches
/// `ClaimRepository::patch_claim_atomic_conn` (whose parameter is a
/// `Transaction`, not a `PgConnection`, so this rule correctly skips it) and it
/// misses all eleven of the functions the widening added. Quote the rule with
/// the number; the two are not interchangeable.
///
/// # What this rule still cannot see
///
/// Two residuals, and the second is about SCOPE rather than spelling. Naming
/// only the first would leave this paragraph asserting safety by omission — the
/// defect species this whole batch exists to remove.
///
/// 1. **Spelling.** A `Transaction` parameter, as the `patch_claim_atomic_conn`
///    case shows. The generic `E: sqlx::PgExecutor<'e>` spelling is covered
///    separately by [`every_executor_taking_repo_fn_takes_a_viewer_or_is_exempt`];
///    between the two, the remaining uncovered executor spelling is the
///    transaction.
/// 2. **Scan root.** [`repo_files`] is a NON-RECURSIVE `read_dir` of
///    `crates/epigraph-db/src/repos/`, so all three registers see that directory
///    and nothing else. `repos/` has no subdirectories today, so nothing inside
///    the root is missed; but a connection-taking function written anywhere else
///    — a route, a middleware, a job, `epigraph-db/src/pool.rs` — is outside
///    every register here. Those live under their own controls, not this one.
///    Widening the root is a contract change of the same size as the name →
///    signature widening this test just made, and is left as a follow-up rather
///    than smuggled in beside it.
#[test]
fn every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt() {
    let mut without: Vec<(String, String)> = Vec::new();
    let mut with_viewer = 0usize;

    for f in repo_fns() {
        // THE SIGNATURE, NOT THE NAME. `repo_fns` does not strip comments, and
        // this predicate is also what keeps a doc line that spells out a
        // signature from registering as a declaration — a `///` line quoting
        // `fn foo(` parses as a declaration whose "parameter list" is whatever
        // follows, and it will not mention `PgConnection` unless the prose
        // genuinely reproduces the whole signature.
        if !f.params.contains("PgConnection") {
            continue;
        }
        if f.params.contains("Viewer") {
            with_viewer += 1;
        } else {
            without.push((f.file, f.name));
        }
    }
    without.sort();
    without.dedup();

    // Floors, not measurements. 81 and 27 at the widening; these sit well below
    // so that a shard deleting real functions does not have to edit them, while
    // a scanner that stopped matching declarations still falls through.
    assert!(
        with_viewer + without.len() >= 60,
        "found only {} connection-taking repo fns — the scanner is not matching declarations and \
         this lint would pass vacuously",
        with_viewer + without.len()
    );
    assert!(
        with_viewer >= 15,
        "only {with_viewer} connection-taking repo fns take a Viewer. The conversion shape PR-23 \
         established has been abandoned; that is a decision, not a refactor."
    );

    let mut want: Vec<(String, String)> = CONN_WITHOUT_VIEWER
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        without, want,
        "\n\nThe set of viewer-less connection-taking repo fns changed. A `&mut PgConnection` \
         parameter is the shape a conversion shard writes when it moves a handler onto \
         `AppState::read_as` — whatever the function is CALLED — and one \
         written WITHOUT a Viewer is invisible to \
         `every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer` AND counts as converted in \
         `no_unscoped_pool.rs`. If the new function is a read, give it a `&Viewer` and splice the \
         marker. If it genuinely has nothing to filter, add it to CONN_WITHOUT_VIEWER with a \
         reason naming the table and why.\n"
    );

    for (file, name, reason) in CONN_WITHOUT_VIEWER {
        assert!(
            reason.len() > 80,
            "the reason for {file}::{name} is {} chars. State the table and why it has no \
             tenancy to filter on, not a label.",
            reason.len()
        );
    }
}

/// Repo functions generic over [`sqlx::PgExecutor`] that take NO `Viewer`, each
/// with the reason. Asserted as an exact set, in both directions, by
/// [`every_executor_taking_repo_fn_takes_a_viewer_or_is_exempt`].
///
/// It was EMPTY through PR-27, and that was the measured state rather than an
/// aspiration: all 188 functions PR-27 widened already took a `&Viewer` before
/// it widened them, and it added no new function. PR-29 added the first two
/// entries, because conversion shard 3 is the first shard whose call sites
/// bottom out in reads of tables that have no tenancy at all — PR-27 re-measured
/// only the functions that took BOTH a pool and a `&Viewer`, so a viewer-less
/// read was outside its scope by construction rather than by judgement.
///
/// Keyed on `(file, fn)` the same way [`EXPECTED_EXEMPTIONS`] and
/// [`CONN_WITHOUT_VIEWER`] are, so each entry is a visible diff naming the
/// function.
const EXECUTOR_WITHOUT_VIEWER: &[(&str, &str, &str)] = &[
    // ── THE THREE WRITES. Every other entry in this register is a READ with
    // nothing to filter; these are the first writes, and the argument is a
    // different one, so it is stated in full rather than borrowed.
    (
        "trace.rs",
        "create",
        "INSERT INTO `reasoning_traces`. A WRITE, which is what makes this entry different in          kind from every read above: the control on a write is not an in-query viewer predicate          but migration 077's `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))`,          evaluated by PostgreSQL against the CONNECTION's session GUCs. A `&Viewer` parameter          here would be spent on nothing -- `Viewer::splice` has no marker to fill on an INSERT          with no FROM -- while `Viewer::splice_write` is PR-16's, not this change's. WHY THE          EXECUTOR MOVED: the only connection that can satisfy that `WITH CHECK` is one stamped          by `ScopedPool::begin_as`, which hands back a transaction; a `&PgPool` parameter made          this function unreachable from the one connection shape that works, which is why every          MCP `reasoning_traces` INSERT failed with `42501` once the deployed DSN moved to          `epigraph_app`. `rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`          is the pin on both halves (arm 1 refuses unstamped, arm 3 admits author-stamped).          SCOPE: the executor widened, the SQL is byte-identical and was not re-derived.",
    ),
    (
        "evidence.rs",
        "create",
        "INSERT INTO `evidence`. Same argument as `trace.rs::create` above -- a write, whose          authorization is the connection's stamped GUCs evaluated by the table's `WITH CHECK`,          not an in-query predicate -- and it moved for the same reason: the `evidence` INSERT          belongs in the SAME transaction as the claim it derives from, which a `&PgPool`          parameter cannot express. ONE DIFFERENCE WORTH RECORDING so nobody concludes this          widening was unnecessary: a deployment may carry an orphan PERMISSIVE          `evidence_privacy` policy, present in no migration of the 077 series, whose          unconditional USING is reused as its WITH CHECK -- which is the only reason an          UNSTAMPED evidence INSERT succeeds there, and is what made the 42501 look like a          `reasoning_traces`-only defect. That is an accident of a deployment, not a property of          the schema. SCOPE: executor only; the SQL is unchanged.",
    ),
    (
        "edge.rs",
        "create",
        "INSERT INTO `edges`. Same write-side argument as the two above. It moved because a          verb-edge (`AUTHORED`, `DERIVED_FROM`, `HAS_TRACE`) is emitted ABOUT a row the same          submission just wrote: once that row's INSERT lives in a transaction, an edge emitted          on a different connection points at a row no other session can see yet. NOTE FOR A          CALLER PASSING A TRANSACTION, which the function's own doc also carries: a failed          statement aborts the whole PostgreSQL transaction, so `let _ = create(...)` does NOT          preserve best-effort semantics there -- it defers the failure to COMMIT as          `current transaction is aborted` with the cause gone.          `epigraph-mcp/src/claim_helper.rs::emit_verb_edge_best_effort` wraps it in a SAVEPOINT          for exactly that reason. SCOPE: executor only; the SQL is unchanged.",
    ),
    (
        "method.rs",
        "get",
        "Reads `methods` by primary key, and the statement's FROM is `methods` alone -- it joins \
         nothing. `methods` is global reference data: measured at migration head 91 it has \
         neither a `visibility` nor an `owner_group_id` column, and row-level security is off on \
         it (`pg_class.relrowsecurity` and `relforcerowsecurity` are both false, against `claims` \
         which is true/true). This SITE therefore has no predicate to add to the table it reads, \
         and no RLS policy for a session GUC to select. SCOPE, stated so this entry is not read \
         as blessing more than it measured: PR-29 widened the executor only. The SQL is \
         unchanged, the projected row shape is unchanged, and neither was re-derived here.",
    ),
    (
        "claim_theme.rs",
        "find_similar_themes_at_dim",
        "Reads `claim_themes` centroids to rank themes by vector similarity. `claim_themes` is \
         derived corpus-level clustering output with the same posture as `methods`: measured at \
         migration head 91 it carries neither a `visibility` nor an `owner_group_id` column, and \
         row-level security is off on it (`relrowsecurity` and `relforcerowsecurity` both false). \
         The claim-level read that follows theme selection is \
         `ClaimThemeRepository::claims_in_themes_at_dim_since`, which DOES take a `&Viewer` and \
         splices it. PR-29 widened the executor only; the SQL is unchanged.",
    ),
    (
        "agent.rs",
        "get_by_id",
        "Reads `agents` by primary key; the statement's FROM is `agents` alone and it joins \
         nothing. THIS ENTRY'S ARGUMENT DIFFERS FROM THE TWO ABOVE AND IS STATED AS IT ACTUALLY \
         IS: `methods` and `claim_themes` carry no RLS at all, whereas `agents` DOES \
         (`relrowsecurity` is true) -- its SELECT policy simply does not narrow anything. \
         `migrations/077_rls_policies.sql` section 9 creates `agents_identity ON public.agents \
         FOR SELECT TO PUBLIC USING (true)` and gives the reason in the migration: \
         `agents.id`/`display_name`/`public_key` `must render authorship on public claims, so \
         the ROW is universally readable and PostgreSQL has no column-level RLS to narrow it`. \
         That migration names `AgentRepository::get_by_id` EXPLICITLY among the functions which \
         `take no Viewer and return the full row`, and points at the compensating projection -- \
         `profile_visibility` gating `properties`/`orcid`/`ror_id` -- implemented in exactly one \
         function, `agent.rs::get_public_profile`. The residual that leaves is already on record \
         as `D-PR17-agent-projection-enforced-at-one-call-site`; this entry does not discharge \
         it and does not re-derive it. SCOPE: conversion shard 5 widened the executor ONLY, so \
         that the five `routes/political.rs` handlers calling this beside a viewer-spliced \
         `PoliticalRepository` read can run both statements on ONE stamped connection. The SQL, \
         its binds and the projected row shape are unchanged and were not re-derived here. \
         REACH IS WIDER THAN MOTIVATION: those five are why the signature moved, not the whole \
         caller set. EIGHT other production call sites across six files -- `routes/agents.rs` \
         (2), `routes/crud.rs` (2), and one each in `routes/claims.rs`, `routes/submit.rs`, \
         `routes/webhooks.rs::agent_principal_exists` and \
         `epigraph-engine/src/export/prov.rs` -- were not touched and still pass `&PgPool`, \
         which satisfies `E: PgExecutor<'e>`. That count was TEN with `routes/agents.rs` at four \
         when shard 5 wrote this entry; conversion shard 6 moved two of those four \
         (`get_agent_reputation` and `agent_claims`) onto a stamped connection, and the number \
         is re-measured here rather than left to read as still current. Stated for the same \
         reason the SQL/executor split above is stated: so a reader does not mistake the \
         motivation for the inventory.",
    ),
    (
        "experiment.rs",
        "get_for_hypothesis",
        "Reads `experiments` by `hypothesis_id`, and the statement's FROM is `experiments` alone \
         -- it joins nothing. `experiments` is one of the relations migration 062's `tier_a` \
         roots do NOT reach: measured at migration head 92 it carries neither a `visibility` nor \
         an `owner_group_id` column, and row-level security is off on it \
         (`pg_class.relrowsecurity` and `relforcerowsecurity` both false, against `claims` which \
         is true/true). So this site has no column to attach a predicate to and no policy for a \
         session GUC to select, and a `&Viewer` here would be a parameter the statement could \
         not spend. THE VISIBLE ROW SET IS UNCHANGED BY THE CONVERSION, which is the honest \
         statement: its caller `routes/hypothesis.rs::hypothesis_status` reads this beside four \
         tenancy-carrying reads, and the reason it now shares their connection is that the \
         handler's answer should be assembled under ONE tenancy stamp, not that this read was \
         leaking. SCOPE: \
         conversion shard 6 widened the executor only. The SQL, its single bind and the \
         projected row shape are unchanged and were not re-derived here. REACH IS WIDER THAN \
         MOTIVATION: five other production call sites -- the `method_search`, `experiment`, \
         `protocol_gen` and `hypothesis` binaries in `epigraph-cli`, and \
         `epigraph-api/src/routes/experiment_loop.rs` -- still pass `&PgPool`, which satisfies \
         `E: PgExecutor<'e>`, and none was edited.",
    ),
    (
        "method.rs",
        "get_methods_for_capability",
        "Reads `methods` JOINed to `method_capabilities`, and BOTH relations in that FROM are \
         global reference data with no tenancy: measured at migration head 92 neither carries a \
         `visibility` or an `owner_group_id` column, and row-level security is off on both \
         (`relrowsecurity` and `relforcerowsecurity` false on each). That is the same argument \
         `method.rs::get` above makes for the same table, EXTENDED TO THE JOIN PARTNER rather \
         than inherited from the file name -- a one-table claim would not have covered the \
         second relation, and a join to a FORCEd table would have made this site filterable \
         after all. SCOPE: conversion shard 6 widened the executor only, so that \
         `routes/experiments.rs::method_gap_analysis` can interleave this with the two \
         viewer-spliced `MethodRepository` reads it issues per method on ONE stamped connection. \
         The SQL, its bind and the projected row shape are unchanged. It has exactly one caller, \
         that handler, so reach and motivation coincide here -- unlike the `agent.rs` entry \
         above, where they do not.",
    ),
    (
        "workflow.rs",
        "search_hierarchical_by_text",
        "Reads the `workflows` table by ILIKE over `canonical_name`/`goal`, and the statement's \
         FROM is `workflows` alone -- it joins nothing. `workflows` is the HIERARCHICAL root \
         table, which is a different relation from the `claims` rows labelled `workflow` that \
         `WorkflowRepository::list`/`find_by_embedding` read and DO splice a viewer into; the \
         distinction is why this entry exists beside functions in the same file that need none. \
         Measured at migration head 92 it carries neither a `visibility` nor an `owner_group_id` \
         column, and row-level security is off on it (`pg_class.relrowsecurity` and \
         `relforcerowsecurity` both false, against `claims` which is true/true). So this site has \
         no column to attach a predicate to and no policy for a session GUC to select, and a \
         `&Viewer` here would be a parameter the statement could not spend. THE VISIBLE ROW SET \
         IS UNCHANGED BY THE CONVERSION: its caller \
         `routes/workflows.rs::find_workflow_hierarchical` reads this beside \
         `resolve_steps_to_heads_batched`, which is viewer-spliced over `edges` and `claims`, and \
         the reason it now shares that connection is that the handler's answer should be \
         assembled under ONE tenancy stamp, not that this read was leaking. SCOPE: conversion \
         shard 7 widened the executor only. The SQL, its three binds and the projected row shape \
         are unchanged and were not re-derived here. REACH IS WIDER THAN MOTIVATION: one other \
         production call site -- `epigraph-mcp/src/tools/workflow_hierarchical.rs` -- still \
         passes `&PgPool`, which satisfies `E: PgExecutor<'e>`, and was not edited.",
    ),
    (
        "workflow.rs",
        "find_hierarchical_by_embedding",
        "Cosine-similarity search over `workflows.goal_embedding`; the statement's FROM is \
         `workflows` alone (cross-joined to a one-row `q` CTE holding the query vector) and it \
         joins no other relation. Same relation and same measured posture as \
         `search_hierarchical_by_text` above -- at migration head 92 `workflows` carries neither \
         a `visibility` nor an `owner_group_id` column and has row-level security off \
         (`relrowsecurity` and `relforcerowsecurity` both false) -- but the argument is RESTATED \
         rather than inherited from the file name, because these are two different statements and \
         a shared file proves nothing about either. This is the embedding-ranked sibling of the \
         ILIKE path and falls back to it, so the two must agree about what they may return. \
         SCOPE: conversion shard 7 widened the executor only; the SQL, its four binds and the \
         projected row shape are unchanged. REACH IS WIDER THAN MOTIVATION: one other production \
         call site -- `epigraph-mcp/src/tools/workflow_hierarchical.rs` -- still passes \
         `&PgPool` and was not edited.",
    ),
    (
        "behavioral_execution.rs",
        "rolling_success_rate",
        "Aggregates `AVG(success::int)` over the newest `window` rows of `behavioral_executions` \
         for one workflow. The statement's FROM is `behavioral_executions` alone, and what it \
         projects is a single `float8` SCALAR -- there is no row to withhold and no content \
         column in the result at all. Measured at migration head 92 the relation carries neither \
         a `visibility` nor an `owner_group_id` column, and row-level security is off on it \
         (`relrowsecurity` and `relforcerowsecurity` both false). THE SCOPE LIMIT, STATED: what \
         this relation's posture leaves open is the `F-aggregate-existence-oracles` class, filed \
         against other handlers with an owner that is not this shard, and widening an executor \
         neither creates nor closes it. SCOPE: conversion shard 7 widened the \
         executor only so that `routes/workflows.rs::search_workflows` can run this beside the \
         viewer-spliced `find_by_embedding`/`find_by_text`/`find_lineage_root` reads on ONE \
         stamped connection. The SQL, its two binds and the scalar result type are unchanged. \
         REACH IS WIDER THAN MOTIVATION: one other production call site -- \
         `epigraph-mcp/src/tools/workflows.rs` -- still passes `&PgPool` and was not edited.",
    ),
    (
        "entity.rs",
        "get",
        "Reads `entities` by primary key; the statement's FROM is `entities` alone and it joins \
         nothing. `entities` is the RDF entity dictionary -- canonical names and type tags, with \
         the tenancy-bearing assertions held one level out in `triples`. Measured at migration \
         head 92 it carries neither a `visibility` nor an `owner_group_id` column, and row-level \
         security is off on it (`relrowsecurity` and `relforcerowsecurity` both false), against \
         `triples` in the very next statement of the same handler, which is true/true with a \
         narrowing policy AND is viewer-spliced. So this site has no column to attach a predicate \
         to and no policy for a session GUC to select. SCOPE: conversion shard 7 widened the \
         executor only, so that `routes/entities.rs::entity_neighborhood` can resolve the \
         canonical entity and read its triples under ONE tenancy stamp. The SQL, its single bind \
         and the projected row shape are unchanged and were not re-derived here. REACH IS WIDER \
         THAN MOTIVATION: one other production call site -- `epigraph-mcp/src/tools/rdf.rs` -- \
         still passes `&PgPool`, which satisfies `E: PgExecutor<'e>`, and was not edited.",
    ),
    (
        "entity.rs",
        "find_by_name_and_type",
        "Resolves a caller-supplied `(canonical_name, type_top)` pair to an entity id, \
         case-insensitively and restricted to `is_canonical = true`. Same relation and same \
         measured posture as `entity.rs::get` above -- at migration head 92 `entities` carries \
         neither a `visibility` nor an `owner_group_id` column and has row-level security off \
         (`relrowsecurity` and `relforcerowsecurity` both false) -- restated rather than \
         inherited, because this is a NAME-KEYED resolution rather than a primary-key fetch and \
         the two are not the same statement. Its caller \
         `routes/entities.rs::query_triples` returns an EMPTY list rather than an error when the \
         name does not resolve, which is documented on that handler, and the assertions it then \
         reads are viewer-spliced over `triples`, which IS rls/force with a narrowing policy at \
         head 92. SCOPE: conversion \
         shard 7 widened the executor only. The SQL, its two binds and the projected row shape \
         are unchanged. REACH IS WIDER THAN MOTIVATION: three other production call sites, all \
         in `epigraph-mcp/src/tools/rdf.rs`, still pass `&PgPool` and were not edited.",
    ),
    // ── FIVE MORE WRITES, from the conversion of the MCP tools PR #494 left
    // unconverted. Same argument as the three writes at the top of this
    // register — the control on a write is migration 077's `WITH CHECK`
    // evaluated against the CONNECTION's session GUCs, not an in-query viewer
    // predicate — so each entry below states only what is specific to it.
    (
        "challenge.rs",
        "create",
        "INSERT INTO `challenges`. A WRITE, so its control is migration 077's \
         `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` evaluated against the \
         connection's session GUCs, and a `&Viewer` here would be spent on nothing: the \
         statement is an INSERT with no FROM, so `Viewer::splice` has no marker to fill. WHY THE \
         EXECUTOR MOVED: `challenges` carries NO orphan `*_privacy` policy, so unlike `claims` / \
         `evidence` / `edges` it is refused with `42501` on an unstamped session in PRODUCTION as \
         well as on a clean migrate — MEASURED with the real binary as `epigraph_app` on both \
         schema configurations, `challenge_claim` returning `new row violates row-level security \
         policy for table \"challenges\"` and writing nothing. The only connection that can \
         satisfy that check comes from `ScopedPool::begin_as`, which hands back a transaction. \
         WHOSE group: the row is claim-derived, so 074's `epigraph_derived_require_tenancy` fills \
         its tenancy from the CHALLENGED CLAIM and 070 arm (c) re-stamps it unconditionally — the \
         check is about the claim's owning group, not the challenger's, and \
         `tool_write_tables_require_a_stamp.rs` pins all three directions of that. SCOPE: the \
         executor widened, the SQL is byte-identical and was not re-derived.",
    ),
    (
        "frame.rs",
        "assign_claim",
        "INSERT INTO `claim_frames` (ON CONFLICT DO UPDATE). A write with the same control as the \
         entries above, and the same absence of an orphan `*_privacy` policy to fall back on: \
         `submit_ds_evidence` was MEASURED returning `new row violates row-level security policy \
         for table \"claim_frames\"` on BOTH schema configurations, which is why `claim_frames` \
         stayed empty in production. The executor moved so this assignment and the BBA that gives \
         it meaning can share ONE stamped transaction — a frame membership with no mass function \
         moves no belief, and a BBA whose claim is not assigned to the frame is unreachable from \
         `recompute_claim_belief_on_frame`'s enumeration. Tenancy is inherited from the parent \
         claim by 074/070, exactly as for `challenge.rs::create`. SCOPE: executor only; the SQL \
         is unchanged.",
    ),
    (
        "mass_function.rs",
        "store_with_perspective",
        "INSERT INTO `mass_functions` (ON CONFLICT on `(claim_id, frame_id, source_agent_id, \
         perspective_id)` DO UPDATE). Same write-side control as the entries above. This is the \
         table whose EMPTINESS was the original symptom: its last successful production write was \
         2026-09-22 and it stayed 0 through every e2e run, so every `supports` / `refutes` edge \
         created since the deployed DSN moved to `epigraph_app` moved NO belief mass. The \
         executor moved so it can join `frame.rs::assign_claim` in one author-stamped \
         transaction. The ON CONFLICT is also what makes a caller's RETRY safe after a failure \
         further down its own pipeline — the same BBA is re-stored rather than combined twice — \
         which is why this half was convertible ahead of the pool-bound DS recompute it feeds. \
         SCOPE: executor only; the SQL is unchanged.",
    ),
    (
        "claim.rs",
        "deprecate_claim",
        "UPDATE `claims` SET `is_current = false`, `truth_value = 0.05`, `embedding = NULL`. A \
         write, so the control is `claims_tenancy`'s `WITH CHECK` against the connection's GUCs; \
         a `&Viewer` would be spendable only through `splice_write`, which is PR-16's marker and \
         not this change's, and the UPDATE is by primary key. WHY THE EXECUTOR MOVED: \
         `deprecate_workflow` calls this once per node while CASCADING over a variant tree, so a \
         refusal partway through left a HALF-DEPRECATED hierarchy — some variants flipped, some \
         still current, and `find_workflow_hierarchical` returning the ones that were missed. One \
         transaction for the whole cascade is what removes that state, and a `&PgPool` parameter \
         cannot express it. SCOPE: executor only; the SQL is unchanged.",
    ),
    (
        "workflow.rs",
        "set_truth_value",
        "UPDATE `workflows` SET `truth_value`. THE ONE ENTRY HERE THAT IS NOT ABOUT A REFUSAL, \
         and the distinction is measured rather than assumed: at migration head 101 `workflows` \
         has `relrowsecurity` and `relforcerowsecurity` both FALSE, no policy, and no entry in \
         migration 062's `tier_a` array — so unlike the `claims` UPDATE it cascades from, this \
         statement is NOT refused on an unstamped session and a `&Viewer` would have nothing to \
         filter on either. The executor moved for COHESION: `deprecate_workflow` flips the flat \
         claim and this hierarchical row as two halves of ONE deprecation, and a `claims` row \
         marked `is_current = false` whose `workflows` row keeps its truth value is exactly the \
         split the cascade exists to prevent — `find_workflow_hierarchical` reads the half that \
         was missed. SCOPE: executor only; the SQL is unchanged.",
    ),
];

/// A generic-executor repo fn must spend a viewer, or say in writing why it has
/// none — the same rule [`every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`]
/// applies to `*_conn` siblings, for the shape PR-27 introduced.
///
/// # Why a second test rather than widening the first
///
/// The `_conn` rule keys on the NAME (`ends_with("_conn")`) and then on
/// `params.contains("PgConnection")`. A function written
/// `pub async fn f<'e, E: sqlx::PgExecutor<'e>>(executor: E, …)` matches
/// NEITHER: it has no `_conn` suffix, and its executor type lives in the generic
/// list rather than the parameter list. Widening the first test cannot reach it,
/// because the name filter drops it before the parameter filter ever runs.
///
/// That matters because the generic form accepts a `&mut PgConnection`, so it is
/// a connection-taking repo function by capability even though it is not one by
/// spelling — and PR-27 made it the recommended shape for the single-statement
/// majority. Without this test the hazard the `_conn` rule's own assert message
/// names would simply have a second, unguarded spelling: a read written in the
/// generic form without a `Viewer` would be invisible to
/// [`every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer`] (which filters
/// on `params.contains("Viewer")`) while `no_unscoped_pool.rs` counted its call
/// site as converted, because the `.db_pool` access is gone.
///
/// # Non-vacuity
///
/// The floor is a floor, not the measurement: 188 such functions exist as of
/// PR-27, and a later shard widening more must not have to edit this number. A
/// scanner that stopped matching declarations would fall under it and fail here
/// rather than passing over an empty set.
#[test]
fn every_executor_taking_repo_fn_takes_a_viewer_or_is_exempt() {
    let mut without: Vec<(String, String)> = Vec::new();
    let mut with_viewer = 0usize;

    for f in repo_fns() {
        // Both spellings of the bound: the explicit generic PR-27 used, and
        // `impl PgExecutor<'_>` in argument position, which is equivalent for a
        // single use and would otherwise slip past a generics-only check.
        if !(f.generics.contains("PgExecutor") || f.params.contains("PgExecutor")) {
            continue;
        }
        if f.params.contains("Viewer") {
            with_viewer += 1;
        } else {
            without.push((f.file, f.name));
        }
    }
    without.sort();
    without.dedup();

    assert!(
        with_viewer + without.len() >= 150,
        "found only {} generic-executor repo fns — 188 existed when this lint was written, so \
         the scanner is not matching declarations and this lint would pass vacuously",
        with_viewer + without.len()
    );

    let mut want: Vec<(String, String)> = EXECUTOR_WITHOUT_VIEWER
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        without, want,
        "\n\nThe set of viewer-less generic-executor repo fns changed. A `PgExecutor` parameter \
         accepts a connection, so this is a connection-taking repo function whatever it is \
         called, and one written WITHOUT a Viewer is invisible to \
         `every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer` AND counts as converted in \
         `no_unscoped_pool.rs`. If the new function is a read, give it a `&Viewer` and splice the \
         marker. If it genuinely has nothing to filter, add it to EXECUTOR_WITHOUT_VIEWER with a \
         reason naming the table and why.\n"
    );

    for (file, name, reason) in EXECUTOR_WITHOUT_VIEWER {
        assert!(
            reason.len() > 80,
            "the reason for {file}::{name} is {} chars. State the table and why it has no \
             tenancy to filter on, not a label.",
            reason.len()
        );
    }
}

/// The unconditional `unwrap_or(&[])` bind form and a SPLICED statement must
/// never appear in the same repo function.
///
/// # What the hazard is, in terms of the mechanism
///
/// `Viewer::render_fragment` short-circuits a `Bypass` viewer to `" "`, so a
/// `Bypass` splice "can never emit a `$`". `group_bind()` returns `None` for
/// `Bypass` to match, and `splice_write`'s own doc states the consequence: the
/// conditional bind at the call site "is not optional" — `writable_bind()`
/// returning `None` for `Bypass` "is what makes the guard and the rendered arity
/// agree". `unwrap_or(&[])` discards exactly that `None`. On a spliced string it
/// binds a parameter the rendered SQL has no placeholder for, so the guard and
/// the arity disagree and the statement's correctness depends on which viewer
/// shape arrives at runtime.
///
/// # Why this is a lint and not a bug report
///
/// `F-unconditional-group-bind-on-base` alleged this was live. It was CLOSED as
/// not-reproducible: the sites that `unwrap_or(&[])` are all FIXED-ARITY
/// statements — `sqlx::query!` macro sites, which need a compile-time literal
/// and so carry the predicate verbatim, plus one static `query_as` — where the
/// predicate is unconditionally present and the bind always has its placeholder.
/// Re-measured here at the time this lint was written and still true: **zero**
/// functions combine the two.
///
/// A measurement that has to be redone by hand is not a control. This keeps the
/// finding closed by construction, so the next author who adds `unwrap_or(&[])`
/// beside a splice learns it from a build failure rather than from a re-audit
/// that may not happen.
///
/// # The granularity is the FUNCTION, and that is a deliberate over-approximation
///
/// It reports a function that has a spliced statement somewhere and an
/// unconditional bind somewhere, without proving they are the same statement.
/// That direction is the safe one — it can only refuse a mixture, never permit
/// one — and it matches the granularity the rest of this file already uses for
/// [`SPENT_MARKERS`]. A function that legitimately needs both would be a real
/// finding to argue in review, not a false alarm to suppress: today none exists.
#[test]
fn no_spliced_statement_binds_the_unconditional_group_array() {
    // The form that discards the `None` a Bypass viewer produces.
    const UNCONDITIONAL_BINDS: &[&str] = &[
        "group_bind().unwrap_or(",
        "writable_bind().unwrap_or(",
        "bypass_bind().unwrap_or(",
    ];
    // The forms that build a statement whose predicate can be absent.
    const SPLICED: &[&str] = &[".splice(", ".splice_write("];

    let fns = repo_fns();
    let mut offenders = Vec::new();
    let mut spliced_fns = 0usize;
    let mut unconditional_fns = 0usize;

    for f in &fns {
        let splices = SPLICED.iter().any(|m| f.body.contains(m));
        let unconditional = UNCONDITIONAL_BINDS.iter().any(|m| f.body.contains(m));
        if splices {
            spliced_fns += 1;
        }
        if unconditional {
            unconditional_fns += 1;
        }
        if splices && unconditional {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    // NON-VACUITY, both halves. A scanner that matched no splices, or no
    // unconditional binds, would report a clean tree forever — and this lint's
    // whole claim is that the two populations are large and DISJOINT, which is
    // only worth asserting while both are non-empty. Floors, not measurements:
    // 180 spliced and 30 unconditional when this was written.
    assert!(
        spliced_fns >= 120,
        "found only {spliced_fns} repo fns that splice a viewer — the scanner is not matching \
         bodies and this lint would pass vacuously over an empty set"
    );
    assert!(
        unconditional_fns >= 20,
        "found only {unconditional_fns} repo fns using the unconditional `unwrap_or` bind form. \
         That form is legitimate at a fixed-arity macro site, and this lint's claim is that it \
         never meets a splice — if the population is empty, the claim is vacuous"
    );

    assert!(
        offenders.is_empty(),
        "\n\nThese repo functions build a SPLICED statement and also bind a viewer array with \
         the unconditional `unwrap_or(..)` form:\n{}\n\n\
         A `Bypass` viewer renders the fragment as a single space and emits no placeholder, so \
         `group_bind()` / `writable_bind()` return `None` and the call site must bind nothing. \
         `unwrap_or(&[])` discards that `None` and binds anyway, so the guard and the rendered \
         arity disagree.\n\n\
         Fix: use the conditional form the mechanism is built around —\n\
         `if let Some(g) = viewer.group_bind() {{ q = q.bind(g); }}`\n\n\
         The unconditional form is correct ONLY at a `sqlx::query!` macro site, where the \
         predicate is a compile-time literal of fixed arity and its placeholder is always \
         present. Those sites do not splice, which is why the two never meet.\n",
        offenders.join("\n")
    );
}

/// The lint and the repo layer must not drift to spellings of the marker that
/// only one of them knows.
///
/// There are exactly TWO spellings, and both are constants in `visibility.rs`:
/// [`epigraph_db::visibility::VISIBILITY_MARKER_PREFIX`] and, since PR-13,
/// [`epigraph_db::visibility::EDGE_VISIBILITY_MARKER_PREFIX`]. The second exists
/// because the marker's alias is a text substitution and not a dispatch key —
/// `e` names `edges` in `repos/structural.rs` and `evidence` in
/// `repos/evidence.rs`, so the `edges` co-ownership fragment cannot be selected
/// by alias. See `visibility.rs`'s module docs.
///
/// WIDENED, NOT WEAKENED. A `.splice(` body carrying NEITHER spelling is still
/// an offender, which is the whole assertion: `splice` panics at runtime on a
/// marker-free literal, and this test turns that into a compile-time-shaped
/// failure. What changed is only that an `edges`-only statement is now
/// legitimate rather than reported.
#[test]
fn every_spliced_statement_carries_the_canonical_marker_spelling() {
    let prefix = epigraph_db::visibility::VISIBILITY_MARKER_PREFIX;
    let edge_prefix = epigraph_db::visibility::EDGE_VISIBILITY_MARKER_PREFIX;
    // Statements built with `format!` double their braces, so the marker reads
    // `/* {{VISIBILITY:` in source. Accept both spellings of the same thing.
    let doubled = prefix.replace('{', "{{");
    let edge_doubled = edge_prefix.replace('{', "{{");

    // The two prefixes must stay disjoint strings. If `EDGE_VISIBILITY` ever
    // became a superstring of `VISIBILITY` (or vice versa), `splice`'s two
    // substitution passes would capture each other's markers and this test
    // would accept a statement that filters nothing.
    assert!(
        !edge_prefix.contains(prefix) && !prefix.contains(edge_prefix),
        "the two marker spellings must not contain one another: \
         {prefix} / {edge_prefix}"
    );

    let mut offenders = Vec::new();
    for f in viewer_taking_fns() {
        if !f.body.contains(".splice(") {
            continue;
        }
        let carries = f.body.contains(prefix)
            || f.body.contains(&doubled)
            || f.body.contains(edge_prefix)
            || f.body.contains(&edge_doubled);
        if !carries {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese functions call `Viewer::splice` on SQL that carries neither \
         `{prefix}` nor `{edge_prefix}` (nor their `format!`-doubled forms \
         `{doubled}` / `{edge_doubled}`):\n{}\n\n\
         `splice` panics at runtime on a marker-free literal, so this would be \
         caught the first time the query executes — but only if a test touches \
         it. Catching it here makes it a compile-time-shaped failure.\n",
        offenders.join("\n")
    );
}

/// Every `edges` read that filters must use the EDGE spelling, and no other
/// table may.
///
/// This is the ratchet PR-13's conversion needs and the plain lint cannot give:
/// `visibility = 'public'` appears in both fragments, so a statement that
/// filters `edges` with the SINGLE-OWNER predicate spends its viewer, carries a
/// canonical marker, and passes every existing assertion here — while a
/// cross-group edge remains visible to a principal in only one of its two
/// owning groups. That is a leak that looks exactly like compliance.
///
/// The scan is textual and deliberately crude: for each marker, find the
/// nearest preceding binding of its alias inside the same statement and check
/// which table it names. It is therefore an approximation of the SQL parser
/// nobody wants to write here, and it is calibrated by
/// [`the_edge_marker_scanner_is_not_vacuous`] below.
///
/// # Two bounds this does NOT cover — state them rather than imply completeness
///
/// **1. Directory.** It reads [`repo_files`], i.e. `crates/epigraph-db/src/repos`
/// only. The other `.splice(` call sites in the workspace —
/// `epigraph-mcp/src/tools/{ds_auto,workflows,ds,link_epistemic}.rs` and
/// `epigraph-api/src/routes/cross_source.rs` — are outside it. Every one of
/// those filters `claims` today, so this is a reach limit and not a live leak;
/// an `edges` read added to a route handler or an MCP tool would evade it in
/// both directions. `epigraph-mcp/tests/tool_viewer_is_spent.rs` and
/// `epigraph-api/tests/viewer_route_table_lint.rs` already scan those trees and
/// are where the check would be widened.
///
/// **2. Marker sites only.** It resolves markers, so it is structurally blind
/// to the static `sqlx::query!` / `query_as!` transcriptions, which carry no
/// marker and spell the predicate inline. Those are the majority of PR-13's
/// converted `edges` surface (`edge.rs`, `paper.rs`, `provenance_chain.rs`,
/// `claim.rs`). A future `edges` read written as a macro with the single-owner
/// spelling spends its viewer, contains `visibility = 'public'`, carries no
/// `.splice(` and carries no marker — so it passes every check in this file,
/// including this one. The conversion is complete TODAY (no `edges` read
/// outside the documented exemptions still uses the single-owner form); it is
/// the RATCHET that covers the marker half only.
#[test]
fn every_edges_marker_uses_the_edge_spelling_and_no_others_do() {
    let mut plain_on_edges = Vec::new();
    let mut edge_on_other = Vec::new();

    for (file, src) in repo_files() {
        for (line, alias, is_edge, table) in markers_with_their_tables(&src) {
            match (table.as_deref(), is_edge) {
                (Some("edges"), false) => plain_on_edges.push(format!(
                    "  {file}:{line} — alias `{alias}` names `edges` but takes \
                     the single-owner predicate"
                )),
                (Some(t), true) if t != "edges" => edge_on_other.push(format!(
                    "  {file}:{line} — alias `{alias}` names `{t}`, which has no \
                     co_owner_group_id column"
                )),
                _ => {}
            }
        }
    }

    assert!(
        plain_on_edges.is_empty(),
        "\n\nThese `edges` reads filter on `owner_group_id` alone:\n{}\n\n\
         An edge whose endpoints are private to different groups G and H is \
         stored as (owner = G, co_owner = H) since migration 072. The \
         single-owner predicate shows it to any principal in G, including one \
         with no access to H's endpoint. Use `/* {{EDGE_VISIBILITY:<alias>}} */`.\n",
        plain_on_edges.join("\n")
    );
    assert!(
        edge_on_other.is_empty(),
        "\n\nThese non-`edges` reads use the EDGE marker:\n{}\n\n\
         `co_owner_group_id` exists only on `edges`; the rendered predicate \
         would be a runtime `column does not exist` error, which is \
         compile-time-clean.\n",
        edge_on_other.join("\n")
    );
}

/// The scanner above is an approximation, so it is calibrated rather than
/// trusted: a scanner that resolved every alias to `None` would make the
/// ratchet vacuous and stay green forever.
#[test]
fn the_edge_marker_scanner_is_not_vacuous() {
    let plain = "let sql = viewer.splice(\"SELECT 1 FROM claims c \
                 WHERE true /* {VISIBILITY:c} */\", 2);";
    let edges = "let sql = viewer.splice(\"SELECT 1 FROM edges e \
                 WHERE true /* {EDGE_VISIBILITY:e} */\", 2);";
    let mixed = "let sql = viewer.splice(\"SELECT 1 FROM evidence e JOIN edges ed \
                 ON ed.source_id = e.id /* {EDGE_VISIBILITY:ed} */ \
                 WHERE true /* {VISIBILITY:e} */\", 3);";

    let got = markers_with_their_tables(plain);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].2, got[0].3.as_deref()), (false, Some("claims")));

    let got = markers_with_their_tables(edges);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].2, got[0].3.as_deref()), (true, Some("edges")));

    // The collision that motivates the second spelling: `e` is `evidence` and
    // `ed` is `edges`, in ONE statement.
    let got = markers_with_their_tables(mixed);
    assert_eq!(got.len(), 2, "{got:?}");
    let by_alias: std::collections::HashMap<_, _> = got
        .iter()
        .map(|(_, a, is_edge, t)| (a.clone(), (*is_edge, t.clone())))
        .collect();
    assert_eq!(
        by_alias["ed"],
        (true, Some("edges".to_string())),
        "{by_alias:?}"
    );
    assert_eq!(
        by_alias["e"],
        (false, Some("evidence".to_string())),
        "{by_alias:?}"
    );

    // A SCHEMA-QUALIFIED table resolves to its bare name.
    //
    // Both directions are asserted because the qualifier broke both. The
    // second is the one that mattered: before the fix, `FROM public.edges e`
    // with the SINGLE-OWNER marker resolved to `public.edges`, missed the
    // `Some("edges")` arm, and read as compliance — so the qualified spelling
    // was a way to write the exact leak this file exists to refuse.
    let qualified_edge = "let sql = viewer.splice(\"SELECT 1 FROM public.edges e \
                          WHERE true /* {EDGE_VISIBILITY:e} */\", 2);";
    let got = markers_with_their_tables(qualified_edge);
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].2, got[0].3.as_deref()),
        (true, Some("edges")),
        "a schema-qualified edges read must resolve to `edges`, or the correct EDGE spelling is \
         reported as an error on a table that does not exist"
    );

    let qualified_plain = "let sql = viewer.splice(\"SELECT 1 FROM public.edges e \
                           WHERE true /* {VISIBILITY:e} */\", 2);";
    let got = markers_with_their_tables(qualified_plain);
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].2, got[0].3.as_deref()),
        (false, Some("edges")),
        "a schema-qualified edges read taking the SINGLE-OWNER predicate must still resolve to \
         `edges`, or the ratchet is evaded by writing `public.` in front of the table"
    );

    // A marker in a JOIN's `ON` clause, with a SECOND marker on the driving
    // table. `repos/privatization.rs` writes both shapes — a `LEFT JOIN`
    // predicate has to live in `ON`, because a `WHERE` on the right-hand table
    // would silently turn it back into an inner join — and this scanner's
    // `continue` paths are silent, so a marker it skipped would look exactly
    // like a marker it approved.
    let joined = "let sql = viewer.splice(\"SELECT 1 FROM public.edges e \
                  JOIN public.claims oc ON oc.id = e.target_id /* {VISIBILITY:oc} */ \
                  WHERE true /* {EDGE_VISIBILITY:e} */\", 2);";
    let got = markers_with_their_tables(joined);
    assert_eq!(
        got.len(),
        2,
        "BOTH markers must be seen. One skipped marker is one unfiltered read the lint \
         reports as compliant: {got:?}"
    );
    assert_eq!(
        (got[0].1.as_str(), got[0].2, got[0].3.as_deref()),
        ("oc", false, Some("claims")),
        "a marker in an ON clause must bind to the table the JOIN names: {got:?}"
    );
    assert_eq!(
        (got[1].1.as_str(), got[1].2, got[1].3.as_deref()),
        ("e", true, Some("edges")),
        "and the driving table's own marker must not be captured by the later JOIN: {got:?}"
    );
}

/// `(line, alias, is_edge_spelling, table_the_alias_names)` for every marker.
///
/// The statement window is bounded at the nearest preceding `.splice(`,
/// `sqlx::query`, or `format!` so a binding from an unrelated statement earlier
/// in the file cannot answer for this one. `None` means the scan could not
/// resolve the alias; unresolved aliases are ignored by the caller rather than
/// reported, because a false accusation here is worse than a miss the runtime
/// panic and `splice`'s own assertions already cover.
fn markers_with_their_tables(src: &str) -> Vec<(usize, String, bool, Option<String>)> {
    const ANCHORS: &[&str] = &[".splice(", "sqlx::query", "format!"];
    let mut out = Vec::new();
    let mut idx = 0usize;

    while let Some(rel) = src[idx..].find("VISIBILITY:") {
        let at = idx + rel;
        idx = at + "VISIBILITY:".len();

        // Distinguish `{EDGE_VISIBILITY:` from `{VISIBILITY:`; skip anything
        // that is neither (prose, constant names).
        let before = &src[..at];
        let is_edge = before.ends_with("{EDGE_") || before.ends_with("{{EDGE_");
        let is_plain = before.ends_with('{');
        if !is_edge && !is_plain {
            continue;
        }

        let Some(end) = src[idx..].find('}') else {
            continue;
        };
        let alias = src[idx..idx + end].trim().to_string();
        if alias.is_empty()
            || !alias
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }

        let win_start = ANCHORS
            .iter()
            .filter_map(|a| before.rfind(a))
            .max()
            .unwrap_or(0);
        let window = &src[win_start..at];

        // Last `FROM <table> <alias>` / `JOIN <table> <alias>` in the window,
        // falling back to an unaliased `FROM <alias>` (the marker alias IS the
        // table name, e.g. `/* {EDGE_VISIBILITY:edges} */`).
        let table = last_binding(window, &alias);
        out.push((before.matches('\n').count() + 1, alias, is_edge, table));
    }
    out
}

fn last_binding(window: &str, alias: &str) -> Option<String> {
    let mut found: Option<String> = None;
    let words: Vec<&str> = window.split_whitespace().collect();
    for i in 0..words.len() {
        let kw = words[i].trim_start_matches(['(', ',']);
        if !kw.eq_ignore_ascii_case("FROM") && !kw.eq_ignore_ascii_case("JOIN") {
            continue;
        }
        let Some(tbl_raw) = words.get(i + 1) else {
            continue;
        };
        let tbl =
            tbl_raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_');
        // STRIP THE SCHEMA QUALIFIER, AND WHY THIS IS NOT COSMETIC.
        //
        // `FROM public.edges e` resolved to the literal `public.edges`, which
        // equals neither `edges` nor any other table this scanner compares
        // against — so BOTH arms of the caller missed it. The
        // `edge_marker_on_a_non_edges_table` arm produced a false ACCUSATION
        // (measured: it reported `public.edges` as a table with "no
        // co_owner_group_id column", which is exactly backwards), and the arm
        // that matters for safety — an `edges` read taking the SINGLE-OWNER
        // predicate — silently passed, because `Some("public.edges")` does not
        // match `Some("edges")`. That direction is a fail-open: the qualified
        // spelling was a way to write the leak this test exists to catch and
        // have it read as compliance.
        //
        // The repo layer already schema-qualifies FUNCTIONS routinely
        // (`FROM public.epigraph_claim_tenancy_by_ids(...) cx` in `event.rs`
        // and `claim.rs`), so the qualified spelling is house style rather than
        // a hypothetical, and a qualified TABLE was one edit away.
        let tbl = tbl.rsplit('.').next().unwrap_or(tbl);
        if tbl.is_empty() {
            continue;
        }
        // `FROM edges` with no alias: the marker alias is the table itself.
        if tbl == alias {
            found = Some(tbl.to_string());
            continue;
        }
        let next = words
            .get(i + 2)
            .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_'));
        let aliased = match next {
            Some(n) if n.eq_ignore_ascii_case("AS") => words
                .get(i + 3)
                .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')),
            other => other,
        };
        if aliased == Some(alias) {
            found = Some(tbl.to_string());
        }
    }
    found
}
