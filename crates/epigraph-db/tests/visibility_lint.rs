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

/// The two ways a body can legitimately spend its viewer.
///
/// `.splice(` is the marker path. `visibility = 'public'` is the leading
/// disjunct of the static three-bind form the four `sqlx::query!` macro sites
/// use — those cannot take a spliced literal, because the macro needs a
/// compile-time literal of fixed arity, so they carry the predicate verbatim.
///
/// **`group_bind()` / `bypass_bind()` are deliberately NOT on this list**, even
/// though an earlier draft accepted them. Binding a group array proves the
/// caller supplied a parameter; it does not prove the SQL has a predicate that
/// reads it. A `frame_claims_sorted`-shaped fail-open — `format!` the statement,
/// omit the predicate, bind the array anyway — would pass a lint keyed on the
/// accessor and fail this one. Requiring the predicate TEXT is what makes this
/// check about the query rather than about the call.
const SPENT_MARKERS: &[&str] = &[".splice(", "visibility = 'public'"];

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
];

/// A `*_conn` sibling must spend a viewer, or say in writing why it has none.
///
/// # Why the name and not the signature
///
/// [`every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer`] inspects only
/// functions whose PARAMETER LIST mentions `Viewer`. A `*_conn` sibling that
/// simply omits the `Viewer` parameter is therefore invisible to it — and PR-23
/// made `*_conn` siblings the standard conversion shape for the 391 sites
/// `epigraph-db/tests/no_unscoped_pool.rs` registers. Without this rule, a
/// sibling written without a viewer would pass BOTH controls: this file would
/// not inspect it, and the ratchet would count its call site as converted
/// because the `.db_pool` access is gone. The two together would certify
/// "converted" for a read that filters on nothing.
///
/// So the key is the NAME. Seventeen `*_conn` functions exist today; five take a
/// `Viewer` (`ClaimRepository::{get_by_id_conn, list_conn, count_conn}` and,
/// from PR-26, `LineageRepository::{get_lineage_conn, get_descendants_conn}`)
/// and the twelve below are enumerated with reasons. Seven of the twelve are
/// writes, where migration 077's `WITH CHECK` rather than a read predicate is
/// the control.
///
/// # The name rule is also the hole, and PR-18 fell in it
///
/// Keying on the name means a viewer-less `&mut PgConnection` read called
/// anything else is invisible to all three registers in this file at once.
/// PR-18's third slice shipped `load_plan`, `list_plans` and `load_plan_items`
/// exactly that way — reads of the plan tables, one of them projecting entity
/// ids — and they were registered nowhere. They are the last three entries in
/// [`CONN_WITHOUT_VIEWER`] and were RENAMED to earn them. The alternative,
/// widening the selector to "parameter list mentions `PgConnection`", is a
/// larger change to this lint's contract than a route slice should make; it is
/// recorded as a follow-up rather than done here.
///
/// Counted by this test's own rule — name ends `_conn` AND the parameter list
/// mentions `PgConnection` — not by a bare grep for `_conn`, which finds a
/// fifteenth (`ClaimRepository::patch_claim_atomic_conn`, whose parameter is a
/// `Transaction` rather than a `PgConnection`). Quote the rule with the number.
#[test]
fn every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt() {
    let mut without: Vec<(String, String)> = Vec::new();
    let mut with_viewer = 0usize;

    for f in repo_fns() {
        if !f.name.ends_with("_conn") {
            continue;
        }
        // `repo_fns` does not strip comments, so a doc line that spells out a
        // signature could otherwise register as a declaration.
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

    assert!(
        with_viewer + without.len() >= 12,
        "found only {} `*_conn` repo fns — the scanner is not matching declarations and this \
         lint would pass vacuously",
        with_viewer + without.len()
    );
    assert!(
        with_viewer >= 3,
        "no `*_conn` sibling takes a Viewer any more ({with_viewer} found). The conversion shape \
         PR-23 established has been abandoned; that is a decision, not a refactor."
    );

    let mut want: Vec<(String, String)> = CONN_WITHOUT_VIEWER
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        without, want,
        "\n\nThe set of viewer-less `*_conn` repo fns changed. A `*_conn` sibling is the shape a \
         conversion shard writes when it moves a handler onto `AppState::read_as`, and one \
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
