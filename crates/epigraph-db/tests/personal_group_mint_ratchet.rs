//! Source ratchet: every call site that can reach `epigraph_ensure_personal_group`
//! is enumerated here, with its reason, and a new one fails the build.
//!
//! # The class this exists to stop (batch F)
//!
//! A revoked group membership came back three times, each time through the same
//! mechanism: a read on an UNSTAMPED `epigraph_app` connection (where
//! `groups_tenancy` hides every group) reported "no personal group", and the
//! caller then called `epigraph_ensure_personal_group`, whose migration-077 body
//! ended in `ON CONFLICT … DO UPDATE SET revoked_at = NULL, role = 'admin'`.
//! PR-09's `EpiGraphMcpFull::agent_id` (per HTTP session), the recall audit
//! (#493), and the ingest executor's system agent (#498). Migration 105 removed
//! the revival from the function; this file keeps the CALLERS from growing
//! again unreviewed, and keeps the revival from reappearing as a copy.
//!
//! # The four arms
//!
//! 1. [`every_path_to_the_personal_group_mint_is_registered`] — an exact-set
//!    ratchet over `crates/*/src/**/*.rs` (bins and `#[cfg(test)]` modules
//!    included) of calls to the function (both spellings) and to every helper
//!    that wraps it. `(file, callee, count)` must equal [`REGISTER`] exactly: a
//!    new site ADDS a tuple, a removed one leaves a stale entry, and both fail.
//! 2. [`no_new_revival_statement_in_source_or_migrations`] — the revival
//!    itself, as a statement shape: `revoked_at = NULL` in ANY spelling
//!    (case-insensitive, any whitespace around `=`, quoted identifiers) in
//!    comment-stripped `crates/*/src` AND `migrations/*.sql`, outside
//!    [`REVIVE_REGISTER`]. It catches a copy of the statement (the backfill
//!    carried one) that arm 1 cannot, because a copy calls nothing.
//! 3. [`the_latest_definitions_do_not_revive`] — for each function in
//!    [`GUARDED_DEFINERS`], the LAST migration that `CREATE`s it (optional
//!    `public.` prefix, any case, any whitespace, any parameter name) must
//!    carry exactly the registered number of revivals in that definition. A
//!    later `CREATE OR REPLACE` that restored 077's body, or a redefinition of
//!    106's `epigraph_community_remove_member` that revives, fails here.
//! 4. [`no_live_function_body_revives`] — the database's own answer, on a
//!    test database migrated 001→head: every function in `pg_proc` whose
//!    source matches `revoked_at\s*=\s*null` (case-insensitive) must be in
//!    [`LIVE_REVIVE_ALLOWLIST`]. `pg_proc` holds only the CURRENT definitions,
//!    so this covers 105, 106 and any future definer however its migration
//!    spells the name, including a function arms 2 and 3 have never heard of.
//!    It calibrates itself by creating a reviving function first.
//!
//! [`the_scanner_sees_calls_and_ignores_prose`] and
//! [`the_revival_matcher_sees_every_spelling`] are the calibrations: they feed
//! the scanners synthetic source, so a scanner that silently matched nothing
//! could not keep arms 1-3 green.
//!
//! # ITS BLIND SPOTS, stated so a green run is not over-read
//!
//! * **Wrappers not in [`WATCHED`].** It follows the helpers listed there and
//!   nothing further up. `system_agent_write_authority` IS watched: its two
//!   callers, `api/routes/workflows.rs` and `mcp/claim_helper.rs`, are in the
//!   register, and its own mint runs only after a stamped read proved the
//!   agent has no row at all (`scripts/e2e/probe-unit-e.sh`'s REVOKED/READER
//!   arms). The wrappers deliberately NOT expanded, each with its own pin:
//!   - `EpiGraphMcpFull::agent_id` has a call site in nearly every tool; its
//!     one `ensure_personal_group` call runs once per PROCESS
//!     (`SessionFactory` shares the cell), pinned by `server.rs`'s
//!     `session_factory_tests`. The outcome (no revival, no ingest) is pinned
//!     by `epigraph-mcp/tests/per_session_agent_resolution.rs`.
//!   - `create_claim_idempotent`, `IngestTx::owner_decl` and the two
//!     `begin_system_ingest_stamped_tx` (MCP `claim_helper.rs`, API
//!     `routes/workflows.rs`) wrap a watched call and are called from many
//!     tools. The watched call inside each is registered, and every path
//!     through them ends in migration 105's definer.
//!
//!   A NEW wrapper — a function that calls one of these and is then called
//!   from elsewhere — is caught once (its own call to the watched helper) and
//!   then not followed. Adding it to [`WATCHED`] is the reviewer's job.
//! * **SQL built at runtime.** A statement assembled with `format!` whose
//!   function name or column is split across literals, or read from a file, is
//!   invisible to arms 1-3 (arm 4 still sees any function it creates).
//! * **Revivals not spelled `revoked_at = NULL`.** Arms 2-4 match that
//!   assignment in any case and spacing, and nothing else. `revoked_at = $3`
//!   bound to NULL, the row-constructor form `SET (revoked_at, role) = (NULL,
//!   'admin')`, `revoked_at = CASE … END`, and a DELETE-then-reinsert all pass
//!   all three. The behavioural arms (`personal_group_no_revival.rs`,
//!   `community_membership_integrity.rs`, as `epigraph_app`) are the backstop
//!   for the functions they call; a Rust-source copy on a path no behavioural
//!   arm drives has none.
//! * **Test files.** `crates/*/tests/` is NOT scanned: fixtures there provision
//!   and revoke memberships on purpose. `#[cfg(test)]` modules inside `src/`
//!   ARE scanned and registered.
//! * **Outside `crates/*/src` and `migrations/`.** The workspace member
//!   `tests/engine-integration` (no watched call at the time of writing) and
//!   the e2e shell scripts are not scanned. `scripts/e2e/probe-workflow.sh` calls
//!   `epigraph_ensure_personal_group` in raw SQL, for freshly created fixture
//!   agents only, on a throwaway database; after migration 105 a revoked row
//!   there would RAISE `RVK01` and abort the probe rather than revive.
//! * **It is syntactic.** It says which sites can reach the mint, never whether
//!   the connection they run on is stamped. That axis is the arms that call the
//!   function as `epigraph_app`
//!   (`epigraph-db/tests/personal_group_no_revival.rs`) and the e2e harness.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The function (both spellings) and every helper that wraps it. A call to any
/// of these can reach the mint.
const WATCHED: &[&str] = &[
    // The SQL spelling, inside a query string.
    "epigraph_ensure_personal_group",
    // `AgentRepository::ensure_personal_group`.
    "ensure_personal_group",
    // `ClaimRepository` wrappers (claim.rs).
    "personal_group_of",
    "personal_group_of_pool",
    "default_decl_for_author",
    "default_decl_for_author_pool",
    // `AgentRepository::ensure_for_client` (the OAuth principal mint) and the
    // API helper every token-mint site goes through.
    "ensure_for_client",
    "principal_agent_id",
    // The ingest executor's system-agent preflight, whose last step can
    // provision (`system_agent.rs`).
    "system_agent_write_authority",
];

// ===========================================================================
// THE REGISTER. `(file under crates/, callee, occurrences, disposition)`.
//
// Measured 2026-09-24 at batch F. Every disposition is one of the three the
// batch allows: the read runs on a connection stamped from the agent's own
// viewer; the answer comes from a SECURITY DEFINER read (migration 105's
// function reads every row in its definer frame, writes nothing for a live
// membership, refuses a revoked one); or the caller runs only on a maintenance
// connection.
// ===========================================================================
const REGISTER: &[(&str, &str, usize, &str)] = &[
    (
        "epigraph-db/src/repos/agent.rs",
        "epigraph_ensure_personal_group",
        1,
        "THE function call, `AgentRepository::ensure_personal_group`'s body. Definer; \
         migration 105's contract (live: no write; revoked: RVK01; none: provision).",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "ensure_personal_group",
        1,
        "`ensure_for_client` step 6, the OAuth principal mint. Definer read-and-provision; a \
         revoked row aborts the mint transaction, the client stays unlinked, the route answers \
         403 (`identity_provisioning::a_first_mint_for_a_revoked_agent_is_refused_and_leaves_it_revoked`).",
    ),
    (
        "epigraph-db/src/repos/claim.rs",
        "ensure_personal_group",
        1,
        "`personal_group_of`'s whole body since batch F: the definer answers, no read on the \
         caller's connection first (`personal_group_no_revival::the_owner_group_wrapper_refuses_a_revoked_author_on_every_role`).",
    ),
    (
        "epigraph-db/src/repos/claim.rs",
        "personal_group_of",
        3,
        "`default_decl_for_author`, `personal_group_of_pool` and `consolidate`'s all-public \
         branch. All resolve through the definer.",
    ),
    (
        "epigraph-db/src/repos/claim.rs",
        "default_decl_for_author",
        1,
        "`default_decl_for_author_pool`'s body: acquire a pool connection, then the same \
         definer answer as every other caller.",
    ),
    (
        "epigraph-ingest-executor/src/system_agent.rs",
        "ensure_personal_group",
        1,
        "`system_agent_write_authority`: called only after a read on a connection STAMPED from \
         the agent's own viewer proved it holds no live and no revoked row; runs in that stamped \
         transaction.",
    ),
    (
        "epigraph-ingest-executor/src/workflow.rs",
        "default_decl_for_author",
        1,
        "Workflow ingest's one declaration for the whole plan, on the connection its caller \
         passes (stamped from the system agent's viewer on the MCP path). Definer answer.",
    ),
    (
        "epigraph-ingest-executor/src/workflow_steps.rs",
        "default_decl_for_author",
        1,
        "`add_step`'s declaration for the system agent, on the connection its caller passes \
         (`step_ops.rs`, `routes/workflows.rs`). Definer answer, whatever that connection's stamp.",
    ),
    (
        "epigraph-mcp/src/server.rs",
        "ensure_personal_group",
        1,
        "`EpiGraphMcpFull::agent_id` (PR-09). Once per PROCESS since `SessionFactory` shares the \
         cell (F1); a revoked row is refused and warned, the id still resolves \
         (`per_session_agent_resolution`).",
    ),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "default_decl_for_author",
        1,
        "`create_claim_idempotent`, inside the author-stamped transaction; the refusal maps to \
         INVALID_REQUEST via `db_caller_error`.",
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "default_decl_for_author",
        1,
        "`IngestTx::owner_decl`'s PRIVILEGED arm only (operator `ingest-document` CLI on \
         `MaintenancePool`). The Stamped arm is a pure read that never reaches the mint.",
    ),
    (
        "epigraph-mcp/src/tools/recall.rs",
        "ensure_personal_group",
        2,
        "`#[cfg(test)]` fixtures of the recall audit helper's unit tests (provisioning a live \
         principal and a revoked one). The helper itself never provisions (#493).",
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "default_decl_for_author_pool",
        1,
        "Workflow ingest's system-agent declaration, on the unstamped pool. Definer answer, so \
         the pool's blindness no longer matters.",
    ),
    (
        "epigraph-api/src/oauth/token.rs",
        "ensure_for_client",
        1,
        "`principal_agent_id`, in one transaction on `state.db_pool`. Definer; the refusal maps \
         to 403.",
    ),
    (
        "epigraph-api/src/oauth/token.rs",
        "principal_agent_id",
        3,
        "The three grant handlers (client_credentials, refresh_token, authorization_code). Warm \
         path returns the linked agent without touching the mint.",
    ),
    (
        "epigraph-api/src/oauth/providers/provision.rs",
        "principal_agent_id",
        1,
        "External-provider token mint. Same disposition as the three above.",
    ),
    (
        "epigraph-api/src/routes/claims.rs",
        "default_decl_for_author",
        1,
        "`create_claim`, inside its transaction. Definer answer.",
    ),
    (
        "epigraph-api/src/routes/submit.rs",
        "default_decl_for_author",
        1,
        "`submit_packet`, inside its transaction. Definer answer.",
    ),
    (
        "epigraph-api/src/routes/conventions.rs",
        "default_decl_for_author_pool",
        2,
        "Two conventions writes on `state.db_pool` (unstamped). Definer answer.",
    ),
    (
        "epigraph-api/src/routes/hypothesis.rs",
        "default_decl_for_author_pool",
        1,
        "Hypothesis route on `state.db_pool` (unstamped). Definer answer.",
    ),
    (
        "epigraph-api/src/routes/policies.rs",
        "default_decl_for_author_pool",
        1,
        "Policies route, system agent's declaration on `state.db_pool`. Definer answer.",
    ),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "system_agent_write_authority",
        1,
        "`begin_system_ingest_stamped_tx` (store_workflow, workflow ingest, add_step, \
         delete_step). The preflight's own mint runs only for an agent with no row of any state; \
         a revoked or reader system agent is refused (AgentCreation -> INTERNAL_ERROR, #498's \
         choice: the system agent's membership is operator configuration, not the caller's).",
    ),
    (
        "epigraph-api/src/routes/workflows.rs",
        "system_agent_write_authority",
        1,
        "API `begin_system_ingest_stamped_tx` (both `/workflows/ingest` handlers, add_step). Same \
         preflight, same refusals (InternalError).",
    ),
    (
        "epigraph-cli/src/bin/hypothesis.rs",
        "default_decl_for_author",
        1,
        "Operator CLI on its maintenance connection. Definer answer: a revoked author is refused.",
    ),
    (
        "epigraph-cli/src/bin/method_search.rs",
        "default_decl_for_author",
        1,
        "Operator CLI on its maintenance connection. Definer answer: a revoked author is refused.",
    ),
];

/// `(repo-relative file, occurrences, why)` of the revival statement shape
/// `revoked_at = NULL` in any spelling ([`revival_count`]), comments stripped,
/// over `crates/*/src/**/*.rs` and `migrations/*.sql`.
const REVIVE_REGISTER: &[(&str, usize, &str)] = &[
    (
        "crates/epigraph-db/src/repos/instance_admin.rs",
        1,
        "`InstanceAdminRepository::grant` on `instance_admins`, NOT a group membership: an \
         explicit operator re-grant on the maintenance connection (migration 083 revokes \
         INSERT/UPDATE on the table from `epigraph_app`).",
    ),
    (
        "migrations/071_ownership_compat_shim.sql",
        1,
        "`epigraph_ownership_transcribe()`'s personal-group revival. HISTORY: migration 084 \
         drops the function (`no_live_function_body_revives` confirms it is not live).",
    ),
    (
        "migrations/077_rls_policies.sql",
        1,
        "077's `epigraph_ensure_personal_group` body, the defect itself. HISTORY: superseded by \
         105 (`the_latest_definitions_do_not_revive` pins that 105 is the latest definition).",
    ),
    (
        "migrations/106_community_membership_integrity.sql",
        1,
        "`epigraph_community_add_member`'s restore of a REVOKED community row at the requested \
         `reader` role, reachable only by a live admin actor (`'denied_readmit'` otherwise); \
         pinned by `community_membership_integrity.rs`.",
    ),
];

/// Every function whose LATEST migration definition arm 3 checks, with the
/// number of revivals that definition may carry and the markers it must
/// contain (normalised: lowercase, no whitespace). `(name, revivals, markers)`.
const GUARDED_DEFINERS: &[(&str, usize, &[&str])] = &[
    ("epigraph_ensure_personal_group", 0, &["rvk01", "rvk02"]),
    ("epigraph_community_remove_member", 0, &[]),
    ("epigraph_community_add_member", 1, &["denied_readmit"]),
];

/// Functions the LIVE database may hold whose source matches
/// `revoked_at\s*=\s*null`, each with its reason. Exact set.
const LIVE_REVIVE_ALLOWLIST: &[(&str, &str)] = &[(
    "epigraph_community_add_member",
    "106: restores a REVOKED community row at `reader`, only for a live admin actor; never a \
     personal group, never at the old role.",
)];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn migrations_root() -> PathBuf {
    crates_root()
        .parent()
        .expect("repo root")
        .join("migrations")
}

/// Every `.rs` under `crates/*/src/`, recursively. `tests/`, `benches/` and
/// `examples/` are not production and are not scanned (see the header).
fn src_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for c in std::fs::read_dir(crates_root())
        .expect("read crates/")
        .flatten()
    {
        walk(&c.path().join("src"), &mut out);
    }
    out.sort();
    out
}

/// Strip `//` and `/* */` comments, but NOT inside string literals (normal,
/// escaped, and raw `r#"…"#`) or char literals: the SQL spelling of the
/// function lives in strings, and a string-blind stripper would also eat code
/// after a `"…/*…"` literal such as a glob.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let n = b.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    while i < n {
        let c = b[i];
        if c == '/' && i + 1 < n && b[i + 1] == '/' {
            while i < n && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && b[i + 1] == '*' {
            let mut depth = 1;
            i += 2;
            while i < n && depth > 0 {
                if b[i] == '/' && i + 1 < n && b[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && i + 1 < n && b[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: r"…", r#"…"#, r##"…"##.
        if c == 'r'
            && i + 1 < n
            && (b[i + 1] == '"' || b[i + 1] == '#')
            && (i == 0 || !is_ident(b[i - 1]))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && b[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == '"' {
                let mut k = j + 1;
                'scan: while k < n {
                    if b[k] == '"' {
                        let mut h = 0;
                        while h < hashes && k + 1 + h < n && b[k + 1 + h] == '#' {
                            h += 1;
                        }
                        if h == hashes {
                            k += 1 + hashes;
                            break 'scan;
                        }
                    }
                    k += 1;
                }
                out.extend(&b[i..k.min(n)]);
                i = k.min(n);
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < n && b[j] != '"' {
                j += if b[j] == '\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(n);
            out.extend(&b[i..end]);
            i = end;
            continue;
        }
        // Char literals that would otherwise open or close a "string": '"', '\"'.
        if c == '\'' && i + 2 < n && b[i + 2] == '\'' {
            out.extend(&b[i..i + 3]);
            i += 3;
            continue;
        }
        if c == '\'' && i + 3 < n && b[i + 1] == '\\' && b[i + 3] == '\'' {
            out.extend(&b[i..i + 4]);
            i += 4;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Occurrences of `name(` as a whole identifier that is a CALL, not a `fn`
/// definition. Whitespace between the name and `(` is allowed.
fn count_calls(text: &str, name: &str) -> usize {
    let b = text.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(off) = text[from..].find(name) {
        let start = from + off;
        let end = start + name.len();
        from = end;
        let prev_ok = start == 0 || !(b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'_');
        if !prev_ok {
            continue;
        }
        let mut k = end;
        while k < b.len() && (b[k] == b' ' || b[k] == b'\n' || b[k] == b'\t') {
            k += 1;
        }
        if k >= b.len() || b[k] != b'(' {
            continue;
        }
        if text[..start].trim_end().ends_with("fn") {
            continue;
        }
        count += 1;
    }
    count
}

fn rel(p: &Path) -> String {
    p.strip_prefix(crates_root())
        .expect("under crates/")
        .to_string_lossy()
        .replace('\\', "/")
}

fn measured_calls() -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for p in src_files() {
        let text = strip_comments(&std::fs::read_to_string(&p).expect("read source"));
        for name in WATCHED {
            let n = count_calls(&text, name);
            if n > 0 {
                out.insert((rel(&p), (*name).to_string()), n);
            }
        }
    }
    out
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Lowercase, `"` removed, every whitespace run collapsed to one space, and
/// no space at all next to `=`, `(`, `)`, `.` or `,`. In this form
/// `revoked_at = NULL`, `REVOKED_AT=null` and `"revoked_at"\n = Null` all read
/// `revoked_at=null`, and `CREATE OR REPLACE\n FUNCTION "public" . "f" (`
/// reads `create or replace function public.f(`, while word boundaries (a
/// space) survive everywhere else.
fn normalise(s: &str) -> String {
    let tight = |c: char| matches!(c, '=' | '(' | ')' | '.' | ',');
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars().filter(|c| *c != '"').flat_map(char::to_lowercase) {
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() && !tight(c) && !out.ends_with(tight) {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
    }
    out
}

/// Occurrences of the revival assignment `revoked_at = NULL` in any case and
/// spacing. `revoked_at IS NULL` (a predicate) does not match; neither does
/// `revoked_at = NULLIF(…)` or a column merely ending in `revoked_at`.
fn revival_count(text: &str) -> usize {
    let n = normalise(text);
    let needle = "revoked_at=null";
    let b = n.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut count = 0;
    let mut from = 0;
    while let Some(off) = n[from..].find(needle) {
        let start = from + off;
        let end = start + needle.len();
        let lead = start == 0 || !is_ident(b[start - 1]);
        let tail = end >= b.len() || !is_ident(b[end]);
        if lead && tail {
            count += 1;
        }
        from = end;
    }
    count
}

fn repo_root() -> PathBuf {
    crates_root().parent().expect("repo root").to_path_buf()
}

fn repo_rel(p: &Path) -> String {
    p.strip_prefix(repo_root())
        .expect("under the repo")
        .to_string_lossy()
        .replace('\\', "/")
}

fn migration_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(migrations_root())
        .expect("read migrations/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    files
}

#[test]
fn every_path_to_the_personal_group_mint_is_registered() {
    let measured = measured_calls();
    let expected: BTreeMap<(String, String), usize> = REGISTER
        .iter()
        .map(|(f, c, n, _)| (((*f).to_string(), (*c).to_string()), *n))
        .collect();
    for (_, _, _, why) in REGISTER {
        assert!(why.len() > 40, "every register entry must carry its reason");
    }
    let new: Vec<_> = measured
        .iter()
        .filter(|(k, v)| expected.get(*k) != Some(v))
        .collect();
    let stale: Vec<_> = expected
        .iter()
        .filter(|(k, v)| measured.get(*k) != Some(v))
        .collect();
    assert!(
        new.is_empty() && stale.is_empty(),
        "the set of call sites that can reach epigraph_ensure_personal_group changed.\n\
         NEW or re-counted (measured, not registered): {new:#?}\n\
         STALE (registered, not measured): {stale:#?}\n\
         A new site must say, in REGISTER, why it cannot revive or promote: a read stamped \
         from the agent's own viewer, the definer's own answer, or a maintenance connection."
    );
}

#[test]
fn no_new_revival_statement_in_source_or_migrations() {
    let mut measured: BTreeMap<String, usize> = BTreeMap::new();
    for p in src_files() {
        let n = revival_count(&strip_comments(&std::fs::read_to_string(&p).unwrap()));
        if n > 0 {
            measured.insert(repo_rel(&p), n);
        }
    }
    for p in migration_files() {
        let n = revival_count(&strip_sql_comments(&std::fs::read_to_string(&p).unwrap()));
        if n > 0 {
            measured.insert(repo_rel(&p), n);
        }
    }
    let expected: BTreeMap<String, usize> = REVIVE_REGISTER
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), *n))
        .collect();
    for (_, _, why) in REVIVE_REGISTER {
        assert!(
            why.len() > 40,
            "every revive register entry must carry its reason"
        );
    }
    assert_eq!(
        measured, expected,
        "a `revoked_at = NULL` assignment (any case or spacing) appeared, moved or disappeared \
         in production source or a migration. A revival of a revoked membership is an \
         operator decision; if this one is, register it in REVIVE_REGISTER with the reason."
    );
}

/// Strip `/* … */` block comments, then `--` line comments (not inside '…'
/// literals), from SQL.
fn strip_sql_comments(sql: &str) -> String {
    let mut no_blocks = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(i) = rest.find("/*") {
        no_blocks.push_str(&rest[..i]);
        rest = match rest[i + 2..].find("*/") {
            Some(j) => &rest[i + 2 + j + 2..],
            None => "",
        };
    }
    no_blocks.push_str(rest);
    let mut out = String::with_capacity(no_blocks.len());
    for line in no_blocks.lines() {
        let mut in_str = false;
        let mut cut = line.len();
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                in_str = !in_str;
            } else if !in_str && bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
                cut = i;
                break;
            }
            i += 1;
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// The LAST `CREATE [OR REPLACE] FUNCTION [public.]<name>(` across the
/// migrations, normalised and comment-stripped: the text from that header to
/// the next function `CREATE` in the same file (or its end), and the file.
fn latest_definition(name: &str) -> Option<(PathBuf, String)> {
    let heads = [
        format!("create or replace function {name}("),
        format!("create or replace function public.{name}("),
        format!("create function {name}("),
        format!("create function public.{name}("),
    ];
    let mut found = None;
    for p in migration_files() {
        let n = normalise(&strip_sql_comments(&std::fs::read_to_string(&p).unwrap()));
        let Some(at) = heads.iter().filter_map(|h| n.rfind(h.as_str())).max() else {
            continue;
        };
        let after = &n[at + 1..];
        let end = ["create or replace function", "create function"]
            .iter()
            .filter_map(|k| after.find(k))
            .min()
            .map_or(n.len(), |e| at + 1 + e);
        found = Some((p.clone(), n[at..end].to_string()));
    }
    found
}

#[test]
fn the_latest_definitions_do_not_revive() {
    for (name, revivals, markers) in GUARDED_DEFINERS {
        let (file, body) =
            latest_definition(name).unwrap_or_else(|| panic!("some migration must define {name}"));
        assert_eq!(
            revival_count(&body),
            *revivals,
            "the latest definition of {name} ({}) carries a different number of \
             `revoked_at = NULL` assignments than GUARDED_DEFINERS registers",
            file.display()
        );
        for m in *markers {
            assert!(
                body.contains(m),
                "the latest definition of {name} ({}) must contain `{m}`",
                file.display()
            );
        }
    }
    let (ensure_file, _) = latest_definition("epigraph_ensure_personal_group").unwrap();
    assert!(
        repo_rel(&ensure_file).as_str() >= "migrations/105_personal_group_no_revival.sql",
        "105 or later must hold the latest definition of epigraph_ensure_personal_group, got {}",
        ensure_file.display()
    );
}

/// ARM 4. The live database: every function whose CURRENT source assigns
/// `revoked_at = NULL` (any case or spacing) must be allow-listed. Calibrated
/// in-test: a reviving function is created in this throwaway database first,
/// and the scan must flag it.
#[sqlx::test(migrations = "../../migrations")]
async fn no_live_function_body_revives(pool: sqlx::PgPool) {
    const LIVE_REVIVERS: &str = "SELECT p.proname::text FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') \
           AND p.prosrc ~* 'revoked_at\\s*=\\s*null' \
         ORDER BY 1";

    // CALIBRATION: spelled the way the review's respellings were (lowercase
    // `null`, no spaces, no schema prefix).
    sqlx::query(
        "CREATE FUNCTION ratchet_calibration_revive(p uuid) RETURNS void \
         LANGUAGE plpgsql AS $$ BEGIN \
           UPDATE group_memberships SET revoked_at=null, role='admin' WHERE agent_id = p; \
         END $$",
    )
    .execute(&pool)
    .await
    .expect("create the calibration function");
    let with_calibration: Vec<String> = sqlx::query_scalar(LIVE_REVIVERS)
        .fetch_all(&pool)
        .await
        .expect("scan pg_proc");
    assert!(
        with_calibration
            .iter()
            .any(|n| n == "ratchet_calibration_revive"),
        "the pg_proc scan must flag a reviving body; flagged {with_calibration:?}"
    );
    sqlx::query("DROP FUNCTION ratchet_calibration_revive(uuid)")
        .execute(&pool)
        .await
        .expect("drop the calibration function");

    let live: Vec<String> = sqlx::query_scalar(LIVE_REVIVERS)
        .fetch_all(&pool)
        .await
        .expect("scan pg_proc");
    let mut allowed = Vec::new();
    for (name, why) in LIVE_REVIVE_ALLOWLIST {
        assert!(
            why.len() > 40,
            "every allow-list entry must carry its reason"
        );
        allowed.push((*name).to_string());
    }
    assert_eq!(
        live, allowed,
        "a function in the migrated database assigns `revoked_at = NULL`. Reviving a revoked \
         membership is an operator decision; a definer that does it needs a reviewed \
         LIVE_REVIVE_ALLOWLIST entry."
    );
}

/// CALIBRATION: the scanner reports a call, ignores prose and `fn` definitions,
/// sees the SQL spelling inside a string, and is not fooled by a `/*` inside a
/// string literal.
#[test]
fn the_scanner_sees_calls_and_ignores_prose() {
    let src = r####"
        /// Calls `ensure_personal_group(conn, id)` in prose — must not count.
        // AgentRepository::ensure_personal_group(conn, id) in a line comment.
        /* default_decl_for_author(conn, id) in a block comment */
        pub async fn ensure_personal_group(conn: &mut PgConnection) {}
        async fn caller() {
            let glob = "src/**/*.rs"; // a `/*` inside a string opens no comment
            let _ = AgentRepository::ensure_personal_group(&mut conn, id).await;
            let _ = sqlx::query("SELECT public.epigraph_ensure_personal_group($1)");
            let _ = ClaimRepository::default_decl_for_author_pool (pool, id).await;
            let _ = r#"personal_group_of(in a raw string)"#;
        }
    "####;
    let text = strip_comments(src);
    assert_eq!(count_calls(&text, "ensure_personal_group"), 1, "{text}");
    assert_eq!(count_calls(&text, "epigraph_ensure_personal_group"), 1);
    assert_eq!(count_calls(&text, "default_decl_for_author"), 0);
    assert_eq!(count_calls(&text, "default_decl_for_author_pool"), 1);
    assert_eq!(
        count_calls(&text, "personal_group_of"),
        1,
        "string contents are scanned (the SQL spelling lives there)"
    );
    assert!(collapse_ws(&strip_sql_comments(
        "UPDATE m SET revoked_at   =\n NULL; -- revoked_at = NULL in a comment"
    ))
    .contains("revoked_at = NULL"));
    assert!(!strip_sql_comments("-- ON CONFLICT DO UPDATE SET revoked_at = NULL").contains("NULL"));
}

/// CALIBRATION for arms 2 and 3: every respelling the batch F review used to
/// slip past the old exact-string match is seen, and non-revivals are not.
#[test]
fn the_revival_matcher_sees_every_spelling() {
    for spelled in [
        "UPDATE group_memberships SET revoked_at = NULL, role = 'admin'",
        "DO UPDATE SET revoked_at = null, role = 'admin'",
        "SET revoked_at=NULL, role='admin'",
        "SET \"revoked_at\"\n   =\n Null",
        "set REVOKED_AT = NULL::timestamptz",
    ] {
        assert_eq!(revival_count(spelled), 1, "must see: {spelled}");
    }
    for not_a_revival in [
        "WHERE revoked_at IS NULL",
        "SET revoked_at = now()",
        "SET revoked_at = NULLIF(x, y)",
        "SET unrevoked_at = NULL",
    ] {
        assert_eq!(
            revival_count(not_a_revival),
            0,
            "must not see: {not_a_revival}"
        );
    }
    assert_eq!(
        revival_count(&strip_sql_comments(
            "/* SET revoked_at = NULL */ SELECT 1; -- revoked_at = NULL"
        )),
        0,
        "comments are not statements"
    );
    // Arm 3's definition finder: unqualified, quoted, split across lines, any
    // case.
    let n = normalise("create or replace\n  function Epigraph_Ensure_Personal_Group (p uuid)");
    assert!(n.contains("create or replace function epigraph_ensure_personal_group("));
    let q = normalise("CREATE FUNCTION \"public\" . \"epigraph_community_add_member\"(a uuid)");
    assert!(q.contains("create function public.epigraph_community_add_member("));
}
