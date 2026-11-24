//! Source lint: every SQL read of another agent's identity columns goes
//! through the disclosure rule (spec
//! `docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md`,
//! section 14).
//!
//! A human principal's `display_name` is the person's real name, and the
//! operator's rule shows it only to the callers migration 272's
//! `epigraph_agent_disclosure` admits. `agents` is readable by every session
//! (077 `agents_identity ... USING (true)`), so nothing in the database stops
//! a new statement from reading the name, ORCID, ROR id or `properties` and
//! returning it to anyone. This lint is what does: it scans every Rust source
//! file under `crates/*/src` for a function whose live SQL reads one of
//! those columns from an `agents` row, and requires the exact set of such
//! functions to be one of:
//!
//! * [`GATED`]: the statement decides disclosure itself (it calls
//!   `epigraph_agent_disclosure` / `epigraph_human_named_to_viewer` /
//!   `epigraph_agent_disclosure_for`, or is the disclosure reader);
//! * [`ALLOWED`]: reviewed, with a reason (a writer, an internal check whose
//!   value never leaves the process, a maintenance operator tool);
//!
//! A new or missed surface fails CI, not review.
//!
//! # What it reads, and what it cannot
//!
//! Textual, not a SQL parser. Per function body (Rust comments removed, SQL
//! comments removed, string contents kept: `lint_text::spend_views`), it
//! finds each `FROM agents` / `JOIN agents` (optionally `public.`), takes the
//! next word as the alias unless it is a keyword, and flags the function when
//! `<alias>.display_name`, `.orcid`, `.ror_id` or `.properties` appears; for
//! an unaliased `agents` it flags a bare `display_name`, `orcid` or `ror_id`.
//! A statement assembled across functions (a helper returning a fragment) is
//! seen in the function holding the `FROM agents`. `#[cfg(test)] mod` blocks
//! are not scanned.

mod lint_text;

use lint_text::spend_views;
use std::path::{Path, PathBuf};

/// Functions whose identity read decides disclosure in the statement itself.
/// Each must name one of [`DISCLOSURE_CALLS`] in its live SQL.
const GATED: &[(&str, &str)] = &[
    ("epigraph-db/src/repos/political.rs", "get_claim_genealogy"),
    (
        "epigraph-db/src/repos/political.rs",
        "get_inflation_leaderboard",
    ),
    ("epigraph-db/src/repos/sources.rs", "agents"),
    ("epigraph-db/src/repos/paper.rs", "author_listing_columns"),
    ("epigraph-db/src/repos/agent.rs", "get_public_profile"),
    ("epigraph-db/src/repos/agent_lookup.rs", "author_nodes"),
    ("epigraph-db/src/repos/agent_lookup.rs", "cards_inner"),
    (
        "epigraph-db/src/repos/agent_lookup.rs",
        "exact_name_candidates",
    ),
    ("epigraph-db/src/repos/agent_lookup.rs", "match_ranked"),
    ("epigraph-db/src/repos/agent_disclosure.rs", "names"),
    (
        "epigraph-db/src/repos/agent_disclosure.rs",
        "names_for_audience",
    ),
];

/// The SQL spellings of the rule a [`GATED`] function must carry.
const DISCLOSURE_CALLS: &[&str] = &[
    "epigraph_agent_disclosure(",
    "epigraph_agent_disclosure_for(",
    "epigraph_human_named_to_viewer(",
];

/// Reviewed reads that never return another agent's identity to a caller
/// the rule does not admit, each with the reason.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "epigraph-api/src/routes/policies.rs",
        "ensure_system_agent",
        "a WRITER: finds the policy system agent by public key and INSERTs its constant name; \
         the bare `display_name` is the INSERT column list, nothing is read back for output",
    ),
    (
        "epigraph-api/src/routes/workflows.rs",
        "ensure_system_agent",
        "a WRITER: finds the workflow system agent by public key and INSERTs its constant name; \
         the bare `display_name` is the INSERT column list, nothing is read back for output",
    ),
    (
        "epigraph-cli/src/bin/analyze_graph.rs",
        "main",
        "operator CLI on the maintenance DSN (spec 7.J): a privileged operator act, which the \
         rule's privileged arm admits; output goes to the operator's terminal only",
    ),
    (
        "epigraph-cli/src/bin/dekg.rs",
        "handle_migrate",
        "operator CLI on the maintenance DSN (spec 7.J): a privileged operator act, which the \
         rule's privileged arm admits; output goes to the operator's terminal only",
    ),
    (
        "epigraph-cli/src/cache_owner_audit.rs",
        "audit_edges",
        "operator audit CLI on the maintenance DSN (spec 7.J): a privileged operator act, which \
         the rule's privileged arm admits; its report is the operator's own",
    ),
    (
        "epigraph-cli/src/operator/backfill_markers.rs",
        "signers_statement",
        "operator backfill CLI on the maintenance DSN: identifies signer rows for a marker \
         backfill; a privileged operator act, output to the operator's terminal only",
    ),
    (
        "epigraph-cli/src/operator/system_agent.rs",
        "identity",
        "operator system-agent CLI on the maintenance DSN (spec 7.J): prints a SYSTEM identity's \
         own row to the operator; a privileged operator act",
    ),
    (
        "epigraph-db/src/repos/mass_function.rs",
        "untyped_provenance_page",
        "read only by the operator `evidence_type_backfill` CLI on the maintenance DSN (spec 7.J): \
         a privileged operator act; no request route calls it",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "ensure_for_client",
        "the PROVISIONING writer (spec 9): reads the locked client row and the agent it adopts; \
         returns the caller's OWN principal, never another agent's identity",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "find_by_capability",
        "no caller in any crate (measured); a whole-`Agent` row fetcher like `get_by_id`: a future \
         caller that serializes the row must apply `redact_agent`",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "find_by_role",
        "no caller in any crate (measured); a whole-`Agent` row fetcher like `get_by_id`: a future \
         caller that serializes the row must apply `redact_agent`",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "get_by_orcid",
        "no caller in any crate (measured); an ORCID matcher would be an oracle if served, so a \
         future caller must gate it on `details` as `match_ranked` does",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "get_by_ror_id",
        "no caller in any crate (measured); a ROR matcher would be an oracle if served, so a future \
         caller must gate it on `details` as `match_ranked` does",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "get_with_identity",
        "no caller in any crate (measured); a whole-`Agent` row fetcher like `get_by_id`: a future \
         caller that serializes the row must apply `redact_agent`",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "get_by_id",
        "whole-`Agent` row fetcher: every route that SERIALIZES the row (agents.rs get_agent, \
         reputation, political profile / compare, prov export) applies the disclosure; the other \
         callers use the row for existence, its key or its id only (spec 7.J)",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "get_by_public_key",
        "whole-`Agent` row fetcher keyed on a public key: `create_agent`'s find-hit applies the \
         disclosure; the provenance, conventions, edge-signer and operator bind callers use the \
         row's id or the signer constant only",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "list",
        "whole-`Agent` page fetcher for `GET /api/v1/agents`, which applies `redact_agent` per row \
         on a stamped connection before serializing",
    ),
    // The four below are WRITES that hand their row back (`RETURNING`), seen
    // since review finding leaks#4a extended the scan.
    (
        "epigraph-db/src/repos/agent.rs",
        "update",
        "the profile edit's `UPDATE agents ... RETURNING` row: its one caller, \
         `routes/agents.rs::update_agent`, redacts the response through \
         `AgentDisclosureRepository::disclosure` on the caller's stamped read before \
         serializing (review correctness#7), whichever row the edit moved",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "create_conn",
        "an agent INSERT that echoes the row it just created: the caller's own input \
         (`create_agent` on a new key, the ingest's name-derived author nodes), never \
         another agent's stored identity",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "create_signer_conn",
        "an agent INSERT that echoes the row it just created from the caller's own input \
         (a signer identity); never another agent's stored identity",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "create_seed_derived_conn",
        "a plain INSERT of a seed-derived node (ingest authors, operator bind, provenance \
         seeds): it returns only the row it CREATED from the caller's own input; a key that \
         exists is a DuplicateKey error, never another agent's stored identity",
    ),
    (
        "epigraph-db/src/repos/agent.rs",
        "list_by_label",
        "whole-`Agent` page fetcher for `GET /api/v1/agents?label=`, which applies `redact_agent` \
         per row on a stamped connection before serializing",
    ),
];

/// Surfaces still to convert. Empty since part B converted the last one; a read that needs converting
/// later is listed here with the change that will convert it, never left
/// unregistered.
const PENDING: &[(&str, &str)] = &[];

// `profile_visibility` joined after review (leaks#4b): after migration 274 a
// human principal reads 'group' and non-humans keep the 'public' default, so
// the value itself is near-human evidence. `agent_type` is NOT a lint column:
// on HEAD it is read only for `= 'role'` checks (`cards_inner`,
// `author_nodes`, `exact_name_candidates`), and a role node is public by
// design; a future surface that serves it is review's to catch.
// `profile_public_consented_at` (283, operator ruling C11) is set only on a
// person who opted in, so a non-null value is human evidence too.
const IDENTITY_COLUMNS: &[&str] = &[
    "display_name",
    "orcid",
    "ror_id",
    "properties",
    "profile_visibility",
    "profile_public_consented_at",
];
const BARE_COLUMNS: &[&str] = &[
    "display_name",
    "orcid",
    "ror_id",
    "profile_visibility",
    "profile_public_consented_at",
];
const NOT_ALIASES: &[&str] = &[
    "where",
    "on",
    "join",
    "left",
    "right",
    "inner",
    "cross",
    "full",
    "order",
    "group",
    "limit",
    "using",
    "union",
    "for",
    "returning",
    "having",
    "offset",
    "natural",
    "lateral",
    "except",
    "intersect",
    "window",
    "fetch",
    "set",
    "as",
];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every `crates/<crate>/src/**/*.rs`, as `(<crate>/src/..., source)` with
/// the `#[cfg(test)] mod` tail cut.
fn sources() -> Vec<(String, String)> {
    let root = workspace().join("crates");
    let mut out = Vec::new();
    for c in std::fs::read_dir(&root).expect("crates/").flatten() {
        let src = c.path().join("src");
        let mut files = Vec::new();
        rs_files(&src, &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .expect("under crates/")
                .to_string_lossy()
                .replace('\\', "/");
            let mut text = std::fs::read_to_string(&f).expect("read source");
            if let Some(at) = cfg_test_mod(&text) {
                text.truncate(at);
            }
            out.push((rel, text));
        }
    }
    out
}

fn cfg_test_mod(src: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = src[from..].find("#[cfg(test)]") {
        let at = from + rel;
        let rest = src[at + "#[cfg(test)]".len()..].trim_start();
        if rest.starts_with("mod ") || rest.starts_with("pub mod ") {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

fn balanced(src: &str, start: usize, open: u8, close: u8) -> &str {
    let b = src.as_bytes();
    let mut depth = 0i32;
    for (i, &c) in b.iter().enumerate().skip(start) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return &src[start..=i];
            }
        }
    }
    &src[start..]
}

/// `(name, body)` of every `fn` with a body in `src`.
fn fns(src: &str) -> Vec<(String, String)> {
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
        let after = &src[at + 3..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        if name_end == 0 {
            continue;
        }
        let name = after[..name_end].to_string();
        let cursor = at + 3 + name_end;
        let Some(paren_rel) = src[cursor..].find('(') else {
            continue;
        };
        let paren = cursor + paren_rel;
        if !src[cursor..paren].trim().is_empty() && !src[cursor..paren].trim().starts_with('<') {
            continue;
        }
        let params = balanced(src, paren, b'(', b')');
        let tail = &src[paren + params.len()..];
        let (Some(brace_rel), semi) = (tail.find('{'), tail.find(';')) else {
            continue;
        };
        if semi.is_some_and(|s| s < brace_rel) {
            continue; // a declaration without a body
        }
        let brace = paren + params.len() + brace_rel;
        out.push((name, balanced(src, brace, b'{', b'}').to_string()));
    }
    out
}

/// The live SQL of `body`, lower-cased, with Rust line continuations and
/// runs of whitespace folded to one space.
fn sql_of(body: &str) -> String {
    let (_, live) = spend_views(body);
    let live = string_contents(&live)
        .replace("\\n", " ")
        .replace('\\', " ")
        .to_lowercase();
    live.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Only the contents of the string literals in `src` (Rust code that merely
/// moves a value, `display_name: a.display_name`, is not SQL), joined by
/// spaces. Raw strings (`r"…"`, `r#"…"#`) and `\"` escapes are followed.
fn string_contents(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' {
            // A char literal ('"', '\'') is skipped whole; a lifetime is not one.
            if i + 2 < b.len() && b[i + 2] == b'\'' {
                i += 3;
                continue;
            }
            if i + 3 < b.len() && b[i + 1] == b'\\' && b[i + 3] == b'\'' {
                i += 4;
                continue;
            }
            i += 1;
            continue;
        }
        let raw_hashes = if b[i] == b'r' && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                j += 1;
            }
            (j < b.len() && b[j] == b'"').then_some((j - i - 1, j))
        } else {
            None
        };
        if let Some((hashes, quote)) = raw_hashes {
            let close = format!("\"{}", "#".repeat(hashes));
            let start = quote + 1;
            let end = src[start..].find(&close).map_or(b.len(), |r| start + r);
            out.push_str(&src[start..end]);
            out.push(' ');
            i = (end + close.len()).min(b.len());
            continue;
        }
        if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            out.push_str(&src[i + 1..j.min(b.len())]);
            out.push(' ');
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn word_at(s: &str, at: usize) -> &str {
    let rest = &s[at..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    &rest[..end]
}

fn has_word(s: &str, w: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = s[from..].find(w) {
        let at = from + rel;
        let before_ok = at == 0 || {
            let c = s.as_bytes()[at - 1];
            !(c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
        };
        let end = at + w.len();
        let after_ok = end >= s.len() || {
            let c = s.as_bytes()[end];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Does this SQL read an identity column off an `agents` row? Also true for
/// a fragment builder that names `a.display_name` / `a.orcid` / `a.ror_id`
/// with no `FROM` of its own (`a` is the agents alias by convention), so a
/// column list assembled in a helper is seen where it is written.
fn reads_identity(sql: &str) -> bool {
    // A write that hands the row back (review finding leaks#4a): `UPDATE
    // agents ... RETURNING display_name` is a read of whatever row it moved.
    if let Some(ret) = sql.find(" returning ") {
        let writes_agents = [
            "update agents",
            "update public.agents",
            "insert into agents",
            "insert into public.agents",
        ]
        .iter()
        .any(|w| sql[..ret].contains(w));
        if writes_agents && BARE_COLUMNS.iter().any(|c| has_word(&sql[ret..], c)) {
            return true;
        }
    }
    if [
        "a.display_name",
        "a.orcid",
        "a.ror_id",
        "a.profile_visibility",
    ]
    .iter()
    .any(|c| has_word(sql, c))
        && !sql.contains("from agents")
        && !sql.contains("join agents")
        && !sql.contains("public.agents")
    {
        return true;
    }
    for kw in ["from ", "join "] {
        let mut from = 0;
        while let Some(rel) = sql[from..].find(kw) {
            let at = from + rel;
            from = at + 1;
            if at > 0 {
                let c = sql.as_bytes()[at - 1];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    continue;
                }
            }
            let mut p = at + kw.len();
            if sql[p..].starts_with("public.") {
                p += "public.".len();
            }
            if word_at(sql, p) != "agents" {
                continue;
            }
            p += "agents".len();
            let rest = sql[p..].trim_start();
            let mut alias = word_at(rest, 0);
            if alias == "as" {
                alias = word_at(rest[2..].trim_start(), 0);
            }
            if alias.is_empty() || NOT_ALIASES.contains(&alias) {
                if BARE_COLUMNS.iter().any(|c| has_word(sql, c)) {
                    return true;
                }
            } else if IDENTITY_COLUMNS
                .iter()
                .any(|c| sql.contains(&format!("{alias}.{c}")))
            {
                return true;
            }
        }
    }
    false
}

fn measure() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for (file, src) in sources() {
        for (name, body) in fns(&src) {
            let sql = sql_of(&body);
            if reads_identity(&sql) {
                // The lateral helper writes the call into the statement; keep
                // its spelling so GATED can see it.
                let marker = if body.contains("disclosure_lateral_sql(") {
                    " epigraph_agent_disclosure("
                } else {
                    ""
                };
                found.push((file.clone(), name, format!("{sql}{marker}")));
            }
        }
    }
    found.sort();
    found.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    found
}

#[test]
fn every_identity_read_of_an_agent_is_gated_or_reviewed() {
    let found = measure();
    assert!(
        found.len() >= 3,
        "the scanner found {} identity reads: it is not matching and would pass vacuously",
        found.len()
    );
    let got: Vec<(String, String)> = found
        .iter()
        .map(|(f, n, _)| (f.clone(), n.clone()))
        .collect();
    let mut want: Vec<(String, String)> = GATED
        .iter()
        .chain(PENDING.iter())
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .chain(
            ALLOWED
                .iter()
                .map(|(f, n, _)| ((*f).to_string(), (*n).to_string())),
        )
        .collect();
    want.sort();
    want.dedup();
    let missing: Vec<_> = got.iter().filter(|x| !want.contains(x)).collect();
    let stale: Vec<_> = want.iter().filter(|x| !got.contains(x)).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "\nidentity reads of `agents` not gated or reviewed: {missing:#?}\n\
         registered but no longer reading: {stale:#?}\n\
         Route the read through `AgentDisclosureRepository` / the disclosure lateral, or \
         review it into ALLOWED with a reason.\n"
    );
    for (file, name, sql) in &found {
        if GATED.iter().any(|(f, n)| f == file && n == name) {
            assert!(
                DISCLOSURE_CALLS.iter().any(|c| sql.contains(c)),
                "{file}::{name} is registered GATED but its SQL calls no disclosure function"
            );
        }
    }
    for (file, name, reason) in ALLOWED {
        assert!(
            reason.len() > 60,
            "the reason for {file}::{name} is too short to be a review"
        );
    }
}

#[test]
fn the_scanner_sees_aliased_unaliased_and_gated_shapes() {
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT a.id, a.display_name FROM agents a WHERE a.id = $1") }"#
    )));
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT id, display_name FROM agents WHERE id = ANY($1)") }"#
    )));
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT x FROM claims c JOIN public.agents AS ag ON ag.id = c.agent_id WHERE ag.orcid = $1") }"#
    )));
    assert!(!reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT 1 FROM agents a WHERE a.id = $1") }"#
    )));
    assert!(!reads_identity(&sql_of(
        r#"{ sqlx::query("INSERT INTO agents (public_key, display_name) VALUES ($1, $2)") }"#
    )));
    // A write that returns the identity columns is a read (leaks#4a); one
    // that returns only the id is not.
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("UPDATE agents SET labels = $2 WHERE id = $1 RETURNING id, display_name, orcid") }"#
    )));
    assert!(!reads_identity(&sql_of(
        r#"{ sqlx::query("UPDATE agents SET labels = $2 WHERE id = $1 RETURNING id") }"#
    )));
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("INSERT INTO public.agents (public_key) VALUES ($1) RETURNING id, display_name") }"#
    )));
    // `profile_visibility` is an identity column (leaks#4b).
    assert!(reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT a.profile_visibility FROM agents a WHERE a.id = $1") }"#
    )));
    // A name read commented out of the statement is not a read.
    assert!(!reads_identity(&sql_of(
        r#"{ sqlx::query("SELECT a.id /* , a.display_name */ FROM agents a") }"#
    )));
}

/// Operator ruling C7 (migration 285): wherever a statement decides an
/// agent's name by the disclosure rule, the unnamed reading is the
/// `oauth:<client row id>` placeholder a nameless service principal carries,
/// never NULL (a null name on an OAuth principal marked exactly the hidden
/// humans). So no live SQL in `crates/*/src` may end a name decision with
/// `THEN <alias>.display_name END`: every such `CASE` carries
/// `ELSE public.epigraph_unnamed_agent_name(<alias>.id) END`.
#[test]
fn no_name_decision_falls_back_to_null() {
    fn offenders(sql: &str) -> usize {
        let mut n = 0;
        let mut from = 0;
        while let Some(rel) = sql[from..].find(".display_name end") {
            let at = from + rel;
            from = at + 1;
            let before = sql[..at].trim_end();
            let alias_start = before
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            if before[..alias_start].trim_end().ends_with("then") {
                n += 1;
            }
        }
        n
    }
    // The scanner on planted shapes: the old fallback is seen, the ruled one
    // and an unrelated `END` are not.
    assert_eq!(
        offenders(&sql_of(
            r#"{ sqlx::query("SELECT CASE WHEN d.named THEN a.display_name END FROM agents a") }"#
        )),
        1
    );
    assert_eq!(
        offenders(&sql_of(
            r#"{ sqlx::query("SELECT CASE WHEN d.named THEN a.display_name \
                ELSE public.epigraph_unnamed_agent_name(a.id) END FROM agents a") }"#
        )),
        0
    );
    let mut found = Vec::new();
    let mut scanned = 0usize;
    for (file, src) in sources() {
        for (name, body) in fns(&src) {
            let sql = sql_of(&body);
            if sql.contains("display_name") {
                scanned += 1;
            }
            if offenders(&sql) > 0 {
                found.push(format!("{file}::{name}"));
            }
        }
    }
    assert!(
        scanned >= 10,
        "CALIBRATION: the scan saw only {scanned} functions naming display_name"
    );
    assert!(
        found.is_empty(),
        "these name decisions fall back to NULL instead of the placeholder (C7): {found:?}"
    );
}
