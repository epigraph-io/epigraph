//! **The inherited-successor writer pin** (backlog 1a54283d, ruling R-85).
//!
//! Once the operator binding is armed, migration 185 checks the INSERT of an
//! inherited successor (a new claim naming `supersedes`, restating a retired
//! predecessor under that predecessor's author and group) on its writer alone:
//! the author it restates is no longer attributed to the writer's human. A
//! `BEFORE INSERT` trigger recognises that row by its shape; it cannot see the
//! `AUTHORED` act edge the act writes after the claim. The relief is sound
//! because the only application code that writes a claim naming `supersedes`
//! is the supersede act, which records its actor as the successor's act edge,
//! and `evolve_step`, which authors the caller (its principal is its author,
//! so the relieved branch is not reached).
//!
//! This file holds that: every SQL literal in `crates/*/src` (outside
//! `#[cfg(test)]` items) that inserts into `claims` and mentions `supersedes`
//! anywhere in the statement must sit in one of the registered functions. A
//! new writer of that shape fails here until it is reviewed against 185 and
//! registered. The match is deliberately broad (any mention of the column in
//! the statement), so it over-reports rather than misses; a statement built
//! from several literals or with `format!` is out of its reach and needs the
//! same review.

mod belief_lint;

use belief_lint::{
    has_word, rust_sources, rust_view, sql_without_comments, with_scratch, RustUnits, Source,
};
use std::collections::BTreeSet;

/// Every non-test site that inserts a claim naming `supersedes`, keyed
/// `(path, fn)`, measured on this branch.
const REGISTER: &[(&str, &str)] = &[
    // The supersede act: restates the predecessor under its author and group
    // and records the actor as the successor's `AUTHORED` act edge.
    (
        "crates/epigraph-db/src/repos/claim.rs",
        "supersede_act_conn",
    ),
    // A workflow step's evolution: the new step is authored by the caller.
    ("crates/epigraph-db/src/repos/claim.rs", "evolve_step_conn"),
];

/// Does `sql` hold an `INSERT INTO claims` (or `public.claims`) statement that
/// mentions `supersedes`? The statement runs to the next `;` or the end of
/// the literal.
fn inserts_a_claim_naming_supersedes(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("insert into") {
        let at = from + rel + "insert into".len();
        from = at;
        let rest = lower[at..].trim_start();
        let rest = rest.strip_prefix("public.").unwrap_or(rest);
        let Some(after) = rest.strip_prefix("claims") else {
            continue;
        };
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue; // claims_something, another table
        }
        let statement = after.split(';').next().unwrap_or(after);
        if has_word(statement, "supersedes") {
            return true;
        }
    }
    false
}

/// The `(path, fn)` of every matching site in `sources`.
fn sites(sources: &[Source]) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for s in sources {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for lit in &view.literals {
            if inserts_a_claim_naming_supersedes(&sql_without_comments(&lit.text)) {
                out.insert((s.path.clone(), units.unit_at(lit.start).0));
            }
        }
    }
    out
}

fn register() -> BTreeSet<(String, String)> {
    REGISTER
        .iter()
        .map(|(p, f)| ((*p).to_string(), (*f).to_string()))
        .collect()
}

#[test]
fn only_the_supersede_act_and_evolve_step_insert_a_claim_naming_supersedes() {
    let found = sites(&rust_sources());
    let expected = register();
    let unregistered: Vec<_> = found.difference(&expected).collect();
    let stale: Vec<_> = expected.difference(&found).collect();
    assert!(
        unregistered.is_empty(),
        "a new site inserts a claim naming `supersedes`: {unregistered:?}. Migration 185 checks \
         such a row on its writer alone when it restates a retired predecessor under its \
         author; review the site against that (does it record its actor, or author the \
         caller?) and register it here"
    );
    assert!(
        stale.is_empty(),
        "a registered site no longer matches; remove it from REGISTER: {stale:?}"
    );
}

/// POSITIVE CONTROLS over the real tree plus one scratch source: the scan
/// finds a new writer whatever the statement's spelling, and ignores a
/// `#[cfg(test)]` fixture, another table and a statement that does not name
/// the column.
#[test]
fn the_pin_finds_a_new_writer_and_ignores_fixtures() {
    let base = rust_sources();
    let path = "crates/epigraph-api/src/routes/scratch_r85.rs";
    let hit = |text: &str| -> BTreeSet<(String, String)> {
        sites(&with_scratch(&base, path, text))
            .into_iter()
            .filter(|(p, _)| p == path)
            .collect()
    };
    let one = |f: &str| BTreeSet::from([(path.to_string(), f.to_string())]);

    assert_eq!(
        hit(
            "async fn posed() { sqlx::query(\"INSERT INTO claims (id, agent_id, supersedes) \
             VALUES ($1, $2, $3)\"); }"
        ),
        one("posed"),
        "a plain column list"
    );
    assert_eq!(
        hit(
            "async fn qualified() { sqlx::query(r#\"insert into public.claims AS c \
             (id, agent_id, supersedes) VALUES ($1, $2, $3)\"#); }"
        ),
        one("qualified"),
        "lower case, schema-qualified, aliased, raw string"
    );
    assert_eq!(
        hit(
            "async fn selected() { sqlx::query(\"INSERT INTO claims (id, agent_id, supersedes) \
             SELECT $1, agent_id, id FROM claims WHERE id = $2\"); }"
        ),
        one("selected"),
        "INSERT ... SELECT"
    );
    assert!(
        hit(
            "#[cfg(test)] mod t { fn fixture() { sqlx::query(\"INSERT INTO claims \
             (id, supersedes) VALUES ($1, $2)\"); } }"
        )
        .is_empty(),
        "a #[cfg(test)] fixture is not a served write"
    );
    assert!(
        hit(
            "fn other() { sqlx::query(\"INSERT INTO claims_archive (id, supersedes) \
             VALUES ($1, $2)\"); }"
        )
        .is_empty(),
        "another table"
    );
    assert!(
        hit(
            "fn fresh() { sqlx::query(\"INSERT INTO claims (id, agent_id) VALUES ($1, $2); \
             SELECT supersedes FROM claims\"); }"
        )
        .is_empty(),
        "the column outside the INSERT statement"
    );
}
