//! Layering guard for `epigraph_engine::diverse_retrieval`.
//!
//! CLAUDE.md mandates: *"All SQL stays in `crates/epigraph-db/src/repos/`."*
//! The diverse-retrieval module is the orchestrator, not a SQL author —
//! it must call into `ClaimThemeRepository` for every database touch.
//!
//! This test reads `diverse_retrieval.rs` at compile time via `include_str!`
//! and asserts that neither `sqlx::query` nor `sqlx::Row` appear in the
//! source. If someone re-introduces SQL into the engine module, this test
//! must fail loudly — that's the entire point.
//!
//! Why a crude grep instead of a clippy lint or a structural analysis?
//! The constraint is "no SQL", not "no `sqlx` symbol", so a textual scan
//! is the *most* durable check we can write. A future refactor that
//! genuinely needs `sqlx::Transaction` in the orchestrator (e.g. for
//! atomicity across two repo calls) can update this test to whitelist
//! that specific symbol; the failure forces the conversation.

const SRC: &str = include_str!("../src/diverse_retrieval.rs");

#[test]
fn diverse_retrieval_module_holds_no_raw_sql() {
    let banned = [
        ("sqlx::query", "raw query builder belongs in repos/"),
        ("sqlx::Row", "row decoding belongs in repos/"),
    ];

    let mut violations: Vec<String> = Vec::new();
    for (needle, why) in banned {
        if SRC.contains(needle) {
            violations.push(format!("found `{needle}` — {why}"));
        }
    }

    assert!(
        violations.is_empty(),
        "epigraph-engine/src/diverse_retrieval.rs must not contain raw SQL.\n\
         CLAUDE.md rule: \"All SQL stays in crates/epigraph-db/src/repos/.\"\n\
         Violations:\n  - {}",
        violations.join("\n  - "),
    );
}
