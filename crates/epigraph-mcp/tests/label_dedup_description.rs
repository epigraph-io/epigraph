//! The label-dedup surfaces must say how a mark an apply made is undone
//! (backlog 1f8fda35). They told readers a mark is one-way: the
//! `apply_label_dedup` description ended "there a mark is one-way", and
//! `docs/conventions/label-dedup.md` said "no shipped surface runs one
//! elsewhere, so today a mark is one-way". The operator CLI
//! `unmark_duplicate` takes an apply response (`--applied-marks`) and
//! un-marks its marks on the maintenance DSN, and `revert_label_dedup` with
//! `applied_units` alone reverses the label writes anywhere, so both the
//! descriptions and the doc name that path (as `mark_duplicate`'s description
//! already does, pinned by `mark_duplicate_description.rs`).
//!
//! Asserted against `EpiGraphMcpFull::static_tools()`, the router-derived
//! manifest `tools/list` serves, and the checked-in docs. No DB.

use epigraph_mcp::server::EpiGraphMcpFull;

const LABEL_DEDUP_DOC: &str = include_str!("../../../docs/conventions/label-dedup.md");
const HYGIENE_DOC: &str = include_str!("../../../docs/conventions/duplicates-and-index-hygiene.md");

fn description(tool: &str) -> String {
    EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == tool)
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .unwrap_or_else(|| panic!("{tool} is in the manifest and has a description"))
}

/// The old advice, and the rewordings that would restore it.
fn assert_never_one_way(what: &str, text: &str) {
    let lower = text.to_ascii_lowercase();
    for phrase in ["one-way", "one way", "irreversib", "cannot be undone"] {
        assert!(
            !lower.contains(phrase),
            "{what}: a label-dedup mark can be un-marked (by an operator on a request \
             server), so it must not be called {phrase:?}: {text}"
        );
    }
}

#[test]
fn apply_and_revert_descriptions_name_the_operator_unmark_path() {
    for tool in ["apply_label_dedup", "revert_label_dedup"] {
        let d = description(tool);
        for needle in [
            "`unmark_duplicate` CLI",
            "--applied-marks",
            "maintenance DSN",
            "takes an operator",
            "applied_units alone",
        ] {
            assert!(d.contains(needle), "{tool} lacks {needle:?}: {d}");
        }
        assert_never_one_way(tool, &d);
    }
}

#[test]
fn the_label_dedup_doc_names_the_operator_unmark_path() {
    for needle in [
        "`unmark_duplicate` CLI",
        "`--applied-marks <the apply response>`",
        "maintenance DSN",
        "takes an operator",
        "`applied_units` alone",
    ] {
        assert!(
            LABEL_DEDUP_DOC.contains(needle),
            "label-dedup.md lacks {needle:?}"
        );
    }
    assert_never_one_way("label-dedup.md", LABEL_DEDUP_DOC);
}

/// The hygiene doc may say "one-way" only to deny it.
#[test]
fn the_hygiene_doc_says_one_way_only_to_deny_it() {
    let lower = HYGIENE_DOC.to_ascii_lowercase();
    let total = lower.matches("one-way").count() + lower.matches("one way").count();
    let denied = lower.matches("not one-way").count();
    assert_eq!(
        total, denied,
        "duplicates-and-index-hygiene.md calls a mark one-way without denying it"
    );
}
