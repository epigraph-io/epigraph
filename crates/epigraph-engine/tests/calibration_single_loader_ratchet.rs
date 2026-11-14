//! Ratchet: the evidence-type calibration is resolved in ONE place,
//! `crates/epigraph-engine/src/calibration.rs` (`CalibrationConfig::cached`:
//! the `CALIBRATION_PATH` file when it loads, else the copy compiled into the
//! binary). No other production source reads a calibration file by path
//! (backlog d83b998a).
//!
//! Three private `load_evidence_type_weight` copies (MCP `tools/claims.rs`,
//! `tools/workflows.rs`, CLI `bin/backfill_factors.rs`) read the file
//! `CALIBRATION_PATH` named, else `calibration.toml` in the cwd, and returned
//! 0.7 on any failure, so a process started outside a checkout baked 0.7 into
//! BBAs the served calibration weights at 1.0. This test scans the code of
//! every `crates/*/src` file and `crates/*/build.rs` (comments and
//! `#[cfg(test)] mod` blocks excluded; string literals KEPT, since the
//! needles are literals) for:
//!
//! - `"CALIBRATION_PATH"`: reading the override variable outside the resolver;
//! - `CalibrationConfig::load(`: a path-based read of the calibration;
//! - a string literal ending in `calibration.toml"`: naming the file as a path
//!   (cwd-relative `"calibration.toml"`, or an `include_str!` copy);
//! - `CalibrationConfig::embedded(`: the compiled-in copy alone, which ignores
//!   a `CALIBRATION_PATH` override (`cached()` serves it as the fallback);
//! - `default_for_phase2_fallback(`: a calibration with EMPTY weight and alias
//!   maps, so every evidence type falls to the unknown-type default;
//! - `from_str::<CalibrationConfig`: deserializing a calibration from text
//!   read somewhere other than the resolver.
//!
//! The exemption is the resolver's file by its FULL path (a file-name match
//! would also exempt `matching/calibration.rs`). Any other exception is an
//! entry in [`ALLOWED`] with its reason; an entry that matches nothing fails,
//! so the list cannot rot.
//!
//! Plain text processing (no syn), so it runs everywhere the suite runs.

#[path = "support/rust_sources.rs"]
mod rust_sources;

use rust_sources::{production_code, production_sources, workspace_root};

/// The one module allowed to resolve the calibration from a path.
const RESOLVER: &str = "crates/epigraph-engine/src/calibration.rs";

/// `(workspace-relative file, fragment of the offending code line, reason)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/epigraph-cli/src/bin/backfill_evidence_type.rs",
        "CalibrationConfig::load(&cli.calibration)",
        "an explicit, REQUIRED `--calibration <PATH>` operator argument that refuses an \
         empty [evidence_type_weights]; not an implicit env or cwd read",
    ),
    (
        "crates/epigraph-engine/src/belief_profile.rs",
        "p.overlaid(\"calibration.toml\", over)",
        "a provenance label for the profile overlay, not a path",
    ),
    (
        "crates/epigraph-engine/src/supersede_delta/r173.rs",
        "BeliefProfile::from_calibration(&CalibrationConfig::default_for_phase2_fallback())",
        "`empty_vocabulary_profile`: the R-173 dry run's counterfactual E, the profile a process \
         served when it could NOT load a calibration (the empty vocabulary the measured caches \
         were written under); read-only, never a served or written weight (F and A use \
         BeliefProfile::served)",
    ),
    (
        "crates/epigraph-engine/src/matching/calibration.rs",
        "Self::load_from(Path::new(\"calibration.toml\"))",
        "MatcherConfig ([matcher] section, cross-source matcher), a separate loader that \
         fails loudly instead of falling back; not the evidence-type calibration",
    ),
];

const NEEDLES: &[&str] = &[
    "\"CALIBRATION_PATH\"",
    "CalibrationConfig::load(",
    "calibration.toml\"",
    "CalibrationConfig::embedded(",
    "default_for_phase2_fallback(",
    "from_str::<CalibrationConfig",
];

#[derive(Debug, Clone, PartialEq)]
struct Hit {
    file: String,
    line: usize,
    text: String,
}

/// Every needle hit in one file's production code.
fn scan(file: &str, src: &str) -> Vec<Hit> {
    production_code(src)
        .lines()
        .enumerate()
        .filter(|(_, l)| NEEDLES.iter().any(|n| l.contains(n)))
        .map(|(n, l)| Hit {
            file: file.to_string(),
            line: n + 1,
            text: l.trim().to_string(),
        })
        .collect()
}

fn is_allowed(hit: &Hit) -> bool {
    ALLOWED
        .iter()
        .any(|(f, frag, _)| hit.file == *f && hit.text.contains(frag))
}

#[test]
fn no_path_based_calibration_read_outside_the_resolver() {
    let root = workspace_root();
    let sources = production_sources(&root);
    assert!(
        sources.iter().any(|(f, _)| f == RESOLVER),
        "the resolver {RESOLVER} must exist (did it move? update this ratchet)"
    );
    let hits: Vec<Hit> = sources
        .iter()
        .filter(|(f, _)| f != RESOLVER)
        .flat_map(|(f, s)| scan(f, s))
        .collect();

    let offending: Vec<&Hit> = hits.iter().filter(|h| !is_allowed(h)).collect();
    assert!(
        offending.is_empty(),
        "path-based calibration reads outside {RESOLVER} (use \
         CalibrationConfig::cached(), which serves the CALIBRATION_PATH file or the \
         compiled-in copy; or add an ALLOWED entry with its reason):\n{}",
        offending
            .iter()
            .map(|h| format!("  {}:{}: {}", h.file, h.line, h.text))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let stale: Vec<&str> = ALLOWED
        .iter()
        .filter(|(f, frag, _)| !hits.iter().any(|h| h.file == *f && h.text.contains(frag)))
        .map(|(f, _, _)| *f)
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED entries that exempt nothing (remove them): {stale:?}"
    );
}

/// The scanner itself: the three removed loader shapes are hits; the same
/// text in a comment, a doc comment or a `#[cfg(test)] mod` is not; an
/// `ALLOWED` fragment exempts only its own file.
#[test]
fn the_scanner_flags_the_removed_loader_shapes_and_nothing_in_comments_or_tests() {
    let removed = r#"
fn load_evidence_type_weight(evidence_type: &str) -> f64 {
    let path = std::env::var("CALIBRATION_PATH").unwrap_or_else(|_| "calibration.toml".to_string());
    epigraph_engine::calibration::CalibrationConfig::load(std::path::Path::new(&path))
        .ok()
        .map(|c| c.get_evidence_type_weight(evidence_type))
        .unwrap_or(0.7)
}
const COPY: &str = include_str!("../../../calibration.toml");
fn compiled_in_only() -> f64 { CalibrationConfig::embedded().get_evidence_type_weight("empirical") }
fn empty_maps() -> CalibrationConfig { CalibrationConfig::default_for_phase2_fallback() }
fn parsed(p: &Path) -> CalibrationConfig { toml::from_str::<CalibrationConfig>(&std::fs::read_to_string(p).unwrap()).unwrap() }
"#;
    let hits = scan("x.rs", removed);
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        vec![3, 4, 9, 10, 11, 12],
        "env + cwd literal (line 3), path load (line 4), embedded copy (line 9), \
         compiled-in only (line 10), empty maps (line 11), text parse (line 12): {hits:?}"
    );

    let quiet = r#"
//! Reads `CALIBRATION_PATH`: std::env::var("CALIBRATION_PATH")
/// `CalibrationConfig::load(Path::new("calibration.toml"))` was the old way.
fn served() -> f64 {
    // CalibrationConfig::load(&p) is forbidden here
    /* nested /* "calibration.toml" */ still a comment */
    let msg = "Failed to load calibration.toml: {e}";
    CalibrationConfig::cached().get_evidence_type_weight("empirical")
}
#[cfg(test)]
mod tests {
    fn path() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("calibration.toml") }
    fn load() { CalibrationConfig::load(&path()).unwrap(); }
}
fn after_tests() -> &'static str { "{" }
"#;
    assert_eq!(scan("y.rs", quiet), Vec::<Hit>::new());

    // Code after a test module (and a brace inside a string) is still scanned.
    let after = "#[cfg(test)]\nmod t { fn f() { let _ = \"}\"; } }\nfn g() { CalibrationConfig::load(&p); }\n";
    assert_eq!(scan("z.rs", after).len(), 1);

    let allowed_elsewhere = Hit {
        file: "crates/other/src/lib.rs".into(),
        line: 1,
        text: "CalibrationConfig::load(&cli.calibration)".into(),
    };
    assert!(
        !is_allowed(&allowed_elsewhere),
        "an ALLOWED fragment is per file"
    );
}
