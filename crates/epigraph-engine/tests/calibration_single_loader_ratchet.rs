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
        "crates/epigraph-cli/src/bin/cross_source_sweep.rs",
        "MatcherConfig::load_from(p)",
        "an explicit, optional `--calibration <PATH>` operator argument for the [matcher] \
         section; without it the sweep takes [matcher] from the served calibration \
         (`MatcherConfig::load_default` -> `CalibrationConfig::served_matcher`)",
    ),
];

const NEEDLES: &[&str] = &[
    // Any variable NAMED like the override (`"CALIBRATION_PATH"`, and a second
    // one such as `"EPIGRAPH_CALIBRATION_PATH"`, backlog 26a12f41).
    "CALIBRATION_PATH\"",
    // A path read of the cross-source matcher's `[matcher]` section (backlog
    // 26a12f41): `MatcherConfig::load_default` resolves it with the rest.
    "MatcherConfig::load_from(",
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
    #[arg(long, env = "EPIGRAPH_CALIBRATION_PATH", hide_env_values = true)]
fn matcher_cwd() -> MatcherConfig { Self::load_from(Path::new("calibration.toml")).unwrap() }
fn matcher_path(p: &Path) -> MatcherConfig { MatcherConfig::load_from(p).unwrap() }
"#;
    let hits = scan("x.rs", removed);
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        vec![3, 4, 9, 10, 11, 12, 13, 14, 15],
        "env + cwd literal (line 3), path load (line 4), embedded copy (line 9), \
         compiled-in only (line 10), empty maps (line 11), text parse (line 12), a second \
         override variable (line 13), the old cwd [matcher] read (line 14), a [matcher] \
         path read (line 15): {hits:?}"
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

/// Every `DsAutoInput { .. }` literal in `src`, from its opening brace to the
/// matching closing one, with its 1-based starting line.
fn ds_auto_inputs(src: &str) -> Vec<(usize, String)> {
    const OPEN: &str = "DsAutoInput {";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = src[from..].find(OPEN) {
        let start = from + at;
        let body_start = start + OPEN.len();
        let mut depth = 1usize;
        let mut end = src.len();
        for (i, ch) in src[body_start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((
            src[..start].matches('\n').count() + 1,
            src[body_start..end].to_string(),
        ));
        from = body_start;
    }
    out
}

/// True when a struct-literal body sets `weight` to a numeric literal.
fn sets_a_literal_weight(body: &str) -> bool {
    body.split(',').any(|field| {
        let mut kv = field.splitn(2, ':');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim_start();
        key == "weight" && value.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// Ratchet (backlog 26a12f41): no production `DsAutoInput` passes a literal
/// `weight`. The weight is the evidence type's reliability, which the served
/// calibration owns; `memorize` passed `weight: 0.6`, which matched the
/// shipped `testimonial` weight but ignored a `CALIBRATION_PATH` retune.
///
/// Scope: a source-text scan of `DsAutoInput { .. }` struct literals whose
/// `weight:` field is a numeric literal. It does NOT see a literal routed
/// through a named constant (`weight: TESTIMONY_W`) or a weight passed
/// positionally to a `ds_auto` helper; review those by hand. When added, no
/// production call site did either.
#[test]
fn no_ds_auto_input_hardcodes_its_evidence_type_weight() {
    let root = workspace_root();
    let mut seen = 0;
    let mut offending = Vec::new();
    for (file, src) in production_sources(&root) {
        for (line, body) in ds_auto_inputs(&production_code(&src)) {
            seen += 1;
            if sets_a_literal_weight(&body) {
                offending.push(format!("  {file}:{line}: DsAutoInput {{{}}}", body.trim()));
            }
        }
    }
    assert!(
        seen >= 2,
        "found {seen} DsAutoInput literals; the scan no longer sees the writers (moved? \
         update this ratchet)"
    );
    assert!(
        offending.is_empty(),
        "DsAutoInput with a literal weight (use CalibrationConfig::cached()\
         .get_evidence_type_weight(<the evidence row's tag>)):\n{}",
        offending.join("\n")
    );
}

/// The `DsAutoInput` scanner: a literal weight is a hit, a resolved one,
/// a shorthand field and a `weight_*` field are not, and a nested brace does
/// not end the literal early.
#[test]
fn the_ds_auto_input_scanner_flags_only_a_literal_weight() {
    let src = "fn a() {\n    f(DsAutoInput {\n        confidence,\n        weight: 0.6,\n        \
               supports: true,\n        evidence_type: Some(\"testimony\"),\n    });\n}\n\
               fn b() { g(ds_auto::DsAutoInput { confidence, weight, supports: true, \
               evidence_type: None, evidence_id: None }); }\n\
               fn c() { g(DsAutoInput { confidence: { 0.5 }, weight: w(), supports: true, \
               evidence_type: None, evidence_id: None }); }\n\
               fn d() { g(DsAutoInput { weight_hint: 1.0, weight: cached().get_evidence_type_weight(t), \
               supports: true, evidence_type: None, evidence_id: None }); }\n";
    let found = ds_auto_inputs(src);
    assert_eq!(
        found.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        vec![2, 9, 10, 11]
    );
    let literal: Vec<bool> = found
        .iter()
        .map(|(_, b)| sets_a_literal_weight(b))
        .collect();
    assert_eq!(literal, vec![true, false, false, false], "{found:?}");
    // After the nested `{ 0.5 }` block the scan still reaches `weight: w()`.
    assert!(found[2].1.contains("weight: w()"), "{:?}", found[2]);
}
