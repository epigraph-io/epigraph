//! Tests for LLM-based theme naming — pure functions only, no DB or CLI.

use epigraph_jobs::theme_cluster_rebuild::namer::{build_naming_prompt, parse_theme_name};

#[test]
fn prompt_contains_all_claim_contents() {
    let claims = vec![
        "DNA origami enables 2nm feature fabrication".to_string(),
        "Electrostatic actuation achieves sub-nanometer precision".to_string(),
        "Lipid bilayer voltage-sensitive domains respond to mV gradients".to_string(),
    ];
    let prompt = build_naming_prompt(&claims);
    for claim in &claims {
        assert!(
            prompt.contains(claim.as_str()),
            "prompt missing claim: {claim}"
        );
    }
    assert!(
        prompt.to_lowercase().contains("theme name"),
        "prompt must ask for a theme name"
    );
}

#[test]
fn parse_strips_quotes_and_trailing_punctuation() {
    assert_eq!(parse_theme_name("\"DNA Nanotechnology\""), "DNA Nanotechnology");
    assert_eq!(parse_theme_name("Electrostatic Actuation Mechanisms."), "Electrostatic Actuation Mechanisms");
    assert_eq!(parse_theme_name("  Lipid Bilayer Sensors  "), "Lipid Bilayer Sensors");
}

#[test]
fn parse_takes_first_non_empty_line_on_multi_line_output() {
    let multi = "Here is the theme name:\nDNA Origami Fabrication\nSome explanation.";
    let result = parse_theme_name(multi);
    assert!(!result.contains('\n'), "parse_theme_name must return single line, got: {result:?}");
    assert!(!result.is_empty(), "parse_theme_name must not return empty string");
}

#[test]
fn parse_empty_output_returns_empty_string() {
    assert_eq!(parse_theme_name(""), "");
    assert_eq!(parse_theme_name("   "), "");
}
