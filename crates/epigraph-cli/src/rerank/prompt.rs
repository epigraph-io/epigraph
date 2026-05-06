//! LLM prompt construction and response parsing for the bridge reranker.
//!
//! Moved here from `bin/rerank_bridges.rs` so the same prompt logic is
//! reused by both the original global-join CLI and the new candidates-table
//! library entry point.

use crate::rerank::candidates::{CandidatePair, ValidationResult, VALID_RELATIONSHIPS};

/// Build the validation prompt for a batch of candidate pairs.
pub(crate) fn build_validation_prompt(pairs: &[CandidatePair]) -> String {
    let mut pairs_text = String::new();
    for (i, pair) in pairs.iter().enumerate() {
        let src_doi = pair.source_doi.as_deref().unwrap_or("unknown");
        let tgt_doi = pair.target_doi.as_deref().unwrap_or("unknown");
        // Truncate content to keep prompt manageable
        let src = truncate(&pair.source_content, 300);
        let tgt = truncate(&pair.target_content, 300);
        pairs_text.push_str(&format!(
            "Pair {i} (cosine similarity: {:.4}):\n  Source [{src_doi}]: \"{src}\"\n  Target [{tgt_doi}]: \"{tgt}\"\n\n",
            pair.similarity
        ));
    }

    format!(
        r#"You are a scientific relationship validator for an epistemic knowledge graph.
You evaluate whether pairs of scientific claims have a genuine scientific
relationship, or if their high embedding similarity is merely vocabulary overlap.

## CRITICAL DISTINCTION

GENUINE relationship: Claim A's truth or methodology meaningfully bears on Claim B.
One claim provides evidence, theoretical basis, or specific application of the other.

FALSE POSITIVE (reject): Both claims use the same terms (e.g., "octahedral",
"geometry", "lattice") but in unrelated scientific contexts. Example:
Crystal Field Theory (d-orbital splitting in transition metal complexes) vs
DNA origami (octahedral nanostructure shape) — shared word "octahedral", zero mechanistic link.

## Candidate Pairs

{pairs_text}
## Relationship Types

- supports: A provides evidence or theoretical basis for B
- contradicts: A provides evidence undermining B
- derives_from: A is a logical consequence or application of B
- refines: A adds precision or qualifies B
- analogous: genuinely parallel phenomena in related domains

## Rules

1. REJECT pairs where the ONLY connection is shared vocabulary in different contexts
2. A relationship must be defensible in a peer-reviewed context
3. If uncertain, REJECT — false negatives are preferable to false positives
4. Strength range: 0.3 to 1.0 (for accepted pairs)
5. Rationale must name the SPECIFIC scientific mechanism connecting the claims

## Output

Return a JSON array with one object per pair:
- pair_index: integer (0-based)
- valid: boolean
- relationship: string or null (supports/contradicts/derives_from/refines/analogous)
- strength: number or null (0.3 to 1.0)
- rationale: string (explain the specific scientific connection or why it's a false positive)

Return ONLY the JSON array. Include an entry for EVERY pair."#
    )
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
pub(crate) fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(max_len)
            .map_or(s.len(), |(idx, _)| idx);
        format!("{}...", &s[..end])
    }
}

/// Parse and validate the LLM's JSON response into `ValidationResult`s.
pub(crate) fn parse_validation_response(
    json: &serde_json::Value,
    batch_size: usize,
) -> Vec<ValidationResult> {
    let arr = match json.as_array() {
        Some(a) => a,
        None => {
            eprintln!("  WARNING: LLM response is not a JSON array");
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    for item in arr {
        let parsed: ValidationResult = match serde_json::from_value(item.clone()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  WARNING: Failed to parse validation item: {e}");
                continue;
            }
        };

        // Bounds check
        if parsed.pair_index >= batch_size {
            eprintln!(
                "  WARNING: pair_index {} out of bounds (batch size {})",
                parsed.pair_index, batch_size
            );
            continue;
        }

        // Validate accepted pairs
        if parsed.valid {
            if let Some(ref rel) = parsed.relationship {
                if !VALID_RELATIONSHIPS.contains(&rel.as_str()) {
                    eprintln!(
                        "  WARNING: pair {}: invalid relationship '{}', skipping",
                        parsed.pair_index, rel
                    );
                    continue;
                }
            }
            if let Some(strength) = parsed.strength {
                if !(0.3..=1.0).contains(&strength) {
                    eprintln!(
                        "  WARNING: pair {}: strength {:.2} out of [0.3, 1.0], skipping",
                        parsed.pair_index, strength
                    );
                    continue;
                }
            }
        }

        results.push(parsed);
    }

    results
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_pair(src: &str, tgt: &str, sim: f64) -> CandidatePair {
        CandidatePair {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_content: src.to_string(),
            target_content: tgt.to_string(),
            source_doi: Some("paper/123".to_string()),
            target_doi: Some("textbook/chem".to_string()),
            similarity: sim,
        }
    }

    #[test]
    fn test_build_prompt_contains_pairs() {
        let pairs = vec![
            make_pair(
                "DNA nanoengine driven by chemical energy",
                "DNA is a polymer of four nucleotides",
                0.51,
            ),
            make_pair(
                "CO on Cu(111) occupies on-top sites",
                "Crystal field theory explains d-orbital splitting",
                0.49,
            ),
        ];

        let prompt = build_validation_prompt(&pairs);

        assert!(prompt.contains("Pair 0"));
        assert!(prompt.contains("Pair 1"));
        assert!(prompt.contains("DNA nanoengine"));
        assert!(prompt.contains("CO on Cu(111)"));
        assert!(prompt.contains("0.5100"));
        assert!(prompt.contains("0.4900"));
    }

    #[test]
    fn test_build_prompt_includes_rejection_criteria() {
        let pairs = vec![make_pair("a", "b", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        assert!(prompt.contains("FALSE POSITIVE"));
        assert!(prompt.contains("Crystal Field"));
        assert!(prompt.contains("vocabulary overlap"));
        assert!(prompt.contains("REJECT"));
        assert!(prompt.contains("peer-reviewed"));
    }

    #[test]
    fn test_build_prompt_includes_all_relationship_types() {
        let pairs = vec![make_pair("a", "b", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        for rel in VALID_RELATIONSHIPS {
            assert!(
                prompt.contains(rel),
                "Prompt missing relationship type: {rel}"
            );
        }
    }

    #[test]
    fn test_build_prompt_truncates_long_content() {
        let long_content = "A".repeat(500);
        let pairs = vec![make_pair(&long_content, "short", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        // Should be truncated to 300 chars + "..."
        assert!(!prompt.contains(&"A".repeat(400)));
        assert!(prompt.contains("..."));
    }

    #[test]
    fn test_parse_response_accepted() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 0.75,
                "rationale": "DNA origami uses DNA polymer structure"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert_eq!(results.len(), 1);
        assert!(results[0].valid);
        assert_eq!(results[0].relationship.as_deref(), Some("supports"));
        assert!((results[0].strength.unwrap() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_response_rejected() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": false,
                "relationship": null,
                "strength": null,
                "rationale": "Vocabulary overlap: both use 'octahedral' in different contexts"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert_eq!(results.len(), 1);
        assert!(!results[0].valid);
        assert!(results[0].relationship.is_none());
        assert!(results[0].strength.is_none());
    }

    #[test]
    fn test_parse_response_mixed() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "derives_from",
                "strength": 0.6,
                "rationale": "EUV photon energy relates to photoelectric effect"
            },
            {
                "pair_index": 1,
                "valid": false,
                "relationship": null,
                "strength": null,
                "rationale": "No genuine link between CFT and DNA lattice"
            }
        ]);

        let results = parse_validation_response(&json, 2);
        assert_eq!(results.len(), 2);
        assert!(results[0].valid);
        assert!(!results[1].valid);
    }

    #[test]
    fn test_parse_response_invalid_relationship() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "causes",
                "strength": 0.7,
                "rationale": "some reason"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(
            results.is_empty(),
            "Invalid relationship type should be rejected"
        );
    }

    #[test]
    fn test_parse_response_strength_too_low() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 0.1,
                "rationale": "weak connection"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty(), "Strength < 0.3 should be rejected");
    }

    #[test]
    fn test_parse_response_strength_too_high() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 1.5,
                "rationale": "too strong"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty(), "Strength > 1.0 should be rejected");
    }

    #[test]
    fn test_parse_response_pair_index_out_of_bounds() {
        let json = serde_json::json!([
            {
                "pair_index": 5,
                "valid": true,
                "relationship": "supports",
                "strength": 0.5,
                "rationale": "reason"
            }
        ]);

        let results = parse_validation_response(&json, 3);
        assert!(
            results.is_empty(),
            "pair_index >= batch_size should be rejected"
        );
    }

    #[test]
    fn test_parse_response_not_array() {
        let json = serde_json::json!({"error": "something"});
        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_response_empty_array() {
        let json = serde_json::json!([]);
        let results = parse_validation_response(&json, 5);
        assert!(results.is_empty());
    }

    #[test]
    fn test_valid_relationships_matches_domain_model() {
        // These must match the SemanticLinkType enum in epigraph-core
        assert!(VALID_RELATIONSHIPS.contains(&"supports"));
        assert!(VALID_RELATIONSHIPS.contains(&"contradicts"));
        assert!(VALID_RELATIONSHIPS.contains(&"derives_from"));
        assert!(VALID_RELATIONSHIPS.contains(&"refines"));
        assert!(VALID_RELATIONSHIPS.contains(&"analogous"));
        assert_eq!(VALID_RELATIONSHIPS.len(), 5);
    }

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let long = "A".repeat(500);
        let result = truncate(&long, 300);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 304); // 300 + "..."
    }

    #[test]
    fn test_truncate_exact_length() {
        let exact = "A".repeat(300);
        assert_eq!(truncate(&exact, 300), exact);
    }
}
