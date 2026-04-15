//! Prompt engineering for LLM-based enrichment
//!
//! Structured prompts for relationship extraction, confidence assessment,
//! and implicit claim detection. Follows the harvester pattern:
//! system prompt → few-shot examples → structured output schema.

use serde::{Deserialize, Serialize};

// =============================================================================
// OUTPUT SCHEMA
// =============================================================================

/// A single relationship extracted by the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedRelationship {
    /// Index of the source commit in the input window
    pub source_index: usize,
    /// Index of the target commit in the input window
    pub target_index: usize,
    /// Relationship type
    pub relationship: String,
    /// Strength of the relationship [0.0, 1.0]
    pub strength: f64,
    /// Explanation for why this relationship exists
    pub rationale: String,
}

/// Valid relationship types the LLM should output
pub const RELATIONSHIP_TYPES: &[&str] = &[
    "supports",
    "refutes",
    "elaborates",
    "specializes",
    "generalizes",
    "challenges",
];

// =============================================================================
// PROMPT TEMPLATES
// =============================================================================

/// Format a commit for inclusion in a relationship extraction prompt
pub fn format_commit_for_prompt(
    index: usize,
    commit_type: &str,
    scope: &str,
    claim: &str,
    evidence: &[String],
    reasoning: &[String],
) -> String {
    let mut parts = vec![format!("{index}. [{commit_type}][{scope}] {claim}")];

    if !evidence.is_empty() {
        parts.push(format!("   Evidence: {}", evidence.join("; ")));
    }
    if !reasoning.is_empty() {
        parts.push(format!("   Reasoning: {}", reasoning.join("; ")));
    }

    parts.join("\n")
}

/// Build the relationship extraction prompt for a window of commits
pub fn build_relationship_prompt(commit_descriptions: &[String]) -> String {
    let commits_text = commit_descriptions.join("\n\n");

    format!(
        r#"You are an epistemic graph analyst. Given these commits from a knowledge graph project, identify semantic relationships between them.

## Commits

{commits_text}

## Relationship Types

- **supports**: A provides evidence or foundation for B
- **refutes**: A contradicts or undermines B
- **elaborates**: A adds detail to B
- **specializes**: A is a specific case of B
- **generalizes**: A is a broader version of B
- **challenges**: A raises questions about B's validity

## Rules

1. Only include relationships with strength >= 0.3
2. Strength must be between 0.0 and 1.0
3. A commit cannot relate to itself
4. Prefer fewer, stronger relationships over many weak ones
5. The rationale must explain WHY the relationship exists

## Output

Return a JSON array of objects with these fields:
- source_index: integer (index of source commit, 0-based)
- target_index: integer (index of target commit, 0-based)
- relationship: string (one of: supports, refutes, elaborates, specializes, generalizes, challenges)
- strength: number (0.0 to 1.0)
- rationale: string (brief explanation)

Return ONLY the JSON array, no other text. If no relationships exist, return an empty array [].

## Examples

Example input commits:
0. [feat][core] define Claim model with bounded truth values
   Evidence: IMPLEMENTATION_PLAN.md specifies truth in [0.0, 1.0]
1. [fix][core] prevent NaN truth values from bypassing validation
   Evidence: Fuzzing found f64::NAN passes bounds check
2. [security][crypto] prevent timing attacks in signature verification
   Evidence: Audit flagged constant-time comparison missing

Example output:
[
  {{
    "source_index": 1,
    "target_index": 0,
    "relationship": "elaborates",
    "strength": 0.9,
    "rationale": "The NaN fix addresses an edge case in the Claim model's truth validation that commit 0 established"
  }},
  {{
    "source_index": 1,
    "target_index": 0,
    "relationship": "challenges",
    "strength": 0.7,
    "rationale": "The NaN bug reveals that commit 0's bounds check was incomplete"
  }}
]
"#
    )
}

// =============================================================================
// VALIDATION
// =============================================================================

/// Validate and filter extracted relationships
pub fn validate_relationships(
    relationships: Vec<ExtractedRelationship>,
    num_commits: usize,
) -> Vec<ExtractedRelationship> {
    relationships
        .into_iter()
        .filter(|r| {
            // Valid indices
            r.source_index < num_commits
                && r.target_index < num_commits
                // No self-references
                && r.source_index != r.target_index
                // Valid strength
                && (0.0..=1.0).contains(&r.strength)
                // Valid relationship type
                && RELATIONSHIP_TYPES.contains(&r.relationship.as_str())
        })
        .collect()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_commit_for_prompt() {
        let result = format_commit_for_prompt(
            0,
            "feat",
            "core",
            "define Claim model",
            &["Plan requires it".to_string()],
            &["Chose f64 for precision".to_string()],
        );

        assert!(result.contains("0. [feat][core] define Claim model"));
        assert!(result.contains("Evidence: Plan requires it"));
        assert!(result.contains("Reasoning: Chose f64 for precision"));
    }

    #[test]
    fn test_format_commit_no_evidence() {
        let result = format_commit_for_prompt(1, "chore", "build", "update deps", &[], &[]);

        assert!(result.contains("1. [chore][build] update deps"));
        assert!(!result.contains("Evidence:"));
        assert!(!result.contains("Reasoning:"));
    }

    #[test]
    fn test_relationship_prompt_includes_all_commits() {
        let commits = vec![
            "0. [feat][core] first".to_string(),
            "1. [fix][core] second".to_string(),
            "2. [docs][api] third".to_string(),
        ];

        let prompt = build_relationship_prompt(&commits);
        assert!(prompt.contains("0. [feat][core] first"));
        assert!(prompt.contains("1. [fix][core] second"));
        assert!(prompt.contains("2. [docs][api] third"));
    }

    #[test]
    fn test_relationship_prompt_enforces_json_schema() {
        let prompt = build_relationship_prompt(&["0. test".to_string()]);

        // Must mention all required fields
        assert!(prompt.contains("source_index"));
        assert!(prompt.contains("target_index"));
        assert!(prompt.contains("relationship"));
        assert!(prompt.contains("strength"));
        assert!(prompt.contains("rationale"));
        // Must mention JSON output
        assert!(prompt.contains("JSON array"));
    }

    #[test]
    fn test_few_shot_examples_cover_all_relationship_types() {
        let prompt = build_relationship_prompt(&["0. test".to_string()]);

        // The prompt must define all relationship types
        for rtype in RELATIONSHIP_TYPES {
            assert!(
                prompt.contains(rtype),
                "Prompt must mention relationship type: {rtype}"
            );
        }
    }

    #[test]
    fn test_validate_relationships_filters_invalid() {
        let relationships = vec![
            ExtractedRelationship {
                source_index: 0,
                target_index: 1,
                relationship: "supports".to_string(),
                strength: 0.8,
                rationale: "valid".to_string(),
            },
            // Self-reference: should be filtered
            ExtractedRelationship {
                source_index: 0,
                target_index: 0,
                relationship: "supports".to_string(),
                strength: 0.5,
                rationale: "self-ref".to_string(),
            },
            // Out-of-bounds index: should be filtered
            ExtractedRelationship {
                source_index: 0,
                target_index: 99,
                relationship: "supports".to_string(),
                strength: 0.5,
                rationale: "out of bounds".to_string(),
            },
            // Invalid strength: should be filtered
            ExtractedRelationship {
                source_index: 0,
                target_index: 1,
                relationship: "supports".to_string(),
                strength: 1.5,
                rationale: "too strong".to_string(),
            },
            // Invalid relationship type: should be filtered
            ExtractedRelationship {
                source_index: 0,
                target_index: 1,
                relationship: "unknown_type".to_string(),
                strength: 0.5,
                rationale: "bad type".to_string(),
            },
        ];

        let valid = validate_relationships(relationships, 3);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].rationale, "valid");
    }

    #[test]
    fn test_validate_relationships_empty_input() {
        let valid = validate_relationships(vec![], 5);
        assert!(valid.is_empty());
    }

    #[test]
    fn test_validate_relationships_boundary_strength() {
        let relationships = vec![
            ExtractedRelationship {
                source_index: 0,
                target_index: 1,
                relationship: "supports".to_string(),
                strength: 0.0,
                rationale: "min".to_string(),
            },
            ExtractedRelationship {
                source_index: 0,
                target_index: 1,
                relationship: "supports".to_string(),
                strength: 1.0,
                rationale: "max".to_string(),
            },
        ];

        let valid = validate_relationships(relationships, 2);
        assert_eq!(valid.len(), 2);
    }

    #[test]
    fn test_extracted_relationship_deserializes() {
        let json = serde_json::json!({
            "source_index": 0,
            "target_index": 2,
            "relationship": "elaborates",
            "strength": 0.75,
            "rationale": "Commit 0 provides detail for commit 2"
        });

        let rel: ExtractedRelationship = serde_json::from_value(json).unwrap();
        assert_eq!(rel.source_index, 0);
        assert_eq!(rel.target_index, 2);
        assert_eq!(rel.relationship, "elaborates");
        assert!((rel.strength - 0.75).abs() < f64::EPSILON);
    }
}
