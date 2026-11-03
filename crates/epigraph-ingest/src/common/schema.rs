//! Schema types shared across `document::` and `workflow::` artifact kinds.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An author with affiliations and roles. Workflows can be authored by humans,
/// LLMs, or external systems — same shape as document authors.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuthorEntry {
    pub name: String,
    #[serde(default)]
    pub affiliations: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Normalised author names that an extractor emits when it could NOT identify
/// an author ("Authors Not Specified", "Unknown", ...). Each one, taken as a
/// name, derives the same deterministic author agent on every paper, so that
/// one fake agent `authored` and `asserts` everything it touches (backlog
/// a55aac45: arXiv:2606.16707 gained an "Authors Not Specified" agent asserting
/// all 269 of its claims). Matched EXACTLY after [`normalize_author_name`],
/// never as a substring, so real names such as "Noneman" survive.
const PLACEHOLDER_AUTHOR_NAMES: &[&str] = &[
    "authors not specified",
    "author not specified",
    "not specified",
    "unspecified",
    "unknown",
    "unknown author",
    "unknown authors",
    "author unknown",
    "authors unknown",
    "anonymous",
    "anonymous author",
    "anonymous authors",
    "anon",
    "no author",
    "no authors",
    "not available",
    "not provided",
    "not listed",
    "not stated",
    // "na" is deliberately absent: it is a real surname (e.g. Korean "Na"), and
    // the placeholder spellings "N/A" and "N.A." are listed.
    "n/a",
    "n.a",
    "none",
    "null",
    "nil",
    "-",
    "tbd",
    "various",
    "various authors",
    "author",
    "authors",
    "et al",
];

/// ASCII-lowercase, spell a plural marker `(s)` as `s` ("Author(s) Not
/// Specified" -> "authors not specified"), strip surrounding brackets, quotes
/// and dots in any order ("[Authors Not Specified]." included), and collapse
/// internal whitespace.
fn normalize_author_name(name: &str) -> String {
    let lowered = name.to_ascii_lowercase().replace("(s)", "s");
    lowered
        .trim_matches(|c: char| "[]()<>\"'.".contains(c) || c.is_whitespace())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// True when `name` is empty or a known placeholder for "no author identified".
#[must_use]
pub fn is_placeholder_author_name(name: &str) -> bool {
    let normalized = normalize_author_name(name);
    normalized.is_empty() || PLACEHOLDER_AUTHOR_NAMES.contains(&normalized.as_str())
}

impl AuthorEntry {
    /// True when this entry names no real author (empty or a placeholder such
    /// as "Authors Not Specified"). Ingest skips such entries instead of
    /// minting a shared fake author agent.
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        is_placeholder_author_name(&self.name)
    }
}

/// A relationship between two claims identified by path. Workflow steps can
/// support / contradict / refute each other across phases just like document
/// atoms can across paragraphs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClaimRelationship {
    pub source_path: String,
    pub target_path: String,
    pub relationship: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub strength: Option<f64>,
}

/// Refuse an extraction whose `relationships` name the lineage relationship
/// `supersedes`, in any spelling (supersede SPEC K12a, ruling R-132).
///
/// Both plan builders copy a relationship verbatim into the plan the walks
/// insert, so without this an ingest would write a `supersedes` edge that
/// retires nothing: that edge is the supersession act's alone. Every ingest
/// entry point calls this BEFORE any write and refuses the whole ingest (it
/// never drops the edge silently). The error names the offending entry and
/// carries the shared refusal
/// (`epigraph_core::edge::relationships::SUPERSEDES_ACT_ONLY`).
///
/// # Errors
/// The first entry whose relationship is `supersedes` in any ASCII case.
pub fn refuse_lineage_relationships(relationships: &[ClaimRelationship]) -> Result<(), String> {
    use epigraph_core::edge::relationships::{is_lineage_relationship, SUPERSEDES_ACT_ONLY};
    match relationships
        .iter()
        .enumerate()
        .find(|(_, r)| is_lineage_relationship(&r.relationship))
    {
        Some((i, r)) => Err(format!(
            "relationships[{i}].relationship {:?}: {SUPERSEDES_ACT_ONLY}",
            r.relationship
        )),
        None => Ok(()),
    }
}

/// Whether the thesis was derived top-down or bottom-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum ThesisDerivation {
    #[default]
    TopDown,
    BottomUp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(relationship: &str) -> ClaimRelationship {
        ClaimRelationship {
            source_path: "sections/0/paragraphs/1".to_string(),
            target_path: "sections/0/paragraphs/0".to_string(),
            relationship: relationship.to_string(),
            rationale: None,
            strength: None,
        }
    }

    #[test]
    fn a_lineage_relationship_is_refused_in_any_spelling_and_named_by_index() {
        for spelling in ["supersedes", "SUPERSEDES", "Supersedes", "sUpErSeDeS"] {
            let err = refuse_lineage_relationships(&[rel("supports"), rel(spelling)])
                .expect_err(spelling);
            assert!(
                err.starts_with(&format!("relationships[1].relationship {spelling:?}:"))
                    && err.contains("written only by the supersession act"),
                "{spelling}: names the entry and the act: {err}"
            );
        }
        // Not the lineage relationship: a different word, a padded spelling
        // (no reader treats it as lineage), and the ordinary relationships.
        refuse_lineage_relationships(&[
            rel("supports"),
            rel("contradicts"),
            rel("refines"),
            rel("superseded"),
            rel("supersedes_by"),
        ])
        .expect("no lineage relationship");
        refuse_lineage_relationships(&[]).expect("no relationships");
    }

    #[test]
    fn placeholder_author_names_are_rejected_in_any_case_or_padding() {
        // Every PLACEHOLDER_AUTHOR_NAMES entry as a LITERAL (not by iterating the
        // list, which would not notice a deleted entry), each followed by a
        // cased / padded / bracketed variant that must normalise onto it.
        for name in [
            "authors not specified",
            "AUTHORS NOT SPECIFIED",
            "  authors   not\tspecified  ",
            "[Authors Not Specified]",
            "[Authors Not Specified].",
            "Author(s) Not Specified",
            "author not specified",
            "Author Not Specified.",
            "not specified",
            "(Not Specified)",
            "unspecified",
            "UNSPECIFIED",
            "unknown",
            "\"Unknown\"",
            "(unknown)",
            "unknown author",
            "<Unknown Author>",
            "unknown authors",
            "Unknown Author(s)",
            "author unknown",
            "Author Unknown",
            "authors unknown",
            "Author(s) Unknown",
            "anonymous",
            "Anonymous.",
            "anonymous author",
            "'Anonymous Author'",
            "anonymous authors",
            "Anonymous Author(s)",
            "anon",
            " Anon. ",
            "no author",
            "No Author",
            "no authors",
            "No author(s)",
            "not available",
            "Not Available",
            "not provided",
            "Not Provided.",
            "not listed",
            "[Not Listed]",
            "not stated",
            "Not Stated",
            "n/a",
            "N/A",
            "n.a",
            "N.A.",
            " n.a. ",
            "none",
            "None",
            "null",
            "NULL",
            "nil",
            "Nil",
            "-",
            " - ",
            "tbd",
            "TBD",
            "various",
            "Various",
            "various authors",
            "Various Authors",
            "author",
            "Author",
            "authors",
            "Authors",
            "et al",
            "et al.",
            "",
            "   ",
        ] {
            assert!(
                is_placeholder_author_name(name),
                "{name:?} must be treated as a placeholder"
            );
        }
    }

    #[test]
    fn real_author_names_survive_exact_match_only() {
        for name in [
            "Alice Smith",
            "Smith, J.",
            "test",
            "Noneman",
            "Unknownson",
            "Anon Kumar",
            "Nadia Al-Na",
            "Na",
            "NA",
            "Ji-hoon Na",
            "Ann Author",
        ] {
            assert!(
                !is_placeholder_author_name(name),
                "{name:?} is a real name and must not be dropped"
            );
        }
        let entry = AuthorEntry {
            name: "Unknown".to_string(),
            affiliations: vec![],
            roles: vec![],
        };
        assert!(entry.is_placeholder());
        let real = AuthorEntry {
            name: "Alice Smith".to_string(),
            ..entry
        };
        assert!(!real.is_placeholder());
    }
}
