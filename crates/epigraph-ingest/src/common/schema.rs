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
    /// The EXISTING agent this author is, by id (a UUID string, e.g. from
    /// MCP `find_agent`). Optional; document ingest only.
    ///
    /// * Given: the author's `authored` and `asserts` edges attach to exactly
    ///   that agent. It must exist and must not be a registered system
    ///   identity, a role node, or a system agent's legacy key; otherwise the
    ///   whole ingest is refused before any write. `name` is still recorded
    ///   in the report but does not choose the node.
    /// * Absent (the default, unchanged): the author is the node whose key
    ///   `did_key_for_author` derives from `name` (reused when it exists,
    ///   created when not). The ingest NEVER attaches an absent-id author to
    ///   another existing agent that merely shares the name; it reports such
    ///   agents as `candidates` (`status: "ambiguous"`) so the caller can
    ///   re-ingest with an explicit `agent_id`.
    ///
    /// Workflow ingest refuses an `agent_id` (workflow authors are always
    /// name-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
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

/// Parse every `source.authors[].agent_id` of a DOCUMENT, before any write.
///
/// Returns one entry per author, in order: `Some(id)` where the author names
/// an existing agent, `None` where it does not (the name-derived default).
/// Refuses, naming the offending `source.authors[i].agent_id`:
/// * a value that is not a UUID;
/// * an `agent_id` on a placeholder name ("Unknown", ...): the ingest skips
///   placeholder entries, so the id would be dropped without a word;
/// * the same agent on two entries: its edges dedupe on the triple, so one of
///   the two positions would be lost.
///
/// Existence and kind (not a system identity, not a role node) need the
/// database and are checked by the ingest walk.
///
/// # Errors
/// The first offending entry.
pub fn parse_author_agent_ids(authors: &[AuthorEntry]) -> Result<Vec<Option<uuid::Uuid>>, String> {
    let mut out: Vec<Option<uuid::Uuid>> = Vec::with_capacity(authors.len());
    for (i, author) in authors.iter().enumerate() {
        let Some(raw) = author.agent_id.as_deref() else {
            out.push(None);
            continue;
        };
        let id = uuid::Uuid::parse_str(raw.trim()).map_err(|_| {
            format!("source.authors[{i}].agent_id {raw:?}: not a UUID (pass an agent id, e.g. from find_agent)")
        })?;
        if author.is_placeholder() {
            return Err(format!(
                "source.authors[{i}].agent_id {id}: the name {:?} is empty or a placeholder, and \
                 placeholder authors are skipped; give the author's real name with the agent_id",
                author.name
            ));
        }
        if let Some(j) = out.iter().position(|o| *o == Some(id)) {
            return Err(format!(
                "source.authors[{i}].agent_id {id}: the same agent as source.authors[{j}]; \
                 list each author once"
            ));
        }
        out.push(Some(id));
    }
    Ok(out)
}

/// Refuse a WORKFLOW whose authors carry an `agent_id`: workflow ingest
/// resolves its authors by name only, and ignoring the id would attribute the
/// workflow to a node the caller did not choose.
///
/// # Errors
/// The first author with an `agent_id`.
pub fn refuse_author_agent_ids(authors: &[AuthorEntry]) -> Result<(), String> {
    match authors.iter().position(|a| a.agent_id.is_some()) {
        Some(i) => Err(format!(
            "source.authors[{i}].agent_id: workflow ingest resolves authors by name only and \
             does not accept an agent_id; remove it (agent_id is for document ingest)"
        )),
        None => Ok(()),
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
            agent_id: None,
        };
        assert!(entry.is_placeholder());
        let real = AuthorEntry {
            name: "Alice Smith".to_string(),
            ..entry
        };
        assert!(!real.is_placeholder());
    }

    fn author(name: &str, agent_id: Option<&str>) -> AuthorEntry {
        AuthorEntry {
            name: name.to_string(),
            affiliations: vec![],
            roles: vec![],
            agent_id: agent_id.map(str::to_string),
        }
    }

    #[test]
    fn author_agent_ids_parse_or_refuse_naming_the_entry() {
        let a = "6f1c1f9e-3a52-4c1b-9d55-0d4b1f7f2a10";
        let b = "0b7d2c6e-9a41-4f7e-8c3a-5e2d1a9b8c70";
        let ids =
            parse_author_agent_ids(&[author("Ada Q", Some(a)), author("Bo R", None)]).expect("ok");
        assert_eq!(ids, vec![Some(uuid::Uuid::parse_str(a).unwrap()), None]);

        let err = parse_author_agent_ids(&[author("Ada Q", None), author("Bo R", Some("nope"))])
            .unwrap_err();
        assert!(err.starts_with("source.authors[1].agent_id"), "{err}");
        assert!(err.contains("not a UUID"), "{err}");

        let err = parse_author_agent_ids(&[author("Unknown", Some(a))]).unwrap_err();
        assert!(err.starts_with("source.authors[0].agent_id"), "{err}");
        assert!(err.contains("placeholder"), "{err}");

        let err = parse_author_agent_ids(&[
            author("Ada Q", Some(a)),
            author("Bo R", Some(b)),
            author("Ada Quinn", Some(&a.to_uppercase())),
        ])
        .unwrap_err();
        assert!(err.starts_with("source.authors[2].agent_id"), "{err}");
        assert!(err.contains("source.authors[0]"), "{err}");
    }

    #[test]
    fn an_absent_agent_id_is_not_serialised_and_old_json_parses() {
        let parsed: AuthorEntry =
            serde_json::from_str(r#"{"name": "Ada Q", "affiliations": [], "roles": []}"#)
                .expect("pre-agent_id JSON parses");
        assert!(parsed.agent_id.is_none());
        let json = serde_json::to_value(&parsed).expect("serialise");
        assert!(json.get("agent_id").is_none(), "{json}");
    }

    #[test]
    fn workflow_authors_refuse_an_agent_id() {
        refuse_author_agent_ids(&[author("Ada Q", None)]).expect("name only is fine");
        let err = refuse_author_agent_ids(&[
            author("Ada Q", None),
            author("Bo R", Some("6f1c1f9e-3a52-4c1b-9d55-0d4b1f7f2a10")),
        ])
        .unwrap_err();
        assert!(err.starts_with("source.authors[1].agent_id"), "{err}");
    }
}
