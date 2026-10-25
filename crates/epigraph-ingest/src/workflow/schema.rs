//! Schema types for hierarchical workflow extraction. Isomorphic to
//! `document::schema::DocumentExtraction` but with workflow-native field
//! names (phases/steps/operations) and workflow-specific source metadata
//! (canonical_name, generation, parent_canonical_name).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use crate::document::schema::default_confidence;

/// Top-level extraction result from a workflow.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WorkflowExtraction {
    pub source: WorkflowSource,
    #[serde(default)]
    pub thesis: Option<String>,
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub phases: Vec<Phase>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
}

/// Metadata about the workflow.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WorkflowSource {
    /// Required slug; drives the deterministic root ID.
    pub canonical_name: String,
    /// Free-text statement of the workflow's goal.
    pub goal: String,
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub parent_canonical_name: Option<String>,
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    /// Recorded on the workflows row as `metadata.tags` (trimmed, empties
    /// dropped, de-duplicated, appended after any caller `metadata.tags`
    /// array) when the row is first created and `metadata` is absent, null or
    /// an object; re-ingesting an existing `(canonical_name, generation)`
    /// keeps the original tags.
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A phase within a workflow (analog of `document::schema::Section`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Phase {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

/// A step within a phase (analog of `document::schema::Paragraph`).
/// Remaining paper-specific fields (methodology, page, instruments_used,
/// reagents_involved, conditions) are intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Step {
    pub compound: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Evidence type for this step and its operation atoms. The extractor picks
    /// ONE canonical value from [`crate::common::evidence_type::EVIDENCE_TYPES`]
    /// (regulatory, empirical, statistical, logical, testimonial,
    /// circumstantial, conversational). Normalised at plan-build time; any
    /// unrecognised value is dropped to `None`. Mirrors
    /// `document::schema::Paragraph::evidence_type` so workflow-ingested
    /// operation BBAs participate in the evidence-type reliability tier.
    #[serde(default)]
    pub evidence_type: Option<String>,
}

/// The tenancy an ingest DECLARES for the claims it creates, beside the
/// extraction (`ingest_workflow`'s `tenancy` parameter, and the same key in
/// `POST /api/v1/workflows/ingest`'s body).
///
/// Only `visibility: "group"` is a declaration: absent, an ingest keeps its
/// default (public, owned by the ingest system agent's default group), so
/// there is nothing to declare for "public". Any other value is refused at
/// deserialization. `deny_unknown_fields`, so a misspelt key INSIDE the
/// declaration is refused. A misspelt or unsupported `tenancy` key itself is
/// not: the request bodies ignore unknown keys, so it parses as an absent
/// declaration and the plan is published public. A caller must therefore treat
/// a response without `reused_items` (present exactly when a declaration was
/// honoured) as "not declared" and fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct WorkflowTenancy {
    /// Always `"group"`: readable only by live members of `owner_group_id`.
    pub visibility: DeclaredVisibility,
    /// The group that owns every claim the ingest creates. The calling agent
    /// itself, and the ingest system agent, must each hold a live writer or
    /// admin membership of it.
    #[schemars(with = "String")]
    pub owner_group_id: uuid::Uuid,
}

/// The one visibility a [`WorkflowTenancy`] may declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DeclaredVisibility {
    /// `visibility = 'group'`.
    Group,
}

#[cfg(test)]
mod tenancy_tests {
    use super::{DeclaredVisibility, WorkflowTenancy};

    #[test]
    fn only_a_group_declaration_parses() {
        let g = uuid::Uuid::from_u128(7);
        let ok: WorkflowTenancy =
            serde_json::from_value(serde_json::json!({"visibility": "group", "owner_group_id": g}))
                .expect("a group declaration");
        assert_eq!(ok.visibility, DeclaredVisibility::Group);
        assert_eq!(ok.owner_group_id, g);
        for refused in [
            serde_json::json!({"visibility": "public", "owner_group_id": g}),
            serde_json::json!({"visibility": "Group", "owner_group_id": g}),
            serde_json::json!({"owner_group_id": g}),
            serde_json::json!({"visibility": "group"}),
            serde_json::json!({"visibility": "group", "owner_group_id": g, "group": g}),
        ] {
            assert!(
                serde_json::from_value::<WorkflowTenancy>(refused.clone()).is_err(),
                "{refused} must not parse"
            );
        }
    }
}
