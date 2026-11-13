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

/// The tenancy a workflow write DECLARES for the rows it creates, beside the
/// extraction (`ingest_workflow`'s and `store_workflow`'s `tenancy` parameter,
/// and the same key in the bodies of `POST /api/v1/workflows/ingest` and
/// `POST /api/v1/workflows`).
///
/// Two forms, both naming the owner group, which the calling agent itself must
/// write (a live writer or admin membership; its operator's does not count):
///
/// * `{"visibility": "group", "owner_group_id": G}`: readable only by live
///   members of G.
/// * `{"visibility": "public", "owner_group_id": G}`: readable by every
///   principal, owned by G. The ONLY way to publish a new workflow: an
///   undeclared write is private to its owner group (the caller's one team
///   group, else its own default group), and a new generation keeps its
///   lineage's visibility. Declaring public on a new generation of a
///   group-private lineage is refused (it would publish the lineage).
///
/// Any other visibility is refused at deserialization. `deny_unknown_fields`,
/// so a misspelt key INSIDE the declaration is refused. A misspelt `tenancy`
/// key itself is not (the request bodies ignore unknown keys): it parses as an
/// absent declaration, whose default is the private one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct WorkflowTenancy {
    /// `"group"` (readable only by live members of `owner_group_id`) or
    /// `"public"` (readable by every principal, owned by `owner_group_id`).
    pub visibility: DeclaredVisibility,
    /// The group that owns every row the write creates. The calling agent
    /// itself must hold a live writer or admin membership of it.
    #[schemars(with = "String")]
    pub owner_group_id: uuid::Uuid,
}

impl WorkflowTenancy {
    /// The declaration as the row tenancy it binds.
    #[must_use]
    pub const fn decl(&self) -> epigraph_core::TenancyDecl {
        match self.visibility {
            DeclaredVisibility::Group => epigraph_core::TenancyDecl::group(self.owner_group_id),
            DeclaredVisibility::Public => epigraph_core::TenancyDecl::public(self.owner_group_id),
        }
    }
}

/// The visibilities a [`WorkflowTenancy`] may declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DeclaredVisibility {
    /// `visibility = 'group'`.
    Group,
    /// `visibility = 'public'`: the explicit request to publish.
    Public,
}

#[cfg(test)]
mod tenancy_tests {
    use super::{DeclaredVisibility, WorkflowTenancy};

    #[test]
    fn a_group_or_an_explicit_public_declaration_parses_and_nothing_else() {
        let g = uuid::Uuid::from_u128(7);
        let ok: WorkflowTenancy =
            serde_json::from_value(serde_json::json!({"visibility": "group", "owner_group_id": g}))
                .expect("a group declaration");
        assert_eq!(ok.visibility, DeclaredVisibility::Group);
        assert_eq!(ok.owner_group_id, g);
        assert_eq!(ok.decl(), epigraph_core::TenancyDecl::group(g));
        let public: WorkflowTenancy = serde_json::from_value(
            serde_json::json!({"visibility": "public", "owner_group_id": g}),
        )
        .expect("an explicit public declaration");
        assert_eq!(public.visibility, DeclaredVisibility::Public);
        assert_eq!(public.decl(), epigraph_core::TenancyDecl::public(g));
        for refused in [
            serde_json::json!({"visibility": "Group", "owner_group_id": g}),
            serde_json::json!({"visibility": "Public", "owner_group_id": g}),
            serde_json::json!({"visibility": "world", "owner_group_id": g}),
            serde_json::json!({"owner_group_id": g}),
            serde_json::json!({"visibility": "group"}),
            serde_json::json!({"visibility": "public"}),
            serde_json::json!({"visibility": "group", "owner_group_id": g, "group": g}),
        ] {
            assert!(
                serde_json::from_value::<WorkflowTenancy>(refused.clone()).is_err(),
                "{refused} must not parse"
            );
        }
    }
}
