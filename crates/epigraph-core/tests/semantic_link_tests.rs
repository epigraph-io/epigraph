//! Integration tests for `SemanticLink` domain model

use epigraph_core::{
    AgentId, ClaimId, CoreError, LinkStrength, SemanticLink, SemanticLinkId, SemanticLinkType,
};
use uuid::Uuid;

// =============================================================================
// SemanticLinkId Tests
// =============================================================================

#[test]
fn semantic_link_id_is_distinct_from_other_ids() {
    let link_id = SemanticLinkId::new();
    let claim_id = ClaimId::new();

    // They use the same underlying UUID type but are distinct types
    assert_ne!(link_id.as_uuid(), claim_id.as_uuid());
}

#[test]
fn semantic_link_id_display_has_prefix() {
    let id = SemanticLinkId::from_uuid(Uuid::nil());
    assert!(id.to_string().starts_with("semantic_link:"));
}

#[test]
fn semantic_link_id_serializes_as_uuid() {
    let id = SemanticLinkId::from_uuid(Uuid::nil());
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
}

// =============================================================================
// SemanticLinkType Tests
// =============================================================================

#[test]
fn semantic_link_type_display() {
    assert_eq!(SemanticLinkType::Supports.to_string(), "supports");
    assert_eq!(SemanticLinkType::Contradicts.to_string(), "contradicts");
    assert_eq!(SemanticLinkType::DerivesFrom.to_string(), "derives_from");
    assert_eq!(SemanticLinkType::Refines.to_string(), "refines");
    assert_eq!(SemanticLinkType::Analogous.to_string(), "analogous");
}

#[test]
fn semantic_link_type_serialization() {
    let link_type = SemanticLinkType::DerivesFrom;
    let json = serde_json::to_string(&link_type).unwrap();
    assert_eq!(json, "\"derives_from\"");

    let parsed: SemanticLinkType = serde_json::from_str("\"supports\"").unwrap();
    assert_eq!(parsed, SemanticLinkType::Supports);
}

// =============================================================================
// LinkStrength Tests
// =============================================================================

#[test]
fn valid_link_strength_values() {
    assert!(LinkStrength::new(0.0).is_ok());
    assert!(LinkStrength::new(0.5).is_ok());
    assert!(LinkStrength::new(1.0).is_ok());
    assert!(LinkStrength::new(0.73).is_ok());
}

#[test]
fn invalid_link_strength_values() {
    assert!(LinkStrength::new(-0.1).is_err());
    assert!(LinkStrength::new(1.1).is_err());
    assert!(LinkStrength::new(f64::NAN).is_err());
    assert!(LinkStrength::new(f64::INFINITY).is_err());
    assert!(LinkStrength::new(f64::NEG_INFINITY).is_err());
}

#[test]
fn link_strength_error_message() {
    let err = LinkStrength::new(-0.5).unwrap_err();
    assert!(err.to_string().contains("-0.5"));
    assert!(err.to_string().contains("[0.0, 1.0]"));
}

#[test]
fn link_strength_clamped_handles_out_of_bounds() {
    assert_eq!(LinkStrength::clamped(-5.0).value(), 0.0);
    assert_eq!(LinkStrength::clamped(10.0).value(), 1.0);
    assert_eq!(LinkStrength::clamped(f64::NAN).value(), 0.5);
}

#[test]
fn link_strength_default() {
    let strength = LinkStrength::default();
    assert_eq!(strength.value(), 0.5);
}

#[test]
fn link_strength_serialization() {
    let strength = LinkStrength::new(0.75).unwrap();
    let json = serde_json::to_string(&strength).unwrap();
    assert_eq!(json, "0.75");

    let parsed: LinkStrength = serde_json::from_str("0.75").unwrap();
    assert_eq!(parsed, strength);
}

#[test]
fn link_strength_deserialization_rejects_invalid() {
    let result: Result<LinkStrength, _> = serde_json::from_str("1.5");
    assert!(result.is_err());
}

// =============================================================================
// SemanticLink Tests
// =============================================================================

#[test]
fn create_semantic_link_success() {
    let source = ClaimId::new();
    let target = ClaimId::new();
    let agent = AgentId::new();
    let strength = LinkStrength::new(0.8).unwrap();

    let link =
        SemanticLink::new(source, target, SemanticLinkType::Supports, strength, agent).unwrap();

    assert_eq!(link.source_claim_id, source);
    assert_eq!(link.target_claim_id, target);
    assert_eq!(link.link_type, SemanticLinkType::Supports);
    assert_eq!(link.strength, strength);
    assert_eq!(link.created_by, agent);
    assert!(link.is_supporting());
    assert!(!link.is_contradicting());
}

#[test]
fn semantic_link_rejects_self_reference() {
    let claim = ClaimId::new();
    let agent = AgentId::new();
    let strength = LinkStrength::new(0.5).unwrap();

    let result = SemanticLink::new(
        claim,
        claim, // Same as source - should fail
        SemanticLinkType::Supports,
        strength,
        agent,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::SelfReferentialEdge(uuid) => {
            assert_eq!(uuid, claim.as_uuid());
        }
        _ => panic!("Expected SelfReferentialEdge error"),
    }
}

#[test]
fn semantic_link_type_predicates() {
    let source = ClaimId::new();
    let target = ClaimId::new();
    let agent = AgentId::new();
    let strength = LinkStrength::default();

    let supports =
        SemanticLink::new(source, target, SemanticLinkType::Supports, strength, agent).unwrap();
    assert!(supports.is_supporting());
    assert!(!supports.is_contradicting());
    assert!(!supports.is_derivation());

    let contradicts = SemanticLink::new(
        source,
        target,
        SemanticLinkType::Contradicts,
        strength,
        agent,
    )
    .unwrap();
    assert!(contradicts.is_contradicting());
    assert!(!contradicts.is_supporting());

    let derives = SemanticLink::new(
        source,
        target,
        SemanticLinkType::DerivesFrom,
        strength,
        agent,
    )
    .unwrap();
    assert!(derives.is_derivation());
}

#[test]
fn semantic_link_serialization() {
    let source = ClaimId::new();
    let target = ClaimId::new();
    let agent = AgentId::new();

    let link = SemanticLink::new(
        source,
        target,
        SemanticLinkType::DerivesFrom,
        LinkStrength::new(0.85).unwrap(),
        agent,
    )
    .unwrap();

    let json = serde_json::to_string(&link).unwrap();
    let deserialized: SemanticLink = serde_json::from_str(&json).unwrap();

    assert_eq!(link.id, deserialized.id);
    assert_eq!(link.source_claim_id, deserialized.source_claim_id);
    assert_eq!(link.target_claim_id, deserialized.target_claim_id);
    assert_eq!(link.link_type, deserialized.link_type);
    assert_eq!(link.strength, deserialized.strength);
    assert_eq!(link.created_by, deserialized.created_by);
}

#[test]
fn all_link_types_can_be_created() {
    let source = ClaimId::new();
    let target = ClaimId::new();
    let agent = AgentId::new();
    let strength = LinkStrength::default();

    for link_type in [
        SemanticLinkType::Supports,
        SemanticLinkType::Contradicts,
        SemanticLinkType::DerivesFrom,
        SemanticLinkType::Refines,
        SemanticLinkType::Analogous,
    ] {
        let link = SemanticLink::new(source, target, link_type, strength, agent);
        assert!(link.is_ok(), "Failed to create link of type {link_type:?}");
    }
}
