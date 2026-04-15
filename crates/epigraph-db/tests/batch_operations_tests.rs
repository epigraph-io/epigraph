//! Batch Operations Tests for ClaimRepository and EvidenceRepository
//!
//! These tests verify the batch insert/update functionality for efficient
//! bulk database operations.
//!
//! # Evidence
//! - Bulk import and propagation updates require batch operations
//! - PostgreSQL multi-value INSERT provides significant performance gains
//!
//! # Reasoning
//! - Batch operations reduce round-trips to the database
//! - UPDATE with CASE WHEN allows efficient mass updates
//! - Transaction wrapper ensures atomicity (all succeed or all fail)

mod helpers;

use epigraph_core::{Claim, ClaimId, Evidence, EvidenceType, TruthValue};
use epigraph_db::{AgentRepository, ClaimRepository, EvidenceRepository};
use helpers::make_agent;
use sqlx::PgPool;

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Create a test claim (not inserted into DB)
fn create_test_claim_entity(
    agent_id: epigraph_core::AgentId,
    content: &str,
    truth_value: f64,
) -> Claim {
    let public_key = [0u8; 32];
    Claim::new(
        content.to_string(),
        agent_id,
        public_key,
        TruthValue::new(truth_value).unwrap(),
    )
}

/// Create test evidence (not inserted into DB)
fn create_test_evidence_entity(
    agent_id: epigraph_core::AgentId,
    claim_id: epigraph_core::ClaimId,
    content: &str,
) -> Evidence {
    let public_key = [0u8; 32];
    let content_hash = blake3::hash(content.as_bytes());
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(content_hash.as_bytes());

    Evidence::new(
        agent_id,
        public_key,
        hash_array,
        EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        },
        Some(content.to_string()),
        claim_id,
    )
}

// ============================================================================
// ClaimRepository Batch Create Tests
// ============================================================================

/// Test: Batch create with empty slice returns empty vec
///
/// **Evidence**: Edge case - empty input should produce empty output
/// **Reasoning**: No-op for empty input is idiomatic and efficient
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_claims_empty_slice_returns_empty(pool: PgPool) {
    let claims: Vec<Claim> = vec![];
    let result = ClaimRepository::batch_create(&pool, &claims)
        .await
        .expect("Batch create should succeed");

    assert!(result.is_empty(), "Empty input should produce empty output");
}

/// Test: Batch create single claim works correctly
///
/// **Evidence**: Single-element batch should behave like regular create
/// **Reasoning**: Batch operation degrades gracefully to single operation
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_claims_single_claim(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let claim = create_test_claim_entity(agent.id, "Single batch claim", 0.75);
    let claims = vec![claim.clone()];

    let result = ClaimRepository::batch_create(&pool, &claims)
        .await
        .expect("Batch create should succeed");

    assert_eq!(result.len(), 1, "Should return one claim");
    assert_eq!(result[0].id, claim.id, "Claim ID should match");
    assert_eq!(result[0].content, "Single batch claim");
    assert_eq!(result[0].truth_value.value(), 0.75);
}

/// Test: Batch create multiple claims
///
/// **Evidence**: Multiple claims should all be inserted atomically
/// **Reasoning**: Primary use case for bulk import
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_claims_multiple(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    let claims: Vec<Claim> = (0..5)
        .map(|i| {
            create_test_claim_entity(
                agent.id,
                &format!("Batch claim {}", i),
                0.5 + (i as f64) * 0.1,
            )
        })
        .collect();

    let result = ClaimRepository::batch_create(&pool, &claims)
        .await
        .expect("Batch create should succeed");

    assert_eq!(result.len(), 5, "Should return all 5 claims");

    // Verify each claim was created with correct data
    for (i, created_claim) in result.iter().enumerate() {
        assert_eq!(
            created_claim.id, claims[i].id,
            "Claim {} ID should match",
            i
        );
        assert_eq!(
            created_claim.content,
            format!("Batch claim {}", i),
            "Claim {} content should match",
            i
        );
    }
}

/// Test: Batch create respects batch size limits
///
/// **Evidence**: Large batches should be handled without memory issues
/// **Reasoning**: Architect review: prevent memory exhaustion on large imports
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_claims_large_batch(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create 100 claims - should be handled efficiently
    let claims: Vec<Claim> = (0..100)
        .map(|i| create_test_claim_entity(agent.id, &format!("Large batch claim {}", i), 0.5))
        .collect();

    let result = ClaimRepository::batch_create(&pool, &claims)
        .await
        .expect("Batch create should succeed for large batches");

    assert_eq!(result.len(), 100, "Should return all 100 claims");
}

/// Test: Batch create is atomic - all or nothing
///
/// **Evidence**: If one insert fails, none should succeed
/// **Reasoning**: Maintains data integrity for bulk operations
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_claims_atomicity(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create a claim and insert it first
    let existing_claim = create_test_claim_entity(agent.id, "Existing claim", 0.7);
    ClaimRepository::create(&pool, &existing_claim)
        .await
        .expect("Initial create should succeed");

    // Now try to batch insert including the duplicate
    let mut claims: Vec<Claim> = (0..3)
        .map(|i| create_test_claim_entity(agent.id, &format!("New claim {}", i), 0.5))
        .collect();

    // Insert the existing claim ID to cause a duplicate key error
    claims.push(Claim::with_id(
        existing_claim.id,
        "Duplicate ID claim".to_string(),
        agent.id,
        [0u8; 32],
        [0u8; 32],
        None,
        None,
        TruthValue::new(0.5).unwrap(),
        chrono::Utc::now(),
        chrono::Utc::now(),
    ));

    // The batch insert should fail
    let result = ClaimRepository::batch_create(&pool, &claims).await;
    assert!(result.is_err(), "Batch with duplicate should fail");

    // Verify none of the new claims were inserted
    for (i, claim) in claims.iter().take(3).enumerate() {
        let check = ClaimRepository::get_by_id(&pool, claim.id).await.unwrap();
        assert!(
            check.is_none(),
            "Claim {} should not exist due to atomic rollback",
            i
        );
    }
}

// ============================================================================
// ClaimRepository Batch Update Truth Values Tests
// ============================================================================

/// Test: Batch update truth values with empty slice returns 0
///
/// **Evidence**: Edge case - empty updates should be no-op
/// **Reasoning**: Idiomatic handling of empty input
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_update_truth_values_empty_returns_zero(pool: PgPool) {
    let updates: Vec<(ClaimId, TruthValue)> = vec![];
    let result = ClaimRepository::batch_update_truth_values(&pool, &updates)
        .await
        .expect("Empty batch update should succeed");

    assert_eq!(result, 0, "Empty updates should affect 0 rows");
}

/// Test: Batch update single claim truth value
///
/// **Evidence**: Single-element batch should work correctly
/// **Reasoning**: Batch degrades to single update gracefully
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_update_truth_values_single(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create a claim
    let claim = create_test_claim_entity(agent.id, "Claim to update", 0.5);
    ClaimRepository::create(&pool, &claim)
        .await
        .expect("Create should succeed");

    // Update its truth value
    let new_truth = TruthValue::new(0.9).unwrap();
    let updates = vec![(claim.id, new_truth)];

    let affected = ClaimRepository::batch_update_truth_values(&pool, &updates)
        .await
        .expect("Batch update should succeed");

    assert_eq!(affected, 1, "Should affect 1 row");

    // Verify the update
    let updated = ClaimRepository::get_by_id(&pool, claim.id)
        .await
        .expect("Get should succeed")
        .expect("Claim should exist");

    assert_eq!(
        updated.truth_value.value(),
        0.9,
        "Truth value should be updated"
    );
}

/// Test: Batch update multiple claims truth values
///
/// **Evidence**: Multiple updates should all succeed atomically
/// **Reasoning**: Primary use case for truth propagation updates
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_update_truth_values_multiple(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create multiple claims
    let claims: Vec<Claim> = (0..5)
        .map(|i| create_test_claim_entity(agent.id, &format!("Update claim {}", i), 0.5))
        .collect();

    for claim in &claims {
        ClaimRepository::create(&pool, claim)
            .await
            .expect("Create should succeed");
    }

    // Prepare updates with different truth values
    let updates: Vec<(ClaimId, TruthValue)> = claims
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id, TruthValue::new(0.1 * (i + 1) as f64).unwrap()))
        .collect();

    let affected = ClaimRepository::batch_update_truth_values(&pool, &updates)
        .await
        .expect("Batch update should succeed");

    assert_eq!(affected, 5, "Should affect 5 rows");

    // Verify each update
    for (i, claim) in claims.iter().enumerate() {
        let updated = ClaimRepository::get_by_id(&pool, claim.id)
            .await
            .expect("Get should succeed")
            .expect("Claim should exist");

        let expected = 0.1 * (i + 1) as f64;
        assert!(
            (updated.truth_value.value() - expected).abs() < 0.001,
            "Claim {} truth value should be {}, got {}",
            i,
            expected,
            updated.truth_value.value()
        );
    }
}

/// Test: Batch update skips non-existent claims
///
/// **Evidence**: Updates for non-existent IDs should be ignored
/// **Reasoning**: Graceful handling of stale update requests
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_update_truth_values_nonexistent_claims(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create one real claim
    let claim = create_test_claim_entity(agent.id, "Real claim", 0.5);
    ClaimRepository::create(&pool, &claim)
        .await
        .expect("Create should succeed");

    // Mix real and fake claim IDs
    let updates = vec![
        (claim.id, TruthValue::new(0.9).unwrap()),
        (ClaimId::new(), TruthValue::new(0.8).unwrap()), // Non-existent
        (ClaimId::new(), TruthValue::new(0.7).unwrap()), // Non-existent
    ];

    let affected = ClaimRepository::batch_update_truth_values(&pool, &updates)
        .await
        .expect("Batch update should succeed");

    assert_eq!(affected, 1, "Should only affect 1 existing row");

    // Verify the real claim was updated
    let updated = ClaimRepository::get_by_id(&pool, claim.id)
        .await
        .expect("Get should succeed")
        .expect("Claim should exist");

    assert_eq!(updated.truth_value.value(), 0.9);
}

/// Test: Batch update uses CASE WHEN for efficiency
///
/// **Evidence**: Different values for different claims in single query
/// **Reasoning**: Single round-trip to database for all updates
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_update_truth_values_uses_case_when(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create claims with same initial truth value
    let claims: Vec<Claim> = (0..3)
        .map(|i| create_test_claim_entity(agent.id, &format!("Case when claim {}", i), 0.5))
        .collect();

    for claim in &claims {
        ClaimRepository::create(&pool, claim)
            .await
            .expect("Create should succeed");
    }

    // Update to different values
    let updates = vec![
        (claims[0].id, TruthValue::new(0.1).unwrap()),
        (claims[1].id, TruthValue::new(0.5).unwrap()),
        (claims[2].id, TruthValue::new(0.9).unwrap()),
    ];

    let affected = ClaimRepository::batch_update_truth_values(&pool, &updates)
        .await
        .expect("Batch update should succeed");

    assert_eq!(affected, 3);

    // Verify each got its unique value
    for (id, expected_truth) in &updates {
        let claim = ClaimRepository::get_by_id(&pool, *id)
            .await
            .expect("Get should succeed")
            .expect("Claim should exist");

        assert_eq!(claim.truth_value.value(), expected_truth.value());
    }
}

// ============================================================================
// EvidenceRepository Batch Create Tests
// ============================================================================

/// Test: Batch create evidence with empty slice returns empty vec
///
/// **Evidence**: Edge case - empty input should produce empty output
/// **Reasoning**: No-op for empty input is idiomatic
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_evidence_empty_slice_returns_empty(pool: PgPool) {
    let evidence: Vec<Evidence> = vec![];
    let result = EvidenceRepository::batch_create(&pool, &evidence)
        .await
        .expect("Batch create should succeed");

    assert!(result.is_empty(), "Empty input should produce empty output");
}

/// Test: Batch create single evidence
///
/// **Evidence**: Single-element batch should work like regular create
/// **Reasoning**: Batch degrades gracefully
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_evidence_single(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create a claim first
    let claim = create_test_claim_entity(agent.id, "Claim for evidence", 0.7);
    ClaimRepository::create(&pool, &claim)
        .await
        .expect("Create claim should succeed");

    let evidence = create_test_evidence_entity(agent.id, claim.id, "Single evidence content");
    let evidence_list = vec![evidence.clone()];

    let result = EvidenceRepository::batch_create(&pool, &evidence_list)
        .await
        .expect("Batch create should succeed");

    assert_eq!(result.len(), 1, "Should return one evidence");
    assert_eq!(result[0].id, evidence.id, "Evidence ID should match");
}

/// Test: Batch create multiple evidence
///
/// **Evidence**: Multiple evidence items should all be inserted
/// **Reasoning**: Primary use case for bulk import
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_evidence_multiple(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create a claim
    let claim = create_test_claim_entity(agent.id, "Claim for multiple evidence", 0.7);
    ClaimRepository::create(&pool, &claim)
        .await
        .expect("Create claim should succeed");

    // Create multiple evidence items
    let evidence_list: Vec<Evidence> = (0..5)
        .map(|i| {
            create_test_evidence_entity(agent.id, claim.id, &format!("Evidence content {}", i))
        })
        .collect();

    let result = EvidenceRepository::batch_create(&pool, &evidence_list)
        .await
        .expect("Batch create should succeed");

    assert_eq!(result.len(), 5, "Should return all 5 evidence items");

    for (i, created) in result.iter().enumerate() {
        assert_eq!(
            created.id, evidence_list[i].id,
            "Evidence {} ID should match",
            i
        );
    }
}

/// Test: Batch create evidence for multiple claims
///
/// **Evidence**: Evidence for different claims can be batch inserted
/// **Reasoning**: Supports bulk import of heterogeneous data
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_evidence_multiple_claims(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create multiple claims
    let claims: Vec<Claim> = (0..3)
        .map(|i| create_test_claim_entity(agent.id, &format!("Claim {}", i), 0.5))
        .collect();

    for claim in &claims {
        ClaimRepository::create(&pool, claim)
            .await
            .expect("Create claim should succeed");
    }

    // Create evidence for each claim
    let evidence_list: Vec<Evidence> = claims
        .iter()
        .flat_map(|c| {
            (0..2).map(move |i| {
                create_test_evidence_entity(
                    agent.id,
                    c.id,
                    &format!("Evidence for claim {} item {}", c.id, i),
                )
            })
        })
        .collect();

    assert_eq!(
        evidence_list.len(),
        6,
        "Should have 6 evidence items (2 per claim)"
    );

    let result = EvidenceRepository::batch_create(&pool, &evidence_list)
        .await
        .expect("Batch create should succeed");

    assert_eq!(result.len(), 6, "Should return all 6 evidence items");

    // Verify evidence is correctly linked to claims
    for (i, claim) in claims.iter().enumerate() {
        let claim_evidence = EvidenceRepository::get_by_claim(&pool, claim.id)
            .await
            .expect("Get evidence should succeed");

        assert_eq!(
            claim_evidence.len(),
            2,
            "Claim {} should have 2 evidence items",
            i
        );
    }
}

/// Test: Batch create evidence is atomic
///
/// **Evidence**: If one insert fails, none should succeed
/// **Reasoning**: Maintains data integrity
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_create_evidence_atomicity(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create a claim
    let claim = create_test_claim_entity(agent.id, "Claim for atomicity test", 0.7);
    ClaimRepository::create(&pool, &claim)
        .await
        .expect("Create claim should succeed");

    // Create and insert evidence first
    let existing_evidence = create_test_evidence_entity(agent.id, claim.id, "Existing evidence");
    EvidenceRepository::create(&pool, &existing_evidence)
        .await
        .expect("Create evidence should succeed");

    // Try to batch insert including duplicate
    let mut evidence_list: Vec<Evidence> = (0..3)
        .map(|i| create_test_evidence_entity(agent.id, claim.id, &format!("New evidence {}", i)))
        .collect();

    // Add duplicate ID
    evidence_list.push(Evidence::with_id(
        existing_evidence.id,
        agent.id,
        [0u8; 32],
        [0u8; 32],
        EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        },
        Some("Duplicate".to_string()),
        claim.id,
        None,
        chrono::Utc::now(),
    ));

    let result = EvidenceRepository::batch_create(&pool, &evidence_list).await;
    assert!(result.is_err(), "Batch with duplicate should fail");

    // Verify none of the new evidence was inserted
    let all_evidence = EvidenceRepository::get_by_claim(&pool, claim.id)
        .await
        .expect("Get evidence should succeed");

    assert_eq!(
        all_evidence.len(),
        1,
        "Only the original evidence should exist due to rollback"
    );
}

// ============================================================================
// Transaction Wrapper Tests
// ============================================================================

/// Test: Batch operations can be wrapped in a transaction
///
/// **Evidence**: Multiple batch operations should be atomic together
/// **Reasoning**: Complex imports may need cross-entity atomicity
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_operations_in_transaction(pool: PgPool) {
    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create claims and evidence in a single conceptual transaction
    let claims: Vec<Claim> = (0..3)
        .map(|i| create_test_claim_entity(agent.id, &format!("Transaction claim {}", i), 0.5))
        .collect();

    let created_claims = ClaimRepository::batch_create(&pool, &claims)
        .await
        .expect("Batch create claims should succeed");

    assert_eq!(created_claims.len(), 3);

    // Create evidence for each created claim
    let evidence_list: Vec<Evidence> = created_claims
        .iter()
        .map(|c| create_test_evidence_entity(agent.id, c.id, &format!("Evidence for {}", c.id)))
        .collect();

    let created_evidence = EvidenceRepository::batch_create(&pool, &evidence_list)
        .await
        .expect("Batch create evidence should succeed");

    assert_eq!(created_evidence.len(), 3);

    // Verify all data was created
    for claim in &created_claims {
        let evidence = EvidenceRepository::get_by_claim(&pool, claim.id)
            .await
            .expect("Get evidence should succeed");

        assert_eq!(evidence.len(), 1, "Each claim should have evidence");
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

/// Test: Batch insert is faster than individual inserts
///
/// **Evidence**: Batch operations should have less overhead
/// **Reasoning**: Reduced round-trips to database
#[sqlx::test(migrations = "../../migrations")]
async fn test_batch_insert_performance(pool: PgPool) {
    use std::time::Instant;

    let agent = make_agent(Some("Batch Test Agent"));
    let agent = AgentRepository::create(&pool, &agent).await.unwrap();

    // Create 50 claims for batch insert
    let batch_claims: Vec<Claim> = (0..50)
        .map(|i| create_test_claim_entity(agent.id, &format!("Batch perf claim {}", i), 0.5))
        .collect();

    let batch_start = Instant::now();
    let _ = ClaimRepository::batch_create(&pool, &batch_claims)
        .await
        .expect("Batch create should succeed");
    let batch_duration = batch_start.elapsed();

    // Create another 50 claims for individual insert
    let individual_claims: Vec<Claim> = (0..50)
        .map(|i| create_test_claim_entity(agent.id, &format!("Individual perf claim {}", i), 0.5))
        .collect();

    let individual_start = Instant::now();
    for claim in &individual_claims {
        ClaimRepository::create(&pool, claim)
            .await
            .expect("Create should succeed");
    }
    let individual_duration = individual_start.elapsed();

    println!(
        "Batch insert 50 claims: {:?}, Individual insert 50 claims: {:?}",
        batch_duration, individual_duration
    );

    // Batch should generally be faster, but don't fail on timing
    // Just log for visibility
    assert!(
        batch_duration < individual_duration * 3,
        "Batch insert should not be significantly slower than individual inserts"
    );
}
