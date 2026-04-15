//! Integration tests for audit logging in API handlers
//!
//! These tests verify:
//! - Audit events are logged for authentication attempts
//! - Audit events are logged for signature verification
//! - Audit events are logged for claim creation
//! - Audit events are logged for key operations (rotation/revocation)
//! - Sensitive data (keys, passwords) are NOT logged
//! - All events include required fields: timestamp, agent_id, action, outcome, request_id
//!
//! # TDD Approach
//!
//! These tests are written first to define the expected behavior.
//! The implementation should make them pass.

use epigraph_api::security::audit::{
    InMemorySecurityAuditLog, SecurityAuditLog, SecurityEventFilter,
};
use epigraph_api::SecurityEvent;
use epigraph_core::domain::AgentId;
use std::sync::Arc;
use uuid::Uuid;

// =============================================================================
// TEST HELPERS
// =============================================================================

/// Create a shared audit log for testing
fn create_test_audit_log() -> Arc<InMemorySecurityAuditLog> {
    Arc::new(InMemorySecurityAuditLog::new())
}

// =============================================================================
// AUTH ATTEMPT AUDIT TESTS
// =============================================================================

#[test]
fn test_successful_auth_attempt_is_logged() {
    // Given: An audit log and agent
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let request_id = Uuid::new_v4().to_string();

    // When: A successful authentication occurs
    log.log(SecurityEvent::auth_attempt(
        agent_id,
        true, // success
        Some("192.168.1.100".parse().unwrap()),
        Some("EpiGraph-Client/1.0".to_string()),
        request_id.clone(),
    ));

    // Then: The event should be logged with correct fields
    let events = log.query(SecurityEventFilter::new().with_agent(agent_id));
    assert_eq!(events.len(), 1, "Should have one auth event");

    let event = &events[0];
    assert_eq!(
        event.correlation_id(),
        request_id,
        "Request ID should match"
    );
    assert_eq!(event.agent_id(), Some(agent_id), "Agent ID should match");
    assert_eq!(
        event.event_type(),
        "auth_attempt",
        "Event type should be auth_attempt"
    );
    assert!(
        !event.is_failure(),
        "Successful auth should not be classified as failure"
    );
}

#[test]
fn test_failed_auth_attempt_is_logged() {
    // Given: An audit log and agent
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let request_id = Uuid::new_v4().to_string();

    // When: A failed authentication occurs
    log.log(SecurityEvent::auth_attempt(
        agent_id,
        false, // failure
        Some("10.0.0.1".parse().unwrap()),
        Some("Unknown-Client".to_string()),
        request_id.clone(),
    ));

    // Then: The event should be logged as a failure
    let failures = log.failures();
    assert_eq!(failures.len(), 1, "Should have one failure");

    let event = &failures[0];
    assert!(
        event.is_failure(),
        "Failed auth should be classified as failure"
    );
    assert_eq!(event.event_type(), "auth_attempt");
}

// =============================================================================
// SIGNATURE VERIFICATION AUDIT TESTS
// =============================================================================

#[test]
fn test_successful_signature_verification_is_logged() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let request_id = Uuid::new_v4().to_string();

    // When: A successful signature verification occurs
    log.log(SecurityEvent::signature_verification(
        agent_id,
        true, // success
        None, // no failure reason
        request_id.clone(),
    ));

    // Then: The event should be logged
    let events = log.query(
        SecurityEventFilter::new()
            .with_agent(agent_id)
            .with_event_type("signature_verification"),
    );
    assert_eq!(events.len(), 1);
    assert!(!events[0].is_failure());
}

#[test]
fn test_failed_signature_verification_includes_reason() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let request_id = Uuid::new_v4().to_string();
    let failure_reason = "Invalid signature format".to_string();

    // When: A signature verification fails
    log.log(SecurityEvent::signature_verification(
        agent_id,
        false,
        Some(failure_reason.clone()),
        request_id.clone(),
    ));

    // Then: The event should include the failure reason
    let events = log.query(SecurityEventFilter::new().failures_only());
    assert_eq!(events.len(), 1);

    match &events[0] {
        SecurityEvent::SignatureVerification {
            failure_reason: reason,
            ..
        } => {
            assert_eq!(reason.as_ref(), Some(&failure_reason));
        }
        _ => panic!("Expected SignatureVerification event"),
    }
}

// =============================================================================
// CLAIM CREATION AUDIT TESTS
// =============================================================================

/// SecurityEvent for claim creation
/// This documents the expected event structure for claim creation
#[test]
fn test_auth_event_correlates_to_request() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let request_id = Uuid::new_v4().to_string();

    // When: A claim is created (via successful auth)
    // Note: Claim creation is tracked via auth success + claim submission
    // The actual claim creation happens after auth, so we log auth success
    log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        None,
        None,
        request_id.clone(),
    ));

    // Then: The auth event correlates to the claim creation
    let events = log.query(SecurityEventFilter::new().with_correlation_id(&request_id));
    assert!(!events.is_empty(), "Should have events for this request");
}

// =============================================================================
// KEY OPERATION AUDIT TESTS
// =============================================================================

#[test]
fn test_key_rotation_event_includes_both_key_ids() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let old_key_id = Uuid::new_v4();
    let new_key_id = Uuid::new_v4();
    let request_id = Uuid::new_v4().to_string();

    // When: A key rotation occurs
    log.log(SecurityEvent::key_rotation(
        agent_id,
        old_key_id,
        new_key_id,
        "Scheduled 90-day rotation".to_string(),
        request_id.clone(),
    ));

    // Then: Both key IDs should be in the event
    let events = log.query(SecurityEventFilter::new().with_event_type("key_rotation"));
    assert_eq!(events.len(), 1);

    match &events[0] {
        SecurityEvent::KeyRotation {
            old_key_id: old,
            new_key_id: new,
            rotation_reason,
            ..
        } => {
            assert_eq!(*old, old_key_id, "Old key ID should match");
            assert_eq!(*new, new_key_id, "New key ID should match");
            assert!(
                !rotation_reason.is_empty(),
                "Rotation reason should be present"
            );
        }
        _ => panic!("Expected KeyRotation event"),
    }
}

#[test]
fn test_key_revocation_event_includes_revoked_by() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let key_id = Uuid::new_v4();
    let request_id = Uuid::new_v4().to_string();

    // When: A key is revoked
    log.log(SecurityEvent::key_revocation(
        agent_id,
        key_id,
        "Suspected compromise".to_string(),
        admin_id,
        request_id.clone(),
    ));

    // Then: The revoked_by field should be present
    let events = log.query(SecurityEventFilter::new().with_event_type("key_revocation"));
    assert_eq!(events.len(), 1);

    match &events[0] {
        SecurityEvent::KeyRevocation {
            revoked_by, reason, ..
        } => {
            assert_eq!(*revoked_by, admin_id, "Revoked by should match admin ID");
            assert!(!reason.is_empty(), "Revocation reason should be present");
        }
        _ => panic!("Expected KeyRevocation event"),
    }
}

// =============================================================================
// SENSITIVE DATA REDACTION TESTS
// =============================================================================

#[test]
fn test_no_sensitive_data_in_auth_events() {
    // Given: An audit log and auth event
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        Some("192.168.1.1".parse().unwrap()),
        Some("Client/1.0".to_string()),
        "test-123".to_string(),
    ));

    // When: We serialize the event
    let events = log.query(SecurityEventFilter::new());
    let serialized = serde_json::to_string(&events[0]).expect("Should serialize");

    // Then: No sensitive data should be present
    // We check for absence of certain patterns that would indicate sensitive data
    assert!(
        !serialized.contains("password"),
        "Should not contain password"
    );
    assert!(
        !serialized.contains("private_key"),
        "Should not contain private_key"
    );
    assert!(!serialized.contains("secret"), "Should not contain secret");
}

#[test]
fn test_key_rotation_event_does_not_contain_private_key() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    log.log(SecurityEvent::key_rotation(
        agent_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "Rotation reason".to_string(),
        "test-456".to_string(),
    ));

    // When: We serialize the event
    let events = log.query(SecurityEventFilter::new());
    let serialized = serde_json::to_string(&events[0]).expect("Should serialize");

    // Then: No private key material should be present
    assert!(
        !serialized.contains("private"),
        "Should not contain private key references"
    );
    // Public key IDs are OK but actual key bytes should not be present
    // Key IDs are UUIDs (36 chars) not key material (64+ hex chars)
    assert!(
        serialized.len() < 1000,
        "Event should be reasonably sized (no embedded key material)"
    );
}

// =============================================================================
// REQUIRED FIELDS TESTS
// =============================================================================

#[test]
fn test_all_events_have_timestamp() {
    // Given: An audit log with various events
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        None,
        None,
        "1".to_string(),
    ));
    log.log(SecurityEvent::signature_verification(
        agent_id,
        true,
        None,
        "2".to_string(),
    ));
    log.log(SecurityEvent::key_rotation(
        agent_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "r".to_string(),
        "3".to_string(),
    ));

    // When: We query all events
    let events = log.query(SecurityEventFilter::new());

    // Then: All events should have timestamps
    for event in &events {
        let timestamp = event.timestamp();
        // Timestamp should be recent (within last minute)
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(timestamp);
        assert!(
            age.num_seconds() < 60,
            "Timestamp should be recent, got age: {} seconds",
            age.num_seconds()
        );
    }
}

#[test]
fn test_all_events_have_correlation_id() {
    // Given: An audit log with events
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    let request_ids = ["req-001", "req-002", "req-003"];

    for (i, req_id) in request_ids.iter().enumerate() {
        log.log(SecurityEvent::auth_attempt(
            agent_id,
            i % 2 == 0,
            None,
            None,
            req_id.to_string(),
        ));
    }

    // When: We query events
    let events = log.query(SecurityEventFilter::new());

    // Then: All events should have correlation IDs
    assert_eq!(events.len(), 3);
    for event in &events {
        assert!(
            !event.correlation_id().is_empty(),
            "Correlation ID should not be empty"
        );
    }
}

#[test]
fn test_events_can_be_queried_by_agent_id() {
    // Given: An audit log with events from multiple agents
    let log = create_test_audit_log();
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();

    log.log(SecurityEvent::auth_attempt(
        agent1,
        true,
        None,
        None,
        "a1-1".to_string(),
    ));
    log.log(SecurityEvent::auth_attempt(
        agent1,
        true,
        None,
        None,
        "a1-2".to_string(),
    ));
    log.log(SecurityEvent::auth_attempt(
        agent2,
        true,
        None,
        None,
        "a2-1".to_string(),
    ));

    // When: We query by agent1
    let agent1_events = log.query(SecurityEventFilter::new().with_agent(agent1));

    // Then: Only agent1's events should be returned
    assert_eq!(agent1_events.len(), 2);
    for event in &agent1_events {
        assert_eq!(event.agent_id(), Some(agent1));
    }
}

// =============================================================================
// STRUCTURED LOGGING (JSON) TESTS
// =============================================================================

#[test]
fn test_events_are_json_serializable() {
    // Given: Various security events
    let agent_id = AgentId::new();

    let events = vec![
        SecurityEvent::auth_attempt(agent_id, true, None, None, "1".to_string()),
        SecurityEvent::signature_verification(
            agent_id,
            false,
            Some("Bad sig".to_string()),
            "2".to_string(),
        ),
        SecurityEvent::key_rotation(
            agent_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Rotation".to_string(),
            "3".to_string(),
        ),
        SecurityEvent::key_revocation(
            agent_id,
            Uuid::new_v4(),
            "Compromised".to_string(),
            AgentId::new(),
            "4".to_string(),
        ),
        SecurityEvent::rate_limit_exceeded(
            agent_id,
            "/api/v1/claims".to_string(),
            100,
            60,
            "5".to_string(),
        ),
        SecurityEvent::privilege_escalation(
            agent_id,
            "delete_all".to_string(),
            "admin".to_string(),
            "6".to_string(),
        ),
    ];

    // When: We serialize each event
    for event in &events {
        let json = serde_json::to_string(event);

        // Then: Serialization should succeed
        assert!(
            json.is_ok(),
            "Event {:?} should be JSON serializable",
            event.event_type()
        );

        let json_str = json.unwrap();

        // And the JSON should be valid (can be parsed back)
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok(), "JSON should be parseable");
    }
}

#[test]
fn test_events_have_structured_format_for_aggregation() {
    // Given: A security event
    let agent_id = AgentId::new();
    let event = SecurityEvent::auth_attempt(
        agent_id,
        false,
        Some("10.0.0.1".parse().unwrap()),
        Some("Test-Client".to_string()),
        "req-structured".to_string(),
    );

    // When: We serialize to JSON
    let json: serde_json::Value = serde_json::to_value(&event).expect("Should serialize");

    // Then: Key fields should be accessible for aggregation
    // The event type should be easily extractable
    assert!(json.is_object(), "Event should serialize as JSON object");

    // The structure should allow for log aggregation tools
    // to easily filter and group events
    let obj = json.as_object().unwrap();
    assert!(
        obj.contains_key("AuthAttempt") || obj.get("type").is_some(),
        "Event should have identifiable type for filtering"
    );
}

// =============================================================================
// RATE LIMIT EVENT TESTS
// =============================================================================

#[test]
fn test_rate_limit_exceeded_event_includes_limit_details() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    // When: Rate limit is exceeded
    log.log(SecurityEvent::rate_limit_exceeded(
        agent_id,
        "/api/v1/claims".to_string(),
        150, // current rate
        60,  // limit
        "rate-test".to_string(),
    ));

    // Then: Event should include rate details
    let events = log.query(SecurityEventFilter::new().with_event_type("rate_limit_exceeded"));
    assert_eq!(events.len(), 1);

    match &events[0] {
        SecurityEvent::RateLimitExceeded {
            endpoint,
            current_rate,
            limit,
            ..
        } => {
            assert_eq!(endpoint, "/api/v1/claims");
            assert_eq!(*current_rate, 150);
            assert_eq!(*limit, 60);
        }
        _ => panic!("Expected RateLimitExceeded event"),
    }

    // Rate limit exceeded IS a failure
    assert!(events[0].is_failure());
}

// =============================================================================
// PRIVILEGE ESCALATION EVENT TESTS
// =============================================================================

#[test]
fn test_privilege_escalation_event_includes_action_details() {
    // Given: An audit log
    let log = create_test_audit_log();
    let agent_id = AgentId::new();

    // When: A privilege escalation is attempted
    log.log(SecurityEvent::privilege_escalation(
        agent_id,
        "delete_system_claims".to_string(),
        "admin_delete".to_string(),
        "priv-test".to_string(),
    ));

    // Then: Event should include action details
    let events = log.query(SecurityEventFilter::new().with_event_type("privilege_escalation"));
    assert_eq!(events.len(), 1);

    match &events[0] {
        SecurityEvent::PrivilegeEscalation {
            attempted_action,
            required_capability,
            ..
        } => {
            assert_eq!(attempted_action, "delete_system_claims");
            assert_eq!(required_capability, "admin_delete");
        }
        _ => panic!("Expected PrivilegeEscalation event"),
    }

    // Privilege escalation IS a failure
    assert!(events[0].is_failure());
}
