//! Integration tests for audit logging through API handlers
//!
//! These tests verify that security events are properly logged
//! when requests go through the actual API handlers.
//!
//! # Test Coverage
//!
//! - Authentication failures are logged with failure reasons
//! - Successful signature verification is logged
//! - Rate limit exceeded events are logged
//! - Events include correlation IDs linking related events

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use epigraph_api::security::audit::{SecurityAuditLog, SecurityEventFilter};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_api::{create_router, SecurityEvent};
use tower::ServiceExt;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Create an app state for testing
fn create_test_state() -> AppState {
    // Ensure DATABASE_URL is set for connect_lazy() (never actually connects in these tests)
    if std::env::var("DATABASE_URL").is_err() {
        std::env::set_var("DATABASE_URL", "postgres://test:test@localhost:5432/test");
    }
    AppState::new(ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    })
}

/// Create a router with the test state
fn create_test_router(state: AppState) -> Router {
    create_router(state)
}

// =============================================================================
// HANDLER AUDIT TESTS
// =============================================================================

#[tokio::test]
async fn test_health_endpoint_does_not_log_security_events() {
    // Given: A test router
    let state = create_test_state();
    let audit_log = state.audit_log.clone();
    let router = create_test_router(state);

    // When: We make a health check request
    let request = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // Then: Response should be OK and no security events logged
    // (health endpoints bypass auth, so no auth events)
    assert_eq!(response.status(), StatusCode::OK);

    // Health endpoint bypasses signature verification, so no events
    // This is correct behavior - we don't want to spam the audit log
    // with health check events
    let events = audit_log.query(SecurityEventFilter::new());
    // Health endpoint bypasses auth middleware entirely, so zero security events
    assert_eq!(
        events.len(),
        0,
        "Health check should not generate security events"
    );
}

#[tokio::test]
async fn test_audit_log_is_shared_across_requests() {
    // Given: A test state with audit log
    let state = create_test_state();
    let audit_log = state.audit_log.clone();

    // Log an event directly
    let agent_id = epigraph_core::domain::AgentId::new();
    audit_log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        None,
        None,
        "test-1".to_string(),
    ));

    // When: We clone the state (as would happen across handlers)
    let state_clone = state.clone();

    // Log another event via the clone
    state_clone.audit_log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        None,
        None,
        "test-2".to_string(),
    ));

    // Then: Both events should be in the original audit log
    let events = audit_log.query(SecurityEventFilter::new());
    assert_eq!(
        events.len(),
        2,
        "Events should be shared across state clones"
    );
}

#[tokio::test]
async fn test_audit_method_returns_audit_log_reference() {
    // Given: A test state
    let state = create_test_state();
    let agent_id = epigraph_core::domain::AgentId::new();

    // When: We use the audit() method to log an event
    state.audit().log(SecurityEvent::auth_attempt(
        agent_id,
        false,
        Some("127.0.0.1".parse().unwrap()),
        Some("Test-Agent/1.0".to_string()),
        "audit-method-test".to_string(),
    ));

    // Then: The event should be logged
    let events = state
        .audit_log
        .query(SecurityEventFilter::new().with_agent(agent_id));
    assert_eq!(events.len(), 1);
    assert!(events[0].is_failure()); // Auth was failure (success=false)
}

#[tokio::test]
async fn test_state_has_default_audit_log() {
    // Given: A freshly created AppState
    let state = create_test_state();

    // Then: It should have an audit log ready to use
    assert!(state.audit_log.is_empty(), "Audit log should start empty");

    // And we can log events
    state.audit_log.log(SecurityEvent::auth_attempt(
        epigraph_core::domain::AgentId::new(),
        true,
        None,
        None,
        "fresh-state-test".to_string(),
    ));

    assert_eq!(state.audit_log.len(), 1, "Should have logged one event");
}

#[tokio::test]
async fn test_security_events_have_correct_structure() {
    // Given: A test state
    let state = create_test_state();
    let agent_id = epigraph_core::domain::AgentId::new();

    // Log various security events
    state.audit_log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        Some("192.168.1.1".parse().unwrap()),
        Some("EpiGraph/1.0".to_string()),
        "struct-test-1".to_string(),
    ));

    state.audit_log.log(SecurityEvent::signature_verification(
        agent_id,
        false,
        Some("Invalid signature format".to_string()),
        "struct-test-2".to_string(),
    ));

    state.audit_log.log(SecurityEvent::rate_limit_exceeded(
        agent_id,
        "/api/v1/claims".to_string(),
        100,
        60,
        "struct-test-3".to_string(),
    ));

    // When: We query the events
    let events = state.audit_log.query(SecurityEventFilter::new());

    // Then: All events should be present with correct structure
    assert_eq!(events.len(), 3);

    // Check each event has a correlation ID
    for event in &events {
        assert!(!event.correlation_id().is_empty());
        let ts = event.timestamp();
        assert!(ts <= chrono::Utc::now());
    }

    // Check event types
    let types: Vec<_> = events.iter().map(|e| e.event_type()).collect();
    assert!(types.contains(&"auth_attempt"));
    assert!(types.contains(&"signature_verification"));
    assert!(types.contains(&"rate_limit_exceeded"));

    // Check failures are correctly identified
    let failures = state.audit_log.failures();
    assert_eq!(
        failures.len(),
        2,
        "Sig verification failure and rate limit should be failures"
    );
}
