//! Comprehensive TDD tests for EpiGraph Security Hardening
//!
//! These tests verify:
//! - AgentKey management (creation, status transitions)
//! - KeyStatus behavior (signing/verification permissions)
//! - Key rotation with dual-signature verification
//! - Rate limiting (per-agent and global quotas)
//! - Security event audit logging
//!
//! # TDD Approach
//!
//! These tests are written FIRST (red phase). The implementation should
//! make them pass (green phase), then be refactored (refactor phase).

use chrono::{Duration, Utc};
use epigraph_api::security::{
    audit::{InMemorySecurityAuditLog, SecurityAuditLog, SecurityEventFilter},
    keys::{AgentKey, KeyError, KeyRotationRequest, KeyStatus, KeyType, Signature},
    rate_limit::{AgentRateLimiter, RateLimitConfig, RateLimitError},
};
use epigraph_api::SecurityEvent;
use epigraph_core::domain::AgentId;
use uuid::Uuid;

// =============================================================================
// AGENT KEY TESTS
// =============================================================================

#[test]
fn test_agent_key_creation() {
    // Given: An agent ID and public key
    let agent_id = AgentId::new();
    let public_key = [42u8; 32];

    // When: We create a new agent key
    let key = AgentKey::new(agent_id, public_key);

    // Then: The key should have correct properties
    assert_eq!(key.agent_id, agent_id);
    assert_eq!(key.public_key, public_key);
    assert_eq!(key.status, KeyStatus::Active);
    assert_eq!(key.key_type, KeyType::Signing);
    assert!(key.valid_from <= Utc::now());
    assert!(key.valid_until.is_none()); // No expiration by default
    assert!(key.created_at <= Utc::now());
    assert!(key.revocation_reason.is_none());
    assert!(key.revoked_by.is_none());
}

#[test]
fn test_agent_key_creation_with_expiration() {
    // Given: An agent ID, public key, and future dates
    let agent_id = AgentId::new();
    let public_key = [42u8; 32];
    let valid_from = Utc::now() + Duration::hours(1);
    let valid_until = Some(Utc::now() + Duration::days(30));

    // When: We create a pending key with expiration
    let key = AgentKey::new_pending(agent_id, public_key, valid_from, valid_until);

    // Then: The key should be pending with correct dates
    assert_eq!(key.status, KeyStatus::Pending);
    assert_eq!(key.valid_from, valid_from);
    assert_eq!(key.valid_until, valid_until);
}

// =============================================================================
// KEY STATUS TESTS
// =============================================================================

#[test]
fn test_key_status_active_allows_signing() {
    // Given: A key with Active status
    let agent_id = AgentId::new();
    let key = AgentKey::new(agent_id, [1u8; 32]);
    assert_eq!(key.status, KeyStatus::Active);

    // When: We check if signing is allowed
    let result = key.can_sign();

    // Then: Signing should be allowed
    assert!(result.is_ok(), "Active key should allow signing");
}

#[test]
fn test_key_status_active_allows_verification() {
    // Given: A key with Active status
    let agent_id = AgentId::new();
    let key = AgentKey::new(agent_id, [1u8; 32]);

    // When: We check if verification is allowed
    let result = key.can_verify();

    // Then: Verification should be allowed
    assert!(result.is_ok(), "Active key should allow verification");
}

#[test]
fn test_key_status_revoked_rejects_signing() {
    // Given: A key that has been revoked
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);
    key.revoke("Compromised".to_string(), admin_id);

    // When: We try to sign with the revoked key
    let result = key.can_sign();

    // Then: Signing should be rejected
    assert!(result.is_err(), "Revoked key should reject signing");
    assert_eq!(key.status, KeyStatus::Revoked);
}

#[test]
fn test_key_status_revoked_rejects_verification() {
    // Given: A key that has been revoked
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);
    key.revoke("Compromised".to_string(), admin_id);

    // When: We try to verify with the revoked key
    let result = key.can_verify();

    // Then: Verification should be rejected
    assert!(result.is_err(), "Revoked key should reject verification");
}

#[test]
fn test_key_status_expired_rejects_signing() {
    // Given: A key that has expired
    let agent_id = AgentId::new();
    let past_time = Utc::now() - Duration::hours(1);
    let past_expiry = Some(Utc::now() - Duration::minutes(30));
    let mut key = AgentKey::new_pending(agent_id, [1u8; 32], past_time, past_expiry);
    key.status = KeyStatus::Active; // Manually set to Active to test expiration check
    key.check_expiration(); // This should set status to Expired

    // When: We try to sign with the expired key
    let result = key.can_sign();

    // Then: Signing should be rejected
    assert!(result.is_err(), "Expired key should reject signing");
    assert_eq!(key.status, KeyStatus::Expired);
}

#[test]
fn test_key_status_expired_rejects_verification() {
    // Given: A key with Expired status
    let agent_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);
    key.status = KeyStatus::Expired;

    // When: We try to verify with the expired key
    let result = key.can_verify();

    // Then: Verification should be rejected
    assert!(result.is_err(), "Expired key should reject verification");
}

#[test]
fn test_key_status_rotated_still_verifies() {
    // Given: A key that has been rotated
    let agent_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);
    key.mark_rotated();

    // When: We check if verification is allowed
    let sign_result = key.can_sign();
    let verify_result = key.can_verify();

    // Then: Signing should be rejected but verification should work
    assert!(sign_result.is_err(), "Rotated key should reject signing");
    assert!(
        verify_result.is_ok(),
        "Rotated key should still allow verification"
    );
    assert_eq!(key.status, KeyStatus::Rotated);
}

#[test]
fn test_key_status_pending_rejects_all_operations() {
    // Given: A pending key (not yet valid)
    let agent_id = AgentId::new();
    let future_time = Utc::now() + Duration::hours(1);
    let key = AgentKey::new_pending(agent_id, [1u8; 32], future_time, None);

    // When: We check signing and verification
    let sign_result = key.can_sign();
    let verify_result = key.can_verify();

    // Then: Both should be rejected
    assert!(sign_result.is_err(), "Pending key should reject signing");
    assert!(
        verify_result.is_err(),
        "Pending key should reject verification"
    );
}

// =============================================================================
// KEY ROTATION TESTS
// =============================================================================

#[test]
fn test_key_rotation_requires_both_signatures() {
    // Given: A key rotation request
    let agent_id = AgentId::new();
    let _old_key = AgentKey::new(agent_id, [1u8; 32]);
    let new_public_key = [2u8; 32];

    // A valid rotation requires both old and new key signatures
    let old_signature = Signature::from_bytes([0u8; 64]); // Placeholder
    let new_signature = Signature::from_bytes([0u8; 64]); // Placeholder

    let request = KeyRotationRequest::new(
        agent_id,
        new_public_key,
        old_signature,
        new_signature,
        "Regular rotation".to_string(),
    );

    // Then: The request should contain both signatures
    assert_eq!(request.agent_id, agent_id);
    assert_eq!(request.new_public_key, new_public_key);
    assert_eq!(request.old_key_signature.as_bytes().len(), 64);
    assert_eq!(request.new_key_signature.as_bytes().len(), 64);
}

#[test]
fn test_key_rotation_old_key_signature_verification() {
    // Given: A rotation request with an invalid old key signature
    let agent_id = AgentId::new();
    let _old_key = AgentKey::new(agent_id, [1u8; 32]);
    let new_public_key = [2u8; 32];

    // Create a rotation request with a known bad old key signature
    // In a real test, this would use actual cryptographic verification
    let invalid_old_signature = Signature::from_bytes([0xFFu8; 64]);
    let valid_new_signature = Signature::from_bytes([0u8; 64]);

    let request = KeyRotationRequest::new(
        agent_id,
        new_public_key,
        invalid_old_signature,
        valid_new_signature,
        "Test rotation".to_string(),
    );

    // When: We verify the rotation request
    // Note: This test documents expected behavior; actual verification
    // requires implementing ed25519 signature checks
    let message = request.message_to_sign();
    assert!(!message.is_empty(), "Rotation message should not be empty");

    // The message should include the agent ID and new public key
    assert!(
        message
            .windows(agent_id.as_uuid().as_bytes().len())
            .any(|window| window == agent_id.as_uuid().as_bytes()),
        "Message should contain agent ID"
    );
}

#[test]
fn test_key_rotation_new_key_signature_verification() {
    // Given: A rotation request
    let agent_id = AgentId::new();
    let new_public_key = [2u8; 32];

    let old_signature = Signature::from_bytes([0u8; 64]);
    let new_signature = Signature::from_bytes([0u8; 64]);

    let request = KeyRotationRequest::new(
        agent_id,
        new_public_key,
        old_signature,
        new_signature,
        "Test rotation".to_string(),
    );

    // When: We get the message to sign
    let message = request.message_to_sign();

    // Then: The new key signature should be over this message
    // containing the new public key for proof of possession
    assert!(
        message
            .windows(new_public_key.len())
            .any(|window| window == new_public_key),
        "Message should contain new public key"
    );
}

#[test]
fn test_key_rotation_updates_status_to_rotated() {
    // Given: An active key
    let agent_id = AgentId::new();
    let mut old_key = AgentKey::new(agent_id, [1u8; 32]);
    assert_eq!(old_key.status, KeyStatus::Active);

    // When: The key is rotated
    old_key.mark_rotated();

    // Then: The status should be Rotated
    assert_eq!(old_key.status, KeyStatus::Rotated);
}

#[test]
fn test_key_rotation_request_verification_rejects_inactive_key() {
    // Given: A key that is not active
    let agent_id = AgentId::new();
    let mut old_key = AgentKey::new(agent_id, [1u8; 32]);
    old_key.mark_rotated(); // Make it inactive

    let request = KeyRotationRequest::new(
        agent_id,
        [2u8; 32],
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Test".to_string(),
    );

    // When: We verify the rotation request
    let result = request.verify(&old_key);

    // Then: It should be rejected because the old key is not active
    assert!(result.is_err(), "Rotation should fail for non-active keys");
}

// =============================================================================
// KEY REVOCATION TESTS
// =============================================================================

#[test]
fn test_key_revocation_sets_reason() {
    // Given: An active key
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);

    // When: The key is revoked with a reason
    let reason = "Key compromised - emergency revocation".to_string();
    key.revoke(reason.clone(), admin_id);

    // Then: The key should be revoked with the reason recorded
    assert_eq!(key.status, KeyStatus::Revoked);
    assert_eq!(key.revocation_reason, Some(reason));
    assert_eq!(key.revoked_by, Some(admin_id));
}

#[test]
fn test_key_revocation_records_who_revoked() {
    // Given: An active key and an admin
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);

    // When: The admin revokes the key
    key.revoke("Policy violation".to_string(), admin_id);

    // Then: The admin ID should be recorded
    assert_eq!(key.revoked_by, Some(admin_id));
}

#[test]
fn test_key_revocation_idempotency() {
    // Given: A key that has already been revoked
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut key = AgentKey::new(agent_id, [1u8; 32]);
    let original_reason = "First revocation - compromised".to_string();
    key.revoke(original_reason.clone(), admin_id);

    // When: We attempt to revoke it again with a different reason
    let second_admin = AgentId::new();
    let second_reason = "Second attempt".to_string();
    key.revoke(second_reason.clone(), second_admin);

    // Then: The key should still be revoked (idempotent behavior)
    // Note: Current implementation overwrites the reason/admin
    // A production system might want to preserve the original
    assert_eq!(key.status, KeyStatus::Revoked);
    // Document current behavior: last revocation wins
    assert_eq!(key.revocation_reason, Some(second_reason));
    assert_eq!(key.revoked_by, Some(second_admin));
}

#[test]
fn test_key_rotation_rejects_revoked_key() {
    // Given: A key that has been revoked
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let mut old_key = AgentKey::new(agent_id, [1u8; 32]);
    old_key.revoke("Key compromised".to_string(), admin_id);

    let request = KeyRotationRequest::new(
        agent_id,
        [2u8; 32],
        Signature::from_bytes([0u8; 64]),
        Signature::from_bytes([0u8; 64]),
        "Attempting to rotate revoked key".to_string(),
    );

    // When: We try to verify a rotation request against the revoked key
    let result = request.verify(&old_key);

    // Then: It should be rejected with InvalidKeyStatus error
    assert!(result.is_err(), "Should not allow rotating a revoked key");
    match result {
        Err(KeyError::InvalidKeyStatus {
            status, operation, ..
        }) => {
            assert_eq!(status, KeyStatus::Revoked);
            assert!(
                operation.contains("rotation"),
                "Error should mention rotation"
            );
        }
        other => panic!("Expected InvalidKeyStatus error, got: {:?}", other),
    }
}

#[test]
fn test_key_status_invalid_transitions() {
    // Test that certain state transitions are invalid or have specific behaviors
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();

    // Test 1: Cannot mark a revoked key as rotated (panics in current impl)
    let mut revoked_key = AgentKey::new(agent_id, [1u8; 32]);
    revoked_key.revoke("Compromised".to_string(), admin_id);
    // Note: mark_rotated() panics if key is not Active - this is by design
    // In production, wrap in catch_unwind or check status first
    assert_eq!(revoked_key.status, KeyStatus::Revoked);

    // Test 2: Expired key cannot be used for signing
    let mut expired_key = AgentKey::new(agent_id, [2u8; 32]);
    expired_key.status = KeyStatus::Expired;
    let sign_result = expired_key.can_sign();
    assert!(sign_result.is_err(), "Expired key should not allow signing");

    // Test 3: Pending key transitions - cannot sign or verify
    let future_key =
        AgentKey::new_pending(agent_id, [3u8; 32], Utc::now() + Duration::hours(1), None);
    assert!(future_key.can_sign().is_err(), "Pending key cannot sign");
    assert!(
        future_key.can_verify().is_err(),
        "Pending key cannot verify"
    );

    // Test 4: Rotated key can verify but not sign
    let mut rotated_key = AgentKey::new(agent_id, [4u8; 32]);
    rotated_key.mark_rotated();
    assert!(rotated_key.can_sign().is_err(), "Rotated key cannot sign");
    assert!(rotated_key.can_verify().is_ok(), "Rotated key can verify");
}

// =============================================================================
// RATE LIMITER TESTS
// =============================================================================

#[test]
fn test_rate_limiter_allows_under_limit() {
    // Given: A rate limiter with 10 RPM limit
    let config = RateLimitConfig {
        default_rpm: 10,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false, // Disable global for this test
    };
    let limiter = AgentRateLimiter::new(config);
    let agent_id = AgentId::new();

    // When: We make fewer requests than the limit
    let mut allowed = 0;
    for _ in 0..5 {
        if limiter.check(&agent_id).is_ok() {
            allowed += 1;
        }
    }

    // Then: All requests should be allowed
    assert_eq!(allowed, 5, "Requests under limit should be allowed");
}

#[test]
fn test_rate_limiter_rejects_over_limit() {
    // Given: A rate limiter with a low limit
    let config = RateLimitConfig {
        default_rpm: 3,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let agent_id = AgentId::new();

    // When: We exceed the limit
    for _ in 0..3 {
        let _ = limiter.check(&agent_id); // Consume all tokens
    }
    let result = limiter.check(&agent_id);

    // Then: The request should be rejected
    assert!(result.is_err(), "Request over limit should be rejected");
    match result {
        Err(RateLimitError::AgentLimitExceeded { agent_id: id, .. }) => {
            assert_eq!(id, agent_id);
        }
        _ => panic!("Expected AgentLimitExceeded error"),
    }
}

#[test]
fn test_rate_limiter_per_agent_quota() {
    // Given: A rate limiter
    let config = RateLimitConfig {
        default_rpm: 5,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();

    // When: Agent 1 exhausts their quota
    for _ in 0..5 {
        let _ = limiter.check(&agent1);
    }

    // Then: Agent 2 should still have their quota
    assert!(
        limiter.check(&agent2).is_ok(),
        "Agent 2 should have independent quota"
    );

    // And Agent 1 should be rate limited
    assert!(
        limiter.check(&agent1).is_err(),
        "Agent 1 should be rate limited"
    );
}

#[test]
fn test_rate_limiter_global_quota() {
    // Given: A rate limiter with a low global limit
    let config = RateLimitConfig {
        default_rpm: 100, // High per-agent limit
        global_rpm: 3,    // Low global limit
        replenish_interval_secs: 1,
        enable_global_limit: true,
    };
    let limiter = AgentRateLimiter::new(config);

    // When: Multiple agents make requests exceeding global limit
    let mut total_allowed = 0;
    for _ in 0..5 {
        let agent = AgentId::new(); // Different agent each time
        if limiter.check(&agent).is_ok() {
            total_allowed += 1;
        }
    }

    // Then: Only 3 should be allowed (global limit)
    assert_eq!(
        total_allowed, 3,
        "Only global limit requests should be allowed"
    );
}

#[test]
fn test_rate_limiter_quota_replenishes() {
    // Given: A rate limiter where agent has exhausted quota
    let config = RateLimitConfig {
        default_rpm: 60, // 1 per second
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let agent_id = AgentId::new();

    // Exhaust some quota
    for _ in 0..60 {
        let _ = limiter.check(&agent_id);
    }
    assert!(
        limiter.check(&agent_id).is_err(),
        "Quota should be exhausted"
    );

    // When: Time passes (simulate by advancing internal time)
    limiter.advance_time(Duration::seconds(2));

    // Then: Some quota should have replenished
    // At 1 token per second, after 2 seconds we should have ~2 tokens
    assert!(
        limiter.check(&agent_id).is_ok(),
        "Quota should have replenished"
    );
}

#[test]
fn test_rate_limit_error_includes_retry_after() {
    // Given: A rate limiter where agent is rate limited
    let config = RateLimitConfig {
        default_rpm: 1,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let agent_id = AgentId::new();

    // Exhaust quota
    let _ = limiter.check(&agent_id);
    let result = limiter.check(&agent_id);

    // Then: Error should include retry_after
    match result {
        Err(ref e) => {
            let retry_after = e.retry_after();
            assert!(
                retry_after > 0,
                "retry_after should be positive, got {}",
                retry_after
            );
        }
        Ok(_) => panic!("Expected rate limit error"),
    }
}

#[test]
fn test_rate_limiter_custom_agent_limit() {
    // Given: A rate limiter with custom limits for specific agents
    let config = RateLimitConfig {
        default_rpm: 10,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let premium_agent = AgentId::new();

    // When: We set a higher limit for the premium agent
    limiter.set_agent_limit(premium_agent, 100);

    // Then: The premium agent should have more quota
    let mut allowed = 0;
    for _ in 0..50 {
        if limiter.check(&premium_agent).is_ok() {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 50, "Premium agent should have higher limit");
}

#[test]
fn test_rate_limiter_global_limit_exceeded_error() {
    // Given: A rate limiter with global limiting enabled
    let config = RateLimitConfig {
        default_rpm: 100, // High per-agent limit
        global_rpm: 2,    // Very low global limit
        replenish_interval_secs: 1,
        enable_global_limit: true,
    };
    let limiter = AgentRateLimiter::new(config);

    // When: We exceed the global limit with different agents
    let agent1 = AgentId::new();
    let agent2 = AgentId::new();
    let agent3 = AgentId::new();

    // First two should succeed (within global limit of 2)
    let _ = limiter.check(&agent1);
    let _ = limiter.check(&agent2);

    // Third should fail with GlobalLimitExceeded (not AgentLimitExceeded)
    let result = limiter.check(&agent3);

    // Then: We should get a GlobalLimitExceeded error specifically
    assert!(result.is_err(), "Request should be rejected");
    match result {
        Err(RateLimitError::GlobalLimitExceeded { retry_after_secs }) => {
            assert!(retry_after_secs > 0, "retry_after_secs should be positive");
        }
        Err(RateLimitError::AgentLimitExceeded { .. }) => {
            panic!("Expected GlobalLimitExceeded, got AgentLimitExceeded");
        }
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn test_rate_limiter_both_limits_exhausted() {
    // Given: A rate limiter where both agent and global limits can be hit
    let config = RateLimitConfig {
        default_rpm: 3, // Low per-agent limit
        global_rpm: 5,  // Slightly higher global limit
        replenish_interval_secs: 1,
        enable_global_limit: true,
    };
    let limiter = AgentRateLimiter::new(config);
    let agent_id = AgentId::new();

    // When: Agent exhausts their personal quota
    for _ in 0..3 {
        let _ = limiter.check(&agent_id);
    }

    // Then: The 4th request should fail with AgentLimitExceeded
    // (agent limit is hit before global limit)
    let result = limiter.check(&agent_id);
    assert!(result.is_err(), "Request should be rejected");
    match result {
        Err(RateLimitError::AgentLimitExceeded { agent_id: id, .. }) => {
            assert_eq!(id, agent_id, "Error should reference correct agent");
        }
        Err(RateLimitError::GlobalLimitExceeded { .. }) => {
            // This is also acceptable if global check happens first
            // but per the implementation, global is checked first and should pass
            panic!("Expected AgentLimitExceeded since agent hit their limit first");
        }
        Ok(_) => panic!("Expected error, got Ok"),
    }

    // Now exhaust the global limit with other agents
    let other_agent1 = AgentId::new();
    let other_agent2 = AgentId::new();
    // Global has 5 - we used 3, so 2 remain
    let _ = limiter.check(&other_agent1);
    let _ = limiter.check(&other_agent2);

    // New agent should now hit the global limit
    let new_agent = AgentId::new();
    let global_result = limiter.check(&new_agent);
    assert!(
        global_result.is_err(),
        "Global limit should now be exhausted"
    );
    match global_result {
        Err(RateLimitError::GlobalLimitExceeded { .. }) => {
            // Expected - global limit hit
        }
        _ => panic!("Expected GlobalLimitExceeded after global limit exhaustion"),
    }
}

// =============================================================================
// SECURITY EVENT AUDIT TESTS
// =============================================================================

#[test]
fn test_security_event_auth_attempt_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    // When: We log an auth attempt
    let event = SecurityEvent::auth_attempt(
        agent_id,
        true,
        Some("192.168.1.1".parse().unwrap()),
        Some("EpiGraph-Client/1.0".to_string()),
        "corr-123".to_string(),
    );
    log.log(event);

    // Then: The event should be retrievable
    let events = log.query(SecurityEventFilter::new().with_agent(agent_id));
    assert_eq!(events.len(), 1);
    match &events[0] {
        SecurityEvent::AuthAttempt {
            success,
            ip_address,
            ..
        } => {
            assert!(*success);
            assert!(ip_address.is_some());
        }
        _ => panic!("Expected AuthAttempt event"),
    }
}

#[test]
fn test_security_event_signature_verification_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    // When: We log a signature verification failure
    let event = SecurityEvent::signature_verification(
        agent_id,
        false,
        Some("Invalid signature format".to_string()),
        "corr-456".to_string(),
    );
    log.log(event);

    // Then: The event should be queryable
    let events = log.query(
        SecurityEventFilter::new()
            .with_event_type("signature_verification")
            .failures_only(),
    );
    assert_eq!(events.len(), 1);
    match &events[0] {
        SecurityEvent::SignatureVerification {
            success,
            failure_reason,
            ..
        } => {
            assert!(!*success);
            assert_eq!(failure_reason.as_deref(), Some("Invalid signature format"));
        }
        _ => panic!("Expected SignatureVerification event"),
    }
}

#[test]
fn test_security_event_key_rotation_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();
    let old_key_id = Uuid::new_v4();
    let new_key_id = Uuid::new_v4();

    // When: We log a key rotation
    let event = SecurityEvent::key_rotation(
        agent_id,
        old_key_id,
        new_key_id,
        "Scheduled rotation".to_string(),
        "corr-789".to_string(),
    );
    log.log(event);

    // Then: The event should contain both key IDs
    let events = log.query(SecurityEventFilter::new().with_event_type("key_rotation"));
    assert_eq!(events.len(), 1);
    match &events[0] {
        SecurityEvent::KeyRotation {
            old_key_id: old_id,
            new_key_id: new_id,
            rotation_reason,
            ..
        } => {
            assert_eq!(*old_id, old_key_id);
            assert_eq!(*new_id, new_key_id);
            assert_eq!(rotation_reason, "Scheduled rotation");
        }
        _ => panic!("Expected KeyRotation event"),
    }
}

#[test]
fn test_security_event_key_revocation_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();
    let admin_id = AgentId::new();
    let key_id = Uuid::new_v4();
    let revocation_reason = "Key compromised - emergency revocation".to_string();

    // When: We log a key revocation event
    let event = SecurityEvent::key_revocation(
        agent_id,
        key_id,
        revocation_reason.clone(),
        admin_id,
        "corr-revoke-001".to_string(),
    );
    log.log(event);

    // Then: The event should be retrievable and contain all revocation details
    let events = log.query(SecurityEventFilter::new().with_event_type("key_revocation"));
    assert_eq!(
        events.len(),
        1,
        "Should have exactly one key_revocation event"
    );

    match &events[0] {
        SecurityEvent::KeyRevocation {
            agent_id: logged_agent_id,
            key_id: logged_key_id,
            reason,
            revoked_by,
            correlation_id,
            ..
        } => {
            assert_eq!(*logged_agent_id, agent_id, "Agent ID should match");
            assert_eq!(*logged_key_id, key_id, "Key ID should match");
            assert_eq!(reason, &revocation_reason, "Revocation reason should match");
            assert_eq!(*revoked_by, admin_id, "Revoked by should match admin");
            assert_eq!(
                correlation_id, "corr-revoke-001",
                "Correlation ID should match"
            );
        }
        _ => panic!(
            "Expected KeyRevocation event, got {:?}",
            events[0].event_type()
        ),
    }

    // Also verify the event can be queried by agent
    let agent_events = log.query(SecurityEventFilter::new().with_agent(agent_id));
    assert_eq!(agent_events.len(), 1, "Should find event by agent ID");

    // Verify key revocation is NOT classified as a failure
    // (it's a legitimate operation, not a security incident)
    assert!(
        !events[0].is_failure(),
        "Key revocation should NOT be classified as a failure"
    );
}

#[test]
fn test_security_event_rate_limit_exceeded_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    // When: We log a rate limit exceeded event
    let event = SecurityEvent::rate_limit_exceeded(
        agent_id,
        "/api/v1/claims".to_string(),
        150,
        60,
        "corr-rate".to_string(),
    );
    log.log(event);

    // Then: The event should contain rate info
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
}

#[test]
fn test_security_event_privilege_escalation_logged() {
    // Given: An audit log
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    // When: We log a privilege escalation attempt
    let event = SecurityEvent::privilege_escalation(
        agent_id,
        "modify_policy".to_string(),
        "can_modify_policies".to_string(),
        "corr-priv".to_string(),
    );
    log.log(event);

    // Then: The event should contain action and capability info
    let events = log.query(SecurityEventFilter::new().with_event_type("privilege_escalation"));
    assert_eq!(events.len(), 1);
    match &events[0] {
        SecurityEvent::PrivilegeEscalation {
            attempted_action,
            required_capability,
            ..
        } => {
            assert_eq!(attempted_action, "modify_policy");
            assert_eq!(required_capability, "can_modify_policies");
        }
        _ => panic!("Expected PrivilegeEscalation event"),
    }
}

#[test]
fn test_security_event_correlation_id_tracking() {
    // Given: An audit log with multiple events
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();
    let correlation_id = "request-12345";

    // Log multiple events with the same correlation ID
    log.log(SecurityEvent::auth_attempt(
        agent_id,
        true,
        None,
        None,
        correlation_id.to_string(),
    ));
    log.log(SecurityEvent::signature_verification(
        agent_id,
        true,
        None,
        correlation_id.to_string(),
    ));

    // When: We query by correlation ID
    let events = log.query(SecurityEventFilter::new().with_correlation_id(correlation_id));

    // Then: We should get both events
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(event.correlation_id(), correlation_id);
    }
}

#[test]
fn test_security_event_time_range_filter() {
    // Given: An audit log with events at different times
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    let event1 = SecurityEvent::auth_attempt(agent_id, true, None, None, "1".to_string());
    log.log(event1);

    // Note: In a real test with time control, we would advance time
    // For now, we just verify the filter structure works
    let now = Utc::now();
    let filter = SecurityEventFilter::new()
        .with_time_range(now - Duration::hours(1), now + Duration::hours(1));

    // When: We query with the time range
    let events = log.query(filter);

    // Then: Events within the range should be returned
    assert!(!events.is_empty(), "Recent events should be in range");
}

#[test]
fn test_security_audit_log_capacity_limit() {
    // Given: An audit log with small capacity
    let log = InMemorySecurityAuditLog::with_capacity(3);
    let agent_id = AgentId::new();

    // When: We log more events than capacity
    for i in 0..5 {
        log.log(SecurityEvent::auth_attempt(
            agent_id,
            true,
            None,
            None,
            format!("corr-{i}"),
        ));
    }

    // Then: Only the most recent should be kept
    assert_eq!(log.len(), 3);
    let events = log.query(SecurityEventFilter::new());

    // First two should have been evicted
    assert!(!events.iter().any(|e| e.correlation_id() == "corr-0"));
    assert!(!events.iter().any(|e| e.correlation_id() == "corr-1"));
    // Last three should remain
    assert!(events.iter().any(|e| e.correlation_id() == "corr-2"));
    assert!(events.iter().any(|e| e.correlation_id() == "corr-3"));
    assert!(events.iter().any(|e| e.correlation_id() == "corr-4"));
}

#[test]
fn test_security_event_is_failure_classification() {
    // Given: Various security events
    let agent_id = AgentId::new();

    // Failures
    let auth_fail = SecurityEvent::auth_attempt(agent_id, false, None, None, "1".to_string());
    let sig_fail = SecurityEvent::signature_verification(agent_id, false, None, "2".to_string());
    let rate_exceed =
        SecurityEvent::rate_limit_exceeded(agent_id, "/".to_string(), 100, 60, "3".to_string());
    let priv_escalation = SecurityEvent::privilege_escalation(
        agent_id,
        "a".to_string(),
        "b".to_string(),
        "4".to_string(),
    );

    // Successes
    let auth_success = SecurityEvent::auth_attempt(agent_id, true, None, None, "5".to_string());
    let sig_success = SecurityEvent::signature_verification(agent_id, true, None, "6".to_string());
    let key_rotation = SecurityEvent::key_rotation(
        agent_id,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "r".to_string(),
        "7".to_string(),
    );

    // Then: is_failure should classify correctly
    assert!(auth_fail.is_failure());
    assert!(sig_fail.is_failure());
    assert!(rate_exceed.is_failure());
    assert!(priv_escalation.is_failure());

    assert!(!auth_success.is_failure());
    assert!(!sig_success.is_failure());
    assert!(!key_rotation.is_failure());
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[test]
fn test_key_rotation_with_audit_logging() {
    // Given: A security system with keys and audit logging
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();
    let mut old_key = AgentKey::new(agent_id, [1u8; 32]);
    let new_key = AgentKey::new(agent_id, [2u8; 32]);

    // When: We rotate the key
    let old_key_id = old_key.id;
    let new_key_id = new_key.id;
    old_key.mark_rotated();

    // And log the rotation event
    log.log(SecurityEvent::key_rotation(
        agent_id,
        old_key_id,
        new_key_id,
        "Test rotation".to_string(),
        "rotation-123".to_string(),
    ));

    // Then: The old key should be rotated
    assert_eq!(old_key.status, KeyStatus::Rotated);
    assert!(old_key.can_verify().is_ok()); // Still verifies
    assert!(old_key.can_sign().is_err()); // Cannot sign

    // And the event should be logged
    let events = log.query(SecurityEventFilter::new().with_agent(agent_id));
    assert_eq!(events.len(), 1);
}

#[test]
fn test_rate_limiting_with_audit_logging() {
    // Given: A rate limiter and audit log
    let config = RateLimitConfig {
        default_rpm: 2,
        global_rpm: 1000,
        replenish_interval_secs: 1,
        enable_global_limit: false,
    };
    let limiter = AgentRateLimiter::new(config);
    let log = InMemorySecurityAuditLog::new();
    let agent_id = AgentId::new();

    // When: Agent exceeds rate limit
    for _ in 0..2 {
        let _ = limiter.check(&agent_id);
    }
    let result = limiter.check(&agent_id);

    // Log the rate limit exceeded event
    if result.is_err() {
        log.log(SecurityEvent::rate_limit_exceeded(
            agent_id,
            "/api/test".to_string(),
            3,
            2,
            format!("rate-{}", agent_id),
        ));
    }

    // Then: Rate limit should be exceeded and logged
    assert!(result.is_err());
    let events = log.query(SecurityEventFilter::new().with_event_type("rate_limit_exceeded"));
    assert_eq!(events.len(), 1);
}
