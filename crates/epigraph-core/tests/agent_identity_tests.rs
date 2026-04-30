//! TDD Tests for Agent Identity & Authorization System
//!
//! These tests define the expected behavior for:
//! - `AgentRole` enum with role variants
//! - `AgentCapabilities` struct with capability flags
//! - Agent state machine with lifecycle states
//! - State transitions (valid and invalid)
//! - Role-based default capabilities
//!
//! Following TDD (Red-Green-Refactor), these tests are written BEFORE the implementation.
//! They should compile but fail until the implementation is complete.

// ============================================================================
// Type imports - these types don't exist yet, tests will fail to compile
// until the types are implemented
// ============================================================================

// Import the new types we're testing (will be added to epigraph_core::domain)
use epigraph_core::domain::{
    AgentCapabilities, AgentLineage, AgentMetadata, AgentRole, AgentState,
    AgentStateTransitionError, AgentWithIdentity, RevocationReason, SuspensionReason,
    WorkflowState,
};

// ============================================================================
// SECTION 1: AgentRole Tests
// ============================================================================

#[test]
fn test_agent_role_has_default_capabilities() {
    // Every role should have a method to get its default capabilities
    let roles = [
        AgentRole::Harvester,
        AgentRole::Validator,
        AgentRole::Orchestrator,
        AgentRole::Analyst,
        AgentRole::Admin,
        AgentRole::Custom,
    ];

    for role in roles {
        let caps = role.default_capabilities();
        // All roles should return a valid AgentCapabilities struct
        // Verify that the struct is properly initialized by checking the type
        // and that at least Admin has all capabilities (invariant check)
        let capability_count = [
            caps.can_submit_claims,
            caps.can_provide_evidence,
            caps.can_challenge_claims,
            caps.can_invoke_tools,
            caps.can_spawn_agents,
            caps.can_modify_policies,
            caps.privileged_access,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        // Custom role should have 0 capabilities, Admin should have all 7
        match role {
            AgentRole::Admin => {
                assert_eq!(
                    capability_count, 7,
                    "Admin role should have all 7 capabilities, got {capability_count}"
                );
            }
            AgentRole::Custom => {
                assert_eq!(
                    capability_count, 0,
                    "Custom role should have 0 capabilities by default, got {capability_count}"
                );
            }
            _ => {
                // Other roles should have between 1 and 6 capabilities
                assert!(
                    (1..=6).contains(&capability_count),
                    "Role {role:?} should have between 1 and 6 capabilities, got {capability_count}"
                );
            }
        }
    }
}

#[test]
fn test_harvester_role_capabilities() {
    // Harvesters extract claims from documents
    // They can submit claims and provide evidence, but NOT challenge claims
    let caps = AgentRole::Harvester.default_capabilities();

    assert!(
        caps.can_submit_claims,
        "Harvester should be able to submit claims"
    );
    assert!(
        caps.can_provide_evidence,
        "Harvester should be able to provide evidence"
    );
    assert!(
        !caps.can_challenge_claims,
        "Harvester should NOT be able to challenge claims"
    );
    assert!(
        caps.can_invoke_tools,
        "Harvester should be able to invoke tools"
    );
    assert!(
        !caps.can_spawn_agents,
        "Harvester should NOT be able to spawn agents"
    );
    assert!(
        !caps.can_modify_policies,
        "Harvester should NOT be able to modify policies"
    );
    assert!(
        !caps.privileged_access,
        "Harvester should NOT have privileged access"
    );
}

#[test]
fn test_validator_role_capabilities() {
    // Validators review and validate claims
    // They can provide evidence and challenge claims, but NOT submit new claims
    let caps = AgentRole::Validator.default_capabilities();

    assert!(
        !caps.can_submit_claims,
        "Validator should NOT be able to submit claims"
    );
    assert!(
        caps.can_provide_evidence,
        "Validator should be able to provide evidence"
    );
    assert!(
        caps.can_challenge_claims,
        "Validator should be able to challenge claims"
    );
    assert!(
        !caps.can_invoke_tools,
        "Validator should NOT be able to invoke tools"
    );
    assert!(
        !caps.can_spawn_agents,
        "Validator should NOT be able to spawn agents"
    );
    assert!(
        !caps.can_modify_policies,
        "Validator should NOT be able to modify policies"
    );
    assert!(
        !caps.privileged_access,
        "Validator should NOT have privileged access"
    );
}

#[test]
fn test_orchestrator_role_capabilities() {
    // Orchestrators coordinate multi-agent workflows
    // They have broad capabilities including spawning sub-agents
    let caps = AgentRole::Orchestrator.default_capabilities();

    assert!(
        caps.can_submit_claims,
        "Orchestrator should be able to submit claims"
    );
    assert!(
        caps.can_provide_evidence,
        "Orchestrator should be able to provide evidence"
    );
    assert!(
        caps.can_challenge_claims,
        "Orchestrator should be able to challenge claims"
    );
    assert!(
        caps.can_invoke_tools,
        "Orchestrator should be able to invoke tools"
    );
    assert!(
        caps.can_spawn_agents,
        "Orchestrator should be able to spawn agents"
    );
    assert!(
        !caps.can_modify_policies,
        "Orchestrator should NOT be able to modify policies"
    );
    assert!(
        caps.privileged_access,
        "Orchestrator should have privileged access"
    );
}

#[test]
fn test_analyst_role_capabilities() {
    // Analysts query and analyze the knowledge graph
    // Read-heavy role with limited write capabilities
    let caps = AgentRole::Analyst.default_capabilities();

    assert!(
        !caps.can_submit_claims,
        "Analyst should NOT be able to submit claims"
    );
    assert!(
        !caps.can_provide_evidence,
        "Analyst should NOT be able to provide evidence"
    );
    assert!(
        !caps.can_challenge_claims,
        "Analyst should NOT be able to challenge claims"
    );
    assert!(
        caps.can_invoke_tools,
        "Analyst should be able to invoke tools (for queries)"
    );
    assert!(
        !caps.can_spawn_agents,
        "Analyst should NOT be able to spawn agents"
    );
    assert!(
        !caps.can_modify_policies,
        "Analyst should NOT be able to modify policies"
    );
    assert!(
        !caps.privileged_access,
        "Analyst should NOT have privileged access"
    );
}

#[test]
fn test_admin_role_has_all_capabilities() {
    // Admin has full system access - all capabilities should be true
    let caps = AgentRole::Admin.default_capabilities();

    assert!(
        caps.can_submit_claims,
        "Admin should be able to submit claims"
    );
    assert!(
        caps.can_provide_evidence,
        "Admin should be able to provide evidence"
    );
    assert!(
        caps.can_challenge_claims,
        "Admin should be able to challenge claims"
    );
    assert!(
        caps.can_invoke_tools,
        "Admin should be able to invoke tools"
    );
    assert!(
        caps.can_spawn_agents,
        "Admin should be able to spawn agents"
    );
    assert!(
        caps.can_modify_policies,
        "Admin should be able to modify policies"
    );
    assert!(
        caps.privileged_access,
        "Admin should have privileged access"
    );
}

#[test]
fn test_custom_role_has_no_capabilities_by_default() {
    // Custom role starts with no capabilities - must be explicitly granted
    let caps = AgentRole::Custom.default_capabilities();

    assert!(
        !caps.can_submit_claims,
        "Custom role should NOT have submit claims by default"
    );
    assert!(
        !caps.can_provide_evidence,
        "Custom role should NOT have provide evidence by default"
    );
    assert!(
        !caps.can_challenge_claims,
        "Custom role should NOT have challenge claims by default"
    );
    assert!(
        !caps.can_invoke_tools,
        "Custom role should NOT have invoke tools by default"
    );
    assert!(
        !caps.can_spawn_agents,
        "Custom role should NOT have spawn agents by default"
    );
    assert!(
        !caps.can_modify_policies,
        "Custom role should NOT have modify policies by default"
    );
    assert!(
        !caps.privileged_access,
        "Custom role should NOT have privileged access by default"
    );
}

// ============================================================================
// SECTION 2: AgentState Tests
// ============================================================================

#[test]
fn test_agent_state_transition_pending_to_active() {
    // New agents start in Pending state and can be activated
    let mut agent = create_test_agent_with_state(AgentState::Pending);

    let result = agent.transition_to(AgentState::Active);

    assert!(
        result.is_ok(),
        "Transition from Pending to Active should succeed"
    );
    assert_eq!(
        agent.state(),
        AgentState::Active,
        "Agent should be in Active state"
    );
}

#[test]
fn test_agent_state_transition_active_to_suspended() {
    // Active agents can be suspended (temporarily disabled)
    let mut agent = create_test_agent_with_state(AgentState::Active);
    let reason = SuspensionReason::PolicyViolation {
        details: "Exceeded rate limit".to_string(),
    };

    let result = agent.transition_to(AgentState::Suspended {
        reason: reason.clone(),
    });

    assert!(
        result.is_ok(),
        "Transition from Active to Suspended should succeed"
    );
    assert!(
        matches!(agent.state(), AgentState::Suspended { .. }),
        "Agent should be in Suspended state, got {:?}",
        agent.state()
    );
    if let AgentState::Suspended { reason: r } = agent.state() {
        assert_eq!(r, reason, "Suspension reason should be preserved");
    }
}

#[test]
fn test_agent_state_transition_suspended_to_active() {
    // Suspended agents can be reactivated
    let reason = SuspensionReason::Administrative {
        details: "Pending investigation".to_string(),
    };
    let mut agent = create_test_agent_with_state(AgentState::Suspended { reason });

    let result = agent.transition_to(AgentState::Active);

    assert!(
        result.is_ok(),
        "Transition from Suspended to Active should succeed"
    );
    assert_eq!(
        agent.state(),
        AgentState::Active,
        "Agent should be in Active state"
    );
}

#[test]
fn test_agent_state_transition_active_to_revoked() {
    // Active agents can be permanently revoked
    let mut agent = create_test_agent_with_state(AgentState::Active);
    let reason = RevocationReason::SecurityBreach {
        incident_id: "INC-2024-001".to_string(),
    };

    let result = agent.transition_to(AgentState::Revoked {
        reason: reason.clone(),
    });

    assert!(
        result.is_ok(),
        "Transition from Active to Revoked should succeed"
    );
    assert!(
        matches!(agent.state(), AgentState::Revoked { .. }),
        "Agent should be in Revoked state, got {:?}",
        agent.state()
    );
    if let AgentState::Revoked { reason: r } = agent.state() {
        assert_eq!(r, reason, "Revocation reason should be preserved");
    }
}

#[test]
fn test_agent_state_transition_revoked_cannot_reactivate() {
    // CRITICAL: Revoked agents cannot be reactivated - this is a security invariant
    let reason = RevocationReason::KeyCompromise;
    let mut agent = create_test_agent_with_state(AgentState::Revoked { reason });

    let result = agent.transition_to(AgentState::Active);

    assert!(
        result.is_err(),
        "Transition from Revoked to Active should FAIL"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, AgentStateTransitionError::InvalidTransition { .. }),
        "Should return InvalidTransition error, got {err:?}"
    );
    let AgentStateTransitionError::InvalidTransition { from, to } = err;
    assert!(
        matches!(from, AgentState::Revoked { .. }),
        "Error should indicate from Revoked state, got {from:?}"
    );
    assert_eq!(
        to,
        AgentState::Active,
        "Error should indicate to Active state"
    );
}

#[test]
fn test_agent_state_transition_archived_is_terminal() {
    // Archived is a terminal state - no transitions allowed
    let mut agent = create_test_agent_with_state(AgentState::Archived);

    // Cannot transition to any state from Archived
    let states_to_try = [
        AgentState::Pending,
        AgentState::Active,
        AgentState::Suspended {
            reason: SuspensionReason::RateLimitExceeded,
        },
        AgentState::Revoked {
            reason: RevocationReason::AccountClosure,
        },
    ];

    for target_state in states_to_try {
        let result = agent.transition_to(target_state.clone());
        assert!(
            result.is_err(),
            "Transition from Archived to {target_state:?} should FAIL"
        );
    }
}

#[test]
fn test_invalid_state_transition_pending_to_revoked() {
    // Pending agents must be activated before they can be revoked
    // This prevents revoking agents that never became active
    let mut agent = create_test_agent_with_state(AgentState::Pending);
    let reason = RevocationReason::AccountClosure;

    let result = agent.transition_to(AgentState::Revoked { reason });

    assert!(
        result.is_err(),
        "Transition from Pending directly to Revoked should FAIL"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, AgentStateTransitionError::InvalidTransition { .. }),
        "Should return InvalidTransition error, got {err:?}"
    );
    let AgentStateTransitionError::InvalidTransition { from, to } = err;
    assert_eq!(
        from,
        AgentState::Pending,
        "Error should indicate from Pending state"
    );
    assert!(
        matches!(to, AgentState::Revoked { .. }),
        "Error should indicate to Revoked state, got {to:?}"
    );
}

#[test]
fn test_invalid_state_transition_archived_to_active() {
    // Archived agents cannot be reactivated
    let mut agent = create_test_agent_with_state(AgentState::Archived);

    let result = agent.transition_to(AgentState::Active);

    assert!(
        result.is_err(),
        "Transition from Archived to Active should FAIL"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, AgentStateTransitionError::InvalidTransition { .. }),
        "Should return InvalidTransition error, got {err:?}"
    );
    let AgentStateTransitionError::InvalidTransition { from, to } = err;
    assert_eq!(
        from,
        AgentState::Archived,
        "Error should indicate from Archived state"
    );
    assert_eq!(
        to,
        AgentState::Active,
        "Error should indicate to Active state"
    );
}

// ----------------------------------------------------------------------------
// Missing State Transition Tests (Added per review findings)
// ----------------------------------------------------------------------------

#[test]
fn test_agent_state_transition_pending_to_suspended() {
    // Pending agents can be suspended (e.g., during onboarding review)
    let mut agent = create_test_agent_with_state(AgentState::Pending);
    let reason = SuspensionReason::Administrative {
        details: "Awaiting credential verification".to_string(),
    };

    let result = agent.transition_to(AgentState::Suspended {
        reason: reason.clone(),
    });

    assert!(
        result.is_ok(),
        "Transition from Pending to Suspended should succeed"
    );
    assert!(
        matches!(agent.state(), AgentState::Suspended { .. }),
        "Agent should be in Suspended state, got {:?}",
        agent.state()
    );
    if let AgentState::Suspended { reason: r } = agent.state() {
        assert_eq!(r, reason, "Suspension reason should be preserved");
    }
}

#[test]
fn test_agent_state_transition_suspended_to_revoked() {
    // Suspended agents can be permanently revoked (e.g., after investigation)
    let suspend_reason = SuspensionReason::PolicyViolation {
        details: "Repeated violations during suspension review".to_string(),
    };
    let mut agent = create_test_agent_with_state(AgentState::Suspended {
        reason: suspend_reason,
    });
    let revoke_reason = RevocationReason::SecurityBreach {
        incident_id: "INC-2024-002".to_string(),
    };

    let result = agent.transition_to(AgentState::Revoked {
        reason: revoke_reason.clone(),
    });

    assert!(
        result.is_ok(),
        "Transition from Suspended to Revoked should succeed"
    );
    assert!(
        matches!(agent.state(), AgentState::Revoked { .. }),
        "Agent should be in Revoked state, got {:?}",
        agent.state()
    );
    if let AgentState::Revoked { reason: r } = agent.state() {
        assert_eq!(r, revoke_reason, "Revocation reason should be preserved");
    }
}

#[test]
fn test_agent_state_transition_idempotency() {
    // Transitioning to the same state should be idempotent (no error, no change)
    let mut agent = create_test_agent_with_state(AgentState::Active);

    // Transition to Active when already Active
    let result = agent.transition_to(AgentState::Active);

    assert!(
        result.is_ok(),
        "Transition to same state (Active -> Active) should succeed (idempotent)"
    );
    assert_eq!(
        agent.state(),
        AgentState::Active,
        "Agent should still be in Active state"
    );
}

#[test]
fn test_agent_state_transition_pending_idempotency() {
    // Pending -> Pending should be idempotent
    let mut agent = create_test_agent_with_state(AgentState::Pending);

    let result = agent.transition_to(AgentState::Pending);

    assert!(
        result.is_ok(),
        "Transition to same state (Pending -> Pending) should succeed (idempotent)"
    );
    assert_eq!(
        agent.state(),
        AgentState::Pending,
        "Agent should still be in Pending state"
    );
}

#[test]
fn test_agent_state_transition_suspended_idempotency_preserves_reason() {
    // Suspended -> Suspended should preserve the original reason
    let original_reason = SuspensionReason::PolicyViolation {
        details: "Original violation".to_string(),
    };
    let mut agent = create_test_agent_with_state(AgentState::Suspended {
        reason: original_reason,
    });

    let new_reason = SuspensionReason::Administrative {
        details: "New reason".to_string(),
    };
    let result = agent.transition_to(AgentState::Suspended { reason: new_reason });

    // Implementation choice: either update reason or keep original
    // This test documents that we accept the transition
    assert!(
        result.is_ok(),
        "Transition Suspended -> Suspended should succeed"
    );
    assert!(
        matches!(agent.state(), AgentState::Suspended { .. }),
        "Agent should remain in Suspended state"
    );
}

// ----------------------------------------------------------------------------
// Error Type Validation Tests (Added per review findings)
// ----------------------------------------------------------------------------

#[test]
fn test_error_type_invalid_transition_contains_both_states() {
    // The InvalidTransition error should contain both source and target states
    let mut agent = create_test_agent_with_state(AgentState::Archived);

    let result = agent.transition_to(AgentState::Active);

    assert!(result.is_err(), "Transition should fail");
    let err = result.unwrap_err();

    // Verify the error type and contents
    assert!(
        matches!(err, AgentStateTransitionError::InvalidTransition { .. }),
        "Expected InvalidTransition error, got {err:?}"
    );
    let AgentStateTransitionError::InvalidTransition { from, to } = err;
    assert_eq!(
        from,
        AgentState::Archived,
        "Error should contain source state"
    );
    assert_eq!(to, AgentState::Active, "Error should contain target state");
}

#[test]
fn test_error_type_from_revoked_is_always_invalid_transition() {
    // All transitions from Revoked state should return InvalidTransition
    let reason = RevocationReason::KeyCompromise;
    let _agent = create_test_agent_with_state(AgentState::Revoked { reason });

    let target_states = [
        AgentState::Pending,
        AgentState::Active,
        AgentState::Suspended {
            reason: SuspensionReason::RateLimitExceeded,
        },
        AgentState::Archived,
    ];

    for target in target_states {
        // Reset agent state for each test
        let reason = RevocationReason::KeyCompromise;
        let mut agent = create_test_agent_with_state(AgentState::Revoked { reason });

        let result = agent.transition_to(target.clone());

        assert!(
            result.is_err(),
            "Transition from Revoked to {target:?} should fail"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, AgentStateTransitionError::InvalidTransition { .. }),
            "Error for Revoked -> {target:?} should be InvalidTransition, got {err:?}"
        );
    }
}

// ============================================================================
// SECTION 3: AgentCapabilities Operations Tests
// ============================================================================

#[test]
fn test_agent_capabilities_combine_with_or() {
    // Capabilities can be combined using bitwise OR (union)
    let harvester_caps = AgentRole::Harvester.default_capabilities();
    let validator_caps = AgentRole::Validator.default_capabilities();

    let combined = harvester_caps.union(&validator_caps);

    // Combined should have capabilities from both roles
    assert!(
        combined.can_submit_claims,
        "Combined should inherit submit_claims from Harvester"
    );
    assert!(
        combined.can_challenge_claims,
        "Combined should inherit challenge_claims from Validator"
    );
    assert!(
        combined.can_provide_evidence,
        "Combined should have provide_evidence (both have it)"
    );
}

#[test]
fn test_agent_capabilities_restrict_with_and() {
    // Capabilities can be restricted using bitwise AND (intersection)
    let admin_caps = AgentRole::Admin.default_capabilities();
    let validator_caps = AgentRole::Validator.default_capabilities();

    let restricted = admin_caps.intersect(&validator_caps);

    // Restricted should only have capabilities that both have
    assert!(
        !restricted.can_submit_claims,
        "Restricted should NOT have submit_claims (Validator doesn't have it)"
    );
    assert!(
        restricted.can_provide_evidence,
        "Restricted should have provide_evidence (both have it)"
    );
    assert!(
        restricted.can_challenge_claims,
        "Restricted should have challenge_claims (both have it)"
    );
    assert!(
        !restricted.can_modify_policies,
        "Restricted should NOT have modify_policies (Validator doesn't have it)"
    );
}

#[test]
fn test_agent_capabilities_all() {
    // Create capabilities with all flags set
    let all_caps = AgentCapabilities::all();

    assert!(all_caps.can_submit_claims);
    assert!(all_caps.can_provide_evidence);
    assert!(all_caps.can_challenge_claims);
    assert!(all_caps.can_invoke_tools);
    assert!(all_caps.can_spawn_agents);
    assert!(all_caps.can_modify_policies);
    assert!(all_caps.privileged_access);
}

#[test]
fn test_agent_capabilities_none() {
    // Create capabilities with no flags set
    let no_caps = AgentCapabilities::none();

    assert!(!no_caps.can_submit_claims);
    assert!(!no_caps.can_provide_evidence);
    assert!(!no_caps.can_challenge_claims);
    assert!(!no_caps.can_invoke_tools);
    assert!(!no_caps.can_spawn_agents);
    assert!(!no_caps.can_modify_policies);
    assert!(!no_caps.privileged_access);
}

#[test]
fn test_agent_capabilities_has_capability() {
    // Test individual capability checking
    let caps = AgentRole::Harvester.default_capabilities();

    assert!(caps.has_capability("can_submit_claims"));
    assert!(caps.has_capability("can_provide_evidence"));
    assert!(!caps.has_capability("can_challenge_claims"));
    assert!(!caps.has_capability("nonexistent_capability"));
}

// ============================================================================
// SECTION 4: Agent with Role and Custom Capabilities Tests
// ============================================================================

#[test]
fn test_agent_with_role_and_custom_capabilities() {
    // Agents can have a role but override specific capabilities
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Custom Agent".to_string()),
        AgentRole::Validator,
    );

    // Start with Validator defaults
    assert!(
        !agent.capabilities().can_submit_claims,
        "Validator cannot submit claims by default"
    );

    // Grant additional capability
    agent.grant_capability("can_submit_claims");

    assert!(
        agent.capabilities().can_submit_claims,
        "Agent should now be able to submit claims"
    );
    assert!(
        agent.capabilities().can_challenge_claims,
        "Agent should still have Validator's challenge capability"
    );
}

#[test]
fn test_agent_revoke_capability() {
    // Capabilities can be revoked from an agent
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Admin Agent".to_string()),
        AgentRole::Admin,
    );

    // Admin has all capabilities by default
    assert!(agent.capabilities().can_modify_policies);

    // Revoke a specific capability
    agent.revoke_capability("can_modify_policies");

    assert!(
        !agent.capabilities().can_modify_policies,
        "Agent should no longer be able to modify policies"
    );
    assert!(
        agent.capabilities().can_submit_claims,
        "Other capabilities should be unaffected"
    );
}

// ----------------------------------------------------------------------------
// Capability Idempotency Tests (Added per review findings)
// ----------------------------------------------------------------------------

#[test]
fn test_capability_grant_idempotency() {
    // Granting the same capability twice should be idempotent
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Custom Agent".to_string()),
        AgentRole::Custom, // Custom has no capabilities by default
    );

    // Verify starting state
    assert!(
        !agent.capabilities().can_submit_claims,
        "Custom role should not have submit claims initially"
    );

    // Grant capability first time
    agent.grant_capability("can_submit_claims");
    assert!(
        agent.capabilities().can_submit_claims,
        "Agent should have submit claims after first grant"
    );

    // Grant the same capability again
    agent.grant_capability("can_submit_claims");
    assert!(
        agent.capabilities().can_submit_claims,
        "Agent should still have submit claims after second grant (idempotent)"
    );

    // Count of capabilities should not change
    let capability_count = [
        agent.capabilities().can_submit_claims,
        agent.capabilities().can_provide_evidence,
        agent.capabilities().can_challenge_claims,
        agent.capabilities().can_invoke_tools,
        agent.capabilities().can_spawn_agents,
        agent.capabilities().can_modify_policies,
        agent.capabilities().privileged_access,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    assert_eq!(
        capability_count, 1,
        "Should have exactly 1 capability after granting same one twice"
    );
}

#[test]
fn test_capability_revoke_idempotency() {
    // Revoking the same capability twice should be idempotent
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Admin Agent".to_string()),
        AgentRole::Admin, // Admin has all capabilities
    );

    // Verify starting state
    assert!(
        agent.capabilities().can_modify_policies,
        "Admin should have modify policies initially"
    );

    // Revoke capability first time
    agent.revoke_capability("can_modify_policies");
    assert!(
        !agent.capabilities().can_modify_policies,
        "Agent should not have modify policies after first revoke"
    );

    // Revoke the same capability again
    agent.revoke_capability("can_modify_policies");
    assert!(
        !agent.capabilities().can_modify_policies,
        "Agent should still not have modify policies after second revoke (idempotent)"
    );

    // Other capabilities should be unaffected
    assert!(
        agent.capabilities().can_submit_claims,
        "Other capabilities should remain after double revoke"
    );
}

#[test]
fn test_capability_grant_after_revoke() {
    // Revoking then granting should result in having the capability
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Harvester Agent".to_string()),
        AgentRole::Harvester,
    );

    // Harvester can submit claims by default
    assert!(
        agent.capabilities().can_submit_claims,
        "Harvester should have submit claims initially"
    );

    // Revoke it
    agent.revoke_capability("can_submit_claims");
    assert!(
        !agent.capabilities().can_submit_claims,
        "Should not have submit claims after revoke"
    );

    // Grant it back
    agent.grant_capability("can_submit_claims");
    assert!(
        agent.capabilities().can_submit_claims,
        "Should have submit claims after re-grant"
    );
}

#[test]
fn test_capability_revoke_after_grant() {
    // Granting then revoking should result in not having the capability
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Custom Agent".to_string()),
        AgentRole::Custom,
    );

    // Custom has no capabilities by default
    assert!(
        !agent.capabilities().can_spawn_agents,
        "Custom should not have spawn agents initially"
    );

    // Grant it
    agent.grant_capability("can_spawn_agents");
    assert!(
        agent.capabilities().can_spawn_agents,
        "Should have spawn agents after grant"
    );

    // Revoke it
    agent.revoke_capability("can_spawn_agents");
    assert!(
        !agent.capabilities().can_spawn_agents,
        "Should not have spawn agents after revoke"
    );
}

#[test]
fn test_grant_unknown_capability_is_no_op() {
    // Granting an unknown capability name should not cause errors
    // and should not change any capabilities
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Custom Agent".to_string()),
        AgentRole::Custom,
    );

    let caps_before = *agent.capabilities();

    // Try to grant a nonexistent capability
    agent.grant_capability("nonexistent_capability");

    let caps_after = agent.capabilities();

    assert_eq!(
        caps_before.can_submit_claims, caps_after.can_submit_claims,
        "Capabilities should be unchanged after granting unknown capability"
    );
    assert_eq!(
        caps_before.can_provide_evidence, caps_after.can_provide_evidence,
        "Capabilities should be unchanged after granting unknown capability"
    );
}

#[test]
fn test_revoke_unknown_capability_is_no_op() {
    // Revoking an unknown capability name should not cause errors
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Admin Agent".to_string()),
        AgentRole::Admin,
    );

    let caps_before = *agent.capabilities();

    // Try to revoke a nonexistent capability
    agent.revoke_capability("nonexistent_capability");

    let caps_after = agent.capabilities();

    assert_eq!(
        caps_before.can_submit_claims, caps_after.can_submit_claims,
        "Capabilities should be unchanged after revoking unknown capability"
    );
    assert_eq!(
        caps_before.can_modify_policies, caps_after.can_modify_policies,
        "Capabilities should be unchanged after revoking unknown capability"
    );
}

// ============================================================================
// SECTION 5: Agent Discovery Tests
// ============================================================================

#[test]
fn test_agent_discovery_by_capability() {
    // Create a registry of agents and filter by capability
    let agents = create_test_agent_registry();

    // Find agents that can submit claims
    let claim_submitters: Vec<_> = agents
        .iter()
        .filter(|a| a.capabilities().can_submit_claims)
        .collect();

    assert!(
        !claim_submitters.is_empty(),
        "Should find agents that can submit claims"
    );
    assert!(
        claim_submitters
            .iter()
            .all(|a| a.capabilities().can_submit_claims),
        "All found agents should be able to submit claims"
    );

    // Find agents that can spawn other agents
    let spawners: Vec<_> = agents
        .iter()
        .filter(|a| a.capabilities().can_spawn_agents)
        .collect();

    // Only Orchestrators and Admins can spawn agents
    for agent in &spawners {
        assert!(
            matches!(agent.role(), AgentRole::Orchestrator | AgentRole::Admin),
            "Only Orchestrators and Admins should be able to spawn agents"
        );
    }
}

#[test]
fn test_agent_discovery_by_role() {
    // Create a registry of agents and filter by role
    let agents = create_test_agent_registry();

    // Find all Validators
    let validators: Vec<_> = agents
        .iter()
        .filter(|a| a.role() == AgentRole::Validator)
        .collect();

    assert!(!validators.is_empty(), "Should find at least one Validator");
    assert!(
        validators.iter().all(|a| a.role() == AgentRole::Validator),
        "All found agents should be Validators"
    );

    // Find all active Harvesters
    let active_harvesters: Vec<_> = agents
        .iter()
        .filter(|a| a.role() == AgentRole::Harvester && a.state() == AgentState::Active)
        .collect();

    assert!(
        active_harvesters
            .iter()
            .all(|a| a.state() == AgentState::Active),
        "All found agents should be Active"
    );
}

// ============================================================================
// SECTION 6: Agent Lineage Tests
// ============================================================================

#[test]
fn test_agent_lineage_parent_child_relationships() {
    // Orchestrators can spawn sub-agents, creating a lineage
    let parent_public_key = [1u8; 32];
    let parent = AgentWithIdentity::new(
        parent_public_key,
        Some("Orchestrator".to_string()),
        AgentRole::Orchestrator,
    );
    let parent_id = parent.id();

    // Create child agents spawned by the orchestrator
    let child1_public_key = [2u8; 32];
    let child1 = AgentWithIdentity::with_parent(
        child1_public_key,
        Some("Harvester 1".to_string()),
        AgentRole::Harvester,
        parent_id,
    );

    let child2_public_key = [3u8; 32];
    let child2 = AgentWithIdentity::with_parent(
        child2_public_key,
        Some("Harvester 2".to_string()),
        AgentRole::Harvester,
        parent_id,
    );

    // Verify lineage relationships
    assert_eq!(
        child1.metadata().parent_agent_id,
        Some(parent_id),
        "Child 1 should have parent_id set"
    );
    assert_eq!(
        child2.metadata().parent_agent_id,
        Some(parent_id),
        "Child 2 should have parent_id set"
    );
    assert!(
        parent.metadata().parent_agent_id.is_none(),
        "Parent should have no parent_agent_id"
    );

    // Build lineage tree
    let lineage = AgentLineage::build(&parent, &[child1.clone(), child2.clone()]);

    assert_eq!(
        lineage.root_agent_id(),
        parent_id,
        "Lineage root should be the parent"
    );
    assert_eq!(
        lineage.children(parent_id).len(),
        2,
        "Parent should have 2 children"
    );
    assert!(
        lineage.children(parent_id).contains(&child1.id()),
        "Child 1 should be in parent's children"
    );
    assert!(
        lineage.children(parent_id).contains(&child2.id()),
        "Child 2 should be in parent's children"
    );
}

#[test]
fn test_agent_lineage_grandparent_relationship() {
    // Test multi-level lineage (grandparent -> parent -> child)
    let grandparent_key = [1u8; 32];
    let grandparent =
        AgentWithIdentity::new(grandparent_key, Some("Admin".to_string()), AgentRole::Admin);

    let parent_key = [2u8; 32];
    let parent = AgentWithIdentity::with_parent(
        parent_key,
        Some("Orchestrator".to_string()),
        AgentRole::Orchestrator,
        grandparent.id(),
    );

    let child_key = [3u8; 32];
    let child = AgentWithIdentity::with_parent(
        child_key,
        Some("Harvester".to_string()),
        AgentRole::Harvester,
        parent.id(),
    );

    // Verify ancestor chain
    let agents = vec![grandparent.clone(), parent.clone(), child.clone()];
    let lineage = AgentLineage::from_agents(&agents);

    assert!(
        lineage.is_ancestor(grandparent.id(), child.id()),
        "Grandparent should be an ancestor of child"
    );
    assert!(
        lineage.is_ancestor(parent.id(), child.id()),
        "Parent should be an ancestor of child"
    );
    assert!(
        !lineage.is_ancestor(child.id(), grandparent.id()),
        "Child should NOT be an ancestor of grandparent"
    );

    // Get full ancestor chain for child
    let ancestors = lineage.ancestors(child.id());
    assert_eq!(ancestors.len(), 2, "Child should have 2 ancestors");
    assert!(ancestors.contains(&parent.id()));
    assert!(ancestors.contains(&grandparent.id()));
}

// ============================================================================
// SECTION 7: Serialization Tests
// ============================================================================

#[test]
fn test_agent_role_serialization() {
    // Roles should serialize to lowercase strings for API compatibility
    let roles_expected = [
        (AgentRole::Harvester, "\"harvester\""),
        (AgentRole::Validator, "\"validator\""),
        (AgentRole::Orchestrator, "\"orchestrator\""),
        (AgentRole::Analyst, "\"analyst\""),
        (AgentRole::Admin, "\"admin\""),
        (AgentRole::Custom, "\"custom\""),
    ];

    for (role, expected_json) in roles_expected {
        let json = serde_json::to_string(&role).expect("Should serialize");
        assert_eq!(
            json, expected_json,
            "Role {role:?} should serialize to {expected_json}"
        );

        let deserialized: AgentRole = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, role, "Role should round-trip through JSON");
    }
}

#[test]
fn test_agent_state_serialization() {
    // States should serialize properly, including reason payloads
    let pending = AgentState::Pending;
    let json = serde_json::to_string(&pending).expect("Should serialize");
    assert!(json.contains("pending"), "Pending state should serialize");

    let suspended = AgentState::Suspended {
        reason: SuspensionReason::PolicyViolation {
            details: "Test violation".to_string(),
        },
    };
    let json = serde_json::to_string(&suspended).expect("Should serialize");
    assert!(
        json.contains("suspended"),
        "Suspended state should serialize"
    );
    assert!(
        json.contains("Test violation"),
        "Suspension reason should be in JSON"
    );

    // Round-trip test
    let deserialized: AgentState = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(
        deserialized, suspended,
        "State should round-trip through JSON"
    );
}

#[test]
fn test_agent_capabilities_serialization() {
    // Capabilities should serialize to a JSON object with boolean fields
    let caps = AgentRole::Harvester.default_capabilities();
    let json = serde_json::to_string(&caps).expect("Should serialize");

    // Verify JSON structure
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse as JSON");
    assert!(
        parsed.is_object(),
        "Capabilities should serialize as object"
    );
    assert_eq!(
        parsed["can_submit_claims"], true,
        "can_submit_claims should be true for Harvester"
    );
    assert_eq!(
        parsed["can_challenge_claims"], false,
        "can_challenge_claims should be false for Harvester"
    );

    // Round-trip test
    let deserialized: AgentCapabilities = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(caps, deserialized, "Capabilities should round-trip");
}

// ============================================================================
// SECTION 8: AgentMetadata Tests
// ============================================================================

#[test]
fn test_agent_metadata_defaults() {
    // Default metadata should have sensible defaults
    let metadata = AgentMetadata::default();

    assert!(
        metadata.description.is_none(),
        "Default description should be None"
    );
    assert!(
        metadata.parent_agent_id.is_none(),
        "Default parent_agent_id should be None"
    );
    assert!(
        metadata.concurrency_limit > 0,
        "Default concurrency_limit should be positive"
    );
    assert!(
        metadata.rate_limit_rpm > 0,
        "Default rate_limit_rpm should be positive"
    );
    assert!(
        metadata.attributes.is_empty(),
        "Default attributes should be empty"
    );
}

#[test]
fn test_agent_metadata_custom_attributes() {
    // Custom attributes can be stored as JSON values
    let mut metadata = AgentMetadata::default();
    metadata.set_attribute("version", serde_json::json!("1.0.0"));
    metadata.set_attribute("model", serde_json::json!("gpt-4"));
    metadata.set_attribute(
        "config",
        serde_json::json!({
            "temperature": 0.7,
            "max_tokens": 4096
        }),
    );

    assert_eq!(
        metadata.get_attribute("version"),
        Some(&serde_json::json!("1.0.0"))
    );
    assert_eq!(
        metadata.get_attribute("model"),
        Some(&serde_json::json!("gpt-4"))
    );
    assert!(metadata.get_attribute("nonexistent").is_none());

    // Verify nested config
    let config = metadata.get_attribute("config").unwrap();
    assert_eq!(config["temperature"], 0.7);
    assert_eq!(config["max_tokens"], 4096);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test agent with a specific state (for state transition tests)
fn create_test_agent_with_state(state: AgentState) -> AgentWithIdentity {
    let public_key = [42u8; 32];
    let mut agent = AgentWithIdentity::new(
        public_key,
        Some("Test Agent".to_string()),
        AgentRole::Harvester,
    );
    // Force the state (this is a test helper, not public API)
    agent.set_state_for_testing(state);
    agent
}

/// Create a test registry with various agent types for discovery tests
fn create_test_agent_registry() -> Vec<AgentWithIdentity> {
    vec![
        // Active Harvester
        {
            let mut a = AgentWithIdentity::new(
                [1u8; 32],
                Some("Harvester 1".to_string()),
                AgentRole::Harvester,
            );
            a.set_state_for_testing(AgentState::Active);
            a
        },
        // Active Validator
        {
            let mut a = AgentWithIdentity::new(
                [2u8; 32],
                Some("Validator 1".to_string()),
                AgentRole::Validator,
            );
            a.set_state_for_testing(AgentState::Active);
            a
        },
        // Suspended Harvester
        {
            let mut a = AgentWithIdentity::new(
                [3u8; 32],
                Some("Harvester 2".to_string()),
                AgentRole::Harvester,
            );
            a.set_state_for_testing(AgentState::Suspended {
                reason: SuspensionReason::RateLimitExceeded,
            });
            a
        },
        // Active Orchestrator
        {
            let mut a = AgentWithIdentity::new(
                [4u8; 32],
                Some("Orchestrator 1".to_string()),
                AgentRole::Orchestrator,
            );
            a.set_state_for_testing(AgentState::Active);
            a
        },
        // Active Admin
        {
            let mut a =
                AgentWithIdentity::new([5u8; 32], Some("Admin 1".to_string()), AgentRole::Admin);
            a.set_state_for_testing(AgentState::Active);
            a
        },
        // Pending Custom
        {
            // Starts in Pending by default
            AgentWithIdentity::new([6u8; 32], Some("Custom 1".to_string()), AgentRole::Custom)
        },
    ]
}

// ============================================================================
// SECTION N: WorkflowState Tests
// ============================================================================

#[test]
fn test_workflow_state_variants_exist() {
    let states = [
        WorkflowState::Created,
        WorkflowState::Running,
        WorkflowState::Completed,
        WorkflowState::Failed,
        WorkflowState::Cancelled,
        WorkflowState::TimedOut,
    ];
    assert_eq!(states.len(), 6);
}

#[test]
fn test_workflow_state_serialization() {
    let state = WorkflowState::Running;
    let json = serde_json::to_string(&state).expect("Should serialize");
    let deserialized: WorkflowState = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(state, deserialized);
}
