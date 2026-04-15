//! Event types for the `EpiGraph` system
//!
//! All significant state changes in `EpiGraph` are represented as events.
//! These events can be published to the event bus for reactive handling.

use chrono::{DateTime, Utc};
use epigraph_core::domain::{AgentRole, SuspensionReason, WorkflowState};
use epigraph_core::{AgentId, ClaimId, TruthValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a challenge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeId(Uuid);

impl ChallengeId {
    /// Create a new random `ChallengeId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a workflow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkflowId(Uuid);

impl WorkflowId {
    /// Create a new random `WorkflowId`
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for WorkflowId {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification status for a claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Claim is pending verification
    Pending,
    /// Claim is verified as true (truth >= 0.8)
    VerifiedTrue,
    /// Claim is verified as false (truth <= 0.2)
    VerifiedFalse,
    /// Claim is in uncertain state
    Uncertain,
    /// Claim is disputed with active challenges
    Disputed,
}

/// Event types in the `EpiGraph` system
///
/// Each variant represents a significant state change that other components
/// may want to react to. Events are immutable records of what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpiGraphEvent {
    /// A new claim was submitted to the knowledge graph
    ClaimSubmitted {
        /// ID of the submitted claim
        claim_id: ClaimId,
        /// ID of the agent who submitted the claim
        agent_id: AgentId,
        /// Initial truth value assigned to the claim
        initial_truth: TruthValue,
    },

    /// A claim's truth value was updated (e.g., from propagation)
    TruthUpdated {
        /// ID of the claim whose truth changed
        claim_id: ClaimId,
        /// Previous truth value
        old_truth: TruthValue,
        /// New truth value
        new_truth: TruthValue,
        /// ID of the claim that triggered this update (for propagation)
        source_claim_id: ClaimId,
    },

    /// A claim reached a verification status threshold
    ClaimVerified {
        /// ID of the verified claim
        claim_id: ClaimId,
        /// New verification status
        verification_status: VerificationStatus,
    },

    /// An agent's reputation score changed significantly
    ReputationChanged {
        /// ID of the agent whose reputation changed
        agent_id: AgentId,
        /// Previous reputation score
        old_reputation: f64,
        /// New reputation score
        new_reputation: f64,
    },

    /// A challenge was raised against a claim
    ClaimChallenged {
        /// ID of the claim being challenged
        claim_id: ClaimId,
        /// ID of the agent raising the challenge
        challenger_id: AgentId,
        /// ID of the challenge
        challenge_id: ChallengeId,
    },

    /// A workflow completed execution
    WorkflowCompleted {
        /// ID of the completed workflow
        workflow_id: WorkflowId,
        /// Final state of the workflow
        final_state: WorkflowState,
    },

    /// A new agent was created
    AgentCreated {
        /// ID of the new agent
        agent_id: AgentId,
        /// Role assigned to the agent
        role: AgentRole,
    },

    /// An agent was suspended
    AgentSuspended {
        /// ID of the suspended agent
        agent_id: AgentId,
        /// Reason for suspension
        reason: SuspensionReason,
        /// ID of the agent who performed the suspension
        suspended_by: AgentId,
    },

    /// DS belief interval updated for a claim within a frame
    BeliefUpdated {
        /// ID of the claim whose belief changed
        claim_id: Uuid,
        /// Frame in which the belief was updated
        frame_id: Uuid,
        /// Previous belief value (None if first evidence)
        old_belief: Option<f64>,
        /// New belief value
        new_belief: f64,
        /// New plausibility value
        new_plausibility: f64,
    },

    /// CDST conflict detected during combination
    ConflictDetected {
        /// Frame in which conflict was detected
        frame_id: Uuid,
        /// Claim for which conflict was detected
        claim_id: Uuid,
        /// Conflict coefficient K
        conflict_k: f64,
    },

    /// DS-Bayesian divergence spike detected
    DivergenceSpiked {
        /// Claim exhibiting divergence
        claim_id: Uuid,
        /// Frame context
        frame_id: Uuid,
        /// KL divergence value
        kl_divergence: f64,
    },
}

impl EpiGraphEvent {
    /// Get the event type as a string for filtering
    ///
    /// # Returns
    /// A string representation of the event variant name
    #[must_use]
    pub fn event_type(&self) -> String {
        match self {
            Self::ClaimSubmitted { .. } => "ClaimSubmitted".to_string(),
            Self::TruthUpdated { .. } => "TruthUpdated".to_string(),
            Self::ClaimVerified { .. } => "ClaimVerified".to_string(),
            Self::ReputationChanged { .. } => "ReputationChanged".to_string(),
            Self::ClaimChallenged { .. } => "ClaimChallenged".to_string(),
            Self::WorkflowCompleted { .. } => "WorkflowCompleted".to_string(),
            Self::AgentCreated { .. } => "AgentCreated".to_string(),
            Self::AgentSuspended { .. } => "AgentSuspended".to_string(),
            Self::BeliefUpdated { .. } => "BeliefUpdated".to_string(),
            Self::ConflictDetected { .. } => "ConflictDetected".to_string(),
            Self::DivergenceSpiked { .. } => "DivergenceSpiked".to_string(),
        }
    }
}

/// An event with its timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEvent {
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// The event itself
    pub event: EpiGraphEvent,
}

impl TimestampedEvent {
    /// Create a new timestamped event with the current time
    #[must_use]
    pub fn new(event: EpiGraphEvent) -> Self {
        Self {
            timestamp: Utc::now(),
            event,
        }
    }

    /// Create a timestamped event with a specific timestamp
    #[must_use]
    pub const fn with_timestamp(event: EpiGraphEvent, timestamp: DateTime<Utc>) -> Self {
        Self { timestamp, event }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ========================================================================
    // Event Type Classification
    // ========================================================================

    #[test]
    fn test_event_type_classification() {
        // Each EpiGraphEvent variant must return the correct event_type string.
        let cases: Vec<(EpiGraphEvent, &str)> = vec![
            (
                EpiGraphEvent::ClaimSubmitted {
                    claim_id: ClaimId::new(),
                    agent_id: AgentId::new(),
                    initial_truth: TruthValue::new(0.5).unwrap(),
                },
                "ClaimSubmitted",
            ),
            (
                EpiGraphEvent::TruthUpdated {
                    claim_id: ClaimId::new(),
                    old_truth: TruthValue::new(0.3).unwrap(),
                    new_truth: TruthValue::new(0.7).unwrap(),
                    source_claim_id: ClaimId::new(),
                },
                "TruthUpdated",
            ),
            (
                EpiGraphEvent::ClaimVerified {
                    claim_id: ClaimId::new(),
                    verification_status: VerificationStatus::Pending,
                },
                "ClaimVerified",
            ),
            (
                EpiGraphEvent::ReputationChanged {
                    agent_id: AgentId::new(),
                    old_reputation: 0.5,
                    new_reputation: 0.8,
                },
                "ReputationChanged",
            ),
            (
                EpiGraphEvent::ClaimChallenged {
                    claim_id: ClaimId::new(),
                    challenger_id: AgentId::new(),
                    challenge_id: ChallengeId::new(),
                },
                "ClaimChallenged",
            ),
            (
                EpiGraphEvent::WorkflowCompleted {
                    workflow_id: WorkflowId::new(),
                    final_state: WorkflowState::Completed,
                },
                "WorkflowCompleted",
            ),
            (
                EpiGraphEvent::AgentCreated {
                    agent_id: AgentId::new(),
                    role: AgentRole::Harvester,
                },
                "AgentCreated",
            ),
            (
                EpiGraphEvent::AgentSuspended {
                    agent_id: AgentId::new(),
                    reason: SuspensionReason::RateLimitExceeded,
                    suspended_by: AgentId::new(),
                },
                "AgentSuspended",
            ),
            (
                EpiGraphEvent::BeliefUpdated {
                    claim_id: Uuid::new_v4(),
                    frame_id: Uuid::new_v4(),
                    old_belief: Some(0.3),
                    new_belief: 0.7,
                    new_plausibility: 0.9,
                },
                "BeliefUpdated",
            ),
            (
                EpiGraphEvent::ConflictDetected {
                    frame_id: Uuid::new_v4(),
                    claim_id: Uuid::new_v4(),
                    conflict_k: 0.45,
                },
                "ConflictDetected",
            ),
            (
                EpiGraphEvent::DivergenceSpiked {
                    claim_id: Uuid::new_v4(),
                    frame_id: Uuid::new_v4(),
                    kl_divergence: 0.85,
                },
                "DivergenceSpiked",
            ),
        ];

        for (event, expected) in cases {
            assert_eq!(
                event.event_type(),
                expected,
                "event_type() for {:?} should be '{}'",
                std::mem::discriminant(&event),
                expected,
            );
        }
    }

    // ========================================================================
    // TimestampedEvent
    // ========================================================================

    #[test]
    fn test_timestamped_event_has_timestamp() {
        // TimestampedEvent::new should wrap the event with a timestamp close to now.
        let before = Utc::now();
        let event = EpiGraphEvent::ClaimSubmitted {
            claim_id: ClaimId::new(),
            agent_id: AgentId::new(),
            initial_truth: TruthValue::new(0.5).unwrap(),
        };
        let ts_event = TimestampedEvent::new(event);
        let after = Utc::now();

        assert!(
            ts_event.timestamp >= before && ts_event.timestamp <= after,
            "Timestamp should be between before and after the call"
        );
        assert!(
            matches!(ts_event.event, EpiGraphEvent::ClaimSubmitted { .. }),
            "Wrapped event should preserve its variant"
        );
    }

    #[test]
    fn test_timestamped_event_with_specific_timestamp() {
        let specific = Utc::now() - Duration::days(30);
        let event = EpiGraphEvent::AgentCreated {
            agent_id: AgentId::new(),
            role: AgentRole::Admin,
        };
        let ts_event = TimestampedEvent::with_timestamp(event, specific);

        assert_eq!(
            ts_event.timestamp, specific,
            "with_timestamp should use the provided timestamp exactly"
        );
    }

    // ========================================================================
    // Serialization round-trip
    // ========================================================================

    #[test]
    fn test_event_serialization_round_trip() {
        let event = EpiGraphEvent::ReputationChanged {
            agent_id: AgentId::new(),
            old_reputation: 0.42,
            new_reputation: 0.87,
        };

        let json = serde_json::to_string(&event).expect("Serialization should succeed");
        let restored: EpiGraphEvent =
            serde_json::from_str(&json).expect("Deserialization should succeed");

        assert_eq!(
            std::mem::discriminant(&event),
            std::mem::discriminant(&restored),
            "Round-trip should preserve variant"
        );

        match restored {
            EpiGraphEvent::ReputationChanged {
                old_reputation,
                new_reputation,
                ..
            } => {
                assert!(
                    (old_reputation - 0.42).abs() < f64::EPSILON,
                    "old_reputation should survive round-trip"
                );
                assert!(
                    (new_reputation - 0.87).abs() < f64::EPSILON,
                    "new_reputation should survive round-trip"
                );
            }
            _ => panic!("Expected ReputationChanged after round-trip"),
        }
    }

    #[test]
    fn test_timestamped_event_serialization_round_trip() {
        let event = EpiGraphEvent::ClaimVerified {
            claim_id: ClaimId::new(),
            verification_status: VerificationStatus::VerifiedTrue,
        };
        let ts = TimestampedEvent::new(event);

        let json = serde_json::to_string(&ts).expect("Serialization should succeed");
        let restored: TimestampedEvent =
            serde_json::from_str(&json).expect("Deserialization should succeed");

        assert_eq!(
            ts.timestamp, restored.timestamp,
            "Timestamp should survive round-trip"
        );
        assert_eq!(
            ts.event.event_type(),
            restored.event.event_type(),
            "Event type should survive round-trip"
        );
    }

    // ========================================================================
    // ID types
    // ========================================================================

    #[test]
    fn test_challenge_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = ChallengeId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid, "ChallengeId should wrap the given UUID");
    }

    #[test]
    fn test_workflow_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = WorkflowId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid, "WorkflowId should wrap the given UUID");
    }

    #[test]
    fn test_challenge_id_default_is_unique() {
        let a = ChallengeId::default();
        let b = ChallengeId::default();
        assert_ne!(a, b, "Default ChallengeIds should be unique");
    }

    #[test]
    fn test_workflow_id_default_is_unique() {
        let a = WorkflowId::default();
        let b = WorkflowId::default();
        assert_ne!(a, b, "Default WorkflowIds should be unique");
    }

    // ========================================================================
    // Enum variant equality
    // ========================================================================

    #[test]
    fn test_verification_status_all_variants_distinct() {
        let variants = [
            VerificationStatus::Pending,
            VerificationStatus::VerifiedTrue,
            VerificationStatus::VerifiedFalse,
            VerificationStatus::Uncertain,
            VerificationStatus::Disputed,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "Same variant should be equal");
                } else {
                    assert_ne!(a, b, "Different variants should not be equal");
                }
            }
        }
    }

    #[test]
    fn test_workflow_state_all_variants_distinct() {
        let variants = [
            WorkflowState::Created,
            WorkflowState::Running,
            WorkflowState::Completed,
            WorkflowState::Failed,
            WorkflowState::Cancelled,
            WorkflowState::TimedOut,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
