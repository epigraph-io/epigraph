//! Challenge and dispute mechanism for claims.
//!
//! Challenges are how agents dispute existing claims with counter-evidence.
//! This is a core anti-sycophancy mechanism: any agent may challenge a claim,
//! and high DS conflict (K ≥ threshold) auto-generates a challenge.

use crate::domain::{AgentId, ClaimId};
use crate::truth::TruthValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

// ── ChallengeId ─────────────────────────────────────────────────────────────

/// Type-safe identifier for a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeId(Uuid);

impl ChallengeId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

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

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "challenge:{}", self.0)
    }
}

impl From<Uuid> for ChallengeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<ChallengeId> for Uuid {
    fn from(id: ChallengeId) -> Self {
        id.0
    }
}

// ── Error types ──────────────────────────────────────────────────────────────

/// Errors from the challenge system.
#[derive(Error, Debug)]
pub enum ChallengeError {
    #[error("Challenge {challenge_id} not found")]
    NotFound { challenge_id: ChallengeId },

    #[error("Claim {claim_id} not found")]
    ClaimNotFound { claim_id: ClaimId },

    #[error("Invalid challenge state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Agent not authorized to {action}")]
    Unauthorized { action: String },

    #[error("A pending challenge already exists for claim {claim_id}")]
    Duplicate { claim_id: ClaimId },
}

// ── Challenge types ──────────────────────────────────────────────────────────

/// Type of challenge being raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Evidence is insufficient to support the claim.
    InsufficientEvidence,
    /// Evidence is outdated and may no longer be valid.
    OutdatedEvidence,
    /// The methodology used to derive the claim is flawed.
    FlawedMethodology,
    /// Contradicting evidence exists.
    ContradictingEvidence,
    /// The claim contains a factual error.
    FactualError,
}

/// State of a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChallengeState {
    /// Challenge submitted, pending review.
    Pending,
    /// Challenge is being reviewed.
    UnderReview,
    /// Challenge accepted, claim truth reduced.
    Accepted,
    /// Challenge rejected, original claim upheld.
    Rejected,
    /// Challenge withdrawn by challenger.
    Withdrawn,
}

impl ChallengeState {
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected | Self::Withdrawn)
    }

    #[must_use]
    pub const fn can_transition_to(&self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Pending, Self::UnderReview | Self::Withdrawn)
                | (
                    Self::UnderReview,
                    Self::Accepted | Self::Rejected | Self::Withdrawn
                )
        )
    }
}

impl fmt::Display for ChallengeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::UnderReview => write!(f, "under_review"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
            Self::Withdrawn => write!(f, "withdrawn"),
        }
    }
}

/// Resolution applied when a challenge is decided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeResolution {
    Accept { truth_reduction: f64 },
    Reject { reason: String },
}

// ── Challenge ────────────────────────────────────────────────────────────────

/// A challenge to an existing claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: ChallengeId,
    pub claim_id: ClaimId,
    pub challenger_id: AgentId,
    pub challenge_type: ChallengeType,
    pub explanation: String,
    pub state: ChallengeState,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<AgentId>,
}

impl Challenge {
    #[must_use]
    pub fn new(
        claim_id: ClaimId,
        challenger_id: AgentId,
        challenge_type: ChallengeType,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            id: ChallengeId::new(),
            claim_id,
            challenger_id,
            challenge_type,
            explanation: explanation.into(),
            state: ChallengeState::Pending,
            created_at: Utc::now(),
            resolved_at: None,
            resolved_by: None,
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn with_id(
        id: ChallengeId,
        claim_id: ClaimId,
        challenger_id: AgentId,
        challenge_type: ChallengeType,
        explanation: impl Into<String>,
        state: ChallengeState,
        created_at: DateTime<Utc>,
        resolved_at: Option<DateTime<Utc>>,
        resolved_by: Option<AgentId>,
    ) -> Self {
        Self {
            id,
            claim_id,
            challenger_id,
            challenge_type,
            explanation: explanation.into(),
            state,
            created_at,
            resolved_at,
            resolved_by,
        }
    }

    /// Transition to a new state.
    ///
    /// # Errors
    /// Returns [`ChallengeError::InvalidStateTransition`] if the transition is not allowed.
    pub fn transition_to(&mut self, new_state: ChallengeState) -> Result<(), ChallengeError> {
        if !self.state.can_transition_to(new_state) {
            return Err(ChallengeError::InvalidStateTransition {
                from: self.state.to_string(),
                to: new_state.to_string(),
            });
        }
        self.state = new_state;
        if new_state.is_final() {
            self.resolved_at = Some(Utc::now());
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self.state, ChallengeState::Pending)
    }

    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.state.is_final()
    }
}

// ── ChallengeService ─────────────────────────────────────────────────────────

/// In-memory service for managing challenges.
///
/// In a production deployment this would delegate to a database; the in-memory
/// store is sufficient for the kernel's single-process use-case.
pub struct ChallengeService {
    challenges: std::sync::RwLock<Vec<Challenge>>,
}

impl ChallengeService {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            challenges: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Submit a new challenge.
    ///
    /// # Errors
    /// Returns [`ChallengeError::Duplicate`] if a pending challenge already exists
    /// for this claim by the same agent.
    #[allow(clippy::significant_drop_tightening)]
    pub fn submit(&self, challenge: Challenge) -> Result<ChallengeId, ChallengeError> {
        let mut challenges = self.challenges.write().unwrap();
        let has_duplicate = challenges.iter().any(|c| {
            c.claim_id == challenge.claim_id
                && c.challenger_id == challenge.challenger_id
                && c.is_pending()
        });
        if has_duplicate {
            return Err(ChallengeError::Duplicate {
                claim_id: challenge.claim_id,
            });
        }
        let id = challenge.id;
        challenges.push(challenge);
        Ok(id)
    }

    #[must_use]
    pub fn get(&self, challenge_id: ChallengeId) -> Option<Challenge> {
        self.challenges
            .read()
            .unwrap()
            .iter()
            .find(|c| c.id == challenge_id)
            .cloned()
    }

    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn list_by_claim(&self, claim_id: ClaimId) -> Vec<Challenge> {
        let challenges = self.challenges.read().unwrap();
        let mut result: Vec<Challenge> = challenges
            .iter()
            .filter(|c| c.claim_id == claim_id)
            .cloned()
            .collect();
        result.sort_by_key(|c| c.created_at);
        result
    }

    /// Resolve a challenge.
    ///
    /// Returns the truth reduction amount if the challenge was accepted, or `None` if rejected.
    ///
    /// # Errors
    /// Returns [`ChallengeError::NotFound`] if the challenge doesn't exist.
    #[allow(clippy::significant_drop_tightening)]
    pub fn resolve(
        &self,
        challenge_id: ChallengeId,
        resolution: &ChallengeResolution,
        resolver_id: AgentId,
    ) -> Result<Option<f64>, ChallengeError> {
        let mut challenges = self.challenges.write().unwrap();
        let challenge = challenges
            .iter_mut()
            .find(|c| c.id == challenge_id)
            .ok_or(ChallengeError::NotFound { challenge_id })?;

        if challenge.state != ChallengeState::UnderReview {
            challenge.transition_to(ChallengeState::UnderReview)?;
        }
        challenge.resolved_by = Some(resolver_id);

        match resolution {
            ChallengeResolution::Accept { truth_reduction } => {
                challenge.transition_to(ChallengeState::Accepted)?;
                Ok(Some(*truth_reduction))
            }
            ChallengeResolution::Reject { .. } => {
                challenge.transition_to(ChallengeState::Rejected)?;
                Ok(None)
            }
        }
    }

    #[must_use]
    pub fn apply_truth_reduction(current_truth: TruthValue, reduction: f64) -> TruthValue {
        TruthValue::clamped((current_truth.value() - reduction).max(0.0))
    }

    #[must_use]
    pub fn total_challenges(&self) -> usize {
        self.challenges.read().unwrap().len()
    }
}

impl Default for ChallengeService {
    fn default() -> Self {
        Self::new()
    }
}

// ── auto_create_challenge ─────────────────────────────────────────────────────

/// Automatically create a [`ContradictingEvidence`](ChallengeType::ContradictingEvidence)
/// challenge when the CDST conflict coefficient K meets or exceeds `high_conflict_threshold`.
///
/// Returns `None` if `conflict_k` is below the threshold. The challenge is attributed
/// to a system sentinel agent (nil UUID) to signal it is machine-generated.
#[must_use]
pub fn auto_create_challenge(
    conflict_k: f64,
    claim_id: Uuid,
    frame_id: Uuid,
    high_conflict_threshold: f64,
) -> Option<Challenge> {
    if conflict_k < high_conflict_threshold {
        return None;
    }
    let explanation = format!(
        "Auto-generated: CDST conflict K={conflict_k:.4} exceeds threshold \
         {high_conflict_threshold:.4} (frame {frame_id})"
    );
    Some(Challenge::new(
        ClaimId::from_uuid(claim_id),
        AgentId::from_uuid(Uuid::nil()),
        ChallengeType::ContradictingEvidence,
        explanation,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_challenge_above_threshold() {
        let claim_id = Uuid::new_v4();
        let frame_id = Uuid::new_v4();
        let ch = auto_create_challenge(0.8, claim_id, frame_id, 0.7).unwrap();
        assert_eq!(ch.challenge_type, ChallengeType::ContradictingEvidence);
        assert_eq!(ch.state, ChallengeState::Pending);
        assert!(ch.explanation.contains("K=0.8000"));
    }

    #[test]
    fn auto_challenge_below_threshold() {
        let claim_id = Uuid::new_v4();
        let frame_id = Uuid::new_v4();
        assert!(auto_create_challenge(0.5, claim_id, frame_id, 0.7).is_none());
    }

    #[test]
    fn duplicate_challenge_rejected() {
        let svc = ChallengeService::new();
        let claim_id = ClaimId::from_uuid(Uuid::new_v4());
        let agent_id = AgentId::from_uuid(Uuid::new_v4());
        let ch = Challenge::new(claim_id, agent_id, ChallengeType::FactualError, "test");
        svc.submit(ch.clone()).unwrap();
        let err = svc.submit(ch).unwrap_err();
        assert!(matches!(err, ChallengeError::Duplicate { .. }));
    }
}
