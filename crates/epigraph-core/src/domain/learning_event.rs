//! Learning event model for capturing resolution lessons from conflicts
//!
//! When a challenge is resolved (Accepted/Rejected), the system captures
//! what was learned to improve future extraction quality.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A record of what was learned from resolving a conflict between claims.
///
/// Created when a challenge is accepted or rejected, capturing the
/// resolution rationale and any extraction adjustments for future runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningEvent {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub conflict_claim_a: Uuid,
    pub conflict_claim_b: Uuid,
    pub resolution: String,
    pub lesson: String,
    pub extraction_adjustments: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl LearningEvent {
    /// Create a new learning event
    #[must_use]
    pub fn new(
        challenge_id: Uuid,
        conflict_claim_a: Uuid,
        conflict_claim_b: Uuid,
        resolution: String,
        lesson: String,
        extraction_adjustments: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge_id,
            conflict_claim_a,
            conflict_claim_b,
            resolution,
            lesson,
            extraction_adjustments,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learning_event_creation() {
        let event = LearningEvent::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Claim A superseded by more recent data".to_string(),
            "Older synthesis routes may report higher yields than reproducible".to_string(),
            Some(serde_json::json!({"adjust_yield_confidence": -0.1})),
        );
        assert!(!event.resolution.is_empty());
        assert!(!event.lesson.is_empty());
        assert!(event.extraction_adjustments.is_some());
    }

    #[test]
    fn test_learning_event_serialization() {
        let event = LearningEvent::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Rejected".to_string(),
            "Temperature ranges in methods sections are precise".to_string(),
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: LearningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, event.id);
        assert_eq!(deserialized.resolution, event.resolution);
    }
}
