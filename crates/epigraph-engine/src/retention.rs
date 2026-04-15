//! Data retention policy configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub archive_after_days: u32,
    pub delete_after_days: u32,
    pub preserve_verified_evidence: bool,
    pub max_audit_entries: u64,
    pub security_event_retention_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            archive_after_days: 365,
            delete_after_days: 730,
            preserve_verified_evidence: true,
            max_audit_entries: 1_000_000,
            security_event_retention_days: 90,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.archive_after_days, 365);
        assert_eq!(policy.delete_after_days, 730);
        assert!(policy.preserve_verified_evidence);
        assert_eq!(policy.max_audit_entries, 1_000_000);
        assert_eq!(policy.security_event_retention_days, 90);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let policy = RetentionPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.archive_after_days, policy.archive_after_days);
    }
}
