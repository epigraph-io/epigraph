//! Security event audit logging
//!
//! This module provides:
//! - Structured logging of security-relevant events
//! - Queryable audit trail for forensics
//! - Event types for authentication, authorization, and key operations
//!
//! # Design Principles
//!
//! 1. **Completeness**: All security events are logged
//! 2. **Immutability**: Audit logs cannot be modified after creation
//! 3. **Queryability**: Events can be filtered and searched
//! 4. **Correlation**: Events include correlation IDs for request tracing

use chrono::{DateTime, Utc};
use epigraph_core::domain::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// A security-relevant event in the system
///
/// These events form an audit trail for security analysis
/// and forensic investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Agent authentication attempt
    AuthAttempt {
        /// Agent attempting to authenticate
        agent_id: AgentId,
        /// Whether authentication succeeded
        success: bool,
        /// IP address of the request
        ip_address: Option<IpAddr>,
        /// User agent string from the request
        user_agent: Option<String>,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Signature verification result
    SignatureVerification {
        /// Agent whose signature was verified
        agent_id: AgentId,
        /// Whether verification succeeded
        success: bool,
        /// Reason for failure (if any)
        failure_reason: Option<String>,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Key rotation event
    KeyRotation {
        /// Agent whose key was rotated
        agent_id: AgentId,
        /// ID of the old key that was rotated out
        old_key_id: Uuid,
        /// ID of the new key that is now active
        new_key_id: Uuid,
        /// Reason provided for the rotation
        rotation_reason: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Key revocation event
    KeyRevocation {
        /// Agent whose key was revoked
        agent_id: AgentId,
        /// ID of the revoked key
        key_id: Uuid,
        /// Reason for revocation
        reason: String,
        /// Agent who performed the revocation
        revoked_by: AgentId,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Rate limit exceeded
    RateLimitExceeded {
        /// Agent who exceeded the limit
        agent_id: AgentId,
        /// Endpoint that was rate limited
        endpoint: String,
        /// Current request rate
        current_rate: u32,
        /// Configured limit
        limit: u32,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Privilege escalation attempt
    PrivilegeEscalation {
        /// Agent who attempted the escalation
        agent_id: AgentId,
        /// Action that was attempted
        attempted_action: String,
        /// Capability that would have been required
        required_capability: String,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },

    /// Suspicious activity detected
    SuspiciousActivity {
        /// Agent involved in the activity
        agent_id: Option<AgentId>,
        /// Description of the suspicious activity
        description: String,
        /// Severity level (1-5, where 5 is most severe)
        severity: u8,
        /// Timestamp of the event
        timestamp: DateTime<Utc>,
        /// Correlation ID for request tracing
        correlation_id: String,
    },
}

impl SecurityEvent {
    /// Get the timestamp of this event
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::AuthAttempt { timestamp, .. }
            | Self::SignatureVerification { timestamp, .. }
            | Self::KeyRotation { timestamp, .. }
            | Self::KeyRevocation { timestamp, .. }
            | Self::RateLimitExceeded { timestamp, .. }
            | Self::PrivilegeEscalation { timestamp, .. }
            | Self::SuspiciousActivity { timestamp, .. } => *timestamp,
        }
    }

    /// Get the correlation ID of this event
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        match self {
            Self::AuthAttempt { correlation_id, .. }
            | Self::SignatureVerification { correlation_id, .. }
            | Self::KeyRotation { correlation_id, .. }
            | Self::KeyRevocation { correlation_id, .. }
            | Self::RateLimitExceeded { correlation_id, .. }
            | Self::PrivilegeEscalation { correlation_id, .. }
            | Self::SuspiciousActivity { correlation_id, .. } => correlation_id,
        }
    }

    /// Get the agent ID associated with this event (if any)
    #[must_use]
    pub fn agent_id(&self) -> Option<AgentId> {
        match self {
            Self::AuthAttempt { agent_id, .. }
            | Self::SignatureVerification { agent_id, .. }
            | Self::KeyRotation { agent_id, .. }
            | Self::KeyRevocation { agent_id, .. }
            | Self::RateLimitExceeded { agent_id, .. }
            | Self::PrivilegeEscalation { agent_id, .. } => Some(*agent_id),
            Self::SuspiciousActivity { agent_id, .. } => *agent_id,
        }
    }

    /// Get a human-readable event type string
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::AuthAttempt { .. } => "auth_attempt",
            Self::SignatureVerification { .. } => "signature_verification",
            Self::KeyRotation { .. } => "key_rotation",
            Self::KeyRevocation { .. } => "key_revocation",
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
            Self::PrivilegeEscalation { .. } => "privilege_escalation",
            Self::SuspiciousActivity { .. } => "suspicious_activity",
        }
    }

    /// Check if this is a security failure event
    #[must_use]
    pub fn is_failure(&self) -> bool {
        match self {
            Self::AuthAttempt { success, .. } => !success,
            Self::SignatureVerification { success, .. } => !success,
            Self::RateLimitExceeded { .. } => true,
            Self::PrivilegeEscalation { .. } => true,
            Self::SuspiciousActivity { .. } => true,
            Self::KeyRotation { .. } | Self::KeyRevocation { .. } => false,
        }
    }

    /// Create a new auth attempt event
    #[must_use]
    pub fn auth_attempt(
        agent_id: AgentId,
        success: bool,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        correlation_id: String,
    ) -> Self {
        Self::AuthAttempt {
            agent_id,
            success,
            ip_address,
            user_agent,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    /// Create a new signature verification event
    #[must_use]
    pub fn signature_verification(
        agent_id: AgentId,
        success: bool,
        failure_reason: Option<String>,
        correlation_id: String,
    ) -> Self {
        Self::SignatureVerification {
            agent_id,
            success,
            failure_reason,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    /// Create a new key rotation event
    #[must_use]
    pub fn key_rotation(
        agent_id: AgentId,
        old_key_id: Uuid,
        new_key_id: Uuid,
        rotation_reason: String,
        correlation_id: String,
    ) -> Self {
        Self::KeyRotation {
            agent_id,
            old_key_id,
            new_key_id,
            rotation_reason,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    /// Create a new key revocation event
    #[must_use]
    pub fn key_revocation(
        agent_id: AgentId,
        key_id: Uuid,
        reason: String,
        revoked_by: AgentId,
        correlation_id: String,
    ) -> Self {
        Self::KeyRevocation {
            agent_id,
            key_id,
            reason,
            revoked_by,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    /// Create a new rate limit exceeded event
    #[must_use]
    pub fn rate_limit_exceeded(
        agent_id: AgentId,
        endpoint: String,
        current_rate: u32,
        limit: u32,
        correlation_id: String,
    ) -> Self {
        Self::RateLimitExceeded {
            agent_id,
            endpoint,
            current_rate,
            limit,
            timestamp: Utc::now(),
            correlation_id,
        }
    }

    /// Create a new privilege escalation event
    #[must_use]
    pub fn privilege_escalation(
        agent_id: AgentId,
        attempted_action: String,
        required_capability: String,
        correlation_id: String,
    ) -> Self {
        Self::PrivilegeEscalation {
            agent_id,
            attempted_action,
            required_capability,
            timestamp: Utc::now(),
            correlation_id,
        }
    }
}

/// Convert a `SecurityEvent` to a `SecurityEventRow` for database persistence.
///
/// This helper is used by middleware to fire-and-forget security events to the DB
/// without blocking the request path. The DB write is non-critical supplementary
/// persistence; the in-memory log remains the primary source for admin stats.
#[cfg(feature = "db")]
pub fn security_event_row_from(
    event: &SecurityEvent,
) -> epigraph_db::repos::security_event::SecurityEventRow {
    use epigraph_db::repos::security_event::SecurityEventRow;
    use serde_json::json;

    let (event_type, agent_id_opt, success, details, ip_address, user_agent, correlation_id) =
        match event {
            SecurityEvent::AuthAttempt {
                agent_id,
                success,
                ip_address,
                user_agent,
                timestamp: _,
                correlation_id,
            } => (
                "auth_attempt",
                Some(*agent_id),
                Some(*success),
                json!({}),
                ip_address.map(|ip| ip.to_string()),
                user_agent.clone(),
                Some(correlation_id.clone()),
            ),
            SecurityEvent::SignatureVerification {
                agent_id,
                success,
                failure_reason,
                timestamp: _,
                correlation_id,
            } => (
                "signature_verification",
                Some(*agent_id),
                Some(*success),
                json!({ "failure_reason": failure_reason }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
            SecurityEvent::KeyRotation {
                agent_id,
                old_key_id,
                new_key_id,
                rotation_reason,
                timestamp: _,
                correlation_id,
            } => (
                "key_rotation",
                Some(*agent_id),
                None,
                json!({
                    "old_key_id": old_key_id,
                    "new_key_id": new_key_id,
                    "rotation_reason": rotation_reason,
                }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
            SecurityEvent::KeyRevocation {
                agent_id,
                key_id,
                reason,
                revoked_by,
                timestamp: _,
                correlation_id,
            } => (
                "key_revocation",
                Some(*agent_id),
                None,
                json!({
                    "key_id": key_id,
                    "reason": reason,
                    "revoked_by": revoked_by,
                }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
            SecurityEvent::RateLimitExceeded {
                agent_id,
                endpoint,
                current_rate,
                limit,
                timestamp: _,
                correlation_id,
            } => (
                "rate_limit_exceeded",
                Some(*agent_id),
                Some(false),
                json!({
                    "endpoint": endpoint,
                    "current_rate": current_rate,
                    "limit": limit,
                }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
            SecurityEvent::PrivilegeEscalation {
                agent_id,
                attempted_action,
                required_capability,
                timestamp: _,
                correlation_id,
            } => (
                "privilege_escalation",
                Some(*agent_id),
                Some(false),
                json!({
                    "attempted_action": attempted_action,
                    "required_capability": required_capability,
                }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
            SecurityEvent::SuspiciousActivity {
                agent_id,
                description,
                severity,
                timestamp: _,
                correlation_id,
            } => (
                "suspicious_activity",
                *agent_id,
                Some(false),
                json!({
                    "description": description,
                    "severity": severity,
                }),
                None,
                None,
                Some(correlation_id.clone()),
            ),
        };

    SecurityEventRow {
        id: uuid::Uuid::new_v4(),
        event_type: event_type.to_string(),
        agent_id: agent_id_opt.map(|a| a.as_uuid()),
        success,
        details,
        ip_address,
        user_agent,
        correlation_id,
        created_at: event.timestamp(),
    }
}

/// Filter criteria for querying security events
#[derive(Debug, Clone, Default)]
pub struct SecurityEventFilter {
    /// Filter by agent ID
    pub agent_id: Option<AgentId>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by correlation ID
    pub correlation_id: Option<String>,
    /// Filter events after this time
    pub from: Option<DateTime<Utc>>,
    /// Filter events before this time
    pub until: Option<DateTime<Utc>>,
    /// Only include failure events
    pub failures_only: bool,
    /// Maximum number of results
    pub limit: Option<usize>,
}

impl SecurityEventFilter {
    /// Create a new empty filter (matches all events)
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by agent ID
    #[must_use]
    pub fn with_agent(mut self, agent_id: AgentId) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// Filter by event type
    #[must_use]
    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Filter by correlation ID
    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Filter events in a time range
    #[must_use]
    pub fn with_time_range(mut self, from: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self.until = Some(until);
        self
    }

    /// Only include failure events
    #[must_use]
    pub fn failures_only(mut self) -> Self {
        self.failures_only = true;
        self
    }

    /// Limit the number of results
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Check if an event matches this filter
    #[must_use]
    pub fn matches(&self, event: &SecurityEvent) -> bool {
        // Check agent ID
        if let Some(agent_id) = self.agent_id {
            if event.agent_id() != Some(agent_id) {
                return false;
            }
        }

        // Check event type
        if let Some(ref event_type) = self.event_type {
            if event.event_type() != event_type {
                return false;
            }
        }

        // Check correlation ID
        if let Some(ref correlation_id) = self.correlation_id {
            if event.correlation_id() != correlation_id {
                return false;
            }
        }

        // Check time range
        let timestamp = event.timestamp();
        if let Some(from) = self.from {
            if timestamp < from {
                return false;
            }
        }
        if let Some(until) = self.until {
            if timestamp > until {
                return false;
            }
        }

        // Check failures only
        if self.failures_only && !event.is_failure() {
            return false;
        }

        true
    }
}

/// Trait for security audit logging
///
/// Implementations may store events in memory, database, or external systems.
pub trait SecurityAuditLog: Send + Sync {
    /// Log a security event
    fn log(&self, event: SecurityEvent);

    /// Query events matching a filter
    fn query(&self, filter: SecurityEventFilter) -> Vec<SecurityEvent>;

    /// Get recent events (convenience method)
    fn recent(&self, limit: usize) -> Vec<SecurityEvent> {
        self.query(SecurityEventFilter::new().with_limit(limit))
    }

    /// Get events for a specific agent
    fn agent_events(&self, agent_id: AgentId) -> Vec<SecurityEvent> {
        self.query(SecurityEventFilter::new().with_agent(agent_id))
    }

    /// Get all failure events
    fn failures(&self) -> Vec<SecurityEvent> {
        self.query(SecurityEventFilter::new().failures_only())
    }
}

/// In-memory implementation of security audit log
///
/// This is suitable for testing and development.
/// Production systems should use a persistent implementation.
#[derive(Clone)]
pub struct InMemorySecurityAuditLog {
    events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    max_events: usize,
}

impl InMemorySecurityAuditLog {
    /// Create a new in-memory audit log with default capacity (10000 events)
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Create a new in-memory audit log with specified capacity
    #[must_use]
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(max_events))),
            max_events,
        }
    }

    /// Get the number of stored events
    #[must_use]
    pub fn len(&self) -> usize {
        self.events
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Check if the log is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all events (for testing)
    pub fn clear(&self) {
        self.events
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

impl Default for InMemorySecurityAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAuditLog for InMemorySecurityAuditLog {
    fn log(&self, event: SecurityEvent) {
        let mut events = self
            .events
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Evict oldest event if at capacity
        if events.len() >= self.max_events {
            events.pop_front();
        }

        events.push_back(event);
    }

    fn query(&self, filter: SecurityEventFilter) -> Vec<SecurityEvent> {
        let events = self
            .events
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut results: Vec<_> = events
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect();

        // Sort by timestamp descending (most recent first)
        results.sort_by_key(|e| std::cmp::Reverse(e.timestamp()));

        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        results
    }
}

impl std::fmt::Debug for InMemorySecurityAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySecurityAuditLog")
            .field("event_count", &self.len())
            .field("max_events", &self.max_events)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_log_stores_events() {
        let log = InMemorySecurityAuditLog::new();
        let agent_id = AgentId::new();

        log.log(SecurityEvent::auth_attempt(
            agent_id,
            true,
            None,
            None,
            "test-123".to_string(),
        ));

        assert_eq!(log.len(), 1);
    }

    #[test]
    fn in_memory_log_evicts_oldest() {
        let log = InMemorySecurityAuditLog::with_capacity(2);
        let agent_id = AgentId::new();

        for i in 0..3 {
            log.log(SecurityEvent::auth_attempt(
                agent_id,
                true,
                None,
                None,
                format!("corr-{i}"),
            ));
        }

        assert_eq!(log.len(), 2);
        // First event should have been evicted
        let events = log.query(SecurityEventFilter::new());
        assert!(!events.iter().any(|e| e.correlation_id() == "corr-0"));
    }

    #[test]
    fn filter_by_agent_id() {
        let log = InMemorySecurityAuditLog::new();
        let agent1 = AgentId::new();
        let agent2 = AgentId::new();

        log.log(SecurityEvent::auth_attempt(
            agent1,
            true,
            None,
            None,
            "1".to_string(),
        ));
        log.log(SecurityEvent::auth_attempt(
            agent2,
            true,
            None,
            None,
            "2".to_string(),
        ));

        let events = log.query(SecurityEventFilter::new().with_agent(agent1));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_id(), Some(agent1));
    }
}
