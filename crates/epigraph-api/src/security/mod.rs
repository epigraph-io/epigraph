//! Security hardening module for EpiGraph API
//!
//! This module provides:
//! - **Key Management**: Agent key rotation and revocation
//! - **Rate Limiting**: Per-agent and global request rate limiting
//! - **Security Audit**: Event logging for security-relevant operations
//!
//! # Design Principles
//!
//! 1. **Defense in Depth**: Multiple layers of security controls
//! 2. **Fail Secure**: Deny access when in doubt
//! 3. **Audit Everything**: All security events are logged
//! 4. **Key Lifecycle**: Support for rotation without downtime

pub mod audit;
pub mod keys;
pub mod rate_limit;

pub use audit::{SecurityAuditLog, SecurityEvent, SecurityEventFilter};
pub use keys::{
    AgentKey, KeyError, KeyManager, KeyRepository, KeyRevocationRequest, KeyRotationRequest,
    KeyStatus, KeyType, Signature,
};
pub use rate_limit::{AgentRateLimiter, RateLimitConfig, RateLimitError};
