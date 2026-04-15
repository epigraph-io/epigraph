//! Service Layer for EpiGraph API
//!
//! This module contains business logic services that handlers delegate to.
//! Following the "thin handler" principle:
//!
//! - Handlers: Parse input, call services, format output
//! - Services: Business logic, validation, orchestration
//!
//! # Architecture
//!
//! ```text
//! HTTP Request
//!     |
//!     v
//! [Handler] - thin, only HTTP concerns
//!     |
//!     v
//! [Service] - business logic, validation
//!     |
//!     v
//! [Repository/Engine] - data access, algorithms
//! ```

pub mod submission;
pub mod validation;

pub use submission::SubmissionService;
pub use validation::ValidationService;
