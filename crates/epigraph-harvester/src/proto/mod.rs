//! Generated protobuf types for the harvester gRPC service
//!
//! This module includes code generated from proto/harvester.proto by tonic-build.
//! The generation happens at build time via build.rs.
//!
//! # Build Requirements
//!
//! The Protocol Buffers compiler (`protoc`) must be installed to build this crate.
//! See the crate README.md for installation instructions.
//!
//! # Generated Types
//!
//! This module will contain:
//! - `ExtractionServiceClient`: gRPC client for the harvester service
//! - `FragmentRequest`, `BatchRequest`, `HealthRequest`: Request messages
//! - `VerifiedGraph`, `BatchResponse`, `HealthResponse`: Response messages
//! - `ExtractedClaim`, `ExtractedConcept`, `ExtractedRelation`: Domain objects
//! - `AuditTrail`, `SkepticReport`, `LogicianReport`, `VarianceReport`: QA reports
//! - Enums: `ExtractionStatus`, `Methodology`, `ClaimType`, etc.
//!
//! The generated code is placed in this directory by tonic-build during compilation.

// Include the generated protobuf code
// The file is pre-generated and stored in this directory
include!("harvester.rs");
