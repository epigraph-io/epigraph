//! Dempster-Shafer error types

use thiserror::Error;

/// Errors from the Dempster-Shafer / TBM subsystem
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DsError {
    /// Mass function values do not sum to 1.0
    #[error("Mass function does not sum to 1.0 (got {sum})")]
    InvalidMassSum { sum: f64 },

    /// Mass assigned to a subset containing elements outside the frame
    #[error("Mass assigned to element outside frame: {element}")]
    ElementOutsideFrame { element: String },

    /// Cannot combine mass functions defined on different frames
    #[error("Incompatible frames: {left} vs {right}")]
    IncompatibleFrames { left: String, right: String },

    /// Frame of discernment must have at least one hypothesis
    #[error("Empty frame of discernment")]
    EmptyFrame,

    /// Sources completely contradict — Dempster's rule is undefined
    #[error("Total conflict (K=1.0): sources completely contradict")]
    TotalConflict,

    /// Mass values must be non-negative
    #[error("Negative mass value: {value}")]
    NegativeMass { value: f64 },

    /// Discount factor must be in [0, 1]
    #[error("Invalid discount factor: {alpha} (must be in [0, 1])")]
    InvalidDiscountFactor { alpha: f64 },

    /// Need at least one mass function to combine
    #[error("Need at least one mass function (got 0)")]
    InsufficientSources,
}
