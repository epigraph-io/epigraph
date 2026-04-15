//! Frame of discernment
//!
//! A frame is a named set of mutually exclusive, exhaustive hypotheses.
//! Every mass function is defined relative to a frame, and combination
//! requires compatible frames.

use crate::errors::DsError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A frame of discernment: the set of possible hypotheses for a question
///
/// For example, a frame for material stability might contain
/// `["stable", "metastable", "unstable"]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameOfDiscernment {
    /// Unique identifier for this frame (e.g. `material_stability`)
    pub id: String,
    /// Ordered list of mutually exclusive hypotheses
    pub hypotheses: Vec<String>,
    /// Version number (incremented on frame extension)
    #[serde(default = "default_version")]
    pub version: u32,
}

const fn default_version() -> u32 {
    1
}

impl FrameOfDiscernment {
    /// Create a new frame, rejecting empty or duplicate hypotheses
    ///
    /// # Errors
    /// Returns `DsError::EmptyFrame` if `hypotheses` is empty after dedup.
    pub fn new(id: impl Into<String>, hypotheses: Vec<String>) -> Result<Self, DsError> {
        // Deduplicate while preserving order
        let mut seen = BTreeSet::new();
        let deduped: Vec<String> = hypotheses
            .into_iter()
            .filter(|h| seen.insert(h.clone()))
            .collect();

        if deduped.is_empty() {
            return Err(DsError::EmptyFrame);
        }

        Ok(Self {
            id: id.into(),
            hypotheses: deduped,
            version: 1,
        })
    }

    /// Generate the power set (all 2^n subsets, excluding empty set)
    ///
    /// Each subset is a `BTreeSet<usize>` of hypothesis indices.
    ///
    /// # Errors
    ///
    /// Returns [`DsError::FrameTooLarge`] if the frame has more than 20 hypotheses.
    /// 2^20 = 1 048 576 subsets is the practical upper bound for in-memory enumeration.
    /// Larger frames must use sparse representations.
    pub fn power_set(&self) -> Result<Vec<BTreeSet<usize>>, DsError> {
        let n = self.hypotheses.len();
        if n > 20 {
            return Err(DsError::FrameTooLarge { n });
        }
        let total = 1usize << n; // 2^n — safe because n <= 20
        let mut subsets = Vec::with_capacity(total - 1);

        for mask in 1..total {
            let mut subset = BTreeSet::new();
            for bit in 0..n {
                if mask & (1 << bit) != 0 {
                    subset.insert(bit);
                }
            }
            subsets.push(subset);
        }

        Ok(subsets)
    }

    /// The full set Theta (all hypothesis indices)
    #[must_use]
    pub fn full_set(&self) -> BTreeSet<usize> {
        (0..self.hypotheses.len()).collect()
    }

    /// Check if a hypothesis label is in this frame
    #[must_use]
    pub fn contains(&self, hypothesis: &str) -> bool {
        self.hypotheses.iter().any(|h| h == hypothesis)
    }

    /// Get the index of a hypothesis by label
    #[must_use]
    pub fn index_of(&self, hypothesis: &str) -> Option<usize> {
        self.hypotheses.iter().position(|h| h == hypothesis)
    }

    /// Number of hypotheses in this frame
    #[must_use]
    pub const fn hypothesis_count(&self) -> usize {
        self.hypotheses.len()
    }

    /// Check if an index is valid within this frame
    #[must_use]
    pub const fn is_valid_index(&self, idx: usize) -> bool {
        idx < self.hypotheses.len()
    }

    /// Check if all indices in a subset are valid
    #[must_use]
    pub fn is_valid_subset(&self, subset: &BTreeSet<usize>) -> bool {
        subset.iter().all(|&idx| self.is_valid_index(idx))
    }

    /// Create an extended frame with additional hypotheses (version + 1)
    ///
    /// New hypotheses are appended after existing ones. Existing indices
    /// remain stable. Returns a new frame with incremented version.
    ///
    /// # Errors
    /// Returns `DsError::EmptyFrame` if the combined result would be empty.
    pub fn extend(&self, new_hypotheses: Vec<String>) -> Result<Self, DsError> {
        let mut combined = self.hypotheses.clone();
        let mut seen: BTreeSet<String> = self.hypotheses.iter().cloned().collect();
        for h in new_hypotheses {
            if seen.insert(h.clone()) {
                combined.push(h);
            }
        }
        if combined.is_empty() {
            return Err(DsError::EmptyFrame);
        }
        Ok(Self {
            id: self.id.clone(),
            hypotheses: combined,
            version: self.version + 1,
        })
    }

    /// Build the union frame from two frames
    ///
    /// Merges hypothesis lists preserving order: `self`'s hypotheses first,
    /// then `other`'s hypotheses that aren't already present.
    /// The union frame gets a combined id and version 1.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut hypotheses = self.hypotheses.clone();
        let seen: BTreeSet<&str> = self.hypotheses.iter().map(String::as_str).collect();
        for h in &other.hypotheses {
            if !seen.contains(h.as_str()) {
                hypotheses.push(h.clone());
            }
        }
        Self {
            id: format!("{}+{}", self.id, other.id),
            hypotheses,
            version: 1,
        }
    }

    /// Compute index mapping from this frame's indices to a target frame
    ///
    /// Returns a map from `self.index -> target.index` for each shared hypothesis.
    ///
    /// # Errors
    /// Returns `DsError::IncompatibleFrames` if any hypothesis in self is missing from target.
    pub fn index_mapping_to(
        &self,
        target: &Self,
    ) -> Result<std::collections::HashMap<usize, usize>, DsError> {
        let mut mapping = std::collections::HashMap::new();
        for (i, h) in self.hypotheses.iter().enumerate() {
            match target.index_of(h) {
                Some(j) => {
                    mapping.insert(i, j);
                }
                None => {
                    return Err(DsError::IncompatibleFrames {
                        left: self.id.clone(),
                        right: target.id.clone(),
                    });
                }
            }
        }
        Ok(mapping)
    }

    /// Check if this frame is a subframe of another (all hypotheses present)
    #[must_use]
    pub fn is_subframe_of(&self, other: &Self) -> bool {
        self.hypotheses.iter().all(|h| other.hypotheses.contains(h))
    }
}

impl PartialEq for FrameOfDiscernment {
    fn eq(&self, other: &Self) -> bool {
        // Both id AND hypotheses must match: two frames with the same id but
        // different hypothesis sets are mathematically incompatible and must
        // not be silently treated as equal during Dempster-Shafer combination.
        self.id == other.id && self.hypotheses == other.hypotheses
    }
}

impl Eq for FrameOfDiscernment {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_frame() {
        let frame = FrameOfDiscernment::new(
            "stability",
            vec!["stable".into(), "metastable".into(), "unstable".into()],
        )
        .unwrap();

        assert_eq!(frame.hypothesis_count(), 3);
        assert!(frame.contains("stable"));
        assert!(!frame.contains("unknown"));
        assert_eq!(frame.index_of("metastable"), Some(1));
    }

    #[test]
    fn empty_frame_rejected() {
        let result = FrameOfDiscernment::new("empty", vec![]);
        assert_eq!(result.unwrap_err(), DsError::EmptyFrame);
    }

    #[test]
    fn duplicates_removed() {
        let frame =
            FrameOfDiscernment::new("dup", vec!["a".into(), "b".into(), "a".into(), "c".into()])
                .unwrap();
        assert_eq!(frame.hypothesis_count(), 3);
        assert_eq!(frame.hypotheses, vec!["a", "b", "c"]);
    }

    #[test]
    fn power_set_binary_frame() {
        let frame = FrameOfDiscernment::new("binary", vec!["true".into(), "false".into()]).unwrap();
        let ps = frame.power_set().unwrap();
        // 2^2 - 1 = 3 non-empty subsets: {0}, {1}, {0,1}
        assert_eq!(ps.len(), 3);
    }

    #[test]
    fn power_set_ternary_frame() {
        let frame =
            FrameOfDiscernment::new("ternary", vec!["a".into(), "b".into(), "c".into()]).unwrap();
        let ps = frame.power_set().unwrap();
        // 2^3 - 1 = 7 non-empty subsets
        assert_eq!(ps.len(), 7);
    }

    #[test]
    fn power_set_rejects_oversized_frame() {
        let hypotheses: Vec<String> = (0..=20).map(|i| i.to_string()).collect(); // 21 hypotheses
        let frame = FrameOfDiscernment::new("big", hypotheses).unwrap();
        assert!(matches!(
            frame.power_set(),
            Err(DsError::FrameTooLarge { n: 21 })
        ));
    }

    #[test]
    fn full_set() {
        let frame =
            FrameOfDiscernment::new("test", vec!["x".into(), "y".into(), "z".into()]).unwrap();
        let full = frame.full_set();
        assert_eq!(full, BTreeSet::from([0, 1, 2]));
    }

    #[test]
    fn valid_subset_check() {
        let frame = FrameOfDiscernment::new("test", vec!["a".into(), "b".into()]).unwrap();
        assert!(frame.is_valid_subset(&BTreeSet::from([0, 1])));
        assert!(!frame.is_valid_subset(&BTreeSet::from([0, 2])));
    }

    #[test]
    fn frame_equality_requires_matching_hypotheses() {
        // Same id + same hypotheses → equal
        let f1 = FrameOfDiscernment::new("same_id", vec!["a".into()]).unwrap();
        let f1b = FrameOfDiscernment::new("same_id", vec!["a".into()]).unwrap();
        assert_eq!(f1, f1b);

        // Same id but different hypotheses → NOT equal (would cause silent DS misuse)
        let f2 = FrameOfDiscernment::new("same_id", vec!["b".into()]).unwrap();
        assert_ne!(f1, f2);

        // Different id → not equal
        let f3 = FrameOfDiscernment::new("other_id", vec!["a".into()]).unwrap();
        assert_ne!(f1, f3);
    }

    #[test]
    fn serialization_roundtrip() {
        let frame = FrameOfDiscernment::new("test", vec!["h1".into(), "h2".into()]).unwrap();
        let json = serde_json::to_string(&frame).unwrap();
        let parsed: FrameOfDiscernment = serde_json::from_str(&json).unwrap();
        assert_eq!(frame.id, parsed.id);
        assert_eq!(frame.hypotheses, parsed.hypotheses);
    }

    // ======== Frame versioning ========

    #[test]
    fn frame_version_starts_at_one() {
        let frame = FrameOfDiscernment::new("v", vec!["a".into()]).unwrap();
        assert_eq!(frame.version, 1);
    }

    #[test]
    fn extend_increments_version() {
        let frame = FrameOfDiscernment::new("ext", vec!["a".into(), "b".into()]).unwrap();
        let extended = frame.extend(vec!["c".into(), "d".into()]).unwrap();
        assert_eq!(extended.version, 2);
        assert_eq!(extended.hypothesis_count(), 4);
        assert_eq!(extended.hypotheses, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn extend_deduplicates() {
        let frame = FrameOfDiscernment::new("ext", vec!["a".into(), "b".into()]).unwrap();
        let extended = frame.extend(vec!["b".into(), "c".into()]).unwrap();
        assert_eq!(extended.hypothesis_count(), 3);
        assert_eq!(extended.hypotheses, vec!["a", "b", "c"]);
    }

    // ======== Union frame ========

    #[test]
    fn union_merges_hypotheses() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["b".into(), "c".into()]).unwrap();
        let union = f1.union(&f2);
        assert_eq!(union.hypotheses, vec!["a", "b", "c"]);
        assert_eq!(union.id, "f1+f2");
    }

    #[test]
    fn union_same_frame() {
        let f = FrameOfDiscernment::new("f", vec!["a".into(), "b".into()]).unwrap();
        let union = f.union(&f);
        assert_eq!(union.hypothesis_count(), 2);
    }

    // ======== Index mapping ========

    #[test]
    fn index_mapping_to_superset() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["x".into(), "a".into(), "b".into()]).unwrap();
        let mapping = f1.index_mapping_to(&f2).unwrap();
        assert_eq!(mapping[&0], 1); // "a" is at index 1 in f2
        assert_eq!(mapping[&1], 2); // "b" is at index 2 in f2
    }

    #[test]
    fn index_mapping_missing_hypothesis_errors() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["a".into(), "c".into()]).unwrap();
        let result = f1.index_mapping_to(&f2);
        assert!(matches!(result, Err(DsError::IncompatibleFrames { .. })));
    }

    // ======== Subframe check ========

    #[test]
    fn is_subframe_of_superset() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["a".into(), "b".into(), "c".into()]).unwrap();
        assert!(f1.is_subframe_of(&f2));
        assert!(!f2.is_subframe_of(&f1));
    }
}
