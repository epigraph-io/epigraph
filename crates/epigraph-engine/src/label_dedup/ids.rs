//! Id tokenization: lift every plausible item identifier out of free text.
//!
//! Format-independent by construction. The whole content is tokenized rather
//! than trusting a field layout, which is what lets a prose claim
//! (`Notice: … (KX-4417) — …`) match a pipe record (`… KX-4417 … | …`).

use serde::{Deserialize, Serialize};

use super::profile::IdSpec;

/// One identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdToken {
    /// As it appeared (trimmed), for human-readable plans. A carried id has
    /// its normalized form here.
    pub raw: String,
    /// Uppercase ASCII alphanumerics only: the comparison key.
    pub norm: String,
    /// Distinctive enough to match on by itself.
    pub strong: bool,
}

/// Every id in `content`, in order of first appearance, de-duplicated by
/// normalized form. `content` is cut at the last `scan_cut_at_last` marker
/// first.
#[must_use]
pub fn extract_ids(spec: &IdSpec, content: &str) -> Vec<IdToken> {
    let _ = (spec, content);
    Vec::new()
}

/// Uppercase, ASCII alphanumerics only.
#[must_use]
pub fn normalize_id(token: &str) -> String {
    let _ = token;
    String::new()
}

/// The id a carry label holds (`<prefix><NORM>`), if `label` is one.
#[must_use]
pub fn carried_id(spec: &IdSpec, label: &str) -> Option<IdToken> {
    let _ = (spec, label);
    None
}

/// `content` up to the last occurrence of the cut marker, or whole.
#[must_use]
pub fn scan_region<'a>(spec: &IdSpec, content: &'a str) -> &'a str {
    let _ = spec;
    content
}
