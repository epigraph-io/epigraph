//! The record parser: fields out of claim content, whichever layout wrote it,
//! plus the comparison keys derived from them.
//!
//! Two layouts are understood. A body with at least two `|` is a pipe record:
//! keyed fields (`key: value`), ignored fields, and positional fields (title
//! first, after an optional header). Anything else is prose:
//! `<type>: <title> — <entity>, <marker> <value>, …`, or the header variant
//! `<HEADER> — <entity>: <title>; …`. Deadline and value fall back to marker
//! scans of the whole body in both layouts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ids::IdToken;
use super::profile::PassProfile;
use super::DedupClaim;

/// Fields parsed out of one claim.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Facts {
    pub title: String,
    pub entity: Option<String>,
    pub deadline: Option<String>,
    pub value: Option<String>,
    pub class: Option<String>,
    /// Present values of the profile's extra fields.
    pub extra: BTreeMap<String, String>,
    /// Content ids plus carried ids.
    pub ids: Vec<IdToken>,
}

impl Facts {
    /// A field by profile name (`title`, `entity`, `deadline`, `value`,
    /// `class`, or an extra field).
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        match name {
            "title" => Some(self.title.as_str()).filter(|t| !t.is_empty()),
            "entity" => self.entity.as_deref(),
            "deadline" => self.deadline.as_deref(),
            "value" => self.value.as_deref(),
            "class" => self.class.as_deref(),
            other => self.extra.get(other).map(String::as_str),
        }
    }
}

/// Comparison keys, computed once per claim (pairing is O(n²)).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchKeys {
    pub title_key: String,
    pub title_tokens: BTreeSet<String>,
    /// `None` when the claim names no entity: an unnamed entity matches nothing.
    pub entity_tokens: Option<BTreeSet<String>>,
    pub strong_ids: BTreeSet<String>,
    pub all_ids: BTreeSet<String>,
}

/// A claim (or a probe candidate, which has no id) with facts and keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedRecord {
    pub id: Option<Uuid>,
    /// The hyphenated id, or empty for a candidate. Revision and distinct
    /// labels match a prefix of it.
    pub id_str: String,
    pub content: String,
    pub labels: Vec<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub facts: Facts,
    pub keys: MatchKeys,
}

impl ParsedRecord {
    #[must_use]
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l == label)
    }
}

/// Parse content only (no labels).
#[must_use]
pub fn parse_content(pass: &PassProfile, content: &str) -> Facts {
    let _ = (pass, content);
    Facts::default()
}

/// Parse a claim, letting labels fill or override fields per the profile,
/// and adding carried ids.
#[must_use]
pub fn parse_record(pass: &PassProfile, claim: &DedupClaim) -> ParsedRecord {
    parse_parts(
        pass,
        Some(claim.id),
        &claim.content,
        &claim.labels,
        claim.created_at,
    )
}

/// Parse a probe candidate.
#[must_use]
pub fn parse_candidate(pass: &PassProfile, content: &str, labels: &[String]) -> ParsedRecord {
    parse_parts(pass, None, content, labels, None)
}

fn parse_parts(
    pass: &PassProfile,
    id: Option<Uuid>,
    content: &str,
    labels: &[String],
    created_at: Option<DateTime<Utc>>,
) -> ParsedRecord {
    let _ = pass;
    ParsedRecord {
        id,
        id_str: id.map(|u| u.to_string()).unwrap_or_default(),
        content: content.to_string(),
        labels: labels.to_vec(),
        created_at,
        facts: Facts::default(),
        keys: MatchKeys::default(),
    }
}

/// Discriminating title tokens: normalized, stopwords and 1-char tokens dropped.
#[must_use]
pub fn title_tokens(pass: &PassProfile, title: &str) -> BTreeSet<String> {
    let _ = (pass, title);
    BTreeSet::new()
}

/// Alias-expanded entity tokens with stopwords dropped, or `None` when empty.
#[must_use]
pub fn entity_tokens(pass: &PassProfile, entity: Option<&str>) -> Option<BTreeSet<String>> {
    let _ = (pass, entity);
    None
}

/// Whether two entity token sets denote the same entity.
#[must_use]
pub fn entities_match(
    pass: &PassProfile,
    a: Option<&BTreeSet<String>>,
    b: Option<&BTreeSet<String>>,
) -> bool {
    let _ = (pass, a, b);
    false
}

/// How many of the profile's `count_fields` are missing.
#[must_use]
pub fn unknown_count(pass: &PassProfile, facts: &Facts) -> usize {
    let _ = (pass, facts);
    0
}
