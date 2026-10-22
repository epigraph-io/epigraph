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

use super::ids::{carried_id, extract_ids, IdToken};
use super::profile::{FieldSpec, PassProfile};
use super::{normalize_text, overlap_coefficient, DedupClaim};

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
    /// The facts of the claims marked duplicates of this one
    /// ([`DedupClaim::duplicates`](super::DedupClaim::duplicates)), ordered by
    /// id. Read for a field's value (a later date) only: never for matching,
    /// never written.
    pub duplicate_facts: Vec<Facts>,
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
    let (flag, body) = split_flag(pass, content);
    // A pipe record needs a title and at least one more field; prose can
    // carry a stray `|`, so two separators are required.
    let mut facts = if body.matches('|').count() >= 2 {
        parse_pipe(pass, body)
    } else {
        parse_prose(pass, body)
    };
    if let Some(flag) = flag {
        if pass.fields.class.from_flag {
            facts.class = Some(flag.clone());
        }
        for (name, spec) in &pass.fields.extra {
            if spec.from_flag {
                facts.extra.insert(name.clone(), flag.clone());
            }
        }
    }
    facts.ids = extract_ids(&pass.ids, content);
    if facts.title.is_empty() {
        facts.title = content
            .chars()
            .take(pass.fields.title.fallback_chars)
            .collect();
    }
    facts
}

/// Parse a claim, letting labels fill or override fields per the profile,
/// and adding carried ids.
#[must_use]
pub fn parse_record(pass: &PassProfile, claim: &DedupClaim) -> ParsedRecord {
    let mut r = parse_parts(
        pass,
        Some(claim.id),
        &claim.content,
        &claim.labels,
        claim.created_at,
    );
    // Every duplicate down the chain (a duplicate's own duplicates included),
    // each once, ordered by id; bounded so a malformed cyclic or huge input
    // cannot run away.
    let mut seen: std::collections::BTreeMap<uuid::Uuid, &DedupClaim> =
        std::collections::BTreeMap::new();
    let mut stack: Vec<&DedupClaim> = claim.duplicates.iter().collect();
    while let Some(d) = stack.pop() {
        if d.id == claim.id || seen.contains_key(&d.id) || seen.len() >= MAX_DUPLICATES {
            continue;
        }
        seen.insert(d.id, d);
        stack.extend(d.duplicates.iter());
    }
    r.duplicate_facts = seen
        .into_values()
        .map(|d| parse_parts(pass, Some(d.id), &d.content, &d.labels, d.created_at).facts)
        .collect();
    r
}

/// The most duplicates (down every chain) read for one claim.
pub const MAX_DUPLICATES: usize = 1024;

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
    // Label order is not part of a claim's meaning (a store may return it in
    // any order), but several rules take the FIRST matching label. Sort and
    // dedup once here so every rule, and so the plan, is label-order free.
    let mut sorted_labels = labels.to_vec();
    sorted_labels.sort();
    sorted_labels.dedup();
    let labels = sorted_labels.as_slice();
    let mut facts = parse_content(pass, content);
    let f = &pass.fields;
    merge_label(&mut facts.entity, &f.entity, labels, None);
    merge_label(&mut facts.deadline, &f.deadline, labels, None);
    merge_label(&mut facts.value, &f.value, labels, None);
    merge_label(&mut facts.class, &f.class, labels, Some(pass));
    for (name, spec) in &f.extra {
        let mut v = facts.extra.remove(name);
        merge_label(&mut v, spec, labels, None);
        if let Some(v) = v {
            facts.extra.insert(name.clone(), v);
        }
    }
    for label in labels {
        if let Some(carried) = carried_id(&pass.ids, label) {
            if !facts.ids.iter().any(|i| i.norm == carried.norm) {
                facts.ids.push(carried);
            }
        }
    }
    let keys = MatchKeys {
        title_key: normalize_text(&facts.title),
        title_tokens: title_tokens(pass, &facts.title),
        entity_tokens: entity_tokens(pass, facts.entity.as_deref()),
        strong_ids: facts
            .ids
            .iter()
            .filter(|i| i.strong)
            .map(|i| i.norm.clone())
            .collect(),
        all_ids: facts.ids.iter().map(|i| i.norm.clone()).collect(),
    };
    ParsedRecord {
        id,
        id_str: id.map(|u| u.to_string()).unwrap_or_default(),
        content: content.to_string(),
        labels: labels.to_vec(),
        created_at,
        facts,
        keys,
        duplicate_facts: Vec::new(),
    }
}

/// Fill (or, with `prefer_label`, override) a field from the first label
/// carrying the spec's prefix. `canonical` applies the flag canonicalization.
fn merge_label(
    slot: &mut Option<String>,
    spec: &FieldSpec,
    labels: &[String],
    canonical: Option<&PassProfile>,
) {
    let Some(prefix) = spec.from_label_prefix.as_deref() else {
        return;
    };
    let from_label = labels
        .iter()
        .find_map(|l| l.strip_prefix(prefix))
        .filter(|v| !v.trim().is_empty())
        .map(|v| canonical.map_or_else(|| v.to_string(), |p| canonical_flag(p, v)));
    if spec.prefer_label {
        if from_label.is_some() {
            *slot = from_label;
        }
    } else if slot.is_none() {
        *slot = from_label;
    }
}

/// Discriminating title tokens: normalized, stopwords and 1-char tokens dropped.
#[must_use]
pub fn title_tokens(pass: &PassProfile, title: &str) -> BTreeSet<String> {
    let stop: BTreeSet<String> = pass
        .title_match
        .stopwords
        .iter()
        .map(|w| normalize_text(w))
        .collect();
    normalize_text(title)
        .split(' ')
        .filter(|t| t.len() > 1 && !stop.contains(*t))
        .map(str::to_string)
        .collect()
}

/// Alias-expanded entity tokens with stopwords dropped, or `None` when empty.
#[must_use]
pub fn entity_tokens(pass: &PassProfile, entity: Option<&str>) -> Option<BTreeSet<String>> {
    let entity = entity?;
    let m = &pass.entity_match;
    let stop: BTreeSet<String> = m.stopwords.iter().map(|w| normalize_text(w)).collect();
    let expanded: BTreeSet<String> = normalize_text(entity)
        .split(' ')
        .filter(|t| !t.is_empty() && !stop.contains(*t))
        .flat_map(|t| {
            m.aliases
                .iter()
                .find(|(k, _)| normalize_text(k) == t)
                .map_or_else(
                    || vec![t.to_string()],
                    |(_, v)| normalize_text(v).split(' ').map(str::to_string).collect(),
                )
        })
        .filter(|t| !t.is_empty())
        .collect();
    if expanded.is_empty() {
        None
    } else {
        Some(expanded)
    }
}

/// Whether two entity token sets denote the same entity.
#[must_use]
pub fn entities_match(
    pass: &PassProfile,
    a: Option<&BTreeSet<String>>,
    b: Option<&BTreeSet<String>>,
) -> bool {
    match (a, b) {
        (Some(ta), Some(tb)) => overlap_coefficient(ta, tb) >= pass.entity_match.threshold,
        _ => false,
    }
}

/// How many of the profile's `count_fields` are missing.
#[must_use]
pub fn unknown_count(pass: &PassProfile, facts: &Facts) -> usize {
    pass.unknown
        .count_fields
        .iter()
        .filter(|f| facts.field(f).is_none())
        .count()
}

/// Whether a value means "missing".
#[must_use]
pub fn is_unknown(pass: &PassProfile, value: &str) -> bool {
    let n = normalize_text(value);
    if pass
        .unknown
        .not_unknown
        .iter()
        .any(|t| normalize_text(t) == n)
    {
        return false;
    }
    n.is_empty() || pass.unknown.tokens.iter().any(|t| normalize_text(t) == n)
}

/// Trim whitespace, then `.` and `,`; a missing value is `None`.
fn clean(pass: &PassProfile, v: &str) -> Option<String> {
    let v = v.trim().trim_matches(['.', ',']);
    if is_unknown(pass, v) {
        None
    } else {
        Some(v.to_string())
    }
}

/// The canonical form of a flag or class value: normalized, spaces as
/// dashes, then mapped through `flag.canonical`.
#[must_use]
pub fn canonical_flag(pass: &PassProfile, raw: &str) -> String {
    let key = normalize_text(raw).replace(' ', "-");
    pass.flag
        .canonical
        .iter()
        .find(|(k, _)| normalize_text(k).replace(' ', "-") == key)
        .map_or(key, |(_, v)| v.clone())
}

/// Strip a leading `[FLAG]`, returning its canonical value and the rest.
pub(crate) fn split_flag<'a>(pass: &PassProfile, content: &'a str) -> (Option<String>, &'a str) {
    let trimmed = content.trim_start();
    if !trimmed.starts_with('[') {
        return (None, trimmed);
    }
    let Some(close) = trimmed.find(']') else {
        return (None, trimmed);
    };
    let flag = &trimmed[1..close];
    if flag.is_empty()
        || flag.len() > pass.flag.max_len
        || (flag.contains(' ') && flag.split(' ').count() > pass.flag.max_words)
    {
        return (None, trimmed);
    }
    (
        Some(canonical_flag(pass, flag)),
        trimmed[close + 1..].trim_start(),
    )
}

fn match_key<'k>(lower: &str, keys: &'k [String]) -> Option<&'k str> {
    keys.iter()
        .map(String::as_str)
        .find(|k| !k.is_empty() && lower.starts_with(&k.to_ascii_lowercase()))
}

/// The value of a keyed pipe field: after its first `:`, else after the key.
fn after_colon_or_key<'a>(part: &'a str, key: &str) -> &'a str {
    let at = part.find(':').map_or(key.len(), |i| i + 1);
    part.get(at..).unwrap_or("")
}

fn parse_pipe(pass: &PassProfile, body: &str) -> Facts {
    let f = &pass.fields;
    let mut facts = Facts::default();
    let mut positional: Vec<&str> = Vec::new();
    for part in body.split('|').map(str::trim) {
        let lower = part.to_ascii_lowercase();
        if let Some(key) = match_key(&lower, &f.entity.keys) {
            facts.entity = clean(pass, after_colon_or_key(part, key));
        } else if let Some(key) = match_key(&lower, &f.deadline.keys) {
            facts.deadline = clean(
                pass,
                part.get(key.len()..).unwrap_or("").trim_start_matches(':'),
            );
        } else if let Some(key) = match_key(&lower, &f.value.keys) {
            facts.value = clean(pass, after_colon_or_key(part, key));
        } else if let Some(key) = match_key(&lower, &f.class.keys) {
            facts.class =
                clean(pass, after_colon_or_key(part, key)).map(|v| canonical_flag(pass, &v));
        } else if let Some((name, key)) = f
            .extra
            .iter()
            .find_map(|(name, spec)| match_key(&lower, &spec.keys).map(|k| (name, k)))
        {
            match clean(pass, after_colon_or_key(part, key)) {
                Some(v) => facts.extra.insert(name.clone(), v),
                None => facts.extra.remove(name),
            };
        } else if match_key(&lower, &f.ignored_keys).is_some() {
            // Classification and provenance fields: not used for matching.
        } else if !part.is_empty() {
            positional.push(part);
        }
    }

    // A leading header field (`ACTIVE NOTICE — SCHOOL`) precedes the title in
    // some layouts.
    let mut idx = 0;
    if positional.len() > 1 {
        let head = normalize_text(positional[0]);
        let is_header = head.split(' ').count() <= f.title.header_words_max
            && f.title.header_tokens.iter().any(|t| {
                let t = normalize_text(t);
                !t.is_empty() && head.contains(&t)
            });
        if is_header {
            idx = 1;
        }
    }

    if let Some(t) = positional.get(idx + f.title.pipe_position).copied() {
        // `ABC: Title …`: a short, space-free prefix is the entity, not title.
        match t.find(':') {
            Some(colon)
                if colon <= f.title.strip_short_prefix_max
                    && !t[..colon].contains(' ')
                    && t.len() - colon > 2 =>
            {
                facts.title = t[colon + 1..].trim().to_string();
                if facts.entity.is_none() {
                    facts.entity = clean(pass, &t[..colon]);
                }
            }
            _ => facts.title = t.to_string(),
        }
    }
    if facts.entity.is_none() {
        if let Some(pos) = f.entity.pipe_position {
            facts.entity = positional.get(idx + pos).and_then(|s| clean(pass, s));
        }
    }
    if facts.deadline.is_none() {
        facts.deadline = scan_field(pass, body, &f.deadline.prose_markers);
    }
    if facts.value.is_none() {
        facts.value = scan_value(pass, body, &f.value.prose_markers);
    }
    fill_extra_scans(pass, body, &positional, idx, &mut facts);
    facts
}

fn fill_extra_scans(
    pass: &PassProfile,
    body: &str,
    positional: &[&str],
    idx: usize,
    facts: &mut Facts,
) {
    for (name, spec) in &pass.fields.extra {
        if facts.extra.contains_key(name) {
            continue;
        }
        let v = spec
            .pipe_position
            .and_then(|pos| positional.get(idx + pos).and_then(|s| clean(pass, s)))
            .or_else(|| scan_field(pass, body, &spec.prose_markers));
        if let Some(v) = v {
            facts.extra.insert(name.clone(), v);
        }
    }
}

fn parse_prose(pass: &PassProfile, body: &str) -> Facts {
    let f = &pass.fields;
    let mut facts = Facts::default();
    // A short type prefix (`Notice:`, `Bid&Q:`) is stripped.
    let after_prefix = body
        .find(':')
        .filter(|i| *i <= f.title.prose_prefix_max)
        .map_or(body, |i| body[i + 1..].trim_start());

    let (left, right) = match after_prefix.split_once(" — ") {
        Some((l, r)) => (l.trim(), r.trim()),
        None => match after_prefix.split_once(" - ") {
            Some((l, r)) => (l.trim(), r.trim()),
            None => (after_prefix.trim(), ""),
        },
    };

    // `<HEADER> — <entity>: <title>`: the left side is a short status header.
    let left_norm = normalize_text(left);
    let header_left = left_norm.split(' ').count() <= f.title.prose_header_words_max
        && (left_norm.is_empty()
            || f.title.prose_header_tokens.iter().any(|t| {
                let t = normalize_text(t);
                !t.is_empty() && left_norm.contains(&t)
            }));

    if header_left && !right.is_empty() {
        if let Some((entity, title)) = right.split_once(':') {
            facts.entity = clean(pass, entity);
            let end = title.find([';', ',']).unwrap_or(title.len());
            facts.title = title[..end].trim().to_string();
        } else {
            facts.title = right.to_string();
        }
    } else {
        facts.title = left.to_string();
        if !right.is_empty() {
            // The entity runs to the first comma or semicolon; a trailing
            // parenthetical or sentence is not part of it.
            let end = right.find([',', ';']).unwrap_or(right.len());
            let mut entity = right[..end].trim();
            if let Some(paren) = entity.find('(') {
                entity = entity[..paren].trim();
            }
            if let Some(dot) = entity.find(". ") {
                entity = entity[..dot].trim();
            }
            facts.entity = clean(pass, entity);
        }
    }

    facts.deadline = scan_field(pass, body, &f.deadline.prose_markers);
    facts.value = scan_value(pass, body, &f.value.prose_markers);
    fill_extra_scans(pass, body, &[], 0, &mut facts);
    facts
}

/// `<marker><value>` up to `,` `;` or `|`, for the first marker that yields a
/// present value. Markers match case-insensitively (ASCII), so byte offsets
/// in the lowered text are offsets in the original.
fn scan_field(pass: &PassProfile, rest: &str, markers: &[String]) -> Option<String> {
    let lower = rest.to_ascii_lowercase();
    for marker in markers.iter().filter(|m| !m.is_empty()) {
        if let Some(pos) = lower.find(&marker.to_ascii_lowercase()) {
            let tail = &rest[pos + marker.len()..];
            let end = tail.find([',', ';', '|']).unwrap_or(tail.len());
            if let Some(v) = clean(pass, &tail[..end]) {
                return Some(v);
            }
        }
    }
    None
}

/// Like [`scan_field`], but a comma inside a figure (`3,000,000`) does not end
/// the value; a comma before a non-digit or a sentence end does.
fn scan_value(pass: &PassProfile, rest: &str, markers: &[String]) -> Option<String> {
    let lower = rest.to_ascii_lowercase();
    for marker in markers.iter().filter(|m| !m.is_empty()) {
        if let Some(pos) = lower.find(&marker.to_ascii_lowercase()) {
            let tail = &rest[pos + marker.len()..];
            let end = tail.find([';', '|']).unwrap_or(tail.len());
            let bytes = tail.as_bytes();
            let mut cut = end;
            for (i, b) in bytes.iter().enumerate().take(end) {
                let next = bytes.get(i + 1);
                let comma_break = *b == b',' && !next.is_some_and(u8::is_ascii_digit);
                let sentence_break = *b == b'.' && next.is_some_and(u8::is_ascii_whitespace);
                if comma_break || sentence_break {
                    cut = i;
                    break;
                }
            }
            if let Some(v) = clean(pass, &tail[..cut]) {
                return Some(v);
            }
        }
    }
    None
}
