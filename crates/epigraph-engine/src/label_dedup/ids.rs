//! Id tokenization: lift every plausible item identifier out of free text.
//!
//! Format-independent by construction. The whole content is tokenized rather
//! than trusting a field layout, which is what lets a prose claim
//! (`Notice: … (KX-4417) — …`) match a pipe record (`… KX-4417 … | …`).
//!
//! A piece is split on whitespace and `| , ; "`, then on `( ) [ ]`. The money,
//! clock-time and percent rejections test the piece BEFORE trimming:
//! trimming first turns `$48M.` into `48M` and `2:00` into `200`, both of
//! which read as plausible short ids and corroborate unrelated pairs.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::profile::{IdSpec, RejectRule};

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
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let region = scan_region(spec, content);
    for token in region.split(|c: char| c.is_whitespace() || matches!(c, '|' | ',' | ';' | '"')) {
        for piece in token.split(['(', ')', '[', ']']) {
            if let Some(id) = id_candidate(spec, piece) {
                if seen.insert(id.norm.clone()) {
                    out.push(id);
                }
            }
        }
    }
    out
}

/// Uppercase, ASCII alphanumerics only.
#[must_use]
pub fn normalize_id(token: &str) -> String {
    token
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The id a carry label holds (`<prefix><NORM>`), if `label` is one.
#[must_use]
pub fn carried_id(spec: &IdSpec, label: &str) -> Option<IdToken> {
    let prefix = spec.carry_label_prefix.as_deref()?;
    let norm = normalize_id(label.strip_prefix(prefix)?);
    if norm.is_empty() {
        return None;
    }
    let strong = is_strong(spec, &norm, &norm);
    Some(IdToken {
        raw: norm.clone(),
        norm,
        strong,
    })
}

/// `content` up to the last occurrence of the cut marker, or whole.
#[must_use]
pub fn scan_region<'a>(spec: &IdSpec, content: &'a str) -> &'a str {
    match spec.scan_cut_at_last.as_deref() {
        Some(marker) if !marker.is_empty() => {
            content.rfind(marker).map_or(content, |at| &content[..at])
        }
        _ => content,
    }
}

fn rejects(spec: &IdSpec, rule: RejectRule) -> bool {
    spec.reject.contains(&rule)
}

fn is_strong(spec: &IdSpec, raw: &str, norm: &str) -> bool {
    let digits = norm.bytes().filter(u8::is_ascii_digit).count();
    (norm.len() >= spec.strong_min_len && digits >= spec.strong_min_digits)
        || spec.compiled_strong.iter().any(|re| re.is_match(raw))
}

/// A token is a candidate id when it mixes letters and digits, or is a run of
/// at least `pure_digit_min_len` digits.
fn id_candidate(spec: &IdSpec, piece: &str) -> Option<IdToken> {
    if (rejects(spec, RejectRule::Money) && piece.contains('$'))
        || (rejects(spec, RejectRule::ClockTime) && piece.contains(':'))
        || (rejects(spec, RejectRule::Percent) && piece.contains('%'))
    {
        return None;
    }
    let t = piece.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if t.len() < spec.min_len {
        return None;
    }
    if (rejects(spec, RejectRule::IsoDate) && is_iso_date(t))
        || (rejects(spec, RejectRule::UsDate) && is_us_date(t))
        || (rejects(spec, RejectRule::BareYear) && is_bare_year(t))
        || (rejects(spec, RejectRule::YearRange) && is_year_range(t))
        || (rejects(spec, RejectRule::FiscalYear) && is_fiscal_year(t))
        || spec.compiled_reject.iter().any(|re| re.is_match(t))
    {
        return None;
    }
    if !t.bytes().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let has_alpha = t.bytes().any(|c| c.is_ascii_alphabetic());
    if !has_alpha && t.len() < spec.pure_digit_min_len {
        return None;
    }
    let norm = normalize_id(t);
    if norm.len() < spec.min_len {
        return None;
    }
    let strong = is_strong(spec, t, &norm);
    Some(IdToken {
        raw: t.to_string(),
        norm,
        strong,
    })
}

/// `YYYY-MM-DD` (shape only).
pub(crate) fn is_iso_date(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// `M/D/YY` or `M/D/YYYY`, with 1-2 digit month and day.
pub(crate) fn is_us_date(t: &str) -> bool {
    let mut parts = t.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(d), Some(y), None) => {
            (1..=2).contains(&m.len())
                && (1..=2).contains(&d.len())
                && (y.len() == 2 || y.len() == 4)
                && all_digits(m)
                && all_digits(d)
                && all_digits(y)
        }
        _ => false,
    }
}

fn all_digits(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit())
}

fn is_bare_year(t: &str) -> bool {
    // The `19` arm deliberately does not require digits after the prefix
    // (`19AB` reads as a year too); the `20` arm does.
    (t.len() == 4 && t.starts_with("19")) || (t.len() == 4 && t.starts_with("20") && all_digits(t))
}

fn is_year_range(t: &str) -> bool {
    let mut parts = t.split('-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), None) => is_bare_year(a) && is_bare_year(b),
        _ => false,
    }
}

/// A school or fiscal year: `2026-27` / `2026/27` (the second part is the
/// NEXT year's last two digits), or the same with an `FY` prefix
/// (`FY2026-27`, `FY2026-2027`). With the prefix the short forms count too:
/// `FY26-27`, `FY25/26`, and a single year `FY2026` / `FY26`. Numbering such
/// as `2026-15` or `FY28-35-X` is not the next year (or carries a suffix), so
/// it stays an id.
fn is_fiscal_year(t: &str) -> bool {
    let stripped = t
        .strip_prefix("FY")
        .or_else(|| t.strip_prefix("fy"))
        .or_else(|| t.strip_prefix("Fy"));
    let fy = stripped.is_some();
    let t = stripped.unwrap_or(t);
    if is_year_range(t) {
        return true;
    }
    if fy && (is_bare_year(t) || (t.len() == 2 && all_digits(t))) {
        return true;
    }
    let mut parts = t.split(['-', '/']);
    match (parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(yy), None)
            if (is_bare_year(y) || (fy && y.len() == 2 && all_digits(y)))
                && yy.len() == 2
                && all_digits(yy) =>
        {
            match (y.parse::<u32>(), yy.parse::<u32>()) {
                (Ok(y), Ok(yy)) => (y + 1) % 100 == yy,
                _ => false,
            }
        }
        _ => false,
    }
}
