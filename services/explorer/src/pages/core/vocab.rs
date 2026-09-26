//! Display vocabulary shared by the core pages: evidence-type names, source
//! links (DOIs), and number/date formatting.
//!
//! Evidence types come from three different vocabularies depending on the
//! endpoint (critique.md "Evidence type vocabularies"); [`evidence_type_label`]
//! maps all of them onto one set of display names.

use serde::Serialize;
use url::Url;
use uuid::Uuid;

/// Placeholder for a missing number.
pub const DASH: &str = "—";

/// One display name for every evidence-type vocabulary upstream uses:
///
/// - `/claims/:id/evidence`: `empirical | testimonial | analytical |
///   statistical | figure` (mapped from the serde-tagged `EvidenceType`;
///   `empirical` is Document *or* Observation).
/// - `/search/evidence`: the column CHECK set `document | observation |
///   testimony | computation | reference | figure | conversational`.
/// - `/evidence/:id`: `properties->>'evidence_type'`, else `unknown`.
///
/// Unknown values are shown as-is (underscores to spaces), never dropped.
pub fn evidence_type_label(raw: &str) -> String {
    let folded = raw.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    let label = match folded.as_str() {
        "empirical" => "Document or observation",
        "document" => "Document",
        "observation" => "Observation",
        "testimonial" | "testimony" => "Testimony",
        "analytical" | "literature" | "reference" => "Literature",
        "statistical" | "consensus" => "Consensus",
        "computation" | "computational" => "Computation",
        "figure" => "Figure",
        "conversational" | "conversation" => "Conversation",
        "" | "unknown" => "Unspecified",
        _ => return folded.replace('_', " "),
    };
    label.to_string()
}

/// A source reference: a link when it is an http(s) URL or a DOI, else text.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourceLink {
    pub text: String,
    pub href: Option<String>,
}

/// Interpret a `source_url`-ish value. `/claims/:id/evidence` puts a *bare*
/// DOI there for literature and figure evidence, so a DOI becomes
/// `https://doi.org/<doi>`; an http(s) URL is kept; anything else (a
/// testimony source, a `javascript:` URL, …) is plain text.
pub fn source_link(raw: &str) -> Option<SourceLink> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(href) = doi_url(raw) {
        return Some(SourceLink {
            text: raw.to_string(),
            href: Some(href),
        });
    }
    let href = Url::parse(raw)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .map(|u| u.to_string());
    Some(SourceLink {
        text: raw.to_string(),
        href,
    })
}

/// `https://doi.org/<doi>` for a bare DOI, `doi:<doi>`, or a doi.org URL.
pub fn doi_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    let doi = [
        "https://doi.org/",
        "http://doi.org/",
        "https://dx.doi.org/",
        "http://dx.doi.org/",
        "doi:",
    ]
    .iter()
    .find(|p| lower.starts_with(*p))
    .map(|p| s[p.len()..].trim_start())
    .unwrap_or(s);
    if !is_doi(doi) {
        return None;
    }
    let mut out = String::from("https://doi.org/");
    for b in doi.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:;()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Some(out)
}

/// `10.<4-9 digits>/<suffix>` with no whitespace (the Crossref shape).
fn is_doi(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("10.") else {
        return false;
    };
    let Some((registrant, suffix)) = rest.split_once('/') else {
        return false;
    };
    let registrant_ok =
        (4..=9).contains(&registrant.len()) && registrant.bytes().all(|b| b.is_ascii_digit());
    registrant_ok && !suffix.is_empty() && !suffix.chars().any(char::is_whitespace)
}

/// `0.75`, or [`DASH`] when missing or not finite.
pub fn fmt_prob(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.2}"),
        _ => DASH.to_string(),
    }
}

/// `92%` for a similarity in `0..=1`.
pub fn fmt_percent(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{:.0}%", x * 100.0),
        _ => DASH.to_string(),
    }
}

/// Thousands-separated integer: `343,000`.
pub fn fmt_count(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        out.insert(0, '-');
    }
    out
}

/// The date part of an RFC 3339 timestamp (`2026-01-02`); the raw string if
/// it does not parse.
pub fn fmt_date(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw.trim())
        .map(|d| d.with_timezone(&chrono::Utc).format("%Y-%m-%d").to_string())
        .unwrap_or_else(|_| raw.trim().to_string())
}

/// `2026-01-02 03:04 UTC`.
pub fn fmt_datetime(d: &chrono::DateTime<chrono::Utc>) -> String {
    d.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// First 8 hex digits: enough to tell ids apart on one page.
pub fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Collapse runs of whitespace (newlines in claim text) into single spaces,
/// for one-line contexts such as titles and OG tags.
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_vocabularies_share_display_names() {
        assert_eq!(evidence_type_label("testimonial"), "Testimony");
        assert_eq!(evidence_type_label("testimony"), "Testimony");
        assert_eq!(evidence_type_label("analytical"), "Literature");
        assert_eq!(evidence_type_label("reference"), "Literature");
        assert_eq!(evidence_type_label("statistical"), "Consensus");
        assert_eq!(evidence_type_label("FIGURE"), "Figure");
        assert_eq!(evidence_type_label("unknown"), "Unspecified");
        assert_eq!(evidence_type_label(""), "Unspecified");
        assert_eq!(evidence_type_label("lab_notebook"), "lab notebook");
    }

    #[test]
    fn dois_become_doi_org_links() {
        assert_eq!(
            doi_url("10.1038/nature12373").as_deref(),
            Some("https://doi.org/10.1038/nature12373")
        );
        assert_eq!(
            doi_url("doi:10.1000/xyz<1>").as_deref(),
            Some("https://doi.org/10.1000/xyz%3C1%3E")
        );
        assert_eq!(
            doi_url("https://doi.org/10.1000/abc").as_deref(),
            Some("https://doi.org/10.1000/abc")
        );
        assert_eq!(doi_url("10.12/too-short"), None);
        assert_eq!(doi_url("10.1000/has space"), None);
        assert_eq!(doi_url("not a doi"), None);
    }

    #[test]
    fn only_http_urls_and_dois_are_links() {
        let doi = source_link("10.1038/nature12373").unwrap();
        assert_eq!(
            doi.href.as_deref(),
            Some("https://doi.org/10.1038/nature12373")
        );
        let web = source_link("https://example.com/paper.pdf").unwrap();
        assert_eq!(web.href.as_deref(), Some("https://example.com/paper.pdf"));
        let js = source_link("javascript:alert(1)").unwrap();
        assert_eq!(js.href, None, "never a javascript: link");
        assert_eq!(js.text, "javascript:alert(1)");
        let who = source_link("Dr. Example, interview").unwrap();
        assert_eq!(who.href, None);
        assert_eq!(source_link("  "), None);
    }

    #[test]
    fn numbers_and_dates() {
        assert_eq!(fmt_prob(Some(0.756)), "0.76");
        assert_eq!(fmt_prob(None), DASH);
        assert_eq!(fmt_prob(Some(f64::NAN)), DASH);
        assert_eq!(fmt_percent(Some(0.923)), "92%");
        assert_eq!(fmt_count(343000), "343,000");
        assert_eq!(fmt_count(12), "12");
        assert_eq!(fmt_count(-1234), "-1,234");
        assert_eq!(fmt_date("2026-01-02T03:04:05.123+00:00"), "2026-01-02");
        assert_eq!(fmt_date("yesterday"), "yesterday");
        assert_eq!(one_line(" a\n\n b\tc "), "a b c");
        assert_eq!(
            short_id(Uuid::parse_str("0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10").unwrap()),
            "0b9a5a4e"
        );
    }
}
