//! Source-licence policy shared by every ingest path (backlog 8709d128,
//! 1a462cc1): whether a source's verbatim passages may be republished in
//! `evidence.raw_content`, or only a locator plus a BLAKE3 hash of them.
//!
//! The database enforces the same rule (migration 349, backlog b62ae3f2): a
//! literature or figure evidence row carrying a passage, image or caption is
//! refused unless the paper's recorded licence passes
//! `public.epigraph_passage_retention_permitted`, a SQL mirror of
//! [`passage_retention_permitted`]. Change the two together: the parity test
//! `epigraph-mcp/tests/evidence_passage_licence_guard.rs` runs both over one
//! corpus and fails when they disagree.

/// Whether a source under `licence` may have its verbatim text republished in
/// `evidence.raw_content` (backlog 8709d128). An exact allowlist, matched
/// case-insensitively with spaces and underscores read as hyphens:
/// `PUBLIC-DOMAIN`, `PD`, `CC0`, `CC0-1.0`, the bare `CC-BY` / `CC-BY-SA`,
/// and the SPDX ids `CC-BY-<d.d>` / `CC-BY-SA-<d.d>` with an optional
/// jurisdiction port (`CC-BY-3.0-IGO`). Everything else is
/// all-rights-reserved for this purpose: `None` (unknown), every
/// non-commercial or no-derivatives variant however it is spelled, and any
/// free text. The graph is exported as a unit, so a licence that restricts
/// reuse cannot ride along. An unrecognised spelling fails closed.
#[must_use]
pub fn passage_retention_permitted(licence: Option<&str>) -> bool {
    let Some(licence) = licence else {
        return false;
    };
    let id = licence.trim().to_ascii_uppercase().replace([' ', '_'], "-");
    if matches!(
        id.as_str(),
        "PUBLIC-DOMAIN" | "PD" | "CC0" | "CC0-1.0" | "CC-BY" | "CC-BY-SA"
    ) {
        return true;
    }
    let Some(rest) = id
        .strip_prefix("CC-BY-SA-")
        .or_else(|| id.strip_prefix("CC-BY-"))
    else {
        return false;
    };
    let (version, port) = match rest.split_once('-') {
        Some((version, port)) => (version, Some(port)),
        None => (rest, None),
    };
    is_cc_licence_version(version)
        && match port {
            None => true,
            Some(port) => is_cc_jurisdiction_port(port),
        }
}

/// A Creative Commons licence version as SPDX writes it: `<digit>.<digit>`.
fn is_cc_licence_version(version: &str) -> bool {
    matches!(version.as_bytes(), [major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit())
}

/// A CC jurisdiction port suffix (`US`, `IGO`, `AU`): 2-4 letters, and never
/// a licence element (`NC`, `ND`, `SA`) misplaced after the version.
fn is_cc_jurisdiction_port(port: &str) -> bool {
    (2..=4).contains(&port.len())
        && port.bytes().all(|b| b.is_ascii_uppercase())
        && !matches!(port, "NC" | "ND" | "SA")
}
