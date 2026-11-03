//! The refusal codes migration 176 gave to designed database refusals that an
//! API or MCP caller can reach (backlog e2c22c7c, ruling R-25).
//!
//! A designed refusal's MESSAGE opens with its code (`GRM05: ...`); its
//! SQLSTATE is the one it had before 176, so callers that branch on the
//! SQLSTATE answer as before. The MCP layer sends any message that opens with
//! a code (`epigraph_mcp::errors::internal_error`). The HTTP layer sends the
//! message only for a code listed here, each reviewed for what its text
//! discloses (`From<DbError> for ApiError`): an older coded refusal whose text
//! nobody reviewed for the HTTP body stays the redacted 500.
//!
//! `tests/caller_refusal_codes_restatement.rs` pins that this list is exactly
//! the set of codes 176 introduces.
//!
//! The supersede architecture's refusal codes (`SR01`..`SR13`, SPEC section
//! 7.2) follow 176's pattern but are not 176's, so they live in a second
//! reviewed list, [`SUPERSEDE_REFUSAL_CODES`], each code added by the
//! migration that first raises it. [`caller_refusal_code`] consults both.

/// Every refusal code migration 176 introduced.
#[rustfmt::skip]
pub const CALLER_REFUSAL_CODES: &[&str] = &[
    // epigraph_admin_act_args (130): an admin act's kind and arguments.
    "AAR01", "AAR02", "AAR03", "AAR04", "AAR05", "AAR06",
    "AAR07", "AAR08", "AAR09", "AAR10", "AAR11",
    // epigraph_propose_admin_act (130): passkey.register names the proposer.
    "AAR12",
    // epigraph_owner_immutable_guard (115), epigraph_writer_owner_guard (114).
    "TEN01", "TEN02",
    // 108, 109 and 164's guards on groups and group_memberships.
    "GRM01", "GRM02", "GRM03", "GRM04", "GRM05", "GRM06",
    // epigraph_no_public_sealed (081).
    "PRV01",
    // epigraph_agents_refuse_registered_system_key (148).
    "AGK01",
];

/// The supersede architecture's caller-reachable refusal codes (SPEC section
/// 7.2), each reviewed for what its message discloses (row ids go in DETAIL).
/// The SQLSTATE of each is the class its HTTP answer follows: `42501` -> 403,
/// `55000` -> 409.
#[rustfmt::skip]
pub const SUPERSEDE_REFUSAL_CODES: &[&str] = &[
    // Migration 194 (H10): delete a retracted BBA outside the purge definer.
    "SR09",
];

/// The code `message` opens with, `"CODE: ..."`, when `list` names it.
fn listed_code(message: &str, list: &'static [&'static str]) -> Option<&'static str> {
    let (code, _) = message.split_once(": ")?;
    list.iter().copied().find(|c| *c == code)
}

/// The [`CALLER_REFUSAL_CODES`] or [`SUPERSEDE_REFUSAL_CODES`] entry `message`
/// opens with (`"GRM05: ..."` gives `Some("GRM05")`), or `None`.
#[must_use]
pub fn caller_refusal_code(message: &str) -> Option<&'static str> {
    listed_code(message, CALLER_REFUSAL_CODES)
        .or_else(|| listed_code(message, SUPERSEDE_REFUSAL_CODES))
}

/// The [`SUPERSEDE_REFUSAL_CODES`] entry `message` opens with, or `None`.
#[must_use]
pub fn supersede_refusal_code(message: &str) -> Option<&'static str> {
    listed_code(message, SUPERSEDE_REFUSAL_CODES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_listed_code_at_the_start_is_recognised() {
        assert_eq!(caller_refusal_code("GRM05: the roster"), Some("GRM05"));
        assert_eq!(caller_refusal_code("AGK01: agents: x"), Some("AGK01"));
        for other in [
            // An older code no one reviewed for the HTTP body.
            "FA07: duplicate x is bound",
            "CR04: x is not a resolution status",
            // Listed, but not at the start, or not followed by ": ".
            "x GRM05: the roster",
            "GRM05 the roster",
            "GRM05:the roster",
            "grm05: the roster",
            "",
        ] {
            assert_eq!(caller_refusal_code(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_supersede_code_is_recognised_by_both_and_kept_out_of_176s_list() {
        assert_eq!(caller_refusal_code("SR09: a retracted x"), Some("SR09"));
        assert_eq!(supersede_refusal_code("SR09: a retracted x"), Some("SR09"));
        assert!(!CALLER_REFUSAL_CODES.contains(&"SR09"));
        // A 176 code is a caller code but not a supersede code.
        assert_eq!(supersede_refusal_code("GRM05: the roster"), None);
        for other in [
            "SR99: unlisted",
            "SR10: not yet raised",
            "x SR09: y",
            "SR09 y",
            "sr09: y",
        ] {
            assert_eq!(caller_refusal_code(other), None, "{other:?}");
            assert_eq!(supersede_refusal_code(other), None, "{other:?}");
        }
    }
}
