//! The versions of an agent's Ed25519 `client_assertion`
//! (`client_assertion_type=urn:epigraph:ed25519`) and the switch that decides
//! whether the old one is still accepted (backlog bada894d, 950696a1).
//!
//! The wire format is the same 88 bytes in both versions:
//! `timestamp(8, big-endian) || nonce(16) || Ed25519 signature(64)`. Only the
//! SIGNED message differs:
//!
//! * version 2 ([`AssertionVersion::V2`]) signs
//!   `epigraph_crypto::oauth_assertion_message(issuer, timestamp, nonce)`, so
//!   the signature names this authorization server (its published `issuer`)
//!   and what it is for;
//! * version 1 ([`AssertionVersion::V1`], deprecated) signed the bare 24
//!   bytes `timestamp || nonce`, good at any server that knows the key.
//!
//! The token endpoint tries version 2 first. A version-1 assertion is accepted
//! while [`AssertionV1Policy::Accept`] (the default) holds, logged and counted
//! (one `security_events` row, [`V1_ACCEPTED_EVENT`]), and refused under
//! [`AssertionV1Policy::Refuse`]. Either version's nonce is spent once
//! (migration 213).

/// The environment variable [`AssertionV1Policy::from_env`] reads.
pub const ASSERTION_V1_ENV: &str = "EPIGRAPH_ASSERTION_V1";

/// The `security_events.event_type` of one ACCEPTED version-1 assertion
/// (written after its nonce was spent, so a replay never adds a row). Count
/// these per `details->>'client_id'` to see who still signs version 1 before
/// setting [`ASSERTION_V1_ENV`] to `refuse`.
pub const V1_ACCEPTED_EVENT: &str = "oauth.agent_assertion_v1_accepted";

/// Which message an accepted agent assertion was signed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionVersion {
    /// The bare `timestamp || nonce` (deprecated): bound to no server.
    V1,
    /// `epigraph_crypto::oauth_assertion_message`: bound to this issuer.
    V2,
}

impl AssertionVersion {
    /// `"v1"` / `"v2"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// Whether the token endpoint still accepts a version-1 agent assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AssertionV1Policy {
    /// Accept it, with a warning and a `security_events` row (the default,
    /// so a deploy of the version-2 verifier breaks no agent).
    #[default]
    Accept,
    /// Refuse it (`invalid_client`, like every other failed credential).
    Refuse,
}

impl AssertionV1Policy {
    /// Parse [`ASSERTION_V1_ENV`]'s value: unset or blank is `accept`;
    /// `accept` and `refuse` in any case. Anything else is an error, so a typo
    /// never silently keeps (or drops) the old assertion.
    ///
    /// # Errors
    /// A message naming the unrecognised value.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(Self::Accept),
            Some(v) if v.eq_ignore_ascii_case("accept") => Ok(Self::Accept),
            Some(v) if v.eq_ignore_ascii_case("refuse") => Ok(Self::Refuse),
            Some(other) => Err(format!(
                "{ASSERTION_V1_ENV}={other:?} is neither `accept` nor `refuse`"
            )),
        }
    }

    /// [`Self::parse`] of the process environment.
    ///
    /// # Errors
    /// As [`Self::parse`].
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(ASSERTION_V1_ENV).ok().as_deref())
    }

    /// `"accept"` / `"refuse"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Refuse => "refuse",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_blank_accepts_version_1() {
        assert_eq!(
            AssertionV1Policy::parse(None),
            Ok(AssertionV1Policy::Accept)
        );
        assert_eq!(
            AssertionV1Policy::parse(Some("  ")),
            Ok(AssertionV1Policy::Accept)
        );
        assert_eq!(AssertionV1Policy::default(), AssertionV1Policy::Accept);
    }

    #[test]
    fn accept_and_refuse_parse_in_any_case() {
        assert_eq!(
            AssertionV1Policy::parse(Some("accept")),
            Ok(AssertionV1Policy::Accept)
        );
        assert_eq!(
            AssertionV1Policy::parse(Some("REFUSE")),
            Ok(AssertionV1Policy::Refuse)
        );
        assert_eq!(
            AssertionV1Policy::parse(Some(" refuse\n")),
            Ok(AssertionV1Policy::Refuse)
        );
    }

    #[test]
    fn any_other_value_is_an_error() {
        for raw in ["refused", "no", "off", "0", "deny"] {
            let err = AssertionV1Policy::parse(Some(raw)).unwrap_err();
            assert!(err.contains(ASSERTION_V1_ENV), "{err}");
        }
    }
}
