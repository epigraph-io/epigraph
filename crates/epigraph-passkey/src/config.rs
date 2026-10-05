//! The relying party's configuration, read from the environment.
//!
//! # Absent means off, partial means refuse
//!
//! With neither [`ENV_RP_ID`] nor [`ENV_ORIGIN`] set, [`PasskeyConfig::from_env`]
//! answers `Ok(None)`: passkeys are not configured, every enrollment and
//! elevation endpoint answers 503, and nothing else changes. That is what dev
//! and CI run with.
//!
//! Anything else that is not a complete, valid configuration is an ERROR, never
//! a silent `None`: an operator who set some of the variables meant to turn
//! passkeys on, and a server that quietly answered 503 instead would hide the
//! mistake until someone tried to enroll.
//!
//! # The attestation policy (operator question EQ-1)
//!
//! While the operator ruling D3 is not in effect, whoever holds the maintenance
//! DSN can open an enrollment ticket. With `none` attestation accepted, that
//! holder could complete the ticket with a SOFTWARE authenticator and own a
//! "passkey" of the operator's. The default policy therefore requires a
//! verified attestation that chains to a configured CA
//! ([`ENV_ATTESTATION_CA_FILE`]) from an authenticator model on a configured
//! AAGUID allowlist ([`ENV_AAGUIDS`]): [`AttestationPolicy::Allowlist`].
//!
//! [`ENV_ALLOW_SOFTWARE_ATTESTATION`] replaces it with
//! [`AttestationPolicy::SoftwareAllowed`] (`none` and self attestation
//! accepted). It exists for tests and local development only, and a request
//! binary refuses to start with it on a database armed for operator binding
//! (the same refusal shape as operator ruling OQ-7 (b)).

use std::collections::BTreeSet;

use url::Url;
use uuid::Uuid;

/// The relying party id: the host name passkeys are bound to. Effectively
/// PERMANENT: a passkey registered under one `rp_id` never asserts under
/// another, so changing it orphans every registered passkey.
pub const ENV_RP_ID: &str = "EPIGRAPH_WEBAUTHN_RP_ID";

/// The exact origin (scheme, host, port) the ceremony pages are served from.
pub const ENV_ORIGIN: &str = "EPIGRAPH_WEBAUTHN_ORIGIN";

/// The AAGUID allowlist: comma- or whitespace-separated UUIDs of the
/// authenticator models whose attestation is accepted.
pub const ENV_AAGUIDS: &str = "EPIGRAPH_WEBAUTHN_AAGUIDS";

/// A PEM file of the attestation root certificates the allowlisted models
/// chain to.
pub const ENV_ATTESTATION_CA_FILE: &str = "EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE";

/// TEST AND DEVELOPMENT ONLY: accept `none` and self attestation (a software
/// authenticator). Refused at boot on an armed database.
pub const ENV_ALLOW_SOFTWARE_ATTESTATION: &str = "EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION";

/// Every variable this module reads, for a caller that reports which are set.
pub const ALL_ENV: &[&str] = &[
    ENV_RP_ID,
    ENV_ORIGIN,
    ENV_AAGUIDS,
    ENV_ATTESTATION_CA_FILE,
    ENV_ALLOW_SOFTWARE_ATTESTATION,
];

/// Which registrations the relying party accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// EQ-1 (a), the default: a verified attestation that chains to one of
    /// `ca_pem`'s certificates, from an authenticator whose AAGUID is in
    /// `aaguids`. `none` and self attestation are refused.
    Allowlist {
        /// The attestation roots, PEM (one or more certificates).
        ca_pem: Vec<u8>,
        /// The accepted authenticator models. Never empty, never the nil
        /// AAGUID (which is what `none` attestation reports).
        aaguids: BTreeSet<Uuid>,
    },
    /// TEST AND DEVELOPMENT ONLY: `none` and self attestation accepted.
    SoftwareAllowed,
}

/// A complete relying-party configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyConfig {
    /// See [`ENV_RP_ID`].
    pub rp_id: String,
    /// See [`ENV_ORIGIN`].
    pub origin: Url,
    /// See [`AttestationPolicy`].
    pub policy: AttestationPolicy,
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Some passkey variables are set but the relying party is not.
    #[error(
        "passkeys are partially configured: {set} set, but {ENV_RP_ID} and {ENV_ORIGIN} must \
         both be set to turn passkeys on (or every passkey variable unset to leave them off)"
    )]
    Partial {
        /// The variables that were set.
        set: String,
    },
    /// [`ENV_ORIGIN`] is not an origin.
    #[error(
        "{ENV_ORIGIN} is not a bare origin (scheme://host[:port], no path, query or fragment): {0}"
    )]
    Origin(String),
    /// [`ENV_RP_ID`] is empty or not a host name.
    #[error("{ENV_RP_ID} is not a host name: {0:?}")]
    RpId(String),
    /// [`ENV_ALLOW_SOFTWARE_ATTESTATION`] holds something other than a flag.
    #[error(
        "{ENV_ALLOW_SOFTWARE_ATTESTATION} must be 1/true/yes or 0/false/no (or unset), got {0:?}"
    )]
    Flag(String),
    /// The software flag was combined with an allowlist.
    #[error(
        "{ENV_ALLOW_SOFTWARE_ATTESTATION} replaces the attestation allowlist; unset \
         {ENV_AAGUIDS} and {ENV_ATTESTATION_CA_FILE}, or unset the flag"
    )]
    FlagWithAllowlist,
    /// The allowlist policy lacks its AAGUIDs or its CA file.
    #[error(
        "attestation is required ({ENV_ALLOW_SOFTWARE_ATTESTATION} is off): set {ENV_AAGUIDS} \
         to the accepted authenticator models and {ENV_ATTESTATION_CA_FILE} to their \
         attestation roots ({0} missing)"
    )]
    AllowlistMissing(&'static str),
    /// An entry of [`ENV_AAGUIDS`] is not a UUID, or is the nil UUID.
    #[error("{ENV_AAGUIDS}: {0:?} is not an authenticator AAGUID")]
    Aaguid(String),
    /// [`ENV_ATTESTATION_CA_FILE`] could not be read or holds no certificate.
    #[error("{ENV_ATTESTATION_CA_FILE}: {0}")]
    CaFile(String),
}

/// `1`/`true`/`yes` is on, `0`/`false`/`no` or empty is off (trimmed,
/// case-insensitive); anything else is an error, not off.
fn parse_flag(raw: &str) -> Result<bool, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "" | "0" | "false" | "no" => Ok(false),
        _ => Err(ConfigError::Flag(raw.to_string())),
    }
}

/// The certificates of a PEM bundle, each as its own PEM block.
#[must_use]
pub fn pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let Some(end) = after.find(END) else { break };
        out.push(after.as_bytes()[..end + END.len()].to_vec());
        rest = &after[end + END.len()..];
    }
    out
}

impl PasskeyConfig {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    /// See [`PasskeyConfig::from_lookup`].
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok(), |p| std::fs::read(p))
    }

    /// Read the configuration through `get` (a variable's value; empty counts
    /// as unset) and `read_file` (the CA file). `Ok(None)` when passkeys are
    /// not configured at all.
    ///
    /// # Errors
    /// [`ConfigError`]: a partial configuration, a malformed value, or an
    /// allowlist policy without its AAGUIDs or roots.
    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        read_file: impl Fn(&str) -> std::io::Result<Vec<u8>>,
    ) -> Result<Option<Self>, ConfigError> {
        let val = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let (rp_id, origin) = match (val(ENV_RP_ID), val(ENV_ORIGIN)) {
            (None, None) => {
                let set: Vec<&str> = ALL_ENV
                    .iter()
                    .copied()
                    .filter(|k| val(k).is_some())
                    .collect();
                if set.is_empty() {
                    return Ok(None);
                }
                return Err(ConfigError::Partial {
                    set: set.join(", "),
                });
            }
            (Some(rp_id), Some(origin)) => (rp_id, origin),
            (rp_id, origin) => {
                let set = [(ENV_RP_ID, rp_id.is_some()), (ENV_ORIGIN, origin.is_some())]
                    .iter()
                    .filter(|(_, s)| *s)
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(ConfigError::Partial { set });
            }
        };

        let RelyingParty { rp_id, origin } = RelyingParty::checked(&rp_id, &origin)?;

        let software = match val(ENV_ALLOW_SOFTWARE_ATTESTATION) {
            Some(raw) => parse_flag(&raw)?,
            None => false,
        };
        let aaguids = val(ENV_AAGUIDS);
        let ca_file = val(ENV_ATTESTATION_CA_FILE);

        let policy = if software {
            if aaguids.is_some() || ca_file.is_some() {
                return Err(ConfigError::FlagWithAllowlist);
            }
            AttestationPolicy::SoftwareAllowed
        } else {
            let aaguids = aaguids.ok_or(ConfigError::AllowlistMissing(ENV_AAGUIDS))?;
            let ca_file = ca_file.ok_or(ConfigError::AllowlistMissing(ENV_ATTESTATION_CA_FILE))?;
            let mut set = BTreeSet::new();
            for raw in aaguids.split(|c: char| c == ',' || c.is_whitespace()) {
                if raw.is_empty() {
                    continue;
                }
                let id = Uuid::parse_str(raw).map_err(|_| ConfigError::Aaguid(raw.to_string()))?;
                if id.is_nil() {
                    return Err(ConfigError::Aaguid(raw.to_string()));
                }
                set.insert(id);
            }
            if set.is_empty() {
                return Err(ConfigError::AllowlistMissing(ENV_AAGUIDS));
            }
            let ca_pem = read_file(ca_file.trim())
                .map_err(|e| ConfigError::CaFile(format!("cannot read {}: {e}", ca_file.trim())))?;
            if pem_certificates(&ca_pem).is_empty() {
                return Err(ConfigError::CaFile(format!(
                    "{} holds no PEM certificate",
                    ca_file.trim()
                )));
            }
            AttestationPolicy::Allowlist {
                ca_pem,
                aaguids: set,
            }
        };

        Ok(Some(Self {
            rp_id,
            origin,
            policy,
        }))
    }

    /// Whether this configuration accepts a software authenticator
    /// ([`AttestationPolicy::SoftwareAllowed`]): the state a request binary
    /// refuses on an armed database.
    #[must_use]
    pub fn allows_software_attestation(&self) -> bool {
        matches!(self.policy, AttestationPolicy::SoftwareAllowed)
    }
}

/// The relying party alone: the rp id and the origin, without an attestation
/// policy. What an OFFLINE VERIFIER of stored assertions needs
/// ([`crate::Verifier`]): the attestation policy governs registration, which a
/// verifier never runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    /// See [`ENV_RP_ID`].
    pub rp_id: String,
    /// See [`ENV_ORIGIN`].
    pub origin: Url,
}

impl RelyingParty {
    /// Read [`ENV_RP_ID`] and [`ENV_ORIGIN`] from the process environment.
    ///
    /// # Errors
    /// See [`RelyingParty::from_lookup`].
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read [`ENV_RP_ID`] and [`ENV_ORIGIN`] through `get` (empty counts as
    /// unset), checked exactly as [`PasskeyConfig::from_lookup`] checks them.
    /// Every other passkey variable is ignored: with neither of the two set
    /// this answers `Ok(None)`, whatever else is set.
    ///
    /// # Errors
    /// [`ConfigError::Partial`] (one of the two is set),
    /// [`ConfigError::RpId`] or [`ConfigError::Origin`].
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let val = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        match (val(ENV_RP_ID), val(ENV_ORIGIN)) {
            (None, None) => Ok(None),
            (Some(rp_id), Some(origin)) => Self::checked(&rp_id, &origin).map(Some),
            (Some(_), None) => Err(ConfigError::Partial {
                set: ENV_RP_ID.to_string(),
            }),
            (None, Some(_)) => Err(ConfigError::Partial {
                set: ENV_ORIGIN.to_string(),
            }),
        }
    }

    /// The rp id (trimmed, lower-cased, a bare host name) and the origin (a
    /// bare origin), or why not.
    fn checked(rp_id: &str, origin: &str) -> Result<Self, ConfigError> {
        let rp_id = rp_id.trim().to_ascii_lowercase();
        if rp_id.contains(['/', ':', ' ']) || rp_id.starts_with('.') || rp_id.ends_with('.') {
            return Err(ConfigError::RpId(rp_id));
        }
        Ok(Self {
            rp_id,
            origin: parse_origin(origin.trim())?,
        })
    }
}

fn parse_origin(raw: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(raw).map_err(|e| ConfigError::Origin(format!("{raw}: {e}")))?;
    let bare = matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !bare {
        return Err(ConfigError::Origin(raw.to_string()));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn read(vars: &[(&str, &str)]) -> Result<Option<PasskeyConfig>, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        PasskeyConfig::from_lookup(
            |k| map.get(k).cloned(),
            |p| {
                if p == "/ca.pem" {
                    Ok(CA.as_bytes().to_vec())
                } else if p == "/empty.pem" {
                    Ok(b"not a certificate".to_vec())
                } else {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                }
            },
        )
    }

    const AAGUID: &str = "2fc0579f-8113-47ea-b116-bb5a8db9202a";

    fn full() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_RP_ID, "auth.example.com"),
            (ENV_ORIGIN, "https://auth.example.com"),
            (ENV_AAGUIDS, AAGUID),
            (ENV_ATTESTATION_CA_FILE, "/ca.pem"),
        ]
    }

    /// Nothing set is "passkeys off", and so is a variable set to blanks.
    /// Mutation: the empty-string filter dropped -> the blank RP id is a
    /// partial configuration.
    #[test]
    fn nothing_set_is_off() {
        assert_eq!(read(&[]), Ok(None));
        assert_eq!(read(&[(ENV_RP_ID, "  ")]), Ok(None));
    }

    /// A partial configuration is an error naming what was set, never a
    /// silent `None` (which would 503 every ceremony and hide the mistake).
    /// Mutation: the `(None, None)` arm returns `Ok(None)` unconditionally ->
    /// the AAGUID-only case is off.
    #[test]
    fn a_partial_configuration_is_refused() {
        for vars in [
            vec![(ENV_RP_ID, "auth.example.com")],
            vec![(ENV_ORIGIN, "https://auth.example.com")],
            vec![(ENV_AAGUIDS, AAGUID)],
            vec![(ENV_ALLOW_SOFTWARE_ATTESTATION, "1")],
        ] {
            match read(&vars) {
                Err(ConfigError::Partial { set }) => {
                    assert!(set.contains(vars[0].0), "{set}");
                }
                other => panic!("{vars:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_allowlist_policy_is_the_default() {
        let cfg = read(&full()).unwrap().unwrap();
        assert_eq!(cfg.rp_id, "auth.example.com");
        assert_eq!(cfg.origin.as_str(), "https://auth.example.com/");
        match cfg.policy {
            AttestationPolicy::Allowlist { aaguids, ca_pem } => {
                assert_eq!(aaguids.len(), 1);
                assert_eq!(ca_pem, CA.as_bytes());
            }
            AttestationPolicy::SoftwareAllowed => panic!("software"),
        }
        assert!(!read(&full())
            .unwrap()
            .unwrap()
            .allows_software_attestation());
    }

    /// Without the software flag, the allowlist and its roots are REQUIRED.
    /// Mutation: a missing allowlist falls back to `SoftwareAllowed` -> each
    /// case answers Ok.
    #[test]
    fn attestation_is_required_unless_the_flag_says_otherwise() {
        let base = &full()[..2];
        assert_eq!(read(base), Err(ConfigError::AllowlistMissing(ENV_AAGUIDS)));
        let mut v = base.to_vec();
        v.push((ENV_AAGUIDS, AAGUID));
        assert_eq!(
            read(&v),
            Err(ConfigError::AllowlistMissing(ENV_ATTESTATION_CA_FILE))
        );
        let mut v = full();
        v[3] = (ENV_ATTESTATION_CA_FILE, "/missing.pem");
        assert!(matches!(read(&v), Err(ConfigError::CaFile(_))));
        v[3] = (ENV_ATTESTATION_CA_FILE, "/empty.pem");
        assert!(matches!(read(&v), Err(ConfigError::CaFile(_))));
        let mut v = full();
        v[2] = (ENV_AAGUIDS, "00000000-0000-0000-0000-000000000000");
        assert!(matches!(read(&v), Err(ConfigError::Aaguid(_))));
        v[2] = (ENV_AAGUIDS, "not-a-uuid");
        assert!(matches!(read(&v), Err(ConfigError::Aaguid(_))));
    }

    /// The software flag is a strict flag, and it does not combine with an
    /// allowlist. Mutation: an unknown flag value read as off -> `"on"`
    /// answers Ok.
    #[test]
    fn the_software_flag_is_strict_and_exclusive() {
        let mut v = full()[..2].to_vec();
        v.push((ENV_ALLOW_SOFTWARE_ATTESTATION, "1"));
        let cfg = read(&v).unwrap().unwrap();
        assert_eq!(cfg.policy, AttestationPolicy::SoftwareAllowed);
        assert!(cfg.allows_software_attestation());
        let mut bad = v.clone();
        bad[2] = (ENV_ALLOW_SOFTWARE_ATTESTATION, "on");
        assert!(matches!(read(&bad), Err(ConfigError::Flag(_))));
        let mut off = full();
        off.push((ENV_ALLOW_SOFTWARE_ATTESTATION, "0"));
        assert!(!read(&off).unwrap().unwrap().allows_software_attestation());
        let mut both = full();
        both.push((ENV_ALLOW_SOFTWARE_ATTESTATION, "true"));
        assert_eq!(read(&both), Err(ConfigError::FlagWithAllowlist));
    }

    #[test]
    fn the_origin_is_a_bare_origin() {
        for bad in [
            "auth.example.com",
            "https://auth.example.com/elevate",
            "https://auth.example.com/?x=1",
            "ftp://auth.example.com",
            "https://user@auth.example.com",
        ] {
            let mut v = full();
            v[1] = (ENV_ORIGIN, bad);
            assert!(matches!(read(&v), Err(ConfigError::Origin(_))), "{bad}");
        }
        let mut v = full();
        v[1] = (ENV_ORIGIN, "https://auth.example.com:8443");
        assert_eq!(
            read(&v).unwrap().unwrap().origin.as_str(),
            "https://auth.example.com:8443/"
        );
    }

    /// An offline verifier needs the relying party alone: the rp id and the
    /// origin, checked exactly as the full configuration checks them. The
    /// attestation variables configure REGISTRATION, which a verifier never
    /// runs, so they neither complete nor break its configuration (a CA file
    /// that does not exist is never read). Mutations: the attestation
    /// variables read (the missing CA file refuses the `full()` case); the
    /// origin check skipped (the path-bearing origin is accepted); a partial
    /// relying party read as off (the rp-id-only case answers `Ok(None)`).
    #[test]
    fn a_verifier_reads_the_relying_party_alone() {
        let rp = |vars: &[(&str, &str)]| {
            let map: HashMap<String, String> = vars
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            RelyingParty::from_lookup(|k| map.get(k).cloned())
        };
        assert_eq!(rp(&[]), Ok(None));
        assert_eq!(
            rp(&[(ENV_AAGUIDS, AAGUID), (ENV_ALLOW_SOFTWARE_ATTESTATION, "1")]),
            Ok(None),
            "attestation variables alone configure no relying party"
        );
        let mut v = full();
        v[0] = (ENV_RP_ID, " Auth.Example.COM ");
        v[3] = (ENV_ATTESTATION_CA_FILE, "/missing.pem");
        let got = rp(&v).unwrap().unwrap();
        assert_eq!(got.rp_id, "auth.example.com");
        assert_eq!(got.origin.as_str(), "https://auth.example.com/");
        for vars in [
            vec![(ENV_RP_ID, "auth.example.com")],
            vec![(ENV_ORIGIN, "https://auth.example.com")],
        ] {
            match rp(&vars) {
                Err(ConfigError::Partial { set }) => assert_eq!(set, vars[0].0),
                other => panic!("{vars:?}: {other:?}"),
            }
        }
        let mut v = full()[..2].to_vec();
        v[1] = (ENV_ORIGIN, "https://auth.example.com/elevate");
        assert!(matches!(rp(&v), Err(ConfigError::Origin(_))));
        let mut v = full()[..2].to_vec();
        v[0] = (ENV_RP_ID, "auth.example.com:443");
        assert!(matches!(rp(&v), Err(ConfigError::RpId(_))));
    }

    #[test]
    fn a_pem_bundle_splits_into_certificates() {
        let two = format!("{CA}junk\n{CA}");
        assert_eq!(pem_certificates(two.as_bytes()).len(), 2);
        assert!(pem_certificates(b"nothing").is_empty());
    }
}
