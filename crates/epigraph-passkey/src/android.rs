//! What this crate checks of an `android-key` attestation itself, on top of
//! `webauthn-rs-core` 0.5.5 (used unmodified):
//!
//! * the security level. The library accepts a KeyDescription whose
//!   `attestationSecurityLevel` / `keyMintSecurityLevel` is 0 (Software) and
//!   whose `purpose` / `origin` sit only in the SOFTWARE-enforced list: a key
//!   in a software keystore. This crate requires both levels to be
//!   TrustedEnvironment (1) or StrongBox (2), and `purpose` (SIGN) and
//!   `origin` (GENERATED) in the HARDWARE-enforced list ([`hardware_rules`]).
//!   The 0.5.5 parser refuses level 2 outright (`InvalidTag`), so a StrongBox
//!   key cannot register through it today; this crate admits level 2 so that
//!   a library that parses it needs no change here.
//! * where the KeyDescription sits. Only the first occurrence counts, and it
//!   must be the leaf's: a chain in which any other certificate also carries
//!   one is refused (Google's guidance: a later occurrence may be an
//!   attacker's certificate extending a genuine chain).
//! * revocation. Google publishes the serial numbers of revoked and suspended
//!   attestation certificates at <https://android.googleapis.com/attestation/status>.
//!   The library loads no CRL and no status list, so this crate reads an
//!   operator-refreshed local copy ([`StatusList`]): every certificate of the
//!   chain, the root included, must be absent from it (looked up by its serial
//!   in lowercase hex AND in decimal: the published list keys its 64-bit
//!   serials in decimal and its 128-bit ones in hex, measured 2026-11-06:
//!   981 of 1,771 entries were 17-20 decimal digits), and a copy older than
//!   [`ANDROID_KEY_STATUS_MAX_AGE`] refuses every Android enrollment and
//!   anchor (fail closed). Nothing here reaches the network.
//!
//! All of it is read from the certificates themselves, never from the
//! library's recorded `AndroidKey { is_km_tee, is_attest_tee }` metadata,
//! which is stored in a row the request DSN writes.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::der::{
    parse_der, parse_der_container, parse_der_enum, parse_der_integer, parse_der_octetstring,
    Header, Tag,
};
use x509_parser::der_parser::error::{BerError, BerResult};

/// The Android key attestation extension (`KeyDescription`).
pub const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// The oldest a status list copy may be (by its file's modification time) for
/// an Android enrollment or anchor to proceed: 48 hours. A daily refresh job
/// leaves a day's slack for one failed run.
pub const ANDROID_KEY_STATUS_MAX_AGE: Duration = Duration::from_secs(48 * 60 * 60);

/// The age past which a status list copy is reported as AGING: a WARN at
/// boot and at every use, a day before it is refused at
/// [`ANDROID_KEY_STATUS_MAX_AGE`]. A daily refresh job that ran keeps the
/// file younger than this; one that failed, or stopped, does not.
pub const ANDROID_KEY_STATUS_WARN_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How a status list copy's age stands ([`freshness`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFreshness {
    /// At most [`ANDROID_KEY_STATUS_WARN_AGE`] old.
    Fresh,
    /// Older than [`ANDROID_KEY_STATUS_WARN_AGE`], at most
    /// [`ANDROID_KEY_STATUS_MAX_AGE`]: still used, and logged at WARN (the
    /// refresh job has missed a run).
    Aging,
    /// Older than [`ANDROID_KEY_STATUS_MAX_AGE`]: refused (fail closed).
    Stale,
}

/// How a copy `age` old stands.
#[must_use]
pub fn freshness(age: Duration) -> StatusFreshness {
    if age > ANDROID_KEY_STATUS_MAX_AGE {
        StatusFreshness::Stale
    } else if age > ANDROID_KEY_STATUS_WARN_AGE {
        StatusFreshness::Aging
    } else {
        StatusFreshness::Fresh
    }
}

/// How old the file at `path` is at `now`, by its modification time. A file
/// dated in the future within the clock-skew allowance is 0 old.
///
/// # Errors
/// It cannot be read, or it is dated further in the future than the skew
/// allows (a copy dated far ahead would stay "fresh" forever).
pub fn age_of(path: &Path, now: SystemTime) -> Result<Duration, String> {
    let shown = path.display();
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| format!("the attestation status list {shown} cannot be read: {e}"))?;
    match now.duration_since(modified) {
        Ok(age) => Ok(age),
        Err(ahead) if ahead.duration() > STATUS_FUTURE_SKEW => Err(format!(
            "the attestation status list {shown} is dated {}s in the future",
            ahead.duration().as_secs()
        )),
        Err(_) => Ok(Duration::ZERO),
    }
}

/// How far in the future a status file's modification time may be (clock
/// skew) before the file is refused: a time far ahead would keep a stale copy
/// "fresh" forever.
const STATUS_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

/// `keyMintSecurityLevel` / `attestationSecurityLevel`: TrustedEnvironment.
const LEVEL_TEE: u32 = 1;
/// StrongBox.
const LEVEL_STRONGBOX: u32 = 2;
/// `origin` GENERATED: the key was generated in the keystore.
const ORIGIN_GENERATED: u32 = 0;
/// `purpose` SIGN.
const PURPOSE_SIGN: u32 = 2;

/// A serial number's big-endian bytes as a status list keys it: lowercase
/// hex, no leading zeros (`"0"` for zero).
#[must_use]
pub fn serial_hex(raw: &[u8]) -> String {
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// A status list key in the same form ([`serial_hex`]), or `None` when it is
/// not hex.
fn normalized_key(key: &str) -> Option<String> {
    let lower = key.trim().to_ascii_lowercase();
    if lower.is_empty() || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let trimmed = lower.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    })
}

/// A serial number's big-endian bytes in decimal, the other form the
/// published list keys serials in.
#[must_use]
pub fn serial_decimal(raw: &[u8]) -> String {
    x509_parser::num_bigint::BigUint::from_bytes_be(raw).to_str_radix(10)
}

/// A local copy of Google's attestation status list: `{"entries": {<serial>:
/// {"status": "REVOKED" | "SUSPENDED", ...}}}`. Google's schema documents the
/// key as the serial in lowercase hex; the published list also keys serials
/// in decimal, so a certificate is looked up in both forms
/// ([`Self::status_of_serial`]). Every listed serial is NOT in good standing,
/// whatever its status says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusList {
    entries: BTreeMap<String, String>,
}

impl StatusList {
    /// Parse a list in Google's format.
    ///
    /// # Errors
    /// Not JSON, no `entries` object, a key that is not hex, or an entry
    /// without a `status` string.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let v: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("not a JSON document: {e}"))?;
        let entries = v
            .get("entries")
            .and_then(Value::as_object)
            .ok_or_else(|| "no `entries` object".to_string())?;
        let mut out = BTreeMap::new();
        for (key, entry) in entries {
            let serial =
                normalized_key(key).ok_or_else(|| format!("entry key {key:?} is not hex"))?;
            let status = entry
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("entry {key:?} has no status"))?;
            out.insert(serial, status.to_string());
        }
        Ok(Self { entries: out })
    }

    /// Read the list at `path`, refusing a copy older than
    /// [`ANDROID_KEY_STATUS_MAX_AGE`] at `now` (or dated in the future), and
    /// logging a WARN for one older than [`ANDROID_KEY_STATUS_WARN_AGE`] (it
    /// is still used).
    ///
    /// # Errors
    /// The file cannot be read, is stale, or does not parse.
    pub fn load(path: &Path, now: SystemTime) -> Result<Self, String> {
        let shown = path.display();
        let age = age_of(path, now)?;
        match freshness(age) {
            StatusFreshness::Stale => {
                return Err(format!(
                    "the attestation status list {shown} is {}h old, older than the {}h maximum; \
                     refresh it",
                    age.as_secs() / 3600,
                    ANDROID_KEY_STATUS_MAX_AGE.as_secs() / 3600
                ))
            }
            StatusFreshness::Aging => tracing::warn!(
                target: "passkey.android_status",
                path = %shown,
                age_hours = age.as_secs() / 3600,
                "the Android attestation status list is older than {}h; its refresh job has \
                 missed a run, and every Android enrollment and anchor is refused once it is \
                 older than {}h",
                ANDROID_KEY_STATUS_WARN_AGE.as_secs() / 3600,
                ANDROID_KEY_STATUS_MAX_AGE.as_secs() / 3600
            ),
            StatusFreshness::Fresh => {}
        }
        let bytes = std::fs::read(path)
            .map_err(|e| format!("the attestation status list {shown} cannot be read: {e}"))?;
        Self::parse(&bytes).map_err(|e| format!("the attestation status list {shown}: {e}"))
    }

    /// How many serials it lists.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it lists none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The status of the certificate with serial `serial` ([`serial_hex`]
    /// form), `None` when it is not listed (good standing).
    #[must_use]
    pub fn status_of(&self, serial: &str) -> Option<&str> {
        self.entries.get(serial).map(String::as_str)
    }

    /// The listed form and status of the certificate whose serial number has
    /// the big-endian bytes `raw`, looked up as hex and as decimal; `None`
    /// when neither is listed. (A decimal string is also a hex string, so a
    /// certificate whose decimal serial equals another's hex key is refused
    /// too: fail closed, and vanishingly rare.)
    #[must_use]
    pub fn status_of_serial(&self, raw: &[u8]) -> Option<(String, &str)> {
        [serial_hex(raw), serial_decimal(raw)]
            .into_iter()
            .find_map(|form| {
                let key = normalized_key(&form)?;
                self.status_of(&key).map(|status| (form, status))
            })
    }
}

/// One of a KeyDescription's authorization lists, as far as this crate reads
/// it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    /// `allApplications` [600] is present.
    pub all_applications: bool,
    /// `origin` [702].
    pub origin: Option<u32>,
    /// `purpose` [1], every member of the set.
    pub purposes: Vec<u32>,
}

/// A KeyDescription (Android Keystore attestation schema), as far as this
/// crate reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDescription {
    /// `attestationSecurityLevel`.
    pub attestation_level: u32,
    /// `keyMintSecurityLevel` (`keymasterSecurityLevel`).
    pub keymaster_level: u32,
    /// `softwareEnforced`.
    pub software_enforced: AuthorizationList,
    /// `hardwareEnforced` (`teeEnforced`).
    pub hardware_enforced: AuthorizationList,
}

fn authorization_list(i: &[u8]) -> BerResult<'_, AuthorizationList> {
    parse_der_container(|i: &[u8], hdr: Header| {
        if hdr.tag() != Tag::Sequence {
            return Err(x509_parser::nom::Err::Error(BerError::BerTypeError));
        }
        let mut list = AuthorizationList::default();
        let mut i = i;
        while !i.is_empty() {
            let (rest, obj) = parse_der(i)?;
            i = rest;
            match obj.tag() {
                Tag(600) => list.all_applications = true,
                Tag(702) => {
                    if let BerObjectContent::Unknown(o) = obj.content {
                        let (_, v) = parse_der_integer(o.data)?;
                        list.origin = Some(v.as_u32()?);
                    }
                }
                Tag(1) => {
                    if let BerObjectContent::Unknown(o) = obj.content {
                        let (_, set) = parse_der_container(|mut s: &[u8], _| {
                            let mut out = Vec::new();
                            while !s.is_empty() {
                                let (rest, v) = parse_der_integer(s)?;
                                out.push(v.as_u32()?);
                                s = rest;
                            }
                            Ok((s, out))
                        })(o.data)?;
                        list.purposes = set;
                    }
                }
                _ => {}
            }
        }
        Ok((i, list))
    })(i)
}

fn key_description_der(i: &[u8]) -> BerResult<'_, KeyDescription> {
    parse_der_container(|i: &[u8], hdr: Header| {
        if hdr.tag() != Tag::Sequence {
            return Err(x509_parser::nom::Err::Error(BerError::BerTypeError));
        }
        let (i, _version) = parse_der_integer(i)?;
        let (i, attestation_level) = parse_der_enum(i)?;
        let (i, _keymaster_version) = parse_der_integer(i)?;
        let (i, keymaster_level) = parse_der_enum(i)?;
        let (i, _challenge) = parse_der_octetstring(i)?;
        let (i, _unique_id) = parse_der_octetstring(i)?;
        let (i, software_enforced) = authorization_list(i)?;
        let (i, hardware_enforced) = authorization_list(i)?;
        Ok((
            i,
            KeyDescription {
                attestation_level: attestation_level.as_u32()?,
                keymaster_level: keymaster_level.as_u32()?,
                software_enforced,
                hardware_enforced,
            },
        ))
    })(i)
}

/// Parse a KeyDescription extension's value.
///
/// # Errors
/// It is not a KeyDescription.
pub fn parse_key_description(value: &[u8]) -> Result<KeyDescription, String> {
    key_description_der(value)
        .map(|(_, kd)| kd)
        .map_err(|e| format!("the KeyDescription does not parse: {e}"))
}

/// What a certificate chain (`x5c` order, leaf first, DER) says: every
/// certificate's serial number (big-endian bytes) and the leaf's
/// KeyDescription.
///
/// # Errors
/// A certificate does not parse, the leaf carries no KeyDescription, or a
/// certificate other than the leaf carries one.
pub fn inspect_chain(chain: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, KeyDescription), String> {
    let mut serials = Vec::with_capacity(chain.len());
    let mut leaf_description = None;
    for (index, der) in chain.iter().enumerate() {
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| format!("attestation certificate {index} does not parse: {e}"))?;
        serials.push(cert.raw_serial().to_vec());
        let mut found = cert
            .iter_extensions()
            .filter(|ext| ext.oid.to_id_string() == KEY_DESCRIPTION_OID);
        let first = found.next();
        if found.next().is_some() {
            return Err(format!(
                "attestation certificate {index} carries more than one KeyDescription"
            ));
        }
        match (index, first) {
            (0, Some(ext)) => leaf_description = Some(parse_key_description(ext.value)?),
            (0, None) => return Err("the leaf certificate carries no KeyDescription".into()),
            (_, Some(_)) => {
                return Err(format!(
                    "attestation certificate {index} carries a KeyDescription too; only the \
                     leaf's may"
                ))
            }
            (_, None) => {}
        }
    }
    let description = leaf_description.ok_or_else(|| "no attestation certificate".to_string())?;
    Ok((serials, description))
}

/// The hardware rules of a KeyDescription: the attestation and the key in a
/// TEE or StrongBox, the key's `purpose` (SIGN) and `origin` (GENERATED)
/// enforced by that hardware, and the key scoped to the relying party (no
/// `allApplications`).
///
/// # Errors
/// Which rule it breaks.
pub fn hardware_rules(kd: &KeyDescription) -> Result<(), String> {
    let hardware = |level: u32| level == LEVEL_TEE || level == LEVEL_STRONGBOX;
    if !hardware(kd.attestation_level) || !hardware(kd.keymaster_level) {
        return Err(format!(
            "the key is not attested as hardware-backed (attestation security level {}, key \
             security level {}; TEE 1 or StrongBox 2 required)",
            kd.attestation_level, kd.keymaster_level
        ));
    }
    if kd.software_enforced.all_applications || kd.hardware_enforced.all_applications {
        return Err("the key is not scoped to this relying party (allApplications)".into());
    }
    let hw = &kd.hardware_enforced;
    if hw.origin != Some(ORIGIN_GENERATED) || !hw.purposes.contains(&PURPOSE_SIGN) {
        return Err(
            "the key's purpose (SIGN) and origin (GENERATED) are not in the hardware-enforced \
             list"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A serial number is keyed as lowercase hex without leading zeros, on
    /// both sides: the certificate's bytes and the list's keys. Mutation:
    /// `serial_hex` keeping the byte padding -> the leading-zero serial is
    /// `0a1b...` and misses the list's `a1b2...` key.
    #[test]
    fn serials_are_lowercase_hex_without_leading_zeros() {
        assert_eq!(
            serial_hex(&[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71]),
            "a1b2c3d4e5f6071"
        );
        assert_eq!(serial_hex(&[0x00, 0xC8, 0x96]), "c896");
        assert_eq!(serial_hex(&[0x00]), "0");
        let list = StatusList::parse(
            br#"{"entries": {"00A1B2": {"status": "REVOKED"}, "c8": {"status": "SUSPENDED"}}}"#,
        )
        .unwrap();
        assert_eq!(list.status_of("a1b2"), Some("REVOKED"));
        assert_eq!(list.status_of("c8"), Some("SUSPENDED"));
        assert_eq!(list.status_of("c9"), None);
        // The decimal form: 0x8b1a2c3d4e5f6071 = 10023372562485960817.
        let raw = [0x8b, 0x1a, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
        assert_eq!(serial_decimal(&raw), "10023372562485960817");
        let decimal =
            StatusList::parse(br#"{"entries": {"10023372562485960817": {"status": "REVOKED"}}}"#)
                .unwrap();
        assert_eq!(
            decimal.status_of_serial(&raw),
            Some(("10023372562485960817".to_string(), "REVOKED"))
        );
        let hex =
            StatusList::parse(br#"{"entries": {"8b1a2c3d4e5f6071": {"status": "SUSPENDED"}}}"#)
                .unwrap();
        assert_eq!(
            hex.status_of_serial(&raw),
            Some(("8b1a2c3d4e5f6071".to_string(), "SUSPENDED"))
        );
        assert_eq!(list.status_of_serial(&raw), None);
    }

    /// A list that is not Google's format is an error, never an empty list
    /// (which would put every certificate in good standing). Mutation:
    /// a missing `entries` read as no entry -> the `{}` case parses.
    #[test]
    fn a_malformed_list_is_refused() {
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"entries": []}"#,
            br#"{"entries": {"xyz": {"status": "REVOKED"}}}"#,
            br#"{"entries": {"ab": {"reason": "KEY_COMPROMISE"}}}"#,
        ] {
            assert!(
                StatusList::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The status list's age thresholds (P779R-4): up to 24h fresh; past 24h
    /// AGING (still used, a WARN at boot and at every use); past 48h STALE
    /// (refused). Each boundary is inclusive on the younger side. Mutations:
    /// the warn age set to the maximum age (48h) -> 25h is Fresh; the
    /// comparison `>=` -> exactly 24h is Aging.
    #[test]
    fn the_status_list_warns_past_24_hours_and_refuses_past_48() {
        let h = |n: u64| Duration::from_secs(n * 3600);
        let s = Duration::from_secs(1);
        assert_eq!(freshness(Duration::ZERO), StatusFreshness::Fresh);
        assert_eq!(freshness(h(23) + h(1) - s), StatusFreshness::Fresh);
        assert_eq!(freshness(h(24)), StatusFreshness::Fresh);
        assert_eq!(freshness(h(24) + s), StatusFreshness::Aging);
        assert_eq!(freshness(h(25)), StatusFreshness::Aging);
        assert_eq!(freshness(h(47)), StatusFreshness::Aging);
        assert_eq!(freshness(h(48)), StatusFreshness::Aging);
        assert_eq!(freshness(h(48) + s), StatusFreshness::Stale);
        assert_eq!(freshness(h(49)), StatusFreshness::Stale);
        assert_eq!(ANDROID_KEY_STATUS_WARN_AGE, h(24));
        assert_eq!(ANDROID_KEY_STATUS_MAX_AGE, h(48));
    }

    fn kd(level: u32, hw_origin: Option<u32>, hw_purposes: Vec<u32>) -> KeyDescription {
        KeyDescription {
            attestation_level: level,
            keymaster_level: level,
            software_enforced: AuthorizationList::default(),
            hardware_enforced: AuthorizationList {
                all_applications: false,
                origin: hw_origin,
                purposes: hw_purposes,
            },
        }
    }

    /// TEE and StrongBox pass; Software, an unknown level, a software-only
    /// origin/purpose, a purpose set without SIGN and `allApplications` do
    /// not. Mutations: the level check accepting 0 -> the Software case
    /// passes; the hardware-list check reading the software list -> the
    /// empty-hardware-list case passes.
    #[test]
    fn the_hardware_rules() {
        assert_eq!(hardware_rules(&kd(1, Some(0), vec![2])), Ok(()));
        assert_eq!(hardware_rules(&kd(2, Some(0), vec![3, 2])), Ok(()));
        assert!(hardware_rules(&kd(0, Some(0), vec![2])).is_err());
        assert!(hardware_rules(&kd(3, Some(0), vec![2])).is_err());
        let mut mixed = kd(1, Some(0), vec![2]);
        mixed.keymaster_level = 0;
        assert!(hardware_rules(&mixed).is_err());
        assert!(hardware_rules(&kd(1, None, vec![])).is_err());
        assert!(hardware_rules(&kd(1, Some(0), vec![3])).is_err());
        assert!(hardware_rules(&kd(1, Some(1), vec![2])).is_err());
        let mut everywhere = kd(1, Some(0), vec![2]);
        everywhere.software_enforced.all_applications = true;
        assert!(hardware_rules(&everywhere).is_err());
    }
}
