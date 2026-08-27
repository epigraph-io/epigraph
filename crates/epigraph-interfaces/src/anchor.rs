//! `AnchorBackend` — publishing a Merkle root to a party OTHER than the
//! operator (backlog 94e62824).
//!
//! `provenance_log` and `manifests` are tamper-EVIDENT but self-hosted:
//! whoever controls the Postgres controls the log, and every countersignature
//! lives in the same database. An anchor moves the *existence-at-a-time* claim
//! outside that blast radius — a third party attests that these 32 bytes were
//! published before block N, so a later edit is detectable without trusting us.
//!
//! # Deliberately NO no-op implementation
//!
//! Every other trait in this crate ships a `NoOp*` kernel default. This one
//! does not, and the omission is the point: a no-op anchor backend IS the
//! inert-feature failure mode — it would report success while publishing
//! nothing, which is strictly worse than not anchoring at all. The kernel
//! default is `epigraph_db::anchor::MockAnchorBackend`, which does real work
//! (it writes the published bytes to an append-only ledger table and reads
//! them back). See that module for the honest statement of what a *mock*
//! ledger does and does not prove.
//!
//! # What lives here and why
//!
//! [`AnchorCommitment`] is beside the trait because [`AnchorBackend::submit`]
//! takes it, and this crate cannot depend on `epigraph-core` (core depends on
//! *this* crate). It is pure: no database, no chrono, no I/O.
//!
//! # The 64-byte rule
//!
//! Cardano caps any single transaction-metadata bytestring or text string at
//! 64 bytes. That constraint — not aesthetics — is why the commitment is a
//! flat 7-pair map of short scalars rather than nested structure, and why
//! `every_commitment_value_fits_cardano_64_byte_limit` is a test rather than a
//! comment. A future field that overflows it makes the payload unpublishable
//! on the leading candidate chain without changing a single type signature.

use async_trait::async_trait;
use ciborium::value::Value;

use crate::InterfaceError;

/// Size of a BLAKE3 digest, and therefore of every root this module carries.
pub const ROOT_SIZE: usize = 32;

/// The only [`AnchorCommitment::version`] this build writes or accepts.
///
/// A verifier that meets a `v` it does not know must refuse, not guess: the
/// whole value of the commitment is that its meaning is fixed at publish time.
pub const COMMITMENT_VERSION: u64 = 1;

/// The `t` (type) discriminator embedded in every commitment.
///
/// 15 bytes, so it fits the 64-byte metadatum limit with room to spare. It
/// exists so that a commitment found on a shared public chain is
/// self-identifying rather than 32 anonymous bytes.
pub const COMMITMENT_TAG: &str = "epigraph.anchor";

/// The largest Cardano transaction-metadata bytestring / text string.
pub const CARDANO_METADATUM_VALUE_LIMIT: usize = 64;

/// Errors returned by [`AnchorBackend`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The backend exists and is selectable but has no credentials / wallet /
    /// endpoint configured. Distinct from [`AnchorError::Unimplemented`] so an
    /// operator can tell "I forgot to set the env var" from "this build cannot
    /// do it at all".
    #[error("anchor backend {backend} is not configured: {detail}")]
    NotConfigured {
        backend: &'static str,
        detail: String,
    },

    /// The backend is configured but this build does not implement the call.
    #[error("anchor backend {backend} does not implement {operation} in this build")]
    Unimplemented {
        backend: &'static str,
        operation: &'static str,
    },

    /// The commitment could not be encoded or decoded.
    #[error("commitment codec error: {0}")]
    Codec(String),

    /// Network / RPC / ledger transport failure. Retryable.
    #[error("anchor transport failure: {0}")]
    Transport(String),

    /// Any other backend-specific error.
    #[error("anchor backend error: {0}")]
    Backend(#[from] InterfaceError),
}

/// What gets published: a commitment to one Merkle root.
///
/// Encoded as deterministic CBOR (RFC 8949 §4.2.1) by [`Self::to_cbor`]. The
/// encoding is byte-pinned by a golden-vector test, because these bytes are
/// the thing a third party holds — changing them silently would orphan every
/// anchor already published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorCommitment {
    /// Commitment format version. Always [`COMMITMENT_VERSION`] on write.
    pub version: u64,
    /// What kind of root this is: `"manifest"` today, `"checkpoint"` reserved
    /// for a future tree over many manifest roots.
    pub kind: String,
    /// The anchored row's id, as raw bytes (16).
    pub root_id: [u8; 16],
    /// The 32-byte BLAKE3 Merkle root itself.
    pub root_hash: [u8; ROOT_SIZE],
    /// How many leaves the root covers. Published so a verifier can detect a
    /// root re-derived over a *different-sized* set without fetching the set.
    pub leaf_count: u64,
    /// Seal time CLAIMED by the sealer, in unix seconds.
    ///
    /// The chain block carries the PROVEN upper bound. Both are surfaced at
    /// verification time precisely so `sealed_at > block_time` — a backdated
    /// seal — is detectable rather than smoothed over. Unix seconds rather
    /// than a `chrono` type keeps this crate chrono-free.
    pub sealed_at_unix: u64,
}

impl AnchorCommitment {
    /// Build a v1 commitment.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        root_id: [u8; 16],
        root_hash: [u8; ROOT_SIZE],
        leaf_count: u64,
        sealed_at_unix: u64,
    ) -> Self {
        Self {
            version: COMMITMENT_VERSION,
            kind: kind.into(),
            root_id,
            root_hash,
            leaf_count,
            sealed_at_unix,
        }
    }

    /// Encode as deterministic CBOR (RFC 8949 §4.2.1).
    ///
    /// A definite-length 7-pair map (major type 5, `0xa7`) with single-char
    /// text keys emitted in canonical order — length first, then bytewise, so
    /// for seven one-char keys simply `i, k, n, r, s, t, v`:
    ///
    /// | key | value |
    /// |---|---|
    /// | `i` | `root_id`, byte string (16) |
    /// | `k` | `kind`, text |
    /// | `n` | `leaf_count`, uint |
    /// | `r` | `root_hash`, byte string (32) |
    /// | `s` | `sealed_at_unix`, uint |
    /// | `t` | [`COMMITMENT_TAG`], text (15) |
    /// | `v` | `version`, uint |
    ///
    /// # Why the map is built by hand
    ///
    /// A `#[derive(Serialize)]` would encode `[u8; 32]` as a CBOR *array of 32
    /// uints* — measured, `{r: [u8;32]}` comes out at 69 bytes (`a1 61 72 98
    /// 20 18 ab …`) against 37 for the bytestring form (`a1 61 72 58 20 ab
    /// …`). That is a different wire format, nearly double the transaction
    /// payload, and a value type the 64-byte metadatum rule was never written
    /// for — and it would compile perfectly. Building the `Value::Map`
    /// explicitly gives byte-exact control and makes the golden vector
    /// auditable by eye. `every_commitment_value_fits_cardano_64_byte_limit`
    /// panics on any value that is not `Bytes` / `Text` / `Integer`, so the
    /// array form cannot slip in unnoticed.
    ///
    /// # Errors
    /// [`AnchorError::Codec`] if the CBOR writer fails, which for an in-memory
    /// `Vec` means an allocation failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>, AnchorError> {
        let map = Value::Map(vec![
            (Value::Text("i".into()), Value::Bytes(self.root_id.to_vec())),
            (Value::Text("k".into()), Value::Text(self.kind.clone())),
            (
                Value::Text("n".into()),
                Value::Integer(self.leaf_count.into()),
            ),
            (
                Value::Text("r".into()),
                Value::Bytes(self.root_hash.to_vec()),
            ),
            (
                Value::Text("s".into()),
                Value::Integer(self.sealed_at_unix.into()),
            ),
            (Value::Text("t".into()), Value::Text(COMMITMENT_TAG.into())),
            (Value::Text("v".into()), Value::Integer(self.version.into())),
        ]);

        let mut out = Vec::with_capacity(128);
        ciborium::ser::into_writer(&map, &mut out)
            .map_err(|e| AnchorError::Codec(format!("encode: {e}")))?;
        Ok(out)
    }

    /// Decode a commitment from published bytes.
    ///
    /// STRICT on purpose. An unknown `v`, a `r` that is not 32 bytes, or a
    /// missing key is an error rather than a lenient parse: verification
    /// re-derives the root from these bytes and never trusts a stored column,
    /// so a decoder that guesses would hand back an attacker-chosen root.
    ///
    /// # Errors
    /// [`AnchorError::Codec`] for malformed CBOR, a missing or wrongly-typed
    /// key, an unknown version, or a wrong-width `i` / `r`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, AnchorError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| AnchorError::Codec(format!("decode: {e}")))?;
        let Value::Map(pairs) = value else {
            return Err(AnchorError::Codec(
                "commitment must be a CBOR map".to_string(),
            ));
        };

        let get = |key: &str| -> Option<&Value> {
            pairs.iter().find_map(|(k, v)| match k {
                Value::Text(t) if t == key => Some(v),
                _ => None,
            })
        };
        let missing = |key: &str| AnchorError::Codec(format!("commitment is missing key `{key}`"));

        let tag = match get("t").ok_or_else(|| missing("t"))? {
            Value::Text(t) => t.clone(),
            other => {
                return Err(AnchorError::Codec(format!(
                    "`t` must be text, got {other:?}"
                )))
            }
        };
        if tag != COMMITMENT_TAG {
            return Err(AnchorError::Codec(format!(
                "commitment tag is {tag:?}, expected {COMMITMENT_TAG:?}"
            )));
        }

        let version = uint(get("v").ok_or_else(|| missing("v"))?, "v")?;
        if version != COMMITMENT_VERSION {
            return Err(AnchorError::Codec(format!(
                "commitment version {version} is not supported (this build writes and reads v{COMMITMENT_VERSION})"
            )));
        }

        let kind = match get("k").ok_or_else(|| missing("k"))? {
            Value::Text(t) => t.clone(),
            other => {
                return Err(AnchorError::Codec(format!(
                    "`k` must be text, got {other:?}"
                )))
            }
        };

        let root_id = fixed_bytes::<16>(get("i").ok_or_else(|| missing("i"))?, "i")?;
        let root_hash = fixed_bytes::<ROOT_SIZE>(get("r").ok_or_else(|| missing("r"))?, "r")?;
        let leaf_count = uint(get("n").ok_or_else(|| missing("n"))?, "n")?;
        let sealed_at_unix = uint(get("s").ok_or_else(|| missing("s"))?, "s")?;

        Ok(Self {
            version,
            kind,
            root_id,
            root_hash,
            leaf_count,
            sealed_at_unix,
        })
    }
}

/// Read a non-negative CBOR integer, rejecting anything else.
fn uint(value: &Value, key: &str) -> Result<u64, AnchorError> {
    let Value::Integer(i) = value else {
        return Err(AnchorError::Codec(format!(
            "`{key}` must be an unsigned integer, got {value:?}"
        )));
    };
    u64::try_from(*i).map_err(|_| AnchorError::Codec(format!("`{key}` is not a u64")))
}

/// Read a byte string of exactly `N` bytes, rejecting anything else.
fn fixed_bytes<const N: usize>(value: &Value, key: &str) -> Result<[u8; N], AnchorError> {
    let Value::Bytes(b) = value else {
        return Err(AnchorError::Codec(format!(
            "`{key}` must be a byte string, got {value:?}"
        )));
    };
    <[u8; N]>::try_from(b.as_slice())
        .map_err(|_| AnchorError::Codec(format!("`{key}` is {} bytes, expected {N}", b.len())))
}

/// What a backend returns from [`AnchorBackend::submit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Ledger-native transaction identifier. Opaque to the kernel; the only
    /// requirement is that [`AnchorBackend::fetch`] accepts it back.
    pub tx_id: String,
    /// Block height, when the backend confirms synchronously. A real chain
    /// will return `None` here and fill it in on a later `fetch`.
    pub block_height: Option<i64>,
    /// Block time in unix seconds, when known at submit time.
    pub block_time_unix: Option<i64>,
}

/// The ledger's own copy of a published commitment, read back by
/// [`AnchorBackend::fetch`].
///
/// `metadata_cbor` is what makes verification meaningful: it is the ledger's
/// bytes, not ours, and comparing them against the locally stored
/// `commitment_bytes` is the check that catches a rewritten local row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedAnchor {
    /// The exact published payload, as the ledger holds it.
    pub metadata_cbor: Vec<u8>,
    pub block_height: i64,
    /// Unix seconds. Not `chrono`, to keep this crate free of that dependency.
    pub block_time_unix: i64,
    /// How many blocks have been built on top. `0` for a backend that confirms
    /// instantly; a real chain lets a caller demand depth before believing it.
    pub confirmations: u32,
}

/// Pluggable external-anchoring backend.
///
/// Deliberately tiny — submit bytes, get an id; fetch by id — because that is
/// the intersection of every candidate: a Cardano transaction carrying
/// metadatum label 40961, a Sigstore/Rekor log entry, and a signed git tag
/// pushed to a forge all fit it without change. The chain choice is therefore
/// a configuration decision, not a code rewrite.
///
/// [`Self::fetch`] serves BOTH confirmation polling and verification, so there
/// is no method a working deployment leaves cold.
#[async_trait]
pub trait AnchorBackend: Send + Sync + 'static {
    /// Stable short name, recorded in `anchors.backend`. Changing it orphans
    /// existing rows from their backend, so treat it as part of the schema.
    fn name(&self) -> &'static str;

    /// Which ledger instance this backend talks to (`"mock"`, `"preprod"`,
    /// `"mainnet"`, ...), recorded in `anchors.network`. Kept separate from
    /// `name` so a testnet anchor can never be mistaken for a mainnet one.
    fn network(&self) -> &'static str;

    /// Publish `commitment` and return its ledger identifier.
    ///
    /// # Errors
    /// Implementation-specific; see [`AnchorError`].
    async fn submit(&self, commitment: &AnchorCommitment) -> Result<AnchorReceipt, AnchorError>;

    /// Read a previously published commitment back out of the ledger.
    ///
    /// `Ok(None)` means "the ledger does not have this transaction" — a real
    /// answer (the submission never landed), distinct from a transport error.
    ///
    /// # Errors
    /// Implementation-specific; see [`AnchorError`].
    async fn fetch(&self, tx_id: &str) -> Result<Option<PublishedAnchor>, AnchorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed commitment, so the golden vector below is reproducible by hand.
    fn fixture() -> AnchorCommitment {
        AnchorCommitment::new(
            "manifest",
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            [0xab; ROOT_SIZE],
            5,
            1_760_000_000,
        )
    }

    /// THE WIRE FORMAT IS PINNED. These bytes are what a third party holds; if
    /// this test goes red, every anchor already published means something
    /// different from what this build would publish.
    #[test]
    fn commitment_cbor_is_canonical_and_pinned() {
        let bytes = fixture().to_cbor().expect("encode");

        assert_eq!(
            bytes[0], 0xa7,
            "must be a DEFINITE-length map of exactly 7 pairs (RFC 8949 4.2.1 forbids \
             indefinite-length items in deterministic encoding); got 0x{:02x}",
            bytes[0]
        );

        // Keys in wire order. `ciborium`'s `Value::Map` preserves the order it
        // read them in, so decoding is a faithful reading of the bytes — and
        // far less brittle than scanning for 0x61 markers, which also occur
        // inside the values ("m-a-n-ifest" carries a 0x61 0x6e pair).
        let Value::Map(pairs) = ciborium::de::from_reader::<Value, _>(&bytes[..]).expect("decode")
        else {
            panic!("commitment must decode as a map");
        };
        let keys: Vec<String> = pairs
            .iter()
            .map(|(k, _)| match k {
                Value::Text(t) => t.clone(),
                other => panic!("keys must be text, got {other:?}"),
            })
            .collect();
        assert_eq!(
            keys,
            vec!["i", "k", "n", "r", "s", "t", "v"],
            "canonical key order (length-first, then bytewise) is i,k,n,r,s,t,v"
        );

        // The golden vector. Hand-checkable:
        //   a7                             map(7)
        //   61 69  50 0102..10             "i" : h'0102030405060708090a0b0c0d0e0f10'
        //   61 6b  68 6d616e6966657374     "k" : "manifest"
        //   61 6e  05                      "n" : 5
        //   61 72  5820 abab..ab           "r" : h'abab..ab' (32)
        //   61 73  1a68e77800              "s" : 1760000000
        //   61 74  6f 65706967726170682e616e63686f72
        //                                  "t" : "epigraph.anchor"
        //   61 76  01                      "v" : 1
        assert_eq!(
            hex::encode(&bytes),
            "a7\
             616950\
             0102030405060708090a0b0c0d0e0f10\
             616b686d616e6966657374\
             616e05\
             61725820\
             abababababababababababababababababababababababababababababababab\
             61731a68e77800\
             61746f65706967726170682e616e63686f72\
             617601",
            "golden vector broke: the published wire format changed"
        );
        // Size is not fixed — `kind` and the two integers are variable-width —
        // but it is small, and staying small is what keeps a real transaction
        // cheap. Under 200 bytes is the standing budget; 98 is where v1 sits.
        assert_eq!(bytes.len(), 98, "sanity: the pinned v1 payload is 98 bytes");
        assert!(bytes.len() < 200, "commitment must stay transaction-cheap");
    }

    #[test]
    fn commitment_cbor_roundtrips() {
        let cases = [
            // Zero leaves: the tree layer rejects an empty set, but the codec
            // must not silently mangle the number if one ever arrives.
            AnchorCommitment::new("manifest", [0u8; 16], [0u8; ROOT_SIZE], 0, 0),
            fixture(),
            // Straddles the 2^32 boundary in both numeric fields, where a
            // 4-byte CBOR uint gives way to an 8-byte one.
            AnchorCommitment::new(
                "checkpoint",
                [0xff; 16],
                [0x5a; ROOT_SIZE],
                4_294_967_296,
                4_294_967_296,
            ),
            AnchorCommitment::new(
                "manifest",
                [0x7f; 16],
                [0x01; ROOT_SIZE],
                1,
                u32::MAX.into(),
            ),
        ];

        for c in cases {
            let bytes = c.to_cbor().expect("encode");
            let back = AnchorCommitment::from_cbor(&bytes).expect("decode");
            assert_eq!(back, c, "roundtrip lost information");
            assert_eq!(
                back.to_cbor().expect("re-encode"),
                bytes,
                "re-encoding a decoded commitment must be byte-identical"
            );
        }
    }

    /// THE PUBLISHABILITY CONSTRAINT. Cardano rejects any metadatum bytestring
    /// or text string over 64 bytes, so a field that outgrows it makes the
    /// commitment unpublishable on the leading candidate chain — a failure
    /// that would otherwise surface only against a real wallet.
    #[test]
    fn every_commitment_value_fits_cardano_64_byte_limit() {
        let bytes = fixture().to_cbor().expect("encode");
        let Value::Map(pairs) = ciborium::de::from_reader::<Value, _>(&bytes[..]).expect("decode")
        else {
            panic!("commitment must decode as a map");
        };
        assert_eq!(pairs.len(), 7);

        for (key, value) in &pairs {
            let payload_len = match value {
                Value::Bytes(b) => b.len(),
                Value::Text(t) => t.len(),
                // Integers are at most 9 bytes on the wire and are not subject
                // to the string limit at all.
                Value::Integer(_) => 0,
                other => panic!("unexpected commitment value type for {key:?}: {other:?}"),
            };
            assert!(
                payload_len <= CARDANO_METADATUM_VALUE_LIMIT,
                "{key:?} carries {payload_len} bytes, over the {CARDANO_METADATUM_VALUE_LIMIT}-byte \
                 Cardano metadatum limit"
            );
        }
    }

    #[test]
    fn from_cbor_rejects_wrong_version_and_short_root() {
        // v = 2: refuse rather than reinterpret bytes whose meaning we do not
        // know.
        let wrong_version = Value::Map(vec![
            (Value::Text("i".into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("k".into()), Value::Text("manifest".into())),
            (Value::Text("n".into()), Value::Integer(1.into())),
            (Value::Text("r".into()), Value::Bytes(vec![0u8; ROOT_SIZE])),
            (Value::Text("s".into()), Value::Integer(0.into())),
            (Value::Text("t".into()), Value::Text(COMMITMENT_TAG.into())),
            (Value::Text("v".into()), Value::Integer(2.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&wrong_version, &mut buf).expect("encode");
        let err = AnchorCommitment::from_cbor(&buf).expect_err("v=2 must be refused");
        assert!(
            err.to_string().contains("version 2"),
            "error must name the version: {err}"
        );

        // A 31-byte root would leave a verifier comparing a truncated digest.
        let short_root = Value::Map(vec![
            (Value::Text("i".into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("k".into()), Value::Text("manifest".into())),
            (Value::Text("n".into()), Value::Integer(1.into())),
            (Value::Text("r".into()), Value::Bytes(vec![0u8; 31])),
            (Value::Text("s".into()), Value::Integer(0.into())),
            (Value::Text("t".into()), Value::Text(COMMITMENT_TAG.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&short_root, &mut buf).expect("encode");
        let err = AnchorCommitment::from_cbor(&buf).expect_err("a 31-byte root must be refused");
        assert!(
            err.to_string().contains("`r` is 31 bytes"),
            "error must name the width: {err}"
        );

        // A foreign tag: these bytes are not ours to interpret.
        let foreign = Value::Map(vec![
            (Value::Text("i".into()), Value::Bytes(vec![0u8; 16])),
            (Value::Text("k".into()), Value::Text("manifest".into())),
            (Value::Text("n".into()), Value::Integer(1.into())),
            (Value::Text("r".into()), Value::Bytes(vec![0u8; ROOT_SIZE])),
            (Value::Text("s".into()), Value::Integer(0.into())),
            (Value::Text("t".into()), Value::Text("other.system".into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&foreign, &mut buf).expect("encode");
        assert!(
            AnchorCommitment::from_cbor(&buf).is_err(),
            "a foreign tag must be refused"
        );

        // A missing key is not a default.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![(
                Value::Text("t".into()),
                Value::Text(COMMITMENT_TAG.into()),
            )]),
            &mut buf,
        )
        .expect("encode");
        let err = AnchorCommitment::from_cbor(&buf).expect_err("a truncated map must be refused");
        assert!(err.to_string().contains("missing key"), "got {err}");
    }
}
