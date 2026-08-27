//! Anchoring and verifying Merkle manifests (backlog 6e2364b8).
//!
//! A per-row signature proves who wrote a row. It proves nothing about the
//! *boundary* of a set: an exporter can drop inconvenient rows from a subgraph
//! export and every surviving row still verifies. A manifest closes that hole —
//! one Ed25519 signature over one 32-byte Merkle root that changes if any
//! committed row is dropped, added, or substituted.
//!
//! Two entry points:
//!
//! * [`anchor_manifest`] — load the write-once subset of each requested row,
//!   fold the canonical tree, sign a small fixed-size header, and persist the
//!   root plus every leaf. **Fails closed**: if any requested id has no live
//!   row the whole call errors with [`ManifestError::UnknownRow`] and nothing
//!   is written. Degrading to "skip the ones I couldn't find" would reintroduce
//!   exactly the silent omission the feature exists to kill.
//! * [`verify_manifest`] — re-read every committed row, recompute its leaf, and
//!   report seven independent checks (plus an optional inclusion proof).
//!
//! # Why the checks are reported separately
//!
//! The failure modes are genuinely different and a boolean would destroy the
//! difference. A legitimately deleted claim gives `status = missing` +
//! `live_root_matches = false` while `signature_valid` stays true — the
//! manifest is honest, the graph moved on. A forged `manifests` row gives
//! `header_consistent = false`. A deleted `manifest_entries` row gives
//! `entry_count_matches = false`. Collapsing them would make the tool useless
//! for triage.
//!
//! # The signed header, and the gap that storing it opens
//!
//! The signer signs a small canonical-JSON header — `{algo, manifest_id, root,
//! entry_count, created_at, signer_agent_id, signer_did, subject}` — not the
//! leaf list, so signing cost is independent of set size. Those exact bytes are
//! stored in `manifests.signed_header` so verification never depends on
//! re-deriving the serialization.
//!
//! That opens one gap and closes it deliberately: because the bytes are stored,
//! a tamperer could rewrite the `root` / `entry_count` **columns** while leaving
//! a signature that is still cryptographically valid over *different* bytes. So
//! [`verify_manifest`] parses the header and cross-checks it against the columns
//! before reporting [`ManifestVerification::signature_valid`], which is
//! therefore "the signature verifies AND the header actually describes this
//! row". The raw cryptographic result is still reported separately as
//! [`ManifestVerification::signature_bytes_valid`], so a rewritten column is
//! distinguishable from a forged signature.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use epigraph_crypto::{
    canonical_order, claim_leaf, edge_leaf, inclusion_proof, merkle_root, to_canonical_bytes,
    verify_inclusion, AgentSigner, ContentHasher, CryptoError, DidKey, ManifestLeaf,
    ManifestRowKind, MerkleError, ProofStep, SignatureVerifier, HASH_SIZE, PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
};
use epigraph_db::{
    AgentRepository, DbError, ManifestRepository, NewManifest, NewManifestEntry, PgPool,
    MANIFEST_ALGO,
};

/// Everything that can go wrong anchoring or verifying a manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("database error: {0}")]
    Db(#[from] DbError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("merkle error: {0}")]
    Merkle(#[from] MerkleError),

    /// A requested id had no live row. Anchoring fails closed on this rather
    /// than signing a commitment to a row it could not read.
    #[error("cannot anchor a manifest over {kind} {id}: no such row")]
    UnknownRow { kind: ManifestRowKind, id: Uuid },

    /// Zero rows after deduplication.
    #[error("a manifest must commit to at least one row")]
    Empty,

    #[error("manifest {0} not found")]
    NotFound(Uuid),

    /// Input that the schema's CHECK constraints would reject *after* signing:
    /// a non-object `subject`, a `content_hash` of the wrong width, a set too
    /// large for the `INTEGER` entry count. Caught before any bytes are signed.
    #[error("invalid manifest input: {reason}")]
    Invalid { reason: String },
}

/// The canonical, fixed-size document that actually gets signed.
///
/// Small on purpose: signing cost must not scale with the committed set. Field
/// order in this struct is irrelevant — [`to_canonical_bytes`] sorts keys
/// recursively before signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub algo: String,
    pub manifest_id: Uuid,
    /// Lowercase hex, per [`ContentHasher::to_hex`].
    pub root: String,
    pub entry_count: u32,
    /// RFC 3339, truncated to microseconds — Postgres `timestamptz` resolution,
    /// so the header and the stored column cannot drift.
    pub created_at: String,
    pub signer_agent_id: Uuid,
    pub signer_did: String,
    /// What this manifest is ABOUT. Inside the signature, so a narrow export
    /// cannot be re-labelled as a broad one.
    pub subject: serde_json::Value,
}

/// The kind-specific leaf material carried in the exported bundle, so an
/// off-platform consumer can recompute the leaf without database access.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum AnchoredEntryPayload {
    Claim {
        /// Lowercase hex, 64 chars.
        content_hash: String,
        agent_id: Uuid,
    },
    Edge {
        relationship: String,
    },
}

/// One committed row as it appears in the self-verifying bundle.
#[derive(Debug, Clone, Serialize)]
pub struct AnchoredEntry {
    pub position: i32,
    /// `"claim"` or `"edge"`.
    pub kind: String,
    pub id: Uuid,
    /// RFC 3339, microsecond resolution (human-readable form).
    pub created_at: String,
    /// The exact integer that goes into the leaf preimage. Emitted alongside
    /// `created_at` so an off-platform verifier never has to parse and convert
    /// a timestamp to reproduce the hash.
    pub created_at_micros: i64,
    /// Lowercase hex of this leaf's 32-byte hash.
    pub leaf: String,
    #[serde(flatten)]
    pub payload: AnchoredEntryPayload,
}

/// A freshly anchored manifest, carrying everything needed to verify it with no
/// database access at all.
#[derive(Debug, Clone)]
pub struct AnchoredManifest {
    pub id: Uuid,
    pub root: [u8; HASH_SIZE],
    pub entry_count: i32,
    pub created_at: DateTime<Utc>,
    pub subject: serde_json::Value,
    pub signer_agent_id: Uuid,
    pub signer_public_key: [u8; PUBLIC_KEY_SIZE],
    pub signer_did: String,
    pub signature: [u8; SIGNATURE_SIZE],
    /// The exact canonical-JSON bytes that were signed.
    pub signed_header: Vec<u8>,
    pub entries: Vec<AnchoredEntry>,
}

impl AnchoredManifest {
    /// The bundle as it is spliced into an exported document.
    ///
    /// A consumer with no database can recompute every leaf from `entries`,
    /// fold the root, compare it to the root inside `signed_header`, and
    /// Ed25519-verify `signature` over `signed_header` against
    /// `signer_public_key`. That is what makes an omission attack detectable by
    /// the RECIPIENT rather than only by the origin instance.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "algo": MANIFEST_ALGO,
            "manifest_id": self.id,
            "root": ContentHasher::to_hex(&self.root),
            "entry_count": self.entry_count,
            "created_at": rfc3339_micros(&self.created_at),
            "signer_agent_id": self.signer_agent_id,
            "signer_did": self.signer_did,
            "signer_public_key": hex_lower(&self.signer_public_key),
            "signature": hex_lower(&self.signature),
            // The canonical JSON *string* exactly as signed. Not a nested
            // object: re-serializing an object is not guaranteed to reproduce
            // the signed bytes, and these bytes are the signature's message.
            "signed_header": String::from_utf8_lossy(&self.signed_header),
            "subject": self.subject,
            "entries": self.entries,
        })
    }
}

/// Whether a committed row still hashes to the leaf that was signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryVerdict {
    /// The live row reproduces the stored leaf exactly.
    Ok,
    /// The row is still there but its write-once subset changed.
    Mismatch,
    /// The row is gone. The `manifest_entries` row survives on purpose (it is
    /// deliberately not a foreign key) so the omission stays visible.
    Missing,
}

/// Per-entry verification result.
#[derive(Debug, Clone, Serialize)]
pub struct EntryStatus {
    pub position: i32,
    pub kind: String,
    pub row_id: Uuid,
    /// Lowercase hex of the leaf as stored at anchoring time.
    pub stored_leaf: String,
    /// Lowercase hex of the leaf recomputed from the live row, when it exists.
    pub live_leaf: Option<String>,
    pub status: EntryVerdict,
}

/// One sibling on a returned inclusion path.
#[derive(Debug, Clone, Serialize)]
pub struct ProofStepReport {
    /// Lowercase hex of the sibling subtree root.
    pub sibling: String,
    pub sibling_is_right: bool,
}

/// An inclusion proof for one committed row against the manifest's root.
#[derive(Debug, Clone, Serialize)]
pub struct InclusionProofReport {
    pub kind: String,
    pub row_id: Uuid,
    /// Leaf index within the canonical order.
    pub position: i32,
    pub leaf: String,
    pub tree_size: usize,
    pub path: Vec<ProofStepReport>,
    /// Result of folding `leaf` with `path` and comparing to `manifests.root`.
    pub verified: bool,
}

/// The seven checks, reported separately.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestVerification {
    pub manifest_id: Uuid,
    pub algo: String,
    /// Lowercase hex of the `manifests.root` column.
    pub root: String,
    pub entry_count: i32,
    pub created_at: String,
    pub subject: serde_json::Value,
    pub signer_id: Option<Uuid>,
    pub signer_did: String,

    /// (6) The signature verifies over `signed_header` **and** that header
    /// describes this row (`header_consistent`). A rewritten column therefore
    /// fails here even though the stored bytes still carry a valid signature.
    pub signature_valid: bool,
    /// The raw Ed25519 result, before the header/column cross-check. Reported
    /// so "someone rewrote a column" is distinguishable from "the signature is
    /// forged".
    pub signature_bytes_valid: bool,
    /// (5) The parsed header agrees with the id / root / entry_count /
    /// created_at / signer_id columns.
    pub header_consistent: bool,
    /// (2) The stored `leaf_hash` column values still fold to `manifests.root`
    /// — catches `manifest_entries` tampering independently of the live graph.
    pub stored_root_intact: bool,
    /// (3) Leaves recomputed from the LIVE rows fold to `manifests.root`.
    pub live_root_matches: bool,
    /// Lowercase hex of the live root; `None` when no committed row survives.
    pub live_root: Option<String>,
    /// (4) `COUNT(manifest_entries)` equals the signed `entry_count` — catches
    /// a deleted entry row.
    pub entry_count_matches: bool,
    /// (7) `Some(true/false)` when the signer's `agents` row survives and its
    /// key does / does not still match the snapshot; `None` when the row is
    /// gone (ON DELETE SET NULL).
    pub signer_key_current: Option<bool>,
    /// (1) Per-entry status.
    pub entries: Vec<EntryStatus>,
    /// Present only when a `prove_row` was requested.
    pub inclusion_proof: Option<InclusionProofReport>,
}

/// RFC 3339 at microsecond resolution — the one timestamp rendering used by
/// both the signed header and the exported bundle.
fn rfc3339_micros(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Lowercase hex for arbitrary-length byte strings. (`ContentHasher::to_hex` is
/// fixed at 32 bytes and is used for every hash; this covers keys and
/// signatures.)
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Truncate to microseconds, matching Postgres `timestamptz` resolution.
///
/// chrono is nanosecond-resolution. Signing a nanosecond timestamp and letting
/// Postgres store the microsecond truncation would make `header_consistent`
/// fail on every manifest ever written.
fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now)
}

/// Sort and deduplicate a slice of ids. A set with a repeated member is the
/// same set, so anchoring must not treat it as an error the way the crypto
/// layer does.
fn dedup(ids: &[Uuid]) -> Vec<Uuid> {
    let mut out = ids.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn to_hash32(bytes: &[u8], what: &str) -> Result<[u8; HASH_SIZE], ManifestError> {
    <[u8; HASH_SIZE]>::try_from(bytes).map_err(|_| ManifestError::Invalid {
        reason: format!("{what} is {} bytes, expected {HASH_SIZE}", bytes.len()),
    })
}

/// Anchor a signed Merkle manifest over exactly `claim_ids` + `edge_ids`.
///
/// Input ids are deduplicated first (a repeated member is the same set), then
/// every one of them is loaded through [`ManifestRepository`]. If any id has no
/// live row the call fails with [`ManifestError::UnknownRow`] and **nothing is
/// written** — you cannot sign a commitment to a row you could not read.
///
/// # Errors
/// - [`ManifestError::Empty`] if the deduplicated set is empty.
/// - [`ManifestError::UnknownRow`] if any requested id is unreadable.
/// - [`ManifestError::Invalid`] if `subject` is not a JSON object, a row is
///   malformed, or the set is too large for the schema's `INTEGER` count.
/// - [`ManifestError::Db`] / [`ManifestError::Crypto`] / [`ManifestError::Merkle`]
///   on the underlying failure.
pub async fn anchor_manifest(
    pool: &PgPool,
    signer: &AgentSigner,
    signer_agent_id: Uuid,
    subject: serde_json::Value,
    claim_ids: &[Uuid],
    edge_ids: &[Uuid],
) -> Result<AnchoredManifest, ManifestError> {
    // The `manifests_subject_is_object` CHECK would reject a bare scalar at
    // INSERT time — i.e. after we had already signed it. Reject here instead.
    if !subject.is_object() {
        return Err(ManifestError::Invalid {
            reason: format!(
                "subject must be a JSON object, got {}",
                match &subject {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "boolean",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => unreachable!(),
                }
            ),
        });
    }

    let wanted_claims = dedup(claim_ids);
    let wanted_edges = dedup(edge_ids);
    if wanted_claims.is_empty() && wanted_edges.is_empty() {
        return Err(ManifestError::Empty);
    }

    // --- Load the write-once subset of every requested row, fail closed ---

    let claim_rows = ManifestRepository::load_claim_leaf_inputs(pool, &wanted_claims).await?;
    if claim_rows.len() != wanted_claims.len() {
        let found: std::collections::HashSet<Uuid> = claim_rows.iter().map(|r| r.id).collect();
        let missing = wanted_claims
            .iter()
            .find(|id| !found.contains(id))
            .copied()
            .unwrap_or_default();
        return Err(ManifestError::UnknownRow {
            kind: ManifestRowKind::Claim,
            id: missing,
        });
    }

    let edge_rows = ManifestRepository::load_edge_leaf_inputs(pool, &wanted_edges).await?;
    if edge_rows.len() != wanted_edges.len() {
        let found: std::collections::HashSet<Uuid> = edge_rows.iter().map(|r| r.id).collect();
        let missing = wanted_edges
            .iter()
            .find(|id| !found.contains(id))
            .copied()
            .unwrap_or_default();
        return Err(ManifestError::UnknownRow {
            kind: ManifestRowKind::Edge,
            id: missing,
        });
    }

    // --- Build leaves, keeping the bundle material alongside each one -------

    struct Built {
        leaf: ManifestLeaf,
        payload: AnchoredEntryPayload,
    }

    let mut built: Vec<Built> = Vec::with_capacity(claim_rows.len() + edge_rows.len());
    for row in &claim_rows {
        let content_hash = to_hash32(
            &row.content_hash,
            &format!("claims.content_hash for {}", row.id),
        )?;
        built.push(Built {
            leaf: claim_leaf(
                *row.id.as_bytes(),
                &content_hash,
                row.agent_id.as_bytes(),
                row.created_at.timestamp_micros(),
            ),
            payload: AnchoredEntryPayload::Claim {
                content_hash: ContentHasher::to_hex(&content_hash),
                agent_id: row.agent_id,
            },
        });
    }
    for row in &edge_rows {
        built.push(Built {
            leaf: edge_leaf(
                *row.id.as_bytes(),
                &row.relationship,
                row.created_at.timestamp_micros(),
            ),
            payload: AnchoredEntryPayload::Edge {
                relationship: row.relationship.clone(),
            },
        });
    }

    // Canonical order first, then carry the payloads along by matching on the
    // leaf's (kind, row id) — the same key the sort used, so the pairing is
    // exact.
    let ordered = canonical_order(built.iter().map(|b| b.leaf).collect())?;
    let payload_for = |leaf: &ManifestLeaf| -> AnchoredEntryPayload {
        built
            .iter()
            .find(|b| b.leaf.sort_key() == leaf.sort_key())
            .map(|b| b.payload.clone())
            .unwrap_or(AnchoredEntryPayload::Edge {
                relationship: String::new(),
            })
    };

    let leaf_hashes: Vec<[u8; HASH_SIZE]> = ordered.iter().map(ManifestLeaf::hash).collect();
    let root = merkle_root(&leaf_hashes)?;

    let entry_count = i32::try_from(ordered.len()).map_err(|_| ManifestError::Invalid {
        reason: format!(
            "{} rows exceeds the INTEGER entry_count the schema records",
            ordered.len()
        ),
    })?;
    let entry_count_u32 = u32::try_from(ordered.len()).map_err(|_| ManifestError::Invalid {
        reason: "entry count does not fit in u32".to_string(),
    })?;

    // --- Sign a small canonical header -------------------------------------

    let manifest_id = Uuid::new_v4();
    let created_at = now_micros();
    let public_key = signer.public_key();
    let signer_did = DidKey::from_public_key(&public_key).to_string();

    let header = ManifestHeader {
        algo: MANIFEST_ALGO.to_string(),
        manifest_id,
        root: ContentHasher::to_hex(&root),
        entry_count: entry_count_u32,
        created_at: rfc3339_micros(&created_at),
        signer_agent_id,
        signer_did: signer_did.clone(),
        subject: subject.clone(),
    };
    // Serialize ONCE and store those exact bytes: the signature's message must
    // never depend on re-deriving the serialization later.
    let signed_header = to_canonical_bytes(&header)?;
    let signature = signer.sign(&signed_header);

    // --- Persist ------------------------------------------------------------

    let db_entries: Vec<NewManifestEntry> = ordered
        .iter()
        .enumerate()
        .map(|(i, leaf)| NewManifestEntry {
            position: i32::try_from(i).unwrap_or(i32::MAX),
            row_kind: leaf.kind().as_str().to_string(),
            row_id: Uuid::from_bytes(leaf.row_id()),
            leaf_hash: leaf.hash().to_vec(),
        })
        .collect();

    ManifestRepository::insert(
        pool,
        &NewManifest {
            id: manifest_id,
            root: root.to_vec(),
            entry_count,
            subject: subject.clone(),
            signed_header: signed_header.clone(),
            signature: signature.to_vec(),
            signer_id: Some(signer_agent_id),
            signer_public_key: public_key.to_vec(),
            created_at,
            entries: db_entries,
        },
    )
    .await?;

    let entries = ordered
        .iter()
        .enumerate()
        .map(|(i, leaf)| {
            let micros = leaf.created_at_micros();
            AnchoredEntry {
                position: i32::try_from(i).unwrap_or(i32::MAX),
                kind: leaf.kind().as_str().to_string(),
                id: Uuid::from_bytes(leaf.row_id()),
                created_at: DateTime::from_timestamp_micros(micros)
                    .map_or_else(|| micros.to_string(), |dt| rfc3339_micros(&dt)),
                created_at_micros: micros,
                leaf: ContentHasher::to_hex(&leaf.hash()),
                payload: payload_for(leaf),
            }
        })
        .collect();

    Ok(AnchoredManifest {
        id: manifest_id,
        root,
        entry_count,
        created_at,
        subject,
        signer_agent_id,
        signer_public_key: public_key,
        signer_did,
        signature,
        signed_header,
        entries,
    })
}

/// Re-verify a stored manifest against the live graph.
///
/// Pass `prove_row` to additionally return an RFC 6962 inclusion proof for one
/// committed row against `manifests.root`.
///
/// # Errors
/// - [`ManifestError::NotFound`] if `manifest_id` does not exist.
/// - [`ManifestError::Db`] on an underlying query failure.
/// - [`ManifestError::Invalid`] if a stored column has the wrong width.
pub async fn verify_manifest(
    pool: &PgPool,
    manifest_id: Uuid,
    prove_row: Option<(ManifestRowKind, Uuid)>,
) -> Result<ManifestVerification, ManifestError> {
    let manifest = ManifestRepository::get(pool, manifest_id)
        .await?
        .ok_or(ManifestError::NotFound(manifest_id))?;
    let entries = ManifestRepository::entries(pool, manifest_id).await?;

    let stored_root = to_hash32(&manifest.root, "manifests.root")?;
    let public_key = <[u8; PUBLIC_KEY_SIZE]>::try_from(manifest.signer_public_key.as_slice())
        .map_err(|_| ManifestError::Invalid {
            reason: format!(
                "manifests.signer_public_key is {} bytes, expected {PUBLIC_KEY_SIZE}",
                manifest.signer_public_key.len()
            ),
        })?;
    let signature =
        <[u8; SIGNATURE_SIZE]>::try_from(manifest.signature.as_slice()).map_err(|_| {
            ManifestError::Invalid {
                reason: format!(
                    "manifests.signature is {} bytes, expected {SIGNATURE_SIZE}",
                    manifest.signature.len()
                ),
            }
        })?;
    let signer_did = DidKey::from_public_key(&public_key).to_string();

    // --- (1) per-entry status, live leaves ---------------------------------

    let claim_ids: Vec<Uuid> = entries
        .iter()
        .filter(|e| e.row_kind == ManifestRowKind::Claim.as_str())
        .map(|e| e.row_id)
        .collect();
    let edge_ids: Vec<Uuid> = entries
        .iter()
        .filter(|e| e.row_kind == ManifestRowKind::Edge.as_str())
        .map(|e| e.row_id)
        .collect();

    let live_claims = ManifestRepository::load_claim_leaf_inputs(pool, &claim_ids).await?;
    let live_edges = ManifestRepository::load_edge_leaf_inputs(pool, &edge_ids).await?;

    let mut live_leaf_by_row: std::collections::HashMap<(String, Uuid), [u8; HASH_SIZE]> =
        std::collections::HashMap::new();
    for row in &live_claims {
        let Ok(content_hash) = <[u8; HASH_SIZE]>::try_from(row.content_hash.as_slice()) else {
            // A malformed content_hash cannot reproduce any leaf; leaving it out
            // reports the entry as `missing`, which is the honest verdict.
            continue;
        };
        live_leaf_by_row.insert(
            (ManifestRowKind::Claim.as_str().to_string(), row.id),
            claim_leaf(
                *row.id.as_bytes(),
                &content_hash,
                row.agent_id.as_bytes(),
                row.created_at.timestamp_micros(),
            )
            .hash(),
        );
    }
    for row in &live_edges {
        live_leaf_by_row.insert(
            (ManifestRowKind::Edge.as_str().to_string(), row.id),
            edge_leaf(
                *row.id.as_bytes(),
                &row.relationship,
                row.created_at.timestamp_micros(),
            )
            .hash(),
        );
    }

    let mut entry_statuses = Vec::with_capacity(entries.len());
    let mut stored_leaves: Vec<[u8; HASH_SIZE]> = Vec::with_capacity(entries.len());
    let mut live_leaves: Vec<[u8; HASH_SIZE]> = Vec::with_capacity(entries.len());

    for entry in &entries {
        let stored_leaf = to_hash32(
            &entry.leaf_hash,
            &format!("manifest_entries.leaf_hash at position {}", entry.position),
        )?;
        stored_leaves.push(stored_leaf);

        let live = live_leaf_by_row.get(&(entry.row_kind.clone(), entry.row_id));
        let status = match live {
            None => EntryVerdict::Missing,
            Some(l) if *l == stored_leaf => EntryVerdict::Ok,
            Some(_) => EntryVerdict::Mismatch,
        };
        if let Some(l) = live {
            live_leaves.push(*l);
        }

        entry_statuses.push(EntryStatus {
            position: entry.position,
            kind: entry.row_kind.clone(),
            row_id: entry.row_id,
            stored_leaf: ContentHasher::to_hex(&stored_leaf),
            live_leaf: live.map(ContentHasher::to_hex),
            status,
        });
    }

    // --- (2) stored leaves still fold to the root --------------------------

    let stored_root_intact = merkle_root(&stored_leaves).is_ok_and(|r| r == stored_root);

    // --- (3) live leaves fold to the root ----------------------------------

    let live_root = merkle_root(&live_leaves).ok();
    // A short live list (some rows deleted) can never equal the stored root, so
    // this correctly reports false without any special-casing.
    let live_root_matches = live_root == Some(stored_root);

    // --- (4) entry count -----------------------------------------------------

    let counted = ManifestRepository::count_entries(pool, manifest_id).await?;
    let entry_count_matches = counted == i64::from(manifest.entry_count);

    // --- (5) header / column cross-check -------------------------------------

    let parsed: Option<ManifestHeader> = serde_json::from_slice(&manifest.signed_header).ok();
    let header_consistent = parsed.as_ref().is_some_and(|h| {
        h.algo == manifest.algo
            && h.manifest_id == manifest.id
            && h.root == ContentHasher::to_hex(&stored_root)
            && i64::from(h.entry_count) == i64::from(manifest.entry_count)
            && h.created_at == rfc3339_micros(&manifest.created_at)
            && h.subject == manifest.subject
            // Only cross-check the signer when the lineage FK survives; the
            // column is ON DELETE SET NULL and the snapshotted key remains the
            // verification authority either way.
            && manifest
                .signer_id
                .is_none_or(|sid| h.signer_agent_id == sid)
            && h.signer_did == signer_did
    });

    // --- (6) signature ------------------------------------------------------

    let signature_bytes_valid =
        SignatureVerifier::verify(&public_key, &manifest.signed_header, &signature)
            .unwrap_or(false);
    let signature_valid = signature_bytes_valid && header_consistent;

    // --- (7) is the snapshotted key still the agent's current key? ----------

    let signer_key_current = match manifest.signer_id {
        None => None,
        Some(sid) => {
            let agent =
                AgentRepository::get_by_id(pool, epigraph_core::AgentId::from_uuid(sid)).await?;
            agent.map(|a| a.public_key == public_key)
        }
    };

    // --- optional inclusion proof -------------------------------------------

    let inclusion_proof_report = prove_row.and_then(|(kind, row_id)| {
        let idx = entries
            .iter()
            .position(|e| e.row_kind == kind.as_str() && e.row_id == row_id)?;
        let path = inclusion_proof(&stored_leaves, idx).ok()?;
        let leaf = stored_leaves[idx];
        Some(InclusionProofReport {
            kind: kind.as_str().to_string(),
            row_id,
            position: entries[idx].position,
            leaf: ContentHasher::to_hex(&leaf),
            tree_size: stored_leaves.len(),
            path: path
                .iter()
                .map(|s: &ProofStep| ProofStepReport {
                    sibling: ContentHasher::to_hex(&s.sibling),
                    sibling_is_right: s.sibling_is_right,
                })
                .collect(),
            verified: verify_inclusion(leaf, idx, stored_leaves.len(), &path, stored_root),
        })
    });

    Ok(ManifestVerification {
        manifest_id,
        algo: manifest.algo.clone(),
        root: ContentHasher::to_hex(&stored_root),
        entry_count: manifest.entry_count,
        created_at: rfc3339_micros(&manifest.created_at),
        subject: manifest.subject.clone(),
        signer_id: manifest.signer_id,
        signer_did,
        signature_valid,
        signature_bytes_valid,
        header_consistent,
        stored_root_intact,
        live_root_matches,
        live_root: live_root.map(|r| ContentHasher::to_hex(&r)),
        entry_count_matches,
        signer_key_current,
        entries: entry_statuses,
        inclusion_proof: inclusion_proof_report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_micros_is_stable_and_microsecond_truncated() {
        // Built from a literal instant rather than an epoch integer, so the
        // expected string is self-evident: the trailing 789 nanoseconds must be
        // TRUNCATED, not rounded — Postgres truncates too, and a rounding
        // renderer would put the header one microsecond ahead of the column.
        let dt: DateTime<Utc> = "2026-08-27T12:34:56.123456789Z".parse().unwrap();
        assert_eq!(rfc3339_micros(&dt), "2026-08-27T12:34:56.123456Z");

        // And the rendering round-trips at microsecond resolution.
        let reparsed: DateTime<Utc> = rfc3339_micros(&dt).parse().unwrap();
        assert_eq!(reparsed.timestamp_micros(), dt.timestamp_micros());
    }

    #[test]
    fn now_micros_has_no_sub_microsecond_component() {
        // The single most likely way to ship this broken: sign a nanosecond
        // timestamp, store its microsecond truncation, and fail
        // `header_consistent` on every manifest forever.
        let t = now_micros();
        assert_eq!(
            t.timestamp_micros() * 1000,
            t.timestamp_nanos_opt().unwrap(),
            "now_micros must carry no nanosecond remainder"
        );
    }

    #[test]
    fn hex_lower_is_lowercase_and_padded() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    }

    #[test]
    fn dedup_collapses_repeats() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_eq!(dedup(&[a, b, a, a]), vec![a, b]);
    }

    #[test]
    fn header_round_trips_through_canonical_json() {
        let header = ManifestHeader {
            algo: MANIFEST_ALGO.to_string(),
            manifest_id: Uuid::from_u128(7),
            root: "ab".repeat(32),
            entry_count: 3,
            created_at: "2026-01-01T00:00:00.000000Z".to_string(),
            signer_agent_id: Uuid::from_u128(9),
            signer_did: "did:key:z6Mk".to_string(),
            subject: serde_json::json!({"kind": "provenance_export"}),
        };
        let bytes = to_canonical_bytes(&header).unwrap();
        let back: ManifestHeader = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.manifest_id, header.manifest_id);
        assert_eq!(back.root, header.root);
        assert_eq!(back.entry_count, header.entry_count);
        assert_eq!(back.created_at, header.created_at);
        assert_eq!(back.subject, header.subject);
    }
}
