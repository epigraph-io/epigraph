//! Evidence domain model
//!
//! Evidence represents supporting material for claims. All evidence must be:
//! - Cryptographically signed by an agent
//! - Content-addressed (BLAKE3 hash)
//! - Typed (Document, Observation, Testimony, Literature, Consensus, Figure,
//!   Dataset)

use super::ids::{AgentId, ClaimId, EvidenceId};
use chrono::{DateTime, Utc};
use epigraph_crypto::SIGNATURE_SIZE;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// Values writers put in a DOI slot to mean "this document has no DOI". They
/// are ABSENT, not an identity: keying on them collapses every DOI-less
/// document onto one shared key (issue #356). Ingest's document key and the
/// belief engine's source key both reject them.
pub const DOI_PLACEHOLDERS: [&str; 8] = ["unknown", "n/a", "na", "none", "null", "nil", "-", "tbd"];

/// True when `s` is empty/whitespace or one of the [`DOI_PLACEHOLDERS`]
/// (trimmed, ASCII case-insensitive).
#[must_use]
pub fn is_placeholder_id(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || DOI_PLACEHOLDERS.contains(&t.to_ascii_lowercase().as_str())
}

/// Types of evidence with their specific attributes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceType {
    /// Digital document or artifact
    Document {
        /// URL or storage location
        source_url: Option<String>,
        /// MIME type (e.g., "application/pdf", "image/png")
        mime_type: String,
        /// Optional additional checksum for verification
        checksum: Option<String>,
    },

    /// Direct observation by an agent
    Observation {
        /// When the observation occurred
        observed_at: DateTime<Utc>,
        /// Method of observation (e.g., "visual", "instrumental")
        method: String,
        /// Optional location where observation was made
        location: Option<String>,
    },

    /// Testimony from an agent or external source
    Testimony {
        /// Source of the testimony
        source: String,
        /// When the testimony was given
        testified_at: DateTime<Utc>,
        /// Optional verification method
        verification: Option<String>,
    },

    /// Published literature (academic papers, books, etc.)
    Literature {
        /// DOI or other persistent identifier
        doi: String,
        /// Specific section or page reference
        extraction_target: String,
        /// Optional page range
        page_range: Option<(u32, u32)>,
    },

    /// Consensus from multiple agents
    Consensus {
        /// Agent IDs that participated
        participants: Vec<AgentId>,
        /// Quorum threshold (0.0 to 1.0)
        quorum: f64,
        /// Optional voting mechanism description
        voting_mechanism: Option<String>,
    },

    /// Figure or image extracted from a document (e.g., STM image, XPS spectrum)
    Figure {
        /// DOI or source identifier for the parent document
        doi: String,
        /// Figure identifier within the document (e.g., "Figure 1", "Fig. 2a")
        figure_id: Option<String>,
        /// Caption text extracted from the document
        caption: Option<String>,
        /// MIME type of the image data (e.g., "image/png")
        mime_type: String,
        /// Page number where the figure appears
        page: Option<u32>,
    },

    /// A multi-file dataset, committed to by the digest of its manifest
    /// (backlog c8beb101).
    ///
    /// The manifest lists every file of the dataset with its own digest, so
    /// one row commits to a whole run directory: a reader resolves
    /// `root_uri`, fetches the manifest (`manifest_uri` or
    /// `manifest_blob_id`), checks it against `manifest_hash`, then checks
    /// each file against the manifest. Nothing here needs `raw_content`.
    ///
    /// Build one with [`EvidenceType::dataset`], which normalises and
    /// validates the fields; [`EvidenceType::validate`] checks a value that
    /// arrived already built (an HTTP body).
    Dataset {
        /// Where the dataset lives (a URI or path naming its root directory).
        root_uri: String,
        /// Where the manifest itself can be fetched, when not at a known
        /// name under `root_uri`.
        manifest_uri: Option<String>,
        /// The blob store id of the manifest, when it was uploaded as one.
        manifest_blob_id: Option<String>,
        /// The manifest's digest, `<hash_algorithm>:<lowercase hex>`, e.g.
        /// `blake3:af13...`.
        manifest_hash: String,
        /// The algorithm of `manifest_hash`, one of
        /// [`MANIFEST_HASH_ALGORITHMS`]; always equal to its prefix.
        hash_algorithm: String,
        /// How many files the manifest lists.
        file_count: u64,
        /// The summed size, in bytes, of the files the manifest lists.
        total_bytes: u64,
        /// An episcience sample id the dataset belongs to.
        sample_id: Option<String>,
        /// Blob store ids of files of the dataset that were uploaded.
        #[serde(default)]
        blob_ids: Vec<String>,
        /// The writing server's signature over these fields, bound to the
        /// row's evidence and claim ids ([`EvidenceType::attest_dataset`]).
        ///
        /// The evidence row's own signature covers only its `content_hash`
        /// (`BLAKE3(raw_content)`), so without this nothing signed the
        /// manifest digest a reader checks the files against. Written by the
        /// server, never accepted from a caller; absent on a row no server
        /// signed (an HTTP write), which a reader treats as unverified.
        /// Omitted from the serialised form when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation: Option<DatasetAttestation>,
    },
}

/// A signature over a dataset row's structured fields
/// ([`EvidenceType::dataset_attestation_digest`]), stored beside them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetAttestation {
    /// The signed-message scheme: `v1`
    /// (`epigraph_crypto::signing_message(SignedEntity::Dataset, digest)`).
    pub scheme: String,
    /// The digest that was signed, lowercase hex. A verifier recomputes it
    /// from the fields; this copy is for comparison and diagnostics only.
    pub digest: String,
    /// The Ed25519 signature, lowercase hex (128 characters).
    pub signature: String,
}

/// Version prefix of the bytes [`EvidenceType::dataset_attestation_digest`]
/// hashes. A new layout takes a new prefix; this one never changes.
pub const DATASET_ATTESTATION_DOMAIN_V1: &[u8] = b"epigraph-dataset-attestation-v1\0";

fn push_field(buf: &mut Vec<u8>, value: &str) {
    // A u32 length prefix: every field is bounded far below 4 GiB by
    // `EvidenceType::validate`, and the prefix keeps adjacent fields from
    // running together ("ab"+"c" vs "a"+"bc").
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn push_opt(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => buf.push(0),
        Some(v) => {
            buf.push(1);
            push_field(buf, v);
        }
    }
}

/// The values the `evidence.evidence_type` column admits (the
/// `evidence_type_valid` CHECK: migration 001's seven, plus `dataset` from
/// migration 229).
///
/// Not the same vocabulary as the [`EvidenceType`] serde tags: `Literature` is
/// stored as `reference` and `Consensus` as `computation`
/// ([`EvidenceType::stored_type`]); `conversational` has no variant.
pub const STORED_EVIDENCE_TYPES: &[&str] = &[
    "document",
    "observation",
    "testimony",
    "computation",
    "reference",
    "figure",
    "conversational",
    "dataset",
];

/// The hash algorithms a [`EvidenceType::Dataset`] manifest digest may name,
/// each with the length of its lowercase hex digest. `sha256` and `blake3`
/// are the two manifest formats in use (`MANIFEST.sha256`, `MANIFEST.b3`).
pub const MANIFEST_HASH_ALGORITHMS: &[(&str, usize)] =
    &[("blake3", 64), ("sha256", 64), ("sha512", 128)];

/// The longest `root_uri` / `manifest_uri` a dataset row may carry, in bytes.
pub const MAX_DATASET_URI_LEN: usize = 2048;
/// The longest `manifest_blob_id`, `sample_id` or blob id, in bytes.
pub const MAX_DATASET_ID_LEN: usize = 256;
/// The most `blob_ids` one dataset row may list. The manifest, not this list,
/// is what commits to the files; this is for the few that were uploaded.
pub const MAX_DATASET_BLOB_IDS: usize = 64;

/// The fields of a dataset as a caller supplies them, before
/// [`EvidenceType::dataset`] normalises them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetManifestInput {
    pub root_uri: String,
    pub manifest_uri: Option<String>,
    pub manifest_blob_id: Option<String>,
    /// `<algorithm>:<hex>`, or bare hex when `hash_algorithm` names the
    /// algorithm. Case-insensitive.
    pub manifest_hash: String,
    /// Optional when `manifest_hash` carries the prefix; must agree with it
    /// when both are given.
    pub hash_algorithm: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub sample_id: Option<String>,
    pub blob_ids: Vec<String>,
}

/// Why a dataset's fields were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid dataset evidence: {field}: {reason}")]
pub struct DatasetEvidenceError {
    /// The offending field, as named on the wire.
    pub field: &'static str,
    pub reason: String,
}

fn dataset_error(field: &'static str, reason: impl Into<String>) -> DatasetEvidenceError {
    DatasetEvidenceError {
        field,
        reason: reason.into(),
    }
}

fn check_text(field: &'static str, value: &str, max: usize) -> Result<(), DatasetEvidenceError> {
    if value.trim().is_empty() {
        return Err(dataset_error(field, "must not be empty"));
    }
    if value.trim() != value {
        return Err(dataset_error(
            field,
            "must not have leading or trailing whitespace",
        ));
    }
    if value.len() > max {
        return Err(dataset_error(
            field,
            format!("is {} bytes; the maximum is {max}", value.len()),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(dataset_error(field, "must not contain control characters"));
    }
    Ok(())
}

fn trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl EvidenceType {
    /// Build a [`EvidenceType::Dataset`] from caller input: trim the text
    /// fields, drop empty optional ones, lower-case the digest and give it its
    /// `<algorithm>:` prefix, then [`Self::validate`] the result.
    ///
    /// # Errors
    /// [`DatasetEvidenceError`] naming the first field that fails.
    pub fn dataset(input: DatasetManifestInput) -> Result<Self, DatasetEvidenceError> {
        let hash = input.manifest_hash.trim().to_ascii_lowercase();
        let declared = trimmed(input.hash_algorithm).map(|a| a.to_ascii_lowercase());
        let (algorithm, hex) = match (hash.split_once(':'), declared) {
            (Some((prefix, hex)), Some(declared)) => {
                if prefix != declared {
                    return Err(dataset_error(
                        "hash_algorithm",
                        format!("is {declared:?} but manifest_hash is prefixed {prefix:?}"),
                    ));
                }
                (declared, hex.to_string())
            }
            (Some((prefix, hex)), None) => (prefix.to_string(), hex.to_string()),
            (None, Some(declared)) => (declared, hash.clone()),
            (None, None) => {
                return Err(dataset_error(
                    "manifest_hash",
                    "names no algorithm: write it as <algorithm>:<hex> (e.g. blake3:...) \
                     or pass hash_algorithm",
                ))
            }
        };
        let built = Self::Dataset {
            root_uri: input.root_uri.trim().to_string(),
            manifest_uri: trimmed(input.manifest_uri),
            manifest_blob_id: trimmed(input.manifest_blob_id),
            manifest_hash: format!("{algorithm}:{hex}"),
            hash_algorithm: algorithm,
            file_count: input.file_count,
            total_bytes: input.total_bytes,
            sample_id: trimmed(input.sample_id),
            blob_ids: input
                .blob_ids
                .into_iter()
                .map(|b| b.trim().to_string())
                .collect(),
            attestation: None,
        };
        built.validate()?;
        Ok(built)
    }

    /// Check a value's own invariants. Only [`Self::Dataset`] has any: its
    /// `manifest_hash` is `<hash_algorithm>:<lowercase hex>` of the length that
    /// algorithm produces, the algorithm is one of
    /// [`MANIFEST_HASH_ALGORITHMS`], and its text fields are non-empty and
    /// within [`MAX_DATASET_URI_LEN`] / [`MAX_DATASET_ID_LEN`] /
    /// [`MAX_DATASET_BLOB_IDS`]. Every other variant is `Ok`.
    ///
    /// # Errors
    /// [`DatasetEvidenceError`] naming the first field that fails.
    pub fn validate(&self) -> Result<(), DatasetEvidenceError> {
        let Self::Dataset {
            root_uri,
            manifest_uri,
            manifest_blob_id,
            manifest_hash,
            hash_algorithm,
            file_count: _,
            total_bytes: _,
            sample_id,
            blob_ids,
            attestation: _,
        } = self
        else {
            return Ok(());
        };
        check_text("root_uri", root_uri, MAX_DATASET_URI_LEN)?;
        if let Some(uri) = manifest_uri {
            check_text("manifest_uri", uri, MAX_DATASET_URI_LEN)?;
        }
        if let Some(id) = manifest_blob_id {
            check_text("manifest_blob_id", id, MAX_DATASET_ID_LEN)?;
        }
        if let Some(id) = sample_id {
            check_text("sample_id", id, MAX_DATASET_ID_LEN)?;
        }
        if blob_ids.len() > MAX_DATASET_BLOB_IDS {
            return Err(dataset_error(
                "blob_ids",
                format!(
                    "lists {} ids; the maximum is {MAX_DATASET_BLOB_IDS}",
                    blob_ids.len()
                ),
            ));
        }
        for id in blob_ids {
            check_text("blob_ids", id, MAX_DATASET_ID_LEN)?;
        }
        let Some(&(_, hex_len)) = MANIFEST_HASH_ALGORITHMS
            .iter()
            .find(|(name, _)| *name == hash_algorithm.as_str())
        else {
            return Err(dataset_error(
                "hash_algorithm",
                format!(
                    "{hash_algorithm:?} is not one of {}",
                    MANIFEST_HASH_ALGORITHMS
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        };
        let Some(hex) = manifest_hash
            .strip_prefix(hash_algorithm.as_str())
            .and_then(|rest| rest.strip_prefix(':'))
        else {
            return Err(dataset_error(
                "manifest_hash",
                format!("must be prefixed \"{hash_algorithm}:\""),
            ));
        };
        if hex.len() != hex_len
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(dataset_error(
                "manifest_hash",
                format!("a {hash_algorithm} digest is {hex_len} lowercase hex characters"),
            ));
        }
        Ok(())
    }

    /// The digest a dataset row's [`DatasetAttestation`] signs, or `None` for
    /// any other variant.
    ///
    /// BLAKE3 over [`DATASET_ATTESTATION_DOMAIN_V1`], the row's evidence id
    /// and claim id (16 bytes each), then every field in declaration order:
    /// text as a big-endian u32 length and its bytes, an optional text as
    /// `0x00` (absent) or `0x01` and the text, counts as big-endian u64, and
    /// `blob_ids` as a u32 count and each id. The attestation itself is not
    /// hashed.
    ///
    /// The ids are what stop a valid dataset and its attestation being copied
    /// onto another row or claim: the copy hashes to a different digest. A
    /// byte layout rather than JSON, so a verifier in another language
    /// reproduces it without a canonical-JSON library, and so JSONB's key
    /// reordering cannot move it.
    #[must_use]
    pub fn dataset_attestation_digest(
        &self,
        evidence_id: EvidenceId,
        claim_id: ClaimId,
    ) -> Option<[u8; epigraph_crypto::HASH_SIZE]> {
        let Self::Dataset {
            root_uri,
            manifest_uri,
            manifest_blob_id,
            manifest_hash,
            hash_algorithm,
            file_count,
            total_bytes,
            sample_id,
            blob_ids,
            attestation: _,
        } = self
        else {
            return None;
        };
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(DATASET_ATTESTATION_DOMAIN_V1);
        buf.extend_from_slice(evidence_id.as_uuid().as_bytes());
        buf.extend_from_slice(claim_id.as_uuid().as_bytes());
        push_field(&mut buf, root_uri);
        push_opt(&mut buf, manifest_uri.as_deref());
        push_opt(&mut buf, manifest_blob_id.as_deref());
        push_field(&mut buf, manifest_hash);
        push_field(&mut buf, hash_algorithm);
        buf.extend_from_slice(&file_count.to_be_bytes());
        buf.extend_from_slice(&total_bytes.to_be_bytes());
        push_opt(&mut buf, sample_id.as_deref());
        #[allow(clippy::cast_possible_truncation)]
        buf.extend_from_slice(&(blob_ids.len() as u32).to_be_bytes());
        for id in blob_ids {
            push_field(&mut buf, id);
        }
        Some(epigraph_crypto::ContentHasher::hash(&buf))
    }

    /// Sign a dataset row's fields with `signer` and store the result as its
    /// [`DatasetAttestation`], replacing any there was. Returns `false`, and
    /// changes nothing, for any other variant.
    pub fn attest_dataset(
        &mut self,
        evidence_id: EvidenceId,
        claim_id: ClaimId,
        signer: &epigraph_crypto::AgentSigner,
    ) -> bool {
        let Some(digest) = self.dataset_attestation_digest(evidence_id, claim_id) else {
            return false;
        };
        let signature = signer.sign_entity(epigraph_crypto::SignedEntity::Dataset, &digest);
        if let Self::Dataset { attestation, .. } = self {
            *attestation = Some(DatasetAttestation {
                scheme: "v1".to_string(),
                digest: hex::encode(digest),
                signature: hex::encode(signature),
            });
        }
        true
    }

    /// Whether a dataset row's [`DatasetAttestation`] verifies under
    /// `public_key` for these fields and these ids.
    ///
    /// `None` when there is nothing to check: not a dataset, or a dataset with
    /// no attestation. `Some(false)` when the attestation is malformed, its
    /// scheme is not `v1`, or the signature does not verify over the digest
    /// recomputed from the CURRENT fields (an edited field, or a dataset
    /// copied from another row, lands here). The stored `digest` copy is never
    /// trusted.
    #[must_use]
    pub fn verify_dataset_attestation(
        &self,
        evidence_id: EvidenceId,
        claim_id: ClaimId,
        public_key: &[u8; epigraph_crypto::PUBLIC_KEY_SIZE],
    ) -> Option<bool> {
        let Self::Dataset {
            attestation: Some(att),
            ..
        } = self
        else {
            return None;
        };
        let digest = self.dataset_attestation_digest(evidence_id, claim_id)?;
        if att.scheme != "v1" {
            return Some(false);
        }
        let Ok(sig) = hex::decode(&att.signature) else {
            return Some(false);
        };
        let Ok(sig) = <[u8; SIGNATURE_SIZE]>::try_from(sig.as_slice()) else {
            return Some(false);
        };
        let verified = epigraph_crypto::SignatureVerifier::verify_entity(
            public_key,
            epigraph_crypto::SignedEntity::Dataset,
            &digest,
            &sig,
        );
        // Only the v1 rung counts: a legacy bare-digest signature binds no
        // entity kind, so it could have been made for any other purpose.
        Some(matches!(
            verified,
            Ok(Some(epigraph_crypto::SignatureScheme::V1))
        ))
    }

    /// The `evidence.evidence_type` column value this variant is stored
    /// under (one of [`STORED_EVIDENCE_TYPES`]).
    #[must_use]
    pub const fn stored_type(&self) -> &'static str {
        match self {
            Self::Document { .. } => "document",
            Self::Observation { .. } => "observation",
            Self::Testimony { .. } => "testimony",
            Self::Literature { .. } => "reference",
            Self::Consensus { .. } => "computation",
            Self::Figure { .. } => "figure",
            Self::Dataset { .. } => "dataset",
        }
    }
}

/// Evidence supporting or refuting a claim
///
/// # Design Notes
///
/// - All evidence MUST be signed by the agent who provided it
/// - Content hash prevents tampering
/// - Raw content is optional (may be stored externally)
/// - Evidence can support multiple claims via the `claim_id` reference
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier for this evidence
    pub id: EvidenceId,

    /// The agent who provided this evidence
    pub agent_id: AgentId,

    /// Ed25519 public key of the signing agent (32 bytes)
    /// Required for signature verification without database lookup
    #[serde_as(as = "Bytes")]
    pub public_key: [u8; 32],

    /// BLAKE3 content hash (32 bytes)
    #[serde_as(as = "Bytes")]
    pub content_hash: [u8; 32],

    /// Type-specific evidence data
    pub evidence_type: EvidenceType,

    /// Optional raw content (may be external)
    pub raw_content: Option<String>,

    /// The claim this evidence supports
    pub claim_id: ClaimId,

    /// Ed25519 signature from the agent (64 bytes)
    #[serde_as(as = "Option<Bytes>")]
    pub signature: Option<[u8; 64]>,

    /// When this evidence was created/submitted
    pub created_at: DateTime<Utc>,
}

impl Evidence {
    /// Create new evidence (signature must be added separately)
    #[must_use]
    pub fn new(
        agent_id: AgentId,
        public_key: [u8; 32],
        content_hash: [u8; 32],
        evidence_type: EvidenceType,
        raw_content: Option<String>,
        claim_id: ClaimId,
    ) -> Self {
        Self {
            id: EvidenceId::new(),
            agent_id,
            public_key,
            content_hash,
            evidence_type,
            raw_content,
            claim_id,
            signature: None,
            created_at: Utc::now(),
        }
    }

    /// Create evidence with a specific ID (for database deserialization)
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn with_id(
        id: EvidenceId,
        agent_id: AgentId,
        public_key: [u8; 32],
        content_hash: [u8; 32],
        evidence_type: EvidenceType,
        raw_content: Option<String>,
        claim_id: ClaimId,
        signature: Option<[u8; 64]>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            agent_id,
            public_key,
            content_hash,
            evidence_type,
            raw_content,
            claim_id,
            signature,
            created_at,
        }
    }

    /// Check if this evidence has been signed
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Get a human-readable description of the evidence type
    #[must_use]
    pub const fn type_description(&self) -> &'static str {
        match &self.evidence_type {
            EvidenceType::Document { .. } => "Document",
            EvidenceType::Observation { .. } => "Observation",
            EvidenceType::Testimony { .. } => "Testimony",
            EvidenceType::Literature { .. } => "Literature",
            EvidenceType::Consensus { .. } => "Consensus",
            EvidenceType::Figure { .. } => "Figure",
            EvidenceType::Dataset { .. } => "Dataset",
        }
    }
}

impl std::hash::Hash for Evidence {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// Only compare by ID for equality (structural equivalence)
impl PartialEq for Evidence {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Evidence {}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_crypto::AgentSigner;

    #[test]
    fn create_document_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [0u8; 32];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Document {
                source_url: Some("https://example.com/doc.pdf".to_string()),
                mime_type: "application/pdf".to_string(),
                checksum: None,
            },
            Some("document content".to_string()),
            claim_id,
        );

        assert_eq!(evidence.agent_id, agent_id);
        assert_eq!(evidence.claim_id, claim_id);
        assert_eq!(evidence.type_description(), "Document");
        assert!(!evidence.is_signed());
    }

    #[test]
    fn create_literature_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [1u8; 32];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Literature {
                doi: "10.1000/xyz123".to_string(),
                extraction_target: "Section 3.2".to_string(),
                page_range: Some((10, 15)),
            },
            None,
            claim_id,
        );

        assert_eq!(evidence.type_description(), "Literature");

        if let EvidenceType::Literature {
            doi, page_range, ..
        } = &evidence.evidence_type
        {
            assert_eq!(doi, "10.1000/xyz123");
            assert_eq!(page_range, &Some((10, 15)));
        } else {
            panic!("Expected Literature evidence type");
        }
    }

    #[test]
    fn create_consensus_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [2u8; 32];

        let participants = vec![AgentId::new(), AgentId::new(), AgentId::new()];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Consensus {
                participants,
                quorum: 0.67,
                voting_mechanism: Some("majority".to_string()),
            },
            None,
            claim_id,
        );

        assert_eq!(evidence.type_description(), "Consensus");

        if let EvidenceType::Consensus {
            participants: p,
            quorum,
            ..
        } = &evidence.evidence_type
        {
            assert_eq!(p.len(), 3);
            assert!((quorum - 0.67).abs() < f64::EPSILON);
        } else {
            panic!("Expected Consensus evidence type");
        }
    }

    #[test]
    fn create_observation_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [3u8; 32];
        let observed_at = Utc::now();

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Observation {
                observed_at,
                method: "visual inspection".to_string(),
                location: Some("Laboratory A".to_string()),
            },
            Some("Observed phenomenon X".to_string()),
            claim_id,
        );

        assert_eq!(evidence.type_description(), "Observation");

        if let EvidenceType::Observation {
            method, location, ..
        } = &evidence.evidence_type
        {
            assert_eq!(method, "visual inspection");
            assert_eq!(location, &Some("Laboratory A".to_string()));
        } else {
            panic!("Expected Observation evidence type");
        }
    }

    #[test]
    fn create_testimony_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [4u8; 32];
        let testified_at = Utc::now();

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Testimony {
                source: "Dr. Jane Smith".to_string(),
                testified_at,
                verification: Some("notarized".to_string()),
            },
            Some("Witness statement about the event".to_string()),
            claim_id,
        );

        assert_eq!(evidence.type_description(), "Testimony");

        if let EvidenceType::Testimony {
            source,
            verification,
            ..
        } = &evidence.evidence_type
        {
            assert_eq!(source, "Dr. Jane Smith");
            assert_eq!(verification, &Some("notarized".to_string()));
        } else {
            panic!("Expected Testimony evidence type");
        }
    }

    #[test]
    fn evidence_with_id_and_signature() {
        let id = EvidenceId::new();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [5u8; 32];
        let signature = [0xABu8; 64];
        let created_at = Utc::now();

        let evidence = Evidence::with_id(
            id,
            agent_id,
            public_key,
            hash,
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            None,
            claim_id,
            Some(signature),
            created_at,
        );

        assert_eq!(evidence.id, id);
        assert!(evidence.is_signed());
        assert_eq!(evidence.signature, Some(signature));
    }

    #[test]
    fn evidence_equality_by_id() {
        let id = EvidenceId::new();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let now = Utc::now();

        let evidence1 = Evidence::with_id(
            id,
            agent_id,
            public_key,
            [1u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "a".to_string(),
                checksum: None,
            },
            None,
            claim_id,
            None,
            now,
        );

        let evidence2 = Evidence::with_id(
            id,
            agent_id,
            public_key,
            [2u8; 32], // Different hash
            EvidenceType::Document {
                source_url: None,
                mime_type: "b".to_string(),
                checksum: None,
            },
            None,
            claim_id,
            None,
            now,
        );

        assert_eq!(
            evidence1, evidence2,
            "Evidence with same ID should be equal"
        );
    }

    #[test]
    fn evidence_serializes_to_json() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [42u8; 32];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Observation {
                observed_at: Utc::now(),
                method: "visual".to_string(),
                location: Some("lab".to_string()),
            },
            Some("observed a thing".to_string()),
            claim_id,
        );

        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: Evidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.id, deserialized.id);
        assert_eq!(evidence.agent_id, deserialized.agent_id);
        assert_eq!(evidence.content_hash, deserialized.content_hash);
    }

    #[test]
    fn create_figure_evidence() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [6u8; 32];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Figure {
                doi: "10.1000/fig123".to_string(),
                figure_id: Some("Figure 2a".to_string()),
                caption: Some("STM image of TiO2 surface".to_string()),
                mime_type: "image/png".to_string(),
                page: Some(10),
            },
            Some("base64-image-data-here".to_string()),
            claim_id,
        );

        assert_eq!(evidence.type_description(), "Figure");

        if let EvidenceType::Figure {
            doi,
            figure_id,
            caption,
            mime_type,
            page,
        } = &evidence.evidence_type
        {
            assert_eq!(doi, "10.1000/fig123");
            assert_eq!(figure_id, &Some("Figure 2a".to_string()));
            assert_eq!(caption, &Some("STM image of TiO2 surface".to_string()));
            assert_eq!(mime_type, "image/png");
            assert_eq!(page, &Some(10));
        } else {
            panic!("Expected Figure evidence type");
        }
    }

    #[test]
    fn figure_evidence_serializes_to_json() {
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();
        let public_key = [0u8; 32];
        let hash = [7u8; 32];

        let evidence = Evidence::new(
            agent_id,
            public_key,
            hash,
            EvidenceType::Figure {
                doi: "10.1000/xyz".to_string(),
                figure_id: Some("Fig. 1".to_string()),
                caption: None,
                mime_type: "image/png".to_string(),
                page: Some(5),
            },
            None,
            claim_id,
        );

        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: Evidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.id, deserialized.id);
        if let EvidenceType::Figure { doi, mime_type, .. } = &deserialized.evidence_type {
            assert_eq!(doi, "10.1000/xyz");
            assert_eq!(mime_type, "image/png");
        } else {
            panic!("Deserialized evidence should be Figure type");
        }
    }

    // ==================== Dataset evidence (backlog c8beb101) ====================

    const B3_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn dataset_input() -> DatasetManifestInput {
        DatasetManifestInput {
            root_uri: "s3://lab-runs/campaign-7/run-0042/".to_string(),
            manifest_uri: Some("s3://lab-runs/campaign-7/run-0042/MANIFEST.b3".to_string()),
            manifest_blob_id: None,
            manifest_hash: format!("blake3:{B3_HEX}"),
            hash_algorithm: None,
            file_count: 1_204,
            total_bytes: 73_014_444_032,
            sample_id: Some("sample-17".to_string()),
            blob_ids: vec![],
        }
    }

    fn dataset_error_field(input: DatasetManifestInput) -> &'static str {
        EvidenceType::dataset(input)
            .expect_err("the input must be refused")
            .field
    }

    /// The wire shape an HTTP caller sends: `type: dataset`, the optional
    /// fields omitted. It must parse into the variant with every field intact,
    /// and serialise back under the same tag.
    #[test]
    fn dataset_evidence_parses_from_wire_json_and_keeps_its_tag() {
        let wire = serde_json::json!({
            "type": "dataset",
            "root_uri": "file:///data/run-0042",
            "manifest_hash": format!("sha256:{SHA256_HEX}"),
            "hash_algorithm": "sha256",
            "file_count": 3,
            "total_bytes": 4096
        });
        let parsed: EvidenceType = serde_json::from_value(wire).expect("dataset JSON must parse");
        assert_eq!(
            parsed,
            EvidenceType::Dataset {
                root_uri: "file:///data/run-0042".to_string(),
                manifest_uri: None,
                manifest_blob_id: None,
                manifest_hash: format!("sha256:{SHA256_HEX}"),
                hash_algorithm: "sha256".to_string(),
                file_count: 3,
                total_bytes: 4096,
                sample_id: None,
                blob_ids: vec![],
                attestation: None,
            }
        );
        assert_eq!(parsed.validate(), Ok(()));
        assert_eq!(parsed.stored_type(), "dataset");
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(back["type"], "dataset");
        assert_eq!(back["manifest_hash"], format!("sha256:{SHA256_HEX}"));
        assert_eq!(back["total_bytes"], 4096);
    }

    #[test]
    fn dataset_builder_normalises_the_digest() {
        // Upper-case prefixed digest: lower-cased, algorithm read off the prefix.
        let mut input = dataset_input();
        input.manifest_hash = format!("  BLAKE3:{}  ", B3_HEX.to_ascii_uppercase());
        let EvidenceType::Dataset {
            manifest_hash,
            hash_algorithm,
            ..
        } = EvidenceType::dataset(input).unwrap()
        else {
            panic!("dataset() must build a Dataset");
        };
        assert_eq!(manifest_hash, format!("blake3:{B3_HEX}"));
        assert_eq!(hash_algorithm, "blake3");

        // Bare hex with the algorithm named separately: the prefix is added.
        let mut input = dataset_input();
        input.manifest_hash = SHA256_HEX.to_string();
        input.hash_algorithm = Some("SHA256".to_string());
        let EvidenceType::Dataset {
            manifest_hash,
            hash_algorithm,
            ..
        } = EvidenceType::dataset(input).unwrap()
        else {
            panic!("dataset() must build a Dataset");
        };
        assert_eq!(manifest_hash, format!("sha256:{SHA256_HEX}"));
        assert_eq!(hash_algorithm, "sha256");
    }

    #[test]
    fn dataset_builder_refuses_a_digest_a_reader_could_not_check() {
        // A prefix that disagrees with the named algorithm.
        let mut i = dataset_input();
        i.hash_algorithm = Some("sha256".to_string());
        assert_eq!(dataset_error_field(i), "hash_algorithm");
        // An algorithm outside the list.
        let mut i = dataset_input();
        i.manifest_hash = format!("md5:{}", &B3_HEX[..32]);
        assert_eq!(dataset_error_field(i), "hash_algorithm");
        // No algorithm anywhere.
        let mut i = dataset_input();
        i.manifest_hash = B3_HEX.to_string();
        assert_eq!(dataset_error_field(i), "manifest_hash");
        // The wrong length for the algorithm (a sha256-length digest named sha512).
        let mut i = dataset_input();
        i.manifest_hash = format!("sha512:{SHA256_HEX}");
        assert_eq!(dataset_error_field(i), "manifest_hash");
        // Not hex.
        let mut i = dataset_input();
        i.manifest_hash = format!("blake3:{}zz", &B3_HEX[..62]);
        assert_eq!(dataset_error_field(i), "manifest_hash");
    }

    #[test]
    fn dataset_builder_refuses_unbounded_or_empty_text() {
        let mut i = dataset_input();
        i.root_uri = "   ".to_string();
        assert_eq!(dataset_error_field(i), "root_uri");
        let mut i = dataset_input();
        i.root_uri = format!("s3://{}", "x".repeat(MAX_DATASET_URI_LEN));
        assert_eq!(dataset_error_field(i), "root_uri");
        let mut i = dataset_input();
        i.blob_ids = vec!["b".to_string(); MAX_DATASET_BLOB_IDS + 1];
        assert_eq!(dataset_error_field(i), "blob_ids");
        let mut i = dataset_input();
        i.blob_ids = vec![String::new()];
        assert_eq!(dataset_error_field(i), "blob_ids");
        // An empty optional is dropped, not refused.
        let mut i = dataset_input();
        i.manifest_uri = Some("  ".to_string());
        let EvidenceType::Dataset { manifest_uri, .. } = EvidenceType::dataset(i).unwrap() else {
            panic!("dataset() must build a Dataset");
        };
        assert_eq!(manifest_uri, None);
    }

    /// `validate` is what the HTTP route runs on a body that was deserialised
    /// straight into the variant: it must refuse a value the builder would
    /// have normalised (upper-case hex), so a stored digest is always in the
    /// one form a reader compares against.
    #[test]
    fn validate_refuses_a_deserialised_dataset_in_non_canonical_form() {
        let wire = serde_json::json!({
            "type": "dataset",
            "root_uri": "file:///data/run",
            "manifest_hash": format!("blake3:{}", B3_HEX.to_ascii_uppercase()),
            "hash_algorithm": "blake3",
            "file_count": 1,
            "total_bytes": 1
        });
        let parsed: EvidenceType = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.validate().unwrap_err().field, "manifest_hash");
        // Every other variant has no invariant of its own.
        assert_eq!(
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            }
            .validate(),
            Ok(())
        );
    }

    /// The field set and order of the canonical evidence form the in-memory
    /// `ContentAddressable` impl used to hash (deleted with that impl, backlog
    /// 8c6fc756). Kept as a test-local struct so the two digest pins below
    /// still guard `EvidenceType`'s serde shape. Canonical JSON sorts keys and
    /// carries no type name, so the digests are unchanged by the move.
    #[derive(Serialize)]
    struct CanonicalEvidenceForm {
        id: EvidenceId,
        agent_id: AgentId,
        evidence_type: EvidenceType,
        raw_content: Option<String>,
        claim_id: ClaimId,
        created_at: DateTime<Utc>,
    }

    fn fixed_hashable(evidence_type: EvidenceType) -> CanonicalEvidenceForm {
        CanonicalEvidenceForm {
            id: EvidenceId::from_uuid(uuid::Uuid::from_u128(1)),
            agent_id: AgentId::from_uuid(uuid::Uuid::from_u128(2)),
            evidence_type,
            raw_content: Some("fixed body".to_string()),
            claim_id: ClaimId::from_uuid(uuid::Uuid::from_u128(3)),
            created_at: DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    /// Serialisation stability of the canonical evidence form
    /// (`CanonicalEvidenceForm` above): adding the Dataset
    /// variant must not move it for a row of an EXISTING variant. The digest
    /// is pinned to the value the pre-Dataset code computes for the same
    /// fixed row. No STORED signature covers this form (writers sign
    /// `content_hash = BLAKE3(raw_content)`, which this batch does not
    /// touch), so this guards the serde shape, not a stored signature.
    #[test]
    fn existing_variant_canonical_digest_is_unchanged() {
        let doc = fixed_hashable(EvidenceType::Document {
            source_url: Some("https://example.org/a.pdf".to_string()),
            mime_type: "application/pdf".to_string(),
            checksum: None,
        });
        let digest = epigraph_crypto::ContentHasher::hash_canonical(&doc).unwrap();
        assert_eq!(
            hex::encode(digest),
            "e2d0d1f23ab0a65fd695a53ee9df5830d0bd6aa53b6c6d53eef16fd0bcfdde2b"
        );
    }

    /// The Dataset variant's serialised form inside that in-memory canonical
    /// form, pinned, so a later rename or serde attribute change on it is
    /// caught. Also shows that an absent `attestation` is not serialised (the
    /// value was pinned before the field existed). The stored binding of a
    /// dataset's fields is pinned separately, by
    /// `dataset_attestation_digest_is_pinned`.
    #[test]
    fn dataset_canonical_digest_is_pinned() {
        let ds = fixed_hashable(EvidenceType::dataset(dataset_input()).unwrap());
        let digest = epigraph_crypto::ContentHasher::hash_canonical(&ds).unwrap();
        assert_eq!(
            hex::encode(digest),
            "9d8c3a769df35dda7a1018f31178b43d7c6856080026b0dbee3801f9ec09f5e9"
        );
    }

    // ============ Dataset attestation (backlog c8beb101, review finding 1) ============

    fn attestation_ids() -> (EvidenceId, ClaimId) {
        (
            EvidenceId::from_uuid(uuid::Uuid::from_u128(0x11)),
            ClaimId::from_uuid(uuid::Uuid::from_u128(0x22)),
        )
    }

    fn attested_dataset(signer: &AgentSigner) -> EvidenceType {
        let (e, c) = attestation_ids();
        let mut ds = EvidenceType::dataset(dataset_input()).unwrap();
        assert!(ds.attest_dataset(e, c, signer));
        ds
    }

    /// The byte layout a verifier in another language reproduces, pinned
    /// twice: as the explicit bytes, and as their BLAKE3. Moving a field,
    /// dropping one, or changing an encoding orphans every stored attestation.
    #[test]
    fn dataset_attestation_digest_is_pinned() {
        let (e, c) = attestation_ids();
        let ds = EvidenceType::dataset(dataset_input()).unwrap();

        let mut want = b"epigraph-dataset-attestation-v1\0".to_vec();
        want.extend_from_slice(&0x11u128.to_be_bytes());
        want.extend_from_slice(&0x22u128.to_be_bytes());
        let field = |buf: &mut Vec<u8>, v: &str| {
            buf.extend_from_slice(&u32::try_from(v.len()).unwrap().to_be_bytes());
            buf.extend_from_slice(v.as_bytes());
        };
        field(&mut want, "s3://lab-runs/campaign-7/run-0042/");
        want.push(1);
        field(&mut want, "s3://lab-runs/campaign-7/run-0042/MANIFEST.b3");
        want.push(0); // manifest_blob_id absent
        field(&mut want, &format!("blake3:{B3_HEX}"));
        field(&mut want, "blake3");
        want.extend_from_slice(&1_204u64.to_be_bytes());
        want.extend_from_slice(&73_014_444_032u64.to_be_bytes());
        want.push(1);
        field(&mut want, "sample-17");
        want.extend_from_slice(&0u32.to_be_bytes()); // no blob ids

        let digest = ds.dataset_attestation_digest(e, c).unwrap();
        assert_eq!(digest, epigraph_crypto::ContentHasher::hash(&want));
        assert_eq!(
            hex::encode(digest),
            "fddcab06eee69762021e4f6e9499c4315ec770448aab11c92ac27867407d5e0e"
        );
        // The attestation is not part of what it signs.
        let signer = AgentSigner::from_bytes(&[7; 32]).unwrap();
        assert_eq!(
            attested_dataset(&signer).dataset_attestation_digest(e, c),
            Some(digest)
        );
        // No other variant has one.
        let doc = EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        };
        assert_eq!(doc.dataset_attestation_digest(e, c), None);
    }

    /// The review's tamper scenario: an edit to any signed field, or a valid
    /// dataset plus attestation copied onto another row or claim, must not
    /// verify. The converse (the untouched row verifies) keeps "never
    /// verifies" from passing.
    #[test]
    fn dataset_attestation_verifies_and_catches_tamper_and_transplant() {
        let signer = AgentSigner::from_bytes(&[7; 32]).unwrap();
        let pk = signer.public_key();
        let (e, c) = attestation_ids();
        let ds = attested_dataset(&signer);
        assert_eq!(ds.verify_dataset_attestation(e, c, &pk), Some(true));

        type Edit = fn(&mut EvidenceType);
        let edits: [(&str, Edit); 9] = [
            ("root_uri", |d| {
                if let EvidenceType::Dataset { root_uri, .. } = d {
                    root_uri.push('x');
                }
            }),
            ("manifest_uri", |d| {
                if let EvidenceType::Dataset { manifest_uri, .. } = d {
                    *manifest_uri = None;
                }
            }),
            ("manifest_blob_id", |d| {
                if let EvidenceType::Dataset {
                    manifest_blob_id, ..
                } = d
                {
                    *manifest_blob_id = Some("blob-1".to_string());
                }
            }),
            ("manifest_hash", |d| {
                if let EvidenceType::Dataset { manifest_hash, .. } = d {
                    *manifest_hash = format!("blake3:{}", "0".repeat(64));
                }
            }),
            ("hash_algorithm", |d| {
                if let EvidenceType::Dataset { hash_algorithm, .. } = d {
                    *hash_algorithm = "sha256".to_string();
                }
            }),
            ("file_count", |d| {
                if let EvidenceType::Dataset { file_count, .. } = d {
                    *file_count += 1;
                }
            }),
            ("total_bytes", |d| {
                if let EvidenceType::Dataset { total_bytes, .. } = d {
                    *total_bytes -= 1;
                }
            }),
            ("sample_id", |d| {
                if let EvidenceType::Dataset { sample_id, .. } = d {
                    *sample_id = None;
                }
            }),
            ("blob_ids", |d| {
                if let EvidenceType::Dataset { blob_ids, .. } = d {
                    blob_ids.push("blob-2".to_string());
                }
            }),
        ];
        for (field, edit) in edits {
            let mut tampered = ds.clone();
            edit(&mut tampered);
            assert_ne!(tampered, ds, "{field}: the edit must change the row");
            assert_eq!(
                tampered.verify_dataset_attestation(e, c, &pk),
                Some(false),
                "an edited {field} still verified"
            );
        }

        // Transplant: the same fields and attestation on another row or claim.
        let other_e = EvidenceId::from_uuid(uuid::Uuid::from_u128(0x33));
        let other_c = ClaimId::from_uuid(uuid::Uuid::from_u128(0x44));
        assert_eq!(ds.verify_dataset_attestation(other_e, c, &pk), Some(false));
        assert_eq!(ds.verify_dataset_attestation(e, other_c, &pk), Some(false));

        // Another key.
        let stranger = AgentSigner::from_bytes(&[8; 32]).unwrap();
        assert_eq!(
            ds.verify_dataset_attestation(e, c, &stranger.public_key()),
            Some(false)
        );

        // A signature over the right digest under another kind, or the bare
        // digest (legacy), binds no dataset and must not verify.
        let digest = ds.dataset_attestation_digest(e, c).unwrap();
        for sig in [
            signer.sign_entity(epigraph_crypto::SignedEntity::Evidence, &digest),
            signer.sign(&digest),
        ] {
            let mut forged = ds.clone();
            if let EvidenceType::Dataset {
                attestation: Some(a),
                ..
            } = &mut forged
            {
                a.signature = hex::encode(sig);
            }
            assert_eq!(forged.verify_dataset_attestation(e, c, &pk), Some(false));
        }

        // Malformed or unknown-scheme attestations are refusals, not panics.
        for mangle in [
            |a: &mut DatasetAttestation| a.signature = "zz".to_string(),
            |a: &mut DatasetAttestation| a.signature.truncate(10),
            |a: &mut DatasetAttestation| a.scheme = "v2".to_string(),
        ] {
            let mut bad = ds.clone();
            if let EvidenceType::Dataset {
                attestation: Some(a),
                ..
            } = &mut bad
            {
                mangle(a);
            }
            assert_eq!(bad.verify_dataset_attestation(e, c, &pk), Some(false));
        }

        // Nothing to check: no attestation, or not a dataset.
        let unsigned = EvidenceType::dataset(dataset_input()).unwrap();
        assert_eq!(unsigned.verify_dataset_attestation(e, c, &pk), None);
        let mut doc = EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        };
        assert!(!doc.attest_dataset(e, c, &signer));
        assert_eq!(doc.verify_dataset_attestation(e, c, &pk), None);
    }

    /// The attestation survives the JSONB round trip the row's `properties`
    /// take, and still verifies after it.
    #[test]
    fn dataset_attestation_round_trips_through_json() {
        let signer = AgentSigner::from_bytes(&[7; 32]).unwrap();
        let (e, c) = attestation_ids();
        let ds = attested_dataset(&signer);
        let json = serde_json::to_value(&ds).unwrap();
        assert_eq!(json["attestation"]["scheme"], "v1");
        assert_eq!(
            json["attestation"]["signature"].as_str().unwrap().len(),
            128
        );
        let back: EvidenceType = serde_json::from_value(json).unwrap();
        assert_eq!(back, ds);
        assert_eq!(
            back.verify_dataset_attestation(e, c, &signer.public_key()),
            Some(true)
        );
        // Absent: not serialised at all.
        let unsigned =
            serde_json::to_value(EvidenceType::dataset(dataset_input()).unwrap()).unwrap();
        assert!(unsigned.get("attestation").is_none());
    }
}
