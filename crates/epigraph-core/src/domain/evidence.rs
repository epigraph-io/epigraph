//! Evidence domain model
//!
//! Evidence represents supporting material for claims. All evidence must be:
//! - Cryptographically signed by an agent
//! - Content-addressed (BLAKE3 hash)
//! - Typed (Document, Observation, Testimony, Literature, Consensus, Figure,
//!   Dataset)

use super::ids::{AgentId, ClaimId, EvidenceId};
use crate::traits::{ContentAddressable, Signable, Verifiable};
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
    },
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

/// Content that is signed for Evidence
///
/// Excludes the signature field to avoid circular dependency.
/// Uses deterministic field ordering for canonical serialization.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceSignableContent {
    pub id: EvidenceId,
    pub agent_id: AgentId,
    pub content_hash: [u8; 32],
    pub evidence_type: EvidenceType,
    pub raw_content: Option<String>,
    pub claim_id: ClaimId,
    pub created_at: DateTime<Utc>,
}

/// Content that is hashed for Evidence
///
/// Excludes the `content_hash` and signature fields to avoid circular dependency.
/// Uses deterministic field ordering for canonical serialization.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceHashableContent {
    pub id: EvidenceId,
    pub agent_id: AgentId,
    pub evidence_type: EvidenceType,
    pub raw_content: Option<String>,
    pub claim_id: ClaimId,
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

// ==================== Trait Implementations ====================

impl Signable for Evidence {
    type SignableContent = EvidenceSignableContent;

    fn signable_content(&self) -> Self::SignableContent {
        EvidenceSignableContent {
            id: self.id,
            agent_id: self.agent_id,
            content_hash: self.content_hash,
            evidence_type: self.evidence_type.clone(),
            raw_content: self.raw_content.clone(),
            claim_id: self.claim_id,
            created_at: self.created_at,
        }
    }

    fn signature(&self) -> Option<&[u8; SIGNATURE_SIZE]> {
        self.signature.as_ref()
    }

    fn set_signature(&mut self, signature: [u8; SIGNATURE_SIZE]) {
        self.signature = Some(signature);
    }
}

impl Verifiable for Evidence {
    fn signer_public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl ContentAddressable for Evidence {
    fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    fn set_content_hash(&mut self, hash: [u8; 32]) {
        self.content_hash = hash;
    }

    fn compute_hash(&self) -> Result<[u8; 32], epigraph_crypto::CryptoError> {
        let hashable = EvidenceHashableContent {
            id: self.id,
            agent_id: self.agent_id,
            evidence_type: self.evidence_type.clone(),
            raw_content: self.raw_content.clone(),
            claim_id: self.claim_id,
            created_at: self.created_at,
        };
        epigraph_crypto::ContentHasher::hash_canonical(&hashable)
    }
}

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

    // ==================== Signable Trait Tests ====================

    #[test]
    fn evidence_sign_and_verify() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: Some("https://example.com/doc.pdf".to_string()),
                mime_type: "application/pdf".to_string(),
                checksum: None,
            },
            Some("test content".to_string()),
            claim_id,
        );

        assert!(evidence.signature().is_none());

        // Sign the evidence
        evidence.sign(&signer).expect("signing should succeed");

        assert!(evidence.signature().is_some());

        // Verify the signature
        let is_valid = evidence.verify().expect("verification should succeed");
        assert!(is_valid, "Valid signature should verify");
    }

    #[test]
    fn evidence_verify_fails_with_wrong_public_key() {
        let signer1 = AgentSigner::generate();
        let signer2 = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer2.public_key(), // Wrong public key
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            None,
            claim_id,
        );

        // Sign with signer1 but evidence has signer2's public key
        evidence.sign(&signer1).expect("signing should succeed");

        let is_valid = evidence.verify().expect("verification should complete");
        assert!(!is_valid, "Wrong public key should fail verification");
    }

    #[test]
    fn evidence_verify_fails_with_tampered_content() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            Some("original content".to_string()),
            claim_id,
        );

        evidence.sign(&signer).expect("signing should succeed");

        // Tamper with the content
        evidence.raw_content = Some("tampered content".to_string());

        let is_valid = evidence.verify().expect("verification should complete");
        assert!(!is_valid, "Tampered content should fail verification");
    }

    #[test]
    fn evidence_verify_missing_signature_returns_error() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            None,
            claim_id,
        );

        // Attempt to verify without signature
        let result = evidence.verify();
        assert!(result.is_err(), "Missing signature should return error");
    }

    // ==================== ContentAddressable Trait Tests ====================

    #[test]
    fn evidence_content_hash_compute_and_verify() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32], // Initial zero hash
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            Some("content to hash".to_string()),
            claim_id,
        );

        // Update the hash
        evidence.update_hash().expect("hash update should succeed");

        assert_ne!(
            evidence.content_hash(),
            &[0u8; 32],
            "Hash should be updated from zero"
        );

        // Verify the hash
        let is_valid = evidence
            .verify_hash()
            .expect("hash verification should succeed");
        assert!(is_valid, "Hash should verify after update");
    }

    #[test]
    fn evidence_hash_changes_with_content() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence1 = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            Some("content one".to_string()),
            claim_id,
        );

        let mut evidence2 = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            Some("content two".to_string()),
            claim_id,
        );

        evidence1.update_hash().unwrap();
        evidence2.update_hash().unwrap();

        assert_ne!(
            evidence1.content_hash(),
            evidence2.content_hash(),
            "Different content should produce different hashes"
        );
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

    #[test]
    fn figure_evidence_sign_and_verify() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Figure {
                doi: "10.1000/sig".to_string(),
                figure_id: None,
                caption: Some("Test figure".to_string()),
                mime_type: "image/png".to_string(),
                page: None,
            },
            Some("base64-png-data".to_string()),
            claim_id,
        );

        evidence.sign(&signer).expect("signing should succeed");
        let is_valid = evidence.verify().expect("verification should succeed");
        assert!(is_valid, "Figure evidence signature should verify");
    }

    #[test]
    fn figure_evidence_content_hash() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Figure {
                doi: "10.1000/hash".to_string(),
                figure_id: Some("Figure 3".to_string()),
                caption: Some("XPS spectrum".to_string()),
                mime_type: "image/png".to_string(),
                page: Some(15),
            },
            Some("iVBORw0KGgoAAAANS...".to_string()),
            claim_id,
        );

        evidence.update_hash().expect("hash update should succeed");
        assert_ne!(evidence.content_hash(), &[0u8; 32]);

        let is_valid = evidence
            .verify_hash()
            .expect("hash verification should succeed");
        assert!(is_valid, "Figure evidence hash should verify");
    }

    #[test]
    fn evidence_hash_detects_tampering() {
        let signer = AgentSigner::generate();
        let agent_id = AgentId::new();
        let claim_id = ClaimId::new();

        let mut evidence = Evidence::new(
            agent_id,
            signer.public_key(),
            [0u8; 32],
            EvidenceType::Document {
                source_url: None,
                mime_type: "text/plain".to_string(),
                checksum: None,
            },
            Some("original".to_string()),
            claim_id,
        );

        evidence.update_hash().unwrap();

        // Tamper with content
        evidence.raw_content = Some("tampered".to_string());

        let is_valid = evidence.verify_hash().unwrap();
        assert!(!is_valid, "Tampered content should fail hash verification");
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

    /// A dataset row signs and verifies through `Signable` like every other
    /// variant, and the signature covers its structured fields: changing the
    /// manifest digest or the file count after signing breaks verification.
    #[test]
    fn dataset_evidence_sign_verify_and_tamper() {
        let signer = AgentSigner::generate();
        let mut evidence = Evidence::new(
            AgentId::new(),
            signer.public_key(),
            [0u8; 32],
            EvidenceType::dataset(dataset_input()).unwrap(),
            Some("run 42 of campaign 7".to_string()),
            ClaimId::new(),
        );
        evidence.update_hash().unwrap();
        evidence.sign(&signer).unwrap();
        assert!(
            evidence.verify().unwrap(),
            "a signed dataset row must verify"
        );
        assert!(evidence.verify_hash().unwrap());

        let mut tampered = evidence.clone();
        if let EvidenceType::Dataset { manifest_hash, .. } = &mut tampered.evidence_type {
            *manifest_hash = format!("blake3:{}", "0".repeat(64));
        }
        assert!(
            !tampered.verify().unwrap(),
            "a changed manifest digest must not verify"
        );
        assert!(!tampered.verify_hash().unwrap());

        let mut tampered = evidence;
        if let EvidenceType::Dataset { file_count, .. } = &mut tampered.evidence_type {
            *file_count += 1;
        }
        assert!(
            !tampered.verify().unwrap(),
            "a changed file count must not verify"
        );
    }

    fn fixed_hashable(evidence_type: EvidenceType) -> EvidenceHashableContent {
        EvidenceHashableContent {
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

    /// Canonicalisation stability: adding the Dataset variant must not move
    /// the canonical digest of a row of an EXISTING variant, or every stored
    /// signature over one would stop verifying. The digest is pinned to the
    /// value the pre-Dataset code computes for the same fixed row.
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

    /// The Dataset variant's own canonical form, pinned, so a later rename or
    /// a serde attribute change on it is caught before it orphans the
    /// signatures over stored dataset rows.
    #[test]
    fn dataset_canonical_digest_is_pinned() {
        let ds = fixed_hashable(EvidenceType::dataset(dataset_input()).unwrap());
        let digest = epigraph_crypto::ContentHasher::hash_canonical(&ds).unwrap();
        assert_eq!(
            hex::encode(digest),
            "9d8c3a769df35dda7a1018f31178b43d7c6856080026b0dbee3801f9ec09f5e9"
        );
    }
}
