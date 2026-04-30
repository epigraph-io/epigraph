//! Evidence domain model
//!
//! Evidence represents supporting material for claims. All evidence must be:
//! - Cryptographically signed by an agent
//! - Content-addressed (BLAKE3 hash)
//! - Typed (Document, Observation, Testimony, Literature, Consensus)

use super::ids::{AgentId, ClaimId, EvidenceId};
use crate::traits::{ContentAddressable, Signable, Verifiable};
use chrono::{DateTime, Utc};
use epigraph_crypto::SIGNATURE_SIZE;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

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
}
