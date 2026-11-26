//! Literature Ingestion CLI
//!
//! Reads a JSON file of literature extractions and submits them as
//! epistemic packets to the EpiGraph API. Each extracted claim becomes
//! a signed Knowledge Packet with Literature evidence and Extraction
//! methodology.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin ingest_literature -- \
//!   --input fixtures/sample_claims.json \
//!   --endpoint http://localhost:8080 \
//!   --agent-key <base64-encoded-32-byte-secret>
//! ```
//!
//! # Licence gate (backlog 1a462cc1)
//!
//! A claim's `supporting_text` (and a figure's image and caption) is
//! publisher text. It is shipped verbatim only when `source.licence` permits
//! retention (`epigraph_ingest::common::licence::passage_retention_permitted`,
//! the same allowlist as the document-ingest path). Under any other licence,
//! or none, the passage evidence carries the citation, a locator (page and
//! section) and the passage's BLAKE3 hash instead, and figures are not
//! attached; the run prints what it withheld. `--allow-verbatim` is the
//! operator override for a source the operator has the right to republish.
//!
//! The server applies the same rule against the paper's RECORDED licence
//! (`papers.licence`, migration 349, backlog b62ae3f2), not the extraction's:
//! a packet carrying a verbatim passage or a figure for a DOI whose paper row
//! has no permitting licence (or no row at all) is refused with a 400, with
//! or without `--allow-verbatim`. Record the licence first, through the
//! operator definer `epigraph_set_paper_licence` (migration 255).
//!
//! # Input Format
//!
//! ```json
//! {
//!   "source": {
//!     "doi": "10.1000/example",
//!     "title": "Example Paper",
//!     "authors": ["Author One"],
//!     "journal": "Nature",
//!     "licence": "CC-BY-4.0"
//!   },
//!   "claims": [
//!     {
//!       "statement": "Water boils at 100°C at sea level",
//!       "page": 42,
//!       "section": "Results",
//!       "confidence": 0.9,
//!       "supporting_text": "Our measurements confirm..."
//!     }
//!   ],
//!   "extraction_metadata": {
//!     "extractor_version": "1.0.0",
//!     "model_used": "gpt-4"
//!   }
//! }
//! ```

use epigraph_crypto::{AgentSigner, ContentHasher, SignedEntity};
use epigraph_ingest::common::licence::passage_retention_permitted;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

/// Simple CLI argument parsing (no clap dependency needed)
struct Args {
    /// Path to JSON file with literature extractions
    input: PathBuf,
    /// API endpoint base URL
    endpoint: String,
    /// Agent private key (base64-encoded 32 bytes), or "generate" for a new key
    agent_key: String,
    /// Dry run mode - validate and show packets without submitting
    dry_run: bool,
    /// Ship verbatim passages and figures whatever `source.licence` says
    /// (operator override of the licence gate)
    allow_verbatim: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();

        let mut input = None;
        let mut endpoint = "http://localhost:8080".to_string();
        let mut agent_key = "generate".to_string();
        let mut dry_run = false;
        let mut allow_verbatim = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--input" | "-i" => {
                    i += 1;
                    input = Some(PathBuf::from(
                        args.get(i).ok_or("--input requires a path argument")?,
                    ));
                }
                "--endpoint" | "-e" => {
                    i += 1;
                    endpoint = args
                        .get(i)
                        .ok_or("--endpoint requires a URL argument")?
                        .clone();
                }
                "--agent-key" | "-k" => {
                    i += 1;
                    agent_key = args
                        .get(i)
                        .ok_or("--agent-key requires a base64 key or 'generate'")?
                        .clone();
                }
                "--dry-run" | "-n" => {
                    dry_run = true;
                }
                "--allow-verbatim" => {
                    allow_verbatim = true;
                }
                "--help" | "-h" => {
                    return Err(USAGE.to_string());
                }
                other => {
                    return Err(format!("Unknown argument: {other}\n{USAGE}"));
                }
            }
            i += 1;
        }

        let input = input.ok_or(format!("--input is required\n{USAGE}"))?;

        Ok(Self {
            input,
            endpoint,
            agent_key,
            dry_run,
            allow_verbatim,
        })
    }
}

const USAGE: &str = "\
Usage: ingest_literature [OPTIONS] --input <FILE>

Options:
  -i, --input <FILE>       Path to JSON file with literature extractions (required)
  -e, --endpoint <URL>     API endpoint [default: http://localhost:8080]
  -k, --agent-key <KEY>    Base64-encoded 32-byte agent key, or 'generate' [default: generate]
  -n, --dry-run            Validate and show packets without submitting
      --allow-verbatim     Ship supporting passages and figures verbatim even when
                           source.licence does not permit retention (operator override;
                           the server still refuses them unless the paper's recorded
                           licence permits retention)
  -h, --help               Show this help message";

/// Maximum allowed input file size (100 MB). Prevents OOM from malicious or
/// oversized files being read entirely into memory via `read_to_string`.
const MAX_INPUT_FILE_SIZE: u64 = 100 * 1024 * 1024;

// =============================================================================
// LITERATURE EXTRACTION TYPES
// =============================================================================

/// Root structure of the literature extraction JSON file
#[derive(Debug, Deserialize)]
struct LiteratureExtraction {
    source: LiteratureSource,
    claims: Vec<ExtractedClaim>,
    #[serde(default)]
    figures: Vec<ExtractedFigure>,
    #[serde(default)]
    provenance: ProvenanceBlock,
    #[serde(default)]
    #[allow(dead_code)]
    extraction_metadata: ExtractionMetadata,
}

/// Bibliographic source information (supports both simple and enriched authors)
#[derive(Debug, Deserialize)]
struct LiteratureSource {
    doi: String,
    title: String,
    authors: Vec<AuthorEntry>,
    #[allow(dead_code)]
    journal: Option<String>,
    /// The source's licence (an SPDX id such as `CC-BY-4.0`). Decides whether
    /// supporting passages and figures may be shipped verbatim; absent means
    /// unknown, which withholds them. `license` (US spelling) is read too, so
    /// a producer that spells it that way is not silently treated as unknown.
    #[serde(default, alias = "license")]
    licence: Option<String>,
}

/// Author entry — backward-compatible with plain strings or enriched objects
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum AuthorEntry {
    Simple(String),
    Detailed(AuthorInfo),
}

impl AuthorEntry {
    fn name(&self) -> &str {
        match self {
            AuthorEntry::Simple(s) => s,
            AuthorEntry::Detailed(info) => &info.name,
        }
    }

    fn affiliations(&self) -> &[String] {
        match self {
            AuthorEntry::Simple(_) => &[],
            AuthorEntry::Detailed(info) => &info.affiliations,
        }
    }

    fn roles(&self) -> &[String] {
        match self {
            AuthorEntry::Simple(_) => &[],
            AuthorEntry::Detailed(info) => &info.roles,
        }
    }
}

/// Enriched author with affiliations and roles
#[derive(Debug, Clone, Deserialize)]
struct AuthorInfo {
    name: String,
    #[serde(default)]
    affiliations: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// Paper-level provenance metadata (all fields default to empty)
#[derive(Debug, Default, Deserialize)]
struct ProvenanceBlock {
    #[serde(default)]
    instruments: Vec<InstrumentInfo>,
    #[serde(default)]
    reagents: Vec<ReagentInfo>,
    #[serde(default)]
    experimental_conditions: Vec<ExperimentalCondition>,
    #[serde(default)]
    computational_methods: Vec<ComputationalMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstrumentInfo {
    name: String,
    #[serde(default)]
    abbreviation: String,
    #[serde(default)]
    conditions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReagentInfo {
    name: String,
    #[serde(default)]
    abbreviation: String,
    #[serde(default)]
    formula: String,
    #[serde(default)]
    role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentalCondition {
    parameter: String,
    value: String,
    #[serde(default)]
    context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComputationalMethod {
    method: String,
    #[serde(default)]
    software: String,
    #[serde(default)]
    functional: String,
    #[serde(default)]
    basis_set: String,
}

/// A single claim extracted from the literature
#[derive(Debug, Deserialize)]
struct ExtractedClaim {
    statement: String,
    page: Option<u32>,
    #[allow(dead_code)]
    section: Option<String>,
    confidence: f64,
    supporting_text: String,
    #[serde(default)]
    methodology: Option<String>,
    #[serde(default)]
    instruments_used: Vec<String>,
    #[serde(default)]
    reagents_involved: Vec<String>,
    #[serde(default)]
    conditions: Vec<String>,
}

/// A figure extracted from the PDF
#[derive(Debug, Deserialize)]
struct ExtractedFigure {
    page: Option<u32>,
    figure_id: Option<String>,
    caption: Option<String>,
    #[serde(default)]
    image_base64: Option<String>,
    #[allow(dead_code)]
    width: Option<f64>,
    #[allow(dead_code)]
    height: Option<f64>,
}

/// Metadata about the extraction process
#[derive(Debug, Default, Deserialize)]
struct ExtractionMetadata {
    #[serde(default = "default_version")]
    #[allow(dead_code)]
    extractor_version: String,
    #[allow(dead_code)]
    model_used: Option<String>,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

// =============================================================================
// API SUBMISSION TYPES (mirrors submit.rs)
// =============================================================================

#[derive(Debug, Serialize)]
struct EpistemicPacket {
    claim: ClaimSubmission,
    evidence: Vec<EvidenceSubmission>,
    reasoning_trace: ReasoningTraceSubmission,
    signature: String,
}

/// The server's `routes::submit::ClaimSubmission` in the shape the server
/// RE-serializes it, because the packet signature covers the server's
/// canonical bytes (`EpistemicPacket::signable_bytes`): `idempotency_key`,
/// `properties` (`null`) and `labels` (`[]`) are always present, as the
/// server writes them; an absent `initial_truth` is skipped (the server
/// refuses `null`).
#[derive(Debug, Serialize)]
struct ClaimSubmission {
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_truth: Option<f64>,
    agent_id: Uuid,
    idempotency_key: Option<String>,
    properties: Option<serde_json::Value>,
    labels: Vec<String>,
}

/// The bytes the submit route verifies a packet signature over: the canonical
/// JSON of `(claim, evidence, reasoning_trace)`, signature excluded, as the
/// server's `EpistemicPacket::signable_bytes` builds them.
#[derive(Serialize)]
struct PacketSignable<'a> {
    claim: &'a ClaimSubmission,
    evidence: &'a [EvidenceSubmission],
    reasoning_trace: &'a ReasoningTraceSubmission,
}

/// The packet signature: raw Ed25519 by the claim's agent over
/// [`PacketSignable`], which the server checks when
/// `EPIGRAPH_REQUIRE_SIGNATURES` is on.
fn packet_signature(
    signer: &AgentSigner,
    claim: &ClaimSubmission,
    evidence: &[EvidenceSubmission],
    reasoning_trace: &ReasoningTraceSubmission,
) -> String {
    // Canonicalize the packet as the server will PARSE it (JSON text read
    // back), so each float is the f64 the server derives from the request.
    let wire = serde_json::to_vec(&PacketSignable {
        claim,
        evidence,
        reasoning_trace,
    })
    .expect("a packet of strings, numbers and JSON values always serializes");
    let as_parsed: serde_json::Value =
        serde_json::from_slice(&wire).expect("serde_json reads back its own output");
    let canonical =
        epigraph_crypto::to_canonical_bytes(&as_parsed).expect("a JSON value always serializes");
    hex::encode(signer.sign(&canonical))
}

#[derive(Debug, Serialize)]
struct EvidenceSubmission {
    content_hash: String,
    evidence_type: EvidenceTypeSubmission,
    raw_content: Option<String>,
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EvidenceTypeSubmission {
    Literature {
        doi: String,
        extraction_target: String,
    },
    Figure {
        doi: String,
        figure_id: Option<String>,
        caption: Option<String>,
        mime_type: String,
        page: Option<u32>,
    },
}

#[derive(Debug, Serialize)]
struct ReasoningTraceSubmission {
    methodology: String,
    inputs: Vec<TraceInputSubmission>,
    confidence: f64,
    explanation: String,
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TraceInputSubmission {
    Evidence { index: usize },
}

#[derive(Debug, Deserialize)]
struct SubmitResponse {
    claim_id: Uuid,
    truth_value: f64,
    #[allow(dead_code)]
    was_duplicate: bool,
}

/// Request body for POST /agents
#[derive(Debug, Serialize)]
struct CreateAgentRequest {
    public_key: String,
    display_name: Option<String>,
    /// `seed-derived` for a key computable from a public seed (the server then
    /// stores it as no verifier and provisions no OAuth client); omitted for a
    /// real signer, which the server takes as `ed25519`.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_kind: Option<&'static str>,
    /// With `key_kind`: the hex signature, under `public_key`, of
    /// `key_kind_declaration_message(key_kind, public_key)`, proving this
    /// caller holds the key it declares (the server refuses a declaration
    /// without it).
    #[serde(skip_serializing_if = "Option::is_none")]
    key_kind_proof: Option<String>,
}

/// Response from POST /agents
#[derive(Debug, Deserialize)]
struct AgentResponse {
    id: Uuid,
    #[allow(dead_code)]
    public_key: String,
}

/// Generate a deterministic Ed25519 signer from a seed string.
/// Uses BLAKE3(seed) as the 32-byte secret key, so the same seed always
/// produces the same keypair.
///
/// The seed is PUBLIC (`<doi>:<author name>`), so anyone can compute this
/// private key: it NAMES an author and must never sign a claim, evidence or
/// edge (backlog 57943a39). It leaves this file only through
/// [`author_agent_request`]: its public half, and the domain-separated
/// proof that declares it `seed-derived`.
fn deterministic_signer(seed: &str) -> AgentSigner {
    let hash = ContentHasher::hash(seed.as_bytes());
    let key_bytes: [u8; 32] = hash[..32].try_into().expect("BLAKE3 produces 32 bytes");
    AgentSigner::from_bytes(&key_bytes).expect("valid Ed25519 key from BLAKE3 output")
}

/// The POST /agents body for one author of the paper `doi`: the public half
/// of the deterministic `<doi>:<name>` key (so the same author of the same
/// paper is the same agent on every run), declared `seed-derived` because
/// its private half is computable by anyone, with the proof of possession
/// the server requires for that declaration. The server stores it so that no
/// verifier accepts the key and gives it no OAuth client.
fn author_agent_request(doi: &str, name: &str) -> CreateAgentRequest {
    let seed = format!("{doi}:{name}");
    let author = deterministic_signer(&seed);
    let public_key = author.public_key();
    let proof = author.sign(&epigraph_crypto::key_kind_declaration_message(
        "seed-derived",
        &public_key,
    ));
    CreateAgentRequest {
        public_key: hex::encode(public_key),
        display_name: Some(name.to_string()),
        key_kind: Some("seed-derived"),
        key_kind_proof: Some(hex::encode(proof)),
    }
}

/// Register an agent via the API. Returns the server-assigned agent ID.
async fn register_agent(
    client: &reqwest::Client,
    endpoint: &str,
    req: &CreateAgentRequest,
) -> Result<Uuid, String> {
    let url = format!("{endpoint}/agents");
    let resp = client
        .post(&url)
        .json(req)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Failed to register agent: {e}"))?;

    if resp.status().is_success() {
        let agent: AgentResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse agent response: {e}"))?;
        Ok(agent.id)
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Agent registration failed (HTTP {status}): {body}"))
    }
}

// =============================================================================
// PACKET BUILDER
// =============================================================================

/// Whether this run may ship the source's passages and figures verbatim: the
/// source's licence permits retention, or the operator passed
/// `--allow-verbatim`.
fn verbatim_permitted(source: &LiteratureSource, allow_verbatim: bool) -> bool {
    allow_verbatim || passage_retention_permitted(source.licence.as_deref())
}

/// The `raw_content` of a claim's passage evidence. Verbatim
/// `supporting_text` when `verbatim` holds; otherwise the citation, a locator
/// a reader holding the paper can follow, and the passage's BLAKE3 hash, worded
/// like the document-ingest writer's body (`literature_evidence_body`).
fn passage_evidence_body(
    source: &LiteratureSource,
    claim: &ExtractedClaim,
    verbatim: bool,
) -> String {
    if verbatim {
        return claim.supporting_text.clone();
    }
    let mut locator = claim
        .page
        .map_or_else(|| "full document".to_string(), |p| format!("page {p}"));
    if let Some(section) = &claim.section {
        locator.push_str(&format!(", section {section:?}"));
    }
    let passage_hash = hex::encode(ContentHasher::hash(claim.supporting_text.as_bytes()));
    let licence = source.licence.as_deref().map_or_else(
        || "licence unknown".to_string(),
        |l| format!("licence: {l}"),
    );
    format!(
        "Source: {} (DOI: {}). Locator: {locator}. Passage BLAKE3: {passage_hash}. \
         Passage not retained ({licence}).",
        source.title, source.doi
    )
}

/// What the licence gate kept out of a run's packets, for the operator log:
/// `None` when nothing was withheld.
fn withheld_summary(extraction: &LiteratureExtraction, allow_verbatim: bool) -> Option<String> {
    if verbatim_permitted(&extraction.source, allow_verbatim) {
        return None;
    }
    let figures = extraction
        .figures
        .iter()
        .filter(|f| f.image_base64.is_some())
        .count();
    Some(format!(
        "Licence gate ({}): withheld {} supporting passage(s) (stored as locator + BLAKE3 \
         hash) and {figures} figure(s). Pass --allow-verbatim only for a source you may \
         republish.",
        extraction
            .source
            .licence
            .as_deref()
            .unwrap_or("licence unknown"),
        extraction.claims.len(),
    ))
}

fn build_packets(
    extraction: &LiteratureExtraction,
    signer: &AgentSigner,
    agent_id: Uuid,
    allow_verbatim: bool,
) -> Vec<EpistemicPacket> {
    let verbatim = verbatim_permitted(&extraction.source, allow_verbatim);
    extraction
        .claims
        .iter()
        .map(|claim| {
            // Build literature text evidence (licence-gated, backlog 1a462cc1)
            let raw_content = passage_evidence_body(&extraction.source, claim, verbatim);
            let content_hash = ContentHasher::hash(raw_content.as_bytes());
            let content_hash_hex = hex::encode(content_hash);

            let evidence_signature =
                hex::encode(signer.sign_entity(SignedEntity::Evidence, &content_hash));

            let text_evidence = EvidenceSubmission {
                content_hash: content_hash_hex,
                evidence_type: EvidenceTypeSubmission::Literature {
                    doi: extraction.source.doi.clone(),
                    extraction_target: claim
                        .page
                        .map(|p| format!("Page {p}"))
                        .unwrap_or_else(|| "Full document".to_string()),
                },
                raw_content: Some(raw_content),
                signature: Some(evidence_signature),
            };

            let mut evidence_items = vec![text_evidence];

            // Find figures near this claim's page and create Figure evidence.
            // Uses ±2 page proximity: main text figures are often on adjacent pages.
            // Cap at 3 figures per claim to avoid bloating packets.
            // A figure's image and caption are publisher content too: under a
            // licence that does not permit retention none is attached.
            if let (true, Some(claim_page)) = (verbatim, claim.page) {
                let mut fig_count = 0u32;
                for fig in &extraction.figures {
                    if fig_count >= 3 {
                        break;
                    }
                    if let Some(fig_page) = fig.page {
                        let distance = (claim_page as i64 - fig_page as i64).unsigned_abs();
                        if distance <= 2 {
                            if let Some(ref image_data) = fig.image_base64 {
                                let fig_hash = ContentHasher::hash(image_data.as_bytes());
                                let fig_hash_hex = hex::encode(fig_hash);
                                let fig_signature = hex::encode(
                                    signer.sign_entity(SignedEntity::Evidence, &fig_hash),
                                );

                                evidence_items.push(EvidenceSubmission {
                                    content_hash: fig_hash_hex,
                                    evidence_type: EvidenceTypeSubmission::Figure {
                                        doi: extraction.source.doi.clone(),
                                        figure_id: fig.figure_id.clone(),
                                        caption: fig.caption.clone(),
                                        mime_type: "image/png".to_string(),
                                        page: fig.page,
                                    },
                                    raw_content: Some(image_data.clone()),
                                    signature: Some(fig_signature),
                                });
                                fig_count += 1;
                            }
                        }
                    }
                }
            }

            // Build trace inputs referencing all evidence
            let trace_inputs: Vec<TraceInputSubmission> = (0..evidence_items.len())
                .map(|i| TraceInputSubmission::Evidence { index: i })
                .collect();

            // Build reasoning trace with per-claim methodology if available
            let methodology = claim
                .methodology
                .as_deref()
                .unwrap_or("extraction")
                .to_string();

            let explanation = format!(
                "Extracted from '{}' (DOI: {}). Confidence: {:.0}%",
                extraction.source.title,
                extraction.source.doi,
                claim.confidence * 100.0,
            );

            let trace = ReasoningTraceSubmission {
                methodology,
                inputs: trace_inputs,
                confidence: claim.confidence,
                explanation,
                signature: None,
            };

            // Build claim
            let claim_submission = ClaimSubmission {
                content: claim.statement.clone(),
                initial_truth: None, // Let the engine calculate from evidence
                agent_id,
                idempotency_key: None,
                properties: None,
                labels: Vec::new(),
            };

            // Signed over the submit route's canonical bytes, so the packet
            // passes with EPIGRAPH_REQUIRE_SIGNATURES on.
            let packet_signature =
                packet_signature(signer, &claim_submission, &evidence_items, &trace);

            EpistemicPacket {
                claim: claim_submission,
                evidence: evidence_items,
                reasoning_trace: trace,
                signature: packet_signature,
            }
        })
        .collect()
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // Parse arguments
    let args = match Args::parse() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    // Check file size before reading to prevent OOM on oversized files
    match std::fs::metadata(&args.input) {
        Ok(meta) => {
            if meta.len() > MAX_INPUT_FILE_SIZE {
                eprintln!(
                    "Error: input file {} is {} bytes, exceeding the {} byte limit",
                    args.input.display(),
                    meta.len(),
                    MAX_INPUT_FILE_SIZE,
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error reading metadata for {}: {e}", args.input.display());
            std::process::exit(1);
        }
    }

    // Read input file
    let json = match std::fs::read_to_string(&args.input) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Error reading {}: {e}", args.input.display());
            std::process::exit(1);
        }
    };

    // Parse extractions
    let extraction: LiteratureExtraction = match serde_json::from_str(&json) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error parsing JSON: {e}");
            std::process::exit(1);
        }
    };

    let has_provenance = !extraction.provenance.instruments.is_empty()
        || !extraction.provenance.reagents.is_empty()
        || !extraction.provenance.experimental_conditions.is_empty()
        || !extraction.provenance.computational_methods.is_empty();

    println!(
        "Parsed {} claims, {} figures from '{}'{}",
        extraction.claims.len(),
        extraction.figures.len(),
        extraction.source.title,
        if has_provenance {
            " (enriched with provenance)"
        } else {
            ""
        },
    );

    // Show author info
    let author_count = extraction.source.authors.len();
    if author_count > 0 {
        let author_names: Vec<&str> = extraction.source.authors.iter().map(|a| a.name()).collect();
        println!("Authors ({author_count}): {}", author_names.join(", "));
    }

    // Create or load agent signer
    let signer = if args.agent_key == "generate" {
        let signer = AgentSigner::generate();
        println!(
            "Generated agent key (public): {}",
            hex::encode(signer.public_key())
        );
        signer
    } else {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let key_bytes: Vec<u8> = match STANDARD.decode(&args.agent_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Invalid base64 agent key: {e}");
                std::process::exit(1);
            }
        };
        let key_array: [u8; 32] = match key_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!("Agent key must be exactly 32 bytes (got different length)");
                std::process::exit(1);
            }
        };
        match AgentSigner::from_bytes(&key_array) {
            Ok(signer) => signer,
            Err(e) => {
                eprintln!("Invalid agent key: {e}");
                std::process::exit(1);
            }
        }
    };

    // Build a reqwest client with optional Bearer token from EPIGRAPH_TOKEN env var
    let auth_client = {
        let mut builder = reqwest::Client::builder();
        if let Ok(token) = std::env::var("EPIGRAPH_TOKEN") {
            let mut headers = reqwest::header::HeaderMap::new();
            let header_val = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("token must be ASCII");
            headers.insert(reqwest::header::AUTHORIZATION, header_val);
            builder = builder.default_headers(headers);
        }
        builder.build().expect("Failed to build HTTP client")
    };

    // In live mode, register agent via API; in dry-run, use random UUID
    let agent_id = if args.dry_run {
        let id = Uuid::new_v4();
        println!("Agent ID: {id} (dry-run, not registered)");
        id
    } else {
        let client = auth_client.clone();
        // The run's own signer: a random or operator-supplied key, a real
        // verifier (it signs the evidence), so no `key_kind` is declared.
        let req = CreateAgentRequest {
            public_key: hex::encode(signer.public_key()),
            display_name: Some(format!("literature-ingester:{}", extraction.source.doi)),
            key_kind: None,
            key_kind_proof: None,
        };
        match register_agent(&client, &args.endpoint, &req).await {
            Ok(id) => {
                println!("Registered agent: {id}");
                id
            }
            Err(e) => {
                eprintln!("Error registering agent: {e}");
                std::process::exit(1);
            }
        }
    };

    // Build packets
    let packets = build_packets(&extraction, &signer, agent_id, args.allow_verbatim);
    println!("Built {} epistemic packets", packets.len());
    match withheld_summary(&extraction, args.allow_verbatim) {
        Some(summary) => eprintln!("{summary}"),
        None if args.allow_verbatim
            && !passage_retention_permitted(extraction.source.licence.as_deref()) =>
        {
            eprintln!(
                "Licence gate overridden by --allow-verbatim ({}): passages and figures ship verbatim.",
                extraction.source.licence.as_deref().unwrap_or("licence unknown")
            );
        }
        None => {}
    }

    if args.dry_run {
        println!("\n--- DRY RUN MODE ---");

        // Show provenance summary
        if has_provenance {
            println!("\n-- Provenance Summary --");
            println!("Authors:");
            for author in &extraction.source.authors {
                let affs = author.affiliations();
                let roles = author.roles();
                let affs_str = if affs.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", affs.join(", "))
                };
                let roles_str = if roles.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", roles.join(", "))
                };
                println!("  {}{}{}", author.name(), affs_str, roles_str);
            }
            println!("Instruments:");
            for inst in &extraction.provenance.instruments {
                let conds = inst.conditions.join(", ");
                println!(
                    "  {} ({}){}",
                    inst.name,
                    inst.abbreviation,
                    if conds.is_empty() {
                        String::new()
                    } else {
                        format!(" [{conds}]")
                    }
                );
            }
            println!("Reagents:");
            for r in &extraction.provenance.reagents {
                println!("  {} ({}) - {}", r.name, r.formula, r.role);
            }
            if !extraction.provenance.experimental_conditions.is_empty() {
                println!("Conditions:");
                for c in &extraction.provenance.experimental_conditions {
                    println!("  {}: {} ({})", c.parameter, c.value, c.context);
                }
            }
            if !extraction.provenance.computational_methods.is_empty() {
                println!("Computational Methods:");
                for cm in &extraction.provenance.computational_methods {
                    println!("  {} / {} / {}", cm.method, cm.software, cm.functional);
                }
            }
        }

        // Show per-claim details
        for (i, packet) in packets.iter().enumerate() {
            let claim = &extraction.claims[i];
            println!(
                "\nPacket {}: \"{}\"",
                i + 1,
                &packet.claim.content[..packet.claim.content.len().min(80)]
            );
            let fig_count = packet
                .evidence
                .iter()
                .filter(|e| matches!(e.evidence_type, EvidenceTypeSubmission::Figure { .. }))
                .count();
            let text_count = packet.evidence.len() - fig_count;
            println!(
                "  Evidence: {} text + {} figure ({} total), hash: {}...",
                text_count,
                fig_count,
                packet.evidence.len(),
                &packet.evidence[0].content_hash[..16]
            );
            println!(
                "  Methodology: {}, confidence: {:.0}%",
                packet.reasoning_trace.methodology,
                packet.reasoning_trace.confidence * 100.0,
            );
            if !claim.instruments_used.is_empty() {
                println!("  Instruments: {}", claim.instruments_used.join(", "));
            }
            if !claim.reagents_involved.is_empty() {
                println!("  Reagents: {}", claim.reagents_involved.join(", "));
            }
            if !claim.conditions.is_empty() {
                println!("  Conditions: {}", claim.conditions.join(", "));
            }
        }

        // Methodology distribution
        let mut method_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for packet in &packets {
            *method_counts
                .entry(&packet.reasoning_trace.methodology)
                .or_insert(0) += 1;
        }
        println!("\nMethodology distribution:");
        for (method, count) in &method_counts {
            println!("  {method}: {count}");
        }

        println!("\nDry run complete. Use without --dry-run to submit.");
        return;
    }

    // Submit packets
    let client = auth_client;
    let mut submitted = 0;
    let mut failed = 0;

    // Register per-author agents (deterministic keys so same author → same
    // agent), declared seed-derived: they name the authors and sign nothing.
    let mut author_agents: std::collections::HashMap<String, Uuid> =
        std::collections::HashMap::new();

    for author in &extraction.source.authors {
        let name = author.name();
        let req = author_agent_request(&extraction.source.doi, name);
        match register_agent(&client, &args.endpoint, &req).await {
            Ok(id) => {
                println!("Registered author agent: {name} → {id}");
                author_agents.insert(name.to_string(), id);
            }
            Err(e) => {
                eprintln!("Warning: failed to register author agent '{name}': {e}");
            }
        }
    }

    // Create PROV-O Activity record for this ingestion run
    let ingestion_activity_id = create_activity(
        &client,
        &args.endpoint,
        "ingestion",
        agent_id,
        &format!("Literature ingestion: {}", extraction.source.title),
        serde_json::json!({
            "source_doi": extraction.source.doi,
            "source_title": extraction.source.title,
            "claims_count": packets.len(),
        }),
    )
    .await;

    if let Some(ref id) = ingestion_activity_id {
        println!("Created ingestion activity: {id}");
    }

    // Create experiment Activity to represent the paper's experimental work
    let experiment_activity_id = if has_provenance {
        let props = serde_json::json!({
            "doi": extraction.source.doi,
            "instruments": extraction.provenance.instruments,
            "reagents": extraction.provenance.reagents,
            "experimental_conditions": extraction.provenance.experimental_conditions,
            "computational_methods": extraction.provenance.computational_methods,
        });
        let id = create_activity(
            &client,
            &args.endpoint,
            "experiment",
            agent_id,
            &format!("Paper: {}", extraction.source.title),
            props,
        )
        .await;

        if let Some(ref exp_id) = id {
            println!("Created experiment activity: {exp_id}");

            // Link experiment activity to each author agent
            for &author_id in author_agents.values() {
                create_prov_edge(
                    &client,
                    &args.endpoint,
                    *exp_id,
                    "activity",
                    author_id,
                    "agent",
                    "associated_with",
                )
                .await;
            }
        }
        id
    } else {
        None
    };

    for (i, packet) in packets.iter().enumerate() {
        let url = format!("{}/api/v1/submit/packet", args.endpoint);

        match client
            .post(&url)
            .json(packet)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<SubmitResponse>().await {
                        Ok(result) => {
                            println!(
                                "[{}/{}] Submitted: {} (truth={:.3})",
                                i + 1,
                                packets.len(),
                                result.claim_id,
                                result.truth_value,
                            );
                            submitted += 1;

                            // Edge: ingestion Activity --generated--> Claim
                            if let Some(ref act_id) = ingestion_activity_id {
                                create_prov_edge(
                                    &client,
                                    &args.endpoint,
                                    *act_id,
                                    "activity",
                                    result.claim_id,
                                    "claim",
                                    "generated",
                                )
                                .await;
                            }

                            // Edge: experiment Activity --generated--> Claim
                            if let Some(ref exp_id) = experiment_activity_id {
                                create_prov_edge(
                                    &client,
                                    &args.endpoint,
                                    *exp_id,
                                    "activity",
                                    result.claim_id,
                                    "claim",
                                    "generated",
                                )
                                .await;
                            }

                            // No `claim --attributed_to--> author` edge. It
                            // credits the author agent with the claim, and
                            // POST /api/v1/edges accepts a credited edge only
                            // from that agent itself or its operator: this
                            // tool is neither, so every one was refused (403).
                            // A document's authorship is recorded by the
                            // document ingest (`ingest_document`), which
                            // records a third party as pending their
                            // countersignature.
                        }
                        Err(e) => {
                            eprintln!("[{}/{}] Response parse error: {e}", i + 1, packets.len());
                            failed += 1;
                        }
                    }
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    eprintln!(
                        "[{}/{}] Failed (HTTP {status}): {body}",
                        i + 1,
                        packets.len(),
                    );
                    failed += 1;
                }
            }
            Err(e) => {
                eprintln!("[{}/{}] Connection error: {e}", i + 1, packets.len());
                failed += 1;
            }
        }
    }

    // Complete the activity records
    if let Some(ref act_id) = ingestion_activity_id {
        complete_activity(
            &client,
            &args.endpoint,
            *act_id,
            serde_json::json!({
                "claims_submitted": submitted,
                "claims_failed": failed,
            }),
        )
        .await;
    }
    if let Some(ref exp_id) = experiment_activity_id {
        complete_activity(
            &client,
            &args.endpoint,
            *exp_id,
            serde_json::json!({
                "claims_generated": submitted,
                "author_agents": author_agents.len(),
            }),
        )
        .await;
    }

    println!(
        "\nIngestion complete: {submitted} submitted, {failed} failed, {} total",
        packets.len()
    );
    if !author_agents.is_empty() {
        println!(
            "Registered {} author agents with PROV-O attribution edges",
            author_agents.len()
        );
    }

    if failed > 0 {
        std::process::exit(1);
    }
}

// =============================================================================
// PROV-O ACTIVITY HELPERS
// =============================================================================

/// Create a PROV-O Activity record via the API. Returns the activity ID on success.
async fn create_activity(
    client: &reqwest::Client,
    endpoint: &str,
    activity_type: &str,
    agent_id: Uuid,
    description: &str,
    properties: serde_json::Value,
) -> Option<Uuid> {
    let url = format!("{endpoint}/api/v1/activities");
    let body = serde_json::json!({
        "activity_type": activity_type,
        "agent_id": agent_id,
        "description": description,
        "properties": properties,
    });

    match client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            #[derive(Deserialize)]
            struct ActivityResp {
                id: Uuid,
            }
            resp.json::<ActivityResp>().await.ok().map(|r| r.id)
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!("Warning: failed to create activity (HTTP {status}): {body}");
            None
        }
        Err(e) => {
            eprintln!("Warning: failed to create activity: {e}");
            None
        }
    }
}

/// Mark a PROV-O Activity as completed via the API.
async fn complete_activity(
    client: &reqwest::Client,
    endpoint: &str,
    activity_id: Uuid,
    properties: serde_json::Value,
) {
    let url = format!("{endpoint}/api/v1/activities/{activity_id}/complete");
    let body = serde_json::json!({ "properties": properties });

    if let Err(e) = client
        .put(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        eprintln!("Warning: failed to complete activity: {e}");
    }
}

/// Create a provenance edge (Activity --> Entity) via the API.
async fn create_prov_edge(
    client: &reqwest::Client,
    endpoint: &str,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
) {
    let url = format!("{endpoint}/api/v1/edges");
    let body = serde_json::json!({
        "source_id": source_id,
        "target_id": target_id,
        "source_type": source_type,
        "target_type": target_type,
        "relationship": relationship,
        "properties": { "prov_type": format!("prov:{relationship}") },
    });

    match client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Err(e) => eprintln!("Warning: failed to create prov edge: {e}"),
        // A refusal is a failure too: report the status and the server's
        // reason, never carry on as if the edge exists.
        Ok(response) if !response.status().is_success() => {
            let status = response.status();
            let reason = response.text().await.unwrap_or_default();
            eprintln!(
                "Warning: prov edge {source_type} -{relationship}-> {target_type} refused \
                 ({status}): {reason}"
            );
        }
        Ok(_) => {}
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_extraction_json() -> &'static str {
        r#"{
            "source": {
                "doi": "10.1038/s41586-023-12345",
                "title": "Test Paper on Climate Change",
                "authors": ["Smith, J.", "Jones, A."],
                "journal": "Nature"
            },
            "claims": [
                {
                    "statement": "Global temperature has risen 1.1°C since pre-industrial levels",
                    "page": 42,
                    "section": "Results",
                    "confidence": 0.95,
                    "supporting_text": "Our analysis shows a consistent warming trend of 1.1°C"
                },
                {
                    "statement": "Arctic ice extent has decreased by 13% per decade",
                    "page": 45,
                    "section": "Discussion",
                    "confidence": 0.88,
                    "supporting_text": "Satellite measurements indicate a 13% per decade decline"
                }
            ],
            "extraction_metadata": {
                "extractor_version": "2.0.0",
                "model_used": "gpt-4"
            }
        }"#
    }

    #[test]
    fn test_parse_literature_extraction() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();

        assert_eq!(extraction.source.doi, "10.1038/s41586-023-12345");
        assert_eq!(extraction.source.title, "Test Paper on Climate Change");
        assert_eq!(extraction.claims.len(), 2);
        assert_eq!(extraction.claims[0].page, Some(42));
        assert!((extraction.claims[0].confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_packets_from_extraction() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        assert_eq!(packets.len(), 2, "Should produce one packet per claim");

        // Verify first packet
        let p0 = &packets[0];
        assert!(p0.claim.content.contains("Global temperature"));
        assert_eq!(p0.evidence.len(), 1);
        assert_eq!(p0.claim.agent_id, agent_id);
        assert_eq!(p0.reasoning_trace.methodology, "extraction");
        assert!(!p0.signature.is_empty());

        // Verify evidence hash matches raw content
        let expected_hash = hex::encode(ContentHasher::hash(
            p0.evidence[0].raw_content.as_ref().unwrap().as_bytes(),
        ));
        assert_eq!(p0.evidence[0].content_hash, expected_hash);
    }

    #[test]
    fn test_packet_has_valid_evidence_signature() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        // Evidence should have a valid hex-encoded signature
        let sig_hex = packets[0].evidence[0].signature.as_ref().unwrap();
        let sig_bytes = hex::decode(sig_hex).expect("Signature should be valid hex");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");

        // Ruling R-34: a v1 EVIDENCE signature over the evidence's content
        // hash, which is no claim signature over that hash.
        let sig: [u8; 64] = sig_bytes.try_into().unwrap();
        let mut hash = [0u8; 32];
        hex::decode_to_slice(&packets[0].evidence[0].content_hash, &mut hash).unwrap();
        let check = |kind| {
            epigraph_crypto::SignatureVerifier::verify_entity(
                &signer.public_key(),
                kind,
                &hash,
                &sig,
            )
            .unwrap()
        };
        assert_eq!(
            check(SignedEntity::Evidence),
            Some(epigraph_crypto::SignatureScheme::V1)
        );
        assert_eq!(check(SignedEntity::Claim), None);
    }

    #[test]
    fn test_packet_explanation_includes_source() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        assert!(
            packets[0]
                .reasoning_trace
                .explanation
                .contains("Test Paper on Climate Change"),
            "Explanation should reference the paper title"
        );
        assert!(
            packets[0].reasoning_trace.explanation.contains("10.1038"),
            "Explanation should include the DOI"
        );
    }

    #[test]
    fn test_parse_minimal_extraction() {
        let json = r#"{
            "source": {
                "doi": "10.1000/test",
                "title": "Minimal",
                "authors": []
            },
            "claims": [
                {
                    "statement": "Test claim",
                    "confidence": 0.5,
                    "supporting_text": "Evidence text"
                }
            ]
        }"#;

        let extraction: LiteratureExtraction = serde_json::from_str(json).unwrap();
        assert_eq!(extraction.claims.len(), 1);
        assert!(extraction.claims[0].page.is_none());
    }

    #[test]
    fn test_empty_claims_produces_no_packets() {
        let json = r#"{
            "source": {
                "doi": "10.1000/test",
                "title": "Empty",
                "authors": []
            },
            "claims": []
        }"#;

        let extraction: LiteratureExtraction = serde_json::from_str(json).unwrap();
        let signer = AgentSigner::generate();
        let packets = build_packets(&extraction, &signer, Uuid::new_v4(), false);

        assert!(packets.is_empty());
    }

    #[test]
    fn test_max_input_file_size_constant() {
        assert_eq!(MAX_INPUT_FILE_SIZE, 100 * 1024 * 1024);
        assert_eq!(MAX_INPUT_FILE_SIZE, 104_857_600);
    }

    #[test]
    fn test_small_file_passes_size_check() {
        // Write a small temporary file and verify its metadata is under the cap
        let dir = std::env::temp_dir();
        let path = dir.join("epigraph_test_small_input.json");
        std::fs::write(&path, b"{}").expect("failed to write temp file");

        let meta = std::fs::metadata(&path).expect("failed to read metadata");
        assert!(
            meta.len() <= MAX_INPUT_FILE_SIZE,
            "A trivially small file must be under the size cap"
        );

        std::fs::remove_file(&path).ok();
    }

    fn sample_extraction_with_figures_json() -> &'static str {
        r#"{
            "source": {
                "doi": "10.1000/fig-test",
                "title": "Paper With Figures",
                "authors": ["Test Author"],
                "licence": "CC-BY-4.0"
            },
            "claims": [
                {
                    "statement": "Surface shows atomic resolution features",
                    "page": 10,
                    "section": "Results",
                    "confidence": 0.85,
                    "supporting_text": "STM imaging reveals clear atomic features"
                },
                {
                    "statement": "XPS confirms elemental composition",
                    "page": 15,
                    "section": "Results",
                    "confidence": 0.9,
                    "supporting_text": "XPS spectrum shows expected peaks"
                }
            ],
            "figures": [
                {
                    "page": 10,
                    "figure_id": "Figure 2a",
                    "caption": "STM image of surface at atomic resolution",
                    "image_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
                    "width": 400.0,
                    "height": 300.0
                },
                {
                    "page": 15,
                    "figure_id": "Figure 3",
                    "caption": "XPS spectrum of sample",
                    "image_base64": "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0k",
                    "width": 500.0,
                    "height": 350.0
                },
                {
                    "page": 20,
                    "figure_id": "Figure 4",
                    "caption": "Supplementary data",
                    "image_base64": "iVBORw0KGgoAAAANSAAAA",
                    "width": 300.0,
                    "height": 200.0
                }
            ]
        }"#
    }

    #[test]
    fn test_parse_extraction_with_figures() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_with_figures_json()).unwrap();

        assert_eq!(extraction.figures.len(), 3);
        assert_eq!(
            extraction.figures[0].figure_id,
            Some("Figure 2a".to_string())
        );
        assert_eq!(extraction.figures[0].page, Some(10));
        assert!(extraction.figures[0].image_base64.is_some());
        assert!(extraction.figures[0].caption.is_some());
    }

    #[test]
    fn test_parse_extraction_without_figures() {
        // Old JSON format without figures array — should parse with empty vec
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();

        assert!(
            extraction.figures.is_empty(),
            "Missing figures field should default to empty vec"
        );
    }

    #[test]
    fn test_build_packets_attaches_figure_evidence() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_with_figures_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        // First claim is on page 10, figure 2a is also on page 10
        assert_eq!(
            packets[0].evidence.len(),
            2,
            "Claim on page 10 should have text + figure evidence"
        );
        assert!(
            matches!(
                packets[0].evidence[1].evidence_type,
                EvidenceTypeSubmission::Figure { .. }
            ),
            "Second evidence should be Figure type"
        );

        // Second claim is on page 15, figure 3 is also on page 15
        assert_eq!(
            packets[1].evidence.len(),
            2,
            "Claim on page 15 should have text + figure evidence"
        );

        // Trace inputs should reference all evidence
        assert_eq!(packets[0].reasoning_trace.inputs.len(), 2);

        // Ruling R-34: the FIGURE evidence (its own sign site) carries a v1
        // EVIDENCE signature over its content hash, which is no claim
        // signature over that hash.
        let fig = &packets[0].evidence[1];
        let sig: [u8; 64] = hex::decode(fig.signature.as_ref().expect("figure is signed"))
            .unwrap()
            .try_into()
            .unwrap();
        let mut hash = [0u8; 32];
        hex::decode_to_slice(&fig.content_hash, &mut hash).unwrap();
        let check = |kind| {
            epigraph_crypto::SignatureVerifier::verify_entity(
                &signer.public_key(),
                kind,
                &hash,
                &sig,
            )
            .unwrap()
        };
        assert_eq!(
            check(SignedEntity::Evidence),
            Some(epigraph_crypto::SignatureScheme::V1),
            "the figure evidence is not signed as v1 evidence"
        );
        assert_eq!(check(SignedEntity::Claim), None);
    }

    #[test]
    fn test_figure_content_hash_integrity() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_with_figures_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        // Verify figure evidence hash matches raw_content
        let fig_evidence = &packets[0].evidence[1]; // Figure evidence on page 10
        let raw = fig_evidence.raw_content.as_ref().unwrap();
        let expected_hash = hex::encode(ContentHasher::hash(raw.as_bytes()));
        assert_eq!(
            fig_evidence.content_hash, expected_hash,
            "Figure content hash must match raw_content"
        );
    }

    // =========================================================================
    // ENRICHED PROVENANCE TESTS
    // =========================================================================

    fn sample_enriched_json() -> &'static str {
        r#"{
            "source": {
                "doi": "10.48550/arXiv.2508.16798",
                "title": "Molecular Tools for Non-Planar Surface Chemistry",
                "authors": [
                    {"name": "Huff, T.", "affiliations": ["CBN Nano Technologies"], "roles": ["co-first-author"]},
                    {"name": "Blue, B.", "affiliations": ["CBN Nano Technologies"], "roles": ["co-first-author"]}
                ],
                "journal": "arXiv preprint"
            },
            "provenance": {
                "instruments": [
                    {"name": "Scanning Tunneling Microscope", "abbreviation": "STM", "conditions": ["UHV", "77K"]}
                ],
                "reagents": [
                    {"name": "Tetrakis(iodomethyl)germane", "abbreviation": "TIMe-Ge", "formula": "Ge(CH2I)4", "role": "molecular tool"}
                ],
                "experimental_conditions": [
                    {"parameter": "temperature", "value": "150-300 K", "context": "substrate during deposition"}
                ],
                "computational_methods": [
                    {"method": "DFT", "software": "Q-Chem", "functional": "B3LYP-D3(BJ)", "basis_set": "6-31G(d,p)"}
                ]
            },
            "claims": [
                {
                    "statement": "TIMe-Ge chemisorbs on Si(100) predominantly in a single on-dimer configuration",
                    "page": 19,
                    "section": "Conclusions",
                    "confidence": 0.92,
                    "supporting_text": "TIMe-Ge was shown to land predominantly in a single on-dimer configuration",
                    "methodology": "instrumental",
                    "instruments_used": ["STM"],
                    "reagents_involved": ["TIMe-Ge", "Si(100)"],
                    "conditions": ["150-300 K", "UHV"]
                },
                {
                    "statement": "DFT predicts binding energy of -2.3 eV for three-leg-down configuration",
                    "page": 22,
                    "section": "DFT Results",
                    "confidence": 0.88,
                    "supporting_text": "B3LYP-D3(BJ) calculations yield a binding energy of -2.3 eV",
                    "methodology": "computational",
                    "instruments_used": [],
                    "reagents_involved": ["TIMe-Ge"],
                    "conditions": []
                }
            ],
            "extraction_metadata": {
                "extractor_version": "2.0.0",
                "model_used": "gpt-4o",
                "enrichment_model": "gpt-4o"
            }
        }"#
    }

    #[test]
    fn test_parse_enriched_json_with_author_objects() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_enriched_json()).unwrap();

        assert_eq!(extraction.source.authors.len(), 2);
        assert_eq!(extraction.source.authors[0].name(), "Huff, T.");
        assert_eq!(extraction.source.authors[1].name(), "Blue, B.");
        assert_eq!(
            extraction.source.authors[0].affiliations(),
            &["CBN Nano Technologies"]
        );
        assert_eq!(extraction.source.authors[0].roles(), &["co-first-author"]);
    }

    #[test]
    fn test_parse_old_format_with_string_authors() {
        // Old format: authors are plain strings — backward compatibility
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();

        assert_eq!(extraction.source.authors.len(), 2);
        assert_eq!(extraction.source.authors[0].name(), "Smith, J.");
        assert_eq!(extraction.source.authors[1].name(), "Jones, A.");
        // Simple authors have no affiliations or roles
        assert!(extraction.source.authors[0].affiliations().is_empty());
        assert!(extraction.source.authors[0].roles().is_empty());
    }

    #[test]
    fn test_provenance_block_parsing() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_enriched_json()).unwrap();

        assert_eq!(extraction.provenance.instruments.len(), 1);
        assert_eq!(
            extraction.provenance.instruments[0].name,
            "Scanning Tunneling Microscope"
        );
        assert_eq!(extraction.provenance.instruments[0].abbreviation, "STM");
        assert_eq!(
            extraction.provenance.instruments[0].conditions,
            vec!["UHV", "77K"]
        );

        assert_eq!(extraction.provenance.reagents.len(), 1);
        assert_eq!(extraction.provenance.reagents[0].formula, "Ge(CH2I)4");
        assert_eq!(extraction.provenance.reagents[0].role, "molecular tool");

        assert_eq!(extraction.provenance.experimental_conditions.len(), 1);
        assert_eq!(
            extraction.provenance.experimental_conditions[0].parameter,
            "temperature"
        );

        assert_eq!(extraction.provenance.computational_methods.len(), 1);
        assert_eq!(extraction.provenance.computational_methods[0].method, "DFT");
        assert_eq!(
            extraction.provenance.computational_methods[0].software,
            "Q-Chem"
        );
    }

    #[test]
    fn test_provenance_block_defaults_to_empty() {
        // Old format without provenance block — should default to empty
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();

        assert!(extraction.provenance.instruments.is_empty());
        assert!(extraction.provenance.reagents.is_empty());
        assert!(extraction.provenance.experimental_conditions.is_empty());
        assert!(extraction.provenance.computational_methods.is_empty());
    }

    #[test]
    fn test_per_claim_methodology_override() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_enriched_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        assert_eq!(packets.len(), 2);
        // First claim has methodology "instrumental" from enriched JSON
        assert_eq!(packets[0].reasoning_trace.methodology, "instrumental");
        // Second claim has methodology "computational"
        assert_eq!(packets[1].reasoning_trace.methodology, "computational");
    }

    #[test]
    fn test_methodology_defaults_to_extraction() {
        // Old format without per-claim methodology
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_extraction_json()).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packets = build_packets(&extraction, &signer, agent_id, false);

        // All claims should default to "extraction" methodology
        for packet in &packets {
            assert_eq!(packet.reasoning_trace.methodology, "extraction");
        }
    }

    #[test]
    fn test_per_claim_instruments_and_reagents() {
        let extraction: LiteratureExtraction =
            serde_json::from_str(sample_enriched_json()).unwrap();

        assert_eq!(extraction.claims[0].instruments_used, vec!["STM"]);
        assert_eq!(
            extraction.claims[0].reagents_involved,
            vec!["TIMe-Ge", "Si(100)"]
        );
        assert_eq!(extraction.claims[0].conditions, vec!["150-300 K", "UHV"]);

        // Second claim is computational — no instruments
        assert!(extraction.claims[1].instruments_used.is_empty());
        assert_eq!(extraction.claims[1].reagents_involved, vec!["TIMe-Ge"]);
        assert!(extraction.claims[1].conditions.is_empty());
    }

    /// Backlog 57943a39: an author's key is computable from the DOI and the
    /// name, so its registration must declare it `seed-derived` (the server
    /// then stores no verifier and provisions no OAuth client). Before, the
    /// body carried no `key_kind` and the server stored an `ed25519` signer
    /// with an active client. The key is still the deterministic one, so the
    /// same author of the same paper stays one agent.
    #[test]
    fn an_author_is_registered_as_a_seed_derived_key() {
        let doi = "10.48550/arXiv.2508.16798";
        let body = serde_json::to_value(author_agent_request(doi, "Huff, T.")).unwrap();
        assert_eq!(body["key_kind"], "seed-derived", "{body}");
        assert_eq!(
            body["public_key"],
            hex::encode(deterministic_signer(&format!("{doi}:Huff, T.")).public_key()),
            "{body}"
        );
        assert_eq!(body["display_name"], "Huff, T.", "{body}");
        // The proof of possession the server requires with the declaration.
        let key: [u8; 32] = hex::decode(body["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let proof: [u8; 64] = hex::decode(body["key_kind_proof"].as_str().expect("proof"))
            .unwrap()
            .try_into()
            .unwrap();
        assert!(epigraph_crypto::SignatureVerifier::verify(
            &key,
            &epigraph_crypto::key_kind_declaration_message("seed-derived", &key),
            &proof
        )
        .unwrap());

        // The run's own signer is a real verifier: no declaration at all.
        let run = CreateAgentRequest {
            public_key: hex::encode(AgentSigner::generate().public_key()),
            display_name: None,
            key_kind: None,
            key_kind_proof: None,
        };
        let body = serde_json::to_value(run).unwrap();
        assert!(body.get("key_kind").is_none(), "{body}");
        assert!(body.get("key_kind_proof").is_none(), "{body}");
    }

    #[test]
    fn test_deterministic_agent_key_generation() {
        let seed = "10.48550/arXiv.2508.16798:Huff, T.";
        let signer1 = deterministic_signer(seed);
        let signer2 = deterministic_signer(seed);

        // Same seed must produce identical keys
        assert_eq!(signer1.public_key(), signer2.public_key());

        // Different seed must produce different keys
        let signer3 = deterministic_signer("10.48550/arXiv.2508.16798:Blue, B.");
        assert_ne!(signer1.public_key(), signer3.public_key());
    }

    #[test]
    fn test_mixed_author_formats() {
        // Mix of simple strings and detailed objects in the same array
        let json = r#"{
            "source": {
                "doi": "10.1000/mixed",
                "title": "Mixed Authors",
                "authors": [
                    "Plain Author",
                    {"name": "Detailed, A.", "affiliations": ["MIT"], "roles": ["corresponding-author"]}
                ]
            },
            "claims": [
                {
                    "statement": "Test claim",
                    "confidence": 0.5,
                    "supporting_text": "Evidence"
                }
            ]
        }"#;

        let extraction: LiteratureExtraction = serde_json::from_str(json).unwrap();
        assert_eq!(extraction.source.authors.len(), 2);
        assert_eq!(extraction.source.authors[0].name(), "Plain Author");
        assert!(extraction.source.authors[0].affiliations().is_empty());
        assert_eq!(extraction.source.authors[1].name(), "Detailed, A.");
        assert_eq!(extraction.source.authors[1].affiliations(), &["MIT"]);
    }

    // =========================================================================
    // LICENCE GATE (backlog 1a462cc1)
    // =========================================================================

    /// One claim near one figure, under `licence` (omitted when `None`).
    fn licensed_extraction(licence: Option<&str>) -> LiteratureExtraction {
        let mut json = serde_json::json!({
            "source": {
                "doi": "10.9999/t88-licence",
                "title": "Licence Gate Paper",
                "authors": ["Gate, L."]
            },
            "claims": [{
                "statement": "The film conducts above 40 K",
                "page": 7,
                "section": "Results",
                "confidence": 0.8,
                "supporting_text": LICENSED_PASSAGE
            }],
            "figures": [{
                "page": 7,
                "figure_id": "fig3",
                "caption": "Figure 3. Publisher caption text.",
                "image_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
            }]
        });
        if let Some(l) = licence {
            json["source"]["licence"] = serde_json::json!(l);
        }
        serde_json::from_value(json).expect("fixture parses")
    }

    const LICENSED_PASSAGE: &str =
        "Publisher prose the evidence table must not republish verbatim, word for word";

    /// The withheld shape: no passage, no figure image or caption, a body
    /// whose stored hash is its own digest, and the passage's BLAKE3.
    fn assert_withheld(packets: &[EpistemicPacket], why: &str) {
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        let passage_hash = hex::encode(ContentHasher::hash(LICENSED_PASSAGE.as_bytes()));
        for ev in &p.evidence {
            let raw = ev.raw_content.as_deref().unwrap_or("");
            assert!(
                !raw.contains(LICENSED_PASSAGE),
                "verbatim passage shipped ({why}): {raw}"
            );
            assert!(
                !matches!(ev.evidence_type, EvidenceTypeSubmission::Figure { .. }),
                "publisher figure shipped ({why})"
            );
            assert_eq!(
                ev.content_hash,
                hex::encode(ContentHasher::hash(raw.as_bytes())),
                "content_hash must be the digest of the body the server checks"
            );
        }
        let body = p.evidence[0].raw_content.as_deref().unwrap();
        assert!(
            body.contains(&format!("Passage BLAKE3: {passage_hash}.")),
            "the passage hash pins the withheld text: {body}"
        );
        assert!(
            body.contains("page 7"),
            "a locator a reader can follow: {body}"
        );
        assert!(body.contains("Passage not retained"), "{body}");
    }

    #[test]
    fn non_open_licence_input_emits_no_verbatim_passage() {
        let signer = AgentSigner::generate();
        let packets = build_packets(
            &licensed_extraction(Some("CC-BY-NC-4.0")),
            &signer,
            Uuid::new_v4(),
            false,
        );
        assert_withheld(&packets, "CC-BY-NC-4.0");
    }

    #[test]
    fn unknown_licence_input_emits_no_verbatim_passage() {
        let signer = AgentSigner::generate();
        let packets = build_packets(&licensed_extraction(None), &signer, Uuid::new_v4(), false);
        assert_withheld(&packets, "no licence");
        assert!(
            withheld_summary(&licensed_extraction(None), false).is_some_and(|s| s
                .contains("withheld 1 supporting passage(s)")
                && s.contains("1 figure(s)"))
        );
    }

    #[test]
    fn open_licence_ships_passage_and_figure_verbatim() {
        let signer = AgentSigner::generate();
        let extraction = licensed_extraction(Some("CC-BY-4.0"));
        let packets = build_packets(&extraction, &signer, Uuid::new_v4(), false);
        assert_eq!(
            packets[0].evidence[0].raw_content.as_deref(),
            Some(LICENSED_PASSAGE)
        );
        assert!(packets[0]
            .evidence
            .iter()
            .any(|e| matches!(e.evidence_type, EvidenceTypeSubmission::Figure { .. })));
        assert_eq!(withheld_summary(&extraction, false), None);
    }

    #[test]
    fn us_spelled_license_key_is_read() {
        // A producer writing `license` must not be silently read as "unknown".
        let mut json = serde_json::json!({
            "source": {"doi": "10.9999/t88-us", "title": "US Spelling", "authors": []},
            "claims": [{
                "statement": "s", "page": 1, "confidence": 0.5,
                "supporting_text": LICENSED_PASSAGE
            }]
        });
        json["source"]["license"] = serde_json::json!("CC-BY-4.0");
        let extraction: LiteratureExtraction = serde_json::from_value(json).unwrap();
        assert_eq!(extraction.source.licence.as_deref(), Some("CC-BY-4.0"));
        let packets = build_packets(&extraction, &AgentSigner::generate(), Uuid::new_v4(), false);
        assert_eq!(
            packets[0].evidence[0].raw_content.as_deref(),
            Some(LICENSED_PASSAGE)
        );
    }

    #[test]
    fn allow_verbatim_overrides_a_restrictive_licence() {
        let signer = AgentSigner::generate();
        let extraction = licensed_extraction(Some("All rights reserved"));
        let packets = build_packets(&extraction, &signer, Uuid::new_v4(), true);
        assert_eq!(
            packets[0].evidence[0].raw_content.as_deref(),
            Some(LICENSED_PASSAGE)
        );
        assert_eq!(packets[0].evidence.len(), 2, "passage + figure");
        assert_eq!(withheld_summary(&extraction, true), None);
    }

    // =========================================================================
    // PACKET SIGNATURE (sibling of backlog 7d9e60c6)
    // =========================================================================

    /// What `routes/submit.rs` does with `require_packet_signatures` on: parse
    /// the wire JSON into the server's packet, recompute `signable_bytes()`,
    /// verify the signature under the claim agent's key.
    fn server_accepts(packet: &EpistemicPacket, signer: &AgentSigner) -> bool {
        // The request body as bytes, parsed the way axum's `Json` parses it.
        let wire = serde_json::to_vec(packet).expect("client packet serializes");
        let server: epigraph_api::routes::submit::EpistemicPacket =
            serde_json::from_slice(&wire).expect("server parses the client packet");
        let canonical = server.signable_bytes().expect("canonical bytes");
        let Ok(sig) = <[u8; 64]>::try_from(hex::decode(&server.signature).unwrap()) else {
            return false;
        };
        epigraph_crypto::SignatureVerifier::verify(&signer.public_key(), &canonical, &sig)
            .unwrap_or(false)
    }

    #[test]
    fn literature_packets_verify_like_the_server() {
        let signer = AgentSigner::generate();
        // Open licence: a text passage AND a figure in the signed evidence.
        let open = build_packets(
            &licensed_extraction(Some("CC-BY-4.0")),
            &signer,
            Uuid::new_v4(),
            false,
        );
        // Withheld: the locator + hash body.
        let withheld = build_packets(&licensed_extraction(None), &signer, Uuid::new_v4(), false);
        // A float with a long shortest representation travels as JSON text.
        let mut awkward = licensed_extraction(None);
        awkward.claims[0].confidence = 0.1 + 0.2;
        let awkward = build_packets(&awkward, &signer, Uuid::new_v4(), false);
        for p in open.iter().chain(&withheld).chain(&awkward) {
            assert_ne!(p.signature, "0".repeat(128), "no placeholder signature");
            assert!(
                server_accepts(p, &signer),
                "a literature packet must pass require_packet_signatures verification"
            );
            assert!(!server_accepts(p, &AgentSigner::generate()));
        }
    }
}
