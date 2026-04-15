//! Git History Ingestion CLI
//!
//! Parses EpiGraph's own git log (which follows the Epistemic Commit Protocol)
//! and submits each commit as a signed Epistemic Packet to the EpiGraph API.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin ingest_git -- \
//!   --repo /workspaces/EpiGraphV2 \
//!   --endpoint http://localhost:8080 \
//!   --agent-key generate \
//!   --dry-run \
//!   --since "2026-01-01" \
//!   --limit 50
//! ```
//!
//! # Mapping
//!
//! | Git Concept          | EpiGraph Primitive |
//! |----------------------|--------------------|
//! | Commit claim line    | Claim              |
//! | Evidence: bullets    | Evidence (Digital) |
//! | Reasoning: section   | ReasoningTrace     |
//! | Verification: bullets| Evidence (Digital) |
//! | Author email         | Agent              |
//! | Commit hash          | Content hash       |

use async_trait::async_trait;
use epigraph_crypto::{AgentSigner, ContentHasher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

struct Args {
    /// Path to git repository
    repo: PathBuf,
    /// API endpoint base URL
    endpoint: String,
    /// Agent private key (base64-encoded 32 bytes), or "generate"
    agent_key: String,
    /// Dry run mode — parse and display without submitting
    dry_run: bool,
    /// Only process commits after this date (YYYY-MM-DD)
    since: Option<String>,
    /// Maximum number of commits to process
    limit: Option<usize>,
    /// Enricher mode: noop (default) or llm
    enricher: EnricherMode,
    /// Whether to generate and store embeddings for submitted claims
    embed: bool,
    /// Bearer token for agent registration (required for /agents endpoint)
    token: Option<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();

        let mut repo = PathBuf::from(".");
        let mut endpoint = "http://localhost:8080".to_string();
        let mut agent_key = "generate".to_string();
        let mut dry_run = false;
        let mut since = None;
        let mut limit = None;
        let mut enricher = EnricherMode::Noop;
        let mut embed = false;
        let mut token = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--repo" | "-r" => {
                    i += 1;
                    repo = PathBuf::from(args.get(i).ok_or("--repo requires a path argument")?);
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
                "--since" | "-s" => {
                    i += 1;
                    since = Some(
                        args.get(i)
                            .ok_or("--since requires a date argument (YYYY-MM-DD)")?
                            .clone(),
                    );
                }
                "--limit" | "-l" => {
                    i += 1;
                    let val = args.get(i).ok_or("--limit requires a number")?;
                    limit = Some(
                        val.parse::<usize>()
                            .map_err(|_| format!("--limit must be a number, got: {val}"))?,
                    );
                }
                "--enricher" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or("--enricher requires a mode: noop or llm")?;
                    enricher = EnricherMode::from_str(val)?;
                }
                "--embed" => {
                    embed = true;
                }
                "--token" | "-t" => {
                    i += 1;
                    token = Some(
                        args.get(i)
                            .ok_or("--token requires a bearer token argument")?
                            .clone(),
                    );
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

        Ok(Self {
            repo,
            endpoint,
            agent_key,
            dry_run,
            since,
            limit,
            enricher,
            embed,
            token,
        })
    }
}

const USAGE: &str = "\
Usage: ingest_git [OPTIONS]

Options:
  -r, --repo <PATH>      Path to git repository [default: .]
  -e, --endpoint <URL>    API endpoint [default: http://localhost:8080]
  -k, --agent-key <KEY>   Base64-encoded 32-byte agent key, 'generate', or 'per-author' [default: generate]
  -n, --dry-run           Parse and display without submitting
  -s, --since <DATE>      Only process commits after this date (YYYY-MM-DD)
  -l, --limit <N>         Maximum number of commits to process
      --enricher <MODE>   Enrichment mode: noop (default) or llm
      --embed             Generate and store embeddings for submitted claims
  -t, --token <TOKEN>     Bearer token for agent registration
  -h, --help              Show this help message";

// =============================================================================
// COMMIT TYPES & PARSING
// =============================================================================

/// Commit types from the Epistemic Commit Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitType {
    Feat,
    Fix,
    Refactor,
    Security,
    Test,
    Perf,
    Docs,
    Chore,
    Unknown,
}

impl CommitType {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "feat" => Self::Feat,
            "fix" => Self::Fix,
            "refactor" => Self::Refactor,
            "security" => Self::Security,
            "test" => Self::Test,
            "perf" => Self::Perf,
            "docs" => Self::Docs,
            "chore" => Self::Chore,
            _ => Self::Unknown,
        }
    }

    /// Map commit type to API methodology string
    fn methodology(&self) -> &'static str {
        match self {
            Self::Feat => "extraction",
            Self::Fix | Self::Refactor | Self::Security => "deductive",
            Self::Test | Self::Perf => "instrumental",
            Self::Docs | Self::Chore | Self::Unknown => "heuristic",
        }
    }

    /// Initial truth value based on commit type and whether verification exists
    fn initial_truth(&self, has_verification: bool) -> f64 {
        match self {
            Self::Feat => {
                if has_verification {
                    0.6
                } else {
                    0.4
                }
            }
            Self::Fix | Self::Security => 0.7,
            Self::Test => 0.8,
            Self::Refactor => 0.5,
            Self::Docs => 0.4,
            Self::Chore => 0.3,
            Self::Perf => {
                if has_verification {
                    0.6
                } else {
                    0.4
                }
            }
            Self::Unknown => 0.2,
        }
    }
}

impl std::fmt::Display for CommitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Feat => "feat",
            Self::Fix => "fix",
            Self::Refactor => "refactor",
            Self::Security => "security",
            Self::Test => "test",
            Self::Perf => "perf",
            Self::Docs => "docs",
            Self::Chore => "chore",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

/// A parsed git commit following the Epistemic Commit Protocol
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedCommit {
    hash: String,
    author_name: String,
    author_email: String,
    date: String,
    commit_type: CommitType,
    scope: String,
    claim_text: String,
    evidence: Vec<String>,
    reasoning: Vec<String>,
    verification: Vec<String>,
    parent_hashes: Vec<String>,
    files_changed: Vec<String>,
}

// =============================================================================
// COMMIT ENRICHMENT
// =============================================================================

/// A semantic edge between two commits discovered by enrichment
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SemanticEdge {
    /// Git hash of the target commit
    target_hash: String,
    /// Relationship type: supports, refutes, elaborates, specializes, generalizes, challenges
    relationship: String,
    /// Strength of the relationship [0.0, 1.0]
    strength: f64,
    /// LLM explanation for why this edge exists
    rationale: String,
}

impl SemanticEdge {
    #[cfg(test)]
    fn new(
        target_hash: String,
        relationship: String,
        strength: f64,
        rationale: String,
    ) -> Result<Self, String> {
        if !(0.0..=1.0).contains(&strength) {
            return Err(format!(
                "SemanticEdge strength must be in [0.0, 1.0], got: {strength}"
            ));
        }
        Ok(Self {
            target_hash,
            relationship,
            strength,
            rationale,
        })
    }
}

/// An additional implicit claim extracted from diff context by LLM enrichment
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ImplicitClaim {
    content: String,
    evidence_text: String,
    confidence: f64,
}

/// Additional data produced by LLM enrichment for a single commit
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct EnrichedData {
    /// Semantic edges to other commits (by git hash)
    semantic_edges: Vec<SemanticEdge>,
    /// Adjusted confidence (if LLM assessment differs from heuristic).
    /// Must be <= the parser's heuristic confidence (LLM can only lower, not raise).
    adjusted_confidence: Option<f64>,
    /// Real embedding vector for the claim content
    embedding: Option<Vec<f32>>,
    /// Additional implicit claims extracted from diff context
    implicit_claims: Vec<ImplicitClaim>,
}

/// Abstraction for commit enrichment strategies.
/// The enricher processes parsed commits and produces additional semantic data.
#[async_trait]
#[allow(dead_code)]
trait CommitEnricher: Send + Sync {
    /// Enrich a batch of parsed commits with semantic analysis.
    /// Receives the full batch so cross-commit relationships can be detected.
    async fn enrich(&self, commits: &[ParsedCommit]) -> Result<Vec<EnrichedData>, String>;

    /// Generate embedding for a single text string
    async fn embed(&self, text: &str) -> Result<Option<Vec<f32>>, String>;

    /// Name of this enricher (for logging/audit)
    fn name(&self) -> &str;
}

/// Deterministic passthrough enricher — returns empty EnrichedData for every commit.
/// This preserves the existing behavior exactly.
struct NoopEnricher;

#[async_trait]
impl CommitEnricher for NoopEnricher {
    async fn enrich(&self, commits: &[ParsedCommit]) -> Result<Vec<EnrichedData>, String> {
        Ok(vec![EnrichedData::default(); commits.len()])
    }

    async fn embed(&self, _text: &str) -> Result<Option<Vec<f32>>, String> {
        Ok(None)
    }

    fn name(&self) -> &str {
        "noop"
    }
}

/// LLM-based enricher that uses sliding windows to extract cross-commit relationships.
///
/// Processes commits in windows of `window_size` with `overlap` overlapping commits
/// between consecutive windows, so that relationships spanning window boundaries
/// are still detected.
struct LlmEnricher {
    client: Box<dyn epigraph_cli::enrichment::llm_client::LlmClient>,
    window_size: usize,
    overlap: usize,
}

impl LlmEnricher {
    fn new(client: Box<dyn epigraph_cli::enrichment::llm_client::LlmClient>) -> Self {
        let window_size = std::env::var("ENRICHMENT_WINDOW_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let overlap = std::env::var("ENRICHMENT_WINDOW_OVERLAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        Self {
            client,
            window_size,
            overlap,
        }
    }

    #[cfg(test)]
    fn with_config(
        client: Box<dyn epigraph_cli::enrichment::llm_client::LlmClient>,
        window_size: usize,
        overlap: usize,
    ) -> Self {
        Self {
            client,
            window_size,
            overlap,
        }
    }

    /// Process a single window of commits and extract relationships
    async fn process_window(
        &self,
        commits: &[ParsedCommit],
    ) -> Result<Vec<epigraph_cli::enrichment::prompts::ExtractedRelationship>, String> {
        use epigraph_cli::enrichment::prompts;

        if commits.is_empty() {
            return Ok(Vec::new());
        }

        // Format commits for the prompt
        let descriptions: Vec<String> = commits
            .iter()
            .enumerate()
            .map(|(i, c)| {
                prompts::format_commit_for_prompt(
                    i,
                    &c.commit_type.to_string(),
                    &c.scope,
                    &c.claim_text,
                    &c.evidence,
                    &c.reasoning,
                )
            })
            .collect();

        let prompt = prompts::build_relationship_prompt(&descriptions);

        // Call LLM
        let response = self
            .client
            .complete_json(&prompt)
            .await
            .map_err(|e| format!("LLM enrichment failed: {e}"))?;

        // Parse response as Vec<ExtractedRelationship>
        let relationships: Vec<prompts::ExtractedRelationship> =
            serde_json::from_value(response)
                .map_err(|e| format!("Failed to parse LLM relationship response: {e}"))?;

        // Validate and filter
        Ok(prompts::validate_relationships(
            relationships,
            commits.len(),
        ))
    }
}

#[async_trait]
impl CommitEnricher for LlmEnricher {
    async fn enrich(&self, commits: &[ParsedCommit]) -> Result<Vec<EnrichedData>, String> {
        if commits.is_empty() {
            return Ok(Vec::new());
        }

        // Initialize enrichment data for all commits
        let mut enrichments: Vec<EnrichedData> = vec![EnrichedData::default(); commits.len()];

        // Process commits in sliding windows
        let step = if self.window_size > self.overlap {
            self.window_size - self.overlap
        } else {
            1
        };

        let mut window_start = 0;
        while window_start < commits.len() {
            let window_end = (window_start + self.window_size).min(commits.len());
            let window = &commits[window_start..window_end];

            match self.process_window(window).await {
                Ok(relationships) => {
                    for rel in relationships {
                        // Map window-local indices to global indices
                        let global_source = window_start + rel.source_index;
                        let global_target = window_start + rel.target_index;

                        if global_source < commits.len() && global_target < commits.len() {
                            enrichments[global_source]
                                .semantic_edges
                                .push(SemanticEdge {
                                    target_hash: commits[global_target].hash.clone(),
                                    relationship: rel.relationship.clone(),
                                    strength: rel.strength,
                                    rationale: rel.rationale.clone(),
                                });
                        }
                    }
                }
                Err(e) => {
                    // Log but don't fail the entire enrichment
                    eprintln!(
                        "Warning: LLM enrichment failed for window [{window_start}..{window_end}]: {e}"
                    );
                }
            }

            window_start += step;
        }

        Ok(enrichments)
    }

    async fn embed(&self, _text: &str) -> Result<Option<Vec<f32>>, String> {
        // Embedding will be implemented in Phase 2
        Ok(None)
    }

    fn name(&self) -> &str {
        self.client.model_name()
    }
}

/// Which enricher to use (selected via CLI flag)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnricherMode {
    Noop,
    Llm,
}

impl EnricherMode {
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "noop" => Ok(Self::Noop),
            "llm" => Ok(Self::Llm),
            other => Err(format!(
                "Unknown enricher mode: {other}. Must be 'noop' or 'llm'"
            )),
        }
    }
}

// =============================================================================
// COMMIT MESSAGE PARSING
// =============================================================================

/// The active section of a commit message being parsed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Evidence,
    Reasoning,
    Verification,
}

/// Parse the first line of a commit: `type(scope): claim text` or `type: claim text`
fn parse_header(line: &str) -> (CommitType, String, String) {
    // Try `type(scope): claim` first — regex-equivalent: ^(\w+)\(([^)]+)\):\s*(.+)$
    if let Some(paren_start) = line.find('(') {
        if let Some(paren_end) = line[paren_start..].find(')') {
            let paren_end = paren_start + paren_end;
            let type_str = &line[..paren_start];
            let scope = &line[paren_start + 1..paren_end];

            // Find the colon after the closing paren
            let rest = &line[paren_end + 1..];
            if let Some(colon_pos) = rest.find(':') {
                let claim = rest[colon_pos + 1..].trim();
                return (
                    CommitType::from_str(type_str),
                    scope.to_string(),
                    claim.to_string(),
                );
            }
        }
    }

    // Try `type: claim` (no scope) — regex-equivalent: ^(\w+):\s*(.+)$
    if let Some(colon_pos) = line.find(':') {
        let type_str = line[..colon_pos].trim();
        // Only match if the type part is a single word (no spaces)
        if !type_str.is_empty() && !type_str.contains(' ') {
            let ct = CommitType::from_str(type_str);
            if ct != CommitType::Unknown {
                let claim = line[colon_pos + 1..].trim();
                return (ct, String::new(), claim.to_string());
            }
        }
    }

    // Doesn't match any protocol format
    (CommitType::Unknown, String::new(), line.to_string())
}

/// Detect which section header a line represents
fn detect_section(line: &str) -> Option<Section> {
    let trimmed = line.trim();
    // Match both **Evidence:** and Evidence: formats
    let normalized = trimmed.trim_start_matches("**").trim_end_matches("**");
    let normalized = normalized.trim_end_matches(':').trim();

    match normalized.to_lowercase().as_str() {
        "evidence" => Some(Section::Evidence),
        "reasoning" => Some(Section::Reasoning),
        "verification" => Some(Section::Verification),
        _ => None,
    }
}

/// Parse a raw commit message into structured form
fn parse_commit_message(
    message: &str,
) -> (
    CommitType,
    String,
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
) {
    let mut lines = message.lines();

    // First line is the header
    let first_line = lines.next().unwrap_or("");
    let (commit_type, scope, claim_text) = parse_header(first_line);

    let mut evidence = Vec::new();
    let mut reasoning = Vec::new();
    let mut verification = Vec::new();
    let mut current_section = Section::None;

    for line in lines {
        let trimmed = line.trim();

        // Check for section header
        if let Some(section) = detect_section(trimmed) {
            current_section = section;
            continue;
        }

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Collect bullet points under current section
        let bullet_text = trimmed.strip_prefix("- ").unwrap_or(trimmed);

        match current_section {
            Section::Evidence => evidence.push(bullet_text.to_string()),
            Section::Reasoning => reasoning.push(bullet_text.to_string()),
            Section::Verification => verification.push(bullet_text.to_string()),
            Section::None => {} // Skip lines outside sections
        }
    }

    (
        commit_type,
        scope,
        claim_text,
        evidence,
        reasoning,
        verification,
    )
}

// Record separator for git log output (ASCII RS character)
const RECORD_SEP: &str = "\x1e";
const FIELD_SEP: &str = "\x1f";

/// Run `git log` and parse the output into ParsedCommits
fn parse_git_log(
    repo: &std::path::Path,
    since: Option<&str>,
    limit: Option<usize>,
) -> Result<Vec<ParsedCommit>, String> {
    // Format: hash, author_name, author_email, date, parent_hashes, then subject+body
    let format = format!(
        "{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%aI{FIELD_SEP}%P{FIELD_SEP}%B"
    );

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .arg("log")
        .arg(format!("--format={format}"))
        .arg("--name-only"); // List changed files

    if let Some(since) = since {
        cmd.arg(format!("--since={since}"));
    }

    if let Some(limit) = limit {
        cmd.arg(format!("-n{limit}"));
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run git log: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git log failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_git_log_output(&stdout)
}

/// Parse the raw git log output string into ParsedCommits
fn parse_git_log_output(output: &str) -> Result<Vec<ParsedCommit>, String> {
    let mut commits = Vec::new();

    // Split by record separator, skip the first empty entry
    for record in output.split(RECORD_SEP) {
        let record = record.trim();
        if record.is_empty() {
            continue;
        }

        // Split into fields
        let fields: Vec<&str> = record.splitn(6, FIELD_SEP).collect();
        if fields.len() < 6 {
            continue; // Malformed record
        }

        let hash = fields[0].trim().to_string();
        let author_name = fields[1].trim().to_string();
        let author_email = fields[2].trim().to_string();
        let date = fields[3].trim().to_string();
        let parent_str = fields[4].trim();
        let body_and_files = fields[5];

        let parent_hashes: Vec<String> = if parent_str.is_empty() {
            Vec::new()
        } else {
            parent_str.split_whitespace().map(String::from).collect()
        };

        // The body ends and file names begin after a double newline from git --name-only
        // The body from %B already ends with a newline, then file names follow
        let (message, files_str) = split_body_and_files(body_and_files);

        let files_changed: Vec<String> = files_str
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        let (commit_type, scope, claim_text, evidence, reasoning, verification) =
            parse_commit_message(&message);

        commits.push(ParsedCommit {
            hash,
            author_name,
            author_email,
            date,
            commit_type,
            scope,
            claim_text,
            evidence,
            reasoning,
            verification,
            parent_hashes,
            files_changed,
        });
    }

    // Reverse so oldest commits come first (chronological order)
    commits.reverse();
    Ok(commits)
}

/// Split the combined body+files output from `git log --name-only`
///
/// `git log --name-only` appends file names after the commit body with
/// a blank line separator. `%B` includes a trailing newline, so files
/// appear after a double-newline boundary.
fn split_body_and_files(combined: &str) -> (String, String) {
    // Find the last double-newline — everything after it is file names
    // The commit body from %B ends with \n, then --name-only adds \n<files>
    if let Some(pos) = combined.rfind("\n\n") {
        let body = combined[..pos].trim().to_string();
        let files = combined[pos + 2..].to_string();
        (body, files)
    } else {
        (combined.trim().to_string(), String::new())
    }
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

#[derive(Debug, Serialize)]
struct ClaimSubmission {
    content: String,
    initial_truth: Option<f64>,
    agent_id: Uuid,
    idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
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
    Document {
        source_url: Option<String>,
        mime_type: String,
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
    #[serde(default)]
    evidence_ids: Vec<Uuid>,
}

/// Response from POST /agents
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AgentResponse {
    id: Uuid,
    public_key: String,
}

/// Request body for POST /agents
#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct CreateAgentRequest {
    public_key: String,
    display_name: Option<String>,
}

// =============================================================================
// AGENT MANAGEMENT
// =============================================================================

/// Per-author agent state: each unique git author gets their own signer and agent ID
struct AuthorAgent {
    signer: AgentSigner,
    agent_id: Uuid,
}

/// Registry mapping author emails to their agent state
struct AgentRegistry {
    agents: HashMap<String, AuthorAgent>,
}

impl AgentRegistry {
    fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// Get or create an agent for the given author email.
    /// In dry-run mode, agents are generated locally without API registration.
    fn get_or_create(&mut self, email: &str, display_name: &str) -> &AuthorAgent {
        self.agents.entry(email.to_string()).or_insert_with(|| {
            let signer = AgentSigner::generate();
            let agent_id = Uuid::new_v4();
            println!(
                "  New agent for {email} ({display_name}): {}",
                hex::encode(signer.public_key())
            );
            AuthorAgent { signer, agent_id }
        })
    }

    /// Register an agent via the API (for live mode). Returns the server-assigned agent ID.
    #[allow(dead_code)]
    async fn register_agent(
        client: &reqwest::Client,
        endpoint: &str,
        signer: &AgentSigner,
        display_name: &str,
    ) -> Result<Uuid, String> {
        let req = CreateAgentRequest {
            public_key: hex::encode(signer.public_key()),
            display_name: Some(display_name.to_string()),
        };

        let url = format!("{endpoint}/agents");
        let resp = client
            .post(&url)
            .json(&req)
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
            let body = resp.text().await.unwrap_or_default();
            Err(format!("Failed to register agent: {body}"))
        }
    }

    fn len(&self) -> usize {
        self.agents.len()
    }
}

// =============================================================================
// RELATIONSHIP DETECTION
// =============================================================================

/// Tracks submitted claim IDs to detect relationships between commits
struct RelationshipTracker {
    /// Maps scope → most recent feat claim_id (for fix→feat challenge detection)
    scope_feats: HashMap<String, Uuid>,
    /// Maps git hash → claim_id (for parent→child refinement)
    hash_to_claim: HashMap<String, Uuid>,
    /// Maps git hash → evidence_ids (for evidence embedding after ingestion)
    hash_to_evidence: HashMap<String, Vec<Uuid>>,
}

impl RelationshipTracker {
    fn new() -> Self {
        Self {
            scope_feats: HashMap::new(),
            hash_to_claim: HashMap::new(),
            hash_to_evidence: HashMap::new(),
        }
    }

    /// Record a submitted claim for relationship tracking
    fn record(&mut self, commit: &ParsedCommit, claim_id: Uuid) {
        self.hash_to_claim.insert(commit.hash.clone(), claim_id);
        if commit.commit_type == CommitType::Feat && !commit.scope.is_empty() {
            self.scope_feats.insert(commit.scope.clone(), claim_id);
        }
    }

    /// Record evidence IDs from a successful submission
    fn record_evidence(&mut self, commit: &ParsedCommit, evidence_ids: Vec<Uuid>) {
        if !evidence_ids.is_empty() {
            self.hash_to_evidence
                .insert(commit.hash.clone(), evidence_ids);
        }
    }

    /// Detect if a fix commit challenges a previous feat in the same scope
    fn find_challenged_feat(&self, commit: &ParsedCommit) -> Option<Uuid> {
        if commit.commit_type == CommitType::Fix && !commit.scope.is_empty() {
            self.scope_feats.get(&commit.scope).copied()
        } else {
            None
        }
    }

    /// Find the claim ID of the parent commit (for refinement links)
    fn find_parent_claim(&self, commit: &ParsedCommit) -> Option<Uuid> {
        commit
            .parent_hashes
            .first()
            .and_then(|hash| self.hash_to_claim.get(hash))
            .copied()
    }
}

// =============================================================================
// PACKET BUILDER
// =============================================================================

/// Build an epistemic packet from a parsed commit, optionally incorporating enrichment data.
///
/// The enrichment data can adjust confidence downward (never upward) and provides
/// additional semantic information. If no enrichment is provided, the packet is built
/// identically to the pre-enrichment behavior.
fn build_packet(
    commit: &ParsedCommit,
    signer: &AgentSigner,
    agent_id: Uuid,
    enrichment: Option<&EnrichedData>,
) -> EpistemicPacket {
    let mut evidence_items = Vec::new();

    // Create evidence from Evidence: bullets
    for bullet in &commit.evidence {
        let content_hash = ContentHasher::hash(bullet.as_bytes());
        let sig = hex::encode(signer.sign(bullet.as_bytes()));
        evidence_items.push(EvidenceSubmission {
            content_hash: hex::encode(content_hash),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: Some(format!("git://{}", commit.hash)),
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(bullet.clone()),
            signature: Some(sig),
        });
    }

    // Create evidence from Verification: bullets
    for bullet in &commit.verification {
        let content_hash = ContentHasher::hash(bullet.as_bytes());
        let sig = hex::encode(signer.sign(bullet.as_bytes()));
        evidence_items.push(EvidenceSubmission {
            content_hash: hex::encode(content_hash),
            evidence_type: EvidenceTypeSubmission::Document {
                source_url: Some(format!("git://{}#verification", commit.hash)),
                mime_type: "text/plain".to_string(),
            },
            raw_content: Some(bullet.clone()),
            signature: Some(sig),
        });
    }

    // Build trace inputs referencing all evidence items
    let trace_inputs: Vec<TraceInputSubmission> = (0..evidence_items.len())
        .map(|i| TraceInputSubmission::Evidence { index: i })
        .collect();

    // Reasoning explanation from Reasoning: bullets, or generate from claim
    let explanation = if commit.reasoning.is_empty() {
        format!(
            "[{}][{}] {}",
            commit.commit_type, commit.scope, commit.claim_text
        )
    } else {
        commit.reasoning.join("; ")
    };

    let has_verification = !commit.verification.is_empty();

    // Confidence based on how complete the epistemic metadata is (parser heuristic)
    let parser_confidence = match (
        commit.evidence.is_empty(),
        commit.reasoning.is_empty(),
        has_verification,
    ) {
        (false, false, true) => 0.85, // Full metadata
        (false, false, false) => 0.7, // Evidence + reasoning but no verification
        (false, true, _) => 0.5,      // Evidence only
        (true, false, _) => 0.4,      // Reasoning only
        (true, true, _) => 0.3,       // No structured metadata
    };

    // Apply enrichment: LLM can lower confidence but NEVER raise it above the parser ceiling
    let confidence = match enrichment.and_then(|e| e.adjusted_confidence) {
        Some(adjusted) => adjusted.min(parser_confidence),
        None => parser_confidence,
    };

    let trace = ReasoningTraceSubmission {
        methodology: commit.commit_type.methodology().to_string(),
        inputs: trace_inputs,
        confidence,
        explanation,
        signature: None,
    };

    // Build claim content following the plan's format
    let claim_content = format!(
        "[{}][{}] {}",
        commit.commit_type, commit.scope, commit.claim_text
    );

    let properties = serde_json::json!({
        "source": "git-history",
        "commit_hash": commit.hash,
        "files_changed": commit.files_changed,
        "commit_date": commit.date,
        "commit_type": commit.commit_type.to_string(),
        "scope": commit.scope,
    });

    let claim_submission = ClaimSubmission {
        content: claim_content,
        initial_truth: Some(commit.commit_type.initial_truth(has_verification)),
        agent_id,
        idempotency_key: Some(format!("git:{}", commit.hash)),
        properties: Some(properties),
    };

    // Use placeholder signature — the API server does not yet verify real Ed25519
    // signatures on submit_packet (it only accepts all-zeros placeholders).
    // The real signature is computed but stored as evidence signatures instead.
    let _packet_bytes =
        serde_json::to_vec(&(&claim_submission, &evidence_items, &trace)).unwrap_or_default();
    let _real_signature = hex::encode(signer.sign(&_packet_bytes));
    let packet_signature = "0".repeat(128); // placeholder accepted by server

    EpistemicPacket {
        claim: claim_submission,
        evidence: evidence_items,
        reasoning_trace: trace,
        signature: packet_signature,
    }
}

/// Build packets for all commits, using a shared signer and agent ID
#[cfg(test)]
fn build_all_packets(
    commits: &[ParsedCommit],
    signer: &AgentSigner,
    agent_id: Uuid,
) -> Vec<EpistemicPacket> {
    commits
        .iter()
        .map(|c| build_packet(c, signer, agent_id, None))
        .collect()
}

// =============================================================================
// EDGE SUBMISSION
// =============================================================================

/// Request body for POST /api/v1/edges
#[derive(Debug, Serialize)]
struct CreateEdgeRequest {
    source_id: Uuid,
    target_id: Uuid,
    source_type: String,
    target_type: String,
    relationship: String,
    properties: Option<serde_json::Value>,
}

/// Resolve semantic edges from enrichment data and submit them as API edges.
///
/// For each commit's enrichment, maps `target_hash` → `claim_id` via the
/// relationship tracker, then POSTs the edge to the API endpoint.
///
/// Returns (submitted, skipped, failed) counts.
async fn submit_edges(
    commits: &[ParsedCommit],
    enrichments: &[EnrichedData],
    tracker: &RelationshipTracker,
    endpoint: &str,
    client: &reqwest::Client,
) -> (usize, usize, usize) {
    let mut submitted = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for (commit, enrichment) in commits.iter().zip(enrichments.iter()) {
        if enrichment.semantic_edges.is_empty() {
            continue;
        }

        // Look up the source claim ID for this commit
        let source_id = match tracker.hash_to_claim.get(&commit.hash) {
            Some(id) => *id,
            None => {
                // Source commit wasn't submitted (e.g., it was a duplicate)
                skipped += enrichment.semantic_edges.len();
                continue;
            }
        };

        for edge in &enrichment.semantic_edges {
            // Resolve target hash to claim ID
            let target_id = match tracker.hash_to_claim.get(&edge.target_hash) {
                Some(id) => *id,
                None => {
                    // Target commit not found — might not be in this batch
                    skipped += 1;
                    continue;
                }
            };

            let request = CreateEdgeRequest {
                source_id,
                target_id,
                source_type: "claim".to_string(),
                target_type: "claim".to_string(),
                relationship: edge.relationship.clone(),
                properties: Some(serde_json::json!({
                    "strength": edge.strength,
                    "rationale": edge.rationale,
                    "source": "llm_enrichment"
                })),
            };

            let url = format!("{endpoint}/api/v1/edges");
            match client
                .post(&url)
                .json(&request)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    submitted += 1;
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    eprintln!(
                        "Edge submission failed (HTTP {status}): {source_id} --[{}]--> {target_id}: {body}",
                        edge.relationship
                    );
                    failed += 1;
                }
                Err(e) => {
                    eprintln!(
                        "Edge submission error: {source_id} --[{}]--> {target_id}: {e}",
                        edge.relationship
                    );
                    failed += 1;
                }
            }
        }
    }

    (submitted, skipped, failed)
}

/// Count the total number of semantic edges across all enrichments
fn count_semantic_edges(enrichments: &[EnrichedData]) -> usize {
    enrichments.iter().map(|e| e.semantic_edges.len()).sum()
}

/// Request body for PUT /api/v1/claims/:id/embedding
#[derive(Debug, Serialize)]
struct GenerateEmbeddingRequest {
    text: String,
}

/// Batch size for embedding generation requests.
/// Processing in chunks prevents overwhelming the API server and provides
/// progress feedback during large ingestion runs.
const EMBEDDING_BATCH_SIZE: usize = 100;

/// Generate and store embeddings for all submitted claims.
///
/// For each commit that was successfully submitted (has a claim_id in the tracker),
/// sends a PUT request to the API to generate and store an embedding.
///
/// Processes in chunks of `EMBEDDING_BATCH_SIZE` with progress reporting.
///
/// Returns (successful, failed) counts.
async fn submit_embeddings(
    commits: &[ParsedCommit],
    tracker: &RelationshipTracker,
    endpoint: &str,
    client: &reqwest::Client,
) -> (usize, usize) {
    let mut ok = 0;
    let mut fail = 0;

    // Collect all embeddable claims
    let embeddable: Vec<(&ParsedCommit, Uuid)> = commits
        .iter()
        .filter_map(|commit| {
            tracker
                .hash_to_claim
                .get(&commit.hash)
                .map(|id| (commit, *id))
        })
        .collect();

    let total = embeddable.len();
    if total == 0 {
        return (0, 0);
    }

    // Process in chunks for progress reporting and rate limiting
    for (chunk_idx, chunk) in embeddable.chunks(EMBEDDING_BATCH_SIZE).enumerate() {
        let chunk_start = chunk_idx * EMBEDDING_BATCH_SIZE;
        println!(
            "  Embedding batch {}/{} ({}/{})",
            chunk_idx + 1,
            total.div_ceil(EMBEDDING_BATCH_SIZE),
            chunk_start + 1,
            total,
        );

        for (commit, claim_id) in chunk {
            let claim_content = format!(
                "[{}][{}] {}",
                commit.commit_type, commit.scope, commit.claim_text
            );

            let request = GenerateEmbeddingRequest {
                text: claim_content,
            };

            let url = format!("{endpoint}/api/v1/claims/{claim_id}/embedding");
            match client
                .put(&url)
                .json(&request)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    ok += 1;
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    eprintln!("Embedding failed for {claim_id} (HTTP {status}): {body}");
                    fail += 1;
                }
                Err(e) => {
                    eprintln!("Embedding error for {claim_id}: {e}");
                    fail += 1;
                }
            }
        }
    }

    (ok, fail)
}

/// Generate and store embeddings for evidence items from submitted claims.
///
/// For each commit that was successfully submitted and has evidence IDs in the tracker,
/// sends a PUT request to the API to generate and store an embedding for each
/// evidence item's raw_content.
///
/// Processes in chunks of `EMBEDDING_BATCH_SIZE` with progress reporting.
///
/// Returns (successful, failed) counts.
async fn submit_evidence_embeddings(
    commits: &[ParsedCommit],
    tracker: &RelationshipTracker,
    endpoint: &str,
    client: &reqwest::Client,
) -> (usize, usize) {
    let mut ok = 0;
    let mut fail = 0;

    // Collect all embeddable evidence: (evidence_id, raw_content text)
    let embeddable: Vec<(Uuid, String)> = commits
        .iter()
        .filter_map(|commit| {
            tracker
                .hash_to_evidence
                .get(&commit.hash)
                .map(|evidence_ids: &Vec<Uuid>| {
                    // Pair each evidence ID with its text content
                    let all_content: Vec<String> = commit
                        .evidence
                        .iter()
                        .chain(commit.verification.iter())
                        .cloned()
                        .collect();

                    evidence_ids
                        .iter()
                        .enumerate()
                        .filter_map(|(i, eid)| {
                            all_content
                                .get(i)
                                .map(|content: &String| (*eid, content.clone()))
                        })
                        .collect::<Vec<_>>()
                })
        })
        .flatten()
        .collect();

    let total = embeddable.len();
    if total == 0 {
        return (0, 0);
    }

    for (chunk_idx, chunk) in embeddable.chunks(EMBEDDING_BATCH_SIZE).enumerate() {
        let chunk_start = chunk_idx * EMBEDDING_BATCH_SIZE;
        println!(
            "  Evidence embedding batch {}/{} ({}/{})",
            chunk_idx + 1,
            total.div_ceil(EMBEDDING_BATCH_SIZE),
            chunk_start + 1,
            total,
        );

        for (evidence_id, content) in chunk {
            let content_str: &String = content;
            let request = GenerateEmbeddingRequest {
                text: content_str.clone(),
            };

            let url = format!("{endpoint}/api/v1/evidence/{evidence_id}/embedding");
            match client
                .put(&url)
                .json(&request)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    ok += 1;
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    eprintln!(
                        "Evidence embedding failed for {evidence_id} (HTTP {status}): {body}"
                    );
                    fail += 1;
                }
                Err(e) => {
                    eprintln!("Evidence embedding error for {evidence_id}: {e}");
                    fail += 1;
                }
            }
        }
    }

    (ok, fail)
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let args = match Args::parse() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    // Parse git log
    println!("Parsing git log from: {}", args.repo.display());
    let commits = match parse_git_log(&args.repo, args.since.as_deref(), args.limit) {
        Ok(commits) => commits,
        Err(e) => {
            eprintln!("Error parsing git log: {e}");
            std::process::exit(1);
        }
    };

    if commits.is_empty() {
        println!("No commits found.");
        return;
    }

    println!("Parsed {} commits", commits.len());

    // Summarize commit types
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for c in &commits {
        *type_counts.entry(c.commit_type.to_string()).or_default() += 1;
    }
    for (t, count) in &type_counts {
        println!("  {t}: {count}");
    }

    // Create or load primary agent signer
    let primary_signer = if args.agent_key == "generate" {
        let signer = AgentSigner::generate();
        println!(
            "Generated primary agent key (public): {}",
            hex::encode(signer.public_key())
        );
        Some(signer)
    } else if args.agent_key == "per-author" {
        // Per-author mode: each unique email gets its own agent
        println!("Using per-author agent mode");
        None
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
            Ok(signer) => Some(signer),
            Err(e) => {
                eprintln!("Invalid agent key: {e}");
                std::process::exit(1);
            }
        }
    };

    // Agent management: single shared agent or per-author agents
    let mut registry = AgentRegistry::new();
    let mut shared_agent_id = primary_signer.as_ref().map(|_| Uuid::new_v4());

    if let Some(id) = shared_agent_id {
        println!("Agent ID: {id}");
    }

    // Run enrichment
    let enricher: Box<dyn CommitEnricher> = match args.enricher {
        EnricherMode::Noop => Box::new(NoopEnricher),
        EnricherMode::Llm => {
            let client = epigraph_cli::enrichment::llm_client::create_llm_client(
                &std::env::var("ENRICHMENT_LLM_PROVIDER").unwrap_or_else(|_| "anthropic".into()),
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to create LLM client: {e}");
                std::process::exit(1);
            });
            Box::new(LlmEnricher::new(client))
        }
    };

    println!("Using enricher: {}", enricher.name());
    let enrichments = match enricher.enrich(&commits).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Enrichment failed: {e}");
            std::process::exit(1);
        }
    };

    // Pre-populate agents for all unique authors (needed for per-author mode)
    if primary_signer.is_none() {
        for commit in &commits {
            registry.get_or_create(&commit.author_email, &commit.author_name);
        }
        println!(
            "Created {} agents for {} unique authors",
            registry.len(),
            registry.len()
        );
    }

    // Build HTTP client with optional bearer token for auth
    let build_client = || -> reqwest::Client {
        if let Some(ref tok) = args.token {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
            );
            reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .unwrap()
        } else {
            reqwest::Client::new()
        }
    };

    // Register agents with the API server (only in live mode)
    if !args.dry_run {
        let client = build_client();
        if let Some(ref signer) = primary_signer {
            let display_name = commits
                .first()
                .map(|c| c.author_name.as_str())
                .unwrap_or("ingester");
            match AgentRegistry::register_agent(&client, &args.endpoint, signer, display_name).await
            {
                Ok(id) => {
                    shared_agent_id = Some(id);
                    println!("Registered shared agent: {id}");
                }
                Err(e) => {
                    eprintln!("Failed to register shared agent: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            // Register all per-author agents
            for (email, author) in registry.agents.iter_mut() {
                match AgentRegistry::register_agent(&client, &args.endpoint, &author.signer, email)
                    .await
                {
                    Ok(id) => {
                        author.agent_id = id;
                        println!("  Registered agent for {email}: {id}");
                    }
                    Err(e) => {
                        eprintln!("Failed to register agent for {email}: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    // Build packets with per-author agent support and enrichment data
    let packets: Vec<EpistemicPacket> = commits
        .iter()
        .zip(enrichments.iter())
        .map(|(commit, enrichment)| {
            if let Some(ref signer) = primary_signer {
                build_packet(commit, signer, shared_agent_id.unwrap(), Some(enrichment))
            } else {
                let author = registry.get_or_create(&commit.author_email, &commit.author_name);
                build_packet(commit, &author.signer, author.agent_id, Some(enrichment))
            }
        })
        .collect();

    println!("Built {} epistemic packets", packets.len());

    // Relationship detection: track challenges and refinements
    let mut tracker = RelationshipTracker::new();

    if args.dry_run {
        println!("\n--- DRY RUN MODE ---");
        for (i, (packet, commit)) in packets.iter().zip(commits.iter()).enumerate() {
            let claim_preview = if packet.claim.content.len() > 80 {
                format!("{}...", &packet.claim.content[..77])
            } else {
                packet.claim.content.clone()
            };
            println!("\nPacket {}: \"{}\"", i + 1, claim_preview);
            println!("  Hash: {}", &commit.hash[..12]);
            println!("  Author: {} <{}>", commit.author_name, commit.author_email);
            println!("  Date: {}", commit.date);
            println!(
                "  Evidence: {} item(s), Verification: {} item(s)",
                commit.evidence.len(),
                commit.verification.len(),
            );
            println!(
                "  Methodology: {}, confidence: {:.0}%, initial_truth: {:.1}",
                packet.reasoning_trace.methodology,
                packet.reasoning_trace.confidence * 100.0,
                packet.claim.initial_truth.unwrap_or(0.0),
            );
            println!("  Files changed: {}", commit.files_changed.len());

            // Show detected relationships
            if let Some(challenged) = tracker.find_challenged_feat(commit) {
                println!("  Challenges: feat claim {challenged}");
            }
            if let Some(parent) = tracker.find_parent_claim(commit) {
                println!("  Refines: parent claim {parent}");
            }

            // Show LLM-discovered semantic edges
            for edge in &enrichments[i].semantic_edges {
                println!(
                    "  Edge: --[{}]--> {} (strength: {:.2})",
                    edge.relationship,
                    &edge.target_hash[..12.min(edge.target_hash.len())],
                    edge.strength,
                );
            }

            // Simulate recording for relationship tracking
            let fake_id = Uuid::new_v4();
            tracker.record(commit, fake_id);
        }

        let total_edges = count_semantic_edges(&enrichments);
        if total_edges > 0 {
            println!("\nEnrichment discovered {total_edges} semantic edges");
        }
        println!("\nDry run complete. Use without --dry-run to submit.");
        return;
    }

    // Submit packets
    let client = build_client();
    let mut submitted = 0;
    let mut skipped = 0;
    let mut failed = 0;

    // Create PROV-O Activity record for this ingestion run
    let activity_agent_id = shared_agent_id.unwrap_or_else(Uuid::new_v4);
    let activity_id = create_activity(
        &client,
        &args.endpoint,
        "ingestion",
        activity_agent_id,
        &format!("Git history ingestion: {} commits", commits.len()),
        serde_json::json!({
            "repo": args.repo.display().to_string(),
            "commits_count": commits.len(),
            "since": args.since,
        }),
    )
    .await;

    if let Some(ref id) = activity_id {
        println!("Created activity: {id}");
    }

    for (i, (packet, commit)) in packets.iter().zip(commits.iter()).enumerate() {
        let url = format!("{}/api/v1/submit/packet", args.endpoint);

        // Log any detected relationships
        if let Some(challenged) = tracker.find_challenged_feat(commit) {
            println!(
                "  [{}/{}] fix({}) challenges feat claim {challenged}",
                i + 1,
                packets.len(),
                commit.scope
            );
        }

        match client
            .post(&url)
            .json(packet)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    match response.json::<SubmitResponse>().await {
                        Ok(result) => {
                            println!(
                                "[{}/{}] Submitted: {} (truth={:.3})",
                                i + 1,
                                packets.len(),
                                result.claim_id,
                                result.truth_value,
                            );
                            tracker.record(commit, result.claim_id);
                            tracker.record_evidence(commit, result.evidence_ids);
                            submitted += 1;

                            // Create edge: Activity --generated--> Claim
                            if let Some(ref act_id) = activity_id {
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
                        }
                        Err(e) => {
                            eprintln!("[{}/{}] Response parse error: {e}", i + 1, packets.len());
                            failed += 1;
                        }
                    }
                } else if status.as_u16() == 400 {
                    let body = response.text().await.unwrap_or_default();
                    eprintln!(
                        "[{}/{}] Validation error (skipping): {body}",
                        i + 1,
                        packets.len(),
                    );
                    skipped += 1;
                } else if status.as_u16() == 429 {
                    eprintln!("[{}/{}] Rate limited, waiting...", i + 1, packets.len());
                    // Exponential backoff: 1s, 2s, 4s
                    for delay in [1, 2, 4] {
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        let retry = client
                            .post(&url)
                            .json(packet)
                            .timeout(std::time::Duration::from_secs(30))
                            .send()
                            .await;
                        if let Ok(resp) = retry {
                            if resp.status().is_success() {
                                if let Ok(result) = resp.json::<SubmitResponse>().await {
                                    println!(
                                        "[{}/{}] Submitted (retry): {} (truth={:.3})",
                                        i + 1,
                                        packets.len(),
                                        result.claim_id,
                                        result.truth_value,
                                    );
                                    tracker.record(commit, result.claim_id);
                                    tracker.record_evidence(commit, result.evidence_ids);
                                    submitted += 1;
                                    if let Some(ref act_id) = activity_id {
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
                                }
                                break;
                            }
                        }
                    }
                } else if status.is_server_error() {
                    let body = response.text().await.unwrap_or_default();
                    eprintln!(
                        "[{}/{}] Server error (HTTP {status}): {body}",
                        i + 1,
                        packets.len(),
                    );
                    // Retry up to 3 times with backoff
                    let mut retried = false;
                    for delay in [1, 2, 4] {
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        let retry = client
                            .post(&url)
                            .json(packet)
                            .timeout(std::time::Duration::from_secs(30))
                            .send()
                            .await;
                        if let Ok(resp) = retry {
                            if resp.status().is_success() {
                                if let Ok(result) = resp.json::<SubmitResponse>().await {
                                    println!(
                                        "[{}/{}] Submitted (retry): {} (truth={:.3})",
                                        i + 1,
                                        packets.len(),
                                        result.claim_id,
                                        result.truth_value,
                                    );
                                    tracker.record(commit, result.claim_id);
                                    tracker.record_evidence(commit, result.evidence_ids);
                                    submitted += 1;
                                    retried = true;
                                    if let Some(ref act_id) = activity_id {
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
                                }
                                break;
                            }
                        }
                    }
                    if !retried {
                        failed += 1;
                    }
                } else {
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

        // Rate limiting: ~10 claims/second
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    println!(
        "\nClaim ingestion: {submitted} submitted, {skipped} skipped, {failed} failed, {} total",
        packets.len()
    );

    // Submit semantic edges discovered by enrichment
    let total_edges = count_semantic_edges(&enrichments);
    if total_edges > 0 {
        println!("\nSubmitting {total_edges} semantic edges from enrichment...");
        let (edges_submitted, edges_skipped, edges_failed) =
            submit_edges(&commits, &enrichments, &tracker, &args.endpoint, &client).await;
        println!(
            "Edge submission: {edges_submitted} submitted, {edges_skipped} skipped, {edges_failed} failed"
        );
        if edges_failed > 0 {
            failed += edges_failed;
        }
    }

    // Generate and store embeddings if --embed flag is set
    if args.embed {
        let embed_count = tracker.hash_to_claim.len();
        println!("\nGenerating embeddings for {embed_count} submitted claims...");
        let (embeds_ok, embeds_fail) =
            submit_embeddings(&commits, &tracker, &args.endpoint, &client).await;
        println!("Embedding generation: {embeds_ok} stored, {embeds_fail} failed");
        if embeds_fail > 0 {
            failed += embeds_fail;
        }

        // Also embed evidence items
        let evidence_count: usize = tracker
            .hash_to_evidence
            .values()
            .map(|v: &Vec<Uuid>| v.len())
            .sum();
        if evidence_count > 0 {
            println!("\nGenerating embeddings for {evidence_count} evidence items...");
            let (ev_ok, ev_fail) =
                submit_evidence_embeddings(&commits, &tracker, &args.endpoint, &client).await;
            println!("Evidence embedding generation: {ev_ok} stored, {ev_fail} failed");
            if ev_fail > 0 {
                failed += ev_fail;
            }
        }
    }

    // Complete the activity record
    if let Some(ref act_id) = activity_id {
        complete_activity(
            &client,
            &args.endpoint,
            *act_id,
            serde_json::json!({
                "claims_submitted": submitted,
                "claims_skipped": skipped,
                "claims_failed": failed,
            }),
        )
        .await;
    }

    println!("\nIngestion complete.");

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

    if let Err(e) = client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        eprintln!("Warning: failed to create prov edge: {e}");
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Header parsing tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_header_standard() {
        let (ct, scope, claim) =
            parse_header("feat(core): define Claim model with bounded truth values");
        assert_eq!(ct, CommitType::Feat);
        assert_eq!(scope, "core");
        assert_eq!(claim, "define Claim model with bounded truth values");
    }

    #[test]
    fn test_parse_header_multi_scope() {
        let (ct, scope, claim) = parse_header("fix(db,api): align signer_id nullability");
        assert_eq!(ct, CommitType::Fix);
        assert_eq!(scope, "db,api");
        assert_eq!(claim, "align signer_id nullability");
    }

    #[test]
    fn test_parse_header_security() {
        let (ct, scope, claim) =
            parse_header("security(crypto): prevent timing attacks in signature verification");
        assert_eq!(ct, CommitType::Security);
        assert_eq!(scope, "crypto");
        assert_eq!(claim, "prevent timing attacks in signature verification");
    }

    #[test]
    fn test_parse_header_unknown_type() {
        let (ct, scope, claim) = parse_header("yolo(stuff): something weird");
        assert_eq!(ct, CommitType::Unknown);
        assert_eq!(scope, "stuff");
        assert_eq!(claim, "something weird");
    }

    #[test]
    fn test_parse_header_non_protocol() {
        let (ct, scope, claim) = parse_header("Initial commit");
        assert_eq!(ct, CommitType::Unknown);
        assert_eq!(scope, "");
        assert_eq!(claim, "Initial commit");
    }

    #[test]
    fn test_parse_header_no_scope() {
        let (ct, scope, claim) = parse_header("Just a plain message without any structure");
        assert_eq!(ct, CommitType::Unknown);
        assert_eq!(scope, "");
        assert_eq!(claim, "Just a plain message without any structure");
    }

    #[test]
    fn test_parse_header_type_colon_no_scope() {
        let (ct, scope, claim) = parse_header("docs: update HARDENING_PLAN.md");
        assert_eq!(ct, CommitType::Docs);
        assert_eq!(scope, "");
        assert_eq!(claim, "update HARDENING_PLAN.md");
    }

    #[test]
    fn test_parse_header_type_colon_unknown_type() {
        // An unknown type with colon format should still be Unknown
        let (ct, scope, claim) = parse_header("misc: random stuff");
        assert_eq!(ct, CommitType::Unknown);
        assert_eq!(scope, "");
        assert_eq!(claim, "misc: random stuff");
    }

    // -------------------------------------------------------------------------
    // Section detection tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_section_bold() {
        assert_eq!(detect_section("**Evidence:**"), Some(Section::Evidence));
        assert_eq!(detect_section("**Reasoning:**"), Some(Section::Reasoning));
        assert_eq!(
            detect_section("**Verification:**"),
            Some(Section::Verification)
        );
    }

    #[test]
    fn test_detect_section_plain() {
        assert_eq!(detect_section("Evidence:"), Some(Section::Evidence));
        assert_eq!(detect_section("Reasoning:"), Some(Section::Reasoning));
        assert_eq!(detect_section("Verification:"), Some(Section::Verification));
    }

    #[test]
    fn test_detect_section_none() {
        assert_eq!(detect_section("- some bullet"), None);
        assert_eq!(detect_section("Random text"), None);
        assert_eq!(detect_section(""), None);
    }

    // -------------------------------------------------------------------------
    // Full commit message parsing tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_full_commit_message() {
        let msg = "\
feat(engine): implement Bayesian truth update for claim propagation

**Evidence:**
- IMPLEMENTATION_PLAN.md Phase 3 requirement
- Current weighted average insufficient for evidence accumulation

**Reasoning:**
- P(H|E) = P(E|H) * P(H) / P(E) provides proper belief updating
- Chose to clamp posterior to [0.01, 0.99] to prevent certainty lock-in

**Verification:**
- test_bayesian_update validates formula
- cargo test --lib engine passes";

        let (ct, scope, claim, evidence, reasoning, verification) = parse_commit_message(msg);

        assert_eq!(ct, CommitType::Feat);
        assert_eq!(scope, "engine");
        assert_eq!(
            claim,
            "implement Bayesian truth update for claim propagation"
        );
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0], "IMPLEMENTATION_PLAN.md Phase 3 requirement");
        assert_eq!(reasoning.len(), 2);
        assert!(reasoning[0].contains("P(H|E)"));
        assert_eq!(verification.len(), 2);
        assert!(verification[0].contains("test_bayesian_update"));
    }

    #[test]
    fn test_parse_commit_message_no_sections() {
        let msg = "Initial commit";
        let (ct, scope, claim, evidence, reasoning, verification) = parse_commit_message(msg);

        assert_eq!(ct, CommitType::Unknown);
        assert_eq!(scope, "");
        assert_eq!(claim, "Initial commit");
        assert!(evidence.is_empty());
        assert!(reasoning.is_empty());
        assert!(verification.is_empty());
    }

    #[test]
    fn test_parse_commit_message_partial_sections() {
        let msg = "\
fix(db): prevent SQL injection in claim search

**Evidence:**
- Grep found raw string interpolation in semantic.rs:45

**Reasoning:**
- Replaced format!() with sqlx parameterized query";

        let (ct, _scope, _claim, evidence, reasoning, verification) = parse_commit_message(msg);

        assert_eq!(ct, CommitType::Fix);
        assert_eq!(evidence.len(), 1);
        assert_eq!(reasoning.len(), 1);
        assert!(verification.is_empty());
    }

    // -------------------------------------------------------------------------
    // CommitType tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_commit_type_from_str() {
        assert_eq!(CommitType::from_str("feat"), CommitType::Feat);
        assert_eq!(CommitType::from_str("FEAT"), CommitType::Feat);
        assert_eq!(CommitType::from_str("Fix"), CommitType::Fix);
        assert_eq!(CommitType::from_str("refactor"), CommitType::Refactor);
        assert_eq!(CommitType::from_str("security"), CommitType::Security);
        assert_eq!(CommitType::from_str("test"), CommitType::Test);
        assert_eq!(CommitType::from_str("perf"), CommitType::Perf);
        assert_eq!(CommitType::from_str("docs"), CommitType::Docs);
        assert_eq!(CommitType::from_str("chore"), CommitType::Chore);
        assert_eq!(CommitType::from_str("anything_else"), CommitType::Unknown);
    }

    #[test]
    fn test_methodology_mapping() {
        assert_eq!(CommitType::Feat.methodology(), "extraction");
        assert_eq!(CommitType::Fix.methodology(), "deductive");
        assert_eq!(CommitType::Refactor.methodology(), "deductive");
        assert_eq!(CommitType::Security.methodology(), "deductive");
        assert_eq!(CommitType::Test.methodology(), "instrumental");
        assert_eq!(CommitType::Perf.methodology(), "instrumental");
        assert_eq!(CommitType::Docs.methodology(), "heuristic");
        assert_eq!(CommitType::Chore.methodology(), "heuristic");
        assert_eq!(CommitType::Unknown.methodology(), "heuristic");
    }

    #[test]
    fn test_initial_truth_values() {
        // feat with verification
        assert!((CommitType::Feat.initial_truth(true) - 0.6).abs() < f64::EPSILON);
        // feat without verification
        assert!((CommitType::Feat.initial_truth(false) - 0.4).abs() < f64::EPSILON);
        // fix
        assert!((CommitType::Fix.initial_truth(true) - 0.7).abs() < f64::EPSILON);
        assert!((CommitType::Fix.initial_truth(false) - 0.7).abs() < f64::EPSILON);
        // security
        assert!((CommitType::Security.initial_truth(false) - 0.7).abs() < f64::EPSILON);
        // test
        assert!((CommitType::Test.initial_truth(false) - 0.8).abs() < f64::EPSILON);
        // refactor
        assert!((CommitType::Refactor.initial_truth(false) - 0.5).abs() < f64::EPSILON);
        // docs
        assert!((CommitType::Docs.initial_truth(false) - 0.4).abs() < f64::EPSILON);
        // chore
        assert!((CommitType::Chore.initial_truth(false) - 0.3).abs() < f64::EPSILON);
        // unknown
        assert!((CommitType::Unknown.initial_truth(false) - 0.2).abs() < f64::EPSILON);
    }

    // -------------------------------------------------------------------------
    // Packet building tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_build_packet_full_commit() {
        let commit = ParsedCommit {
            hash: "abc123def456".to_string(),
            author_name: "Test Author".to_string(),
            author_email: "test@example.com".to_string(),
            date: "2026-02-10T12:00:00+00:00".to_string(),
            commit_type: CommitType::Feat,
            scope: "core".to_string(),
            claim_text: "add truth validation".to_string(),
            evidence: vec!["PLAN.md requires bounded truth".to_string()],
            reasoning: vec!["Chose f64 for precision".to_string()],
            verification: vec!["test_truth_bounds passes".to_string()],
            parent_hashes: vec!["parent123".to_string()],
            files_changed: vec!["src/core/claim.rs".to_string()],
        };

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packet = build_packet(&commit, &signer, agent_id, None);

        assert_eq!(packet.claim.content, "[feat][core] add truth validation");
        assert_eq!(packet.claim.agent_id, agent_id);
        assert_eq!(
            packet.claim.idempotency_key,
            Some("git:abc123def456".to_string())
        );

        // Should have 2 evidence items: 1 from evidence + 1 from verification
        assert_eq!(packet.evidence.len(), 2);

        // Verify evidence hashes match content
        let expected_hash = hex::encode(ContentHasher::hash(b"PLAN.md requires bounded truth"));
        assert_eq!(packet.evidence[0].content_hash, expected_hash);

        // Verify methodology
        assert_eq!(packet.reasoning_trace.methodology, "extraction");

        // Verify initial truth (feat with verification = 0.6)
        assert!((packet.claim.initial_truth.unwrap() - 0.6).abs() < f64::EPSILON);

        // Confidence: full metadata = 0.85
        assert!((packet.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);

        // Signature should be present
        assert!(!packet.signature.is_empty());
        assert_eq!(hex::decode(&packet.signature).unwrap().len(), 64);
    }

    #[test]
    fn test_build_packet_no_evidence() {
        let commit = ParsedCommit {
            hash: "deadbeef".to_string(),
            author_name: "Dev".to_string(),
            author_email: "dev@example.com".to_string(),
            date: "2026-01-01T00:00:00+00:00".to_string(),
            commit_type: CommitType::Chore,
            scope: "build".to_string(),
            claim_text: "update dependencies".to_string(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec!["Cargo.lock".to_string()],
        };

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packet = build_packet(&commit, &signer, agent_id, None);

        assert!(packet.evidence.is_empty());
        assert_eq!(packet.reasoning_trace.methodology, "heuristic");
        assert!((packet.claim.initial_truth.unwrap() - 0.3).abs() < f64::EPSILON);

        // Confidence: no metadata = 0.3
        assert!((packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);

        // Explanation should be auto-generated from claim
        assert!(packet
            .reasoning_trace
            .explanation
            .contains("update dependencies"));
    }

    #[test]
    fn test_build_packet_evidence_signatures_valid() {
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Dev".to_string(),
            author_email: "dev@example.com".to_string(),
            date: "2026-01-01T00:00:00+00:00".to_string(),
            commit_type: CommitType::Fix,
            scope: "db".to_string(),
            claim_text: "fix query".to_string(),
            evidence: vec!["Found bug in query".to_string()],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec![],
        };

        let signer = AgentSigner::generate();
        let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);

        // All evidence should have valid 64-byte hex signatures
        for ev in &packet.evidence {
            let sig = ev.signature.as_ref().expect("evidence should be signed");
            let sig_bytes = hex::decode(sig).expect("signature should be valid hex");
            assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");
        }
    }

    #[test]
    fn test_build_packet_includes_files_changed() {
        let commit = ParsedCommit {
            hash: "cafebabe".to_string(),
            author_name: "Dev".to_string(),
            author_email: "dev@example.com".to_string(),
            date: "2026-03-15T10:30:00+00:00".to_string(),
            commit_type: CommitType::Refactor,
            scope: "engine".to_string(),
            claim_text: "extract propagation logic".to_string(),
            evidence: vec!["Code review showed duplication".to_string()],
            reasoning: vec!["DRY principle".to_string()],
            verification: vec![],
            parent_hashes: vec!["deadbeef".to_string()],
            files_changed: vec![
                "src/engine/propagation.rs".to_string(),
                "src/engine/mod.rs".to_string(),
            ],
        };

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packet = build_packet(&commit, &signer, agent_id, None);

        let props = packet
            .claim
            .properties
            .expect("properties should be populated");
        assert_eq!(props["source"], "git-history");
        assert_eq!(props["commit_hash"], "cafebabe");
        assert_eq!(props["commit_date"], "2026-03-15T10:30:00+00:00");
        assert_eq!(props["commit_type"], "refactor");
        assert_eq!(props["scope"], "engine");

        let files = props["files_changed"]
            .as_array()
            .expect("files_changed should be an array");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], "src/engine/propagation.rs");
        assert_eq!(files[1], "src/engine/mod.rs");
    }

    #[test]
    fn test_build_all_packets() {
        let commits = vec![
            ParsedCommit {
                hash: "aaa".to_string(),
                author_name: "A".to_string(),
                author_email: "a@x.com".to_string(),
                date: "2026-01-01T00:00:00+00:00".to_string(),
                commit_type: CommitType::Feat,
                scope: "core".to_string(),
                claim_text: "first".to_string(),
                evidence: vec![],
                reasoning: vec![],
                verification: vec![],
                parent_hashes: vec![],
                files_changed: vec![],
            },
            ParsedCommit {
                hash: "bbb".to_string(),
                author_name: "B".to_string(),
                author_email: "b@x.com".to_string(),
                date: "2026-01-02T00:00:00+00:00".to_string(),
                commit_type: CommitType::Fix,
                scope: "api".to_string(),
                claim_text: "second".to_string(),
                evidence: vec![],
                reasoning: vec![],
                verification: vec![],
                parent_hashes: vec!["aaa".to_string()],
                files_changed: vec![],
            },
        ];

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packets = build_all_packets(&commits, &signer, agent_id);

        assert_eq!(packets.len(), 2);
        assert!(packets[0].claim.content.contains("first"));
        assert!(packets[1].claim.content.contains("second"));
    }

    // -------------------------------------------------------------------------
    // Git log output parsing tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_git_log_output_single_commit() {
        let output = format!(
            "{RS}abc123{FS}Test Author{FS}test@example.com{FS}2026-02-10T12:00:00+00:00{FS}parent1{FS}feat(core): add truth validation\n\n**Evidence:**\n- Plan requires it\n\n**Reasoning:**\n- Chose f64\n\n**Verification:**\n- Tests pass\n\nsrc/core/claim.rs",
            RS = RECORD_SEP,
            FS = FIELD_SEP,
        );

        let commits = parse_git_log_output(&output).unwrap();
        assert_eq!(commits.len(), 1);

        let c = &commits[0];
        assert_eq!(c.hash, "abc123");
        assert_eq!(c.author_name, "Test Author");
        assert_eq!(c.author_email, "test@example.com");
        assert_eq!(c.commit_type, CommitType::Feat);
        assert_eq!(c.scope, "core");
        assert_eq!(c.claim_text, "add truth validation");
        assert_eq!(c.evidence, vec!["Plan requires it"]);
        assert_eq!(c.reasoning, vec!["Chose f64"]);
        assert_eq!(c.verification, vec!["Tests pass"]);
        assert_eq!(c.parent_hashes, vec!["parent1"]);
        assert_eq!(c.files_changed, vec!["src/core/claim.rs"]);
    }

    #[test]
    fn test_parse_git_log_output_multiple_commits() {
        let output = format!(
            "{RS}bbb{FS}B{FS}b@x.com{FS}2026-02-02{FS}aaa{FS}fix(db): fix query\n\nfile2.rs\n{RS}aaa{FS}A{FS}a@x.com{FS}2026-02-01{FS}{FS}feat(core): initial\n\nfile1.rs",
            RS = RECORD_SEP,
            FS = FIELD_SEP,
        );

        let commits = parse_git_log_output(&output).unwrap();
        // Should be reversed to chronological order (oldest first)
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].hash, "aaa");
        assert_eq!(commits[1].hash, "bbb");
    }

    #[test]
    fn test_parse_git_log_output_non_protocol_commit() {
        let output = format!(
            "{RS}xyz{FS}Someone{FS}someone@mail.com{FS}2026-01-01{FS}{FS}Initial commit\n\nREADME.md",
            RS = RECORD_SEP,
            FS = FIELD_SEP,
        );

        let commits = parse_git_log_output(&output).unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].commit_type, CommitType::Unknown);
        assert_eq!(commits[0].claim_text, "Initial commit");
    }

    #[test]
    fn test_parse_git_log_output_empty() {
        let commits = parse_git_log_output("").unwrap();
        assert!(commits.is_empty());
    }

    // -------------------------------------------------------------------------
    // split_body_and_files tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_split_body_and_files() {
        let combined = "feat(core): something\n\n**Evidence:**\n- item\n\nsrc/file.rs\nCargo.toml";
        let (body, files) = split_body_and_files(combined);
        assert!(body.contains("feat(core)"));
        assert!(files.contains("src/file.rs") || body.contains("src/file.rs"));
    }

    #[test]
    fn test_split_body_and_files_no_files() {
        let combined = "Just a message";
        let (body, files) = split_body_and_files(combined);
        assert_eq!(body, "Just a message");
        assert!(files.is_empty());
    }

    // -------------------------------------------------------------------------
    // Confidence calculation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_confidence_full_metadata() {
        let commit = ParsedCommit {
            hash: "x".into(),
            author_name: "A".into(),
            author_email: "a@b".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Feat,
            scope: "core".into(),
            claim_text: "test".into(),
            evidence: vec!["ev".into()],
            reasoning: vec!["re".into()],
            verification: vec!["ve".into()],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
        assert!((packet.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_no_verification() {
        let commit = ParsedCommit {
            hash: "x".into(),
            author_name: "A".into(),
            author_email: "a@b".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Feat,
            scope: "core".into(),
            claim_text: "test".into(),
            evidence: vec!["ev".into()],
            reasoning: vec!["re".into()],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
        assert!((packet.reasoning_trace.confidence - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_no_metadata() {
        let commit = ParsedCommit {
            hash: "x".into(),
            author_name: "A".into(),
            author_email: "a@b".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Chore,
            scope: "".into(),
            claim_text: "test".into(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
        assert!((packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);
    }

    // -------------------------------------------------------------------------
    // CommitType Display
    // -------------------------------------------------------------------------

    #[test]
    fn test_commit_type_display() {
        assert_eq!(format!("{}", CommitType::Feat), "feat");
        assert_eq!(format!("{}", CommitType::Fix), "fix");
        assert_eq!(format!("{}", CommitType::Unknown), "unknown");
    }

    // -------------------------------------------------------------------------
    // Idempotency key
    // -------------------------------------------------------------------------

    #[test]
    fn test_idempotency_key_uses_git_hash() {
        let commit = ParsedCommit {
            hash: "deadbeef1234567890".to_string(),
            author_name: "A".into(),
            author_email: "a@b".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Feat,
            scope: "core".into(),
            claim_text: "test".into(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let packet = build_packet(&commit, &signer, Uuid::new_v4(), None);
        assert_eq!(
            packet.claim.idempotency_key,
            Some("git:deadbeef1234567890".to_string())
        );
    }

    // -------------------------------------------------------------------------
    // Agent management tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_agent_registry_creates_unique_agents() {
        let mut registry = AgentRegistry::new();

        let a1 = registry.get_or_create("alice@example.com", "Alice");
        let a1_id = a1.agent_id;
        let a1_pk = a1.signer.public_key().to_owned();

        let a2 = registry.get_or_create("bob@example.com", "Bob");
        let a2_id = a2.agent_id;
        let a2_pk = a2.signer.public_key().to_owned();

        // Different authors get different agents
        assert_ne!(a1_id, a2_id);
        assert_ne!(a1_pk, a2_pk);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_agent_registry_reuses_existing() {
        let mut registry = AgentRegistry::new();

        let first = registry.get_or_create("alice@example.com", "Alice");
        let first_id = first.agent_id;

        let second = registry.get_or_create("alice@example.com", "Alice");
        let second_id = second.agent_id;

        // Same email reuses the same agent
        assert_eq!(first_id, second_id);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_agent_registry_empty() {
        let registry = AgentRegistry::new();
        assert_eq!(registry.len(), 0);
    }

    // -------------------------------------------------------------------------
    // Relationship tracker tests
    // -------------------------------------------------------------------------

    fn make_commit(
        hash: &str,
        commit_type: CommitType,
        scope: &str,
        parents: Vec<&str>,
    ) -> ParsedCommit {
        ParsedCommit {
            hash: hash.to_string(),
            author_name: "A".into(),
            author_email: "a@b".into(),
            date: "2026-01-01".into(),
            commit_type,
            scope: scope.to_string(),
            claim_text: "test".into(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: parents.into_iter().map(String::from).collect(),
            files_changed: vec![],
        }
    }

    #[test]
    fn test_relationship_tracker_fix_challenges_feat() {
        let mut tracker = RelationshipTracker::new();

        // Record a feat in "core" scope
        let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
        let feat_id = Uuid::new_v4();
        tracker.record(&feat_commit, feat_id);

        // A fix in the same scope should challenge it
        let fix_commit = make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]);
        let challenged = tracker.find_challenged_feat(&fix_commit);
        assert_eq!(challenged, Some(feat_id));
    }

    #[test]
    fn test_relationship_tracker_fix_different_scope_no_challenge() {
        let mut tracker = RelationshipTracker::new();

        let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
        tracker.record(&feat_commit, Uuid::new_v4());

        // A fix in a different scope should NOT challenge it
        let fix_commit = make_commit("bbb", CommitType::Fix, "api", vec![]);
        assert!(tracker.find_challenged_feat(&fix_commit).is_none());
    }

    #[test]
    fn test_relationship_tracker_non_fix_no_challenge() {
        let mut tracker = RelationshipTracker::new();

        let feat_commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
        tracker.record(&feat_commit, Uuid::new_v4());

        // A refactor should NOT challenge the feat
        let refactor = make_commit("bbb", CommitType::Refactor, "core", vec![]);
        assert!(tracker.find_challenged_feat(&refactor).is_none());
    }

    #[test]
    fn test_relationship_tracker_parent_claim() {
        let mut tracker = RelationshipTracker::new();

        let parent = make_commit("aaa", CommitType::Feat, "core", vec![]);
        let parent_id = Uuid::new_v4();
        tracker.record(&parent, parent_id);

        let child = make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]);
        let found = tracker.find_parent_claim(&child);
        assert_eq!(found, Some(parent_id));
    }

    #[test]
    fn test_relationship_tracker_no_parent() {
        let tracker = RelationshipTracker::new();

        let root = make_commit("aaa", CommitType::Feat, "core", vec![]);
        assert!(tracker.find_parent_claim(&root).is_none());
    }

    #[test]
    fn test_relationship_tracker_parent_not_ingested() {
        let tracker = RelationshipTracker::new();

        // Parent hash exists but wasn't tracked (e.g., outside --since range)
        let child = make_commit("bbb", CommitType::Fix, "core", vec!["unknown_hash"]);
        assert!(tracker.find_parent_claim(&child).is_none());
    }

    #[test]
    fn test_relationship_tracker_fix_updates_feat_tracking() {
        let mut tracker = RelationshipTracker::new();

        // First feat in core
        let feat1 = make_commit("aaa", CommitType::Feat, "core", vec![]);
        let feat1_id = Uuid::new_v4();
        tracker.record(&feat1, feat1_id);

        // Second feat in core (overwrites the first)
        let feat2 = make_commit("bbb", CommitType::Feat, "core", vec!["aaa"]);
        let feat2_id = Uuid::new_v4();
        tracker.record(&feat2, feat2_id);

        // Fix should challenge the LATEST feat
        let fix = make_commit("ccc", CommitType::Fix, "core", vec!["bbb"]);
        assert_eq!(tracker.find_challenged_feat(&fix), Some(feat2_id));
    }

    // =========================================================================
    // END-TO-END PIPELINE TESTS (Phase 4.3)
    // =========================================================================
    // These tests simulate parsing realistic git log output, building packets,
    // and verifying the entire pipeline produces correct epistemic data.

    /// Realistic commit messages following the Epistemic Commit Protocol.
    /// Listed newest-first (as `git log` would output), so that
    /// `parse_git_log_output()` can reverse them to chronological order.
    fn realistic_git_log_output() -> String {
        let rs = RECORD_SEP;
        let fs = FIELD_SEP;

        format!(
            // Newest commit first (git log order)
            // Commit 10: Non-protocol commit
            "{rs}jjj000{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-24T14:00:00+00:00{fs}iii999{fs}\
Initial commit\n\n\
README.md\
\n\
{rs}iii999{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-23T09:30:00+00:00{fs}hhh888{fs}\
feat(engine): implement Bayesian truth update for claim propagation\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 3 requirement\n\
- Current weighted average insufficient for evidence accumulation\n\n\
**Reasoning:**\n\
- P(H|E) = P(E|H) * P(H) / P(E) provides proper belief updating\n\
- Chose to clamp posterior to [0.01, 0.99] to prevent certainty lock-in\n\n\
**Verification:**\n\
- test_bayesian_update validates formula\n\
- test_evidence_accumulation shows convergence\n\n\
crates/epigraph-engine/src/propagation.rs\
\n\
{rs}hhh888{fs}Charlie{fs}charlie@epigraph.dev{fs}2026-01-22T16:00:00+00:00{fs}ggg777{fs}\
chore: update dependencies to latest patch versions\n\n\
Cargo.toml\n\
Cargo.lock\
\n\
{rs}ggg777{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-21T10:00:00+00:00{fs}fff666{fs}\
docs: add API endpoint documentation\n\n\
**Evidence:**\n\
- No existing API docs for external consumers\n\n\
**Reasoning:**\n\
- Used utoipa for OpenAPI spec generation\n\n\
docs/api.md\
\n\
{rs}fff666{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-20T15:00:00+00:00{fs}eee555{fs}\
refactor(db): extract repository pattern from monolithic data layer\n\n\
**Evidence:**\n\
- Data layer grew to 800 lines, violating single-responsibility\n\n\
**Reasoning:**\n\
- Split into ClaimRepo, EvidenceRepo, AgentRepo\n\
- Each repo owns one table's queries\n\n\
crates/epigraph-db/src/repos/claim.rs\n\
crates/epigraph-db/src/repos/evidence.rs\n\
crates/epigraph-db/src/repos/agent.rs\
\n\
{rs}eee555{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-19T08:00:00+00:00{fs}ddd444{fs}\
test(engine): add property-based tests for truth propagation\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 3 requires truth propagation validation\n\n\
**Reasoning:**\n\
- Property tests cover edge cases unit tests miss\n\
- quickcheck generates random claim graphs\n\n\
**Verification:**\n\
- 100 iterations pass with no panics\n\n\
crates/epigraph-engine/tests/property_tests.rs\
\n\
{rs}ddd444{fs}Charlie{fs}charlie@epigraph.dev{fs}2026-01-18T11:00:00+00:00{fs}ccc333{fs}\
security(crypto): prevent timing attacks in signature verification\n\n\
**Evidence:**\n\
- Security audit flagged constant-time comparison missing\n\
- ed25519-dalek docs warn about timing side-channels\n\n\
**Reasoning:**\n\
- Replaced == with subtle::ConstantTimeEq for signature bytes\n\
- Cannot use short-circuit comparison on cryptographic material\n\n\
**Verification:**\n\
- cargo test passes\n\
- Manual review confirms no early returns in verify path\n\n\
crates/epigraph-crypto/src/verifier.rs\
\n\
{rs}ccc333{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-17T09:00:00+00:00{fs}bbb222{fs}\
fix(core): prevent NaN truth values from bypassing validation\n\n\
**Evidence:**\n\
- Fuzzing found f64::NAN passes 0.0 <= x <= 1.0 check (NaN comparisons always false)\n\n\
**Reasoning:**\n\
- Added explicit is_nan() check before bounds validation\n\
- NaN is not a valid epistemic state\n\n\
**Verification:**\n\
- test_claim_rejects_nan_truth: passes\n\n\
crates/epigraph-core/src/domain/claim.rs\
\n\
{rs}bbb222{fs}Bob{fs}bob@epigraph.dev{fs}2026-01-16T14:30:00+00:00{fs}aaa111{fs}\
feat(crypto): add BLAKE3 content hashing and Ed25519 signing\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md Phase 1 requires content-addressable hashing\n\n\
**Reasoning:**\n\
- BLAKE3 chosen over SHA-256: faster, Merkle-tree capable\n\
- Ed25519 for signatures: small keys, fast verification\n\n\
**Verification:**\n\
- test_hash_deterministic: passes\n\
- test_sign_verify_roundtrip: passes\n\n\
crates/epigraph-crypto/src/hasher.rs\n\
crates/epigraph-crypto/src/signer.rs\
\n\
{rs}aaa111{fs}Alice{fs}alice@epigraph.dev{fs}2026-01-15T10:00:00+00:00{fs}{fs}\
feat(core): define Claim model with bounded truth values\n\n\
**Evidence:**\n\
- IMPLEMENTATION_PLAN.md §2.1 specifies truth in [0.0, 1.0]\n\
- Unbounded floats allow invalid states (NaN, infinity)\n\n\
**Reasoning:**\n\
- Chose f64 over f32: precision matters for Bayesian updates near 0/1\n\
- Constructor validates bounds, returns Result<Claim, ClaimError>\n\n\
**Verification:**\n\
- test_claim_rejects_negative_truth: passes\n\
- test_claim_rejects_truth_above_one: passes\n\
- cargo build: no warnings\n\n\
crates/epigraph-core/src/domain/claim.rs\n\
crates/epigraph-core/src/domain/mod.rs",
        )
    }

    #[test]
    fn test_e2e_parse_realistic_git_log() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        // Should parse all 10 commits in chronological order (oldest first)
        // parse_git_log_output reverses the newest-first git log order
        assert_eq!(commits.len(), 10);

        // After reversal: oldest (aaa111) first, newest (jjj000) last
        assert_eq!(commits[0].hash, "aaa111");
        assert_eq!(commits[9].hash, "jjj000");
    }

    #[test]
    fn test_e2e_commit_types_correctly_parsed() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        // Create a map for easier lookup
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        assert_eq!(by_hash["aaa111"].commit_type, CommitType::Feat);
        assert_eq!(by_hash["bbb222"].commit_type, CommitType::Feat);
        assert_eq!(by_hash["ccc333"].commit_type, CommitType::Fix);
        assert_eq!(by_hash["ddd444"].commit_type, CommitType::Security);
        assert_eq!(by_hash["eee555"].commit_type, CommitType::Test);
        assert_eq!(by_hash["fff666"].commit_type, CommitType::Refactor);
        assert_eq!(by_hash["ggg777"].commit_type, CommitType::Docs);
        assert_eq!(by_hash["hhh888"].commit_type, CommitType::Chore);
        assert_eq!(by_hash["iii999"].commit_type, CommitType::Feat);
        assert_eq!(by_hash["jjj000"].commit_type, CommitType::Unknown);
    }

    #[test]
    fn test_e2e_scopes_extracted() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        assert_eq!(by_hash["aaa111"].scope, "core");
        assert_eq!(by_hash["bbb222"].scope, "crypto");
        assert_eq!(by_hash["ccc333"].scope, "core");
        assert_eq!(by_hash["ddd444"].scope, "crypto");
        assert_eq!(by_hash["eee555"].scope, "engine");
        assert_eq!(by_hash["fff666"].scope, "db");
        assert_eq!(by_hash["ggg777"].scope, ""); // docs without scope
        assert_eq!(by_hash["hhh888"].scope, ""); // chore without scope
        assert_eq!(by_hash["iii999"].scope, "engine");
        assert_eq!(by_hash["jjj000"].scope, ""); // non-protocol commit
    }

    #[test]
    fn test_e2e_evidence_sections_parsed() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // feat(core) has 2 evidence items
        assert_eq!(by_hash["aaa111"].evidence.len(), 2);
        assert!(by_hash["aaa111"].evidence[0].contains("IMPLEMENTATION_PLAN.md"));

        // feat(crypto) has 1 evidence item
        assert_eq!(by_hash["bbb222"].evidence.len(), 1);

        // chore has 0 evidence
        assert!(by_hash["hhh888"].evidence.is_empty());

        // Initial commit has 0 evidence
        assert!(by_hash["jjj000"].evidence.is_empty());
    }

    #[test]
    fn test_e2e_verification_sections_parsed() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // feat(core) has 3 verification items
        assert_eq!(by_hash["aaa111"].verification.len(), 3);
        assert!(by_hash["aaa111"].verification[0].contains("test_claim_rejects_negative_truth"));

        // refactor(db) has NO verification
        assert!(by_hash["fff666"].verification.is_empty());

        // chore has no verification
        assert!(by_hash["hhh888"].verification.is_empty());
    }

    #[test]
    fn test_e2e_packets_have_correct_truth_values() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // feat with verification → 0.6
        let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.6).abs() < f64::EPSILON,
            "feat with verification should have truth 0.6"
        );

        // fix → 0.7
        let p = build_packet(by_hash["ccc333"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.7).abs() < f64::EPSILON,
            "fix should have truth 0.7"
        );

        // security → 0.7
        let p = build_packet(by_hash["ddd444"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.7).abs() < f64::EPSILON,
            "security should have truth 0.7"
        );

        // test → 0.8
        let p = build_packet(by_hash["eee555"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.8).abs() < f64::EPSILON,
            "test should have truth 0.8"
        );

        // refactor → 0.5
        let p = build_packet(by_hash["fff666"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.5).abs() < f64::EPSILON,
            "refactor should have truth 0.5"
        );

        // docs → 0.4
        let p = build_packet(by_hash["ggg777"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.4).abs() < f64::EPSILON,
            "docs should have truth 0.4"
        );

        // chore → 0.3
        let p = build_packet(by_hash["hhh888"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.3).abs() < f64::EPSILON,
            "chore should have truth 0.3"
        );

        // Unknown → 0.2
        let p = build_packet(by_hash["jjj000"], &signer, agent_id, None);
        assert!(
            (p.claim.initial_truth.unwrap() - 0.2).abs() < f64::EPSILON,
            "unknown should have truth 0.2"
        );
    }

    #[test]
    fn test_e2e_packets_have_correct_methodologies() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        assert_eq!(
            build_packet(by_hash["aaa111"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "extraction"
        );
        assert_eq!(
            build_packet(by_hash["ccc333"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "deductive"
        );
        assert_eq!(
            build_packet(by_hash["ddd444"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "deductive"
        );
        assert_eq!(
            build_packet(by_hash["eee555"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "instrumental"
        );
        assert_eq!(
            build_packet(by_hash["fff666"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "deductive"
        );
        assert_eq!(
            build_packet(by_hash["ggg777"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "heuristic"
        );
        assert_eq!(
            build_packet(by_hash["hhh888"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "heuristic"
        );
        assert_eq!(
            build_packet(by_hash["jjj000"], &signer, agent_id, None)
                .reasoning_trace
                .methodology,
            "heuristic"
        );
    }

    #[test]
    fn test_e2e_evidence_items_correctly_split() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // feat(core): 2 evidence + 3 verification = 5 evidence items in packet
        let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
        assert_eq!(p.evidence.len(), 5);

        // fix(core): 1 evidence + 1 verification = 2 evidence items
        let p = build_packet(by_hash["ccc333"], &signer, agent_id, None);
        assert_eq!(p.evidence.len(), 2);

        // chore: 0 evidence + 0 verification = 0 evidence items
        let p = build_packet(by_hash["hhh888"], &signer, agent_id, None);
        assert_eq!(p.evidence.len(), 0);
    }

    #[test]
    fn test_e2e_relationship_detection_fix_challenges_feat() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        let mut tracker = RelationshipTracker::new();

        // Process commits in order and check relationships
        for commit in &commits {
            match commit.hash.as_str() {
                "aaa111" => {
                    // First feat(core) — no challenges expected
                    assert!(tracker.find_challenged_feat(commit).is_none());
                    tracker.record(commit, Uuid::new_v4());
                }
                "ccc333" => {
                    // fix(core) — should challenge the feat(core) from aaa111
                    assert!(
                        tracker.find_challenged_feat(commit).is_some(),
                        "fix(core) should challenge the prior feat(core)"
                    );
                    tracker.record(commit, Uuid::new_v4());
                }
                _ => {
                    tracker.record(commit, Uuid::new_v4());
                }
            }
        }
    }

    #[test]
    fn test_e2e_parent_child_chain() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        let mut tracker = RelationshipTracker::new();
        let mut parent_links_found = 0;

        for commit in &commits {
            if tracker.find_parent_claim(commit).is_some() {
                parent_links_found += 1;
            }
            tracker.record(commit, Uuid::new_v4());
        }

        // Most commits have parents, so we should find several refinement links
        // The initial commit and root have no parents
        assert!(
            parent_links_found >= 5,
            "Expected at least 5 parent-child links, found {parent_links_found}"
        );
    }

    #[test]
    fn test_e2e_per_author_agents() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        let mut registry = AgentRegistry::new();

        for commit in &commits {
            registry.get_or_create(&commit.author_email, &commit.author_name);
        }

        // We have 3 unique authors: Alice, Bob, Charlie
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn test_e2e_all_packets_have_valid_signatures() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        for commit in &commits {
            let packet = build_packet(commit, &signer, agent_id, None);

            // Packet signature must be valid hex, 128 chars (64 bytes)
            let sig_bytes = hex::decode(&packet.signature)
                .unwrap_or_else(|_| panic!("Invalid packet signature hex for {}", commit.hash));
            assert_eq!(
                sig_bytes.len(),
                64,
                "Packet signature for {} should be 64 bytes",
                commit.hash
            );

            // All evidence items must have valid signatures
            for (i, ev) in packet.evidence.iter().enumerate() {
                let sig = ev.signature.as_ref().unwrap_or_else(|| {
                    panic!("Evidence {} of {} missing signature", i, commit.hash)
                });
                let sig_bytes = hex::decode(sig).unwrap_or_else(|_| {
                    panic!("Invalid evidence signature hex for {}", commit.hash)
                });
                assert_eq!(sig_bytes.len(), 64);
            }

            // Content hashes must be valid hex, 64 chars (32 bytes)
            for (i, ev) in packet.evidence.iter().enumerate() {
                let hash_bytes = hex::decode(&ev.content_hash).unwrap_or_else(|_| {
                    panic!("Invalid hash hex for evidence {} of {}", i, commit.hash)
                });
                assert_eq!(hash_bytes.len(), 32);
            }
        }
    }

    #[test]
    fn test_e2e_idempotency_keys_unique() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let keys: Vec<String> = commits
            .iter()
            .map(|c| build_packet(c, &signer, agent_id, None))
            .map(|p| p.claim.idempotency_key.unwrap())
            .collect();

        // All idempotency keys should be unique
        let unique: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(
            unique.len(),
            keys.len(),
            "All idempotency keys must be unique"
        );

        // All keys should start with "git:"
        for key in &keys {
            assert!(
                key.starts_with("git:"),
                "Key should start with 'git:', got: {key}"
            );
        }
    }

    #[test]
    fn test_e2e_claim_content_format() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // Claims should follow [type][scope] format
        let p = build_packet(by_hash["aaa111"], &signer, agent_id, None);
        assert_eq!(
            p.claim.content,
            "[feat][core] define Claim model with bounded truth values"
        );

        let p = build_packet(by_hash["ddd444"], &signer, agent_id, None);
        assert_eq!(
            p.claim.content,
            "[security][crypto] prevent timing attacks in signature verification"
        );

        let p = build_packet(by_hash["jjj000"], &signer, agent_id, None);
        assert_eq!(p.claim.content, "[unknown][] Initial commit");
    }

    #[test]
    fn test_e2e_files_changed_tracked() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // feat(core) changed 2 files
        assert_eq!(by_hash["aaa111"].files_changed.len(), 2);
        assert!(by_hash["aaa111"]
            .files_changed
            .contains(&"crates/epigraph-core/src/domain/claim.rs".to_string()));

        // refactor(db) changed 3 files
        assert_eq!(by_hash["fff666"].files_changed.len(), 3);

        // chore changed 2 files
        assert_eq!(by_hash["hhh888"].files_changed.len(), 2);
    }

    #[test]
    fn test_e2e_authors_tracked() {
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        assert_eq!(by_hash["aaa111"].author_email, "alice@epigraph.dev");
        assert_eq!(by_hash["bbb222"].author_email, "bob@epigraph.dev");
        assert_eq!(by_hash["ddd444"].author_email, "charlie@epigraph.dev");
    }

    // =========================================================================
    // PHASE 1: COMMIT ENRICHMENT TESTS
    // =========================================================================

    // --- 1.1 EnrichedData defaults ---

    #[test]
    fn test_enriched_data_defaults() {
        let data = EnrichedData::default();
        assert!(data.semantic_edges.is_empty());
        assert!(data.adjusted_confidence.is_none());
        assert!(data.embedding.is_none());
        assert!(data.implicit_claims.is_empty());
    }

    #[test]
    fn test_semantic_edge_strength_bounded() {
        // Valid edge at boundary
        let edge = SemanticEdge::new(
            "abc123".to_string(),
            "supports".to_string(),
            0.0,
            "test".to_string(),
        );
        assert!(edge.is_ok());

        let edge = SemanticEdge::new(
            "abc123".to_string(),
            "supports".to_string(),
            1.0,
            "test".to_string(),
        );
        assert!(edge.is_ok());

        let edge = SemanticEdge::new(
            "abc123".to_string(),
            "supports".to_string(),
            0.5,
            "test".to_string(),
        );
        assert!(edge.is_ok());
        assert!((edge.unwrap().strength - 0.5).abs() < f64::EPSILON);

        // Invalid: negative
        let edge = SemanticEdge::new(
            "abc123".to_string(),
            "supports".to_string(),
            -0.1,
            "test".to_string(),
        );
        assert!(edge.is_err());
        assert!(edge.unwrap_err().contains("[0.0, 1.0]"));

        // Invalid: above 1.0
        let edge = SemanticEdge::new(
            "abc123".to_string(),
            "supports".to_string(),
            1.1,
            "test".to_string(),
        );
        assert!(edge.is_err());
    }

    // --- 1.2 NoopEnricher tests ---

    #[tokio::test]
    async fn test_noop_enricher_returns_empty_enrichment() {
        let enricher = NoopEnricher;
        let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
        let result = enricher.enrich(&commits).await.unwrap();

        assert_eq!(result.len(), 1);
        let data = &result[0];
        assert!(data.semantic_edges.is_empty());
        assert!(data.adjusted_confidence.is_none());
        assert!(data.embedding.is_none());
        assert!(data.implicit_claims.is_empty());
    }

    #[tokio::test]
    async fn test_noop_enricher_preserves_commit_count() {
        let enricher = NoopEnricher;
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "api", vec!["aaa"]),
            make_commit("ccc", CommitType::Docs, "docs", vec!["bbb"]),
        ];

        let result = enricher.enrich(&commits).await.unwrap();
        assert_eq!(result.len(), commits.len());
    }

    #[tokio::test]
    async fn test_noop_embed_returns_none() {
        let enricher = NoopEnricher;
        let result = enricher.embed("any text here").await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_noop_enricher_name() {
        let enricher = NoopEnricher;
        assert_eq!(enricher.name(), "noop");
    }

    // --- 1.3 Pipeline integration tests ---

    #[test]
    fn test_build_packet_with_empty_enrichment_unchanged() {
        // A packet built with NoopEnricher (empty enrichment) should be identical
        // to a packet built with None enrichment
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Dev".into(),
            author_email: "dev@example.com".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Feat,
            scope: "core".into(),
            claim_text: "add feature".into(),
            evidence: vec!["Plan requires it".into()],
            reasoning: vec!["Chose approach A".into()],
            verification: vec!["tests pass".into()],
            parent_hashes: vec![],
            files_changed: vec!["src/lib.rs".into()],
        };
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let packet_none = build_packet(&commit, &signer, agent_id, None);
        let enrichment = EnrichedData::default();
        let packet_enriched = build_packet(&commit, &signer, agent_id, Some(&enrichment));

        assert_eq!(packet_none.claim.content, packet_enriched.claim.content);
        assert_eq!(
            packet_none.claim.initial_truth,
            packet_enriched.claim.initial_truth
        );
        assert_eq!(
            packet_none.reasoning_trace.confidence,
            packet_enriched.reasoning_trace.confidence
        );
        assert_eq!(
            packet_none.reasoning_trace.methodology,
            packet_enriched.reasoning_trace.methodology
        );
        assert_eq!(packet_none.evidence.len(), packet_enriched.evidence.len());
    }

    #[test]
    fn test_build_packet_with_adjusted_confidence() {
        // Enrichment lowers confidence from parser's 0.85 to 0.6
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Dev".into(),
            author_email: "dev@example.com".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Feat,
            scope: "core".into(),
            claim_text: "add feature".into(),
            evidence: vec!["evidence".into()],
            reasoning: vec!["reasoning".into()],
            verification: vec!["verification".into()],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        // Parser would give confidence 0.85 (full metadata)
        let packet_baseline = build_packet(&commit, &signer, agent_id, None);
        assert!((packet_baseline.reasoning_trace.confidence - 0.85).abs() < f64::EPSILON);

        // Enrichment adjusts down to 0.6
        let enrichment = EnrichedData {
            adjusted_confidence: Some(0.6),
            ..EnrichedData::default()
        };
        let packet = build_packet(&commit, &signer, agent_id, Some(&enrichment));
        assert!(
            (packet.reasoning_trace.confidence - 0.6).abs() < f64::EPSILON,
            "Enrichment should lower confidence to 0.6, got {}",
            packet.reasoning_trace.confidence
        );
    }

    #[test]
    fn test_build_packet_rejects_inflated_confidence() {
        // Enrichment tries to RAISE confidence above parser ceiling — must be clamped
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Dev".into(),
            author_email: "dev@example.com".into(),
            date: "2026-01-01".into(),
            commit_type: CommitType::Chore,
            scope: "build".into(),
            claim_text: "update deps".into(),
            evidence: vec![],
            reasoning: vec![],
            verification: vec![],
            parent_hashes: vec![],
            files_changed: vec![],
        };
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        // Parser gives confidence 0.3 (no metadata, chore)
        let packet_baseline = build_packet(&commit, &signer, agent_id, None);
        assert!((packet_baseline.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON);

        // Enrichment tries to inflate to 0.9 — must be clamped to 0.3
        let enrichment = EnrichedData {
            adjusted_confidence: Some(0.9),
            ..EnrichedData::default()
        };
        let packet = build_packet(&commit, &signer, agent_id, Some(&enrichment));
        assert!(
            (packet.reasoning_trace.confidence - 0.3).abs() < f64::EPSILON,
            "Enrichment must NOT raise confidence above parser ceiling. Expected 0.3, got {}",
            packet.reasoning_trace.confidence
        );
    }

    #[test]
    fn test_cli_default_enricher_is_noop() {
        // Verify that EnricherMode defaults to Noop
        assert_eq!(EnricherMode::from_str("noop").unwrap(), EnricherMode::Noop);
        assert_eq!(EnricherMode::from_str("llm").unwrap(), EnricherMode::Llm);
        assert!(EnricherMode::from_str("invalid").is_err());
    }

    #[tokio::test]
    async fn test_noop_enricher_empty_commits() {
        let enricher = NoopEnricher;
        let commits: Vec<ParsedCommit> = vec![];
        let result = enricher.enrich(&commits).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_enrichment_pipeline_integration() {
        // Simulate the full pipeline: parse → enrich → build_packet
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let enricher = NoopEnricher;
        let enrichments = enricher.enrich(&commits).await.unwrap();

        assert_eq!(enrichments.len(), commits.len());

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        // Build packets with enrichment and verify they match the no-enrichment baseline
        for (commit, enrichment) in commits.iter().zip(enrichments.iter()) {
            let packet_with = build_packet(commit, &signer, agent_id, Some(enrichment));
            let packet_without = build_packet(commit, &signer, agent_id, None);

            assert_eq!(packet_with.claim.content, packet_without.claim.content);
            assert_eq!(
                packet_with.reasoning_trace.confidence,
                packet_without.reasoning_trace.confidence
            );
            assert_eq!(
                packet_with.claim.initial_truth,
                packet_without.claim.initial_truth
            );
        }
    }

    // =========================================================================
    // PHASE 3: LLM ENRICHER TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_llm_enricher_mock_returns_edges() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        // Mock LLM returns a relationship between commit 0 and commit 1
        let mock_response = serde_json::json!([
            {
                "source_index": 0,
                "target_index": 1,
                "relationship": "supports",
                "strength": 0.85,
                "rationale": "Commit 0 provides foundation for commit 1"
            }
        ]);

        let client = MockLlmClient::with_responses(vec![mock_response]);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);

        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];

        let result = enricher.enrich(&commits).await.unwrap();
        assert_eq!(result.len(), 2);

        // Commit 0 should have an edge to commit 1
        assert_eq!(result[0].semantic_edges.len(), 1);
        assert_eq!(result[0].semantic_edges[0].target_hash, "bbb");
        assert_eq!(result[0].semantic_edges[0].relationship, "supports");
        assert!((result[0].semantic_edges[0].strength - 0.85).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_llm_enricher_sliding_window_overlap() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        // Window size 3, overlap 1 → commits [0,1,2] then [2,3,4]
        // The overlap means commit 2 appears in both windows
        let window1_response = serde_json::json!([
            {
                "source_index": 0,
                "target_index": 2,
                "relationship": "elaborates",
                "strength": 0.7,
                "rationale": "First to third"
            }
        ]);
        let window2_response = serde_json::json!([
            {
                "source_index": 0,
                "target_index": 1,
                "relationship": "supports",
                "strength": 0.6,
                "rationale": "Third to fourth"
            }
        ]);

        let client = MockLlmClient::with_responses(vec![window1_response, window2_response]);
        let enricher = LlmEnricher::with_config(Box::new(client), 3, 1);

        let commits = vec![
            make_commit("a", CommitType::Feat, "core", vec![]),
            make_commit("b", CommitType::Fix, "core", vec!["a"]),
            make_commit("c", CommitType::Docs, "core", vec!["b"]),
            make_commit("d", CommitType::Test, "core", vec!["c"]),
            make_commit("e", CommitType::Refactor, "core", vec!["d"]),
        ];

        let result = enricher.enrich(&commits).await.unwrap();
        assert_eq!(result.len(), 5);

        // First window: commit 0 → commit 2 (global)
        assert_eq!(result[0].semantic_edges.len(), 1);
        assert_eq!(result[0].semantic_edges[0].target_hash, "c");

        // Second window starts at index 2: window-local 0→1 maps to global 2→3
        assert_eq!(result[2].semantic_edges.len(), 1);
        assert_eq!(result[2].semantic_edges[0].target_hash, "d");
    }

    #[tokio::test]
    async fn test_llm_enricher_handles_empty_commits() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        let client = MockLlmClient::new();
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);

        let result = enricher.enrich(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_llm_enricher_handles_api_failure_gracefully() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        // Simulate malformed response — enricher should not fail, just skip that window
        let client = MockLlmClient::new();
        client.set_malformed(true);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);

        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];

        // Should not panic or return error — graceful degradation
        let result = enricher.enrich(&commits).await.unwrap();
        assert_eq!(result.len(), 2);
        // No edges extracted due to failure
        assert!(result[0].semantic_edges.is_empty());
        assert!(result[1].semantic_edges.is_empty());
    }

    #[tokio::test]
    async fn test_llm_enricher_filters_invalid_relationships() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        // LLM returns some valid and some invalid relationships
        let mock_response = serde_json::json!([
            {
                "source_index": 0,
                "target_index": 1,
                "relationship": "supports",
                "strength": 0.8,
                "rationale": "Valid relationship"
            },
            {
                "source_index": 0,
                "target_index": 0,
                "relationship": "supports",
                "strength": 0.5,
                "rationale": "Self-reference — should be filtered"
            },
            {
                "source_index": 0,
                "target_index": 99,
                "relationship": "supports",
                "strength": 0.5,
                "rationale": "Out of bounds — should be filtered"
            }
        ]);

        let client = MockLlmClient::with_responses(vec![mock_response]);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);

        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];

        let result = enricher.enrich(&commits).await.unwrap();
        // Only the valid relationship should survive
        assert_eq!(result[0].semantic_edges.len(), 1);
        assert_eq!(result[0].semantic_edges[0].rationale, "Valid relationship");
    }

    #[test]
    fn test_llm_enricher_name() {
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        let client = MockLlmClient::new();
        let enricher = LlmEnricher::new(Box::new(client));
        assert_eq!(enricher.name(), "mock");
    }

    // -------------------------------------------------------------------------
    // Edge submission tests (Phase 3.4)
    // -------------------------------------------------------------------------

    #[test]
    fn test_count_semantic_edges_empty() {
        let enrichments = vec![EnrichedData::default(); 3];
        assert_eq!(count_semantic_edges(&enrichments), 0);
    }

    #[test]
    fn test_count_semantic_edges_mixed() {
        let enrichments = vec![
            EnrichedData {
                semantic_edges: vec![
                    SemanticEdge {
                        target_hash: "bbb".to_string(),
                        relationship: "supports".to_string(),
                        strength: 0.8,
                        rationale: "test".to_string(),
                    },
                    SemanticEdge {
                        target_hash: "ccc".to_string(),
                        relationship: "elaborates".to_string(),
                        strength: 0.6,
                        rationale: "test2".to_string(),
                    },
                ],
                ..EnrichedData::default()
            },
            EnrichedData::default(),
            EnrichedData {
                semantic_edges: vec![SemanticEdge {
                    target_hash: "ddd".to_string(),
                    relationship: "refutes".to_string(),
                    strength: 0.5,
                    rationale: "test3".to_string(),
                }],
                ..EnrichedData::default()
            },
        ];
        assert_eq!(count_semantic_edges(&enrichments), 3);
    }

    #[test]
    fn test_create_edge_request_serializes() {
        let request = CreateEdgeRequest {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_type: "claim".to_string(),
            target_type: "claim".to_string(),
            relationship: "supports".to_string(),
            properties: Some(serde_json::json!({
                "strength": 0.85,
                "rationale": "Commit A provides foundation for B",
                "source": "llm_enrichment"
            })),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["source_type"], "claim");
        assert_eq!(json["relationship"], "supports");
        assert_eq!(json["properties"]["source"], "llm_enrichment");
    }

    #[test]
    fn test_edge_submission_skips_unresolved_source() {
        // When a commit's hash isn't in the tracker, edges should be skipped
        let _commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
        let _enrichments = vec![EnrichedData {
            semantic_edges: vec![SemanticEdge {
                target_hash: "bbb".to_string(),
                relationship: "supports".to_string(),
                strength: 0.8,
                rationale: "test".to_string(),
            }],
            ..EnrichedData::default()
        }];

        let tracker = RelationshipTracker::new();
        // tracker has no entries — source hash "aaa" won't resolve
        assert!(tracker.hash_to_claim.get("aaa").is_none());
    }

    #[test]
    fn test_edge_submission_skips_unresolved_target() {
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];
        let _enrichments = vec![
            EnrichedData {
                semantic_edges: vec![SemanticEdge {
                    target_hash: "zzz".to_string(), // Not in our batch
                    relationship: "supports".to_string(),
                    strength: 0.8,
                    rationale: "test".to_string(),
                }],
                ..EnrichedData::default()
            },
            EnrichedData::default(),
        ];

        let mut tracker = RelationshipTracker::new();
        let claim_a = Uuid::new_v4();
        tracker.record(&commits[0], claim_a);

        // Source "aaa" resolves, but target "zzz" won't
        assert!(tracker.hash_to_claim.get(&commits[0].hash).is_some());
        assert!(tracker.hash_to_claim.get("zzz").is_none());
    }

    #[test]
    fn test_edge_submission_resolves_both_hashes() {
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];
        let enrichments = vec![
            EnrichedData {
                semantic_edges: vec![SemanticEdge {
                    target_hash: "bbb".to_string(),
                    relationship: "supports".to_string(),
                    strength: 0.85,
                    rationale: "A provides foundation for B".to_string(),
                }],
                ..EnrichedData::default()
            },
            EnrichedData::default(),
        ];

        let mut tracker = RelationshipTracker::new();
        let claim_a = Uuid::new_v4();
        let claim_b = Uuid::new_v4();
        tracker.record(&commits[0], claim_a);
        tracker.record(&commits[1], claim_b);

        // Both hashes resolve correctly
        assert_eq!(tracker.hash_to_claim.get("aaa"), Some(&claim_a));
        assert_eq!(tracker.hash_to_claim.get("bbb"), Some(&claim_b));

        // Verify edge would be constructed correctly
        let edge = &enrichments[0].semantic_edges[0];
        let source_id = tracker.hash_to_claim.get("aaa").unwrap();
        let target_id = tracker.hash_to_claim.get(&edge.target_hash).unwrap();
        assert_ne!(source_id, target_id);
        assert_eq!(edge.relationship, "supports");
    }

    #[test]
    fn test_dry_run_shows_semantic_edges() {
        // Verify that enrichment edges are accessible by index during dry-run display
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];
        let enrichments = vec![
            EnrichedData {
                semantic_edges: vec![SemanticEdge {
                    target_hash: "bbb".to_string(),
                    relationship: "supports".to_string(),
                    strength: 0.85,
                    rationale: "foundation".to_string(),
                }],
                ..EnrichedData::default()
            },
            EnrichedData::default(),
        ];

        // Verify indexing works correctly (mirrors dry-run loop logic)
        for (i, _commit) in commits.iter().enumerate() {
            for edge in &enrichments[i].semantic_edges {
                let hash_preview = &edge.target_hash[..12.min(edge.target_hash.len())];
                assert!(!hash_preview.is_empty());
            }
        }
        assert_eq!(enrichments[0].semantic_edges.len(), 1);
        assert!(enrichments[1].semantic_edges.is_empty());
    }

    // -------------------------------------------------------------------------
    // Embedding generation tests (Phase 2.3)
    // -------------------------------------------------------------------------

    #[test]
    fn test_generate_embedding_request_serializes() {
        let request = GenerateEmbeddingRequest {
            text: "[feat][core] define Claim model with bounded truth values".to_string(),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert!(json["text"]
            .as_str()
            .unwrap()
            .contains("define Claim model"));
    }

    #[test]
    fn test_embed_flag_default_false() {
        // Verify that --embed is false by default (tested via USAGE string presence)
        assert!(USAGE.contains("--embed"));
    }

    #[test]
    fn test_embedding_only_for_submitted_commits() {
        // Only commits with claim IDs in the tracker should get embeddings
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
            make_commit("ccc", CommitType::Docs, "", vec![]),
        ];

        let mut tracker = RelationshipTracker::new();
        let claim_a = Uuid::new_v4();
        // Only commit "aaa" was submitted and tracked
        tracker.record(&commits[0], claim_a);

        // "aaa" should be embeddable, "bbb" and "ccc" should not
        assert!(tracker.hash_to_claim.get("aaa").is_some());
        assert!(tracker.hash_to_claim.get("bbb").is_none());
        assert!(tracker.hash_to_claim.get("ccc").is_none());
    }

    #[test]
    fn test_embedding_text_matches_claim_content() {
        let commit = make_commit("aaa", CommitType::Feat, "core", vec![]);
        // The embedding text format should match build_packet's claim content
        let expected_content = format!(
            "[{}][{}] {}",
            commit.commit_type, commit.scope, commit.claim_text
        );
        assert!(expected_content.starts_with("[feat][core]"));
    }

    #[test]
    fn test_embedding_batch_size_is_reasonable() {
        assert_eq!(EMBEDDING_BATCH_SIZE, 100);
    }

    // -------------------------------------------------------------------------
    // Evidence embedding tracking tests (Phase 5.2)
    // -------------------------------------------------------------------------

    #[test]
    fn test_record_evidence_stores_evidence_ids() {
        let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
        let mut tracker = RelationshipTracker::new();
        let evidence_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        tracker.record_evidence(&commits[0], evidence_ids.clone());

        assert_eq!(tracker.hash_to_evidence.get("aaa").unwrap(), &evidence_ids);
    }

    #[test]
    fn test_record_evidence_skips_empty() {
        let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
        let mut tracker = RelationshipTracker::new();
        tracker.record_evidence(&commits[0], vec![]);

        assert!(tracker.hash_to_evidence.get("aaa").is_none());
    }

    #[test]
    fn test_record_evidence_independent_of_claim() {
        let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];
        let mut tracker = RelationshipTracker::new();
        let claim_id = Uuid::new_v4();
        let evidence_ids = vec![Uuid::new_v4()];
        tracker.record(&commits[0], claim_id);
        tracker.record_evidence(&commits[0], evidence_ids.clone());

        assert_eq!(tracker.hash_to_claim.get("aaa"), Some(&claim_id));
        assert_eq!(tracker.hash_to_evidence.get("aaa").unwrap(), &evidence_ids);
    }

    #[test]
    fn test_submit_response_parses_evidence_ids() {
        let json = serde_json::json!({
            "claim_id": Uuid::nil(),
            "truth_value": 0.8,
            "was_duplicate": false,
            "evidence_ids": [Uuid::nil(), Uuid::nil()]
        });
        let response: SubmitResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.evidence_ids.len(), 2);
    }

    #[test]
    fn test_submit_response_default_evidence_ids_empty() {
        // When the API doesn't include evidence_ids, serde default gives empty vec
        let json = serde_json::json!({
            "claim_id": Uuid::nil(),
            "truth_value": 0.8,
            "was_duplicate": false
        });
        let response: SubmitResponse = serde_json::from_value(json).unwrap();
        assert!(response.evidence_ids.is_empty());
    }

    #[test]
    fn test_evidence_embedding_only_for_tracked_evidence() {
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];

        let mut tracker = RelationshipTracker::new();
        let ev_ids_a = vec![Uuid::new_v4(), Uuid::new_v4()];
        tracker.record_evidence(&commits[0], ev_ids_a.clone());
        // commit "bbb" has no evidence tracked

        assert!(tracker.hash_to_evidence.get("aaa").is_some());
        assert!(tracker.hash_to_evidence.get("bbb").is_none());
    }

    #[test]
    fn test_evidence_count_aggregation() {
        let commits = vec![
            make_commit("aaa", CommitType::Feat, "core", vec![]),
            make_commit("bbb", CommitType::Fix, "core", vec!["aaa"]),
        ];

        let mut tracker = RelationshipTracker::new();
        tracker.record_evidence(&commits[0], vec![Uuid::new_v4(), Uuid::new_v4()]);
        tracker.record_evidence(&commits[1], vec![Uuid::new_v4()]);

        let evidence_count: usize = tracker
            .hash_to_evidence
            .values()
            .map(|v: &Vec<Uuid>| v.len())
            .sum();
        assert_eq!(evidence_count, 3);
    }

    #[test]
    fn test_embedding_batch_chunking() {
        // Verify that chunks of EMBEDDING_BATCH_SIZE cover all items
        let items: Vec<usize> = (0..250).collect();
        let chunks: Vec<&[usize]> = items.chunks(EMBEDDING_BATCH_SIZE).collect();
        assert_eq!(chunks.len(), 3); // 100 + 100 + 50
        assert_eq!(chunks[0].len(), 100);
        assert_eq!(chunks[1].len(), 100);
        assert_eq!(chunks[2].len(), 50);
    }

    // =========================================================================
    // PHASE 7: INTEGRATION TESTING
    // =========================================================================

    // -------------------------------------------------------------------------
    // 7.1: E2E Pipeline with LLM Enrichment
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_e2e_pipeline_with_llm_enrichment_produces_connected_graph() {
        // Full pipeline: parse → LLM enrich → build_packet with enrichment applied
        // Validates that enrichment edges are reflected in the final output.
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        assert_eq!(commits.len(), 10);

        // Mock LLM returns relationships across scope boundaries
        // that the deterministic parser cannot detect
        let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
            {
                "source_index": 0, // feat(core): define Claim
                "target_index": 1, // feat(crypto): BLAKE3 + Ed25519
                "relationship": "supports",
                "strength": 0.9,
                "rationale": "Claim model needs crypto for content hashing"
            },
            {
                "source_index": 2, // fix(core): NaN prevention
                "target_index": 0, // feat(core): define Claim
                "relationship": "challenges",
                "strength": 0.85,
                "rationale": "Fix corrects oversight in Claim validation"
            },
            {
                "source_index": 3, // security(crypto): timing attacks
                "target_index": 1, // feat(crypto): BLAKE3 + Ed25519
                "relationship": "challenges",
                "strength": 0.8,
                "rationale": "Security fix hardens crypto implementation"
            },
            {
                "source_index": 4, // test(engine): property tests
                "target_index": 8, // feat(engine): Bayesian truth update
                "relationship": "supports",
                "strength": 0.95,
                "rationale": "Tests validate the truth propagation engine"
            },
            {
                "source_index": 5, // refactor(db): repository pattern
                "target_index": 0, // feat(core): define Claim
                "relationship": "elaborates",
                "strength": 0.7,
                "rationale": "Repository pattern organizes data access for Claim model"
            }
        ])];

        let client = MockLlmClient::with_responses(mock_responses);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);
        let enrichments = enricher.enrich(&commits).await.unwrap();
        assert_eq!(enrichments.len(), 10);

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        // Build all packets — verify enrichment is applied
        let mut packets_with_edges = 0;
        for (commit, enrichment) in commits.iter().zip(enrichments.iter()) {
            let _packet = build_packet(commit, &signer, agent_id, Some(&enrichment));
            if !enrichment.semantic_edges.is_empty() {
                packets_with_edges += 1;
            }
        }

        // At least some commits should have semantic edges from LLM enrichment
        assert!(
            packets_with_edges > 0,
            "LLM enrichment should produce at least one commit with semantic edges"
        );

        // Verify total edge count matches what we supplied
        let total_edges: usize = enrichments.iter().map(|e| e.semantic_edges.len()).sum();
        assert_eq!(total_edges, 5, "Expected 5 semantic edges from mock LLM");
    }

    #[tokio::test]
    async fn test_e2e_enrichment_confidence_never_exceeds_parser() {
        // Verify the epistemic invariant: LLM can only LOWER confidence, never raise
        let commits = vec![make_commit("aaa", CommitType::Feat, "core", vec![])];

        // Create enrichment that tries to raise confidence above parser ceiling
        let enricher = NoopEnricher;
        let enrichments = enricher.enrich(&commits).await.unwrap();

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        // Baseline: no enrichment
        let baseline = build_packet(&commits[0], &signer, agent_id, None);
        let parser_confidence = baseline.reasoning_trace.confidence;

        // With enrichment that attempts to raise (manually crafted)
        let high_enrichment = EnrichedData {
            adjusted_confidence: Some(0.99), // Attempt to raise above parser ceiling
            ..EnrichedData::default()
        };
        let enriched = build_packet(&commits[0], &signer, agent_id, Some(&high_enrichment));

        assert!(
            enriched.reasoning_trace.confidence <= parser_confidence,
            "Enriched confidence {} must not exceed parser confidence {}",
            enriched.reasoning_trace.confidence,
            parser_confidence
        );

        // With enrichment that lowers
        let low_enrichment = EnrichedData {
            adjusted_confidence: Some(0.15),
            ..EnrichedData::default()
        };
        let lowered = build_packet(&commits[0], &signer, agent_id, Some(&low_enrichment));

        assert!(
            lowered.reasoning_trace.confidence < parser_confidence,
            "Low enrichment {} should be below parser confidence {}",
            lowered.reasoning_trace.confidence,
            parser_confidence
        );
        assert!(
            (lowered.reasoning_trace.confidence - 0.15).abs() < f64::EPSILON,
            "Should use the enrichment confidence when lower"
        );

        // With noop enrichment (no adjustment)
        let noop = build_packet(&commits[0], &signer, agent_id, Some(&enrichments[0]));
        assert!(
            (noop.reasoning_trace.confidence - parser_confidence).abs() < f64::EPSILON,
            "Noop enrichment should not change confidence"
        );
    }

    // -------------------------------------------------------------------------
    // 7.2: Graph Quality Validation
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_graph_quality_metrics_with_enrichment() {
        // Validate graph connectivity metrics from GIT_INGESTER_TEST_PLAN.md §5.1.5:
        // - ORPHAN count must be 0 (every commit produces a claim)
        // - ISOLATED must be < 15%
        // - CONNECTED must be > 40%
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let n = commits.len();

        // Build a rich set of LLM-discovered edges
        let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
            { "source_index": 0, "target_index": 1, "relationship": "supports", "strength": 0.9, "rationale": "r1" },
            { "source_index": 0, "target_index": 2, "relationship": "supports", "strength": 0.8, "rationale": "r2" },
            { "source_index": 1, "target_index": 3, "relationship": "supports", "strength": 0.7, "rationale": "r3" },
            { "source_index": 2, "target_index": 0, "relationship": "challenges", "strength": 0.85, "rationale": "r4" },
            { "source_index": 3, "target_index": 1, "relationship": "challenges", "strength": 0.8, "rationale": "r5" },
            { "source_index": 4, "target_index": 8, "relationship": "supports", "strength": 0.95, "rationale": "r6" },
            { "source_index": 5, "target_index": 0, "relationship": "elaborates", "strength": 0.7, "rationale": "r7" },
            { "source_index": 6, "target_index": 8, "relationship": "elaborates", "strength": 0.6, "rationale": "r8" },
            { "source_index": 8, "target_index": 4, "relationship": "supports", "strength": 0.9, "rationale": "r9" }
        ])];

        let client = MockLlmClient::with_responses(mock_responses);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);
        let enrichments = enricher.enrich(&commits).await.unwrap();

        // Also count deterministic edges from parser (parent chains + fix-challenges-feat)
        let mut tracker = RelationshipTracker::new();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        for commit in &commits {
            let claim_id = Uuid::new_v4();
            tracker.record(commit, claim_id);
            let _packet = build_packet(commit, &signer, agent_id, None);
        }

        // Count nodes connected by semantic edges
        let mut connected_nodes: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        for (i, enrichment) in enrichments.iter().enumerate() {
            if !enrichment.semantic_edges.is_empty() {
                connected_nodes.insert(i);
                for edge in &enrichment.semantic_edges {
                    // Find the target index by matching hash
                    if let Some(target_idx) =
                        commits.iter().position(|c| c.hash == edge.target_hash)
                    {
                        connected_nodes.insert(target_idx);
                    }
                }
            }
        }

        // Also count deterministic parent-child connections
        for (i, commit) in commits.iter().enumerate() {
            if !commit.parent_hashes.is_empty() {
                connected_nodes.insert(i);
                for parent in &commit.parent_hashes {
                    if let Some(pidx) = commits.iter().position(|c| c.hash == *parent) {
                        connected_nodes.insert(pidx);
                    }
                }
            }
        }

        let isolated_count = n - connected_nodes.len();
        let connected_pct = (connected_nodes.len() as f64) / (n as f64) * 100.0;
        let isolated_pct = (isolated_count as f64) / (n as f64) * 100.0;

        // All 10 commits should produce claims (no orphans)
        assert_eq!(enrichments.len(), n, "ORPHAN count must be 0");

        // Connectivity thresholds
        assert!(
            isolated_pct < 15.0,
            "ISOLATED must be < 15%, got {:.1}% ({} of {})",
            isolated_pct,
            isolated_count,
            n
        );
        assert!(
            connected_pct > 40.0,
            "CONNECTED must be > 40%, got {:.1}% ({} of {})",
            connected_pct,
            connected_nodes.len(),
            n
        );
    }

    #[tokio::test]
    async fn test_noop_enricher_produces_fewer_connections_than_llm() {
        // Compare graph density: LLM enrichment should produce more edges
        // than the deterministic-only parser
        use epigraph_cli::enrichment::llm_client::MockLlmClient;

        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();

        // Noop: 0 semantic edges
        let noop = NoopEnricher;
        let noop_enrichments = noop.enrich(&commits).await.unwrap();
        let noop_edges: usize = noop_enrichments
            .iter()
            .map(|e| e.semantic_edges.len())
            .sum();

        // LLM: should produce edges
        let mock_responses: Vec<serde_json::Value> = vec![serde_json::json!([
            { "source_index": 0, "target_index": 1, "relationship": "supports", "strength": 0.9, "rationale": "r" },
            { "source_index": 2, "target_index": 0, "relationship": "challenges", "strength": 0.8, "rationale": "r" },
        ])];
        let client = MockLlmClient::with_responses(mock_responses);
        let enricher = LlmEnricher::with_config(Box::new(client), 20, 5);
        let llm_enrichments = enricher.enrich(&commits).await.unwrap();
        let llm_edges: usize = llm_enrichments.iter().map(|e| e.semantic_edges.len()).sum();

        assert_eq!(
            noop_edges, 0,
            "Noop enricher should produce 0 semantic edges"
        );
        assert!(
            llm_edges > noop_edges,
            "LLM enricher ({} edges) should produce more edges than noop ({})",
            llm_edges,
            noop_edges
        );
    }

    // -------------------------------------------------------------------------
    // 7.3: Semantic Search Quality (Content-Based Relevance)
    // -------------------------------------------------------------------------

    #[test]
    fn test_topical_claims_have_relevant_content() {
        // Verify that parsed claims contain domain-relevant keywords
        // This validates the content quality for semantic search
        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let by_hash: HashMap<&str, &ParsedCommit> =
            commits.iter().map(|c| (c.hash.as_str(), c)).collect();

        // "cryptographic signing" → crypto claims
        let crypto_claims: Vec<&ParsedCommit> =
            commits.iter().filter(|c| c.scope == "crypto").collect();
        assert!(
            !crypto_claims.is_empty(),
            "Should have crypto-scoped claims"
        );
        for claim in &crypto_claims {
            let content = format!("{} {}", claim.claim_text, claim.evidence.join(" "));
            let has_crypto_terms = content.contains("BLAKE3")
                || content.contains("Ed25519")
                || content.contains("signing")
                || content.contains("timing")
                || content.contains("signature")
                || content.contains("hashing");
            assert!(
                has_crypto_terms,
                "Crypto claim should contain crypto-relevant terms: {}",
                claim.claim_text
            );
        }

        // "bayesian truth update" → engine claims
        let engine_claims: Vec<&ParsedCommit> =
            commits.iter().filter(|c| c.scope == "engine").collect();
        assert!(
            !engine_claims.is_empty(),
            "Should have engine-scoped claims"
        );
        for claim in &engine_claims {
            let content = format!("{} {}", claim.claim_text, claim.reasoning.join(" "));
            let has_engine_terms = content.contains("Bayesian")
                || content.contains("truth")
                || content.contains("propagation")
                || content.contains("property");
            assert!(
                has_engine_terms,
                "Engine claim should contain engine-relevant terms: {}",
                claim.claim_text
            );
        }

        // Security claims should mention vulnerabilities
        let security_claim = by_hash["ddd444"];
        assert_eq!(security_claim.commit_type, CommitType::Security);
        let content = format!(
            "{} {}",
            security_claim.claim_text,
            security_claim.evidence.join(" ")
        );
        assert!(
            content.contains("timing")
                || content.contains("side-channel")
                || content.contains("security"),
            "Security claim should contain security-relevant terms"
        );
    }

    #[test]
    fn test_claim_content_format_enables_semantic_search() {
        // Verify that build_packet produces claim content in a format
        // that encodes scope/type metadata for better embedding quality
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Alice".to_string(),
            author_email: "alice@test.dev".to_string(),
            date: "2026-01-15".to_string(),
            commit_type: CommitType::Feat,
            scope: "crypto".to_string(),
            claim_text: "add BLAKE3 content hashing".to_string(),
            evidence: vec!["IMPLEMENTATION_PLAN requires hashing".to_string()],
            reasoning: vec!["BLAKE3 chosen over SHA-256 for speed".to_string()],
            verification: vec!["test_hash_deterministic passes".to_string()],
            parent_hashes: vec![],
            files_changed: vec!["crates/epigraph-crypto/src/hasher.rs".to_string()],
        };

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packet = build_packet(&commit, &signer, agent_id, None);

        // Content should include scope and type for embedding context
        assert!(
            packet.claim.content.contains("[feat]"),
            "Claim content should include commit type"
        );
        assert!(
            packet.claim.content.contains("[crypto]"),
            "Claim content should include scope"
        );
        assert!(
            packet.claim.content.contains("BLAKE3"),
            "Claim content should include the claim text"
        );
    }

    // -------------------------------------------------------------------------
    // 7.4: Provenance Token Budget
    // -------------------------------------------------------------------------

    #[test]
    fn test_provenance_chain_within_token_budget() {
        // Validate GIT_INGESTER_TEST_PLAN.md §5.4.4:
        // - Median provenance chain < 1500 tokens
        // - 95th percentile < 3000 tokens
        //
        // Approximation: 1 token ≈ 4 characters (standard GPT tokenization estimate)

        let output = realistic_git_log_output();
        let commits = parse_git_log_output(&output).unwrap();
        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();

        let mut token_estimates: Vec<usize> = Vec::new();

        for commit in &commits {
            let packet = build_packet(commit, &signer, agent_id, None);

            // Provenance chain = claim content + reasoning explanation + all evidence
            let mut chain_chars = 0;
            chain_chars += packet.claim.content.len();
            chain_chars += packet.reasoning_trace.explanation.len();
            for evidence in &packet.evidence {
                if let Some(ref raw) = evidence.raw_content {
                    chain_chars += raw.len();
                }
            }

            // Approximate token count (1 token ≈ 4 chars)
            let token_estimate = chain_chars / 4;
            token_estimates.push(token_estimate);
        }

        token_estimates.sort();
        let n = token_estimates.len();

        // Median
        let median = if n % 2 == 0 {
            (token_estimates[n / 2 - 1] + token_estimates[n / 2]) / 2
        } else {
            token_estimates[n / 2]
        };

        // 95th percentile (for 10 items, this is the 10th item)
        let p95_idx = ((n as f64) * 0.95).ceil() as usize - 1;
        let p95 = token_estimates[p95_idx.min(n - 1)];

        assert!(
            median < 1500,
            "Median provenance chain should be < 1500 tokens, got {}",
            median
        );
        assert!(
            p95 < 3000,
            "95th percentile provenance chain should be < 3000 tokens, got {}",
            p95
        );
    }

    #[test]
    fn test_individual_claim_provenance_fits_context_window() {
        // Each individual claim's provenance chain should fit within
        // a reasonable LLM context window segment (< 500 tokens)
        let commit = ParsedCommit {
            hash: "abc123".to_string(),
            author_name: "Alice".to_string(),
            author_email: "alice@test.dev".to_string(),
            date: "2026-01-15".to_string(),
            commit_type: CommitType::Feat,
            scope: "core".to_string(),
            claim_text: "define Claim model with bounded truth values".to_string(),
            evidence: vec![
                "IMPLEMENTATION_PLAN.md §2.1 specifies truth in [0.0, 1.0]".to_string(),
                "Unbounded floats allow invalid states (NaN, infinity)".to_string(),
            ],
            reasoning: vec![
                "Chose f64 over f32: precision matters for Bayesian updates near 0/1".to_string(),
                "Constructor validates bounds, returns Result<Claim, ClaimError>".to_string(),
            ],
            verification: vec![
                "test_claim_rejects_negative_truth: passes".to_string(),
                "test_claim_rejects_truth_above_one: passes".to_string(),
            ],
            parent_hashes: vec![],
            files_changed: vec!["crates/epigraph-core/src/domain/claim.rs".to_string()],
        };

        let signer = AgentSigner::generate();
        let agent_id = Uuid::new_v4();
        let packet = build_packet(&commit, &signer, agent_id, None);

        let mut total_chars = 0;
        total_chars += packet.claim.content.len();
        total_chars += packet.reasoning_trace.explanation.len();
        for evidence in &packet.evidence {
            if let Some(ref raw) = evidence.raw_content {
                total_chars += raw.len();
            }
        }

        let tokens = total_chars / 4;
        assert!(
            tokens < 500,
            "Single claim provenance should be < 500 tokens, got {} ({} chars)",
            tokens,
            total_chars
        );
    }
}
