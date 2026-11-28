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
use epigraph_crypto::{AgentSigner, ContentHasher, SignedEntity};
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
    /// Bearer token for agent registration (required for /agents endpoint)
    token: Option<String>,
    /// PR-hierarchical ingestion mode (repo → PR → commit hierarchy)
    pr_mode: bool,
    /// Repository slug `owner/name` (PR mode)
    repo_slug: Option<String>,
    /// Pull-request number (PR mode)
    pr_number: Option<u64>,
    /// Pull-request title (PR mode)
    pr_title: Option<String>,
    /// Pull-request body / description (PR mode)
    pr_body: Option<String>,
    /// Merge commit SHA of the PR (PR mode)
    merge_sha: Option<String>,
    /// ISO-8601 merge timestamp (PR mode)
    merged_at: Option<String>,
    /// GitHub login of the PR author (PR mode)
    pr_author: Option<String>,
    /// Git revision range `A..B` for the PR's commits (PR mode)
    rev_range: Option<String>,
    /// Explicit orchestrator agent id, overriding trailer/env resolution (PR mode)
    orchestrator_id: Option<Uuid>,
    /// File holding the host secret that keys the author and repo-root agent
    /// keys (`--author-key-file`, else `EPIGRAPH_GIT_AUTHOR_KEY_FILE`)
    author_key_file: Option<PathBuf>,
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
        let mut token = None;
        let mut pr_mode = false;
        let mut repo_slug = None;
        let mut pr_number = None;
        let mut pr_title = None;
        let mut pr_body = None;
        let mut merge_sha = None;
        let mut merged_at = None;
        let mut pr_author = None;
        let mut rev_range = None;
        let mut orchestrator_id = None;
        let mut author_key_file = None;

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
                    // The server's PUT /api/v1/{claims,evidence}/:id/embedding
                    // routes are gone (backlog 9bef22f3): any bearer could
                    // overwrite any row's vector from caller-supplied text.
                    return Err(
                        "--embed was removed: the server embeds each claim when the \
                                packet is submitted, and `epigraph-cli reembed` backfills \
                                claim and evidence vectors"
                            .into(),
                    );
                }
                "--token" | "-t" => {
                    i += 1;
                    token = Some(
                        args.get(i)
                            .ok_or("--token requires a bearer token argument")?
                            .clone(),
                    );
                }
                "--pr-ingest" => {
                    pr_mode = true;
                }
                "--repo-slug" => {
                    i += 1;
                    repo_slug = Some(
                        args.get(i)
                            .ok_or("--repo-slug requires an owner/name argument")?
                            .clone(),
                    );
                }
                "--pr-number" => {
                    i += 1;
                    let val = args.get(i).ok_or("--pr-number requires a number")?;
                    pr_number = Some(
                        val.parse::<u64>()
                            .map_err(|_| format!("--pr-number must be a number, got: {val}"))?,
                    );
                }
                "--pr-title" => {
                    i += 1;
                    pr_title = Some(
                        args.get(i)
                            .ok_or("--pr-title requires a string argument")?
                            .clone(),
                    );
                }
                "--pr-body" => {
                    i += 1;
                    pr_body = Some(
                        args.get(i)
                            .ok_or("--pr-body requires a string argument")?
                            .clone(),
                    );
                }
                "--merge-sha" => {
                    i += 1;
                    merge_sha = Some(
                        args.get(i)
                            .ok_or("--merge-sha requires a SHA argument")?
                            .clone(),
                    );
                }
                "--merged-at" => {
                    i += 1;
                    merged_at = Some(
                        args.get(i)
                            .ok_or("--merged-at requires an ISO-8601 timestamp argument")?
                            .clone(),
                    );
                }
                "--pr-author" => {
                    i += 1;
                    pr_author = Some(
                        args.get(i)
                            .ok_or("--pr-author requires a login argument")?
                            .clone(),
                    );
                }
                "--rev-range" => {
                    i += 1;
                    rev_range = Some(
                        args.get(i)
                            .ok_or("--rev-range requires an A..B revision range")?
                            .clone(),
                    );
                }
                "--orchestrator-id" => {
                    i += 1;
                    let val = args.get(i).ok_or("--orchestrator-id requires a UUID")?;
                    orchestrator_id =
                        Some(val.parse::<Uuid>().map_err(|_| {
                            format!("--orchestrator-id must be a UUID, got: {val}")
                        })?);
                }
                "--author-key-file" => {
                    i += 1;
                    author_key_file = Some(PathBuf::from(
                        args.get(i)
                            .ok_or("--author-key-file requires a path argument")?,
                    ));
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

        let token = token_or_env(token, std::env::var("EPIGRAPH_TOKEN").ok());
        let author_key_file = author_key_file.or_else(|| {
            std::env::var_os("EPIGRAPH_GIT_AUTHOR_KEY_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        });

        Ok(Self {
            repo,
            endpoint,
            agent_key,
            dry_run,
            since,
            limit,
            enricher,
            token,
            pr_mode,
            repo_slug,
            pr_number,
            pr_title,
            pr_body,
            merge_sha,
            merged_at,
            pr_author,
            rev_range,
            orchestrator_id,
            author_key_file,
        })
    }
}

/// The Bearer token: `--token` when given, else a non-empty `EPIGRAPH_TOKEN`.
/// The variable keeps the token off the command line (and out of
/// `/proc/<pid>/cmdline`), which is how the reconciler hands it over.
fn token_or_env(flag: Option<String>, env: Option<String>) -> Option<String> {
    flag.or_else(|| env.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()))
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
  -t, --token <TOKEN>     Bearer token [default: $EPIGRAPH_TOKEN]
      --author-key-file <PATH>  File holding the 32-byte host secret (64 hex
                              characters) that keys every author and repo-root
                              agent key; required for a live --pr-ingest or
                              per-author run [default: $EPIGRAPH_GIT_AUTHOR_KEY_FILE]
  -h, --help              Show this help message

PR-hierarchical mode (build a repo -> PR -> commit claim hierarchy):
      --pr-ingest             Enable PR-hierarchical ingestion mode
      --repo-slug <OWNER/NAME>  Repository slug (e.g. epigraph-io/epigraph)
      --pr-number <N>         Pull-request number
      --pr-title <TITLE>      Pull-request title
      --pr-body <BODY>        Pull-request body / description
      --merge-sha <SHA>       Merge commit SHA
      --merged-at <ISO8601>   Merge timestamp (ISO-8601)
      --pr-author <LOGIN>     GitHub login of the PR author
      --rev-range <A..B>      Git revision range covering the PR's commits
      --orchestrator-id <UUID>  Explicit orchestrator agent id (overrides the
                              Epigraph-Orchestrator-Id trailer and
                              $EPIGRAPH_DEFAULT_ORCHESTRATOR_ID)";

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
    /// Formatting only (rustfmt, whitespace): a one-line body, no sections.
    Style,
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
            "style" => Self::Style,
            _ => Self::Unknown,
        }
    }

    /// Map commit type to API methodology string
    fn methodology(&self) -> &'static str {
        match self {
            Self::Feat => "extraction",
            Self::Fix | Self::Refactor | Self::Security => "deductive",
            Self::Test | Self::Perf => "instrumental",
            Self::Docs | Self::Style | Self::Chore | Self::Unknown => "heuristic",
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
            Self::Docs | Self::Style => 0.4,
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
            Self::Style => "style",
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
    /// The message's trailer block (`Key: value` lines), e.g.
    /// `Epigraph-Orchestrator-Id: <uuid>`; never part of a section.
    trailers: Vec<String>,
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
#[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
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
    client: std::sync::Arc<dyn epigraph_cli::enrichment::llm_client::LlmProvider>,
    window_size: usize,
    overlap: usize,
}

impl LlmEnricher {
    fn new(client: std::sync::Arc<dyn epigraph_cli::enrichment::llm_client::LlmProvider>) -> Self {
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
        client: std::sync::Arc<dyn epigraph_cli::enrichment::llm_client::LlmProvider>,
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

/// Single-word keys that are trailers by convention. Any other trailer key
/// must be hyphenated (`Co-Authored-By`, `Signed-off-by`, `Claude-Session`,
/// `Epigraph-Orchestrator-Id`), so a closing one-line paragraph such as
/// `Verification: cargo test passes` or `Note: see #12` stays message text.
const SINGLE_WORD_TRAILER_KEYS: &[&str] = &[
    "Fixes",
    "Closes",
    "Resolves",
    "Refs",
    "References",
    "Cc",
    "Link",
    "Bug",
];

/// Is `line` a git trailer line (`Key: value`, the key one token of letters,
/// digits and `-`, hyphenated or a conventional single-word key)? Section
/// headers (`Verification:`) carry no value and are not trailers; neither is a
/// bullet (`- cargo test: ok`), whose key holds a space or starts with a marker.
fn is_trailer_line(line: &str) -> bool {
    let Some((key, value)) = line.split_once(':') else {
        return false;
    };
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphanumeric())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && (key.contains('-')
            || SINGLE_WORD_TRAILER_KEYS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(key)))
        && value.starts_with(char::is_whitespace)
        && !value.trim().is_empty()
}

/// Split a commit message into its body and its trailer block, as git does:
/// the trailer block is the LAST paragraph (after the last blank line), and only
/// when every line of it is a trailer line and it is not the header paragraph.
/// `Co-Authored-By:`, `Claude-Session:` and `Epigraph-Orchestrator-Id:` live
/// there, so they are kept out of the Evidence/Reasoning/Verification sections
/// and handed to the trailer readers instead.
fn split_trailers(message: &str) -> (String, Vec<String>) {
    let lines: Vec<&str> = message.trim_end().lines().collect();
    let Some(last_blank) = lines.iter().rposition(|l| l.trim().is_empty()) else {
        return (message.trim_end().to_string(), Vec::new());
    };
    let block = &lines[last_blank + 1..];
    let first_content = lines.iter().position(|l| !l.trim().is_empty());
    if block.is_empty()
        || first_content.is_some_and(|i| i > last_blank)
        || !block.iter().all(|l| is_trailer_line(l.trim()))
    {
        return (message.trim_end().to_string(), Vec::new());
    }
    let body = lines[..last_blank].join("\n").trim_end().to_string();
    let trailers = block.iter().map(|l| l.trim().to_string()).collect();
    (body, trailers)
}

/// Strip a list marker (`- `, `* `, `+ `, `1. `, `1) `) from a trimmed line.
/// Returns `None` when the line does not start a list item.
fn strip_bullet(trimmed: &str) -> Option<&str> {
    for m in ["- ", "* ", "+ "] {
        if let Some(rest) = trimmed.strip_prefix(m) {
            return Some(rest.trim_start());
        }
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 {
        let rest = &trimmed[digits..];
        if let Some(r) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return Some(r.trim_start());
        }
    }
    None
}

/// Parse a raw commit message into structured form.
///
/// Each list item under a section is one entry: a line that starts with a list
/// marker opens an item, and a following line with no blank line between (a
/// wrapped bullet) continues it. The trailer block (`split_trailers`) is not part
/// of any section.
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
    let (body, _trailers) = split_trailers(message);
    let mut lines = body.lines();

    // First line is the header
    let first_line = lines.next().unwrap_or("");
    let (commit_type, scope, claim_text) = parse_header(first_line);

    let mut evidence: Vec<String> = Vec::new();
    let mut reasoning: Vec<String> = Vec::new();
    let mut verification: Vec<String> = Vec::new();
    let mut current_section = Section::None;
    // Whether the previous line belonged to an item that a wrapped line extends.
    let mut item_open = false;

    for line in lines {
        let trimmed = line.trim();

        // Check for section header
        if let Some(section) = detect_section(trimmed) {
            current_section = section;
            item_open = false;
            continue;
        }

        // A blank line closes the open item.
        if trimmed.is_empty() {
            item_open = false;
            continue;
        }

        let items = match current_section {
            Section::Evidence => &mut evidence,
            Section::Reasoning => &mut reasoning,
            Section::Verification => &mut verification,
            Section::None => continue, // Skip lines outside sections
        };

        match (strip_bullet(trimmed), items.last_mut()) {
            (None, Some(last)) if item_open => {
                last.push(' ');
                last.push_str(trimmed);
            }
            (bullet, _) => items.push(bullet.unwrap_or(trimmed).to_string()),
        }
        item_open = true;
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

/// Run `git log <rev_range> --no-merges` and parse the output into ParsedCommits.
///
/// PR mode supplies an explicit revision range (e.g. `base..head`) instead of a
/// `--since` date so exactly the PR's own commits are ingested. `--no-merges`
/// keeps merge commits out of the claim hierarchy (design §4.2: only real work
/// commits become claims). Reuses the same format string and `parse_git_log_output`
/// as `parse_git_log` so both paths produce identical `ParsedCommit`s.
#[allow(dead_code)]
fn parse_git_log_range(
    repo: &std::path::Path,
    rev_range: &str,
) -> Result<Vec<ParsedCommit>, String> {
    let format = format!(
        "{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%aI{FIELD_SEP}%P{FIELD_SEP}%B"
    );

    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("log")
        .arg(format!("--format={format}"))
        .arg("--name-only")
        .arg("--no-merges")
        .arg(rev_range)
        .output()
        .map_err(|e| format!("Failed to run git log: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git log {rev_range} failed: {stderr}"));
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
        let (_, trailers) = split_trailers(&message);

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
            trailers,
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

/// The wire shape of the server's `routes::submit::ClaimSubmission`, field for
/// field as the server RE-serializes it, because the packet signature covers
/// the server's canonical bytes (`EpistemicPacket::signable_bytes`): an absent
/// `initial_truth` is skipped (the server refuses `null`), and `properties` /
/// `labels` are always present (`null` / `[]`), as the server writes them.
#[derive(Debug, Serialize)]
struct ClaimSubmission {
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_truth: Option<f64>,
    agent_id: Uuid,
    idempotency_key: Option<String>,
    pub properties: Option<serde_json::Value>,
    /// Labels set on the claim AT CREATION by the server (creator-owned), so a
    /// multi-principal writer needs no ownership-gated label PATCH / claims:admin.
    /// Signed like every other claim field, so a packet is (re-)signed after
    /// its labels are set ([`labelled_and_signed`]).
    pub labels: Vec<String>,
}

/// The bytes the submit route verifies a packet signature over: the canonical
/// JSON of `(claim, evidence, reasoning_trace)`, signature excluded — the same
/// construction as the server's `EpistemicPacket::signable_bytes`.
#[derive(Serialize)]
struct PacketSignable<'a> {
    claim: &'a ClaimSubmission,
    evidence: &'a [EvidenceSubmission],
    reasoning_trace: &'a ReasoningTraceSubmission,
}

/// Sign `packet` as its claim's agent, over [`PacketSignable`]. The server
/// checks this signature (raw Ed25519 over the canonical bytes, not a
/// domain-separated entity signature) when `EPIGRAPH_REQUIRE_SIGNATURES` is on.
///
/// The canonical bytes are taken from the packet as the server will PARSE it:
/// serialized to JSON text and read back, so every float is the f64 the
/// server's parser produces from the text the request carries, not the
/// client's in-memory value (serde_json's default float parse is not
/// guaranteed to round-trip every f64).
fn sign_packet(packet: &mut EpistemicPacket, signer: &AgentSigner) {
    let wire = serde_json::to_vec(&PacketSignable {
        claim: &packet.claim,
        evidence: &packet.evidence,
        reasoning_trace: &packet.reasoning_trace,
    })
    .expect("a packet of strings, numbers and JSON values always serializes");
    let as_parsed: serde_json::Value =
        serde_json::from_slice(&wire).expect("serde_json reads back its own output");
    let canonical =
        epigraph_crypto::to_canonical_bytes(&as_parsed).expect("a JSON value always serializes");
    packet.signature = hex::encode(signer.sign(&canonical));
}

/// Set the creation labels on `packet`, then sign it when the ingester holds
/// the claim agent's key. Labels are inside the signed bytes, so signing must
/// come after they are set; a packet whose agent key the ingester does not
/// hold (`signer = None`, the PR node) keeps whatever signature it carries.
fn labelled_and_signed(
    mut packet: EpistemicPacket,
    labels: &[&str],
    signer: Option<&AgentSigner>,
) -> EpistemicPacket {
    packet.claim.labels = labels.iter().map(|s| s.to_string()).collect();
    if let Some(signer) = signer {
        sign_packet(&mut packet, signer);
    }
    packet
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

/// The host secret that keys every git-author and repo-root signing key.
///
/// The key for an author is `blake3::keyed_hash(secret, "epigraph-git-author-v2:" +
/// normalized email)`. Without the secret, that key would be a function of the
/// email alone, which is public in `git log`. An agent client accepts any
/// assertion that verifies under its agent's key, so once such a key has a
/// login (servers before backlog 2f87eb08 gave every newly registered agent an
/// active client; current ones only on an admin-approved `login` request) a key
/// anyone can compute is a login anyone can use. The secret makes the key
/// stable on the host that holds it and unguessable everywhere else, the same
/// pattern as the keyed LLM-agent identity (`keypair_from_llm_agent_keyed`).
struct GitAuthorKeys {
    secret: [u8; 32],
}

/// Domain-separation prefixes for the keyed derivation. Changing one changes
/// every derived agent, so they are versioned.
const GIT_AUTHOR_KEY_CONTEXT: &str = "epigraph-git-author-v2:";
const GIT_REPO_ROOT_KEY_CONTEXT: &str = "epigraph-git-repo-root-v2";

impl GitAuthorKeys {
    /// Parse a key file: exactly 64 hex characters (32 bytes) after trimming,
    /// not all zero. `openssl rand -hex 32` makes one. The error never echoes
    /// the content.
    fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim();
        let mut secret = [0u8; 32];
        if t.len() != 64 || hex::decode_to_slice(t, &mut secret).is_err() {
            return Err("the author key file must hold exactly 64 hex characters \
                        (32 bytes), e.g. from `openssl rand -hex 32`"
                .to_string());
        }
        if secret == [0u8; 32] {
            return Err("the author key file holds an all-zero key".to_string());
        }
        Ok(Self { secret })
    }

    fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read author key file {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// A random secret for a dry run with no key file. Nothing is registered in
    /// a dry run, so the keys only need to be distinct per author within it.
    fn ephemeral() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self { secret }
    }

    fn signer_for(&self, input: &str) -> AgentSigner {
        let seed = blake3::keyed_hash(&self.secret, input.as_bytes());
        AgentSigner::from_bytes(seed.as_bytes())
            .expect("32-byte blake3 hash is a valid Ed25519 seed")
    }

    /// The signer for a git author. The email is normalized (trimmed and
    /// lowercased) and the display name is not an input, so one human maps to
    /// one agent across runs and repos on this host. This is the interim
    /// author-DID scheme pending the project's real DID system (spec §6.3).
    fn author(&self, email: &str) -> AgentSigner {
        let normalized = email.trim().to_ascii_lowercase();
        self.signer_for(&format!("{GIT_AUTHOR_KEY_CONTEXT}{normalized}"))
    }

    /// The signer for the single repo-root *system* agent. Every repo-root node
    /// is authored by it, so `(content_hash, agent_id)` is constant across every
    /// PR and orchestrator and the server's find-or-create collapses it to one
    /// node. Its input is not an email, so no git author can collide with it.
    fn repo_root(&self) -> AgentSigner {
        self.signer_for(GIT_REPO_ROOT_KEY_CONTEXT)
    }
}

/// The author keys for a run that derives author keys (`--pr-ingest`, or
/// `--agent-key per-author`): the key file when one is given; with none, a live
/// run is refused before any network call and a dry run gets an ephemeral
/// secret.
fn author_keys_for_run(
    key_file: Option<&std::path::Path>,
    dry_run: bool,
) -> Result<GitAuthorKeys, String> {
    match key_file {
        Some(path) => GitAuthorKeys::load(path),
        None if dry_run => Ok(GitAuthorKeys::ephemeral()),
        None => Err(
            "a live run needs --author-key-file (or EPIGRAPH_GIT_AUTHOR_KEY_FILE): \
             without the host secret every author key is computable from the public \
             git log, so any login that key ever holds is usable by anyone"
                .to_string(),
        ),
    }
}

/// Resolve (and register if needed) the stable agent id for a git author.
/// Caches the resolved agent id per email within a run to avoid duplicate POSTs.
///
/// `AgentSigner` is not `Clone` and the key is fully derived from the host secret
/// and the (normalized) email, so the cache stores only the `Uuid`; the signer is
/// rebuilt deterministically via `GitAuthorKeys::author` on every call. `POST /agents` is find-or-create on
/// `public_key`, so a later run gets the same id back; the cache only saves the
/// repeated POSTs within a run.
#[allow(dead_code)]
async fn resolve_author_agent(
    client: &reqwest::Client,
    endpoint: &str,
    keys: &GitAuthorKeys,
    cache: &mut std::collections::HashMap<String, Uuid>,
    display_name: &str,
    email: &str,
) -> Result<(AgentSigner, Uuid), String> {
    let key = email.trim().to_ascii_lowercase();
    let signer = keys.author(email);
    if let Some(&agent_id) = cache.get(&key) {
        return Ok((signer, agent_id));
    }
    let agent_id = AgentRegistry::register_agent(client, endpoint, &signer, display_name).await?;
    cache.insert(key, agent_id);
    Ok((signer, agent_id))
}

/// Parse an `Epigraph-Orchestrator-Id: <uuid>` trailer from a PR body or commit message.
/// Case-insensitive key match; last occurrence wins (trailers live at the bottom).
fn parse_orchestrator_trailer(text: &str) -> Option<Uuid> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("Epigraph-Orchestrator-Id") {
                v.trim().parse::<Uuid>().ok()
            } else {
                None
            }
        })
        .next_back()
}

/// Resolve the implementing orchestrator agent id for a PR, first match wins:
/// 1) `explicit` (`--orchestrator-id`);
/// 2) an `Epigraph-Orchestrator-Id:` trailer in the PR body;
/// 3) that trailer in a commit message's trailer block, oldest commit first;
/// 4) `env_default` (`EPIGRAPH_DEFAULT_ORCHESTRATOR_ID`), a fallback only.
///
/// Returns an error if none is present (the PR claim MUST have an author), or if
/// the fallback is set but is not a UUID. The resolver only determines the id,
/// never mints one; a bogus id surfaces at submit time.
fn resolve_orchestrator_agent(
    explicit: Option<Uuid>,
    pr_body: &str,
    commits: &[ParsedCommit],
    env_default: Option<&str>,
) -> Result<Uuid, String> {
    if let Some(id) = explicit {
        return Ok(id);
    }
    if let Some(id) = parse_orchestrator_trailer(pr_body) {
        return Ok(id);
    }
    for c in commits {
        if let Some(id) = parse_orchestrator_trailer(&c.trailers.join("\n")) {
            return Ok(id);
        }
    }
    match env_default.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v
            .parse::<Uuid>()
            .map_err(|_| format!("EPIGRAPH_DEFAULT_ORCHESTRATOR_ID must be a UUID, got: {v}")),
        None => Err(
            "no --orchestrator-id, no Epigraph-Orchestrator-Id trailer in the PR body or a \
             commit, and EPIGRAPH_DEFAULT_ORCHESTRATOR_ID unset"
                .to_string(),
        ),
    }
}

/// Candidate resolution references extracted from PR body + commit text.
#[derive(Debug, Default, PartialEq)]
struct References {
    claim_uuids: Vec<Uuid>,
    pr_numbers: Vec<u64>,
}

/// Extract resolution references from PR body + commit text:
/// - any token parseable as a UUID that appears after "Resolves" or in a
///   "Resolves-Claim:" trailer;
/// - any `#<n>` token (PR/issue numbers).
///
/// This deliberately treats *any* UUID in the text as a candidate claim
/// reference (the `Resolves`/`Resolves-Claim:` context is human convention);
/// existence is validated before any edge is created (`link_resolutions`), so a
/// stray UUID that isn't a claim is simply dropped at lookup time.
#[allow(dead_code)]
fn extract_references(text: &str) -> References {
    let mut r = References::default();
    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let tok = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '#');
        if let Ok(id) = tok.parse::<Uuid>() {
            if !r.claim_uuids.contains(&id) {
                r.claim_uuids.push(id);
            }
        } else if let Some(num) = tok.strip_prefix('#').and_then(|n| n.parse::<u64>().ok()) {
            if !r.pr_numbers.contains(&num) {
                r.pr_numbers.push(num);
            }
        }
    }
    r
}

/// Per-author agent state: each unique git author gets their own signer and agent ID
struct AuthorAgent {
    signer: AgentSigner,
    agent_id: Uuid,
}

/// Registry mapping author emails to their agent state
struct AgentRegistry {
    keys: GitAuthorKeys,
    agents: HashMap<String, AuthorAgent>,
}

impl AgentRegistry {
    fn new(keys: GitAuthorKeys) -> Self {
        Self {
            keys,
            agents: HashMap::new(),
        }
    }

    /// Get or create an agent for the given author email. The key is derived
    /// from the host secret and the normalized email (`GitAuthorKeys::author`),
    /// so the same author maps to the same agent on every run, as in PR mode;
    /// the id is a placeholder until registration returns the server's id (live
    /// mode).
    fn get_or_create(&mut self, email: &str, display_name: &str) -> &AuthorAgent {
        let key = email.trim().to_ascii_lowercase();
        let keys = &self.keys;
        self.agents.entry(key).or_insert_with(|| {
            let signer = keys.author(email);
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
}

impl RelationshipTracker {
    fn new() -> Self {
        Self {
            scope_feats: HashMap::new(),
            hash_to_claim: HashMap::new(),
        }
    }

    /// Record a submitted claim for relationship tracking
    fn record(&mut self, commit: &ParsedCommit, claim_id: Uuid) {
        self.hash_to_claim.insert(commit.hash.clone(), claim_id);
        if commit.commit_type == CommitType::Feat && !commit.scope.is_empty() {
            self.scope_feats.insert(commit.scope.clone(), claim_id);
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
        let sig = hex::encode(signer.sign_entity(SignedEntity::Evidence, &content_hash));
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
        let sig = hex::encode(signer.sign_entity(SignedEntity::Evidence, &content_hash));
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
        labels: Vec::new(), // set by submit_find_or_create at creation
    };

    // Signed over the submit route's canonical bytes, so the packet passes
    // with EPIGRAPH_REQUIRE_SIGNATURES on. `submit_find_or_create` re-signs it
    // after setting its labels (PR mode).
    let mut packet = EpistemicPacket {
        claim: claim_submission,
        evidence: evidence_items,
        reasoning_trace: trace,
        signature: String::new(),
    };
    sign_packet(&mut packet, signer);
    packet
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

/// Build the find-or-create packet for a repository's root node.
///
/// Keyed on a stable `repo:{slug}` idempotency_key so re-runs across every PR
/// resolve to the same persistent root claim (the hierarchy's anchor). The
/// `node`/`repo` properties let downstream queries find the root by repository.
fn build_repo_packet(repo_slug: &str, agent_id: Uuid, signer: &AgentSigner) -> EpistemicPacket {
    let content = format!("Repository {repo_slug} — development history (commits and PRs).");
    let evidence_text = format!("Repository slug: {repo_slug}");
    let ev = EvidenceSubmission {
        content_hash: hex::encode(ContentHasher::hash(evidence_text.as_bytes())),
        evidence_type: EvidenceTypeSubmission::Document {
            source_url: Some(format!("repo://{repo_slug}")),
            mime_type: "text/plain".into(),
        },
        raw_content: Some(evidence_text.clone()),
        signature: Some(hex::encode(signer.sign_entity(
            SignedEntity::Evidence,
            &ContentHasher::hash(evidence_text.as_bytes()),
        ))),
    };
    let mut packet = EpistemicPacket {
        claim: ClaimSubmission {
            content,
            initial_truth: Some(0.95),
            agent_id,
            idempotency_key: Some(format!("repo:{repo_slug}")),
            properties: Some(serde_json::json!({
                "source": "git-history", "node": "repo", "repo": repo_slug
            })),
            labels: Vec::new(), // set by submit_find_or_create at creation
        },
        evidence: vec![ev],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: "heuristic".into(),
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.95,
            explanation: format!("Root node for repository {repo_slug}"),
            signature: None,
        },
        signature: String::new(),
    };
    sign_packet(&mut packet, signer);
    packet
}

/// Metadata describing a single merged pull request, supplied by the CI caller.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PrMeta {
    repo_slug: String,
    number: u64,
    title: String,
    body: String,
    merge_sha: String,
    merged_at: String, // ISO-8601
    author_login: String,
}

/// Build the find-or-create packet for a PR node. `orchestrator_id` is the
/// implementing orchestrator agent (resolved upstream), which authors the PR
/// claim per the design's attribution rule (§6.1).
///
/// Keyed on a stable `pr:{slug}#{number}` idempotency_key so re-runs of the same
/// PR resolve to one claim. The PR body is carried as evidence; the merge sha,
/// merge time, url, and number live in `properties` for downstream datestamped
/// edge linking and resolution lookup.
#[allow(dead_code)]
fn build_pr_packet(meta: &PrMeta, orchestrator_id: Uuid) -> EpistemicPacket {
    let content = format!("[PR #{}] {}", meta.number, meta.title);
    let body = if meta.body.trim().is_empty() {
        meta.title.clone()
    } else {
        meta.body.clone()
    };
    let url = format!("https://github.com/{}/pull/{}", meta.repo_slug, meta.number);
    let ev = EvidenceSubmission {
        content_hash: hex::encode(ContentHasher::hash(body.as_bytes())),
        evidence_type: EvidenceTypeSubmission::Document {
            source_url: Some(url.clone()),
            mime_type: "text/markdown".into(),
        },
        raw_content: Some(body),
        signature: None,
    };
    EpistemicPacket {
        claim: ClaimSubmission {
            content,
            initial_truth: Some(0.8),
            agent_id: orchestrator_id,
            idempotency_key: Some(format!("pr:{}#{}", meta.repo_slug, meta.number)),
            properties: Some(serde_json::json!({
                "source": "git-history", "node": "pr",
                "repo": meta.repo_slug, "pr_number": meta.number,
                "merge_sha": meta.merge_sha, "merged_at": meta.merged_at,
                "url": url,
                "author_login": meta.author_login, "orchestrator_agent_id": orchestrator_id,
            })),
            labels: Vec::new(), // set by submit_find_or_create at creation
        },
        evidence: vec![ev],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: "heuristic".into(),
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.8,
            explanation: format!("PR #{} merged at {}", meta.number, meta.merged_at),
            signature: None,
        },
        // UNSIGNED: the PR node is authored by the orchestrator agent, whose
        // private key this ingester does not hold, and the submit route verifies
        // the signature against `claim.agent_id`'s key. This placeholder is
        // accepted only while EPIGRAPH_REQUIRE_SIGNATURES is off; with it on,
        // the PR node is refused (401). See backlog 7d9e60c6.
        signature: "0".repeat(128),
    }
}

/// Submit a packet and return its claim id. Because the packet carries a stable
/// `idempotency_key`, a second call returns the same `claim_id` (`was_duplicate=true`),
/// making this the find-or-create primitive for the hierarchy's nodes.
///
/// Labels are baked into the packet's claim so the SERVER sets them AT CREATION
/// (as the creating principal), instead of a separate ownership-gated
/// `PATCH /claims/{id}/labels` that would require `claims:admin` — the ingester
/// creates claims under system/author/orchestrator agents it does not "own", so
/// a post-hoc relabel would be rejected. Labels are applied only on the create
/// path server-side; a duplicate submit leaves the existing claim's labels intact.
#[allow(dead_code)]
async fn submit_find_or_create(
    client: &reqwest::Client,
    endpoint: &str,
    packet: EpistemicPacket,
    labels: &[&str],
    signer: Option<&AgentSigner>,
) -> Result<Uuid, String> {
    let packet = labelled_and_signed(packet, labels, signer);
    let url = format!("{endpoint}/api/v1/submit/packet");
    let resp = client
        .post(&url)
        .json(&packet)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("submit failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "submit {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let parsed: SubmitResponse = resp
        .json()
        .await
        .map_err(|e| format!("decode submit resp: {e}"))?;
    Ok(parsed.claim_id)
}

/// Find-or-create the repository's root node and return its claim id, labelled
/// `source:git-history` / `node:repo` / `repo:<slug>`.
#[allow(dead_code)]
async fn ensure_repo_node(
    client: &reqwest::Client,
    endpoint: &str,
    repo_slug: &str,
    agent_id: Uuid,
    signer: &AgentSigner,
) -> Result<Uuid, String> {
    let packet = build_repo_packet(repo_slug, agent_id, signer);
    let label = format!("repo:{repo_slug}");
    submit_find_or_create(
        client,
        endpoint,
        packet,
        &["source:git-history", "node:repo", &label],
        Some(signer),
    )
    .await
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

/// Build a generic POST /api/v1/edges body. Uses the generic endpoint (not
/// /edges/hierarchical) because only this one accepts `valid_from` +
/// `if_not_exists`, which the hierarchy needs for datestamping and re-run safety.
#[allow(dead_code)]
fn edge_body(
    source_id: Uuid,
    target_id: Uuid,
    relationship: &str,
    valid_from: Option<&str>,
) -> serde_json::Value {
    let mut b = serde_json::json!({
        "source_id": source_id,
        "target_id": target_id,
        "source_type": "claim",
        "target_type": "claim",
        "relationship": relationship,
        "if_not_exists": true,
        "properties": { "source": "git-history" },
    });
    if let Some(ts) = valid_from {
        b["valid_from"] = serde_json::json!(ts);
    }
    b
}

/// Create an idempotent, datestamped edge via POST /api/v1/edges. Both 200 and
/// 201 mean success (existing edge returned vs newly created).
#[allow(dead_code)]
async fn link_edge(
    client: &reqwest::Client,
    endpoint: &str,
    source_id: Uuid,
    target_id: Uuid,
    relationship: &str,
    valid_from: Option<&str>,
) -> Result<(), String> {
    let url = format!("{endpoint}/api/v1/edges");
    let resp = client
        .post(&url)
        .json(&edge_body(source_id, target_id, relationship, valid_from))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("edge POST failed: {e}"))?;
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "edge {}: {}",
            status,
            resp.text().await.unwrap_or_default()
        ))
    }
}

// =============================================================================
// RESOLUTION LINKING
// =============================================================================

/// Confirm a claim exists (GET returns 200). `properties` are not exposed by the
/// read endpoint, but existence is all we need before creating a resolution edge.
#[allow(dead_code)]
async fn claim_exists(client: &reqwest::Client, endpoint: &str, id: Uuid) -> bool {
    let url = format!("{endpoint}/api/v1/claims/{id}");
    matches!(
        client
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

/// Does `content` cite exactly `PR #<n>`? The server's `content_contains` is a
/// case-insensitive substring match, so `PR #8` also returns claims citing
/// `PR #80`, `PR #812` or `SPR #8`; a digit right after the number, or a letter
/// or digit right before `PR`, rules those out.
fn content_cites_pr(content: &str, n: u64) -> bool {
    let haystack = content.to_ascii_lowercase();
    let needle = format!("pr #{n}");
    haystack.match_indices(&needle).any(|(i, _)| {
        // `apr #8` or `SPR #8` is not `PR #8`: no letter or digit right before.
        let starts_a_word = !haystack[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        starts_a_word
            && !haystack[i + needle.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
    })
}

/// The ids in a `GET /api/v1/claims` response whose content cites exactly
/// `PR #<n>` (see `content_cites_pr`).
fn claim_ids_citing_pr(v: &serde_json::Value, n: u64) -> Vec<Uuid> {
    v["claims"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| {
                    c["content"]
                        .as_str()
                        .is_some_and(|t| content_cites_pr(t, n))
                })
                .filter_map(|c| c["id"].as_str()?.parse::<Uuid>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Find existing resolution/backlog claims whose CONTENT cites "PR #<n>".
#[allow(dead_code)]
async fn find_claims_citing_pr(client: &reqwest::Client, endpoint: &str, n: u64) -> Vec<Uuid> {
    let needle = format!("PR #{n}");
    let url = format!("{endpoint}/api/v1/claims");
    let resp = client
        .get(&url)
        .query(&[
            ("content_contains", needle.as_str()),
            ("is_current", "true"),
            ("limit", "25"),
        ])
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;
    let Ok(resp) = resp else { return vec![] };
    if !resp.status().is_success() {
        return vec![];
    }
    let Ok(v) = resp.json::<serde_json::Value>().await else {
        return vec![];
    };
    claim_ids_citing_pr(&v, n)
}

/// For each resolved target, create `target --RESOLVED_BY--> PR`, datestamped at
/// merge time. Direction reads "X was resolved by this PR". `RESOLVED_BY` is in
/// `VALID_RELATIONSHIPS` and non-evidential (no DS recompute). Self-references and
/// the PR's own claim are skipped; UUID refs are validated for existence first, so
/// stray tokens from `extract_references` are harmless.
#[allow(dead_code)]
async fn link_resolutions(
    client: &reqwest::Client,
    endpoint: &str,
    pr_claim_id: Uuid,
    refs: &References,
    merged_at: &str,
) -> Result<usize, String> {
    let mut linked = 0;
    for uuid in &refs.claim_uuids {
        if *uuid != pr_claim_id && claim_exists(client, endpoint, *uuid).await {
            link_edge(
                client,
                endpoint,
                *uuid,
                pr_claim_id,
                "RESOLVED_BY",
                Some(merged_at),
            )
            .await?;
            linked += 1;
        }
    }
    for n in &refs.pr_numbers {
        for target in find_claims_citing_pr(client, endpoint, *n).await {
            if target != pr_claim_id {
                link_edge(
                    client,
                    endpoint,
                    target,
                    pr_claim_id,
                    "RESOLVED_BY",
                    Some(merged_at),
                )
                .await?;
                linked += 1;
            }
        }
    }
    Ok(linked)
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

// =============================================================================
// PR-HIERARCHICAL INGESTION
// =============================================================================

/// Build a reqwest client, attaching `Authorization: Bearer <token>` when a
/// token is configured. Required because the label PATCH route
/// (`PATCH /api/v1/claims/{id}/labels`) demands `claims:write`; a tokenless
/// client would 401 on every label application.
fn build_http_client(token: Option<&str>) -> reqwest::Client {
    if let Some(tok) = token {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}"))
                .expect("bearer token is a valid header value"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("client builder with bearer header")
    } else {
        reqwest::Client::new()
    }
}

/// Assemble the `repo → PR → commit` claim hierarchy for one merged PR:
/// find-or-create the repo root + PR node, attribute the PR to the orchestrator
/// agent and each commit to its (stable) git-author agent, stamp the
/// `decomposes_to` edges at merge/commit time, and link the PR to any backlog /
/// resolution claims it resolves via `RESOLVED_BY` (design §4, §6, §7).
async fn run_pr_ingest(args: &Args) -> Result<(), String> {
    let client = build_http_client(args.token.as_deref());
    let repo_slug = args.repo_slug.clone().ok_or("--repo-slug required")?;
    let meta = PrMeta {
        repo_slug: repo_slug.clone(),
        number: args.pr_number.ok_or("--pr-number required")?,
        title: args.pr_title.clone().ok_or("--pr-title required")?,
        body: args.pr_body.clone().unwrap_or_default(),
        merge_sha: args.merge_sha.clone().ok_or("--merge-sha required")?,
        merged_at: args.merged_at.clone().ok_or("--merged-at required")?,
        author_login: args.pr_author.clone().unwrap_or_default(),
    };
    let rev_range = args.rev_range.clone().ok_or("--rev-range required")?;
    let commits = parse_git_log_range(&args.repo, &rev_range)?;

    // Resolution references (PR-level): UUID refs + PR-number citations from the
    // PR body and commit messages. Computed up front so --dry-run can show the
    // planned resolution targets, and reused by section 5 below.
    let mut ref_text = meta.body.clone();
    for c in &commits {
        ref_text.push('\n');
        ref_text.push_str(&c.claim_text);
    }
    let refs = extract_references(&ref_text);

    // --dry-run: parse + print the planned hierarchy and resolution targets, then
    // return BEFORE any POST (the first write is register_agent in section 2).
    // Safe to run on untrusted/unmerged PRs since it makes no network calls.
    if args.dry_run {
        println!(
            "[dry-run] repo={} pr=#{} commits={} refs={:?}",
            meta.repo_slug,
            meta.number,
            commits.len(),
            refs
        );
        return Ok(());
    }

    // The host secret for the author and repo-root keys, checked before any
    // network call: a live run without it is refused.
    let author_keys = author_keys_for_run(args.author_key_file.as_deref(), false)?;

    // 1) Resolve the implementing orchestrator agent: explicit flag, then trailer
    //    (PR body, then each commit's trailer block), then
    //    EPIGRAPH_DEFAULT_ORCHESTRATOR_ID as the fallback.
    let orchestrator_id = resolve_orchestrator_agent(
        args.orchestrator_id,
        &meta.body,
        &commits,
        std::env::var("EPIGRAPH_DEFAULT_ORCHESTRATOR_ID")
            .ok()
            .as_deref(),
    )?;

    // 2) Repo root node, attributed to a fixed system agent (NOT the per-PR
    //    orchestrator). Keying on the orchestrator made the repo node's
    //    (content_hash, agent_id) vary per PR, defeating the server's find-or-create
    //    and re-creating the repo node every run. We register the system agent and
    //    use its returned id as the node's author. Registration is now `.await?`
    //    (not best-effort) because create_agent is idempotent on public_key
    //    (Plan 2.5 Tasks 1-2): a re-run returns the same id instead of a 400.
    let repo_root_signer = author_keys.repo_root();
    let repo_root_id = AgentRegistry::register_agent(
        &client,
        &args.endpoint,
        &repo_root_signer,
        "git-ingester-system",
    )
    .await?;
    let repo_id = ensure_repo_node(
        &client,
        &args.endpoint,
        &repo_slug,
        repo_root_id,
        &repo_root_signer,
    )
    .await?;

    // 3) PR node, attributed to the orchestrator.
    let pr_packet = build_pr_packet(&meta, orchestrator_id);
    let pr_label = format!("repo:{repo_slug}");
    let pr_id = submit_find_or_create(
        &client,
        &args.endpoint,
        pr_packet,
        &["source:git-history", "node:pr", &pr_label],
        None, // the orchestrator's key is not held here; see build_pr_packet
    )
    .await?;
    // repo --decomposes_to--> PR, stamped at merge time.
    link_edge(
        &client,
        &args.endpoint,
        repo_id,
        pr_id,
        "decomposes_to",
        Some(&meta.merged_at),
    )
    .await?;

    // 4) Commit children, attributed to their (stable) git-author agents.
    let mut author_cache = std::collections::HashMap::new();
    for commit in &commits {
        let (signer, author_id) = resolve_author_agent(
            &client,
            &args.endpoint,
            &author_keys,
            &mut author_cache,
            &commit.author_name,
            &commit.author_email,
        )
        .await?;
        let packet = build_packet(commit, &signer, author_id, None);
        let commit_label = format!("repo:{repo_slug}");
        let commit_id = submit_find_or_create(
            &client,
            &args.endpoint,
            packet,
            &["source:git-history", "node:commit", &commit_label],
            Some(&signer),
        )
        .await?;
        // PR --decomposes_to--> commit, stamped at commit time.
        link_edge(
            &client,
            &args.endpoint,
            pr_id,
            commit_id,
            "decomposes_to",
            Some(&commit.date),
        )
        .await?;
    }

    // 5) Resolution links (PR-level): create the RESOLVED_BY edges for the
    //    references gathered above (UUID refs + PR-number citations).
    let linked = link_resolutions(&client, &args.endpoint, pr_id, &refs, &meta.merged_at).await?;
    println!(
        "PR #{}: repo={repo_id} pr={pr_id} commits={} resolved_links={linked}",
        meta.number,
        commits.len()
    );
    Ok(())
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

    // PR-hierarchical ingestion is a distinct mode: it builds a repo -> PR ->
    // commit hierarchy from the supplied PR metadata + rev-range and returns.
    if args.pr_mode {
        if let Err(e) = run_pr_ingest(&args).await {
            eprintln!("pr-ingest failed: {e}");
            std::process::exit(1);
        }
        return;
    }

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

    // Per-author keys need the host secret; a live per-author run without it is
    // refused here, before enrichment or registration makes a network call. The
    // other modes never derive an author key.
    let author_keys = if primary_signer.is_none() {
        match author_keys_for_run(args.author_key_file.as_deref(), args.dry_run) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    } else {
        GitAuthorKeys::ephemeral()
    };

    // Agent management: single shared agent or per-author agents
    let mut registry = AgentRegistry::new(author_keys);
    let mut shared_agent_id = primary_signer.as_ref().map(|_| Uuid::new_v4());

    if let Some(id) = shared_agent_id {
        println!("Agent ID: {id}");
    }

    // Run enrichment
    let enricher: Box<dyn CommitEnricher> = match args.enricher {
        EnricherMode::Noop => Box::new(NoopEnricher),
        EnricherMode::Llm => {
            let client = epigraph_cli::enrichment::llm_client::create_llm_client(
                &std::env::var("ENRICHMENT_LLM_PROVIDER").unwrap_or_else(|_| "epigraph".into()),
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
#[path = "ingest_git/tests.rs"]
mod tests;
