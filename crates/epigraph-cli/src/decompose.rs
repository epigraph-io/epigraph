//! Compound-claim -> atomic-proposition decomposition core.
//!
//! A hardened port of the deterministic logic of V2
//! `scripts/decompose_claims_claude.py` (the Claude-CLI variant — the
//! `_api.py`/`_openai.py` SDK variants are REJECTED per
//! feedback_claude_cli_oauth: LLM calls go through the prepaid Claude path,
//! never the Anthropic SDK with a pay-per-token key). The actual model call
//! is made by the `decompose_claims` binary via
//! `epigraph_cli::enrichment::llm_client::create_llm_client` (which prefers
//! `CLAUDE_CODE_OAUTH_TOKEN`); this module owns the prompt, the response
//! parser, and the graph-write side so both are unit/integration testable
//! without a network round-trip.
//!
//! "Hardened" because the parser adds three robustness behaviors NOT present
//! in V2 `_parse_batch_response`: (1) a generality array whose length does not
//! match the atoms array is discarded (all `-1`) rather than zip-truncated;
//! (2) out-of-range generality values are sanitized to `-1` instead of passed
//! through; (3) an entry whose `atoms` array contains a non-string element is
//! dropped entirely rather than coerced — so a malformed entry never
//! fabricates a decomposition. The unit tests below pin all three.

use serde_json::Value;

/// The batch decomposition prompt. `{claims}` is replaced with a newline-
/// delimited `[idx] statement` list. Ported (semantics) from V2
/// `DECOMPOSE_BATCH_PROMPT`.
pub const DECOMPOSE_BATCH_PROMPT: &str = r#"You are an epistemic claim decomposer. Given a set of numbered claims, break each into atomic propositions — each expressing exactly ONE subject-predicate-object relationship that can be independently true or false.

Rules:
- Each atomic claim must be a complete, self-contained sentence
- Resolve pronouns and references (replace \"it\", \"they\", \"this\" with the actual referent)
- Preserve specific numbers, names, and quantitative details exactly
- Do NOT add information not present in the original
- Do NOT include opinions or interpretations
- If a claim is already atomic, return it unchanged as a single item
- Separate definitional claims (\"X is Y\") from consequential claims (\"X leads to Y\")

Return ONLY a JSON object mapping each claim index to an object with \"atoms\" (array of atomic strings) and \"generality\" (array of integers, one per atom: 0=foundational/definitional, 1=intermediate/contextual, 2=specialized/applied).

Example output: {\"0\": {\"atoms\": [\"X is defined as Y\", \"X leads to Z\"], \"generality\": [0, 1]}, \"1\": {\"atoms\": [\"Company A uses X\"], \"generality\": [2]}}

Claims:
{claims}"#;

/// One claim's decomposition: atoms plus a generality tier per atom
/// (0=foundational, 1=intermediate, 2=specialized, -1=unknown).
#[derive(Debug, Clone, PartialEq)]
pub struct Decomposition {
    pub atoms: Vec<String>,
    pub generality: Vec<i64>,
}

/// Build the batch prompt body for a slice of `(local_index, statement)`.
pub fn build_batch_prompt(claims: &[(usize, &str)]) -> String {
    let body = claims
        .iter()
        .map(|(idx, stmt)| format!("[{idx}] {stmt}"))
        .collect::<Vec<_>>()
        .join("\n");
    DECOMPOSE_BATCH_PROMPT.replace("{claims}", &body)
}

/// Parse a batch decomposition response into `local_index -> Decomposition`.
///
/// Hardened port of V2 `_parse_batch_response`: tolerant to a JSON object, a
/// markdown ```json fence, leading/trailing prose, integer-or-string keys, and
/// a bare atoms array (no generality). Invalid/empty atom lists for a key are
/// dropped (NOT defaulted to a single atom) so a malformed entry never
/// fabricates a decomposition. Generality is sanitized to the {-1,0,1,2} set
/// and length-matched to atoms (mismatch -> all -1). The length-mismatch,
/// out-of-range, and non-string-drop behaviors are intentional additions over
/// V2 (see module doc; pinned by the tests below).
pub fn parse_batch_response(raw: &str) -> std::collections::BTreeMap<usize, Decomposition> {
    let mut out = std::collections::BTreeMap::new();

    // Strip a markdown code fence if present (```json ... ``` or ``` ... ```).
    let text = strip_code_fence(raw);
    // Slice to the outermost {...}.
    let (start, end) = match (text.find('{'), text.rfind('}')) {
        (Some(s), Some(e)) if e > s => (s, e + 1),
        _ => return out,
    };
    let parsed: Value = match serde_json::from_str(&text[start..end]) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let Some(obj) = parsed.as_object() else {
        return out;
    };

    for (key, val) in obj {
        let Ok(idx) = key.parse::<usize>() else {
            continue;
        };
        // Accept {"atoms":[...], "generality":[...]} OR a bare [..] array.
        let (atoms_val, gen_val) = match val {
            Value::Object(m) => (m.get("atoms").cloned(), m.get("generality").cloned()),
            Value::Array(_) => (Some(val.clone()), None),
            _ => continue,
        };
        let Some(Value::Array(atoms_arr)) = atoms_val else {
            continue;
        };
        let atoms: Vec<String> = atoms_arr
            .iter()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();
        // Drop entries whose atoms aren't all strings, or are empty.
        if atoms.is_empty() || atoms.len() != atoms_arr.len() {
            continue;
        }
        let generality = match gen_val {
            Some(Value::Array(g)) if g.len() == atoms.len() => g
                .iter()
                // Only 0/1/2 are valid generality tiers; anything else
                // (out-of-range int, non-int) sanitizes to -1 (unknown).
                .map(|v| v.as_i64().filter(|n| (0..=2).contains(n)).unwrap_or(-1))
                .collect(),
            _ => vec![-1; atoms.len()],
        };
        out.insert(idx, Decomposition { atoms, generality });
    }
    out
}

// =============================================================================
// ELIGIBILITY: which undecomposed claims are worth an LLM call
// =============================================================================

/// Longest claim, in Unicode scalar values, that [`looks_atomic`] may call
/// atomic. Chosen by the operator brief (2026-09-24): "one sentence and ≤ 160
/// chars".
pub const ATOMIC_MAX_CHARS: usize = 160;

/// Number of sentences in `text`, by a deliberately simple rule.
///
/// A boundary is either
/// * a run of `.` `!` `?` (plus any closing quote/bracket), followed by
///   whitespace, followed by an uppercase letter, a digit, or an opening
///   quote/bracket; or
/// * a line break between two non-blank lines (bullet lists, pasted notes).
///
/// It errs toward COUNTING a boundary: `"Dr. Smith"` and `"e.g. The"` read as
/// two sentences. That direction only sends a claim to the LLM that could have
/// been skipped; the opposite error would silently skip a compound claim.
/// Decimals (`3.5`) and dotted identifiers (`epigraph.io`) never count, because
/// no whitespace follows the dot.
pub fn sentence_count(text: &str) -> usize {
    let chars: Vec<char> = text.trim().chars().collect();
    if chars.is_empty() {
        return 0;
    }
    let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '\u{201d}' | '\u{2019}');
    let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '\u{201c}' | '\u{2018}');
    let mut n = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?') {
            let mut j = i + 1;
            while j < chars.len() && (matches!(chars[j], '.' | '!' | '?') || closing(chars[j])) {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k > j && k < chars.len() {
                let next = chars[k];
                if next.is_uppercase() || next.is_ascii_digit() || opening(next) {
                    n += 1;
                    // The whitespace run is consumed: a newline inside it must
                    // not count the same boundary twice.
                    i = k;
                    continue;
                }
            }
            i = j;
        } else if c == '\n' {
            // A line break between non-blank lines is a boundary.
            let mut k = i + 1;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() {
                n += 1;
            }
            i = k;
        } else {
            i += 1;
        }
    }
    n
}

/// Whether `content` is already atomic enough that decomposing it would spend
/// an LLM call to get the claim back unchanged: exactly one sentence (see
/// [`sentence_count`]) and at most [`ATOMIC_MAX_CHARS`] characters.
///
/// This is the ONE definition of the heuristic; the eligibility filter and its
/// report both call it.
pub fn looks_atomic(content: &str) -> bool {
    sentence_count(content) <= 1 && content.trim().chars().count() <= ATOMIC_MAX_CHARS
}

/// The opt-out eligibility filters. Both default ON (`skip_* = true`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityFilters {
    /// Skip `backlog`-labelled claims (`--include-backlog` turns this off).
    pub skip_backlog: bool,
    /// Skip claims [`looks_atomic`] accepts (`--include-short` turns this off).
    pub skip_short: bool,
}

impl Default for EligibilityFilters {
    fn default() -> Self {
        Self {
            skip_backlog: true,
            skip_short: true,
        }
    }
}

/// Why a candidate was not sent to the LLM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    /// Carries the `backlog` label.
    Backlog,
    /// [`looks_atomic`] accepted it.
    LooksAtomic { sentences: usize, chars: usize },
}

impl std::fmt::Display for Ineligible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backlog => write!(
                f,
                "labelled `backlog` (pass --include-backlog to decompose it)"
            ),
            Self::LooksAtomic { sentences, chars } => write!(
                f,
                "looks atomic ({sentences} sentence, {chars} chars <= {ATOMIC_MAX_CHARS}; \
                 pass --include-short to decompose it)"
            ),
        }
    }
}

/// Apply `filters` to one claim. `Ok(())` means "send it to the LLM".
///
/// # Errors
/// The reason the claim is skipped.
pub fn check_eligibility(
    content: &str,
    labels: &[String],
    filters: EligibilityFilters,
) -> Result<(), Ineligible> {
    if filters.skip_backlog && labels.iter().any(|l| l == "backlog") {
        return Err(Ineligible::Backlog);
    }
    if filters.skip_short && looks_atomic(content) {
        return Err(Ineligible::LooksAtomic {
            sentences: sentence_count(content),
            chars: content.trim().chars().count(),
        });
    }
    Ok(())
}

// =============================================================================
// PLAN FILE: what `--plan` writes and `--apply-plan` persists
// =============================================================================

/// One claim's proposed decomposition, exactly as the LLM answered it.
///
/// `--plan` writes one of these per answered claim as a JSONL line;
/// `--apply-plan` persists exactly these atoms with no second LLM call, so
/// what the operator reviewed is what gets written. `content` is the parent's
/// text at plan time: apply refuses a parent whose text has since changed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PlannedDecomposition {
    /// Always `"decomposition"`, so a plan file is self-describing and a
    /// retarget manifest handed to `--apply-plan` by mistake is refused.
    pub kind: String,
    pub claim_id: uuid::Uuid,
    pub agent_id: uuid::Uuid,
    pub content: String,
    pub atoms: Vec<String>,
    pub generality: Vec<i64>,
    /// `LlmProvider::model_name()` of the provider that produced the atoms.
    pub model: String,
}

impl PlannedDecomposition {
    pub const KIND: &'static str = "decomposition";

    /// The parsed decomposition this plan line carries.
    pub fn decomposition(&self) -> Decomposition {
        Decomposition {
            atoms: self.atoms.clone(),
            generality: self.generality.clone(),
        }
    }
}

/// Write `plans` to `path` as JSONL (one object per line), replacing any file.
///
/// # Errors
/// I/O or serialization failure.
pub fn write_plan_jsonl(
    path: &std::path::Path,
    plans: &[PlannedDecomposition],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    for p in plans {
        serde_json::to_writer(&mut f, p)?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    Ok(())
}

/// Read a JSONL plan written by [`write_plan_jsonl`]. Blank lines are
/// ignored; any other line that is not a `"decomposition"` plan entry is an
/// error, and the whole file is refused (nothing is applied).
///
/// # Errors
/// I/O failure, a malformed line, or a line of another `kind`.
pub fn read_plan_jsonl(
    path: &std::path::Path,
) -> Result<Vec<PlannedDecomposition>, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let p: PlannedDecomposition = serde_json::from_str(line).map_err(|e| {
            format!(
                "{}:{}: not a decomposition plan line: {e}",
                path.display(),
                n + 1
            )
        })?;
        if p.kind != PlannedDecomposition::KIND {
            return Err(format!(
                "{}:{}: kind {:?} is not {:?}",
                path.display(),
                n + 1,
                p.kind,
                PlannedDecomposition::KIND
            )
            .into());
        }
        out.push(p);
    }
    Ok(out)
}

pub(crate) fn strip_code_fence(raw: &str) -> String {
    let t = raw.trim();
    if let Some(start) = t.find("```") {
        let after = &t[start + 3..];
        let after = after.strip_prefix("json").unwrap_or(after);
        if let Some(end) = after.find("```") {
            return after[..end].trim().to_string();
        }
    }
    t.to_string()
}

#[cfg(feature = "db")]
pub use db_writes::{
    persist_decomposition, persist_planned, plan_decomposition_batches, run_decomposition_batches,
    select_candidates, verify_plan, BatchClaim, BatchTotals, PersistOutcome, PlanDrift, Priority,
    Selection,
};

#[cfg(feature = "db")]
mod db_writes {
    use super::Decomposition;
    use epigraph_db::{ClaimRepository, EdgeRepository};
    use sqlx::PgPool;
    use std::sync::Arc;
    use uuid::Uuid;

    /// What `persist_decomposition` did, for reporting/tests.
    pub struct PersistOutcome {
        pub atom_claim_ids: Vec<Uuid>,
        pub edges_created: usize,
        pub skipped_singletons: usize,
    }

    /// Persist one compound claim's atoms as child claims and wire
    /// `parent -decomposes_to-> atom` edges.
    ///
    /// Direction is parent (source) -> child (target), matching
    /// `epigraph_ingest::common::edges::decomposes_edge` and
    /// `MCP link_hierarchical`. Idempotent on the edge triple via
    /// `EdgeRepository::create_if_not_exists`.
    ///
    /// Atom claims are written through `submit_via` — a closure the caller
    /// supplies that goes through the CANONICAL claim-create path so signing,
    /// provenance, DS auto-wire and embed-on-write are preserved. In the
    /// binary this closure POSTs to the local API `/api/v1/claims` (or calls
    /// the in-process submit helper); in tests it is a fake that inserts a
    /// minimal claim row, letting us verify the edge/label wiring WITHOUT an
    /// LLM or an embedder.
    ///
    /// Single-atom decompositions are SKIPPED (a claim that decomposes to
    /// exactly itself is already atomic — writing a self-equivalent child +
    /// edge would pollute the graph and is what `is_current`-atoms look like).
    pub async fn persist_decomposition<F, Fut>(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        parent_id: Uuid,
        decomp: &Decomposition,
        embedder: Option<Arc<dyn epigraph_embeddings::EmbeddingService>>,
        submit_via: F,
    ) -> Result<PersistOutcome, Box<dyn std::error::Error>>
    where
        F: Fn(String, i64) -> Fut,
        Fut: std::future::Future<Output = Result<Uuid, Box<dyn std::error::Error>>>,
    {
        // Already atomic: nothing to decompose.
        if decomp.atoms.len() <= 1 {
            return Ok(PersistOutcome {
                atom_claim_ids: vec![],
                edges_created: 0,
                skipped_singletons: 1,
            });
        }
        // Guard: parent must still be current (never wire onto a retired claim).
        if !ClaimRepository::are_all_current(pool, viewer, &[parent_id]).await? {
            return Err(format!("parent claim {parent_id} is not current").into());
        }
        // Phase 1: submit EVERY atom before wiring ANY edge. The
        // `decomposes_to` edges are what take the parent out of the
        // undecomposed population; writing them per atom meant a submit that
        // failed on atom k (an API restart, a 502) left the parent with k-1
        // atoms for good — `--apply-plan` then refused it as no longer
        // undecomposed and no selection ever chose it again. Atoms without
        // edges change nothing about the parent, and `if_not_exists` on the
        // atom POST hands back the same ids when the line is re-applied.
        let mut atom_ids = Vec::with_capacity(decomp.atoms.len());
        let mut gens = Vec::with_capacity(decomp.atoms.len());
        for (i, atom) in decomp.atoms.iter().enumerate() {
            let gen = decomp.generality.get(i).copied().unwrap_or(-1);
            let atom_id = submit_via(atom.clone(), gen).await.map_err(|e| {
                format!(
                    "atom {} of {} for parent {parent_id}: {e}; no decomposes_to edge \
                     was written, so the parent is still undecomposed and the line can be \
                     re-applied",
                    i + 1,
                    decomp.atoms.len()
                )
            })?;
            // Best-effort embed-on-write when the caller passes a live embedder
            // and the submit path did not already embed (API path embeds; the
            // direct-insert test fake does not).
            if let Some(ref e) = embedder {
                if let Ok(vec) = e.generate(atom).await {
                    let _ = e.store(atom_id, &vec).await;
                }
            }
            atom_ids.push(atom_id);
            gens.push(gen);
        }
        // Phase 2: every edge in ONE transaction, so the parent goes from
        // "no decomposition" to "all atoms" with nothing in between.
        let mut tx = pool.begin().await?;
        let mut edges = 0usize;
        for (&atom_id, &gen) in atom_ids.iter().zip(gens.iter()) {
            let (_row, was_created) = EdgeRepository::create_if_not_exists_conn(
                &mut tx,
                parent_id,
                "claim",
                atom_id,
                "claim",
                "decomposes_to",
                Some(serde_json::json!({"generality": gen, "via": "decompose_claims"})),
                None,
                None,
            )
            .await?;
            if was_created {
                edges += 1;
            }
        }
        tx.commit().await?;
        Ok(PersistOutcome {
            atom_claim_ids: atom_ids,
            edges_created: edges,
            skipped_singletons: 0,
        })
    }

    /// One undecomposed compound claim, as [`run_decomposition_batches`] needs
    /// it. Deliberately not `epigraph_core::Claim` — the runner only needs the
    /// parent id, the author to inherit, and the text to decompose, and a
    /// narrow struct lets tests construct input without a full claim.
    #[derive(Debug, Clone)]
    pub struct BatchClaim {
        pub claim_id: Uuid,
        pub agent_id: Uuid,
        pub content: String,
    }

    /// Totals accumulated across every batch of a decomposition run.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct BatchTotals {
        pub atoms: usize,
        pub edges: usize,
        /// Parents whose line failed to persist, with the reason. Each is
        /// still undecomposed (no edge is written until every atom is).
        pub failed: Vec<(Uuid, String)>,
    }

    /// Chunk `claims` into batches, decompose each batch through `llm`, and
    /// persist the results.
    ///
    /// Extracted verbatim from `decompose_claims`'s `main` so the
    /// prompt -> model -> parse -> persist chain — in particular the
    /// `chunk.get(local_idx)` mapping that decides WHICH parent an atom is
    /// wired to — is reachable from a test. `main` keeps only credential
    /// resolution and the HTTP submit closure.
    ///
    /// `submit_via` receives `(atom_text, generality, parent_agent_id)`; atoms
    /// inherit their parent compound claim's author, and the parent varies
    /// across a batch, so the author cannot be captured once by the caller.
    ///
    /// A batch whose LLM call fails is logged and skipped (the run continues);
    /// a persist failure aborts the run.
    pub async fn run_decomposition_batches<F, Fut>(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        claims: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
        embedder: Option<Arc<dyn epigraph_embeddings::EmbeddingService>>,
        submit_via: F,
    ) -> Result<BatchTotals, Box<dyn std::error::Error>>
    where
        F: Fn(String, i64, Uuid) -> Fut,
        Fut: std::future::Future<Output = Result<Uuid, Box<dyn std::error::Error>>>,
    {
        let mut totals = BatchTotals::default();
        for chunk in claims.chunks(batch_size.max(1)) {
            let planned = plan_chunk(chunk, llm).await;
            let chunk_totals =
                persist_planned(pool, viewer, &planned, embedder.clone(), &submit_via).await?;
            totals.atoms += chunk_totals.atoms;
            totals.edges += chunk_totals.edges;
            // A normal run still ABORTS on a persist failure (after finishing
            // the chunk): the next chunk would spend another LLM call on an
            // API that is probably down. `--apply-plan` makes no LLM call and
            // continues instead (see `persist_planned`).
            if !chunk_totals.failed.is_empty() {
                let lines: Vec<String> = chunk_totals
                    .failed
                    .iter()
                    .map(|(id, why)| format!("{id}: {why}"))
                    .collect();
                return Err(format!(
                    "persist failed for {} parent(s), aborting before the next LLM call \
                     ({} atoms / {} edges written so far): {}",
                    lines.len(),
                    totals.atoms,
                    totals.edges,
                    lines.join("; ")
                )
                .into());
            }
        }
        Ok(totals)
    }

    /// One LLM call for one chunk: prompt -> model -> parse -> the parent each
    /// answer belongs to. Writes nothing.
    ///
    /// A failed call is logged and yields an empty plan for the chunk (the run
    /// continues), matching the historical batch loop. The parent lookup is
    /// `chunk.get(local_idx)`: an index the model invented is dropped, never
    /// wired to a neighbour.
    async fn plan_chunk(
        chunk: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
    ) -> Vec<super::PlannedDecomposition> {
        let indexed: Vec<(usize, &str)> = chunk
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.content.as_str()))
            .collect();
        let prompt = super::build_batch_prompt(&indexed);
        // SCAFFOLD BOUNDARY: this network call cannot run in the CI box.
        let raw = match llm.complete_json(&prompt).await {
            Ok(v) => v.to_string(),
            Err(e) => {
                eprintln!("  LLM call failed for batch: {e}; skipping");
                return vec![];
            }
        };
        super::parse_batch_response(&raw)
            .into_iter()
            .filter_map(|(local_idx, decomp)| {
                let parent = chunk.get(local_idx)?;
                Some(super::PlannedDecomposition {
                    kind: super::PlannedDecomposition::KIND.to_string(),
                    claim_id: parent.claim_id,
                    agent_id: parent.agent_id,
                    content: parent.content.clone(),
                    atoms: decomp.atoms,
                    generality: decomp.generality,
                    model: llm.model_name().to_string(),
                })
            })
            .collect()
    }

    /// `--plan`: every LLM call a decomposition run would make, and nothing
    /// else. No claim, edge or embedding is written; the caller serializes the
    /// result with [`super::write_plan_jsonl`].
    pub async fn plan_decomposition_batches(
        claims: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
    ) -> Vec<super::PlannedDecomposition> {
        let mut out = Vec::new();
        for chunk in claims.chunks(batch_size.max(1)) {
            out.extend(plan_chunk(chunk, llm).await);
        }
        out
    }

    /// Persist already-planned decompositions. Makes NO LLM call — this is
    /// the whole of `--apply-plan`, and the persist half of a normal run.
    ///
    /// A line that fails is recorded in [`BatchTotals::failed`] and the next
    /// line is still attempted: one bad line (or a transient API error) must
    /// not strand the rest of a reviewed plan. Because
    /// [`persist_decomposition`] writes no edge until every atom is
    /// submitted, a failed line leaves its parent undecomposed and a re-run of
    /// the same plan applies it.
    ///
    /// Atoms inherit the parent compound claim's author: `agent_id` is a
    /// REQUIRED field of CreateClaimRequest (POST /api/v1/claims), and omitting
    /// it returned 422, which silently dropped every decomposition atom.
    ///
    /// # Errors
    /// None today; the `Result` is kept for callers.
    pub async fn persist_planned<F, Fut>(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        planned: &[super::PlannedDecomposition],
        embedder: Option<Arc<dyn epigraph_embeddings::EmbeddingService>>,
        submit_via: &F,
    ) -> Result<BatchTotals, Box<dyn std::error::Error>>
    where
        F: Fn(String, i64, Uuid) -> Fut,
        Fut: std::future::Future<Output = Result<Uuid, Box<dyn std::error::Error>>>,
    {
        let mut totals = BatchTotals::default();
        for plan in planned {
            let parent_agent_id = plan.agent_id;
            match persist_decomposition(
                pool,
                viewer,
                plan.claim_id,
                &plan.decomposition(),
                embedder.clone(),
                move |atom_text, generality| submit_via(atom_text, generality, parent_agent_id),
            )
            .await
            {
                Ok(outcome) => {
                    totals.atoms += outcome.atom_claim_ids.len();
                    totals.edges += outcome.edges_created;
                }
                Err(e) => totals.failed.push((plan.claim_id, e.to_string())),
            }
        }
        Ok(totals)
    }

    /// Why a plan line was not applied by [`verify_plan`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PlanDrift {
        /// The parent is gone, retired, invisible, or already decomposed.
        NoLongerUndecomposed,
        /// The parent's text differs from the text the atoms were derived from.
        ContentChanged,
    }

    /// Split a plan into the lines that still describe the graph and the
    /// lines that do not. A line applies only if its parent is still in the
    /// undecomposed population AND its content is byte-identical to the plan
    /// text, so atoms are never wired onto text they were not derived from.
    ///
    /// # Errors
    /// Database failure.
    pub async fn verify_plan(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        planned: Vec<super::PlannedDecomposition>,
    ) -> Result<
        (
            Vec<super::PlannedDecomposition>,
            Vec<(super::PlannedDecomposition, PlanDrift)>,
        ),
        Box<dyn std::error::Error>,
    > {
        use epigraph_db::repos::decomposition_priority::DecompositionPriorityRepository as R;
        let ids: Vec<Uuid> = planned.iter().map(|p| p.claim_id).collect();
        let mut live = std::collections::HashMap::new();
        for chunk in ids.chunks(1000) {
            for c in R::list_undecomposed_by_ids(pool, viewer, chunk).await? {
                live.insert(c.id, c.content);
            }
        }
        let mut ok = Vec::new();
        let mut drifted = Vec::new();
        for p in planned {
            match live.get(&p.claim_id) {
                None => drifted.push((p, PlanDrift::NoLongerUndecomposed)),
                Some(text) if *text != p.content => drifted.push((p, PlanDrift::ContentChanged)),
                Some(_) => ok.push(p),
            }
        }
        Ok((ok, drifted))
    }

    /// Candidate ordering for [`select_candidates`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Priority {
        /// Undecomposed conflict targets, most-contested first.
        Conflict,
        /// Newest first.
        Recent,
        /// Oldest first — the historical order and the default.
        Oldest,
    }

    /// What [`select_candidates`] chose and why it passed over the rest.
    #[derive(Debug, Default)]
    pub struct Selection {
        pub chosen: Vec<epigraph_db::repos::decomposition_priority::DecomposeCandidate>,
        /// Candidates the eligibility filters rejected, with the reason.
        pub skipped: Vec<(Uuid, super::Ineligible)>,
        /// `--ids-file` ids that are not in the undecomposed population
        /// (absent, retired, invisible, or already decomposed/an atom).
        pub not_undecomposed: Vec<Uuid>,
        /// Rows read from the database to fill `chosen`.
        pub scanned: usize,
        /// True when the scan stopped at `max_scan` with the population not
        /// exhausted and fewer than `limit` chosen.
        pub scan_capped: bool,
        /// `--ids-file` ids that are eligible but fell past `--limit`, in file
        /// order. Reported, not silently dropped.
        pub over_limit: Vec<Uuid>,
    }

    /// Choose up to `limit` eligible candidates.
    ///
    /// With `ids`, only those ids are considered, in file order, and every
    /// one the filters reject or the population excludes is REPORTED in the
    /// returned [`Selection`] (the caller prints each), because an operator
    /// who named an id must be told why it was not decomposed.
    ///
    /// Otherwise the population is read in `priority` order, page by page,
    /// and filtered in Rust until `limit` are chosen, the population runs out,
    /// or `max_scan` rows have been read. Paging is what keeps a filter from
    /// starving the run: filtering one `LIMIT`ed page would let ≈87k short
    /// legacy extracts at the head of `oldest` consume every run's budget.
    ///
    /// # Errors
    /// Database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn select_candidates(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        priority: Priority,
        ids: Option<&[Uuid]>,
        filters: super::EligibilityFilters,
        limit: usize,
        max_scan: usize,
    ) -> Result<Selection, Box<dyn std::error::Error>> {
        use epigraph_db::repos::decomposition_priority::{
            DecompositionPriorityRepository as R, UndecomposedOrder,
        };
        let mut sel = Selection::default();
        if let Some(ids) = ids {
            let mut rows = Vec::new();
            for chunk in ids.chunks(1000) {
                rows.extend(R::list_undecomposed_by_ids(pool, viewer, chunk).await?);
            }
            sel.scanned = rows.len();
            let present: std::collections::HashSet<Uuid> = rows.iter().map(|r| r.id).collect();
            let mut seen = std::collections::HashSet::new();
            sel.not_undecomposed = ids
                .iter()
                .copied()
                .filter(|id| !present.contains(id) && seen.insert(*id))
                .collect();
            // A repeated id in the file must not be decomposed twice.
            let mut taken = std::collections::HashSet::new();
            for r in rows {
                if !taken.insert(r.id) {
                    continue;
                }
                match super::check_eligibility(&r.content, &r.labels, filters) {
                    // Past `--limit`: named, eligible, and NOT silently dropped.
                    Ok(()) if sel.chosen.len() >= limit => sel.over_limit.push(r.id),
                    Ok(()) => sel.chosen.push(r),
                    Err(why) => sel.skipped.push((r.id, why)),
                }
            }
            return Ok(sel);
        }

        const PAGE: i64 = 500;
        let mut offset: i64 = 0;
        loop {
            if sel.chosen.len() >= limit {
                break;
            }
            if sel.scanned >= max_scan {
                sel.scan_capped = true;
                break;
            }
            let page = match priority {
                Priority::Conflict => {
                    R::list_undecomposed_conflict_targets(pool, viewer, PAGE, offset).await?
                }
                Priority::Recent => {
                    R::list_undecomposed_ordered(
                        pool,
                        viewer,
                        UndecomposedOrder::Recent,
                        PAGE,
                        offset,
                    )
                    .await?
                }
                Priority::Oldest => {
                    R::list_undecomposed_ordered(
                        pool,
                        viewer,
                        UndecomposedOrder::Oldest,
                        PAGE,
                        offset,
                    )
                    .await?
                }
            };
            let n = page.len();
            sel.scanned += n;
            offset += n as i64;
            for r in page {
                if sel.chosen.len() >= limit {
                    break;
                }
                match super::check_eligibility(&r.content, &r.labels, filters) {
                    Ok(()) => sel.chosen.push(r),
                    Err(why) => sel.skipped.push((r.id, why)),
                }
            }
            if (n as i64) < PAGE {
                break;
            }
        }
        Ok(sel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_with_atoms_and_generality() {
        let raw = r#"{"0": {"atoms": ["X is Y", "X causes Z"], "generality": [0, 1]}}"#;
        let out = parse_batch_response(raw);
        let d = out.get(&0).expect("index 0 parsed");
        assert_eq!(
            d.atoms,
            vec!["X is Y".to_string(), "X causes Z".to_string()]
        );
        assert_eq!(d.generality, vec![0, 1]);
    }

    #[test]
    fn recovers_json_from_markdown_fence_with_prose() {
        let raw = "Here you go:\n```json\n{\"2\": {\"atoms\": [\"A\", \"B\"], \"generality\": [1, 2]}}\n```\nDone.";
        let out = parse_batch_response(raw);
        assert!(
            out.contains_key(&2),
            "must recover the fenced object despite surrounding prose"
        );
        assert_eq!(out.get(&2).unwrap().atoms.len(), 2);
    }

    #[test]
    fn malformed_json_yields_empty_not_panic() {
        assert!(parse_batch_response("not json at all").is_empty());
        assert!(parse_batch_response("{ broken").is_empty());
        assert!(parse_batch_response("").is_empty());
    }

    #[test]
    fn bare_array_form_defaults_generality_to_unknown() {
        let raw = r#"{"0": ["only atom", "second atom"]}"#;
        let d = parse_batch_response(raw);
        let entry = d.get(&0).unwrap();
        assert_eq!(entry.atoms.len(), 2);
        assert_eq!(
            entry.generality,
            vec![-1, -1],
            "bare array has no generality => all -1"
        );
    }

    #[test]
    fn generality_length_mismatch_falls_back_to_unknown() {
        let raw = r#"{"0": {"atoms": ["a", "b"], "generality": [0]}}"#;
        let d = parse_batch_response(raw).remove(&0).unwrap();
        assert_eq!(
            d.generality,
            vec![-1, -1],
            "mismatched generality length must be discarded, not zip-truncated"
        );
    }

    #[test]
    fn entry_with_non_string_atoms_is_dropped_not_coerced() {
        let raw = r#"{"0": {"atoms": ["valid", 42], "generality": [0, 1]}, "1": {"atoms": ["good"], "generality": [0]}}"#;
        let out = parse_batch_response(raw);
        assert!(!out.contains_key(&0), "an atoms array with a non-string element must be dropped entirely (no fabricated decomposition)");
        assert!(out.contains_key(&1), "the valid sibling entry survives");
    }

    // --- atomic heuristic ---

    #[test]
    fn one_short_sentence_looks_atomic() {
        assert_eq!(sentence_count("Water boils at 100 C at sea level."), 1);
        assert!(looks_atomic("Water boils at 100 C at sea level."));
        // No terminal punctuation at all is still one sentence.
        assert!(looks_atomic("Gravity bends light"));
    }

    #[test]
    fn two_sentences_are_not_atomic_even_when_short() {
        let t = "Gravity bends light. Time dilates near mass.";
        assert_eq!(sentence_count(t), 2);
        assert!(
            !looks_atomic(t),
            "two sentences are compound regardless of length"
        );
        assert_eq!(sentence_count("Is it true? Yes! It is."), 3);
    }

    #[test]
    fn one_long_sentence_is_not_atomic() {
        let long = format!("The system {} works.", "really ".repeat(30));
        assert_eq!(sentence_count(&long), 1);
        assert!(long.chars().count() > ATOMIC_MAX_CHARS);
        assert!(
            !looks_atomic(&long),
            "over the char cap is compound-suspect"
        );
    }

    #[test]
    fn the_char_cap_is_inclusive_and_counts_chars_not_bytes() {
        let exact = "a".repeat(ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&exact), "exactly the cap is still atomic");
        let over = "a".repeat(ATOMIC_MAX_CHARS + 1);
        assert!(!looks_atomic(&over));
        // 160 two-byte chars: 320 bytes, 160 chars -> atomic.
        let multibyte = "é".repeat(ATOMIC_MAX_CHARS);
        assert!(multibyte.len() > ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&multibyte), "cap is in chars, not bytes");
    }

    #[test]
    fn decimals_and_dotted_names_are_not_boundaries() {
        assert_eq!(sentence_count("Version 3.5 of epigraph.io ships in Q3."), 1);
        assert_eq!(sentence_count("pH was 7.4 in the sample"), 1);
    }

    #[test]
    fn lowercase_after_a_period_is_not_a_boundary() {
        // Conservative in the other direction would be wrong here: "etc. and"
        // continues the sentence.
        assert_eq!(sentence_count("apples, pears, etc. are fruit"), 1);
    }

    #[test]
    fn line_breaks_between_non_blank_lines_are_boundaries() {
        assert_eq!(sentence_count("- first point\n- second point"), 2);
        assert_eq!(sentence_count("First line.\nSecond line."), 2);
        // A trailing newline adds nothing.
        assert_eq!(sentence_count("Only line.\n\n"), 1);
    }

    #[test]
    fn empty_text_has_no_sentences() {
        assert_eq!(sentence_count(""), 0);
        assert_eq!(sentence_count("   "), 0);
    }

    // --- eligibility filters ---

    fn labels(ls: &[&str]) -> Vec<String> {
        ls.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_filters_skip_backlog_and_atomic_claims() {
        let f = EligibilityFilters::default();
        let compound = "Gravity bends light. Time dilates near mass.";
        assert_eq!(check_eligibility(compound, &labels(&[]), f), Ok(()));
        assert_eq!(
            check_eligibility(compound, &labels(&["backlog"]), f),
            Err(Ineligible::Backlog)
        );
        assert!(matches!(
            check_eligibility("Gravity bends light.", &labels(&[]), f),
            Err(Ineligible::LooksAtomic {
                sentences: 1,
                chars: 20
            })
        ));
    }

    #[test]
    fn each_filter_opts_out_independently() {
        let no_backlog_filter = EligibilityFilters {
            skip_backlog: false,
            skip_short: true,
        };
        let compound = "Gravity bends light. Time dilates near mass.";
        assert_eq!(
            check_eligibility(compound, &labels(&["backlog"]), no_backlog_filter),
            Ok(())
        );
        let no_short_filter = EligibilityFilters {
            skip_backlog: true,
            skip_short: false,
        };
        assert_eq!(
            check_eligibility("Gravity bends light.", &labels(&[]), no_short_filter),
            Ok(())
        );
        // The other filter is still on.
        assert_eq!(
            check_eligibility(compound, &labels(&["backlog"]), no_short_filter),
            Err(Ineligible::Backlog)
        );
    }

    #[test]
    fn a_label_that_merely_contains_backlog_is_not_backlog() {
        let f = EligibilityFilters::default();
        let compound = "Gravity bends light. Time dilates near mass.";
        assert_eq!(
            check_eligibility(compound, &labels(&["backlog-resolved-2026"]), f),
            Ok(())
        );
    }

    // --- plan file ---

    #[test]
    fn plan_jsonl_round_trips_and_refuses_foreign_kinds() {
        let dir = std::env::temp_dir().join(format!("decomp-plan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plan.jsonl");
        let plans = vec![PlannedDecomposition {
            kind: PlannedDecomposition::KIND.to_string(),
            claim_id: uuid::Uuid::new_v4(),
            agent_id: uuid::Uuid::new_v4(),
            content: "A and B.\nWith a newline".to_string(),
            atoms: vec!["A".to_string(), "B".to_string()],
            generality: vec![0, -1],
            model: "fixture".to_string(),
        }];
        write_plan_jsonl(&path, &plans).unwrap();
        assert_eq!(read_plan_jsonl(&path).unwrap(), plans);

        let mut foreign = serde_json::to_value(&plans[0]).unwrap();
        foreign["kind"] = serde_json::json!("retarget");
        std::fs::write(&path, format!("{foreign}\n")).unwrap();
        let err = read_plan_jsonl(&path).unwrap_err().to_string();
        assert!(err.contains("kind"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn out_of_range_generality_clamped_to_unknown() {
        let raw = r#"{"0": {"atoms": ["a", "b", "c"], "generality": [0, 7, -3]}}"#;
        let d = parse_batch_response(raw).remove(&0).unwrap();
        assert_eq!(
            d.generality,
            vec![0, -1, -1],
            "only 0/1/2 are valid tiers; others -> -1"
        );
    }
}
