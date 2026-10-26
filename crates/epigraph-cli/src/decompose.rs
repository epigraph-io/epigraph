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

// The heuristic lives in `epigraph-core` so the MCP server, which this crate
// depends on and so cannot depend back on, can flag the same rows this filter
// skips. Re-exported so every `epigraph_cli::decompose::looks_atomic` path still
// resolves to the ONE definition.
pub use epigraph_core::atomicity::{looks_atomic, sentence_count, ATOMIC_MAX_CHARS};

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
    /// Not `visibility = 'public'`. Atoms are POSTed with `if_not_exists`,
    /// which the API allows only for the public tier, and their derivation
    /// evidence copies the parent's text; decomposing a group-private parent
    /// would republish it. Not overridable.
    NotPublic { visibility: String },
    /// The model already answered this exact text with one atom (recorded in
    /// the [`SingletonLedger`]); asking again would buy the same answer.
    JudgedAtomic,
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
            Self::NotPublic { visibility } => write!(
                f,
                "visibility is `{visibility}`, not `public` (atoms are public and carry the \
                 parent's text as derivation evidence; never decomposed)"
            ),
            Self::JudgedAtomic => write!(
                f,
                "the model already judged this text atomic (singleton ledger; pass \
                 --include-judged-atomic to ask again)"
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

/// The one eligibility rule no flag overrides: only a `visibility = 'public'`
/// claim is decomposed.
///
/// Selection on the maintenance path runs under a BYPASS viewer and so sees
/// group-private claims (on the `--as-agent` path only those of the acting
/// agent's groups), but every atom is POSTed public (`if_not_exists` is public-tier
/// only) and records the parent's text as its derivation evidence (U041). A
/// group-private parent would be republished as public atoms, and the API
/// refuses its `derived_from` — which would abort a normal run. So it is
/// skipped here and reported.
///
/// # Errors
/// [`Ineligible::NotPublic`] for any other visibility.
pub fn check_publicly_decomposable(visibility: &str) -> Result<(), Ineligible> {
    if visibility == "public" {
        Ok(())
    } else {
        Err(Ineligible::NotPublic {
            visibility: visibility.to_string(),
        })
    }
}

// =============================================================================
// ATOM CREATE BODY: what `decompose_claims` POSTs to `/api/v1/claims`
// =============================================================================

/// The parent an atom is being written for, as the submit closure of
/// `run_decomposition_batches` / `persist_planned` receives it.
///
/// A struct rather than two adjacent `Uuid` arguments: the closure needs
/// both the parent's id (the atom POST names it in `derived_from`, which
/// records the atom's derivation evidence) and its author (atoms inherit it
/// as `agent_id`), and a swapped pair of bare `Uuid`s would compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomParent {
    /// The compound claim being decomposed.
    pub claim_id: uuid::Uuid,
    /// Its author, which the atom inherits.
    pub agent_id: uuid::Uuid,
}

/// The `derived_from.method` every `decompose_claims` atom names.
pub const DECOMPOSE_DERIVATION_METHOD: &str = "decompose_claims";

/// The JSON body `decompose_claims` POSTs to `/api/v1/claims` for one atom.
///
/// A pure function, so the wire shape is testable: the API's
/// `CreateClaimRequest` has no `deny_unknown_fields`, so a misspelt key here
/// (or a swapped parent id / author) is silently dropped with a 200, and the
/// atom is born with `evidence_ids=[]` again (backlog 3590a2d8).
///
/// * `agent_id` is the PARENT's author — atoms inherit it.
/// * `if_not_exists=true`: an atom whose text already exists for that author
///   dedups onto the existing claim, and edges are re-wired idempotently.
/// * methodology/evidence_type belong in `properties` (JSONB); top-level they
///   were unknown fields and silently dropped.
/// * `derived_from` names the parent: the API records one `document`
///   evidence row carrying the parent's text, in the atom's own transaction.
///   Provenance, not belief: no mass function, truth stays 0.5 (U041).
pub fn atom_create_body(atom_text: &str, generality: i64, parent: AtomParent) -> Value {
    serde_json::json!({
        "content": atom_text,
        "agent_id": parent.agent_id,
        "initial_truth": 0.5,
        "if_not_exists": true,
        "properties": {
            "methodology": "inductive_generalization",
            "evidence_type": "logical"
        },
        "labels": ["atom", format!("generality:{generality}")],
        "derived_from": {"claim_id": parent.claim_id, "method": DECOMPOSE_DERIVATION_METHOD},
    })
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

/// Write `plans` to `path` as JSONL (one object per line). The file must NOT
/// already exist: a plan an operator already reviewed is never silently
/// replaced by a new LLM run (the retarget manifest has the same rule).
///
/// # Errors
/// `path` exists; I/O or serialization failure.
pub fn write_plan_jsonl(
    path: &std::path::Path,
    plans: &[PlannedDecomposition],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "plan file {} already exists; pass a new --plan path (a reviewed plan is \
                     never overwritten)",
                    path.display()
                )
            } else {
                format!("cannot create plan file {}: {e}", path.display())
            }
        })?;
    let mut f = std::io::BufWriter::new(file);
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

// =============================================================================
// SINGLETON LEDGER: parents the model already judged atomic
// =============================================================================

/// One `--singleton-ledger` line: the model answered this parent's text with
/// a single atom ("already atomic"), so nothing was written for it.
///
/// [`persist_decomposition`](db_writes::persist_decomposition) deliberately
/// writes no self-equivalent child and no edge for such a parent, so it stays
/// in the undecomposed population; without this record every later run would
/// select it again and spend another LLM call on the same answer (backlog
/// 68d03c24). The verdict is keyed on the parent's id AND the BLAKE3 of the
/// exact text the model judged, so a parent whose text changes is asked again.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct JudgedAtomicEntry {
    /// Always [`SingletonLedger::KIND`], so a plan or retarget manifest
    /// handed to `--singleton-ledger` by mistake is refused.
    pub kind: String,
    pub claim_id: uuid::Uuid,
    /// Lower-case hex BLAKE3 of the parent text the model judged.
    pub content_blake3: String,
    /// `LlmProvider::model_name()` of the provider that judged it.
    pub model: String,
    pub decided_at: chrono::DateTime<chrono::Utc>,
}

/// The JSONL file of [`JudgedAtomicEntry`] lines that takes LLM-judged
/// singletons out of `decompose_claims` selection.
///
/// A file, not a DB marker (U040 ruling, 2026-10-14): labelling the parent
/// would mutate other agents' claims from a maintenance job, and a verdict
/// table is a migration plus four transcribed predicates. Selection reads it
/// through [`SingletonLedger::contains`]; the persist path appends to it
/// (`persist_planned`), so a run records its own verdicts and a `--plan`
/// records nothing until the plan is applied.
#[derive(Debug, Default)]
pub struct SingletonLedger {
    path: std::path::PathBuf,
    entries: std::collections::HashSet<(uuid::Uuid, [u8; 32])>,
    writable: bool,
}

impl SingletonLedger {
    pub const KIND: &'static str = "judged_atomic";

    /// Read `path` for selection only. A missing file is an empty ledger and
    /// is NOT created (`--dry-run` and `--plan` write nothing).
    ///
    /// A final line with no newline that does not parse is a TORN append (a
    /// crash or a full disk mid-write): it is skipped with a warning, so the
    /// scheduled job does not fail at startup until someone edits the file.
    /// [`open_for_append`](Self::open_for_append) cuts it off. Any other bad
    /// line is refused.
    ///
    /// # Errors
    /// I/O failure other than not-found, or a line that is not a
    /// [`JudgedAtomicEntry`] (reported as `path:line`; nothing is loaded).
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = match std::fs::read(path) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(format!("cannot read singleton ledger {}: {e}", path.display()).into())
            }
        };
        let torn_tail = (!raw.is_empty() && !raw.ends_with('\n'))
            .then(|| raw.lines().count())
            .filter(|_| {
                raw.lines()
                    .last()
                    .is_some_and(|l| parse_ledger_line(l).is_err())
            });
        let mut entries = std::collections::HashSet::new();
        for (n, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if torn_tail == Some(n + 1) {
                eprintln!(
                    "WARNING: {}:{}: skipping a torn final line (an interrupted append); the \
                     next recording run removes it",
                    path.display(),
                    n + 1
                );
                continue;
            }
            let (id, digest) = parse_ledger_line(line).map_err(|why| {
                format!(
                    "{}:{}: not a singleton-ledger line ({why}); fix or remove the line",
                    path.display(),
                    n + 1
                )
            })?;
            entries.insert((id, digest));
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
            writable: false,
        })
    }

    /// [`load`](Self::load), and also create the file if it is missing, so a
    /// path that cannot be written fails BEFORE any LLM call rather than after
    /// the verdicts are paid for.
    ///
    /// An unterminated final line is settled first, so the next append starts
    /// on a line of its own: a torn one (it does not parse) is cut off, a
    /// complete one gets its newline.
    ///
    /// # Errors
    /// As [`load`](Self::load), or the file cannot be opened for append.
    pub fn open_for_append(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        use std::io::Write;
        let cannot = |e: std::io::Error| {
            format!(
                "cannot open singleton ledger {} for append: {e}",
                path.display()
            )
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(cannot)?;
        let raw = std::fs::read(path).map_err(cannot)?;
        if !raw.is_empty() && !raw.ends_with(b"\n") {
            let start = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            if parse_ledger_line(&String::from_utf8_lossy(&raw[start..])).is_ok() {
                f.write_all(b"\n").map_err(cannot)?;
            } else {
                f.set_len(start as u64).map_err(cannot)?;
                eprintln!(
                    "WARNING: {}: removed a torn final line ({} bytes) left by an interrupted \
                     append",
                    path.display(),
                    raw.len() - start
                );
            }
        }
        let mut ledger = Self::load(path)?;
        ledger.writable = true;
        Ok(ledger)
    }

    /// Whether the model already judged `claim_id`, with exactly this text,
    /// atomic.
    pub fn contains(&self, claim_id: uuid::Uuid, content: &str) -> bool {
        self.entries.contains(&(claim_id, content_digest(content)))
    }

    /// Number of distinct `(claim, text)` verdicts held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append one verdict as a single JSONL line (one `write_all`, so a crash
    /// cannot interleave two records). A verdict already held is not written
    /// twice.
    ///
    /// # Errors
    /// The ledger was [`load`](Self::load)ed read-only, or the append failed.
    pub fn record(
        &mut self,
        claim_id: uuid::Uuid,
        content: &str,
        model: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        if !self.writable {
            return Err(format!(
                "singleton ledger {} was opened read-only",
                self.path.display()
            )
            .into());
        }
        let digest = content_digest(content);
        if self.entries.contains(&(claim_id, digest)) {
            return Ok(());
        }
        let entry = JudgedAtomicEntry {
            kind: Self::KIND.to_string(),
            claim_id,
            content_blake3: hex::encode(digest),
            model: model.to_string(),
            decided_at: chrono::Utc::now(),
        };
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                format!(
                    "cannot append to singleton ledger {}: {e}",
                    self.path.display()
                )
            })?;
        f.write_all(&line)?;
        f.flush()?;
        self.entries.insert((claim_id, digest));
        Ok(())
    }
}

/// One ledger line as `(claim id, BLAKE3 of the judged text)`, or why not.
fn parse_ledger_line(line: &str) -> Result<(uuid::Uuid, [u8; 32]), String> {
    let e: JudgedAtomicEntry = serde_json::from_str(line).map_err(|e| e.to_string())?;
    if e.kind != SingletonLedger::KIND {
        return Err(format!(
            "kind {:?} is not {:?}",
            e.kind,
            SingletonLedger::KIND
        ));
    }
    let digest: [u8; 32] = hex::decode(&e.content_blake3)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "content_blake3 is not 32 hex bytes".to_string())?;
    Ok((e.claim_id, digest))
}

fn content_digest(content: &str) -> [u8; 32] {
    *blake3::hash(content.as_bytes()).as_bytes()
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
    persist_decomposition, persist_planned, plan_decomposition_batches,
    plan_decomposition_batches_with_gaps, run_decomposition_batches, select_candidates,
    verify_plan, visible_claim_count, writer_group, BatchClaim, BatchTotals, DecomposeDb,
    DecomposeRead, DecomposeTx, PersistOutcome, PlanDrift, PlanGaps, Priority, Selection,
};

#[cfg(feature = "db")]
mod db_writes {
    use super::{AtomParent, Decomposition};
    use epigraph_db::visibility::Viewer;
    use epigraph_db::{ClaimRepository, DbError, EdgeRepository};
    use sqlx::{PgConnection, PgPool};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Where a decomposition run's statements go, and as whom.
    ///
    /// Two implementations, one per way `decompose_claims` connects:
    ///
    /// * [`PgPool`] — the MAINTENANCE path. The pool is a privileged
    ///   connection (`epigraph_cli::MaintenancePool`, checked at startup) and
    ///   the viewer a bypass, so statements run on it as they are: row
    ///   security does not filter them.
    /// * [`epigraph_db::ScopedPool`] — the `--as-agent` path, on the ordinary
    ///   application login with NO maintenance privilege (backlog 9a877b7c,
    ///   operator ruling 2026-10-20). Every read runs on a connection stamped
    ///   for the viewer ([`epigraph_db::ScopedPool::read_as`]) and every write
    ///   in a transaction stamped for it ([`epigraph_db::ScopedPool::begin_as`]),
    ///   so the in-query predicate and row security agree, and a
    ///   `decomposes_to` edge records the acting agent's group as its writer
    ///   (migration 120) instead of landing ownerless through the world arm an
    ///   unstamped insert would take. Both refuse a bypass viewer. The edge
    ///   dedup probe inside `persist_decomposition`
    ///   (`EdgeRepository::create_if_absent_including_retracted_conn`, marked
    ///   VISIBILITY-EXEMPT) is NOT exempt here: on this login row security
    ///   filters it, so an existing edge the agent cannot see does not stop
    ///   a second identical one.
    ///
    /// The library functions take `&dyn DecomposeDb`, so a caller holding a
    /// `PgPool` passes `&pool` unchanged.
    #[allow(clippy::double_must_use)] // async_trait's generated #[must_use] on an already-must-use boxed future
    #[async_trait::async_trait]
    pub trait DecomposeDb: Send + Sync {
        /// A connection to read on, as `viewer`.
        async fn read<'a>(&'a self, viewer: &Viewer) -> Result<DecomposeRead<'a>, DbError>;
        /// A transaction to write in, as `viewer`.
        async fn write<'a>(&'a self, viewer: &Viewer) -> Result<DecomposeTx<'a>, DbError>;
    }

    /// A read connection from a [`DecomposeDb`]; derefs to the connection.
    pub enum DecomposeRead<'a> {
        Pool(sqlx::pool::PoolConnection<sqlx::Postgres>),
        Scoped(epigraph_db::ScopedRead<'a>),
    }

    impl std::ops::Deref for DecomposeRead<'_> {
        type Target = PgConnection;
        fn deref(&self) -> &PgConnection {
            match self {
                Self::Pool(c) => c,
                Self::Scoped(c) => c,
            }
        }
    }

    impl std::ops::DerefMut for DecomposeRead<'_> {
        fn deref_mut(&mut self) -> &mut PgConnection {
            match self {
                Self::Pool(c) => c,
                Self::Scoped(c) => c,
            }
        }
    }

    /// A write transaction from a [`DecomposeDb`]. Dropped without
    /// [`Self::commit`], it rolls back.
    pub enum DecomposeTx<'a> {
        Pool(sqlx::Transaction<'static, sqlx::Postgres>),
        Scoped(epigraph_db::ScopedTx<'a>),
    }

    impl DecomposeTx<'_> {
        /// The transaction's connection.
        pub fn conn(&mut self) -> &mut PgConnection {
            match self {
                Self::Pool(t) => t,
                Self::Scoped(t) => t,
            }
        }

        /// Commit.
        ///
        /// # Errors
        /// The commit failed.
        pub async fn commit(self) -> Result<(), DbError> {
            match self {
                Self::Pool(t) => t.commit().await.map_err(DbError::from),
                Self::Scoped(t) => t.commit().await,
            }
        }
    }

    #[async_trait::async_trait]
    impl DecomposeDb for PgPool {
        async fn read<'a>(&'a self, _viewer: &Viewer) -> Result<DecomposeRead<'a>, DbError> {
            Ok(DecomposeRead::Pool(
                self.acquire()
                    .await
                    .map_err(|source| DbError::ConnectionFailed { source })?,
            ))
        }

        async fn write<'a>(&'a self, _viewer: &Viewer) -> Result<DecomposeTx<'a>, DbError> {
            Ok(DecomposeTx::Pool(self.begin().await?))
        }
    }

    #[async_trait::async_trait]
    impl DecomposeDb for epigraph_db::ScopedPool {
        async fn read<'a>(&'a self, viewer: &Viewer) -> Result<DecomposeRead<'a>, DbError> {
            Ok(DecomposeRead::Scoped(self.read_as(viewer).await?))
        }

        async fn write<'a>(&'a self, viewer: &Viewer) -> Result<DecomposeTx<'a>, DbError> {
            Ok(DecomposeTx::Scoped(self.begin_as(viewer).await?))
        }
    }

    /// How many claims `viewer` sees on `db`, through the same visibility
    /// predicate (and, on a [`epigraph_db::ScopedPool`], the same row
    /// security) every selection read uses.
    ///
    /// The `--as-agent` zero-visible check for a population narrower than
    /// "every undecomposed claim" (`--priority conflict`): an empty conflict
    /// queue is a legitimate result, a session that sees no claim at all is
    /// not.
    ///
    /// # Errors
    /// Database failure.
    pub async fn visible_claim_count(
        db: &dyn DecomposeDb,
        viewer: &Viewer,
    ) -> Result<i64, DbError> {
        ClaimRepository::count_conn(&mut *db.read(viewer).await?, viewer, None).await
    }

    /// The group a `decomposes_to` edge written as `viewer` on `db` records
    /// as its writer ([`EdgeRepository::session_writer_group`], the function
    /// migration 120's edge trigger stamps `writer_group_id` from), evaluated
    /// in a write transaction stamped exactly like the edge transaction and
    /// rolled back: nothing is written.
    ///
    /// `None` means such an edge would land with no writer group. That is the
    /// case for an agent with no writable group, and ALSO for one whose
    /// writable groups include neither its operator's personal group nor its
    /// own: a count of writable groups answers a different question.
    ///
    /// # Errors
    /// Database failure.
    pub async fn writer_group(
        db: &dyn DecomposeDb,
        viewer: &Viewer,
    ) -> Result<Option<Uuid>, DbError> {
        let mut tx = db.write(viewer).await?;
        let group = EdgeRepository::session_writer_group(tx.conn()).await?;
        // Dropped without commit: rolled back.
        drop(tx);
        Ok(group)
    }

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
    /// derivation provenance and embed-on-write are preserved (that path
    /// writes no DS mass function for an atom). In the
    /// binary this closure POSTs to the local API `/api/v1/claims` (or calls
    /// the in-process submit helper); in tests it is a fake that inserts a
    /// minimal claim row, letting us verify the edge/label wiring WITHOUT an
    /// LLM or an embedder.
    ///
    /// Single-atom decompositions are SKIPPED (a claim that decomposes to
    /// exactly itself is already atomic — writing a self-equivalent child +
    /// edge would pollute the graph and is what `is_current`-atoms look like).
    pub async fn persist_decomposition<F, Fut>(
        db: &dyn DecomposeDb,
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
        if !ClaimRepository::are_all_current(&mut *db.read(viewer).await?, viewer, &[parent_id])
            .await?
        {
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
        // "no decomposition" to "all atoms" with nothing in between. On the
        // `--as-agent` path the transaction is stamped for the acting agent,
        // so each edge records it as the writer (see [`DecomposeDb`]).
        let mut tx = db.write(viewer).await?;
        let mut edges = 0usize;
        for (&atom_id, &gen) in atom_ids.iter().zip(gens.iter()) {
            let (_row, was_created) = EdgeRepository::create_if_absent_including_retracted_conn(
                tx.conn(),
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
        /// Parents the model answered with one atom (already atomic), so
        /// nothing was written for them.
        pub singletons: Vec<Uuid>,
        /// Claims sent to the LLM that got no plan line (normal runs only;
        /// `--apply-plan` makes no LLM call and leaves this empty).
        pub gaps: PlanGaps,
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
    /// `submit_via` receives `(atom_text, generality, parent)`; atoms inherit
    /// their parent compound claim's author and record it as their derivation
    /// source, and the parent varies across a batch, so neither can be
    /// captured once by the caller.
    ///
    /// A batch whose LLM call fails is logged and skipped (the run continues);
    /// a persist failure aborts the run. With `ledger`, every parent the model
    /// answers with one atom is recorded (see [`persist_planned`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_decomposition_batches<F, Fut>(
        db: &dyn DecomposeDb,
        viewer: &epigraph_db::visibility::Viewer,
        claims: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
        embedder: Option<Arc<dyn epigraph_embeddings::EmbeddingService>>,
        mut ledger: Option<&mut super::SingletonLedger>,
        submit_via: F,
    ) -> Result<BatchTotals, Box<dyn std::error::Error>>
    where
        F: Fn(String, i64, AtomParent) -> Fut,
        Fut: std::future::Future<Output = Result<Uuid, Box<dyn std::error::Error>>>,
    {
        let mut totals = BatchTotals::default();
        for chunk in claims.chunks(batch_size.max(1)) {
            let (planned, gaps) = plan_chunk(chunk, llm).await;
            totals.gaps.extend(gaps);
            // Verdicts are appended per chunk, so a run that aborts later
            // keeps the ones it already paid for.
            let chunk_totals = persist_planned(
                db,
                viewer,
                &planned,
                embedder.clone(),
                ledger.as_deref_mut(),
                &submit_via,
            )
            .await?;
            totals.atoms += chunk_totals.atoms;
            totals.edges += chunk_totals.edges;
            totals.singletons.extend(chunk_totals.singletons);
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

    /// Chosen claims the planner could not turn into a plan line, and why.
    /// Without this a claim named in `--ids-file` that the model skipped, or
    /// whose batch call failed, would simply be missing from the output.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct PlanGaps {
        /// The LLM call for the claim's batch failed, with the error.
        pub llm_error: Vec<(Uuid, String)>,
        /// The response had no usable answer for the claim.
        pub no_answer: Vec<Uuid>,
    }

    impl PlanGaps {
        fn extend(&mut self, other: PlanGaps) {
            self.llm_error.extend(other.llm_error);
            self.no_answer.extend(other.no_answer);
        }
    }

    /// One LLM call for one chunk: prompt -> model -> parse -> the parent each
    /// answer belongs to. Writes nothing.
    ///
    /// A failed call is logged and yields an empty plan for the chunk (the run
    /// continues), matching the historical batch loop; every claim of the
    /// chunk is reported in [`PlanGaps::llm_error`]. A claim the response does
    /// not answer is reported in [`PlanGaps::no_answer`]. The parent lookup is
    /// `chunk.get(local_idx)`: an index the model invented is dropped, never
    /// wired to a neighbour.
    async fn plan_chunk(
        chunk: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
    ) -> (Vec<super::PlannedDecomposition>, PlanGaps) {
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
                let why = e.to_string();
                let gaps = PlanGaps {
                    llm_error: chunk.iter().map(|c| (c.claim_id, why.clone())).collect(),
                    no_answer: vec![],
                };
                return (vec![], gaps);
            }
        };
        let planned: Vec<super::PlannedDecomposition> = super::parse_batch_response(&raw)
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
            .collect();
        let answered: std::collections::HashSet<Uuid> =
            planned.iter().map(|p| p.claim_id).collect();
        let gaps = PlanGaps {
            llm_error: vec![],
            no_answer: chunk
                .iter()
                .map(|c| c.claim_id)
                .filter(|id| !answered.contains(id))
                .collect(),
        };
        (planned, gaps)
    }

    /// `--plan`: every LLM call a decomposition run would make, and nothing
    /// else. No claim, edge or embedding is written; the caller serializes the
    /// result with [`super::write_plan_jsonl`]. See
    /// [`plan_decomposition_batches_with_gaps`] for what was NOT planned.
    pub async fn plan_decomposition_batches(
        claims: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
    ) -> Vec<super::PlannedDecomposition> {
        plan_decomposition_batches_with_gaps(claims, llm, batch_size)
            .await
            .0
    }

    /// [`plan_decomposition_batches`], also returning every claim that got
    /// no plan line and why, so the caller can name each one.
    pub async fn plan_decomposition_batches_with_gaps(
        claims: &[BatchClaim],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
    ) -> (Vec<super::PlannedDecomposition>, PlanGaps) {
        let mut out = Vec::new();
        let mut gaps = PlanGaps::default();
        for chunk in claims.chunks(batch_size.max(1)) {
            let (planned, g) = plan_chunk(chunk, llm).await;
            out.extend(planned);
            gaps.extend(g);
        }
        (out, gaps)
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
    /// With `ledger`, every line the model answered with one atom is appended
    /// to it, so the next selection passes the parent over
    /// ([`super::Ineligible::JudgedAtomic`]). This is where a run records its
    /// verdicts — not the binary — so `--apply-plan` records them too and
    /// `--plan` (which never persists) records none. A failed append is a
    /// failed line in [`BatchTotals::failed`], not an abort.
    ///
    /// # Errors
    /// None today; the `Result` is kept for callers.
    pub async fn persist_planned<F, Fut>(
        db: &dyn DecomposeDb,
        viewer: &epigraph_db::visibility::Viewer,
        planned: &[super::PlannedDecomposition],
        embedder: Option<Arc<dyn epigraph_embeddings::EmbeddingService>>,
        mut ledger: Option<&mut super::SingletonLedger>,
        submit_via: &F,
    ) -> Result<BatchTotals, Box<dyn std::error::Error>>
    where
        F: Fn(String, i64, AtomParent) -> Fut,
        Fut: std::future::Future<Output = Result<Uuid, Box<dyn std::error::Error>>>,
    {
        let mut totals = BatchTotals::default();
        for plan in planned {
            let parent = AtomParent {
                claim_id: plan.claim_id,
                agent_id: plan.agent_id,
            };
            match persist_decomposition(
                db,
                viewer,
                plan.claim_id,
                &plan.decomposition(),
                embedder.clone(),
                move |atom_text, generality| submit_via(atom_text, generality, parent),
            )
            .await
            {
                Ok(outcome) => {
                    totals.atoms += outcome.atom_claim_ids.len();
                    totals.edges += outcome.edges_created;
                    if outcome.skipped_singletons > 0 {
                        totals.singletons.push(plan.claim_id);
                        // The verdict is on the text the model judged, which
                        // is the plan's `content` (verified equal to the live
                        // parent before an apply). A failed append fails this
                        // LINE, like a failed submit: the parent stays
                        // undecomposed and unrecorded, a re-run records it,
                        // and the rest of the plan is still applied. Only a
                        // ONE-atom answer is a verdict that the text is
                        // atomic: an empty line (hand-edited plan) is not.
                        if let Some(l) = ledger.as_deref_mut().filter(|_| plan.atoms.len() == 1) {
                            if let Err(e) = l.record(plan.claim_id, &plan.content, &plan.model) {
                                totals.failed.push((
                                    plan.claim_id,
                                    format!("judged atomic, but not recorded: {e}"),
                                ));
                            }
                        }
                    }
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
        /// The plan names this parent on more than one line (two `--plan`
        /// outputs concatenated, say). Every such line is refused: applying
        /// both would give one parent two sets of atoms, and picking one
        /// would be a guess about which the operator reviewed.
        DuplicateInPlan,
        /// The line's `agent_id` is not the live parent's author. Atoms are
        /// POSTed under the line's `agent_id`, so a stale or edited value
        /// would attribute them to someone else.
        AgentChanged,
    }

    /// Split a plan into the lines that still describe the graph and the
    /// lines that do not. A line applies only if its parent is named on no
    /// other line, is still in the undecomposed population, has content
    /// byte-identical to the plan text (atoms are never wired onto text they
    /// were not derived from), and is authored by the line's `agent_id`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn verify_plan(
        db: &dyn DecomposeDb,
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
        let mut lines_per_parent: std::collections::HashMap<Uuid, usize> =
            std::collections::HashMap::new();
        for p in &planned {
            *lines_per_parent.entry(p.claim_id).or_default() += 1;
        }
        let ids: Vec<Uuid> = lines_per_parent.keys().copied().collect();
        let mut live = std::collections::HashMap::new();
        for chunk in ids.chunks(1000) {
            for c in
                R::list_undecomposed_by_ids(&mut *db.read(viewer).await?, viewer, chunk).await?
            {
                live.insert(c.id, (c.content, c.agent_id));
            }
        }
        let mut ok = Vec::new();
        let mut drifted = Vec::new();
        for p in planned {
            if lines_per_parent.get(&p.claim_id).copied().unwrap_or(0) > 1 {
                drifted.push((p, PlanDrift::DuplicateInPlan));
                continue;
            }
            match live.get(&p.claim_id) {
                None => drifted.push((p, PlanDrift::NoLongerUndecomposed)),
                Some((text, _)) if *text != p.content => {
                    drifted.push((p, PlanDrift::ContentChanged))
                }
                Some((_, agent)) if *agent != p.agent_id => {
                    drifted.push((p, PlanDrift::AgentChanged))
                }
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
        db: &dyn DecomposeDb,
        viewer: &epigraph_db::visibility::Viewer,
        priority: Priority,
        ids: Option<&[Uuid]>,
        filters: super::EligibilityFilters,
        judged_atomic: Option<&super::SingletonLedger>,
        limit: usize,
        max_scan: usize,
    ) -> Result<Selection, Box<dyn std::error::Error>> {
        use epigraph_db::repos::decomposition_priority::{
            DecomposeCandidate, DecompositionPriorityRepository as R, UndecomposedOrder,
        };
        // Every rule a candidate must pass, in reporting order. The ledger is
        // consulted last, so `skipped_judged_atomic` counts only parents an
        // LLM call would otherwise have gone to: up to `limit`, exactly the
        // calls it saved (with `--count-eligible`, `limit` is the whole scan,
        // so it counts every judged parent read).
        let verdict = |r: &DecomposeCandidate| -> Result<(), super::Ineligible> {
            super::check_publicly_decomposable(&r.visibility)?;
            super::check_eligibility(&r.content, &r.labels, filters)?;
            if judged_atomic.is_some_and(|l| l.contains(r.id, &r.content)) {
                return Err(super::Ineligible::JudgedAtomic);
            }
            Ok(())
        };
        let mut sel = Selection::default();
        if let Some(ids) = ids {
            let mut rows = Vec::new();
            for chunk in ids.chunks(1000) {
                rows.extend(
                    R::list_undecomposed_by_ids(&mut *db.read(viewer).await?, viewer, chunk)
                        .await?,
                );
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
                match verdict(&r) {
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
        // One stamped connection for the whole scan: every page is read as
        // the same viewer.
        let mut conn = db.read(viewer).await?;
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
                    R::list_undecomposed_conflict_targets(&mut *conn, viewer, PAGE, offset).await?
                }
                Priority::Recent => {
                    R::list_undecomposed_ordered(
                        &mut *conn,
                        viewer,
                        UndecomposedOrder::Recent,
                        PAGE,
                        offset,
                    )
                    .await?
                }
                Priority::Oldest => {
                    R::list_undecomposed_ordered(
                        &mut *conn,
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
                match verdict(&r) {
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

        // A second --plan to the same path is refused, and the reviewed plan
        // is left byte-for-byte as it was.
        let before = std::fs::read(&path).unwrap();
        let err = write_plan_jsonl(&path, &[]).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let mut foreign = serde_json::to_value(&plans[0]).unwrap();
        foreign["kind"] = serde_json::json!("retarget");
        std::fs::write(&path, format!("{foreign}\n")).unwrap();
        let err = read_plan_jsonl(&path).unwrap_err().to_string();
        assert!(err.contains("kind"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- plan gaps: every chosen claim is accounted for ---

    #[cfg(feature = "db")]
    struct DownLlm;

    #[cfg(feature = "db")]
    #[async_trait::async_trait]
    impl epigraph_interfaces::LlmProvider for DownLlm {
        fn name(&self) -> &str {
            "down"
        }
        fn model_name(&self) -> &str {
            "down"
        }
        fn is_active(&self) -> bool {
            true
        }
        async fn complete_json(
            &self,
            _prompt: &str,
        ) -> Result<serde_json::Value, epigraph_interfaces::LlmError> {
            Err(epigraph_interfaces::LlmError::RequestFailed {
                message: "503 upstream".into(),
            })
        }
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn planning_names_every_claim_it_could_not_plan() {
        let claim = |t: &str| BatchClaim {
            claim_id: uuid::Uuid::new_v4(),
            agent_id: uuid::Uuid::new_v4(),
            content: t.to_string(),
        };
        let claims = vec![
            claim("Answered compound. With a second part."),
            claim("Answered as a single atom."),
            claim("Ignored by the model. Entirely."),
        ];
        let llm = crate::enrichment::llm_client::FixtureLlmClient::from_json(&serde_json::json!({
            claims[0].content.clone(): {"atoms": ["a", "b"], "generality": [0, 0]},
            claims[1].content.clone(): {"atoms": ["x"], "generality": [0]},
        }))
        .unwrap();
        let (plans, gaps) = plan_decomposition_batches_with_gaps(&claims, &llm, 10).await;
        assert_eq!(
            plans.iter().map(|p| p.claim_id).collect::<Vec<_>>(),
            vec![claims[0].claim_id, claims[1].claim_id]
        );
        assert_eq!(gaps.no_answer, vec![claims[2].claim_id]);
        assert!(gaps.llm_error.is_empty());

        // A failed call names every claim of every failed batch.
        let (plans, gaps) = plan_decomposition_batches_with_gaps(&claims, &DownLlm, 2).await;
        assert!(plans.is_empty());
        assert_eq!(
            gaps.llm_error.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            claims.iter().map(|c| c.claim_id).collect::<Vec<_>>()
        );
        assert!(gaps.llm_error[0].1.contains("503 upstream"));
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

    // --- singleton ledger ---

    fn temp_ledger_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", uuid::Uuid::new_v4()))
    }

    #[test]
    fn singleton_ledger_round_trips_and_keys_on_content_hash() {
        let path = temp_ledger_path();
        let id = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
        ledger
            .record(id, "Text A. Still text A.", "model-x")
            .unwrap();
        // The same verdict again is not appended twice.
        ledger
            .record(id, "Text A. Still text A.", "model-x")
            .unwrap();

        let back = SingletonLedger::load(&path).unwrap();
        assert!(back.contains(id, "Text A. Still text A."));
        assert!(
            !back.contains(id, "Text B. Edited since."),
            "a changed text is a new question"
        );
        assert!(
            !back.contains(other, "Text A. Still text A."),
            "the verdict belongs to one claim id"
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 1, "{raw}");
        let line: JudgedAtomicEntry = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(line.kind, SingletonLedger::KIND);
        assert_eq!(line.model, "model-x");
        assert_eq!(
            line.content_blake3,
            blake3::hash(b"Text A. Still text A.").to_hex().to_string()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_read_only_ledger_creates_nothing_and_refuses_to_record() {
        let path = temp_ledger_path();
        let mut ledger = SingletonLedger::load(&path).unwrap();
        assert!(ledger.is_empty());
        assert!(
            !path.exists(),
            "--dry-run / --plan must not create the file"
        );
        let err = ledger
            .record(uuid::Uuid::new_v4(), "x", "m")
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only"), "{err}");
        assert!(!path.exists());
    }

    /// A crash or a full disk mid-append can leave a final line with no
    /// newline. That torn tail must not take the daily job down at startup
    /// (every later load would refuse the file until someone edits it): the
    /// reader skips it, and the next recording run cuts it off before it
    /// appends. A COMPLETE final line that only lacks its newline is kept.
    #[test]
    fn a_torn_final_line_is_skipped_and_cut_off_before_the_next_append() {
        let path = temp_ledger_path();
        let (a, b, c) = (
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
        ledger.record(a, "Text A. More A.", "m").unwrap();
        let whole = std::fs::read_to_string(&path).unwrap();
        // Half of a second record, as an interrupted append leaves it.
        std::fs::write(&path, format!("{whole}{}", &whole[..whole.len() / 2])).unwrap();

        let back = SingletonLedger::load(&path).expect("a torn final line is skipped");
        assert_eq!(back.len(), 1);
        assert!(back.contains(a, "Text A. More A."));

        let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
        ledger.record(b, "Text B. More B.", "m").unwrap();
        let back = SingletonLedger::load(&path).expect("the torn tail was cut off");
        assert_eq!(back.len(), 2);
        assert!(back.contains(b, "Text B. More B."));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);

        // A complete last line without its newline (a hand edit) is a verdict.
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.trim_end_matches('\n')).unwrap();
        assert_eq!(SingletonLedger::load(&path).unwrap().len(), 2);
        let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
        ledger.record(c, "Text C. More C.", "m").unwrap();
        let back = SingletonLedger::load(&path).unwrap();
        assert_eq!(back.len(), 3, "the unterminated verdict was kept");
        assert!(back.contains(a, "Text A. More A.") && back.contains(c, "Text C. More C."));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_malformed_or_foreign_ledger_line_is_refused_with_its_line_number() {
        let path = temp_ledger_path();
        let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
        ledger.record(uuid::Uuid::new_v4(), "ok", "m").unwrap();
        std::fs::write(
            &path,
            format!("{}not json\n", std::fs::read_to_string(&path).unwrap()),
        )
        .unwrap();
        let err = SingletonLedger::load(&path).unwrap_err().to_string();
        assert!(err.contains(&format!("{}:2:", path.display())), "{err}");

        // A decomposition plan line handed over by mistake.
        let plan = serde_json::json!({
            "kind": "decomposition",
            "claim_id": uuid::Uuid::new_v4(),
            "content_blake3": "00".repeat(32),
            "model": "m",
            "decided_at": "2026-10-15T00:00:00Z",
        });
        std::fs::write(&path, format!("{plan}\n")).unwrap();
        let err = SingletonLedger::load(&path).unwrap_err().to_string();
        assert!(
            err.contains(":1:") && err.contains("judged_atomic"),
            "{err}"
        );
        std::fs::remove_file(&path).ok();
    }
}
