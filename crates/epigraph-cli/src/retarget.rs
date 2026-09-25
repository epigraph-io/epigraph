//! Move a conflict edge from a decomposed parent onto the atom it actually
//! disputes.
//!
//! # The problem (production, read-only, 2026-09-24)
//!
//! 183 of 619 contradicts/refutes claim→claim edges point at NON-atomic
//! targets; 24 of those targets are already decomposed, so the contradiction
//! still lands on the conjunction while the atoms it disputes carry nothing.
//!
//! # What this module does
//!
//! For each in-force contradicts/refutes edge whose target has current
//! `decomposes_to` atoms:
//!
//! 1. Ask the LLM — the same prepaid path decompose uses — which atom(s) the
//!    SOURCE claim contradicts. Allowed answers: a non-empty subset of atom
//!    indices, `"whole"`, or `"unclear"`. Anything else is malformed, and a
//!    malformed answer takes NO action for that edge ([`parse_retarget_response`]).
//! 2. For each chosen atom, create the same relationship source→atom, in its
//!    lower-case spelling ([`api_relationship`]), through `POST /api/v1/edges`,
//!    so the API's create→wire path runs and DS belief is wired on the atom
//!    exactly as a fresh link would be. Provenance rides on the edge's
//!    properties. `contradicts` retargets are HELD until the API accepts that
//!    spelling ([`HELD_RELATIONSHIPS`]); `refutes` retargets are applied.
//! 3. KEEP the parent edge and mark it `properties.retargeted_to = [...]`
//!    through `PATCH /api/v1/edges/:id`. Its belief mass is not touched.
//!
//! Writing is opt-in: the binary's default is a dry run that calls the LLM,
//! prints the mapping, writes a JSONL manifest, and writes nothing to the
//! graph.
//!
//! # Idempotency — four guards, each for a different failure
//!
//! * **Marked parents are not re-planned.** [`load_retarget_items`] skips edges
//!   that already carry `retargeted_to` with an empty `retarget_unwired`, so a
//!   re-run after a successful, fully-wired apply makes no LLM call and no
//!   write.
//! * **Resume, don't re-ask.** An edge an earlier run already moved (atom
//!   edges with `retargeted_from_edge = <this edge>` exist) is re-planned from
//!   those atoms with NO LLM call ([`plan_with_resume`]): a lost PATCH or an
//!   unwired atom edge is retried with the same atoms, never with a second,
//!   possibly different, LLM answer.
//! * **Pre-create check.** Before creating source→atom, [`apply_entry`] looks
//!   the edge up (both orientations for a symmetric relationship). A live
//!   match is recorded as `existing`, not re-created, and re-asserted through
//!   the API if it still has no BBA.
//! * **`if_not_exists: true`** on the POST, so a concurrent writer racing the
//!   pre-check still cannot produce a duplicate.
//!
//! # When an atom edge carries no BBA
//!
//! The API can store an edge and wire nothing: the source claim has no belief
//! interval yet (`SourceFactorless`), or — conditional on how production is
//! deployed, not measured here — the API runs as `epigraph_app`, where the
//! still-unstamped edge DS path cannot write `mass_functions`. The parent is
//! then marked with the atom edge in `retargeted_to` AND in
//! `retarget_unwired`, which brings it back on the next run to be resumed and
//! re-asserted (the dedup-hit path of `POST /api/v1/edges` re-runs the
//! auto-wire), until it wires.
//!
//! A RETIRED source→atom edge blocks the retarget for that atom: someone
//! retracted exactly this claim, and `if_not_exists` would hand back the
//! retired row, which never wires. The block is reported, never overridden.

use crate::decompose::strip_code_fence;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// The retarget batch prompt. `{items}` is replaced by [`build_retarget_prompt`].
///
/// Formatting contract (the fixture provider depends on it): the ONLY lines
/// that start with `[` are the per-item `[<idx>] <source claim>` headers. Rule,
/// example and atom lines never do.
pub const RETARGET_BATCH_PROMPT: &str = r#"You are an epistemic conflict router. Each numbered item below is a SOURCE claim that was filed as contradicting a COMPOUND claim, followed by the compound claim's atomic propositions, numbered from 0.

For each item decide which atomic proposition(s) the SOURCE claim actually contradicts.

Answer for each item with exactly one of:
- {"atoms": [<atom numbers>]}  when the source contradicts specific atoms (a non-empty list of the atom numbers shown for THAT item);
- "whole"    when the source genuinely disputes the conjunction as a whole and no individual atom;
- "unclear"  when you cannot tell.

Do not guess: prefer "unclear" over a weak atom choice.

Return ONLY a JSON object mapping each item number to its answer.
Example output: {"0": {"atoms": [1]}, "1": "whole", "2": "unclear", "3": {"atoms": [0, 2]}}

Items:
{items}"#;

/// The spelling a retargeted atom edge is sent (and therefore stored) with:
/// the lower-case conflict relationship, the spelling every exact-case reader
/// matches (`ClaimRepository::dispute_batch`, `repos/sheaf.rs`,
/// `routes/computation.rs`, `repos/alternative_set.rs`, and
/// `create_symmetric_if_absent_oriented`'s dedup). A relationship this
/// function does not know is returned unchanged and left to the API to judge.
///
/// This is NOT always a spelling `POST /api/v1/edges` accepts: see
/// [`hold_reason`], which stops a retarget before it reaches the API when it
/// is not.
pub fn api_relationship(stored: &str) -> String {
    let lower = stored.to_ascii_lowercase();
    match lower.as_str() {
        "contradicts" | "refutes" => lower,
        _ => stored.to_string(),
    }
}

/// Conflict relationships whose retarget is HELD: planned (the dry run and
/// the manifest still show the LLM's mapping) but never applied.
///
/// # Why `contradicts` is held
///
/// The HTTP whitelist (`routes/edges.rs::VALID_RELATIONSHIPS`) is
/// case-sensitive and accepts `contradicts` ONLY as `CONTRADICTS`. An atom
/// edge stored as `CONTRADICTS` is invisible to every reader that matches the
/// lower-case spelling MCP `link_epistemic` stores — measured in review:
/// after an apply, `dispute_batch` reported the parent disputed and the atom
/// not (lower-casing the same row made the atom count 1), and a later
/// `link_epistemic` of the same dispute onto the atom created a SECOND edge
/// and a second BBA from the same source (DS double counting), because its
/// symmetric dedup matches the relationship byte-exactly. Writing that split
/// 100+ times in production is hard to undo, so it is not written at all.
///
/// The hold lifts when the owner of `routes/edges.rs` adds lower-case
/// `contradicts` to `VALID_RELATIONSHIPS`: then remove it from this list.
/// `tests/retarget_conflicts.rs` pins the hold to the whitelist, so it fails
/// the moment the whitelist changes. `refutes` is accepted in lower case and
/// is not held.
pub const HELD_RELATIONSHIPS: [&str; 1] = ["contradicts"];

/// Why a retarget of `stored` must not be applied, or `None` if it may be.
pub fn hold_reason(stored: &str) -> Option<String> {
    let lower = stored.to_ascii_lowercase();
    HELD_RELATIONSHIPS.contains(&lower.as_str()).then(|| {
        format!(
            "HELD: `{lower}` retargets are not applied — POST /api/v1/edges accepts only \
             `CONTRADICTS`, which readers matching `{lower}` (dispute_batch, sheaf, \
             link_epistemic dedup) do not see; waiting on routes/edges.rs \
             VALID_RELATIONSHIPS to accept `{lower}`"
        )
    })
}

/// One conflict edge to retarget, with the parent's atoms in their stable
/// numbering order (index = position in `atoms`).
#[derive(Debug, Clone, PartialEq)]
pub struct RetargetItem {
    pub edge_id: Uuid,
    pub relationship: String,
    pub source_id: Uuid,
    pub source_content: String,
    pub parent_id: Uuid,
    pub atoms: Vec<(Uuid, String)>,
}

/// Collapse all whitespace runs (newlines included) to single spaces, so an
/// item's text occupies exactly one prompt line.
pub fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Build one batch prompt. Each item renders as
///
/// ```text
/// [<idx>] <source claim, one line>
///     atom 0: <atom text, one line>
///     atom 1: ...
/// ```
pub fn build_retarget_prompt(items: &[(usize, &RetargetItem)]) -> String {
    let mut body = String::new();
    for (idx, item) in items {
        body.push_str(&format!("[{idx}] {}\n", one_line(&item.source_content)));
        for (a, (_, text)) in item.atoms.iter().enumerate() {
            body.push_str(&format!("    atom {a}: {}\n", one_line(text)));
        }
    }
    RETARGET_BATCH_PROMPT.replace("{items}", body.trim_end())
}

/// The model's answer for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetargetVerdict {
    /// Sorted, de-duplicated, in-range atom indices. Never empty.
    Atoms(Vec<usize>),
    /// The source disputes the conjunction; leave the edge on the parent.
    Whole,
    /// The model could not tell; leave the edge on the parent.
    Unclear,
}

/// Parse a batch response strictly.
///
/// `atom_counts[i]` is how many atoms item `i` showed the model. The result
/// maps each item index the response mentions to either its verdict or the
/// reason the answer was rejected. Items the response does not mention are
/// absent. A response that is not a JSON object yields an empty map.
///
/// Rejected (per item, no action): an index outside `atom_counts`; an atom
/// list that is empty, contains a non-integer, a negative number, or a number
/// `>= atom_counts[i]`, or repeats an index; any string other than `whole` /
/// `unclear` (case-insensitive, surrounding whitespace ignored); any other
/// JSON shape, including an object with keys besides `atoms`.
pub fn parse_retarget_response(
    raw: &str,
    atom_counts: &[usize],
) -> BTreeMap<usize, Result<RetargetVerdict, String>> {
    let mut out = BTreeMap::new();
    let text = strip_code_fence(raw);
    let (start, end) = match (text.find('{'), text.rfind('}')) {
        (Some(s), Some(e)) if e > s => (s, e + 1),
        _ => return out,
    };
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&text[start..end]) else {
        return out;
    };
    for (key, val) in obj {
        let Ok(idx) = key.trim().parse::<usize>() else {
            continue;
        };
        let Some(&n_atoms) = atom_counts.get(idx) else {
            continue;
        };
        out.insert(idx, parse_one_verdict(&val, n_atoms));
    }
    out
}

fn parse_one_verdict(val: &Value, n_atoms: usize) -> Result<RetargetVerdict, String> {
    match val {
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "whole" => Ok(RetargetVerdict::Whole),
            "unclear" => Ok(RetargetVerdict::Unclear),
            other => Err(format!("unknown verdict string {other:?}")),
        },
        Value::Object(m) => {
            if m.len() != 1 {
                return Err(format!(
                    "object answer must have exactly the key \"atoms\", got {:?}",
                    m.keys().collect::<Vec<_>>()
                ));
            }
            let Some(Value::Array(arr)) = m.get("atoms") else {
                return Err("object answer has no \"atoms\" array".to_string());
            };
            if arr.is_empty() {
                return Err("empty atom list".to_string());
            }
            let mut picked = Vec::with_capacity(arr.len());
            for v in arr {
                let Some(i) = v.as_u64() else {
                    return Err(format!("atom index {v} is not a non-negative integer"));
                };
                let i = usize::try_from(i).map_err(|_| format!("atom index {i} overflows"))?;
                if i >= n_atoms {
                    return Err(format!("atom index {i} out of range (item has {n_atoms})"));
                }
                if picked.contains(&i) {
                    return Err(format!("atom index {i} repeated"));
                }
                picked.push(i);
            }
            picked.sort_unstable();
            Ok(RetargetVerdict::Atoms(picked))
        }
        other => Err(format!("unsupported answer shape {other}")),
    }
}

/// An atom as recorded in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomRef {
    pub index: usize,
    pub atom_id: Uuid,
}

/// The per-edge verdict label written to the manifest.
pub mod verdict {
    pub const ATOMS: &str = "atoms";
    pub const WHOLE: &str = "whole";
    pub const UNCLEAR: &str = "unclear";
    /// The model answered this item, but not in an allowed form.
    pub const MALFORMED: &str = "malformed";
    /// The model's response did not mention this item.
    pub const NO_ANSWER: &str = "no_answer";
    /// The LLM call for this item's batch failed.
    pub const LLM_ERROR: &str = "llm_error";
}

/// One manifest line: what the LLM said about one parent conflict edge.
///
/// `--retarget` (dry run) writes one per edge. `--retarget --apply` and
/// `--retarget --apply-plan <manifest>` act on the `atoms` entries only, and
/// append one [`AppliedEntry`] line per entry they act on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetargetPlanEntry {
    /// Always `"retarget_plan"`.
    pub kind: String,
    pub edge_id: Uuid,
    pub relationship: String,
    pub source_id: Uuid,
    pub parent_id: Uuid,
    /// Every atom the model was shown, with its index.
    pub atoms: Vec<AtomRef>,
    /// One of the [`verdict`] constants.
    pub verdict: String,
    /// Why a `malformed` / `llm_error` answer was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The atoms the edge would move to. Non-empty only for `atoms`.
    pub chosen_atom_ids: Vec<Uuid>,
    pub model: String,
}

impl RetargetPlanEntry {
    pub const KIND: &'static str = "retarget_plan";
}

/// What an apply did for one plan entry. Appended to the manifest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AppliedEntry {
    /// Always `"retarget_applied"`.
    pub kind: String,
    pub edge_id: Uuid,
    /// source→atom edges this run created.
    pub created_edge_ids: Vec<Uuid>,
    /// source→atom edges that already existed and were adopted, not created.
    pub existing_edge_ids: Vec<Uuid>,
    /// Atoms skipped because a RETIRED source→atom edge exists.
    pub blocked_by_retired_edge: Vec<Uuid>,
    /// Atom edge ids whose DS BBA exists after the write. An edge in
    /// `created_edge_ids` but not here was written but NOT wired — typically a
    /// source claim with no belief interval yet (`SourceFactorless`).
    pub ds_wired_edge_ids: Vec<Uuid>,
    /// Adopted atom edges that had no BBA and were re-asserted through
    /// `POST /api/v1/edges` (`if_not_exists`), whose dedup-hit path re-runs
    /// the DS auto-wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasserted_edge_ids: Vec<Uuid>,
    /// Whether `retargeted_to` on the parent edge now lists every atom edge.
    /// The mark also records `retarget_unwired` (resolved edges with no BBA);
    /// a non-empty list brings the parent edge back on the next run.
    pub parent_marked: bool,
    /// The relationship is in [`HELD_RELATIONSHIPS`]: nothing was sent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Why nothing (or not everything) was applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl AppliedEntry {
    pub const KIND: &'static str = "retarget_applied";
}

/// Why a manifest entry is not a well-formed `atoms` retarget, judged on the
/// entry alone (no database): the relationship must be a conflict
/// relationship, every chosen atom must be one the model was shown
/// (`entry.atoms`), and the source must not be one of the atoms.
///
/// These are the checks a hand-edited or concatenated manifest can fail; the
/// live-graph checks (edge in force, atoms still current atoms of the parent,
/// endpoints current) run after it in `apply_entry`.
pub fn entry_shape_error(entry: &RetargetPlanEntry) -> Option<String> {
    let rel = entry.relationship.to_ascii_lowercase();
    if !CONFLICT_RELATIONSHIPS.contains(&rel.as_str()) {
        return Some(format!(
            "relationship {:?} is not a conflict relationship {CONFLICT_RELATIONSHIPS:?}",
            entry.relationship
        ));
    }
    if entry.verdict != verdict::ATOMS || entry.chosen_atom_ids.is_empty() {
        return Some(format!(
            "verdict {:?} with {} chosen atoms is not an atoms retarget",
            entry.verdict,
            entry.chosen_atom_ids.len()
        ));
    }
    let shown: std::collections::HashSet<Uuid> = entry.atoms.iter().map(|a| a.atom_id).collect();
    let unshown: Vec<Uuid> = entry
        .chosen_atom_ids
        .iter()
        .copied()
        .filter(|a| !shown.contains(a))
        .collect();
    if !unshown.is_empty() {
        return Some(format!(
            "chosen atoms {unshown:?} are not among the atoms the entry lists"
        ));
    }
    if entry.chosen_atom_ids.contains(&entry.source_id) || shown.contains(&entry.source_id) {
        return Some("the source claim is listed as one of the atoms".to_string());
    }
    None
}

/// The conflict relationships a retarget may carry, lower-case. Available
/// without the `db` feature; equal to
/// `epigraph_db::repos::decomposition_priority::CONFLICT_RELATIONSHIPS`
/// (pinned by a `db`-feature unit test).
pub const CONFLICT_RELATIONSHIPS: [&str; 2] = ["contradicts", "refutes"];

/// Ask the LLM about every item, in batches of `batch_size`. Writes nothing.
pub async fn plan_retarget(
    items: &[RetargetItem],
    llm: &dyn epigraph_interfaces::LlmProvider,
    batch_size: usize,
) -> Vec<RetargetPlanEntry> {
    let mut out = Vec::with_capacity(items.len());
    for chunk in items.chunks(batch_size.max(1)) {
        let indexed: Vec<(usize, &RetargetItem)> = chunk.iter().enumerate().collect();
        let prompt = build_retarget_prompt(&indexed);
        let counts: Vec<usize> = chunk.iter().map(|i| i.atoms.len()).collect();
        let answers = match llm.complete_json(&prompt).await {
            Ok(v) => Ok(parse_retarget_response(&v.to_string(), &counts)),
            Err(e) => Err(e.to_string()),
        };
        for (i, item) in chunk.iter().enumerate() {
            let (verdict, reason, chosen) = match &answers {
                Err(e) => (verdict::LLM_ERROR, Some(e.clone()), vec![]),
                Ok(map) => match map.get(&i) {
                    None => (verdict::NO_ANSWER, None, vec![]),
                    Some(Err(why)) => (verdict::MALFORMED, Some(why.clone()), vec![]),
                    Some(Ok(RetargetVerdict::Whole)) => (verdict::WHOLE, None, vec![]),
                    Some(Ok(RetargetVerdict::Unclear)) => (verdict::UNCLEAR, None, vec![]),
                    Some(Ok(RetargetVerdict::Atoms(ix))) => (
                        verdict::ATOMS,
                        None,
                        ix.iter().map(|&k| item.atoms[k].0).collect(),
                    ),
                },
            };
            out.push(RetargetPlanEntry {
                kind: RetargetPlanEntry::KIND.to_string(),
                edge_id: item.edge_id,
                relationship: item.relationship.clone(),
                source_id: item.source_id,
                parent_id: item.parent_id,
                atoms: item
                    .atoms
                    .iter()
                    .enumerate()
                    .map(|(index, (atom_id, _))| AtomRef {
                        index,
                        atom_id: *atom_id,
                    })
                    .collect(),
                verdict: verdict.to_string(),
                reason,
                chosen_atom_ids: chosen,
                model: llm.model_name().to_string(),
            });
        }
    }
    out
}

/// Append `lines` (any serializable values) to `path` as JSONL, creating it.
///
/// # Errors
/// I/O or serialization failure.
pub fn append_jsonl<T: Serialize>(
    path: &std::path::Path,
    lines: &[T],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut w = std::io::BufWriter::new(f);
    for l in lines {
        serde_json::to_writer(&mut w, l)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

/// Read the `retarget_plan` lines of a manifest, ignoring `retarget_applied`
/// lines. Any other line is an error and the whole file is refused.
///
/// # Errors
/// I/O failure or a line that is neither kind.
pub fn read_retarget_manifest(
    path: &std::path::Path,
) -> Result<Vec<RetargetPlanEntry>, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: not JSON: {e}", path.display(), n + 1))?;
        match v.get("kind").and_then(Value::as_str) {
            Some(RetargetPlanEntry::KIND) => out.push(serde_json::from_value(v).map_err(|e| {
                format!("{}:{}: bad retarget_plan line: {e}", path.display(), n + 1)
            })?),
            Some(AppliedEntry::KIND) => {}
            other => {
                return Err(format!(
                    "{}:{}: kind {other:?} is not a retarget manifest line",
                    path.display(),
                    n + 1
                )
                .into())
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "db")]
pub use db::{
    apply_entry, apply_retarget, existing_atom_edges, load_retarget_items, plan_with_resume,
    run_retarget, EdgeApiClient, RetargetOptions, RetargetRun,
};

/// `model` of a plan entry resumed from existing atom edges (no LLM call).
pub const RESUMED_MODEL: &str = "resumed";
/// `reason` of a plan entry resumed from existing atom edges.
pub const RESUMED_REASON: &str =
    "resumed from atom edges an earlier run created from this parent edge; no LLM call";

/// Conflict relationships that are one fact in either orientation (MCP
/// `link_epistemic`'s `SYMMETRIC_RELATIONSHIPS` holds `contradicts` and
/// `corroborates`; only `contradicts` is a conflict). `refutes` is directional.
pub const SYMMETRIC_RELATIONSHIPS: [&str; 1] = ["contradicts"];

#[cfg(feature = "db")]
mod db {
    use super::{AppliedEntry, RetargetItem, RetargetPlanEntry};
    use epigraph_db::repos::decomposition_priority::DecompositionPriorityRepository as R;
    use epigraph_db::MassFunctionRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    /// Load every retarget candidate: in-force contradicts/refutes edges onto
    /// a decomposed parent, with the parent's current atoms. `include_marked`
    /// re-plans edges that already carry `retargeted_to` (off by default: it
    /// is the first idempotency guard). Edges whose parent has no current
    /// atom are never returned.
    ///
    /// # Errors
    /// Database failure.
    pub async fn load_retarget_items(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        include_marked: bool,
        limit: usize,
    ) -> Result<Vec<RetargetItem>, Box<dyn std::error::Error>> {
        const PAGE: i64 = 500;
        let mut edges = Vec::new();
        let mut offset = 0i64;
        while edges.len() < limit {
            let page =
                R::list_parent_conflict_edges(pool, viewer, include_marked, PAGE, offset).await?;
            let n = page.len();
            offset += n as i64;
            edges.extend(page);
            if (n as i64) < PAGE {
                break;
            }
        }
        edges.truncate(limit);
        let mut parents: Vec<Uuid> = edges.iter().map(|e| e.parent_id).collect();
        parents.sort_unstable();
        parents.dedup();
        let mut atoms_by_parent: std::collections::HashMap<Uuid, Vec<(Uuid, String)>> =
            std::collections::HashMap::new();
        for chunk in parents.chunks(1000) {
            for a in R::list_current_atoms(pool, viewer, chunk).await? {
                atoms_by_parent
                    .entry(a.parent_id)
                    .or_default()
                    .push((a.atom_id, a.content));
            }
        }
        Ok(edges
            .into_iter()
            .filter_map(|e| {
                let atoms = atoms_by_parent.get(&e.parent_id)?.clone();
                // An atom that IS the source (a claim contradicting its own
                // parent's decomposition) cannot be a retarget destination:
                // source→source is a self-loop the API refuses.
                let atoms: Vec<_> = atoms
                    .into_iter()
                    .filter(|(id, _)| *id != e.source_id)
                    .collect();
                if atoms.is_empty() {
                    return None;
                }
                Some(RetargetItem {
                    edge_id: e.edge_id,
                    relationship: e.relationship,
                    source_id: e.source_id,
                    source_content: e.source_content,
                    parent_id: e.parent_id,
                    atoms,
                })
            })
            .collect())
    }

    /// Thin client for the two API routes the retarget pass writes through.
    #[derive(Clone)]
    pub struct EdgeApiClient {
        pub http: reqwest::Client,
        /// e.g. `http://127.0.0.1:8080`, no trailing slash needed.
        pub api_base: String,
        pub token: String,
    }

    impl EdgeApiClient {
        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.api_base.trim_end_matches('/'))
        }

        /// `POST /api/v1/edges` with `if_not_exists: true`. Returns the edge id
        /// and whether the API created it (201) or returned an existing one (200).
        ///
        /// # Errors
        /// Transport failure or a non-2xx response.
        pub async fn create_edge(
            &self,
            source_id: Uuid,
            target_id: Uuid,
            relationship: &str,
            properties: serde_json::Value,
        ) -> Result<(Uuid, bool), Box<dyn std::error::Error>> {
            let url = self.url("/api/v1/edges");
            let resp = self
                .http
                .post(&url)
                .bearer_auth(&self.token)
                .json(&serde_json::json!({
                    "source_id": source_id,
                    "target_id": target_id,
                    "source_type": "claim",
                    "target_type": "claim",
                    "relationship": relationship,
                    "properties": properties,
                    "if_not_exists": true,
                }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("POST {url} -> HTTP {status}: {body}").into());
            }
            let v: serde_json::Value = resp.json().await?;
            let id = v
                .get("id")
                .and_then(|x| x.as_str())
                .ok_or("edge create returned no id")?;
            Ok((Uuid::parse_str(id)?, status == reqwest::StatusCode::CREATED))
        }

        /// `PATCH /api/v1/edges/:id` with a shallow-merged `properties` object.
        ///
        /// # Errors
        /// Transport failure or a non-2xx response.
        pub async fn patch_edge_properties(
            &self,
            edge_id: Uuid,
            properties: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let url = self.url(&format!("/api/v1/edges/{edge_id}"));
            let resp = self
                .http
                .patch(&url)
                .bearer_auth(&self.token)
                .json(&serde_json::json!({ "properties": properties }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("PATCH {url} -> HTTP {status}: {body}").into());
            }
            Ok(())
        }
    }

    /// Every existing `source -rel- atom` edge the pre-create check must see,
    /// live and retired. For a symmetric relationship
    /// ([`super::SYMMETRIC_RELATIONSHIPS`]) both orientations count, because
    /// `atom -contradicts-> source` is the same dispute as
    /// `source -contradicts-> atom` and creating the second would add a
    /// duplicate row and a second BBA. For a directional one (`refutes`) only
    /// `source -> atom` counts.
    ///
    /// # Errors
    /// Database failure.
    pub async fn existing_atom_edges(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        source_id: Uuid,
        atom_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<epigraph_db::repos::decomposition_priority::TripleEdge>, epigraph_db::DbError>
    {
        let rel = relationship.to_ascii_lowercase();
        if super::SYMMETRIC_RELATIONSHIPS.contains(&rel.as_str()) {
            R::find_edges_either_direction(pool, viewer, source_id, atom_id, relationship).await
        } else {
            R::find_edges_by_triple(pool, viewer, source_id, atom_id, relationship).await
        }
    }

    /// Apply one `atoms` plan entry. Entries of any other verdict are returned
    /// untouched as `None`.
    ///
    /// Re-validates against the live graph first: the parent edge must still
    /// be in force, and every chosen atom must still be a current atom of the
    /// parent. A stale entry is reported in `errors` and nothing is written.
    ///
    /// # Errors
    /// Database failure. API failures are recorded in the entry's `errors`
    /// and do not abort the run.
    pub async fn apply_entry(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        api: &EdgeApiClient,
        entry: &RetargetPlanEntry,
    ) -> Result<Option<AppliedEntry>, Box<dyn std::error::Error>> {
        if entry.verdict != super::verdict::ATOMS || entry.chosen_atom_ids.is_empty() {
            return Ok(None);
        }
        let mut applied = AppliedEntry {
            kind: AppliedEntry::KIND.to_string(),
            edge_id: entry.edge_id,
            ..Default::default()
        };
        if let Some(why) = super::hold_reason(&entry.relationship) {
            applied.held = true;
            applied.errors.push(why);
            return Ok(Some(applied));
        }
        // A manifest is a file an operator can edit: nothing in it is trusted
        // beyond what the live graph confirms below.
        if let Some(why) = super::entry_shape_error(entry) {
            applied.errors.push(format!("{why}; nothing applied"));
            return Ok(Some(applied));
        }
        // Both endpoints of the conflict must still be current: a claim
        // retired between the reviewed dry run and the apply must not gain a
        // conflict edge, and a retired parent's atoms are not its dispute.
        if !epigraph_db::ClaimRepository::are_all_current(
            pool,
            viewer,
            &[entry.source_id, entry.parent_id],
        )
        .await?
        {
            applied.errors.push(
                "source or parent claim is no longer current (or not visible); nothing applied"
                    .into(),
            );
            return Ok(Some(applied));
        }

        // The parent edge as it is NOW.
        let parent_edge = R::find_edges_by_triple(
            pool,
            viewer,
            entry.source_id,
            entry.parent_id,
            &entry.relationship,
        )
        .await?
        .into_iter()
        .find(|e| e.id == entry.edge_id);
        let Some(parent_edge) = parent_edge.filter(|e| e.in_force) else {
            applied
                .errors
                .push("parent edge is gone or no longer in force; nothing applied".into());
            return Ok(Some(applied));
        };
        let live_atoms: std::collections::HashSet<Uuid> =
            R::list_current_atoms(pool, viewer, &[entry.parent_id])
                .await?
                .into_iter()
                .map(|a| a.atom_id)
                .collect();
        let stale: Vec<Uuid> = entry
            .chosen_atom_ids
            .iter()
            .copied()
            .filter(|a| !live_atoms.contains(a))
            .collect();
        if !stale.is_empty() {
            applied.errors.push(format!(
                "chosen atoms {stale:?} are no longer current atoms of the parent; nothing applied"
            ));
            return Ok(Some(applied));
        }

        let sent_relationship = super::api_relationship(&entry.relationship);
        // Live edges this run ADOPTED rather than created, that `POST
        // if_not_exists` would find again: same orientation, same stored
        // spelling (the API's dedup matches the relationship byte-exactly, so
        // re-asserting any other spelling would create a second row).
        let mut reassertable: Vec<(Uuid, Uuid)> = Vec::new();
        // From here on an entry may already have written something, so a
        // database error is RECORDED on the entry (keeping the ids created so
        // far in the manifest) rather than propagated with `?`.
        for &atom in &entry.chosen_atom_ids {
            let matches =
                match existing_atom_edges(pool, viewer, entry.source_id, atom, &entry.relationship)
                    .await
                {
                    Ok(m) => m,
                    Err(e) => {
                        applied.errors.push(format!(
                            "database: looking up existing edges to {atom}: {e}; \
                         this and later atoms not applied"
                        ));
                        break;
                    }
                };
            if let Some(live) = matches.iter().find(|e| e.in_force) {
                applied.existing_edge_ids.push(live.id);
                if live.source_id == entry.source_id && live.relationship == sent_relationship {
                    reassertable.push((live.id, atom));
                }
                continue;
            }
            if !matches.is_empty() {
                applied.blocked_by_retired_edge.push(atom);
                continue;
            }
            match api
                .create_edge(
                    entry.source_id,
                    atom,
                    &sent_relationship,
                    retarget_edge_properties(entry),
                )
                .await
            {
                Ok((id, true)) => applied.created_edge_ids.push(id),
                Ok((id, false)) => applied.existing_edge_ids.push(id),
                Err(e) => applied.errors.push(format!("create {atom}: {e}")),
            }
        }

        // Re-assert adopted edges that carry no BBA yet. The API's dedup-hit
        // path re-runs the DS auto-wire (`trigger_edge_ds_recomputation` is
        // outside its `was_created` block), so an edge whose source has since
        // acquired belief wires now; an already-wired edge is never re-sent.
        for (id, atom) in reassertable {
            match MassFunctionRepository::exists_for_perspective(pool, viewer, id).await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    applied.errors.push(format!(
                        "database: BBA check for {id}: {e}; not re-asserted"
                    ));
                    continue;
                }
            }
            match api
                .create_edge(
                    entry.source_id,
                    atom,
                    &sent_relationship,
                    retarget_edge_properties(entry),
                )
                .await
            {
                Ok((got, _)) if got == id => applied.reasserted_edge_ids.push(id),
                Ok((got, _)) => applied.errors.push(format!(
                    "re-assert {atom}: API returned edge {got}, expected {id}"
                )),
                Err(e) => applied.errors.push(format!("re-assert {atom}: {e}")),
            }
        }

        let resolved: Vec<Uuid> = applied
            .created_edge_ids
            .iter()
            .chain(applied.existing_edge_ids.iter())
            .copied()
            .collect();
        for &id in &resolved {
            // A failed check counts as unwired: that keeps the edge open for
            // the next run instead of marking it done on no evidence.
            match MassFunctionRepository::exists_for_perspective(pool, viewer, id).await {
                Ok(true) => applied.ds_wired_edge_ids.push(id),
                Ok(false) => {}
                Err(e) => applied
                    .errors
                    .push(format!("database: BBA check for {id}: {e}")),
            }
        }
        let unwired: Vec<Uuid> = resolved
            .iter()
            .copied()
            .filter(|id| !applied.ds_wired_edge_ids.contains(id))
            .collect();

        // Mark the parent. PATCH merges shallowly (`||`), so a second patch
        // would REPLACE the array: always write the union of what is already
        // recorded and what this run resolved.
        //
        // `retarget_unwired` lists the resolved atom edges with no BBA. While
        // it is non-empty the parent edge is NOT treated as done:
        // `load_retarget_items` returns it again, the next run resumes it from
        // its existing atom edges (no LLM call) and re-asserts them, and only
        // an empty list lets the mark stand on its own.
        let mut union: Vec<Uuid> = parent_edge
            .properties
            .get("retargeted_to")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                    .collect()
            })
            .unwrap_or_default();
        let before = union.clone();
        for id in &resolved {
            if !union.contains(id) {
                union.push(*id);
            }
        }
        if union.is_empty() {
            // Nothing resolved (all blocked or failed): leave the parent as is.
            return Ok(Some(applied));
        }
        let unwired_json = serde_json::json!(unwired);
        if union == before && parent_edge.properties.get("retarget_unwired") == Some(&unwired_json)
        {
            applied.parent_marked = true;
            return Ok(Some(applied));
        }
        let mut mark = serde_json::json!({
            "retargeted_to": union,
            "retarget_unwired": unwired_json,
            "retarget_method": "llm-retarget",
        });
        // A resumed entry carries no model of its own: keep the one that
        // chose the atoms.
        if entry.model != super::RESUMED_MODEL {
            mark["retarget_model"] = serde_json::json!(entry.model);
        }
        match api.patch_edge_properties(entry.edge_id, mark).await {
            Ok(()) => applied.parent_marked = true,
            Err(e) => applied.errors.push(format!("mark parent: {e}")),
        }
        Ok(Some(applied))
    }

    /// Provenance carried by every atom edge a retarget creates.
    fn retarget_edge_properties(entry: &RetargetPlanEntry) -> serde_json::Value {
        serde_json::json!({
            "retargeted_from_edge": entry.edge_id,
            "from_parent": entry.parent_id,
            "method": "llm-retarget",
            "model": entry.model,
        })
    }

    /// Plan `items`: an edge that an earlier run already retargeted (atom
    /// edges carrying `retargeted_from_edge = <this edge>` exist, in force,
    /// onto current atoms of the parent) is RESUMED from those atoms with no
    /// LLM call; every other edge is asked of the LLM ([`super::plan_retarget`]).
    ///
    /// Resuming instead of re-asking is what makes a partial run (a lost
    /// PATCH, an unwired atom edge) safe to repeat: a second LLM answer could
    /// name a different atom and add a second source→atom edge the first mark
    /// never recorded. Output order is `items` order.
    ///
    /// # Errors
    /// Database failure.
    pub async fn plan_with_resume(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        items: &[RetargetItem],
        llm: &dyn epigraph_interfaces::LlmProvider,
        batch_size: usize,
    ) -> Result<Vec<RetargetPlanEntry>, Box<dyn std::error::Error>> {
        let mut children: std::collections::HashMap<Uuid, Vec<Uuid>> =
            std::collections::HashMap::new();
        let keys: Vec<(Uuid, Uuid)> = items.iter().map(|i| (i.edge_id, i.source_id)).collect();
        for chunk in keys.chunks(1000) {
            for c in R::list_retargeted_children(pool, viewer, chunk).await? {
                if c.in_force {
                    children
                        .entry(c.parent_edge_id)
                        .or_default()
                        .push(c.target_id);
                }
            }
        }
        let mut resumed: std::collections::HashMap<Uuid, RetargetPlanEntry> =
            std::collections::HashMap::new();
        let mut ask: Vec<RetargetItem> = Vec::new();
        for item in items {
            let prior = children.get(&item.edge_id);
            // Chosen in the parent's atom numbering order.
            let chosen: Vec<Uuid> = item
                .atoms
                .iter()
                .map(|(id, _)| *id)
                .filter(|id| prior.is_some_and(|p| p.contains(id)))
                .collect();
            if chosen.is_empty() {
                ask.push(item.clone());
                continue;
            }
            resumed.insert(
                item.edge_id,
                RetargetPlanEntry {
                    kind: RetargetPlanEntry::KIND.to_string(),
                    edge_id: item.edge_id,
                    relationship: item.relationship.clone(),
                    source_id: item.source_id,
                    parent_id: item.parent_id,
                    atoms: item
                        .atoms
                        .iter()
                        .enumerate()
                        .map(|(index, (atom_id, _))| super::AtomRef {
                            index,
                            atom_id: *atom_id,
                        })
                        .collect(),
                    verdict: super::verdict::ATOMS.to_string(),
                    reason: Some(super::RESUMED_REASON.to_string()),
                    chosen_atom_ids: chosen,
                    model: super::RESUMED_MODEL.to_string(),
                },
            );
        }
        let mut asked: std::collections::HashMap<Uuid, RetargetPlanEntry> = if ask.is_empty() {
            std::collections::HashMap::new()
        } else {
            super::plan_retarget(&ask, llm, batch_size)
                .await
                .into_iter()
                .map(|e| (e.edge_id, e))
                .collect()
        };
        Ok(items
            .iter()
            .filter_map(|i| {
                resumed
                    .remove(&i.edge_id)
                    .or_else(|| asked.remove(&i.edge_id))
            })
            .collect())
    }

    /// What one `--retarget` invocation does, besides the manifest path.
    #[derive(Debug, Clone, Copy)]
    pub struct RetargetOptions {
        pub include_marked: bool,
        pub limit: usize,
        pub batch_size: usize,
        /// `false` (the default in the binary) is the dry run: the LLM is
        /// called and the manifest written, and NOTHING reaches the API.
        pub apply: bool,
    }

    /// The outcome of [`run_retarget`].
    #[derive(Debug, Default)]
    pub struct RetargetRun {
        pub plan: Vec<RetargetPlanEntry>,
        /// Empty on a dry run.
        pub applied: Vec<AppliedEntry>,
    }

    /// The whole `--retarget` / `--retarget --apply` flow, as the binary runs
    /// it: load candidates → (none: return, no LLM call) → plan through the
    /// LLM → append plan lines to `manifest` → if and only if
    /// `opts.apply`, write through `api` and append the applied lines.
    ///
    /// # Errors
    /// Database or manifest I/O failure; `opts.apply` without an `api`.
    pub async fn run_retarget(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        llm: &dyn epigraph_interfaces::LlmProvider,
        api: Option<&EdgeApiClient>,
        manifest: &std::path::Path,
        opts: RetargetOptions,
    ) -> Result<RetargetRun, Box<dyn std::error::Error>> {
        let items = load_retarget_items(pool, viewer, opts.include_marked, opts.limit).await?;
        if items.is_empty() {
            return Ok(RetargetRun::default());
        }
        let plan = plan_with_resume(pool, viewer, &items, llm, opts.batch_size).await?;
        super::append_jsonl(manifest, &plan)?;
        if !opts.apply {
            return Ok(RetargetRun {
                plan,
                applied: vec![],
            });
        }
        let api = api.ok_or("retarget apply requires an API client")?;
        let applied = apply_retarget(pool, viewer, api, &plan, Some(manifest)).await?;
        Ok(RetargetRun { plan, applied })
    }

    /// Apply every `atoms` entry in `plan`, in order.
    ///
    /// Each [`AppliedEntry`] is appended to `manifest` (when given) AS SOON AS
    /// its entry finishes, so edges already created are on record even if the
    /// run dies later (killed, an API that stops answering). A database error
    /// while applying one entry is recorded in that entry's `errors` and the
    /// run moves on to the next entry; a re-run adopts whatever was written.
    ///
    /// # Errors
    /// Manifest I/O failure only.
    pub async fn apply_retarget(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        api: &EdgeApiClient,
        plan: &[RetargetPlanEntry],
        manifest: Option<&std::path::Path>,
    ) -> Result<Vec<AppliedEntry>, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        for entry in plan {
            let applied = match apply_entry(pool, viewer, api, entry).await {
                Ok(Some(a)) => a,
                Ok(None) => continue,
                Err(e) => AppliedEntry {
                    kind: AppliedEntry::KIND.to_string(),
                    edge_id: entry.edge_id,
                    errors: vec![format!(
                        "database: {e}; entry not applied (re-run to resume it)"
                    )],
                    ..Default::default()
                },
            };
            if let Some(m) = manifest {
                super::append_jsonl(m, std::slice::from_ref(&applied))?;
            }
            out.push(applied);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(src: &str, atoms: &[&str]) -> RetargetItem {
        RetargetItem {
            edge_id: Uuid::new_v4(),
            relationship: "contradicts".into(),
            source_id: Uuid::new_v4(),
            source_content: src.into(),
            parent_id: Uuid::new_v4(),
            atoms: atoms
                .iter()
                .map(|a| (Uuid::new_v4(), a.to_string()))
                .collect(),
        }
    }

    #[cfg(feature = "db")]
    #[test]
    fn conflict_relationships_match_the_repo_layer() {
        assert_eq!(
            CONFLICT_RELATIONSHIPS,
            epigraph_db::repos::decomposition_priority::CONFLICT_RELATIONSHIPS
        );
    }

    fn plan_entry(chosen: Vec<Uuid>, atoms: Vec<Uuid>, rel: &str) -> RetargetPlanEntry {
        RetargetPlanEntry {
            kind: RetargetPlanEntry::KIND.into(),
            edge_id: Uuid::new_v4(),
            relationship: rel.into(),
            source_id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            atoms: atoms
                .into_iter()
                .enumerate()
                .map(|(index, atom_id)| AtomRef { index, atom_id })
                .collect(),
            verdict: verdict::ATOMS.into(),
            reason: None,
            chosen_atom_ids: chosen,
            model: "fixture".into(),
        }
    }

    #[test]
    fn entry_shape_refuses_what_a_hand_edited_manifest_can_say() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(
            entry_shape_error(&plan_entry(vec![a], vec![a, b], "refutes")),
            None
        );
        assert_eq!(
            entry_shape_error(&plan_entry(vec![a], vec![a, b], "REFUTES")),
            None
        );
        // A non-conflict relationship.
        assert!(entry_shape_error(&plan_entry(vec![a], vec![a, b], "supports")).is_some());
        // A chosen atom the entry never showed the model.
        assert!(
            entry_shape_error(&plan_entry(vec![Uuid::new_v4()], vec![a, b], "refutes")).is_some()
        );
        // Not an atoms verdict.
        let mut whole = plan_entry(vec![a], vec![a, b], "refutes");
        whole.verdict = verdict::WHOLE.into();
        assert!(entry_shape_error(&whole).is_some());
        // The source listed as an atom.
        let mut selfish = plan_entry(vec![a], vec![a, b], "refutes");
        selfish.source_id = a;
        assert!(entry_shape_error(&selfish).is_some());
    }

    #[test]
    fn contradicts_is_held_in_every_spelling_and_refutes_is_not() {
        for s in ["contradicts", "CONTRADICTS", "Contradicts"] {
            assert!(hold_reason(s).is_some(), "{s} must be held");
        }
        for s in ["refutes", "REFUTES"] {
            assert!(hold_reason(s).is_none(), "{s} must not be held");
        }
    }

    #[test]
    fn api_relationship_sends_the_lower_case_conflict_spelling() {
        assert_eq!(api_relationship("REFUTES"), "refutes");
        assert_eq!(api_relationship("refutes"), "refutes");
        assert_eq!(api_relationship("CONTRADICTS"), "contradicts");
        assert_eq!(api_relationship("supports"), "supports");
    }

    #[test]
    fn parses_atoms_whole_and_unclear() {
        let raw = r#"{"0": {"atoms": [2, 0]}, "1": "whole", "2": "UNCLEAR "}"#;
        let out = parse_retarget_response(raw, &[3, 2, 2]);
        assert_eq!(out[&0], Ok(RetargetVerdict::Atoms(vec![0, 2])), "sorted");
        assert_eq!(out[&1], Ok(RetargetVerdict::Whole));
        assert_eq!(out[&2], Ok(RetargetVerdict::Unclear));
    }

    #[test]
    fn out_of_range_atom_index_rejects_the_whole_answer() {
        // Index 2 on a two-atom item: the valid 0 must NOT be kept either —
        // a partly-hallucinated answer is not trusted in part.
        let out = parse_retarget_response(r#"{"0": {"atoms": [0, 2]}}"#, &[2]);
        let err = out[&0].as_ref().unwrap_err();
        assert!(err.contains("out of range"), "{err}");
    }

    #[test]
    fn malformed_atom_lists_are_rejected() {
        let counts = [3; 7];
        let raw = r#"{
            "0": {"atoms": []},
            "1": {"atoms": [1, 1]},
            "2": {"atoms": ["1"]},
            "3": {"atoms": [-1]},
            "4": {"atoms": [1.5]},
            "5": {"atoms": [1], "why": "because"},
            "6": {"picks": [1]}
        }"#;
        let out = parse_retarget_response(raw, &counts);
        for i in 0..7 {
            assert!(out[&i].is_err(), "item {i} must be rejected: {:?}", out[&i]);
        }
    }

    #[test]
    fn unknown_strings_and_shapes_are_rejected() {
        let raw = r#"{"0": "partial", "1": 1, "2": null, "3": [0], "4": true}"#;
        let out = parse_retarget_response(raw, &[2; 5]);
        for i in 0..5 {
            assert!(out[&i].is_err(), "item {i}: {:?}", out[&i]);
        }
    }

    #[test]
    fn item_indices_outside_the_batch_are_ignored_not_misapplied() {
        let out =
            parse_retarget_response(r#"{"0": "whole", "5": {"atoms": [0]}, "x": "whole"}"#, &[2]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[&0], Ok(RetargetVerdict::Whole));
    }

    #[test]
    fn non_object_or_garbage_response_yields_nothing() {
        assert!(parse_retarget_response("not json", &[2]).is_empty());
        assert!(parse_retarget_response("[1,2]", &[2]).is_empty());
        assert!(parse_retarget_response("{ broken", &[2]).is_empty());
        assert!(parse_retarget_response("", &[2]).is_empty());
    }

    #[test]
    fn fenced_response_with_prose_is_recovered() {
        let raw = "Sure:\n```json\n{\"0\": {\"atoms\": [1]}}\n```\n";
        let out = parse_retarget_response(raw, &[2]);
        assert_eq!(out[&0], Ok(RetargetVerdict::Atoms(vec![1])));
    }

    #[test]
    fn prompt_has_exactly_one_bracket_line_per_item_with_collapsed_text() {
        let a = item(
            "Light does\nnot bend.",
            &["Gravity bends light", "Time\ndilates"],
        );
        let b = item("Other source", &["x", "y", "z"]);
        let p = build_retarget_prompt(&[(0, &a), (1, &b)]);
        let bracket_lines: Vec<&str> = p.lines().filter(|l| l.starts_with('[')).collect();
        assert_eq!(
            bracket_lines,
            vec!["[0] Light does not bend.", "[1] Other source"]
        );
        assert!(p.contains("    atom 1: Time dilates"));
        assert!(p.contains("    atom 2: z"));
    }

    #[tokio::test]
    async fn plan_maps_indices_to_atom_ids_and_labels_every_edge() {
        let items = vec![
            item("src A", &["a0", "a1"]),
            item("src B", &["b0", "b1"]),
            item("src C", &["c0", "c1"]),
            item("src D", &["d0", "d1"]),
        ];
        let llm = crate::enrichment::llm_client::FixtureLlmClient::from_json(&serde_json::json!({
            "src A": {"atoms": [1]},
            "src B": "whole",
            "src C": {"atoms": [9]},
        }))
        .unwrap();
        let plan = plan_retarget(&items, &llm, 10).await;
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].verdict, verdict::ATOMS);
        assert_eq!(plan[0].chosen_atom_ids, vec![items[0].atoms[1].0]);
        assert_eq!(plan[1].verdict, verdict::WHOLE);
        assert!(plan[1].chosen_atom_ids.is_empty());
        assert_eq!(plan[2].verdict, verdict::MALFORMED);
        assert!(
            plan[2].chosen_atom_ids.is_empty(),
            "malformed takes no action"
        );
        assert_eq!(plan[3].verdict, verdict::NO_ANSWER);
        assert_eq!(llm.call_count(), 1, "one batch, one call");
    }

    #[test]
    fn manifest_reader_skips_applied_lines_and_refuses_foreign_kinds() {
        let dir = std::env::temp_dir().join(format!("retarget-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.jsonl");
        let entry = RetargetPlanEntry {
            kind: RetargetPlanEntry::KIND.into(),
            edge_id: Uuid::new_v4(),
            relationship: "contradicts".into(),
            source_id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            atoms: vec![],
            verdict: verdict::WHOLE.into(),
            reason: None,
            chosen_atom_ids: vec![],
            model: "fixture".into(),
        };
        append_jsonl(&path, std::slice::from_ref(&entry)).unwrap();
        append_jsonl(
            &path,
            &[AppliedEntry {
                kind: AppliedEntry::KIND.into(),
                edge_id: entry.edge_id,
                ..Default::default()
            }],
        )
        .unwrap();
        assert_eq!(read_retarget_manifest(&path).unwrap(), vec![entry]);
        append_jsonl(&path, &[serde_json::json!({"kind": "decomposition"})]).unwrap();
        assert!(read_retarget_manifest(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
