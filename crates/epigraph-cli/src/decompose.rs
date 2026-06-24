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

fn strip_code_fence(raw: &str) -> String {
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
pub use db_writes::{persist_decomposition, PersistOutcome};

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
        if !ClaimRepository::are_all_current(pool, &[parent_id]).await? {
            return Err(format!("parent claim {parent_id} is not current").into());
        }
        let mut atom_ids = Vec::with_capacity(decomp.atoms.len());
        let mut edges = 0usize;
        for (i, atom) in decomp.atoms.iter().enumerate() {
            let gen = decomp.generality.get(i).copied().unwrap_or(-1);
            let atom_id = submit_via(atom.clone(), gen).await?;
            // Best-effort embed-on-write when the caller passes a live embedder
            // and the submit path did not already embed (API path embeds; the
            // direct-insert test fake does not).
            if let Some(ref e) = embedder {
                if let Ok(vec) = e.generate(atom).await {
                    let _ = e.store(atom_id, &vec).await;
                }
            }
            let (_row, was_created) = EdgeRepository::create_if_not_exists(
                pool,
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
            atom_ids.push(atom_id);
        }
        Ok(PersistOutcome {
            atom_claim_ids: atom_ids,
            edges_created: edges,
            skipped_singletons: 0,
        })
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
