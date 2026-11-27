//! Document hierarchy walker. Reads a `DocumentExtraction` and produces an
//! `IngestPlan` of claims + edges + path index.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::common::edges::{decomposes_edge, thesis_derivation_str};
use crate::common::ids::{
    compound_claim_id, compound_content_hash, content_hash, scoped_atom_content_hash,
    scoped_atom_id, scoped_seed, ID_SCOPE_KEY, ID_SCOPE_OWNER_GROUP,
};
use crate::common::paths::normalize_claim_path;
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::document::schema::{ByteSpan, DocumentExtraction, Paragraph, SourceType};
use crate::workflow::builder::{CONTENT_HASH_SCOPE_CANONICAL_NAME, CONTENT_HASH_SCOPE_KEY};

const fn source_type_str(st: &SourceType) -> &'static str {
    match st {
        SourceType::Paper => "Paper",
        SourceType::Textbook => "Textbook",
        SourceType::InternalDocument => "InternalDocument",
        SourceType::Report => "Report",
        SourceType::Transcript => "Transcript",
        SourceType::Legal => "Legal",
        SourceType::Tabular => "Tabular",
    }
}

/// Every value [`source_type_str`] can emit — i.e. the `properties.source_type`
/// stamp that marks a persisted row as DOCUMENT ingest output.
///
/// Deliberately not "anything that is not `workflow`": `ClaimRepository::
/// evolve_step` writes `properties = {"level": n, "step_lineage_id": …}` with no
/// `source_type` at all, and those rows bind the plain content hash.
/// Spelled through [`source_type_str`] so the mapping has exactly one
/// definition; `every_source_type_stamp_is_listed` holds the other end of the
/// drift guard with an exhaustive `match` that stops compiling when a
/// [`SourceType`] variant is added.
pub const DOCUMENT_SOURCE_TYPES: [&str; 7] = [
    source_type_str(&SourceType::Paper),
    source_type_str(&SourceType::Textbook),
    source_type_str(&SourceType::InternalDocument),
    source_type_str(&SourceType::Report),
    source_type_str(&SourceType::Transcript),
    source_type_str(&SourceType::Legal),
    source_type_str(&SourceType::Tabular),
];

/// The `properties.source_type` stamp of workflow ingest output
/// (`workflow::build_ingest_plan`, `epigraph_ingest_executor::add_step`).
const WORKFLOW_SOURCE_TYPE: &str = "workflow";

/// Whether a persisted claim's `properties` identify it as a row whose
/// `claims.content_hash` is a [`compound_content_hash`] — a digest that is NOT
/// `blake3(content)` and CANNOT be re-derived from the claim alone.
///
/// # Why a reader needs this
///
/// `build_ingest_plan` binds `compound_content_hash(blake3(text),
/// artifact_seed)` on every level-0/1/2 node (see the `content_hash` field doc
/// on [`PlannedClaim`](crate::common::plan::PlannedClaim)), so that migration
/// 013's `UNIQUE (content_hash, agent_id)` cannot collapse two documents'
/// "Introduction" rows. A reader that recomputes `blake3(content)` and compares
/// it to the stored digest therefore gets a disagreement on every *untampered*
/// structural row of every ingested document. That disagreement is not
/// evidence of tampering and must not be reported as such — MCP `verify_claim`
/// routes on this predicate to answer "not applicable" instead for document
/// rows, and to re-derive the digest for the workflow subset (see below).
///
/// The WORKFLOW builder (`workflow::build_ingest_plan`) and
/// `epigraph_ingest_executor::add_step` do the same on their level-0/1/2 nodes
/// with seed `canonical_name` (backlog 6178a205). A workflow row is in the
/// class only when it carries the scope marker those writers stamp
/// (`properties[CONTENT_HASH_SCOPE_KEY] == CONTENT_HASH_SCOPE_CANONICAL_NAME`,
/// see `workflow::builder`) — NOT by its `source_type` alone. Workflow rows
/// written before that change share the `{level 0-2, source_type: "workflow"}`
/// stamp but keep the PLAIN digest, so for them a body/digest disagreement IS
/// evidence of tampering: unmarked, they fall outside the class and
/// `verify_claim` still reports `mismatch` (and `match` when untampered,
/// because it compares before it classifies).
///
/// # What it deliberately does NOT do
///
/// It does not attempt to re-derive the stored digest. For DOCUMENT rows the
/// artifact seed is `"{document title}\u{1f}{path}"`, which is not carried on
/// the claim row, so recomputation would have to guess it — and a guessed seed
/// that happened to match would manufacture exactly the false confidence this
/// predicate exists to remove. The honest answer for that class is
/// "undecided", not "verified".
///
/// WORKFLOW rows differ: their seed is the `canonical_name` of the workflow
/// that executes the row, which is recovered from the `executes` edge, not
/// guessed. [`stored_content_hash_is_canonical_name_scoped`] picks them out so
/// `verify_claim` can re-derive their digest and report `match` / `mismatch`;
/// only a marked row with no executing workflow stays undecided.
///
/// # Class predicate, not a security boundary
///
/// The inputs are `claims.properties`, and reaching them does NOT require
/// database access: `ClaimRepository::patch_claim_atomic_conn` merges
/// caller-supplied properties with `properties = COALESCE(properties,'{}') || $1`,
/// reachable from MCP `patch_claim` and HTTP `PATCH /claims/:id`. A caller with
/// patch rights can therefore add `{"level":0,"source_type":"Paper"}` to a
/// plain-hash claim and turn a future `mismatch` verdict into `not_applicable`.
/// The workflow stamp plus its scope marker does the same only on a claim no
/// visible workflow executes; on one that a workflow does execute,
/// `verify_claim` re-derives the digest from that workflow's `canonical_name`,
/// which a plain digest does not reproduce, and still reports `mismatch`.
///
/// That is a defence-in-depth degradation rather than a bypass, for one specific
/// reason worth stating so a later reader does not have to re-derive it: no API
/// surface can create the mismatch it would be masking. `PatchClaimInput` is
/// only `{trace_id, properties, add_labels, remove_labels}`, and there is no
/// `UPDATE claims SET content` anywhere in the workspace — so the attacker who
/// could produce a body/digest disagreement is one with direct table access, and
/// that attacker can rewrite `content_hash` regardless of this predicate.
/// (`POST /claims` accepting a caller-supplied `content_hash` override is a
/// separate, pre-existing gap — backlog 365bc9f0.)
///
/// Do not read a `true` here as an attestation of anything. It classifies, it
/// does not verify.
///
/// # Scope-derived document atoms
///
/// A level-3 document row is in the class too when it carries the
/// [`ID_SCOPE_KEY`]` = `[`ID_SCOPE_OWNER_GROUP`] marker: a non-public ingest
/// stores `blake3(blake3(text) || owner_group)` on its atoms
/// ([`crate::common::ids::scoped_atom_content_hash`]). An UNMARKED atom keeps
/// the plain digest, so for it a body/digest disagreement is still a
/// mismatch. For a marked atom, [`scoped_atom_hash_matches`] re-derives the
/// digest from the row's current owner, so `verify_claim` reports `match` for
/// an unchanged row instead of `not_applicable`.
#[must_use]
pub fn stored_content_hash_is_seed_scoped(properties: &serde_json::Value) -> bool {
    let is_document = properties
        .get("source_type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|st| DOCUMENT_SOURCE_TYPES.contains(&st));
    // The workflow arm is keyed on the marker, not the stamp alone: see the doc
    // comment above.
    (is_compound_level(properties) && (is_document || is_scoped_workflow(properties)))
        || (is_document && is_scoped_atom(properties))
}

/// Re-derive a scope-derived document atom's stored digest from its body and
/// the group that owns the row NOW: `Some(true)` when
/// `blake3(blake3(content) || owner_group)` is `stored`, `Some(false)` when it
/// is not, and `None` when `properties` is not a scope-derived document atom
/// (the caller then classifies the row as before).
///
/// `Some(false)` is NOT proof of tampering: a row
/// `share_claims_with_team` moved to a team keeps the digest its first owner
/// derived. `verify_claim` therefore reports `match` on `Some(true)` and
/// `not_applicable` otherwise, so an honest row still verifies and only a row
/// whose body or owner changed since it was written loses the check.
#[must_use]
pub fn scoped_atom_hash_matches(
    properties: &serde_json::Value,
    content: &str,
    stored: &[u8; 32],
    owner_group: Uuid,
) -> Option<bool> {
    let is_document = properties
        .get("source_type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|st| DOCUMENT_SOURCE_TYPES.contains(&st));
    if !(is_document && is_scoped_atom(properties)) {
        return None;
    }
    Some(
        crate::common::ids::scoped_atom_content_hash(
            &crate::common::ids::content_hash(content),
            Some(owner_group),
        ) == *stored,
    )
}

/// A level-3 row carrying the scope-derived id marker.
fn is_scoped_atom(properties: &serde_json::Value) -> bool {
    let level = properties.get("level").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    });
    level == Some(3)
        && properties
            .get(ID_SCOPE_KEY)
            .and_then(serde_json::Value::as_str)
            == Some(ID_SCOPE_OWNER_GROUP)
}

/// The workflow subset of [`stored_content_hash_is_seed_scoped`]: a level-0..2
/// row carrying the workflow stamp AND its
/// [`CONTENT_HASH_SCOPE_KEY`]` = `[`CONTENT_HASH_SCOPE_CANONICAL_NAME`] marker,
/// whose stored digest is `compound_content_hash(blake3(content),
/// canonical_name)`.
///
/// Unlike the document class, this seed is RECOVERABLE: the workflow that wrote
/// the row links it with an `executes` edge, so a reader routes this subset to
/// `workflow::builder::canonical_name_scoped_hash_matches` with the executing
/// workflows' `canonical_name`s instead of answering "not applicable". Same
/// caveat as the parent predicate: it classifies, it does not verify.
#[must_use]
pub fn stored_content_hash_is_canonical_name_scoped(properties: &serde_json::Value) -> bool {
    is_compound_level(properties) && is_scoped_workflow(properties)
}

/// `properties.level` in 0..=2. `level` is written as a JSON number by both
/// builders, but every query in the repo reads it through
/// `properties->>'level'` (text), so accept either spelling rather than
/// silently failing the class check on a string.
fn is_compound_level(properties: &serde_json::Value) -> bool {
    let level = properties.get("level").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    });
    matches!(level, Some(0..=2))
}

fn is_scoped_workflow(properties: &serde_json::Value) -> bool {
    properties
        .get("source_type")
        .and_then(serde_json::Value::as_str)
        == Some(WORKFLOW_SOURCE_TYPE)
        && properties
            .get(CONTENT_HASH_SCOPE_KEY)
            .and_then(serde_json::Value::as_str)
            == Some(CONTENT_HASH_SCOPE_CANONICAL_NAME)
}

fn enrichment_from_paragraph(paragraph: &Paragraph) -> serde_json::Value {
    serde_json::json!({
        "instruments_used": paragraph.instruments_used,
        "reagents_involved": paragraph.reagents_involved,
        "conditions": paragraph.conditions,
    })
}

/// The suffix a [`PlannedClaim::supporting_locator`] carries when no byte span
/// into the source reproduces the passage (backlog c083c1c9): a Tier-2
/// extraction with no `source_text`, or a passage the extractor rewrote so it
/// occurs nowhere in `source_text`. A reader of a withheld passage then knows
/// the stored hash pins what was extracted, not a quote they can re-derive.
pub const NOT_SOURCE_VERIFIABLE: &str = "source_verifiable: false";

/// Where `passage` sits in the extraction's `source_text`: the span the
/// extractor supplied when `source_text[start..end]` is exactly `passage`,
/// else the first byte-exact occurrence of `passage` in `source_text`. `None`
/// when there is no `source_text` (Tier 2), even if the extractor supplied a
/// span: nothing has checked that span against the publication
/// (`verify_extraction_verbatim` is a no-op without `source_text`), so it may
/// index the extractor's own text. Also `None` when the passage does not
/// occur in `source_text` verbatim. A returned span always satisfies
/// `source_text[start..end] == passage`, so a reader who holds the source
/// re-derives exactly the bytes the evidence hash covers.
#[must_use]
pub fn locate_passage(
    extraction: &DocumentExtraction,
    passage: &str,
    supplied: Option<&ByteSpan>,
) -> Option<ByteSpan> {
    let source = extraction.source_text.as_deref()?;
    if passage.is_empty() {
        return None;
    }
    if let Some(span) = supplied {
        if source.get(span.start..span.end) == Some(passage) {
            return Some(span.clone());
        }
    }
    source.find(passage).map(|start| ByteSpan {
        start,
        end: start + passage.len(),
    })
}

/// The [`PlannedClaim::supporting_locator`] of a thesis, section or paragraph
/// node: its extraction path, the section title a reader can find in the
/// source (none for the thesis), and then EITHER the byte span into
/// `source_text` ([`locate_passage`]) OR the [`NOT_SOURCE_VERIFIABLE`] flag.
/// Every locator a document plan writes ends in exactly one of the two.
#[must_use]
pub fn passage_locator(path: &str, section_title: Option<&str>, span: Option<&ByteSpan>) -> String {
    let mut locator = match section_title {
        Some(title) => format!("{path} ({title:?})"),
        None => path.to_string(),
    };
    match span {
        Some(span) => locator.push_str(&format!(", bytes {}..{}", span.start, span.end)),
        None => locator.push_str(&format!(", {NOT_SOURCE_VERIFIABLE}")),
    }
    locator
}

/// Tier stamp (§2). Tier 1 (`verbatim_v2`) when the extraction carries
/// `source_text` (so section/paragraph nodes are byte-exact verbatim spans);
/// else Tier 2 (`extracted_v2`, e.g. the Python HTML/CNXML emitters).
fn spine_text_kind(extraction: &DocumentExtraction) -> &'static str {
    if extraction.source_text.is_some() {
        "verbatim_v2"
    } else {
        "extracted_v2"
    }
}

/// Walk a `DocumentExtraction` tree and produce a flat list of operations,
/// with the GLOBAL ids of a public ingest: [`build_ingest_plan_scoped`] with
/// no scope. Every id and stored hash is exactly what it was before ids could
/// be scope-derived.
#[must_use]
pub fn build_ingest_plan(extraction: &DocumentExtraction) -> IngestPlan {
    build_ingest_plan_scoped(extraction, None)
}

/// Mark a scope-derived claim's `properties` (see
/// [`crate::common::ids::ID_SCOPE_KEY`]); a global claim's are left alone.
fn mark_scope(mut properties: serde_json::Value, scope: Option<Uuid>) -> serde_json::Value {
    if scope.is_some() {
        properties[ID_SCOPE_KEY] = serde_json::json!(ID_SCOPE_OWNER_GROUP);
    }
    properties
}

/// Walk a `DocumentExtraction` tree and produce a flat list of operations,
/// deriving ids for an ingest whose rows `scope` owns.
///
/// `scope` is `None` for a PUBLIC ingest (global ids, cross-source
/// convergence) and `Some(owner_group_id)` for a `private` or `team` one: then
/// every atom id and stored hash folds in the group
/// ([`scoped_atom_id`], [`scoped_atom_content_hash`]), every compound seed gets
/// `":" + group` ([`scoped_seed`]), each claim carries `id_scope` and the
/// [`ID_SCOPE_KEY`] property marker. See [`crate::common::ids`],
/// "Scope-derived ids". The plan's SHAPE (claims, their order, edges, paths)
/// does not depend on `scope`, only its ids and hashes do, so two plans of one
/// extraction twin claim by claim ([`adopt_recorded_ids`] relies on it).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_ingest_plan_scoped(
    extraction: &DocumentExtraction,
    scope: Option<Uuid>,
) -> IngestPlan {
    let mut claims = Vec::new();
    let mut edges = Vec::new();
    let mut path_index = HashMap::new();

    let source_type = source_type_str(&extraction.source.source_type);
    let doc_title = &extraction.source.title;

    // Step 1: Thesis (level 0)
    #[allow(clippy::option_if_let_else)]
    let thesis_id = if let Some(ref thesis_text) = extraction.thesis {
        let hash = content_hash(thesis_text);
        let seed = scoped_seed(&format!("{doc_title}\u{1f}thesis"), scope);
        let id = compound_claim_id(&hash, &seed);
        // Stored hash is scoped too, so the (content_hash, agent_id) dedup
        // (`uq_claims_content_hash_agent` through migration 149, the app-layer
        // lock from 150) cannot collapse two documents' structural rows. See
        // `ids::compound_content_hash`.
        let stored_hash = compound_content_hash(&hash, &seed);
        path_index.insert("thesis".to_string(), id);

        claims.push(PlannedClaim {
            id,
            content: thesis_text.clone(),
            level: 0,
            properties: mark_scope(
                serde_json::json!({
                    "level": 0,
                    "source_type": source_type,
                    "thesis_derivation": thesis_derivation_str(&extraction.thesis_derivation),
                }),
                scope,
            ),
            content_hash: stored_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            axis: None,
            supporting_text: None,
            supporting_locator: Some(passage_locator(
                "thesis",
                None,
                locate_passage(extraction, thesis_text, None).as_ref(),
            )),
            enrichment: serde_json::json!({}),
            id_scope: scope,
        });
        Some(id)
    } else {
        None
    };

    let mut section_ids: Vec<Uuid> = Vec::new();

    for (si, section) in extraction.sections.iter().enumerate() {
        let section_path = format!("sections[{si}]");
        let section_hash = content_hash(&section.title);
        let section_seed = scoped_seed(&format!("{doc_title}\u{1f}{section_path}"), scope);
        let section_id = compound_claim_id(&section_hash, &section_seed);
        let section_stored_hash = compound_content_hash(&section_hash, &section_seed);
        section_ids.push(section_id);
        path_index.insert(section_path.clone(), section_id);

        claims.push(PlannedClaim {
            id: section_id,
            content: section.title.clone(),
            level: 1,
            properties: mark_scope(
                serde_json::json!({
                    "level": 1,
                    "source_type": source_type,
                    "section": section.title,
                    "spine_text_kind": spine_text_kind(extraction),
                }),
                scope,
            ),
            content_hash: section_stored_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            // Structural spine nodes (thesis, section) are not DS-wired, so an
            // axis on them would have nothing to place.
            axis: None,
            supporting_text: None,
            supporting_locator: Some(passage_locator(
                &section_path,
                Some(&section.title),
                // The validated heading span, when it reproduces the title,
                // places the locator at the real heading rather than at the
                // first occurrence of a short title such as "Results".
                locate_passage(extraction, &section.title, section.heading_span.as_ref()).as_ref(),
            )),
            enrichment: serde_json::json!({}),
            id_scope: scope,
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, section_id));
        }

        let mut para_ids: Vec<Uuid> = Vec::new();

        for (pi, paragraph) in section.paragraphs.iter().enumerate() {
            let para_path = format!("{section_path}.paragraphs[{pi}]");
            let para_locator = passage_locator(
                &para_path,
                Some(&section.title),
                locate_passage(extraction, &paragraph.text, paragraph.span.as_ref()).as_ref(),
            );
            let para_hash = content_hash(&paragraph.text);
            let para_seed = scoped_seed(&format!("{doc_title}\u{1f}{para_path}"), scope);
            let para_id = compound_claim_id(&para_hash, &para_seed);
            let para_stored_hash = compound_content_hash(&para_hash, &para_seed);
            para_ids.push(para_id);
            path_index.insert(para_path.clone(), para_id);

            let enrichment = enrichment_from_paragraph(paragraph);
            // Normalise once per paragraph to a canonical calibration key (or
            // None); the atoms below inherit the same tag. Keeps unrecognised
            // extractor values off the BBA, where they'd hit the 0.5
            // unknown-evidence-type fallback.
            let para_evidence_type = crate::common::evidence_type::normalize_evidence_type(
                paragraph.evidence_type.as_deref(),
            );

            // Declared labeled axis (issue #222), from the paragraph or
            // inherited from its section, plus per-atom label overrides.
            //
            // `build_ingest_plan` is infallible by contract, and
            // `axis::validate_axes` is the gate that rejects a malformed
            // declaration with a path-qualified message — every write path calls
            // it first. A failure here therefore means a caller bypassed the
            // gate: assert loudly in dev/test, and in release fall back to the
            // binary default rather than panicking mid-plan.
            let resolved = crate::document::axis::resolve_paragraph_axes(paragraph, section);
            debug_assert!(
                resolved.is_ok(),
                "unvalidated axis at {para_path}: {:?} — call axis::validate_axes before \
                 build_ingest_plan",
                resolved.as_ref().err()
            );
            let (para_axis, atom_axes) =
                resolved.unwrap_or_else(|_| (None, vec![None; paragraph.atoms.len()]));

            claims.push(PlannedClaim {
                id: para_id,
                content: paragraph.text.clone(),
                level: 2,
                properties: mark_scope(
                    serde_json::json!({
                        "level": 2,
                        "source_type": source_type,
                        "section": section.title,
                        "spine_text_kind": spine_text_kind(extraction),
                    }),
                    scope,
                ),
                content_hash: para_stored_hash,
                confidence: paragraph.confidence,
                methodology: paragraph.methodology.clone(),
                evidence_type: para_evidence_type.clone(),
                axis: para_axis,
                supporting_text: Some(paragraph.text.clone()),
                supporting_locator: Some(para_locator.clone()),
                enrichment: enrichment.clone(),
                id_scope: scope,
            });

            edges.push(decomposes_edge(section_id, para_id));

            for (ai, atom_text) in paragraph.atoms.iter().enumerate() {
                let atom_hash = content_hash(atom_text);
                let aid = scoped_atom_id(&atom_hash, scope);
                let atom_path = format!("{para_path}.atoms[{ai}]");
                path_index.insert(atom_path, aid);

                let generality = paragraph.generality.get(ai).copied().filter(|&g| g >= 0);

                let mut props = serde_json::json!({
                    "level": 3,
                    "source_type": source_type,
                    "section": section.title,
                });
                if let Some(g) = generality {
                    props["generality"] = serde_json::json!(g);
                }
                let props = mark_scope(props, scope);

                claims.push(PlannedClaim {
                    id: aid,
                    content: atom_text.clone(),
                    level: 3,
                    properties: props,
                    // Plain for a public ingest (global convergence); folded
                    // with the owning group otherwise, so no content-hash
                    // lookup in another scope can find this row.
                    content_hash: scoped_atom_content_hash(&atom_hash, scope),
                    confidence: paragraph.confidence,
                    methodology: paragraph.methodology.clone(),
                    evidence_type: para_evidence_type.clone(),
                    // Atoms are the DS-wired units, so this is the placement
                    // that actually reaches a mass function.
                    axis: atom_axes.get(ai).cloned().flatten(),
                    supporting_text: Some(paragraph.text.clone()),
                    supporting_locator: Some(para_locator.clone()),
                    enrichment: enrichment.clone(),
                    id_scope: scope,
                });

                edges.push(decomposes_edge(para_id, aid));
            }
        }

        for w in para_ids.windows(2) {
            edges.push(PlannedEdge {
                source_id: w[0],
                source_type: "claim".to_string(),
                target_id: w[1],
                target_type: "claim".to_string(),
                relationship: "continues_argument".to_string(),
                properties: serde_json::json!({}),
            });
        }
    }

    for w in section_ids.windows(2) {
        edges.push(PlannedEdge {
            source_id: w[0],
            source_type: "claim".to_string(),
            target_id: w[1],
            target_type: "claim".to_string(),
            relationship: "section_follows".to_string(),
            properties: serde_json::json!({}),
        });
    }

    for rel in &extraction.relationships {
        let src_path = normalize_claim_path(&rel.source_path);
        let tgt_path = normalize_claim_path(&rel.target_path);

        let source_id = match path_index.get(&src_path) {
            Some(id) => *id,
            None => continue,
        };
        let target_id = match path_index.get(&tgt_path) {
            Some(id) => *id,
            None => continue,
        };

        let mut props = serde_json::json!({});
        if let Some(ref rationale) = rel.rationale {
            props["rationale"] = serde_json::json!(rationale);
        }
        if let Some(strength) = rel.strength {
            props["strength"] = serde_json::json!(strength);
        }

        edges.push(PlannedEdge {
            source_id,
            source_type: "claim".to_string(),
            target_id,
            target_type: "claim".to_string(),
            relationship: rel.relationship.clone(),
            properties: props,
        });
    }

    for (author_idx, author) in extraction.source.authors.iter().enumerate() {
        // Placeholder names ("Authors Not Specified", "Unknown", ...) get no
        // per-claim assertion (backlog a55aac45). Skip WITHOUT re-enumerating:
        // `author_index` keeps the ORIGINAL position, which is the key the MCP
        // walk's author-agent map uses for the same (equally skipped) entry.
        if author.is_placeholder() {
            continue;
        }
        for planned_claim in &claims {
            edges.push(PlannedEdge {
                source_id: Uuid::nil(),
                source_type: "author_placeholder".to_string(),
                target_id: planned_claim.id,
                target_type: "claim".to_string(),
                relationship: "asserts".to_string(),
                properties: serde_json::json!({
                    "author_index": author_idx,
                    "role": "author",
                    "source": "document_attribution",
                }),
            });
        }
    }

    IngestPlan {
        claims,
        edges,
        path_index,
    }
}

/// Re-use, claim by claim, the ids an earlier ingest of the same document in
/// the same scope recorded, so a group re-ingesting a document it ingested
/// before ids became scope-derived converges on its own rows instead of
/// writing scoped duplicates.
///
/// `scoped` and `global` are [`build_ingest_plan_scoped`] of ONE extraction
/// with `Some(owner_group)` and `None`; they twin by index. `recorded` is
/// each recorded claim's id and, when the caller can read the row, its
/// stored `content_hash`, in order of preference (the first entry wins a
/// hash two entries share). The MCP walk passes what the ingest's in-scope
/// `papers` row already asserts through ingest-written `asserts` edges,
/// followed by the owning group's own non-public rows that hold one of the
/// global plan's ids or stored hashes (an ingest from before migration 246,
/// whose paper row was backfilled public, recorded nothing on the group's
/// row). A claim is adopted when its global twin's id is recorded, or when
/// its global twin's stored hash is a recorded claim's hash (an atom the
/// earlier ingest converged onto an existing row with that text, whose id is
/// not the content address). An adopted claim is its global twin under the
/// recorded id, and every edge and path of the plan is re-pointed with it;
/// every other claim keeps its scoped id.
///
/// Returns the plan and the set of adopted ids. A write path MUST write an
/// adopted claim BY ID, like a scoped one, even though it is a global atom
/// (`id_is_document_scoped()` is `false` for it): only the row the document
/// recorded may be resolved to, never another row found by its text in
/// another scope. Only recorded claims are adopted, so a claim new in the
/// re-ingest (an added paragraph) still gets a scoped id.
///
/// Plans that do not twin (not one extraction) are returned unchanged.
#[must_use]
pub fn adopt_recorded_ids(
    mut scoped: IngestPlan,
    global: &IngestPlan,
    recorded: &[(Uuid, Option<[u8; 32]>)],
) -> (IngestPlan, HashSet<Uuid>) {
    let mut adopted = HashSet::new();
    let twins = scoped.claims.len() == global.claims.len()
        && scoped
            .claims
            .iter()
            .zip(&global.claims)
            .all(|(s, g)| s.level == g.level && s.content == g.content);
    if recorded.is_empty() || !twins {
        return (scoped, adopted);
    }
    let ids: HashSet<Uuid> = recorded.iter().map(|(id, _)| *id).collect();
    // First entry wins: `recorded` is in the caller's order of preference
    // (what the document's paper recorded, then the oldest own-scope row).
    let mut by_hash: HashMap<[u8; 32], Uuid> = HashMap::new();
    for (id, hash) in recorded {
        if let Some(h) = hash {
            by_hash.entry(*h).or_insert(*id);
        }
    }
    let mut remap: HashMap<Uuid, Uuid> = HashMap::new();
    for (claim, twin) in scoped.claims.iter_mut().zip(&global.claims) {
        let Some(id) = ids
            .get(&twin.id)
            .copied()
            .or_else(|| by_hash.get(&twin.content_hash).copied())
        else {
            continue;
        };
        remap.insert(claim.id, id);
        adopted.insert(id);
        *claim = twin.clone();
        claim.id = id;
    }
    let re = |id: &mut Uuid| {
        if let Some(to) = remap.get(id) {
            *id = *to;
        }
    };
    for edge in &mut scoped.edges {
        re(&mut edge.source_id);
        re(&mut edge.target_id);
    }
    for id in scoped.path_index.values_mut() {
        re(id);
    }
    (scoped, adopted)
}

impl crate::common::walker::Walker for DocumentExtraction {
    fn build_ingest_plan(&self) -> IngestPlan {
        build_ingest_plan(self)
    }
}

#[cfg(test)]
mod source_type_guard {
    use super::{source_type_str, DOCUMENT_SOURCE_TYPES};
    use crate::document::schema::SourceType;

    /// Every `SourceType` stamp must appear in [`DOCUMENT_SOURCE_TYPES`].
    ///
    /// The list is what MCP `verify_claim` consults to tell "this digest is not
    /// `blake3(content)` by construction" from "this body was mutated". A stamp
    /// missing from it makes every thesis/section/paragraph row of that source
    /// type report a tampering mismatch.
    ///
    /// The `match` below is exhaustive on purpose: adding a `SourceType` variant
    /// is a COMPILE error here until someone decides whether its stamp belongs
    /// in the list (and adds it to `ALL` so this test still covers it).
    #[test]
    fn every_source_type_stamp_is_listed() {
        const ALL: [SourceType; 7] = [
            SourceType::Paper,
            SourceType::Textbook,
            SourceType::InternalDocument,
            SourceType::Report,
            SourceType::Transcript,
            SourceType::Legal,
            SourceType::Tabular,
        ];

        for st in &ALL {
            match st {
                SourceType::Paper
                | SourceType::Textbook
                | SourceType::InternalDocument
                | SourceType::Report
                | SourceType::Transcript
                | SourceType::Legal
                | SourceType::Tabular => {}
            }
            let stamp = source_type_str(st);
            assert!(
                DOCUMENT_SOURCE_TYPES.contains(&stamp),
                "builder stamps source_type {stamp:?} but DOCUMENT_SOURCE_TYPES omits it — \
                 verify_claim would report every structural row of this source type as tampered"
            );
        }
        assert_eq!(
            DOCUMENT_SOURCE_TYPES.len(),
            ALL.len(),
            "the stamp list and the variant list must stay the same size"
        );
        assert!(
            !DOCUMENT_SOURCE_TYPES.contains(&"workflow"),
            "a workflow row is seed-scoped only when it carries CONTENT_HASH_SCOPE_KEY; rows \
             written before backlog 6178a205 share the stamp but store the PLAIN hash, so \
             listing the stamp here would excuse a tampered legacy workflow phase/step body"
        );
    }
}

/// Backlog c083c1c9: every passage locator a document plan writes either
/// carries a byte span into the source that reproduces the hashed passage, or
/// says explicitly that it is not source-verifiable. Before the fix a Tier-2
/// extraction (no `source_text`) got a span-less locator with no flag, and a
/// span-less paragraph in an extraction that DID carry `source_text` was never
/// located in it.
#[cfg(test)]
mod passage_locator_tests {
    use super::build_ingest_plan;
    use crate::common::plan::PlannedClaim;
    use crate::document::schema::DocumentExtraction;

    const FLAG: &str = ", source_verifiable: false";
    const THESIS: &str = "Locators either reproduce or admit they cannot";
    const PARA: &str = "The measured value was 4.2 under the stated conditions.";

    fn extraction(
        source_text: Option<&str>,
        para_span: Option<(usize, usize)>,
    ) -> DocumentExtraction {
        let mut paragraph = serde_json::json!({
            "text": PARA,
            "atoms": ["The measured value was 4.2"],
            "generality": [1],
            "confidence": 0.8
        });
        if let Some((start, end)) = para_span {
            paragraph["span"] = serde_json::json!({"start": start, "end": end});
        }
        let mut json = serde_json::json!({
            "source": {"title": "Locator Paper", "source_type": "Paper", "authors": []},
            "thesis": THESIS,
            "thesis_derivation": "TopDown",
            "sections": [{"title": "Results", "paragraphs": [paragraph]}],
            "relationships": []
        });
        if let Some(src) = source_text {
            json["source_text"] = serde_json::json!(src);
        }
        serde_json::from_value(json).expect("fixture parses")
    }

    /// The passage the evidence writer hashes for this claim
    /// (`literature_evidence_body`: `supporting_text`, else `content`).
    fn passage(c: &PlannedClaim) -> &str {
        c.supporting_text.as_deref().unwrap_or(&c.content)
    }

    /// `(start, end)` parsed from a locator's `, bytes a..b` suffix.
    fn span_of(locator: &str) -> Option<(usize, usize)> {
        let (_, tail) = locator.rsplit_once(", bytes ")?;
        let (a, b) = tail.split_once("..")?;
        Some((a.parse().ok()?, b.parse().ok()?))
    }

    /// The invariant: a span that reproduces the passage from `source`, or the
    /// explicit flag. Never neither, never both.
    fn assert_every_locator_verifiable_or_flagged(claims: &[PlannedClaim], source: Option<&str>) {
        for c in claims {
            let loc = c
                .supporting_locator
                .as_deref()
                .expect("document claims carry a locator");
            match (span_of(loc), loc.ends_with(FLAG)) {
                (Some((a, b)), false) => {
                    let src = source.unwrap_or_else(|| {
                        panic!("a span with no source_text is not verifiable: {loc}")
                    });
                    assert_eq!(
                        src.get(a..b),
                        Some(passage(c)),
                        "span must reproduce the hashed passage: {loc}"
                    );
                }
                (None, true) => {}
                other => panic!("locator neither spanned nor flagged ({other:?}): {loc}"),
            }
        }
    }

    #[test]
    fn tier2_locators_are_flagged_not_source_verifiable() {
        let plan = build_ingest_plan(&extraction(None, None));
        assert_eq!(plan.claims.len(), 4, "thesis, section, paragraph, atom");
        for c in &plan.claims {
            let loc = c.supporting_locator.as_deref().unwrap();
            assert!(
                loc.ends_with(FLAG),
                "Tier-2 locator must carry the flag: {loc}"
            );
        }
        assert_every_locator_verifiable_or_flagged(&plan.claims, None);
    }

    #[test]
    fn spanless_passages_found_in_source_text_get_a_byte_span() {
        let src = format!("Header noise. {THESIS}\n\nResults\n\nPreamble. {PARA} Trailing.");
        let plan = build_ingest_plan(&extraction(Some(&src), None));
        let para_start = src.find(PARA).unwrap();
        for c in plan.claims.iter().filter(|c| c.level >= 2) {
            let loc = c.supporting_locator.as_deref().unwrap();
            assert_eq!(
                span_of(loc),
                Some((para_start, para_start + PARA.len())),
                "paragraph/atom locator: {loc}"
            );
        }
        let thesis = plan.claims.iter().find(|c| c.level == 0).unwrap();
        let t0 = src.find(THESIS).unwrap();
        assert_eq!(
            span_of(thesis.supporting_locator.as_deref().unwrap()),
            Some((t0, t0 + THESIS.len()))
        );
        assert_every_locator_verifiable_or_flagged(&plan.claims, Some(&src));
    }

    #[test]
    fn passages_missing_from_source_text_are_flagged() {
        // The extractor paraphrased: neither the paragraph nor the thesis nor
        // the section title occurs in the source bytes.
        let src = "Something else entirely, with no shared sentence.";
        let plan = build_ingest_plan(&extraction(Some(src), None));
        for c in &plan.claims {
            let loc = c.supporting_locator.as_deref().unwrap();
            assert!(
                loc.ends_with(FLAG),
                "unlocatable passage must be flagged: {loc}"
            );
            assert!(span_of(loc).is_none(), "no invented span: {loc}");
        }
    }

    #[test]
    fn an_extractor_supplied_span_is_kept() {
        let src = format!("xx{PARA}yy");
        let plan = build_ingest_plan(&extraction(Some(&src), Some((2, 2 + PARA.len()))));
        let para = plan.claims.iter().find(|c| c.level == 2).unwrap();
        assert_eq!(
            para.supporting_locator.as_deref(),
            Some(
                format!(
                    r#"sections[0].paragraphs[0] ("Results"), bytes 2..{}"#,
                    2 + PARA.len()
                )
                .as_str()
            )
        );
        assert_every_locator_verifiable_or_flagged(&plan.claims, Some(&src));
    }

    /// Review finding on c083c1c9: a Tier-2 extractor may emit offsets into
    /// its own (e.g. HTML-stripped) text, and with no `source_text` no writer
    /// checks them. Such a span must not make the locator look re-derivable.
    #[test]
    fn a_supplied_span_without_source_text_is_flagged() {
        let plan = build_ingest_plan(&extraction(None, Some((40, 40 + PARA.len()))));
        for c in plan.claims.iter().filter(|c| c.level >= 2) {
            let loc = c.supporting_locator.as_deref().unwrap();
            assert!(loc.ends_with(FLAG), "unchecked span must be flagged: {loc}");
            assert!(span_of(loc).is_none(), "no unchecked span: {loc}");
        }
        assert_every_locator_verifiable_or_flagged(&plan.claims, None);
    }

    /// A supplied span whose source bytes are not the passage is not trusted:
    /// the passage is located by search instead.
    #[test]
    fn a_supplied_span_that_misses_the_passage_is_replaced() {
        let src = format!("xx{PARA}yy");
        let plan = build_ingest_plan(&extraction(Some(&src), Some((0, PARA.len()))));
        let para = plan.claims.iter().find(|c| c.level == 2).unwrap();
        assert_eq!(
            span_of(para.supporting_locator.as_deref().unwrap()),
            Some((2, 2 + PARA.len()))
        );
        assert_every_locator_verifiable_or_flagged(&plan.claims, Some(&src));
    }

    /// Review finding 5: a short section title also occurring earlier in the
    /// source (here inside the abstract) is located at its validated heading
    /// span, not at the first match.
    #[test]
    fn a_section_locator_uses_the_heading_span() {
        let src = format!("Abstract. Results are reported below.\n\nResults\n\n{PARA}");
        let heading = src.rfind("Results\n").unwrap();
        let para = src.find(PARA).unwrap();
        let json = serde_json::json!({
            "source": {"title": "Heading Paper", "source_type": "Paper", "authors": []},
            "source_text": src,
            "thesis_derivation": "TopDown",
            "sections": [{
                "title": "Results",
                "heading_span": {"start": heading, "end": heading + "Results".len()},
                "paragraphs": [{
                    "text": PARA,
                    "span": {"start": para, "end": para + PARA.len()},
                    "atoms": ["The measured value was 4.2"],
                    "generality": [1],
                    "confidence": 0.8
                }]
            }],
            "relationships": []
        });
        let ex: DocumentExtraction = serde_json::from_value(json).expect("fixture parses");
        let plan = build_ingest_plan(&ex);
        let section = plan.claims.iter().find(|c| c.level == 1).unwrap();
        assert_eq!(
            span_of(section.supporting_locator.as_deref().unwrap()),
            Some((heading, heading + "Results".len()))
        );
        assert_every_locator_verifiable_or_flagged(&plan.claims, Some(&src));
    }
}
