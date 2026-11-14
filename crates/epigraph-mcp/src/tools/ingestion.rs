#![allow(clippy::wildcard_imports)]

use std::collections::{HashMap, HashSet};

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{db_caller_error, internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto::{self, BatchDsEntry};
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    ClaimRepository, EdgeRepository, EvidenceRepository, PaperRepository, ReasoningTraceRepository,
};
use epigraph_ingest::common::plan::PlannedClaim;
use epigraph_ingest::document::builder::build_ingest_plan;
use epigraph_ingest::document::schema::ByteSpan;
use epigraph_ingest::document::schema::{DocumentExtraction, DocumentSource, Paragraph, Section};
use epigraph_ingest::document::structure::{
    parse_structure, slice_segmentation, SourceFormat, StructuredDoc,
};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

// ────────────────────────────────────────────────────────────────────────────
// structure_source — raw markdown/plaintext → verbatim DocumentExtraction
// ────────────────────────────────────────────────────────────────────────────

/// Map a verbatim [`StructuredDoc`] into a [`DocumentExtraction`] with atoms
/// EMPTY. The agent fills `atoms` per paragraph and resubmits via
/// `ingest_document_inline`. `source_text` + per-node spans are populated so the
/// writer's verbatim guard re-verifies the round-trip.
fn structured_doc_to_extraction(doc: StructuredDoc, source: DocumentSource) -> DocumentExtraction {
    let sections = doc
        .sections
        .into_iter()
        .map(|s| Section {
            title: s
                .heading
                .as_ref()
                .map(|h| h.text.clone())
                .unwrap_or_default(),
            heading_span: s.heading.map(|h| ByteSpan {
                start: h.start,
                end: h.end,
            }),
            // Deterministic structuring cannot infer a labeled axis from raw
            // bytes (issue #222). The agent adds `axis` to the paragraphs (or
            // sections) it wants placed on one before resubmitting via
            // `ingest_document_inline`.
            axis: None,
            paragraphs: s
                .paragraphs
                .into_iter()
                .map(|p| Paragraph {
                    text: p.span.text,
                    span: Some(ByteSpan {
                        start: p.span.start,
                        end: p.span.end,
                    }),
                    atoms: Vec::new(),
                    generality: Vec::new(),
                    confidence: 0.8,
                    methodology: Some("verbatim_structurer".to_string()),
                    evidence_type: None,
                    axis: None,
                    axis_labels: Vec::new(),
                    page: None,
                    instruments_used: Vec::new(),
                    reagents_involved: Vec::new(),
                    conditions: Vec::new(),
                })
                .collect(),
        })
        .collect();
    DocumentExtraction {
        source,
        thesis: None,
        thesis_derivation: Default::default(),
        sections,
        relationships: Vec::new(),
        source_text: Some(doc.source_text),
        labels: Vec::new(),
    }
}

/// Deterministically structure raw markdown/plaintext (or an agent-supplied
/// messy-input `segmentation`) into a verbatim [`DocumentExtraction`].
/// Read-only / no DB writes — pure compute, hence `clippy::unused_async`: the
/// `#[tool]` server method must be `async`, and it `.await`s this fn.
#[allow(clippy::unused_async)]
pub async fn structure_source(
    _server: &EpiGraphMcpFull,
    params: StructureSourceParams,
) -> Result<CallToolResult, McpError> {
    let doc = if let Some(seg) = params.segmentation {
        slice_segmentation(&params.text, &seg.into())
            .map_err(|e| invalid_params(format!("segmentation failed: {e}")))?
    } else {
        let fmt = match params.format.as_str() {
            "markdown" => SourceFormat::Markdown,
            "plaintext" => SourceFormat::PlainText,
            other => {
                return Err(invalid_params(format!(
                    "unknown format {other:?}; use markdown|plaintext"
                )))
            }
        };
        parse_structure(&params.text, fmt)
            .map_err(|e| invalid_params(format!("structuring failed: {e}")))?
    };
    let extraction = structured_doc_to_extraction(doc, params.source);
    success_json(&extraction)
}

// ────────────────────────────────────────────────────────────────────────────
// ingest_document — hierarchical DocumentExtraction → graph
// ────────────────────────────────────────────────────────────────────────────

const PIPELINE_VERSION_BASE: &str = "hierarchical_extraction_v2";

/// Pipeline version stamp written on the paper's `processed_by` edge and read
/// by `check_already_ingested`.
///
/// For documents ingested whole (papers), this is just `PIPELINE_VERSION_BASE`.
/// For chunked ingests where many `DocumentExtraction`s share one paper row
/// (e.g. a textbook ingested chapter-by-chapter), `source.metadata.chapter_index`
/// is appended (`...:ch{n}`), and
/// `EdgeRepository::create_processed_by_stamp_if_absent_conn` keys its dedup on
/// the stamp, so each chunk records its own `processed_by` edge and
/// `check_already_ingested` can answer for one chunk. The ingest tools do not
/// short-circuit on the stamp: node-level dedup makes a re-run safe.
fn effective_pipeline_version(extraction: &DocumentExtraction) -> String {
    extraction
        .source
        .metadata
        .get("chapter_index")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(
            || PIPELINE_VERSION_BASE.to_string(),
            |n| format!("{PIPELINE_VERSION_BASE}:ch{n}"),
        )
}

pub async fn ingest_document(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestDocumentParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let canonical = std::fs::canonicalize(&params.file_path)
        .map_err(|e| invalid_params(format!("invalid file path: {e}")))?;
    let cwd = std::env::current_dir()
        .map_err(|e| crate::errors::internal_error_logged("cannot determine CWD", e))?;
    if !canonical.starts_with(&cwd) {
        return Err(invalid_params(
            "file path must be within the working directory",
        ));
    }
    let data = tokio::fs::read_to_string(&canonical)
        .await
        .map_err(|e| invalid_params(format!("cannot read {}: {e}", canonical.display())))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).map_err(|e| invalid_params(format!("invalid JSON: {e}")))?;

    let doi = resolve_doi(&extraction);
    let title = extraction.source.title.clone();
    // The label set is validated before ANY write, here in the handler: the walk
    // runs detached, so a refusal there would reach only the server log after
    // the caller was told `queued` and after `ensure_paper_node` wrote the
    // `papers` row. The core re-derives (and re-checks) the same set.
    ingest_claim_labels(&extraction, &doi)?;
    refuse_lineage_relationships(&extraction)?;
    refuse_bad_author_ids(&extraction)?;
    let choice = parse_ingest_visibility(params.visibility.as_deref(), params.group_id.as_deref())?;

    // The ingest is handed to a task DETACHED from this request, so it needs an
    // owned viewer: a spawned task is `'static` and cannot borrow the caller's.
    // `Viewer` is not `Clone`; `detach_scoped` is the narrow replacement, and
    // what it yields is the caller's own scoped read authority and nothing
    // wider. THAT IS THE WHOLE OF THE CLAIM, said narrowly because the obvious
    // over-reading is wrong: it constrains the VIEWER the detached task holds,
    // not the task's database reach. `do_ingest_document` spends this `&Viewer`
    // on its DS reads; its WRITES are authorised by the transaction it stamps
    // from the ingesting agent (`begin_author_stamped_tx`), not by this viewer.
    //
    // ABOVE `ensure_paper_node`, not below it, which is the file's own stated
    // convention two guards up in `do_ingest_document`: fail closed BEFORE any
    // DB write. On the refusal arm nothing has been written, so no `papers` row
    // survives an ingest that was refused. `request_viewer` resolves an
    // `agents.id` on both transports, so the arm is not reachable today — it is
    // written as a refusal rather than an `expect` because the state it would
    // represent is a widening, and those fail closed. `invalid_request` rather
    // than `internal_error` for the same reason `request_viewer` uses it one
    // frame up: a denial of authority is not a server fault, and classifying it
    // as one would send an operator hunting a crash.
    //
    // An ELEVATED request is refused before the detach: `detach_scoped`
    // downgrades it to the principal's scoped viewer, so nothing after this
    // line could still see that the request was elevated (and read-only).
    crate::write_identity::refuse_elevated(viewer)?;
    let viewer = viewer.detach_scoped().ok_or_else(|| {
        McpError::invalid_request(
            "ingest_document requires the caller's own read authority",
            None,
        )
    })?;

    preflight_write_authority(
        server,
        &viewer,
        "ingest_document",
        auth,
        &extraction.source.authors,
        &doi,
        choice,
    )
    .await?;
    if params.wait.unwrap_or(false) {
        return ingest_in_request(server, &viewer, &extraction, auth, &doi, choice).await;
    }
    let paper_id = ensure_paper_node(server, &extraction, &doi).await?;
    // A CLONE of the parent, not a fresh `new_shared`: it must carry the
    // parent's `agent_db_id` cache, `ScopedPool` and `privileged_pool` — the
    // exact state the preflight above was run against.
    //
    // The cache is the load-bearing part. A fresh server has an EMPTY
    // `agent_db_id`, so the task's `agent_id()` re-ran PR-09's
    // `ensure_personal_group` on the unstamped pool — the reviving `ON
    // CONFLICT` — once per ingest rather than once per process. MEASURED by
    // review (SQL trace of the detached task): agents lookup ->
    // `epigraph_ensure_personal_group` -> the revoked personal membership is
    // live again -> `INSERT INTO claims`.
    let bg = server.clone();
    let doi_log = doi.clone();
    // Owned, for the same `'static` reason as the viewer: the detached walk
    // authors as the request's principal (batch H-b, D1), so it needs the
    // request's token, not a borrow of it.
    let auth = auth.cloned();
    // Tracked, not a bare `tokio::spawn`: a stdio process whose client closes
    // the session drains it before exiting (`crate::background`), instead of
    // cancelling a walk the caller was told is `queued`.
    server.background_tasks().spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &viewer, &extraction, auth.as_ref(), choice).await {
            tracing::error!(
                target: "tenancy.scoped_write",
                doi = doi_log,
                "background ingest_document failed and wrote NOTHING (the walk is one \
                 transaction): {e:?}"
            );
        }
    });
    success_json(&queued_response(&doi, &title, paper_id))
}

/// Synchronous write-authority preflight for the two DETACHED ingest entry
/// points, run before `ensure_paper_node` writes anything.
///
/// `do_ingest_document` runs in a spawned task, so a refusal inside it
/// reaches no caller — the caller has already been told `queued`. The walk is
/// now one author-stamped transaction, so such a refusal leaves nothing behind
/// (and no `processed_by` edge, which is what `check_already_ingested` reports),
/// but the COMMON refusals are knowable before the task starts: the author
/// cannot write the group that owns every row the walk writes (its own
/// personal group, or its operator's when it is operator-linked and acting;
/// see `owner_decl`), the author is bound to no human operator once operator
/// binding is armed (`OPL01`), a linked agent whose link is not acting would
/// fall back to a group its operator does not write (`OPL02`), or the process
/// was built without a `ScopedPool`. This opens exactly the transaction the task will open, from the same
/// author, runs the same owner-group check ([`IngestTx::owner_decl`]), and
/// drops it: so that refusal is returned to the caller as an error with nothing
/// written, instead of a `queued` over a task that cannot write.
///
/// Checking only "some writable group" was the earlier shape, and it was the
/// wrong question: a server agent revoked in its personal group but live in a
/// team group passed it, and the detached walk then revived the revoked
/// membership (see `owner_decl`).
///
/// What it cannot pre-empt, and is disclosed rather than hidden: a failure
/// specific to the document's content (a constraint on one of its rows, a
/// converged atom owned by another group). Those still surface only in the
/// server log and as the ABSENCE of the paper's `processed_by` edge.
async fn preflight_write_authority(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    tool_name: &'static str,
    auth: Option<&epigraph_auth::AuthContext>,
    authors: &[epigraph_ingest::common::schema::AuthorEntry],
    doi: &str,
    choice: epigraph_core::VisibilityChoice,
) -> Result<(), McpError> {
    let author = server.write_identity(auth, viewer).await?;
    let agent_id = author.agent_id();
    // The visibility too: a refused team is reported here, not after `queued`.
    let resolution = resolve_ingest_visibility(server, agent_id, choice).await?;
    let mut tx = begin_ingest_tx(server, author, tool_name, resolution.grant()).await?;
    // The OWNER group, not merely "some writable group": the same read-only
    // check the walk itself makes (`IngestTx::owner_decl`), so an author whose
    // owner-group membership is revoked or read-only, an unbound author once
    // armed (OPL01), and a linked agent whose link is not acting (OPL02) are
    // refused HERE, to the caller, instead of being told `queued` over a task
    // that writes nothing.
    tx.owner_decl(agent_id, tool_name, &resolution).await?;
    // Every explicit `source.authors[].agent_id` names an agent that may
    // author (backlog 94cc12db), on the same connection the walk will use, so
    // an unknown or system id is refused to the caller BEFORE the eager
    // `papers` row, not in the detached task's log. On a re-ingest (the row
    // exists) the name-derived authors an `agent_id` replaces are retracted
    // here too, inside this transaction, so an author this caller cannot
    // retract is refused now rather than in the task.
    let existing_paper = find_paper_by_document_key(&server.pool, doi)
        .await?
        .map(|p| p.id);
    crate::tools::ingest_authors::preflight_document_authors(
        &mut tx,
        viewer,
        authors,
        agent_id,
        existing_paper,
    )
    .await?;
    // Nothing is kept from it; dropping it rolls back (the retractions too).
    drop(tx);
    Ok(())
}

/// Inline (typed-param) counterpart to [`ingest_document`]. Takes a
/// `DocumentExtraction` directly instead of a file path and routes it through
/// the same [`do_ingest_document`] core, so an MCP client can produce the
/// hierarchy in-band — without first writing a file it then can't reference.
/// Identical graph result and idempotency gate as the file-path path.
pub async fn ingest_document_inline(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestDocumentInlineParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let wait = params.wait.unwrap_or(false);
    let choice = parse_ingest_visibility(params.visibility.as_deref(), params.group_id.as_deref())?;
    let extraction = params.extraction;
    let doi = resolve_doi(&extraction);
    let title = extraction.source.title.clone();
    // Before any write, for the reason given in `ingest_document` above.
    ingest_claim_labels(&extraction, &doi)?;
    refuse_lineage_relationships(&extraction)?;
    refuse_bad_author_ids(&extraction)?;

    // Same detached-task ownership requirement, the same refusals (an elevated
    // request first, before the detach downgrades it) and the same
    // before-any-DB-write placement as `ingest_document` above.
    crate::write_identity::refuse_elevated(viewer)?;
    let viewer = viewer.detach_scoped().ok_or_else(|| {
        McpError::invalid_request(
            "ingest_document_inline requires the caller's own read authority",
            None,
        )
    })?;

    preflight_write_authority(
        server,
        &viewer,
        "ingest_document_inline",
        auth,
        &extraction.source.authors,
        &doi,
        choice,
    )
    .await?;
    if wait {
        return ingest_in_request(server, &viewer, &extraction, auth, &doi, choice).await;
    }
    let paper_id = ensure_paper_node(server, &extraction, &doi).await?;
    // A clone of the parent, sharing its `agent_db_id` cache; see
    // `ingest_document` above for why a fresh `new_shared` revived revoked
    // memberships.
    let bg = server.clone();
    let doi_log = doi.clone();
    // Owned, for the same `'static` reason as the viewer: the detached walk
    // authors as the request's principal (batch H-b, D1), so it needs the
    // request's token, not a borrow of it.
    let auth = auth.cloned();
    // Tracked, not a bare `tokio::spawn`: a stdio process whose client closes
    // the session drains it before exiting (`crate::background`), instead of
    // cancelling a walk the caller was told is `queued`.
    server.background_tasks().spawn(async move {
        if let Err(e) = do_ingest_document(&bg, &viewer, &extraction, auth.as_ref(), choice).await {
            tracing::error!(
                target: "tenancy.scoped_write",
                doi = doi_log,
                "background ingest_document_inline failed and wrote NOTHING (the walk is one \
                 transaction): {e:?}"
            );
        }
    });
    success_json(&queued_response(&doi, &title, paper_id))
}

/// The `wait: true` arm of the two detached ingest handlers: run the walk IN
/// the request and hand its result, or its error, to the caller.
///
/// Detached, a walk that fails past [`preflight_write_authority`] (a constraint
/// on one of the document's rows, a refused trace, a malformed axis) reaches
/// only the server log, and the caller, already told `queued`, can infer it
/// only from `query_paper`'s claim_count staying 0 (backlog b1924b39). Waiting
/// is what `ingest_document_spine` already does.
///
/// Called AFTER the same `refuse_elevated` / `detach_scoped` / preflight the
/// detached arm runs, so both modes author under exactly the same authority.
/// It skips `ensure_paper_node`: `do_ingest_document` gets-or-creates the row
/// itself, after its verbatim and axis guards, so a guard refusal here leaves
/// no `papers` row at all. A failure later in the walk can still leave that
/// row (it is written on the pool, outside the walk's transaction), and the
/// error says so.
async fn ingest_in_request(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
    doi: &str,
    choice: epigraph_core::VisibilityChoice,
) -> Result<CallToolResult, McpError> {
    do_ingest_document(server, viewer, extraction, auth, choice)
        .await
        .map_err(|e| McpError {
            code: e.code,
            message: std::borrow::Cow::from(format!(
                "{}. The ingest walk is one transaction, so no claims or edges were written \
                 for document_key {doi:?}; its papers row may exist with 0 claims. Fix the \
                 cause and retry: a retry is safe and converges on existing nodes.",
                e.message
            )),
            data: e.data,
        })
}

/// Refuse a document whose `relationships` name `supersedes` in any spelling
/// (supersede SPEC K12a): the lineage edge is the supersession act's alone.
/// A caller payload error, before any write, on every document entry point.
fn refuse_lineage_relationships(extraction: &DocumentExtraction) -> Result<(), McpError> {
    epigraph_ingest::common::schema::refuse_lineage_relationships(&extraction.relationships)
        .map_err(invalid_params)
}

/// Refuse a document whose `source.authors[].agent_id` is malformed, on a
/// placeholder name, or repeated (backlog 94cc12db): a caller payload error,
/// before any write, on every document entry point. Whether each id names an
/// agent that may author is checked on a connection: in the handlers'
/// preflight and again in the walk (`tools::ingest_authors`).
fn refuse_bad_author_ids(extraction: &DocumentExtraction) -> Result<(), McpError> {
    crate::tools::ingest_authors::parse_explicit_author_ids(&extraction.source.authors).map(|_| ())
}

/// Create (or fetch) the document's `papers` row **synchronously**, before the
/// ingest is handed to a detached task, so the caller gets an id it can address
/// what it just wrote by. Idempotent on the identity key, and the background
/// `do_ingest_document` calls the same get-or-create, so this only moves the
/// node creation earlier — it does not create a second row.
///
/// Previously both ingest entry points returned `{doi, status, title, note}`
/// with no id at all (issue #356): a caller could not reference, verify, or
/// link the document it had just created.
async fn ensure_paper_node(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
    doi: &str,
) -> Result<Uuid, McpError> {
    PaperRepository::get_or_create(
        &server.pool,
        doi,
        Some(&extraction.source.title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)
}

/// Shared response body for the two queued ingest entry points.
fn queued_response(doi: &str, title: &str, paper_id: Uuid) -> serde_json::Value {
    let mut note = String::from(
        "DB writes are running as a detached background task; confirm they landed by \
         query_paper(`document_key`)'s claim_count rising, not with check_already_ingested, \
         which is already true after ingest_document_spine or any earlier ingest of this \
         document.",
    );
    if is_synthetic_key(doi) {
        note.push_str(
            " This document has no DOI, so `document_key` was SYNTHESIZED from its identity \
             — it is the key to poll and label with, not a real DOI. Set source.external_id \
             to pin the key to your own run id so re-ingests converge on this same node.",
        );
    }
    serde_json::json!({
        "status": "queued",
        // `paper_id` is the addressable node; `document_key` is what `papers.doi`,
        // the `doi:<key>` claim label, and check_already_ingested are keyed on.
        "paper_id": paper_id,
        "document_key": doi,
        "synthesized_key": is_synthetic_key(doi),
        // Retained under its original name for callers that already read it.
        "doi": doi,
        "title": title,
        "note": note,
    })
}

/// Gate check: returns `Some(paper_id)` iff a paper with `doi` exists AND has
/// a `processed_by` edge `viewer` can read whose `properties.pipeline` equals
/// `pipeline_version`. Mirrors the inline gate used by `do_ingest_document`.
///
/// The `papers` lookup runs on the plain pool (`papers` has no row security);
/// the EDGE read runs on a read stamped from `viewer`
/// (`EpiGraphMcpFull::read_as`). It used to run on the plain pool too, where
/// FORCEd row security admits public rows only, so a group-private ingest's
/// `processed_by` stamp was invisible to the group's own members and the gate
/// reported "not ingested".
pub async fn paper_already_ingested(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    doi: &str,
    pipeline_version: &str,
) -> Result<Option<Uuid>, McpError> {
    let Some(prior) = find_paper_by_document_key(&server.pool, doi).await? else {
        return Ok(None);
    };
    let mut read = server.read_as(viewer, "check_already_ingested").await?;
    let stamped =
        PaperRepository::has_processed_by_edge(&mut *read, viewer, prior.id, pipeline_version)
            .await
            .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;
    Ok(stamped.then_some(prior.id))
}

/// Pre-flight idempotency check exposing the same `(doi, pipeline)` gate that
/// `do_ingest_document` runs internally. Lets callers (skills, orchestrators)
/// short-circuit *before* paying for an `extract-claims` LLM call when a
/// paper has already been processed at the requested pipeline version.
///
/// This tool only reads the gate; it does no extraction or ingestion. To
/// actually save extraction cost on re-runs, callers must invoke this tool
/// first and skip their own LLM call when `already_ingested` is true.
///
/// When the caller omits `pipeline_version`, matches the whole
/// [`PIPELINE_VERSION_BASE`] family — the whole-document stamp and every
/// per-chapter `:ch{n}` stamp [`effective_pipeline_version`] writes — and
/// reports which stamps were found. A default-mode `true` therefore means AT
/// LEAST ONE stamp in the family exists, not that every chunk landed. An
/// explicit `pipeline_version` is matched exactly, which is how a caller gates
/// a single chunk: each chunk writes its own stamp
/// (`EdgeRepository::create_processed_by_stamp_if_absent_conn`).
pub async fn check_already_ingested(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: CheckAlreadyIngestedParams,
) -> Result<CallToolResult, McpError> {
    // A placeholder is not an identity. Answering the gate for `doi: "unknown"`
    // used to report on whatever shared bucket every DOI-less document had
    // collapsed into (issue #356); fail loudly and point at the real key instead.
    if is_placeholder_id(&params.doi) {
        return Err(invalid_params(format!(
            "{:?} is a placeholder, not a document identity. Documents with no DOI are keyed \
             on a synthesized `urn:epigraph:doc:*` key — pass the `document_key` the ingest \
             call returned (set source.external_id to control it).",
            params.doi
        )));
    }
    // An explicit `pipeline_version` is matched EXACTLY — that is how a caller
    // gates one chunk (`...:ch3`). An omitted one used to default to the bare
    // base stamp, which a chunked ingest never writes (it stamps `base:ch{n}`
    // via `effective_pipeline_version`), so a textbook ingested chapter by
    // chapter read as never ingested (backlog 02653c4a, G8). The default now
    // matches the whole family the ingest tools actually write: the base stamp
    // and every `base:ch{n}`. The explicit arm stays exact, and it is reliable
    // for every chunk only because each chunk now writes its own stamp (G8
    // review: the triple-keyed writer kept only the first chunk's).
    //
    // The `processed_by` stamps are read as the CALLER (see
    // `paper_already_ingested`): on the plain pool a group-private ingest read
    // as "not ingested" to the group that ran it.
    let (pipeline, paper_id, matched) = match params.pipeline_version {
        Some(exact) => {
            let paper_id = paper_already_ingested(server, viewer, &params.doi, &exact).await?;
            let matched = paper_id.map(|_| vec![exact.clone()]).unwrap_or_default();
            (exact, paper_id, matched)
        }
        None => {
            let paper = find_paper_by_document_key(&server.pool, &params.doi).await?;
            let matched = match &paper {
                Some(p) => {
                    let mut read = server.read_as(viewer, "check_already_ingested").await?;
                    let matched = PaperRepository::processed_by_pipelines_in_family(
                        &mut *read,
                        viewer,
                        p.id,
                        PIPELINE_VERSION_BASE,
                    )
                    .await
                    .map_err(internal_error)?;
                    read.commit().await.map_err(internal_error)?;
                    matched
                }
                None => Vec::new(),
            };
            let paper_id = paper.filter(|_| !matched.is_empty()).map(|p| p.id);
            (PIPELINE_VERSION_BASE.to_string(), paper_id, matched)
        }
    };

    success_json(&CheckAlreadyIngestedResponse {
        already_ingested: paper_id.is_some(),
        paper_id: paper_id.map(|id| id.to_string()),
        doi: params.doi,
        pipeline_version: pipeline,
        matched_pipeline_versions: matched,
    })
}

/// Phase 1 of the two-phase ingest flow. Writes thesis + sections +
/// paragraphs (levels 0–2) and returns which paragraph paths are NEW so the
/// caller atomizes only those before submitting atoms via
/// `ingest_document_inline`. Skips atoms entirely. Structural nodes are keyed
/// on (document title, structural path, text), so re-ingesting the SAME
/// document reuses them; a DIFFERENT document that happens to share a heading
/// or a boilerplate paragraph gets its own nodes.
pub async fn ingest_document_spine(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestDocumentSpineParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let choice = parse_ingest_visibility(params.visibility.as_deref(), params.group_id.as_deref())?;
    do_ingest_document_spine(server, viewer, &params.extraction, auth, choice).await
}

/// Parse an ingest's `visibility` / `group_id` (docs/tenancy/claim-visibility-controls.md).
fn parse_ingest_visibility(
    visibility: Option<&str>,
    group_id: Option<&str>,
) -> Result<epigraph_core::VisibilityChoice, McpError> {
    epigraph_core::VisibilityChoice::parse_str(visibility, group_id).map_err(invalid_params)
}

/// Resolve an ingest's visibility for its author: whose the claims are, and
/// the team-write grant to stamp (D-V3). Pure definer reads on the pool. The
/// home group stays `IngestTx::owner_decl`'s read-only resolution.
async fn resolve_ingest_visibility(
    server: &EpiGraphMcpFull,
    agent_id: Uuid,
    choice: epigraph_core::VisibilityChoice,
) -> Result<epigraph_db::ChoiceResolution, McpError> {
    let mut conn = server.pool.acquire().await.map_err(internal_error)?;
    ClaimRepository::resolve_visibility_choice(&mut conn, agent_id, choice)
        .await
        .map_err(crate::claim_helper::visibility_caller_error)
}

/// Core ingestion logic factored out so integration tests can drive a parsed
/// `DocumentExtraction` without round-tripping through the file-path validation
/// in `ingest_document`.
#[allow(clippy::too_many_lines)]
/// Add this document's labels (`doi:<doi>` and the caller's `labels`, see
/// [`ingest_claim_labels`]) to a claim the walk RESOLVED TO rather than
/// created — returning `false`, with nothing changed, when that claim belongs
/// to a group the ingesting agent cannot write.
///
/// # Why a refusal here is skipped rather than propagated
///
/// Atoms are content-addressed: convergence onto a row another agent already
/// wrote is how cross-source corroboration finds agreement, and it is the
/// FEATURE. On the stamped transaction, adding a label to such a row is an
/// `UPDATE claims` that `claims_tenancy`'s `WITH CHECK` refuses (the row's
/// owner is not in the author's writable set). Propagating that would abort the
/// WHOLE document for one converged atom. MEASURED on a cleanly-migrated schema
/// as `epigraph_app`: a document whose first atom converged onto a workflow
/// operation atom owned by the ingest-system group wrote nothing at all
/// (`processed_by=0 doc_claims=0`). The tenancy-correct outcome is narrower:
/// this author may not tag another group's claim, so the tag is not applied,
/// and the paper still `asserts` the atom (that edge is written by the caller).
///
/// # Why a SAVEPOINT (hard constraint #6)
///
/// This is a swallowed failure inside the caller's transaction. Without its own
/// savepoint the refused statement would abort the whole transaction, and the
/// eventual COMMIT would be answered with ROLLBACK and no error — the ingest
/// reporting success having written nothing. Only an RLS refusal (SQLSTATE
/// 42501) is swallowed; every other error propagates and fails the document.
async fn label_resolved_claim(
    conn: &mut sqlx::PgConnection,
    claim_id: Uuid,
    labels: &[String],
) -> Result<bool, McpError> {
    use sqlx::Acquire;
    let mut sp = conn.begin().await.map_err(internal_error)?;
    match ClaimRepository::update_labels_conn(&mut sp, claim_id, labels, &[]).await {
        Ok(_) => {
            sp.commit().await.map_err(internal_error)?;
            Ok(true)
        }
        Err(e) if is_rls_refusal(&e) => {
            sp.rollback().await.map_err(internal_error)?;
            tracing::warn!(
                target: "tenancy.scoped_write",
                claim_id = %claim_id,
                labels = ?labels,
                "ingest resolved to an existing claim owned by a group this agent cannot write; \
                 its document labels were NOT added (the paper still asserts it)"
            );
            Ok(false)
        }
        Err(e) => Err(internal_error(e)),
    }
}

/// The labels this ingest may merge onto a claim it RESOLVED TO: the full set
/// ([`ingest_claim_labels`]) when the ingesting agent authored that claim, and
/// only `doi:<doi>` (its first entry) otherwise.
///
/// # Why the caller's labels stop at another author's row
///
/// The resolved branch is reached by content, not by ownership: an atom
/// converges onto ANY row with its `content_hash` (`ClaimRepository::create_conn`
/// has no author filter), and a document-scoped node onto any row with its
/// (title, path, text) id. The only check on the label write is RLS, and under
/// D1 a writer of a TEAM group passes it on a colleague's claim owned by that
/// team. `doi:<doi>` is safe there — its fixed prefix can never spell a
/// workflow label. Caller vocabulary is not: `labels: ["resolved"]` on an atom
/// restating a colleague's backlog item retired it with no `Resolves <id>:`
/// trail, past [`crate::tools::claims`]'s retirement gate and the HTTP
/// whole-mutation `require_owner_or_admin` bar on `update_labels`. MEASURED on
/// `epigraph_app` (`tests/ingest_caller_labels_foreign_claim.rs`).
///
/// Author equality is deliberately narrower than `require_owner_or_admin`: an
/// agent linked to the author's operator, or an admin, gets `doi:` only here
/// and relabels through `update_labels`, which asks those questions. Fail
/// closed: an author this walk cannot read (`None`) is treated as foreign.
///
/// With no caller labels the set is just `[doi:<doi>]` and no read is made, so
/// the default ingest's behaviour and cost are unchanged.
async fn labels_for_resolved_claim<'l>(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    known_author: Option<Uuid>,
    agent_id: Uuid,
    claim_labels: &'l [String],
) -> Result<&'l [String], McpError> {
    if claim_labels.len() <= 1 {
        return Ok(claim_labels);
    }
    let author = match known_author {
        Some(author) => Some(author),
        None => ClaimRepository::get_agent_id(&mut *conn, viewer, claim_id)
            .await
            .map_err(internal_error)?,
    };
    if author == Some(agent_id) {
        return Ok(claim_labels);
    }
    tracing::warn!(
        target: "tenancy.scoped_write",
        claim_id = %claim_id,
        author = ?author,
        ingesting_agent = %agent_id,
        withheld = ?&claim_labels[1..],
        "ingest resolved to a claim another agent authored; the caller's labels were NOT \
         added to it (only the document's doi: label is)"
    );
    Ok(&claim_labels[..1])
}

/// The write transaction a document ingest runs in.
///
/// `Stamped` is the production shape: `begin_author_stamped_tx` from the
/// ingesting agent. `Privileged` exists for exactly one caller, the operator
/// `ingest-document` CLI, which runs on `MaintenancePool` (BYPASSRLS) and has no
/// tenancy context to stamp; it is reachable only when the server was built
/// with `EpiGraphMcpFull::on_a_privileged_pool`. A server with neither fails
/// closed with `begin_author_stamped_tx`'s refusal.
enum IngestTx<'p> {
    Stamped(epigraph_db::ScopedTx<'p>),
    Privileged(sqlx::Transaction<'static, sqlx::Postgres>),
}

impl std::ops::Deref for IngestTx<'_> {
    type Target = sqlx::PgConnection;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Stamped(tx) => tx,
            Self::Privileged(tx) => tx,
        }
    }
}

impl std::ops::DerefMut for IngestTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Stamped(tx) => tx,
            Self::Privileged(tx) => tx,
        }
    }
}

impl IngestTx<'_> {
    async fn commit(self) -> Result<(), String> {
        match self {
            Self::Stamped(tx) => tx.commit().await.map_err(|e| e.to_string()),
            Self::Privileged(tx) => tx.commit().await.map_err(|e| e.to_string()),
        }
    }

    /// The tenancy declaration every row of this ingest is owned under — the
    /// same owner rule `submit_claim` / `memorize` apply
    /// (`ClaimRepository::default_decl_for_author`), resolved without ever
    /// minting:
    ///
    /// * an operator-linked agent that is ACTING for its operator (migration
    ///   107's `epigraph_operator_actor`): the OPERATOR's personal group;
    /// * any other author: its OWN personal group, proved live and writable on
    ///   THIS transaction.
    ///
    /// # Why the operator branch comes first
    ///
    /// Once operator binding is armed (migration 122), the claims trigger
    /// refuses a linked agent's claim owned by a group its operator does not
    /// write (`OPL02`). A linked agent's own personal group is such a group.
    /// This arm used to read ONLY that group, so a linked agent that still
    /// held a live membership there passed the synchronous preflight, was
    /// told `queued`, and then lost the whole detached walk to `OPL02` on the
    /// first claim INSERT, where only the server log saw it. A linked agent
    /// with no personal group of its own was refused outright. The operator
    /// branch is what `default_decl_for_author` has done since migration 107;
    /// this arm predated it and was never re-pointed.
    ///
    /// # Why not call `ClaimRepository::default_decl_for_author`
    ///
    /// That helper resolves through `ensure_personal_group`, which on migration
    /// 077's body revived a revoked admin membership (`ON CONFLICT … DO UPDATE
    /// SET revoked_at = NULL, role = 'admin'`, hard constraint #3). Migration
    /// 105 makes it refuse instead, but this arm stays a PURE READ: on a
    /// transaction stamped from the author, "not visible" already means "no
    /// LIVE membership", and a read-only check can refuse with the
    /// operator-facing reason without spending the function's RAISE on an
    /// ingest transaction. So it mirrors that helper's ORDER with reads and
    /// refusals only.
    ///
    /// `begin_author_stamped_tx` only proves the author has SOME writable
    /// group, and "some writable group is not the same question"
    /// (`epigraph_ingest_executor::system_agent_write_authority` says so for
    /// its own agent). MEASURED by review, on the real binary as `epigraph_app`:
    /// server agent revoked in its personal group but a live `writer` in a team
    /// group, `ingest_document_inline` twice — `personal:admin(revoked)` became
    /// `personal:admin(live)` and +3 / +4 claims committed under it.
    ///
    /// So on the Stamped arm this is, in order, the claims trigger's own
    /// questions asked before anything is written:
    /// 1. [`epigraph_db::AgentRepository::require_bound_author`] — an author
    ///    bound to no registered human operator is refused by name (`OPL01`)
    ///    once armed; quiet when unarmed. Asked FIRST and of every author,
    ///    because an acting link (step 2) does not read the human registry: a
    ///    link whose operator was de-registered still acts, and still does not
    ///    bind.
    /// 2. [`epigraph_db::AgentRepository::operator_actor`] (a definer read) —
    ///    `Some` gives the operator's personal group. An acting link means the
    ///    agent AND the operator hold live writer/admin rows there, so the
    ///    trigger's writer-scope check passes and the stamp carries the group.
    /// 3. Otherwise [`epigraph_db::GroupMembershipRepository::visible_personal_group_conn`]
    ///    — `None` means no live membership; refuse (`OPL02`, by name, when
    ///    the agent is live-linked: its link is not acting and it has no group
    ///    it may write).
    /// 4. [`epigraph_db::AgentRepository::require_writer_authority`] with the
    ///    author as the writer — the trigger's writer-scope question on the
    ///    resolved group. A live link that is NOT acting (the operator revoked
    ///    the agent's row in its group, or no longer holds the group itself)
    ///    falls back to the agent's own personal group, which its operator
    ///    does not write: `OPL02`. So does an author bound only through the
    ///    client allowlist (migration 149), whose own personal group is not
    ///    one its human writes. Quiet for an unlinked agent and when unarmed.
    /// 5. [`epigraph_db::GroupMembershipRepository::session_can_write_group_conn`]
    ///    — `group = ANY(epigraph_writable_groups())` on the same transaction,
    ///    the exact question migration 077's `WITH CHECK` will ask of every row;
    ///    a live `reader` membership fails it; refuse.
    ///
    /// Every refusal here reaches the caller synchronously, because
    /// [`preflight_write_authority`] runs this same check before the detached
    /// walk is spawned and before the `papers` row is written.
    ///
    /// The Privileged arm (the operator CLI on `MaintenancePool`, BYPASSRLS)
    /// calls `default_decl_for_author`: there is no stamp to reason about. Since
    /// batch F that helper no longer reads the group on the caller's connection
    /// first, so an operator ingest authored by an agent whose personal
    /// membership is REVOKED is refused (`DbError::MembershipRevoked`) instead
    /// of being owned by the group the agent was revoked from.
    async fn owner_decl(
        &mut self,
        agent_id: Uuid,
        tool_name: &'static str,
        resolution: &epigraph_db::ChoiceResolution,
    ) -> Result<epigraph_core::TenancyDecl, McpError> {
        let tx = match self {
            Self::Privileged(tx) => {
                let home = ClaimRepository::default_decl_for_author(tx, agent_id)
                    .await
                    .map_err(crate::errors::db_caller_error)?
                    .owner_group_bind()
                    .ok_or_else(|| {
                        crate::errors::internal_error_text(format!(
                            "{tool_name}: the author's home group did not resolve"
                        ))
                    })?;
                return Ok(resolution.decl(home));
            }
            Self::Stamped(tx) => tx,
        };
        let refuse = |why: String| {
            tracing::error!(
                target: "tenancy.scoped_write",
                tool = tool_name,
                author = %agent_id,
                "{why}"
            );
            crate::errors::internal_error_text(format!("{tool_name}: {why}"))
        };
        // 1. The claims trigger's first question, asked of EVERY author: is it
        //    bound to a registered human operator? OPL01 by name once armed.
        //    Unconditional, because an acting link (107) does not read the
        //    human registry: a link whose operator was de-registered still
        //    "acts", and only this check sees that it no longer binds.
        epigraph_db::AgentRepository::require_bound_author(tx, agent_id)
            .await
            .map_err(crate::errors::db_caller_error)?;
        // 2. Operator-linked and ACTING: the operator's personal group.
        let group = if let Some(link) = epigraph_db::AgentRepository::operator_actor(tx, agent_id)
            .await
            .map_err(crate::errors::db_caller_error)?
        {
            link.operator_group_id
        } else {
            // 3. The author's own personal group, a pure read.
            let Some(own) =
                epigraph_db::GroupMembershipRepository::visible_personal_group_conn(tx, agent_id)
                    .await
                    .map_err(internal_error)?
            else {
                // A live-linked agent whose link is not acting has no group
                // it may write: say that (OPL02), not "restore your personal
                // membership", which would not help.
                let binding = epigraph_db::AgentRepository::author_binding(tx, agent_id)
                    .await
                    .map_err(crate::errors::db_caller_error)?;
                if binding.as_deref() == Some(epigraph_db::LIVE_LINK_BINDING) {
                    let why = format!(
                        "the ingesting agent ({agent_id}) is operator-linked, but its link is not \
                         acting (its membership in its operator's personal group was revoked, or \
                         the operator no longer holds that group), and it has no personal group \
                         of its own; a linked agent writes only where its operator writes. \
                         Nothing was written"
                    );
                    tracing::error!(
                        target: "tenancy.scoped_write",
                        tool = tool_name,
                        author = %agent_id,
                        "{why}"
                    );
                    return Err(crate::errors::db_caller_error(
                        epigraph_db::DbError::OperatorScopeRefused { message: why },
                    ));
                }
                return Err(refuse(format!(
                    "the ingesting agent ({agent_id}) holds no LIVE membership of its personal \
                     group, which owns every row this ingest would write. Refusing: if the \
                     membership was revoked, restoring it is an operator decision, and nothing on \
                     this path will restore it. Nothing was written"
                )));
            };
            own
        };
        // 4. The trigger's own writer-scope question on the resolved group
        //    (bound writer, writer scope, attribution; the author IS the
        //    writer here). OPL02 by name for a live link that is not acting
        //    (its fallback is a group its operator does not write), an author
        //    bound only through the client allowlist (149: its own group is
        //    not one its human writes), and a retired link under the valve.
        epigraph_db::AgentRepository::require_writer_authority(tx, agent_id, Some(agent_id), group)
            .await
            .map_err(crate::errors::db_caller_error)?;
        // 5. The stamp must carry the owner group (077's WITH CHECK).
        let writable =
            epigraph_db::GroupMembershipRepository::session_can_write_group_conn(tx, group)
                .await
                .map_err(|e| {
                    crate::errors::internal_error_logged(
                        format!("{tool_name}: writable-group check"),
                        e,
                    )
                })?;
        if !writable {
            return Err(refuse(format!(
                "the ingesting agent ({agent_id}) holds a live but READ-ONLY membership of the \
                 group that owns every row this ingest would write ({group}: its own personal \
                 group, or its operator's when it is operator-linked), so every INSERT would be \
                 refused. Nothing was written"
            )));
        }
        // 6. The caller's visibility (docs/tenancy/claim-visibility-controls.md).
        //    The home group checked above owns a private or public ingest. A
        //    TEAM ingest is owned by the team, so the trigger's writer scope and
        //    077's WITH CHECK are asked again of the team, on this transaction
        //    (begun with the D-V3 grant when the author writes it through its
        //    human).
        if let Some(team) = resolution.team() {
            epigraph_db::AgentRepository::require_writer_authority(
                tx,
                agent_id,
                Some(agent_id),
                team,
            )
            .await
            .map_err(crate::errors::db_caller_error)?;
            let team_writable =
                epigraph_db::GroupMembershipRepository::session_can_write_group_conn(tx, team)
                    .await
                    .map_err(|e| {
                        crate::errors::internal_error_logged(
                            format!("{tool_name}: team writable-group check"),
                            e,
                        )
                    })?;
            if !team_writable {
                return Err(refuse(format!(
                    "the ingesting agent ({agent_id}) cannot write team {team} on this \
                     transaction. Nothing was written"
                )));
            }
        }
        Ok(resolution.decl(group))
    }
}

async fn begin_ingest_tx<'p>(
    server: &'p EpiGraphMcpFull,
    author: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
    grant: Option<&epigraph_db::TeamWriteGrant>,
) -> Result<IngestTx<'p>, McpError> {
    if server.scoped.is_none() {
        if let Some(reason) = server.privileged_pool {
            tracing::info!(
                tool = tool_name,
                reason = reason,
                "document ingest on a DECLARED privileged pool: a plain transaction, no stamp"
            );
            let tx = server.pool.begin().await.map_err(|e| {
                crate::errors::internal_error_logged(
                    format!("{tool_name}: could not begin a transaction"),
                    e,
                )
            })?;
            return Ok(IngestTx::Privileged(tx));
        }
    }
    Ok(IngestTx::Stamped(
        crate::claim_helper::begin_author_stamped_tx_for(server, author, tool_name, grant).await?,
    ))
}

/// SQLSTATE 42501 — `new row violates row-level security policy`.
fn is_rls_refusal(e: &epigraph_db::DbError) -> bool {
    matches!(
        e,
        epigraph_db::DbError::QueryFailed { source: sqlx::Error::Database(d) }
            if d.code().as_deref() == Some("42501")
    )
}

/// One plan edge the walk wrote, carried out of the walk's transaction so its
/// DS factor can be wired post-commit on a transaction of its own.
struct PlanEdgeForDs {
    edge_id: Uuid,
    was_created: bool,
    source_id: Uuid,
    source_type: String,
    target_id: Uuid,
    target_type: String,
    relationship: String,
}

/// A plan edge the planner emitted as an author's attribution of one of the
/// document's claims (`author_placeholder -asserts-> claim`, resolved by the
/// walk to the author's agent). The walk writes it with the ingest-written
/// marker (`epigraph_db::ingest_written`), naming its write identity, and
/// only when its target is a claim THIS walk persisted (in `id_map`); no
/// other plan edge carries one.
fn is_author_attribution(edge: &epigraph_ingest::common::plan::PlannedEdge) -> bool {
    edge.source_type == "author_placeholder"
        && edge.relationship == "asserts"
        && edge.target_type == "claim"
}

/// The canonical document ingest. Every claim it CREATES is written with
/// `choice`; claims it converges onto keep their own tenancy.
///
/// `choice` is required, with no defaulted wrapper (operator ruling,
/// 2026-11-10: the claims of a paper an agent ingests go to its team, never
/// silently public). The MCP tools pass what the caller named, and
/// [`epigraph_core::VisibilityChoice::Default`] when it named nothing, which
/// resolves D-V1: the author's default team if still writable, else its
/// human's under the same condition, else its only writable team, else
/// private. The operator `ingest-document` CLI does the same from its
/// `--visibility` / `--group-id` flags. A test harness that needs a public
/// paper passes [`epigraph_core::VisibilityChoice::Public`].
///
/// `choice` scopes the CLAIMS only. The `papers` row (title, DOI, journal),
/// the author agents and the `processed_by` stamp carry no tenancy and stay
/// world-readable whatever `choice` is. See
/// docs/tenancy/claim-visibility-controls.md section 3.1 and
/// docs/tenancy/papers-tenancy-followup.md.
pub async fn do_ingest_document(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
    choice: epigraph_core::VisibilityChoice,
) -> Result<CallToolResult, McpError> {
    do_ingest_document_reporting(server, viewer, extraction, auth, choice)
        .await
        .map(|(result, _)| result)
}

/// Where an ingest put the claims it created: what
/// [`do_ingest_document_reporting`] actually resolved and wrote with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestTenancy {
    /// `"team"`, `"private"` or `"public"`.
    pub visibility: &'static str,
    /// The owning group of every claim the ingest created.
    pub owner_group_id: Uuid,
    /// D-V1's note when a default fell back to private.
    pub note: Option<String>,
}

/// [`do_ingest_document`], also returning the [`IngestTenancy`] its new claims
/// were written with, so a synchronous caller (the operator `ingest-document`
/// CLI) can tell its operator where the paper's claims landed. The response
/// itself is unchanged (spec section 3.1).
///
/// # Errors
/// Every error of [`do_ingest_document`].
#[allow(clippy::too_many_lines)]
pub async fn do_ingest_document_reporting(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
    choice: epigraph_core::VisibilityChoice,
) -> Result<(CallToolResult, IngestTenancy), McpError> {
    // D9 writer-side verbatim re-verification: when the extraction carries
    // `source_text`, every span-backed paragraph's stored `text` must equal the
    // bytes its span points at. Fail closed before any DB write so paraphrase
    // drift can never reach a verbatim_v2 node. No-op for Tier 2 (no source_text).
    epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
        .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;

    // Declared-axis guard (issue #222): reject a malformed axis before any DB
    // write. Fail closed — silently degrading to the binary frame would record a
    // belief about TRUE for a claim the caller placed on a labeled hypothesis.
    epigraph_ingest::document::axis::validate_axes(extraction)
        .map_err(|e| invalid_params(format!("axis declaration invalid: {e}")))?;
    refuse_lineage_relationships(extraction)?;
    refuse_bad_author_ids(extraction)?;

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    // Author = the request's principal (batch H-b, D1); signer = this server's
    // key, recorded on evidence as its `signer_id` (see `Evidence::agent_id`).
    let author = server.write_identity(auth, viewer).await?;
    let agent_id = author.agent_id();
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let signer_typed = AgentId::from_uuid(server.signer_agent_id().await?);
    let pub_key = server.signer.public_key();
    // Every edge the walk INSERTS (authored, asserts, the plan's relationships,
    // processed_by) is attested at INSERT by this server's key (R-49/R-50); a
    // dedup hit returns the existing edge unchanged.
    let edge_key = Some(server.edge_signing_key().await?);

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);
    // Attached to every claim this paper asserts so `query_claims_by_label`
    // and `recompute_beliefs(labels=[...])` can address a paper's full claim
    // set (backlog c9d12a95: neither could ever find it before the `doi:`
    // label existed), followed by the caller's own `extraction.labels`
    // (backlog b6b5ac28: they were silently dropped before).
    // Validated ONCE, here, before the paper node or any claim is written.
    // `doi` and the caller labels come from the extraction, and the per-claim
    // `update_labels` call that applies them runs INSIDE the plan walk — so a
    // `$` in either would fail the ingest partway through, with the paper row
    // and some claims already landed. Refusing up front keeps the "reject and
    // write nothing" contract the rest of this branch establishes.
    let claim_labels = ingest_claim_labels(extraction, &doi)?;

    // ── 1. Get-or-create paper node ──
    // (Pipeline-version gate removed: deterministic node ids handle idempotency
    //  so re-ingesting an abstract then the full paper is safe — structural nodes
    //  by document-scoped id, atoms by content hash.
    //  Use ingest_document_spine → ingest_document_inline for the two-phase
    //  flow that avoids redundant LLM atomization.)
    let paper_id = PaperRepository::get_or_create(
        pool,
        &doi,
        Some(&paper_title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    // ── 2. ONE transaction for the whole walk, stamped from the INGESTING agent ──
    //
    // Every claim below is authored by the write identity and owned by `decl`
    // (that agent's personal group, or its operator's when it is
    // operator-linked; see `IngestTx::owner_decl`), so that agent's viewer is the one
    // migration 077's `WITH CHECK` asks about — the sibling-tool identity, which
    // here IS the row's author (contrast the workflow executor, which authors as
    // its own system agent).
    //
    // Before this, every statement in the walk ran on `server.pool`: on a
    // cleanly-migrated schema the first claim INSERT was refused, AFTER the
    // author agents and their `authored` edges had already committed — and
    // because this runs in a DETACHED task, the caller had been told "queued"
    // and nobody saw the refusal. Now the walk lands whole or leaves nothing,
    // and a retry converges: document-scoped nodes are `ON CONFLICT (id)` on a
    // deterministic id, atoms dedupe on `content_hash`, edges on the triple, and
    // the fresh-UUID trace/evidence rows are written only for a claim that was
    // new in THIS transaction, so a rolled-back attempt leaves none behind.
    //
    // `papers` stays on the pool: it has no row-level security, and
    // `ensure_paper_node` already created the row synchronously before this
    // task was spawned, so the call above is an idempotent read of it.
    let resolution = resolve_ingest_visibility(server, author.agent_id(), choice).await?;
    let mut tx = begin_ingest_tx(server, author, "ingest_document", resolution.grant()).await?;

    // ── 3. Ensure author agents + agent --authored--> paper ──
    // An author with an `agent_id` IS that existing agent (backlog 94cc12db).
    // Every other author gets a deterministic ed25519 keypair via
    // `did_key_for_author` — same name maps to the same agent across papers,
    // which is how co-authorship lights up in the graph — and is never
    // attached to another agent that merely shares the name (those are
    // reported as `candidates`; see `tools::ingest_authors`). Affiliations and roles are
    // not yet first-class on Agent and remain in the extraction JSON
    // pending an AgentRepository properties surface.
    let mut author_responses = Vec::new();
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    // Defensive backstop (backlog a55aac45): hierarchical extraction sometimes
    // drops `source.authors` (empty array), so a paper would be recorded with no
    // real authors. When the structured list has no real author (empty or
    // placeholder-only), fall back to parsing the author byline out of the raw
    // `source_text` body (Tier 1 only; Tier 2 has no `source_text` and silently
    // no-ops). The parser is conservative and
    // returns empty when unsure — it never fabricates a placeholder author, so
    // the empty-fallback case preserves the pre-existing behavior exactly.
    //
    // Gated on `source_type` Paper/Textbook: only those follow the
    // title→authors→abstract convention the byline parser assumes. Reports,
    // legal, transcripts etc. put institution/label lines where a byline would
    // be, so running the parser there is pure false-positive downside.
    let byline_eligible = matches!(
        extraction.source.source_type,
        epigraph_ingest::document::schema::SourceType::Paper
            | epigraph_ingest::document::schema::SourceType::Textbook
    );
    // "No real author" covers an empty list AND a list of only placeholder
    // names ("Authors Not Specified", "Unknown", ...): either way the byline
    // backstop gets its chance (backlog a55aac45, arXiv:2606.16707).
    //
    // Index alignment with the planner's `author_placeholder` edges (keyed by
    // `author_index` into `author_agent_map`):
    // - structured list in use: the planner and the loop below skip the SAME
    //   original indices (`AuthorEntry::is_placeholder`), so every planned
    //   `asserts` edge maps to a real author's agent;
    // - byline fallback in use: every structured entry was a placeholder, so the
    //   planner emitted NO `author_placeholder` edges; the fallback's indices are
    //   never looked up for `asserts`, and byline authors get `authored → paper`
    //   only — the same as the empty-list fallback.
    let has_real_author = extraction
        .source
        .authors
        .iter()
        .any(|a| !a.is_placeholder());
    let parsed_fallback;
    let authors: &[epigraph_ingest::common::schema::AuthorEntry] = if !has_real_author
        && byline_eligible
    {
        parsed_fallback = extraction
            .source_text
            .as_deref()
            .map(epigraph_ingest::document::byline::parse_byline_authors)
            .unwrap_or_default();
        if parsed_fallback.is_empty() {
            tracing::warn!(
                paper = %paper_title,
                "ingest_document: source.authors empty or placeholder-only and no byline recovered from body; paper will have no author agents"
            );
        } else {
            tracing::info!(
                paper = %paper_title,
                count = parsed_fallback.len(),
                "ingest_document: source.authors empty or placeholder-only; recovered authors from body byline fallback"
            );
        }
        &parsed_fallback
    } else {
        &extraction.source.authors
    };
    // Explicit `agent_id`s, the name-derived default, migration 148's
    // system-identity skips and the per-author report: `tools::ingest_authors`.
    let resolved = crate::tools::ingest_authors::resolve_document_authors(
        &mut tx,
        viewer,
        authors,
        agent_id,
        paper_id,
        "ingest_document",
        &paper_title,
    )
    .await?;
    // The document's authors as THIS walk resolved them, in the extraction's
    // order: written into every ingest record, and on the record of a claim
    // this walk creates, the claim's primary authors (`ClaimIngestRecord::
    // authors`), fixed at creation whatever a later ingest adds.
    let mut recorded_authors: Vec<(usize, Uuid)> =
        resolved.iter().map(|r| (r.idx, r.agent_id)).collect();
    recorded_authors.sort_by_key(|(idx, _)| *idx);
    let recorded_authors: Vec<Uuid> = recorded_authors.into_iter().map(|(_, a)| a).collect();
    for r in resolved {
        let author = &authors[r.idx];
        let (_row, _was_created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut tx,
            edge_key,
            "ingest_document",
            agent_id,
            r.agent_id,
            "agent",
            paper_id,
            "paper",
            "authored",
            Some(crate::tools::ingest_authors::authored_edge_properties(
                &r, author, agent_id,
            )),
        )
        .await
        .map_err(internal_error)?;
        // The plan's per-claim `asserts` edges come from this map: an author
        // the ingester does not speak for is not in it, so it gets `authored`
        // only (`tools::ingest_authors`, the explicit-author rule).
        if r.asserts {
            author_agent_map.insert(r.idx, r.agent_id);
        }
        author_responses.push(r.report);
    }

    // ── 4. Walk planned claims: dedup → claim/trace/evidence/embed ──
    let source_url = if doi.starts_with("10.") {
        format!("https://doi.org/{doi}")
    } else {
        format!("doi:{doi}")
    };

    let mut claim_ids: Vec<String> = Vec::new();
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut embed_queue: Vec<(Uuid, String)> = Vec::new();
    let mut dedup_count = 0_usize;
    let mut converged_unlabelled = 0_usize;
    let mut caller_labels_withheld = 0_usize;
    let mut ds_entries: Vec<BatchDsEntry> = Vec::new();

    // Tenancy declaration (PR-16), hoisted above the loop -- see
    // `persist_planned_claim`'s `decl` parameter for why. `TenancyDecl` is
    // `Copy`, so passing it per iteration costs nothing.
    //
    // On the STAMPED transaction, and through a helper that never mints:
    // `IngestTx::owner_decl`. The earlier comment here said "an author with no
    // live writable group was already refused by `begin_author_stamped_tx`" —
    // true, and the wrong discriminator: an author live in a TEAM group but
    // revoked in its personal one passed that check, and
    // `default_decl_for_author`'s mint path then revived the revoked admin
    // membership inside this transaction. See `owner_decl`.
    let decl = tx
        .owner_decl(agent_id, "ingest_document", &resolution)
        .await?;
    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let methodology = methodology_from_planned(planned);
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            planned.content.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        // Override generated id with the planner's deterministic UUID.
        claim.id = ClaimId::from_uuid(planned.id);
        // Bind the PLANNER's hash, not `hash(content)`: for document-scoped
        // nodes it folds in the artifact seed (see `ids::compound_content_hash`).
        claim.content_hash = planned.content_hash;
        claim.signature = Some(
            server
                .signer
                .sign_entity(epigraph_crypto::SignedEntity::Claim, &claim.content_hash),
        );

        let (persisted_id, resolved_to_existing, known_author) = persist_planned_claim(
            &mut tx,
            &claim,
            planned,
            agent_id,
            signer_typed.as_uuid(),
            TruthValue::clamped(raw_truth),
            decl,
        )
        .await?;
        // Idempotent add: also runs on the dedup branch below, so an atom
        // shared across papers (convergence) picks up every paper's label —
        // when this author may write it; see `label_resolved_claim`.
        if resolved_to_existing {
            let labels = labels_for_resolved_claim(
                &mut tx,
                viewer,
                persisted_id,
                known_author,
                agent_id,
                &claim_labels,
            )
            .await?;
            if !label_resolved_claim(&mut tx, persisted_id, labels).await? {
                converged_unlabelled += 1;
            } else if labels.len() < claim_labels.len() {
                caller_labels_withheld += 1;
            }
        } else {
            ClaimRepository::update_labels_conn(&mut tx, persisted_id, &claim_labels, &[])
                .await
                .map_err(internal_error)?;
        }
        if resolved_to_existing {
            let (_row, _was_created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
                &mut tx,
                edge_key,
                "ingest_document",
                agent_id,
                paper_id,
                "paper",
                persisted_id,
                "claim",
                "asserts",
                Some(planned.properties.clone()),
            )
            .await
            .map_err(internal_error)?;
            // The ingest record: this walk converged on an existing claim.
            epigraph_db::ClaimIngestRepository::record_signed_conn(
                &mut tx,
                edge_key,
                paper_id,
                persisted_id,
                agent_id,
                false,
                &recorded_authors,
                "ingest_document",
                &pipeline_version,
            )
            .await
            .map_err(internal_error)?;
            id_map.insert(planned.id, persisted_id);
            claim_ids.push(persisted_id.to_string());
            dedup_count += 1;
            continue;
        }

        // Persist hierarchy metadata (level, section, source_type, generality)
        // from the ingest plan onto the new claim's `properties` column.
        ClaimRepository::set_properties_conn(
            &mut tx,
            ClaimId::from_uuid(persisted_id),
            planned.properties.clone(),
        )
        .await
        .map_err(internal_error)?;

        // New claim: write the supporting evidence and reasoning trace.
        let evidence_text = planned
            .supporting_text
            .as_deref()
            .unwrap_or(&planned.content);
        let formatted_evidence =
            format!("Source: {paper_title} (DOI: {doi}). Passage: '{evidence_text}'");
        let evidence_hash = ContentHasher::hash(formatted_evidence.as_bytes());
        let mut evidence = Evidence::new(
            signer_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: format!("level_{}", planned.level),
                page_range: None,
            },
            Some(formatted_evidence),
            claim.id,
        );
        evidence.signature = Some(
            server
                .signer
                .sign_entity(epigraph_crypto::SignedEntity::Evidence, &evidence_hash),
        );

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!(
                "Extracted from '{paper_title}' (DOI: {doi}); level {} ({})",
                planned.level,
                level_label(planned.level),
            ),
        );

        ReasoningTraceRepository::create(&mut *tx, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&mut *tx, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id_conn(&mut tx, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let (_row, _was_created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut tx,
            edge_key,
            "ingest_document",
            agent_id,
            paper_id,
            "paper",
            persisted_id,
            "claim",
            "asserts",
            Some(planned.properties.clone()),
        )
        .await
        .map_err(internal_error)?;

        // The ingest record: this walk CREATED the claim.
        epigraph_db::ClaimIngestRepository::record_signed_conn(
            &mut tx,
            edge_key,
            paper_id,
            persisted_id,
            agent_id,
            true,
            &recorded_authors,
            "ingest_document",
            &pipeline_version,
        )
        .await
        .map_err(internal_error)?;

        embed_queue.push((persisted_id, planned.content.clone()));

        // Atoms (level 3) are the units we trust to carry CDST evidence.
        if planned.level == 3 {
            ds_entries.push(BatchDsEntry {
                claim_id: persisted_id,
                confidence,
                weight,
                evidence_type: planned.evidence_type.clone(),
                // Declared labeled axis, or None for the binary frame (#222).
                axis: planned.axis.clone(),
            });
        }

        id_map.insert(planned.id, persisted_id);
        claim_ids.push(persisted_id.to_string());

        // Touch source_url (kept for parity with V2 evidence formatting; the
        // current EvidenceType::Literature already carries the DOI).
        let _ = &source_url;
    }

    // ── 5. Plan edges (decomposes_to / section_follows / supports / authored placeholders) ──
    let mut relationships_created = 0_usize;
    let mut wired_edges: Vec<PlanEdgeForDs> = Vec::new();
    for edge in &plan.edges {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        // Filter self-loops introduced by content-hash dedup collapsing
        // distinct planned UUIDs onto the same persisted claim. Since
        // structural nodes keep their document-scoped ids, the old
        // paragraph-equals-its-sole-atom collapse no longer happens; this
        // still guards atom-to-atom collapse within one document. The
        // semantically correct outcome is a no-op decomposition; the DB
        // would otherwise reject this with edges_no_self_loop.
        if src == tgt && src_type == edge.target_type {
            continue;
        }

        // An author's attribution is an ingest-written edge (the card and
        // the provenance reads trust it by its marker); every other plan edge
        // is written without the marker, a smuggled one dropped.
        let (row, was_created) =
            if is_author_attribution(edge) && id_map.contains_key(&edge.target_id) {
                epigraph_db::create_ingest_written_edge_if_absent_conn(
                    &mut tx,
                    edge_key,
                    "ingest_document",
                    agent_id,
                    src,
                    &src_type,
                    tgt,
                    &edge.target_type,
                    &edge.relationship,
                    Some(edge.properties.clone()),
                )
                .await
            } else {
                EdgeRepository::create_if_absent_including_retracted_signed_conn(
                    &mut tx,
                    edge_key,
                    src,
                    &src_type,
                    tgt,
                    &edge.target_type,
                    &edge.relationship,
                    Some(epigraph_db::without_ingest_marker(edge.properties.clone())),
                    None,
                    None,
                )
                .await
            }
            .map_err(internal_error)?;
        relationships_created += usize::from(was_created);

        // The edge's DS factor is wired AFTER the walk commits (step 6), on its
        // own stamped transaction. Record what that needs; the helper filters
        // non-epistemic and non-claim edges itself.
        wired_edges.push(PlanEdgeForDs {
            edge_id: row.id,
            was_created,
            source_id: src,
            source_type: src_type,
            target_id: tgt,
            target_type: edge.target_type.clone(),
            relationship: edge.relationship.clone(),
        });
    }

    // ── 5b. Mark paper as processed by this pipeline — INSIDE the walk ──
    // Idempotent PER STAMP: the first ingest at a given `pipeline_version`
    // stamps the edge and re-runs at that version (full paper after abstract,
    // or ingest_document_spine + ingest_document_inline) write none, while each
    // chunk of a chunked ingest (`...:ch{n}`) writes its own. Deduplicating on
    // the (paper, agent, processed_by) triple alone kept only the FIRST chunk's
    // stamp (G8 review).
    //
    // In the same transaction as the claims on purpose: `processed_by` is what
    // `check_already_ingested` reports, and this path runs DETACHED, so that
    // edge is the caller's only way to learn whether the queued ingest landed.
    // Written with the walk, it exists if and only if the walk committed.
    EdgeRepository::create_processed_by_stamp_if_absent_signed_conn(
        &mut tx,
        edge_key,
        paper_id,
        agent_id,
        &pipeline_version,
        "ingest_document",
    )
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(|e| {
        crate::errors::internal_error_logged("ingest_document: could not commit", e)
    })?;

    // ── 6. DS wiring: edge factors + per-atom BBAs, POST-COMMIT, best-effort ──
    //
    // Its own transaction, stamped from the same author, for the reason
    // `workflow_ingest::execute_workflow_ingest_with_inserted` records: the DS
    // half is best-effort by this tool's contract, so a DS failure must not roll
    // back a document that landed. Inside it the per-edge and per-entry work is
    // SAVEPOINT-wrapped by `auto_wire_edge_if_epistemic` / `auto_wire_ds_batch`,
    // so one bad entry does not abort the rest — and because this connection IS
    // inside a transaction, their `conn.begin()` is a SAVEPOINT, not the bare
    // `BEGIN` a pooled checkout would have turned it into.
    //
    // On the unstamped pool this half was refused at `claim_frames` on BOTH
    // schema configurations, so `claims_ds_wired` was never non-zero there.
    let (claims_ds_wired, ds_frame_id) =
        match begin_ingest_tx(server, author, "ingest_document_ds", resolution.grant()).await {
            Ok(mut ds_tx) => {
                for e in &wired_edges {
                    ds_auto::auto_wire_edge_if_epistemic(
                        &mut ds_tx,
                        viewer,
                        e.was_created,
                        e.edge_id,
                        e.source_id,
                        &e.source_type,
                        e.target_id,
                        &e.target_type,
                        &e.relationship,
                        agent_id,
                    )
                    .await;
                }
                let wired = if ds_entries.is_empty() {
                    (None, None)
                } else {
                    match ds_auto::auto_wire_ds_batch(&mut ds_tx, viewer, &ds_entries, agent_id)
                        .await
                    {
                        Ok((fid, count)) => (Some(count), Some(fid.to_string())),
                        Err(e) => {
                            tracing::warn!("ds auto-wire batch failed: {e}");
                            (None, None)
                        }
                    }
                };
                match ds_tx.commit().await {
                    Ok(()) => wired,
                    Err(e) => {
                        tracing::warn!(
                            paper_id = %paper_id,
                            "ingest_document ds wiring could not commit: {e}. The document is \
                             stored; its atoms carry no BBA until a recompute reaches them"
                        );
                        (None, None)
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    paper_id = %paper_id,
                    "ingest_document ds wiring skipped: {}. The document is stored and intact",
                    e.message
                );
                (None, None)
            }
        };

    // ── 8. Detach embeddings so the MCP response returns immediately after commit ──
    // All DB writes are done. Embed in the background so the caller is not blocked
    // by N × ~0.8 s OpenAI calls. The response reports the number QUEUED (0 when
    // this server has no embedding provider), never a number stored: nothing has
    // been stored when it is built. The task logs stored against queued.
    let queued = spawn_created_claim_embeds(
        server,
        agent_id,
        resolution.grant(),
        embed_queue,
        "ingest_document",
    );

    let tenancy = IngestTenancy {
        visibility: resolution.label(),
        owner_group_id: decl.owner_group_bind().ok_or_else(|| {
            crate::errors::internal_error_text(
                "ingest_document: the claims' owner group did not resolve",
            )
        })?,
        note: resolution.note(),
    };
    let result = success_json(&IngestDocumentResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        synthesized_key: is_synthetic_key(&doi),
        doi,
        authors: author_responses,
        ingested_by: agent_id.to_string(),
        claims_ingested: claim_ids.len() - dedup_count,
        claims_embedding_queued: queued,
        claims_embedded: queued,
        claims_skipped_dedup: dedup_count,
        relationships_created,
        claims_ds_wired,
        ds_frame_id,
        converged_claims_unlabelled: converged_unlabelled,
        converged_claims_caller_labels_withheld: caller_labels_withheld,
        already_ingested: claim_ids.len() == dedup_count && dedup_count > 0,
    })?;
    Ok((result, tenancy))
}

/// Embed the claims a document walk CREATED, post-commit and best-effort, in a
/// task on the server's tracker (`crate::background`).
///
/// Each vector is stored as the walk's AUTHOR, with the team-write grant the
/// walk wrote under (`claim_helper::embed_claim_author_stamped_with_grant`),
/// not through `McpEmbedder::embed_and_store`. That path resolves a claim's
/// author by reading the claim as PUBLIC, and a document ingest that names no visibility
/// lands in the author's team or private, never public (backlog 46902f71): on
/// such a claim it found no author and stored nothing, and only a WARN said so.
/// The walk already knows the author and the grant, as
/// `workflow_ingest::store_ingest_embedding` knows its author.
///
/// The queue holds only claims this walk created (a converged claim is skipped
/// before it is queued), so every row in it is the author's to write.
///
/// Returns how many embeddings were QUEUED (backlog fdacc14f): 0 when the queue
/// is empty or this server has no embedding provider
/// (`McpEmbedder::embeddings_disabled`), in which case no task is spawned,
/// because every provider call would fail. The task logs how many it stored
/// against how many were queued when it finishes.
fn spawn_created_claim_embeds(
    server: &EpiGraphMcpFull,
    author: Uuid,
    grant: Option<&epigraph_db::TeamWriteGrant>,
    queue: Vec<(Uuid, String)>,
    tool_name: &'static str,
) -> usize {
    if queue.is_empty() {
        return 0;
    }
    if server.embedder.embeddings_disabled() {
        tracing::warn!(
            tool = tool_name,
            claims = queue.len(),
            "embeddings are disabled on this server (no provider key), so the claims this \
             ingest created carry no vector until the maintenance backfill reaches them"
        );
        return 0;
    }
    let queued = queue.len();
    // A clone shares the parent's pools and tracker; the grant is owned for
    // the same `'static` reason.
    let bg = server.clone();
    let grant = grant.cloned();
    server.background_tasks().spawn(async move {
        let mut stored = 0usize;
        for (id, content) in queue {
            // A server DECLARED to run on a privileged pool (the operator
            // `ingest-document` CLI on `MaintenancePool`, mirroring
            // `begin_ingest_tx`) has no tenancy context to stamp: the
            // embedder's own declared privileged store applies there.
            let one = if bg.scoped.is_none() && bg.privileged_pool.is_some() {
                bg.embedder.embed_and_store(id, &content).await
            } else {
                crate::claim_helper::embed_claim_author_stamped_with_grant(
                    &bg,
                    author,
                    grant.as_ref(),
                    id,
                    &content,
                    None,
                    tool_name,
                )
                .await
            };
            if one {
                stored += 1;
            }
        }
        if stored == queued {
            tracing::info!(
                tool = tool_name,
                stored,
                queued,
                "background embedding done"
            );
        } else {
            tracing::warn!(
                tool = tool_name,
                stored,
                queued,
                "background embedding stored fewer vectors than it queued; the rest carry no \
                 vector until the maintenance backfill reaches them"
            );
        }
    });
    queued
}

/// URN prefix for a synthesized (non-DOI) document identity key.
const SYNTHETIC_KEY_PREFIX: &str = "urn:epigraph:doc:";

// Values callers pass to mean "this document has no DOI" are treated as
// ABSENT, not as an identity: keying on them collapsed every DOI-less document
// onto a single shared `papers` row (issue #356 — one node had accrued 1244
// claims from at least four unrelated sources, with their author lists
// unioned). The list lives in epigraph-core so the belief engine's source key
// rejects exactly the same values.
use epigraph_core::domain::evidence::is_placeholder_id;

/// Legible-but-bounded slug for the human-readable half of a synthetic key:
/// lowercased, non-alphanumerics collapsed to single `-`, capped at 48 bytes on
/// a char boundary. Only a debugging aid — uniqueness comes from the hash half.
fn key_slug(s: &str) -> String {
    let mut out = String::with_capacity(48);
    let mut pending_dash = false;
    for ch in s.chars() {
        if out.len() >= 48 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    out
}

/// Synthesize a stable identity key for a document with no usable DOI.
///
/// Shape: `urn:epigraph:doc:<slug>-<16 hex>`. The hash half is the identity;
/// the slug is there so the key is recognisable in logs and `doi:<key>` labels.
///
/// Two hashing bases, in priority order:
///
/// 1. `source.external_id` — the caller's own run/entry id. Identity is the
///    external id ALONE, so a re-ingest that corrects the title or adds authors
///    converges on the same node.
/// 2. Otherwise the source metadata tuple (title, type, journal, year, sorted
///    authors). Deterministic, but a title edit yields a new node — which is
///    why `external_id` is the documented path for authored records.
fn synthetic_document_key(source: &DocumentSource) -> String {
    let (basis, slug_seed) = match source.external_id.as_deref() {
        Some(ext) if !is_placeholder_id(ext) => {
            (format!("external_id\u{1f}{}", ext.trim()), ext.to_string())
        }
        _ => {
            let mut authors: Vec<String> = source
                .authors
                .iter()
                .map(|a| a.name.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            authors.sort_unstable();
            authors.dedup();
            let basis = format!(
                "title\u{1f}{}\u{1e}type\u{1f}{:?}\u{1e}journal\u{1f}{}\u{1e}year\u{1f}{}\u{1e}authors\u{1f}{}",
                source.title.trim().to_ascii_lowercase(),
                source.source_type,
                source.journal.as_deref().unwrap_or("").trim(),
                source.year.map_or_else(String::new, |y| y.to_string()),
                authors.join(","),
            );
            (basis, source.title.clone())
        }
    };
    let digest = ContentHasher::to_hex(&ContentHasher::hash(basis.as_bytes()));
    let slug = key_slug(&slug_seed);
    if slug.is_empty() {
        format!("{SYNTHETIC_KEY_PREFIX}{}", &digest[..16])
    } else {
        format!("{SYNTHETIC_KEY_PREFIX}{slug}-{}", &digest[..16])
    }
}

/// True when `key` was synthesized by [`synthetic_document_key`] rather than
/// being a real DOI/URI the caller supplied.
fn is_synthetic_key(key: &str) -> bool {
    key.starts_with(SYNTHETIC_KEY_PREFIX)
}

/// The full label set one ingest call applies to every claim it writes or
/// resolves to: `doi:<doi>` first, then the caller's `extraction.labels`
/// (deduplicated, order-preserving). With no caller labels this is exactly
/// `[doi:<doi>]`, the set the writer applied before caller labels existed.
/// `doi:<doi>` is always entry 0: [`labels_for_resolved_claim`] keeps only that
/// entry for a resolved row another agent authored.
///
/// Validated HERE so every entry point fails closed before any write: the two
/// detached handlers call it before `ensure_paper_node` writes the `papers`
/// row (a refusal inside the spawned walk would reach only the server log,
/// after the caller was told `queued`), and both cores call it again before
/// their first write, for the callers that reach a core directly (the spine
/// handler, the operator `ingest_document` CLI).
fn ingest_claim_labels(
    extraction: &DocumentExtraction,
    doi: &str,
) -> Result<Vec<String>, McpError> {
    let mut labels = vec![format!("doi:{doi}")];
    for label in &extraction.labels {
        if !labels.contains(label) {
            labels.push(label.clone());
        }
    }
    epigraph_db::reject_unexpanded_labels(&labels).map_err(db_caller_error)?;
    Ok(labels)
}

// The document-key normalizer is shared with the REST paper routes
// (`epigraph-api` `routes/papers.rs`), so both transports key `papers.doi`
// identically (backlog 90756d26). See `epigraph_db::repos::paper`.
pub(crate) use epigraph_db::repos::paper::canonical_document_key;

/// Find the `papers` row a caller-supplied document key names, trying each of
/// [`epigraph_db::repos::paper::document_key_spellings`] in order: the
/// [`canonical_document_key`] first, then the key as given (trimmed), then,
/// for a bare DOI, each legacy resolver-prefix spelling of it. A row written
/// under a resolver-URL spelling before keys were canonicalized is thus found
/// by that spelling AND by the bare DOI, which is what the monitor's dedup
/// probe asks with.
pub(crate) async fn find_paper_by_document_key(
    pool: &sqlx::PgPool,
    raw: &str,
) -> Result<Option<epigraph_db::PaperRow>, McpError> {
    for spelling in epigraph_db::repos::paper::document_key_spellings(raw) {
        if let Some(row) = PaperRepository::find_by_doi(pool, &spelling)
            .await
            .map_err(internal_error)?
        {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

/// Resolve the identity key a document's `papers` row is keyed on.
///
/// Priority: real DOI → arXiv id parsed from `uri` → a DOI spelled as `uri` →
/// `external_id` (synthesized key) → plain `uri` → metadata-synthesized key.
/// A DOI given as a resolver URL or `doi:` (in `doi` or in `uri`) is keyed on
/// the bare DOI ([`canonical_document_key`]).
/// Placeholder DOIs/URIs/external ids (`"unknown"`, `"n/a"`, empty, …) are
/// treated as absent so they fall through instead of becoming a shared bucket.
///
/// `external_id` outranks a plain `uri` (backlog b69dfb91): a uri is where a
/// document lives, and several works can live at one (an ELN notebook page, a
/// repository landing page), while `external_id` is the caller's identity for
/// the record. Keyed on the uri, two works sharing one merged under one paper
/// node. A uri that IS an identifier (arXiv, DOI) still wins, as `doi` does.
/// Consequence: a document ingested before this change with both a plain uri
/// and an external_id was keyed on the uri, and re-ingesting it now keys a new
/// node. No lookup falls back to the old uri key, because that key may be the
/// merged node this rule exists to stop reusing.
fn resolve_doi(extraction: &DocumentExtraction) -> String {
    if let Some(d) = &extraction.source.doi {
        if !is_placeholder_id(d) {
            return canonical_document_key(d);
        }
        tracing::warn!(
            doi = %d,
            title = %extraction.source.title,
            "ingest: placeholder DOI treated as absent; synthesizing a stable document key (issue #356). Pass source.external_id to control this key."
        );
    }
    let has_external_id = extraction
        .source
        .external_id
        .as_deref()
        .is_some_and(|ext| !is_placeholder_id(ext));
    if let Some(uri) = &extraction.source.uri {
        if !is_placeholder_id(uri) {
            // Hand-rolled arXiv pattern: \d{4}\.\d{4,5}. It matches any digit
            // run, so against an external_id it counts only when the uri
            // names arXiv (host or `arXiv:` scheme); a date-shaped path
            // segment must not fabricate a shared arXiv key. Without an
            // external_id the legacy behaviour is kept so existing keys hold.
            let names_arxiv = !has_external_id || uri.to_ascii_lowercase().contains("arxiv");
            if let Some(arxiv) = find_arxiv_id(uri).filter(|_| names_arxiv) {
                return format!("10.48550/arXiv.{arxiv}");
            }
            let key = canonical_document_key(uri);
            if !has_external_id || epigraph_db::repos::paper::is_bare_doi(&key) {
                return key;
            }
        }
    }
    synthetic_document_key(&extraction.source)
}

fn find_arxiv_id(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    'outer: for start in 0..bytes.len() {
        if start + 9 > bytes.len() {
            return None;
        }
        // Need 4 digits, '.', then 4 or 5 digits.
        for i in 0..4 {
            if !bytes[start + i].is_ascii_digit() {
                continue 'outer;
            }
        }
        if bytes[start + 4] != b'.' {
            continue;
        }
        let mut tail = 0;
        while tail < 5 && start + 5 + tail < bytes.len() && bytes[start + 5 + tail].is_ascii_digit()
        {
            tail += 1;
        }
        if tail >= 4 {
            return Some(
                std::str::from_utf8(&bytes[start..start + 5 + tail])
                    .ok()?
                    .to_string(),
            );
        }
    }
    None
}

/// Persist one planned claim, routing on the identity class the PLANNER chose.
///
/// Returns `(persisted_id, resolved_to_existing, known_author)`.
/// `resolved_to_existing` means the row was already there with its provenance
/// (trace + evidence) written, so the caller must only wire the `asserts` edge
/// and must NOT clobber it. `known_author` is the row's author when this call
/// already knows it without another read: the ingesting agent for a row it
/// created, the existing row's author for an atom. It is `None` for a
/// document-scoped node the walk resolved to (`ON CONFLICT (id) DO NOTHING`
/// returns nothing about the existing row); see [`labels_for_resolved_claim`].
///
/// Two classes, per `epigraph_ingest::common::ids`:
///
/// * **document-scoped (COMPOUND, levels 0–2)** — thesis / section / paragraph.
///   `id = uuid_v5(COMPOUND_NAMESPACE, hash(text) ++ "{title}\u{1f}{path}")`, so
///   two papers with a section titled "Introduction" get two different ids *by
///   design*. Written with [`ClaimRepository::create_with_id_if_absent`], which
///   binds the caller's id and hash and resolves on `ON CONFLICT (id)`. This is
///   the same primitive `workflow_ingest` and `epigraph-ingest-executor`
///   already use; the document path was the sole holdout.
///
///   The legacy [`ClaimRepository::create`] instead re-resolves
///   `SELECT id FROM claims WHERE content_hash = $1`, discarding the planner's
///   id — that is what fused 70 papers onto one `Abstract` node and, through
///   `id_map`, remapped every planned structural edge onto it.
///
/// * **content-addressed (ATOM, level 3)** — `id = uuid_v5(ATOM_NAMESPACE,
///   hash(text))`. Convergence across papers IS the feature (it is how
///   cross-source corroboration finds agreement), so these stay on the
///   content-hash path unchanged.
#[allow(clippy::too_many_arguments)]
async fn persist_planned_claim(
    conn: &mut sqlx::PgConnection,
    claim: &Claim,
    planned: &PlannedClaim,
    agent_id: Uuid,
    // The server's signer agent: `claims.signer_id` of a row this call
    // INSERTS, next to the claim's signature (backlog 4ff87716). A row the
    // walk resolves to is never written.
    signer_id: Uuid,
    truth: TruthValue,
    // Tenancy declaration (PR-16): the owner group `IngestTx::owner_decl`
    // resolves (the ingesting agent's own personal group, or its operator's
    // when it is operator-linked), resolved ONCE by the caller above its loop. It was resolved here per
    // planned claim until review: an N-claim document then performed N
    // `pool.acquire()` calls and N identical `SELECT id FROM groups WHERE
    // did_key = ...` round trips for the same agent.
    // `epigraph-ingest-executor::execute_workflow_ingest_plan` already hoists
    // the identical lookup, with a comment saying exactly that; the two
    // siblings now agree.
    decl: epigraph_core::TenancyDecl,
) -> Result<(Uuid, bool, Option<Uuid>), McpError> {
    if planned.id_is_document_scoped() {
        let was_new = ClaimRepository::create_with_id_if_absent_signed_conn(
            &mut *conn,
            planned.id,
            &planned.content,
            &planned.content_hash,
            agent_id,
            truth,
            &[],
            decl,
            claim
                .signature
                .map(|signature| (claim.public_key, signature, signer_id)),
        )
        .await
        .map_err(internal_error)?;
        // Idempotency is now by id rather than by content hash: re-ingesting
        // the SAME document re-derives the same seed → the same id → conflict →
        // `was_new == false`. Narrow window: a run that dies between this insert
        // and the trace write below leaves the node without trace/evidence, and
        // the retry takes the reuse branch. The old `already_had_trace` probe
        // covered that; closing it again would cost a SELECT per claim.
        return Ok((planned.id, !was_new, was_new.then_some(agent_id)));
    }

    // Atom: content-addressed, so `create` dedupes on content_hash and
    // returns the existing row. Whether THIS call created the row is what its
    // INSERT reports (`create_signed_reporting_conn`), never inferred from the
    // row: an existing row is resolved to, never rewritten (no
    // `set_properties`, no trace or evidence hung on it) and never recorded as
    // this ingest's creation, whoever filed it and whether or not it has a
    // trace.
    //
    // The inferred signals this replaces each missed a case. "It has a trace"
    // missed a trace-less row; "another author wrote it" missed the SAME
    // agent's trace-less row: a workflow operation atom written as the
    // caller's own agent (same `atom_id` derivation, no trace), or a claim
    // the agent filed directly without one. Treated as new, the walk
    // overwrote that row's workflow metadata with this document's
    // level/section (breaking step versioning), hung this paper's trace on
    // it, and recorded `created_claim: true`, so the agent's own claim read as
    // the document's literature. On a stamped transaction such writes onto
    // another author's row were also refused by `claims_tenancy`'s WITH CHECK,
    // which took the whole document down (measured before the author signal
    // existed). `persisted_id != planned.id` still catches a hash collision
    // against some other claim.
    let (persisted, inserted) =
        ClaimRepository::create_signed_reporting_conn(&mut *conn, claim, decl, Some(signer_id))
            .await
            .map_err(internal_error)?;
    let persisted_id: Uuid = persisted.id.into();
    let persisted_author: Uuid = persisted.agent_id.into();
    Ok((
        persisted_id,
        !inserted || persisted_id != planned.id,
        Some(persisted_author),
    ))
}

fn methodology_from_planned(planned: &PlannedClaim) -> Methodology {
    match planned.methodology.as_deref() {
        Some("statistical" | "instrumental" | "computational") => Methodology::Instrumental,
        Some("deductive") => Methodology::Deductive,
        Some("inductive") => Methodology::Inductive,
        Some("visual_inspection") => Methodology::VisualInspection,
        Some("expert_elicitation") => Methodology::Heuristic,
        _ => Methodology::Extraction,
    }
}

const fn level_label(level: u8) -> &'static str {
    match level {
        0 => "thesis",
        1 => "section",
        2 => "paragraph",
        3 => "atom",
        _ => "unknown",
    }
}

/// Core spine ingest: thesis + sections + paragraphs (levels 0–2) only.
/// Atoms in the extraction are ignored; the agent atomizes only the NEW
/// paragraph paths returned here, then submits via `ingest_document_inline`.
///
/// Ordering guarantee: the builder iterates sections then paragraphs in
/// extraction order, so `new_paragraph_paths` is in document order.
///
/// `choice` is required, for the reason [`do_ingest_document`] gives: every
/// spine node it CREATES is written with it.
#[allow(clippy::too_many_lines)]
pub async fn do_ingest_document_spine(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &DocumentExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
    choice: epigraph_core::VisibilityChoice,
) -> Result<CallToolResult, McpError> {
    epigraph_ingest::document::structure::verify_extraction_verbatim(extraction)
        .map_err(|e| invalid_params(format!("verbatim guard failed: {e}")))?;

    // Declared-axis guard (issue #222): reject a malformed axis before any DB
    // write. Fail closed — silently degrading to the binary frame would record a
    // belief about TRUE for a claim the caller placed on a labeled hypothesis.
    epigraph_ingest::document::axis::validate_axes(extraction)
        .map_err(|e| invalid_params(format!("axis declaration invalid: {e}")))?;
    refuse_lineage_relationships(extraction)?;
    refuse_bad_author_ids(extraction)?;

    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    // Author = the request's principal (batch H-b, D1); signer = this server's
    // key, recorded on evidence as its `signer_id` (see `Evidence::agent_id`).
    let author = server.write_identity(auth, viewer).await?;
    let agent_id = author.agent_id();
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let signer_typed = AgentId::from_uuid(server.signer_agent_id().await?);
    let pub_key = server.signer.public_key();
    // Every edge the walk INSERTS (authored, asserts, the plan's relationships,
    // processed_by) is attested at INSERT by this server's key (R-49/R-50); a
    // dedup hit returns the existing edge unchanged.
    let edge_key = Some(server.edge_signing_key().await?);

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);
    let pipeline_version = effective_pipeline_version(extraction);
    // See do_ingest_document: `doi:<doi>` plus the caller's labels, attached to
    // every claim so label-based lookup (recompute_beliefs,
    // query_claims_by_label) can find this paper's set, and validated here for
    // the same reason — before the first write. This is the spine handler's
    // only label check: it calls this core synchronously.
    let claim_labels = ingest_claim_labels(extraction, &doi)?;

    // Atom planned IDs — skip these claims and any edges referencing them.
    let atom_planned_ids: HashSet<Uuid> = plan
        .claims
        .iter()
        .filter(|c| c.level == 3)
        .map(|c| c.id)
        .collect();

    // Map para planned ID → document path e.g. "sections[0].paragraphs[1]".
    // Builder iterates sections/paragraphs in extraction order so zipping is safe.
    let para_id_to_path: HashMap<Uuid, String> = {
        let mut map = HashMap::new();
        let mut level2_iter = plan.claims.iter().filter(|c| c.level == 2);
        for (si, section) in extraction.sections.iter().enumerate() {
            for (pi, _para) in section.paragraphs.iter().enumerate() {
                if let Some(pc) = level2_iter.next() {
                    map.insert(pc.id, format!("sections[{si}].paragraphs[{pi}]"));
                }
            }
        }
        map
    };

    // ── 1. Get-or-create paper node ──
    let paper_id = PaperRepository::get_or_create(
        pool,
        &doi,
        Some(&paper_title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    // ONE transaction for the spine walk, stamped from the ingesting agent —
    // the same conversion, for the same reasons, as `do_ingest_document`'s
    // (see the comment there): on the unstamped pool the first claim INSERT was
    // refused on a cleanly-migrated schema after the author agents and their
    // edges had committed, and the owner-group read was blind and minted on
    // every call. This path is synchronous, so the refusal now reaches the
    // caller, and it leaves nothing behind.
    let resolution = resolve_ingest_visibility(server, agent_id, choice).await?;
    let mut tx =
        begin_ingest_tx(server, author, "ingest_document_spine", resolution.grant()).await?;

    // ── 2. Ensure author agents + authored edges ──
    let mut author_responses = Vec::new();
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    // Same defensive backstop as `do_ingest_document` (backlog a55aac45): the
    // spine path is the recommended two-phase entry and shares the empty-authors
    // failure mode, so recover the byline from `source_text` when the structured
    // author list has no real author (empty or placeholder-only). Gated on Paper/Textbook source_type (see the
    // `do_ingest_document` rationale). Conservative parser; empty ⇒ pre-existing
    // behavior.
    let byline_eligible = matches!(
        extraction.source.source_type,
        epigraph_ingest::document::schema::SourceType::Paper
            | epigraph_ingest::document::schema::SourceType::Textbook
    );
    // "No real author" covers an empty list AND a list of only placeholder
    // names ("Authors Not Specified", "Unknown", ...): either way the byline
    // backstop gets its chance (backlog a55aac45, arXiv:2606.16707).
    //
    // Index alignment with the planner's `author_placeholder` edges (keyed by
    // `author_index` into `author_agent_map`):
    // - structured list in use: the planner and the loop below skip the SAME
    //   original indices (`AuthorEntry::is_placeholder`), so every planned
    //   `asserts` edge maps to a real author's agent;
    // - byline fallback in use: every structured entry was a placeholder, so the
    //   planner emitted NO `author_placeholder` edges; the fallback's indices are
    //   never looked up for `asserts`, and byline authors get `authored → paper`
    //   only — the same as the empty-list fallback.
    let has_real_author = extraction
        .source
        .authors
        .iter()
        .any(|a| !a.is_placeholder());
    let parsed_fallback;
    let authors: &[epigraph_ingest::common::schema::AuthorEntry] = if !has_real_author
        && byline_eligible
    {
        parsed_fallback = extraction
            .source_text
            .as_deref()
            .map(epigraph_ingest::document::byline::parse_byline_authors)
            .unwrap_or_default();
        if parsed_fallback.is_empty() {
            tracing::warn!(
                paper = %paper_title,
                "ingest_document_spine: source.authors empty or placeholder-only and no byline recovered from body; paper will have no author agents"
            );
        } else {
            tracing::info!(
                paper = %paper_title,
                count = parsed_fallback.len(),
                "ingest_document_spine: source.authors empty or placeholder-only; recovered authors from body byline fallback"
            );
        }
        &parsed_fallback
    } else {
        &extraction.source.authors
    };
    // Explicit `agent_id`s, the name-derived default, migration 148's
    // system-identity skips and the per-author report: `tools::ingest_authors`.
    let resolved = crate::tools::ingest_authors::resolve_document_authors(
        &mut tx,
        viewer,
        authors,
        agent_id,
        paper_id,
        "ingest_document_spine",
        &paper_title,
    )
    .await?;
    // The document's authors as THIS walk resolved them, in the extraction's
    // order: written into every ingest record, and on the record of a claim
    // this walk creates, the claim's primary authors (`ClaimIngestRecord::
    // authors`), fixed at creation whatever a later ingest adds.
    let mut recorded_authors: Vec<(usize, Uuid)> =
        resolved.iter().map(|r| (r.idx, r.agent_id)).collect();
    recorded_authors.sort_by_key(|(idx, _)| *idx);
    let recorded_authors: Vec<Uuid> = recorded_authors.into_iter().map(|(_, a)| a).collect();
    for r in resolved {
        let author = &authors[r.idx];
        let (_row, _) = epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut tx,
            edge_key,
            "ingest_document_spine",
            agent_id,
            r.agent_id,
            "agent",
            paper_id,
            "paper",
            "authored",
            Some(crate::tools::ingest_authors::authored_edge_properties(
                &r, author, agent_id,
            )),
        )
        .await
        .map_err(internal_error)?;
        // As in `do_ingest_document`: `asserts` only from an author the
        // ingester speaks for.
        if r.asserts {
            author_agent_map.insert(r.idx, r.agent_id);
        }
        author_responses.push(r.report);
    }

    // ── 3. Walk claims: levels 0–2 only ──
    let source_url = if doi.starts_with("10.") {
        format!("https://doi.org/{doi}")
    } else {
        format!("doi:{doi}")
    };

    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut embed_queue: Vec<(Uuid, String)> = Vec::new();
    let mut para_new_count = 0_usize;
    let mut para_dedup_count = 0_usize;
    let mut converged_unlabelled = 0_usize;
    let mut caller_labels_withheld = 0_usize;
    let mut new_paragraph_paths: Vec<String> = Vec::new();

    // Hoisted, as above, and through the same never-minting helper.
    let decl = tx
        .owner_decl(agent_id, "ingest_document_spine", &resolution)
        .await?;
    for planned in &plan.claims {
        if planned.level == 3 {
            continue;
        }

        let confidence = planned.confidence.clamp(0.0, 1.0);
        let methodology = methodology_from_planned(planned);
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            planned.content.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        claim.id = ClaimId::from_uuid(planned.id);
        claim.content_hash = planned.content_hash;
        claim.signature = Some(
            server
                .signer
                .sign_entity(epigraph_crypto::SignedEntity::Claim, &claim.content_hash),
        );

        let (persisted_id, resolved_to_existing, known_author) = persist_planned_claim(
            &mut tx,
            &claim,
            planned,
            agent_id,
            signer_typed.as_uuid(),
            TruthValue::clamped(raw_truth),
            decl,
        )
        .await?;
        // Same rule as `do_ingest_document`: a node this walk resolved to may
        // belong to another group (another agent ingested this document's spine
        // first); its label is skipped and disclosed, not allowed to abort the
        // spine. A node this walk CREATED is the author's own and must label.
        if resolved_to_existing {
            let labels = labels_for_resolved_claim(
                &mut tx,
                viewer,
                persisted_id,
                known_author,
                agent_id,
                &claim_labels,
            )
            .await?;
            if !label_resolved_claim(&mut tx, persisted_id, labels).await? {
                converged_unlabelled += 1;
            } else if labels.len() < claim_labels.len() {
                caller_labels_withheld += 1;
            }
        } else {
            ClaimRepository::update_labels_conn(&mut tx, persisted_id, &claim_labels, &[])
                .await
                .map_err(internal_error)?;
        }

        if resolved_to_existing {
            let (_row, _) = epigraph_db::create_ingest_written_edge_if_absent_conn(
                &mut tx,
                edge_key,
                "ingest_document_spine",
                agent_id,
                paper_id,
                "paper",
                persisted_id,
                "claim",
                "asserts",
                Some(planned.properties.clone()),
            )
            .await
            .map_err(internal_error)?;
            // The ingest record: this walk converged on an existing claim.
            epigraph_db::ClaimIngestRepository::record_signed_conn(
                &mut tx,
                edge_key,
                paper_id,
                persisted_id,
                agent_id,
                false,
                &recorded_authors,
                "ingest_document_spine",
                &pipeline_version,
            )
            .await
            .map_err(internal_error)?;
            id_map.insert(planned.id, persisted_id);
            if planned.level == 2 {
                para_dedup_count += 1;
            }
            continue;
        }

        ClaimRepository::set_properties_conn(
            &mut tx,
            ClaimId::from_uuid(persisted_id),
            planned.properties.clone(),
        )
        .await
        .map_err(internal_error)?;

        let evidence_text = planned
            .supporting_text
            .as_deref()
            .unwrap_or(&planned.content);
        let formatted_evidence =
            format!("Source: {paper_title} (DOI: {doi}). Passage: '{evidence_text}'");
        let evidence_hash = ContentHasher::hash(formatted_evidence.as_bytes());
        let mut evidence = Evidence::new(
            signer_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: format!("level_{}", planned.level),
                page_range: None,
            },
            Some(formatted_evidence),
            claim.id,
        );
        evidence.signature = Some(
            server
                .signer
                .sign_entity(epigraph_crypto::SignedEntity::Evidence, &evidence_hash),
        );

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!(
                "Extracted from '{paper_title}' (DOI: {doi}); level {} ({})",
                planned.level,
                level_label(planned.level),
            ),
        );

        ReasoningTraceRepository::create(&mut *tx, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&mut *tx, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id_conn(&mut tx, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let (_row, _) = epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut tx,
            edge_key,
            "ingest_document_spine",
            agent_id,
            paper_id,
            "paper",
            persisted_id,
            "claim",
            "asserts",
            Some(planned.properties.clone()),
        )
        .await
        .map_err(internal_error)?;

        // The ingest record: this walk CREATED the claim.
        epigraph_db::ClaimIngestRepository::record_signed_conn(
            &mut tx,
            edge_key,
            paper_id,
            persisted_id,
            agent_id,
            true,
            &recorded_authors,
            "ingest_document_spine",
            &pipeline_version,
        )
        .await
        .map_err(internal_error)?;

        embed_queue.push((persisted_id, planned.content.clone()));

        if planned.level == 2 {
            para_new_count += 1;
            if let Some(path) = para_id_to_path.get(&planned.id) {
                new_paragraph_paths.push(path.clone());
            }
        }

        id_map.insert(planned.id, persisted_id);
        let _ = &source_url;
    }

    // ── 4. Plan edges (skip any edge to/from atom planned IDs) ──
    for edge in &plan.edges {
        if atom_planned_ids.contains(&edge.target_id) || atom_planned_ids.contains(&edge.source_id)
        {
            continue;
        }

        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        if src == tgt && src_type == edge.target_type {
            continue;
        }

        // As the document walk: only an author's attribution is marked.
        let (_row, _) = if is_author_attribution(edge) && id_map.contains_key(&edge.target_id) {
            epigraph_db::create_ingest_written_edge_if_absent_conn(
                &mut tx,
                edge_key,
                "ingest_document_spine",
                agent_id,
                src,
                &src_type,
                tgt,
                &edge.target_type,
                &edge.relationship,
                Some(edge.properties.clone()),
            )
            .await
        } else {
            EdgeRepository::create_if_absent_including_retracted_signed_conn(
                &mut tx,
                edge_key,
                src,
                &src_type,
                tgt,
                &edge.target_type,
                &edge.relationship,
                Some(epigraph_db::without_ingest_marker(edge.properties.clone())),
                None,
                None,
            )
            .await
        }
        .map_err(internal_error)?;
    }

    // ── 5. processed_by edge (idempotent per pipeline stamp; each :ch{n} chunk gets its own) ──
    EdgeRepository::create_processed_by_stamp_if_absent_signed_conn(
        &mut tx,
        edge_key,
        paper_id,
        agent_id,
        &pipeline_version,
        "ingest_document_spine",
    )
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(|e| {
        crate::errors::internal_error_logged("ingest_document_spine: could not commit", e)
    })?;

    // ── 6. Detach embeddings (the response reports the number queued; see step 8
    // of `do_ingest_document_reporting`) ──
    let queued = spawn_created_claim_embeds(
        server,
        agent_id,
        resolution.grant(),
        embed_queue,
        "ingest_document_spine",
    );

    success_json(&IngestDocumentSpineResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        synthesized_key: is_synthetic_key(&doi),
        doi,
        authors: author_responses,
        ingested_by: agent_id.to_string(),
        paragraphs_new: para_new_count,
        paragraphs_deduped: para_dedup_count,
        paragraphs_embedding_queued: queued,
        paragraphs_embedded: queued,
        new_paragraph_paths,
        converged_claims_unlabelled: converged_unlabelled,
        converged_claims_caller_labels_withheld: caller_labels_withheld,
        already_ingested: para_new_count == 0 && para_dedup_count > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server over the test pool with a lazily connected `ScopedPool` on the
    /// pool's own options (a superuser, so row security filters nothing): the
    /// gate's caller read is `read_as`, which refuses on a server with no
    /// `ScopedPool`. The application-role behaviour is
    /// `tests/dedup_probes_app_role.rs`'s.
    fn server_over(pool: &sqlx::PgPool) -> EpiGraphMcpFull {
        let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x51u8; 32]).expect("signer");
        let embedder = crate::embed::McpEmbedder::new(pool.clone(), None);
        let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
            (*pool.connect_options()).clone(),
            epigraph_db::SessionGucMode::Session,
        );
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped)
    }

    /// Gate returns false when the DOI is unknown, false when the paper exists
    /// but has no `processed_by` edge at this pipeline version, and true once
    /// the edge is present.
    #[sqlx::test(migrations = "../../migrations")]
    async fn paper_already_ingested_gate(pool: sqlx::PgPool) {
        let doi = "urn:test:check-gate";

        // Unknown DOI → not ingested.
        assert!(paper_already_ingested(
            &server_over(&pool),
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Create the paper without a processed_by edge → still not ingested.
        let paper_id = PaperRepository::get_or_create(&pool, doi, Some("test"), None)
            .await
            .expect("create paper");
        assert!(paper_already_ingested(
            &server_over(&pool),
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Insert a `processed_by` edge with a *different* pipeline → still not
        // ingested under PIPELINE_VERSION_BASE. Edges enforce target existence, so
        // create a real agent first.
        let agent_a = epigraph_core::Agent::new([7u8; 32], Some("test-agent-a".to_string()));
        let agent_a_id: Uuid = epigraph_db::AgentRepository::create(&pool, &agent_a)
            .await
            .expect("create agent a")
            .id
            .into();
        EdgeRepository::create_if_not_exists(
            &pool,
            paper_id,
            "paper",
            agent_a_id,
            "agent",
            "processed_by",
            Some(serde_json::json!({ "pipeline": "some-other-pipeline" })),
            None,
            None,
        )
        .await
        .expect("create edge with other pipeline");
        assert!(paper_already_ingested(
            &server_over(&pool),
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE
        )
        .await
        .expect("gate query")
        .is_none());

        // Insert a `processed_by` edge with the matching pipeline (different
        // target so it isn't deduped by the (source,target,relationship) key).
        let agent_b = epigraph_core::Agent::new([8u8; 32], Some("test-agent-b".to_string()));
        let agent_b_id: Uuid = epigraph_db::AgentRepository::create(&pool, &agent_b)
            .await
            .expect("create agent b")
            .id
            .into();
        EdgeRepository::create_if_not_exists(
            &pool,
            paper_id,
            "paper",
            agent_b_id,
            "agent",
            "processed_by",
            Some(serde_json::json!({ "pipeline": PIPELINE_VERSION_BASE })),
            None,
            None,
        )
        .await
        .expect("create edge with matching pipeline");
        let hit = paper_already_ingested(
            &server_over(&pool),
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            doi,
            PIPELINE_VERSION_BASE,
        )
        .await
        .expect("gate query");
        assert_eq!(hit, Some(paper_id));
    }

    // ── Document identity keying (issue #356) ──────────────────────────────

    fn src(title: &str) -> DocumentSource {
        DocumentSource {
            title: title.to_string(),
            doi: None,
            external_id: None,
            uri: None,
            source_type: epigraph_ingest::document::schema::SourceType::InternalDocument,
            authors: Vec::new(),
            journal: None,
            year: None,
            metadata: serde_json::Value::Null,
        }
    }

    fn extraction_of(source: DocumentSource) -> DocumentExtraction {
        DocumentExtraction {
            source,
            thesis: None,
            thesis_derivation: Default::default(),
            sections: Vec::new(),
            relationships: Vec::new(),
            source_text: None,
            labels: Vec::new(),
        }
    }

    #[test]
    fn real_doi_is_used_verbatim() {
        let mut s = src("A paper");
        s.doi = Some("10.1000/xyz123".to_string());
        let key = resolve_doi(&extraction_of(s));
        assert_eq!(key, "10.1000/xyz123");
        assert!(!is_synthetic_key(&key));
    }

    fn key_for_doi(doi: &str) -> String {
        let mut s = src("A paper");
        s.doi = Some(doi.to_string());
        resolve_doi(&extraction_of(s))
    }

    fn key_for_uri(uri: &str) -> String {
        let mut s = src("A paper");
        s.uri = Some(uri.to_string());
        resolve_doi(&extraction_of(s))
    }

    /// A resolver-URL or `doi:` spelling of a DOI keys the SAME `papers` row as
    /// the bare DOI. Observed: `https://doi.org/10.1021/acsnano.9b05650` was
    /// stored verbatim, so a `query_paper` on the bare DOI found nothing and
    /// the same DOI could exist under two keys.
    #[test]
    fn resolve_doi_strips_doi_org_url_prefix() {
        let bare = "10.1021/acsnano.9b05650";
        for spelled in [
            "https://doi.org/10.1021/acsnano.9b05650",
            "http://doi.org/10.1021/acsnano.9b05650",
            "https://dx.doi.org/10.1021/acsnano.9b05650",
            "http://dx.doi.org/10.1021/acsnano.9b05650",
            "HTTPS://DOI.ORG/10.1021/acsnano.9b05650",
            "doi:10.1021/acsnano.9b05650",
            "DOI: 10.1021/acsnano.9b05650",
            "  https://doi.org/10.1021/acsnano.9b05650  ",
        ] {
            assert_eq!(key_for_doi(spelled), bare, "source.doi = {spelled:?}");
            assert_eq!(key_for_uri(spelled), bare, "source.uri = {spelled:?}");
        }
        // The suffix's case is part of the stored key: it is NOT lowercased
        // (that would re-key existing rows and their `doi:` labels).
        assert_eq!(
            key_for_doi("https://doi.org/10.1103/PhysRevLett.116.061102"),
            "10.1103/PhysRevLett.116.061102"
        );
        // A doi.org link to an arXiv DOI converges with the arXiv-uri key.
        assert_eq!(
            key_for_uri("https://doi.org/10.48550/arXiv.2606.04990"),
            key_for_uri("https://arxiv.org/abs/2606.04990"),
        );
    }

    /// Only a prefix in front of a DOI-shaped remainder is stripped; anything
    /// else keeps the verbatim key it always had.
    #[test]
    fn resolve_doi_leaves_non_doi_keys_verbatim() {
        for verbatim in [
            "https://doi.org/about",
            "https://doi.org/10.1021",
            "https://doi.org/10.12/short-registrant",
            "https://example.com/report/10.1021/x",
            "https://example.org/eln/entry-42",
        ] {
            assert_eq!(key_for_uri(verbatim), verbatim, "source.uri = {verbatim:?}");
            assert_eq!(key_for_doi(verbatim), verbatim, "source.doi = {verbatim:?}");
        }
        assert_eq!(key_for_doi("10.1000/xyz123"), "10.1000/xyz123");
    }

    #[test]
    fn arxiv_uri_still_resolves_to_arxiv_doi() {
        let mut s = src("A preprint");
        s.uri = Some("https://arxiv.org/abs/2606.04990".to_string());
        assert_eq!(resolve_doi(&extraction_of(s)), "10.48550/arXiv.2606.04990");
    }

    /// The core of #356: two unrelated DOI-less documents must NOT share a key.
    #[test]
    fn distinct_doi_less_documents_get_distinct_keys() {
        let a = resolve_doi(&extraction_of(src("V4 pre-flight: layered 18HB joint")));
        let b = resolve_doi(&extraction_of(src("Anatomy & Physiology, Ch. 1")));
        assert!(is_synthetic_key(&a) && is_synthetic_key(&b));
        assert_ne!(a, b, "unrelated DOI-less documents collapsed onto one key");
    }

    /// Every placeholder spelling is treated as absent, not as an identity — so
    /// none of them lands on a shared bucket, and none equals another document's key.
    #[test]
    fn placeholder_dois_are_treated_as_absent() {
        let baseline = resolve_doi(&extraction_of(src("Run 3 summary")));
        for placeholder in ["unknown", "UNKNOWN", " n/a ", "", "None", "-", "TBD"] {
            let mut s = src("Run 3 summary");
            s.doi = Some(placeholder.to_string());
            let key = resolve_doi(&extraction_of(s));
            assert!(
                is_synthetic_key(&key),
                "placeholder {placeholder:?} was kept as an identity key: {key}"
            );
            // Same document metadata ⇒ same synthesized key regardless of which
            // placeholder spelling the caller used.
            assert_eq!(key, baseline);
        }
        // ...and a *different* document with the same placeholder does not collide.
        let mut other = src("Run 4 summary");
        other.doi = Some("unknown".to_string());
        assert_ne!(resolve_doi(&extraction_of(other)), baseline);
    }

    #[test]
    fn synthesized_key_is_stable_across_calls() {
        let s = src("Run 3 summary");
        assert_eq!(
            resolve_doi(&extraction_of(s.clone())),
            resolve_doi(&extraction_of(s))
        );
    }

    /// `external_id` pins identity: a re-ingest that corrects the title (the
    /// exact case that used to overwrite the shared node's title) converges on
    /// the same node instead of forking a new one.
    #[test]
    fn external_id_pins_identity_across_metadata_edits() {
        let mut a = src("ELN entry: variant V2");
        a.external_id = Some("eln-run-2026-07-23-v2".to_string());
        let mut b = src("ELN entry: variant V2 (joint_bp=84, corrected)");
        b.external_id = Some("eln-run-2026-07-23-v2".to_string());
        b.year = Some(2026);
        assert_eq!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b))
        );
    }

    #[test]
    fn distinct_external_ids_do_not_collide() {
        let mut a = src("Sweep variant");
        a.external_id = Some("eln-run-v2".to_string());
        let mut b = src("Sweep variant");
        b.external_id = Some("eln-run-v3".to_string());
        assert_ne!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b)),
            "two sweep variants with the same title shared one node"
        );
    }

    /// Backlog b69dfb91: with `doi` null, a plain `uri` keyed the document and
    /// `external_id` was never read, so two different works sharing one uri
    /// (an ELN host page, a repository landing page) merged under one paper
    /// node. `external_id` is the documented identity for a DOI-less record,
    /// so it must keep them apart.
    #[test]
    fn shared_uri_with_distinct_external_ids_does_not_merge() {
        let uri = "https://example.org/eln/notebook";
        let mut a = src("Sweep variant");
        a.uri = Some(uri.to_string());
        a.external_id = Some("eln-run-v2".to_string());
        let mut b = src("Sweep variant");
        b.uri = Some(uri.to_string());
        b.external_id = Some("eln-run-v3".to_string());
        let (ka, kb) = (
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b)),
        );
        assert_ne!(
            ka, kb,
            "two works sharing source.uri but carrying different external_id \
             were keyed onto one paper node"
        );
        assert!(
            is_synthetic_key(&ka) && is_synthetic_key(&kb),
            "the external_id identity, not the shared uri, keys them: {ka} / {kb}"
        );
    }

    /// The same record (same uri, same external_id) still converges, and it
    /// converges with the uri-less spelling of that record: identity is the
    /// external id alone, so adding or correcting the uri does not fork it.
    #[test]
    fn same_external_id_converges_with_or_without_the_uri() {
        let mk = |uri: Option<&str>| {
            let mut s = src("ELN entry: variant V2");
            s.uri = uri.map(str::to_string);
            s.external_id = Some("eln-run-2026-07-23-v2".to_string());
            resolve_doi(&extraction_of(s))
        };
        let with_uri = mk(Some("https://example.org/eln/notebook"));
        assert_eq!(with_uri, mk(Some("https://example.org/eln/notebook")));
        assert_eq!(with_uri, mk(None));
        assert_eq!(with_uri, mk(Some("https://example.org/eln/moved-notebook")));
    }

    /// A uri with no usable external_id keeps the verbatim key it always had,
    /// so rows ingested that way are still found on re-ingest.
    #[test]
    fn uri_without_external_id_keeps_its_verbatim_key() {
        let uri = "https://example.org/eln/entry-42";
        assert_eq!(key_for_uri(uri), uri);
        for placeholder in ["unknown", " n/a ", ""] {
            let mut s = src("A paper");
            s.uri = Some(uri.to_string());
            s.external_id = Some(placeholder.to_string());
            assert_eq!(
                resolve_doi(&extraction_of(s)),
                uri,
                "placeholder external_id {placeholder:?} must not displace the uri key"
            );
        }
    }

    /// A uri that names a real identifier (a DOI resolver link, an arXiv
    /// page) outranks external_id, exactly as a real `doi` does.
    #[test]
    fn identifier_shaped_uri_outranks_external_id() {
        let mut d = src("A paper");
        d.uri = Some("https://doi.org/10.1021/acsnano.9b05650".to_string());
        d.external_id = Some("lab-copy-1".to_string());
        assert_eq!(resolve_doi(&extraction_of(d)), "10.1021/acsnano.9b05650");

        let mut x = src("A preprint");
        x.uri = Some("https://arxiv.org/abs/2606.04990".to_string());
        x.external_id = Some("lab-copy-1".to_string());
        assert_eq!(resolve_doi(&extraction_of(x)), "10.48550/arXiv.2606.04990");

        let mut p = src("A paper");
        p.uri = Some("doi:10.1021/acsnano.9b05650".to_string());
        p.external_id = Some("lab-copy-1".to_string());
        assert_eq!(resolve_doi(&extraction_of(p)), "10.1021/acsnano.9b05650");
    }

    /// A shared uri whose path merely contains an arXiv-shaped digit run
    /// (`2026.1102`, `20261102.14301`) does not name arXiv, so it must not
    /// outrank external_id: keyed on a fabricated `10.48550/arXiv.*` DOI, two
    /// different works at that uri merged exactly as b69dfb91 describes.
    #[test]
    fn digit_run_in_a_shared_uri_is_not_an_arxiv_identifier() {
        for uri in [
            "https://lab.example/eln/2026.1102/notebook",
            "https://lab.example/eln/entry/20261102.14301",
        ] {
            let mut a = src("Sweep variant");
            a.uri = Some(uri.to_string());
            a.external_id = Some("run-a".to_string());
            let mut b = src("Sweep variant");
            b.uri = Some(uri.to_string());
            b.external_id = Some("run-b".to_string());
            let (ka, kb) = (
                resolve_doi(&extraction_of(a)),
                resolve_doi(&extraction_of(b)),
            );
            assert_ne!(ka, kb, "two works at {uri} merged under one key {ka}");
            assert!(
                is_synthetic_key(&ka) && is_synthetic_key(&kb),
                "external_id, not a digit run in {uri}, keys them: {ka} / {kb}"
            );
        }
    }

    #[test]
    fn placeholder_external_id_falls_back_to_metadata() {
        let mut a = src("Report X");
        a.external_id = Some("unknown".to_string());
        assert_eq!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(src("Report X")))
        );
    }

    /// Authors participate in metadata-derived identity, so the two documents
    /// whose author lists got unioned in #356 key apart even given one title.
    #[test]
    fn authors_disambiguate_same_titled_documents() {
        let mut a = src("Overview");
        a.authors = vec![epigraph_ingest::common::schema::AuthorEntry {
            name: "Lawrence J. Gitman".to_string(),
            affiliations: Vec::new(),
            roles: Vec::new(),
            agent_id: None,
        }];
        let mut b = src("Overview");
        b.authors = vec![epigraph_ingest::common::schema::AuthorEntry {
            name: "Amit Shah".to_string(),
            affiliations: Vec::new(),
            roles: Vec::new(),
            agent_id: None,
        }];
        assert_ne!(
            resolve_doi(&extraction_of(a)),
            resolve_doi(&extraction_of(b))
        );
    }

    #[test]
    fn author_order_does_not_change_the_key() {
        let mk = |names: [&str; 2]| {
            let mut s = src("Joint work");
            s.authors = names
                .iter()
                .map(|n| epigraph_ingest::common::schema::AuthorEntry {
                    name: (*n).to_string(),
                    affiliations: Vec::new(),
                    roles: Vec::new(),
                    agent_id: None,
                })
                .collect();
            resolve_doi(&extraction_of(s))
        };
        assert_eq!(mk(["Ada", "Grace"]), mk(["Grace", "Ada"]));
    }

    #[test]
    fn synthetic_key_shape_is_urn_slug_hash() {
        let mut s = src("V4 pre-flight: layered 18HB compliant joint");
        s.external_id = Some("eln/run 42".to_string());
        let key = resolve_doi(&extraction_of(s));
        let rest = key
            .strip_prefix(SYNTHETIC_KEY_PREFIX)
            .expect("synthetic keys are URN-prefixed");
        let (slug, hash) = rest.rsplit_once('-').expect("slug-hash shape");
        assert_eq!(slug, "eln-run-42");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// A title of only non-alphanumerics leaves an empty slug; the key must
    /// still be a well-formed, unique URN rather than a dangling prefix.
    #[test]
    fn empty_slug_still_yields_a_valid_key() {
        let key = resolve_doi(&extraction_of(src("!!! ???")));
        let rest = key.strip_prefix(SYNTHETIC_KEY_PREFIX).expect("prefixed");
        assert_eq!(rest.len(), 16);
        assert!(rest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn key_slug_is_bounded_and_collapses_separators() {
        let long = "a".repeat(200);
        assert!(key_slug(&long).len() <= 48);
        assert_eq!(key_slug("Hello   World -- Again"), "hello-world-again");
        assert_eq!(key_slug("  leading and trailing  "), "leading-and-trailing");
    }
}
