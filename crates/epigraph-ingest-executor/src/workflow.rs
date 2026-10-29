//! Workflow ingest executor — applies an [`epigraph_ingest::common::plan::IngestPlan`]
//! built from a [`epigraph_ingest::workflow::WorkflowExtraction`] to the database.
//!
//! This module consolidates logic previously duplicated between
//! `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow_via_pool` and
//! `epigraph-api::routes::workflows::ingest_workflow`.

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_core::TruthValue;
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, WorkflowRepository};
use epigraph_ingest::common::plan::IngestPlan;
use epigraph_ingest::workflow::builder::root_workflow_id;
use epigraph_ingest::workflow::WorkflowExtraction;

use crate::error::IngestExecutorError;
use crate::system_agent::get_or_create_system_agent;

/// Labels for one planned claim: always `claim`, plus the plan's `kind` when it
/// is usable as a label.
///
/// `kind` is MACHINE-DERIVED — it is `planned.properties["kind"]`, i.e. whatever
/// the extraction LLM emitted — not a value a caller typed. Since backlog
/// f6310444, `ClaimRepository::create_with_id_if_absent` refuses any label
/// containing `$`. Passing such a `kind` straight through would therefore abort
/// the ENTIRE workflow ingest at the first offending claim (e.g. a plan emitting
/// `kind = "cost_$_per_unit"`), to punish the caller for one cosmetic label on
/// one node.
///
/// So the machine-derived label is DROPPED with a warning rather than escalated
/// into a write error. That keeps the repo-layer guard absolute — no `$` label
/// can reach `claims.labels` from any path — while confining the blast radius of
/// bad LLM output to the label it affects. The `claim` label, which is what the
/// structural queries filter on, always survives.
///
/// One half of the original argument has since dissolved and is recorded rather
/// than deleted: this used to say the abort left "the claims already inserted
/// behind as a partial ingest", because the walk ran on a shared pool with no
/// enclosing transaction. It now runs inside the caller's transaction, so an
/// abort leaves nothing behind. The trade is still worth making — a whole
/// document's ingest lost to one cosmetic label is the wrong price — but it is
/// now "fails cleanly" rather than "fails dirty".
///
/// Note the asymmetry with the caller-supplied paths (`submit_claim`, `memorize`,
/// HTTP `POST /claims`), which REFUSE the write outright: there the caller can
/// see the error and fix the value, and silently dropping their label would be
/// the "silently ungrouped" failure the backlog names. An extraction plan has no
/// such caller — nobody is waiting to correct `properties.kind` — so a hard
/// failure converts a cosmetic defect into data loss for the whole document.
fn labels_for_planned_kind(kind: &str) -> Vec<String> {
    let mut labels = vec!["claim".to_string()];
    let owned = kind.to_string();
    match epigraph_db::reject_unexpanded_labels(std::slice::from_ref(&owned)) {
        Ok(()) => labels.push(owned),
        Err(e) => tracing::warn!(
            kind,
            "workflow ingest: dropping unusable machine-derived kind label: {e}"
        ),
    }
    labels
}

#[cfg(test)]
mod label_derivation_tests {
    use super::labels_for_planned_kind;

    /// The normal case must be untouched: `claim` plus the plan's kind.
    #[test]
    fn a_usable_kind_is_kept_alongside_claim() {
        assert_eq!(
            labels_for_planned_kind("workflow_step"),
            vec!["claim".to_string(), "workflow_step".to_string()]
        );
        // Separators the label vocabulary actually uses must survive — this is
        // the negative direction, guarding against an over-broad predicate.
        assert_eq!(
            labels_for_planned_kind("phase:setup"),
            vec!["claim".to_string(), "phase:setup".to_string()]
        );
    }

    /// An LLM-emitted kind carrying `$` must cost its own label and NOTHING
    /// else. The pre-fix derivation (`vec!["claim", kind]`) handed exactly this
    /// array to `create_with_id_if_absent`, whose guard turns it into
    /// `DbError::InvalidData` — aborting the whole plan walk mid-ingest.
    #[test]
    fn a_kind_carrying_shell_syntax_is_dropped_not_escalated() {
        let kind = "cost_$_per_unit";

        // What the pre-fix code would have written, and what the repo layer
        // does to it. This is the abort mode being closed, asserted rather
        // than described.
        let pre_fix = vec!["claim".to_string(), kind.to_string()];
        assert!(
            epigraph_db::reject_unexpanded_labels(&pre_fix).is_err(),
            "premise of this test: the repo layer refuses the pre-fix array"
        );

        let derived = labels_for_planned_kind(kind);
        assert_eq!(
            derived,
            vec!["claim".to_string()],
            "the offending kind must be dropped, and `claim` must survive"
        );
        assert!(
            epigraph_db::reject_unexpanded_labels(&derived).is_ok(),
            "the derived labels must be writable, i.e. the ingest proceeds"
        );
    }
}

/// The `workflows.metadata` an ingest writes: the caller's `source.metadata`
/// with `source.tags` recorded under `"tags"`.
///
/// `WorkflowSource.tags` is the only place `store_workflow`, `ingest_workflow`
/// and their REST twins put a caller's tags, and nothing else in the ingest
/// reads it, so without this the tags were lost (backlog 055f7114). They are
/// trimmed, empties dropped, and de-duplicated in first-seen order.
///
/// Merge policy, so no caller value is lost:
/// - no usable tags: the metadata is returned unchanged (a tagless workflow
///   reads exactly as before);
/// - `Null` metadata (the caller sent none) becomes `{"tags": [...]}`;
/// - an object keeps every key; a caller `"tags"` ARRAY is extended with the
///   tags it lacks (its own entries first), and a caller `"tags"` that is not
///   an array is left as the caller wrote it;
/// - any other JSON value (a string, number or array) is left unchanged, since
///   it has no key to put the tags under.
///
/// The wfd1 plan digest does not read metadata, so this changes no digest.
fn workflow_row_metadata(metadata: &serde_json::Value, tags: &[String]) -> serde_json::Value {
    let mut wanted: Vec<String> = Vec::new();
    for t in tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        if !wanted.iter().any(|w| w == t) {
            wanted.push(t.to_string());
        }
    }
    if wanted.is_empty() {
        return metadata.clone();
    }
    let mut obj = match metadata {
        serde_json::Value::Null => serde_json::Map::new(),
        serde_json::Value::Object(o) => o.clone(),
        _ => return metadata.clone(),
    };
    match obj.get_mut("tags") {
        None => {
            obj.insert("tags".to_string(), serde_json::json!(wanted));
        }
        Some(serde_json::Value::Array(existing)) => {
            for t in wanted {
                if !existing.iter().any(|e| e.as_str() == Some(t.as_str())) {
                    existing.push(serde_json::Value::String(t));
                }
            }
        }
        Some(_) => {}
    }
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod row_metadata_tests {
    use super::workflow_row_metadata;
    use serde_json::json;

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn tags_are_trimmed_deduplicated_and_empties_dropped() {
        let got = workflow_row_metadata(
            &json!({ "prerequisites": ["cargo"] }),
            &tags(&[" rust ", "", "deployment", "rust", "   "]),
        );
        assert_eq!(
            got,
            json!({ "prerequisites": ["cargo"], "tags": ["rust", "deployment"] })
        );
    }

    #[test]
    fn null_metadata_becomes_an_object_holding_the_tags() {
        assert_eq!(
            workflow_row_metadata(&serde_json::Value::Null, &tags(&["rust"])),
            json!({ "tags": ["rust"] })
        );
    }

    #[test]
    fn no_usable_tags_leaves_the_metadata_untouched() {
        assert_eq!(
            workflow_row_metadata(&serde_json::Value::Null, &tags(&["", "  "])),
            serde_json::Value::Null
        );
        assert_eq!(
            workflow_row_metadata(&json!({ "prerequisites": [] }), &[]),
            json!({ "prerequisites": [] })
        );
    }

    #[test]
    fn a_caller_tags_array_is_extended_not_replaced() {
        let got = workflow_row_metadata(
            &json!({ "owner_team": "infra", "tags": ["legacy", 7] }),
            &tags(&["rust", "legacy"]),
        );
        assert_eq!(
            got,
            json!({ "owner_team": "infra", "tags": ["legacy", 7, "rust"] })
        );
    }

    #[test]
    fn values_with_no_place_for_tags_are_left_as_the_caller_wrote_them() {
        assert_eq!(
            workflow_row_metadata(&json!({ "tags": "csv,list" }), &tags(&["rust"])),
            json!({ "tags": "csv,list" })
        );
        assert_eq!(
            workflow_row_metadata(&json!("opaque"), &tags(&["rust"])),
            json!("opaque")
        );
    }
}

/// A newly inserted plan edge as returned by the executor. Callers iterate
/// these post-hoc to fire `auto_wire_edge_if_epistemic` (the executor itself
/// is pure-DB and doesn't depend on epigraph-engine — mirrors the embedding
/// pattern documented in CLAUDE.md "Embedding policy").
#[derive(Debug, Clone)]
pub struct InsertedPlanEdge {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
}

/// Summary of what the executor wrote (or skipped) for a single plan.
#[derive(Debug, Clone)]
pub struct WorkflowIngestExecutionResult {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    /// The `executes` edges this call wrote. On an idempotent re-ingest
    /// (`already_ingested`) it is instead the existing plan's `executes` edges
    /// that the CALLER can read: never the count on the ingest's own stamp,
    /// which reads every group the system agent serves. Zero on a re-ingest
    /// through [`execute_workflow_ingest_plan`], which has no caller viewer.
    pub executes_edges_created: usize,
    /// `true` when this ingest inserted (or upserted) a `workflow → variant_of
    /// → workflow` edge, i.e. when a parent was resolved (the named
    /// `parent_canonical_name` at `generation - 1`, or this lineage's
    /// predecessor; see `WorkflowRepository::resolve_ingest_parent`).
    /// Idempotent re-ingests that hit the gate at step 1 return `false` (no
    /// insertion attempted) even when the edge already exists in the DB.
    pub variant_of_edge_created: bool,
    pub relationship_edges_created: usize,
    /// `true` when the idempotency gate short-circuited (workflow already
    /// has `executes` edges). The other counters are zero in that case, except
    /// `executes_edges_created` (the caller's view of the existing plan).
    pub already_ingested: bool,
    /// (claim_id, content) for every newly inserted claim in this run.
    /// Empty on idempotent re-ingest. Callers embed these to satisfy the
    /// is_current=true → has-embedding invariant; see CLAUDE.md
    /// "Embedding policy".
    pub inserted: Vec<(Uuid, String)>,
    /// Newly inserted plan edges (claim→claim relationships from
    /// `IngestPlan::edges`). Callers fire `auto_wire_edge_if_epistemic` on
    /// each so epistemic edges materialize their factor BBA on the target.
    /// Empty on idempotent re-ingest.
    pub inserted_edges: Vec<InsertedPlanEdge>,
    /// Agent the workflow attributes its writes to. Callers pass this to
    /// `auto_wire_edge_if_epistemic` as the BBA's `source_agent_id`. `None`
    /// on idempotent re-ingest (no agent created, no edges to wire).
    pub system_agent_id: Option<Uuid>,
    /// Declared-tenancy ingests only ([`execute_workflow_ingest_plan_in_group`]
    /// with a group): every planned claim this call did NOT create whose
    /// tenancy is not `('group', <the declared group>)`, in plan order. On an
    /// idempotent re-ingest that is every planned claim of another tenancy.
    /// Always empty when no group was declared.
    pub reused_items: Vec<ReusedClaim>,
}

/// A planned claim a declared-tenancy ingest reused rather than created, whose
/// tenancy differs from the declared one. Nothing re-tenants it: the plan then
/// executes a claim outside the declared group, and the caller decides whether
/// that is acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedClaim {
    pub claim_id: Uuid,
    /// `public` or `group`; `None` when the caller (or the ingest's own
    /// system-agent stamp) cannot read the claim. Only an idempotent re-ingest
    /// (which writes nothing) can report `None`: a fresh walk refuses such a
    /// claim ([`IngestExecutorError::ReusedClaimOutsideCallerGroups`]).
    pub visibility: Option<String>,
    /// The claim's owner group; `None` exactly when `visibility` is.
    pub owner_group_id: Option<Uuid>,
}

/// The app-side half of a declared-tenancy ingest's authority: the CALLING
/// agent itself must hold a live `writer` / `admin` membership of `group`.
///
/// Asked of the caller's OWN viewer, never its human's: an operated agent's
/// writer authority through its operator (`AgentRepository::require_writer_authority`)
/// would admit every agent the group's writer operates. `viewer` must be the
/// caller's (its principal is compared); a bypass viewer has no writable set
/// and is refused. Call it before any transaction is opened, so a refusal
/// writes nothing (not even the system agent's first-use provisioning).
///
/// # Errors
/// [`IngestExecutorError::CallerNotGroupWriter`].
pub fn require_caller_writes_group(
    viewer: &epigraph_db::visibility::Viewer,
    caller: Uuid,
    group: Uuid,
) -> Result<(), IngestExecutorError> {
    if viewer.principal() == Some(caller) && viewer.writable_groups().contains(&group) {
        Ok(())
    } else {
        Err(IngestExecutorError::CallerNotGroupWriter { caller, group })
    }
}

/// The reused claims among `planned` whose tenancy is not `('group', group)`,
/// first occurrence first.
async fn reused_with_another_tenancy(
    conn: &mut sqlx::PgConnection,
    planned: impl IntoIterator<Item = Uuid>,
    caller: &epigraph_db::visibility::Viewer,
    group: Uuid,
) -> Result<Vec<ReusedClaim>, IngestExecutorError> {
    let mut ids: Vec<Uuid> = Vec::new();
    for id in planned {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let readable: HashMap<Uuid, (String, Uuid)> =
        ClaimRepository::tenancy_of_conn(conn, caller, &ids)
            .await?
            .into_iter()
            .map(|(id, v, o)| (id, (v, o)))
            .collect();
    Ok(ids
        .into_iter()
        .filter_map(|claim_id| match readable.get(&claim_id) {
            Some((v, o)) if v == "group" && *o == group => None,
            Some((v, o)) => Some(ReusedClaim {
                claim_id,
                visibility: Some(v.clone()),
                owner_group_id: Some(*o),
            }),
            None => Some(ReusedClaim {
                claim_id,
                visibility: None,
                owner_group_id: None,
            }),
        })
        .collect())
}

/// Execute a workflow ingest plan against the database.
///
/// Idempotent. If the canonical workflow already has `executes` edges, this
/// returns early with `already_ingested: true` and no DB writes. Otherwise it
/// inserts the workflow row, ensures author and system agents, persists each
/// planned claim with dedup, writes `workflow —executes→ claim` edges, and
/// emits the intra-claim plan edges.
///
/// # This takes a CONNECTION, and the caller must have stamped it
///
/// Every row below is owned by the `workflow-ingest-system` agent's personal
/// group (see `decl`), and migration 077's `WITH CHECK` on `claims` and `edges`
/// asks about the ROW's owner group. On the unstamped pool this whole function
/// was refused on a cleanly-migrated schema — `new row violates row-level
/// security policy for table "claims"`, the refusal that made `store_workflow`
/// entirely unavailable. Callers resolve
/// [`crate::system_agent::system_agent_write_authority`] and pass
/// `&mut *ScopedPool::begin_as(&authority.viewer)`; see that function for the
/// measurement of which identity the stamp must be.
///
/// # And it must be a TRANSACTION, not just a connection
///
/// This walk previously ran statement-by-statement on a shared pool with no
/// enclosing transaction (the note on [`labels_for_planned_kind`] says so in as
/// many words), so a refusal partway through left the `workflows` row, the
/// claims inserted so far and their `executes` edges behind as a partial ingest.
/// Handed `&mut *tx` every statement here is one unit: the ingest either lands
/// or leaves nothing. That is safe to retry precisely because every write is
/// keyed on a DETERMINISTIC id with an `ON CONFLICT` clause — `insert_root` on
/// `(canonical_name, generation)`, `create_with_id_if_absent` on `(id)`,
/// `create_if_not_exists` on the edge triple — so a re-run after a rollback
/// converges rather than accumulating rows.
///
/// # It has no caller viewer
///
/// So an idempotent re-ingest reports `executes_edges_created: 0`: the only
/// count it could read is the stamp's, and the stamp is not the caller. A
/// caller-facing entry point uses [`execute_workflow_ingest_plan_in_group`].
pub async fn execute_workflow_ingest_plan(
    conn: &mut sqlx::PgConnection,
    plan: &IngestPlan,
    extraction: &WorkflowExtraction,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    execute_plan(conn, plan, extraction, None, None).await
}

/// [`execute_workflow_ingest_plan`] for a CALLER, with an optional DECLARED
/// owner group.
///
/// `caller` is the viewer of the principal the answer goes back to. Every
/// tenancy-bearing fact the result reports about rows this call did not write
/// is read through it, on top of the stamp's own row security: the existing
/// plan's `executes` count on an idempotent re-ingest, and `reused_items`. The
/// stamp is the system agent's, which reads every group it serves, so an
/// answer read on the stamp alone would describe another group's plan to a
/// non-member.
///
/// `declared_group: None` writes what [`execute_workflow_ingest_plan`] writes:
/// every claim the walk creates is public, owned by the system agent's default
/// group.
///
/// `Some(group)` declares `('group', group)` for every claim the walk CREATES
/// (`TenancyDecl::group`); the `executes` and plan edges then derive the same
/// tenancy from their endpoints. Before anything is written (and before the
/// idempotency gate, so a re-ingest is refused the same way) it asks the
/// stamped connection whether its stamp writes `group`
/// (`GroupMembershipRepository::session_can_write_group_conn`, the question
/// the row-security `WITH CHECK` asks of every row): the stamp is the system
/// agent's, so this refuses with
/// [`IngestExecutorError::DeclaredGroupNotWritable`] unless that agent holds a
/// live writer membership of the group. It does NOT check the caller: that is
/// [`require_caller_writes_group`], which every caller runs first, on the same
/// `caller` viewer. Claims the
/// walk reuses keep their tenancy and are reported in
/// [`WorkflowIngestExecutionResult::reused_items`]. A reused claim private to a
/// group outside the CALLER's writable set (or unreadable to the stamp) refuses
/// the ingest before any edge is written
/// ([`IngestExecutorError::ReusedClaimOutsideCallerGroups`]): its edges would be
/// owned by that group and written on the system agent's stamp.
///
/// # Errors
/// As [`execute_workflow_ingest_plan`], plus
/// [`IngestExecutorError::DeclaredGroupNotWritable`] and
/// [`IngestExecutorError::ReusedClaimOutsideCallerGroups`].
pub async fn execute_workflow_ingest_plan_in_group(
    conn: &mut sqlx::PgConnection,
    plan: &IngestPlan,
    extraction: &WorkflowExtraction,
    caller: &epigraph_db::visibility::Viewer,
    declared_group: Option<Uuid>,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    execute_plan(conn, plan, extraction, Some(caller), declared_group).await
}

/// The walk both entry points share. `caller` is `None` only for
/// [`execute_workflow_ingest_plan`], which never declares a group.
#[allow(clippy::too_many_lines)]
async fn execute_plan(
    conn: &mut sqlx::PgConnection,
    plan: &IngestPlan,
    extraction: &WorkflowExtraction,
    caller: Option<&epigraph_db::visibility::Viewer>,
    declared_group: Option<Uuid>,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    // A declared group always comes with the caller it is declared for.
    let declared = match (declared_group, caller) {
        (Some(group), Some(caller)) => Some((group, caller)),
        (None, _) => None,
        (Some(group), None) => {
            return Err(IngestExecutorError::CallerNotGroupWriter {
                caller: Uuid::nil(),
                group,
            })
        }
    };
    let canonical_name = &extraction.source.canonical_name;
    let generation = extraction.source.generation as i32;
    let goal = &extraction.source.goal;

    let workflow_id = root_workflow_id(extraction);

    // ── 0. Pre-flight: reject blank claim content before any DB write ────
    // Catches fields that serde(default) silently turns into "" (e.g.
    // Phase.summary when omitted from JSON), which would later hit the
    // claims_content_not_empty DB constraint and leave a zombie workflows row.
    {
        let rev_index: std::collections::HashMap<uuid::Uuid, &str> = plan
            .path_index
            .iter()
            .map(|(path, id)| (*id, path.as_str()))
            .collect();
        for planned in &plan.claims {
            if planned.content.trim().is_empty() {
                let path = rev_index
                    .get(&planned.id)
                    .map(|s| (*s).to_string())
                    .unwrap_or_else(|| planned.id.to_string());
                return Err(crate::error::IngestExecutorError::InvalidContent { path });
            }
        }
    }

    // ── 0b. Pre-flight: refuse a content-less generation (U032) ─────────
    // `WorkflowExtraction::phases` is `#[serde(default)]` and unknown keys are
    // ignored, so a payload whose steps sit under an unrecognised key parses
    // as `phases: []`. As a NEW generation (> 0) that committed the thesis
    // alone, and `improve_workflow_hierarchy` mints `max + 1` on every call,
    // so each agent retry minted another empty generation (backlog 28fb40c4 /
    // 1e6872e7). A plan with no claims at all is refused at every generation:
    // it writes a bare row that the `executes`-edge gate below never treats as
    // processed. Generation 0 with a thesis and no steps stays legal: that is
    // the `store_workflow` / `POST /workflows` `steps: []` scaffold `add_step`
    // fills in place. Runs AFTER the blank-content check (callers assert on
    // that error for a blank thesis over a step-less phase) and BEFORE the
    // idempotency gate, so a re-ingest of an empty plan is refused too rather
    // than reported `already_ingested`.
    {
        let level2 = plan.claims.iter().filter(|c| c.level == 2).count();
        if plan.claims.is_empty() || (generation > 0 && level2 == 0) {
            return Err(IngestExecutorError::EmptyGeneration {
                canonical_name: canonical_name.clone(),
                generation,
                level2,
                claims: plan.claims.len(),
            });
        }
    }

    // ── 0c. Declared tenancy: the stamp must write the declared group ────
    if let Some(group) = declared_group {
        if !epigraph_db::GroupMembershipRepository::session_can_write_group_conn(&mut *conn, group)
            .await?
        {
            let system_agent = get_or_create_system_agent(&mut *conn).await?;
            return Err(IngestExecutorError::DeclaredGroupNotWritable {
                group,
                system_agent,
            });
        }
    }

    // ── 1. Idempotency gate: skip if workflow row already processed ──────
    if let Some(existing_id) =
        WorkflowRepository::find_root_by_canonical(&mut *conn, canonical_name, generation).await?
    {
        // The gate DECIDES on the stamp's view (every `executes` edge the
        // system agent can read): a workflow whose plan the caller cannot see
        // is still processed, and falling through would write the caller's
        // claims under another group's workflow row. It REPORTS the caller's
        // view only; see `executes_edges_created`.
        let targets: Vec<Uuid> = sqlx::query_scalar(
            "SELECT target_id FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(existing_id)
        .fetch_all(&mut *conn)
        .await?;

        if !targets.is_empty() {
            let visible_to_caller = match caller {
                Some(caller) => {
                    let mut ids: Vec<Uuid> = Vec::new();
                    for id in &targets {
                        if !ids.contains(id) {
                            ids.push(*id);
                        }
                    }
                    let readable: std::collections::HashSet<Uuid> =
                        ClaimRepository::tenancy_of_conn(&mut *conn, caller, &ids)
                            .await?
                            .into_iter()
                            .map(|(id, _, _)| id)
                            .collect();
                    targets.iter().filter(|t| readable.contains(t)).count()
                }
                None => 0,
            };
            let reused_items = match declared {
                Some((group, caller)) => {
                    reused_with_another_tenancy(
                        &mut *conn,
                        plan.claims.iter().map(|c| c.id),
                        caller,
                        group,
                    )
                    .await?
                }
                None => Vec::new(),
            };
            return Ok(WorkflowIngestExecutionResult {
                workflow_id: existing_id,
                canonical_name: canonical_name.clone(),
                generation,
                claims_ingested: 0,
                claims_skipped_dedup: 0,
                executes_edges_created: visible_to_caller,
                variant_of_edge_created: false,
                relationship_edges_created: 0,
                already_ingested: true,
                inserted: Vec::new(),
                inserted_edges: Vec::new(),
                system_agent_id: None,
                reused_items,
            });
        }
    }

    // ── 2. Ensure system agent ───────────────────────────────────────────
    let system_agent_id = get_or_create_system_agent(&mut *conn).await?;

    // Tenancy declaration (PR-16). One lookup for the whole plan: every claim
    // in a workflow ingest is authored by the same system agent, and resolving
    // it per claim would be N identical round trips. The executor is pure-DB
    // and its callers do not choose a group -- `store_workflow`,
    // `ingest_workflow` and `POST /api/v1/workflows/ingest` all post
    // instance-wide workflow content -- so the system agent's own group is the
    // declaration, publicly visible.
    //
    // A DECLARED group (`execute_workflow_ingest_plan_in_group`) replaces that
    // default for the claims this walk creates; step 0c proved the stamp writes
    // it. The `workflows` row takes the same declaration (ruling R-74,
    // migration 183): the row is the plan's, and its tenancy is what every
    // reader of the plan and the outcome report decide on.
    let decl = match declared_group {
        Some(group) => epigraph_core::TenancyDecl::group(group),
        None => ClaimRepository::default_decl_for_author(&mut *conn, system_agent_id).await?,
    };

    // ── 3. Insert workflow row (idempotent) ──────────────────────────────
    // The parent is resolved in ONE place, shared with the authority check
    // (`WorkflowRepository::ingest_anchors`): the named parent at
    // `generation - 1`, else this lineage's predecessor (U032). Before, a
    // generation > 0 that named no parent was stored as a parentless root.
    let parent_id = WorkflowRepository::resolve_ingest_parent(
        &mut *conn,
        canonical_name,
        generation,
        extraction.source.parent_canonical_name.as_deref(),
    )
    .await?;

    WorkflowRepository::insert_root(
        &mut *conn,
        workflow_id,
        canonical_name,
        generation,
        goal,
        parent_id,
        workflow_row_metadata(&extraction.source.metadata, &extraction.source.tags),
        decl,
    )
    .await
    .map_err(|e| IngestExecutorError::WorkflowInsert(e.to_string()))?;
    // `ON CONFLICT DO NOTHING` also skips a row this stamp cannot read (step 1
    // did not find it): writing this plan's claims and edges under it would
    // extend a plan the stamp has no view of. Refuse, so nothing is written.
    if WorkflowRepository::find_root_by_canonical(&mut *conn, canonical_name, generation)
        .await?
        .is_none()
    {
        return Err(IngestExecutorError::WorkflowOutsideView {
            canonical_name: canonical_name.to_string(),
            generation,
        });
    }

    // ── 3a. variant_of edge for hierarchical workflows (issue #51) ──────
    // When a parent was resolved above (the named parent, or this lineage's
    // predecessor), insert workflow → variant_of → parent
    // so graph-traversal queries that don't know about workflows.parent_id
    // can still see the lineage. Idempotent on re-ingest via
    // create_if_not_exists.
    let variant_of_edge_created = if let Some(parent_id_uuid) = parent_id {
        EdgeRepository::create_if_absent_including_retracted_conn(
            &mut *conn,
            workflow_id,
            "workflow",
            parent_id_uuid,
            "workflow",
            "variant_of",
            Some(serde_json::json!({"generation": generation})),
            None,
            None,
        )
        .await?;
        true
    } else {
        false
    };

    // ── 4. Ensure author agents ──────────────────────────────────────────
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    // Migration 148: a workflow never names a system identity as its author.
    // The legacy public-constant key is refused before the lookup (never
    // adopted, never re-minted after a rotation); an author that resolves to a
    // REGISTERED system agent under any other key is skipped after it. A
    // skipped author has no `author_agent_map` entry, so its
    // `author_placeholder` plan edges are skipped below.
    let registered_system_agents = if extraction.source.authors.is_empty() {
        Vec::new()
    } else {
        epigraph_db::SystemAgentRepository::registered_agent_ids(&mut *conn)
            .await
            .map_err(|e| {
                IngestExecutorError::AgentCreation(format!("system-agent registry read: {e}"))
            })?
    };
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        if epigraph_db::is_reserved_author_key(&pub_key_bytes) {
            tracing::warn!(
                target: "ingest.authors",
                author_index = idx,
                "skipping an author whose name derives a system agent's legacy key: a document \
                 cannot name a system identity as its author (migration 148)"
            );
            continue;
        }
        let agent_uuid: Uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(&mut *conn, &pub_key_bytes)
                .await
                .map_err(|e| IngestExecutorError::AgentCreation(format!("author lookup: {e}")))?
        {
            let id: Uuid = existing.id.into();
            if registered_system_agents.contains(&id) {
                tracing::warn!(
                    target: "ingest.authors",
                    author_index = idx,
                    "skipping an author that resolves to a registered system agent: a document \
                     cannot name a system identity as its author (migration 148)"
                );
                continue;
            }
            id
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create_conn(&mut *conn, &author_agent)
                .await
                .map_err(|e| IngestExecutorError::AgentCreation(format!("author create: {e}")))?;
            created.id.into()
        };
        author_agent_map.insert(idx, agent_uuid);
    }

    // ── 5. Walk planned claims: dedup-by-id ─────────────────────────────
    let mut claims_ingested = 0_usize;
    let mut claims_skipped_dedup = 0_usize;
    let mut inserted: Vec<(Uuid, String)> = Vec::new();
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();

    // The tenancy declaration `decl` (step 2) covers every claim this walk
    // creates, as it covered the `workflows` row.
    let mut reused_ids: Vec<Uuid> = Vec::new();

    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let raw_truth = confidence.clamp(0.01, 0.99);
        let truth = TruthValue::clamped(raw_truth);

        // Derive labels from kind property.
        let kind = planned
            .properties
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("workflow_claim");
        let labels = labels_for_planned_kind(kind);

        let was_new = ClaimRepository::create_with_id_if_absent_conn(
            &mut *conn,
            planned.id,
            &planned.content,
            &planned.content_hash,
            system_agent_id,
            truth,
            &labels,
            decl,
        )
        .await?;

        if was_new {
            // For level=2 (steps) and level=3 (operations), assign a
            // `step_lineage_id` UUID — see spec
            // `2026-05-05-step-level-versioning-design.md` §6.1, §6.2, §9.6, §9.7.
            // If the caller supplied one in `properties.step_lineage_id`, preserve it;
            // otherwise generate `Uuid::new_v4()`. Level=0/1 (thesis/phase) leave the
            // column NULL — workflow-level `variant_of` covers their evolution (§9.8).
            let mut properties = planned.properties.clone();
            let lineage_uuid: Option<Uuid> = if planned.level == 2 || planned.level == 3 {
                let existing = properties
                    .get("step_lineage_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok());
                let chosen = existing.unwrap_or_else(Uuid::new_v4);
                properties
                    .as_object_mut()
                    .expect("PlannedClaim.properties must be a JSON object")
                    .insert(
                        "step_lineage_id".to_string(),
                        serde_json::Value::String(chosen.to_string()),
                    );
                Some(chosen)
            } else {
                None
            };

            // Set properties + step_lineage_id via raw SQL (no set_properties
            // method on ClaimRepository).
            sqlx::query("UPDATE claims SET properties = $1, step_lineage_id = $2 WHERE id = $3")
                .bind(&properties)
                .bind(lineage_uuid)
                .bind(planned.id)
                .execute(&mut *conn)
                .await?;
            claims_ingested += 1;
            inserted.push((planned.id, planned.content.clone()));
        } else {
            claims_skipped_dedup += 1;
            reused_ids.push(planned.id);
        }

        id_map.insert(planned.id, planned.id);
    }

    // ── 5b. Declared tenancy: every reused claim must be the caller's to link ──
    //
    // A reused claim keeps its tenancy, and the edge trigger derives the
    // `executes` / `decomposes_to` edges' owner from their endpoints: an edge to
    // a claim private to G is owned by G. Those edges are written on the SYSTEM
    // agent's stamp, which (provisioned as a writer of every target group)
    // passes `WITH CHECK` for G even when the caller holds no membership of G.
    // So before any edge is written, read every reused claim on the stamp and
    // refuse one the stamp cannot read, or one private to a group outside the
    // caller's own writable set. A refusal rolls the whole ingest back.
    if let Some((group, caller)) = declared {
        let mut ids: Vec<Uuid> = Vec::new();
        for id in &reused_ids {
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
        let on_stamp: HashMap<Uuid, (String, Uuid)> =
            ClaimRepository::tenancy_on_session_conn(&mut *conn, &ids)
                .await?
                .into_iter()
                .map(|(id, v, o)| (id, (v, o)))
                .collect();
        let writable = caller.writable_groups();
        for claim_id in ids {
            let linkable = match on_stamp.get(&claim_id) {
                Some((v, _)) if v == "public" => true,
                Some((_, owner)) => *owner == group || writable.contains(owner),
                None => false,
            };
            if !linkable {
                return Err(IngestExecutorError::ReusedClaimOutsideCallerGroups { claim_id });
            }
        }
    }

    // ── 6. workflow —executes→ claim edges ──────────────────────────────
    //
    // `plan_index` IS LOAD-BEARING AND IT IS NEW. Every reader that maps a
    // hierarchical workflow's steps to "plan order" ordered by `e.created_at
    // ASC, c.id ASC`, and that worked only because each edge was inserted on its
    // OWN pool checkout and so got its own `NOW()`. The readers, all now keyed on
    // this ordinal with `created_at` as the fallback:
    //
    // * `WorkflowRepository::resolve_steps_to_heads`, `::resolve_steps_to_heads_batched`
    //   and `::step_texts_for_hierarchical` (`epigraph-db/src/repos/workflow.rs`);
    // * the two `report_hierarchical_outcome` handlers that turn a caller's
    //   `step_index` into a `behavioral_executions.step_claim_id` —
    //   `epigraph-mcp/src/tools/workflow_hierarchical.rs` and
    //   `epigraph-api/src/routes/workflows.rs`;
    // * `workflow_steps::find_phase` and `workflow_steps::ordered_steps`'s
    //   fallback ordering in this crate.
    //
    // The first revision of this comment claimed "every reader" after moving
    // only two of them. The report handlers were among those left behind, and
    // they failed SILENTLY: MEASURED on the real binary as `epigraph_app`, a
    // 6-step workflow reported with step_index 0..5 attached 4 of the 6
    // `behavioral_executions` rows to the WRONG step claim, on both schema
    // configurations, with `isError: false`.
    // `epigraph-mcp/tests/plan_order_under_one_transaction.rs` pins it.
    //
    // `claims.created_at` ties the same way — every claim in the plan is written
    // in this transaction — so a reader choosing among a workflow's claims by
    // `c.created_at` needs this ordinal too, not just the edge readers.
    //
    // Inside one transaction `NOW()` is TRANSACTION-start time in PostgreSQL, so
    // every edge in a plan shares it exactly, the tiebreak falls through to
    // `c.id ASC` — a content-derived UUID — and the steps come back in an
    // arbitrary order. MEASURED, not anticipated:
    // `find_workflow_union_hierarchical_test::find_workflow_returns_a_workflow_that_store_workflow_created`
    // failed with `["record the outcome", "recall recent theme claims", "cluster
    // without wipe_first"]` against a plan that ordered them the other way round.
    //
    // So the ordinal is recorded explicitly instead of being inferred from a
    // timestamp. That is strictly more robust than what it replaces: a
    // `created_at` tiebreak was already fragile for two edges written inside the
    // same clock tick, which is why `c.id ASC` was there at all.
    let mut executes_edges = 0_usize;
    for (plan_index, planned) in plan.claims.iter().enumerate() {
        let (_row, _was_created) = EdgeRepository::create_if_absent_including_retracted_conn(
            &mut *conn,
            workflow_id,
            "workflow",
            planned.id,
            "claim",
            "executes",
            Some(serde_json::json!({
                "level": planned.level,
                "plan_index": plan_index,
            })),
            None,
            None,
        )
        .await?;
        executes_edges += 1;
    }

    // ── 7. Intra-claim plan edges (decomposes_to / step_follows / phase_follows / cross-refs) ──
    let mut relationships_created = 0_usize;
    let mut inserted_edges: Vec<InsertedPlanEdge> = Vec::new();
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

        let (row, was_created) = EdgeRepository::create_if_absent_including_retracted_conn(
            &mut *conn,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await?;
        relationships_created += 1;
        if was_created {
            inserted_edges.push(InsertedPlanEdge {
                edge_id: row.id,
                source_id: src,
                source_type: src_type,
                target_id: tgt,
                target_type: edge.target_type.clone(),
                relationship: edge.relationship.clone(),
            });
        }
    }

    let reused_items = match declared {
        Some((group, caller)) => {
            reused_with_another_tenancy(&mut *conn, reused_ids, caller, group).await?
        }
        None => Vec::new(),
    };

    Ok(WorkflowIngestExecutionResult {
        workflow_id,
        canonical_name: canonical_name.clone(),
        generation,
        claims_ingested,
        claims_skipped_dedup,
        executes_edges_created: executes_edges,
        variant_of_edge_created,
        relationship_edges_created: relationships_created,
        already_ingested: false,
        inserted,
        inserted_edges,
        system_agent_id: Some(system_agent_id),
        reused_items,
    })
}
