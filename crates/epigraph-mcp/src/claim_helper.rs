//! Idempotent claim creation + AUTHORED verb-edge emission for MCP-layer
//! writers. See docs/architecture/noun-claims-and-verb-edges.md and
//! docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md.

use epigraph_core::Claim;
use epigraph_db::repos::EdgeSigningKey;
use epigraph_db::{ClaimRepository, EdgeRepository};
use serde_json::json;
use sqlx::{Acquire, PgConnection};

use crate::errors::{internal_error, internal_error_logged, internal_error_text, McpError};
use crate::server::EpiGraphMcpFull;

/// The two things every author-stamped write needs and neither can be faked:
/// the [`epigraph_db::ScopedPool`] that can stamp a connection at all, and the
/// author's own [`Viewer`](epigraph_db::visibility::Viewer), proven to carry
/// write authority.
///
/// Extracted from [`begin_author_stamped_tx`] when the post-commit embed became
/// the second caller. It is ONE function rather than two copies because the
/// three refusals below are the whole safety argument — a second site that
/// resolved a viewer and skipped the empty-writable check would stamp a session
/// with an empty writable set and get a bare `42501` from whichever statement
/// ran first, which is precisely the diagnosis-free failure this module exists
/// to remove.
///
/// # Why it takes the pool and the `ScopedPool` rather than the server
///
/// Because [`crate::embed::McpEmbedder`] is the third caller and is not the
/// server: it holds its own `ScopedPool` (declared via
/// `McpEmbedder::with_scoped_pool`) and is cloned into detached background tasks
/// where no `&EpiGraphMcpFull` survives — `tools/ingestion.rs`'s embed queue is
/// `tokio::spawn`ed with `Arc::clone(&server.embedder)` alone. Parameterising
/// here is what lets all three write paths share ONE refusal triple instead of a
/// second copy that resolved a viewer and skipped the empty-writable check.
///
/// # Errors
/// * `McpError::internal_error` if this process was not built from a
///   [`epigraph_db::ScopedPool`] — never a fallback to the unstamped pool.
/// * `McpError::internal_error` if the author's viewer cannot be resolved.
/// * `McpError::internal_error` if that viewer has no writable group.
async fn author_write_authority<'p>(
    scoped: Option<&'p epigraph_db::ScopedPool>,
    pool: &sqlx::PgPool,
    author_agent_id: uuid::Uuid,
    tool_name: &'static str,
) -> Result<(&'p epigraph_db::ScopedPool, epigraph_db::visibility::Viewer), McpError> {
    let scoped = scoped.ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            "write refused: this MCP process was not built from a ScopedPool, so no \
             connection can be stamped with the author's tenancy context. Refusing rather \
             than writing on the unstamped pool, which commits the claim and then loses its \
             trace, evidence and AUTHORED edge to a 42501. Construct the server with \
             EpiGraphMcpFull::with_scoped_pool."
        );
        internal_error_text(format!(
            "{tool_name}: this MCP server was not built from a ScopedPool, so the write \
             path cannot stamp a connection with the author's tenancy context. Nothing was \
             written. Construct the server with EpiGraphMcpFull::with_scoped_pool."
        ))
    })?;

    let author_viewer = epigraph_db::visibility::Viewer::resolve(pool, author_agent_id)
        .await
        .map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_write",
                tool = tool_name,
                author = %author_agent_id,
                error = %e,
                "could not resolve the author's viewer"
            );
            internal_error_text(format!(
                "{tool_name}: could not resolve the author's viewer"
            ))
        })?;

    if author_viewer.writable_groups().is_empty() {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            author = %author_agent_id,
            "write refused: the author's viewer carries NO writable group, so the session \
             would be stamped with an empty writable set and every tier-A WITH CHECK would \
             refuse this submission from inside the transaction. What is missing is a live \
             `admin`/`writer` membership in a group the submission's rows would be owned by. \
             Nothing was written."
        );
        return Err(internal_error_text(format!(
            "{tool_name}: the author ({author_agent_id}) has no live writable group membership, \
             so no connection can be stamped with write authority for the rows this submission \
             would own. Nothing was written."
        )));
    }

    Ok((scoped, author_viewer))
}

/// Begin the ONE transaction an MCP submission runs in, stamped from the
/// **author's** viewer.
///
/// # Whose viewer: the author's, which since batch H-b IS the caller's
///
/// The author is a [`crate::write_identity::WriteIdentity`], which only
/// `EpiGraphMcpFull::write_identity` constructs: the principal of the request's
/// own viewer, i.e. `auth.agent_id` over HTTP and the server's own agent on
/// stdio. Taking the newtype rather than a bare `Uuid` is the ratchet: no tool
/// can stamp from an agent it picked itself, and the compiler enumerates every
/// site. Before batch H-b every tool passed `server.agent_id()` here whatever
/// the transport, so an authenticated caller's writes were authored and stamped
/// as the shared server signer (#505 F5).
///
/// The rows a submission writes inherit `owner_group_id` from the AUTHOR
/// (`default_decl_for_author`: the author's personal group, or its operator's
/// for an operated agent), and migration 077's `WITH CHECK` on every
/// claim-derived table asks `owner_group_id = ANY(epigraph_writable_groups())`,
/// so the stamp must be the author's writable set.
/// `epigraph-db/tests/rls_enforcement.rs::an_unstamped_app_connection_cannot_write_a_claim_derived_row`
/// is the pin: its arm 3 stamps the author's group and succeeds, its arm 4
/// stamps a *different* real group and is still refused.
///
/// `Viewer::resolve` reads `group_memberships` through
/// `epigraph_live_memberships(uuid)`, a SECURITY DEFINER function granted to
/// `epigraph_app` (migration 077), so resolving on the *unstamped* pool returns
/// the author's real memberships rather than the empty set
/// `group_memberships_tenancy` would otherwise yield. That is what makes this
/// bootstrap non-circular.
///
/// # Why `None` is a refusal and never a fallback
///
/// Falling back to `server.pool` when no `ScopedPool` is attached is precisely
/// how the defect this exists to fix presents: the claim INSERT is admitted (by
/// an orphan `claims_privacy` policy, where one exists), the trace INSERT is
/// refused with `42501`, and the caller receives an error carrying no claim id
/// for a row that is now a permanent orphan. A loud refusal with nothing written
/// is the only safe shape. Same decision, same reasoning and the same
/// `tenancy.scoped_write` log target as
/// `epigraph-api/src/routes/groups.rs::rotate_key`.
///
/// # Why an empty writable set is a REFUSAL, and why the group is NOT ensured here
///
/// The stamp is taken from the viewer as it is at `BEGIN` time, and every row
/// this submission writes is owned by the author's personal group — so if that
/// group has no live writable membership, the viewer's writable set is EMPTY and
/// the `WITH CHECK` on `claims` / `reasoning_traces` / `evidence` refuses the
/// write from inside the transaction. Minting inside the transaction cannot
/// repair that either: `create_claim_idempotent`'s first statement is
/// `ClaimRepository::default_decl_for_author`, whose `personal_group_of` does
/// mint on a miss, but the GUCs were stamped before it ran and a session's
/// writable set is not re-read per statement. So the empty set is refused up
/// front: it reports the real cause — this author has no writable group —
/// instead of a `42501` from whichever statement happened to be first, and
/// nothing is half-written.
///
/// A belt-and-braces `ClaimRepository::personal_group_of_pool` call was added
/// here first and then REMOVED, because on this connection it is not the
/// read-first lookup its name promises. MEASURED on a migrated database, as
/// `epigraph_app` with no GUCs: `SELECT id FROM groups WHERE did_key = …`
/// returns **0 rows** for a group that exists — `groups_tenancy`'s USING is
/// `bypass OR definer_bypass OR id = ANY(session_groups) OR created_by_agent_id =
/// principal_id`, and on an unstamped app session every arm is false. So the read
/// is BLIND in production and `personal_group_of` would take its mint path on
/// EVERY submission; migration 077's `epigraph_ensure_personal_group` membership
/// statement was `ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET
/// revoked_at = NULL, role = 'admin'`, which was measured to take a revoked
/// membership from 0 live rows back to 1 — a privilege change hidden inside an
/// unrelated claim insert. Migration 105 makes that call refuse a revoked row
/// instead of reviving it, so the hazard is gone at its root; the call stays
/// removed because a per-submission control-plane write on the pool buys
/// nothing the refusal below does not already report.
/// `epigraph-db/tests/author_stamped_write_loop.rs` pins both measurements.
///
/// The group is therefore ensured exactly where it already was:
/// `server.rs::agent_id`'s PR-09 block, once per process, before either caller
/// reaches this function.
///
/// The refusal is the one part of this conversion that changes behaviour for a
/// deployment that currently works: on a superuser DSN `epigraph_bypass()` is
/// true, so a submission by an author with no writable group commits today. That
/// is exactly the configuration whose DSN change turned the same write into a
/// half-landed orphan, and a write that only succeeds because the session
/// bypasses RLS is not a write this path should be making.
///
/// # Errors
/// * `McpError::internal_error` if this process was not built from a
///   [`epigraph_db::ScopedPool`].
/// * `McpError::internal_error` if the author's viewer cannot be resolved, if
///   that viewer has no writable group, or if `BEGIN` / the GUC stamp fails.
pub async fn begin_author_stamped_tx<'p>(
    server: &'p EpiGraphMcpFull,
    author: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
) -> Result<epigraph_db::ScopedTx<'p>, McpError> {
    begin_author_stamped_tx_for(server, author, tool_name, None).await
}

/// [`begin_author_stamped_tx`] for a claim write whose declared tenancy may
/// name a TEAM the author writes only through its live human (owner decision
/// D-V3, `docs/tenancy/claim-visibility-controls.md`).
///
/// `grant` is the [`epigraph_db::TeamWriteGrant`] that
/// `ClaimRepository::resolve_write_decl` returned, and only that function mints
/// one. With it, the stamp carries the team in its writable set
/// (`Viewer::with_team_write_grant`). The grant must name THIS author, or the
/// write is refused. Everything else, including all three refusals of
/// [`author_write_authority`], is unchanged.
///
/// # Errors
/// As [`begin_author_stamped_tx`], plus `McpError::internal_error` for a grant
/// that names another agent.
pub async fn begin_author_stamped_tx_for<'p>(
    server: &'p EpiGraphMcpFull,
    author: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
    grant: Option<&epigraph_db::TeamWriteGrant>,
) -> Result<epigraph_db::ScopedTx<'p>, McpError> {
    let author_agent_id = author.agent_id();
    let (scoped, author_viewer) = author_write_authority(
        server.scoped.as_ref(),
        &server.pool,
        author_agent_id,
        tool_name,
    )
    .await?;
    let author_viewer = match grant {
        None => author_viewer,
        Some(g) => author_viewer.with_team_write_grant(g).ok_or_else(|| {
            internal_error_text(format!(
                "{tool_name}: the team-write grant names agent {}, not the author {author_agent_id}; \
                 nothing was written",
                g.agent()
            ))
        })?,
    };

    scoped.begin_as(&author_viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            author = %author_agent_id,
            error = %e,
            "could not begin an author-stamped transaction"
        );
        internal_error_text(format!(
            "{tool_name}: could not begin an author-stamped transaction"
        ))
    })
}

/// Map a visibility-control error for the caller. A designed refusal keeps its
/// text, with `Input` as `INVALID_PARAMS` and `Authority`/`State` as
/// `INVALID_REQUEST`. A claim the caller cannot read is answered exactly as a
/// missing one. Everything else goes to [`crate::errors::db_caller_error`].
pub fn visibility_caller_error(e: epigraph_db::DbError) -> McpError {
    use epigraph_db::errors::RefusalKind;
    match e {
        epigraph_db::DbError::Refused {
            kind: RefusalKind::Input,
            message,
        } => crate::errors::invalid_params(message),
        epigraph_db::DbError::Refused { message, .. } => McpError {
            code: rmcp::model::ErrorCode::INVALID_REQUEST,
            message: std::borrow::Cow::from(message),
            data: None,
        },
        epigraph_db::DbError::NotFound { entity, id } => {
            crate::errors::invalid_params(format!("{entity} {id} not found"))
        }
        other => crate::errors::db_caller_error(other),
    }
}

/// Resolve a claim write's `visibility` / `group_id` parameters for `author`
/// (docs/tenancy/claim-visibility-controls.md): team by default, else private,
/// never public unless asked. Runs BEFORE the author-stamped transaction
/// because a team the author writes only through its human (D-V3) must be
/// stamped into it ([`begin_author_stamped_tx_for`]). Every read is a migration
/// 206 or 107 definer, so the unstamped pool answers correctly.
///
/// # Errors
/// `INVALID_PARAMS` for a malformed or contradictory pair, and the caller
/// errors of [`visibility_caller_error`] for a refused team or author.
pub async fn resolve_claim_visibility(
    server: &EpiGraphMcpFull,
    author: uuid::Uuid,
    visibility: Option<&str>,
    group_id: Option<&str>,
) -> Result<epigraph_db::ResolvedWriteDecl, McpError> {
    let choice = epigraph_core::VisibilityChoice::parse_str(visibility, group_id)
        .map_err(crate::errors::invalid_params)?;
    let mut conn = server.pool.acquire().await.map_err(internal_error)?;
    ClaimRepository::resolve_write_decl(&mut conn, author, choice)
        .await
        .map_err(visibility_caller_error)
}

/// The viewer the reads of ONE write run through (the DS wiring, the
/// read-backs), when the request's own viewer would not see the row:
///
/// * the resolution just PROVISIONED the author's home group
///   (`default_decl_for_author` mints a personal group on a miss), which the
///   viewer resolved at the start of the request does not hold, so a private
///   claim written there would be invisible to its own DS wiring. The viewer
///   is re-resolved once (the rare first-write path; `epigraph-api`
///   `routes/claims.rs::create_claim_core` does the same);
/// * a D-V3 team grant: the viewer widened by it, for this write only.
///
/// `None` when neither applies, or when the grant names another agent: the
/// caller then keeps its own viewer, and the stamp (which refuses such a
/// grant) decides.
///
/// # Errors
/// `McpError::internal_error` if the re-resolve fails.
pub async fn write_viewer(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    author: uuid::Uuid,
    resolved: &epigraph_db::ResolvedWriteDecl,
) -> Result<Option<epigraph_db::visibility::Viewer>, McpError> {
    let refreshed = if resolved.operator_grant.is_none()
        && resolved.decl.visibility_bind() == Some("group")
        && viewer.principal() == Some(author)
        && viewer.group_bind().is_some_and(|g| {
            resolved
                .decl
                .owner_group_bind()
                .is_some_and(|o| !g.contains(&o))
        }) {
        Some(
            epigraph_db::visibility::Viewer::resolve(&server.pool, author)
                .await
                .map_err(internal_error)?,
        )
    } else {
        None
    };
    let granted = resolved.operator_grant.as_ref().and_then(|g| {
        refreshed
            .as_ref()
            .unwrap_or(viewer)
            .with_team_write_grant(g)
    });
    Ok(granted.or(refreshed))
}

/// The tenancy the claim landed in, read on the write's own transaction
/// (`ClaimRepository::write_tenancy_report`, D-V4 note included).
///
/// # Errors
/// `McpError::internal_error` if the read fails.
pub async fn claim_tenancy_report(
    conn: &mut PgConnection,
    claim_id: uuid::Uuid,
    resolved: &epigraph_db::ResolvedWriteDecl,
    was_created: bool,
) -> Result<epigraph_db::WriteTenancyReport, McpError> {
    ClaimRepository::write_tenancy_report(conn, claim_id, resolved, was_created)
        .await
        .map_err(internal_error)
}

/// Begin the ONE transaction a WORKFLOW write runs in (`store_workflow`,
/// `ingest_workflow`, `improve_workflow_hierarchy`, `add_step`, `delete_step`,
/// `deprecate_workflow`, and the post-commit DS wiring of an ingest), stamped
/// from the CALLER's own viewer: [`begin_author_stamped_tx`] for the request's
/// write identity, exactly as every other writer tool.
///
/// # Why the caller and no longer the workflow-ingest system agent
///
/// These writes used to be authored by, and stamped from, ONE shared
/// workflow-ingest system agent, and the caller was bound to that agent's
/// human (`epigraph_ingest_executor::require_caller_write_authority`). Once
/// the system agent was live-linked to one human operator, every OTHER human
/// was refused `OPL02` ("holds no writer/admin membership in group <that
/// operator's group>"), however fully it was onboarded into a team, and the
/// rows of the one human it admitted landed in the operator's group under a
/// shared identity. Now the executor authors every row as the caller
/// (`epigraph_ingest_executor::execute_workflow_ingest_plan_in_group`,
/// `epigraph_ingest_executor::add_step`) and owns it in a group the caller
/// writes (`epigraph_ingest_executor::owner`), so the stamp is the caller's
/// and the database's own checks (row security, migration 122's claims
/// trigger) apply to the real writer. No caller can write into a group it
/// does not write through any of these paths: the stamp is its own, and the
/// executor re-checks a chosen group live on this transaction.
///
/// The authority over an EXISTING workflow (`tools::workflow_authority`: the
/// submitter, its operator, or the audited admin arm) is unchanged and still
/// checked at every call site on this transaction, before the write.
///
/// # Errors
/// As [`begin_author_stamped_tx`]: no `ScopedPool`, an unresolvable viewer, an
/// author with no writable group, or a failed `BEGIN` / stamp. Never a
/// fallback to the unstamped pool.
pub async fn begin_caller_workflow_tx<'p>(
    server: &'p EpiGraphMcpFull,
    caller: crate::write_identity::WriteIdentity,
    tool_name: &'static str,
) -> Result<epigraph_db::ScopedTx<'p>, McpError> {
    begin_author_stamped_tx(server, caller, tool_name).await
}

/// Run `ds_auto::auto_wire_ds_for_claim` INSIDE the submission's own
/// author-stamped transaction, before COMMIT. A failure is RETURNED.
///
/// # Why the DS wiring joined the write transaction
///
/// It used to run post-commit on its own stamped transaction and be warn-only.
/// On failure the tool reported success with `belief: null` over a claim that
/// had committed without the BBA every consumer's belief read is derived from.
/// That is the partial-state-behind-a-success-response shape the R3 gate
/// forbids. The reason it stayed outside was that the wiring was refused
/// outright on the unstamped pool (`claim_frames` carries no orphan
/// `*_privacy` policy), and folding a refusal into the write would have
/// converted a WARN into a total `submit_claim` outage. That reason is gone.
/// The wiring now runs on the same stamp as the claim, and the rows it writes
/// (`claim_frames`, `mass_functions`, the cached-belief `UPDATE claims`) take
/// their tenancy from that claim. If the claim may be written, so may its
/// wiring. What is left is a genuine failure, and a genuine failure should fail
/// the submission.
///
/// Retrying is safe: nothing committed, `create_claim_idempotent` dedupes on
/// `(content_hash, agent_id)`, and the Evidence / Trace rows the failed attempt
/// built were in the rolled-back transaction, so no orphan is left behind.
///
/// # THE `was_created` GATE IS THE CALLER'S AND MUST NOT MOVE
///
/// Both callers gate this on `was_created` alone, and the asymmetry with the
/// embed gate (which was deliberately widened) is not an oversight — the two
/// have OPPOSITE safety properties. Re-running the embed overwrites one vector
/// with an equivalent one; re-running this COMBINES the same mass a second time
/// and inflates the claim's belief. This helper therefore takes no view on when
/// it should run: it is called inside the caller's `if was_created` and that is
/// where the decision stays.
///
/// `persist_truth_from_pignistic` folds the caller's follow-up
/// `UPDATE claims SET truth_value` into the SAME transaction. `submit_claim`
/// needs it and `memorize` does not. The UPDATE writes a value DERIVED from the
/// BBA this wiring just stored, so the two are one fact.
///
/// # Errors
/// `McpError::internal_error` naming the step, when the wiring or the
/// `truth_value` update fails. The caller propagates it and never reaches
/// COMMIT, so nothing is written.
pub async fn wire_ds_for_new_claim_in_tx(
    conn: &mut PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    author_agent_id: uuid::Uuid,
    claim_id: uuid::Uuid,
    input: crate::tools::ds_auto::DsAutoInput<'_>,
    persist_truth_from_pignistic: bool,
    tool_name: &'static str,
) -> Result<crate::tools::ds_auto::DsAutoResult, McpError> {
    let result = crate::tools::ds_auto::auto_wire_ds_for_claim(
        &mut *conn,
        viewer,
        claim_id,
        author_agent_id,
        input,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            claim_id = %claim_id,
            tool = tool_name,
            "ds auto-wire failed inside the submission transaction: {e}. Rolling back the \
             whole submission; nothing was written"
        );
        internal_error_text(format!(
            "{tool_name}: the claim's Dempster-Shafer belief could not be wired. The \
             submission was rolled back and nothing was written; retrying is safe."
        ))
    })?;

    if persist_truth_from_pignistic {
        let ds_truth = epigraph_core::TruthValue::clamped(result.pignistic_prob);
        ClaimRepository::update_truth_value_conn(
            &mut *conn,
            epigraph_core::ClaimId::from_uuid(claim_id),
            ds_truth,
        )
        .await
        .map_err(|e| {
            internal_error_logged(
                format!(
                    "{tool_name}: the truth value derived from the claim's belief could not \
                     be stored. The submission was rolled back and nothing was written."
                ),
                e,
            )
        })?;
    }

    Ok(result)
}

/// Generate (or reuse) a claim's embedding vector and store it on a connection
/// stamped from the **author's** viewer. Post-commit, best-effort, and
/// deliberately NOT inside the submission's write transaction.
///
/// Returns whether a vector actually landed on the row — the `embedded` field
/// both tools report.
///
/// # Why this is the release gate rather than a tidy-up
///
/// `ClaimRepository::store_embedding(&server.pool, …)` is an `UPDATE claims`,
/// and migration 077's `claims_tenancy` `WITH CHECK` asks
/// `owner_group_id = ANY(epigraph_writable_groups())`. On the unstamped pool
/// that set is `{}`, so on a cleanly-migrated schema the UPDATE is **refused**
/// — and the refusal was swallowed by design, because the embed is best-effort.
/// MEASURED end-to-end against the real binary as `epigraph_app`: the tool
/// returned success with `embedded: false` and the row kept `embedding IS NULL`.
///
/// Production does not show this today only because it carries an orphan
/// PERMISSIVE `claims_privacy` policy that exists in no migration. Dropping
/// that policy is the remediation; doing it before this site is converted would
/// make every new claim land unembedded and therefore invisible to `recall()`,
/// surfacing only as CLAUDE.md's `live_missing` climbing with **no error
/// anywhere**. Hence: convert first, drop second.
///
/// # `begin_as`, not `acquire_as`
///
/// A stamped *connection* is what this needs, and `acquire_as` is the one-round-trip
/// way to get one — but it hard-refuses `SessionGucMode::Transaction`, the
/// transaction-pooler fallback `bin/server.rs` advertises to operators
/// (`EPIGRAPH_SESSION_GUC_MODE=transaction`). A site written that way is
/// unservable in a supported configuration and CI has no pgbouncer fixture to
/// catch it, which is exactly the rule
/// `epigraph-db/tests/no_unscoped_pool.rs` states for shard authors: reads
/// convert onto the mode-dispatching helper, **writes target
/// `ScopedPool::begin_as`**. `ScopedPool::read_as`'s own doc adds the other half
/// — it is documented read-only because its `Session` arm is not a transaction.
/// So the embed's single `UPDATE` runs in its own one-statement transaction.
///
/// # The provider round trip stays OUTSIDE the transaction
///
/// `generate` is awaited before `begin_as` is called. That is the point of
/// keeping the embed post-commit at all: an embedding call must not hold a
/// transaction — nor a pooled connection — open across a network hop to OpenAI.
///
/// # Why `store_embedding_if_unsealed` and not `store_embedding`
///
/// The pair exists because the read that decided this claim needs a vector and
/// the write that stores one are separated by that provider round trip, and a
/// claim can be SEALED inside the window. `store_embedding_if_unsealed` takes
/// the row lock first and re-checks `claim_encryption` and `is_current` against
/// a snapshot that includes anything committed during the wait, and it splices
/// the viewer's `{WRITABLE:c}` predicate so the statement's own qual agrees with
/// the session GUCs this connection was stamped with. Both halves must be the
/// AUTHOR's viewer: the row is owned by the author's personal group, so a
/// caller-viewer splice here would render a predicate no row satisfies while the
/// GUCs said otherwise — a mismatch `#[sqlx::test]` cannot see, because that
/// harness connects as a BYPASSRLS superuser.
///
/// # Failures are warned, never returned
///
/// The claim is already committed. CLAUDE.md's embedding policy is explicit that
/// a failed embed must not block or unwind the write, so every failure path here
/// logs and reports `false`. The missing-`ScopedPool` and empty-writable-set
/// refusals are logged at ERROR on `tenancy.scoped_write` — loud, named, and
/// never a fallback to `server.pool`, which is how a `42501` becomes a silent
/// `live_missing` row.
pub async fn embed_claim_author_stamped(
    server: &EpiGraphMcpFull,
    author_agent_id: uuid::Uuid,
    claim_id: uuid::Uuid,
    text: &str,
    pending_embedding: Option<String>,
    tool_name: &'static str,
) -> bool {
    // Reuse the novelty gate's already-generated vector when there is one; only
    // the gate's embedder-failure path and the repair arm (where an exact
    // resubmit means the gate never ran) pay a second provider call.
    let pgvec = match pending_embedding {
        Some(v) => v,
        None => match server.embedder.generate(text).await {
            Ok(v) => crate::embed::format_pgvector(&v),
            Err(e) => {
                tracing::warn!(
                    claim_id = %claim_id,
                    tool = tool_name,
                    "embedding generation failed (claim still stored): {e}"
                );
                return false;
            }
        },
    };

    match store_embedding_author_stamped(
        server.scoped.as_ref(),
        &server.pool,
        author_agent_id,
        claim_id,
        &pgvec,
        tool_name,
    )
    .await
    {
        Ok(stored) => stored,
        Err(e) => {
            tracing::warn!(
                claim_id = %claim_id,
                tool = tool_name,
                "the post-commit embed could not store a vector: {e}. The claim is stored but \
                 carries no vector and is invisible to semantic recall until the maintenance \
                 backfill reaches it"
            );
            false
        }
    }
}

/// Run ONE `UPDATE claims SET embedding` on a connection stamped from
/// `author_agent_id`'s viewer. **The single stamped-store mechanism in this
/// crate.**
///
/// Extracted from [`embed_claim_author_stamped`] when the reviewer of the first
/// revision of this branch pointed out the real shape of the defect: that
/// revision converted `submit_claim` and `memorize`'s embed and left
/// `McpEmbedder::embed_and_store` — used by `store_workflow`, `ingest_workflow`,
/// `improve_workflow_hierarchy`, `add_step`, `consolidate_claims` and both
/// `ingest_document` paths — storing through the embedder's own unstamped pool.
/// Seven callers of a broken store, fixed at two call sites. Both entry points
/// now land here, so there is one place the tenancy argument has to be right.
///
/// # `begin_as`, not `acquire_as`
///
/// A stamped *connection* is what this needs, and `acquire_as` is the
/// one-round-trip way to get one — but it hard-refuses
/// `SessionGucMode::Transaction`, the transaction-pooler fallback `bin/server.rs`
/// advertises to operators (`EPIGRAPH_SESSION_GUC_MODE=transaction`). A site
/// written that way is unservable in a supported configuration and CI has no
/// pgbouncer fixture to catch it, which is exactly the rule
/// `epigraph-db/tests/no_unscoped_pool.rs` states for shard authors: reads
/// convert onto the mode-dispatching helper, **writes target
/// `ScopedPool::begin_as`**. So the single `UPDATE` runs in its own
/// one-statement transaction.
///
/// # Why `store_embedding_if_unsealed` and not `store_embedding`
///
/// The pair exists because the read that decided this claim needs a vector and
/// the write that stores one are separated by a provider round trip, and a claim
/// can be SEALED inside the window. `store_embedding_if_unsealed` takes the row
/// lock first and re-checks `claim_encryption` and `is_current` against a
/// snapshot that includes anything committed during the wait, and it splices the
/// viewer's `{WRITABLE:c}` predicate so the statement's own qual agrees with the
/// session GUCs this connection was stamped with. Both halves must be the
/// AUTHOR's viewer: the row is owned by the author's personal group, so a
/// caller-viewer splice here would render a predicate no row satisfies while the
/// GUCs said otherwise — a mismatch `#[sqlx::test]` cannot see, because that
/// harness connects as a BYPASSRLS superuser.
///
/// # Errors
///
/// `Err(String)` when no vector could be stored for a reason the caller may want
/// to name in its own log line: no `ScopedPool`, an author with no writable
/// group, a failed stamp, a failed statement, or a failed commit. `Ok(false)`
/// means the statement ran and matched no row — claim missing, sealed,
/// superseded, or not writable by its author's viewer. Callers treat both as
/// "not embedded"; CLAUDE.md's embedding policy forbids either from unwinding an
/// already-committed claim.
pub(crate) async fn store_embedding_author_stamped(
    scoped: Option<&epigraph_db::ScopedPool>,
    pool: &sqlx::PgPool,
    author_agent_id: uuid::Uuid,
    claim_id: uuid::Uuid,
    pgvec: &str,
    tool_name: &'static str,
) -> Result<bool, String> {
    // `author_write_authority` has already logged the specific cause at ERROR on
    // `tenancy.scoped_write`; its message is re-surfaced here so the caller's own
    // warn line carries it too.
    let (scoped, author_viewer) = author_write_authority(scoped, pool, author_agent_id, tool_name)
        .await
        .map_err(|e| e.message.to_string())?;

    let mut tx = scoped
        .begin_as(&author_viewer)
        .await
        .map_err(|e| format!("could not begin an author-stamped transaction: {e}"))?;

    match ClaimRepository::store_embedding_if_unsealed(&mut tx, &author_viewer, claim_id, pgvec)
        .await
    {
        Ok(true) => tx
            .commit()
            .await
            .map(|()| true)
            .map_err(|e| format!("the embedding UPDATE succeeded but could not commit: {e}")),
        Ok(false) => {
            // Four indistinguishable causes by construction: no such claim, a
            // claim sealed or superseded since the text was read, or a row this
            // viewer may not write. None of them is an error the caller can act
            // on, and all of them mean "no vector was stored".
            let _ = tx.commit().await;
            Ok(false)
        }
        Err(e) => Err(format!(
            "embedding store failed on the author-stamped connection: {e}"
        )),
    }
}

/// Emit a verb-edge whose failure must NOT abort the caller's transaction.
///
/// # Why a SAVEPOINT rather than `let _ = EdgeRepository::create(…)`
///
/// The architecture doc's atomicity policy makes verb-edges best-effort: a
/// failed `AUTHORED` / `DERIVED_FROM` / `HAS_TRACE` emit is logged and the
/// submission still succeeds. That was expressible as a swallowed error only
/// while every statement ran on its own pool checkout. Inside a PostgreSQL
/// transaction a failed statement aborts the whole transaction, so swallowing
/// the error does not preserve the policy — it *defers* the failure to `COMMIT`,
/// which then fails with `current transaction is aborted, commands ignored until
/// end of transaction block` and the real cause nowhere in the error the caller
/// receives. That is strictly worse than either alternative: the claim is lost
/// (as if the edge were fatal) AND the diagnostic is gone.
///
/// Propagating instead was also refused, and the reason is deployment-shaped
/// rather than stylistic. `edges` is one of the three tables that a deployment
/// may carry an orphan PERMISSIVE `*_privacy` policy for; where that policy is
/// absent, `edges_tenancy`'s `WITH CHECK` governs alone. Making the edge fatal
/// would therefore convert a WARN into a total `submit_claim` / `memorize`
/// outage on any deployment whose edge policy refuses the row, which is exactly
/// the fail-closed-regression-as-data-loss shape this programme is trying to
/// avoid creating.
///
/// A savepoint keeps both properties: the edge either lands or is rolled back
/// alone, and the outer transaction is still usable either way.
///
/// `key` attests the edge AT INSERT (rulings R-49, R-50): the server's
/// signer ([`EpiGraphMcpFull::edge_signing_key`]). These verb-edges have an
/// `agent` or `evidence` / `trace` endpoint, and an agent-sourced edge is
/// world-owned, which no application session may UPDATE afterwards, so the
/// INSERT is the only point it can be signed. `None` writes it unsigned.
///
/// # Errors
///
/// Returns an error only if the SAVEPOINT itself could not be taken or released
/// — i.e. the outer transaction was already unusable, which the caller must not
/// paper over. An edge INSERT that is *refused* is logged and reported as
/// `Ok(())`.
#[allow(clippy::too_many_arguments)]
pub async fn emit_verb_edge_best_effort(
    conn: &mut PgConnection,
    source_id: uuid::Uuid,
    source_type: &str,
    target_id: uuid::Uuid,
    target_type: &str,
    relationship: &str,
    properties: Option<serde_json::Value>,
    tool_name: &'static str,
    key: Option<EdgeSigningKey<'_>>,
) -> Result<(), McpError> {
    let mut sp = conn.begin().await.map_err(internal_error)?;
    match EdgeRepository::create_signed_conn(
        &mut sp,
        key,
        source_id,
        source_type,
        target_id,
        target_type,
        relationship,
        properties,
        None,
        None,
    )
    .await
    {
        Ok(_) => sp.commit().await.map_err(internal_error),
        Err(e) => {
            tracing::warn!(
                source_id = %source_id,
                target_id = %target_id,
                relationship = relationship,
                tool = tool_name,
                error = %e,
                "verb-edge emit failed; rolled back to savepoint and continuing — the \
                 claim and its provenance are unaffected"
            );
            sp.rollback().await.map_err(internal_error)
        }
    }
}

/// Idempotently create a claim by `(content_hash, agent_id)` and emit an
/// AUTHORED verb-edge marking the submission lifecycle event.
///
/// Mirrors the API handler's pattern at routes/claims.rs: dedup via
/// `ClaimRepository::create_or_get`, then the AUTHORED verb-edge. Each
/// submission emits a distinct AUTHORED edge regardless of `was_created`,
/// because each submission is an authorship verb-event.
///
/// # This takes a connection, not a pool, and that is the fix
///
/// It used to take `&PgPool`, acquire its own checkout for the claim, drop it,
/// and then emit AUTHORED on a second checkout. Three consequences, all
/// observed in production:
///
/// 1. **The claim committed on its own.** A caller whose trace INSERT was then
///    refused (`42501` on `reasoning_traces`, the unstamped-connection defect
///    `epigraph-db/tests/rls_enforcement.rs` pins) got an error with no claim
///    id, while the claim row survived with no trace, no evidence and no
///    AUTHORED edge. The log line this function used to carry said so in as
///    many words: *"claim row persisted as orphan"*.
/// 2. **The connection could not be the stamped one.** Only
///    `ScopedPool::begin_as` stamps the tenancy GUCs the 077 policies read, and
///    it yields a transaction. A pool parameter cannot accept one.
/// 3. **Each checkout was a separate tenancy context**, so which statements were
///    admitted depended on which pooled connection each one happened to get.
///
/// The caller now owns the transaction — see
/// `tools::claims::submit_claim` and `tools::memory::memorize` — and passes
/// `&mut *tx`.
///
/// `viewer` is the CALLER's read authority, deliberately distinct from the
/// author's authority that stamped the connection: the spliced predicate on the
/// dedup read asks "may this caller see this row", while the session GUCs ask
/// "may the author write into this group". Both must hold; neither substitutes
/// for the other.
///
/// # Errors
/// Returns `McpError::internal_error` if `default_decl_for_author` or
/// `ClaimRepository::create_or_get` fail. AUTHORED edge failure is not returned
/// (logged + rolled back to a savepoint, see
/// [`emit_verb_edge_best_effort`]).
pub async fn create_claim_idempotent(
    conn: &mut PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim: &Claim,
    signer_agent_id: Option<uuid::Uuid>,
    tool_name: &'static str,
    edge_key: Option<EdgeSigningKey<'_>>,
    decl: epigraph_core::TenancyDecl,
) -> Result<(Claim, bool), McpError> {
    // Tenancy declaration. Every MCP writer that reaches this helper
    // (`submit_claim`, `memorize`, `batch_submit_claims`) resolves it from the
    // caller's `visibility` / `group_id` through
    // `ClaimRepository::resolve_write_decl` (team by default, private and public
    // on request; docs/tenancy/claim-visibility-controls.md) BEFORE the
    // transaction opens, because a team the author writes only through its human
    // must be stamped into the transaction (`begin_author_stamped_tx_for`).
    // `resolve_write_decl` calls `default_decl_for_author` first, so its
    // refusals (OPL01, OPL02, RVK01) still fire for every visibility.
    // The signature is persisted with its SIGNER (batch H-b, D1-sig): the author
    // is `claim.agent_id`, the signer is `signer_agent_id`, and since D1 they
    // differ for every authenticated caller. `verify_claim` checks the stored
    // signature against the signer's key. `None` stores no signature, as before.
    let (claim, was_created) =
        ClaimRepository::create_or_get_signed(&mut *conn, viewer, claim, decl, signer_agent_id)
            .await
            .map_err(internal_error)?;

    emit_verb_edge_best_effort(
        &mut *conn,
        claim.agent_id.as_uuid(),
        "agent",
        claim.id.as_uuid(),
        "claim",
        "AUTHORED",
        Some(json!({"tool": tool_name, "was_created": was_created})),
        tool_name,
        edge_key,
    )
    .await?;

    // Note: the durable `claim.created` event for this submission is emitted
    // inside `ClaimRepository::create_strict` (which `create_or_get` calls on
    // the success branch). Centralizing the emit at the repository boundary
    // ensures all writers — submit_claim, ingest_paper, ingest_workflow,
    // batch ingestion, API conventions — produce the event, not just the
    // MCP submit_claim path. See claim.rs::create_strict for the emit site
    // and crates/epigraph-db/src/repos/event.rs::publish_or_log_conn for
    // the transactional sink.

    Ok((claim, was_created))
}
