//! Idempotent claim creation + AUTHORED verb-edge emission for MCP-layer
//! writers. See docs/architecture/noun-claims-and-verb-edges.md and
//! docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md.

use epigraph_core::Claim;
use epigraph_db::{ClaimRepository, EdgeRepository};
use serde_json::json;
use sqlx::{Acquire, PgConnection};

use crate::errors::{internal_error, McpError};
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
        internal_error(format!(
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
            internal_error(format!(
                "{tool_name}: could not resolve the author's viewer: {e}"
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
        return Err(internal_error(format!(
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
/// # Why the author's viewer and not the caller's
///
/// `submit_claim` and `memorize` author as `server.agent_id()` — the MCP
/// process's own agent — not as the HTTP principal on the bearer token. The rows
/// they write therefore inherit `owner_group_id` from the AUTHOR's personal
/// group, and migration 077's `WITH CHECK` on every claim-derived table asks
/// `owner_group_id = ANY(epigraph_writable_groups())`. Stamping the caller's
/// writable set would answer a question nothing asked and refuse the write.
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
/// EVERY submission; `epigraph_ensure_personal_group`'s membership statement is
/// `ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL,
/// role = 'admin'`, which was measured to take a revoked membership from 0 live
/// rows back to 1. That is a privilege change hidden inside an unrelated claim
/// insert — exactly what `ClaimRepository::personal_group_of`'s doc says the
/// read-first order exists to prevent — and it would also make the refusal below
/// unreachable in production while it still passed under the superuser test
/// harness. `epigraph-db/tests/author_stamped_write_loop.rs` pins both
/// measurements.
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
    author_agent_id: uuid::Uuid,
    tool_name: &'static str,
) -> Result<epigraph_db::ScopedTx<'p>, McpError> {
    let (scoped, author_viewer) = author_write_authority(
        server.scoped.as_ref(),
        &server.pool,
        author_agent_id,
        tool_name,
    )
    .await?;

    scoped.begin_as(&author_viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_write",
            tool = tool_name,
            author = %author_agent_id,
            error = %e,
            "could not begin an author-stamped transaction"
        );
        internal_error(format!(
            "{tool_name}: could not begin an author-stamped transaction: {e}"
        ))
    })
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
) -> Result<(), McpError> {
    let mut sp = conn.begin().await.map_err(internal_error)?;
    match EdgeRepository::create(
        &mut *sp,
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
    tool_name: &'static str,
) -> Result<(Claim, bool), McpError> {
    // Tenancy declaration (PR-16). Every MCP writer that reaches this helper
    // (`submit_claim`, `memorize`, `batch_submit_claims`) posts a claim
    // authored by the calling principal and carries no visibility parameter, so
    // the declaration is the author's own personal group, publicly visible.
    // Giving those tools a `visibility` argument is the write-side gate's work,
    // not this PR's; when it arrives, this is the single place it lands for all
    // three.
    let decl = ClaimRepository::default_decl_for_author(&mut *conn, claim.agent_id.into())
        .await
        .map_err(internal_error)?;
    let (claim, was_created) = ClaimRepository::create_or_get(&mut *conn, viewer, claim, decl)
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
