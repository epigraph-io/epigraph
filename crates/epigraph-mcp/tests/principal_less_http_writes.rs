//! Batch HTTP-id: every HTTP write is authored by an agent that belongs to the
//! calling human, and a caller with no authenticated principal writes nothing.
//!
//! Measured first (`scripts/e2e/probe-httpid.sh` at the batch H-b tip): an OAuth
//! principal's writes were already its own; the `--allow-unauthenticated-http`
//! listener's writes were authored by the listener's signer, an agent no human
//! owns. These arms pin both halves at the tool-function layer, which is BELOW
//! the per-tool scope gate: `tests/http_auth_test.rs` pins that the gate refuses
//! the principal-less listener's write tools; here the tool functions are
//! driven directly, so what is exercised is the second, independent layer in
//! `EpiGraphMcpFull::write_identity`.
//!
//! Superuser harness (BYPASSRLS): what is visible is WHO the rows name and
//! whether rows were written at all, not a `42501`. The RLS half is the probe's.
//!
//! Load-bearing, verified by reverting the `is_principal_less` refusal in
//! `write_identity`: `a_principal_less_caller_writes_nothing_by_default` fails
//! (the claim is written, authored by the signer).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_mcp::auth::{unauthenticated_context, UnauthenticatedWrites};
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    MemorizeParams, ResolveBacklogItemParams, SubmitClaimParams, UpdateLabelsParams,
    UpdateWithEvidenceParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// A HUMAN principal's token as the authorization-code / consent flow mints it:
/// `sub` is the human's own `oauth_clients` row, `agent_id` its agent.
fn human_token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Human,
        scopes: vec!["claims:read".into(), "claims:write".into()],
        jti: Uuid::new_v4(),
    }
}

fn submit(content: &str, labels: &[&str]) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "extraction".to_string(),
        evidence_data: format!("evidence for {content}"),
        evidence_type: "empirical".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
        labels: labels.iter().map(|l| (*l).to_string()).collect(),
        novelty_threshold: Some(0.0),
    }
}

fn memorize(content: &str) -> MemorizeParams {
    MemorizeParams {
        content: content.to_string(),
        confidence: None,
        tags: None,
        novelty_threshold: Some(0.0),
    }
}

fn evidence_for(claim: Uuid) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        claim_id: claim.to_string(),
        canonical_name: None,
        step_index: None,
        evidence_data: "HTTP-id: supporting evidence".to_string(),
        evidence_type: "empirical".to_string(),
        supports: true,
        strength: 0.6,
        source_url: None,
        labels: vec![],
    }
}

fn resolve(item: Uuid, text: &str) -> ResolveBacklogItemParams {
    ResolveBacklogItemParams {
        original_id: item.to_string(),
        resolution_content: text.to_string(),
        methodology: None,
        basis_claim_ids: vec![],
    }
}

async fn row_of(pool: &PgPool, content: &str) -> Option<(Uuid, Uuid, Uuid)> {
    sqlx::query_as("SELECT id, agent_id, owner_group_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_optional(pool)
        .await
        .expect("read back")
}

async fn has_label(pool: &PgPool, claim: Uuid, label: &str) -> bool {
    sqlx::query_scalar("SELECT $2 = ANY(labels) FROM claims WHERE id = $1")
        .bind(claim)
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("read labels")
}

async fn resolutions_of(pool: &PgPool, item: Uuid) -> Vec<(Uuid, Uuid)> {
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content LIKE $1")
        .bind(format!("Resolves {item}:%"))
        .fetch_all(pool)
        .await
        .expect("read resolutions")
}

/// The human's own backlog item, written over HTTP as the human.
async fn humans_backlog_item(
    pool: &PgPool,
    server: &epigraph_mcp::EpiGraphMcpFull,
    human: Uuid,
    content: &str,
) -> Uuid {
    let viewer = Viewer::resolve(pool, human).await.expect("human viewer");
    tools::claims::submit_claim(
        server,
        &viewer,
        submit(content, &["backlog"]),
        Some(&human_token(human)),
    )
    .await
    .expect("the human files a backlog item");
    row_of(pool, content).await.expect("the item").0
}

/// An OAuth HUMAN principal's writes are authored by the human's own agent and
/// owned by the human's personal group; the evidence it adds is the human's
/// too. (Already true at the batch H-b tip, which is what the probe measured;
/// pinned here so it stays true.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_oauth_callers_writes_are_authored_and_owned_by_the_human(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let signer = server.server_agent_id().await.expect("signer");
    let (human, human_group) = fixture::seed_agent_with_group(&pool, "httpid-human").await;
    let viewer = Viewer::resolve(&pool, human).await.expect("viewer");
    let token = human_token(human);

    let c = "HTTP-id: a human's submit_claim over HTTP";
    tools::claims::submit_claim(&server, &viewer, submit(c, &[]), Some(&token))
        .await
        .expect("submit");
    let (claim, author, owner) = row_of(&pool, c).await.expect("written");
    assert_ne!(
        human, signer,
        "fixture: the caller is not the listener's signer"
    );
    assert_eq!((author, owner), (human, human_group));

    let m = "HTTP-id: a human's memorize over HTTP";
    tools::memory::memorize(&server, &viewer, memorize(m), Some(&token))
        .await
        .expect("memorize");
    let (_, author, owner) = row_of(&pool, m).await.expect("written");
    assert_eq!((author, owner), (human, human_group));

    tools::claims::update_with_evidence(&server, &viewer, evidence_for(claim), Some(&token))
        .await
        .expect("update_with_evidence");
    let owners: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(&pool)
            .await
            .expect("evidence");
    assert_eq!(
        owners.len(),
        2,
        "the submission's evidence and the added one"
    );
    assert!(
        owners.iter().all(|g| *g == human_group),
        "every evidence row is owned by the human's group: {owners:?}"
    );
}

/// The human retires its OWN backlog item over HTTP: the item is labelled, and
/// the resolution claim is the human's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_retires_its_own_backlog_item_over_http(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (human, human_group) = fixture::seed_agent_with_group(&pool, "httpid-retire").await;
    let item = humans_backlog_item(&pool, &server, human, "HTTP-id: the human's item").await;
    let viewer = Viewer::resolve(&pool, human).await.expect("viewer");

    tools::claims::resolve_backlog_item(
        &server,
        &viewer,
        resolve(item, "done by the human"),
        Some(&human_token(human)),
    )
    .await
    .expect("the human retires its own item");

    assert!(has_label(&pool, item, "resolved").await);
    assert_eq!(
        resolutions_of(&pool, item).await,
        vec![(human, human_group)]
    );
}

/// A principal-less caller (the default `--allow-unauthenticated-http`
/// context) authors nothing: every write tool refuses, naming the cause, and
/// no row is written. Reached through the tool functions, so this is the
/// `write_identity` layer, not the scope gate.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_less_caller_writes_nothing_by_default(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let signer = server.server_agent_id().await.expect("signer");
    let viewer = Viewer::resolve(&pool, signer).await.expect("viewer");
    let ctx = unauthenticated_context(Some(signer), UnauthenticatedWrites::default());

    let c = "HTTP-id: principal-less submit";
    let err = tools::claims::submit_claim(&server, &viewer, submit(c, &[]), Some(&ctx))
        .await
        .expect_err("a principal-less submit_claim has no author");
    assert!(
        err.message.contains("no authenticated principal"),
        "{}",
        err.message
    );
    assert!(row_of(&pool, c).await.is_none(), "nothing written");

    let m = "HTTP-id: principal-less memorize";
    let err = tools::memory::memorize(&server, &viewer, memorize(m), Some(&ctx))
        .await
        .expect_err("a principal-less memorize has no author");
    assert!(
        err.message.contains("no authenticated principal"),
        "{}",
        err.message
    );
    assert!(row_of(&pool, m).await.is_none(), "nothing written");
}

/// A principal-less caller gets NO human's authority over a human's items,
/// whether the listener is read-only (the default) or opted into writes: the
/// human's backlog item stays open and no resolution is written. With the
/// opt-in the context carries `claims:admin`, and the audited admin path
/// refuses it because no client record names an admin to audit.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_less_caller_cannot_retire_a_humans_item(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let signer = server.server_agent_id().await.expect("signer");
    let (human, _) = fixture::seed_agent_with_group(&pool, "httpid-victim").await;
    let item = humans_backlog_item(&pool, &server, human, "HTTP-id: a human's open item").await;
    let viewer = Viewer::resolve(&pool, signer).await.expect("viewer");

    for writes in [
        UnauthenticatedWrites::Refused,
        UnauthenticatedWrites::AsListenerSigner,
    ] {
        let ctx = unauthenticated_context(Some(signer), writes);
        tools::claims::resolve_backlog_item(&server, &viewer, resolve(item, "no"), Some(&ctx))
            .await
            .expect_err("a principal-less caller must not retire a human's item");
        tools::claims::update_labels(
            &server,
            &viewer,
            UpdateLabelsParams {
                claim_id: item.to_string(),
                add: vec!["resolved".into()],
                remove: vec![],
            },
            Some(&ctx),
        )
        .await
        .expect_err("nor label it resolved");
        assert!(
            !has_label(&pool, item, "resolved").await,
            "{writes:?}: still open"
        );
        assert!(
            resolutions_of(&pool, item).await.is_empty(),
            "{writes:?}: no resolution"
        );
    }
}

/// With `--allow-unauthenticated-writes` a principal-less write is authored by
/// the listener's own signer, in the signer's own group: never by or into a
/// human, and the signer carries no operator link.
#[sqlx::test(migrations = "../../migrations")]
async fn an_opt_in_principal_less_write_is_the_unlinked_signers(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let signer = server.server_agent_id().await.expect("signer");
    let signer_group: Uuid =
        sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1")
            .bind(signer.to_string())
            .fetch_one(&pool)
            .await
            .expect("signer's personal group");
    let viewer = Viewer::resolve(&pool, signer).await.expect("viewer");
    let ctx = unauthenticated_context(Some(signer), UnauthenticatedWrites::AsListenerSigner);

    let c = "HTTP-id: opted-in principal-less submit";
    tools::claims::submit_claim(&server, &viewer, submit(c, &[]), Some(&ctx))
        .await
        .expect("the opt-in admits the write");
    assert_eq!(
        row_of(&pool, c).await.map(|r| (r.1, r.2)),
        Some((signer, signer_group))
    );
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
        .bind(signer)
        .fetch_one(&pool)
        .await
        .expect("links");
    assert_eq!(links, 0, "the signer is linked to no human");
}

/// The payoff of goal 2: a FORMER shared signer's backlog item becomes its
/// human's to retire over HTTP once the signer is link-retired to the human
/// through migration 116's attested retire. Before the link the human is
/// neither author nor operator and is refused; after it the ownership gate's
/// operator arm admits the human and the resolution is the human's.
///
/// Superuser harness: this pins the GATE. On a clean schema (config A) the
/// label write itself also needs the item's owner group to be writable by the
/// human, which `epigraph-operator reown-claims` provides; the probe
/// (`probe-httpid.sh retired`, with `E2E_OPERATOR_BIN`) measures that half.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_retires_a_former_signers_item_after_the_attested_link(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (human, human_group) = fixture::seed_agent_with_group(&pool, "httpid-operator").await;
    let (former_signer, _) = fixture::seed_agent_with_group(&pool, "httpid-old-signer").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "httpid-other-principal").await;
    for principal in [human, other] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
        )
        .bind(former_signer)
        .bind(principal)
        .execute(&pool)
        .await
        .expect("auth-lineage edge");
    }
    let item: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels) \
         VALUES (gen_random_uuid(), 'HTTP-id: an item the old signer wrote', \
                 decode(md5(random()::text) || md5(random()::text), 'hex'), 0.6, $1, \
                 ARRAY['backlog']) RETURNING id",
    )
    .bind(former_signer)
    .fetch_one(&pool)
    .await
    .expect("the former signer's item");
    let viewer = Viewer::resolve(&pool, human).await.expect("viewer");
    let token = human_token(human);

    tools::claims::resolve_backlog_item(&server, &viewer, resolve(item, "not yet"), Some(&token))
        .await
        .expect_err("before the link the human neither wrote it nor operates its author");
    assert!(!has_label(&pool, item, "resolved").await);

    let linked: bool = sqlx::query_scalar(
        "SELECT link_retired FROM public.epigraph_link_retired_shared_signer($1, $2, $3)",
    )
    .bind(former_signer)
    .bind(human)
    .bind(vec![other])
    .fetch_one(&pool)
    .await
    .expect("the attested retire");
    assert!(linked);

    tools::claims::resolve_backlog_item(&server, &viewer, resolve(item, "mine"), Some(&token))
        .await
        .expect("after the link the human is the author's operator");
    assert!(has_label(&pool, item, "resolved").await);
    assert_eq!(
        resolutions_of(&pool, item).await,
        vec![(human, human_group)]
    );
}
