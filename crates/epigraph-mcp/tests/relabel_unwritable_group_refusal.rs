//! A label write onto a claim whose owning group the caller's stamp cannot
//! write is a clean, NAMED refusal (backlog 3e7bfee3), not an internal error.
//!
//! `update_labels` (and `patch_claim`'s `add_labels`, and every
//! `apply_label_dedup` write unit, which share `relabel_claim`) runs one
//! `UPDATE claims` on a transaction stamped from the write identity. Migration
//! 077's `claims_tenancy` `WITH CHECK` refuses that UPDATE with `42501` when the
//! claim's `owner_group_id` is not in the stamp's writable set, and the tool
//! used to answer that refusal as `INTERNAL_ERROR`: a server fault the caller
//! retries, for a denial of authority no retry can fix. The reported case is a
//! stdio agent relabelling another agent's PUBLIC claim with a free label.
//!
//! What these arms pin, on an APPLICATION-ROLE server (both pools downgraded to
//! `epigraph_app`; a superuser pool bypasses row security, so every refusal
//! here would be vacuous on it):
//!
//! * stdio `update_labels` with a free (ungated) label on another agent's
//!   public claim: `INVALID_REQUEST`, `data.rule` names the rule, the owning
//!   group is not disclosed, the labels are unchanged; the same call on the
//!   server agent's own claim lands (calibration);
//! * stdio `patch_claim` with `add_labels`: the same refusal, nothing written;
//! * HTTP `update_labels` by the claim's AUTHOR (who passes the ownership gate)
//!   on a claim owned by a group it cannot write: the same refusal;
//! * stdio `patch_claim` with `properties` only (no labels): the same
//!   `UPDATE claims`, so the same refusal, with no label-specific remedy;
//! * a coded `42501`, or a row-security refusal on ANOTHER table a trigger
//!   writes, is NOT renamed: only `claims`' own row security is this refusal.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::{patch_claim, update_labels};
use epigraph_mcp::types::{PatchClaimParams, UpdateLabelsParams};
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// The `data.rule` the refusal carries.
const RULE: &str = "label_requires_claim_group_writer";

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Viewer) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, agent, viewer)
}

/// A `visibility = 'public'` claim authored by `agent` and OWNED BY `group`:
/// readable by every session, writable only by the group's writers.
async fn public_claim_in(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id, labels) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5, ARRAY['rfp-pipeline']::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed public claim");
    id
}

async fn labels_of(pool: &PgPool, claim_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read labels")
}

fn free_label(claim: Uuid) -> UpdateLabelsParams {
    UpdateLabelsParams {
        claim_id: claim.to_string(),
        add: vec!["norcal-rfp-2026-10-29".to_string()],
        remove: vec![],
    }
}

fn assert_named_refusal(e: &rmcp::ErrorData, claim: Uuid, group: Uuid, arm: &str) {
    assert_eq!(
        e.code,
        ErrorCode::INVALID_REQUEST,
        "{arm}: a label write the claim's group refuses is a denial of authority, not a \
         server fault: {e:?}"
    );
    assert!(
        !e.message.contains("row-level security"),
        "{arm}: the refusal must not be the raw row-security error: {e:?}"
    );
    assert!(
        e.message.contains(&claim.to_string()) && e.message.contains("nothing was written"),
        "{arm}: the message names the claim and says nothing was written: {e:?}"
    );
    assert!(
        e.message.contains("claims:admin"),
        "{arm}: the message names the audited admin path as the remedy: {e:?}"
    );
    let data = e.data.clone().expect("the refusal carries data");
    assert_eq!(data["error"], "not_writer", "{arm}: {data}");
    assert_eq!(data["rule"], RULE, "{arm}: {data}");
    assert_eq!(data["claim_id"], claim.to_string(), "{arm}: {data}");
    assert_eq!(data["retryable"], false, "{arm}: {data}");
    assert!(
        !e.message.contains(&group.to_string()) && !data.to_string().contains(&group.to_string()),
        "{arm}: the owning group's id appears nowhere in the refusal: {e:?}"
    );
}

/// The reported shape: a stdio agent adds a free label to another agent's
/// public claim. Calibration: the same call on the server agent's own claim
/// lands on the same server.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_update_labels_on_a_foreign_groups_claim_is_a_named_refusal(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "relabel-author").await;
    let foreign = public_claim_in(&pool, author, author_group, "B's public pipeline signal").await;
    let before = labels_of(&pool, foreign).await;

    let e = update_labels(&server, &viewer, free_label(foreign), None)
        .await
        .expect_err("the claim's group refuses the stdio server's stamp");
    assert_named_refusal(&e, foreign, author_group, "stdio update_labels");
    assert_eq!(labels_of(&pool, foreign).await, before, "nothing written");

    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "the server agent's own claim").await;
    update_labels(&server, &viewer, free_label(mine), None)
        .await
        .expect("CALIBRATION: the server agent relabels its own group's claim");
    assert!(
        labels_of(&pool, mine)
            .await
            .contains(&"norcal-rfp-2026-10-29".to_string()),
        "calibration: the label landed"
    );
}

/// `patch_claim` writes labels on the same stamped path; its refusal is the
/// same named one, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_patch_claim_add_labels_on_a_foreign_groups_claim_is_a_named_refusal(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "patch-author").await;
    let foreign = public_claim_in(&pool, author, author_group, "B's public claim, patched").await;
    let before = labels_of(&pool, foreign).await;
    let patch = |claim: Uuid| PatchClaimParams {
        claim_id: claim.to_string(),
        trace_id: None,
        properties: None,
        add_labels: vec!["norcal-rfp-2026-10-29".to_string()],
        remove_labels: vec![],
    };

    let e = patch_claim(&server, &viewer, patch(foreign), None)
        .await
        .expect_err("the claim's group refuses the stdio server's stamp");
    assert_named_refusal(&e, foreign, author_group, "stdio patch_claim");
    assert_eq!(labels_of(&pool, foreign).await, before, "nothing written");

    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "own claim, patched").await;
    patch_claim(&server, &viewer, patch(mine), None)
        .await
        .expect("CALIBRATION: the server agent patches its own group's claim");
}

/// Over HTTP the whole label mutation is ownership-gated first, and the claim's
/// AUTHOR passes that gate. When the claim is owned by a group the author's
/// stamp cannot write, the database refuses the UPDATE; that is the same named
/// refusal, not an internal error.
#[sqlx::test(migrations = "../../migrations")]
async fn http_author_relabelling_its_claim_in_an_unwritable_group_is_a_named_refusal(pool: PgPool) {
    let (server, _agent, _viewer) = app_role_server(&pool).await;
    let (_owner, group) = fixture::seed_agent_with_group(&pool, "relabel-group-admin").await;
    let (caller, token, caller_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let claim = public_claim_in(&pool, caller, group, "caller-authored, group-owned").await;
    let before = labels_of(&pool, claim).await;

    let e = update_labels(&server, &caller_viewer, free_label(claim), Some(&token))
        .await
        .expect_err("the claim's group refuses the author's stamp");
    assert_named_refusal(&e, claim, group, "http update_labels by the author");
    assert_eq!(labels_of(&pool, claim).await, before, "nothing written");
}

/// Only the row-security refusal is renamed. A CODED `42501` a trigger raises
/// (a designed refusal, migration 176's convention) keeps its own text, so the
/// mapping cannot swallow a refusal the schema wrote for the caller. Forced on
/// the server agent's OWN claim, which the row-security check admits.
#[sqlx::test(migrations = "../../migrations")]
async fn a_coded_42501_from_a_trigger_keeps_its_own_text(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "own claim, trigger-refused").await;
    const CODED: &str = "TST01: relabel refused by the test trigger";
    sqlx::query(&format!(
        "CREATE FUNCTION test_coded_42501() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION '{CODED}' USING ERRCODE = '42501'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create the forcing function");
    sqlx::query("GRANT EXECUTE ON FUNCTION test_coded_42501() TO PUBLIC")
        .execute(&pool)
        .await
        .expect("grant execute");
    sqlx::query(
        "CREATE TRIGGER test_coded_42501 BEFORE UPDATE ON claims \
         FOR EACH ROW WHEN (NEW.id = '{id}'::uuid) EXECUTE FUNCTION test_coded_42501()"
            .replace("{id}", &mine.to_string())
            .as_str(),
    )
    .execute(&pool)
    .await
    .expect("create the forcing trigger");

    let e = update_labels(&server, &viewer, free_label(mine), None)
        .await
        .expect_err("the trigger refuses the UPDATE");
    assert_eq!(
        e.message, CODED,
        "a coded refusal reaches the caller as written, not renamed: {e:?}"
    );
    assert!(
        e.data
            .as_ref()
            .is_none_or(|d| d["rule"] != "label_requires_claim_group_writer"),
        "a coded refusal is not the row-security refusal: {e:?}"
    );
}

async fn properties_of(pool: &PgPool, claim_id: Uuid) -> Option<serde_json::Value> {
    sqlx::query_scalar("SELECT properties FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read properties")
}

/// A `patch_claim` that touches no label is the same `UPDATE claims` and so
/// the same refusal; its message names no label-only remedy. Calibration: the
/// same properties patch lands on the server agent's own claim.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_patch_claim_properties_only_on_a_foreign_groups_claim_is_a_named_refusal(
    pool: PgPool,
) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "props-author").await;
    let foreign = public_claim_in(&pool, author, author_group, "B's claim, properties").await;
    let before = (
        labels_of(&pool, foreign).await,
        properties_of(&pool, foreign).await,
    );
    let patch = |claim: Uuid| PatchClaimParams {
        claim_id: claim.to_string(),
        trace_id: None,
        properties: Some(serde_json::json!({ "pipeline_state": "aged-out-3e7b" })),
        add_labels: vec![],
        remove_labels: vec![],
    };

    let e = patch_claim(&server, &viewer, patch(foreign), None)
        .await
        .expect_err("the claim's group refuses the stdio server's stamp");
    assert_named_refusal(
        &e,
        foreign,
        author_group,
        "stdio patch_claim, properties only",
    );
    assert!(
        !e.message.contains("Relabel"),
        "a properties-only patch is not told to relabel: {e:?}"
    );
    assert_eq!(
        (
            labels_of(&pool, foreign).await,
            properties_of(&pool, foreign).await
        ),
        before,
        "nothing written"
    );

    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "own claim, properties").await;
    patch_claim(&server, &viewer, patch(mine), None)
        .await
        .expect("CALIBRATION: the server agent patches its own group's claim");
    assert_eq!(
        properties_of(&pool, mine)
            .await
            .as_ref()
            .map(|p| p["pipeline_state"].clone()),
        Some(serde_json::json!("aged-out-3e7b")),
        "calibration: the properties landed"
    );
}

/// Only `claims`' OWN row-security refusal is renamed. An uncoded `42501` from
/// another table's row security (here a sink table a trigger on the claim's
/// UPDATE writes, whose policy admits nothing) is not a statement about the
/// claim's group, so it keeps the redacted internal-error answer. Forced on
/// the server agent's OWN claim, which `claims`' row security admits.
#[sqlx::test(migrations = "../../migrations")]
async fn another_tables_row_security_refusal_is_not_renamed(pool: PgPool) {
    let (server, agent, viewer) = app_role_server(&pool).await;
    let own_group = personal_group_of(&pool, agent).await;
    let mine = public_claim_in(&pool, agent, own_group, "own claim, sink-refused").await;
    for stmt in [
        "CREATE TABLE test_rls_sink (claim_id uuid)".to_string(),
        "ALTER TABLE test_rls_sink ENABLE ROW LEVEL SECURITY".to_string(),
        "CREATE POLICY test_rls_sink_none ON test_rls_sink FOR INSERT WITH CHECK (false)"
            .to_string(),
        "GRANT INSERT ON test_rls_sink TO PUBLIC".to_string(),
        "CREATE FUNCTION test_rls_sink_write() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN INSERT INTO test_rls_sink VALUES (NEW.id); RETURN NEW; END $$"
            .to_string(),
        "GRANT EXECUTE ON FUNCTION test_rls_sink_write() TO PUBLIC".to_string(),
        format!(
            "CREATE TRIGGER test_rls_sink_write BEFORE UPDATE ON claims \
             FOR EACH ROW WHEN (NEW.id = '{mine}'::uuid) EXECUTE FUNCTION test_rls_sink_write()"
        ),
    ] {
        sqlx::query(&stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }

    let e = update_labels(&server, &viewer, free_label(mine), None)
        .await
        .expect_err("the sink's row security refuses the trigger's INSERT");
    assert_eq!(
        e.code,
        ErrorCode::INTERNAL_ERROR,
        "another table's row-security refusal is not the claim-group refusal: {e:?}"
    );
    assert!(
        e.data
            .as_ref()
            .is_none_or(|d| d["rule"] != "label_requires_claim_group_writer"),
        "not renamed to the claim-group rule: {e:?}"
    );
}
