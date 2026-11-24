//! `update_with_evidence` on a claim the caller can READ but whose owning
//! group it cannot WRITE is a named `not_writer` refusal, not an internal
//! error (backlog 1c93eec8).
//!
//! The reported shape: a group-visible claim (`visibility = 'group'`), the
//! caller a READER of the owning group. `is_foreign_public_claim` answers false (the
//! claim is not public, so migration 114's non-owner attach does not apply),
//! the call takes the ordinary path, and the database refuses the evidence
//! INSERT with an uncoded `42501` ("new row violates row-level security
//! policy"). The tool mapped that through `internal_error` to the redacted
//! INTERNAL_ERROR text: a server fault the caller retries, for a denial of
//! authority no retry can fix.
//!
//! What these arms pin, on an APPLICATION-ROLE server (both pools downgraded
//! to `epigraph_app`; a superuser pool bypasses row security, so every refusal
//! here would be vacuous on it):
//!
//! * over HTTP, a group reader with no labels: `INVALID_REQUEST`,
//!   `data.error = "not_writer"`, `data.rule` names the rule, the owning group
//!   is not disclosed, nothing written (no evidence, no BBA, truth unmoved);
//! * over HTTP, the claim's own AUTHOR, only a reader of the owning group, with
//!   labels (so the ownership gate admits it and the database decides): the
//!   same refusal, labels unchanged;
//! * on stdio, the server's agent as a group reader: the same refusal;
//! * calibration: the same call by a WRITER of the group lands, so the refusal
//!   is the caller's role in the owning group and not the claim's shape;
//! * the same refusal and calibration on a TEAM group (migration 164's keyless
//!   `did:epigraph:group:` shape), whose memberships are live only for a human
//!   operator (or an agent under one), so the team machinery is exercised.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::update_with_evidence;
use epigraph_mcp::types::UpdateWithEvidenceParams;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// The `data.rule` the refusal carries.
const RULE: &str = "evidence_requires_claim_group_writer";

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
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
    (server, agent)
}

/// The shared group: `owner`'s own group, which other agents join below as a
/// reader or a writer. Not a `did:epigraph:group:` team group, whose
/// memberships are live only for human operators (migration 164), so a plain
/// agent's reader row here is live and the claim is readable to it.
async fn shared_group(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    fixture::seed_agent_with_group(pool, label).await
}

/// A keyless team group in migration 164's shape, seeded on the superuser
/// pool (which the verbs' triggers admit), with `admin` as its admin.
async fn team_group(pool: &PgPool, admin: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, 'did:epigraph:group:' || $1::text, ''::bytea, 'team', $3)",
    )
    .bind(id)
    .bind(format!("1c93eec8 team {id}"))
    .bind(admin)
    .execute(pool)
    .await
    .expect("seed a team group");
    add_member(pool, id, admin, "admin").await;
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// A group-visible claim (`visibility = 'group'`) authored by `agent`, owned by
/// `group`, labelled `backlog`, `truth_value = 0.5`.
async fn group_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5, ARRAY['backlog'])",
    )
    .bind(id)
    .bind(format!("1c93eec8 group claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

fn params(claim: Uuid, labels: &[&str]) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        claim_id: claim.to_string(),
        canonical_name: None,
        step_index: None,
        evidence_data: format!("1c93eec8 observation {}", Uuid::new_v4()),
        evidence_type: "empirical".into(),
        supports: true,
        strength: 0.9,
        source_url: None,
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// `(labels, truth_value, evidence rows, BBA rows)` of `claim`, read on the
/// superuser harness connection so nothing is filtered.
async fn state_of(pool: &PgPool, claim: Uuid) -> (Vec<String>, f64, i64, i64) {
    let (labels, truth): (Vec<String>, f64) = sqlx::query_as(
        "SELECT COALESCE(labels, ARRAY[]::text[]), truth_value FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("claim");
    let evidence: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("evidence");
    let bbas: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("mass_functions");
    (labels, truth, evidence, bbas)
}

fn assert_named_refusal(e: &rmcp::ErrorData, claim: Uuid, group: Uuid, arm: &str) {
    assert_eq!(
        e.code,
        ErrorCode::INVALID_REQUEST,
        "{arm}: evidence the claim's group refuses is a denial of authority, not a server \
         fault: {e:?}"
    );
    assert!(
        !e.message.contains("row-level security"),
        "{arm}: the refusal must not be the raw row-security error: {e:?}"
    );
    assert!(
        e.message.contains(&claim.to_string()) && e.message.contains("nothing was written"),
        "{arm}: the message names the claim and says nothing was written: {e:?}"
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

/// The reported case over HTTP: a reader of the owning group, no labels.
#[sqlx::test(migrations = "../../migrations")]
async fn http_group_reader_without_labels_is_a_named_refusal(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (owner, group) = shared_group(&pool, "uwe-nw-owner").await;
    let claim = group_claim(&pool, owner, group).await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    add_member(&pool, group, caller, "reader").await;
    let caller_viewer = viewer(&pool, caller).await;
    let before = state_of(&pool, claim).await;

    let e = update_with_evidence(&server, &caller_viewer, params(claim, &[]), Some(&token))
        .await
        .expect_err("a group reader cannot attach evidence to the group's claim");
    assert_named_refusal(&e, claim, group, "http group reader");
    assert_eq!(state_of(&pool, claim).await, before, "nothing written");
}

/// The claim's own author, only a READER of the owning group, with labels: the
/// ownership gate admits the author, so only the database refuses.
#[sqlx::test(migrations = "../../migrations")]
async fn http_author_demoted_to_reader_with_labels_is_a_named_refusal(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (_owner, group) = shared_group(&pool, "uwe-nw-group-admin").await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    add_member(&pool, group, caller, "reader").await;
    let claim = group_claim(&pool, caller, group).await;
    let caller_viewer = viewer(&pool, caller).await;
    let before = state_of(&pool, claim).await;

    let e = update_with_evidence(
        &server,
        &caller_viewer,
        params(claim, &["run-1c93eec8"]),
        Some(&token),
    )
    .await
    .expect_err("the author's stamp cannot write the group");
    assert_named_refusal(&e, claim, group, "http author, reader");
    assert_eq!(state_of(&pool, claim).await, before, "nothing written");
}

/// On stdio the server's own agent, a reader of the owning group.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_group_reader_is_a_named_refusal(pool: PgPool) {
    let (server, agent) = app_role_server(&pool).await;
    let (owner, group) = shared_group(&pool, "uwe-nw-stdio-owner").await;
    let claim = group_claim(&pool, owner, group).await;
    add_member(&pool, group, agent, "reader").await;
    let server_viewer = viewer(&pool, agent).await;
    let before = state_of(&pool, claim).await;

    let e = update_with_evidence(&server, &server_viewer, params(claim, &[]), None)
        .await
        .expect_err("the server agent's stamp cannot write the group");
    assert_named_refusal(&e, claim, group, "stdio group reader");
    assert_eq!(state_of(&pool, claim).await, before, "nothing written");
}

/// Calibration: a WRITER of the same group attaches the same evidence to the
/// same shape of claim, and it lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_attaches_evidence(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (owner, group) = shared_group(&pool, "uwe-nw-cal-owner").await;
    let claim = group_claim(&pool, owner, group).await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    add_member(&pool, group, caller, "writer").await;
    let caller_viewer = viewer(&pool, caller).await;

    update_with_evidence(&server, &caller_viewer, params(claim, &[]), Some(&token))
        .await
        .expect("CALIBRATION: a group writer attaches evidence");
    let (_, _, evidence, bbas) = state_of(&pool, claim).await;
    assert_eq!(evidence, 1, "calibration: the evidence landed");
    assert!(bbas >= 1, "calibration: its BBA landed");
}

/// A team group: the caller is a human operator (so its team membership is
/// live) holding only a READER row. The same named refusal, nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn http_team_reader_is_a_named_refusal(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (owner, _) = fixture::seed_agent_with_group(&pool, "uwe-nw-team-owner").await;
    fixture::make_human_operator(&pool, owner).await;
    let team = team_group(&pool, owner).await;
    let claim = group_claim(&pool, owner, team).await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    fixture::make_human_operator(&pool, caller).await;
    add_member(&pool, team, caller, "reader").await;
    let caller_viewer = viewer(&pool, caller).await;
    let before = state_of(&pool, claim).await;

    let e = update_with_evidence(&server, &caller_viewer, params(claim, &[]), Some(&token))
        .await
        .expect_err("a team reader cannot attach evidence to the team's claim");
    assert_named_refusal(&e, claim, team, "http team reader");
    assert_eq!(state_of(&pool, claim).await, before, "nothing written");
}

/// Calibration for the team arm: a human operator holding a WRITER row in the
/// same kind of team group attaches the same evidence, so the team membership
/// is live (the claim is read, not "not found") and the refusal above is the
/// reader role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_writer_attaches_evidence(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (owner, _) = fixture::seed_agent_with_group(&pool, "uwe-nw-team-cal-owner").await;
    fixture::make_human_operator(&pool, owner).await;
    let team = team_group(&pool, owner).await;
    let claim = group_claim(&pool, owner, team).await;
    let (caller, token, _) = seed_caller(&pool, &["claims:write"]).await;
    fixture::make_human_operator(&pool, caller).await;
    add_member(&pool, team, caller, "writer").await;
    let caller_viewer = viewer(&pool, caller).await;

    update_with_evidence(&server, &caller_viewer, params(claim, &[]), Some(&token))
        .await
        .expect("CALIBRATION: a team writer attaches evidence");
    let (_, _, evidence, bbas) = state_of(&pool, claim).await;
    assert_eq!(evidence, 1, "calibration: the evidence landed");
    assert!(bbas >= 1, "calibration: its BBA landed");
}
