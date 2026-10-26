//! The MCP twin of `epigraph-api/tests/evidence_content_oracle_test.rs`
//! (backlog 12b68201), on the APPLICATION ROLE.
//!
//! `update_with_evidence` onto a PUBLIC claim the caller cannot write files a
//! writer-owned row (migration 114 arm (e)): owned by the caller's group, not
//! the claim's. While `evidence` was `UNIQUE (content_hash, claim_id)` across
//! owners, that INSERT collided with ANY row on the claim with the same body,
//! including one held by a group the caller cannot read. The refusal confirmed
//! the hidden row and its exact content. This is the path the backlog item
//! describes: a stamped app-role session, where the writer's row really is
//! owned by the writer. The HTTP tests run on the superuser harness, where a
//! POSTed row inherits the claim's owner instead.
//!
//! The discriminating pair:
//!
//! * a body another group holds and a body nobody holds both land;
//! * the SAME writer's identical retry is still refused, so evidence is still
//!   de-duplicated within one owner (MCP redacts the refusal's text, so the
//!   row count is what pins it; `epigraph-db/tests/evidence_dedup_per_owner.rs`
//!   pins the `DuplicateKey` itself).
//!
//! Both pools are downgraded to `epigraph_app` exactly as in
//! `writer_owned_attach_app_role.rs`, whose header says why.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::ContentHasher;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid, Viewer) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the test is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(pool, agent).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    (server, group, viewer)
}

async fn binary_truth(pool: &PgPool) {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if existing.is_none() {
        epigraph_db::FrameRepository::create(
            pool,
            "binary_truth",
            Some("canonical binary frame"),
            &["TRUE".to_string(), "FALSE".to_string()],
        )
        .await
        .expect("binary_truth");
    }
}

fn uwe(claim: Uuid, data: &str) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim.to_string(),
        evidence_type: "empirical".into(),
        evidence_data: data.into(),
        source_url: None,
        supports: true,
        strength: 0.8,
        labels: vec![],
    }
}

/// Evidence with `update_with_evidence`'s digest of `data`, owned by `group`
/// and readable only inside it, made so the way the operator `hide` does it: a
/// visibility pin, then the owner and visibility. The pin keeps migration 070's
/// per-insert re-sync from handing the row back to the claim's owner.
async fn seed_hidden_evidence(pool: &PgPool, claim: Uuid, group: Uuid, data: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id) \
         VALUES ($1, 'document', $2, $3) RETURNING id",
    )
    .bind(ContentHasher::hash(data.as_bytes()).as_slice())
    .bind(data)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed evidence");
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden from the writer')",
    )
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("pin the hidden row");
    sqlx::query("UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE id = $1")
        .bind(id)
        .bind(group)
        .execute(pool)
        .await
        .expect("hide the row in the other group");
    id
}

async fn tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read evidence tenancy")
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_cannot_tell_another_groups_hidden_body_from_a_fresh_one(
    pool: PgPool,
) {
    let (server, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let claim = seed_claim(&pool, "a shared public claim someone else wrote", 0.5).await;
    let (_other, other_group) = fixture::seed_agent_with_group(&pool, "ev-oracle-other").await;
    let hidden = format!("another group's observation {}", Uuid::new_v4());
    let fresh = format!("an observation nobody holds {}", Uuid::new_v4());
    let other_row = seed_hidden_evidence(&pool, claim, other_group, &hidden).await;
    assert_eq!(
        tenancy(&pool, other_row).await,
        (other_group, "group".to_string()),
        "fixture: the hidden row is the other group's"
    );
    assert!(
        epigraph_db::EvidenceRepository::get_by_id(
            &pool,
            &viewer,
            epigraph_core::EvidenceId::from_uuid(other_row)
        )
        .await
        .expect("read through the writer's viewer")
        .is_none(),
        "fixture: the writer can read the other group's row, so the test proves nothing"
    );

    let fresh_res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, &fresh),
        None,
    )
    .await;
    assert!(
        fresh_res.is_ok(),
        "control: a body nobody holds lands on the app role: {fresh_res:?}"
    );
    let hidden_res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, &hidden),
        None,
    )
    .await;
    let hidden_ok = hidden_res.as_ref().unwrap_or_else(|e| {
        panic!(
            "a body another group holds on this claim was refused where a fresh body \
                 lands: the refusal confirms that group's unreadable evidence and its exact \
                 content: {e:?}"
        )
    });
    let body = first_text(hidden_ok);
    assert_eq!(body["evidence_owner"], "writer");
    let ev = parse_uuid_field(&body, "evidence_id");
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(&pool)
        .await
        .expect("read the writer's row");
    assert_eq!(owner, group, "the writer's row is the writer's");
    assert_eq!(
        tenancy(&pool, other_row).await,
        (other_group, "group".to_string()),
        "the other group's row is untouched and still hidden"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_same_writers_identical_retry_is_still_refused(pool: PgPool) {
    let (server, group, viewer) = app_role_server(&pool).await;
    binary_truth(&pool).await;
    let claim = seed_claim(&pool, "a shared public claim someone else wrote", 0.5).await;
    let data = format!("the writer's own observation {}", Uuid::new_v4());

    epigraph_mcp::tools::claims::update_with_evidence(&server, &viewer, uwe(claim, &data), None)
        .await
        .expect("the first submission lands");
    let retry = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(claim, &data),
        None,
    )
    .await;
    assert!(
        retry.is_err(),
        "the same owner's identical evidence on the same claim is still a duplicate"
    );
    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT owner_group_id FROM evidence WHERE claim_id = $1 AND content_hash = $2",
    )
    .bind(claim)
    .bind(ContentHasher::hash(data.as_bytes()).as_slice())
    .fetch_all(&pool)
    .await
    .expect("read rows");
    assert_eq!(owners, vec![group], "exactly one row, the writer's");
}
