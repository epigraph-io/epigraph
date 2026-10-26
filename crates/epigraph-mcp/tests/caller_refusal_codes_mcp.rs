//! Backlog e2c22c7c (ruling R-25), MCP half: a designed database refusal an
//! MCP caller can reach arrives with its refusal CODE, not as the generic
//! "internal error; the detail is in the server log".
//!
//! PR #686's fail-closed `internal_error` sends a database message only when it
//! opens with a schema refusal code; these refusals named none, so they were
//! redacted. Three representatives, each raised for real by the database:
//!
//! * AGK01 (55000), migration 148's `agents` guard, through the real
//!   `ingest_document` tool: a document author whose derived key is registered
//!   for a system agent that has rotated off it.
//! * GRM05 (42501), migration 164's team-roster guard, on an application-role
//!   roster write, through `internal_error` and `db_caller_error`.
//! * PRV01 (42501), migration 081's sealing guard, on an application-role
//!   `claim_encryption` row for a public claim, through the same two.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::errors::{db_caller_error, internal_error, INTERNAL_ERROR_MESSAGE};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;
use uuid::Uuid;

const AUTHOR: &str = "Refusal Code Registered Author";

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn extraction() -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": "Refusal code paper",
            "doi": format!("10.1234/refusal-code-{}", Uuid::new_v4()),
            "source_type": "Paper",
            "authors": [{"name": AUTHOR, "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("A registered key is never re-minted {}", Uuid::new_v4()),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Intro",
            "paragraphs": [{
                "text": "Registered keys stay registered after a rotation",
                "atoms": ["Registered keys stay registered after a rotation"],
                "generality": [3],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    }))
    .expect("extraction parses")
}

/// Assert an MCP error carries `code` and `fragment` and is not the redacted
/// reply.
fn assert_coded(e: &rmcp::model::ErrorData, code: &str, fragment: &str, what: &str) {
    assert_ne!(
        e.message, INTERNAL_ERROR_MESSAGE,
        "{what}: a designed refusal reached the caller as the generic internal error"
    );
    assert!(
        e.message.starts_with(&format!("{code}:")) && e.message.contains(fragment),
        "{what}: the caller reads the refusal code and its reason: {}",
        e.message
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_author_key_reaches_ingest_document_as_agk01(pool: PgPool) {
    // The author's derived key K, held by a system agent that was registered
    // under it and then rotated off it: K stays registered.
    let (_did, key) = epigraph_crypto::did_key::did_key_for_author(None, AUTHOR);
    assert!(
        !epigraph_db::is_reserved_author_key(&key),
        "K must not be a legacy constant (that path is refused before any write)"
    );
    let system: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'refusal-code system') \
         RETURNING id",
    )
    .bind(key.as_slice())
    .fetch_one(&pool)
    .await
    .expect("seed the system agent");
    assert!(fixture::register_system_agent(&pool, system).await);
    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(system)
    .execute(&pool)
    .await
    .expect("rotate the system agent off K");

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let e = do_ingest_document(&server, &viewer, &extraction(), None)
        .await
        .expect_err("an author holding a registered system key is refused");
    assert_coded(
        &e,
        "AGK01",
        "registered for a system agent",
        "ingest_document",
    );
    assert!(
        !e.message.contains("workflow-ingest"),
        "the reply names no system identity: {}",
        e.message
    );
    let holders: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(holders, 0, "nothing was written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_team_group_roster_write_reaches_mcp_as_grm05(pool: PgPool) {
    let (admin, _) = fixture::seed_agent_with_group(&pool, "refusal-code admin").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "refusal-code member").await;
    let team = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'refusal-code team', 'did:epigraph:group:' || $1::text, ''::bytea, 'team', $2)",
    )
    .bind(team)
    .bind(admin)
    .execute(&pool)
    .await
    .expect("seed a team group");

    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let write = || {
        epigraph_db::GroupMembershipRepository::add_member(
            &app_pool,
            team,
            member,
            &[],
            0,
            "writer",
        )
    };
    let e = write().await.expect_err("refused");
    assert_coded(
        &internal_error(e),
        "GRM05",
        "team-group verbs",
        "internal_error",
    );
    let e = write().await.expect_err("refused");
    assert_coded(
        &db_caller_error(e),
        "GRM05",
        "team-group verbs",
        "db_caller_error",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn sealing_a_public_claim_reaches_mcp_as_prv01(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "refusal-code author").await;
    let claim = fixture::seed_public_claim(&pool, author, "refusal-code public claim").await;

    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let seal = || async {
        let mut conn = app_pool.acquire().await.expect("app conn");
        epigraph_db::ClaimEncryptionRepository::insert_conn(
            &mut conn,
            claim,
            group,
            0,
            "fully_private",
            b"ciphertext",
            None,
        )
        .await
    };
    let e = seal().await.expect_err("refused");
    assert_coded(
        &internal_error(e),
        "PRV01",
        "Restrict first",
        "internal_error",
    );
    let e = seal().await.expect_err("refused");
    assert_coded(
        &db_caller_error(e),
        "PRV01",
        "Restrict first",
        "db_caller_error",
    );
}
