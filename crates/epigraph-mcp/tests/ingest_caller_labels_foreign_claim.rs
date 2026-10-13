//! Caller `labels` on a hierarchical ingest must not reach a claim ANOTHER
//! agent authored, even one the ingest converges onto and the ingesting agent's
//! stamp can write (drain unit U035, council finding on the resolved branch).
//!
//! # The hole this pins
//!
//! An atom is content-addressed: `ClaimRepository::create_conn` resolves to any
//! existing row with the same `content_hash`, whoever authored it, and
//! `persist_planned_claim` then marks it "resolved to existing". The walk merges
//! the document's label set onto that row through `label_resolved_claim`, whose
//! only check is RLS. Under D1 a `writer` of a TEAM group passes RLS on a
//! colleague's claim owned by that team. Before caller labels existed only
//! `doi:<key>` took this path, and that fixed prefix can never spell a
//! workflow label. Caller vocabulary can: `labels: ["resolved"]` on an atom
//! whose text equals a colleague's backlog item retired it, with no
//! `Resolves <id>:` trail, past `claims.rs::gate_retirement_label` and the
//! HTTP `require_owner_or_admin` bar that `update_labels` applies.
//!
//! # What stays, pinned as calibration
//!
//! * the document's own `doi:<key>` label still lands on the colleague's row
//!   (unchanged behaviour, and the proof that the resolved branch ran and RLS
//!   admitted the write — without it, an absent `resolved` could just mean the
//!   label step never reached the row);
//! * the caller labels still land on every claim the ingest CREATED (its own).
//!
//! Both of the server's pools are downgraded to `epigraph_app`, so RLS answers
//! as in production: on the `#[sqlx::test]` superuser pool every arm here would
//! be vacuous (`update_with_evidence_label_ownership.rs` explains why). Seeding
//! runs on the superuser pool. Deliberately does NOT use `tests/common`: that
//! helper DROPs `uq_claims_content_hash_agent`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;
use uuid::Uuid;

const ATOM: &str = "A colleague's backlog item, restated verbatim as an atom.";
const THESIS: &str = "Paper B thesis on a colleague's backlog item.";
const DOI_B: &str = "10.9999/u035-foreign-b";

/// An ingesting server whose plain and scoped pools both run as `epigraph_app`.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
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
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, AgentSigner::generate(), embedder, false).with_scoped_pool(scoped)
}

async fn team_with_writers(pool: &PgPool, writers: &[Uuid]) -> Uuid {
    let team: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('u035 team', 'did:test:team:' || gen_random_uuid(), \
                 decode(repeat('cd', 32), 'hex'), 'team') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("team group");
    for agent in writers {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(team)
        .bind(agent)
        .execute(pool)
        .await
        .expect("team writer membership");
    }
    team
}

/// Agent A's backlog claim, owned by the team, public, with the hash
/// `create_conn`'s dedup lookup queries (`ContentHasher::hash(content)`).
async fn colleague_backlog_claim(pool: &PgPool, author: Uuid, team: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, ARRAY['backlog'])",
    )
    .bind(id)
    .bind(ATOM)
    .bind(ContentHasher::hash(ATOM.as_bytes()).as_slice())
    .bind(author)
    .bind(team)
    .execute(pool)
    .await
    .expect("seed colleague claim");
    id
}

async fn labels_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read labels")
}

fn doc_b(labels: &[&str]) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": "U035 Paper B", "doi": DOI_B, "source_type": "Paper", "authors": []},
        "thesis": THESIS,
        "thesis_derivation": "TopDown",
        "sections": [{"title": "B section", "paragraphs": [{
            "text": "Paper B paragraph restating the colleague's item.",
            "atoms": [ATOM],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": [],
        "labels": labels
    }))
    .expect("extraction")
}

#[sqlx::test(migrations = "../../migrations")]
async fn caller_labels_do_not_reach_a_colleagues_converged_claim(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let agent_b = server.server_agent_id().await.expect("server agent");
    let (agent_a, _personal_a) = fixture::seed_agent_with_group(&pool, "u035-colleague").await;
    let team = team_with_writers(&pool, &[agent_a, agent_b]).await;
    let colleague = colleague_backlog_claim(&pool, agent_a, team).await;
    let viewer = fixture::public_viewer(&pool).await;

    let result = do_ingest_document(&server, &viewer, &doc_b(&["resolved", "stage:b"]), None)
        .await
        .expect("paper B ingests");

    // Exactly one row: B converged onto A's claim rather than inserting its own.
    let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(ATOM)
        .fetch_all(&pool)
        .await
        .expect("rows with the atom's content");
    assert_eq!(rows, vec![colleague], "B must resolve to A's claim");

    let labels = labels_of(&pool, colleague).await;
    for refused in ["resolved", "stage:b"] {
        assert!(
            !labels.iter().any(|l| l == refused),
            "caller label {refused:?} reached a claim another agent authored: {labels:?}"
        );
    }
    let doi_b = format!("doi:{DOI_B}");
    assert!(
        labels.contains(&doi_b) && labels.iter().any(|l| l == "backlog"),
        "calibration: the colleague's row keeps `backlog` and gains this document's \
         {doi_b:?} label exactly as before caller labels existed: {labels:?}"
    );

    let text = &result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    let json: serde_json::Value = serde_json::from_str(text).expect("JSON response");
    assert_eq!(
        json["converged_claims_caller_labels_withheld"], 1,
        "the withheld caller labels must be disclosed, not swallowed: {json}"
    );
    assert_eq!(
        json["converged_claims_unlabelled"], 0,
        "the doi: label landed, so the row is not unlabelled: {json}"
    );

    // Calibration: B's own new claims still carry its caller labels.
    let thesis: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(THESIS)
        .fetch_one(&pool)
        .await
        .expect("B's thesis");
    let own = labels_of(&pool, thesis).await;
    assert!(
        own.iter().any(|l| l == "stage:b"),
        "the ingest's own claims must still carry its caller labels: {own:?}"
    );
}
