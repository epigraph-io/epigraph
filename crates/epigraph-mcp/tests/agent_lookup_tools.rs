//! MCP `find_agent` and `get_agent` (backlog 94cc12db, 8b29593c).
//!
//! The repository's rules are pinned in `epigraph-db/tests/agent_lookup.rs`;
//! these tests pin what is the tools' own: that they read as the CALLER on an
//! application-role connection (the server's `ScopedPool` is downgraded to
//! `epigraph_app`, so no gate is satisfied by a privileged session), that
//! `get_agent` names the agent that filed a claim, that every reader sees an
//! agent's operator human through both tools, that a private claim changes
//! nothing an outsider receives, and that both tools are mapped to a scope.
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::tools;
use epigraph_mcp::types::{FindAgentParams, GetAgentParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_server(pool: &PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    build_scoped_test_server(pool.clone(), scoped)
}

async fn named(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(a)
        .bind(name)
        .execute(pool)
        .await
        .expect("name");
    (a, g)
}

async fn viewer(pool: &PgPool, who: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, who)
        .await
        .expect("viewer")
}

async fn find(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    who: Uuid,
    name: &str,
) -> Value {
    let v = viewer(pool, who).await;
    let r = tools::agent_lookup::find_agent(
        server,
        &v,
        FindAgentParams {
            name: name.to_string(),
            kind: None,
            role: None,
            limit: None,
        },
    )
    .await
    .expect("find_agent");
    first_text(&r)
}

async fn get(server: &epigraph_mcp::EpiGraphMcpFull, pool: &PgPool, who: Uuid, id: Uuid) -> Value {
    let v = viewer(pool, who).await;
    let r = tools::agent_lookup::get_agent(
        server,
        &v,
        GetAgentParams {
            agent_id: id.to_string(),
        },
    )
    .await
    .expect("get_agent");
    first_text(&r)
}

fn strip(mut v: Value) -> Value {
    let o = v.as_object_mut().expect("object");
    o.remove("id");
    o.remove("display_name");
    o.remove("created_at");
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_agent_names_the_agent_that_filed_a_claim(pool: PgPool) {
    let server = app_server(&pool).await;
    let (reader, _) = named(&pool, "reader").await;
    let (author, _) = named(&pool, "Ivo Pendlebury").await;
    let claim = fixture::seed_public_claim(&pool, author, "a public observation").await;
    let filed_by: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("claim author");

    let card = get(&server, &pool, reader, filed_by).await;
    assert_eq!(card["id"], author.to_string());
    assert_eq!(card["display_name"], "Ivo Pendlebury");
    assert_eq!(card["counts"]["asserted_claims"], 1);
    assert!(card["kind"].is_string());

    let missing = tools::agent_lookup::get_agent(
        &server,
        &viewer(&pool, reader).await,
        GetAgentParams {
            agent_id: Uuid::new_v4().to_string(),
        },
    )
    .await
    .expect_err("no such agent");
    assert!(missing.message.contains("not found"), "{missing:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_reader_sees_the_operator_human_through_both_tools(pool: PgPool) {
    let server = app_server(&pool).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named(&pool, "Talia Brennick").await;
    fixture::make_human_operator(&pool, human).await;
    let (linked, _) = named(&pool, "helper-bot").await;
    let mut conn = pool.acquire().await.expect("acquire");
    assert!(
        AgentRepository::link_operator(&mut conn, linked, human)
            .await
            .expect("link")
            .link_live
    );
    drop(conn);

    for who in [outsider, linked, human] {
        let card = get(&server, &pool, who, linked).await;
        assert_eq!(card["operator_human"]["id"], human.to_string(), "{card}");
        assert_eq!(card["operator_human"]["display_name"], "Talia Brennick");
        assert_eq!(card["kind"], "llm_agent");
        let r = find(&server, &pool, who, "helper-bot").await;
        assert_eq!(
            r["results"][0]["operator_human"]["id"],
            human.to_string(),
            "{r}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_outsider_cannot_tell_a_private_claim(pool: PgPool) {
    let server = app_server(&pool).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let (with_note, group) = named(&pool, "helper-bot").await;
    let (without, _) = named(&pool, "helper-bot").await;
    // A claim private to the author's own group.
    fixture::seed_group_claim(&pool, with_note, group, "a private note").await;

    let r = find(&server, &pool, outsider, "helper-bot").await;
    let results = r["results"].as_array().expect("results");
    assert_eq!(results.len(), 2, "{r}");
    assert_eq!(
        strip(results[0].clone()),
        strip(results[1].clone()),
        "nothing an outsider receives tells the two apart"
    );
    let a = get(&server, &pool, outsider, with_note).await;
    let b = get(&server, &pool, outsider, without).await;
    assert_eq!(strip(a), strip(b), "get_agent: same");

    // The author reads its own private claim.
    let mine = get(&server, &pool, with_note, with_note).await;
    assert_eq!(mine["counts"]["asserted_claims"], 1, "{mine}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_agent_refuses_a_bad_query_as_invalid_params(pool: PgPool) {
    let server = app_server(&pool).await;
    let (caller, _) = named(&pool, "caller").await;
    let v = viewer(&pool, caller).await;
    for (name, kind) in [("x", None), ("ab", Some("wizard"))] {
        let e = tools::agent_lookup::find_agent(
            &server,
            &v,
            FindAgentParams {
                name: name.to_string(),
                kind: kind.map(str::to_string),
                role: None,
                limit: None,
            },
        )
        .await
        .expect_err("refused");
        assert_eq!(
            e.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{name}: {e:?}"
        );
    }
}

#[test]
fn both_tools_are_mapped_to_claims_read() {
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("find_agent"),
        Some("claims:read")
    );
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("get_agent"),
        Some("claims:read")
    );
}

/// A document extraction naming one author, as the ingest tools take it.
fn one_author_extraction(
    doi: &str,
    author: &str,
    tag: &str,
) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("Card Count Study {tag}"),
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": author, "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("Ingested authorship is counted on the author's card ({tag})."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": format!("Counting {tag}"),
            "paragraphs": [{
                "text": format!("Every claim the ingest attributes to an author is backed by its paper ({tag})."),
                "atoms": [format!("An ingest attribution is backed by the author's paper ({tag}).")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

/// The card's trusted-attribution rule against the REAL ingest walks (the
/// document walk and the spine walk), not a hand-built copy of what they
/// write: every in-force `asserts` edge the ingest gives a name-derived
/// author is backed by that author's paper, so `get_agent` counts all of
/// them, and the paper once.
#[sqlx::test(migrations = "../../migrations")]
async fn the_card_counts_every_attribution_the_real_ingest_writes(pool: PgPool) {
    let reader = app_server(&pool).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let ingester = common::build_scoped_test_server_generated_signer(
        pool.clone(),
        fixture::scoped_pool(&pool).await,
    );
    let v = fixture::public_viewer(&pool).await;

    for (walk, doi, author) in [
        ("document", "10.9999/card-count.doc", "Thaddeus Wrenfield"),
        ("spine", "10.9999/card-count.spine", "Philippa Ashcombe"),
    ] {
        let x = one_author_extraction(doi, author, walk);
        if walk == "document" {
            tools::ingestion::do_ingest_document(&ingester, &v, &x, None)
                .await
                .expect("document ingest");
        } else {
            tools::ingestion::do_ingest_document_spine(&ingester, &v, &x, None)
                .await
                .expect("spine ingest");
        }
        let node: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE display_name = $1")
            .bind(author)
            .fetch_one(&pool)
            .await
            .expect("the name-derived author node");
        let attributions: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT e.target_id) FROM edges e \
              WHERE e.source_id = $1 AND e.source_type = 'agent' \
                AND e.relationship = 'asserts' AND e.target_type = 'claim' \
                AND (e.valid_to IS NULL OR e.valid_to > now())",
        )
        .bind(node)
        .fetch_one(&pool)
        .await
        .expect("attribution edges");
        assert!(
            attributions > 0,
            "CALIBRATION ({walk}): the ingest attributed claims to its author"
        );

        let card = get(&reader, &pool, outsider, node).await;
        assert_eq!(card["counts"]["authored_papers"], 1, "{walk}: {card}");
        assert_eq!(
            card["counts"]["pending_authored_papers"], 0,
            "{walk}: {card}"
        );
        assert_eq!(
            card["counts"]["asserted_claims"], attributions,
            "{walk}: the card left out attributions the real ingest wrote: {card}"
        );
    }
}
