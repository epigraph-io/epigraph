//! A claim's `authored_by` block, driven end to end through the real
//! document ingest and read back through MCP `get_claim`, against the agent
//! card (`get_agent`) and the paper listing (`query_paper`) for the same
//! caller.
//!
//! Pinned here:
//! * a document's authors are a claim's PRIMARY authors only when that
//!   document's ingest CREATED the claim (the ingest's own creation record),
//!   never because some document asserts it: a converging document is listed
//!   as corroborating, and a claim someone filed directly keeps its filer as
//!   its author when a document later repeats it;
//! * an author an ingester named without speaking for them is listed as
//!   PENDING (apart from the primary authors, with the ingester that named
//!   them), consistently with the card and `query_paper`;
//! * EVERY ingester of the claim is listed, each with its human bound at the
//!   time of its ingest;
//! * a bare `paper -asserts-> claim` edge with no ingest record is not read;
//! * the agent card's `operator_human` and the claim's `authored_by.human`
//!   name the same human for the same agent and caller while the binding is
//!   in force; once a link is retired or an allowance revoked the card names
//!   nobody, a claim filed before that still names the human bound when it
//!   was filed, and a claim filed after it names nobody.
//!
//! Both of the server's pools run as `epigraph_app`, so row security answers
//! as in production. All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    GetAgentParams, GetClaimParams, IngestDocumentInlineParams, IngestDocumentSpineParams,
    QueryPaperParams, SubmitClaimParams,
};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// An ingesting server whose plain and scoped pools both run as `epigraph_app`.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, AgentSigner::generate(), embedder, false).with_scoped_pool(scoped)
}

fn text(r: &CallToolResult) -> Value {
    let t = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(t).expect("JSON response")
}

/// A registered human operator named `name`.
async fn human_named(pool: &PgPool, name: &str) -> Uuid {
    let (h, _) = fixture::seed_human_operator(pool, "provenance-human").await;
    named(pool, h, name).await;
    h
}

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

fn doc_with_atoms(doi: &str, authors: Value, atoms: &[&str]) -> DocumentExtraction {
    let generality: Vec<u8> = atoms.iter().map(|_| 3).collect();
    serde_json::from_value(json!({
        "source": {"title": format!("Provenance {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": authors},
        "thesis": format!("Thesis of {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Paragraph of {doi}."),
            "atoms": atoms,
            "generality": generality, "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction parses")
}

async fn ingest_wait(server: &EpiGraphMcpFull, pool: &PgPool, extraction: DocumentExtraction) {
    let viewer = fixture::public_viewer(pool).await;
    tools::ingestion::ingest_document_inline(
        server,
        &viewer,
        IngestDocumentInlineParams {
            extraction,
            wait: Some(true),
        },
        None,
    )
    .await
    .expect("ingest succeeds");
}

/// The claim the paper keyed `doi` asserts whose content is `content`.
async fn claim_of(pool: &PgPool, doi: &str, content: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT c.id FROM claims c JOIN edges pc ON pc.target_id = c.id \
           JOIN papers p ON p.id = pc.source_id \
          WHERE p.doi = $1 AND pc.relationship = 'asserts' AND c.content = $2",
    )
    .bind(doi)
    .bind(content)
    .fetch_one(pool)
    .await
    .expect("the paper asserts the claim")
}

/// The node the document ingest derives from an author's name.
async fn name_node(pool: &PgPool, name: &str) -> Uuid {
    let (_did, pk) = epigraph_crypto::did_key::did_key_for_author(None, name);
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(pk.as_slice())
        .fetch_one(pool)
        .await
        .expect("the name-derived author node exists")
}

async fn get_claim_as(server: &EpiGraphMcpFull, pool: &PgPool, caller: Uuid, claim: Uuid) -> Value {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let out = tools::claims::get_claim(
        server,
        &viewer,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .expect("get_claim");
    text(&out)["authored_by"].clone()
}

async fn card_as(server: &EpiGraphMcpFull, pool: &PgPool, caller: Uuid, agent: Uuid) -> Value {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    let out = tools::agent_lookup::get_agent(
        server,
        &viewer,
        GetAgentParams {
            agent_id: agent.to_string(),
        },
    )
    .await
    .expect("get_agent");
    text(&out)
}

async fn query_paper(server: &EpiGraphMcpFull, pool: &PgPool, doi: &str) -> Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = tools::paper_queries::query_paper(
        server,
        &viewer,
        QueryPaperParams {
            doi: doi.to_string(),
            limit: None,
            offset: None,
            ingested_by: None,
        },
    )
    .await
    .expect("query_paper");
    text(&r)
}

fn ids(list: &Value) -> Vec<Value> {
    list.as_array()
        .unwrap_or_else(|| panic!("an array: {list}"))
        .iter()
        .map(|a| a["id"].clone())
        .collect()
}

fn dois(list: &Value) -> Vec<Value> {
    list.as_array()
        .unwrap_or_else(|| panic!("an array: {list}"))
        .iter()
        .map(|p| p["paper"]["doi"].clone())
        .collect()
}

/// `(agent id, paper id, created_claim)` of every listed ingester.
fn ingesters(block: &Value) -> Vec<(Value, Value, Value)> {
    block["ingesters"]
        .as_array()
        .unwrap_or_else(|| panic!("ingesters listed: {block}"))
        .iter()
        .map(|i| {
            (
                i["agent"]["id"].clone(),
                i["paper_id"].clone(),
                i["created_claim"].clone(),
            )
        })
        .collect()
}

async fn paper_id(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("paper row")
}

/// A document's authors are the PRIMARY authors of the claims its ingest
/// created, and only of those. A second document converging on the claim is
/// a corroborating source, and its ingester is listed beside the first. An
/// author the ingester named without speaking for them is listed as pending,
/// never among the primary authors, with the ingester that named them, and
/// the card and `query_paper` say the same.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_is_primary_only_for_the_claims_its_ingest_created(pool: PgPool) {
    let a = app_role_server(&pool).await;
    let b = app_role_server(&pool).await;
    let (a_id, b_id) = (
        a.server_agent_id().await.expect("a"),
        b.server_agent_id().await.expect("b"),
    );
    let person = human_named(&pool, "Odile Varnhagen").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "provenance-stranger").await;
    let (d1, d2) = ("10.9999/provenance-one", "10.9999/provenance-two");
    let shared = "A shared atom both provenance documents state.";

    ingest_wait(
        &a,
        &pool,
        doc_with_atoms(
            d1,
            json!([{"name": "Ingrid Solvang"},
                   {"name": "O. Varnhagen", "agent_id": person.to_string()}]),
            &[shared],
        ),
    )
    .await;
    ingest_wait(
        &b,
        &pool,
        doc_with_atoms(d2, json!([{"name": "Pell Quorrin"}]), &[shared]),
    )
    .await;
    let x = claim_of(&pool, d1, shared).await;
    assert_eq!(
        x,
        claim_of(&pool, d2, shared).await,
        "CALIBRATION: both documents converge on one claim"
    );
    let (ingrid, pell) = (
        name_node(&pool, "Ingrid Solvang").await,
        name_node(&pool, "Pell Quorrin").await,
    );
    let (p1, p2) = (paper_id(&pool, d1).await, paper_id(&pool, d2).await);

    for caller in [stranger, person] {
        let block = get_claim_as(&a, &pool, caller, x).await;
        assert_eq!(block["source"], json!("literature"), "{block}");
        assert_eq!(block["paper"]["paper"]["doi"], json!(d1), "{block}");
        assert_eq!(
            ids(&block["paper"]["authors"]),
            vec![json!(ingrid)],
            "only the creating document's countersigned authors are primary: {block}"
        );
        let pending = &block["paper"]["pending_authors"];
        assert_eq!(ids(pending), vec![json!(person)], "{block}");
        assert_eq!(pending[0]["pending_countersign"], json!(true), "{block}");
        assert_eq!(pending[0]["named_by"]["id"], json!(a_id), "{block}");
        assert_eq!(block["ingested_by"]["agent"]["id"], json!(a_id), "{block}");
        assert_eq!(
            dois(&block["corroborated_by"]),
            vec![json!(d2)],
            "the converging document corroborates: {block}"
        );
        assert_eq!(
            ids(&block["corroborated_by"][0]["authors"]),
            vec![json!(pell)],
            "{block}"
        );
        assert_eq!(
            ingesters(&block),
            vec![
                (json!(a_id), json!(p1), json!(true)),
                (json!(b_id), json!(p2), json!(false)),
            ],
            "every ingester is listed: {block}"
        );
    }

    // The other surfaces say the same about the pending author.
    let listed = query_paper(&a, &pool, d1).await;
    let entry = listed["authors"]
        .as_array()
        .expect("authors")
        .iter()
        .find(|e| e["agent_id"] == json!(person))
        .cloned()
        .unwrap_or_else(|| panic!("query_paper lists the person: {listed}"));
    assert_eq!(entry["pending_countersign"], json!(true), "{listed}");
    let counts = card_as(&a, &pool, stranger, person).await["counts"].clone();
    assert_eq!(counts["authored_papers"], json!(0), "{counts}");
    assert_eq!(counts["pending_authored_papers"], json!(1), "{counts}");
}

/// `ingest_document_spine` on `server`, as a public viewer.
async fn spine_wait(server: &EpiGraphMcpFull, pool: &PgPool, extraction: DocumentExtraction) {
    let viewer = fixture::public_viewer(pool).await;
    tools::ingestion::ingest_document_spine(
        server,
        &viewer,
        IngestDocumentSpineParams { extraction },
        None,
    )
    .await
    .expect("spine ingests");
}

/// Every claim the paper keyed `doi` asserts.
async fn claims_of_doc(pool: &PgPool, doi: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT pc.target_id FROM edges pc JOIN papers p ON p.id = pc.source_id \
          WHERE p.doi = $1 AND pc.relationship = 'asserts' AND pc.target_type = 'claim' \
          ORDER BY pc.target_id",
    )
    .bind(doi)
    .fetch_all(pool)
    .await
    .expect("the paper's claims")
}

/// `(author id, added_by id)` of every author listed under `added_authors`.
fn added(block: &Value) -> Vec<(Value, Value)> {
    let mut out: Vec<(Value, Value)> = block["paper"]["added_authors"]
        .as_array()
        .unwrap_or_else(|| panic!("added authors listed: {block}"))
        .iter()
        .map(|a| (a["id"].clone(), a["added_by"]["id"].clone()))
        .collect();
    out.sort_by_key(|(id, _)| id.to_string());
    out
}

/// A claim's PRIMARY authors are the creating document's authors as that
/// ingest recorded them when it created the claim. A later ingest of the
/// SAME document key that names more authors, by a stranger or by the
/// creator itself, converges on the claim and writes those authorships onto
/// the paper; none of them becomes primary. They are listed apart, under
/// `added_authors`, each with the ingester that added it. Both walks, every
/// reader.
#[sqlx::test(migrations = "../../migrations")]
async fn a_later_ingest_of_the_creating_document_never_changes_its_primary_authors(pool: PgPool) {
    let a = app_role_server(&pool).await;
    let b = app_role_server(&pool).await;
    let (a_id, b_id) = (
        a.server_agent_id().await.expect("a"),
        b.server_agent_id().await.expect("b"),
    );
    assert_ne!(a_id, b_id, "CALIBRATION: two ingesters");
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "provenance-stranger").await;
    let d1 = "10.9999/provenance-creating";
    let atom = "An atom only the creating document first stated.";

    // The document walk.
    ingest_wait(
        &a,
        &pool,
        doc_with_atoms(d1, json!([{"name": "Ingrid Solvang"}]), &[atom]),
    )
    .await;
    let x = claim_of(&pool, d1, atom).await;
    let ingrid = name_node(&pool, "Ingrid Solvang").await;
    let before = get_claim_as(&a, &pool, stranger, x).await;
    assert_eq!(
        ids(&before["paper"]["authors"]),
        vec![json!(ingrid)],
        "CALIBRATION: {before}"
    );
    ingest_wait(
        &b,
        &pool,
        doc_with_atoms(
            d1,
            json!([{"name": "Ingrid Solvang"}, {"name": "Interloper Vexx"}]),
            &[atom],
        ),
    )
    .await;
    ingest_wait(
        &a,
        &pool,
        doc_with_atoms(
            d1,
            json!([{"name": "Ingrid Solvang"}, {"name": "Late Addendum"}]),
            &[atom],
        ),
    )
    .await;
    let (vexx, late) = (
        name_node(&pool, "Interloper Vexx").await,
        name_node(&pool, "Late Addendum").await,
    );
    let listed = query_paper(&a, &pool, d1).await;
    assert_eq!(
        listed["authors"].as_array().map(Vec::len),
        Some(3),
        "CALIBRATION: both re-ingests wrote their authorship onto the paper: {listed}"
    );
    let p1 = paper_id(&pool, d1).await;
    for caller in [stranger, a_id, b_id] {
        let block = get_claim_as(&a, &pool, caller, x).await;
        assert_eq!(block["source"], json!("literature"), "{block}");
        assert_eq!(
            ids(&block["paper"]["authors"]),
            vec![json!(ingrid)],
            "the primary authors are the creating ingest's, as it recorded them: {block}"
        );
        assert_eq!(
            added(&block),
            {
                let mut v = vec![(json!(vexx), json!(b_id)), (json!(late), json!(a_id))];
                v.sort_by_key(|(id, _)| id.to_string());
                v
            },
            "a later ingest's authors are listed apart, with who added them: {block}"
        );
        assert_eq!(block["paper"]["pending_authors"], json!([]), "{block}");
        assert_eq!(block["ingested_by"]["agent"]["id"], json!(a_id), "{block}");
        assert_eq!(
            ingesters(&block),
            vec![
                (json!(a_id), json!(p1), json!(true)),
                (json!(b_id), json!(p1), json!(false)),
            ],
            "{block}"
        );
    }

    // The spine walk.
    let d2 = "10.9999/provenance-creating-spine";
    spine_wait(
        &a,
        &pool,
        doc_with_atoms(d2, json!([{"name": "Spine Lead"}]), &[]),
    )
    .await;
    let spine_claims = claims_of_doc(&pool, d2).await;
    assert!(
        !spine_claims.is_empty(),
        "CALIBRATION: the spine created claims"
    );
    let lead = name_node(&pool, "Spine Lead").await;
    spine_wait(
        &b,
        &pool,
        doc_with_atoms(
            d2,
            json!([{"name": "Spine Lead"}, {"name": "Spine Interloper"}]),
            &[],
        ),
    )
    .await;
    assert_eq!(
        claims_of_doc(&pool, d2).await,
        spine_claims,
        "CALIBRATION: the second spine converged on every claim"
    );
    let interloper = name_node(&pool, "Spine Interloper").await;
    for c in &spine_claims {
        let block = get_claim_as(&a, &pool, stranger, *c).await;
        assert_eq!(block["source"], json!("literature"), "{block}");
        assert_eq!(
            ids(&block["paper"]["authors"]),
            vec![json!(lead)],
            "the spine's creation record fixes its primary authors: {block}"
        );
        assert_eq!(
            added(&block),
            vec![(json!(interloper), json!(b_id))],
            "{block}"
        );
    }
}

/// A claim filed DIRECTLY stays its filer's when a document later repeats
/// it: the document is a corroborating source and its ingester is listed,
/// but the block is the agent's. A bare `paper -asserts-> claim` edge that no
/// ingest recorded is not read at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_document_repeating_a_directly_filed_claim_leaves_the_filer_its_author(pool: PgPool) {
    let a = app_role_server(&pool).await;
    let b = app_role_server(&pool).await;
    let (a_id, b_id) = (
        a.server_agent_id().await.expect("a"),
        b.server_agent_id().await.expect("b"),
    );
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "provenance-stranger").await;
    let viewer = fixture::public_viewer(&pool).await;
    let stated = "Stated directly before any document repeated it.";
    tools::claims::submit_claim(
        &a,
        &viewer,
        SubmitClaimParams {
            content: stated.into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("a files the claim directly");
    let d3 = "10.9999/provenance-repeat";
    ingest_wait(
        &b,
        &pool,
        doc_with_atoms(d3, json!([{"name": "Tamsin Arkwright"}]), &[stated]),
    )
    .await;
    let claim = claim_of(&pool, d3, stated).await;
    let filer: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("filer");
    assert_eq!(
        filer, a_id,
        "CALIBRATION: the document converged on a's claim"
    );

    // A bare assertion edge no ingest recorded, planted administratively.
    let bare: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.9999/provenance-bare', 'Bare') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("bare paper");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(bare)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("bare asserts edge");

    let block = get_claim_as(&a, &pool, stranger, claim).await;
    assert_eq!(block["source"], json!("agent"), "{block}");
    assert_eq!(block["agent"]["id"], json!(a_id), "{block}");
    assert_eq!(
        dois(&block["corroborated_by"]),
        vec![json!(d3)],
        "the repeating document corroborates; the bare edge is not read: {block}"
    );
    assert_eq!(
        ingesters(&block),
        vec![(json!(b_id), json!(paper_id(&pool, d3).await), json!(false))],
        "{block}"
    );
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the link is live");
}

/// A fresh agent bound to `operator` by a client allowance: `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "provenance-allowance").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'provenance allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("provenance-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let allowed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("provenance test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, r)
    })
    .await;
    assert!(allowed, "CALIBRATION: the allowance is in force");
    (agent, client)
}

/// The card's `operator_human.id` and the claim's `authored_by.human.id`, as
/// `caller` reads them.
async fn both(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    agent: Uuid,
    claim: Uuid,
) -> (Value, Value) {
    let card = card_as(server, pool, caller, agent).await;
    let block = get_claim_as(server, pool, caller, claim).await;
    assert_eq!(block["source"], json!("agent"), "{block}");
    assert_eq!(block["agent"]["id"], json!(agent), "{block}");
    (
        card["operator_human"]["id"].clone(),
        block["human"]["id"].clone(),
    )
}

/// The card and the claim name one human under one rule while the binding
/// is in force, through a live link and through a client allowance. After a
/// retirement or a revocation the card names nobody, a claim filed while the
/// binding was in force still names the human bound when it was filed, and a
/// claim filed afterwards names nobody. Every reader sees the same.
#[sqlx::test(migrations = "../../migrations")]
async fn the_card_and_the_claim_name_the_same_human_while_the_binding_is_in_force(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "provenance-stranger").await;
    let h1 = human_named(&pool, "Linnea Carrow").await;
    let h2 = human_named(&pool, "Bertil Osgood").await;

    // A live link.
    let (linked, _) = fixture::seed_agent_with_group(&pool, "provenance-linked").await;
    link(&pool, linked, h1).await;
    let before_retire = fixture::seed_public_claim(&pool, linked, "filed while linked").await;
    for caller in [stranger, h1] {
        let (card, claim) = both(&server, &pool, caller, linked, before_retire).await;
        assert_eq!(card, json!(h1), "live link: the card names the operator");
        assert_eq!(claim, card, "live link: the claim names the card's human");
    }

    // The link retired.
    let outcome: String = sqlx::query_scalar(
        "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'provenance test', true)",
    )
    .bind(linked)
    .fetch_one(&pool)
    .await
    .expect("retire the link");
    assert_eq!(outcome, "retired", "CALIBRATION");
    let after_retire = fixture::seed_public_claim(&pool, linked, "filed after retirement").await;
    for caller in [stranger, h1] {
        let (card, claim) = both(&server, &pool, caller, linked, before_retire).await;
        assert_eq!(card, Value::Null, "retired: the card names nobody");
        assert_eq!(
            claim,
            json!(h1),
            "retired: a claim filed while linked names the human bound then"
        );
        let (_, later) = both(&server, &pool, caller, linked, after_retire).await;
        assert_eq!(
            later,
            Value::Null,
            "a claim filed after retirement names nobody"
        );
    }

    // A client allowance.
    let (allowed, client) = allowance_bound(&pool, h2).await;
    let before_revoke = fixture::seed_public_claim(&pool, allowed, "filed while allowed").await;
    for caller in [stranger, h2] {
        let (card, claim) = both(&server, &pool, caller, allowed, before_revoke).await;
        assert_eq!(card, json!(h2), "allowance: the card names the operator");
        assert_eq!(claim, card, "allowance: the claim names the card's human");
    }

    // The allowance revoked.
    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
        )
        .bind(client)
        .bind("provenance test")
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION");
    let after_revoke = fixture::seed_public_claim(&pool, allowed, "filed after revocation").await;
    for caller in [stranger, h2] {
        let (card, claim) = both(&server, &pool, caller, allowed, before_revoke).await;
        assert_eq!(card, Value::Null, "revoked: the card names nobody");
        assert_eq!(
            claim,
            json!(h2),
            "revoked: a claim filed while allowed names the human bound then"
        );
        let (_, later) = both(&server, &pool, caller, allowed, after_revoke).await;
        assert_eq!(
            later,
            Value::Null,
            "a claim filed after revocation names nobody"
        );
    }
}
