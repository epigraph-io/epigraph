//! `get_neighborhood` and `traverse` hide an edge removed with `delete_edge`.
//!
//! `delete_edge` has retracted rather than deleted since a6adf739 — the row
//! stays with `valid_to` set — and replies `deleted: true`. Until the display
//! tier honoured `valid_to`, both graph tools went on returning the "deleted"
//! edge with nothing marking it, so an agent that re-checked the neighbourhood
//! re-found it and tried to delete it again (which then reports "not found").
//!
//! Every test asserts its precondition — the edge IS visible before the
//! delete — so an absence assertion cannot pass on a fixture that never
//! produced the edge. The edge is removed through `do_delete_edge`, the same
//! function the rmcp dispatcher calls.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, first_text};
use epigraph_mcp::tools::edge_mutation::do_delete_edge;
use epigraph_mcp::tools::graph::{get_neighborhood, traverse};
use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::types::{DeleteEdgeParams, GetNeighborhoodParams, RecallParams, TraverseParams};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn delete(server: &EpiGraphMcpFull, edge_id: Uuid) {
    do_delete_edge(
        server,
        DeleteEdgeParams {
            edge_id: edge_id.to_string(),
        },
    )
    .await
    .expect("delete_edge succeeds");
}

fn nbhd_params(
    node: Uuid,
    direction: &str,
    include_retracted: Option<bool>,
) -> GetNeighborhoodParams {
    GetNeighborhoodParams {
        node_id: node.to_string(),
        relationship: None,
        direction: Some(direction.to_string()),
        limit: None,
        include_retracted,
    }
}

fn traverse_params(start: Uuid, include_retracted: Option<bool>) -> TraverseParams {
    TraverseParams {
        start_id: start.to_string(),
        max_depth: Some(3),
        relationship: None,
        min_truth: None,
        limit: None,
        include_retracted,
    }
}

fn edge_ids(resp: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = resp["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .map(|e| e["edge_id"].as_str().expect("edge_id").to_string())
        .collect();
    v.sort();
    v
}

fn node_ids(resp: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = resp["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["id"].as_str().expect("id").to_string())
        .collect();
    v.sort();
    v
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_hides_a_deleted_edge_and_flags_it_on_opt_in(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "nbhd-retraction").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B").await;
    let c = fixture::seed_public_claim(&pool, agent, "C").await;
    let gone = edge(&pool, a, b, "supports").await;
    let live = edge(&pool, a, c, "supports").await;
    let viewer = fixture::public_viewer(&pool).await;

    let before = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", None))
            .await
            .expect("neighbourhood before"),
    );
    assert_eq!(
        edge_ids(&before),
        sorted(vec![gone.to_string(), live.to_string()]),
        "precondition: both edges are visible before the delete"
    );

    delete(&server, gone).await;

    let after = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", None))
            .await
            .expect("neighbourhood after"),
    );
    assert_eq!(
        edge_ids(&after),
        vec![live.to_string()],
        "the deleted edge must be gone from the default neighbourhood"
    );
    assert_eq!(after["edge_count"], 1);
    let only = &after["edges"][0];
    assert!(
        only.get("retracted").is_none() && only.get("valid_to").is_none(),
        "an in-force edge with no end date serialises exactly as before: {only}"
    );

    // The far end, read inward, must not see it either.
    let from_b = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(b, "incoming", None))
            .await
            .expect("incoming at B"),
    );
    assert_eq!(edge_ids(&from_b), Vec::<String>::new());

    // Opt-in: both edges, the deleted one flagged.
    let audit = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", Some(true)))
            .await
            .expect("neighbourhood, include_retracted"),
    );
    assert_eq!(
        edge_ids(&audit),
        sorted(vec![gone.to_string(), live.to_string()])
    );
    for e in audit["edges"].as_array().expect("edges") {
        let is_gone = e["edge_id"] == gone.to_string();
        assert_eq!(
            e.get("retracted").and_then(serde_json::Value::as_bool),
            if is_gone { Some(true) } else { None },
            "only the deleted edge carries `retracted: true`: {e}"
        );
        assert_eq!(
            e.get("valid_to").is_some(),
            is_gone,
            "only the deleted edge carries a valid_to: {e}"
        );
    }
}

/// A future-dated `valid_to` is "in force until then": shown by default, with
/// its end date, and not flagged retracted.
#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_keeps_a_future_dated_edge_unflagged(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "nbhd-future").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B").await;
    let e = edge(&pool, a, b, "supports").await;
    sqlx::query("UPDATE edges SET valid_to = now() + interval '1 year' WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("future-date");
    let viewer = fixture::public_viewer(&pool).await;

    let resp = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "outgoing", None))
            .await
            .expect("neighbourhood"),
    );
    assert_eq!(edge_ids(&resp), vec![e.to_string()]);
    let only = &resp["edges"][0];
    assert!(
        only.get("valid_to").is_some(),
        "the end date is reported: {only}"
    );
    assert!(
        only.get("retracted").is_none(),
        "but it is not retracted: {only}"
    );
}

/// The traversal filters at the READ: a deleted edge is neither returned nor
/// followed, so the node behind it (and everything past it) is not reached.
#[sqlx::test(migrations = "../../migrations")]
async fn traverse_neither_returns_nor_follows_a_deleted_edge(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "traverse-retraction").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B behind the deleted edge").await;
    let c = fixture::seed_public_claim(&pool, agent, "C").await;
    let d = fixture::seed_public_claim(&pool, agent, "D past B").await;
    let gone = edge(&pool, a, b, "supports").await;
    edge(&pool, a, c, "supports").await;
    edge(&pool, b, d, "supports").await;
    let viewer = fixture::public_viewer(&pool).await;

    let before = first_text(
        &traverse(&server, &viewer, traverse_params(a, None))
            .await
            .expect("traverse before"),
    );
    assert_eq!(
        node_ids(&before),
        sorted(vec![
            a.to_string(),
            b.to_string(),
            c.to_string(),
            d.to_string()
        ]),
        "precondition: B and D are reached through A→B before the delete"
    );

    delete(&server, gone).await;

    let after = first_text(
        &traverse(&server, &viewer, traverse_params(a, None))
            .await
            .expect("traverse after"),
    );
    assert_eq!(
        node_ids(&after),
        sorted(vec![a.to_string(), c.to_string()]),
        "B is reachable only through the deleted edge, and D only through B"
    );
    let pairs: Vec<(String, String)> = after["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .map(|e| {
            (
                e["source_id"].as_str().unwrap().to_string(),
                e["target_id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(pairs, vec![(a.to_string(), c.to_string())]);

    // Opt-in walks it again and flags the edge.
    let audit = first_text(
        &traverse(&server, &viewer, traverse_params(a, Some(true)))
            .await
            .expect("traverse, include_retracted"),
    );
    assert_eq!(
        node_ids(&audit),
        sorted(vec![
            a.to_string(),
            b.to_string(),
            c.to_string(),
            d.to_string()
        ])
    );
    let flagged: Vec<&serde_json::Value> = audit["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .filter(|e| e.get("retracted").and_then(serde_json::Value::as_bool) == Some(true))
        .collect();
    assert_eq!(flagged.len(), 1, "exactly the deleted edge is flagged");
    assert_eq!(flagged[0]["source_id"], a.to_string());
    assert_eq!(flagged[0]["target_id"], b.to_string());
    assert!(flagged[0].get("valid_to").is_some());
}

// ── recall_with_context's batched context (fetch_batched_context) ───────────
//
// Every one of the fifteen `edges` aliases, with the same fixture shape
// `tenant_isolation_mcp.rs` uses for the tenancy predicate — except that each
// "hidden" relation is a RETRACTED edge between public claims rather than a
// private one. An in-force sibling of each class is kept so the absence
// assertions cannot pass on an empty context.

async fn edge_of(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, 'claim', $4) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn retracted_of(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    relationship: &str,
) {
    let id = edge_of(pool, source, source_type, target, relationship).await;
    let closed = epigraph_db::repos::edge::EdgeRepository::retract(pool, &[id])
        .await
        .expect("retract");
    assert_eq!(closed, vec![id], "fixture: the edge must be retracted");
}

async fn leveled(pool: &PgPool, agent: Uuid, label: &str, level: Option<i32>) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, label).await;
    if let Some(l) = level {
        sqlx::query(
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) \
                                            || jsonb_build_object('level', $2::int) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(l)
        .execute(pool)
        .await
        .expect("set level");
    }
    id
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'fixture') RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("insert paper")
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_omits_every_retracted_edge(pool: PgPool) {
    use epigraph_mcp::tools::recall::__test_only::fetch_batched_context;

    let (a, _g) = fixture::seed_agent_with_group(&pool, "recall-retraction").await;
    let s = leveled(&pool, a, "section S", Some(1)).await;
    let s2 = leveled(&pool, a, "section S2", Some(1)).await;
    let p = leveled(&pool, a, "paragraph P", Some(2)).await;
    let q = leveled(&pool, a, "paragraph Q", Some(2)).await;
    let p2 = leveled(&pool, a, "sibling P2", Some(2)).await;
    let p3 = leveled(&pool, a, "continuation P3", Some(2)).await;
    let p4 = leveled(&pool, a, "continued-from P4", Some(2)).await;
    let x = leveled(&pool, a, "other parent X", Some(2)).await;
    let y = leveled(&pool, a, "atom-b parent Y", Some(2)).await;
    let a0 = leveled(&pool, a, "atom A0", Some(3)).await;
    let a1 = leveled(&pool, a, "atom A1", Some(3)).await;
    let b0 = leveled(&pool, a, "atom B0", Some(3)).await;
    let b1 = leveled(&pool, a, "atom B1", Some(3)).await;
    let b2 = leveled(&pool, a, "atom B2", Some(3)).await;
    let n1 = leveled(&pool, a, "corroborator N1", None).await;
    let n2 = leveled(&pool, a, "contradicted N2", None).await;
    let n3 = leveled(&pool, a, "corroborator N3", None).await;
    let n4 = leveled(&pool, a, "corroborating-in N4", None).await;
    let n5 = leveled(&pool, a, "refuting-in N5", None).await;

    edge_of(&pool, s, "claim", p, "decomposes_to").await;
    retracted_of(&pool, s, "claim", p2, "decomposes_to").await; // 6. sibling
    retracted_of(&pool, s2, "claim", q, "decomposes_to").await; // 3. section parent
    edge_of(&pool, p, "claim", a0, "decomposes_to").await;
    retracted_of(&pool, p, "claim", a1, "decomposes_to").await; // 4. atom
    retracted_of(&pool, x, "claim", a0, "decomposes_to").await; // 5. bridge
    retracted_of(&pool, p, "claim", n1, "CORROBORATES").await; // 7. source arm
    retracted_of(&pool, n4, "claim", p, "CORROBORATES").await; // 7. target arm
    edge_of(&pool, p, "claim", n3, "CORROBORATES").await;
    let paper_n3 = paper(&pool, "10.0/retracted-n3").await;
    retracted_of(&pool, paper_n3, "paper", n3, "asserts").await; // 7. asserts_e
    retracted_of(&pool, p, "claim", n2, "contradicts").await; // 7b. source arm
    retracted_of(&pool, n5, "claim", p, "refutes").await; // 7b. target arm
    retracted_of(&pool, p, "claim", p3, "continues_argument").await; // 8. source arm
    retracted_of(&pool, p4, "claim", p, "continues_argument").await; // 8. target arm
    retracted_of(&pool, a0, "claim", b0, "supports").await; // 9. forward
    retracted_of(&pool, b2, "claim", a0, "supports").await; // 9. backward
    edge_of(&pool, a0, "claim", b1, "supports").await;
    retracted_of(&pool, y, "claim", b1, "decomposes_to").await; // 10. atom_b parent
    let paper_p = paper(&pool, "10.0/retracted-p").await;
    retracted_of(&pool, paper_p, "paper", p, "asserts").await; // 2. paper

    let viewer = fixture::public_viewer(&pool).await;
    let ctx = fetch_batched_context(&pool, &viewer, &[p, q], 8, 8, 8)
        .await
        .expect("batched context");

    let atoms = ctx.atoms_by_paragraph.get(&p).cloned().unwrap_or_default();
    let corr = ctx
        .corroborates_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let epi = ctx
        .epistemic_edges_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let siblings = ctx
        .siblings_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let cont = ctx
        .continues_argument_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let links = ctx
        .atom_atom_links_by_atom
        .get(&a0)
        .cloned()
        .unwrap_or_default();
    let b1_parents = ctx.paragraphs_by_atom.get(&b1).cloned().unwrap_or_default();
    let a0_atom = atoms.iter().find(|z| z.atom_id == a0);

    let shown: Vec<(&str, bool)> = vec![
        ("3. section parent of Q", ctx.section_meta.contains_key(&q)),
        ("4. atom A1 of P", atoms.iter().any(|z| z.atom_id == a1)),
        (
            "4. atoms_total of P counts A1",
            ctx.atoms_total_by_paragraph.get(&p) == Some(&2),
        ),
        (
            "5. bridge A0 -> X",
            a0_atom.is_some_and(|z| z.bridge_to_paragraphs.contains(&x)),
        ),
        (
            "6. sibling P2 of P",
            siblings.iter().any(|z| z.paragraph_id == p2),
        ),
        (
            "7. CORROBORATES P -> N1",
            corr.iter().any(|z| z.claim_id == n1),
        ),
        (
            "7. CORROBORATES N4 -> P",
            corr.iter().any(|z| z.claim_id == n4),
        ),
        (
            "7. paper_doi of N3 via asserts_e",
            corr.iter()
                .any(|z| z.claim_id == n3 && z.paper_doi.is_some()),
        ),
        (
            "7b. contradicts P -> N2",
            epi.iter().any(|z| z.claim_id == n2),
        ),
        ("7b. refutes N5 -> P", epi.iter().any(|z| z.claim_id == n5)),
        ("8. continues_argument P -> P3", cont.contains(&p3)),
        ("8. continues_argument P4 -> P", cont.contains(&p4)),
        ("9. atom link A0 -> B0", links.iter().any(|(b, _)| *b == b0)),
        ("9. atom link B2 -> A0", links.iter().any(|(b, _)| *b == b2)),
        ("10. parent Y of B1", b1_parents.contains(&y)),
        ("2. paper of P", ctx.paper_meta.contains_key(&p)),
    ];
    let resurrected: Vec<&str> = shown
        .into_iter()
        .filter_map(|(what, s)| s.then_some(what))
        .collect();
    assert!(
        resurrected.is_empty(),
        "each listed relation rests on a RETRACTED edge; recall context must show \
         none of them. Shown: {resurrected:?}"
    );

    // The in-force relations beside them still arrive.
    assert!(
        corr.iter().any(|z| z.claim_id == n3),
        "in-force N3 still corroborates P"
    );
    assert!(
        links.iter().any(|(b, _)| *b == b1),
        "in-force A0 -> B1 still links"
    );
    assert_eq!(
        ctx.atoms_total_by_paragraph.get(&p),
        Some(&1),
        "P's atom total counts only its in-force child"
    );
    assert!(
        ctx.section_meta.contains_key(&p),
        "P's in-force section parent still resolves"
    );
}

// ── recall's dispute annotation (ClaimRepository::dispute_batch) ────────────

fn recall_params(query: &str, exclude_contested: bool) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec![],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
        exclude_contested,
        since: None,
    }
}

/// The recall row for `claim`, if the page returned it.
fn recall_row(resp: &serde_json::Value, claim: Uuid) -> Option<serde_json::Value> {
    resp["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| r["claim_id"] == claim.to_string())
        .cloned()
}

/// `recall` annotates a hit `is_contested` / `dispute_count` /
/// `contesting_claim_ids` from `dispute_batch`, and `exclude_contested` drops
/// it. After `delete_edge` on the only `contradicts` edge against the target,
/// recall must read it as uncontested — the annotation fields omitted exactly
/// as for a never-contested hit, the removed edge's source no longer named,
/// and `exclude_contested` no longer dropping it. Before the in-force predicate
/// reached `dispute_batch`, all three kept reporting the deleted edge.
///
/// Lexical leg (mock embedder), as in `recall_dispute_awareness.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_reads_a_claim_uncontested_after_delete_edge(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "recall-dispute-retraction").await;
    let target =
        fixture::seed_public_claim(&pool, agent, "zelphorine lattice stability claim").await;
    let contester =
        fixture::seed_public_claim(&pool, agent, "zelphorine lattice stability rebuttal").await;
    let contradicts = edge(&pool, contester, target, "contradicts").await;
    let viewer = fixture::public_viewer(&pool).await;
    let query = "zelphorine lattice stability";

    let before = first_text(
        &recall(&server, &viewer, recall_params(query, false))
            .await
            .expect("recall before"),
    );
    let row = recall_row(&before, target).expect("precondition: the target is recalled");
    assert_eq!(
        row["is_contested"],
        serde_json::json!(true),
        "precondition: the target is contested before the delete: {row}"
    );
    assert_eq!(row["dispute_count"], serde_json::json!(1));
    assert_eq!(
        row["contesting_claim_ids"],
        serde_json::json!([contester.to_string()]),
        "precondition: the contester is named before the delete"
    );
    let excluded_before = first_text(
        &recall(&server, &viewer, recall_params(query, true))
            .await
            .expect("recall exclude_contested before"),
    );
    assert!(
        recall_row(&excluded_before, target).is_none(),
        "precondition: exclude_contested drops the contested target"
    );

    delete(&server, contradicts).await;

    let after = first_text(
        &recall(&server, &viewer, recall_params(query, false))
            .await
            .expect("recall after"),
    );
    let row = recall_row(&after, target).expect("the target is still recalled");
    for field in ["is_contested", "dispute_count", "contesting_claim_ids"] {
        assert!(
            row.get(field).is_none(),
            "after delete_edge the target must read uncontested; `{field}` is still set: {row}"
        );
    }
    let excluded_after = first_text(
        &recall(&server, &viewer, recall_params(query, true))
            .await
            .expect("recall exclude_contested after"),
    );
    assert!(
        recall_row(&excluded_after, target).is_some(),
        "exclude_contested must no longer drop a target whose only contradicts edge was deleted"
    );
}
