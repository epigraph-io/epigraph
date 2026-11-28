//! MCP `link_epistemic` honours `EPIGRAPH_CONTRADICT_COMPOUND_GUARD`
//! (backlog b4c2fc2f). A `contradicts` / `refutes` edge onto a target whose
//! text asserts several independent things and that has NOT been decomposed
//! disputes all of them at once:
//!
//! - `warn` (the default): the edge is written as before, the response adds
//!   `partial_contradiction_risk {conjuncts, hint}`, and the caller (never
//!   the content) is logged under `epigraph::contradiction_guard`;
//! - `refuse`: `invalid_params` with `data.error =
//!   compound_contradiction_target`, and no edge (nor `edge.added` event) is
//!   written;
//! - an atomic target, a decomposed target and a non-negative relationship
//!   are unaffected, in either mode.
//!
//! The server's mode is set with `with_contradict_compound_guard`, so both
//! modes run in one process.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text, seed_claim, seed_claim_with_belief};
use epigraph_engine::belief_modes::ContradictCompoundGuard;
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::types::LinkEpistemicParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// One sentence joining two independent clauses: `conjunct_screen` counts 2.
const COMPOUND_TEXT: &str =
    "b4c2fc2f guard: the catalyst raised the yield, but it shortened the column life.";

async fn server(pool: &PgPool, mode: ContradictCompoundGuard) -> EpiGraphMcpFull {
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
        .with_contradict_compound_guard(mode)
}

fn params(source: Uuid, target: Uuid, relationship: &str) -> LinkEpistemicParams {
    LinkEpistemicParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: relationship.to_string(),
        properties: None,
    }
}

/// In-force edges between `a` and `b`, either direction, any relationship.
async fn edges_between(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges \
          WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

async fn edge_added_events(pool: &PgPool, target: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE event_type = 'edge.added' \
          AND (payload->>'target_id' = $1 OR payload->>'source_id' = $1)",
    )
    .bind(target.to_string())
    .fetch_one(pool)
    .await
    .expect("count edge.added events")
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to");
}

#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn warn_writes_the_edge_and_flags_the_partial_contradiction_risk(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool, ContradictCompoundGuard::Warn).await;
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let target = seed_claim(&pool, COMPOUND_TEXT, 0.5).await;

    for relationship in ["contradicts", "REFUTES"] {
        let resp = first_text(
            &do_link_epistemic(&server, &viewer, params(source, target, relationship), None)
                .await
                .unwrap_or_else(|e| panic!("warn writes the {relationship} edge: {e:?}")),
        );
        let risk = resp
            .get("partial_contradiction_risk")
            .unwrap_or_else(|| panic!("warn must flag the {relationship} edge: {resp}"));
        assert_eq!(risk["conjuncts"], 2, "{resp}");
        assert!(
            risk["hint"]
                .as_str()
                .is_some_and(|h| h.contains("decompose the target")),
            "{resp}"
        );
        assert_eq!(resp["was_created"], true, "{resp}");
    }
    assert_eq!(
        edges_between(&pool, source, target).await,
        2,
        "warn writes both edges"
    );

    // The journal names the caller, never the content.
    let caller = server.server_agent_id().await.expect("server agent");
    // One journal line per accepted edge, naming the caller.
    let caller_id = caller.to_string();
    logs_assert(|lines: &[&str]| {
        let accepted = lines
            .iter()
            .filter(|l| l.contains("contradiction onto an undecomposed compound accepted"))
            .collect::<Vec<_>>();
        if accepted.len() != 2 {
            return Err(format!("expected 2 accepted lines, got {accepted:?}"));
        }
        if accepted.iter().all(|l| l.contains(&caller_id)) {
            Ok(())
        } else {
            Err(format!("an accepted line lacks the caller {caller_id}: {accepted:?}"))
        }
    });
    assert!(
        !logs_contain("shortened the column life"),
        "the guard must never log the claim's content"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn refuse_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool, ContradictCompoundGuard::Refuse).await;
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let target = seed_claim(&pool, COMPOUND_TEXT, 0.5).await;
    let events_before = edge_added_events(&pool, target).await;

    for relationship in ["contradicts", "Refutes"] {
        let err = do_link_epistemic(&server, &viewer, params(source, target, relationship), None)
            .await
            .expect_err("refuse must refuse a contradiction onto an undecomposed compound");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
        assert!(err.message.contains("nothing was written"), "{err:?}");
        let data = err.data.clone().expect("a machine-keyed refusal body");
        assert_eq!(data["error"], "compound_contradiction_target", "{data}");
        assert_eq!(data["claim_id"], target.to_string(), "{data}");
        assert_eq!(data["conjuncts"], 2, "{data}");
        assert_eq!(data["flag"], "EPIGRAPH_CONTRADICT_COMPOUND_GUARD", "{data}");
    }
    assert_eq!(edges_between(&pool, source, target).await, 0, "no edge");
    assert_eq!(
        edge_added_events(&pool, target).await,
        events_before,
        "no edge.added event"
    );
    let (belief,): (Option<f64>,) = sqlx::query_as("SELECT belief FROM claims WHERE id = $1")
        .bind(target)
        .fetch_one(&pool)
        .await
        .expect("read target");
    assert!(belief.is_none(), "no belief wired onto the target");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_atomic_target_a_decomposed_target_and_a_positive_edge_are_unaffected(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    for mode in [ContradictCompoundGuard::Refuse, ContradictCompoundGuard::Warn] {
        let server = server(&pool, mode).await;
        let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;

        // Atomic text.
        let atom = seed_claim(&pool, "b4c2fc2f guard: the catalyst raised the yield.", 0.5).await;
        // Compound text, but decomposed: it has atoms to aim at.
        let decomposed = seed_claim(&pool, COMPOUND_TEXT, 0.5).await;
        let part_a = seed_claim(&pool, "b4c2fc2f guard part a.", 0.5).await;
        let part_b = seed_claim(&pool, "b4c2fc2f guard part b.", 0.5).await;
        decomposes_to(&pool, decomposed, part_a).await;
        decomposes_to(&pool, decomposed, part_b).await;
        // Compound text, undecomposed, but a positive relationship.
        let compound = seed_claim(&pool, COMPOUND_TEXT, 0.5).await;

        for (target, relationship) in [
            (atom, "contradicts"),
            (decomposed, "refutes"),
            (compound, "supports"),
        ] {
            let resp = first_text(
                &do_link_epistemic(&server, &viewer, params(source, target, relationship), None)
                    .await
                    .unwrap_or_else(|e| panic!("{mode:?} {relationship}: {e:?}")),
            );
            assert!(
                resp.get("partial_contradiction_risk").is_none(),
                "{mode:?} {relationship}: {resp}"
            );
            assert_eq!(
                edges_between(&pool, source, target).await,
                1,
                "{mode:?} {relationship}: written as before"
            );
        }
    }
}
