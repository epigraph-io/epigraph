//! `link_hierarchical`'s typed endpoints and workflow references (backlogs
//! 03d87e3a and 41d7b27a).
//!
//! Before: both endpoints were claims and not caller-controllable, so a
//! dropped `workflow -executes-> claim` edge could not be repaired from MCP,
//! and no tool wrote a workflow-to-workflow reference (`invokes`,
//! `depends_on`). These drive `do_link_hierarchical` on the stdio path, and
//! (backlog 298317a7) on the authenticated-HTTP path with a caller's token,
//! against workflows stored through `store_workflow`, the same rows a live
//! plan reads.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkHierarchicalParams, StoreWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn store(server: &epigraph_mcp::EpiGraphMcpFull, steps: &[&str]) -> Uuid {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(stdio_public_tenancy(server).await),
            goal: format!("workflow reference probe {}", Uuid::new_v4()),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
            force_new: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    parse_uuid_field(&first_text(&stored), "workflow_id")
}

async fn step_claim(pool: &PgPool, workflow: Uuid, content: &str) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT e.id, c.id FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.content = $2 \
           AND e.valid_to IS NULL",
    )
    .bind(workflow)
    .bind(content)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("executes edge for {content:?}: {e}"))
}

async fn in_force(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = $3 AND (valid_to IS NULL OR valid_to > now())",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

fn link(
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
) -> LinkHierarchicalParams {
    LinkHierarchicalParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: relationship.to_string(),
        source_type: Some(source_type.to_string()),
        target_type: Some(target_type.to_string()),
        ..Default::default()
    }
}

/// The 03d87e3a incident shape: a workflow's `executes` edge to a live step
/// claim is gone (retracted here), the claims are intact, and the repair must
/// be possible from MCP. The restored row is a `workflow -> claim` edge, typed
/// as such, and the plan reads the step again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_executes_edge_is_repaired_from_mcp(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let workflow = store(&server, &["gather inputs", "publish output"]).await;
    let (dropped, step) = step_claim(&pool, workflow, "publish output").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop the executes edge");
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 0);

    let mut params = link(workflow, "workflow", step, "claim", "executes");
    params.properties = Some(serde_json::json!({"plan_index": 1}));
    let repaired = do_link_hierarchical(&server, &viewer, params, None)
        .await
        .expect("link_hierarchical repairs a workflow -> claim executes edge");
    let repaired = first_text(&repaired);
    assert_eq!(repaired["created"], serde_json::json!(true), "{repaired}");

    let (source_type, target_type, plan_index): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT source_type, target_type, (properties->>'plan_index')::bigint FROM edges \
         WHERE id = $1::uuid AND valid_to IS NULL",
    )
    .bind(repaired["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the repaired edge is in force");
    assert_eq!(
        (source_type.as_str(), target_type.as_str()),
        ("workflow", "claim")
    );
    assert_eq!(plan_index, Some(1));
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 1);
}

/// The type pair is the relationship's, not the caller's: `executes` from a
/// claim, and an unregistered type, are refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn executes_refuses_a_claim_source_and_unknown_types(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = seed_claim(&pool, "not a workflow", 0.5).await;
    let b = seed_claim(&pool, "a step", 0.5).await;

    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "claim", b, "claim", "executes"),
        None,
    )
    .await
    .expect_err("executes from a claim is refused");
    assert!(
        err.message.contains("does not link claim -> claim"),
        "{}",
        err.message
    );
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "no_such_type", b, "claim", "executes"),
        None,
    )
    .await
    .expect_err("an unregistered type is refused");
    assert!(
        err.message.contains("not a registered entity type"),
        "{}",
        err.message
    );
    // The document-structure relationships stay claim to claim.
    let w = store(&server, &["only step"]).await;
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w, "workflow", b, "claim", "decomposes_to"),
        None,
    )
    .await
    .expect_err("decomposes_to from a workflow is refused");
    assert!(err.message.contains("does not link"), "{}", err.message);
    assert_eq!(in_force(&pool, a, b, "executes").await, 0);
    assert_eq!(in_force(&pool, w, b, "decomposes_to").await, 0);
}

/// `depends_on` is a prerequisite: `W1 depends_on W2` then `W2 depends_on W1`
/// is a cycle and the second is refused; a third workflow closing a longer
/// loop is refused too.
#[sqlx::test(migrations = "../../migrations")]
async fn depends_on_refuses_a_cycle(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w1 = store(&server, &["w1 step"]).await;
    let w2 = store(&server, &["w2 step"]).await;
    let w3 = store(&server, &["w3 step"]).await;

    for (s, t) in [(w1, w2), (w2, w3)] {
        let ok = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "depends_on"),
            None,
        )
        .await
        .expect("an acyclic depends_on is written");
        assert_eq!(first_text(&ok)["created"], serde_json::json!(true));
    }
    for (s, t) in [(w2, w1), (w3, w1)] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "depends_on"),
            None,
        )
        .await
        .expect_err("a depends_on closing a cycle is refused");
        assert!(
            err.message.contains("would close a cycle"),
            "{}",
            err.message
        );
        assert_eq!(
            in_force(&pool, s, t, "depends_on").await,
            0,
            "nothing written"
        );
    }
}

/// `invokes` from a step claim belongs to the workflow executing that step:
/// `W1 -executes-> S1 -invokes-> W2` makes `W2 invokes W1` a cycle. A
/// workflow-level `invokes` keeps its `at_step`.
#[sqlx::test(migrations = "../../migrations")]
async fn invokes_through_a_step_claim_refuses_the_closing_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w1 = store(&server, &["call the sub-workflow"]).await;
    let w2 = store(&server, &["sub step"]).await;
    let (_, s1) = step_claim(&pool, w1, "call the sub-workflow").await;

    do_link_hierarchical(
        &server,
        &viewer,
        link(s1, "claim", w2, "workflow", "invokes"),
        None,
    )
    .await
    .expect("a step claim invokes a sub-workflow");
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", w1, "workflow", "invokes"),
        None,
    )
    .await
    .expect_err("W2 invokes W1 closes W1 -executes-> S1 -invokes-> W2");
    assert!(
        err.message.contains("would close a cycle"),
        "{}",
        err.message
    );
    assert_eq!(in_force(&pool, w2, w1, "invokes").await, 0);

    let mut params = link(w1, "workflow", w2, "workflow", "invokes");
    params.at_step = Some(0);
    let ok = do_link_hierarchical(&server, &viewer, params, None)
        .await
        .expect("W1 invokes W2 is acyclic");
    let at_step: Option<i64> = sqlx::query_scalar(
        "SELECT (properties->>'at_step')::bigint FROM edges WHERE id = $1::uuid",
    )
    .bind(first_text(&ok)["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("read at_step");
    assert_eq!(at_step, Some(0));

    let mut bad = link(w1, "workflow", w2, "workflow", "depends_on");
    bad.at_step = Some(0);
    let err = do_link_hierarchical(&server, &viewer, bad, None)
        .await
        .expect_err("at_step belongs to invokes only");
    assert!(err.message.contains("at_step"), "{}", err.message);
}

/// A server whose stdio agent is a DIFFERENT declared signer from
/// `build_scoped_test_server`'s, on the same database.
fn outsider_server(pool: PgPool, scoped: epigraph_db::ScopedPool) -> epigraph_mcp::EpiGraphMcpFull {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5C; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    epigraph_mcp::EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// A workflow SOURCE takes the `add_step` authority gate (backlog 03d87e3a:
/// "under the same authority checks"): another agent that is not the
/// workflow's submitter, its operator or delegate, nor a writer of its owner
/// group, cannot repair its `executes` edges or give it a prerequisite.
/// Refused with nothing written, while the submitter's own repair goes
/// through.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_submitter_cannot_write_a_workflow_sourced_reference(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = epigraph_mcp::tools::viewer::request_viewer(&outsider, None)
        .await
        .expect("outsider stdio viewer");
    let workflow = store(&server, &["gather inputs", "publish output"]).await;
    let other = store(&server, &["other step"]).await;
    let (dropped, step) = step_claim(&pool, workflow, "publish output").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop the executes edge");

    for (target, target_type, rel) in [
        (step, "claim", "executes"),
        (other, "workflow", "depends_on"),
    ] {
        let err = do_link_hierarchical(
            &outsider,
            &outsider_viewer,
            link(workflow, "workflow", target, target_type, rel),
            None,
        )
        .await
        .expect_err("a non-submitter is refused");
        assert!(
            err.message.contains("submitter"),
            "{rel}: refused by the workflow authority rule: {}",
            err.message
        );
        assert_eq!(
            in_force(&pool, workflow, target, rel).await,
            0,
            "{rel}: nothing written"
        );
    }

    do_link_hierarchical(
        &server,
        &viewer,
        link(workflow, "workflow", step, "claim", "executes"),
        None,
    )
    .await
    .expect("the submitter's own repair is admitted");
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 1);
}

/// The stdio server's own viewer: it reads the group rows its agent writes,
/// which `fixture::public_viewer` does not.
async fn own_viewer(server: &epigraph_mcp::EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer")
}

/// `epigraph_node_tenancy` treats a workflow endpoint as public, so a
/// `depends_on` or `invokes` touching a group-private workflow would be
/// stored as a PUBLIC edge naming that workflow to every reader. Both are
/// refused with nothing written, even for the workflow's own submitter, and
/// the private workflow stays unnamed by any edge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reference_to_a_group_private_workflow_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let public = store(&server, &["call the private workflow"]).await;
    let private = store(&server, &["private step"]).await;
    let (_, step) = step_claim(&pool, public, "call the private workflow").await;
    sqlx::query("UPDATE workflows SET visibility = 'group' WHERE id = $1")
        .bind(private)
        .execute(&pool)
        .await
        .expect("make the workflow group-private in its owner group");

    for (s, st, t, tt, rel) in [
        (public, "workflow", private, "workflow", "depends_on"),
        (private, "workflow", public, "workflow", "depends_on"),
        (public, "workflow", private, "workflow", "invokes"),
        (step, "claim", private, "workflow", "invokes"),
    ] {
        let err = do_link_hierarchical(&server, &viewer, link(s, st, t, tt, rel), None)
            .await
            .expect_err("a reference touching a group-private workflow is refused");
        assert!(
            err.message.contains("is not public"),
            "{rel} {st} -> {tt}: {}",
            err.message
        );
        assert_eq!(
            in_force(&pool, s, t, rel).await,
            0,
            "{rel}: nothing written"
        );
    }
    let naming: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE visibility = 'public' \
           AND relationship IN ('invokes', 'depends_on') \
           AND (source_id = $1 OR target_id = $1)",
    )
    .bind(private)
    .fetch_one(&pool)
    .await
    .expect("count public edges naming the private workflow");
    assert_eq!(naming, 0);
}

/// A step claim's `invokes` is its workflow's reference, so it takes the
/// authority gate over the workflow executing the step: an outsider cannot
/// attach a sub-workflow to someone else's public step (nor, through the
/// cycle guard, block the owner's own references), and a claim that no
/// workflow executes is not a step at all.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsider_cannot_invoke_from_another_agents_step_claim(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let w1 = store(&server, &["call a sub-workflow"]).await;
    let w2 = store(&server, &["sub step"]).await;
    let (_, s1) = step_claim(&pool, w1, "call a sub-workflow").await;

    let err = do_link_hierarchical(
        &outsider,
        &outsider_viewer,
        link(s1, "claim", w2, "workflow", "invokes"),
        None,
    )
    .await
    .expect_err("an outsider's invokes from another agent's step is refused");
    assert!(err.message.contains("submitter"), "{}", err.message);
    assert_eq!(in_force(&pool, s1, w2, "invokes").await, 0);

    let loose = seed_claim(&pool, "a claim no workflow executes", 0.5).await;
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(loose, "claim", w2, "workflow", "invokes"),
        None,
    )
    .await
    .expect_err("a claim that is not a step cannot invoke");
    assert!(err.message.contains("not a step"), "{}", err.message);
    assert_eq!(in_force(&pool, loose, w2, "invokes").await, 0);

    // The owner's references are not blocked: both directions of what the
    // outsider tried are still the owner's to choose.
    do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", w1, "workflow", "invokes"),
        None,
    )
    .await
    .expect("the submitter's own W2 invokes W1 is admitted");
}

/// `executes` is cycle-checked too (`W -executes-> S` where `S` already
/// invokes `W`), and is written from a lineage's head generation only, as
/// `add_step` writes it: an older generation's plan is frozen.
#[sqlx::test(migrations = "../../migrations")]
async fn executes_refuses_a_closing_cycle_and_a_non_head_generation(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["call w2"]).await;
    let w2 = store(&server, &["w2 step"]).await;
    let (_, s1) = step_claim(&pool, w1, "call w2").await;
    do_link_hierarchical(
        &server,
        &viewer,
        link(s1, "claim", w2, "workflow", "invokes"),
        None,
    )
    .await
    .expect("S1 invokes W2");
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", s1, "claim", "executes"),
        None,
    )
    .await
    .expect_err("W2 executes S1 closes S1 -invokes-> W2");
    assert!(
        err.message.contains("would close a cycle"),
        "{}",
        err.message
    );
    assert_eq!(in_force(&pool, w2, s1, "executes").await, 0);

    // Make W2 the next generation of W1's lineage: W1 is then frozen.
    sqlx::query(
        "UPDATE workflows SET canonical_name = w1.canonical_name, generation = w1.generation + 1 \
           FROM (SELECT canonical_name, generation FROM workflows WHERE id = $1) w1 \
          WHERE workflows.id = $2",
    )
    .bind(w1)
    .bind(w2)
    .execute(&pool)
    .await
    .expect("put W2 after W1 in one lineage");
    let (dropped, step) = step_claim(&pool, w1, "call w2").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop W1's executes edge");
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w1, "workflow", step, "claim", "executes"),
        None,
    )
    .await
    .expect_err("an older generation's plan is not extended");
    assert!(err.message.contains("head generation"), "{}", err.message);
    assert_eq!(in_force(&pool, w1, step, "executes").await, 0);
}

/// `executes` repairs or extends a plan with its OWN steps. A workflow owner
/// cannot adopt another agent's public claim as a step: that would make the
/// owner's workflow one of "the workflows executing this step", the set
/// `evolve_step` and a step-claim `invokes` take authority over, so the
/// claim's author could no longer evolve or reference their own claim
/// without the adopter. Refused, with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn executes_refuses_adopting_another_agents_claim(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let workflow = store(&server, &["own step"]).await;
    let foreign = seed_claim(&pool, "another agent's public claim", 0.5).await;

    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(workflow, "workflow", foreign, "claim", "executes"),
        None,
    )
    .await
    .expect_err("adopting another agent's claim as a step is refused");
    assert!(
        err.message
            .contains("not a step of this workflow's lineage"),
        "{}",
        err.message
    );
    assert_eq!(in_force(&pool, workflow, foreign, "executes").await, 0);
    let mut conn = pool.acquire().await.expect("conn");
    let executing =
        epigraph_db::WorkflowRepository::workflows_executing_step_lineage(&mut conn, foreign)
            .await
            .expect("executing set");
    assert!(executing.is_empty(), "the foreign claim gained no executor");
}

/// From a non-public workflow, the `executes` edge takes the claim's tenancy
/// (a workflow endpoint has none in the edges trigger), so a public target
/// would name the private plan in a public edge. Refused until the claim
/// carries the plan's own tenancy, then admitted, and the stored edge is no
/// wider than the plan.
#[sqlx::test(migrations = "../../migrations")]
async fn executes_from_a_private_workflow_needs_the_plans_tenancy(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let private = store(&server, &["private step"]).await;
    let other = store(&server, &["a public step of another plan"]).await;
    let (_, step) = step_claim(&pool, other, "a public step of another plan").await;
    let (plan_owner,): (Uuid,) = sqlx::query_as(
        "UPDATE workflows SET visibility = 'group' WHERE id = $1 RETURNING owner_group_id",
    )
    .bind(private)
    .fetch_one(&pool)
    .await
    .expect("make the workflow group-private in its owner group");

    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(private, "workflow", step, "claim", "executes"),
        None,
    )
    .await
    .expect_err("a private plan's executes to a public claim is refused");
    assert!(err.message.contains("is not public"), "{}", err.message);
    assert_eq!(in_force(&pool, private, step, "executes").await, 0);

    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(step)
        .bind(plan_owner)
        .execute(&pool)
        .await
        .expect("give the claim the plan's tenancy");
    do_link_hierarchical(
        &server,
        &viewer,
        link(private, "workflow", step, "claim", "executes"),
        None,
    )
    .await
    .expect("a claim with the plan's tenancy is admitted");
    let (vis, owner): (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes' \
            AND valid_to IS NULL",
    )
    .bind(private)
    .bind(step)
    .fetch_one(&pool)
    .await
    .expect("the edge");
    assert_eq!((vis.as_str(), owner), ("group", plan_owner));
}

/// The executes target of `workflow` at plan `level` (a thesis is level 0, a
/// phase level 1), as `(edge, claim)`.
async fn plan_claim_at_level(pool: &PgPool, workflow: Uuid, level: &str) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT e.id, c.id FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' \
           AND c.properties->>'level' = $2 AND e.valid_to IS NULL \
         ORDER BY c.id LIMIT 1",
    )
    .bind(workflow)
    .bind(level)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("a level-{level} executes target: {e}"))
}

/// Backlog 298317a7 (part 1): outside the plan's own lineage, `executes`
/// admits only a claim shaped as a workflow STEP (plan level 2, with a step
/// lineage), even one the caller wrote. Plan readers and the outcome reports
/// take every level-2 `executes` target as a step, and `evolve_step` and a
/// step-claim `invokes` gate on the workflows executing a step's lineage, so
/// an ordinary claim (or a level-2 document paragraph, which has no step
/// lineage) is not a step to adopt. Refused with nothing written.
///
/// CONTROLS: the caller's own step of another plan is still admitted, and the
/// in-lineage repair still restores a dropped edge to a NON-step plan claim
/// (the thesis and phases carry `executes` edges too).
#[sqlx::test(migrations = "../../migrations")]
async fn executes_refuses_an_own_claim_that_is_not_a_step(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let me = stdio_agent(&server).await;
    let workflow = store(&server, &["the plan's own step"]).await;

    let plain = fixture::seed_public_claim(&pool, me, "my own ordinary claim").await;
    let paragraph = fixture::seed_public_claim(&pool, me, "my own level-2 paragraph").await;
    sqlx::query("UPDATE claims SET properties = '{\"level\": 2}'::jsonb WHERE id = $1")
        .bind(paragraph)
        .execute(&pool)
        .await
        .expect("a level-2 claim with no step lineage");
    for (what, target) in [("an ordinary claim", plain), ("a level-2 paragraph", paragraph)] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(workflow, "workflow", target, "claim", "executes"),
            None,
        )
        .await
        .expect_err(&format!("{what} of the caller's is not a step to adopt"));
        assert!(
            err.message.contains("is not a workflow step"),
            "{what}: {}",
            err.message
        );
        assert_eq!(
            in_force(&pool, workflow, target, "executes").await,
            0,
            "{what}: nothing written"
        );
    }

    // CONTROL: the caller's own step of another of its plans is admitted.
    let other = store(&server, &["a step of my other plan"]).await;
    let (_, step) = step_claim(&pool, other, "a step of my other plan").await;
    do_link_hierarchical(
        &server,
        &viewer,
        link(workflow, "workflow", step, "claim", "executes"),
        None,
    )
    .await
    .expect("CONTROL: an own step of another plan is admitted");
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 1);

    // CONTROL: a dropped edge to the plan's own non-step claim is repaired.
    for level in ["0", "1"] {
        let (dropped, node) = plan_claim_at_level(&pool, workflow, level).await;
        sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
            .bind(dropped)
            .execute(&pool)
            .await
            .expect("drop the executes edge");
        do_link_hierarchical(
            &server,
            &viewer,
            link(workflow, "workflow", node, "claim", "executes"),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("CONTROL: the level-{level} edge is repaired: {e:?}"));
        assert_eq!(in_force(&pool, workflow, node, "executes").await, 1);
    }
}

/// `store_workflow` as an HTTP caller: the caller is the new lineage's
/// submitter, public in the caller's own group.
async fn store_as(
    server: &epigraph_mcp::EpiGraphMcpFull,
    auth: &epigraph_auth::AuthContext,
    steps: &[&str],
) -> Uuid {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, Some(auth))
        .await
        .expect("HTTP viewer");
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(public_tenancy_for(&viewer)),
            goal: format!("http workflow reference probe {}", Uuid::new_v4()),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
            force_new: None,
        },
        Some(auth),
    )
    .await
    .expect("store_workflow over HTTP");
    parse_uuid_field(&first_text(&stored), "workflow_id")
}

/// Backlog 298317a7 (part 2): the typed workflow references over the
/// AUTHENTICATED-HTTP path (an `AuthContext`, the caller's own viewer), where
/// the write identity and the workflow authority are the token's agent, not
/// this server's. The caller repairs its own plan's dropped `executes` edge
/// and gives its own workflow a prerequisite; the same caller is refused on a
/// workflow this server's agent submitted (as the source of `executes` and of
/// `depends_on`), with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_http_caller_writes_references_from_its_own_workflow_only(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, auth, _) = seed_caller(&pool, &["claims:write"]).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, Some(&auth))
        .await
        .expect("HTTP viewer");
    let mine = store_as(&server, &auth, &["my http step"]).await;
    let theirs = store(&server, &["the server's step"]).await;

    let (dropped, step) = step_claim(&pool, mine, "my http step").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop my executes edge");
    let repaired = do_link_hierarchical(
        &server,
        &viewer,
        link(mine, "workflow", step, "claim", "executes"),
        Some(&auth),
    )
    .await
    .expect("the submitter repairs its own plan over HTTP");
    assert_eq!(first_text(&repaired)["created"], serde_json::json!(true));
    assert_eq!(in_force(&pool, mine, step, "executes").await, 1);
    do_link_hierarchical(
        &server,
        &viewer,
        link(mine, "workflow", theirs, "workflow", "depends_on"),
        Some(&auth),
    )
    .await
    .expect("the submitter gives its own workflow a prerequisite over HTTP");
    assert_eq!(in_force(&pool, mine, theirs, "depends_on").await, 1);

    let (dropped, their_step) = step_claim(&pool, theirs, "the server's step").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop the server's executes edge");
    for (relationship, target, target_type) in [
        ("executes", their_step, "claim"),
        ("depends_on", mine, "workflow"),
    ] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(theirs, "workflow", target, target_type, relationship),
            Some(&auth),
        )
        .await
        .expect_err(&format!(
            "{relationship}: the HTTP caller has no authority over the server's workflow"
        ));
        assert!(
            err.message.contains(&format!("caller agent {caller}"))
                && err.message.contains("Nothing was written"),
            "{relationship}: the refusal names the HTTP caller: {}",
            err.message
        );
        assert_eq!(
            in_force(&pool, theirs, target, relationship).await,
            0,
            "{relationship}: nothing written"
        );
    }
}
