//! Workflow references, backlog 41d7b27a (the half after `invokes` and
//! `depends_on` landed).
//!
//! Before: `related_to` was no relationship any tool wrote, `link_alternative`
//! took claims only (its endpoint types were not caller-controllable), and
//! neither workflow reader (`find_workflow`, `find_workflow_hierarchical`)
//! surfaced any reference at all, so a caller could write `invokes` and
//! `depends_on` but never read them back from the tools named to find a
//! workflow. These drive the tools on the stdio path against workflows stored
//! through `store_workflow`, the rows a live plan reads.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_alternative::do_link_alternative;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{
    FindWorkflowHierarchicalParams, FindWorkflowParams, LinkAlternativeParams,
    LinkHierarchicalParams, StoreWorkflowParams,
};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn store(server: &epigraph_mcp::EpiGraphMcpFull, steps: &[&str]) -> Uuid {
    let viewer = own_viewer(server).await;
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(stdio_public_tenancy(server).await),
            goal: format!("workflow reference reader probe {}", Uuid::new_v4()),
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

async fn goal_of(pool: &PgPool, workflow: Uuid) -> String {
    sqlx::query_scalar("SELECT goal FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("the workflow's goal")
}

async fn step_claim(pool: &PgPool, workflow: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.content = $2 \
           AND e.valid_to IS NULL",
    )
    .bind(workflow)
    .bind(content)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("executes edge for {content:?}: {e}"))
}

/// In-force `relationship` edges between `a` and `b`, in EITHER direction.
async fn pair_edges(pool: &PgPool, a: Uuid, b: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
          WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
            AND relationship = $3 AND (valid_to IS NULL OR valid_to > now())",
    )
    .bind(a)
    .bind(b)
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

fn rivals(a: Uuid, b: Uuid) -> LinkAlternativeParams {
    LinkAlternativeParams {
        claim_a: a.to_string(),
        claim_b: b.to_string(),
        source_type: Some("workflow".to_string()),
        target_type: Some("workflow".to_string()),
        ..Default::default()
    }
}

/// A server whose stdio agent is a DIFFERENT declared signer from
/// `build_scoped_test_server`'s, on the same database.
fn outsider_server(pool: PgPool, scoped: epigraph_db::ScopedPool) -> epigraph_mcp::EpiGraphMcpFull {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5C; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    epigraph_mcp::EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// The stdio server's own viewer: it reads the group rows its agent writes.
async fn own_viewer(server: &epigraph_mcp::EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer")
}

async fn make_private(pool: &PgPool, workflow: Uuid) -> Uuid {
    sqlx::query_scalar(
        "UPDATE workflows SET visibility = 'group' WHERE id = $1 RETURNING owner_group_id",
    )
    .bind(workflow)
    .fetch_one(pool)
    .await
    .expect("make the workflow group-private in its owner group")
}

/// `related_to` is a loose, symmetric see-also between two workflows: one
/// edge per unordered pair, so naming the pair the other way round returns
/// the same edge. It links workflows only, refuses a group-private workflow
/// (it would be stored public), and takes the workflow-source authority gate.
#[sqlx::test(migrations = "../../migrations")]
async fn related_to_is_one_symmetric_reference_between_public_workflows(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["w1 step"]).await;
    let w2 = store(&server, &["w2 step"]).await;

    let first = do_link_hierarchical(
        &server,
        &viewer,
        link(w1, "workflow", w2, "workflow", "related_to"),
        None,
    )
    .await
    .expect("W1 related_to W2 is written");
    let first = first_text(&first);
    assert_eq!(first["created"], Value::Bool(true), "{first}");
    let again = do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", w1, "workflow", "related_to"),
        None,
    )
    .await
    .expect("W2 related_to W1 is the same reference");
    let again = first_text(&again);
    assert_eq!(again["created"], Value::Bool(false), "{again}");
    assert_eq!(again["edge_id"], first["edge_id"], "one edge per pair");
    assert_eq!(pair_edges(&pool, w1, w2, "related_to").await, 1);
    // Migration 353 backs the dedup: a second in-force row for the pair (what
    // two concurrent writers past the in-statement guard would insert) is
    // refused by the unique index, in either order.
    let dup = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'workflow', 'related_to')",
    )
    .bind(w2)
    .bind(w1)
    .execute(&pool)
    .await
    .expect_err("a second related_to for the pair violates the symmetric index");
    assert!(
        dup.to_string().contains("edges_related_to_symmetric_uniq"),
        "{dup}"
    );
    let types: (String, String) = sqlx::query_as(
        "SELECT source_type::text, target_type::text FROM edges WHERE id = $1::uuid",
    )
    .bind(first["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the edge");
    assert_eq!(
        (types.0.as_str(), types.1.as_str()),
        ("workflow", "workflow")
    );

    // Claims are not linked by it.
    let a = seed_claim(&pool, "related a", 0.5).await;
    let b = seed_claim(&pool, "related b", 0.5).await;
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "claim", b, "claim", "related_to"),
        None,
    )
    .await
    .expect_err("related_to between claims is refused");
    assert!(
        err.message.contains("does not link claim -> claim"),
        "{}",
        err.message
    );
    assert_eq!(pair_edges(&pool, a, b, "related_to").await, 0);

    // A group-private workflow, either end.
    let private = store(&server, &["private step"]).await;
    make_private(&pool, private).await;
    for (s, t) in [(w1, private), (private, w1)] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "related_to"),
            None,
        )
        .await
        .expect_err("a related_to touching a private workflow is refused");
        assert!(err.message.contains("is not public"), "{}", err.message);
    }
    assert_eq!(pair_edges(&pool, w1, private, "related_to").await, 0);

    // Another agent with no authority over the source workflow.
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let w3 = store(&server, &["w3 step"]).await;
    let err = do_link_hierarchical(
        &outsider,
        &outsider_viewer,
        link(w3, "workflow", w1, "workflow", "related_to"),
        None,
    )
    .await
    .expect_err("an outsider cannot attach a see-also to another agent's workflow");
    assert!(err.message.contains("submitter"), "{}", err.message);
    assert_eq!(pair_edges(&pool, w3, w1, "related_to").await, 0);
}

/// Two rival workflows reaching the same goal are an `alternative_of` pair,
/// written by `link_alternative` with both endpoint types `workflow`: one edge
/// per unordered pair, typed workflow -> workflow. A mixed pair, a private
/// workflow and a caller without authority over `claim_a`'s workflow are each
/// refused with nothing written; the claim pair (the default) is unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn link_alternative_marks_two_rival_workflows(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["route one"]).await;
    let w2 = store(&server, &["route two"]).await;

    let first = do_link_alternative(&server, &viewer, rivals(w1, w2), None)
        .await
        .expect("two rival workflows are linked");
    let first = first_text(&first);
    assert_eq!(first["created"], Value::Bool(true), "{first}");
    let again = do_link_alternative(&server, &viewer, rivals(w2, w1), None)
        .await
        .expect("the reverse order is the same pair");
    let again = first_text(&again);
    assert_eq!(again["created"], Value::Bool(false), "{again}");
    assert_eq!(again["edge_id"], first["edge_id"]);
    assert_eq!(pair_edges(&pool, w1, w2, "alternative_of").await, 1);
    let types: (String, String) = sqlx::query_as(
        "SELECT source_type::text, target_type::text FROM edges WHERE id = $1::uuid",
    )
    .bind(first["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the edge");
    assert_eq!(
        (types.0.as_str(), types.1.as_str()),
        ("workflow", "workflow")
    );

    // A mixed pair.
    let claim = seed_claim(&pool, "a claim, not a workflow", 0.5).await;
    let mut mixed = rivals(w1, claim);
    mixed.target_type = Some("claim".to_string());
    let err = do_link_alternative(&server, &viewer, mixed, None)
        .await
        .expect_err("a workflow and a claim are no alternative pair");
    assert!(
        err.message.contains("workflow <-> workflow"),
        "{}",
        err.message
    );
    assert_eq!(pair_edges(&pool, w1, claim, "alternative_of").await, 0);

    // A workflow id that names no workflow (a claim's id) is not found.
    let err = do_link_alternative(&server, &viewer, rivals(w1, claim), None)
        .await
        .expect_err("a claim id is no workflow");
    assert!(err.message.contains("not found"), "{}", err.message);

    // A group-private workflow, either end.
    let private = store(&server, &["private route"]).await;
    make_private(&pool, private).await;
    for (a, b) in [(w1, private), (private, w1)] {
        let err = do_link_alternative(&server, &viewer, rivals(a, b), None)
            .await
            .expect_err("an alternative touching a private workflow is refused");
        assert!(err.message.contains("is not public"), "{}", err.message);
    }
    assert_eq!(pair_edges(&pool, w1, private, "alternative_of").await, 0);

    // Another agent with no authority over claim_a's workflow.
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let w3 = store(&server, &["route three"]).await;
    let err = do_link_alternative(&outsider, &outsider_viewer, rivals(w3, w1), None)
        .await
        .expect_err("an outsider cannot mark another agent's workflow as a rival");
    assert!(err.message.contains("submitter"), "{}", err.message);
    assert_eq!(pair_edges(&pool, w3, w1, "alternative_of").await, 0);

    // The default claim pair still works.
    let c1 = seed_claim(&pool, "rival claim one", 0.5).await;
    let c2 = seed_claim(&pool, "rival claim two", 0.5).await;
    do_link_alternative(
        &server,
        &viewer,
        LinkAlternativeParams {
            claim_a: c1.to_string(),
            claim_b: c2.to_string(),
            ..Default::default()
        },
        None,
    )
    .await
    .expect("a claim pair is linked as before");
    assert_eq!(pair_edges(&pool, c1, c2, "alternative_of").await, 1);
}

async fn find_hierarchical(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    query: &str,
) -> Value {
    let out = epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical(
        server,
        viewer,
        FindWorkflowHierarchicalParams {
            query: query.to_string(),
            limit: None,
            resolve_to_latest: None,
            min_truth: None,
        },
    )
    .await
    .expect("find_workflow_hierarchical");
    first_text(&out)
}

async fn find_flat_and_hierarchical(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    goal: &str,
) -> Value {
    // No embedder in tests: the text legs of both stores answer.
    let out = epigraph_mcp::tools::workflows::__test_only::find_workflow_with_pgvec(
        server,
        viewer,
        FindWorkflowParams {
            goal: goal.to_string(),
            min_truth: None,
            limit: None,
        },
        None,
    )
    .await
    .expect("find_workflow");
    first_text(&out)
}

/// The `references` of `workflow` in a reader's answer: `find_workflow`
/// returns an array of results, `find_workflow_hierarchical` an object with a
/// `workflows` array.
fn references_of(answer: &Value, workflow: Uuid) -> Vec<Value> {
    let rows = answer
        .get("workflows")
        .unwrap_or(answer)
        .as_array()
        .unwrap_or_else(|| panic!("no result list in {answer}"));
    let row = rows
        .iter()
        .find(|r| r["workflow_id"].as_str() == Some(workflow.to_string().as_str()))
        .unwrap_or_else(|| panic!("{workflow} is not in {answer}"));
    row["references"]
        .as_array()
        .unwrap_or_else(|| panic!("no references on {row}"))
        .clone()
}

/// `(relationship, direction, other workflow, via step, at_step)`.
type RefShape = (String, String, String, Option<String>, Option<i64>);

/// Each reference's [`RefShape`], sorted.
fn shape(refs: &[Value]) -> Vec<RefShape> {
    let mut out: Vec<_> = refs
        .iter()
        .map(|r| {
            (
                r["relationship"].as_str().unwrap_or_default().to_string(),
                r["direction"].as_str().unwrap_or_default().to_string(),
                r["workflow_id"].as_str().unwrap_or_default().to_string(),
                r["via_step_claim_id"].as_str().map(String::from),
                r["at_step"].as_i64(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Both workflow readers list every reference kind touching a workflow: its
/// own `invokes` (with `at_step`), a step's `invokes` (with the step claim),
/// `depends_on`, the symmetric `related_to` and `alternative_of` (`mutual`,
/// seen from either end), and another workflow's step invoking it
/// (`incoming`). A retracted reference is not listed.
#[sqlx::test(migrations = "../../migrations")]
async fn both_workflow_readers_surface_every_reference_kind(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let hub = store(&server, &["call the sub-workflow", "finish"]).await;
    let sub = store(&server, &["sub step"]).await;
    let prereq = store(&server, &["prerequisite step"]).await;
    let see_also = store(&server, &["see-also step"]).await;
    let rival = store(&server, &["rival step"]).await;
    let caller = store(&server, &["call the hub"]).await;
    let dropped = store(&server, &["dropped step"]).await;
    let hub_step = step_claim(&pool, hub, "call the sub-workflow").await;
    let caller_step = step_claim(&pool, caller, "call the hub").await;

    let mut direct = link(hub, "workflow", sub, "workflow", "invokes");
    direct.at_step = Some(1);
    for params in [
        direct,
        link(hub_step, "claim", sub, "workflow", "invokes"),
        link(hub, "workflow", prereq, "workflow", "depends_on"),
        link(see_also, "workflow", hub, "workflow", "related_to"),
        link(caller_step, "claim", hub, "workflow", "invokes"),
        link(hub, "workflow", dropped, "workflow", "depends_on"),
    ] {
        do_link_hierarchical(&server, &viewer, params, None)
            .await
            .expect("the reference is written");
    }
    do_link_alternative(&server, &viewer, rivals(rival, hub), None)
        .await
        .expect("the rival is linked");
    sqlx::query(
        "UPDATE edges SET valid_to = now() WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'depends_on'",
    )
    .bind(hub)
    .bind(dropped)
    .execute(&pool)
    .await
    .expect("retract one reference");

    let s = |u: Uuid| u.to_string();
    let expected = {
        let mut v = vec![
            (
                "alternative_of".into(),
                "mutual".into(),
                s(rival),
                None,
                None,
            ),
            (
                "depends_on".into(),
                "outgoing".into(),
                s(prereq),
                None,
                None,
            ),
            (
                "invokes".into(),
                "incoming".into(),
                s(caller),
                Some(s(caller_step)),
                None,
            ),
            ("invokes".into(), "outgoing".into(), s(sub), None, Some(1)),
            (
                "invokes".into(),
                "outgoing".into(),
                s(sub),
                Some(s(hub_step)),
                None,
            ),
            (
                "related_to".into(),
                "mutual".into(),
                s(see_also),
                None,
                None,
            ),
        ];
        v.sort();
        v
    };

    let hub_goal = goal_of(&pool, hub).await;
    let hierarchical = find_hierarchical(&server, &viewer, &hub_goal).await;
    assert_eq!(
        shape(&references_of(&hierarchical, hub)),
        expected,
        "find_workflow_hierarchical: {hierarchical}"
    );
    let flat = find_flat_and_hierarchical(&server, &viewer, &hub_goal).await;
    assert_eq!(
        shape(&references_of(&flat, hub)),
        expected,
        "find_workflow: {flat}"
    );

    // The other end of a reference sees it too, from its side.
    let sub_goal = goal_of(&pool, sub).await;
    let sub_refs = shape(&references_of(
        &find_hierarchical(&server, &viewer, &sub_goal).await,
        sub,
    ));
    assert_eq!(
        sub_refs,
        {
            let mut v = vec![
                (
                    "invokes".to_string(),
                    "incoming".to_string(),
                    s(hub),
                    None,
                    Some(1),
                ),
                (
                    "invokes".to_string(),
                    "incoming".to_string(),
                    s(hub),
                    Some(s(hub_step)),
                    None,
                ),
            ];
            v.sort();
            v
        },
        "the sub-workflow lists who invokes it"
    );
    let see_also_goal = goal_of(&pool, see_also).await;
    assert_eq!(
        shape(&references_of(
            &find_flat_and_hierarchical(&server, &viewer, &see_also_goal).await,
            see_also,
        )),
        vec![(
            "related_to".to_string(),
            "mutual".to_string(),
            s(hub),
            None,
            None
        )],
    );
    // A workflow with no reference lists none, rather than omitting the key.
    let dropped_goal = goal_of(&pool, dropped).await;
    assert!(references_of(
        &find_hierarchical(&server, &viewer, &dropped_goal).await,
        dropped
    )
    .is_empty());
}

/// A group-private plan's group-private step may invoke a public workflow
/// (only workflow ends must be public; the edge takes the step's tenancy).
/// The public workflow's readers name that caller to a member of the group,
/// and to nobody else: an outsider finds the public workflow with no
/// reference at all, neither the private plan nor its step.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_steps_reference_is_named_to_members_only(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let plan = store(&server, &["private call"]).await;
    let public = store(&server, &["public sub step"]).await;
    let step = step_claim(&pool, plan, "private call").await;
    let group = make_private(&pool, plan).await;
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(step)
        .bind(group)
        .execute(&pool)
        .await
        .expect("give the step the plan's tenancy");

    let written = do_link_hierarchical(
        &server,
        &viewer,
        link(step, "claim", public, "workflow", "invokes"),
        None,
    )
    .await
    .expect("a private step invokes a public workflow");
    let (vis,): (String,) =
        sqlx::query_as("SELECT visibility::text FROM edges WHERE id = $1::uuid")
            .bind(first_text(&written)["edge_id"].as_str().expect("edge_id"))
            .fetch_one(&pool)
            .await
            .expect("the edge");
    assert_eq!(vis, "group", "the edge takes the step's tenancy");

    let goal = goal_of(&pool, public).await;
    let member_view = vec![(
        "invokes".to_string(),
        "incoming".to_string(),
        plan.to_string(),
        Some(step.to_string()),
        None,
    )];
    assert_eq!(
        shape(&references_of(
            &find_hierarchical(&server, &viewer, &goal).await,
            public
        )),
        member_view
    );
    assert_eq!(
        shape(&references_of(
            &find_flat_and_hierarchical(&server, &viewer, &goal).await,
            public
        )),
        member_view
    );

    let outsider_hier = find_hierarchical(&outsider, &outsider_viewer, &goal).await;
    assert!(
        references_of(&outsider_hier, public).is_empty(),
        "an outsider is named nothing: {outsider_hier}"
    );
    let outsider_flat = find_flat_and_hierarchical(&outsider, &outsider_viewer, &goal).await;
    assert!(
        references_of(&outsider_flat, public).is_empty(),
        "an outsider is named nothing: {outsider_flat}"
    );
    for answer in [&outsider_hier, &outsider_flat] {
        let text = answer.to_string();
        assert!(!text.contains(&plan.to_string()), "{text}");
        assert!(!text.contains(&step.to_string()), "{text}");
    }
}

/// A symmetric reference is a statement about BOTH workflows (each reader
/// lists it as `mutual`), so `related_to` and a rival `alternative_of` need
/// authority over both ends. An agent may link two of its own workflows, but
/// it may not pin its workflow onto another agent's as a see-also or a
/// rival, in either order and from either side, which would otherwise show
/// its text on every search for the other workflow with no way for that
/// workflow's owner to retract it. A directional `depends_on` onto another
/// agent's public workflow is unchanged: it is the declaring workflow's own
/// statement, listed as `incoming` on the other end.
#[sqlx::test(migrations = "../../migrations")]
async fn a_symmetric_reference_needs_authority_over_both_workflows(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let theirs = store(&server, &["their step"]).await;
    let mine = store(&outsider, &["my step"]).await;
    let mine_too = store(&outsider, &["my other step"]).await;

    // Control: the outsider links two of its own workflows.
    do_link_hierarchical(
        &outsider,
        &outsider_viewer,
        link(mine, "workflow", mine_too, "workflow", "related_to"),
        None,
    )
    .await
    .expect("an agent links two of its own workflows as a see-also");
    do_link_alternative(&outsider, &outsider_viewer, rivals(mine, mine_too), None)
        .await
        .expect("an agent marks two of its own workflows as rivals");

    // Neither agent pins a see-also across owners, in either order.
    for (who, who_viewer, s, t) in [
        (&outsider, &outsider_viewer, mine, theirs),
        (&outsider, &outsider_viewer, theirs, mine),
        (&server, &viewer, theirs, mine),
        (&server, &viewer, mine, theirs),
    ] {
        let err = do_link_hierarchical(
            who,
            who_viewer,
            link(s, "workflow", t, "workflow", "related_to"),
            None,
        )
        .await
        .expect_err("a see-also onto another agent's workflow is refused");
        assert!(err.message.contains("submitter"), "{}", err.message);
        let err = do_link_alternative(who, who_viewer, rivals(s, t), None)
            .await
            .expect_err("a rival onto another agent's workflow is refused");
        assert!(err.message.contains("submitter"), "{}", err.message);
    }
    assert_eq!(pair_edges(&pool, mine, theirs, "related_to").await, 0);
    assert_eq!(pair_edges(&pool, mine, theirs, "alternative_of").await, 0);

    // A directional prerequisite onto another agent's public workflow stays
    // the declaring workflow's own statement.
    do_link_hierarchical(
        &outsider,
        &outsider_viewer,
        link(mine, "workflow", theirs, "workflow", "depends_on"),
        None,
    )
    .await
    .expect("a workflow may declare another agent's public workflow a prerequisite");
}

/// A rival pair of workflows is stored public, so a `target_claim_id` it
/// carries must be a public claim: a group-private claim id is refused with
/// nothing written, a public one is kept.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rival_workflow_pair_names_only_a_public_target_claim(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["rival goal one"]).await;
    let w2 = store(&server, &["rival goal two"]).await;
    let scratch = store(&server, &["scratch step"]).await;
    let group = make_private(&pool, scratch).await;
    let private_claim = seed_claim(&pool, "a private target", 0.5).await;
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(private_claim)
        .bind(group)
        .execute(&pool)
        .await
        .expect("make the claim group-private in the caller's group");

    let mut params = rivals(w1, w2);
    params.target_claim_id = Some(private_claim.to_string());
    let err = do_link_alternative(&server, &viewer, params, None)
        .await
        .expect_err("a public rival pair does not carry a private claim id");
    assert!(err.message.contains("is not public"), "{}", err.message);
    assert_eq!(pair_edges(&pool, w1, w2, "alternative_of").await, 0);

    let public_claim = seed_claim(&pool, "a public target", 0.5).await;
    let mut params = rivals(w1, w2);
    params.target_claim_id = Some(public_claim.to_string());
    let written = do_link_alternative(&server, &viewer, params, None)
        .await
        .expect("a public target claim is kept");
    let (target,): (Option<String>,) =
        sqlx::query_as("SELECT properties->>'target_claim_id' FROM edges WHERE id = $1::uuid")
            .bind(first_text(&written)["edge_id"].as_str().expect("edge_id"))
            .fetch_one(&pool)
            .await
            .expect("the edge");
    assert_eq!(target, Some(public_claim.to_string()));
}
