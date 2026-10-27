use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_flips_parent(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent step", 0.7).await;
    let res = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "child",
        "supersedes",
        Some("better"),
        2,
        agent,
    )
    .await
    .unwrap();

    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!parent_current);

    let (child_lineage, child_props): (Option<Uuid>, serde_json::Value) =
        sqlx::query_as("SELECT step_lineage_id, properties FROM claims WHERE id = $1")
            .bind(res.new_claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(child_lineage, Some(res.step_lineage_id));
    assert_eq!(child_props["level"].as_i64(), Some(2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_keeps_parent_current(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "branch",
        "revises",
        None,
        2,
        agent,
    )
    .await
    .unwrap();
    let (parent_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(parent_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_bad_edge_type(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    let err = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "x",
        "merges",
        None,
        2,
        agent,
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("supersedes"), "{err:?}");
}

/// evolve_step with edge_type='supersedes' must null the parent's embedding so
/// the retired step drops out of semantic search.  Regression test for the
/// is_current=false → embedding=NULL invariant.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_nulls_parent_embedding(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent step", 0.7).await;

    // Plant a stub vector in BOTH ANN columns on the parent before superseding
    // it: `chk_deprecated_no_embedding` (migration 144) covers both, and recall
    // at centroid_dim=3072 reads `embedding_3072` with no is_current filter.
    let stub = |dim: usize| {
        let mut v = vec!["0.0"; dim];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    sqlx::query(
        "UPDATE claims SET embedding = $1::vector, embedding_3072 = $2::vector WHERE id = $3",
    )
    .bind(stub(1536))
    .bind(stub(3072))
    .bind(parent)
    .execute(&pool)
    .await
    .unwrap();

    ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "child step",
        "supersedes",
        Some("better version"),
        2,
        agent,
    )
    .await
    .unwrap();

    let (parent_has_embedding, parent_has_embedding_3072): (bool, bool) = sqlx::query_as(
        "SELECT embedding IS NOT NULL, embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(parent)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        !parent_has_embedding,
        "parent {parent} embedding must be NULL after evolve_step(supersedes)"
    );
    assert!(
        !parent_has_embedding_3072,
        "parent {parent} embedding_3072 must be NULL after evolve_step(supersedes)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_rejects_non_current_parent(pool: PgPool) {
    // Build agent + v1 step using existing seed helpers.
    let agent_id = seed_agent(&pool).await;
    let v1 = seed_claim(&pool, agent_id, "v1 content", 0.7).await;

    // First supersedes succeeds, flips v1.is_current = false.
    ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(v1),
        "v2 content",
        "supersedes",
        Some("first"),
        2,
        agent_id,
    )
    .await
    .expect("first supersedes");

    // Second supersedes against the same now-non-current v1 must error.
    // Note: 'revises' against a non-current parent is allowed by design — only
    // 'supersedes' is forbidden to prevent forking the lineage chain.
    let err = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(v1),
        "v2 fork",
        "supersedes",
        Some("attempted fork"),
        2,
        agent_id,
    )
    .await
    .expect_err("second supersedes against non-current parent must error");

    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-current step") || msg.contains("cannot supersede"),
        "expected non-current-step error message, got: {msg}"
    );
}

/// An evolve(supersedes) whose retirement of the predecessor the database
/// refuses must be refused with nothing written, leaving the lineage with
/// exactly one current head (backlog d34f5096).
///
/// An UPDATE that changes no row does not raise: it reports success. Before
/// the fix `evolve_step_conn` ignored the retire's row count, so it inserted
/// the successor next to a predecessor that was still current: two live heads
/// on a lineage that `supersedes` keeps linear. A `BEFORE UPDATE` trigger that
/// skips only the predecessor's `is_current` change produces that zero-row
/// retire deterministically (it would let the lineage back-fill, which leaves
/// `is_current` alone, through), named to fire before every other `BEFORE
/// UPDATE` trigger on `claims`. The claims tenancy policy refuses an
/// unwritable parent by raising at its WITH CHECK instead (pinned in
/// `epigraph-api/tests/evolve_step_not_visible_404.rs`), so the check is
/// defensive against any zero-row retire. The
/// caller's transaction is committed whatever the call left on it, so the
/// assertions see what a caller that ignored the error would have persisted.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_refuses_when_the_predecessor_cannot_be_retired(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "predecessor that cannot be retired", 0.7).await;
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION aaa_test_skip_step_retire() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RETURN NULL; END $$; \
         CREATE TRIGGER aaa_test_skip_step_retire BEFORE UPDATE ON claims FOR EACH ROW \
         WHEN (OLD.id = '{parent}'::uuid AND NEW.is_current IS DISTINCT FROM OLD.is_current) \
         EXECUTE FUNCTION aaa_test_skip_step_retire();"
    ))
    .execute(&pool)
    .await
    .expect("install the retirement stand-in");

    let mut tx = pool.begin().await.unwrap();
    let r = ClaimRepository::evolve_step_conn(
        &mut tx,
        ClaimId::from_uuid(parent),
        "successor of an unretirable step",
        "supersedes",
        Some("unretirable"),
        2,
        agent,
    )
    .await;
    tx.commit().await.expect("commit");

    // The lineage's current heads, counted without its lineage id (the
    // refusal must leave the parent without one): the parent itself plus
    // anything written as its successor, by column or by edge. Checked before
    // the error, so the item's headline fails first when the retire is
    // ignored.
    let heads: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims \
         WHERE (id = $1 OR supersedes = $1 \
                OR id IN (SELECT source_id FROM edges WHERE target_id = $1)) \
           AND COALESCE(is_current, true)",
    )
    .bind(parent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(heads, 1, "the lineage keeps exactly one current head");
    let successors: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(successors, 0, "no successor row was inserted");
    let edges: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE target_id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(edges, 0, "no supersedes edge was inserted");

    let err = r.expect_err("a step whose predecessor this session cannot retire must not evolve");
    assert!(
        matches!(&err, epigraph_db::DbError::WriteRefused { id, .. } if *id == parent),
        "a readable, current predecessor the session cannot retire is WriteRefused; got: {err:?}"
    );
    let (still_current, lineage): (bool, Option<Uuid>) =
        sqlx::query_as("SELECT is_current, step_lineage_id FROM claims WHERE id = $1")
            .bind(parent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(still_current, "the predecessor is untouched");
    assert_eq!(
        lineage, None,
        "the refusal wrote nothing, not even the lineage back-fill"
    );
}

// ── evolve_step(supersedes) and the supersede edge cascade (backlog 8d3b4527) ──
//
// evolve_step(supersedes) retires a step and writes its successor, but the
// retired step kept every structural edge: on prod the live head of workflow
// f00fa5e9's D3 step held one edge (`supersedes`) while its decomposition
// parent, its children and its `continues_argument` predecessor all still
// pointed at the retired version. The fix records the supersession in
// `claims.supersedes`, so the Supersede admin cascade
// (`migrate_superseded_edges_conn`, and its deferred replay) accepts the pair,
// and that migration leaves a step lineage's `executes` edge (the workflow's
// frozen step) and its agents' `asserts` / `AUTHORED` edges where they are.

#[path = "viewer_fixture.rs"]
mod fixture;

async fn seed_workflow(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) VALUES ($1, $2, 'evolve-step test')",
    )
    .bind(id)
    .bind(format!("evolve-step-{id}"))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_typed_edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
    id
}

/// `(source_id, target_id)` of edge `id`.
async fn ends(pool: &PgPool, id: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The Supersede admin cascade's edge migration, on the maintenance role (the
/// connection `epigraph_engine::admin_cascade` and the deferred replay run it on).
async fn migrate_as_maintenance(
    pool: &PgPool,
    old: Uuid,
    new: Uuid,
) -> Result<epigraph_db::SupersedeEdgeMigration, epigraph_db::DbError> {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, new).await;
        (conn, r)
    })
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_cascade_carries_structural_edges_but_not_executes(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let other_agent = seed_agent(&pool).await;
    let step = seed_claim(&pool, agent, "D3: measure the yield", 0.7).await;
    let parent = seed_claim(&pool, agent, "the D-arm of the plan", 0.7).await;
    let child1 = seed_claim(&pool, agent, "D3.1 prepare", 0.7).await;
    let child2 = seed_claim(&pool, agent, "D3.2 run", 0.7).await;
    let prior = seed_claim(&pool, agent, "the preceding paragraph", 0.7).await;
    let supporter = seed_claim(&pool, agent, "a supporting observation", 0.7).await;
    let refuter = seed_claim(&pool, agent, "a refuting observation", 0.7).await;
    let workflow = seed_workflow(&pool).await;

    let decomposed_from =
        seed_typed_edge(&pool, parent, "claim", step, "claim", "decomposes_to").await;
    let to_child1 = seed_typed_edge(&pool, step, "claim", child1, "claim", "decomposes_to").await;
    let to_child2 = seed_typed_edge(&pool, step, "claim", child2, "claim", "decomposes_to").await;
    let continued =
        seed_typed_edge(&pool, prior, "claim", step, "claim", "continues_argument").await;
    let supported = seed_typed_edge(&pool, supporter, "claim", step, "claim", "supports").await;
    let refuted = seed_typed_edge(&pool, refuter, "claim", step, "claim", "refutes").await;
    let executes = seed_typed_edge(&pool, workflow, "workflow", step, "claim", "executes").await;
    let asserted = seed_typed_edge(&pool, other_agent, "agent", step, "claim", "asserts").await;
    let authored = seed_typed_edge(&pool, other_agent, "agent", step, "claim", "AUTHORED").await;
    // A NON-agent `asserts` (a claim or paper asserting the step, the shape
    // migration 041 reads) is not authorship by an agent: it follows the head.
    let asserter = seed_claim(&pool, agent, "a claim that asserts the step", 0.7).await;
    let claim_asserted = seed_typed_edge(&pool, asserter, "claim", step, "claim", "asserts").await;

    let evolved = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(step),
        "D3: measure the yield, in triplicate",
        "supersedes",
        Some("tighter protocol"),
        2,
        agent,
    )
    .await
    .expect("evolve_step(supersedes)");
    let head = evolved.new_claim_id;

    migrate_as_maintenance(&pool, step, head)
        .await
        .expect("the Supersede cascade must accept an evolve_step(supersedes) pair");

    // Structural and strengthening edges follow the live head.
    assert_eq!(
        ends(&pool, decomposed_from).await,
        (parent, head),
        "parent -decomposes_to-> head"
    );
    assert_eq!(
        ends(&pool, to_child1).await,
        (head, child1),
        "head -decomposes_to-> child1"
    );
    assert_eq!(
        ends(&pool, to_child2).await,
        (head, child2),
        "head -decomposes_to-> child2"
    );
    assert_eq!(
        ends(&pool, continued).await,
        (prior, head),
        "prior -continues_argument-> head"
    );
    assert_eq!(
        ends(&pool, supported).await,
        (supporter, head),
        "supporter -supports-> head"
    );
    // The workflow's `executes` edge stays on the frozen original step: heads
    // are resolved through the lineage (WorkflowRepository::ResolvedStep).
    assert_eq!(
        ends(&pool, executes).await,
        (workflow, step),
        "executes stays on the frozen step"
    );
    // Weakening edges stay on the content they were filed against (#398).
    assert_eq!(ends(&pool, refuted).await, (refuter, step), "refutes stays");
    // The successor is written by evolve_step's CALLER, so another agent's
    // assertion of the old content does not become an assertion of the new.
    assert_eq!(
        ends(&pool, asserted).await,
        (other_agent, step),
        "agent asserts stays"
    );
    assert_eq!(
        ends(&pool, authored).await,
        (other_agent, step),
        "agent AUTHORED stays"
    );
    assert_eq!(
        ends(&pool, claim_asserted).await,
        (asserter, head),
        "a non-agent asserts follows the head (the carve-out is agents' only)"
    );
}

/// The carve-out is a STEP-LINEAGE rule, derived from the rows: a plain
/// supersede of a claim that happens to carry a `step_lineage_id` writes a
/// successor outside that lineage, so its `executes` and agent edges move as
/// every supersession's do.
#[sqlx::test(migrations = "../../migrations")]
async fn plain_supersede_of_a_lineage_step_still_moves_executes_and_asserts(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let other_agent = seed_agent(&pool).await;
    let step = seed_claim(&pool, agent, "a step with a lineage", 0.7).await;
    sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
        .bind(Uuid::new_v4())
        .bind(step)
        .execute(&pool)
        .await
        .unwrap();
    let workflow = seed_workflow(&pool).await;
    let executes = seed_typed_edge(&pool, workflow, "workflow", step, "claim", "executes").await;
    let asserted = seed_typed_edge(&pool, other_agent, "agent", step, "claim", "asserts").await;

    let mut tx = pool.begin().await.unwrap();
    let (new_id, _) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(step),
        "a plain restatement",
        epigraph_core::TruthValue::clamped(0.6),
        "restated",
        epigraph_db::SupersedeActor::new(agent, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede act");
    tx.commit().await.unwrap();

    migrate_as_maintenance(&pool, step, new_id)
        .await
        .expect("the Supersede cascade");
    assert_eq!(
        ends(&pool, executes).await,
        (workflow, new_id),
        "executes follows a plain supersede"
    );
    assert_eq!(
        ends(&pool, asserted).await,
        (other_agent, new_id),
        "asserts follows a plain supersede"
    );
}

/// `revises` is a parallel branch: both heads stay current and nothing is
/// superseded, so the column stays NULL and the cascade refuses the pair.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_records_no_supersession(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    let r = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "branch",
        "revises",
        None,
        2,
        agent,
    )
    .await
    .unwrap();
    let sup: Option<Uuid> = sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
        .bind(r.new_claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sup, None, "a revises branch records no supersession");
    let e = migrate_as_maintenance(&pool, parent, r.new_claim_id)
        .await
        .expect_err("a revises branch is not a supersession to migrate");
    assert!(e.to_string().contains("does not supersede"), "{e}");
}

/// `revises` is lineage-internal history, like `supersedes`: `R -revises-> S`
/// records that R branched from S. A later step-lineage supersession of
/// EITHER end must leave it where it is. Carried onto S's successor it would
/// say R branched from a version that did not exist when R was written; carried
/// onto R's successor it would say that successor branched from S directly.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_cascade_leaves_revises_history_in_place(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s = seed_claim(&pool, agent, "S: the original step", 0.7).await;

    // R branches from S; both stay current.
    let branch = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(s),
        "R: a concurrent branch of S",
        "revises",
        None,
        2,
        agent,
    )
    .await
    .expect("evolve_step(revises)");
    let r = branch.new_claim_id;
    let revises_edge = branch.edge_id;
    assert_eq!(
        ends(&pool, revises_edge).await,
        (r, s),
        "seeded R -revises-> S"
    );

    // Incoming side: S is superseded by N within the lineage.
    let n = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(s),
        "N: S, refined",
        "supersedes",
        None,
        2,
        agent,
    )
    .await
    .expect("evolve_step(S, supersedes)")
    .new_claim_id;
    migrate_as_maintenance(&pool, s, n)
        .await
        .expect("the Supersede cascade for (S, N)");
    assert_eq!(
        ends(&pool, revises_edge).await,
        (r, s),
        "R -revises-> S stays on S when S is superseded (incoming)"
    );

    // Outgoing side: R is superseded by R2 within the lineage.
    let r2 = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(r),
        "R2: R, refined",
        "supersedes",
        None,
        2,
        agent,
    )
    .await
    .expect("evolve_step(R, supersedes)")
    .new_claim_id;
    migrate_as_maintenance(&pool, r, r2)
        .await
        .expect("the Supersede cascade for (R, R2)");
    assert_eq!(
        ends(&pool, revises_edge).await,
        (r, s),
        "R -revises-> S stays on R when R is superseded (outgoing)"
    );
}

/// A workflow's chain edges (`step_follows` between steps, `phase_follows`
/// between phases) link the FROZEN claims its `executes` edges name, and
/// `workflow_steps::ordered_steps` walks them inside that id set. A
/// step-lineage supersession leaves them, in both directions, on the retired
/// claim; the decomposition edge beside them still follows the head, so this
/// arm is not satisfied by a cascade that moved nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_cascade_leaves_the_step_and_phase_chains_in_place(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let step = seed_claim(&pool, agent, "S: the middle step", 0.7).await;
    let prev = seed_claim(&pool, agent, "the step before", 0.7).await;
    let next = seed_claim(&pool, agent, "the step after", 0.7).await;
    let prev_phase = seed_claim(&pool, agent, "a phase before", 0.7).await;
    let next_phase = seed_claim(&pool, agent, "a phase after", 0.7).await;
    let parent = seed_claim(&pool, agent, "the phase S decomposes", 0.7).await;

    let step_in = seed_typed_edge(&pool, prev, "claim", step, "claim", "step_follows").await;
    let step_out = seed_typed_edge(&pool, step, "claim", next, "claim", "step_follows").await;
    let phase_in =
        seed_typed_edge(&pool, prev_phase, "claim", step, "claim", "phase_follows").await;
    let phase_out =
        seed_typed_edge(&pool, step, "claim", next_phase, "claim", "phase_follows").await;
    let decomposed_from =
        seed_typed_edge(&pool, parent, "claim", step, "claim", "decomposes_to").await;

    let head = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(step),
        "S: the middle step, refined",
        "supersedes",
        None,
        2,
        agent,
    )
    .await
    .expect("evolve_step(supersedes)")
    .new_claim_id;
    migrate_as_maintenance(&pool, step, head)
        .await
        .expect("the Supersede cascade");

    assert_eq!(
        ends(&pool, decomposed_from).await,
        (parent, head),
        "control: decomposes_to follows the head"
    );
    assert_eq!(
        ends(&pool, step_in).await,
        (prev, step),
        "prev -step_follows-> S stays on S"
    );
    assert_eq!(
        ends(&pool, step_out).await,
        (step, next),
        "S -step_follows-> next stays on S"
    );
    assert_eq!(
        ends(&pool, phase_in).await,
        (prev_phase, step),
        "phase_follows (incoming) stays"
    );
    assert_eq!(
        ends(&pool, phase_out).await,
        (step, next_phase),
        "phase_follows (outgoing) stays"
    );
}
