//! `sweep_semantic_duplicates` (backlog e3732d16 / design F4).
//!
//! The properties worth pinning are the destructive ones: that a dry run
//! really does not mutate, that a survivor is chosen by the stated rule, that
//! transitive similarity clusters through union-find, and — the deliberate
//! divergence from the design sketch — that claims which merely RESEMBLE each
//! other are never auto-collapsed, because mark_duplicate discards the
//! duplicate's text.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::dedup_sweep::sweep_semantic_duplicates;
use epigraph_mcp::types::SweepSemanticDuplicatesParams;
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// A server carrying a `ScopedPool`, which `link_epistemic`'s belief wiring now
/// REQUIRES: it writes `claim_frames` / `mass_functions` / `UPDATE claims` on the
/// target, and a server with no `ScopedPool` refuses that rather than falling
/// back to the unstamped pool. Without the stamp this fixture's
/// `belief_wired == true` precondition fails — which is the conversion working,
/// not an inconvenience to route around.
async fn build_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// Unit vector pointing at `axis`, tilted by `tilt` toward axis+1 so distances
/// are controllable.
fn pgvec(axis: usize, tilt: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    v[axis] = 1.0;
    if tilt != 0.0 {
        v[axis + 1] = tilt;
    }
    let s: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
    format!("[{}]", s.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-sweep', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// The operator agent a collapse is attributed to (`--acting-agent` on the
/// CLI; the server's own agent in the MCP tool). Every collapsed pair's
/// `cascade.admin_applied` row names it.
async fn acting_agent(pool: &PgPool) -> Uuid {
    seed_agent(pool).await
}

/// `content` drives content_hash, so identical content => exact-restatement.
async fn seed(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    truth: f64,
    v: &str,
    labels: &[&str],
) -> Uuid {
    let labels: Vec<String> = labels.iter().map(ToString::to_string).collect();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels, embedding)
         VALUES ($1, sha256($1::bytea), $2, $3, true, $4, $5::vector) RETURNING id",
    )
    .bind(content).bind(truth).bind(agent).bind(&labels).bind(v)
    .fetch_one(pool).await.expect("seed claim")
}

fn params(dry_run: bool) -> SweepSemanticDuplicatesParams {
    SweepSemanticDuplicatesParams {
        similarity_threshold: Some(0.10),
        agent_scope: None,
        labels_scope: None,
        dry_run: Some(dry_run),
        limit: Some(100),
        offset: Some(0),
    }
}

fn json_of(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Dry run is the default and must not mutate. A sweep that silently retired
/// claims on a default-arg call would be the worst possible failure here.
#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_reports_without_mutating(pool: PgPool) {
    // Identical content REQUIRES distinct agents: uq_claims_content_hash_agent
    // makes an exact within-agent duplicate impossible, which is precisely why
    // the real duplicate corpus is cross-agent.
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let a = seed(&pool, a1, "identical text", 0.9, &pgvec(0, 0.0), &[]).await;
    let b = seed(&pool, a2, "identical text", 0.5, &pgvec(0, 0.001), &[]).await;

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(true),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    assert_eq!(j["dry_run"], serde_json::json!(true));
    assert_eq!(j["pairs_marked"], serde_json::json!(0));
    assert_eq!(
        j["clusters"].as_array().unwrap().len(),
        1,
        "the duplicate pair is reported"
    );

    let current: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
            .bind(vec![a, b])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(current, 2, "dry run mutated nothing");
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type LIKE 'cascade.%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events, 0, "the dry run recorded a cascade row");
}

/// Executing collapses the exact-restatement pair, keeping the higher-truth
/// claim and forwarding the other at it.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_collapses_exact_restatements_keeping_highest_truth(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "same words", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "same words", 0.4, &pgvec(0, 0.001), &[]).await;

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(false),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    assert_eq!(j["pairs_marked"], serde_json::json!(1));
    assert!(j["failures"].as_array().unwrap().is_empty());

    let r = sqlx::query!(
        "SELECT is_current, supersedes FROM claims WHERE id=$1",
        weak
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!r.is_current, "lower-truth duplicate retired");
    assert_eq!(
        r.supersedes,
        Some(strong),
        "forwarded at the higher-truth survivor"
    );

    let s = sqlx::query!("SELECT is_current FROM claims WHERE id=$1", strong)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(s.is_current, "survivor stays current");
}

/// THE DELIBERATE DIVERGENCE from the design sketch: claims that are close in
/// embedding space but NOT identical in text are never auto-collapsed, because
/// mark_duplicate discards the duplicate's wording. They surface as
/// merge_candidates for consolidate_claims instead.
#[sqlx::test(migrations = "../../migrations")]
async fn similar_but_distinct_text_is_never_auto_collapsed(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed(
        &pool,
        agent,
        "the reactor runs at 300K",
        0.9,
        &pgvec(0, 0.0),
        &[],
    )
    .await;
    let b = seed(
        &pool,
        agent,
        "the reactor operates at 300 kelvin",
        0.8,
        &pgvec(0, 0.001),
        &[],
    )
    .await;

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(false),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    assert_eq!(
        j["pairs_marked"],
        serde_json::json!(0),
        "differing wording must NOT be collapsed — mark_duplicate would discard text"
    );
    assert_eq!(
        j["merge_candidates"].as_array().unwrap().len(),
        1,
        "surfaced for consolidate_claims instead"
    );
    assert_eq!(j["clusters"].as_array().unwrap().len(), 0);

    let current: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
            .bind(vec![a, b])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(current, 2, "both survive");
}

/// Union-find: A~B and B~C cluster together even though A and C were never
/// directly compared. A pairwise-only implementation would emit two clusters.
#[sqlx::test(migrations = "../../migrations")]
async fn transitive_similarity_forms_one_cluster(pool: PgPool) {
    let (a1, a2, a3) = (
        seed_agent(&pool).await,
        seed_agent(&pool).await,
        seed_agent(&pool).await,
    );
    seed(&pool, a1, "chain text", 0.9, &pgvec(0, 0.000), &[]).await;
    seed(&pool, a2, "chain text", 0.8, &pgvec(0, 0.010), &[]).await;
    seed(&pool, a3, "chain text", 0.7, &pgvec(0, 0.020), &[]).await;

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(true),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    let clusters = j["clusters"].as_array().unwrap();
    assert_eq!(
        clusters.len(),
        1,
        "transitive members form ONE cluster: {clusters:?}"
    );
    assert_eq!(clusters[0]["duplicates"].as_array().unwrap().len(), 2);
}

/// Policy exclusions: telemetry claims and document-structure rows never enter
/// the sweep, and neither do already-superseded claims.
#[sqlx::test(migrations = "../../migrations")]
async fn excluded_claim_classes_are_not_swept(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    seed(
        &pool,
        a1,
        "telemetry dupe",
        0.9,
        &pgvec(0, 0.0),
        &["telemetry"],
    )
    .await;
    seed(
        &pool,
        a2,
        "telemetry dupe",
        0.8,
        &pgvec(0, 0.001),
        &["telemetry"],
    )
    .await;

    // Document-structure rows (properties.level set).
    for (i, t) in [0.9_f64, 0.8].into_iter().enumerate() {
        let owner = if i == 0 { a1 } else { a2 };
        let id = seed(&pool, owner, "paragraph dupe", t, &pgvec(2, 0.0), &[]).await;
        sqlx::query(
            "UPDATE claims SET properties = jsonb_build_object('level', 2::int) WHERE id=$1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(true),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    assert_eq!(
        j["scanned"],
        serde_json::json!(0),
        "telemetry and level-tagged structure rows are excluded by policy"
    );
    assert_eq!(j["clusters"].as_array().unwrap().len(), 0);
}

/// Paging is resumable: next_offset advances by what was scanned.
#[sqlx::test(migrations = "../../migrations")]
async fn next_offset_advances_for_resumable_paging(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    for i in 0..3 {
        seed(
            &pool,
            agent,
            &format!("page {i}"),
            0.7,
            &pgvec(10 + i, 0.0),
            &[],
        )
        .await;
    }

    let mut p = params(true);
    p.limit = Some(2);
    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            p,
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );

    assert_eq!(j["scanned"], serde_json::json!(2));
    assert_eq!(
        j["next_offset"],
        serde_json::json!(2),
        "resume point for the next call"
    );
}

/// The BULK collapse path repairs belief too (backlog 20e9ed83).
///
/// `sweep_semantic_duplicates` was rewired from `ClaimRepository::mark_duplicate`
/// to `retraction_cascade::mark_duplicate_with_cascade`, but every pre-existing
/// fixture here seeds bare claims with no edges, so the duplicate never carried
/// an edge-factor BBA and the cascade was always a no-op: the wiring could have
/// been reverted with the whole suite green. A bulk path that skipped the
/// repair would reintroduce the orphaned/stranded-BBA defect at scale, which is
/// exactly where it hurts most.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_repairs_the_survivors_belief_not_just_the_supersedes_pointer(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let a3 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "same words", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "same words", 0.4, &pgvec(0, 0.001), &[]).await;

    // A supporter with a real interval, far away in embedding space so it is
    // never itself a sweep candidate.
    let supporter = seed(
        &pool,
        a3,
        "an independent supporting claim",
        0.8,
        &pgvec(50, 0.0),
        &[],
    )
    .await;
    sqlx::query("UPDATE claims SET belief = 0.7, plausibility = 0.85 WHERE id = $1")
        .bind(supporter)
        .execute(&pool)
        .await
        .expect("plant supporter interval");

    let server = build_server(pool.clone()).await;
    let link = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server,
        &viewer,
        epigraph_mcp::types::LinkEpistemicParams {
            source_claim_id: supporter.to_string(),
            target_claim_id: weak.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic");
    assert_eq!(
        json_of(link)["belief_wired"],
        serde_json::json!(true),
        "fixture precondition: the duplicate must carry an edge-factor BBA"
    );
    let weak_betp_before: Option<f64> =
        sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(weak)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(weak_betp_before.is_some(), "fixture: duplicate has a BetP");

    let j = json_of(
        sweep_semantic_duplicates(
            &mut fixture::scoped_pool(&pool)
                .await
                .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
                .await
                .expect("a maintenance session over the test database"),
            params(false),
            acting_agent(&pool).await,
        )
        .await
        .expect("sweep"),
    );
    assert_eq!(j["pairs_marked"], serde_json::json!(1));
    assert!(
        j["failures"].as_array().unwrap().is_empty(),
        "no collapse and no cascade failure: {}",
        j["failures"]
    );

    // MemTX I2 on the bulk path: no phantom and no invisible supporter.
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge' \
         WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.id = mf.perspective_id)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let stranded: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge' \
         JOIN edges e ON e.id = mf.perspective_id \
         WHERE e.target_type = 'claim' AND e.target_id <> mf.claim_id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        orphaned, 0,
        "no orphaned edge-factor BBA after a bulk collapse"
    );
    assert_eq!(stranded, 0, "the migrated BBA moved onto the survivor");

    // The survivor inherited the supporter, and its cache says so.
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
    )
    .await
    .expect("binary frame");
    let coherent = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        strong,
        frame_id,
    )
    .await
    .expect("preview")
    .expect("the survivor inherited the duplicate's supporter");
    let cached: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(strong)
        .fetch_one(&pool)
        .await
        .unwrap();
    let cached = cached.expect("survivor must have a cached BetP");
    assert!(
        (cached - coherent.pignistic_prob).abs() < 1e-12,
        "the survivor's cached BetP ({cached}) must equal the canonical combine \
         of its post-collapse mass_functions set ({})",
        coherent.pignistic_prob
    );

    // ...and the retired duplicate is no longer believed on evidence it lost.
    let weak_betp_after: Option<f64> =
        sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(weak)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        weak_betp_after, None,
        "the duplicate's supporter moved to the survivor; keeping its old \
         cached BetP is a derived record with nothing behind it"
    );
}

/// Operator decision D1's audit rule on the bulk path (batch W12a): every
/// collapsed pair goes through the administrative cascade and gets EXACTLY ONE
/// `cascade.admin_applied` row naming the acting agent, cause `dedup`, the
/// duplicate as subject and the survivor as object, and the report returns
/// that row's id. Before W12a the sweep collapsed inline
/// (`mark_duplicate_with_cascade`) and wrote no audit row at all. Two pairs,
/// so a sweep that audited only the first would be caught.
#[sqlx::test(migrations = "../../migrations")]
async fn every_collapsed_pair_is_audited_under_the_acting_agent(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let a3 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "thrice said", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak1 = seed(&pool, a2, "thrice said", 0.5, &pgvec(0, 0.001), &[]).await;
    let weak2 = seed(&pool, a3, "thrice said", 0.4, &pgvec(0, 0.002), &[]).await;
    let operator = acting_agent(&pool).await;

    let scoped = fixture::scoped_pool(&pool).await;
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .expect("a maintenance session over the test database");
    let report = epigraph_mcp::tools::dedup_sweep::sweep(&mut session, &params(false), operator)
        .await
        .expect("sweep");
    drop(session);
    assert_eq!(report.pairs_marked, 2, "{report:?}");
    assert!(report.failures.is_empty(), "{report:?}");

    let rows: Vec<(Uuid, Option<Uuid>, String, String, String)> = sqlx::query_as(
        "SELECT id, agent_id, details->>'cause', details#>>'{trigger,subject_id}', \
                details#>>'{trigger,object_id}' \
           FROM security_events WHERE event_type = 'cascade.admin_applied' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .expect("the applied rows");
    assert_eq!(
        rows.len(),
        2,
        "one applied row per collapsed pair: {rows:?}"
    );
    let mut subjects: Vec<String> = rows.iter().map(|r| r.3.clone()).collect();
    subjects.sort();
    let mut want = vec![weak1.to_string(), weak2.to_string()];
    want.sort();
    assert_eq!(subjects, want);
    for (id, agent, cause, _, object) in &rows {
        assert_eq!(*agent, Some(operator), "attributed to the acting agent");
        assert_eq!(cause, "dedup");
        assert_eq!(object, &strong.to_string(), "forwarded at the survivor");
        assert!(
            report.audit_event_ids.contains(id),
            "the report names its audit rows"
        );
    }

    // Each act recorded its pending cascade in its own transaction (through
    // 117's definer, naming the acting agent), and each applied row answers
    // exactly that deferral, so a finished sweep leaves NOTHING pending: the
    // replay timer must not apply these pairs a second time.
    let deferred: Vec<(Uuid, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT id, agent_id, details->>'recorded_by' FROM security_events \
          WHERE event_type = 'cascade.deferred' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .expect("the deferred rows");
    assert_eq!(
        deferred.len(),
        2,
        "one deferral per collapsed pair: {deferred:?}"
    );
    for (_, agent, recorded_by) in &deferred {
        assert_eq!(*agent, Some(operator));
        assert_eq!(recorded_by, "epigraph_record_cascade_deferral");
    }
    let answered: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT details#>>'{replay_of,deferred_event_id}', details#>>'{replay_of,replayed_by}' \
           FROM security_events WHERE event_type = 'cascade.admin_applied'",
    )
    .fetch_all(&pool)
    .await
    .expect("the applied rows' replay_of");
    let mut answered_ids: Vec<String> = answered
        .iter()
        .map(|(id, by)| {
            assert_eq!(
                by.as_deref(),
                Some(epigraph_mcp::tools::dedup_sweep::SWEEP_REPLAYED_BY)
            );
            id.clone().expect("an applied row that answers no deferral")
        })
        .collect();
    answered_ids.sort();
    let mut deferred_ids: Vec<String> = deferred.iter().map(|r| r.0.to_string()).collect();
    deferred_ids.sort();
    assert_eq!(answered_ids, deferred_ids);
    assert_eq!(
        pending(&pool).await,
        0,
        "a finished sweep left cascades pending: the replay would apply them again"
    );
}

/// Pending cascades, as the replay timer reads them.
async fn pending(pool: &PgPool) -> usize {
    epigraph_db::repos::admin_cascade::pending_replays(
        pool,
        100,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("pending replays")
    .len()
}

/// The replay timer's pass, on a connection downgraded to
/// `epigraph_maintenance` (the timer's login shape).
async fn replay(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(pool)
        .await
        .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the replay's connection is privileged");
    let (conn, viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        viewer,
        "w12a-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

/// The applied row for `subject`: its agent and the deferral it answers.
async fn applied_for(pool: &PgPool, subject: Uuid) -> Vec<(Option<Uuid>, Option<String>)> {
    sqlx::query_as(
        "SELECT agent_id, details#>>'{replay_of,deferred_event_id}' FROM security_events \
          WHERE event_type = 'cascade.admin_applied' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(subject)
    .fetch_all(pool)
    .await
    .expect("applied rows")
}

/// The window between the act and its administrative cascade (two
/// transactions). A sweep that dies after the act commits must not leave a
/// collapsed pair with no cascade row: the act's own transaction records it as
/// pending, on the maintenance login, so the replay timer finds it and applies
/// it under the acting agent. Driven by running the act half alone, which is
/// exactly the state a process killed before its apply leaves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_collapse_that_dies_before_its_cascade_is_left_pending_for_the_replay(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "said once", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "said once", 0.4, &pgvec(0, 0.001), &[]).await;
    let operator = acting_agent(&pool).await;

    let maintenance = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .expect("maintenance session");
    let (conn, _) = session.split();
    let (_, deferral) =
        epigraph_mcp::tools::dedup_sweep::collapse_pair_act(conn, operator, weak, strong)
            .await
            .expect("the act");
    drop(session);

    let (is_current, supersedes): (Option<bool>, Option<Uuid>) =
        sqlx::query_as("SELECT is_current, supersedes FROM claims WHERE id = $1")
            .bind(weak)
            .fetch_one(&pool)
            .await
            .expect("weak");
    assert_eq!(
        (is_current, supersedes),
        (Some(false), Some(strong)),
        "the act committed"
    );
    assert!(
        applied_for(&pool, weak).await.is_empty(),
        "nothing applied yet"
    );
    let rows = epigraph_db::repos::admin_cascade::pending_replays(
        &pool,
        100,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("pending");
    assert_eq!(
        rows.len(),
        1,
        "the interrupted collapse is not pending: {rows:?}"
    );
    assert_eq!(rows[0].event_id, deferral);
    assert_eq!(rows[0].details["cause"], "dedup");
    assert_eq!(rows[0].details["trigger"]["subject_id"], weak.to_string());
    assert_eq!(rows[0].details["trigger"]["agent_id"], operator.to_string());

    let r = replay(&pool).await;
    assert_eq!(r.applied, 1, "{r:?}");
    assert_eq!(
        applied_for(&pool, weak).await,
        vec![(Some(operator), Some(deferral.to_string()))],
        "the replay's applied row names the acting agent and answers the deferral"
    );
    assert_eq!(pending(&pool).await, 0);
}

/// While a replay run holds the replay's advisory lock, the sweep does not
/// apply a pair's cascade itself (the replay could be applying the same fresh
/// deferral): the act commits with its pending row, the pair is reported in
/// `left_to_replay` (not as a failure), and the replay timer applies it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pair_is_left_to_the_replay_while_a_replay_run_holds_its_lock(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "said twice", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "said twice", 0.4, &pgvec(0, 0.001), &[]).await;
    let operator = acting_agent(&pool).await;

    let mut holder = pool.acquire().await.expect("a replay run's connection");
    assert!(epigraph_db::repos::maintenance_lock::try_take(
        &mut holder,
        epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY
    )
    .await
    .expect("take the replay lock"));

    let scoped = fixture::scoped_pool(&pool).await;
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .expect("maintenance session");
    let report = epigraph_mcp::tools::dedup_sweep::sweep(&mut session, &params(false), operator)
        .await
        .expect("sweep");
    drop(session);
    assert_eq!(report.pairs_marked, 1, "{report:?}");
    assert!(report.failures.is_empty(), "{report:?}");
    assert!(report.audit_event_ids.is_empty(), "{report:?}");
    assert_eq!(report.left_to_replay, vec![format!("{weak} -> {strong}")]);
    assert!(
        applied_for(&pool, weak).await.is_empty(),
        "the sweep applied a cascade while the replay held its lock"
    );
    assert_eq!(pending(&pool).await, 1);

    epigraph_db::repos::maintenance_lock::release(
        &mut holder,
        epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY,
    )
    .await
    .expect("release");
    drop(holder);
    let r = replay(&pool).await;
    assert_eq!(r.applied, 1, "{r:?}");
    assert_eq!(applied_for(&pool, weak).await.len(), 1);
    assert_eq!(applied_for(&pool, weak).await[0].0, Some(operator));
    assert_eq!(pending(&pool).await, 0);
}

/// `collapse_pair_act`'s two halves commit together or not at all (review
/// W12a-D2). Every other test drives the definer's success path, which cannot
/// tell one transaction from two. Here the deferral half FAILS after the act
/// half has run: the acting agent names no `agents` row, so the definer's
/// `security_events` INSERT is refused (the `agent_id` foreign key). If the act
/// had committed on its own, before the deferral's transaction, the duplicate
/// would now be retired with no cascade row to answer for it, which is the
/// window the single transaction exists to close. So: an error, the duplicate
/// still current and unforwarded, its embedding intact, and no `cascade.*` row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_deferral_rolls_the_act_back_with_it(pool: PgPool) {
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "said thrice", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "said thrice", 0.4, &pgvec(0, 0.001), &[]).await;
    let not_an_agent = Uuid::new_v4();

    let maintenance = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::DedupSweep)
        .await
        .expect("maintenance session");
    let (conn, _) = session.split();
    let err = epigraph_mcp::tools::dedup_sweep::collapse_pair_act(conn, not_an_agent, weak, strong)
        .await
        .expect_err("the deferral names no agent, so the definer must refuse it");
    drop(session);
    // The refusal is the deferral's, not the act's: the act alone succeeds on
    // this pair (the success tests above), and the violated constraint is the
    // audit row's agent key, which only the definer's INSERT touches.
    assert!(
        format!("{err:?}").contains("security_events_agent_id_fkey"),
        "the failure did not come from the deferral half: {err:?}"
    );

    let (is_current, supersedes, embedded): (Option<bool>, Option<Uuid>, bool) = sqlx::query_as(
        "SELECT is_current, supersedes, embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(weak)
    .fetch_one(&pool)
    .await
    .expect("weak");
    assert_eq!(
        (is_current, supersedes, embedded),
        (Some(true), None, true),
        "the act committed without its deferral: a collapse with no cascade row"
    );
    let cascade_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type LIKE 'cascade.%' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(weak)
    .fetch_one(&pool)
    .await
    .expect("cascade rows");
    assert_eq!(cascade_rows, 0);
    assert_eq!(pending(&pool).await, 0);
}
