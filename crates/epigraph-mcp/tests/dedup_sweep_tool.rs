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

fn build_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
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
    let viewer = fixture::public_viewer(&pool).await;
    // Identical content REQUIRES distinct agents: uq_claims_content_hash_agent
    // makes an exact within-agent duplicate impossible, which is precisely why
    // the real duplicate corpus is cross-agent.
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let a = seed(&pool, a1, "identical text", 0.9, &pgvec(0, 0.0), &[]).await;
    let b = seed(&pool, a2, "identical text", 0.5, &pgvec(0, 0.001), &[]).await;

    let server = build_server(pool.clone());
    let j = json_of(
        sweep_semantic_duplicates(&server, &viewer, params(true))
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
}

/// Executing collapses the exact-restatement pair, keeping the higher-truth
/// claim and forwarding the other at it.
#[sqlx::test(migrations = "../../migrations")]
async fn execute_collapses_exact_restatements_keeping_highest_truth(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a1 = seed_agent(&pool).await;
    let a2 = seed_agent(&pool).await;
    let strong = seed(&pool, a1, "same words", 0.9, &pgvec(0, 0.0), &[]).await;
    let weak = seed(&pool, a2, "same words", 0.4, &pgvec(0, 0.001), &[]).await;

    let server = build_server(pool.clone());
    let j = json_of(
        sweep_semantic_duplicates(&server, &viewer, params(false))
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
    let viewer = fixture::public_viewer(&pool).await;
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

    let server = build_server(pool.clone());
    let j = json_of(
        sweep_semantic_duplicates(&server, &viewer, params(false))
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
    let viewer = fixture::public_viewer(&pool).await;
    let (a1, a2, a3) = (
        seed_agent(&pool).await,
        seed_agent(&pool).await,
        seed_agent(&pool).await,
    );
    seed(&pool, a1, "chain text", 0.9, &pgvec(0, 0.000), &[]).await;
    seed(&pool, a2, "chain text", 0.8, &pgvec(0, 0.010), &[]).await;
    seed(&pool, a3, "chain text", 0.7, &pgvec(0, 0.020), &[]).await;

    let server = build_server(pool.clone());
    let j = json_of(
        sweep_semantic_duplicates(&server, &viewer, params(true))
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
    let viewer = fixture::public_viewer(&pool).await;
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

    let server = build_server(pool.clone());
    let j = json_of(
        sweep_semantic_duplicates(&server, &viewer, params(true))
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
    let viewer = fixture::public_viewer(&pool).await;
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

    let server = build_server(pool.clone());
    let mut p = params(true);
    p.limit = Some(2);
    let j = json_of(sweep_semantic_duplicates(&server, &viewer, p).await.expect("sweep"));

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

    let server = build_server(pool.clone());
    let link = epigraph_mcp::tools::link_epistemic::do_link_epistemic(
        &server, &viewer,
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
        sweep_semantic_duplicates(&server, &viewer, params(false))
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
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(&pool, &viewer)
        .await
        .expect("binary frame");
    let coherent =
        epigraph_engine::edge_factor::preview_claim_belief_on_frame(&pool, &viewer, strong, frame_id)
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
