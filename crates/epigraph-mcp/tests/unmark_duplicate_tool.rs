//! The `unmark_duplicate` tool: the reverse of `mark_duplicate`.
//!
//! With the server's administrative connection, a mark followed by an un-mark
//! puts the duplicate back (current, its edges re-pointed back onto it) and
//! answers with counts only. Without it, the un-mark is refused before
//! anything is written: unlike the mark's cascade, it cannot be deferred.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim};
use epigraph_mcp::tools::supersede::{mark_duplicate, unmark_duplicate};
use epigraph_mcp::types::{MarkDuplicateParams, UnmarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

fn body(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("json body")
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn state(pool: &PgPool, dup: Uuid) -> (Option<Uuid>, bool, i64) {
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(pool)
            .await
            .expect("dup");
    let in_force: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'same_as' \
            AND valid_to IS NULL",
    )
    .bind(dup)
    .fetch_one(pool)
    .await
    .expect("identity edges");
    (sup, cur, in_force)
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_then_unmark_through_the_tools_restores_the_duplicate(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let supporter = seed_claim(&pool, "supporter", 0.5).await;
    let e = edge(&pool, supporter, dup).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let marked = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: Some("an index family restatement".to_string()),
        },
        Some(&auth),
    )
    .await
    .expect("mark");
    assert_eq!(body(&marked)["cascade"]["status"], "applied");
    assert_eq!(state(&pool, dup).await, (Some(canonical), false, 1));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        target, canonical,
        "calibration: the mark re-pointed the edge"
    );

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("unmark");
    let b = body(&r);
    assert_eq!(b["mode"], "unmark_duplicate", "{b}");
    assert_eq!(b["canonical_id"], serde_json::json!(canonical), "{b}");
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(b["cascade"]["touched"]["edges_retargeted_back"], 1, "{b}");
    assert!(
        !b.to_string().contains(&e.to_string()),
        "the caller's copy carries counts, not other writers' row ids: {b}"
    );
    assert_eq!(state(&pool, dup).await, (None, true, 0));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, dup, "the edge is back on the duplicate");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unmark_without_the_administrative_connection_writes_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let marked = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&auth),
    )
    .await
    .expect("mark");
    assert_eq!(body(&marked)["cascade"]["status"], "deferred");
    let events_before: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");

    let err = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect_err("refused without the administrative connection");
    assert!(
        err.message.contains("administrative") && err.message.contains("nothing was written"),
        "{}",
        err.message
    );
    assert_eq!(
        state(&pool, dup).await,
        (Some(canonical), false, 1),
        "nothing changed"
    );
    let events_after: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(events_after, events_before, "no audit row either");
}

/// The production shape: the tools on an `epigraph_app` server whose
/// administrative connection runs as `epigraph_maintenance` (not a
/// superuser), with operator binding ARMED (migration 153 refuses an
/// application session that clears a `supersedes`). The duplicate's own writer
/// marks it (a collision-retracted edge's BBA is deleted, another writer's edge
/// is re-pointed), then un-marks it: the deleted BBA comes back from the
/// persisted record with its id, the edge comes back, the claim is current.
#[sqlx::test(migrations = "../../migrations")]
async fn the_writer_unmarks_on_the_app_role_with_binding_armed(pool: PgPool) {
    use epigraph_db::{ScopedPool, SessionGucMode};
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool")
            .with_maintenance_pool(fixture::downgraded_pool(&pool, "epigraph_maintenance").await);
    // A deterministic embedder (no request leaves the process), so the
    // un-mark's post-commit re-embed is exercised, not skipped for want of a key.
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    let server = epigraph_mcp::EpiGraphMcpFull::new(
        plain,
        epigraph_crypto::AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer");
    let group = *viewer.writable_groups().first().expect("a writable group");
    let auth = epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_auth::ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    };
    let own = |content: &'static str| {
        let pool = pool.clone();
        async move {
            let id = Uuid::new_v4();
            let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
            sqlx::query(
                "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                     is_current, visibility, owner_group_id) \
                 VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
            )
            .bind(id)
            .bind(content)
            .bind(&hash)
            .bind(agent)
            .bind(group)
            .execute(&pool)
            .await
            .expect("own public claim");
            id
        }
    };
    let canonical = own("the writer's canonical").await;
    let dup = own("the writer's duplicate").await;
    let third = seed_claim(&pool, "a third claim", 0.5).await;
    let other = seed_claim(&pool, "another writer's claim", 0.5).await;
    let e_other = edge(&pool, other, dup).await;
    let e_diamond = edge(&pool, third, dup).await;
    edge(&pool, third, canonical).await;
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'edge')")
        .bind(e_diamond)
        .execute(&pool)
        .await
        .expect("perspective");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('binary_truth', ARRAY['TRUE','FALSE']) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("frame");
    let diamond_bba = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        frame,
        Some(agent),
        Some(e_diamond),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("diamond bba");

    let marked = mark_duplicate(
        &server,
        &viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: Some("an index restatement".to_string()),
        },
        Some(&auth),
    )
    .await
    .expect("the writer marks its own duplicate");
    assert_eq!(
        body(&marked)["cascade"]["status"],
        "applied",
        "{}",
        body(&marked)
    );
    let gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(diamond_bba)
            .fetch_one(&pool)
            .await
            .expect("bba");
    assert!(
        gone,
        "calibration: the collision-retracted edge's BBA was deleted"
    );
    // The mark's repair, on the `epigraph_maintenance` login, gives the
    // canonical the BP factor of the edge it inherited (backlog ddb231b7).
    let inherited: Vec<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT variable_ids FROM factors WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(e_other)
    .fetch_all(&pool)
    .await
    .expect("factors");
    assert_eq!(
        inherited,
        vec![vec![other.min(canonical), other.max(canonical)]],
        "the moved edge's factor, minted on the canonical as epigraph_maintenance"
    );

    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(&pool)
        .await
        .expect("arm operator binding");

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("the writer un-marks its own duplicate, armed, on the app role");
    let b = body(&r);
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(state(&pool, dup).await, (None, true, 0));
    let embedded: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!(b["embedded"], serde_json::json!(embedded), "{b}");
    assert!(embedded, "the claim is current again and re-embedded");
    let props: serde_json::Value = sqlx::query_scalar(
        "SELECT properties FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    assert_eq!(props["dedup"]["tool"], "mark_duplicate", "{props}");
    assert_eq!(props["dedup"]["rule"], "caller_asserted", "{props}");
    assert_eq!(
        props["dedup"]["marked_by"],
        serde_json::json!(agent),
        "{props}"
    );
    assert_eq!(props["dedup"]["reason"], "an index restatement", "{props}");
    let back: Option<Uuid> =
        sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(diamond_bba)
            .fetch_optional(&pool)
            .await
            .expect("bba");
    assert_eq!(
        back,
        Some(dup),
        "the deleted BBA is restored, same id, on the duplicate"
    );
    let (target, in_force): (Uuid, bool) =
        sqlx::query_as("SELECT target_id, valid_to IS NULL FROM edges WHERE id = $1")
            .bind(e_other)
            .fetch_one(&pool)
            .await
            .expect("edge");
    assert_eq!((target, in_force), (dup, true));
    // The reversal re-mints the BP factors the duplicate's retirement deleted,
    // here on the non-superuser `epigraph_maintenance` login: the edge put
    // back on the duplicate has its factor again, on the duplicate.
    let factors: Vec<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT variable_ids FROM factors WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(e_other)
    .fetch_all(&pool)
    .await
    .expect("factors");
    assert_eq!(
        factors,
        vec![vec![other.min(dup), other.max(dup)]],
        "the restored edge's factor, re-minted as epigraph_maintenance"
    );
    let diamond_in_force: bool =
        sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
            .bind(e_diamond)
            .fetch_one(&pool)
            .await
            .expect("edge");
    assert!(
        diamond_in_force,
        "the collision-retracted edge is back in force"
    );
    // The mark retracted that copy instead of moving it; back in force, it is
    // re-minted on the duplicate too, on the same login.
    let diamond_factors: Vec<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT variable_ids FROM factors WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(e_diamond)
    .fetch_all(&pool)
    .await
    .expect("factors");
    assert_eq!(
        diamond_factors,
        vec![vec![third.min(dup), third.max(dup)]],
        "the un-retracted copy's factor, re-minted as epigraph_maintenance"
    );
}

/// `properties.dedup` marks a dedup act's identity edge, which the un-mark and
/// the revert-record lookup key on. No application edge write may set it:
/// otherwise anyone who can write a `same_as` edge between a duplicate and its
/// canonical could plant one, block the un-mark, and forge its provenance.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_edge_patch_cannot_set_the_dedup_key(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let a = seed_claim(&pool, "a", 0.5).await;
    let b = seed_claim(&pool, "b", 0.5).await;
    let e = edge(&pool, a, b).await;
    let err = epigraph_mcp::tools::edge_mutation::patch_edge(
        &server,
        &viewer,
        epigraph_mcp::types::PatchEdgeParams {
            edge_id: e.to_string(),
            valid_to: None,
            properties: Some(serde_json::json!({"dedup": {"tool": "forged"}})),
        },
        None,
    )
    .await
    .expect_err("the dedup key is reserved");
    assert!(err.message.contains("reserved"), "{}", err.message);
    let props: serde_json::Value = sqlx::query_scalar("SELECT properties FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert!(props.get("dedup").is_none(), "nothing written: {props}");
}

/// A `claims:write` caller that writes neither claim is refused with nothing
/// written (the gate is mark_duplicate's).
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_who_writes_neither_claim_cannot_unmark(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    let (auth, admin_viewer) = common::granted_server_admin(&server, &pool).await;
    mark_duplicate(
        &server,
        &admin_viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&auth),
    )
    .await
    .expect("mark");
    let (_, stranger_auth, stranger) = common::seed_caller(&pool, &["claims:write"]).await;
    let err = unmark_duplicate(
        &server,
        &stranger,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&stranger_auth),
    )
    .await
    .expect_err("not a writer of either claim");
    assert!(
        err.message.contains("nothing was written"),
        "{}",
        err.message
    );
    assert_eq!(state(&pool, dup).await, (Some(canonical), false, 1));
}

/// The semantic sweep's collapse records its own provenance on the identity
/// edge: its tool, the exact-restatement rule, and the acting agent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_records_its_rule_on_the_identity_edge(pool: PgPool) {
    let survivor = seed_claim(&pool, "a restated claim", 0.5).await;
    let dup = seed_claim(&pool, "a restated claim (again)", 0.5).await;
    let acting = common::seed_agent(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_mcp::tools::dedup_sweep::collapse_pair_act(&mut conn, acting, dup, survivor)
        .await
        .expect("collapse");
    let props: serde_json::Value = sqlx::query_scalar(
        "SELECT properties FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'same_as' AND valid_to IS NULL",
    )
    .bind(dup)
    .bind(survivor)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    assert_eq!(
        props["dedup"]["tool"], "sweep_semantic_duplicates",
        "{props}"
    );
    assert_eq!(props["dedup"]["rule"], "exact_restatement", "{props}");
    assert_eq!(
        props["dedup"]["marked_by"],
        serde_json::json!(acting),
        "{props}"
    );
}

/// A duplicate the legacy raw-SQL `fuzzy_dedup_claims` marked is un-markable
/// through the tool once the operator backfill has reconstructed its identity
/// edge (operator ruling R-7), and the answer says it was a legacy mark (no
/// repair record, nothing restored).
#[sqlx::test(migrations = "../../migrations")]
async fn a_backfilled_legacy_mark_unmarks_through_the_tool(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let canonical = seed_claim(&pool, "r7 legacy canonical", 0.5).await;
    let dup = seed_claim(&pool, "r7 legacy duplicate", 0.5).await;
    sqlx::query(
        "UPDATE claims SET supersedes = $1, is_current = false, embedding = NULL, \
                           embedding_3072 = NULL, \
                           labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'), \
                           properties = COALESCE(properties, '{}'::jsonb) \
                             || jsonb_build_object('deduped_into', $1::text, \
                                                   'deduped_by', 'fuzzy_dedup_claims', \
                                                   'deduped_at', now()::text) \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .execute(&pool)
    .await
    .expect("legacy raw-SQL mark");
    let mut conn = pool.acquire().await.expect("acquire");
    let backfilled =
        epigraph_db::ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, true)
            .await
            .expect("backfill");
    assert_eq!(backfilled.inserted, 1, "calibration: {backfilled:?}");
    drop(conn);
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("a backfilled legacy mark is un-markable");
    let b = body(&r);
    assert_eq!(b["canonical_id"], serde_json::json!(canonical), "{b}");
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(b["cascade"]["touched"]["legacy_mark"], true, "{b}");
    assert_eq!(state(&pool, dup).await, (None, true, 0));
}

/// A public claim authored by `agent` and owned by its personal group.
async fn owned_public_claim(pool: &PgPool, agent: Uuid, tag: &str) -> Uuid {
    let group = common::personal_group_of(pool, agent).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             labels, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], 'public', $5)",
    )
    .bind(id)
    .bind(format!("{tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed owned claim");
    id
}

/// Un-marking follows a canonical's consolidation to the merged claim
/// (operator ruling R-11), and the reversal moves the duplicate's rows off THAT
/// claim, so the caller needs the same authority over it as over the
/// canonical. A merge by another agent leaves the caller writing the
/// duplicate and the canonical, not the merged claim: the un-mark is refused,
/// naming the merged claim, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn unmarking_onto_a_merged_canonical_needs_authority_over_the_merged_claim(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let (a, a_auth, a_viewer) = common::seed_caller(&pool, &["claims:write"]).await;
    let (b, _, _) = common::seed_caller(&pool, &["claims:write"]).await;
    let canonical = owned_public_claim(&pool, a, "r11 canonical").await;
    let dup = owned_public_claim(&pool, a, "r11 duplicate").await;
    let partner = owned_public_claim(&pool, b, "r11 merge partner").await;
    mark_duplicate(
        &server,
        &a_viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&a_auth),
    )
    .await
    .expect("the caller marks its own duplicate onto its own canonical");
    assert_eq!(state(&pool, dup).await, (Some(canonical), false, 1));

    let mut conn = pool.acquire().await.expect("acquire");
    let merged = epigraph_db::ClaimRepository::consolidate_act_conn(
        &mut conn,
        &[canonical, partner],
        &format!("r11 merged by another agent {}", Uuid::new_v4()),
        0.5,
        epigraph_db::repos::claim::ConsolidateMode::Merge,
        "merge",
        b,
    )
    .await
    .expect("another agent merges the canonical")
    .merged_id;
    epigraph_db::ClaimRepository::migrate_consolidated_edges_conn(
        &mut conn,
        merged,
        &[canonical, partner],
    )
    .await
    .expect("edge migration");
    drop(conn);

    let err = unmark_duplicate(
        &server,
        &a_viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&a_auth),
    )
    .await
    .expect_err("the caller does not write the merged claim");
    assert!(
        err.message.contains(&merged.to_string()) && !err.message.contains("itself retired"),
        "the refusal names the merged claim the reversal would act on: {}",
        err.message
    );
    assert_eq!(
        state(&pool, dup).await,
        (Some(canonical), false, 1),
        "nothing was written"
    );
}

/// Retire `dup` onto `canonical` exactly as the legacy raw-SQL
/// `fuzzy_dedup_claims` did before 2026-10: no identity edge.
async fn legacy_mark(pool: &PgPool, dup: Uuid, canonical: Uuid) {
    sqlx::query(
        "UPDATE claims SET supersedes = $1, is_current = false, embedding = NULL, \
                           embedding_3072 = NULL, \
                           labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'), \
                           properties = COALESCE(properties, '{}'::jsonb) \
                             || jsonb_build_object('deduped_into', $1::text, \
                                                   'deduped_by', 'fuzzy_dedup_claims', \
                                                   'deduped_at', now()::text) \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .execute(pool)
    .await
    .expect("legacy raw-SQL mark");
}

/// The tool's refusal of a legacy `fuzzy_dedup_claims` mark WITHOUT its
/// identity edge carries the specific reason to the caller (operator ruling
/// R-7): one the backfill can still reconstruct names
/// `backfill_dedup_identity_edges --apply` (also when its canonical is itself
/// retired since: the missing edge is reported first), and one it cannot says
/// why. Nothing is written and no audit row is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unbackfilled_legacy_mark_is_refused_with_its_reason(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let canonical = seed_claim(&pool, "r7 legacy canonical", 0.5).await;
    let pending = seed_claim(&pool, "r7 legacy, not yet backfilled", 0.5).await;
    legacy_mark(&pool, pending, canonical).await;
    let retired = seed_claim(&pool, "r7 legacy canonical retired since", 0.5).await;
    let over_retired = seed_claim(&pool, "r7 legacy mark over it", 0.5).await;
    legacy_mark(&pool, over_retired, retired).await;
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(retired)
    .execute(&pool)
    .await
    .expect("retire the second canonical with no replacement");
    let unlabelled = seed_claim(&pool, "r7 legacy, label removed since", 0.5).await;
    legacy_mark(&pool, unlabelled, canonical).await;
    sqlx::query("UPDATE claims SET labels = array_remove(labels, 'deduped') WHERE id = $1")
        .bind(unlabelled)
        .execute(&pool)
        .await
        .expect("drop the label");
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let events_before: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");

    let refuse = |dup: Uuid| {
        let (server, viewer, auth) = (&server, &viewer, &auth);
        async move {
            unmark_duplicate(
                server,
                viewer,
                UnmarkDuplicateParams {
                    claim_id: dup.to_string(),
                },
                Some(auth),
            )
            .await
            .expect_err("no identity edge: refused")
            .message
            .to_string()
        }
    };
    for (dup, canon) in [(pending, canonical), (over_retired, retired)] {
        let m = refuse(dup).await;
        assert!(
            m.contains("legacy fuzzy_dedup_claims mark")
                && m.contains("backfill_dedup_identity_edges --apply")
                && m.contains("not been reconstructed")
                && !m.contains("no replacement"),
            "a reconstructable legacy mark names the backfill, before anything about its \
             canonical: {m}"
        );
        assert_eq!(state(&pool, dup).await, (Some(canon), false, 0));
    }
    let m = refuse(unlabelled).await;
    assert!(
        m.contains("cannot reconstruct") && m.contains("`deduped` label"),
        "an unreconstructable legacy mark says why: {m}"
    );
    assert_eq!(state(&pool, unlabelled).await, (Some(canonical), false, 0));
    let events_after: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(events_after, events_before, "no audit row either");
}

/// The success path of R-11 through the tool, for a `claims:write` caller with
/// no admin scope who writes every claim of the chain (it merged the canonical
/// itself): the un-mark follows the consolidation to the merged claim, answers
/// both ids, makes the duplicate current, and takes its edge back from the
/// merged claim, where the merge's edge migration had carried it.
#[sqlx::test(migrations = "../../migrations")]
async fn unmarking_onto_its_own_merged_canonical_restores_the_duplicate(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let (a, a_auth, a_viewer) = common::seed_caller(&pool, &["claims:write"]).await;
    let canonical = owned_public_claim(&pool, a, "r11 own canonical").await;
    let dup = owned_public_claim(&pool, a, "r11 own duplicate").await;
    let partner = owned_public_claim(&pool, a, "r11 own merge partner").await;
    let supporter = seed_claim(&pool, "r11 supporter", 0.5).await;
    let e = edge(&pool, supporter, dup).await;
    mark_duplicate(
        &server,
        &a_viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&a_auth),
    )
    .await
    .expect("the caller marks its own duplicate");
    let mut conn = pool.acquire().await.expect("acquire");
    let merged = epigraph_db::ClaimRepository::consolidate_act_conn(
        &mut conn,
        &[canonical, partner],
        &format!("r11 merged by the caller {}", Uuid::new_v4()),
        0.5,
        epigraph_db::repos::claim::ConsolidateMode::Merge,
        "merge",
        a,
    )
    .await
    .expect("the caller merges its canonical")
    .merged_id;
    epigraph_db::ClaimRepository::migrate_consolidated_edges_conn(
        &mut conn,
        merged,
        &[canonical, partner],
    )
    .await
    .expect("edge migration");
    drop(conn);
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, merged, "calibration: the edge followed the merge");

    let r = unmark_duplicate(
        &server,
        &a_viewer,
        UnmarkDuplicateParams {
            claim_id: dup.to_string(),
        },
        Some(&a_auth),
    )
    .await
    .expect("the caller writes every claim of the chain");
    let b = body(&r);
    assert_eq!(b["canonical_id"], serde_json::json!(canonical), "{b}");
    assert_eq!(b["current_canonical_id"], serde_json::json!(merged), "{b}");
    assert_eq!(b["cascade"]["status"], "applied", "{b}");
    assert_eq!(b["cascade"]["touched"]["drifted"], 0, "{b}");
    assert_eq!(state(&pool, dup).await, (None, true, 0));
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        target, dup,
        "the edge is back on the duplicate, from the merged claim"
    );
}
