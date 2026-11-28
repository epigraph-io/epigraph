use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, DbError, RefusalKind};
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

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])"
    ).bind(id).bind(content).bind(&hash).bind(agent)
    .execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_happy_path(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();

    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sup, Some(canonical));
    assert!(!is_current);

    // Canonical untouched.
    let (canon_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(canon_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_already_superseded(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let other_canonical = seed_claim(&pool, agent, "other").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;

    // First mark — succeeds.
    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();
    // Second mark to a different canonical — must fail.
    let err = ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(other_canonical),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("already superseded"), "{err:?}");
    // A STATE refusal (operator ruling R-55): the duplicate was retired
    // before this request, so HTTP answers it 409.
    assert!(
        matches!(
            err,
            DbError::Refused {
                kind: RefusalKind::State,
                ..
            }
        ),
        "{err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_self(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent, "self").await;
    let err = ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(claim),
        ClaimId::from_uuid(claim),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("dup == canonical"), "{err:?}");
    // A repo-authored refusal, so the MCP layer may send it as written
    // (backlog e0f0cb68); never a `QueryFailed`, which it must redact. An
    // INPUT refusal (operator ruling R-55): wrong whatever the graph holds.
    assert!(
        matches!(
            err,
            DbError::Refused {
                kind: RefusalKind::Input,
                ..
            }
        ),
        "{err:?}"
    );
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb, NOW())",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap();
}

/// Counts edges IN FORCE between two claims.
///
/// The `valid_to IS NULL` filter is load-bearing since `mark_duplicate_with_repair`
/// switched from deleting redundant edges to retracting them: the superseded copy
/// survives as a row, so an unfiltered `COUNT(*)` returns 2 where the invariant
/// under test is "exactly one live edge". Counting rows would make this assert the
/// wrong thing.
async fn edge_count(pool: &PgPool, source: Uuid, target: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges
          WHERE source_id = $1 AND target_id = $2 AND valid_to IS NULL",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_migrates_edges_to_canonical(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Incoming: a third claim supports the dup.
    seed_edge(&pool, third, dup, "supports").await;
    // Outgoing: the dup supports the third claim.
    seed_edge(&pool, dup, third, "supports").await;
    // Self-loop hazard: an edge already between dup and canonical. Redirecting its
    // source to canonical would create a canonical->canonical self-loop.
    seed_edge(&pool, dup, canonical, "related").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();

    // Incoming edge migrated: third -> dup became third -> canonical.
    assert_eq!(
        edge_count(&pool, third, canonical).await,
        1,
        "incoming edge not migrated"
    );
    assert_eq!(
        edge_count(&pool, third, dup).await,
        0,
        "incoming edge left dangling at dup"
    );
    // Outgoing edge migrated: dup -> third became canonical -> third.
    assert_eq!(
        edge_count(&pool, canonical, third).await,
        1,
        "outgoing edge not migrated"
    );
    assert_eq!(
        edge_count(&pool, dup, third).await,
        0,
        "outgoing edge left dangling at dup"
    );
    // Self-loop guard: the dup<->canonical edge must NOT become canonical->canonical.
    assert_eq!(
        edge_count(&pool, canonical, canonical).await,
        0,
        "created a self-loop"
    );
}

/// `seed_edge`, returning the new edge's id.
async fn seed_edge_id(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb, NOW()) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Backlog 356207d8: the canonical already points AT the duplicate
/// (`canonical -> dup`, CORROBORATES and supports), the orientation of the
/// 2026-06-17 repro. `mark_duplicate_migrates_edges_to_canonical` seeds only
/// `dup -> canonical`, which the OUTGOING re-point's guard covers; this one
/// reaches the INCOMING re-point, whose `AND NOT (source_type = 'claim' AND
/// source_id = $1)` keeps both edges on the duplicate. Re-pointed, each would
/// become a `canonical -> canonical` self-loop.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_keeps_canonical_to_dup_edges_on_dup(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;

    let corroborates = seed_edge_id(&pool, canonical, dup, "CORROBORATES").await;
    let supports = seed_edge_id(&pool, canonical, dup, "supports").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate with live canonical -> dup edges");

    let (is_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!is_current, "the duplicate is retired");
    assert_eq!(
        edge_count(&pool, canonical, canonical).await,
        0,
        "created a canonical -> canonical self-loop"
    );
    for (name, edge) in [("CORROBORATES", corroborates), ("supports", supports)] {
        let (source, target, live): (Uuid, Uuid, bool) = sqlx::query_as(
            "SELECT source_id, target_id, valid_to IS NULL FROM edges WHERE id = $1",
        )
        .bind(edge)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (source, target, live),
            (canonical, dup, true),
            "the canonical -> dup {name} edge stays live on the duplicate"
        );
    }
}

/// Regression test for backlog 2905150e: mark_duplicate returned HTTP 500
/// "Duplicate entity already exists" when dup and canonical already shared
/// a graph edge via a third claim (diamond pattern).
///
/// Scenario: `third →[CORROBORATES]→ dup` AND `third →[CORROBORATES]→ canonical`
/// both exist.  Migrating the dup-edge would produce a second
/// `third →[CORROBORATES]→ canonical`, tripping `idx_edges_unique_triple_non_authored`
/// and rolling back the transaction before `is_current` was flipped.
///
/// The fix pre-deletes dup-edges whose migrated triple already exists on
/// canonical, so the UPDATE only touches survivors.  Verify both the incoming
/// (target=dup) and outgoing (source=dup) diamond cases.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_with_shared_neighbor_edge_succeeds(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Diamond — incoming: third already points at both dup and canonical with same relationship.
    seed_edge(&pool, third, dup, "CORROBORATES").await;
    seed_edge(&pool, third, canonical, "CORROBORATES").await;

    // Diamond — outgoing: dup and canonical both point at third with same relationship.
    seed_edge(&pool, dup, third, "supports").await;
    seed_edge(&pool, canonical, third, "supports").await;

    // Before the fix this would return Err(DuplicateKey) / HTTP 500.
    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate must succeed even when dup and canonical share a neighbour edge");

    // dup must be retired.
    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sup,
        Some(canonical),
        "dup.supersedes should point at canonical"
    );
    assert!(
        !is_current,
        "dup must not be is_current after mark_duplicate"
    );

    // canonical must still be current.
    let (canon_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(canon_current, "canonical must remain is_current");

    // The canonical→third edge should exist (either migrated or pre-existing).
    assert_eq!(
        edge_count(&pool, canonical, third).await,
        1,
        "canonical should have exactly one outgoing 'supports' edge to third"
    );
    // The third→canonical edge should exist exactly once.
    assert_eq!(
        edge_count(&pool, third, canonical).await,
        1,
        "canonical should have exactly one incoming 'CORROBORATES' edge from third"
    );
    // No dangling edges on dup.
    assert_eq!(
        edge_count(&pool, dup, third).await,
        0,
        "dup should have no remaining outgoing edges to third"
    );
    assert_eq!(
        edge_count(&pool, third, dup).await,
        0,
        "dup should have no remaining incoming edges from third"
    );
}

/// Regression test for backlog 2905150e / issue #286: mark_duplicate returned
/// HTTP 500 "Duplicate entity already exists" when `dup` and `canonical` were
/// both joined to a common third claim by `alternative_of` edges.
///
/// `alternative_of` is governed by a *symmetric* unique index (migration 042,
/// `edges_alternative_of_symmetric_uniq` on `LEAST/GREATEST(source_id,target_id)`),
/// so the directional diamond pre-deletes exercised by
/// `mark_duplicate_with_shared_neighbor_edge_succeeds` do not catch it. The
/// failing shape is two edges of *opposite* orientation:
///
///   `dup →[alternative_of]→ third`  AND  `third →[alternative_of]→ canonical`
///
/// Migrating `dup→canonical` rewrites the first into `canonical→third`, whose
/// symmetric key {canonical,third} collides with the surviving `third→canonical`
/// edge. The fix pre-deletes the redundant dup-side `alternative_of` edge.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_with_shared_alternative_of_edge_succeeds(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Opposite orientations the directional pre-deletes miss.
    seed_edge(&pool, dup, third, "alternative_of").await;
    seed_edge(&pool, third, canonical, "alternative_of").await;

    // Before the fix this returned Err(DuplicateKey) / HTTP 500.
    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate must succeed despite a symmetric alternative_of collision");

    // dup must be retired.
    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sup,
        Some(canonical),
        "dup.supersedes should point at canonical"
    );
    assert!(
        !is_current,
        "dup must not be is_current after mark_duplicate"
    );

    // canonical must remain current.
    let (canon_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(canon_current, "canonical must remain is_current");

    // Exactly one alternative_of edge remains IN FORCE — the canonical↔third pair.
    // The redundant dup-side edge is retracted, not deleted, so it is still a row;
    // counting rows here would assert the old delete semantics.
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges
              WHERE relationship = 'alternative_of' AND valid_to IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        total, 1,
        "the redundant dup-side alternative_of edge should be gone"
    );

    // No alternative_of edge may remain on the retired dup.
    let touching_dup: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'alternative_of' \
         AND (source_id = $1 OR target_id = $1) AND valid_to IS NULL",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        touching_dup, 0,
        "no alternative_of edge should remain on the retired dup"
    );

    // The canonical↔third symmetric pair must survive exactly once.
    let canon_third: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'alternative_of' \
         AND LEAST(source_id, target_id) = LEAST($1, $2) \
         AND GREATEST(source_id, target_id) = GREATEST($1, $2)",
    )
    .bind(canonical)
    .bind(third)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        canon_third, 1,
        "canonical↔third alternative_of pair must survive"
    );
}

/// The same regression class for the SECOND pair-unique relationship,
/// `shifted_to` (migration 358, backlog d639d492). The test ships WITH the
/// index that creates the hazard: `edges_shifted_to_pair_uniq` is keyed on
/// `(LEAST(source_id,target_id), GREATEST(source_id,target_id))`, so issue
/// #286's failing shape reproduces verbatim:
///
///   `dup →[shifted_to]→ third`  AND  `third →[shifted_to]→ canonical`
///
/// Migrating `dup→canonical` rewrites the first into `canonical→third`, whose
/// pair key {canonical,third} collides with the in-force `third→canonical`.
///
/// The trap `alternative_of` does not set: `shifted_to` is DIRECTIONAL, so it
/// is easy to reason that the directional diamond guards already cover it.
/// They do not: the INDEX is direction-agnostic although the RELATIONSHIP is
/// not, and the index is what rolls the transaction back. The repair is
/// driven from `epigraph_db::PAIR_UNIQUE_RELATIONSHIPS`, not from what the
/// relationship means.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_with_shared_shifted_to_edge_succeeds(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Opposite orientations the directional pre-deletes miss.
    seed_edge(&pool, dup, third, "shifted_to").await;
    seed_edge(&pool, third, canonical, "shifted_to").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate must succeed despite a shifted_to pair-key collision");

    // dup must be retired: proof the transaction COMMITTED. A constraint
    // violation would have rolled back before `is_current` flipped.
    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sup,
        Some(canonical),
        "dup.supersedes should point at canonical"
    );
    assert!(
        !is_current,
        "dup must not be is_current after mark_duplicate"
    );

    // Exactly one shifted_to edge remains IN FORCE: the canonical↔third pair,
    // in its original orientation. The redundant dup-side edge is retracted
    // (still a row), never re-pointed.
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'shifted_to' AND valid_to IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        total, 1,
        "the redundant dup-side shifted_to edge should be retracted"
    );
    assert_eq!(
        edge_count(&pool, third, canonical).await,
        1,
        "third→canonical shifted_to must survive in its own direction"
    );
    assert_eq!(
        edge_count(&pool, canonical, third).await,
        0,
        "no reversed canonical→third succession may be created"
    );
    let (dup_side_retracted,): (bool,) = sqlx::query_as(
        "SELECT valid_to IS NOT NULL FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'shifted_to'",
    )
    .bind(dup)
    .bind(third)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        dup_side_retracted,
        "dup→third stays on the retired dup, retracted"
    );
}

/// The pair guard retracts a dup-side edge only when the canonical shares an
/// edge OF THE SAME RELATIONSHIP with the third claim. The pair indexes are
/// per-relationship partial indexes, so `dup →[alternative_of]→ third` and
/// `third →[shifted_to]→ canonical` do not collide once the first is
/// re-pointed: both are legitimate and both must stay in force on the
/// canonical. Matching the colliding edge by "any pair-unique relationship"
/// instead would retract the `alternative_of` for nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_keeps_distinct_pair_unique_relationships_apart(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    seed_edge(&pool, dup, third, "alternative_of").await;
    seed_edge(&pool, third, canonical, "shifted_to").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate");

    for (rel, source, target) in [
        ("alternative_of", canonical, third),
        ("shifted_to", third, canonical),
    ] {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
              WHERE relationship = $1 AND source_id = $2 AND target_id = $3 \
                AND valid_to IS NULL",
        )
        .bind(rel)
        .bind(source)
        .bind(target)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            n, 1,
            "'{rel}' {source}→{target} must be in force after the mark: the two \
             pair-unique relationships have separate indexes and do not collide"
        );
    }
    let on_dup: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE (source_id = $1 OR target_id = $1) \
            AND relationship IN ('alternative_of', 'shifted_to') AND valid_to IS NULL",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(on_dup, 0, "nothing pair-keyed stays in force on the dup");
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_missing_canonical(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let dup = seed_claim(&pool, agent, "dup").await;
    let bogus = Uuid::new_v4();
    let err =
        ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(dup), ClaimId::from_uuid(bogus))
            .await
            .err()
            .unwrap();
    assert!(matches!(err, DbError::NotFound { .. }), "{err:?}");
}

/// A dedup onto a claim that is no longer current is refused, whatever retired
/// it (a mark of its own, a supersession): it would build a chain the caller
/// never asked for, which the un-mark then refuses while the canonical stays
/// retired. Nothing is written: the duplicate stays current, with no
/// `supersedes` and no identity edge.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_retired_canonical(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let c1 = seed_claim(&pool, agent, "first canonical").await;
    let c2 = seed_claim(&pool, agent, "newer canonical").await;
    let s = seed_claim(&pool, agent, "superseded canonical").await;
    let d = seed_claim(&pool, agent, "duplicate").await;
    ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(c1), ClaimId::from_uuid(c2))
        .await
        .expect("calibration: c1 marked onto the current c2");
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(s)
            .fetch_one(&pool)
            .await
            .expect("the superseded claim's author");
    ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(s),
        "superseded canonical, revised",
        epigraph_core::TruthValue::clamped(0.5),
        "revision",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede s");

    for retired in [c1, s] {
        let mut conn = pool.acquire().await.unwrap();
        let err = ClaimRepository::mark_duplicate_act_attributed_conn(
            &mut conn,
            None,
            ClaimId::from_uuid(d),
            ClaimId::from_uuid(retired),
            &epigraph_db::DuplicateProvenance::new(
                "test",
                epigraph_db::DuplicateProvenance::RULE_CALLER_ASSERTED,
            ),
        )
        .await
        .expect_err("a mark onto a retired canonical is refused");
        assert!(
            // A STATE refusal (operator ruling R-55): HTTP answers it 409.
            matches!(
                err,
                DbError::Refused {
                    kind: RefusalKind::State,
                    ..
                }
            ) && format!("{err:?}").contains("not current"),
            "{err:?}"
        );
        let (sup, current): (Option<Uuid>, bool) =
            sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
                .bind(d)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((sup, current), (None, true), "the duplicate is untouched");
        let identity: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
        )
        .bind(d)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(identity, 0, "no identity edge was written");
    }
}
