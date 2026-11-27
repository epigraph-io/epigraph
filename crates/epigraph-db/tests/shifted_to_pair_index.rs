//! Migration 358 (`edges_shifted_to_pair_uniq`, backlog d639d492): the
//! anti-symmetric pair key of the `shifted_to` temporal-succession edge.
//!
//! `A shifted_to B` says B's value replaced A's. The reversal `B shifted_to A`
//! is a temporal contradiction, not a second fact, so the index refuses it as
//! well as the exact duplicate. A chain `A -> B -> C` stays legal, and a
//! RETRACTED row does not hold the pair (091's rule, the one deliberate
//! divergence from the ported source). The undo runbook drops the index.

use epigraph_crypto::AgentSigner;
use epigraph_db::repos::edge::EdgeRepository;
use epigraph_db::repos::edge_signature::EdgeSigningKey;
use epigraph_db::{DbError, RefusalKind, SHIFTED_TO_PAIR_INDEX, SHIFTED_TO_PAIR_REFUSAL};
use sqlx::PgPool;
use uuid::Uuid;

const INDEX: &str = SHIFTED_TO_PAIR_INDEX;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn try_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    rel: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
}

async fn try_typed_edge(
    pool: &PgPool,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    rel: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(rel)
    .fetch_one(pool)
    .await
}

/// The document ingest's edge writer, on a connection of its own, exactly as
/// `ingest_document`'s walk calls it for a caller's relationship.
async fn ingest_writer(
    pool: &PgPool,
    key: Option<EdgeSigningKey<'_>>,
    source: Uuid,
    target: Uuid,
) -> Result<bool, DbError> {
    let mut conn = pool.acquire().await.expect("acquire");
    EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut conn,
        key,
        source,
        "claim",
        target,
        "claim",
        "shifted_to",
        None,
        None,
        None,
    )
    .await
    .map(|(_, created)| created)
}

/// A collision on THIS index reaches the caller as the designed STATE
/// refusal, with its own text, not as `DuplicateKey` or an opaque fault.
fn assert_designed_refusal(res: Result<bool, DbError>, what: &str) {
    match res {
        Err(DbError::Refused {
            kind: RefusalKind::State,
            message,
        }) => {
            assert_eq!(message, SHIFTED_TO_PAIR_REFUSAL, "{what}");
            assert!(message.contains("shifted_to"), "{what}: {message}");
        }
        other => panic!("{what}: expected the designed STATE refusal, got {other:?}"),
    }
}

/// The error is a unique violation of THIS index, not of some other one.
fn assert_refused_by_pair_index(res: Result<Uuid, sqlx::Error>, what: &str) {
    let err = res.expect_err(what);
    let db = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{what}: {err:?}"));
    assert_eq!(db.code().as_deref(), Some("23505"), "{what}: {err:?}");
    assert_eq!(db.constraint(), Some(INDEX), "{what}: {err:?}");
}

async fn index_exists(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes \
                         WHERE schemaname = 'public' AND indexname = $1)",
    )
    .bind(INDEX)
    .fetch_one(pool)
    .await
    .expect("pg_indexes")
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_duplicate_and_a_reversal_are_refused(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;

    try_edge(&pool, a, b, "shifted_to")
        .await
        .expect("the first succession is admitted");
    assert_refused_by_pair_index(
        try_edge(&pool, a, b, "shifted_to").await,
        "an exact duplicate must be refused",
    );
    assert_refused_by_pair_index(
        try_edge(&pool, b, a, "shifted_to").await,
        "the reversal must be refused: each value cannot have succeeded the other",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_chain_and_other_relationships_on_the_pair_are_admitted(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;
    let c = seed_claim(&pool, agent, "ceiling 1500/s").await;

    try_edge(&pool, a, b, "shifted_to").await.expect("a -> b");
    try_edge(&pool, b, c, "shifted_to")
        .await
        .expect("b -> c: not unique on source or target, a chain is legal");
    try_edge(&pool, a, c, "shifted_to")
        .await
        .expect("a -> c: a different pair");
    // Separate partial indexes: another pair-keyed relationship, and an
    // ordinary one, over the same pair do not collide with `shifted_to`.
    try_edge(&pool, b, a, "alternative_of")
        .await
        .expect("alternative_of over the same pair");
    try_edge(&pool, b, a, "supports")
        .await
        .expect("supports over the same pair");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_succession_does_not_hold_the_pair(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;

    let wrong = try_edge(&pool, a, b, "shifted_to").await.expect("a -> b");
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(wrong)
        .execute(&pool)
        .await
        .expect("retract");
    try_edge(&pool, b, a, "shifted_to")
        .await
        .expect("the corrected direction is admitted once the wrong one is retracted");
    try_edge(&pool, a, b, "shifted_to")
        .await
        .expect_err("calibration: an in-force b -> a still holds the pair");
}

/// A pin, not a proof of this change: `shifted_to` has no
/// `edge_to_factor_type` row (175's body is an exact-match table with no
/// fallback), so inserting one mints no belief-propagation factor. A
/// `supports` edge over the same pair does, which shows the trigger runs.
#[sqlx::test(migrations = "../../migrations")]
async fn shifted_to_maps_to_no_factor(pool: PgPool) {
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edge_to_factor_type('shifted_to')")
        .fetch_one(&pool)
        .await
        .expect("edge_to_factor_type");
    assert_eq!(rows, 0, "shifted_to must map to no factor type");

    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;
    let shift = try_edge(&pool, a, b, "shifted_to").await.expect("shift");
    let support = try_edge(&pool, a, b, "supports").await.expect("supports");
    let factors = |edge: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM factors WHERE properties->>'source_edge_id' = $1::text",
            )
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("factors")
        }
    };
    assert_eq!(factors(shift).await, 0, "a shifted_to edge mints no factor");
    assert!(
        factors(support).await > 0,
        "calibration: a supports edge over the same pair does"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_358_undo_drops_the_pair_index(pool: PgPool) {
    assert!(index_exists(&pool).await, "358 created the index");
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;
    try_edge(&pool, a, b, "shifted_to").await.expect("a -> b");

    sqlx::raw_sql(&repo_file("docs/runbooks/358-undo.sql"))
        .execute(&pool)
        .await
        .expect("the undo runs as one statement outside a transaction");
    assert!(!index_exists(&pool).await, "the undo dropped the index");
    try_edge(&pool, b, a, "shifted_to")
        .await
        .expect("without the index the reversal is no longer refused");

    sqlx::raw_sql(&repo_file("docs/runbooks/358-undo.sql"))
        .execute(&pool)
        .await
        .expect("the undo is idempotent");
}

/// Review finding: the document ingest already stores a caller's
/// `shifted_to` verbatim, so after 358 an ingest that reverses (or, through a
/// writer that dedups by direction only, duplicates) an in-force succession
/// trips the index. Its writer must answer with the designed refusal, on the
/// unsigned and on the signed (attested-at-INSERT) path alike, and an
/// ordinary unique violation elsewhere keeps `DuplicateKey`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_writer_answers_a_pair_collision_with_the_designed_refusal(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x58; 32]).expect("signer");
    let agent = seed_agent(&pool).await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(agent)
        .bind(signer.public_key().as_slice())
        .execute(&pool)
        .await
        .expect("register the signer's key");
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;
    let b = seed_claim(&pool, agent, "ceiling 900/s").await;

    assert!(
        ingest_writer(&pool, None, a, b).await.expect("a -> b"),
        "the first succession is written"
    );
    assert!(
        !ingest_writer(&pool, None, a, b)
            .await
            .expect("a -> b again"),
        "calibration: the same direction is the writer's own dedup hit, not a refusal"
    );
    assert_designed_refusal(
        ingest_writer(&pool, None, b, a).await,
        "an unsigned reversal",
    );
    let key = Some(EdgeSigningKey {
        signer: &signer,
        signer_id: agent,
    });
    assert_designed_refusal(ingest_writer(&pool, key, b, a).await, "a signed reversal");

    // Only THIS index is re-classified: a unique violation of another index
    // (042's alternative_of pair key) is still `DuplicateKey`.
    let mut conn = pool.acquire().await.expect("acquire");
    for (s, t) in [(a, b), (b, a)] {
        let res = EdgeRepository::create_signed_conn(
            &mut conn,
            None,
            s,
            "claim",
            t,
            "claim",
            "alternative_of",
            None,
            None,
            None,
        )
        .await;
        if s == b {
            assert!(
                matches!(res, Err(DbError::DuplicateKey { .. })),
                "another pair index keeps its classification: {res:?}"
            );
        } else {
            res.expect("the first alternative_of");
        }
    }
}

/// Review finding: the merge paths' pair guard sees claim/claim edges only,
/// so the index is narrowed to them. A `shifted_to` with a non-claim end
/// (here an agent) does not hold the pair, in either direction.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_claim_endpoint_is_outside_the_pair_index(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, "ceiling 400/s").await;

    try_typed_edge(&pool, (agent, "agent"), (a, "claim"), "shifted_to")
        .await
        .expect("agent -> claim");
    try_typed_edge(&pool, (a, "claim"), (agent, "agent"), "shifted_to")
        .await
        .expect("the reversal over a non-claim end is outside the claim/claim index");
    try_typed_edge(&pool, (agent, "agent"), (a, "claim"), "shifted_to")
        .await
        .expect("so is the duplicate");
}
