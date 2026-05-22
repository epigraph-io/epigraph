use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test");
                return;
            }
        }
    };
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn upsert_inserts_then_updates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id1 = repo
        .upsert(lo, hi, 0.7, serde_json::json!({}), "pending", None)
        .await
        .expect("first upsert");
    let id2 = repo
        .upsert(lo, hi, 0.9, serde_json::json!({"x": 1}), "pending", None)
        .await
        .expect("second upsert");
    assert_eq!(id1, id2, "upsert must reuse the row");

    let row = repo.get(id1).await.expect("get");
    assert!((row.score - 0.9).abs() < 1e-6);
    assert_eq!(row.features.get("x").and_then(|v| v.as_i64()), Some(1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_status_promotes_and_records_decided_fields(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let repo = MatchCandidateRepo::new(pool.clone());

    let id = repo
        .upsert(lo, hi, 0.9, serde_json::json!({}), "pending", None)
        .await
        .expect("upsert");
    repo.set_status(id, "promoted", Some(agent))
        .await
        .expect("set_status");

    let row = repo.get(id).await.expect("get");
    assert_eq!(row.status, "promoted");
    assert_eq!(row.decided_by, Some(agent));
    assert!(row.decided_at.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_pending_orders_by_score_desc(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claims: Vec<Uuid> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(insert_claim(&pool, agent).await);
        }
        v
    };
    let repo = MatchCandidateRepo::new(pool.clone());
    // Three pending candidates with descending scores.
    let scores = [0.5_f32, 0.9, 0.7];
    for i in 0..3 {
        let (lo, hi) = {
            let (a, b) = (claims[i], claims[(i + 1) % 3]);
            if a < b {
                (a, b)
            } else {
                (b, a)
            }
        };
        repo.upsert(lo, hi, scores[i], serde_json::json!({}), "pending", None)
            .await
            .expect("upsert");
    }
    let rows = repo.list_pending(10).await.expect("list");
    let our: Vec<f32> = rows
        .iter()
        .filter(|r| claims.contains(&r.claim_a) && claims.contains(&r.claim_b))
        .map(|r| r.score)
        .collect();
    assert!(
        our.len() >= 3,
        "expected at least 3 of our rows in list_pending"
    );
    // Each consecutive pair must satisfy score[i] >= score[i+1].
    for w in our.windows(2) {
        assert!(
            w[0] >= w[1],
            "list_pending must be desc by score; got {:?}",
            our
        );
    }
}
