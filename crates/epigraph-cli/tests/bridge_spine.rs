//! Integration tests for `compute_spine_destination`.
//!
//! Schema reminder: themes are stored in `claim_themes(id, label, ...)` and
//! referenced via the `claims.theme_id` FK. A claim with `theme_id IS NULL`
//! has no umbrella and is excluded from the aggregation.

use epigraph_cli::bridge::spine::compute_spine_destination;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_atom(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3))",
    )
    .bind(id)
    .bind(format!("a-{id}"))
    .bind(hash)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label) VALUES ($1, $2)")
        .bind(id)
        .bind(label)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn assign_theme(pool: &PgPool, claim_id: Uuid, theme_id: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
        .bind(theme_id)
        .bind(claim_id)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_aggregates_top_themes(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s = seed_atom(&pool, agent).await;

    let t_a = seed_atom(&pool, agent).await; // theme A
    let t_b = seed_atom(&pool, agent).await; // theme A
    let t_c = seed_atom(&pool, agent).await; // theme B
    let t_d = seed_atom(&pool, agent).await; // no theme

    let theme_a = seed_theme(&pool, "A").await;
    let theme_b = seed_theme(&pool, "B").await;
    assign_theme(&pool, t_a, theme_a).await;
    assign_theme(&pool, t_b, theme_a).await;
    assign_theme(&pool, t_c, theme_b).await;
    // t_d intentionally left untouched.

    // Build candidate table.
    let table = format!("test_spine_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table} (source_id uuid, target_id uuid, similarity float8)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for tgt in [t_a, t_b, t_c, t_d] {
        sqlx::query(&format!(
            "INSERT INTO {table} (source_id, target_id, similarity) VALUES ($1, $2, 0.8)"
        ))
        .bind(s)
        .bind(tgt)
        .execute(&pool)
        .await
        .unwrap();
    }

    let umbrellas = compute_spine_destination(&pool, &table, 3).await.unwrap();

    // 3 of 4 candidates have themes (t_d is dropped).
    // Total = 3. A weight = 2/3, B weight = 1/3.
    let a = umbrellas
        .iter()
        .find(|u| u.umbrella == "A")
        .expect("missing A");
    let b = umbrellas
        .iter()
        .find(|u| u.umbrella == "B")
        .expect("missing B");
    assert_eq!(a.count, 2);
    assert_eq!(b.count, 1);
    assert!((a.weight - 2.0 / 3.0).abs() < 1e-9);
    assert!((b.weight - 1.0 / 3.0).abs() < 1e-9);
    assert_eq!(umbrellas.len(), 2, "only A and B should appear");

    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_returns_empty_when_no_targets_have_themes(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s = seed_atom(&pool, agent).await;
    let t = seed_atom(&pool, agent).await;

    let table = format!("test_spine_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table} (source_id uuid, target_id uuid, similarity float8)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {table} (source_id, target_id, similarity) VALUES ($1, $2, 0.8)"
    ))
    .bind(s)
    .bind(t)
    .execute(&pool)
    .await
    .unwrap();

    let umbrellas = compute_spine_destination(&pool, &table, 3).await.unwrap();
    assert!(umbrellas.is_empty());

    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_top_n_truncates_lowest_weight_umbrellas(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s = seed_atom(&pool, agent).await;

    let t_a1 = seed_atom(&pool, agent).await;
    let t_a2 = seed_atom(&pool, agent).await;
    let t_a3 = seed_atom(&pool, agent).await;
    let t_b1 = seed_atom(&pool, agent).await;
    let t_b2 = seed_atom(&pool, agent).await;
    let t_c1 = seed_atom(&pool, agent).await;

    let theme_a = seed_theme(&pool, "A").await;
    let theme_b = seed_theme(&pool, "B").await;
    let theme_c = seed_theme(&pool, "C").await;
    for tgt in [t_a1, t_a2, t_a3] {
        assign_theme(&pool, tgt, theme_a).await;
    }
    for tgt in [t_b1, t_b2] {
        assign_theme(&pool, tgt, theme_b).await;
    }
    assign_theme(&pool, t_c1, theme_c).await;

    let table = format!("test_spine_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table} (source_id uuid, target_id uuid, similarity float8)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for tgt in [t_a1, t_a2, t_a3, t_b1, t_b2, t_c1] {
        sqlx::query(&format!(
            "INSERT INTO {table} (source_id, target_id, similarity) VALUES ($1, $2, 0.8)"
        ))
        .bind(s)
        .bind(tgt)
        .execute(&pool)
        .await
        .unwrap();
    }

    // top_n = 2 → C is dropped, A and B remain ordered by count desc.
    let umbrellas = compute_spine_destination(&pool, &table, 2).await.unwrap();
    assert_eq!(umbrellas.len(), 2);
    assert_eq!(umbrellas[0].umbrella, "A");
    assert_eq!(umbrellas[0].count, 3);
    assert_eq!(umbrellas[1].umbrella, "B");
    assert_eq!(umbrellas[1].count, 2);

    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&pool)
        .await
        .unwrap();
}
