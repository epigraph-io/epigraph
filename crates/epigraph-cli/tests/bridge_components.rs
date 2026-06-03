use epigraph_cli::bridge::components::{
    compute_components, ComponentSummary, STRUCTURAL_RELATIONSHIPS,
};
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

async fn seed_claim(pool: &PgPool, agent_id: Uuid, level: i32) -> Uuid {
    let id = Uuid::new_v4();
    let hash_bytes: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', $5::int))",
    )
    .bind(id)
    .bind(format!("c-{id}"))
    .bind(hash_bytes)
    .bind(agent_id)
    .bind(level)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_edge(
    pool: &PgPool,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)",
    )
    .bind(source_id)
    .bind(source_type)
    .bind(target_id)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_isolated_components(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // Section A with paragraphs A1, A2 linked by continues_argument.
    let s_a = seed_claim(&pool, agent, 1).await;
    let p_a1 = seed_claim(&pool, agent, 2).await;
    let p_a2 = seed_claim(&pool, agent, 2).await;
    seed_edge(&pool, s_a, "claim", p_a1, "claim", "decomposes_to").await;
    seed_edge(&pool, s_a, "claim", p_a2, "claim", "decomposes_to").await;
    seed_edge(&pool, p_a1, "claim", p_a2, "claim", "continues_argument").await;

    // Section B with paragraphs B1, B2 — no edge between A and B.
    let s_b = seed_claim(&pool, agent, 1).await;
    let p_b1 = seed_claim(&pool, agent, 2).await;
    let p_b2 = seed_claim(&pool, agent, 2).await;
    seed_edge(&pool, s_b, "claim", p_b1, "claim", "decomposes_to").await;
    seed_edge(&pool, s_b, "claim", p_b2, "claim", "decomposes_to").await;
    seed_edge(&pool, p_b1, "claim", p_b2, "claim", "continues_argument").await;

    let components = compute_components(&pool).await.unwrap();
    let sizes: Vec<usize> = components.iter().map(|c| c.size).collect();
    assert!(
        sizes.contains(&3),
        "section A's 3-claim component must appear; got sizes={sizes:?}"
    );
    assert_eq!(
        sizes.iter().filter(|&&s| s == 3).count(),
        2,
        "exactly two 3-claim components expected (A and B); got sizes={sizes:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn shared_atom_unifies_components(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // Two paragraphs in different sections, each decomposes_to a distinct atom.
    // Then a CORROBORATES between the two atoms unifies the whole structure.
    let p1 = seed_claim(&pool, agent, 2).await;
    let a1 = seed_claim(&pool, agent, 3).await;
    seed_edge(&pool, p1, "claim", a1, "claim", "decomposes_to").await;

    let p2 = seed_claim(&pool, agent, 2).await;
    let a2 = seed_claim(&pool, agent, 3).await;
    seed_edge(&pool, p2, "claim", a2, "claim", "decomposes_to").await;

    seed_edge(&pool, a1, "claim", a2, "claim", "CORROBORATES").await;

    let components = compute_components(&pool).await.unwrap();
    let large = components
        .iter()
        .find(|c| c.size == 4)
        .expect("expected 1 component of size 4 (p1, a1, p2, a2)");
    assert!(large.claim_ids.contains(&p1));
    assert!(large.claim_ids.contains(&p2));
    assert!(large.claim_ids.contains(&a1));
    assert!(large.claim_ids.contains(&a2));
}

#[test]
fn structural_relationships_includes_all_five() {
    let names: Vec<&str> = STRUCTURAL_RELATIONSHIPS.to_vec();
    for r in [
        "decomposes_to",
        "CORROBORATES",
        "same_as",
        "same_source",
        "continues_argument",
    ] {
        assert!(names.contains(&r), "missing {r}");
    }
}

#[allow(dead_code)]
fn _types_exist(_s: ComponentSummary) {}
