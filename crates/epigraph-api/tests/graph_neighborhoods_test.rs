#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn neighborhoods_expand_compound_returns_compound_nodes_with_induced_edges() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    // Wipe local fixture rows.
    sqlx::query("DELETE FROM neighborhood_edges").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM claim_neighborhood_membership").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_neighborhoods").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_cluster_runs").execute(&pool).await.unwrap();

    let agent_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('CC', 32), 'hex'), 'compound-test', 'system') \
         ON CONFLICT (id) DO NOTHING"
    ).bind(agent_id).execute(&pool).await.unwrap();

    let run_id = Uuid::new_v4();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)")
        .bind(run_id).execute(&pool).await.unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'CompoundTest', '', 0)")
        .bind(theme_id).execute(&pool).await.unwrap();

    // Helper closure to insert a claim row.
    async fn ins_claim(pool: &sqlx::PgPool, content: &str, agent: Uuid, theme: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id.as_bytes().iter().chain(id.as_bytes().iter()).copied().collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)"
        ).bind(id).bind(content).bind(hash).bind(agent).bind(theme).execute(pool).await.unwrap();
        id
    }

    async fn ins_edge(pool: &sqlx::PgPool, src: Uuid, tgt: Uuid, rel: &str) {
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
             VALUES ($1, $2, 'claim', 'claim', $3)"
        ).bind(src).bind(tgt).bind(rel).execute(pool).await.unwrap();
    }

    // Two compound parents, each decomposing to two atoms; one cross-compound atom-edge.
    let compound_a = ins_claim(&pool, "compound-A", agent_id, Some(theme_id)).await;
    let compound_b = ins_claim(&pool, "compound-B", agent_id, Some(theme_id)).await;
    let atom_a1 = ins_claim(&pool, "atom-a1", agent_id, Some(theme_id)).await;
    let atom_a2 = ins_claim(&pool, "atom-a2", agent_id, Some(theme_id)).await;
    let atom_b1 = ins_claim(&pool, "atom-b1", agent_id, Some(theme_id)).await;
    let atom_b2 = ins_claim(&pool, "atom-b2", agent_id, Some(theme_id)).await;

    ins_edge(&pool, compound_a, atom_a1, "decomposes_to").await;
    ins_edge(&pool, compound_a, atom_a2, "decomposes_to").await;
    ins_edge(&pool, compound_b, atom_b1, "decomposes_to").await;
    ins_edge(&pool, compound_b, atom_b2, "decomposes_to").await;

    // One cross-compound SUPPORTS atom edge (forward_strength 0.7).
    ins_edge(&pool, atom_a1, atom_b1, "SUPPORTS").await;

    // Seed one neighborhood that holds all 4 atoms.
    let nbr = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
         VALUES ($1, $2, $3, 'all-atoms', 4, NULL, NULL)"
    ).bind(nbr).bind(run_id).bind(theme_id).execute(&pool).await.unwrap();
    for atom in [atom_a1, atom_a2, atom_b1, atom_b2] {
        sqlx::query(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
             VALUES ($1, $2, $3)"
        ).bind(run_id).bind(atom).bind(nbr).execute(&pool).await.unwrap();
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/neighborhoods/{nbr}/expand?mode=compound"))
        .header("Authorization", format!("Bearer {}", common::test_bearer_token()))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "compound expand should return 200");
    let body: Value = resp.json().await.unwrap();

    let nodes = body["nodes"].as_array().unwrap();
    let kinds: Vec<&str> = nodes.iter().map(|n| n["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds.iter().filter(|k| **k == "compound").count(), 2, "expected 2 compound nodes");

    let induced = body["induced_edges"].as_array().unwrap();
    assert_eq!(induced.len(), 1, "one cross-compound atom edge → one induced compound edge");
    assert_eq!(induced[0]["relationship"].as_str().unwrap(), "SUPPORTS");
    assert!((induced[0]["strength"].as_f64().unwrap() - 0.7).abs() < 1e-9);
    assert_eq!(induced[0]["atom_edge_count"].as_i64().unwrap(), 1);

    let direct = body["direct_edges"].as_array().unwrap();
    assert_eq!(direct.len(), 0, "no direct compound-compound edges seeded");
}

#[tokio::test(flavor = "multi_thread")]
async fn neighborhoods_expand_atomic_returns_atoms_and_compound_groups() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();

    sqlx::query("DELETE FROM neighborhood_edges").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM claim_neighborhood_membership").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_neighborhoods").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM graph_cluster_runs").execute(&pool).await.unwrap();

    let agent_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('CC', 32), 'hex'), 'atomic-test', 'system') \
         ON CONFLICT (id) DO NOTHING"
    ).bind(agent_id).execute(&pool).await.unwrap();

    let run_id = Uuid::new_v4();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)")
        .bind(run_id).execute(&pool).await.unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'AtomicTest', '', 0)")
        .bind(theme_id).execute(&pool).await.unwrap();

    async fn ins_claim(pool: &sqlx::PgPool, content: &str, agent: Uuid, theme: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id.as_bytes().iter().chain(id.as_bytes().iter()).copied().collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)"
        ).bind(id).bind(content).bind(hash).bind(agent).bind(theme).execute(pool).await.unwrap();
        id
    }
    async fn ins_edge(pool: &sqlx::PgPool, src: Uuid, tgt: Uuid, rel: &str) {
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
             VALUES ($1, $2, 'claim', 'claim', $3)"
        ).bind(src).bind(tgt).bind(rel).execute(pool).await.unwrap();
    }

    // One compound with two atom children + one truly-standalone (no decomposes_to in either direction).
    let compound_a = ins_claim(&pool, "compound-A", agent_id, Some(theme_id)).await;
    let atom_a1 = ins_claim(&pool, "atom-a1", agent_id, Some(theme_id)).await;
    let atom_a2 = ins_claim(&pool, "atom-a2", agent_id, Some(theme_id)).await;
    let standalone = ins_claim(&pool, "standalone", agent_id, Some(theme_id)).await;
    ins_edge(&pool, compound_a, atom_a1, "decomposes_to").await;
    ins_edge(&pool, compound_a, atom_a2, "decomposes_to").await;
    // One SUPPORTS edge between atoms inside the same compound (will appear in atomic-mode edges output).
    ins_edge(&pool, atom_a1, atom_a2, "SUPPORTS").await;

    // Seed neighborhood holding all three claim-level nodes (a1, a2, standalone).
    let nbr = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
         VALUES ($1, $2, $3, 'all-atoms', 3, NULL, NULL)"
    ).bind(nbr).bind(run_id).bind(theme_id).execute(&pool).await.unwrap();
    for atom in [atom_a1, atom_a2, standalone] {
        sqlx::query(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
             VALUES ($1, $2, $3)"
        ).bind(run_id).bind(atom).bind(nbr).execute(&pool).await.unwrap();
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/neighborhoods/{nbr}/expand?mode=atomic"))
        .header("Authorization", format!("Bearer {}", common::test_bearer_token()))
        .send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();

    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3, "expected 3 atomic nodes (a1, a2, standalone)");

    // Standalone has compound_id=null; both a1 and a2 have compound_id = compound_a.
    let mut compound_ids: Vec<Option<String>> = nodes.iter()
        .map(|n| n["compound_id"].as_str().map(String::from))
        .collect();
    compound_ids.sort();
    assert!(compound_ids.iter().any(|c| c.is_none()), "standalone should have compound_id=null");
    let with_compound: Vec<&Option<String>> = compound_ids.iter().filter(|c| c.is_some()).collect();
    assert_eq!(with_compound.len(), 2, "two atoms should have compound_id set");

    let edges = body["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1, "expected one atom→atom SUPPORTS edge");
    assert_eq!(edges[0]["relationship"].as_str().unwrap(), "SUPPORTS");

    let groups = body["compound_groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "one compound group for compound-A");
    assert_eq!(groups[0]["compound_id"].as_str().unwrap(), compound_a.to_string());
    let members = groups[0]["member_atom_ids"].as_array().unwrap();
    assert_eq!(members.len(), 2, "compound-A has two atom members in this neighborhood");
}
