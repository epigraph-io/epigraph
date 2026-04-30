//! Shared test helpers for epigraph-jobs integration tests.

/// Truncate all three neighborhood tables before a test run.
///
/// Uses `TRUNCATE … CASCADE` in dependency order (child tables first) rather
/// than `DELETE`, which is orders-of-magnitude faster on large tables and
/// avoids spending minutes on cascade deletes when `graph_neighborhoods` has
/// accumulated hundreds of thousands of rows from prior runs.
pub async fn reset_neighborhood_tables(pool: &sqlx::PgPool) {
    // Child tables first so FK constraints aren't violated.
    for table in &[
        "neighborhood_edges",
        "claim_neighborhood_membership",
        "graph_neighborhoods",
    ] {
        sqlx::query(&format!("TRUNCATE {table} CASCADE"))
            .execute(pool)
            .await
            .unwrap();
    }
}

/// Seeds a fresh run_id, one `claim_themes` row, six atoms in two cliques,
/// and one truly-standalone claim assigned to the same theme (no edges).
///
/// Graph topology (all edges SUPPORTS):
/// ```text
///   Clique 1: a - b - c - a   (3 atoms)
///   Clique 2: d - e - f - d   (3 atoms)
///   Cross:    a → d           (weight 0.7)
///   Standalone: s             (no edges in either direction)
/// ```
///
/// With Louvain + resolution=1.0 the a-b-c group forms one community,
/// d-e-f forms another, and s forms a singleton, for exactly **3 neighborhoods**
/// totalling 7 claims.
///
/// The cross edge a→d (forward_strength=0.7) produces one `neighborhood_edge`
/// with weight 0.7 after the cross-neighborhood edge pass.
///
/// Returns `(run_id, theme_id, atom_ids[6], standalone_id)`.
pub async fn seed_two_clique_theme(
    pool: &sqlx::PgPool,
) -> (uuid::Uuid, uuid::Uuid, Vec<uuid::Uuid>, uuid::Uuid) {
    use uuid::Uuid;

    // 1. agent (idempotent)
    let agent_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    // Use a fixed but distinct public key (ends in 0xBB to avoid clashing with
    // other test agents that use all-zeros keys).
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type)
         VALUES ($1, decode(repeat('bb', 32), 'hex'), 'theme-test', 'system')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .unwrap();

    // 2. cluster run record (required FK for graph_neighborhoods)
    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .unwrap();

    // 3. theme
    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description, claim_count)
         VALUES ($1, 'TestTheme', '', 7)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(theme_id)
    .execute(pool)
    .await
    .unwrap();

    // 4. six atoms (atoms[0..=2] = clique 1, atoms[3..=5] = clique 2)
    let mut atoms = Vec::new();
    for i in 0..6usize {
        let id = Uuid::new_v4();
        // 32-byte content hash (safe unique surrogate)
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id)
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(format!("atom-{i}"))
        .bind(hash)
        .bind(agent_id)
        .bind(theme_id)
        .execute(pool)
        .await
        .unwrap();
        atoms.push(id);
    }

    // 5. SUPPORTS edges
    //    Clique 1: a↔b, b↔c, c↔a
    //    Clique 2: d↔e, e↔f, f↔d
    //    Cross:    a → d  (this will appear as neighborhood_edge weight 0.7)
    let edges: &[(usize, usize)] = &[
        (0, 1),
        (1, 2),
        (2, 0), // clique 1
        (3, 4),
        (4, 5),
        (5, 3), // clique 2
        (0, 3), // cross-clique
    ];
    for &(s, t) in edges {
        sqlx::query(
            "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
             VALUES ($1, $2, 'claim', 'claim', 'SUPPORTS')",
        )
        .bind(atoms[s])
        .bind(atoms[t])
        .execute(pool)
        .await
        .unwrap();
    }

    // 6. standalone — no edges in either direction, so Louvain places it in its
    //    own singleton neighborhood (7 total claims, 3 neighborhoods).
    let standalone = Uuid::new_v4();
    let hash: Vec<u8> = standalone
        .as_bytes()
        .iter()
        .chain(standalone.as_bytes().iter())
        .copied()
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id)
         VALUES ($1, 'standalone', $2, $3, 0.5, $4)",
    )
    .bind(standalone)
    .bind(hash)
    .bind(agent_id)
    .bind(theme_id)
    .execute(pool)
    .await
    .unwrap();

    (run_id, theme_id, atoms, standalone)
}
