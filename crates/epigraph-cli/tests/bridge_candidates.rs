//! `bridge::candidates::build_candidate_table`: top-K / threshold selection,
//! the two table lifetimes, and the TEMP table built and read as a real
//! maintenance login (no CREATE on schema `public`, by design).

mod viewer_fixture;

use epigraph_cli::bridge::candidates::{
    build_candidate_table, drop_candidate_table, CandidateTableLifetime,
};
use epigraph_cli::bridge::spine::compute_spine_destination;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

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

/// Seed a claim with a 1536-dim unit-ish embedding split across two axes.
/// `axis0` is the magnitude on axis 0, `axis1` is the magnitude on axis 1.
/// Because pgvector cosine distance ignores magnitude (direction only), tests
/// that need varying *similarity* must vary the direction — e.g. axis0=1, axis1=0
/// vs axis0=0, axis1=1 yields cosine similarity 0.
async fn seed_atom_with_embedding(pool: &PgPool, agent_id: Uuid, axis0: f64, axis1: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    let mut zeros = vec!["0.0".to_string(); 1536];
    zeros[0] = axis0.to_string();
    zeros[1] = axis1.to_string();
    let pgvec = format!("[{}]", zeros.join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3), $5::vector)",
    )
    .bind(id)
    .bind(format!("a-{id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(&pgvec)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn build_candidate_table_caps_at_top_k(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // 1 source atom on axis 0; 5 target atoms with mixed axis0/axis1 components.
    // Cosine similarity to [1, 0, ...] = axis0 / sqrt(axis0^2 + axis1^2), so
    // varying these changes direction (and therefore similarity), unlike
    // pure-magnitude scaling along a single axis.
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let mut targets = vec![];
    for (a, b) in [(1.0, 0.0), (1.0, 0.1), (1.0, 0.5), (1.0, 1.0), (0.0, 1.0)] {
        targets.push(seed_atom_with_embedding(&pool, agent, a, b).await);
    }

    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await.unwrap();
    let n = build_candidate_table(
        &mut tx,
        &table,
        CandidateTableLifetime::Transaction,
        &[src],
        &targets,
        0.5,
        3,
    )
    .await
    .unwrap();
    // Top-3 by similarity, all >= 0.5: should be 3 (mag 0.45 below threshold).
    // Actually similarity = 1 - cosine_distance which depends on the vectors;
    // the check below is the real assertion.
    let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(rows <= 3, "top_k=3 should cap at 3, got {rows}");
    assert_eq!(n as i64, rows);
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn build_candidate_table_filters_by_min_similarity(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    // Source on axis 0; close target also on axis 0 (cosine sim ~1.0);
    // far target on axis 1 (cosine sim 0).
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let close = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let far = seed_atom_with_embedding(&pool, agent, 0.0, 1.0).await;

    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await.unwrap();
    build_candidate_table(
        &mut tx,
        &table,
        CandidateTableLifetime::Transaction,
        &[src],
        &[close, far],
        0.95,
        10,
    )
    .await
    .unwrap();
    let row_ids: Vec<Uuid> = sqlx::query_scalar(&format!("SELECT target_id FROM {table}"))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert!(row_ids.contains(&close), "near match must appear");
    assert!(
        !row_ids.contains(&far),
        "far match must be filtered by min_similarity"
    );
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn rejects_unsafe_table_name(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    let result = build_candidate_table(
        &mut tx,
        "t; DROP TABLE x",
        CandidateTableLifetime::Transaction,
        &[],
        &[],
        0.5,
        10,
    )
    .await;
    assert!(result.is_err(), "unsafe table name must error");
}

/// Rows in `pg_class` named `table`, in any schema (a TEMP table lives in a
/// per-session `pg_temp_N`, which `pg_class` still lists from other sessions).
async fn relations_named(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_class WHERE relname = $1")
        .bind(table)
        .fetch_one(pool)
        .await
        .expect("pg_class probe")
}

/// Create a NOSUPERUSER login in `epigraph_maintenance` and return
/// `(role, dsn)`. The caller drops the role.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("bridge_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");
    (role, dsn)
}

/// The deployed shape: the bridge bins run on `MaintenancePool`, whose login
/// holds no CREATE on `public`. Before the TEMP table this failed at the
/// CREATE with `permission denied for schema public`.
///
/// Also pinned here:
/// - the read that follows the build (`compute_spine_destination`, given the
///   same transaction) sees the rows, and the table is invisible to any other
///   pooled connection while the transaction is open — so the visibility is
///   the same-session guarantee, not a shared table;
/// - a target that is group-private to a group the login is not a member of
///   is still selected, so the maintenance bypass holds on that session;
/// - after commit nothing named `table` exists in any schema.
#[sqlx::test(migrations = "../../migrations")]
async fn temp_candidate_table_builds_and_reads_as_a_maintenance_login(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let public_target = seed_atom_with_embedding(&pool, agent, 1.0, 0.1).await;
    let (owner, group) = fixture::seed_agent_with_group(&pool, "bridge-scratch").await;
    let private_target =
        fixture::seed_group_claim(&pool, owner, group, "bridge scratch private target").await;
    let mut v = vec!["0".to_string(); 1536];
    v[0] = "1".to_string();
    v[1] = "0.05".to_string();
    fixture::set_claim_embedding(&pool, private_target, &format!("[{}]", v.join(","))).await;
    // Theme the private target so the spine read has something to count.
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ('scratch-theme', 'test') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed theme");
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(private_target)
        .bind(theme)
        .execute(&pool)
        .await
        .expect("theme the target");

    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let (role, dsn) = maintenance_login(&pool).await;
    let outcome = async {
        let maint = epigraph_cli::MaintenancePool::connect_to(&dsn, "bridge-scratch-test")
            .await
            .expect("maintenance pool");
        let (create_on_public, temp_on_db): (bool, bool) = sqlx::query_as(
            "SELECT has_schema_privilege(current_user, 'public', 'CREATE'), \
                    has_database_privilege(current_database(), 'TEMPORARY')",
        )
        .fetch_one(maint.pool())
        .await
        .expect("privilege probe");

        let mut tx = maint.pool().begin().await.expect("begin");
        let built = build_candidate_table(
            &mut tx,
            &table,
            CandidateTableLifetime::Transaction,
            &[src],
            &[public_target, private_target],
            0.5,
            10,
        )
        .await;
        let targets: Vec<Uuid> = match &built {
            Ok(_) => sqlx::query_scalar(&format!("SELECT target_id FROM {table}"))
                .fetch_all(&mut *tx)
                .await
                .expect("read back in the owning transaction"),
            Err(_) => Vec::new(),
        };
        let spine = match &built {
            Ok(_) => compute_spine_destination(&mut tx, &table, 5)
                .await
                .expect("spine on the owning transaction"),
            Err(_) => Vec::new(),
        };
        let seen_elsewhere: Option<String> =
            sqlx::query_scalar(&format!("SELECT to_regclass('{table}')::text"))
                .fetch_one(maint.pool())
                .await
                .expect("to_regclass from another connection");
        tx.commit().await.expect("commit");
        (
            create_on_public,
            temp_on_db,
            built,
            targets,
            spine,
            seen_elsewhere,
        )
    }
    .await;

    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");

    let (create_on_public, temp_on_db, built, targets, spine, seen_elsewhere) = outcome;
    assert!(
        !create_on_public,
        "fixture: the maintenance login must NOT hold CREATE on public"
    );
    assert!(
        temp_on_db,
        "fixture: the maintenance login must hold TEMPORARY on the database"
    );
    let n = built.expect("build_candidate_table as the maintenance login");
    assert_eq!(n, 2, "both targets are above the threshold");
    assert!(
        targets.contains(&private_target),
        "the group-private target must be selected: the bypass must hold on the \
         transaction that builds the table"
    );
    assert!(targets.contains(&public_target));
    assert_eq!(
        spine
            .iter()
            .map(|u| u.umbrella.as_str())
            .collect::<Vec<_>>(),
        vec!["scratch-theme"],
        "the spine read must see the rows in the owning transaction"
    );
    assert_eq!(
        seen_elsewhere, None,
        "a TEMP table must be invisible to any other pooled connection"
    );
    assert_eq!(
        relations_named(&pool, &table).await,
        0,
        "the TEMP table must not outlive its transaction"
    );
}

/// Every early return in the bins drops the transaction rather than
/// committing it. The rollback must take the TEMP table with it.
///
/// Observed on the SAME connection: an uncommitted catalog row is invisible to
/// every other session whether or not it is later rolled back, so only the
/// owning session can tell a rollback from a still-open transaction.
#[sqlx::test(migrations = "../../migrations")]
async fn temp_candidate_table_is_gone_after_a_rollback(pool: PgPool) {
    use sqlx::Connection as _;
    let agent = seed_agent(&pool).await;
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let close = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let probe = format!("SELECT to_regclass('{table}')::text");

    let mut conn = pool.acquire().await.unwrap();
    {
        let mut tx = conn.begin().await.unwrap();
        let n = build_candidate_table(
            &mut tx,
            &table,
            CandidateTableLifetime::Transaction,
            &[src],
            &[close],
            0.5,
            10,
        )
        .await
        .unwrap();
        assert_eq!(n, 1);
        let open: Option<String> = sqlx::query_scalar(&probe)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(
            open.is_some(),
            "the table exists while its transaction is open"
        );
        // `tx` dropped without commit: the early-return path.
    }
    // sqlx queues the ROLLBACK on drop and sends it before the next statement.
    let after: Option<String> = sqlx::query_scalar(&probe)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        after, None,
        "a rolled-back transaction must take its TEMP table with it"
    );
}

/// `--keep-tables`: a `Persistent` table survives the commit, is readable
/// from any connection (e.g. a later `rerank_bridges --candidates-table`),
/// and `drop_candidate_table` removes it. Run as the cluster superuser, since
/// this lifetime needs CREATE on the schema.
#[sqlx::test(migrations = "../../migrations")]
async fn persistent_candidate_table_outlives_its_transaction(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let src = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let close = seed_atom_with_embedding(&pool, agent, 1.0, 0.0).await;
    let table = format!("test_cands_{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await.unwrap();
    build_candidate_table(
        &mut tx,
        &table,
        CandidateTableLifetime::Persistent,
        &[src],
        &[close],
        0.5,
        10,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let rows: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(&pool)
        .await
        .expect("a kept table is readable from any connection");
    assert_eq!(rows, 1);

    drop_candidate_table(&pool, &table).await.unwrap();
    assert_eq!(relations_named(&pool, &table).await, 0);
}
