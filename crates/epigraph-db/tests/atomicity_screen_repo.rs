//! `AtomicityScreenRepository` (backlogs `72850d43`, `c4a8436b`): the
//! in-query viewer predicate alone.
//!
//! These tests run on the test pool's owner login, which row security does
//! not filter, so every row the stranger must not see is hidden ONLY by the
//! `/* {VISIBILITY} */` and `/* {EDGE_VISIBILITY} */` markers the repo splices.
//! (`epigraph-mcp/tests/atomicity_screen_tools.rs` runs the same reads on the
//! application role, where session row security also hides them.)

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{AtomicityScreenRepository, ScreenPopulation};
use sqlx::PgPool;
use uuid::Uuid;

async fn decomposes(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("decomposes_to edge")
}

struct World {
    member: Uuid,
    stranger: Uuid,
    parent: Uuid,
    atom: Uuid,
    child: Uuid,
    private: Uuid,
}

/// A public parent with a public atom; the atom has one public child through
/// an edge private to the member's group; a group-private claim is the
/// atom's second child through an ordinary (trigger-stamped) edge.
async fn seed(pool: &PgPool) -> World {
    let (member, group) = fixture::seed_agent_with_group(pool, "b42repo").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "b42repo-stranger").await;
    let parent = fixture::seed_public_claim(pool, member, "A rose. B fell. C held.").await;
    let atom = fixture::seed_public_claim(pool, member, "A rose, and B fell.").await;
    let child = fixture::seed_public_claim(pool, member, "A rose sharply.").await;
    let private = fixture::seed_group_claim(pool, member, group, "B fell, but C held.").await;
    decomposes(pool, parent, atom).await;
    let hidden = decomposes(pool, atom, child).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(hidden)
    .bind(group)
    .execute(pool)
    .await
    .expect("privatise the edge");
    decomposes(pool, atom, private).await;
    World {
        member,
        stranger,
        parent,
        atom,
        child,
        private,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn by_ids_counts_only_visible_edges_and_neighbours(pool: PgPool) {
    let w = seed(&pool).await;
    let ids = [w.atom, w.private, w.child];

    let stranger = Viewer::resolve(&pool, w.stranger).await.expect("resolve");
    let rows = AtomicityScreenRepository::rows_by_ids(&pool, &stranger, &ids)
        .await
        .unwrap();
    let got: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(got, vec![w.atom, w.child], "the private claim is absent");
    let atom = &rows[0];
    assert_eq!(
        atom.children, 0,
        "a hidden edge to a public child and an edge to a hidden child count nothing"
    );
    assert_eq!(atom.parents, 1);
    assert_eq!(rows[1].parents, 0, "the child's only parent edge is hidden");

    let member = Viewer::resolve(&pool, w.member).await.expect("resolve");
    let rows = AtomicityScreenRepository::rows_by_ids(&pool, &member, &ids)
        .await
        .unwrap();
    let got: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(got, vec![w.atom, w.private, w.child]);
    assert_eq!(rows[0].children, 2, "calibration: the member sees both");
    assert_eq!(rows[2].parents, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_atom_population_is_edge_visible(pool: PgPool) {
    let w = seed(&pool).await;
    let page = |viewer: Viewer, population| {
        let pool = pool.clone();
        async move {
            AtomicityScreenRepository::page(
                &mut pool.acquire().await.unwrap(),
                &viewer,
                population,
                None,
                100,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect::<std::collections::HashSet<Uuid>>()
        }
    };
    let stranger = || Viewer::resolve(&pool, w.stranger);
    let member = || Viewer::resolve(&pool, w.member);

    let s = page(stranger().await.unwrap(), ScreenPopulation::Atoms).await;
    assert_eq!(
        s,
        [w.atom].into_iter().collect(),
        "the child is an atom only through a hidden edge; the private claim is hidden"
    );
    let m = page(member().await.unwrap(), ScreenPopulation::Atoms).await;
    assert_eq!(m, [w.atom, w.child, w.private].into_iter().collect());
    let all = page(stranger().await.unwrap(), ScreenPopulation::All).await;
    assert!(all.contains(&w.parent) && all.contains(&w.child));
    assert!(!all.contains(&w.private));
}

// ── The keyset walk at scale (backlog 9989c0a6) ──────────────────────────────
//
// On a production-sized corpus the atom page was planned as a seq scan of
// `claims` plus a top-N sort on EVERY page: the population filters
// (`COALESCE(is_current, true)`, `length(content)`, the telemetry label,
// `properties ->> 'event'`) have no statistics, so the planner estimated a few
// hundred qualifying rows where there were several hundred thousand, and an
// index walk looked dearer than reading the table. These tests seed a corpus
// large enough for the same misestimate, then hold the page read to the
// `created_at` index and to the old result order.

/// Claims seeded by [`seed_corpus`].
const CORPUS: i64 = 100_000;

/// A corpus of `CORPUS` public claims, three to a `created_at` (one
/// transaction's writes share it, so ties are the normal case), written in an
/// order unrelated to `created_at` (rows are rewritten in place over a claim's
/// life, so production heap order follows it only loosely). Every 5th is
/// telemetry and every 7th a host event, rows the population excludes. In
/// `created_at` order, claim 1 of each block of ten decomposes into claims 2 to
/// 6, so about half the corpus is atoms, except in a run of 7,000 claims (the
/// 40,001st to the 47,000th) with none, longer than any window the page reads
/// at once. Returns the ids in `(created_at, id)` order.
async fn seed_corpus(pool: &PgPool) -> Vec<Uuid> {
    let (agent, _) = fixture::seed_agent_with_group(pool, "b110-corpus").await;
    let world = fixture::world_group(pool).await;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels, properties, created_at) \
         SELECT gen_random_uuid(), \
                'Seeded claim ' || g || ' holds at ' || g || ' K. ' || repeat('Padding. ', 50), \
                sha256(convert_to('b110-' || g, 'UTF8')), 0.8, $1, true, 'public', $2, \
                CASE WHEN g % 5 = 0 THEN ARRAY['telemetry'] ELSE ARRAY[]::text[] END, \
                CASE WHEN g % 7 = 0 THEN jsonb_build_object('event', 'tick') \
                     ELSE '{}'::jsonb END, \
                timestamptz '2026-01-01 00:00:00+00' \
                    + (((g::bigint * 7919) % $3) / 3) * interval '1 second' \
           FROM generate_series(1, $3::int) AS g",
    )
    .bind(agent)
    .bind(world)
    .bind(CORPUS as i32)
    .execute(pool)
    .await
    .expect("seed the corpus");
    sqlx::query(
        "WITH n AS (SELECT id, row_number() OVER (ORDER BY created_at, id) AS g FROM claims \
                     WHERE content LIKE 'Seeded claim %') \
         INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         SELECT gen_random_uuid(), p.id, 'claim', a.id, 'claim', 'decomposes_to' \
           FROM n a JOIN n p ON p.g = a.g - (a.g % 10) + 1 \
          WHERE a.g % 10 BETWEEN 2 AND 6 AND NOT (a.g BETWEEN 40001 AND 47000)",
    )
    .execute(pool)
    .await
    .expect("seed the decompositions");
    sqlx::query("ANALYZE claims").execute(pool).await.unwrap();
    sqlx::query("ANALYZE edges").execute(pool).await.unwrap();
    sqlx::query_scalar(
        "SELECT id FROM claims WHERE content LIKE 'Seeded claim %' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// `(sequential scans, heap tuples read)` on `claims` by this transaction so
/// far. Tuples are counted however they were reached: a seq scan, an index
/// scan or a bitmap heap scan (the old plan's shape on this corpus).
async fn claims_reads(conn: &mut sqlx::PgConnection) -> (i64, i64) {
    sqlx::query_as(
        "SELECT COALESCE(seq_scan, 0), COALESCE(seq_tup_read, 0) + COALESCE(idx_tup_fetch, 0) \
           FROM pg_stat_xact_user_tables WHERE relid = 'claims'::regclass",
    )
    .fetch_optional(&mut *conn)
    .await
    .unwrap()
    .unwrap_or((0, 0))
}

/// The most `claims` tuples the walk may read per claim it passes over (plus
/// one window of look-ahead per page): the keyset read, the screen read by id,
/// the atom probe's parent, and the neighbour counts of the rows it returns.
/// What it must not do is read the claims it has NOT reached: the old plan
/// read every claim after the cursor, on every page.
const MAX_TUPLES_PER_CLAIM_PASSED: i64 = 5;
/// The page's window at `limit = 500` (`PAGE_WINDOW_MIN..=PAGE_WINDOW_MAX`).
const WINDOW_AT_500: i64 = 1000;

#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_page_walks_the_created_at_index_not_the_table(pool: PgPool) {
    let ids = seed_corpus(&pool).await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "b110-reader").await;
    let viewer = Viewer::resolve(&pool, member).await.expect("resolve");
    let mid: (chrono::DateTime<chrono::Utc>, Uuid) =
        sqlx::query_as("SELECT created_at, id FROM claims WHERE id = $1")
            .bind(ids[ids.len() / 3])
            .fetch_one(&pool)
            .await
            .unwrap();

    for plan_mode in ["auto", "force_custom_plan", "force_generic_plan"] {
        for population in [ScreenPopulation::Atoms, ScreenPopulation::All] {
            let mut tx = pool.begin().await.unwrap();
            // Parallel workers' scans are not in this backend's counters.
            sqlx::query("SET LOCAL max_parallel_workers_per_gather = 0")
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query(&format!("SET LOCAL plan_cache_mode = {plan_mode}"))
                .execute(&mut *tx)
                .await
                .unwrap();
            let before = claims_reads(&mut tx).await;
            // Several pages, so a prepared statement reaches its generic plan.
            let mut after = Some(mid);
            for _ in 0..7 {
                let page =
                    AtomicityScreenRepository::page(&mut tx, &viewer, population, after, 500)
                        .await
                        .unwrap();
                assert_eq!(page.len(), 500, "{plan_mode} {population:?}");
                let last = page.last().unwrap();
                after = Some((last.created_at, last.id));
            }
            let now = claims_reads(&mut tx).await;
            let (scans, tuples) = (now.0 - before.0, now.1 - before.1);
            assert_eq!(
                scans, 0,
                "{plan_mode} {population:?}: a page must be an index range read, \
                 not {scans} sequential scan(s) of claims"
            );
            tx.rollback().await.unwrap();
            let (last_at, last_id) = after.unwrap();
            let passed: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM claims \
                  WHERE (created_at, id) > ($1, $2) AND (created_at, id) <= ($3, $4)",
            )
            .bind(mid.0)
            .bind(mid.1)
            .bind(last_at)
            .bind(last_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            let bound = MAX_TUPLES_PER_CLAIM_PASSED * (passed + 7 * WINDOW_AT_500);
            assert!(
                tuples <= bound,
                "{plan_mode} {population:?}: 7 pages of 500 passed {passed} claims and \
                 read {tuples} claims tuples (bound {bound}): the read is not bounded \
                 by the walk"
            );
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn walking_every_page_returns_the_population_in_keyset_order(pool: PgPool) {
    seed_corpus(&pool).await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "b110-walker").await;
    let viewer = Viewer::resolve(&pool, member).await.expect("resolve");

    let reference = |atoms: bool| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT c.id FROM claims c \
                  WHERE c.is_current AND length(c.content) > 10 \
                    AND NOT ('telemetry' = ANY(c.labels)) \
                    AND (c.properties ->> 'event') IS NULL \
                    AND (NOT $1 OR EXISTS (SELECT 1 FROM edges a \
                          WHERE a.target_id = c.id AND a.relationship = 'decomposes_to')) \
                  ORDER BY c.created_at, c.id",
            )
            .bind(atoms)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };

    for (population, atoms) in [
        (ScreenPopulation::Atoms, true),
        (ScreenPopulation::All, false),
    ] {
        let want = reference(atoms).await;
        for limit in [500_i64, 333] {
            let mut got = Vec::new();
            let mut after = None;
            loop {
                let page = AtomicityScreenRepository::page(
                    &mut pool.acquire().await.unwrap(),
                    &viewer,
                    population,
                    after,
                    limit,
                )
                .await
                .unwrap();
                let n = page.len() as i64;
                if let Some(last) = page.last() {
                    after = Some((last.created_at, last.id));
                }
                // Each row carries the same counts a direct read of it does.
                let ids: Vec<Uuid> = page.iter().map(|r| r.id).collect();
                let direct = AtomicityScreenRepository::rows_by_ids(&pool, &viewer, &ids)
                    .await
                    .unwrap();
                assert_eq!(page, direct, "{population:?} limit {limit}");
                got.extend(ids);
                // A short page is the end of the population, never a gap.
                if n < limit {
                    break;
                }
            }
            assert_eq!(got.len(), want.len(), "{population:?} limit {limit}");
            assert!(
                got == want,
                "{population:?} limit {limit}: order or members differ"
            );
        }
    }
}
