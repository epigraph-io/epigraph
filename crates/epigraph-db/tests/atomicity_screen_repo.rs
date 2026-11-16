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
            AtomicityScreenRepository::page(&pool, &viewer, population, None, 100)
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
