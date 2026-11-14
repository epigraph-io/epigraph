//! `epigraph_cli::atomicity_sweep` (backlog `72850d43`): label current
//! compound atoms `compound-atom`, unlabel claims that no longer qualify,
//! write nothing on a dry run, and converge.
//!
//! On the test pool's owner login with a bypass viewer: the binary's own
//! shape (maintenance connection, bypass viewer).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_cli::atomicity_sweep::sweep;
use epigraph_core::atomicity::COMPOUND_ATOM_LABEL;
use sqlx::PgPool;
use uuid::Uuid;

async fn decomposes(pool: &PgPool, source: Uuid, target: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("decomposes_to edge");
}

async fn labels(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn set_labels(pool: &PgPool, id: Uuid, l: &[&str]) {
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(id)
        .bind(l.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .execute(pool)
        .await
        .unwrap();
}

fn has(l: &[String]) -> bool {
    l.iter().any(|x| x == COMPOUND_ATOM_LABEL)
}

struct World {
    compound_leaf: Uuid,
    atomic_leaf: Uuid,
    split_compound: Uuid,
    standalone: Uuid,
    stale: Uuid,
}

async fn seed(pool: &PgPool) -> World {
    let (agent, _) = fixture::seed_agent_with_group(pool, "b42sweep").await;
    let c = |t: &'static str| fixture::seed_public_claim(pool, agent, t);
    let parent = c("The pump failed. The backup took over. The alarm rang.").await;
    let compound_leaf = c("The pump failed, but the backup took over.").await;
    let atomic_leaf = c("The alarm rang at noon.").await;
    let split_compound = c("The valve stuck, and the operator reset it.").await;
    let split_child = c("The valve stuck.").await;
    let standalone = c("The fan stopped; the room overheated.").await;
    // Labelled by an earlier run, but atomic: the label is stale.
    let stale = c("The alarm rang twice.").await;
    for atom in [compound_leaf, atomic_leaf, split_compound, stale] {
        decomposes(pool, parent, atom).await;
    }
    decomposes(pool, split_compound, split_child).await;
    set_labels(pool, compound_leaf, &["atom", "generality:1"]).await;
    set_labels(pool, stale, &["atom", COMPOUND_ATOM_LABEL]).await;
    World {
        compound_leaf,
        atomic_leaf,
        split_compound,
        standalone,
        stale,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_labels_compound_leaves_and_cleans_stale_labels(pool: PgPool) {
    let w = seed(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;

    // Dry run: reports, writes nothing.
    let dry = sweep(&pool, &viewer, false, 1_000_000).await.unwrap();
    assert!(!dry.applied);
    assert_eq!(dry.atoms_scanned, 5, "{dry:?}");
    assert_eq!(dry.compound_atoms, 1, "{dry:?}");
    assert_eq!(dry.labelled, vec![w.compound_leaf]);
    assert_eq!(dry.unlabelled, vec![w.stale]);
    assert!(!has(&labels(&pool, w.compound_leaf).await));
    assert!(has(&labels(&pool, w.stale).await));

    // Apply: the compound leaf is labelled with its other labels kept; the
    // stale label is removed with `atom` kept; nothing else is touched.
    let run = sweep(&pool, &viewer, true, 1_000_000).await.unwrap();
    assert_eq!(run.labelled, vec![w.compound_leaf]);
    assert_eq!(run.unlabelled, vec![w.stale]);
    let leaf = labels(&pool, w.compound_leaf).await;
    assert!(has(&leaf), "{leaf:?}");
    assert!(leaf.contains(&"generality:1".to_string()), "{leaf:?}");
    assert_eq!(labels(&pool, w.stale).await, vec!["atom".to_string()]);
    for untouched in [w.atomic_leaf, w.split_compound, w.standalone] {
        assert!(
            !has(&labels(&pool, untouched).await),
            "{untouched}: atomic, already split, or not an atom"
        );
    }

    // Converged: a second run changes nothing.
    let again = sweep(&pool, &viewer, true, 1_000_000).await.unwrap();
    assert!(
        again.labelled.is_empty() && again.unlabelled.is_empty(),
        "{again:?}"
    );
    assert_eq!(again.compound_atoms, 1);

    // Once the leaf is split, the next run takes its label off.
    let child = fixture::seed_public_claim(
        &pool,
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(w.compound_leaf)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "The pump failed.",
    )
    .await;
    decomposes(&pool, w.compound_leaf, child).await;
    let after_split = sweep(&pool, &viewer, true, 1_000_000).await.unwrap();
    assert_eq!(after_split.unlabelled, vec![w.compound_leaf]);
    assert!(!has(&labels(&pool, w.compound_leaf).await));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_capped_sweep_unlabels_nothing(pool: PgPool) {
    let w = seed(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let capped = sweep(&pool, &viewer, true, 1).await.unwrap();
    assert!(capped.scan_capped);
    assert_eq!(capped.atoms_scanned, 1);
    assert!(capped.unlabelled.is_empty(), "{capped:?}");
    assert!(
        has(&labels(&pool, w.stale).await),
        "a capped walk cannot judge a label stale"
    );
}
