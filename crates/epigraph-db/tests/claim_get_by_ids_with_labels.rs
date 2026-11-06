//! Integration tests for `ClaimRepository::get_by_ids_with_labels` and
//! `ClaimEncryptionRepository::get_by_claim_ids_conn`, the two set-based reads
//! behind `POST /api/v1/claims/batch-get`.
//!
//! Hermetic `#[sqlx::test]` databases, so "exactly these rows come back" means
//! exactly that: nothing but this test's fixtures is in the table.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashMap;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimEncryptionRepository, ClaimRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(&labels)
        .execute(pool)
        .await
        .expect("set labels");
}

fn by_id(
    rows: Vec<(epigraph_core::Claim, Vec<String>)>,
) -> HashMap<Uuid, (epigraph_core::Claim, Vec<String>)> {
    rows.into_iter()
        .map(|(c, l)| (Uuid::from(c.id), (c, l)))
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_only_the_requested_rows(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let a = fixture::seed_public_claim(&pool, agent, "batch claim a").await;
    let b = fixture::seed_public_claim(&pool, agent, "batch claim b").await;
    let c = fixture::seed_public_claim(&pool, agent, "batch claim c").await;
    // A decoy the viewer CAN read, so "only the requested rows" is the id
    // predicate's doing and not an empty table's.
    let decoy = fixture::seed_public_claim(&pool, agent, "batch decoy").await;
    set_labels(&pool, a, &["doi:10.1234/a", "topic:x"]).await;
    set_labels(&pool, decoy, &["decoy-label"]).await;

    let absent = Uuid::new_v4();
    let rows = ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &[a, b, absent])
        .await
        .expect("batch read");
    let got = by_id(rows);

    let mut ids: Vec<Uuid> = got.keys().copied().collect();
    ids.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(ids, want, "exactly the two requested readable rows");

    let mut a_labels = got[&a].1.clone();
    a_labels.sort();
    assert_eq!(a_labels, vec!["doi:10.1234/a", "topic:x"]);
    assert!(got[&b].1.is_empty());
    assert_eq!(got[&a].0.content, "batch claim a");

    // Calibration: the unrequested rows are readable by this viewer.
    let all = ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &[c, decoy])
        .await
        .expect("batch read");
    assert_eq!(all.len(), 2, "c and the decoy are readable when asked for");
}

#[sqlx::test(migrations = "../../migrations")]
async fn is_current_is_the_rows_not_a_placeholder(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let live = fixture::seed_public_claim(&pool, agent, "still current").await;
    let retired = fixture::seed_public_claim(&pool, agent, "retired claim").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .expect("retire the claim");

    let got = by_id(
        ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &[live, retired])
            .await
            .expect("batch read"),
    );
    assert!(got[&live].0.is_current);
    assert!(
        !got[&retired].0.is_current,
        "the row's is_current, not claim_from_row's placeholder true"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn matches_the_single_read_field_for_field(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let traced = fixture::seed_public_claim(&pool, agent, "a traced claim").await;
    let _trace = fixture::seed_reasoning_trace(&pool, traced, "deductive").await;
    let labelled = fixture::seed_public_claim(&pool, agent, "a labelled claim").await;
    set_labels(&pool, labelled, &["doi:10.5555/z", "kind:finding"]).await;
    let retired = fixture::seed_public_claim(&pool, agent, "a retired claim").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .expect("retire the claim");

    let ids = [traced, labelled, retired];
    let batch = by_id(
        ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &ids)
            .await
            .expect("batch read"),
    );
    assert_eq!(batch.len(), 3);

    for id in ids {
        let (single, single_labels) =
            ClaimRepository::get_by_id_with_labels(&pool, &viewer, ClaimId::from_uuid(id))
                .await
                .expect("single read")
                .expect("the claim exists");
        let (many, many_labels) = &batch[&id];
        assert_eq!(many.id, single.id);
        assert_eq!(many.content, single.content);
        assert_eq!(many.truth_value.value(), single.truth_value.value());
        assert_eq!(many.agent_id, single.agent_id);
        assert_eq!(many.trace_id, single.trace_id);
        assert_eq!(many.created_at, single.created_at);
        assert_eq!(many.updated_at, single.updated_at);
        assert_eq!(many_labels, &single_labels);
        assert_eq!(many.is_current, single.is_current);
        assert_eq!(many.supersedes, single.supersedes);
        assert_eq!(many.content_hash, single.content_hash);
        assert_eq!(many.signature, single.signature);
        assert_eq!(many.public_key, single.public_key);
    }
    assert!(
        batch[&traced].0.trace_id.is_some(),
        "the traced fixture must carry a trace, or the trace_id comparison is vacuous"
    );
    assert!(!batch[&retired].0.is_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn withholds_a_group_private_row_from_a_non_member(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "outsider").await;
    let public = fixture::seed_public_claim(&pool, owner, "a public claim").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "a private claim").await;

    let ids = [public, private];
    for (who, viewer) in [
        ("public viewer", fixture::public_viewer(&pool).await),
        (
            "outsider",
            Viewer::resolve(&pool, outsider).await.expect("viewer"),
        ),
    ] {
        let got = ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &ids)
            .await
            .expect("batch read");
        let got: Vec<Uuid> = got.into_iter().map(|(c, _)| Uuid::from(c.id)).collect();
        assert_eq!(got, vec![public], "{who} reads only the public row");
    }

    // Calibration: the owner reads both, so the arms above test the filter.
    let owner_v = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    let mut got: Vec<Uuid> = ClaimRepository::get_by_ids_with_labels(&pool, &owner_v, &ids)
        .await
        .expect("batch read")
        .into_iter()
        .map(|(c, _)| Uuid::from(c.id))
        .collect();
    got.sort();
    let mut want = ids.to_vec();
    want.sort();
    assert_eq!(got, want, "the owner reads both rows");
}

#[sqlx::test(migrations = "../../migrations")]
async fn empty_input_returns_empty(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let _ = fixture::seed_public_claim(&pool, agent, "something to not return").await;
    let rows = ClaimRepository::get_by_ids_with_labels(&pool, &viewer, &[])
        .await
        .expect("batch read");
    assert!(rows.is_empty());
}

async fn seal(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the group key epoch the FK requires");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a claim_encryption row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn encryption_batch_is_filtered_through_the_parent_claim(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "outsider").await;
    let sealed = fixture::seed_group_claim(&pool, owner, group, "a sealed claim").await;
    let plain = fixture::seed_public_claim(&pool, owner, "an unsealed claim").await;
    // Migration 081 refuses a seal on a public claim, so the claim is already
    // group-private here.
    seal(&pool, sealed, group).await;

    let scoped = fixture::scoped_pool(&pool).await;
    let ids = [sealed, plain];

    for (who, viewer) in [
        ("public viewer", fixture::public_viewer(&pool).await),
        (
            "outsider",
            Viewer::resolve(&pool, outsider).await.expect("viewer"),
        ),
    ] {
        let mut read = scoped.read_as(&viewer).await.expect("read_as");
        let got = ClaimEncryptionRepository::get_by_claim_ids_conn(&mut read, &viewer, &ids)
            .await
            .expect("seal read");
        assert!(
            got.is_empty(),
            "{who} must get no seal record for a claim it cannot read, got {:?}",
            got.keys().collect::<Vec<_>>()
        );
        read.commit().await.expect("finish the read");
    }

    let owner_v = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    let mut read = scoped.read_as(&owner_v).await.expect("read_as");
    let got = ClaimEncryptionRepository::get_by_claim_ids_conn(&mut read, &owner_v, &ids)
        .await
        .expect("seal read");
    read.commit().await.expect("finish the read");
    assert_eq!(got.len(), 1, "one seal record, for the sealed claim only");
    let row = &got[&sealed];
    assert_eq!(row.claim_id, sealed);
    assert_eq!(row.group_id, group);
    assert_eq!(row.privacy_tier, "fully_private");
    assert_eq!(row.encrypted_content, vec![0x0b, 0xad, 0xc0, 0xde]);

    // Empty input: an empty map and no statement.
    let mut read = scoped.read_as(&owner_v).await.expect("read_as");
    assert!(
        ClaimEncryptionRepository::get_by_claim_ids_conn(&mut read, &owner_v, &[])
            .await
            .expect("seal read")
            .is_empty()
    );
    read.commit().await.expect("finish the read");
}
