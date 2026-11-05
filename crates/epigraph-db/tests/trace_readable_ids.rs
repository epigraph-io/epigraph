//! Integration tests for `ReasoningTraceRepository::readable_ids`, the trace
//! check `POST /api/v1/claims/batch-get` runs so a claim body never names a
//! trace its viewer cannot read.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashSet;

use epigraph_db::visibility::Viewer;
use epigraph_db::ReasoningTraceRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Stamp a trace group-private with a privileged harness UPDATE, and check the
/// stamp landed: a mis-stamped fixture makes every "the outsider cannot read
/// it" assertion vacuous.
async fn make_trace_private(pool: &PgPool, trace: Uuid, group: Uuid) {
    let got: Option<(String, Uuid)> = sqlx::query_as(
        "UPDATE reasoning_traces SET visibility = 'group', owner_group_id = $2 \
         WHERE id = $1 RETURNING visibility, owner_group_id",
    )
    .bind(trace)
    .bind(group)
    .fetch_optional(pool)
    .await
    .expect("stamp the trace group-private");
    assert_eq!(got, Some(("group".to_string(), group)));
}

#[sqlx::test(migrations = "../../migrations")]
async fn readable_ids_withholds_a_group_private_trace_on_a_public_claim(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "outsider").await;
    let c_pub = fixture::seed_public_claim(&pool, owner, "claim with a public trace").await;
    let c_priv = fixture::seed_public_claim(&pool, owner, "claim with a private trace").await;
    let t_pub = fixture::seed_reasoning_trace(&pool, c_pub, "deductive").await;
    let t_priv = fixture::seed_reasoning_trace(&pool, c_priv, "inductive").await;
    make_trace_private(&pool, t_priv, group).await;

    let ids = [t_pub, t_priv, Uuid::new_v4()];

    for (who, viewer) in [
        ("public viewer", fixture::public_viewer(&pool).await),
        (
            "outsider",
            Viewer::resolve(&pool, outsider).await.expect("viewer"),
        ),
    ] {
        let got = ReasoningTraceRepository::readable_ids(&pool, &viewer, &ids)
            .await
            .expect("trace read");
        assert_eq!(
            got,
            HashSet::from([t_pub]),
            "{who} reads the public trace only; the private one and the absent \
             one are both simply missing"
        );
    }

    // Calibration: the owner reads both traces.
    let owner_v = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    let got = ReasoningTraceRepository::readable_ids(&pool, &owner_v, &ids)
        .await
        .expect("trace read");
    assert_eq!(got, HashSet::from([t_pub, t_priv]));

    // The same answer on a viewer-stamped connection, where migration 077's
    // policies also apply.
    let scoped = fixture::scoped_pool(&pool).await;
    let outsider_v = Viewer::resolve(&pool, outsider).await.expect("viewer");
    let mut read = scoped.read_as(&outsider_v).await.expect("read_as");
    let got = ReasoningTraceRepository::readable_ids(&mut *read, &outsider_v, &ids)
        .await
        .expect("trace read");
    read.commit().await.expect("finish the read");
    assert_eq!(got, HashSet::from([t_pub]));

    let mut read = scoped.read_as(&owner_v).await.expect("read_as");
    let got = ReasoningTraceRepository::readable_ids(&mut *read, &owner_v, &ids)
        .await
        .expect("trace read");
    read.commit().await.expect("finish the read");
    assert_eq!(got, HashSet::from([t_pub, t_priv]));

    // Empty input: an empty set, no statement.
    assert!(ReasoningTraceRepository::readable_ids(&pool, &owner_v, &[])
        .await
        .expect("trace read")
        .is_empty());
}
