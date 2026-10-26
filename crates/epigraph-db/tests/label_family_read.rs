//! [`ClaimRepository::list_all_by_labels_ordered_by_id`]: the one read a
//! label-family planner makes.
//!
//! Pins the contract the planner relies on:
//!
//! * every claim carrying ALL of the include labels and NONE of the exclude
//!   labels, ordered by id, no offset;
//! * at most `cap + 1` rows, so a family larger than the cap is detectable
//!   (the planner refuses to act on a prefix);
//! * viewer-scoped: a row the viewer may not read is absent;
//! * under forced row security, a member's group-private family row is
//!   visible on a connection STAMPED from its viewer and invisible on an
//!   unstamped application-role connection, which is why the tools read on
//!   `ScopedPool::read_as`. The fixtures install no policy of their own.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, DbError, LabelFamilyRow, Viewer};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

async fn set_labels(pool: &PgPool, id: Uuid, labels: &[&str]) {
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(id)
        .bind(s(labels))
        .execute(pool)
        .await
        .expect("set labels");
}

async fn public_with_labels(pool: &PgPool, agent: Uuid, content: &str, labels: &[&str]) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    set_labels(pool, id, labels).await;
    id
}

fn ids(rows: &[LabelFamilyRow]) -> Vec<Uuid> {
    rows.iter().map(|r| r.id).collect()
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn reads_the_whole_family_in_id_order_with_include_exclude_and_current_filters(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "family-read").await;

    let a = public_with_labels(&pool, agent, "member one ACME-100001", &["fam", "src-a"]).await;
    let b = public_with_labels(&pool, agent, "member two ACME-100002", &["fam"]).await;
    let c = public_with_labels(&pool, agent, "member three ACME-100003", &["fam", "src-a"]).await;
    let closed = public_with_labels(&pool, agent, "closed member", &["fam", "closed"]).await;
    let _other = public_with_labels(&pool, agent, "another family", &["other"]).await;
    let old = public_with_labels(&pool, agent, "superseded member", &["fam"]).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .expect("retire the old member");

    let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
        &pool,
        &viewer,
        &s(&["fam"]),
        &s(&["closed"]),
        true,
        100,
    )
    .await
    .expect("read");
    assert_eq!(
        ids(&rows),
        sorted(vec![a, b, c]),
        "id order, closed and superseded excluded"
    );
    let row_a = rows.iter().find(|r| r.id == a).expect("a");
    assert_eq!(row_a.content, "member one ACME-100001");
    assert_eq!(row_a.labels, s(&["fam", "src-a"]));

    // `current_only = false` keeps the superseded member.
    let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
        &pool,
        &viewer,
        &s(&["fam"]),
        &s(&["closed"]),
        false,
        100,
    )
    .await
    .expect("read");
    assert_eq!(ids(&rows), sorted(vec![a, b, c, old]));

    // Every include label is required; no exclusion keeps the closed member.
    let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
        &pool,
        &viewer,
        &s(&["fam", "src-a"]),
        &[],
        true,
        100,
    )
    .await
    .expect("read");
    assert_eq!(ids(&rows), sorted(vec![a, c]));
    let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
        &pool,
        &viewer,
        &s(&["fam"]),
        &[],
        true,
        100,
    )
    .await
    .expect("read");
    assert_eq!(ids(&rows), sorted(vec![a, b, c, closed]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_cap_plus_one_rows_so_a_larger_family_is_detectable(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "family-cap").await;
    let mut all = Vec::new();
    for i in 0..4 {
        all.push(public_with_labels(&pool, agent, &format!("capped member {i}"), &["fam"]).await);
    }
    let all = sorted(all);

    for (cap, want) in [(2_i64, 3_usize), (0, 1), (3, 4), (4, 4), (10, 4)] {
        let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
            &pool,
            &viewer,
            &s(&["fam"]),
            &[],
            true,
            cap,
        )
        .await
        .expect("read");
        assert_eq!(
            ids(&rows),
            all[..want].to_vec(),
            "cap {cap}: the first min(cap + 1, n) rows by id"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_include_set_or_a_negative_cap_is_refused(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "family-refuse").await;
    public_with_labels(&pool, agent, "some member", &["fam"]).await;

    for (include, cap) in [(Vec::new(), 10_i64), (s(&["fam"]), -1)] {
        let err = ClaimRepository::list_all_by_labels_ordered_by_id(
            &pool,
            &viewer,
            &include,
            &[],
            true,
            cap,
        )
        .await
        .expect_err("refused");
        match err {
            DbError::InvalidData { reason } => assert!(
                !reason.contains("NOT_IMPLEMENTED"),
                "a real refusal, not the skeleton: {reason}"
            ),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }
    // Control: the same call with a family and a cap reads.
    let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
        &pool,
        &viewer,
        &s(&["fam"]),
        &[],
        true,
        10,
    )
    .await
    .expect("control read");
    assert_eq!(rows.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_row_the_viewer_cannot_read_is_absent(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "family-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "family-stranger").await;
    let public = public_with_labels(&pool, member, "public member ACME-200001", &["fam"]).await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "private member ACME-200002").await;
    set_labels(&pool, private, &["fam"]).await;

    let member_v = Viewer::resolve(&pool, member).await.expect("member viewer");
    let stranger_v = Viewer::resolve(&pool, stranger)
        .await
        .expect("stranger viewer");
    let read = |v: Viewer| {
        let pool = pool.clone();
        async move {
            ids(&ClaimRepository::list_all_by_labels_ordered_by_id(
                &pool,
                &v,
                &s(&["fam"]),
                &[],
                true,
                100,
            )
            .await
            .expect("read"))
        }
    };
    assert_eq!(
        read(member_v).await,
        sorted(vec![public, private]),
        "control: the member reads both"
    );
    assert_eq!(
        read(stranger_v).await,
        vec![public],
        "a stranger never sees the private row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn under_row_security_only_a_stamped_read_sees_the_members_private_row(pool: PgPool) {
    let scoped = fixture::scoped_pool(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "family-rls").await;
    let public = public_with_labels(&pool, member, "public member ACME-300001", &["fam"]).await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "private member ACME-300002").await;
    set_labels(&pool, private, &["fam"]).await;
    let viewer = Viewer::resolve(&pool, member).await.expect("member viewer");

    // Stamped from the member's viewer, then downgraded to the application
    // role, so the policies (not only the in-query predicate) decide.
    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade to the application role");
    let stamped = ClaimRepository::list_all_by_labels_ordered_by_id(
        &mut *r,
        &viewer,
        &s(&["fam"]),
        &[],
        true,
        100,
    )
    .await
    .expect("stamped read");
    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    r.commit().await.expect("commit");
    assert_eq!(
        ids(&stamped),
        sorted(vec![public, private]),
        "a stamped member read sees its own group-private family row"
    );

    // The same viewer's predicate on an UNSTAMPED application-role
    // connection: the policy admits public rows only.
    let unstamped = fixture::as_role(&pool, "epigraph_app", move |mut conn| async move {
        let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
            &mut *conn,
            &viewer,
            &s(&["fam"]),
            &[],
            true,
            100,
        )
        .await
        .expect("unstamped read");
        (conn, ids(&rows))
    })
    .await;
    assert_eq!(
        unstamped,
        vec![public],
        "an unstamped session loses the member's own private row"
    );
}
