//! Partition access checks (`epigraph_db::access_control`) against a real
//! schema.
//!
//! Each case gets its own `#[sqlx::test]` database, so the seeded ownership
//! rows are the only ones and a failure injected into one case (a renamed
//! table, a closed pool) cannot leak into another.

use std::collections::HashMap;

use epigraph_db::access_control::{
    batch_check_content_access, batch_content_access, check_content_access, ContentAccess,
};
use sqlx::PgPool;
use uuid::Uuid;
use ContentAccess::{Full as F, Redacted as R};

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// `ownership.owner_id` is an FK to `agents`, so owners are seeded agents.
async fn seed_ownership(
    pool: &PgPool,
    node_id: Uuid,
    partition: &str,
    owner_id: Uuid,
    encryption_key_id: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', $2, $3, $4)",
    )
    .bind(node_id)
    .bind(partition)
    .bind(owner_id)
    .bind(encryption_key_id)
    .execute(pool)
    .await
    .unwrap();
}

// ── Fail closed ─────────────────────────────────────────────────────────────

/// A failed ownership lookup must redact. Before the fix the error was
/// swallowed into "no ownership row", which is read as public, so every node —
/// private ones included — came back `Full` to every requester.
#[sqlx::test(migrations = "../../migrations")]
async fn ownership_lookup_error_redacts_instead_of_serving_full(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let stranger = Uuid::new_v4();
    let private_node = Uuid::new_v4();
    let public_node = Uuid::new_v4();
    let bare_node = Uuid::new_v4(); // no ownership row
    seed_ownership(&pool, private_node, "private", owner, None).await;
    seed_ownership(&pool, public_node, "public", owner, None).await;

    // Baseline while the lookup works, so the post-failure assertions below are
    // about the failure and not about the fixtures.
    assert_eq!(
        check_content_access(&pool, private_node, Some(stranger)).await,
        ContentAccess::Redacted
    );
    assert_eq!(
        check_content_access(&pool, private_node, Some(owner)).await,
        ContentAccess::Full
    );
    assert_eq!(
        check_content_access(&pool, public_node, None).await,
        ContentAccess::Full
    );
    assert_eq!(
        check_content_access(&pool, bare_node, None).await,
        ContentAccess::Full
    );

    // Every ownership lookup now errors ("relation does not exist").
    sqlx::query("ALTER TABLE ownership RENAME TO ownership_unavailable")
        .execute(&pool)
        .await
        .unwrap();

    for node in [private_node, public_node, bare_node] {
        for requester in [None, Some(stranger), Some(owner)] {
            assert_eq!(
                check_content_access(&pool, node, requester).await,
                ContentAccess::Redacted,
                "node {node} requester {requester:?}: a lookup error must redact"
            );
        }
    }
}

/// The pool-exhaustion shape of the same failure: acquiring a connection
/// fails, the query never runs, and the private node stays redacted.
#[sqlx::test(migrations = "../../migrations")]
async fn closed_pool_redacts_a_private_node(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let stranger = Uuid::new_v4();
    let private_node = Uuid::new_v4();
    seed_ownership(&pool, private_node, "private", owner, None).await;

    pool.close().await;

    for requester in [None, Some(stranger), Some(owner)] {
        assert_eq!(
            check_content_access(&pool, private_node, requester).await,
            ContentAccess::Redacted,
            "requester {requester:?}: an unreachable database must redact"
        );
    }
}

// ── Batch ≡ single ──────────────────────────────────────────────────────────

/// One community with one member perspective per listed agent.
async fn seed_community(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let community_id = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, name) VALUES ($1, $2)")
        .bind(community_id)
        .bind(format!("community-{community_id}"))
        .execute(pool)
        .await
        .unwrap();
    for &agent in members {
        let perspective_id = Uuid::new_v4();
        sqlx::query("INSERT INTO perspectives (id, name, owner_agent_id) VALUES ($1, $2, $3)")
            .bind(perspective_id)
            .bind(format!("perspective-{perspective_id}"))
            .bind(agent)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
            .bind(community_id)
            .bind(perspective_id)
            .execute(pool)
            .await
            .unwrap();
    }
    community_id
}

/// Every partition shape `check_content_access` distinguishes, each with the
/// expected decision for the requesters in `Fixture::requesters` order
/// (anonymous, owner, member, stranger).
struct Fixture {
    owner: Uuid,
    member: Uuid,
    stranger: Uuid,
    cases: Vec<(&'static str, Uuid, [ContentAccess; 4])>,
}

impl Fixture {
    fn requesters(&self) -> [(&'static str, Option<Uuid>); 4] {
        [
            ("anonymous", None),
            ("owner", Some(self.owner)),
            ("member", Some(self.member)),
            ("stranger", Some(self.stranger)),
        ]
    }

    fn ids(&self) -> Vec<Uuid> {
        self.cases.iter().map(|&(_, id, _)| id).collect()
    }
}

/// `(partition_type, encryption_key_id)` of a seeded ownership row.
type Ownership<'a> = (&'a str, Option<&'a str>);

async fn seed_fixture(pool: &PgPool) -> Fixture {
    let owner = seed_agent(pool).await;
    let member = seed_agent(pool).await;
    let stranger = seed_agent(pool).await;
    let ours = seed_community(pool, &[member]).await;
    let theirs = seed_community(pool, &[stranger]).await;
    let empty = seed_community(pool, &[]).await;

    // `ownership_partition_check` only admits the three known partitions;
    // lift it so the unknown-partition branch is reachable.
    sqlx::query("ALTER TABLE ownership DROP CONSTRAINT ownership_partition_check")
        .execute(pool)
        .await
        .unwrap();

    let ours_hyphenated = ours.to_string();
    let ours_simple = ours.simple().to_string();
    let theirs_key = theirs.to_string();
    let empty_key = empty.to_string();
    #[rustfmt::skip]
    let rows: Vec<(&'static str, Option<Ownership>, [ContentAccess; 4])> = vec![
        //                                                                    anon owner member stranger
        ("public",                Some(("public", None)),                     [F, F, F, F]),
        ("no ownership row",      None,                                       [F, F, F, F]),
        ("private",               Some(("private", None)),                    [R, F, R, R]),
        ("community, member",     Some(("community", Some(&ours_hyphenated))), [R, R, F, R]),
        ("community, simple key", Some(("community", Some(&ours_simple))),     [R, R, F, R]),
        ("community, other",      Some(("community", Some(&theirs_key))),      [R, R, R, F]),
        ("community, no members", Some(("community", Some(&empty_key))),       [R, R, R, R]),
        ("community, bad key",    Some(("community", Some("not-a-uuid"))),     [R, F, R, R]),
        ("community, null key",   Some(("community", None)),                  [R, F, R, R]),
        ("unknown partition",     Some(("quarantine", None)),                 [F, F, F, F]),
    ];

    let mut cases = Vec::new();
    for (name, ownership, expected) in rows {
        let node = Uuid::new_v4();
        if let Some((partition, key)) = ownership {
            seed_ownership(pool, node, partition, owner, key).await;
        }
        cases.push((name, node, expected));
    }
    Fixture {
        owner,
        member,
        stranger,
        cases,
    }
}

/// For every requester: the batch map, the ordered batch view and a per-id
/// `check_content_access` all agree, and match `expected(case, requester, row)`.
async fn assert_batch_matches_single(
    pool: &PgPool,
    fx: &Fixture,
    expected: impl Fn(&str, usize, [ContentAccess; 4]) -> ContentAccess,
) {
    let mut ids = fx.ids();
    // A duplicate must collapse in the map and survive in the ordered view.
    ids.push(ids[0]);

    for (ri, (who, requester)) in fx.requesters().into_iter().enumerate() {
        let batch: HashMap<Uuid, ContentAccess> = batch_content_access(pool, &ids, requester).await;
        assert_eq!(
            batch.len(),
            fx.cases.len(),
            "{who}: one entry per distinct id"
        );

        let ordered = batch_check_content_access(pool, &ids, requester).await;
        assert_eq!(
            ordered.iter().map(|&(id, _)| id).collect::<Vec<_>>(),
            ids,
            "{who}: ordered view keeps input order and duplicates"
        );

        for &(name, node, table) in &fx.cases {
            let single = check_content_access(pool, node, requester).await;
            assert_eq!(batch[&node], single, "{who} / {name}: batch != single");
            assert_eq!(
                single,
                expected(name, ri, table),
                "{who} / {name}: unexpected decision"
            );
        }
        for &(id, decision) in &ordered {
            assert_eq!(decision, batch[&id], "{who}: ordered view != map");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn batch_content_access_matches_check_content_access(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    assert_batch_matches_single(&pool, &fx, |_, ri, table| table[ri]).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn batch_content_access_of_nothing_is_empty(pool: PgPool) {
    assert!(batch_content_access(&pool, &[], None).await.is_empty());
    assert!(batch_check_content_access(&pool, &[], None)
        .await
        .is_empty());
}

/// The membership lookup fails: both paths redact the community nodes that
/// needed it and leave every other decision alone.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_fails_closed_like_single_when_membership_lookup_errors(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    sqlx::query("ALTER TABLE community_members RENAME TO community_members_unavailable")
        .execute(&pool)
        .await
        .unwrap();

    // Community rows that would have gone to the membership query are the
    // only ones whose decision changes: every `F` they had becomes `R`.
    let needs_membership = [
        "community, member",
        "community, simple key",
        "community, other",
        "community, no members",
    ];
    assert_batch_matches_single(&pool, &fx, |name, ri, table| {
        if needs_membership.contains(&name) {
            R
        } else {
            table[ri]
        }
    })
    .await;
}

/// The ownership lookup fails: both paths redact every id, including the ones
/// that have no ownership row.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_fails_closed_like_single_when_ownership_lookup_errors(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    sqlx::query("ALTER TABLE ownership RENAME TO ownership_unavailable")
        .execute(&pool)
        .await
        .unwrap();

    assert_batch_matches_single(&pool, &fx, |_, _, _| R).await;
}
