//! Evidence is de-duplicated per OWNER, in the application, and never across
//! owners (backlog 12b68201, operator ruling R-77).
//!
//! Migration 001's `evidence_content_hash_claim_unique UNIQUE (content_hash,
//! claim_id)` spanned every owner of a claim's evidence, so a write whose body
//! equalled a row another group holds on the same claim was refused, and the
//! refusal confirmed that unreadable row and its exact content. The long-lived
//! database never carried that key (schema drift, like 013's
//! `uq_claims_content_hash_agent` before migration 150), and it holds
//! same-owner duplicate rows. So the key is dropped everywhere and the
//! de-duplication lives in `EvidenceRepository`, under a transaction-scoped
//! advisory lock on `(content_hash, claim_id, owner)`.
//!
//! What each test pins:
//!
//! * on the APPLICATION ROLE with real stamps, a writer's body that another
//!   group already holds on the claim lands, and the same writer's identical
//!   retry is still `DuplicateKey`;
//! * same-owner duplicates already stored (the long-lived database's shape)
//!   stay valid: a third copy is answered as a duplicate, and rewriting one of
//!   them, to its own body or to a fresh one, succeeds;
//! * two concurrent identical first writes serialize to ONE row (the lock is
//!   the only thing that makes this hold without a unique key);
//! * derivation provenance (`record_derivation_conn`) is recorded once and is
//!   then `AlreadyPresent`, with no unique key to name in an `ON CONFLICT`, and
//!   still `AlreadyPresent` (not an error) on a database that keeps 001's key
//!   until migration 171 applies (the binary deploys first);
//! * a claim on which two owners hold the same body can still be privatized,
//!   and both rows survive (no key for the narrowing to collide on);
//! * `batch_create` takes the same per-owner de-duplication: a same-tenancy
//!   duplicate refuses the whole batch, another owner's identical body lands;
//! * a row another group holds on an atom with the parent's text does not
//!   suppress that atom's derivation row.
//! * no unique index on `evidence` covers `(content_hash, claim_id)` (171's
//!   effect).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceId, EvidenceType};
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::{DbError, DerivationEvidence, EvidenceRepository};
use sqlx::{PgConnection, PgPool};
use std::time::Duration;
use uuid::Uuid;

fn digest(body: &str) -> [u8; 32] {
    *blake3::hash(body.as_bytes()).as_bytes()
}

fn document(agent: Uuid, claim: Uuid, body: &str) -> Evidence {
    Evidence::new(
        AgentId::from_uuid(agent),
        [0u8; 32],
        digest(body),
        EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        },
        Some(body.to_string()),
        ClaimId::from_uuid(claim),
    )
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` with `agent`'s real viewer, the way `ScopedPool` does.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("a scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "fixture: the agent can write somewhere"
    );
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

async fn seed_public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("a public claim {id}"))
    .bind(digest(&id.to_string()).as_slice())
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `(owner_group_id, writer_owned)` of every row on `claim` with `body`'s
/// digest, sorted.
async fn rows_with_body(pool: &PgPool, claim: Uuid, body: &str) -> Vec<(Uuid, bool)> {
    sqlx::query_as(
        "SELECT owner_group_id, writer_owned FROM evidence \
          WHERE claim_id = $1 AND content_hash = $2 ORDER BY owner_group_id, writer_owned",
    )
    .bind(claim)
    .bind(digest(body).as_slice())
    .fetch_all(pool)
    .await
    .expect("read rows by digest")
}

fn is_duplicate(res: &Result<Evidence, DbError>) -> bool {
    matches!(res, Err(DbError::DuplicateKey { .. }))
}

#[sqlx::test(migrations = "../../migrations")]
async fn on_the_app_role_another_owners_body_lands_and_an_identical_retry_is_a_duplicate(
    pool: PgPool,
) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-owner").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "dedup-writer").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let body = format!("one body, two owners {}", Uuid::new_v4());

    let p = pool.clone();
    let b = body.clone();
    let (owners_write, writers_write, writers_retry) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, owner).await;
            let o = EvidenceRepository::create(&mut *conn, &document(owner, claim, &b)).await;
            stamp(&mut conn, &p, writer).await;
            let w = EvidenceRepository::create(&mut *conn, &document(writer, claim, &b)).await;
            let r = EvidenceRepository::create(&mut *conn, &document(writer, claim, &b)).await;
            (conn, (o, w, r))
        })
        .await;

    owners_write.expect("the claim owner's evidence lands");
    let landed = writers_write.unwrap_or_else(|e| {
        panic!(
            "the writer's evidence collided with the owner's row: a write must not observe \
             another owner's evidence (and a hidden one would be confirmed by it): {e:?}"
        )
    });
    assert!(
        is_duplicate(&writers_retry),
        "the same writer's identical evidence on the same claim is a duplicate: \
         {writers_retry:?}"
    );
    let mut expected = vec![(owner_group, false), (writer_group, true)];
    expected.sort();
    assert_eq!(
        rows_with_body(&pool, claim, &body).await,
        expected,
        "one row per owner: the owner's inherited row and the writer's own row"
    );
    let stored: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE id = $1")
        .bind(Uuid::from(landed.id))
        .fetch_one(&pool)
        .await
        .expect("read the writer's row");
    assert_eq!(stored, writer_group, "the writer's row is the writer's");
}

#[sqlx::test(migrations = "../../migrations")]
async fn same_owner_duplicates_already_stored_stay_valid(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-legacy").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let body = format!("a legacy duplicated body {}", Uuid::new_v4());

    // The long-lived database's shape: one owner, one body, two rows.
    let mut pair = Vec::new();
    for _ in 0..2 {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id) \
             VALUES ($1, 'document', $2, $3) RETURNING id",
        )
        .bind(digest(&body).as_slice())
        .bind(&body)
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("a same-owner duplicate pair can be stored (no unique evidence key)");
        pair.push(id);
    }

    let third = EvidenceRepository::create(&pool, &document(owner, claim, &body)).await;
    assert!(
        is_duplicate(&third),
        "a third copy is answered as a duplicate: {third:?}"
    );
    assert_eq!(rows_with_body(&pool, claim, &body).await.len(), 2);

    let owners_viewer = Viewer::resolve(&pool, owner).await.expect("owner's viewer");
    let same = EvidenceRepository::update_raw_content(
        &pool,
        &owners_viewer,
        EvidenceId::from_uuid(pair[0]),
        &body,
    )
    .await
    .expect("rewriting a duplicate to its own body is not a new duplicate");
    assert!(same, "the rewrite to its own body lands");
    let fresh = format!("a fresh body {}", Uuid::new_v4());
    let moved = EvidenceRepository::update_raw_content(
        &pool,
        &owners_viewer,
        EvidenceId::from_uuid(pair[1]),
        &fresh,
    )
    .await
    .expect("rewriting a duplicate to a fresh body succeeds");
    assert!(moved, "the rewrite to a fresh body lands");
    assert_eq!(rows_with_body(&pool, claim, &body).await.len(), 1);
    assert_eq!(rows_with_body(&pool, claim, &fresh).await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_identical_first_writes_serialize_to_one_row(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-race").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let body = format!("two first writes at once {}", Uuid::new_v4());

    let mut first = pool.begin().await.expect("begin the first writer");
    EvidenceRepository::create(&mut *first, &document(owner, claim, &body))
        .await
        .expect("the first write lands in its open transaction");

    let p = pool.clone();
    let b = body.clone();
    let mut second =
        tokio::spawn(
            async move { EvidenceRepository::create(&p, &document(owner, claim, &b)).await },
        );
    assert!(
        tokio::time::timeout(Duration::from_millis(750), &mut second)
            .await
            .is_err(),
        "the second identical write must wait for the first to commit; it finished first, \
         so nothing serializes the two"
    );
    first.commit().await.expect("commit the first writer");

    let second = tokio::time::timeout(Duration::from_secs(20), second)
        .await
        .expect("the second write finishes once the first commits")
        .expect("join");
    assert!(
        is_duplicate(&second),
        "the second write sees the committed first and is a duplicate: {second:?}"
    );
    assert_eq!(
        rows_with_body(&pool, claim, &body).await,
        vec![(owner_group, false)],
        "exactly one row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn derivation_evidence_is_recorded_once(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-derive").await;
    let parent = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let atom = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let viewer = fixture::public_viewer(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let first =
        EvidenceRepository::record_derivation_conn(&mut conn, &viewer, atom, parent, "test")
            .await
            .expect("the first derivation write succeeds");
    assert!(
        matches!(first, DerivationEvidence::Recorded(_)),
        "first: {first:?}"
    );
    let again =
        EvidenceRepository::record_derivation_conn(&mut conn, &viewer, atom, parent, "test")
            .await
            .expect("a re-applied derivation succeeds");
    assert!(
        matches!(again, DerivationEvidence::AlreadyPresent),
        "a re-applied derivation writes nothing: {again:?}"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence WHERE claim_id = $1 \
            AND properties->>'derived_from_claim' = $2",
    )
    .bind(atom)
    .bind(parent.to_string())
    .fetch_one(&pool)
    .await
    .expect("count derivation rows");
    assert_eq!(rows, 1, "exactly one derivation row");
}

/// The deploy order is the binary first, then migration 171, so the binary
/// meets databases that still carry 001's `(content_hash, claim_id)` key. A
/// re-applied derivation there hits the key before the application check runs;
/// it must still answer `AlreadyPresent` (as the old `ON CONFLICT DO NOTHING`
/// did), not an error, and leave the caller's transaction usable.
#[sqlx::test(migrations = "../../migrations")]
async fn derivation_is_already_present_on_a_database_that_still_has_the_key(pool: PgPool) {
    sqlx::query(
        "ALTER TABLE evidence ADD CONSTRAINT evidence_content_hash_claim_unique \
         UNIQUE (content_hash, claim_id)",
    )
    .execute(&pool)
    .await
    .expect("re-add 001's key, as on a database below 171");
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-derive-key").await;
    let parent = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let atom = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let viewer = fixture::public_viewer(&pool).await;

    let mut tx = pool.begin().await.expect("the caller's transaction");
    let first = EvidenceRepository::record_derivation_conn(&mut tx, &viewer, atom, parent, "test")
        .await
        .expect("the first derivation write succeeds");
    assert!(
        matches!(first, DerivationEvidence::Recorded(_)),
        "first: {first:?}"
    );
    let again = EvidenceRepository::record_derivation_conn(&mut tx, &viewer, atom, parent, "test")
        .await
        .unwrap_or_else(|e| {
            panic!("a re-applied derivation on a keyed database must not be an error: {e:?}")
        });
    assert!(
        matches!(again, DerivationEvidence::AlreadyPresent),
        "again: {again:?}"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(atom)
        .fetch_one(&mut *tx)
        .await
        .expect("the caller's transaction is still usable");
    assert_eq!(rows, 1);
    tx.commit().await.expect("commit");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_two_owners_hold_one_body_on_can_still_be_privatized(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-priv-owner").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "dedup-priv-writer").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let body = format!("one body before privatization {}", Uuid::new_v4());

    let p = pool.clone();
    let b = body.clone();
    let (o, w) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let o = EvidenceRepository::create(&mut *conn, &document(owner, claim, &b)).await;
        stamp(&mut conn, &p, writer).await;
        let w = EvidenceRepository::create(&mut *conn, &document(writer, claim, &b)).await;
        (conn, (o, w))
    })
    .await;
    o.expect("the owner's row");
    w.expect("the writer's row, beside the owner's");

    let mut tx = pool.begin().await.expect("begin");
    let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, &[claim], owner_group)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "privatizing a claim on which two owners hold one body failed; a same-body \
                 row under another owner must not block the claim's privatization: {e:?}"
            )
        });
    tx.commit().await.expect("commit");
    assert_eq!(moved, vec![claim]);
    // Both rows survive. Which group then owns the writer's row is migration
    // 168's narrowing, not this ruling's, and is deliberately not asserted
    // here (privatization_seal.rs pins it as current behaviour).
    assert_eq!(
        rows_with_body(&pool, claim, &body).await.len(),
        2,
        "both rows survive the privatization"
    );
}

/// Evidence on `claim` with `body`, held by `group` the way the operator
/// `hide` holds a row: a visibility pin (migration 110), then owner and
/// visibility. As the harness superuser.
async fn seed_held_body(pool: &PgPool, claim: Uuid, group: Uuid, body: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id) \
         VALUES ($1, 'document', $2, $3) RETURNING id",
    )
    .bind(digest(body).as_slice())
    .bind(body)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed the held row");
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: held by another group')",
    )
    .bind(id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("pin the held row");
    sqlx::query("UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE id = $1")
        .bind(id)
        .bind(group)
        .execute(pool)
        .await
        .expect("hold the row in the other group");
    id
}

/// `batch_create` de-duplicates per owner like `create`: a batch carrying a
/// body already stored in the same tenancy is refused WHOLE (`DuplicateKey`,
/// nothing written, the fresh row in it included), and a batch carrying a body
/// another group holds on the claim lands beside that group's row.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_create_refuses_a_same_tenancy_duplicate_whole_and_lands_another_owners_body(
    pool: PgPool,
) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-batch-owner").await;
    let (_other, other_group) = fixture::seed_agent_with_group(&pool, "dedup-batch-other").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let stored = format!("a body already stored {}", Uuid::new_v4());
    let fresh = format!("a body nobody holds {}", Uuid::new_v4());
    let held = format!("a body another group holds {}", Uuid::new_v4());

    EvidenceRepository::batch_create(&pool, &[document(owner, claim, &stored)])
        .await
        .expect("control: the first batch lands");

    let refused = EvidenceRepository::batch_create(
        &pool,
        &[
            document(owner, claim, &fresh),
            document(owner, claim, &stored),
        ],
    )
    .await;
    assert!(
        matches!(refused, Err(DbError::DuplicateKey { .. })),
        "a batch carrying a same-tenancy duplicate is a duplicate: {refused:?}"
    );
    assert!(
        rows_with_body(&pool, claim, &fresh).await.is_empty(),
        "a refused batch writes nothing, its fresh row included"
    );
    assert_eq!(rows_with_body(&pool, claim, &stored).await.len(), 1);

    let intra = EvidenceRepository::batch_create(
        &pool,
        &[
            document(owner, claim, &fresh),
            document(owner, claim, &fresh),
        ],
    )
    .await;
    assert!(
        matches!(intra, Err(DbError::DuplicateKey { .. })),
        "two identical rows in one batch are a duplicate: {intra:?}"
    );
    assert!(rows_with_body(&pool, claim, &fresh).await.is_empty());

    let held_row = seed_held_body(&pool, claim, other_group, &held).await;
    let landed = EvidenceRepository::batch_create(&pool, &[document(owner, claim, &held)])
        .await
        .unwrap_or_else(|e| {
            panic!("a body another group holds on the claim must land like a fresh one: {e:?}")
        });
    assert_eq!(landed.len(), 1);
    let rows = rows_with_body(&pool, claim, &held).await;
    assert_eq!(rows.len(), 2, "both rows stand: {rows:?}");
    assert!(
        rows.contains(&(owner_group, false)),
        "the new row is the claim's: {rows:?}"
    );
    let held_owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE id = $1")
        .bind(held_row)
        .fetch_one(&pool)
        .await
        .expect("read the held row");
    assert_eq!(held_owner, other_group, "the held row is untouched");
}

/// A row another group holds on the atom whose body is the parent's text is a
/// different tenancy: it must not suppress the atom's own derivation row.
#[sqlx::test(migrations = "../../migrations")]
async fn another_groups_row_with_the_parents_text_does_not_suppress_a_derivation(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "dedup-derive-x").await;
    let (_other, other_group) = fixture::seed_agent_with_group(&pool, "dedup-derive-held").await;
    let parent = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let atom = seed_public_claim_owned_by(&pool, owner, owner_group).await;
    let parent_text: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("read the parent's text");
    let held = seed_held_body(&pool, atom, other_group, &parent_text).await;
    let viewer = fixture::public_viewer(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let recorded =
        EvidenceRepository::record_derivation_conn(&mut conn, &viewer, atom, parent, "test")
            .await
            .expect("the derivation write succeeds");
    let DerivationEvidence::Recorded(id) = recorded else {
        panic!(
            "another group's row with the parent's text suppressed the atom's derivation: \
             {recorded:?}"
        );
    };
    assert_ne!(id, held);
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT owner_group_id, properties->>'derived_from_claim' FROM evidence \
          WHERE claim_id = $1 ORDER BY (id = $2)",
    )
    .bind(atom)
    .bind(held)
    .fetch_all(&pool)
    .await
    .expect("read the atom's evidence");
    assert_eq!(
        rows,
        vec![(owner_group, Some(parent.to_string())), (other_group, None)],
        "one new derivation row, the claim's, beside the held row"
    );
    assert_eq!(
        rows_with_body(&pool, atom, &parent_text).await.len(),
        2,
        "both rows carry the parent text's digest, so only the tenancy told them apart"
    );
}

/// Migration 171's effect, pinned against a later migration re-adding it: no
/// unique index on `evidence` covers both `content_hash` and `claim_id`,
/// whatever its name. The long-lived database never had one; every freshly
/// migrated one carried 001's until 171.
#[sqlx::test(migrations = "../../migrations")]
async fn migrated_evidence_carries_no_unique_key_over_body_and_claim(pool: PgPool) {
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT ic.relname::text FROM pg_index i \
           JOIN pg_class ic ON ic.oid = i.indexrelid \
          WHERE i.indrelid = 'public.evidence'::regclass AND i.indisunique \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = i.indrelid \
                          AND a.attname = 'content_hash' AND a.attnum = ANY (i.indkey)) \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = i.indrelid \
                          AND a.attname = 'claim_id' AND a.attnum = ANY (i.indkey)) \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("read evidence unique indexes");
    assert!(
        keys.is_empty(),
        "evidence carries a unique key over (content_hash, claim_id): {keys:?}. It spans \
         owners, so a write that collides with another group's hidden row is refused and \
         confirms it; de-duplication is the application's (EvidenceRepository)"
    );
}
