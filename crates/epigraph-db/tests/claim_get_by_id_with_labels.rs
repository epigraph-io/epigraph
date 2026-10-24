//! Integration tests for `ClaimRepository::get_by_id_with_labels`.
//!
//! Regression coverage for the `get_claim` TOCTOU race: the old MCP handler
//! fetched a claim's core fields and its labels via two separate,
//! unsynchronized queries (`get_by_id` then `get_labels`), so a concurrent
//! `update_labels` between the two round trips could return labels
//! inconsistent with the claim row already read. `get_by_id_with_labels`
//! reads both from a single SQL statement, which is inherently consistent
//! under Postgres MVCC.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_with_labels_returns_none_when_no_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;

    // Seed a DECOY that must NOT be returned. On the shared database this arm
    // used to run against, some sibling arm's rows happened to supply this
    // role; that discrimination was an accident of execution order, not a
    // property of the test. `#[sqlx::test]` hands us an empty table, so without
    // an explicit decoy `is_none()` would be satisfied by there being nothing
    // to return at all — deleting the `WHERE id = $1` predicate from
    // `get_by_id_with_labels` would still pass. The decoy makes the predicate
    // the only reason the result is None.
    let decoy_agent = Uuid::new_v4();
    insert_test_agent(&pool, decoy_agent).await;
    let decoy = ClaimRepository::create(
        &pool,
        &make_claim(&format!("decoy {}", Uuid::new_v4()), decoy_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create decoy");

    let found =
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, epigraph_core::ClaimId::new())
            .await
            .expect("query call");

    assert!(found.is_none(), "expected None, got {:?}", found.is_some());

    // The decoy is real, visible to this viewer, and would have been returned
    // by an unfiltered query — otherwise the assertion above proves nothing.
    assert!(
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, decoy.id)
            .await
            .expect("query call")
            .is_some(),
        "decoy must be retrievable by its own id, or it cannot discriminate"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_with_labels_matches_separate_calls(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("atomic read {}", Uuid::new_v4()), agent_id);
    let created = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    ClaimRepository::update_labels(
        &pool,
        created.id.as_uuid(),
        &["backlog".to_string(), "atomic".to_string()],
        &[],
    )
    .await
    .expect("seed labels");

    // Seed a second LABELLED claim under a different agent. Without it the
    // per-test database holds exactly one labelled claim, so dropping the
    // claim_id predicate from `get_labels` would return that same row's labels
    // and the `new_sorted == ["atomic", "backlog"]` assertion would still pass.
    // The decoy's labels are disjoint, so any leak changes the result.
    let decoy_agent = Uuid::new_v4();
    insert_test_agent(&pool, decoy_agent).await;
    let decoy = ClaimRepository::create(
        &pool,
        &make_claim(&format!("decoy labels {}", Uuid::new_v4()), decoy_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create decoy");
    ClaimRepository::update_labels(&pool, decoy.id.as_uuid(), &["decoy-label".to_string()], &[])
        .await
        .expect("seed decoy labels");

    let (via_new, labels_via_new) =
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, created.id)
            .await
            .expect("get_by_id_with_labels")
            .expect("claim exists");

    let via_old = ClaimRepository::get_by_id(&pool, &viewer, created.id)
        .await
        .expect("get_by_id")
        .expect("claim exists");
    let labels_via_old = ClaimRepository::get_labels(&pool, &viewer, created.id)
        .await
        .expect("get_labels");

    assert_eq!(via_new.id, via_old.id);
    assert_eq!(via_new.content, via_old.content);
    assert_eq!(via_new.agent_id, via_old.agent_id);
    assert_eq!(via_new.is_current, via_old.is_current);
    assert_eq!(via_new.supersedes, via_old.supersedes);

    let mut new_sorted = labels_via_new.clone();
    new_sorted.sort();
    let mut old_sorted = labels_via_old.clone();
    old_sorted.sort();
    assert_eq!(new_sorted, old_sorted);
    assert_eq!(
        new_sorted,
        vec!["atomic".to_string(), "backlog".to_string()]
    );
}

const CLAIM_RS: &str = include_str!("../src/repos/claim.rs");

/// The body (outermost braces included) of the function whose signature starts
/// with `signature`. Panics when the signature is absent or appears twice, so a
/// rename cannot make the structural assertion pass vacuously.
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let hits: Vec<usize> = src.match_indices(signature).map(|(i, _)| i).collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{signature}` in repos/claim.rs, found {}",
        hits.len()
    );
    let start = hits[0];
    let open = start + src[start..].find('{').expect("function has a body");
    let mut depth = 0usize;
    for (off, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=open + off];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after `{signature}`");
}

/// The single-claim readers decode through `FromRow`, never `sqlx::Row::get`.
///
/// `Row::get` PANICS on a missing column or a type mismatch; a `FromRow`
/// decode through `query_as` returns `Err` for the same row. These are the
/// read path of MCP and REST `get_claim`, so a schema drift must surface as a
/// `DbError`, not a panicked request task. A behavioural red is not
/// constructible (every projected column exists and `claims.labels` is
/// `NOT NULL`), so the property is pinned on the source. Scoped to these three
/// bodies: other readers in the file use `row.get` and are out of scope here.
///
/// Each body is pinned POSITIVELY on the decode it must use (so deleting the
/// decode cannot pass), and negatively on every spelling of a `Row` decode
/// regardless of what the row variable is called: a bare `sqlx::query(` (which
/// yields a `PgRow`), any `sqlx::Row` import or path call, and any `.get(` /
/// `.get::<` call.
#[test]
fn single_claim_readers_decode_fallibly() {
    for (sig, required) in [
        (
            "pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(",
            &[
                "sqlx::query_as::<_, SingleClaimRow>(&sql)",
                "row.map(SingleClaimRow::into_claim)",
            ][..],
        ),
        (
            "pub async fn get_by_id_with_labels<'e, E: sqlx::PgExecutor<'e>>(",
            &[
                "sqlx::query_as::<_, SingleClaimRowWithLabels>(&sql)",
                "r.row.into_claim()?",
            ][..],
        ),
        (
            "pub async fn get_by_id_conn(",
            &["Self::get_by_id(&mut *conn, viewer, id)"][..],
        ),
    ] {
        let body = fn_body(CLAIM_RS, sig);
        for needle in required {
            assert!(
                body.contains(needle),
                "`{sig}` must decode through `{needle}` (a `FromRow` decode that \
                 returns Err on a drifted column).\nbody:\n{body}"
            );
        }
        for forbidden in ["sqlx::Row", "sqlx::query(", ".get(", ".get::<"] {
            assert!(
                !body.contains(forbidden),
                "`{sig}` decodes with a panicking `sqlx::Row` accessor (`{forbidden}`); \
                 decode through `query_as` + `#[derive(sqlx::FromRow)]` so a drifted \
                 column is an Err, not a panic.\nbody:\n{body}"
            );
        }
    }
}

/// `get_by_id_with_labels` returns the same `Claim` as `get_by_id`, field for
/// field, including the crypto and retirement columns both post-fix — and
/// those values are the STORED ones (absolute pins), so one shared decode that
/// was wrong twice cannot pass on equality alone.
#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_with_labels_matches_get_by_id_on_every_field(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;
    let agent_pk: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Signed, with a stored digest that is NOT blake3(content), and labelled.
    let signed_text = format!("with-labels signed {}", Uuid::new_v4());
    let signed_sig: Vec<u8> = (0u8..64).rev().collect();
    // A NON-NULL trace_id, so its decode is pinned to a stored value rather
    // than compared NULL to NULL. `claims.trace_id` references
    // `reasoning_traces`, whose row names a claim: an anchor carries it.
    let anchor_text = format!("with-labels trace anchor {}", Uuid::new_v4());
    let anchor: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(&anchor_text)
    .bind(agent_id)
    .fetch_one(&pool)
    .await
    .expect("seed trace anchor claim");
    let trace: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
         VALUES ($1, 'deductive', 'get_by_id_with_labels trace fixture') RETURNING id",
    )
    .bind(anchor)
    .fetch_one(&pool)
    .await
    .expect("seed reasoning trace");
    let trace_id: Option<Uuid> = Some(trace);
    let signed: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             signature, signer_id, labels, trace_id) \
         VALUES ($1, sha256($1::bytea), 0.375, $2, $3, $2, ARRAY['sig','x'], $4) RETURNING id",
    )
    .bind(&signed_text)
    .bind(agent_id)
    .bind(&signed_sig)
    .bind(trace)
    .fetch_one(&pool)
    .await
    .expect("seed signed claim");

    // Retired, naming what it supersedes.
    let retired_text = format!("with-labels retired {}", Uuid::new_v4());
    let retired: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             is_current, supersedes) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, false, $3) RETURNING id",
    )
    .bind(&retired_text)
    .bind(agent_id)
    .bind(signed)
    .fetch_one(&pool)
    .await
    .expect("seed retired claim");

    for id in [signed, retired] {
        let cid = epigraph_core::ClaimId::from_uuid(id);
        let (with, _labels) = ClaimRepository::get_by_id_with_labels(&pool, &viewer, cid)
            .await
            .expect("get_by_id_with_labels")
            .expect("claim exists");
        let plain = ClaimRepository::get_by_id(&pool, &viewer, cid)
            .await
            .expect("get_by_id")
            .expect("claim exists");
        assert_eq!(with.id, plain.id);
        assert_eq!(with.content, plain.content);
        assert_eq!(with.agent_id, plain.agent_id);
        assert_eq!(with.truth_value.value(), plain.truth_value.value());
        assert_eq!(with.trace_id, plain.trace_id);
        assert_eq!(with.created_at, plain.created_at);
        assert_eq!(with.updated_at, plain.updated_at);
        assert_eq!(
            with.content_hash, plain.content_hash,
            "content_hash for {id}"
        );
        assert_eq!(with.signature, plain.signature, "signature for {id}");
        assert_eq!(with.public_key, plain.public_key, "public_key for {id}");
        assert_eq!(with.is_current, plain.is_current, "is_current for {id}");
        assert_eq!(with.supersedes, plain.supersedes, "supersedes for {id}");
    }

    let (s, s_labels) = ClaimRepository::get_by_id_with_labels(
        &pool,
        &viewer,
        epigraph_core::ClaimId::from_uuid(signed),
    )
    .await
    .unwrap()
    .unwrap();
    let stored_hash: Vec<u8> = sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = $1")
        .bind(signed)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        s.content_hash.to_vec(),
        stored_hash,
        "the STORED digest, not blake3"
    );
    assert_eq!(s.signature.map(|x| x.to_vec()), Some(signed_sig));
    assert_eq!(s.public_key.to_vec(), agent_pk, "the signer's key");
    assert_eq!(s.truth_value.value(), 0.375);
    assert_eq!(s.trace_id.map(Uuid::from), trace_id, "the STORED trace_id");
    let (created_at, updated_at): (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT created_at, updated_at FROM claims WHERE id = $1")
            .bind(signed)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (s.created_at, s.updated_at),
        (created_at, updated_at),
        "the STORED timestamps"
    );
    assert_eq!(s_labels, vec!["sig".to_string(), "x".to_string()]);

    let (r, _) = ClaimRepository::get_by_id_with_labels(
        &pool,
        &viewer,
        epigraph_core::ClaimId::from_uuid(retired),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!r.is_current, "a retired claim reads back as not current");
    assert_eq!(r.supersedes.map(|c| c.as_uuid()), Some(signed));
}
