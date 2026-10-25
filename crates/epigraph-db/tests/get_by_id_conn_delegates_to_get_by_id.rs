//! `ClaimRepository::get_by_id_conn` and `::get_by_id` are ONE predicate.
//!
//! # What this replaces
//!
//! `get_by_id_conn` was a hand-written second copy of `get_by_id`: its own
//! `viewer.splice` SQL text, its own `/* {VISIBILITY:c} */` marker, its own
//! `row.get` decode. `visibility_lint.rs` checks that each SQL text carries a
//! marker, never that two texts agree, so a fix applied to one copy and not the
//! other is invisible to every gate (backlog `fd47651c`,
//! `F-get-by-id-conn-duplicates-get-by-id`). This exact pair has drifted once
//! already (the seven-vs-nine projection drift `no_unscoped_pool.rs` records).
//!
//! The ledger's reason for not collapsing it — `get_by_id` being a
//! `sqlx::query!` macro site — stopped being true when `get_by_id` moved to a
//! runtime `query_as` + `Viewer::splice` that is generic over
//! `sqlx::PgExecutor`. `&mut PgConnection` is a `PgExecutor`, so the
//! `list_conn` / `count_conn` delegation shape applies directly.
//!
//! # Two tests, two different jobs
//!
//! * `get_by_id_conn_is_a_pure_delegation` is the STRUCTURAL pin: it reads the
//!   repository source and fails if `get_by_id_conn` grows its own SQL again.
//!   That is the property no runtime assertion can see: two copies that agree
//!   today pass every behavioural test until the day they don't.
//! * `get_by_id_conn_returns_exactly_what_get_by_id_returns` is the behavioural
//!   guard. Equality alone is NOT sufficient once both entry points run one
//!   body (a leak in that body leaks through both and they stay equal; see
//!   `list_conn_delegates_to_list.rs`), so it also pins absolute values: the
//!   stranger's `None`, the stored (not recomputed) digest, the stored
//!   signature and signer key, and the retirement state.

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

const CLAIM_RS: &str = include_str!("../src/repos/claim.rs");

/// The body (outermost braces included) of the function whose signature starts
/// with `signature`. Panics when the signature is absent or appears twice, so a
/// rename cannot make the structural assertions pass vacuously.
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let hits: Vec<usize> = src.match_indices(signature).map(|(i, _)| i).collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{signature}` in repos/claim.rs, found {}; the \
         structural pin must name the function it checks",
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

#[test]
fn get_by_id_conn_is_a_pure_delegation() {
    let body = fn_body(CLAIM_RS, "pub async fn get_by_id_conn(");
    for forbidden in [
        "sqlx::query",
        ".splice(",
        "SELECT",
        "row.get",
        "use sqlx::Row",
    ] {
        assert!(
            !body.contains(forbidden),
            "get_by_id_conn carries its own `{forbidden}`: it is a second SQL text for \
             get_by_id's visibility predicate, which nothing keeps in sync. It must \
             delegate to `Self::get_by_id(&mut *conn, ..)`.\nbody:\n{body}"
        );
    }
    assert!(
        body.contains("Self::get_by_id(&mut *conn, viewer, id)"),
        "get_by_id_conn must delegate to get_by_id on the caller's connection.\nbody:\n{body}"
    );
}

/// Every field of a `Claim`, in a comparable form.
type Fields = (
    Uuid,
    String,
    u64,
    Uuid,
    [u8; 32],
    [u8; 32],
    Option<Uuid>,
    Option<Vec<u8>>,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
    bool,
    Option<Uuid>,
);

fn fields(c: &epigraph_core::Claim) -> Fields {
    (
        c.id.as_uuid(),
        c.content.clone(),
        c.truth_value.value().to_bits(),
        c.agent_id.as_uuid(),
        c.public_key,
        c.content_hash,
        c.trace_id.map(Into::into),
        c.signature.map(|s| s.to_vec()),
        c.created_at,
        c.updated_at,
        c.is_current,
        c.supersedes.map(Into::into),
    )
}

async fn both(pool: &PgPool, viewer: &Viewer, id: Uuid) -> (Option<Fields>, Option<Fields>) {
    let via_pool = ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(id))
        .await
        .expect("get_by_id on the pool");
    let mut conn = pool.acquire().await.expect("acquire a connection");
    let via_conn = ClaimRepository::get_by_id_conn(&mut conn, viewer, ClaimId::from_uuid(id))
        .await
        .expect("get_by_id_conn on that connection");
    (via_pool.as_ref().map(fields), via_conn.as_ref().map(fields))
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_conn_returns_exactly_what_get_by_id_returns(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "getbyidconn-owner").await;
    let owner_pk: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();

    // A NON-NULL trace_id, so the trace column's decode is pinned to a stored
    // value rather than compared NULL to NULL. `claims.trace_id` references
    // `reasoning_traces`, whose row in turn names a claim: an anchor claim
    // carries the trace.
    let anchor_text = format!("getbyidconn trace anchor {}", Uuid::new_v4());
    let anchor: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(&anchor_text)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed trace anchor claim");
    let trace: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
         VALUES ($1, 'deductive', 'get_by_id_conn trace fixture') RETURNING id",
    )
    .bind(anchor)
    .fetch_one(&pool)
    .await
    .expect("seed reasoning trace");

    // A SIGNED public claim whose stored digest is deliberately NOT
    // blake3(content): `claim_from_row` recomputes blake3, so only a reader
    // that post-fixes the stored columns returns this sha256.
    let signed_text = format!("getbyidconn signed {}", Uuid::new_v4());
    let signed_sig: Vec<u8> = (0u8..64).collect();
    let signed: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             signature, signer_id, trace_id) \
         VALUES ($1, sha256($1::bytea), 0.625, $2, $3, $2, $4) RETURNING id",
    )
    .bind(&signed_text)
    .bind(owner)
    .bind(&signed_sig)
    .bind(trace)
    .fetch_one(&pool)
    .await
    .expect("seed signed claim");

    // A retired claim naming what it supersedes.
    let retired_text = format!("getbyidconn retired {}", Uuid::new_v4());
    let retired: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                             is_current, supersedes) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, false, $3) RETURNING id",
    )
    .bind(&retired_text)
    .bind(owner)
    .bind(signed)
    .fetch_one(&pool)
    .await
    .expect("seed retired claim");

    let private = fixture::seed_group_claim(&pool, owner, group, "getbyidconn group-private").await;

    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let stranger = fixture::public_viewer(&pool).await;

    for (who, viewer) in [("owner", &owner_viewer), ("stranger", &stranger)] {
        for id in [signed, retired, private] {
            let (via_pool, via_conn) = both(&pool, viewer, id).await;
            assert_eq!(
                via_pool, via_conn,
                "get_by_id and get_by_id_conn disagreed for the {who} viewer on {id}"
            );
        }
    }

    // ABSOLUTE pins: equality above holds just as well for one shared body that
    // is wrong in the same way twice.
    let (stranger_private, stranger_private_conn) = both(&pool, &stranger, private).await;
    assert!(
        stranger_private.is_none() && stranger_private_conn.is_none(),
        "a stranger must not read another group's private claim through either entry point"
    );
    let (owner_private, _) = both(&pool, &owner_viewer, private).await;
    assert!(
        owner_private.is_some(),
        "CALIBRATION: the owner must read its own group-private claim, or the stranger's \
         None above proves nothing"
    );

    let (_, signed_conn) = both(&pool, &stranger, signed).await;
    let signed_conn = signed_conn.expect("a public signed claim is readable");
    let stored_hash: Vec<u8> = sqlx::query_scalar("SELECT content_hash FROM claims WHERE id = $1")
        .bind(signed)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        signed_conn.5.to_vec(),
        stored_hash,
        "get_by_id_conn must return the STORED content_hash, not blake3(content)"
    );
    assert_eq!(
        signed_conn.7,
        Some(signed_sig),
        "get_by_id_conn must return the stored signature"
    );
    assert_eq!(
        signed_conn.4.to_vec(),
        owner_pk,
        "get_by_id_conn must return the signer's public key"
    );
    assert_eq!(
        signed_conn.2,
        0.625f64.to_bits(),
        "truth value is the row's"
    );
    assert_eq!(
        signed_conn.6,
        Some(trace),
        "get_by_id_conn must return the stored trace_id"
    );
    let (created_at, updated_at): (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT created_at, updated_at FROM claims WHERE id = $1")
            .bind(signed)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (signed_conn.8, signed_conn.9),
        (created_at, updated_at),
        "get_by_id_conn must return the stored timestamps"
    );

    let (_, retired_conn) = both(&pool, &stranger, retired).await;
    let retired_conn = retired_conn.expect("a public retired claim is readable");
    assert!(
        !retired_conn.10,
        "a retired claim must read back as not current"
    );
    assert_eq!(
        retired_conn.11,
        Some(signed),
        "a retired claim must name what it supersedes"
    );
}
