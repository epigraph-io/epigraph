//! Storing a claim's embedding is a tier-A write, and on an UNSTAMPED
//! application session it is refused.
//!
//! # Why this file exists
//!
//! The MCP submission path embeds post-commit and best-effort: a failure is
//! warned and the tool still reports success. That is CLAUDE.md's embedding
//! policy and it is correct — but it also means the refusal below reaches
//! nobody. MEASURED end-to-end with the real `epigraph-mcp` binary connected as
//! `epigraph_app` against a cleanly-migrated database: `submit_claim` returned
//! success with `embedded: false` and the committed row kept `embedding IS
//! NULL`, which is exactly CLAUDE.md's `live_missing` invariant violation and is
//! invisible to `recall()` forever.
//!
//! Production does not show it only because it carries an orphan PERMISSIVE
//! `claims_privacy` policy that exists in no migration in this repository.
//! Dropping that policy is the remediation; doing it before the write path is
//! stamped would silently un-embed every new claim. These arms are what make
//! "convert first, drop second" checkable.
//!
//! # NON-VACUITY
//!
//! `#[sqlx::test]` connects as `epigraph`: superuser, `BYPASSRLS`, owner of
//! every protected table. An arm shaped "the write succeeds" passes identically
//! on the unconverted tree and proves nothing — three reviewers of PR #494
//! raised exactly that. So every arm here runs as the real non-bypassing
//! `epigraph_app` role (`fixture::downgraded_pool` / `fixture::as_role`), and
//! the first assertion in each is that the role does not hold `BYPASSRLS`.
//!
//! # What is actually asserted: the STAMP is the only difference
//!
//! Arm 2 and arm 3 issue the SAME statement, through the SAME production
//! function, as the SAME role, with the SAME viewer. The only thing that differs
//! is whether the three session GUCs `ScopedPool::begin_as` sets are set. That
//! is the mechanism `claim_helper::embed_claim_author_stamped` buys, stated in a
//! form that cannot be satisfied by a superuser harness.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::ClaimRepository;
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

/// A well-formed 1536-d pgvector literal — the dimension of `claims.embedding`.
fn pgvec() -> String {
    let mut s = String::from("[");
    for i in 0..1536 {
        if i > 0 {
            s.push(',');
        }
        s.push_str("0.001");
    }
    s.push(']');
    s
}

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so no policy filters it and every arm in this file is \
         vacuous. Fix the role, not this test."
    );
}

/// A claim in the shape the MCP submission path actually writes:
/// `('public', personal_group_of(author))`, which is what
/// `ClaimRepository::default_decl_for_author` binds.
///
/// `fixture::seed_public_claim` is deliberately NOT used: it owns the row by the
/// WORLD group, and a row owned by a group the author cannot write is refused
/// for a reason that has nothing to do with the stamp — which would make the
/// stamped arm below fail and look like the conversion was wrong.
async fn seed_author_owned_public_claim(
    pool: &PgPool,
    author: Uuid,
    author_group: Uuid,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(author)
    .bind(author_group)
    .execute(pool)
    .await
    .expect("seed an author-owned public claim on the superuser harness connection");
    id
}

async fn embedding_is_null(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT embedding IS NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read back the embedding")
}

/// Bind the three session GUCs the 077 policies read, exactly as
/// `ScopedPool::begin_as` does. `begin_as` itself cannot be used: it takes a
/// `ScopedPool`, and `ScopedPoolOptions` exposes no `after_connect`, so there is
/// no way to build one whose connections have been switched to `epigraph_app`.
/// The statement is the same one (`epigraph-db/src/pool.rs::SET_SESSION_GUCS`).
async fn set_gucs(conn: &mut sqlx::PgConnection, groups: &str, writable: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("set session gucs");
}

/// **The release gate.** `store_embedding` on the raw application pool — the
/// shape `submit_claim` and `memorize` used before this conversion — is refused,
/// and the claim is left with no vector.
///
/// The claim is `visibility = 'public'`, which is the shape both tools write, so
/// `claims_tenancy`'s USING admits the row for UPDATE and the refusal comes from
/// its `WITH CHECK`: `owner_group_id = ANY(epigraph_writable_groups())`, and on
/// an unstamped session that set is `{}`. A `42501`, not an empty result — which
/// is why the caller's `Err` arm is what swallowed it.
#[sqlx::test(migrations = "../../migrations")]
async fn store_embedding_on_the_unstamped_app_pool_is_refused(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "embed-unstamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "embed gate: unstamped arm")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    // Resolve BEFORE downgrading: `Viewer::resolve` reads `group_memberships`,
    // which an unstamped app session sees as empty (viewer_fixture's warning).
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;

    let result = ClaimRepository::store_embedding(&app_pool, claim, &pgvec()).await;

    assert!(
        result.is_err(),
        "store_embedding on the unstamped application pool must be REFUSED. It returned {result:?}, \
         which means either the role bypasses RLS or this database carries the orphan \
         `claims_privacy` policy that exists in no migration here. Both make the whole embedding \
         conversion untestable."
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("42501") || err.to_lowercase().contains("row-level security"),
        "the refusal must be the row-level security one, not an unrelated failure: {err}"
    );
    assert!(
        embedding_is_null(&pool, claim).await,
        "the refused UPDATE must leave the claim with no vector — that is the `live_missing` row \
         the tool reports success for"
    );
}

/// **The converted shape.** The same role, the same viewer, the same production
/// function the MCP embed now calls — with the author's tenancy GUCs stamped on
/// the connection, the vector lands.
///
/// Both halves are the AUTHOR's authority and they have to agree:
/// `store_embedding_if_unsealed` splices `{WRITABLE:c}` from the viewer while
/// `claims_tenancy`'s `WITH CHECK` reads the session GUC. A site that stamped one
/// and spliced the other writes a statement no row satisfies — and under the
/// superuser harness that mistake is invisible.
#[sqlx::test(migrations = "../../migrations")]
async fn store_embedding_if_unsealed_lands_on_an_author_stamped_session(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "embed-stamped").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "embed gate: stamped arm")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    // On the superuser pool, before any downgrade — see `downgraded_pool`'s doc.
    let author_viewer = Viewer::resolve(&pool, author)
        .await
        .expect("resolve author");
    assert!(
        !author_viewer.writable_groups().is_empty(),
        "the author must carry a writable group or the stamped arm proves nothing"
    );

    let stored = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs(
            &mut conn,
            &author_group.to_string(),
            &author_group.to_string(),
            &author.to_string(),
        )
        .await;
        let out = ClaimRepository::store_embedding_if_unsealed(
            &mut conn,
            &author_viewer,
            claim,
            &pgvec(),
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(
        matches!(stored, Ok(true)),
        "the author-stamped session must be able to store its own claim's embedding: {stored:?}"
    );
    assert!(
        !embedding_is_null(&pool, claim).await,
        "the vector must actually be on the row"
    );
}

/// **The calibration, and the reason the arm above is not a tautology.** The
/// identical call, on the identical role, with the identical viewer — GUCs
/// UNSET. It is refused.
///
/// This is the file's load-bearing arm. Without it, the arm above is satisfied
/// by "the statement works", which was never in doubt; with it, the only
/// remaining explanation for the difference is the stamp. It is also the exact
/// production shape before the conversion: `server.pool` never stamped anything,
/// so `epigraph_writable_groups()` was `{}` on every MCP connection.
#[sqlx::test(migrations = "../../migrations")]
async fn store_embedding_if_unsealed_is_refused_when_the_session_is_not_stamped(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "embed-calib").await;
    let claim =
        seed_author_owned_public_claim(&pool, author, author_group, "embed gate: calibration arm")
            .await;
    assert_app_role_does_not_bypass(&pool).await;

    let author_viewer = Viewer::resolve(&pool, author)
        .await
        .expect("resolve author");

    let stored = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        // The unstamped steady state: three empty strings, which is also what
        // `ScopedPool`'s release scrub leaves behind.
        set_gucs(&mut conn, "", "", "").await;
        let out = ClaimRepository::store_embedding_if_unsealed(
            &mut conn,
            &author_viewer,
            claim,
            &pgvec(),
        )
        .await;
        (conn, out)
    })
    .await;

    assert!(
        stored.is_err(),
        "with no stamp the write must be refused; it returned {stored:?}. If this passes, the \
         two arms above differ in something other than the stamp and neither proves anything."
    );
    assert!(
        embedding_is_null(&pool, claim).await,
        "nothing may be written on the refused path"
    );
}
