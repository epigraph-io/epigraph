//! `ClaimThemeRepository::set_centroid_from_claims` — the tenancy half.
//!
//! # What was missing
//!
//! The statement already carries `/* {VISIBILITY:c} */` on its averaged
//! `SELECT`, and `visibility_lint.rs` enforces that the marker stays. What had
//! never been asserted is the thing the marker is FOR: that a scoped caller's
//! server-derived centroid is computed from the claims it can see and no
//! others. The one existing test —
//! `epigraph-api/tests/pr07_acceptance_http.rs::create_theme_with_centroid_averages_the_claims_when_no_centroid_is_sent`
//! — drives an all-public fixture with a `claims:admin` token and asserts only
//! `vector_dims(centroid) == 1536`, so it would pass unchanged if the predicate
//! averaged the entire corpus.
//!
//! # Why the assertion is on the VECTOR and not on the row count
//!
//! A centroid is a mean. Excluding a claim changes the returned contributor
//! count immediately, but it changes the mean only if the excluded vector
//! actually pulls it — and if the fixture's vectors happen to be similar, a
//! leak produces a centroid that is numerically indistinguishable from the
//! correct one. A test that asserted "the request succeeded" or "`n` was 2"
//! would therefore be green against a predicate that leaked a claim whose
//! embedding sat near the public mean, which is the *majority* of a real
//! corpus.
//!
//! So the corpus is built adversarially: the two visible claims are the basis
//! vector `e0`, and the invisible one is `e1` — orthogonal, so including it
//! moves the mean by a third of the way to a different axis. Both centroids are
//! read back and compared to each other AND to their exact arithmetic means, so
//! the assertion fails on any leak rather than only on a large one.
//!
//! # Scope
//!
//! This does NOT discharge `D-PR16-theme-cluster-viewer-scope`, the deferred
//! obligation about `claim_themes` itself being registered `tenancy_exempt`.
//! The theme ROW's own reachability is a different question from which claims
//! feed its centroid, and only the latter is asserted here.

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimThemeRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

/// `claims.embedding` and `claim_themes.centroid` are both `vector(1536)`.
/// A shorter literal is rejected by the column type, not silently padded.
const DIM: usize = 1536;

/// The pgvector literal for the `axis`-th standard basis vector.
fn basis(axis: usize) -> String {
    let mut v = vec!["0"; DIM];
    v[axis] = "1";
    format!("[{}]", v.join(","))
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// The first two components of a theme's centroid, or `None` if unset.
///
/// Two components are enough to discriminate every case this file builds — the
/// corpus lives in the `e0`/`e1` plane — and reading two floats keeps the
/// failure message legible. Read as `float8` through `->>`, because the crate
/// does not depend on a pgvector Rust type in its test tree.
async fn centroid_head(pool: &PgPool, theme: Uuid) -> Option<(f64, f64)> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT centroid::text FROM claim_themes WHERE id = $1")
            .bind(theme)
            .fetch_one(pool)
            .await
            .expect("read centroid");
    let raw = raw?;
    let inner = raw.trim_start_matches('[').trim_end_matches(']');
    let mut parts = inner.split(',');
    let a: f64 = parts
        .next()
        .expect("centroid has a first component")
        .trim()
        .parse()
        .expect("parse centroid[0]");
    let b: f64 = parts
        .next()
        .expect("centroid has a second component")
        .trim()
        .parse()
        .expect("parse centroid[1]");
    Some((a, b))
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-4
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_centroid_is_computed_only_from_the_claims_the_viewer_can_see(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "centroid-owner").await;

    // Two public claims on `e0`, one group-private claim on `e1`.
    let pub_a = fixture::seed_public_claim(&pool, owner, "centroid public a").await;
    let pub_b = fixture::seed_public_claim(&pool, owner, "centroid public b").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "centroid private").await;
    fixture::set_claim_embedding(&pool, pub_a, &basis(0)).await;
    fixture::set_claim_embedding(&pool, pub_b, &basis(0)).await;
    fixture::set_claim_embedding(&pool, private, &basis(1)).await;

    let all = [pub_a, pub_b, private];

    let owner_viewer = Viewer::resolve(&pool, owner)
        .await
        .expect("resolve the owning viewer");
    let stranger = fixture::public_viewer(&pool).await;

    // The stranger asks for all three ids. The predicate, not the argument
    // list, is what must exclude the private one — a caller cannot be trusted
    // to pre-filter, and the production caller (`routes/crud.rs::create_theme`)
    // passes whatever ids the request body named.
    let stranger_theme = seed_theme(&pool, "centroid-stranger").await;
    let stranger_n =
        ClaimThemeRepository::set_centroid_from_claims(&pool, &stranger, stranger_theme, &all)
            .await
            .expect("stranger centroid");

    let owner_theme = seed_theme(&pool, "centroid-owner-theme").await;
    let owner_n =
        ClaimThemeRepository::set_centroid_from_claims(&pool, &owner_viewer, owner_theme, &all)
            .await
            .expect("owner centroid");

    assert_eq!(
        stranger_n, 2,
        "the stranger's centroid must be averaged over the two PUBLIC claims \
         only; {stranger_n} contributors means the group-private claim was \
         either included ({stranger_n} == 3) or the fixture is not seeding \
         embeddings at all ({stranger_n} == 0)"
    );
    assert_eq!(
        owner_n, 3,
        "CLASS P: the owner must see all three. A predicate that refuses \
         everybody passes every 'a stranger cannot read' assertion in this file \
         and is a silent, permanent empty result set"
    );

    let (sx, sy) = centroid_head(&pool, stranger_theme)
        .await
        .expect("the stranger's centroid must be written, not left NULL");
    let (ox, oy) = centroid_head(&pool, owner_theme)
        .await
        .expect("the owner's centroid must be written");

    // mean(e0, e0) = (1, 0)
    assert!(
        close(sx, 1.0) && close(sy, 0.0),
        "the stranger's centroid must be the exact mean of the two public \
         vectors, (1, 0). Got ({sx}, {sy}) — a value between (1,0) and \
         (0.667, 0.333) means the private claim contributed."
    );
    // mean(e0, e0, e1) = (2/3, 1/3)
    assert!(
        close(ox, 2.0 / 3.0) && close(oy, 1.0 / 3.0),
        "the owner's centroid must be the exact mean of all three vectors, \
         (0.667, 0.333). Got ({ox}, {oy})."
    );

    // The discriminating statement, spelled out: the two centroids are
    // different vectors. This is what fails if the predicate leaks, even in a
    // corpus where the contributor counts happened to match.
    assert!(
        !close(sx, ox) || !close(sy, oy),
        "the scoped and unscoped centroids are the same vector, so the \
         viewer predicate changed nothing about the computed value. \
         stranger=({sx}, {sy}) owner=({ox}, {oy})"
    );
}

/// A viewer that can see NO embedded claim leaves the centroid unset rather
/// than writing a NULL or a zero vector.
///
/// This is the other half of the same predicate and is easy to get wrong in the
/// direction that looks safe: `AVG()` over an empty set is `NULL`, and an
/// `UPDATE` that wrote it would replace a real centroid with nothing the first
/// time a scoped caller touched somebody else's theme. The `agg.n > 0` guard is
/// what prevents that, and nothing else asserts it.
///
/// WHAT THIS ARM DOES NOT SAY, recorded rather than implied: it passes BECAUSE
/// `n == 0`. `set_centroid_from_claims` returns `Ok(n.unwrap_or(0))` — a filter
/// that affected no row, reported as success — so this arm pins the no-write
/// outcome and not a refusal. Whether the theme ROW itself should be reachable
/// by this viewer at all is a separate question, and it belongs to the existing
/// `D-PR16-theme-cluster-viewer-scope` obligation in `docs/tenancy/progress.json`
/// rather than to this file, which does not discharge it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_with_nothing_visible_leaves_an_existing_centroid_intact(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "centroid-empty-owner").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "centroid empty private").await;
    fixture::set_claim_embedding(&pool, private, &basis(1)).await;

    let theme = seed_theme(&pool, "centroid-preexisting").await;
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme)
        .bind(basis(0))
        .execute(&pool)
        .await
        .expect("plant a pre-existing centroid");

    let stranger = fixture::public_viewer(&pool).await;
    let n = ClaimThemeRepository::set_centroid_from_claims(&pool, &stranger, theme, &[private])
        .await
        .expect("stranger centroid over an invisible claim");
    assert_eq!(
        n, 0,
        "no visible claim had an embedding, so nothing contributed"
    );

    let (x, y) = centroid_head(&pool, theme)
        .await
        .expect("the pre-existing centroid must survive, not become NULL");
    assert!(
        close(x, 1.0) && close(y, 0.0),
        "a scoped caller that can see none of the named claims must leave the \
         centroid untouched. Got ({x}, {y}); (0, 1) would mean the private \
         claim was averaged in anyway."
    );
}
