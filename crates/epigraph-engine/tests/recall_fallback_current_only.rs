//! `epigraph_engine::recall::recall`'s text fallback serves current rows only
//! (supersede SPEC K11; REVIEW D19).
//!
//! The fallback (`text_search_fallback`, the ILIKE leg that answers whenever
//! the embedder errs) is the one recall leg with no currency predicate: the
//! semantic leg reads `search_by_embedding_current`, and a retired row has no
//! embedding anyway (`chk_deprecated_no_embedding`). So the only way a retired
//! claim reaches a recall caller is this leg, and the fixture below drives it
//! there with an embedder that refuses every query.
//!
//! The fixture is shaped so that two different wrong fixes fail differently:
//!
//! * no currency filter at all: the retired row, the NEWEST match, fills the
//!   one-row page;
//! * a filter applied after `LIMIT` (in Rust, over the page the SQL already
//!   cut): the page is the retired row, the filter drops it, and the older
//!   current match is never fetched, so the caller gets nothing.
//!
//! Only a filter applied in SQL, before `LIMIT`, returns the current match.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, SupersedeActor, SupersedeTool, Viewer};
use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider, EmbeddingService};
use epigraph_engine::recall::recall;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("dd".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// A current claim with no embedding (so only the ILIKE leg can return it),
/// created `days_ago` days in the past so the page order is fixed.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, days_ago: i32) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 0.7, true, \
                 now() - make_interval(days => $5), now() - make_interval(days => $5))",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(days_ago)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn is_current(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read is_current")
}

#[sqlx::test(migrations = "../../migrations")]
async fn engine_recall_fallback_never_serves_a_retired_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    // failure_rate 1.0: every generate_query errs, so every `recall` below
    // takes the text-search fallback.
    let failing = MockProvider::new(EmbeddingConfig::openai(1536)).with_failures(1.0);
    assert!(
        failing.generate_query("probe").await.is_err(),
        "fixture: the provider must refuse to embed, or the semantic leg runs instead"
    );
    // ILIKE is `%query%`: both matching fixtures contain the whole query.
    let query = "quorvane flux pinning";

    let agent = seed_agent(&pool).await;
    let current = seed_claim(&pool, agent, "quorvane flux pinning, the standing claim", 2).await;
    let doomed = seed_claim(&pool, agent, "quorvane flux pinning, the first draft", 1).await;

    // Control: before retirement the fallback returns both, so an absence
    // below is currency deciding, not the fixture being unretrievable. The
    // ORDER is pinned too: the post-LIMIT guard below only bites while the
    // doomed draft is the newest match, i.e. while the page is newest first.
    let before = recall(&pool, &scoped, &viewer, &failing, query, 10, 0.0)
        .await
        .expect("recall");
    let before_ids: Vec<&str> = before.iter().map(|r| r.claim_id.as_str()).collect();
    assert_eq!(
        before_ids,
        vec![doomed.to_string().as_str(), current.to_string().as_str()],
        "control: both matches must be served, newest first, while both are current"
    );

    // Retire the newer match through the real supersede act. The revision
    // drops the query terms, so the successor itself is not a match and the
    // only matches left are one current row and one retired row.
    let (successor, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(doomed),
        "a reworded revision of the first draft",
        TruthValue::clamped(0.7),
        "revision",
        SupersedeActor::new(agent, SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede");
    assert!(
        !is_current(&pool, doomed).await && is_current(&pool, successor).await,
        "fixture: the supersede act must retire the draft and leave its successor current"
    );

    // One-row page: the retired draft is the newest match.
    let page = recall(&pool, &scoped, &viewer, &failing, query, 1, 0.0)
        .await
        .expect("recall");
    let page_ids: Vec<&str> = page.iter().map(|r| r.claim_id.as_str()).collect();
    assert!(
        !page_ids.contains(&doomed.to_string().as_str()),
        "the text fallback served a retired claim ({doomed}): got {page_ids:?}"
    );
    assert_eq!(
        page_ids,
        vec![current.to_string().as_str()],
        "the one-row page must hold the current match; an empty page means the currency \
         filter ran after LIMIT and the retired row starved the page"
    );

    // Full page: still no retired row, and the current match is served.
    let full = recall(&pool, &scoped, &viewer, &failing, query, 10, 0.0)
        .await
        .expect("recall");
    let full_ids: Vec<&str> = full.iter().map(|r| r.claim_id.as_str()).collect();
    assert_eq!(
        full_ids,
        vec![current.to_string().as_str()],
        "with room for every match the fallback must serve exactly the current one"
    );
}

/// The fallback's statement changed with K11 (`ClaimRepository::list` became
/// `list_filtered`, whose viewer splice binds at a different position), so the
/// viewer must still decide what the swapped statement serves. Row-level
/// security does not filter the harness pool's reads, so the viewer predicate
/// spliced into the fallback's SQL is the only thing that keeps a
/// group-private row from a public viewer here: stripping that splice from
/// `list_filtered` turns the public-viewer assertion red.
#[sqlx::test(migrations = "../../migrations")]
async fn engine_recall_fallback_respects_viewer(pool: PgPool) {
    let scoped = fixture::scoped_pool(&pool).await;
    let failing = MockProvider::new(EmbeddingConfig::openai(1536)).with_failures(1.0);
    assert!(
        failing.generate_query("probe").await.is_err(),
        "fixture: the provider must refuse to embed, or the semantic leg runs instead"
    );
    let query = "zelquar lattice note";

    let (member, group) = fixture::seed_agent_with_group(&pool, "k11-fallback-viewer").await;
    let private =
        fixture::seed_group_claim(&pool, member, group, "zelquar lattice note, private").await;
    let open = fixture::seed_public_claim(&pool, member, "zelquar lattice note, public").await;

    // Public viewer: the public match is served (so the fallback ran and the
    // query matches), the group-private match is not.
    let public = fixture::public_viewer(&pool).await;
    let served = recall(&pool, &scoped, &public, &failing, query, 10, 0.0)
        .await
        .expect("recall");
    let served_ids: Vec<&str> = served.iter().map(|r| r.claim_id.as_str()).collect();
    assert!(
        served_ids.contains(&open.to_string().as_str()),
        "control: the public match must be served to the public viewer, got {served_ids:?}"
    );
    assert!(
        !served_ids.contains(&private.to_string().as_str()),
        "the text fallback served a group-private claim ({private}) to the public viewer: \
         got {served_ids:?}"
    );

    // Member of the owning group: the same private row IS served, so its
    // absence above is the viewer deciding, not the row being unreachable.
    let owner = Viewer::resolve(&pool, member).await.expect("member viewer");
    let mine = recall(&pool, &scoped, &owner, &failing, query, 10, 0.0)
        .await
        .expect("recall");
    let mine_ids: Vec<&str> = mine.iter().map(|r| r.claim_id.as_str()).collect();
    assert!(
        mine_ids.contains(&private.to_string().as_str()),
        "the owning group's member must be served its private match, got {mine_ids:?}"
    );
}
