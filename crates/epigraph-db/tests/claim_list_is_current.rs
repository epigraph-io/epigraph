//! Regression test for backlog bug `f1992766`: [`ClaimRepository::list`] never
//! projected `is_current`, so every returned `Claim` inherited
//! `claim_from_row`'s `is_current = true` default. A superseded row was
//! indistinguishable from a live one, which made `GET /api/v1/claims` assert
//! currency it had never read and made that endpoint's `?is_current=false`
//! filter compare against a constant.
//!
//! `list` builds two different SELECT strings — one with `WHERE content ILIKE`,
//! one without — so both are exercised here: a fix applied to only one of them
//! would leave half the read path lying.

mod viewer_fixture;
use viewer_fixture as fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn list_reports_real_is_current_on_both_query_paths(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Distinctive marker so the ILIKE variant selects exactly these two rows.
    const MARKER: &str = "zz-list-is-current-marker";
    let live = seed_claim(&pool, agent, &format!("{MARKER} live row"), true, None).await;
    let superseded = seed_claim(
        &pool,
        agent,
        &format!("{MARKER} superseded row"),
        false,
        Some(live),
    )
    .await;

    // ---- Path 1: no search → the plain `SELECT ... FROM claims` variant ----
    let rows = ClaimRepository::list(&pool, &viewer, 50, 0, None)
        .await
        .unwrap();
    let current_of = |id: Uuid| {
        rows.iter()
            .find(|c| c.id.as_uuid() == id)
            .unwrap_or_else(|| panic!("claim {id} missing from list() result"))
            .is_current
    };
    assert!(current_of(live), "live claim must report is_current = true");
    assert!(
        !current_of(superseded),
        "superseded claim must report is_current = false from list(search = None) \
         — a `true` here is the f1992766 fabrication"
    );

    // ---- Path 2: search → the `WHERE content ILIKE $3` variant ----
    let searched = ClaimRepository::list(&pool, &viewer, 50, 0, Some(MARKER))
        .await
        .unwrap();
    assert_eq!(
        searched.len(),
        2,
        "ILIKE on the marker should match exactly the two seeded rows"
    );
    let searched_current_of = |id: Uuid| {
        searched
            .iter()
            .find(|c| c.id.as_uuid() == id)
            .unwrap_or_else(|| panic!("claim {id} missing from list(search) result"))
            .is_current
    };
    assert!(searched_current_of(live));
    assert!(
        !searched_current_of(superseded),
        "superseded claim must report is_current = false from the ILIKE variant too"
    );

    // `supersedes` is the other half of the retirement state and was fabricated
    // as `None` by the same omission. Pinned on both variants so it cannot
    // silently regress the way `is_current` did.
    for (label, set) in [("plain", &rows), ("ilike", &searched)] {
        let row = set
            .iter()
            .find(|c| c.id.as_uuid() == superseded)
            .unwrap_or_else(|| panic!("{label}: superseded row missing"));
        assert_eq!(
            row.supersedes.map(|s| s.as_uuid()),
            Some(live),
            "{label}: superseded row must point at the live claim it replaced"
        );
        let row = set.iter().find(|c| c.id.as_uuid() == live).unwrap();
        assert!(
            row.supersedes.is_none(),
            "{label}: the live claim supersedes nothing"
        );
    }

    // The in-memory `retain(|c| c.is_current == false)` that
    // `list_claims_query`'s slow path performs must now be able to match.
    let only_retired: Vec<Uuid> = searched
        .iter()
        .filter(|c| !c.is_current)
        .map(|c| c.id.as_uuid())
        .collect();
    assert_eq!(
        only_retired,
        vec![superseded],
        "filtering the result on is_current == false must yield the superseded row, \
         not an empty set"
    );
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("ee".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    // Unique content_hash per row — content_hash carries a btree index and some
    // dedup paths key on it (mirrors tests/list_by_labels.rs).
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .unwrap();
    id
}
