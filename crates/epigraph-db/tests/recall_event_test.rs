//! `RecallEventRepository` — recall audit log (backlog 8cbffa0e / design F5).
//!
//! The audit property this table exists for is not "a row was written" but
//! "the row discriminates WHY a replayed query returned something different".
//! These tests pin that discrimination, plus the GIN-backed reverse lookup and
//! retention pruning.
//!
//! # Why every test here now resolves a viewer for the AUTHOR
//!
//! `log` declares `('group', <the author's personal group>)`, so a row is
//! readable by its author and by nobody else. These tests read their own rows
//! back, so they need the author's viewer; a `public_viewer` (the NIL
//! principal, empty group set) correctly sees none of them. The one exception
//! is `agentless_event_is_accepted`, which has no author by construction.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{NewRecallEvent, RecallEventRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// An agent with its personal group and membership, plus a `Scoped` viewer
/// resolved for it.
///
/// `fixture::seed_agent_with_group` rather than a local `INSERT INTO agents`:
/// the row's owner is resolved in production by
/// `ClaimRepository::personal_group_of`, which finds the group by the
/// deterministic `did:epigraph:personal:<agent>` key. An agent seeded without
/// one would have a group MINTED for it at log time, and the viewer resolved
/// here would then name a different group than the row does.
async fn author(pool: &PgPool, label: &str) -> (Uuid, Viewer) {
    let (agent, _group) = fixture::seed_agent_with_group(pool, label).await;
    let viewer = Viewer::resolve(pool, agent)
        .await
        .expect("resolve over a seeded agent");
    (agent, viewer)
}

fn event(
    agent: Option<Uuid>,
    owner_group_id: Option<Uuid>,
    tool: &str,
    query: &str,
    pgvec: Option<&str>,
    ids: Vec<Uuid>,
) -> NewRecallEvent {
    NewRecallEvent {
        id: Uuid::new_v4(),
        agent_id: agent,
        tool: tool.to_string(),
        query_text: query.to_string(),
        query_pgvector: pgvec.map(str::to_string),
        params: serde_json::json!({"limit": 10}),
        returned_claim_ids: ids,
        owner_group_id,
    }
}

/// The event an authenticated recall produces: authored by `agent`, owned by
/// the group `personal_group_of` resolves for it.
async fn authored(
    pool: &PgPool,
    agent: Uuid,
    tool: &str,
    query: &str,
    pgvec: Option<&str>,
    ids: Vec<Uuid>,
) -> NewRecallEvent {
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(pool, agent)
        .await
        .expect("resolve the author's personal group");
    event(Some(agent), Some(group), tool, query, pgvec, ids)
}

/// **The disclosure property this table's tenancy exists for.**
///
/// `query_text` is the querying agent's raw search string. Before the
/// declaration at `log` named the author's group, every row was written
/// `visibility = 'public'` — so `list`'s predicate
/// (`$bypass OR visibility = 'public' OR owner_group_id = ANY($groups)`) was
/// satisfied by the middle disjunct for every row and could never exclude one.
///
/// Both directions, because a filter that excludes EVERYTHING also excludes the
/// stranger: A sees its own row, and does not see B's. The `agent_id` filter is
/// deliberately `None` on the negative leg — passing `Some(b)` would hide B's
/// row by the filter rather than by the tenancy predicate, and the test would
/// pass with no tenancy at all.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_cannot_read_another_agents_recall_history(pool: PgPool) {
    let (a, viewer_a) = author(&pool, "recall-a").await;
    let (b, _viewer_b) = author(&pool, "recall-b").await;

    let own = RecallEventRepository::log(
        &pool,
        authored(&pool, a, "recall", "A's own query", Some("[1]"), vec![]).await,
    )
    .await
    .unwrap();
    let theirs = RecallEventRepository::log(
        &pool,
        authored(&pool, b, "recall", "B's private query", Some("[1]"), vec![]).await,
    )
    .await
    .unwrap();

    let rows = RecallEventRepository::list(&pool, &viewer_a, None, None, None, None, 50, 0)
        .await
        .unwrap();
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();

    assert!(
        ids.contains(&own),
        "an agent must still read its OWN recall history; a predicate that excludes everything \
         passes the negative leg below and is silently, permanently wrong"
    );
    assert!(
        !ids.contains(&theirs),
        "agent A read agent B's recall row, and with it B's raw query text"
    );
    assert!(
        !rows.iter().any(|r| r.query_text == "B's private query"),
        "the query text itself must not surface"
    );
}

/// The core audit property. Same query text with the SAME embedding hash but
/// different results means the corpus changed; the same text with a DIFFERENT
/// hash means the embedder changed. If the hash did not depend on the vector,
/// these two cases would be indistinguishable and the table would be useless.
#[sqlx::test(migrations = "../../migrations")]
async fn embedding_hash_discriminates_corpus_change_from_embedder_change(pool: PgPool) {
    let (agent, viewer) = author(&pool, "recall-hash").await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());

    let e1 = RecallEventRepository::log(
        &pool,
        authored(
            &pool,
            agent,
            "recall",
            "same query",
            Some("[0.1,0.2]"),
            vec![a],
        )
        .await,
    )
    .await
    .unwrap();
    // Corpus changed: identical embedder output, different result set.
    let e2 = RecallEventRepository::log(
        &pool,
        authored(
            &pool,
            agent,
            "recall",
            "same query",
            Some("[0.1,0.2]"),
            vec![a, b],
        )
        .await,
    )
    .await
    .unwrap();
    // Embedder changed: same text, different vector.
    let e3 = RecallEventRepository::log(
        &pool,
        authored(
            &pool,
            agent,
            "recall",
            "same query",
            Some("[0.9,0.8]"),
            vec![a],
        )
        .await,
    )
    .await
    .unwrap();

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 50, 0)
        .await
        .unwrap();
    let get = |id: Uuid| {
        rows.iter()
            .find(|r| r.id == id)
            .expect("row present")
            .clone()
    };

    let (r1, r2, r3) = (get(e1), get(e2), get(e3));
    assert_eq!(
        r1.query_embedding_hash, r2.query_embedding_hash,
        "same vector => same hash, so differing results isolate a CORPUS change"
    );
    assert_ne!(r1.returned_claim_ids, r2.returned_claim_ids);
    assert_ne!(
        r1.query_embedding_hash, r3.query_embedding_hash,
        "different vector => different hash, isolating an EMBEDDER change"
    );
    assert_eq!(r1.returned_claim_ids, r3.returned_claim_ids);
}

/// The raw vector must NOT be recoverable from the log — the design stores a
/// hash precisely to avoid 16x row bloat. A regression that stored the literal
/// would still pass a "row was written" test.
#[sqlx::test(migrations = "../../migrations")]
async fn raw_vector_is_not_stored(pool: PgPool) {
    let (agent, viewer) = author(&pool, "recall-vec").await;
    let pgvec = "[0.12345,0.67890]";
    RecallEventRepository::log(
        &pool,
        authored(&pool, agent, "recall", "q", Some(pgvec), vec![]).await,
    )
    .await
    .unwrap();

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 10, 0)
        .await
        .unwrap();
    let hash = rows[0].query_embedding_hash.clone().expect("hash present");
    assert_eq!(
        hash.len(),
        32,
        "BLAKE3 digest is 32 bytes, not a serialized vector"
    );
    assert!(
        !String::from_utf8_lossy(&hash).contains("0.12345"),
        "the literal must not survive into the stored bytes"
    );
}

/// A lexical-only recall (embedder down) logs a NULL hash rather than failing
/// — the degraded path is itself audit-relevant.
#[sqlx::test(migrations = "../../migrations")]
async fn absent_embedding_logs_null_hash(pool: PgPool) {
    let (agent, viewer) = author(&pool, "recall-lexical").await;
    RecallEventRepository::log(
        &pool,
        authored(&pool, agent, "recall", "lexical only", None, vec![]).await,
    )
    .await
    .unwrap();
    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 10, 0)
        .await
        .unwrap();
    assert!(rows[0].query_embedding_hash.is_none());
}

/// "Which queries ever surfaced this claim?" — the GIN-backed reverse lookup,
/// the read this table's index layout exists to serve.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_filter_finds_queries_that_returned_a_claim(pool: PgPool) {
    let (agent, viewer) = author(&pool, "recall-gin").await;
    let (wanted, other) = (Uuid::new_v4(), Uuid::new_v4());

    RecallEventRepository::log(
        &pool,
        authored(
            &pool,
            agent,
            "recall",
            "hit",
            Some("[1]"),
            vec![wanted, other],
        )
        .await,
    )
    .await
    .unwrap();
    RecallEventRepository::log(
        &pool,
        authored(&pool, agent, "recall", "miss", Some("[1]"), vec![other]).await,
    )
    .await
    .unwrap();

    let found = RecallEventRepository::list(&pool, &viewer, None, Some(wanted), None, None, 50, 0)
        .await
        .unwrap();
    assert_eq!(
        found.len(),
        1,
        "only the query that actually returned the claim"
    );
    assert_eq!(found[0].query_text, "hit");
}

/// An agent-less event is accepted ON A BYPASS CONNECTION rather than dropped.
///
/// It has no group to own the row, so it keeps the instance-wide declaration —
/// see `RecallEventRepository::log` for why a memberless sentinel group cannot
/// stand in — and a `public_viewer` reads it back.
///
/// This runs on the superuser `#[sqlx::test]` pool, where no row policy
/// applies, so it pins the repo contract and NOTHING about the application
/// role: as `epigraph_app`, `recall_events_tenancy` refuses an agent-less row
/// outright (backlog 41841f7b). The engine path that used to send one from the
/// episcience worker now threads its caller's principal;
/// `epigraph-engine/tests/recall_audit_app_role.rs` pins that as
/// `epigraph_app`.
#[sqlx::test(migrations = "../../migrations")]
async fn agentless_event_is_accepted(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let id = RecallEventRepository::log(
        &pool,
        event(None, None, "recall", "anon", Some("[1]"), vec![]),
    )
    .await
    .expect("agentless log must be accepted");
    let rows = RecallEventRepository::list(&pool, &viewer, None, None, None, None, 50, 0)
        .await
        .unwrap();
    assert!(rows.iter().any(|r| r.id == id && r.agent_id.is_none()));
}

/// Retention prunes old rows and spares fresh ones.
#[sqlx::test(migrations = "../../migrations")]
async fn prune_removes_only_rows_past_retention(pool: PgPool) {
    let (agent, viewer) = author(&pool, "recall-prune").await;
    let fresh = RecallEventRepository::log(
        &pool,
        authored(&pool, agent, "recall", "fresh", Some("[1]"), vec![]).await,
    )
    .await
    .unwrap();
    let stale = RecallEventRepository::log(
        &pool,
        authored(&pool, agent, "recall", "stale", Some("[1]"), vec![]).await,
    )
    .await
    .unwrap();

    sqlx::query("UPDATE recall_events SET created_at = NOW() - INTERVAL '120 days' WHERE id = $1")
        .bind(stale)
        .execute(&pool)
        .await
        .unwrap();

    let deleted = RecallEventRepository::prune_older_than(&pool, 90)
        .await
        .unwrap();
    assert_eq!(deleted, 1, "exactly the row past the 90-day window");

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 50, 0)
        .await
        .unwrap();
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert!(ids.contains(&fresh));
    assert!(!ids.contains(&stale));
}

/// A row of `agent`'s in the legacy backfill's shape: `('public', <the
/// agent's personal group>)`. The visibility predicate admits it for every
/// viewer, so only an agent filter can keep it out of someone else's read.
async fn legacy_public_row(pool: &PgPool, agent: Uuid, query: &str, ids: &[Uuid]) -> Uuid {
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(pool, agent)
        .await
        .expect("resolve the author's personal group");
    sqlx::query_scalar(
        "INSERT INTO recall_events \
             (agent_id, tool, query_text, params, returned_claim_ids, visibility, owner_group_id) \
         VALUES ($1, 'recall', $2, '{}'::jsonb, $3, 'public', $4) RETURNING id",
    )
    .bind(agent)
    .bind(query)
    .bind(ids)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed a legacy public-stamped row")
}

/// `list_own` reads the CALLER's rows and no one else's, even where neither
/// row security nor the visibility predicate excludes the other rows.
///
/// This runs on the superuser `#[sqlx::test]` pool, where no row policy
/// applies (the same position as an elevated or bypass connection), and B's
/// row is `'public'`-stamped as the legacy backfill left such rows, so the
/// visibility predicate admits it: `agent_id = <principal>` is the only
/// thing that can keep it out. Every filter a caller controls is aimed at
/// B's row as well (its returned claim, a window around it), and the
/// positive control shows A's own rows come back through the same filters.
#[sqlx::test(migrations = "../../migrations")]
async fn list_own_never_returns_another_agents_rows(pool: PgPool) {
    use epigraph_db::OwnRecallFilter;
    let (a, viewer_a) = author(&pool, "own-a").await;
    let (b, _viewer_b) = author(&pool, "own-b").await;
    let shared = Uuid::new_v4();

    let own = RecallEventRepository::log(
        &pool,
        authored(
            &pool,
            a,
            "recall",
            "A's own query",
            Some("[1]"),
            vec![shared],
        )
        .await,
    )
    .await
    .unwrap();
    let theirs = legacy_public_row(&pool, b, "B's private query", &[shared]).await;

    // CALIBRATION: the MCP-side `list` (no agent filter) does show B's row to
    // A on this connection, so the negative legs below are not vacuous.
    let unfiltered = RecallEventRepository::list(&pool, &viewer_a, None, None, None, None, 50, 0)
        .await
        .unwrap();
    assert!(
        unfiltered.iter().any(|r| r.id == theirs),
        "CALIBRATION: B's public-stamped row must be visible to an unfiltered read here"
    );

    let wide = chrono::Utc::now() - chrono::Duration::days(1);
    for filter in [
        OwnRecallFilter::default(),
        OwnRecallFilter {
            claim_id: Some(shared),
            ..OwnRecallFilter::default()
        },
        OwnRecallFilter {
            since: Some(wide),
            until: Some(chrono::Utc::now() + chrono::Duration::days(1)),
            ..OwnRecallFilter::default()
        },
    ] {
        let rows = RecallEventRepository::list_own(&pool, &viewer_a, &filter, None, 200)
            .await
            .unwrap();
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        assert_eq!(
            ids,
            vec![own],
            "A reads exactly its own row under {filter:?}"
        );
        assert!(
            !rows.iter().any(|r| r.query_text == "B's private query"),
            "B's query text surfaced under {filter:?}"
        );
    }

    // A cursor positioned on B's row moves the start of A's read; it does
    // not admit B's row.
    let theirs_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT created_at FROM recall_events WHERE id = $1")
            .bind(theirs)
            .fetch_one(&pool)
            .await
            .unwrap();
    let after = epigraph_db::repos::claim::LabelCursor {
        created_at: theirs_at + chrono::Duration::seconds(1),
        id: Uuid::max(),
    };
    let rows = RecallEventRepository::list_own(
        &pool,
        &viewer_a,
        &OwnRecallFilter::default(),
        Some(after),
        200,
    )
    .await
    .unwrap();
    assert!(rows.iter().all(|r| r.agent_id == Some(a)));
    assert!(!rows.iter().any(|r| r.id == theirs));
}

/// A viewer with no principal has no own rows.
#[sqlx::test(migrations = "../../migrations")]
async fn list_own_of_a_principal_less_viewer_is_empty(pool: PgPool) {
    let (a, _viewer_a) = author(&pool, "own-bypass").await;
    let _row = legacy_public_row(&pool, a, "someone's query", &[]).await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let rows = RecallEventRepository::list_own(
        &pool,
        &bypass,
        &epigraph_db::OwnRecallFilter::default(),
        None,
        200,
    )
    .await
    .unwrap();
    assert!(rows.is_empty(), "a bypass viewer read {} rows", rows.len());
}

/// Rows logged in one statement share `created_at`. Paging two at a time
/// through seven such rows (plus one older) serves each row exactly once,
/// newest first, with the id breaking the tie.
#[sqlx::test(migrations = "../../migrations")]
async fn list_own_pages_through_rows_sharing_a_timestamp_once_each(pool: PgPool) {
    use epigraph_db::repos::claim::LabelCursor;
    use epigraph_db::OwnRecallFilter;
    let (a, viewer_a) = author(&pool, "own-pages").await;
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(&pool, a)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO recall_events \
             (agent_id, tool, query_text, params, returned_claim_ids, visibility, owner_group_id) \
         SELECT $1, 'recall', 'tied ' || g, '{}'::jsonb, '{}', 'group', $2 \
           FROM generate_series(1, 7) g",
    )
    .bind(a)
    .bind(group)
    .execute(&pool)
    .await
    .unwrap();
    let older = RecallEventRepository::log(
        &pool,
        authored(&pool, a, "recall", "older", None, vec![]).await,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE recall_events SET created_at = created_at - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(older)
    .execute(&pool)
    .await
    .unwrap();
    let distinct_times: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT created_at) FROM recall_events WHERE agent_id = $1",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        distinct_times, 2,
        "CALIBRATION: seven rows share one timestamp"
    );

    let mut seen: Vec<(chrono::DateTime<chrono::Utc>, Uuid)> = Vec::new();
    let mut after: Option<LabelCursor> = None;
    for _ in 0..20 {
        let page = RecallEventRepository::list_own(
            &pool,
            &viewer_a,
            &OwnRecallFilter::default(),
            after,
            2,
        )
        .await
        .unwrap();
        let Some(last) = page.last() else { break };
        after = Some(LabelCursor {
            created_at: last.created_at,
            id: last.id,
        });
        seen.extend(page.iter().map(|r| (r.created_at, r.id)));
    }
    assert_eq!(seen.len(), 8, "every row served once: {seen:?}");
    let mut sorted = seen.clone();
    sorted.sort_by(|x, y| y.cmp(x));
    sorted.dedup();
    assert_eq!(
        seen, sorted,
        "newest first, (created_at, id) descending, no repeats"
    );
    assert_eq!(seen.last().map(|s| s.1), Some(older));
}
