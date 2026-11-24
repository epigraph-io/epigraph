//! `consolidate_claims`'s three explicit modes (backlog 22602dd8).
//!
//! - `identity` is the dedup act per non-survivor source: each gets the
//!   `same_as` identity edge onto the survivor, its edges move through the
//!   dedup cascade, no claim is written, and each can be un-marked.
//! - `abstract` writes a new claim with a `generalizes` edge to each source,
//!   retires nothing, and runs no cascade.
//! - `merge` (and its alias `rewrite`) keeps the retiring merge; it is pinned
//!   in `consolidate_tool.rs` and `epigraph-db/tests/consolidate_test.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim};
use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::tools::supersede::unmark_duplicate;
use epigraph_mcp::types::{ConsolidateClaimsParams, UnmarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

fn body(r: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("json body")
}

fn params(
    mode: &str,
    ids: &[Uuid],
    content: &str,
    survivor: Option<Uuid>,
) -> ConsolidateClaimsParams {
    ConsolidateClaimsParams {
        source_claim_ids: ids.iter().map(ToString::to_string).collect(),
        merged_content: content.to_string(),
        mode: mode.to_string(),
        survivor_claim_id: survivor.map(|s| s.to_string()),
        reason: "consolidate modes test".to_string(),
        confidence: None,
    }
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// `(supersedes, is_current)` of a claim.
async fn standing(pool: &PgPool, id: Uuid) -> (Option<Uuid>, bool) {
    sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// In-force dedup identity edges `dup -same_as-> canonical`.
async fn identity_edges(pool: &PgPool, dup: Uuid, canonical: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'same_as' AND properties ? 'dedup' AND valid_to IS NULL",
    )
    .bind(dup)
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("identity edges")
}

async fn claim_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(pool)
        .await
        .expect("claim count")
}

/// Identity mode is `mark_duplicate` per non-survivor source: each is retired
/// onto the survivor with an identity edge, its edge moves to the survivor,
/// no claim is written, and an un-mark restores it. Before the modes, the
/// call wrote a new merged claim and retired every source, the survivor too,
/// with no identity edge and no un-mark.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_marks_each_non_survivor_and_each_can_be_unmarked(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let survivor = seed_claim(&pool, "the restated fact", 0.6).await;
    let dup_a = seed_claim(&pool, "the restated fact, again", 0.5).await;
    let dup_b = seed_claim(&pool, "the restated fact, once more", 0.5).await;
    let supporter = seed_claim(&pool, "supports a restatement", 0.5).await;
    let e = edge(&pool, supporter, dup_a).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let before = claim_count(&pool).await;

    let out = consolidate_claims(
        &server,
        &viewer,
        params("identity", &[dup_a, survivor, dup_b], "", Some(survivor)),
        Some(&auth),
    )
    .await
    .expect("identity consolidation");
    let b = body(&out);
    assert_eq!(b["mode"], "identity", "{b}");
    assert_eq!(b["survivor_claim_id"], survivor.to_string(), "{b}");
    let marked = b["marked"].as_array().expect("marked");
    assert_eq!(marked.len(), 2, "{b}");
    for m in marked {
        assert_eq!(m["canonical_id"], serde_json::json!(survivor), "{b}");
        assert_eq!(m["cascade"]["status"], "applied", "{b}");
    }

    assert_eq!(claim_count(&pool).await, before, "identity writes no claim");
    assert_eq!(
        standing(&pool, survivor).await,
        (None, true),
        "the survivor stays current"
    );
    for dup in [dup_a, dup_b] {
        assert_eq!(
            standing(&pool, dup).await,
            (Some(survivor), false),
            "{dup} marked"
        );
        assert_eq!(
            identity_edges(&pool, dup, survivor).await,
            1,
            "{dup} identity edge"
        );
    }
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        target, survivor,
        "the dedup cascade moved the edge to the survivor"
    );

    let r = unmark_duplicate(
        &server,
        &viewer,
        UnmarkDuplicateParams {
            claim_id: dup_a.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("an identity-mode source can be un-marked");
    assert_eq!(body(&r)["cascade"]["status"], "applied");
    assert_eq!(standing(&pool, dup_a).await, (None, true), "un-marked");
    assert_eq!(identity_edges(&pool, dup_a, survivor).await, 0);
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, dup_a, "the un-mark put the edge back");
    assert_eq!(
        standing(&pool, dup_b).await,
        (Some(survivor), false),
        "the other source stays marked"
    );
}

/// Every source is checked before any is marked: one source the dedup act
/// would refuse (here a revision successor, whose `supersedes` a mark would
/// overwrite) refuses the whole call, and the markable source is untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_refuses_before_marking_any_source(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let survivor = seed_claim(&pool, "survivor", 0.6).await;
    let markable = seed_claim(&pool, "markable restatement", 0.5).await;
    let older = seed_claim(&pool, "an older version", 0.5).await;
    let successor = seed_claim(&pool, "a revision successor", 0.5).await;
    sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
        .bind(successor)
        .bind(older)
        .execute(&pool)
        .await
        .expect("make a revision successor");
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let err = consolidate_claims(
        &server,
        &viewer,
        params(
            "identity",
            &[survivor, markable, successor],
            "",
            Some(survivor),
        ),
        Some(&auth),
    )
    .await
    .expect_err("a successor source refuses the call");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains(&successor.to_string()), "{err:?}");
    assert_eq!(
        standing(&pool, markable).await,
        (None, true),
        "no source was marked"
    );
    assert_eq!(identity_edges(&pool, markable, survivor).await, 0);
}

/// Identity's parameters: it needs a survivor among the sources and takes no
/// merged content; the other modes take no survivor and need merged content
/// (an omitted one is a parameter error, not an internal one). Each refusal
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_and_survivor_parameters_are_checked(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let s1 = seed_claim(&pool, "param one", 0.5).await;
    let s2 = seed_claim(&pool, "param two", 0.5).await;
    let outsider = seed_claim(&pool, "not a source", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;
    let before = claim_count(&pool).await;

    for (p, needle) in [
        (
            params("identity", &[s1, s2], "", None),
            "needs survivor_claim_id",
        ),
        (
            params("identity", &[s1, s2], "", Some(outsider)),
            "is not one of source_claim_ids",
        ),
        (
            params("identity", &[s1, s2], "a merged text", Some(s1)),
            "takes no merged_content",
        ),
        (
            params("merge", &[s1, s2], "a merged text", Some(s1)),
            "applies to mode 'identity' only",
        ),
        (
            params("abstract", &[s1, s2], "a general text", Some(s1)),
            "applies to mode 'identity' only",
        ),
        (params("merge", &[s1, s2], "", None), "needs merged_content"),
        (
            params("abstract", &[s1, s2], "  ", None),
            "needs merged_content",
        ),
    ] {
        let mode = p.mode.clone();
        let err = consolidate_claims(&server, &viewer, p, Some(&auth))
            .await
            .expect_err("refused");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{mode}: {err:?}"
        );
        assert!(err.message.contains(needle), "{mode}: {err:?}");
    }
    assert_eq!(claim_count(&pool).await, before, "nothing written");
    for s in [s1, s2] {
        assert_eq!(standing(&pool, s).await, (None, true));
    }
}

/// Abstract mode through the tool: a new claim with a `generalizes` edge to
/// each source; every source stays current with its edges, and no cascade
/// runs or is deferred (there is nothing to move). Before the modes, an
/// `abstract` call retired every source like a merge.
#[sqlx::test(migrations = "../../migrations")]
async fn abstract_mode_retires_nothing_and_runs_no_cascade(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let s1 = seed_claim(&pool, "abstract tool source one", 0.6).await;
    let s2 = seed_claim(&pool, "abstract tool source two", 0.8).await;
    let supporter = seed_claim(&pool, "supports source two", 0.5).await;
    let e = edge(&pool, supporter, s2).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let out = consolidate_claims(
        &server,
        &viewer,
        params(
            "abstract",
            &[s1, s2],
            "what both sources have in common",
            None,
        ),
        Some(&auth),
    )
    .await
    .expect("abstract consolidation");
    let b = body(&out);
    assert_eq!(b["mode"], "abstract", "{b}");
    assert_eq!(b["superseded_ids"], serde_json::json!([]), "{b}");
    assert!(
        b.get("cascade").is_none(),
        "an abstraction runs no cascade: {b}"
    );
    let a = Uuid::parse_str(b["merged_claim_id"].as_str().expect("id")).expect("uuid");

    assert_eq!(
        standing(&pool, a).await,
        (None, true),
        "the abstraction is current"
    );
    for s in [s1, s2] {
        assert_eq!(standing(&pool, s).await, (None, true), "{s} stays current");
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
                AND relationship = 'generalizes' AND valid_to IS NULL",
        )
        .bind(a)
        .bind(s)
        .fetch_one(&pool)
        .await
        .expect("generalizes");
        assert_eq!(n, 1, "abstraction -generalizes-> {s}");
    }
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, s2, "the source keeps its edge");
}

/// A `claims:write` caller's authority over EVERY pair is checked before any
/// source is marked. The caller owns the survivor and the first duplicate, but
/// the second duplicate is a public claim owned by a group it cannot write: the
/// call is refused and the first duplicate stays current. Without the
/// per-pair pre-check, the first duplicate would be marked and committed
/// before the second pair was refused.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_checks_authority_over_every_pair_before_marking(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let (caller, auth, viewer) = common::seed_caller(&pool, &["claims:write"]).await;
    let own_group = common::personal_group_of(&pool, caller).await;
    let survivor = seed_claim(&pool, "the caller's restated fact", 0.6).await;
    let dup_own = seed_claim(&pool, "the caller's restated fact, again", 0.5).await;
    let dup_foreign = seed_claim(&pool, "someone else's restatement", 0.5).await;
    common::stamp_group_private(&pool, survivor, own_group).await;
    common::stamp_group_private(&pool, dup_own, own_group).await;
    let stranger = common::seed_agent(&pool).await;
    let stranger_group = common::personal_group_of(&pool, stranger).await;
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(dup_foreign)
        .bind(stranger_group)
        .execute(&pool)
        .await
        .expect("make the foreign duplicate public and stranger-owned");

    let err = consolidate_claims(
        &server,
        &viewer,
        params(
            "identity",
            &[survivor, dup_own, dup_foreign],
            "",
            Some(survivor),
        ),
        Some(&auth),
    )
    .await
    .expect_err("a pair the caller cannot write refuses the whole identity call");
    assert!(
        !err.message.contains("already marked"),
        "the refusal comes from the pre-check, before any source was marked: {}",
        err.message
    );
    for id in [survivor, dup_own, dup_foreign] {
        assert_eq!(
            standing(&pool, id).await,
            (None, true),
            "source {id} is untouched: nothing is marked when any pair is refused"
        );
    }
    assert_eq!(identity_edges(&pool, dup_own, survivor).await, 0);
}

/// What another writer does to a claim of an identity call while the call
/// waits on that claim's row.
#[derive(Clone, Copy)]
enum ConcurrentChange {
    /// Marked a duplicate of some other claim (`supersedes` set).
    MarkedElsewhere,
    /// Retired (`is_current = false`), `supersedes` left NULL: the shape a
    /// claim superseded by a revision, or deprecated, has.
    Retired,
}

/// Which claim of the identity call the other writer changes.
#[derive(Clone, Copy, PartialEq)]
enum RaceTarget {
    /// The last non-survivor source.
    LastSource,
    /// The survivor (the canonical every source is marked onto).
    Survivor,
}

/// Run `consolidate_claims(mode='identity')` over `[survivor, first, last]`
/// (over `[survivor, last]` when the target is the survivor: see
/// [`identity_mode_marks_nothing_when_the_survivor_is_marked_elsewhere_concurrently`])
/// while a second connection holds `target`'s row lock, and apply `change` to
/// it on that connection once the call is waiting on a lock (after the call's
/// checks read every claim as markable, before its acts commit), or, if the
/// call never waits, once it has returned. Returns the call's result, whether
/// it waited on a lock, and the ids.
async fn identity_call_racing_a_change(
    pool: &PgPool,
    target: RaceTarget,
    change: ConcurrentChange,
) -> (
    Result<rmcp::model::CallToolResult, rmcp::model::ErrorData>,
    bool,
    [Uuid; 4],
) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let survivor = seed_claim(pool, "the restated fact", 0.6).await;
    let first = seed_claim(pool, "the restated fact, again", 0.5).await;
    // LAST in the call's order, so that a per-source loop marks `first`
    // before it reaches the source the other writer changes.
    let last = seed_claim(pool, "the restated fact, once more", 0.5).await;
    let elsewhere = seed_claim(pool, "another writer's canonical", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, pool).await;

    let changed = match target {
        RaceTarget::LastSource => last,
        RaceTarget::Survivor => survivor,
    };
    // The other writer, on its own connection: it holds the target's row
    // lock from before the call starts.
    let mut writer = pool.begin().await.expect("writer tx");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE")
        .bind(changed)
        .execute(&mut *writer)
        .await
        .expect("lock the target claim");
    let mut watcher = pool.acquire().await.expect("watcher connection");

    let sources = match target {
        RaceTarget::LastSource => vec![survivor, first, last],
        RaceTarget::Survivor => vec![survivor, last],
    };
    let done = std::sync::atomic::AtomicBool::new(false);
    let call = async {
        let r = consolidate_claims(
            &server,
            &viewer,
            params("identity", &sources, "", Some(survivor)),
            Some(&auth),
        )
        .await;
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        r
    };
    let interfere = async {
        let mut waited = false;
        for _ in 0..400 {
            if done.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                  WHERE datname = current_database() AND pid <> pg_backend_pid() \
                    AND wait_event_type = 'Lock'",
            )
            .fetch_one(&mut *watcher)
            .await
            .expect("pg_stat_activity");
            if waiting > 0 {
                waited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        match change {
            ConcurrentChange::MarkedElsewhere => {
                sqlx::query("UPDATE claims SET supersedes = $2, is_current = false WHERE id = $1")
                    .bind(changed)
                    .bind(elsewhere)
                    .execute(&mut *writer)
                    .await
                    .expect("mark the target elsewhere");
            }
            ConcurrentChange::Retired => {
                sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
                    .bind(changed)
                    .execute(&mut *writer)
                    .await
                    .expect("retire the target");
            }
        }
        writer.commit().await.expect("commit the concurrent change");
        waited
    };
    let (result, waited) = tokio::join!(call, interfere);
    (result, waited, [survivor, first, last, elsewhere])
}

/// The call is all-or-nothing under concurrency (backlog 635dbfae): a source
/// another writer changes after the call's checks and before its own act
/// refuses the WHOLE call, and the source before it is not left marked.
///
/// Before the fix each source was marked in its own committed transaction,
/// so here `first` stayed marked onto the survivor (with its identity edge)
/// and the error only named it ("... stay marked").
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_marks_nothing_when_a_later_source_is_marked_elsewhere_concurrently(
    pool: PgPool,
) {
    let (result, waited, [survivor, first, last, elsewhere]) = identity_call_racing_a_change(
        &pool,
        RaceTarget::LastSource,
        ConcurrentChange::MarkedElsewhere,
    )
    .await;
    assert!(waited, "the call waited on the last source's row lock");
    let err = result.expect_err("the changed source refuses the call");
    assert_eq!(
        standing(&pool, first).await,
        (None, true),
        "the earlier source is not left marked: {err:?}"
    );
    assert_eq!(identity_edges(&pool, first, survivor).await, 0);
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains(&last.to_string()), "{err:?}");
    assert!(
        err.message.contains("no source was marked"),
        "the refusal says nothing was marked: {err:?}"
    );
    assert_eq!(identity_edges(&pool, last, survivor).await, 0);
    assert_eq!(standing(&pool, survivor).await, (None, true));
    assert_eq!(
        standing(&pool, last).await,
        (Some(elsewhere), false),
        "the other writer's mark stands"
    );
}

/// The same race with a source RETIRED concurrently (`is_current = false`,
/// `supersedes` NULL). The dedup act refuses only a duplicate that already
/// supersedes a claim, so this one is caught only by the call's own re-check
/// under the row lock. Before the fix the call marked the retired source
/// onto the survivor and reported success.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_marks_nothing_when_a_later_source_is_retired_concurrently(pool: PgPool) {
    let (result, waited, [survivor, first, last, _]) =
        identity_call_racing_a_change(&pool, RaceTarget::LastSource, ConcurrentChange::Retired)
            .await;
    assert!(waited, "the call waited on the last source's row lock");
    let err = result.expect_err("the retired source refuses the call");
    assert_eq!(
        standing(&pool, first).await,
        (None, true),
        "the earlier source is not left marked: {err:?}"
    );
    assert_eq!(identity_edges(&pool, first, survivor).await, 0);
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains(&last.to_string()), "{err:?}");
    assert!(
        err.message.contains("no source was marked"),
        "the refusal says nothing was marked: {err:?}"
    );
    assert_eq!(
        standing(&pool, last).await,
        (None, false),
        "the retired source is not marked onto the survivor"
    );
    assert_eq!(identity_edges(&pool, last, survivor).await, 0);
}

/// With no administrative connection, every source's cascade deferral is
/// recorded in the call's one transaction, one audit row per source, and
/// every source is marked. Guards the batch path's deferral branch, which
/// records several deferrals before a single commit.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_without_an_admin_connection_defers_each_sources_cascade(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let survivor = seed_claim(&pool, "the restated fact", 0.6).await;
    let dup_a = seed_claim(&pool, "the restated fact, again", 0.5).await;
    let dup_b = seed_claim(&pool, "the restated fact, once more", 0.5).await;
    let (auth, viewer) = common::granted_server_admin(&server, &pool).await;

    let out = consolidate_claims(
        &server,
        &viewer,
        params("identity", &[dup_a, survivor, dup_b], "", Some(survivor)),
        Some(&auth),
    )
    .await
    .expect("identity consolidation with deferred cascades");
    let b = body(&out);
    let marked = b["marked"].as_array().expect("marked");
    assert_eq!(marked.len(), 2, "{b}");
    let mut audit_rows = std::collections::HashSet::new();
    for (m, dup) in marked.iter().zip([dup_a, dup_b]) {
        assert_eq!(m["duplicate_id"], serde_json::json!(dup), "{b}");
        assert_eq!(m["cascade"]["status"], "deferred", "{b}");
        let row = m["cascade"]["audit_event_id"]
            .as_str()
            .expect("a deferral audit row")
            .to_string();
        assert!(audit_rows.insert(row), "one deferral row per source: {b}");
        assert_eq!(
            standing(&pool, dup).await,
            (Some(survivor), false),
            "{dup} marked"
        );
        assert_eq!(identity_edges(&pool, dup, survivor).await, 1);
    }
}

/// The marks are one transaction, and a transaction carries one stamp. A
/// `claims:admin` caller whose pairs would act under different stamps (its own
/// for a source whose owning group it writes, this server's agent through the
/// admin borrow for one it does not) is refused before anything is written,
/// and told to split the call.
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_refuses_sources_that_need_different_write_identities(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let (caller, auth, viewer) =
        common::seed_caller(&pool, &["claims:write", "claims:admin"]).await;
    common::seed_admin_grant(&pool, &auth).await;
    let own_group = common::personal_group_of(&pool, caller).await;
    let survivor = seed_claim(&pool, "the caller's restated fact", 0.6).await;
    let dup_own = seed_claim(&pool, "the caller's restated fact, again", 0.5).await;
    let dup_foreign = seed_claim(&pool, "someone else's restatement", 0.5).await;
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(survivor)
        .bind(own_group)
        .execute(&pool)
        .await
        .expect("make the survivor public and the caller's");
    common::stamp_group_private(&pool, dup_own, own_group).await;
    let stranger = common::seed_agent(&pool).await;
    let stranger_group = common::personal_group_of(&pool, stranger).await;
    sqlx::query("UPDATE claims SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(dup_foreign)
        .bind(stranger_group)
        .execute(&pool)
        .await
        .expect("make the foreign duplicate public and stranger-owned");

    let err = consolidate_claims(
        &server,
        &viewer,
        params(
            "identity",
            &[survivor, dup_own, dup_foreign],
            "",
            Some(survivor),
        ),
        Some(&auth),
    )
    .await
    .expect_err("pairs needing two stamps refuse the call");
    for id in [survivor, dup_own, dup_foreign] {
        assert_eq!(
            standing(&pool, id).await,
            (None, true),
            "source {id} is untouched: {err:?}"
        );
    }
    assert_eq!(identity_edges(&pool, dup_own, survivor).await, 0);
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains("Split the call"), "{err:?}");
    assert!(err.message.contains("nothing was written"), "{err:?}");
}

/// The survivor is locked with the sources (review of 635dbfae): another
/// writer that marks the SURVIVOR elsewhere while the call runs (the shape of
/// a second identity call with the roles swapped, which would leave the
/// cluster with no current claim) refuses the whole call, and no source is
/// marked onto the retired survivor.
///
/// One non-survivor source, so the survivor's retirement can land only after
/// the call's one act has read the survivor as current. Without the survivor
/// in the call's lock, that act passes its own (plain) check of the
/// survivor, waits at most on its identity edge's foreign-key check, and
/// commits once the other writer has: the source stands marked onto a
/// non-current claim and the call reports success. (With two sources the
/// second act's own check would catch the retirement too, so that shape does
/// not tell the lock from the acts.)
#[sqlx::test(migrations = "../../migrations")]
async fn identity_mode_marks_nothing_when_the_survivor_is_marked_elsewhere_concurrently(
    pool: PgPool,
) {
    let (result, waited, [survivor, _, last, elsewhere]) = identity_call_racing_a_change(
        &pool,
        RaceTarget::Survivor,
        ConcurrentChange::MarkedElsewhere,
    )
    .await;
    assert_eq!(
        standing(&pool, last).await,
        (None, true),
        "the source is not left marked onto the retired survivor: {result:?}"
    );
    assert_eq!(identity_edges(&pool, last, survivor).await, 0);
    let err = result.expect_err("the retired survivor refuses the call");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains(&survivor.to_string()), "{err:?}");
    assert!(err.message.contains("no longer current"), "{err:?}");
    assert!(err.message.contains("no source was marked"), "{err:?}");
    assert!(waited, "the call waited on the survivor's row lock");
    assert_eq!(
        standing(&pool, survivor).await,
        (Some(elsewhere), false),
        "the other writer's mark of the survivor stands"
    );
}
