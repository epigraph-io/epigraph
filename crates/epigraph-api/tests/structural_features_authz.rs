//! PR-08 — `GET /api/v1/structural-features/:owner_id`.
//!
//! # Why every test here is a real HTTP round trip
//!
//! The endpoint issues **nine** statements per request (the plan says three).
//! One authenticated 200 therefore executes all nine for real, which is what
//! makes `Viewer::splice`'s missing-marker assert and every bind index in
//! `epigraph_db::repos::structural` actually load-bearing: a marker deleted from
//! any of the nine, or a `splice(sql, 2)` that should have been `splice(sql, 3)`,
//! turns these tests red. A repo-level test of `node_counts` alone would leave
//! eight statements unexecuted and ship green.
//!
//! [`owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part`] is
//! therefore written as one test over one corpus rather than nine, and it
//! asserts on all nine response fields.
//!
//! # Non-vacuity
//!
//! Every visibility assertion is paired with a control in the same response:
//! the stranger must still see the PUBLIC row. A test that only asserted
//! "the stranger does not see the private claim" passes just as well against a
//! handler that 500s, against an empty corpus, and against a `WHERE owner_id =
//! $1` that matches nothing — which is the correction PR-07's own acceptance
//! criterion #3 records.
//!
//! Concretely: the owner's `node_counts` for `claim` is **3** and the
//! stranger's is **2**; the owner sees a `RELATES_TO` edge count and the
//! stranger sees no `RELATES_TO` key at all. Same-number-for-both would be a
//! vacuous pass.
//!
//! # `claims:admin` buys exact counts, not visibility
//!
//! The comparison test gives BOTH principals `claims:admin` (it must, to read
//! exact counts at `epsilon=0`). The stranger is an admin and still sees only
//! the public part — which is the assertion that `claims:admin` is a noise gate
//! and not a tenancy bypass.

use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

/// The corpus one owner owns, plus tokens for the owner and for a stranger.
struct Corpus {
    owner_agent: Uuid,
    pub_a: Uuid,
    pub_b: Uuid,
    priv_c: Uuid,
    owner_token: String,
    stranger_token: String,
}

async fn connect() -> (PgPool, String) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    (pool, url)
}

async fn seed_ownership(pool: &PgPool, node_id: Uuid, node_type: &str, owner_id: Uuid) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, $2, 'public', $3) \
         ON CONFLICT (node_id) DO UPDATE SET node_type = $2, owner_id = $3",
    )
    .bind(node_id)
    .bind(node_type)
    .bind(owner_id)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed ownership row for {node_type} {node_id}: {e}"));
}

/// Build the corpus. Three owned claims — two `public`, one `group` — plus one
/// public and one group-private edge, two frames, two combined beliefs, and two
/// perspective/community pairs, so that **every one of the nine statements has
/// something to hide and something to show**.
///
/// It also writes one `node_type = 'agent'` ownership row. `agents` carries no
/// tenancy columns, so `repos::structural` cannot decide its visibility and
/// excludes it fail-closed; the tests assert it is absent for BOTH principals,
/// which is the only way that deliberate exclusion is distinguishable from an
/// accident.
async fn seed_corpus(pool: &PgPool, scopes: &[&str]) -> Corpus {
    let tag = Uuid::new_v4();
    let (owner_agent, owner_group) =
        fixture::seed_agent_with_group(pool, &format!("structural-owner-{tag}")).await;
    let (stranger_agent, _) =
        fixture::seed_agent_with_group(pool, &format!("structural-stranger-{tag}")).await;

    let pub_a = fixture::seed_public_claim(pool, owner_agent, &format!("{tag} public a")).await;
    let pub_b = fixture::seed_public_claim(pool, owner_agent, &format!("{tag} public b")).await;
    let priv_c =
        fixture::seed_group_claim(pool, owner_agent, owner_group, &format!("{tag} private c"))
            .await;

    for claim in [pub_a, pub_b, priv_c] {
        seed_ownership(pool, claim, "claim", owner_agent).await;
        sqlx::query("UPDATE claims SET belief = 0.6, plausibility = 0.9, pignistic_prob = 0.75 WHERE id = $1")
            .bind(claim)
            .execute(pool)
            .await
            .expect("populate belief columns");
    }

    // A node type with no tenancy columns anywhere. Must vanish from every count.
    seed_ownership(pool, Uuid::new_v4(), "agent", owner_agent).await;

    // A closed triangle pub_a — pub_b — priv_c — pub_a, of which exactly one
    // edge (pub_a → pub_b) is group-private. Three properties fall out of this
    // one shape:
    //
    // * the two public edges touch one visible and one invisible ENDPOINT, so
    //   `edge_counts` separates "the endpoint is filtered" from "the edge is";
    // * the group-private edge joins two PUBLIC claims, so a `RELATES_TO` count
    //   in a stranger's response can only come from an unfiltered `edges` read;
    // * the triangle exists for the owner and is broken for the stranger, which
    //   is the only way `clustering_coefficients` — the largest of the nine, and
    //   the one whose `e3` disjunction had to be re-parenthesised — produces
    //   different answers rather than a shared zero.
    for (src, dst, rel, vis, group) in [
        (pub_a, priv_c, "SUPPORTS", "public", Uuid::nil()),
        (pub_b, priv_c, "SUPPORTS", "public", Uuid::nil()),
        (pub_a, pub_b, "RELATES_TO", "group", owner_group),
        // A FOURTH EDGE, ADDED BY PR-12, WHOSE ONLY JOB IS TO KEEP THE
        // STRANGER'S `edge_counts` MAP NON-EMPTY.
        //
        // Once arm (b)'s endpoint meet made both SUPPORTS edges group-private
        // (they touch `priv_c`), every assertion about `sedges` became
        // NEGATIVE — `!contains_key(..)` twice — so an `edge_counts` statement
        // that returned `{}` for every principal would have passed. This edge
        // joins two PUBLIC claims and is itself public, so the meet leaves it
        // ('public', world) and the stranger MUST count it. That restores a
        // positive on the stranger's edge map, which is what distinguishes a
        // working edge filter from a dead statement.
        //
        // It is deliberately a NEW relationship between the EXISTING pair, so
        // it changes no node count: `degree_stats.total_nodes`,
        // `temporal_bins` and `belief_stats` are untouched, and the stranger's
        // `clustering_stats.eligible_nodes` stays 0 because one public edge
        // still leaves both visible nodes at degree 1.
        //
        // `CONTRADICTS` and not some invented label: `edge_counts` projects only
        // `repos/structural.rs::COARSE_EDGE_TYPES`, so a relationship outside
        // that whitelist is silently dropped and the assertion below would fail
        // for a reason that has nothing to do with tenancy. Measured — the first
        // attempt used `CITES` and the stranger's map came back empty.
        (pub_a, pub_b, "CONTRADICTS", "public", Uuid::nil()),
    ] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                visibility, owner_group_id) \
             VALUES ($1, 'claim', $2, 'claim', $3, $4, $5)",
        )
        .bind(src)
        .bind(dst)
        .bind(rel)
        .bind(vis)
        .bind(if vis == "public" {
            fixture::world_group(pool).await
        } else {
            group
        })
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed {vis} {rel} edge: {e}"));
    }

    // Two frames. The membership row for the private claim is itself made
    // group-private, so `frame_coverage` is filtered on `claim_frames` as well
    // as on `claims` — `claim_frames` is in migration 062's `tier_a`.
    let frame_pub = common::seed_frame_with_claim(pool, pub_a).await;
    let frame_priv = common::seed_frame_with_claim(pool, priv_c).await;
    sqlx::query(
        "UPDATE claim_frames SET visibility = 'group', owner_group_id = $1 \
         WHERE claim_id = $2 AND frame_id = $3",
    )
    .bind(owner_group)
    .bind(priv_c)
    .bind(frame_priv)
    .execute(pool)
    .await
    .expect("make the private frame membership group-private");

    // One combined belief per claim. Both rows are `public`; the private one is
    // hidden only through its claim, which is what exercises the `claims` leg of
    // `conflict_coefficients`.
    for (claim, frame) in [(pub_a, frame_pub), (priv_c, frame_priv)] {
        sqlx::query(
            "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, belief, \
                                              plausibility, conflict_k) \
             VALUES ($1, $2, 'global', 0.6, 0.9, 0.25)",
        )
        .bind(frame)
        .bind(claim)
        .execute(pool)
        .await
        .expect("seed combined belief");
    }

    // Two perspectives owned by the same agent, one public and one
    // group-private, each in its own community.
    for (visibility, group) in [("public", Uuid::nil()), ("group", owner_group)] {
        let perspective: Uuid = sqlx::query_scalar(
            "INSERT INTO perspectives (name, owner_agent_id, visibility, owner_group_id) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(format!("{tag}-{visibility}-perspective"))
        .bind(owner_agent)
        .bind(visibility)
        .bind(if visibility == "public" {
            fixture::world_group(pool).await
        } else {
            group
        })
        .fetch_one(pool)
        .await
        .expect("seed perspective");

        let community: Uuid =
            sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
                .bind(format!("{tag}-{visibility}-community"))
                .fetch_one(pool)
                .await
                .expect("seed community");

        sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
            .bind(community)
            .bind(perspective)
            .execute(pool)
            .await
            .expect("seed community membership");
    }

    Corpus {
        owner_agent,
        pub_a,
        pub_b,
        priv_c,
        owner_token: common::mint_token_with_agent(scopes, owner_agent),
        stranger_token: common::mint_token_with_agent(scopes, stranger_agent),
    }
}

/// `GET /api/v1/structural-features/:owner` and return `(status, body)`.
async fn get_features(
    addr: std::net::SocketAddr,
    owner: Uuid,
    query: &str,
    token: Option<&str>,
) -> (reqwest::StatusCode, String) {
    let mut req = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/structural-features/{owner}?{query}"
        ))
        .timeout(std::time::Duration::from_secs(60));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.expect("structural-features request");
    let status = resp.status();
    (status, resp.text().await.expect("response body"))
}

async fn get_features_ok(
    addr: std::net::SocketAddr,
    owner: Uuid,
    query: &str,
    token: &str,
    who: &str,
) -> Value {
    let (status, body) = get_features(addr, owner, query, Some(token)).await;
    assert!(
        status.is_success(),
        "GET structural-features as {who} must succeed; got {status}: {body}"
    );
    serde_json::from_str(&body).expect("structural-features body is json")
}

/// `{"node_counts": [{"node_type": t, "count": n}]}` → `{t: n}`.
fn counts(v: &Value, field: &str, key: &str) -> BTreeMap<String, i64> {
    v[field]
        .as_array()
        .unwrap_or_else(|| panic!("`{field}` must be an array; got {v}"))
        .iter()
        .map(|row| {
            (
                row[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("row has no string `{key}`: {row}"))
                    .to_string(),
                row["count"].as_i64().expect("row has an integer `count`"),
            )
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// Acceptance: an authenticated non-member's counts exclude every private node
// ─────────────────────────────────────────────────────────────────────────

/// Every one of the nine statements, over one corpus, for two principals.
///
/// Both tokens carry `claims:admin` and both requests pass `epsilon=0`, so the
/// numbers below are EXACT — no Laplace noise to make an assertion
/// probabilistic. That the stranger holds `claims:admin` and still sees only the
/// public part is the point: the scope gates noise, not visibility.
#[tokio::test(flavor = "multi_thread")]
async fn owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part() {
    let (pool, url) = connect().await;
    let corpus = seed_corpus(&pool, &["claims:read", "claims:admin"]).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let owner = corpus.owner_agent;

    let o = get_features_ok(addr, owner, "epsilon=0", &corpus.owner_token, "owner").await;
    let s = get_features_ok(addr, owner, "epsilon=0", &corpus.stranger_token, "stranger").await;

    assert_eq!(
        o["noise_applied"], false,
        "epsilon=0 with claims:admin must return exact counts"
    );

    // 1. node_counts ────────────────────────────────────────────────────
    let onodes = counts(&o, "node_counts", "node_type");
    let snodes = counts(&s, "node_counts", "node_type");
    assert_eq!(
        onodes.get("claim"),
        Some(&3),
        "the owner owns three claims; got {onodes:?}"
    );
    assert_eq!(
        snodes.get("claim"),
        Some(&2),
        "a stranger must see the two PUBLIC claims and not the group-private \
         one — and seeing two rather than zero is what distinguishes a working \
         filter from a broken endpoint; got {snodes:?}"
    );
    for (who, m) in [("owner", &onodes), ("stranger", &snodes)] {
        assert!(
            !m.contains_key("agent"),
            "`agent` ownership rows carry no tenancy columns and are excluded \
             fail-closed for every principal, including the {who}; got {m:?}"
        );
    }

    // 2. edge_counts ────────────────────────────────────────────────────
    let oedges = counts(&o, "edge_counts", "relationship");
    let sedges = counts(&s, "edge_counts", "relationship");
    assert_eq!(
        oedges.get("RELATES_TO"),
        Some(&2),
        "the owner must see its own group-private edge, counted once per owned \
         endpoint; got {oedges:?}"
    );
    assert!(
        !sedges.contains_key("RELATES_TO"),
        "a group-private EDGE must not appear in a stranger's edge counts even \
         though both its endpoints are public claims ({{VISIBILITY:e}}); got \
         {sedges:?}"
    );
    assert_eq!(
        oedges.get("SUPPORTS"),
        Some(&4),
        "each public edge is counted once per owned endpoint, and the owner owns \
         both endpoints of both; got {oedges:?}"
    );
    // PR-12 TIGHTENING: an edge is now the MEET of its endpoints.
    //
    // Both SUPPORTS edges touch `priv_c`, which is group-private. Migration 070
    // arm (b) therefore stamps them ('group', owner_group) at INSERT, and a
    // stranger sees NEITHER. Before PR-12 they were stored ('public', world) as
    // the fixture bound them, and the stranger saw each one at its single
    // visible endpoint.
    //
    // The tightening is correct, not incidental: an edge touching a private
    // claim ATTESTS THAT THE PRIVATE CLAIM EXISTS and stands in a named
    // relationship to a public one. That is precisely the structural leak the
    // endpoint meet exists to close, and it is why arm (b) derives rather than
    // trusting the writer.
    //
    // The discriminating power of this case is preserved, and is now carried by
    // the two assertions around it: the owner still sees SUPPORTS 4 (so the
    // edges exist and the endpoint-pair counting is unchanged), and the stranger
    // still sees the two public CLAIMS (so this is edge filtering, not a dead
    // endpoint).
    assert!(
        !sedges.contains_key("SUPPORTS"),
        "both SUPPORTS edges touch the group-private claim, so migration 070 arm \
         (b)'s endpoint meet makes them group-private too — a stranger must see \
         neither; got {sedges:?}"
    );
    // THE POSITIVE. Without it every assertion about `sedges` is a negative and
    // an `edge_counts` statement returning `{}` would pass.
    assert_eq!(
        sedges.get("CONTRADICTS"),
        Some(&2),
        "the stranger MUST count the public edge between two public claims — \
         once per visible endpoint, the same convention the owner's counts use. \
         An empty map here means the edge statement is dead, not that the \
         filter works; got {sedges:?}"
    );
    assert_eq!(
        oedges.get("CONTRADICTS"),
        Some(&2),
        "and the owner counts it identically — the two principals differ only \
         on what is private; got {oedges:?}"
    );

    // 3. degree_stats ───────────────────────────────────────────────────
    assert_eq!(
        o["degree_stats"]["total_nodes"], 3,
        "degree distribution spans the owner's three visible claims: {o}"
    );
    assert_eq!(
        s["degree_stats"]["total_nodes"], 2,
        "a stranger's degree distribution must span only the visible nodes: {s}"
    );

    // 4. belief_stats ───────────────────────────────────────────────────
    assert_eq!(
        o["belief_stats"]["claims_with_belief"], 3,
        "owner belief_stats: {o}"
    );
    assert_eq!(
        s["belief_stats"]["claims_with_belief"], 2,
        "a group-private claim's belief interval must not enter a stranger's \
         distribution: {s}"
    );

    // 5. frame_coverage ─────────────────────────────────────────────────
    assert_eq!(o["frame_coverage"], 2, "owner frame_coverage: {o}");
    assert_eq!(
        s["frame_coverage"], 1,
        "a stranger must not learn that the owner's claims touch a second frame \
         through a group-private claim_frames row: {s}"
    );

    // 6. temporal_bins ──────────────────────────────────────────────────
    let obins: i64 = counts(&o, "temporal_bins", "bin_label").values().sum();
    let sbins: i64 = counts(&s, "temporal_bins", "bin_label").values().sum();
    assert_eq!(
        obins, 3,
        "the owner's activity bins must total its three visible nodes — the \
         `agent` row is excluded from these too; got {obins}"
    );
    assert_eq!(
        sbins, 2,
        "a stranger's activity bins must total only the visible nodes; got {sbins}"
    );

    // 7. clustering_stats ───────────────────────────────────────────────
    assert!(
        o["clustering_stats"]["eligible_nodes"]
            .as_i64()
            .expect("i64")
            > 0,
        "the owner's three claims form a closed triangle, so the clustering \
         statement must find eligible nodes — a shared zero here would make the \
         stranger assertion below vacuous: {o}"
    );
    assert_eq!(
        s["clustering_stats"]["eligible_nodes"], 0,
        "one leg of the triangle is a group-private EDGE; without it no visible \
         node reaches degree 2 and the stranger learns no clustering at all: {s}"
    );

    // 8. community_membership_count ─────────────────────────────────────
    assert_eq!(
        o["community_membership_count"], 2,
        "owner community count: {o}"
    );
    assert_eq!(
        s["community_membership_count"], 1,
        "a community reached only through a group-private perspective must not \
         be counted for a stranger: {s}"
    );

    // 9. conflict_stats ─────────────────────────────────────────────────
    assert_eq!(
        o["conflict_stats"]["entries"], 2,
        "owner conflict_stats: {o}"
    );
    assert_eq!(
        s["conflict_stats"]["entries"], 1,
        "a combined belief over a group-private claim must not enter a \
         stranger's conflict distribution: {s}"
    );

    // No claim text may appear in either body under any circumstance.
    for (who, body) in [("owner", o.to_string()), ("stranger", s.to_string())] {
        assert!(
            !body.contains("private c") && !body.contains("public a"),
            "structural-features must expose no claim content to the {who}: {body}"
        );
    }

    let _ = (corpus.pub_a, corpus.pub_b, corpus.priv_c);
    let _ = shutdown.send(());
}

// ─────────────────────────────────────────────────────────────────────────
// Acceptance: anonymous → 401
// ─────────────────────────────────────────────────────────────────────────

/// PR-03 moved this route to the `protected` router; PR-08 asserts the
/// consequence rather than re-implementing it. `ViewerExtractor` is the second
/// line of defence if the registration ever moves back.
#[tokio::test(flavor = "multi_thread")]
async fn anonymous_is_401() {
    let (_pool, url) = connect().await;
    let (addr, shutdown) = common::spawn_app(&url).await;

    let (status, body) = get_features(addr, Uuid::new_v4(), "", None).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "an anonymous structural-features request must be 401; got {status}: {body}"
    );

    let _ = shutdown.send(());
}

// ─────────────────────────────────────────────────────────────────────────
// Acceptance: epsilon that disables the mechanism requires claims:admin
// ─────────────────────────────────────────────────────────────────────────

/// 403, not 401 and not 422: the caller is authenticated and known, and the
/// answer to "give me exact counts" is no.
///
/// The six values are the whole class, not six examples. `0` is the one the
/// plan names; `-1` also fails the "did the mechanism engage" predicate; and
/// `NaN`/`inf` are the two that defeat a gate written as a comparison —
/// `NaN <= 0.0` is FALSE, so a `epsilon <= 0.0` gate waves NaN through while the
/// mechanism is silently off.
///
/// `1e300` and `1.0000001` are the fourth case, added after review. Both are
/// FINITE and POSITIVE, so both passed every check the first four motivated,
/// while `b = 1/epsilon` underflows and `(value as f64 + b_tiny).round()`
/// returns the exact value — a `claims:read` caller obtained exact counts with
/// `"noise_applied": true` in the body. `MAX_UNPRIVILEGED_EPSILON` closes it;
/// `1.0000001` pins the boundary immediately above the ceiling, and
/// [`the_default_epsilon_needs_no_scope_and_turns_the_noise_on`] is the control
/// that the ceiling itself is still admitted.
#[tokio::test(flavor = "multi_thread")]
async fn an_epsilon_that_disables_the_noise_needs_claims_admin() {
    let (pool, url) = connect().await;
    let corpus = seed_corpus(&pool, &["claims:read"]).await;
    let (addr, shutdown) = common::spawn_app(&url).await;

    for q in [
        "epsilon=0",
        "epsilon=-1",
        "epsilon=NaN",
        "epsilon=inf",
        "epsilon=1e300",
        "epsilon=1.0000001",
    ] {
        let (status, body) =
            get_features(addr, corpus.owner_agent, q, Some(&corpus.owner_token)).await;
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "`?{q}` returns exact counts, so it must be 403 without \
             claims:admin; got {status}: {body}"
        );
    }

    let _ = shutdown.send(());
}

/// Non-vacuity for the test above: the same token, same corpus, no epsilon —
/// 200, with the Laplace mechanism engaged. Without this, a handler that 403s
/// unconditionally would pass.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_epsilon_needs_no_scope_and_turns_the_noise_on() {
    let (pool, url) = connect().await;
    let corpus = seed_corpus(&pool, &["claims:read"]).await;
    let (addr, shutdown) = common::spawn_app(&url).await;

    let body = get_features_ok(addr, corpus.owner_agent, "", &corpus.owner_token, "owner").await;
    assert_eq!(
        body["noise_applied"], true,
        "PR-08 flips the epsilon default to 1.0, so a caller that omits the \
         parameter gets the mechanism ON: {body}"
    );

    // The default path must return NUMBERS in a sane band, not `i64::MAX`.
    // Asserting only on `noise_applied` is what let the `rand_simple` blocker
    // through review: a handler returning garbage for every count with
    // `noise_applied: true` passed.
    //
    // At epsilon=1 (b=1) a true count of 3 leaves [0, 25] only if |noise| > 22,
    // probability e^-22 = 2.7e-10; over the four fields the joint
    // spurious-failure probability is ~1e-9.
    //
    // The BOUND is what catches the `|u| == 0.5` boundary, where `ln(0) = -inf`
    // saturated the cast to i64::MAX. It deliberately does NOT try to catch the
    // NaN-laundered-to-zero half of the blocker: `0` is a legitimate Laplace
    // outcome for a true count of 3 (probability 0.041 per field), so any
    // HTTP-level "not zero" assertion is flaky by construction. That half is
    // pinned decisively and without a database by the 2000-draw unit test
    // `routes::structural::tests::\
    //  maybe_add_noise_is_centred_on_the_true_value_and_almost_never_zeroes_it`.
    for (block, field) in [
        ("degree_stats", "total_nodes"),
        ("belief_stats", "claims_with_belief"),
        ("clustering_stats", "eligible_nodes"),
        ("conflict_stats", "entries"),
    ] {
        let c = body[block][field]
            .as_i64()
            .unwrap_or_else(|| panic!("{block}.{field} must be an integer: {body}"));
        assert!(
            (0..=25).contains(&c),
            "a Laplace(b=1) draw around a single-digit true count must stay in \
             a sane band; got {block}.{field} = {c} in {body}. i64::MAX here \
             means the mechanism hit ln(0) = -inf and `.max(0.0)` saturated the \
             cast."
        );
    }

    let _ = shutdown.send(());
}

/// The `claims:admin` gate must actually WITHHOLD the exact counts.
///
/// This is the assertion the suite was missing. `degree_stats.total_nodes` is
/// the row count of `StructuralRepository::degrees` — the same quantity as the
/// sum of `node_counts` — and it shipped exact at every epsilon, so a
/// `claims:read` caller refused exact counts by the gate simply read them two
/// fields further down the same JSON body.
///
/// `epsilon=0.001` is allowed unscoped (it buys MORE privacy than the default,
/// not less) and gives `b = 1000`, so each count is exact only if that draw
/// satisfies `|noise| < 0.5`, i.e. with probability `1 - e^(-0.5/1000) = 5e-4`.
/// The assertion is that at least one of the FOUR moment-count fields moved, so
/// the spurious-failure probability is `(5e-4)^4 ~ 6e-14`. Do not "stabilise"
/// this by asserting on fewer fields or by widening it to `noise_applied` —
/// that is precisely the vacuity it was written to remove.
#[tokio::test(flavor = "multi_thread")]
async fn a_claims_read_caller_cannot_read_the_exact_moment_counts() {
    let (pool, url) = connect().await;
    let corpus = seed_corpus(&pool, &["claims:read", "claims:admin"]).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let owner = corpus.owner_agent;

    // A SECOND token over the same principal, carrying claims:read and NOT
    // claims:admin. Reusing the admin token for the noised request would have
    // left the test's own name unasserted: the claim is that a caller *without*
    // the scope cannot get exact counts, so the caller must actually lack it.
    let read_only_token = common::mint_token_with_agent(&["claims:read"], owner);

    // Exact reference, via the admin-only noise-off path.
    let exact = get_features_ok(addr, owner, "epsilon=0", &corpus.owner_token, "admin").await;
    // The same corpus, same principal, heavily noised, at claims:read only.
    let noisy = get_features_ok(
        addr,
        owner,
        "epsilon=0.001",
        &read_only_token,
        "claims:read",
    )
    .await;

    assert_eq!(exact["noise_applied"], false, "{exact}");
    assert_eq!(noisy["noise_applied"], true, "{noisy}");

    let fields = [
        ("degree_stats", "total_nodes"),
        ("belief_stats", "claims_with_belief"),
        ("clustering_stats", "eligible_nodes"),
        ("conflict_stats", "entries"),
    ];

    // Non-vacuity: the exact response must actually carry non-zero counts, or
    // "the noised one differs" could be satisfied by an empty corpus.
    for (block, field) in fields {
        assert!(
            exact[block][field].as_i64().expect("i64") > 0,
            "the fixture must give {block}.{field} a non-zero exact value, or \
             the comparison below proves nothing: {exact}"
        );
    }

    let moved = fields
        .iter()
        .filter(|(block, field)| noisy[*block][*field] != exact[*block][*field])
        .count();
    assert!(
        moved > 0,
        "every one of the four moment-count fields came back EXACTLY equal to \
         the claims:admin response at epsilon=0.001 (b=1000). They are not \
         being routed through the Laplace mechanism, so the claims:admin gate \
         withholds nothing — the exact counts are readable at claims:read.\n\
         exact: {exact}\nnoisy: {noisy}"
    );

    let _ = shutdown.send(());
}

/// `claims:admin` turns the noise off. Paired with
/// [`an_epsilon_that_disables_the_noise_needs_claims_admin`] this pins the scope
/// as the only difference between 403 and 200.
#[tokio::test(flavor = "multi_thread")]
async fn claims_admin_unlocks_exact_counts() {
    let (pool, url) = connect().await;
    let corpus = seed_corpus(&pool, &["claims:read", "claims:admin"]).await;
    let (addr, shutdown) = common::spawn_app(&url).await;

    let body = get_features_ok(
        addr,
        corpus.owner_agent,
        "epsilon=0",
        &corpus.owner_token,
        "admin owner",
    )
    .await;
    assert_eq!(body["noise_applied"], false, "{body}");

    let _ = shutdown.send(());
}
