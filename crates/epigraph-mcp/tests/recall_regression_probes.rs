//! Recall regression probes (backlog 733df577, part 2).
//!
//! Each probe is a `{query, must_recall, must_not_recall}` case run through
//! `recall_with_context` (its post-embed pipeline, entered with a fixed query
//! vector, the same code the tool runs after embedding) on a seeded database.
//! The cases are drawn from recall defects this codebase has had:
//!
//! 1. `superseded` — a retired version (`is_current = false`) of a claim must
//!    never be a hit, and must not take the page slot its replacement should
//!    fill, even when the CHECK that strips a retired claim's vector is not
//!    in force (7720cb7a; the context legs' liveness is bc76b481).
//! 2. `foreign_private` — another group's private claim is never recalled for
//!    an outsider, and does not displace the public claim it outranks.
//! 3. `own_private` — a member's OWN group-private claim IS recalled: reads on
//!    an unstamped connection used to admit public rows only, so a member's
//!    private claims were never seeds.
//! 4. `ds_belief_floor` — `min_truth` gates on the Dempster–Shafer pignistic
//!    probability, not the authored `truth_value`: a claim authored at 0.9
//!    whose evidence pulled it to 0.2 is not recalled at `min_truth = 0.5`
//!    (14b98adc), while an uncached 0.9 claim is.
//! 5. `since_window` — a claim created before `since` is not recalled, and
//!    does not take the slot of an in-window claim.
//!
//! Every probe's retired/forbidden claim is the EXACT match for its query and
//! the claim that must be recalled is a near match, with `limit` sized so the
//! forbidden one would take the slot if its predicate were missing. Probes sit
//! in orthogonal vector buckets, so one probe's claims never rank in another's
//! page. `must_recall` is never empty (an empty page cannot pass), and every
//! violation is collected before the one assertion, so a regressed run names
//! each probe that broke.

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::TimeZone;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

const DIM: usize = 1536;
const N_BUCKETS: usize = 8;
const STRIDE: usize = DIM / N_BUCKETS;
/// No probe queries this bucket; near matches lean into it.
const SPARE_BUCKET: usize = N_BUCKETS - 1;

/// The query vector for `bucket`, and the exact match for it.
fn exact(bucket: usize) -> String {
    vector(bucket, 0.0)
}

/// A near match for `bucket`: the same direction plus a small component in
/// the spare bucket (cosine similarity about 0.98 to the query, about 0 to
/// every other probe's query).
fn near(bucket: usize) -> String {
    vector(bucket, 0.2)
}

fn vector(bucket: usize, spare: f32) -> String {
    assert!(bucket < SPARE_BUCKET);
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().skip(bucket * STRIDE).take(STRIDE) {
        *slot = 1.0;
    }
    for slot in v.iter_mut().skip(SPARE_BUCKET * STRIDE).take(STRIDE) {
        *slot = spare;
    }
    let inner: Vec<String> = v.iter().map(ToString::to_string).collect();
    format!("[{}]", inner.join(","))
}

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    // Every deployed server carries a ScopedPool; content reads refuse
    // without one (`EpiGraphMcpFull::read_as`).
    let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
        (*pool.connect_options()).clone(),
        epigraph_db::SessionGucMode::Session,
    );
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false).with_scoped_pool(scoped)
}

async fn embed(pool: &PgPool, claim: Uuid, pgvec: &str) {
    fixture::set_claim_embedding(pool, claim, pgvec).await;
}

async fn public_claim(pool: &PgPool, agent: Uuid, content: &str, pgvec: &str) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    embed(pool, id, pgvec).await;
    id
}

async fn group_claim(pool: &PgPool, agent: Uuid, group: Uuid, content: &str, pgvec: &str) -> Uuid {
    let id = fixture::seed_group_claim(pool, agent, group, content).await;
    embed(pool, id, pgvec).await;
    id
}

async fn exec(pool: &PgPool, sql: &str, id: Uuid, what: &str) {
    sqlx::query(sql)
        .bind(id)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{what}: {e}"));
}

fn since_fixture() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
}

/// Who runs the probe. `Viewer` is deliberately not `Clone`, so each probe
/// resolves its own.
#[derive(Clone, Copy)]
enum Who {
    /// The anonymous public viewer.
    Public,
    /// The viewer resolved for this agent (its live group memberships).
    Agent(Uuid),
}

async fn viewer_for(pool: &PgPool, who: Who) -> epigraph_db::Viewer {
    match who {
        Who::Public => fixture::public_viewer(pool).await,
        Who::Agent(agent) => epigraph_db::Viewer::resolve(pool, agent)
            .await
            .expect("resolve viewer"),
    }
}

struct Probe {
    name: &'static str,
    who: Who,
    bucket: usize,
    limit: u32,
    min_truth: f64,
    since: Option<chrono::DateTime<chrono::Utc>>,
    must_recall: Vec<Uuid>,
    must_not_recall: Vec<Uuid>,
}

fn params(p: &Probe) -> RecallWithContextParams {
    serde_json::from_value(serde_json::json!({
        "query": format!("recall regression probe {}", p.name),
        "limit": p.limit,
        "min_truth": p.min_truth,
        "centroid_dim": 1536,
        "since": p.since.map(|s| s.to_rfc3339()),
    }))
    .expect("RecallWithContextParams")
}

fn returned_ids(env: &Value) -> BTreeSet<Uuid> {
    env["results"]
        .as_array()
        .unwrap_or_else(|| panic!("`results` missing from {env:#}"))
        .iter()
        .map(|r| {
            r["paragraph_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or_else(|| panic!("hit without a paragraph_id: {r:#}"))
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_honours_every_regression_probe(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "probe-author").await;
    let (member, team) = fixture::seed_agent_with_group(&pool, "probe-member").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "probe-outsider").await;
    let mut probes = Vec::new();

    // 1. superseded: the retired version is the exact match. A retired claim
    //    keeps no vector while `chk_deprecated_no_embedding` holds, so the
    //    probe drops that CHECK in this throwaway database (as
    //    `epigraph-db/tests/claim_search_by_embedding_is_current.rs` does):
    //    recall must keep retired claims out by its own `is_current`
    //    predicate, not only through a write-side invariant (7720cb7a).
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding")
        .execute(&pool)
        .await
        .expect("drop chk_deprecated_no_embedding in the throwaway database");
    {
        let old = public_claim(&pool, author, "probe superseded: old version", &exact(0)).await;
        let new = public_claim(&pool, author, "probe superseded: replacement", &near(0)).await;
        exec(
            &pool,
            "UPDATE claims SET is_current = false WHERE id = $1",
            old,
            "retire the old version",
        )
        .await;
        sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
            .bind(new)
            .bind(old)
            .execute(&pool)
            .await
            .expect("link the replacement");
        probes.push(Probe {
            name: "superseded",
            who: Who::Public,
            bucket: 0,
            limit: 1,
            min_truth: 0.0,
            since: None,
            must_recall: vec![new],
            must_not_recall: vec![old],
        });
    }

    // 2. foreign_private: the team's private claim is the exact match; the
    //    outsider must get the public near match instead.
    let team_private = group_claim(
        &pool,
        member,
        team,
        "probe private: team-only finding",
        &exact(1),
    )
    .await;
    let public_neighbour =
        public_claim(&pool, author, "probe private: public neighbour", &near(1)).await;
    probes.push(Probe {
        name: "foreign_private",
        who: Who::Agent(outsider),
        bucket: 1,
        limit: 1,
        min_truth: 0.0,
        since: None,
        must_recall: vec![public_neighbour],
        must_not_recall: vec![team_private],
    });

    // 3. own_private: the same query, by a member of the owning group.
    probes.push(Probe {
        name: "own_private",
        who: Who::Agent(member),
        bucket: 1,
        limit: 1,
        min_truth: 0.0,
        since: None,
        must_recall: vec![team_private],
        must_not_recall: vec![public_neighbour],
    });

    // 4. ds_belief_floor: both authored at 0.9; the exact match's evidence
    //    pulled its BetP to 0.2. limit 2 so both are retrieved and only the
    //    floor can drop one.
    {
        let refuted = public_claim(&pool, author, "probe belief: refuted", &exact(2)).await;
        let supported = public_claim(&pool, author, "probe belief: supported", &near(2)).await;
        for id in [refuted, supported] {
            exec(
                &pool,
                "UPDATE claims SET truth_value = 0.9 WHERE id = $1",
                id,
                "author at 0.9",
            )
            .await;
        }
        exec(
            &pool,
            "UPDATE claims SET belief = 0.1, plausibility = 0.3, pignistic_prob = 0.2 \
             WHERE id = $1",
            refuted,
            "DS cache pulled below the floor",
        )
        .await;
        probes.push(Probe {
            name: "ds_belief_floor",
            who: Who::Public,
            bucket: 2,
            limit: 2,
            min_truth: 0.5,
            since: None,
            must_recall: vec![supported],
            must_not_recall: vec![refuted],
        });
    }

    // 5. since_window: the exact match predates the window.
    {
        let archived = public_claim(&pool, author, "probe since: archived", &exact(3)).await;
        let current = public_claim(&pool, author, "probe since: in window", &near(3)).await;
        sqlx::query("UPDATE claims SET created_at = $2 WHERE id = $1")
            .bind(archived)
            .bind(chrono::Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap())
            .execute(&pool)
            .await
            .expect("backdate");
        probes.push(Probe {
            name: "since_window",
            who: Who::Public,
            bucket: 3,
            limit: 1,
            min_truth: 0.0,
            since: Some(since_fixture()),
            must_recall: vec![current],
            must_not_recall: vec![archived],
        });
    }

    let server = build_test_server(pool.clone());
    let mut violations = Vec::new();
    for p in &probes {
        assert!(
            !p.must_recall.is_empty(),
            "{}: a probe with nothing to recall passes on an empty page",
            p.name
        );
        let viewer = viewer_for(&pool, p.who).await;
        let out =
            recall_with_context_with_pgvec(&server, &viewer, params(p), 1536, &exact(p.bucket))
                .await
                .unwrap_or_else(|e| panic!("{}: recall_with_context failed: {e:?}", p.name));
        let text = out
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone()))
            .expect("text content");
        let env: Value = serde_json::from_str(&text).expect("parse envelope");
        let got = returned_ids(&env);
        for id in &p.must_recall {
            if !got.contains(id) {
                violations.push(format!("{}: must recall {id}, got {got:?}", p.name));
            }
        }
        for id in &p.must_not_recall {
            if got.contains(id) {
                violations.push(format!("{}: must NOT recall {id}, got {got:?}", p.name));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "recall regression probes failed:\n  {}",
        violations.join("\n  ")
    );
}
