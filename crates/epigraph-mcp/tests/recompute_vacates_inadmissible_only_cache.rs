//! Ruling R-80 (on R-22 / R-71): a claim whose EVERY BBA is inadmissible
//! for its cache (some source is narrower than the claim) gets a VACUOUS
//! cache on recompute (full ignorance: Bel 0, Pl 1, BetP 0.5 on the binary
//! frame, classification `not_enough_info`), instead of keeping its old
//! cached value.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The recompute fold drops every inadmissible BBA
//! (`epigraph_engine::derivation_scope::retain_for_cache`). When that left
//! nothing, `recompute_combined_belief` returned without writing, so the claim
//! kept the value folded BEFORE its source was narrowed (evidence hidden after
//! the fact, or a cache written before R-22). That stale value is what every
//! reader of the claim is served, and it still carries the narrowed evidence's
//! direction and weight. `recompute_beliefs` reported the claim as recomputed.
//!
//! # What is pinned
//!
//! * the vacate, on an `epigraph_app` session stamped as a member of the
//!   evidence's group and as the claim's author (row security applies), and
//!   through the MCP `recompute_beliefs` tool on the maintenance session,
//!   read back as served by MCP `get_belief` and `get_claim`;
//! * the write-free preview (`preview_claim_belief_on_frame`, behind
//!   `recompute_betp --dry-run`, `shadow_report`, MCP `submit_ds_evidence`
//!   and REST `submit_evidence`) returns the value the write leaves;
//! * a vacate on a non-binary owner frame (`claim_validity`): BetP 1/|frame|
//!   and the classification reset to `not_enough_info`;
//! * a GROUP claim whose evidence moves to another group is vacated, read
//!   by a member of the claim's group (the R-80 reads are viewer-spliced);
//! * the claim-wide gate: an admissible input on ANOTHER frame of the claim
//!   means not every BBA is inadmissible, so nothing is vacated (public and
//!   group claims), and the cache is left exactly as it was;
//! * a compound is never vacated (its cache is not a fold of its own BBAs);
//! * a claim with no cache stays without one (writing a vacuous value there
//!   would announce that an unseen BBA exists).
//!
//! The HTTP twin (`POST /api/v1/edges`' dependent propagation on the unstamped
//! connection, read back through `GET /api/v1/claims/:id/belief`) is
//! `crates/epigraph-api/tests/recompute_vacates_inadmissible_only_cache_http.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PerspectiveRepository, ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    ensure_binary_frame, preview_claim_belief_on_frame, recompute_claim_belief_on_frame,
    recompute_claim_cached_belief, resolve_claim_validity_frame,
};
use epigraph_mcp::types::{GetBeliefParams, GetClaimParams, RecomputeBeliefsParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

/// The claim's whole cache: (BetP, Bel, Pl, mass_on_empty, mass_on_missing,
/// belief_frame_id, classification).
type Cache = (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
);

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as(
        "SELECT pignistic_prob, belief, plausibility, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// Put `value` back as the claim's cache (the stale value a recompute meets).
async fn restore(pool: &PgPool, claim: Uuid, value: &Cache) {
    sqlx::query(
        "UPDATE claims SET pignistic_prob = $2, belief = $3, plausibility = $4, \
                mass_on_empty = $5, mass_on_missing = $6, belief_frame_id = $7, \
                classification = $8 \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(value.0)
    .bind(value.1)
    .bind(value.2)
    .bind(value.3)
    .bind(value.4)
    .bind(value.5)
    .bind(value.6.as_deref())
    .execute(pool)
    .await
    .expect("restore the cache");
}

fn near(x: Option<f64>, y: f64) -> bool {
    x.is_some_and(|x| (x - y).abs() < 1e-9)
}

/// Full ignorance on the binary `frame`: BetP 0.5, Bel 0, Pl 1, no conflict,
/// no missing mass, `not_enough_info`.
fn is_vacuous(c: &Cache, frame: Uuid) -> bool {
    is_vacuous_over(c, frame, 2)
}

/// Full ignorance on `frame` of `hypotheses` hypotheses: BetP 1/|frame|.
fn is_vacuous_over(c: &Cache, frame: Uuid, hypotheses: u32) -> bool {
    near(c.0, 1.0 / f64::from(hypotheses))
        && near(c.1, 0.0)
        && near(c.2, 1.0)
        && near(c.3, 0.0)
        && near(c.4, 0.0)
        && c.5 == Some(frame)
        && c.6.as_deref() == Some("not_enough_info")
}

/// The stale value the vacate tests start from where a test sets it by hand:
/// the shape a fold of one supporting BBA leaves on `frame`.
fn stale_on(frame: Uuid) -> Cache {
    (
        Some(0.9),
        Some(0.8),
        Some(1.0),
        Some(0.0),
        Some(0.0),
        Some(frame),
        Some("supported".to_string()),
    )
}

/// The MCP server the tool and reader tests call.
fn server(pool: &PgPool, scoped: ScopedPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x80u8; 32]).expect("signer");
    EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        McpEmbedder::new(pool.clone(), None),
        false,
    )
    .with_scoped_pool(scoped)
}

fn json_of(out: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = match out.content.first().cloned().expect("content") {
        ContentBlock::Text(t) => t.text,
        other => panic!("expected text, got {other:?}"),
    };
    serde_json::from_str(&text).expect("JSON body")
}

/// `recompute_beliefs` over `claim` on the maintenance session; its report.
async fn recompute_beliefs(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    claim: Uuid,
) -> serde_json::Value {
    let out = tools::cdst_maintenance::recompute_beliefs(
        server,
        &mut fixture::scoped_pool(pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("maintenance session"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    json_of(&out)
}

/// A BBA on (`claim`, `frame`) by `agent` citing `evidence`, with `t` on TRUE.
async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid, t: f64) {
    PerspectiveRepository::ensure_evidence_perspective(pool, evidence, Some(agent))
        .await
        .expect("evidence perspective");
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(evidence),
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store a BBA");
}

/// Narrow `evidence` to `group`, pinned as `epigraph-operator hide-evidence`
/// pins it (migration 110). The BBA row citing it stays public.
async fn hide(pool: &PgPool, evidence: Uuid, group: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(evidence)
    .bind(by)
    .execute(pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(evidence)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow the evidence to the group");
}

async fn app_role(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// `recompute_claim_cached_belief` on an `epigraph_app` session stamped as
/// `viewer`, committed.
async fn recompute_as(scoped: &ScopedPool, viewer: &Viewer, claim: Uuid) {
    let mut tx = scoped.begin_as(viewer).await.expect("stamped app session");
    recompute_claim_cached_belief(&mut tx, viewer, claim)
        .await
        .expect("recompute on the application role");
    tx.commit().await.expect("commit");
}

struct World {
    public: Viewer,
    member: Uuid,
    member_viewer: Viewer,
    author: Uuid,
    author_viewer: Viewer,
    group: Uuid,
    binary: Uuid,
}

async fn world(pool: &PgPool, label: &str) -> World {
    let public = fixture::public_viewer(pool).await;
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{label}-member")).await;
    let (author, _) = fixture::seed_agent_with_group(pool, &format!("{label}-author")).await;
    let member_viewer = Viewer::resolve(pool, member).await.expect("member viewer");
    let author_viewer = Viewer::resolve(pool, author).await.expect("author viewer");
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    World {
        public,
        member,
        member_viewer,
        author,
        author_viewer,
        group,
        binary,
    }
}

/// A public claim with one BBA citing public evidence, its cache recomputed,
/// then that evidence hidden: every BBA of the claim is now inadmissible and
/// the cache still holds the value folded from it. Returns (claim, that cache).
async fn stale_claim(pool: &PgPool, w: &World, label: &str) -> (Uuid, Cache) {
    let claim = fixture::seed_public_claim(pool, w.author, label).await;
    let ev = fixture::seed_evidence(pool, claim, "observation").await;
    store(pool, claim, w.binary, w.author, ev, 0.8).await;
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        claim,
    )
    .await
    .expect("recompute while the evidence is public");
    let stale = cache(pool, claim).await;
    assert!(
        stale.0.is_some_and(|b| b > 0.55) && stale.6.is_some(),
        "PREMISE: the public evidence's fold is cached ({stale:?})"
    );
    hide(pool, ev, w.group, w.member).await;
    (claim, stale)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_every_bba_is_inadmissible_gets_a_vacuous_cache_on_recompute(pool: PgPool) {
    let w = world(&pool, "r80-vacate").await;
    let (claim, stale) = stale_claim(&pool, &w, "r80 every bba inadmissible").await;
    let scoped = app_role(&pool).await;

    // The write-free preview a dry run reads (`recompute_betp --dry-run`,
    // `shadow_report`) reports the value the write is about to leave, not
    // "no input".
    {
        let mut tx = scoped
            .begin_as(&w.member_viewer)
            .await
            .expect("stamped app session");
        let preview = preview_claim_belief_on_frame(&mut tx, &w.member_viewer, claim, w.binary)
            .await
            .expect("preview on the application role");
        tx.rollback().await.expect("rollback");
        let p = preview.unwrap_or_else(|| {
            panic!(
                "the preview of a claim whose recompute vacates its cache said there is \
                 nothing to write (stale value {stale:?})"
            )
        });
        assert!(
            near(Some(p.pignistic_prob), 0.5)
                && near(Some(p.belief), 0.0)
                && near(Some(p.plausibility), 1.0)
                && near(Some(p.conflict_k), 0.0)
                && near(Some(p.missing_mass), 0.0)
                && p.classification.as_deref() == Some("not_enough_info"),
            "the preview must be the full-ignorance value the write leaves: {p:?}"
        );
        assert_eq!(
            cache(&pool, claim).await,
            stale,
            "the preview wrote nothing"
        );
    }

    // The member can read the hidden evidence; the author cannot. Neither may
    // leave the claim's readers a belief folded from it.
    for (who, viewer) in [("member", &w.member_viewer), ("author", &w.author_viewer)] {
        restore(&pool, claim, &stale).await;
        recompute_as(&scoped, viewer, claim).await;
        let after = cache(&pool, claim).await;
        assert!(
            is_vacuous(&after, w.binary),
            "recompute as the {who} on the application role must vacate the cache of a claim \
             whose every BBA is inadmissible; it left {after:?} (stale value {stale:?})"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_vacates_a_claim_whose_every_bba_is_inadmissible(pool: PgPool) {
    let w = world(&pool, "r80-tool").await;
    let (claim, stale) = stale_claim(&pool, &w, "r80 recompute_beliefs").await;
    let server = server(&pool, fixture::scoped_pool(&pool).await);

    let report = recompute_beliefs(&pool, &server, claim).await;

    let after = cache(&pool, claim).await;
    assert!(
        is_vacuous(&after, w.binary),
        "recompute_beliefs must vacate the cache of a claim whose every BBA is inadmissible; \
         it left {after:?} (stale value {stale:?}) and reported {report}"
    );
    // The report is the same before and after the fix (it counted the claim
    // as recomputed even when nothing was written), so these do not tell the
    // two apart: they pin that the vacate is reported as a write, not an
    // error.
    assert_eq!(report["claims_recomputed"], 1, "{report}");
    assert_eq!(report["frame_writes"], 1, "{report}");
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");

    // What a reader outside the evidence's group is SERVED afterwards: the
    // unframed MCP `get_belief` (the cached columns) and `get_claim`'s
    // classification.
    let belief = json_of(
        &tools::ds::get_belief(
            &server,
            &w.author_viewer,
            GetBeliefParams {
                claim_id: claim.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .expect("get_belief"),
    );
    assert_eq!(belief["source"], "cached", "{belief}");
    for (field, want) in [
        ("pignistic_prob", 0.5),
        ("belief", 0.0),
        ("plausibility", 1.0),
        ("ignorance", 1.0),
        ("mass_on_conflict", 0.0),
        ("mass_on_missing", 0.0),
    ] {
        assert!(
            near(belief[field].as_f64(), want),
            "get_belief served {field} = {} after the vacate, not {want}: {belief}",
            belief[field]
        );
    }
    let got = json_of(
        &tools::claims::get_claim(
            &server,
            &w.author_viewer,
            GetClaimParams {
                claim_id: claim.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .expect("get_claim"),
    );
    assert_eq!(
        got["classification"], "not_enough_info",
        "get_claim served the old verdict after the vacate: {got}"
    );
}

/// A claim with no cache whose every BBA is inadmissible, through the tool:
/// it keeps no cache. The report still counts it as recomputed and as a
/// frame write although nothing was written; that over-count is a KNOWN
/// RESIDUAL pinned here as it stands (`recompute_claim_belief_on_frame`
/// answers `true` whenever the frame had rows), not intended behaviour.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_gives_a_claim_without_a_cache_none(pool: PgPool) {
    let w = world(&pool, "r80-tool-null").await;
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 tool never cached").await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    hide(&pool, ev, w.group, w.member).await;
    store(&pool, claim, w.binary, w.member, ev, 0.8).await;
    let server = server(&pool, fixture::scoped_pool(&pool).await);

    let report = recompute_beliefs(&pool, &server, claim).await;

    let after = cache(&pool, claim).await;
    assert!(
        after.0.is_none() && after.1.is_none() && after.2.is_none() && after.6.is_none(),
        "recompute_beliefs gave a claim whose only BBA is inadmissible a cache it never \
         had: {after:?} ({report})"
    );
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");
    assert_eq!(
        (&report["claims_recomputed"], &report["frame_writes"]),
        (&serde_json::json!(1), &serde_json::json!(1)),
        "KNOWN RESIDUAL changed (the tool counts a frame whose fold emptied without a write); \
         update this pin with the fix: {report}"
    );
}

/// Not every BBA is inadmissible: the claim keeps an admissible input on
/// `claim_validity` while its `binary_truth` (the cache-owner frame) holds only
/// a hidden-evidence BBA. R-80 does not vacate it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admissible_input_on_another_frame_is_not_vacated(pool: PgPool) {
    let w = world(&pool, "r80-other-frame").await;
    let validity =
        resolve_claim_validity_frame(&mut pool.acquire().await.expect("acquire"), &w.public)
            .await
            .expect("claim_validity");
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 admissible elsewhere").await;
    let open_ev = fixture::seed_evidence(&pool, claim, "observation").await;
    store(&pool, claim, validity, w.author, open_ev, 0.7).await;
    let hidden_ev = fixture::seed_evidence(&pool, claim, "document").await;
    store(&pool, claim, w.binary, w.member, hidden_ev, 0.9).await;
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        claim,
    )
    .await
    .expect("recompute while every source is public");
    let before = cache(&pool, claim).await;
    assert!(
        before.0.is_some() && before.5 == Some(w.binary),
        "PREMISE: binary_truth owns a filled cache ({before:?})"
    );
    hide(&pool, hidden_ev, w.group, w.member).await;

    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    // KNOWN RESIDUAL (R-71), not intended behaviour: the value kept here was
    // folded from the now-hidden evidence. The cache owner rule
    // (`MassFunctionRepository::cache_owner_frame_for_claim`) still picks
    // `binary_truth`, whose inputs are all inadmissible, over
    // `claim_validity`, which has an admissible one, so the claim is neither
    // vacated (R-80 is claim-wide) nor refolded from its admissible input.
    // The owner rule should skip a frame whose inputs are all inadmissible.
    // What R-80 pins here is only that it does not vacate such a claim and
    // leaves its cache exactly as it was.
    assert_eq!(
        after, before,
        "a claim with an admissible BBA on another frame must keep its cache unchanged"
    );
}

/// A claim with no cache whose every BBA is inadmissible keeps no cache: a
/// vacuous value there would tell its readers that an unseen BBA exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_without_a_cache_is_not_given_one(pool: PgPool) {
    let w = world(&pool, "r80-null").await;
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 never cached").await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    hide(&pool, ev, w.group, w.member).await;
    store(&pool, claim, w.binary, w.member, ev, 0.8).await;
    let before = cache(&pool, claim).await;
    assert!(
        before.0.is_none() && before.1.is_none() && before.2.is_none(),
        "PREMISE: the claim has no cache ({before:?})"
    );

    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert!(
        after.0.is_none() && after.1.is_none() && after.2.is_none(),
        "a claim whose only BBA is inadmissible was given a cache it never had: {after:?}"
    );
}

/// A vacate on a cache owned by a NON-binary frame: `claim_validity` (three
/// hypotheses) owns the claim's cache, and its only BBA becomes inadmissible.
/// Full ignorance there is BetP 1/3 on the claim's hypothesis, and the older
/// classification label (which still carries the left-out evidence's
/// direction) is reset to `not_enough_info` with it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_vacate_on_a_non_binary_owner_frame_resets_the_whole_cache(pool: PgPool) {
    let w = world(&pool, "r80-validity").await;
    let validity =
        resolve_claim_validity_frame(&mut pool.acquire().await.expect("acquire"), &w.public)
            .await
            .expect("claim_validity");
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 validity owner").await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    store(&pool, claim, validity, w.author, ev, 0.8).await;
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        claim,
    )
    .await
    .expect("recompute while the evidence is public");
    let mut stale = cache(&pool, claim).await;
    assert!(
        stale.0.is_some_and(|b| b > 0.5) && stale.5 == Some(validity),
        "PREMISE: claim_validity owns a filled cache ({stale:?})"
    );
    // The verdict an earlier binary fold left beside it.
    stale.6 = Some("supported".to_string());
    restore(&pool, claim, &stale).await;
    hide(&pool, ev, w.group, w.member).await;

    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert!(
        is_vacuous_over(&after, validity, 3),
        "the vacate of a claim_validity-owned cache must be Bel 0, Pl 1, BetP 1/3 on \
         claim_validity with not_enough_info; it left {after:?} (stale value {stale:?})"
    );
}

/// A GROUP claim (R-71): its evidence is in its own group (admissible, the
/// cache folds it), then moves to ANOTHER group. Recomputed by a member of the
/// claim's group, on the application role, the cache is vacated. The R-80
/// reads are spliced with the member's viewer, so this is where a splice that
/// lost the member's group would leave the stale value.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_claim_whose_evidence_moves_to_another_group_is_vacated(pool: PgPool) {
    let w = world(&pool, "r80-group").await;
    let (outsider, other_group) = fixture::seed_agent_with_group(&pool, "r80-group-other").await;
    let claim =
        fixture::seed_group_claim(&pool, w.member, w.group, "r80 group claim narrowed").await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    store(&pool, claim, w.binary, w.member, ev, 0.8).await;
    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let stale = cache(&pool, claim).await;
    assert!(
        stale.0.is_some_and(|b| b > 0.55) && stale.6.is_some(),
        "PREMISE: the own-group evidence's fold is cached ({stale:?})"
    );

    hide(&pool, ev, other_group, outsider).await;
    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert!(
        is_vacuous(&after, w.binary),
        "a group claim whose every BBA cites another group's evidence must be vacated when \
         a member recomputes it; it left {after:?} (stale value {stale:?})"
    );
}

/// The claim-wide gate on a GROUP claim: its `binary_truth` BBA cites another
/// group's evidence, but its `claim_validity` BBA cites evidence in the
/// claim's own group, which is admissible. Not every BBA is inadmissible, so
/// the cache is left exactly as it was (the same R-71 owner-rule residual as
/// `an_admissible_input_on_another_frame_is_not_vacated`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_claim_with_own_group_input_elsewhere_is_not_vacated(pool: PgPool) {
    let w = world(&pool, "r80-group-own").await;
    let (outsider, other_group) =
        fixture::seed_agent_with_group(&pool, "r80-group-own-other").await;
    let validity =
        resolve_claim_validity_frame(&mut pool.acquire().await.expect("acquire"), &w.public)
            .await
            .expect("claim_validity");
    let claim =
        fixture::seed_group_claim(&pool, w.member, w.group, "r80 group claim own input").await;
    let own_ev = fixture::seed_evidence(&pool, claim, "observation").await;
    store(&pool, claim, validity, w.member, own_ev, 0.7).await;
    let moved_ev = fixture::seed_evidence(&pool, claim, "document").await;
    store(&pool, claim, w.binary, w.member, moved_ev, 0.9).await;
    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let before = cache(&pool, claim).await;
    assert!(
        before.0.is_some() && before.5 == Some(w.binary),
        "PREMISE: binary_truth owns a filled cache ({before:?})"
    );

    hide(&pool, moved_ev, other_group, outsider).await;
    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert_eq!(
        after, before,
        "a group claim with an own-group BBA on another frame must keep its cache unchanged"
    );
}

/// A COMPOUND (an in-force `decomposes_to` out-edge to a current leaf) is
/// never vacated: its cache is not a fold of its own BBAs. Driven through
/// `recompute_claim_belief_on_frame`, the named-frame writer behind
/// `auto_wire_ds_for_edge`, MCP `submit_ds_evidence` and REST
/// `POST /api/v1/frames/:id/evidence`, which (unlike the cache owner rule)
/// does not itself skip compounds.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_whose_every_bba_is_inadmissible_keeps_its_cache(pool: PgPool) {
    let w = world(&pool, "r80-compound").await;
    let compound = fixture::seed_public_claim(&pool, w.author, "r80 compound").await;
    let leaf = fixture::seed_public_claim(&pool, w.author, "r80 compound leaf").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(compound)
    .bind(leaf)
    .execute(&pool)
    .await
    .expect("decompose the compound");
    let ev = fixture::seed_evidence(&pool, compound, "observation").await;
    store(&pool, compound, w.binary, w.author, ev, 0.8).await;
    let stale = stale_on(w.binary);
    restore(&pool, compound, &stale).await;
    hide(&pool, ev, w.group, w.member).await;

    let scoped = app_role(&pool).await;
    let mut tx = scoped
        .begin_as(&w.member_viewer)
        .await
        .expect("stamped app session");
    recompute_claim_belief_on_frame(&mut tx, &w.member_viewer, compound, w.binary)
        .await
        .expect("recompute the compound's binary frame on the application role");
    tx.commit().await.expect("commit");

    assert_eq!(
        cache(&pool, compound).await,
        stale,
        "a compound's cache must not be vacated (it is not a fold of its own BBAs)"
    );
}
