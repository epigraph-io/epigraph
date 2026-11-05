//! `POST /api/v1/search/semantic` with `theme_id`, `rank_by` and `cursor`.
//!
//! Direct handler calls on [`search_fixture::split_state`], the instrument
//! `search_voids_methods_scoped_read.rs` documents: the scoped pool is a
//! superuser session, so these arms observe the in-query `$V` predicate. The
//! row-policy half of the four new reads (the pinned flat statement under both
//! rankings, `get_summary` and `claims_in_theme_exact_at_dim`) is pinned in
//! `epigraph-db/tests/search_voids_methods_scoped_read_policy.rs`.
//!
//! # Tenancy
//!
//! Every tenancy arm uses two viewers in DIFFERENT groups: the member of group
//! G, which owns the private claim X, and a stranger with a group of its own.
//! X is placed exactly at the probe, so its absence from a stranger's results
//! cannot be explained by ranking or by the limit, and the theme's label is
//! written from X's content (as the labelling script would) so a label leak is
//! visible. The assertions are made on the SERIALISED body, so a rename of a
//! field cannot turn a leak into a pass: no X id, no X content, no label, and
//! a `member_count` that counts only what the stranger can read.

mod search_fixture;
mod viewer_fixture;

use axum::response::IntoResponse;
use epigraph_api::errors::ApiError;
use epigraph_api::routes::search::{SemanticSearchRequest, SemanticSearchResponse};
use epigraph_api::state::AppState;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use search_fixture::*;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_edge, seed_group_claim, seed_public_claim};

// ── Vectors ──

async fn probe_vec(embedder: &Arc<MockProvider>, text: &str) -> Vec<f32> {
    embedder.generate(text).await.expect("mock embed")
}

/// A unit vector at `deg` degrees from the unit vector `p`, in the plane of
/// `p` and a fixed direction orthogonal to it, as pgvector text. Its cosine
/// similarity to `p` is `cos(deg)`.
fn tilt(p: &[f32], deg: f64) -> String {
    let p: Vec<f64> = p.iter().map(|x| f64::from(*x)).collect();
    let norm = p.iter().map(|x| x * x).sum::<f64>().sqrt();
    let p: Vec<f64> = p.iter().map(|x| x / norm).collect();
    // The basis direction p leans on least, made orthogonal to p.
    let k = p
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
        .map(|(i, _)| i)
        .expect("non-empty");
    let mut o: Vec<f64> = p.iter().map(|x| -x * p[k]).collect();
    o[k] += 1.0;
    let on = o.iter().map(|x| x * x).sum::<f64>().sqrt();
    let (s, c) = deg.to_radians().sin_cos();
    let v: Vec<String> = p
        .iter()
        .zip(&o)
        .map(|(a, b)| ((c * a + s * b / on) as f32).to_string())
        .collect();
    format!("[{}]", v.join(","))
}

/// A 3072-d literal, for a `claim_themes.centroid_3072` that lets the 3072
/// guard pass.
fn vec_3072() -> String {
    format!("[{}]", vec!["0.01"; 3072].join(","))
}

// ── Seeding ──

/// A theme with no centroid. The pinned paths never read one.
async fn bare_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'search_theme_filter') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

async fn public_at(pool: &PgPool, agent: Uuid, content: &str, vec: &str, theme: Uuid) -> Uuid {
    let id = seed_public_claim(pool, agent, content).await;
    set_embedding(pool, id, vec).await;
    attach_theme(pool, id, theme).await;
    id
}

async fn private_at(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    content: &str,
    vec: &str,
    theme: Uuid,
) -> Uuid {
    let id = seed_group_claim(pool, agent, group, content).await;
    set_embedding(pool, id, vec).await;
    attach_theme(pool, id, theme).await;
    id
}

async fn set_created_at(pool: &PgPool, id: Uuid, at: &str) {
    sqlx::query("UPDATE claims SET created_at = $2::timestamptz WHERE id = $1")
        .bind(id)
        .bind(at)
        .execute(pool)
        .await
        .expect("set created_at");
}

// ── Requests ──

fn pinned(query: &str, theme: Uuid, limit: u32, cursor: Option<String>) -> SemanticSearchRequest {
    SemanticSearchRequest {
        query: query.to_string(),
        limit: Some(limit),
        theme_id: Some(theme.to_string()),
        cursor,
        ..Default::default()
    }
}

fn core(theme: Uuid, limit: u32, cursor: Option<String>) -> SemanticSearchRequest {
    SemanticSearchRequest {
        limit: Some(limit),
        theme_id: Some(theme.to_string()),
        rank_by: Some("theme_core".to_string()),
        cursor,
        ..Default::default()
    }
}

fn pinned_diverse(query: &str, theme: Uuid) -> SemanticSearchRequest {
    SemanticSearchRequest {
        query: query.to_string(),
        limit: Some(20),
        theme_id: Some(theme.to_string()),
        diverse: Some(true),
        max_themes: Some(5),
        ..Default::default()
    }
}

fn body(r: &SemanticSearchResponse) -> String {
    serde_json::to_string(r).expect("serialise response")
}

fn json(r: &SemanticSearchResponse) -> serde_json::Value {
    serde_json::to_value(r).expect("serialise response")
}

/// Status and body of an error as the router would send it.
async fn error_parts(e: ApiError) -> (u16, serde_json::Value) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("error body");
    (
        status,
        serde_json::from_slice(&bytes).expect("error body is JSON"),
    )
}

fn validation_field(e: ApiError) -> String {
    match e {
        ApiError::ValidationError { field, .. } => field,
        other => panic!("expected a ValidationError, got {other:?}"),
    }
}

/// Follow `next_cursor` from the first page to the end. Returns every page.
async fn walk<F>(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    make: F,
) -> Vec<SemanticSearchResponse>
where
    F: Fn(Option<String>) -> SemanticSearchRequest,
{
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = search(pool, state.clone(), agent, make(cursor.clone()))
            .await
            .expect("page");
        let next = page.next_cursor.clone();
        pages.push(page);
        match next {
            Some(c) => cursor = Some(c),
            None => break,
        }
        assert!(pages.len() < 200, "the cursor walk failed to terminate");
    }
    pages
}

/// The usual tenancy corpus: theme T with public P1 (20 degrees from the
/// probe) and P2 (30 degrees), and X private to G exactly at the probe. T's
/// label quotes X's content.
struct Corpus {
    member: Uuid,
    group: Uuid,
    stranger: Uuid,
    theme: Uuid,
    p1: Uuid,
    p2: Uuid,
    x: Uuid,
    x_content: String,
    label: String,
}

async fn corpus(pool: &PgPool, tag: &str, p: &[f32]) -> Corpus {
    let (member, group) = seed_agent_with_group(pool, &format!("{tag}-member")).await;
    let (stranger, _other_group) = seed_agent_with_group(pool, &format!("{tag}-stranger")).await;
    let x_content = format!("{tag}: the private finding nobody else may read");
    let label = format!("Theme about {x_content}");
    let theme = bare_theme(pool, &label).await;
    let p1 = public_at(
        pool,
        member,
        &format!("{tag}: public one"),
        &tilt(p, 20.0),
        theme,
    )
    .await;
    let p2 = public_at(
        pool,
        member,
        &format!("{tag}: public two"),
        &tilt(p, 30.0),
        theme,
    )
    .await;
    let x = private_at(pool, member, group, &x_content, &tilt(p, 0.0), theme).await;
    Corpus {
        member,
        group,
        stranger,
        theme,
        p1,
        p2,
        x,
        x_content,
        label,
    }
}

fn assert_no_leak(c: &Corpus, text: &str, who: &str) {
    assert!(
        !text.contains(&c.x.to_string()),
        "{who}: the private claim's id leaked: {text}"
    );
    assert!(
        !text.contains(&c.x_content),
        "{who}: the private claim's content leaked: {text}"
    );
    assert!(
        !text.contains(&c.label),
        "{who}: the theme label (built from private content) leaked: {text}"
    );
}

// ── Basics ──

/// Test 12.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_filter_confines_flat_hits_to_the_theme(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-basic").await;
    let embedder = mock_embedder();
    let q = "theme filter basic probe";
    let p = probe_vec(&embedder, q).await;
    let a = bare_theme(&pool, "tf-basic theme A").await;
    let b = bare_theme(&pool, "tf-basic theme B").await;
    let a1 = public_at(&pool, agent, "tf-basic a1", &tilt(&p, 40.0), a).await;
    let a2 = public_at(&pool, agent, "tf-basic a2", &tilt(&p, 50.0), a).await;
    let b1 = public_at(&pool, agent, "tf-basic b1", &tilt(&p, 0.0), b).await;

    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, pinned(q, a, 20, None))
        .await
        .expect("pinned search");

    let got = hit_ids(&out);
    assert_eq!(
        got,
        vec![a1, a2],
        "both A members, nearest first, and no B claim"
    );
    assert!(!got.contains(&b1));
    assert!(out.results.iter().all(|r| r.theme_id == Some(a)));
    let scope = out.theme_scope.as_ref().expect("theme_scope");
    assert_eq!(
        (scope.theme_id, scope.member_count, scope.rank_by),
        (a, 2, "query")
    );
    let v = json(&out);
    let scope_keys: HashSet<&str> = v["theme_scope"]
        .as_object()
        .expect("theme_scope object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        scope_keys,
        HashSet::from(["theme_id", "member_count", "rank_by"]),
        "theme_scope carries no label"
    );
    assert!(!body(&out).contains("tf-basic theme A"));
}

/// Test 13.
#[sqlx::test(migrations = "../../migrations")]
async fn malformed_theme_id_is_400_and_unknown_theme_id_is_404(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-bad-id").await;
    let state = split_state(&pool).await;

    let mut req = pinned("anything", Uuid::nil(), 10, None);
    req.theme_id = Some("not-a-uuid".to_string());
    let e = search(&pool, state.clone(), agent, req).await.unwrap_err();
    assert_eq!(validation_field(e), "theme_id");

    let unknown = Uuid::new_v4();
    let e = search(&pool, state, agent, pinned("anything", unknown, 10, None))
        .await
        .unwrap_err();
    match e {
        ApiError::NotFound { entity, id } => {
            assert_eq!(entity, "Theme");
            assert_eq!(id, unknown.to_string());
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ── Tenancy ──

/// Test 14.
#[sqlx::test(migrations = "../../migrations")]
async fn stranger_cannot_see_a_private_claim_its_id_its_label_or_a_count_revealing_it(
    pool: PgPool,
) {
    let embedder = mock_embedder();
    let q = "tenancy walk probe";
    let p = probe_vec(&embedder, q).await;
    let c = corpus(&pool, "tf-walk", &p).await;
    let state = split_state_with_embedder(&pool, embedder).await;

    // The stranger walks every page, one hit at a time.
    let pages = walk(&pool, &state, c.stranger, |cur| pinned(q, c.theme, 1, cur)).await;
    let mut seen = Vec::new();
    let mut cursors = Vec::new();
    for page in &pages {
        let text = body(page);
        assert_no_leak(&c, &text, "stranger");
        assert_eq!(
            page.theme_scope.as_ref().expect("theme_scope").member_count,
            2,
            "a stranger's member_count counts only the two public members"
        );
        assert!(page.total as usize <= page.results.len());
        seen.extend(hit_ids(page));
        cursors.extend(page.next_cursor.clone());
    }
    assert_eq!(
        seen,
        vec![c.p1, c.p2],
        "exactly the public members, once each"
    );
    assert_eq!(
        cursors,
        vec!["o:1".to_string(), "o:2".to_string()],
        "the walk ends after o:2: an o:3 would reveal a third member"
    );

    // Control: the member of G sees X too, and still no label.
    let pages = walk(&pool, &state, c.member, |cur| pinned(q, c.theme, 1, cur)).await;
    let mut mine = Vec::new();
    for page in &pages {
        assert_eq!(page.theme_scope.as_ref().unwrap().member_count, 3);
        assert!(
            !body(page).contains(&c.label),
            "no label for the member either"
        );
        mine.extend(hit_ids(page));
    }
    assert_eq!(
        mine,
        vec![c.x, c.p1, c.p2],
        "the member sees X at the probe first"
    );
    let _ = c.group;
}

/// Test 15.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_whose_members_are_all_private_is_404_for_a_stranger_like_an_unknown_id(
    pool: PgPool,
) {
    let embedder = mock_embedder();
    let q = "all private probe";
    let p = probe_vec(&embedder, q).await;
    let (member, group) = seed_agent_with_group(&pool, "tf-allpriv-member").await;
    let (stranger, _sg) = seed_agent_with_group(&pool, "tf-allpriv-stranger").await;
    let x_content = "tf-allpriv: private only";
    let label = format!("About {x_content}");
    let theme = bare_theme(&pool, &label).await;
    let x = private_at(&pool, member, group, x_content, &tilt(&p, 0.0), theme).await;
    let state = split_state_with_embedder(&pool, embedder).await;

    let hidden = search(&pool, state.clone(), stranger, pinned(q, theme, 10, None))
        .await
        .unwrap_err();
    let absent = search(
        &pool,
        state.clone(),
        stranger,
        pinned(q, Uuid::new_v4(), 10, None),
    )
    .await
    .unwrap_err();
    let (hs, hb) = error_parts(hidden).await;
    let (as_, ab) = error_parts(absent).await;
    assert_eq!(hs, 404);
    assert_eq!(hs, as_, "the same status as an unknown theme");
    assert_eq!(
        hb["error"], ab["error"],
        "the same error kind as an unknown theme"
    );
    let hb_text = hb.to_string();
    assert!(!hb_text.contains(&label) && !hb_text.contains(&x.to_string()));

    let mine = search(&pool, state, member, pinned(q, theme, 10, None))
        .await
        .expect("the member gets 200");
    assert_eq!(hit_ids(&mine), vec![x]);
}

/// Test 16.
#[sqlx::test(migrations = "../../migrations")]
async fn stranger_pinned_diverse_sees_no_private_claim_or_neighbour(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "pinned diverse tenancy probe";
    let p = probe_vec(&embedder, q).await;
    let c = corpus(&pool, "tf-div", &p).await;
    // X -> P1, stamped by migration 070's trigger from its endpoints.
    seed_edge(&pool, c.x, c.p1).await;
    let state = split_state_with_embedder(&pool, embedder).await;

    // (a) 1536: the pinned diverse branch runs.
    let theirs = search(&pool, state.clone(), c.stranger, pinned_diverse(q, c.theme))
        .await
        .expect("stranger pinned diverse");
    assert_eq!(
        theirs.centroid_dim_used,
        Some(1536),
        "the diverse branch ran"
    );
    assert_no_leak(&c, &body(&theirs), "stranger, diverse 1536");
    assert_eq!(theirs.theme_scope.as_ref().unwrap().member_count, 2);
    let got: HashSet<Uuid> = hit_ids(&theirs).into_iter().collect();
    assert_eq!(got, HashSet::from([c.p1, c.p2]));

    let mine = search(&pool, state.clone(), c.member, pinned_diverse(q, c.theme))
        .await
        .expect("member pinned diverse");
    assert_eq!(mine.centroid_dim_used, Some(1536));
    assert!(hit_ids(&mine).contains(&c.x), "control: the member sees X");

    // (b) 3072 with no `embedding_3072` member: falls through to pinned flat.
    let other = bare_theme(&pool, "tf-div other 3072 theme").await;
    sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
        .bind(other)
        .bind(vec_3072())
        .execute(&pool)
        .await
        .expect("3072 centroid");
    let mut req = pinned_diverse(q, c.theme);
    req.centroid_dim = Some(3072);
    let theirs = search(&pool, state.clone(), c.stranger, req)
        .await
        .expect("stranger pinned diverse at 3072");
    assert_eq!(
        theirs.centroid_dim_used, None,
        "fell through to the flat tail"
    );
    assert_no_leak(&c, &body(&theirs), "stranger, diverse 3072 fall-through");
    assert_eq!(theirs.theme_scope.as_ref().unwrap().member_count, 2);
    assert_eq!(hit_ids(&theirs), vec![c.p1, c.p2]);

    let mut req = pinned_diverse(q, c.theme);
    req.centroid_dim = Some(3072);
    let mine = search(&pool, state, c.member, req)
        .await
        .expect("member pinned diverse at 3072");
    assert_eq!(mine.centroid_dim_used, None);
    assert!(hit_ids(&mine).contains(&c.x), "control: the member sees X");
}

/// Test 17.
#[sqlx::test(migrations = "../../migrations")]
async fn stranger_theme_core_ranking_ignores_private_members(pool: PgPool) {
    let embedder = mock_embedder();
    let p = probe_vec(&embedder, "theme core tenancy").await;
    let c = corpus(&pool, "tf-core", &p).await;
    // The stored centroid points straight at X.
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(c.theme)
        .bind(tilt(&p, 0.0))
        .execute(&pool)
        .await
        .expect("stored centroid at X");
    let state = split_state_with_embedder(&pool, embedder).await;

    let theirs = search(&pool, state.clone(), c.stranger, core(c.theme, 100, None))
        .await
        .expect("stranger theme core");
    let mine = search(&pool, state, c.member, core(c.theme, 100, None))
        .await
        .expect("member theme core");
    assert_no_leak(&c, &body(&theirs), "stranger, theme core");
    assert!(hit_ids(&mine).contains(&c.x), "control: the member sees X");
    assert_eq!(theirs.theme_scope.as_ref().unwrap().rank_by, "theme_core");

    let sim = |r: &SemanticSearchResponse, id: Uuid| {
        r.results
            .iter()
            .find(|h| h.claim_id == id)
            .map(|h| h.similarity)
            .expect("hit present")
    };
    for pid in [c.p1, c.p2] {
        assert!(
            (sim(&theirs, pid) - sim(&mine, pid)).abs() < 1e-9,
            "a public member's similarity must not depend on who asks: the core is \
             the public mean, not a mean over X and not the stored centroid"
        );
    }
}

/// Test 18.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_on_an_all_private_theme_is_404_for_a_stranger(pool: PgPool) {
    let embedder = mock_embedder();
    let p = probe_vec(&embedder, "all private core").await;
    let (member, group) = seed_agent_with_group(&pool, "tf-core404-member").await;
    let (stranger, _sg) = seed_agent_with_group(&pool, "tf-core404-stranger").await;
    let theme = bare_theme(&pool, "tf-core404 label").await;
    let x = private_at(
        &pool,
        member,
        group,
        "tf-core404 private",
        &tilt(&p, 0.0),
        theme,
    )
    .await;
    let state = split_state_with_embedder(&pool, embedder).await;

    let hidden = search(&pool, state.clone(), stranger, core(theme, 10, None))
        .await
        .unwrap_err();
    let absent = search(
        &pool,
        state.clone(),
        stranger,
        core(Uuid::new_v4(), 10, None),
    )
    .await
    .unwrap_err();
    let (hs, hb) = error_parts(hidden).await;
    let (as_, ab) = error_parts(absent).await;
    assert_eq!((hs, &hb["error"]), (as_, &ab["error"]));
    assert_eq!(hs, 404);
    assert!(!hb.to_string().contains(&x.to_string()));

    let mine = search(&pool, state, member, core(theme, 10, None))
        .await
        .expect("member theme core");
    assert_eq!(
        hit_ids(&mine),
        vec![x],
        "the fallback core serves the member"
    );
}

// ── theme_core ──

/// Test 19.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_makes_no_embedding_call(pool: PgPool) {
    let embedder = mock_embedder();
    let p = probe_vec(&embedder, "no embedding call").await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-noembed").await;
    let theme = bare_theme(&pool, "tf-noembed theme").await;
    public_at(&pool, agent, "tf-noembed one", &tilt(&p, 10.0), theme).await;
    public_at(&pool, agent, "tf-noembed two", &tilt(&p, 20.0), theme).await;
    let state = split_state_with_embedder(&pool, embedder.clone()).await;

    let before = embedder.token_usage().total_tokens;
    let out = search(&pool, state.clone(), agent, core(theme, 10, None))
        .await
        .expect("theme core");
    assert_eq!(out.results.len(), 2);
    assert_eq!(
        embedder.token_usage().total_tokens,
        before,
        "rank_by=theme_core must make no embedding call"
    );

    let before = embedder.token_usage().total_tokens;
    search(
        &pool,
        state,
        agent,
        // A text the provider has not embedded yet: `MockProvider` caches,
        // and a cache hit records no tokens.
        pinned("a query text embedded for the first time", theme, 10, None),
    )
    .await
    .expect("query search");
    assert!(
        embedder.token_usage().total_tokens > before,
        "CALIBRATION: a rank_by=query request on the same state does embed, so the \
         counter is live"
    );
}

/// Test 20.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_walk_enumerates_every_embedded_visible_member(pool: PgPool) {
    let embedder = mock_embedder();
    let p = probe_vec(&embedder, "core walk").await;
    let (member, group) = seed_agent_with_group(&pool, "tf-corewalk-member").await;
    let (stranger, _sg) = seed_agent_with_group(&pool, "tf-corewalk-stranger").await;
    let theme = bare_theme(&pool, "tf-corewalk theme").await;
    let mut embedded = HashSet::new();
    for (i, deg) in [5.0, 15.0, 25.0, 40.0, 60.0, 90.0, 150.0]
        .iter()
        .enumerate()
    {
        embedded.insert(
            public_at(
                &pool,
                member,
                &format!("tf-corewalk public {i}"),
                &tilt(&p, *deg),
                theme,
            )
            .await,
        );
    }
    // Visible but unembedded: counted, never a hit.
    let bare = seed_public_claim(&pool, member, "tf-corewalk unembedded").await;
    attach_theme(&pool, bare, theme).await;
    // Private: neither counted nor returned for the stranger.
    let x = private_at(
        &pool,
        member,
        group,
        "tf-corewalk private",
        &tilt(&p, 0.0),
        theme,
    )
    .await;
    let state = split_state_with_embedder(&pool, embedder).await;

    let pages = walk(&pool, &state, stranger, |cur| core(theme, 3, cur)).await;
    let mut seen = Vec::new();
    let mut sims = Vec::new();
    for page in &pages {
        assert_eq!(page.theme_scope.as_ref().unwrap().member_count, 8);
        for h in &page.results {
            seen.push(h.claim_id);
            sims.push(h.similarity);
        }
    }
    assert_eq!(seen.len(), 7, "each embedded visible member exactly once");
    assert_eq!(seen.iter().copied().collect::<HashSet<_>>(), embedded);
    assert!(!seen.contains(&x) && !seen.contains(&bare));
    assert!(
        sims.windows(2).all(|w| w[0] >= w[1]),
        "similarity must be non-increasing across the walk: {sims:?}"
    );
}

/// Test 21.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_validation(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-core-validate").await;
    let state = split_state(&pool).await;
    let theme = Uuid::new_v4();

    let cases: Vec<(SemanticSearchRequest, &str)> = vec![
        (
            SemanticSearchRequest {
                query: "q".into(),
                rank_by: Some("centroid".into()),
                ..Default::default()
            },
            "rank_by",
        ),
        (
            SemanticSearchRequest {
                rank_by: Some("theme_core".into()),
                ..Default::default()
            },
            "rank_by",
        ),
        (
            SemanticSearchRequest {
                diverse: Some(true),
                ..core(theme, 10, None)
            },
            "rank_by",
        ),
        (
            SemanticSearchRequest {
                query: "not used".into(),
                ..core(theme, 10, None)
            },
            "query",
        ),
        (
            SemanticSearchRequest {
                rank_by: Some("query".into()),
                ..Default::default()
            },
            "query",
        ),
    ];
    for (req, field) in cases {
        let shape = format!("{req:?}");
        let e = match search(&pool, state.clone(), agent, req).await {
            Ok(_) => panic!("{shape} must be refused"),
            Err(e) => e,
        };
        assert_eq!(validation_field(e), field, "{shape}");
    }
}

// ── Other ──

/// Test 22.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_filter_holds_when_the_embedder_is_down(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-mock").await;
    // The handler's own mock embedding has only non-negative components, so a
    // uniform positive vector has positive similarity to it.
    let positive = format!("[{}]", vec!["0.0255"; DIM].join(","));
    let a = bare_theme(&pool, "tf-mock A").await;
    let b = bare_theme(&pool, "tf-mock B").await;
    let mut in_a = HashSet::new();
    for i in 0..3 {
        in_a.insert(public_at(&pool, agent, &format!("tf-mock a{i}"), &positive, a).await);
        public_at(&pool, agent, &format!("tf-mock b{i}"), &positive, b).await;
    }
    let state = split_state(&pool).await; // no embedding service
    let out = search(&pool, state, agent, pinned("embedder down", a, 20, None))
        .await
        .expect("mock-embedding search");
    let got: HashSet<Uuid> = hit_ids(&out).into_iter().collect();
    assert_eq!(got, in_a, "every hit is in A, and all of A is found");
}

/// Test 23.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_uses_the_pin_not_the_centroid_shortlist(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "pin beats shortlist";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-pin-shortlist").await;
    let a = seed_theme(&pool, "tf-pin-shortlist A", &tilt(&p, 80.0)).await;
    let b = seed_theme(&pool, "tf-pin-shortlist B", &tilt(&p, 0.0)).await;
    for i in 0..3 {
        public_at(&pool, agent, &format!("tf-ps b{i}"), &tilt(&p, i as f64), b).await;
        public_at(
            &pool,
            agent,
            &format!("tf-ps a{i}"),
            &tilt(&p, 60.0 + i as f64),
            a,
        )
        .await;
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let mut req = pinned_diverse(q, a);
    req.max_themes = Some(1);
    let out = search(&pool, state, agent, req)
        .await
        .expect("pinned diverse");
    assert_eq!(out.centroid_dim_used, Some(1536));
    assert_eq!(out.results.len(), 3);
    assert!(out.results.iter().all(|r| r.theme_id == Some(a)));
    assert!(out.next_cursor.is_none());
}

/// Test 24.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_applies_created_after_in_sql(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "created after in sql";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-div-after").await;
    let a = bare_theme(&pool, "tf-div-after A").await;
    for i in 0..30 {
        let id = public_at(
            &pool,
            agent,
            &format!("tf-da old {i}"),
            &tilt(&p, 1.0 + i as f64),
            a,
        )
        .await;
        set_created_at(&pool, id, "2020-01-01T00:00:00Z").await;
    }
    let mut new = HashSet::new();
    for i in 0..5 {
        let id = public_at(
            &pool,
            agent,
            &format!("tf-da new {i}"),
            &tilt(&p, 50.0 + i as f64),
            a,
        )
        .await;
        set_created_at(&pool, id, "2025-06-01T00:00:00Z").await;
        new.insert(id);
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let mut req = pinned_diverse(q, a);
    req.candidate_pool = Some(10);
    req.created_after = Some(
        chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    let out = search(&pool, state, agent, req)
        .await
        .expect("pinned diverse");
    assert_eq!(out.centroid_dim_used, Some(1536));
    let got: HashSet<Uuid> = hit_ids(&out).into_iter().collect();
    assert_eq!(
        got, new,
        "the window applies inside the candidate pull, so the 30 nearer old claims \
         cannot crowd the 5 new ones out of a pool of 10"
    );
}

/// Test 25.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_applies_min_similarity_exactly(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "min similarity in sql";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-div-floor").await;
    let a = bare_theme(&pool, "tf-div-floor A").await;
    let mut above = HashSet::new();
    for i in 1..=8 {
        let deg = 10.0 * f64::from(i);
        let id = public_at(&pool, agent, &format!("tf-df {i}"), &tilt(&p, deg), a).await;
        if deg < 45.0 {
            above.insert(id);
        }
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let mut req = pinned_diverse(q, a);
    let floor = 45.0_f64.to_radians().cos();
    req.min_similarity = Some(floor);
    let out = search(&pool, state, agent, req)
        .await
        .expect("pinned diverse");
    assert!(out.results.iter().all(|r| r.similarity >= floor - 1e-6));
    let got: HashSet<Uuid> = hit_ids(&out).into_iter().collect();
    assert_eq!(
        got, above,
        "every in-theme claim above the floor, none below"
    );
}

/// Test 26.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_rejects_created_before_claim_type_agent_id(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-div-reject").await;
    let state = split_state(&pool).await;
    let t = Uuid::new_v4();
    let mut a = pinned_diverse("q", t);
    a.created_before = Some(chrono::Utc::now());
    let mut b = pinned_diverse("q", t);
    b.claim_type = Some("factual".into());
    let mut c = pinned_diverse("q", t);
    c.agent_id = Some(Uuid::new_v4());
    for (req, field) in [(a, "created_before"), (b, "claim_type"), (c, "agent_id")] {
        let e = search(&pool, state.clone(), agent, req).await.unwrap_err();
        assert_eq!(validation_field(e), field);
    }
}

/// Test 27.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_candidates_are_exact_for_a_large_theme(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "large theme exact";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-div-large").await;
    let t = bare_theme(&pool, "tf-div-large T").await;
    let mut nearest = HashSet::new();
    for i in 0..120 {
        // The 20 oldest-inserted are the 20 nearest.
        let deg = if i < 20 {
            0.5 * f64::from(i)
        } else {
            20.0 + 0.4 * f64::from(i)
        };
        let id = public_at(&pool, agent, &format!("tf-dl {i}"), &tilt(&p, deg), t).await;
        if i < 20 {
            nearest.insert(id);
        }
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let mut req = pinned_diverse(q, t);
    req.candidate_pool = Some(20);
    let out = search(&pool, state, agent, req)
        .await
        .expect("pinned diverse");
    assert_eq!(out.centroid_dim_used, Some(1536));
    assert!(!out.results.is_empty());
    assert!(
        hit_ids(&out).iter().all(|id| nearest.contains(id)),
        "with candidate_pool=20 every selected claim is one of the 20 nearest"
    );
}

/// Test 28.
#[sqlx::test(migrations = "../../migrations")]
async fn cursor_with_diverse_malformed_and_beyond_window_are_400(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "tf-cursor-400").await;
    let state = split_state(&pool).await;

    let req = SemanticSearchRequest {
        query: "q".into(),
        diverse: Some(true),
        cursor: Some("o:0".into()),
        ..Default::default()
    };
    let e = search(&pool, state.clone(), agent, req).await.unwrap_err();
    assert_eq!(validation_field(e), "cursor", "cursor with diverse");

    for bad in ["o:-1", "x:1", "o:abc", "o:1000"] {
        let req = SemanticSearchRequest {
            query: "q".into(),
            cursor: Some(bad.into()),
            ..Default::default()
        };
        let e = search(&pool, state.clone(), agent, req).await.unwrap_err();
        assert_eq!(validation_field(e), "cursor", "{bad}");
    }
}

/// 60 KiB of content, distinct per `i`.
fn big_content(tag: &str, i: usize) -> String {
    format!("{tag} {i:04} {}", "x".repeat(60 * 1024))
}

/// Test 29.
#[sqlx::test(migrations = "../../migrations")]
async fn byte_budget_truncates_and_the_cursor_resumes(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "byte budget pinned";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-budget").await;
    let t = bare_theme(&pool, "tf-budget T").await;
    let at = tilt(&p, 0.0);
    let mut all = HashSet::new();
    for i in 0..40 {
        all.insert(public_at(&pool, agent, &big_content("tf-budget", i), &at, t).await);
    }
    let state = split_state_with_embedder(&pool, embedder).await;

    let first = search(&pool, state.clone(), agent, pinned(q, t, 100, None))
        .await
        .expect("first page");
    let text = body(&first);
    assert!(text.len() < 2_000_000, "page is {} bytes", text.len());
    let n = first.results.len();
    assert!(n > 0 && n < 40, "the budget cut the page to {n}");
    assert_eq!(
        first.next_cursor.as_deref(),
        Some(format!("o:{n}").as_str())
    );
    assert!(
        !json(&first).as_object().unwrap().contains_key("truncated"),
        "a cut carried by next_cursor is not `truncated`"
    );

    let pages = walk(&pool, &state, agent, |cur| pinned(q, t, 100, cur)).await;
    let ids: Vec<Uuid> = pages.iter().flat_map(hit_ids).collect();
    let unique: HashSet<Uuid> = ids.iter().copied().collect();
    assert_eq!(ids.len(), 40, "no repeats");
    assert_eq!(unique, all, "following the cursor reaches all 40");
}

/// Test 30.
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_unpaged_response_shape_is_unchanged_below_the_budget(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "unchanged shape";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-shape").await;
    for i in 0..3 {
        let id = seed_public_claim(&pool, agent, &format!("tf-shape {i}")).await;
        set_embedding(&pool, id, &tilt(&p, 5.0 * i as f64)).await;
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let out = search(&pool, state, agent, search_request(q, false))
        .await
        .expect("plain search");
    assert_eq!(out.results.len(), 3);
    let v = json(&out);
    let obj = v.as_object().unwrap();
    for key in ["theme_scope", "next_cursor", "truncated"] {
        assert!(!obj.contains_key(key), "{key} must be absent: {v}");
    }
    for r in v["results"].as_array().unwrap() {
        assert!(
            r.get("theme_id").is_none(),
            "flat hits carry no theme_id: {r}"
        );
    }
}

/// Test 31.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_with_no_candidates_falls_through_to_pinned_flat(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "3072 fall through";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-3072").await;
    let t = bare_theme(&pool, "tf-3072 T").await;
    let other = bare_theme(&pool, "tf-3072 other").await;
    sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
        .bind(other)
        .bind(vec_3072())
        .execute(&pool)
        .await
        .expect("3072 centroid");
    let mut in_t = Vec::new();
    for i in 0..3 {
        in_t.push(
            public_at(
                &pool,
                agent,
                &format!("tf-3072 t{i}"),
                &tilt(&p, 10.0 + i as f64),
                t,
            )
            .await,
        );
    }
    // A claim in the other theme, at the probe, with both embeddings.
    let o = public_at(&pool, agent, "tf-3072 other claim", &tilt(&p, 0.0), other).await;
    sqlx::query("UPDATE claims SET embedding_3072 = $2::vector WHERE id = $1")
        .bind(o)
        .bind(vec_3072())
        .execute(&pool)
        .await
        .expect("3072 embedding");
    let state = split_state_with_embedder(&pool, embedder).await;
    let mut req = pinned_diverse(q, t);
    req.centroid_dim = Some(3072);
    let out = search(&pool, state, agent, req)
        .await
        .expect("fall-through");
    assert_eq!(out.centroid_dim_used, None, "the flat tail answered");
    assert_eq!(hit_ids(&out), in_t, "hits come only from T");
    assert!(
        out.next_cursor.is_none(),
        "a diverse request gets no cursor"
    );
}

/// Test 32.
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_full_page_has_no_cursor_unless_one_was_supplied(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "unpinned cursor";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-unpinned-cursor").await;
    let mut all = HashSet::new();
    for i in 0..10 {
        let id = seed_public_claim(&pool, agent, &format!("tf-uc {i}")).await;
        set_embedding(&pool, id, &tilt(&p, 2.0 * i as f64)).await;
        all.insert(id);
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let plain = |cursor: Option<String>| SemanticSearchRequest {
        query: q.to_string(),
        limit: Some(5),
        cursor,
        ..Default::default()
    };

    let out = search(&pool, state.clone(), agent, plain(None))
        .await
        .expect("unpaged");
    assert_eq!(out.results.len(), 5);
    assert!(!json(&out).as_object().unwrap().contains_key("next_cursor"));

    let first = search(&pool, state.clone(), agent, plain(Some("o:0".into())))
        .await
        .expect("paged");
    assert_eq!(first.next_cursor.as_deref(), Some("o:5"));
    let second = search(&pool, state, agent, plain(first.next_cursor.clone()))
        .await
        .expect("second page");
    let mut seen: Vec<Uuid> = hit_ids(&first);
    seen.extend(hit_ids(&second));
    assert_eq!(seen.len(), 10);
    assert_eq!(seen.into_iter().collect::<HashSet<_>>(), all);
}

/// Test 33.
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_unpaged_page_over_the_budget_is_truncated_and_says_so(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "unpinned budget";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-unpinned-budget").await;
    let at = tilt(&p, 0.0);
    for i in 0..40 {
        let id = seed_public_claim(&pool, agent, &big_content("tf-ub", i)).await;
        set_embedding(&pool, id, &at).await;
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let req = SemanticSearchRequest {
        query: q.to_string(),
        limit: Some(100),
        ..Default::default()
    };
    let out = search(&pool, state, agent, req).await.expect("search");
    let text = body(&out);
    assert!(text.len() < 2_000_000, "body is {} bytes", text.len());
    assert!(out.results.len() < 40);
    assert!(out.truncated, "an unpaged cut must say so");
    assert!(out.next_cursor.is_none());
    assert_eq!(json(&out)["truncated"], true);
}

/// Test 34.
#[sqlx::test(migrations = "../../migrations")]
async fn window_cap_stops_cursor(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "window cap";
    let p = probe_vec(&embedder, q).await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-window").await;
    let t = bare_theme(&pool, "tf-window T").await;
    let world = viewer_fixture::world_group(&pool).await;
    sqlx::query(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, is_current, \
                             visibility, owner_group_id, embedding, theme_id) \
         SELECT 'tf-window row ' || g, sha256(('tf-window row ' || g)::bytea), $1, 0.5, true, \
                'public', $2, $3::vector, $4 \
         FROM generate_series(1, 1005) g",
    )
    .bind(agent)
    .bind(world)
    .bind(tilt(&p, 0.0))
    .bind(t)
    .execute(&pool)
    .await
    .expect("bulk insert");
    let state = split_state_with_embedder(&pool, embedder).await;

    let out = search(
        &pool,
        state.clone(),
        agent,
        pinned(q, t, 100, Some("o:900".into())),
    )
    .await
    .expect("o:900");
    assert_eq!(out.results.len(), 100);
    assert_eq!(out.theme_scope.as_ref().unwrap().member_count, 1005);
    assert!(
        out.next_cursor.is_none(),
        "offset 900 + 100 reaches the 1,000-row window: no next_cursor"
    );

    // A page the window cuts short. SQL is asked for the full 100 (so an
    // unpinned walk keeps one `ef_search` to the end), and the rows past the
    // window are dropped in Rust: 50 rows, no cursor, not `truncated`.
    let out = search(&pool, state, agent, pinned(q, t, 100, Some("o:950".into())))
        .await
        .expect("o:950");
    assert_eq!(out.results.len(), 50, "the page stops at the window");
    assert!(out.next_cursor.is_none(), "no cursor past the window");
    assert!(!out.truncated, "a window cut is not a byte-budget cut");
}

// ── Review regression guards ──

/// Theme core with no public member and members of TWO groups: the fallback
/// mean must average only the viewer's own members. Each viewer's own member
/// is then exactly the core (similarity 1). Were the fallback mean's
/// visibility marker dropped, the superuser session here would average both
/// members, and each viewer's similarity (cos 30 degrees, about 0.87) would
/// encode where the other group's private embedding sits.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_fallback_mean_spans_only_the_viewers_own_group(pool: PgPool) {
    let embedder = mock_embedder();
    let p = probe_vec(&embedder, "two group theme core").await;
    let (m1, g1) = seed_agent_with_group(&pool, "tf-core2g-one").await;
    let (m2, g2) = seed_agent_with_group(&pool, "tf-core2g-two").await;
    let theme = bare_theme(&pool, "tf-core2g label").await;
    let x1 = private_at(&pool, m1, g1, "tf-core2g one", &tilt(&p, 0.0), theme).await;
    let x2 = private_at(&pool, m2, g2, "tf-core2g two", &tilt(&p, 60.0), theme).await;
    let state = split_state_with_embedder(&pool, embedder).await;

    for (who, mine, other) in [(m1, x1, x2), (m2, x2, x1)] {
        let out = search(&pool, state.clone(), who, core(theme, 10, None))
            .await
            .expect("theme core on the viewer's own member");
        assert_eq!(hit_ids(&out), vec![mine], "only the viewer's own member");
        assert_eq!(out.theme_scope.as_ref().unwrap().member_count, 1);
        let sim = out.results[0].similarity;
        assert!(
            (sim - 1.0).abs() < 1e-4,
            "the fallback core is the mean of the viewer's own members only, so its \
             one member sits exactly on it; got {sim}, which means another group's \
             private embedding was averaged in"
        );
        assert!(!body(&out).contains(&other.to_string()));
    }
}

/// An unpinned cursor walk, one row a page, with another group's claims
/// nearest the probe. The stranger must get every claim it can read, one per
/// page. Were the unpinned statement's inner visibility marker dropped, the
/// hidden claims would take the inner `LIMIT` slots, the outer filter would
/// empty the page, and the walk would stop early: a count of the hidden rows.
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_cursor_walk_is_not_short_changed_by_another_groups_nearer_claims(pool: PgPool) {
    let embedder = mock_embedder();
    let q = "unpinned two group walk";
    let p = probe_vec(&embedder, q).await;
    let (owner, group) = seed_agent_with_group(&pool, "tf-uw-owner").await;
    let (stranger, _sg) = seed_agent_with_group(&pool, "tf-uw-stranger").await;
    let mut hidden = Vec::new();
    for i in 0..4 {
        let id = seed_group_claim(&pool, owner, group, &format!("tf-uw hidden {i}")).await;
        set_embedding(&pool, id, &tilt(&p, 0.5 * f64::from(i))).await;
        hidden.push(id);
    }
    let mut public = Vec::new();
    for i in 0..3 {
        let id = seed_public_claim(&pool, owner, &format!("tf-uw public {i}")).await;
        set_embedding(&pool, id, &tilt(&p, 10.0 + 10.0 * f64::from(i))).await;
        public.push(id);
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let page = |cursor: Option<String>| SemanticSearchRequest {
        query: q.to_string(),
        limit: Some(1),
        cursor: Some(cursor.unwrap_or_else(|| "o:0".to_string())),
        ..Default::default()
    };

    let pages = walk(&pool, &state, stranger, page).await;
    let seen: Vec<Uuid> = pages.iter().flat_map(hit_ids).collect();
    assert_eq!(seen, public, "every public claim, nearest first, once each");
    let cursors: Vec<String> = pages.iter().filter_map(|r| r.next_cursor.clone()).collect();
    assert_eq!(
        cursors,
        vec!["o:1".to_string(), "o:2".to_string(), "o:3".to_string()],
        "the cursor advances one visible row at a time"
    );
    for r in &pages {
        let text = body(r);
        for h in &hidden {
            assert!(
                !text.contains(&h.to_string()),
                "a hidden claim leaked: {text}"
            );
        }
    }

    // Control: the owner's walk serves the hidden claims first.
    let pages = walk(&pool, &state, owner, page).await;
    let mine: Vec<Uuid> = pages.iter().flat_map(hit_ids).collect();
    let mut expected = hidden.clone();
    expected.extend(&public);
    assert_eq!(mine, expected, "control: the owner sees its own claims");
}

/// Pinned diverse with a candidate pool smaller than the theme, and another
/// group's members nearest the probe. The stranger's pool must fill from the
/// members it can read. Were the exact-candidates statement's inner
/// visibility marker dropped, the hidden members would take four of the six
/// pool slots and the outer filter would leave two.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_diverse_pool_fills_from_visible_members_past_another_groups_nearer_ones(
    pool: PgPool,
) {
    let embedder = mock_embedder();
    let q = "pinned diverse two group pool";
    let p = probe_vec(&embedder, q).await;
    let (owner, group) = seed_agent_with_group(&pool, "tf-dp-owner").await;
    let (stranger, _sg) = seed_agent_with_group(&pool, "tf-dp-stranger").await;
    let t = bare_theme(&pool, "tf-dp T").await;
    let mut hidden = HashSet::new();
    for i in 0..4 {
        let deg = f64::from(i);
        hidden.insert(
            private_at(
                &pool,
                owner,
                group,
                &format!("tf-dp hidden {i}"),
                &tilt(&p, deg),
                t,
            )
            .await,
        );
    }
    let mut nearest_public = HashSet::new();
    for i in 0..10 {
        let deg = 20.0 + f64::from(i);
        let id = public_at(
            &pool,
            owner,
            &format!("tf-dp public {i}"),
            &tilt(&p, deg),
            t,
        )
        .await;
        if i < 6 {
            nearest_public.insert(id);
        }
    }
    let state = split_state_with_embedder(&pool, embedder).await;
    let request = || {
        let mut req = pinned_diverse(q, t);
        req.candidate_pool = Some(6);
        req
    };

    let out = search(&pool, state.clone(), stranger, request())
        .await
        .expect("stranger pinned diverse");
    assert_eq!(out.centroid_dim_used, Some(1536), "the diverse branch ran");
    let got: HashSet<Uuid> = hit_ids(&out).into_iter().collect();
    assert_eq!(
        got, nearest_public,
        "a pool of 6 fills with the 6 nearest public members; another group's \
         nearer members take no slot"
    );
    assert_eq!(out.theme_scope.as_ref().unwrap().member_count, 10);

    // Control: the owner's pool of 6 holds its four nearer members.
    let mine = search(&pool, state, owner, request())
        .await
        .expect("owner pinned diverse");
    let got: HashSet<Uuid> = hit_ids(&mine).into_iter().collect();
    assert!(
        hidden.is_subset(&got),
        "control: the owner's pool holds its own nearer members"
    );
}

/// A request that can carry a cursor must not be served from the mock vector
/// when a configured embedder fails: its offset belongs to the real ranking.
/// It is 503. An unpaged request keeps the old mock fallback, and theme_core
/// makes no embedding call, so neither is affected.
#[sqlx::test(migrations = "../../migrations")]
async fn paged_request_is_503_when_the_configured_embedder_fails(pool: PgPool) {
    let p = probe_vec(&mock_embedder(), "embedder fails").await;
    let (agent, _g) = seed_agent_with_group(&pool, "tf-embed-fail").await;
    let t = bare_theme(&pool, "tf-embed-fail T").await;
    public_at(&pool, agent, "tf-ef one", &tilt(&p, 10.0), t).await;
    public_at(&pool, agent, "tf-ef two", &tilt(&p, 20.0), t).await;
    let failing = Arc::new(MockProvider::new(EmbeddingConfig::openai(DIM)).with_failures(1.0));
    let state = split_state(&pool).await.with_embedding_service(failing);
    let q = "embedder fails";

    let unpinned_paged = SemanticSearchRequest {
        query: q.to_string(),
        limit: Some(10),
        cursor: Some("o:0".to_string()),
        ..Default::default()
    };
    for (name, req) in [
        ("pinned, first page", pinned(q, t, 10, None)),
        ("pinned, later page", pinned(q, t, 10, Some("o:1".into()))),
        ("unpinned, paged", unpinned_paged),
    ] {
        let e = search(&pool, state.clone(), agent, req)
            .await
            .expect_err(name);
        let (status, err) = error_parts(e).await;
        assert_eq!(status, 503, "{name}: {err}");
        assert_eq!(err["error"], "ServiceUnavailable", "{name}");
    }

    let unpaged = SemanticSearchRequest {
        query: q.to_string(),
        limit: Some(10),
        ..Default::default()
    };
    let out = search(&pool, state.clone(), agent, unpaged)
        .await
        .expect("an unpaged request keeps the mock fallback");
    assert!(out.next_cursor.is_none());

    let out = search(&pool, state, agent, core(t, 10, None))
        .await
        .expect("theme_core makes no embedding call");
    assert_eq!(out.results.len(), 2);
}
