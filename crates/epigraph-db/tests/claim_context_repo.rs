//! `ClaimContextRepository`: the reads behind `GET /api/v1/claims/:id/context`.
//!
//! Every tenancy test here has a CALIBRATION arm: a member (or a viewer
//! given the missing membership) sees the row a stranger does not, so "the
//! stranger saw nothing" cannot pass against a read that returns nothing at
//! all. Edges between endpoints of different tenancy are FORCED to the shape
//! under test after insert, because migration 070's trigger otherwise stamps
//! an edge from its endpoints and the edge predicate alone would then hide
//! it, leaving the claim predicate untested (`viewer_fixture.rs`,
//! `seed_edge_owned_by`).

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use epigraph_db::repos::claim::LabelCursor;
use epigraph_db::{
    ClaimContextRepository as Repo, ContextClaimRow, ContextEdgeRow, ContextEdgeTally, Viewer,
};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One edge with an explicit relationship spelling and endpoint types.
/// Tenancy is whatever migration 070's trigger stamps; force it afterwards.
async fn seed_edge_rel(
    pool: &PgPool,
    src: Uuid,
    src_type: &str,
    tgt: Uuid,
    tgt_type: &str,
    rel: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(src)
    .bind(src_type)
    .bind(tgt)
    .bind(tgt_type)
    .bind(rel)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {rel} edge: {e}"));
    id
}

async fn claim_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
    seed_edge_rel(pool, src, "claim", tgt, "claim", rel).await
}

/// Force an edge's own tenancy columns (single owner).
async fn force_edge(pool: &PgPool, id: Uuid, visibility: &str, owner: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

async fn force_edge_public(pool: &PgPool, id: Uuid) {
    let world = fixture::world_group(pool).await;
    force_edge(pool, id, "public", world).await;
}

/// Force an edge co-owned by `(g, h)`: visible only to a principal in both.
async fn force_edge_co_owned(pool: &PgPool, id: Uuid, g: Uuid, h: Uuid) {
    let got: (String, Uuid, Option<Uuid>) = sqlx::query_as(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1 RETURNING visibility, owner_group_id, co_owner_group_id",
    )
    .bind(id)
    .bind(g)
    .bind(h)
    .fetch_one(pool)
    .await
    .expect("force edge co-owned");
    assert_eq!(got, ("group".to_string(), g, Some(h)));
}

async fn add_membership(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// A `kind = 'team'` group (`groups_public_key_shape` wants 32 key bytes).
async fn seed_team_group(pool: &PgPool, label: &str, creator: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, $3, $4, 'team', $5)",
    )
    .bind(id)
    .bind(format!("{label}:{id}"))
    .bind(format!("did:epigraph:test:team:{label}:{id}"))
    .bind(&key)
    .bind(creator)
    .execute(pool)
    .await
    .expect("seed team group");
    id
}

/// A bare agent with no personal group.
async fn seed_bare_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    agent
}

async fn set_level(pool: &PgPool, id: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = properties || jsonb_build_object('level', $2::int) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).expect("in range")
}

async fn set_created_at(pool: &PgPool, id: Uuid, at: DateTime<Utc>) {
    sqlx::query("UPDATE claims SET created_at = $2 WHERE id = $1")
        .bind(id)
        .bind(at)
        .execute(pool)
        .await
        .expect("set claim created_at");
}

async fn seed_paper(pool: &PgPool, title: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("10.1234/{id}"))
        .bind(title)
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'seeded by claim_context_repo', 0) RETURNING id",
    )
    .bind(format!("theme-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed theme")
}

/// A member of a personal group and its viewer, plus a stranger's viewer.
async fn member_and_stranger(pool: &PgPool) -> (Uuid, Uuid, Viewer, Viewer) {
    let (agent, group) = fixture::seed_agent_with_group(pool, "member").await;
    let member = Viewer::resolve(pool, agent).await.expect("resolve member");
    let stranger = fixture::public_viewer(pool).await;
    (agent, group, member, stranger)
}

fn ids(rows: &[ContextClaimRow]) -> BTreeSet<Uuid> {
    rows.iter().map(|r| r.id).collect()
}

fn edge_ids(rows: &[ContextEdgeRow]) -> BTreeSet<Uuid> {
    rows.iter().map(|r| r.edge_id).collect()
}

fn tally_sum(t: &[ContextEdgeTally]) -> i64 {
    t.iter().map(|x| x.count).sum()
}

fn set<const N: usize>(xs: [Uuid; N]) -> BTreeSet<Uuid> {
    xs.into_iter().collect()
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn root_is_none_for_a_hidden_claim_and_for_an_absent_one(pool: PgPool) {
    let (agent, group, member, stranger) = member_and_stranger(&pool).await;
    let secret = fixture::seed_group_claim(&pool, agent, group, "d1 secret").await;
    let theme = seed_theme(&pool).await;
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(secret)
        .bind(theme)
        .execute(&pool)
        .await
        .expect("set theme");
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.expect("read_as stranger");
    assert!(Repo::root(&mut s, &stranger, secret)
        .await
        .unwrap()
        .is_none());
    assert!(Repo::root(&mut s, &stranger, Uuid::new_v4())
        .await
        .unwrap()
        .is_none());

    let mut m = scoped.read_as(&member).await.expect("read_as member");
    let row = Repo::root(&mut m, &member, secret)
        .await
        .unwrap()
        .expect("the member reads its own claim");
    assert_eq!(row.id, secret);
    assert_eq!(row.content, "d1 secret");
    assert_eq!(row.theme_id, Some(theme));
    assert!(Repo::root(&mut m, &member, Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// D2-D4: children
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn children_count_and_page_exclude_a_private_child(pool: PgPool) {
    let (agent, group, member, stranger) = member_and_stranger(&pool).await;
    let parent = fixture::seed_public_claim(&pool, agent, "d2 parent").await;
    let a = fixture::seed_public_claim(&pool, agent, "d2 child a").await;
    let b = fixture::seed_public_claim(&pool, agent, "d2 child b").await;
    let secret = fixture::seed_group_claim(&pool, agent, group, "d2 child secret").await;
    for c in [a, b] {
        claim_edge(&pool, parent, c, "decomposes_to").await;
    }
    let e = claim_edge(&pool, parent, secret, "decomposes_to").await;
    force_edge_public(&pool, e).await;
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.unwrap();
    let page = Repo::children(&mut s, &stranger, parent, None, None, None, 10)
        .await
        .unwrap();
    assert_eq!(ids(&page.items), set([a, b]));
    assert_eq!(page.total, 2, "the total is the visible count");

    let mut m = scoped.read_as(&member).await.unwrap();
    let page = Repo::children(&mut m, &member, parent, None, None, None, 10)
        .await
        .unwrap();
    assert_eq!(ids(&page.items), set([a, b, secret]));
    assert_eq!(page.total, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn children_keyset_pages_cover_the_set_once(pool: PgPool) {
    let (agent, _group, _member, stranger) = member_and_stranger(&pool).await;
    let parent = fixture::seed_public_claim(&pool, agent, "d3 parent").await;
    let mut all = BTreeSet::new();
    for i in 0..7 {
        let c = fixture::seed_public_claim(&pool, agent, &format!("d3 child {i}")).await;
        claim_edge(&pool, parent, c, "decomposes_to").await;
        // Four share one created_at (one ingest transaction); the order then
        // falls back to id.
        let at = if i < 4 { ts(0) } else { ts(i) };
        set_created_at(&pool, c, at).await;
        all.insert(c);
    }
    let scoped = fixture::scoped_pool(&pool).await;
    let mut s = scoped.read_as(&stranger).await.unwrap();

    let mut seen: Vec<Uuid> = Vec::new();
    let mut after: Option<LabelCursor> = None;
    let mut sizes = Vec::new();
    loop {
        let page = Repo::children(&mut s, &stranger, parent, None, None, after, 3)
            .await
            .unwrap();
        assert_eq!(page.total, 7);
        sizes.push(page.items.len());
        seen.extend(page.items.iter().map(|r| r.id));
        if page.items.len() < 3 {
            break;
        }
        let last = page.items.last().unwrap();
        after = Some(LabelCursor {
            created_at: last.created_at,
            id: last.id,
        });
        assert!(sizes.len() < 10, "paging must terminate");
    }
    assert_eq!(sizes, vec![3, 3, 1], "the last page is short");
    let unique: BTreeSet<Uuid> = seen.iter().copied().collect();
    assert_eq!(unique.len(), seen.len(), "no row is served twice: {seen:?}");
    assert_eq!(unique, all, "every row is served once");
}

#[sqlx::test(migrations = "../../migrations")]
async fn children_filter_by_level_and_exclude_the_root(pool: PgPool) {
    let (agent, _group, _member, stranger) = member_and_stranger(&pool).await;
    let parent = fixture::seed_public_claim(&pool, agent, "d4 section").await;
    let root = fixture::seed_public_claim(&pool, agent, "d4 paragraph root").await;
    let s1 = fixture::seed_public_claim(&pool, agent, "d4 paragraph 1").await;
    let s2 = fixture::seed_public_claim(&pool, agent, "d4 paragraph 2").await;
    let atom = fixture::seed_public_claim(&pool, agent, "d4 atom").await;
    set_level(&pool, parent, 1).await;
    for c in [root, s1, s2] {
        set_level(&pool, c, 2).await;
        claim_edge(&pool, parent, c, "decomposes_to").await;
    }
    set_level(&pool, atom, 3).await;
    claim_edge(&pool, parent, atom, "decomposes_to").await;
    let scoped = fixture::scoped_pool(&pool).await;
    let mut s = scoped.read_as(&stranger).await.unwrap();

    let page = Repo::children(&mut s, &stranger, parent, Some("2"), Some(root), None, 50)
        .await
        .unwrap();
    assert_eq!(ids(&page.items), set([s1, s2]));
    assert_eq!(page.total, 2);

    // Calibration: without the filters the same parent has four children.
    let page = Repo::children(&mut s, &stranger, parent, None, None, None, 50)
        .await
        .unwrap();
    assert_eq!(page.total, 4);
}

// ---------------------------------------------------------------------------
// D5-D7: epistemic edges
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_drop_hidden_neighbours_hidden_edges_retracted_and_superseded(
    pool: PgPool,
) {
    let (agent, group, member, stranger) = member_and_stranger(&pool).await;
    let x = fixture::seed_public_claim(&pool, agent, "d5 root").await;
    let clean = fixture::seed_public_claim(&pool, agent, "d5 clean").await;
    let private_n = fixture::seed_group_claim(&pool, agent, group, "d5 private neighbour").await;
    let public_n3 = fixture::seed_public_claim(&pool, agent, "d5 behind a private edge").await;
    let retracted_n = fixture::seed_public_claim(&pool, agent, "d5 retracted").await;
    let superseded_n = fixture::seed_public_claim(&pool, agent, "d5 superseded").await;

    let e_clean = claim_edge(&pool, x, clean, "supports").await;
    let e_private_n = claim_edge(&pool, x, private_n, "refutes").await;
    force_edge_public(&pool, e_private_n).await;
    let e_private_edge = claim_edge(&pool, public_n3, x, "contradicts").await;
    force_edge(&pool, e_private_edge, "group", group).await;
    let e_retracted = claim_edge(&pool, x, retracted_n, "elaborates").await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(e_retracted)
        .execute(&pool)
        .await
        .expect("retract");
    let e_superseded = claim_edge(&pool, superseded_n, x, "supports").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded_n)
        .execute(&pool)
        .await
        .expect("supersede");
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.unwrap();
    let rows = Repo::epistemic_edges(&mut s, &stranger, x, None, 80)
        .await
        .unwrap();
    assert_eq!(edge_ids(&rows), set([e_clean]));
    assert_eq!(rows[0].direction, "outgoing");
    assert_eq!(rows[0].neighbor_id, clean);
    let tallies = Repo::epistemic_tallies(&mut s, &stranger, x).await.unwrap();
    assert_eq!(tally_sum(&tallies), rows.len() as i64);

    let mut m = scoped.read_as(&member).await.unwrap();
    let rows = Repo::epistemic_edges(&mut m, &member, x, None, 80)
        .await
        .unwrap();
    assert_eq!(
        edge_ids(&rows),
        set([e_clean, e_private_n, e_private_edge]),
        "the member sees its private neighbour and its private edge; retracted \
         and superseded stay out for everyone"
    );
    assert!(!edge_ids(&rows).contains(&e_retracted));
    assert!(!edge_ids(&rows).contains(&e_superseded));
    let tallies = Repo::epistemic_tallies(&mut m, &member, x).await.unwrap();
    assert_eq!(tally_sum(&tallies), 3);
    let incoming = rows
        .iter()
        .find(|r| r.edge_id == e_private_edge)
        .expect("private edge");
    assert_eq!(incoming.direction, "incoming");
    assert_eq!(incoming.neighbor_id, public_n3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn epistemic_edges_read_both_spellings_and_lower_case_them(pool: PgPool) {
    let (agent, _group, _member, stranger) = member_and_stranger(&pool).await;
    let x = fixture::seed_public_claim(&pool, agent, "d6 root").await;
    let a = fixture::seed_public_claim(&pool, agent, "d6 a").await;
    let b = fixture::seed_public_claim(&pool, agent, "d6 b").await;
    let c = fixture::seed_public_claim(&pool, agent, "d6 c").await;
    let upper = claim_edge(&pool, x, a, "SUPPORTS").await;
    let lower = claim_edge(&pool, x, b, "supports").await;
    let corr = claim_edge(&pool, c, x, "CORROBORATES").await;
    let scoped = fixture::scoped_pool(&pool).await;
    let mut s = scoped.read_as(&stranger).await.unwrap();

    let rows = Repo::epistemic_edges(&mut s, &stranger, x, None, 80)
        .await
        .unwrap();
    assert_eq!(edge_ids(&rows), set([upper, lower, corr]));
    for r in &rows {
        assert_eq!(r.relationship, r.relationship.to_lowercase());
    }
    let tallies = Repo::epistemic_tallies(&mut s, &stranger, x).await.unwrap();
    let got: Vec<(String, String, i64)> = tallies
        .into_iter()
        .map(|t| (t.relationship, t.direction, t.count))
        .collect();
    assert_eq!(
        got,
        vec![
            ("corroborates".to_string(), "incoming".to_string(), 1),
            ("supports".to_string(), "outgoing".to_string(), 2),
        ]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn structure_and_non_claim_edges_are_not_epistemic(pool: PgPool) {
    let (agent, _group, _member, stranger) = member_and_stranger(&pool).await;
    let x = fixture::seed_public_claim(&pool, agent, "d7 root").await;
    let y = fixture::seed_public_claim(&pool, agent, "d7 part").await;
    let z = fixture::seed_public_claim(&pool, agent, "d7 next passage").await;
    let w = fixture::seed_public_claim(&pool, agent, "d7 cited").await;
    let paper = seed_paper(&pool, "d7 paper").await;
    let evidence = fixture::seed_evidence(&pool, x, "document").await;
    claim_edge(&pool, x, y, "decomposes_to").await;
    claim_edge(&pool, x, z, "continues_argument").await;
    seed_edge_rel(&pool, paper, "paper", x, "claim", "asserts").await;
    seed_edge_rel(&pool, x, "claim", evidence, "evidence", "supports").await;
    // The live control: one real epistemic edge, so "nothing else" cannot
    // come from a dead read.
    let control = claim_edge(&pool, x, w, "cites").await;
    let scoped = fixture::scoped_pool(&pool).await;
    let mut s = scoped.read_as(&stranger).await.unwrap();

    let rows = Repo::epistemic_edges(&mut s, &stranger, x, None, 80)
        .await
        .unwrap();
    assert_eq!(edge_ids(&rows), set([control]));
    let tallies = Repo::epistemic_tallies(&mut s, &stranger, x).await.unwrap();
    assert_eq!(tallies.len(), 1);
    assert_eq!(tallies[0].relationship, "cites");
    assert_eq!(tallies[0].count, 1);
}

// ---------------------------------------------------------------------------
// D8: papers
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn papers_come_from_asserts_edges_only(pool: PgPool) {
    let (agent, _group, _member, stranger) = member_and_stranger(&pool).await;
    let root = fixture::seed_public_claim(&pool, agent, "d8 root").await;
    let asserting = seed_paper(&pool, "d8 asserting paper").await;
    let citing = seed_paper(&pool, "d8 citing paper").await;
    seed_edge_rel(&pool, asserting, "paper", root, "claim", "asserts").await;
    seed_edge_rel(&pool, citing, "paper", root, "claim", "cites").await;
    let scoped = fixture::scoped_pool(&pool).await;
    let mut s = scoped.read_as(&stranger).await.unwrap();

    let page = Repo::papers(&mut s, &stranger, root, None, 5)
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, asserting);
    assert_eq!(page.items[0].title.as_deref(), Some("d8 asserting paper"));
    assert_eq!(page.items[0].doi, format!("10.1234/{asserting}"));
    let first = Repo::first_paper(&mut s, &stranger, root).await.unwrap();
    assert_eq!(first.map(|p| p.id), Some(asserting));
}

// ---------------------------------------------------------------------------
// D9-D10: anchors and bind arity
// ---------------------------------------------------------------------------

/// A group-private anchor with public rows hanging off it in every list, all
/// connecting edges forced public. Returns `(anchor, member viewer)`.
async fn hidden_anchor_corpus(pool: &PgPool) -> (Uuid, Viewer, Viewer) {
    let (agent, group, member, stranger) = member_and_stranger(pool).await;
    let anchor = fixture::seed_group_claim(pool, agent, group, "d9 anchor").await;
    set_level(pool, anchor, 2).await;
    let parent = fixture::seed_public_claim(pool, agent, "d9 parent").await;
    set_level(pool, parent, 1).await;
    let child = fixture::seed_public_claim(pool, agent, "d9 child").await;
    let neighbour = fixture::seed_public_claim(pool, agent, "d9 neighbour").await;
    let paper = seed_paper(pool, "d9 paper").await;
    let edges = [
        claim_edge(pool, parent, anchor, "decomposes_to").await,
        claim_edge(pool, anchor, child, "decomposes_to").await,
        claim_edge(pool, anchor, neighbour, "supports").await,
        seed_edge_rel(pool, paper, "paper", anchor, "claim", "asserts").await,
    ];
    for e in edges {
        force_edge_public(pool, e).await;
    }
    (anchor, member, stranger)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_anchor_empties_every_list(pool: PgPool) {
    let (anchor, member, stranger) = hidden_anchor_corpus(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.unwrap();
    let papers = Repo::papers(&mut s, &stranger, anchor, None, 5)
        .await
        .unwrap();
    assert!(papers.items.is_empty());
    assert_eq!(papers.total, 0);
    assert!(Repo::first_paper(&mut s, &stranger, anchor)
        .await
        .unwrap()
        .is_none());
    let parents = Repo::parents(&mut s, &stranger, anchor, None, 10)
        .await
        .unwrap();
    assert!(parents.items.is_empty());
    assert_eq!(parents.total, 0);
    assert!(Repo::first_parent(&mut s, &stranger, anchor, Some("1"))
        .await
        .unwrap()
        .is_none());
    assert!(Repo::first_parent(&mut s, &stranger, anchor, None)
        .await
        .unwrap()
        .is_none());
    let children = Repo::children(&mut s, &stranger, anchor, None, None, None, 50)
        .await
        .unwrap();
    assert!(children.items.is_empty());
    assert_eq!(children.total, 0);
    assert!(Repo::epistemic_tallies(&mut s, &stranger, anchor)
        .await
        .unwrap()
        .is_empty());
    assert!(Repo::epistemic_edges(&mut s, &stranger, anchor, None, 80)
        .await
        .unwrap()
        .is_empty());

    // Calibration: the member reads every list.
    let mut m = scoped.read_as(&member).await.unwrap();
    assert_eq!(
        Repo::papers(&mut m, &member, anchor, None, 5)
            .await
            .unwrap()
            .total,
        1
    );
    assert!(Repo::first_paper(&mut m, &member, anchor)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        Repo::parents(&mut m, &member, anchor, None, 10)
            .await
            .unwrap()
            .total,
        1
    );
    assert!(Repo::first_parent(&mut m, &member, anchor, Some("1"))
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        Repo::children(&mut m, &member, anchor, None, None, None, 50)
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        tally_sum(
            &Repo::epistemic_tallies(&mut m, &member, anchor)
                .await
                .unwrap()
        ),
        1
    );
    assert_eq!(
        Repo::epistemic_edges(&mut m, &member, anchor, None, 80)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_fn_runs_under_a_bypass_viewer(pool: PgPool) {
    // A bypass viewer renders no group predicate and so no group bind; a fn
    // that bound the group array unconditionally would send one parameter too
    // many and fail on arity here.
    let (anchor, _member, _stranger) = hidden_anchor_corpus(&pool).await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let mut c = pool.acquire().await.expect("acquire");
    let after = Some(LabelCursor {
        created_at: ts(0),
        id: Uuid::nil(),
    });

    assert!(Repo::root(&mut c, &bypass, anchor).await.unwrap().is_some());
    assert_eq!(
        Repo::papers(&mut c, &bypass, anchor, after, 5)
            .await
            .unwrap()
            .total,
        1
    );
    assert!(Repo::first_paper(&mut c, &bypass, anchor)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        Repo::parents(&mut c, &bypass, anchor, after, 10)
            .await
            .unwrap()
            .total,
        1
    );
    assert!(Repo::first_parent(&mut c, &bypass, anchor, Some("1"))
        .await
        .unwrap()
        .is_some());
    let children = Repo::children(&mut c, &bypass, anchor, None, Some(Uuid::nil()), after, 50)
        .await
        .unwrap();
    assert_eq!(children.total, 1);
    assert_eq!(children.items.len(), 1);
    assert_eq!(
        tally_sum(
            &Repo::epistemic_tallies(&mut c, &bypass, anchor)
                .await
                .unwrap()
        ),
        1
    );
    // A cursor far in the future pages from the newest edge downwards.
    let future = Some(LabelCursor {
        created_at: ts(1_000_000_000),
        id: Uuid::nil(),
    });
    assert_eq!(
        Repo::epistemic_edges(&mut c, &bypass, anchor, future, 80)
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// D11: no belief field
// ---------------------------------------------------------------------------

#[test]
fn no_row_type_names_a_belief_field() {
    // Exhaustive destructures, no `..`: adding a field such as
    // `pignistic_prob` to either row type stops this compiling, so the
    // addition has to be looked at. `no_role_blind_belief_reads.rs` covers
    // the SQL with its REGISTER unchanged.
    let ContextClaimRow {
        id: _,
        content: _,
        truth_value: _,
        is_current: _,
        level: _,
        theme_id: _,
        created_at: _,
    } = ContextClaimRow {
        id: Uuid::nil(),
        content: String::new(),
        truth_value: 0.5,
        is_current: true,
        level: None,
        theme_id: None,
        created_at: ts(0),
    };
    let ContextEdgeRow {
        edge_id: _,
        relationship: _,
        direction: _,
        strength: _,
        edge_created_at: _,
        neighbor_id: _,
        content: _,
        truth_value: _,
        is_current: _,
        level: _,
        theme_id: _,
    } = ContextEdgeRow {
        edge_id: Uuid::nil(),
        relationship: String::new(),
        direction: String::new(),
        strength: None,
        edge_created_at: ts(0),
        neighbor_id: Uuid::nil(),
        content: String::new(),
        truth_value: 0.5,
        is_current: true,
        level: None,
        theme_id: None,
    };
}

// ---------------------------------------------------------------------------
// D12-D14: edge tenancy on papers and structure; level-filtered parent
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_owned_asserts_edge_hides_the_paper(pool: PgPool) {
    let (agent, group, member, stranger) = member_and_stranger(&pool).await;
    let root = fixture::seed_public_claim(&pool, agent, "d12 root").await;
    let paper = seed_paper(&pool, "d12 paper").await;
    let e = seed_edge_rel(&pool, paper, "paper", root, "claim", "asserts").await;
    force_edge(&pool, e, "group", group).await;
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.unwrap();
    let page = Repo::papers(&mut s, &stranger, root, None, 5)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.total, 0);
    assert!(Repo::first_paper(&mut s, &stranger, root)
        .await
        .unwrap()
        .is_none());

    let mut m = scoped.read_as(&member).await.unwrap();
    let page = Repo::papers(&mut m, &member, root, None, 5).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].id, paper);
}

#[sqlx::test(migrations = "../../migrations")]
async fn co_owned_edges_need_both_groups(pool: PgPool) {
    let author = seed_bare_agent(&pool).await;
    let g = seed_team_group(&pool, "G", author).await;
    let h = seed_team_group(&pool, "H", author).await;
    let agent_a = seed_bare_agent(&pool).await;
    let agent_b = seed_bare_agent(&pool).await;
    add_membership(&pool, g, agent_a).await;
    add_membership(&pool, h, agent_b).await;

    let x = fixture::seed_public_claim(&pool, author, "d13 x").await;
    let y = fixture::seed_public_claim(&pool, author, "d13 y").await;
    let z = fixture::seed_public_claim(&pool, author, "d13 z").await;
    let w = fixture::seed_public_claim(&pool, author, "d13 atom w").await;
    set_level(&pool, x, 2).await;
    set_level(&pool, w, 3).await;
    let paper = seed_paper(&pool, "d13 paper").await;
    let e_support = claim_edge(&pool, x, y, "supports").await;
    let e_decomp = claim_edge(&pool, x, w, "decomposes_to").await;
    let e_asserts = seed_edge_rel(&pool, paper, "paper", x, "claim", "asserts").await;
    for e in [e_support, e_decomp, e_asserts] {
        force_edge_co_owned(&pool, e, g, h).await;
    }
    // The live control: public, so it is visible to everyone.
    let control = claim_edge(&pool, x, z, "supports").await;
    let scoped = fixture::scoped_pool(&pool).await;

    let in_g = Viewer::resolve(&pool, agent_a).await.unwrap();
    assert_eq!(in_g.group_bind().map(<[Uuid]>::len), Some(1));
    let in_h = Viewer::resolve(&pool, agent_b).await.unwrap();
    for v in [&in_g, &in_h] {
        let mut c = scoped.read_as(v).await.unwrap();
        let rows = Repo::epistemic_edges(&mut c, v, x, None, 80).await.unwrap();
        assert_eq!(edge_ids(&rows), set([control]), "one group is not enough");
        assert_eq!(
            tally_sum(&Repo::epistemic_tallies(&mut c, v, x).await.unwrap()),
            1
        );
        let kids = Repo::children(&mut c, v, x, None, None, None, 50)
            .await
            .unwrap();
        assert!(kids.items.is_empty());
        assert_eq!(kids.total, 0);
        let parents = Repo::parents(&mut c, v, w, None, 10).await.unwrap();
        assert!(parents.items.is_empty());
        assert_eq!(parents.total, 0);
        assert!(Repo::first_parent(&mut c, v, w, Some("2"))
            .await
            .unwrap()
            .is_none());
        let papers = Repo::papers(&mut c, v, x, None, 5).await.unwrap();
        assert!(papers.items.is_empty());
        assert_eq!(papers.total, 0);
    }

    // Calibration: in both groups, every read sees its edge.
    add_membership(&pool, h, agent_a).await;
    let both = Viewer::resolve(&pool, agent_a).await.unwrap();
    assert_eq!(both.group_bind().map(<[Uuid]>::len), Some(2));
    let mut c = scoped.read_as(&both).await.unwrap();
    let rows = Repo::epistemic_edges(&mut c, &both, x, None, 80)
        .await
        .unwrap();
    assert_eq!(edge_ids(&rows), set([control, e_support]));
    assert_eq!(
        tally_sum(&Repo::epistemic_tallies(&mut c, &both, x).await.unwrap()),
        2
    );
    let kids = Repo::children(&mut c, &both, x, None, None, None, 50)
        .await
        .unwrap();
    assert_eq!(ids(&kids.items), set([w]));
    assert_eq!(kids.total, 1);
    let parents = Repo::parents(&mut c, &both, w, None, 10).await.unwrap();
    assert_eq!(ids(&parents.items), set([x]));
    assert_eq!(parents.total, 1);
    assert_eq!(
        Repo::first_parent(&mut c, &both, w, Some("2"))
            .await
            .unwrap()
            .map(|r| r.id),
        Some(x)
    );
    let papers = Repo::papers(&mut c, &both, x, None, 5).await.unwrap();
    assert_eq!(papers.total, 1);
    assert_eq!(papers.items[0].id, paper);
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_parent_filters_by_expected_level(pool: PgPool) {
    let (agent, group, member, stranger) = member_and_stranger(&pool).await;
    let atom = fixture::seed_public_claim(&pool, agent, "d14 atom").await;
    set_level(&pool, atom, 3).await;
    // A compound claim with no level, oldest of all.
    let compound = fixture::seed_public_claim(&pool, agent, "d14 compound").await;
    set_created_at(&pool, compound, ts(0)).await;
    // A hidden paragraph, older than the visible one.
    let hidden = fixture::seed_group_claim(&pool, agent, group, "d14 hidden paragraph").await;
    set_level(&pool, hidden, 2).await;
    set_created_at(&pool, hidden, ts(1)).await;
    let paragraph = fixture::seed_public_claim(&pool, agent, "d14 paragraph").await;
    set_level(&pool, paragraph, 2).await;
    set_created_at(&pool, paragraph, ts(2)).await;
    claim_edge(&pool, compound, atom, "decomposes_to").await;
    let e_hidden = claim_edge(&pool, hidden, atom, "decomposes_to").await;
    force_edge_public(&pool, e_hidden).await;
    claim_edge(&pool, paragraph, atom, "decomposes_to").await;
    let scoped = fixture::scoped_pool(&pool).await;

    let mut s = scoped.read_as(&stranger).await.unwrap();
    let got = |r: Option<ContextClaimRow>| r.map(|r| r.id);
    assert_eq!(
        got(Repo::first_parent(&mut s, &stranger, atom, Some("2"))
            .await
            .unwrap()),
        Some(paragraph),
        "the compound is never the structural parent, and the hidden paragraph is skipped"
    );
    assert_eq!(
        got(Repo::first_parent(&mut s, &stranger, atom, None)
            .await
            .unwrap()),
        Some(compound),
        "with no level the oldest parent wins"
    );
    assert_eq!(
        Repo::parents(&mut s, &stranger, atom, None, 10)
            .await
            .unwrap()
            .total,
        2
    );

    let mut m = scoped.read_as(&member).await.unwrap();
    assert_eq!(
        got(Repo::first_parent(&mut m, &member, atom, Some("2"))
            .await
            .unwrap()),
        Some(hidden),
        "calibration: the member's oldest level-2 parent is its own"
    );
    assert_eq!(
        Repo::parents(&mut m, &member, atom, None, 10)
            .await
            .unwrap()
            .total,
        3
    );
}
