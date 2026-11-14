//! `fetch_batched_context` walks only the `edges` rows the viewer may read, and
//! not only the `claims` rows it returns (`F-edges-unfiltered`, MCP residual).
//!
//! # The instrument
//!
//! `__test_only::fetch_batched_context` acquires a connection from the
//! `#[sqlx::test]` superuser pool, which bypasses row security, so the in-query
//! predicate is the only control on every statement and a missing one is
//! directly observable. [`assert_bypasses_row_security`] pins that, because on a
//! filtered session the edge policies would hide the same rows and the test
//! could not tell a filtered statement from an unfiltered one.
//!
//! # Every edge joins two PUBLIC claims
//!
//! An edge's tenancy is FORCED after the insert. Left to migration 070's
//! trigger, an edge tracks its endpoints, so the claims predicate the
//! statements already carried would hide it for a reason unrelated to the one
//! under test. Each relationship is seeded twice: once private to a STRANGER's
//! group (must not be walked) and once private to the VIEWER's own group (must
//! be walked: the calibration partner that rejects a predicate dropping all
//! edges).

#![allow(clippy::too_many_lines)]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_mcp::tools;
use sqlx::PgPool;
use uuid::Uuid;

struct Cast {
    agent: Uuid,
    viewer: Viewer,
    mine: Uuid,
    theirs: Uuid,
}

async fn assert_bypasses_row_security(pool: &PgPool) {
    let bypass: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(pool)
    .await
    .expect("role privileges");
    assert!(
        bypass,
        "CALIBRATION: the test pool must bypass row security, or the edge policies \
         (not the in-query predicate) are what this file observes"
    );
}

async fn edge(
    pool: &PgPool,
    source: (Uuid, &str),
    target: Uuid,
    relationship: &str,
    owner: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, 'claim', $5)",
    )
    .bind(id)
    .bind(source.0)
    .bind(source.1)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(owner)
    .execute(pool)
    .await
    .expect("force edge tenancy");
    id
}

async fn leveled(pool: &PgPool, c: &Cast, content: &str, level: i32) -> Uuid {
    let id = fixture::seed_public_claim(pool, c.agent, content).await;
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) \
                                        || jsonb_build_object('level', $2::int) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
    id
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'p') RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("seed paper")
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_walks_only_edges_the_viewer_can_read(pool: PgPool) {
    assert_bypasses_row_security(&pool).await;
    let (agent, mine) = fixture::seed_agent_with_group(&pool, "rce-mine").await;
    let (_stranger, theirs) = fixture::seed_agent_with_group(&pool, "rce-theirs").await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let c = Cast {
        agent,
        viewer,
        mine,
        theirs,
    };
    let cl = |s: Uuid| (s, "claim");

    // Two input paragraphs: `p` carries the per-paragraph relationships, `q`
    // the section-scoped ones (a paragraph has one section in the result).
    let p = leveled(&pool, &c, "rce: paragraph p", 2).await;
    let q = leveled(&pool, &c, "rce: paragraph q", 2).await;

    // 3. section parents: p's only section edge is hidden; q's is mine.
    let sec_h = leveled(&pool, &c, "rce: hidden section", 1).await;
    let sec_m = leveled(&pool, &c, "rce: my section", 1).await;
    edge(&pool, cl(sec_h), p, "decomposes_to", c.theirs).await;
    edge(&pool, cl(sec_m), q, "decomposes_to", c.mine).await;

    // 6. siblings under q's section.
    let sib_h = leveled(&pool, &c, "rce: hidden sibling", 2).await;
    let sib_m = leveled(&pool, &c, "rce: my sibling", 2).await;
    edge(&pool, cl(sec_m), sib_h, "decomposes_to", c.theirs).await;
    edge(&pool, cl(sec_m), sib_m, "decomposes_to", c.mine).await;

    // 4. atoms of p.
    let atom_h = leveled(&pool, &c, "rce: hidden atom", 3).await;
    let atom_m = leveled(&pool, &c, "rce: my atom", 3).await;
    edge(&pool, cl(p), atom_h, "decomposes_to", c.theirs).await;
    edge(&pool, cl(p), atom_m, "decomposes_to", c.mine).await;

    // 5. bridge_to_paragraphs: atom_m's other parents.
    let other_h = leveled(&pool, &c, "rce: hidden other parent", 2).await;
    let other_m = leveled(&pool, &c, "rce: my other parent", 2).await;
    edge(&pool, cl(other_h), atom_m, "decomposes_to", c.theirs).await;
    edge(&pool, cl(other_m), atom_m, "decomposes_to", c.mine).await;

    // 7. corroborates, plus the paper attribution of a neighbour.
    let cor_h = leveled(&pool, &c, "rce: hidden corroborator", 2).await;
    let cor_m = leveled(&pool, &c, "rce: my corroborator", 2).await;
    let cor_m2 = leveled(&pool, &c, "rce: my attributed corroborator", 2).await;
    edge(&pool, cl(p), cor_h, "corroborates", c.theirs).await;
    edge(&pool, cl(cor_m), p, "corroborates", c.mine).await;
    edge(&pool, cl(cor_m2), p, "corroborates", c.mine).await;
    let paper_h = paper(&pool, "10.9999/rce-hidden").await;
    let paper_m = paper(&pool, "10.9999/rce-mine").await;
    edge(&pool, (paper_h, "paper"), cor_m, "asserts", c.theirs).await;
    edge(&pool, (paper_m, "paper"), cor_m2, "asserts", c.mine).await;

    // 2. paper attribution of the input paragraphs.
    let paper_hp = paper(&pool, "10.9999/rce-hidden-p").await;
    let paper_mq = paper(&pool, "10.9999/rce-mine-q").await;
    edge(&pool, (paper_hp, "paper"), p, "asserts", c.theirs).await;
    edge(&pool, (paper_mq, "paper"), q, "asserts", c.mine).await;

    // 8. continues_argument.
    let ca_h = leveled(&pool, &c, "rce: hidden continuation", 2).await;
    let ca_m = leveled(&pool, &c, "rce: my continuation", 2).await;
    edge(&pool, cl(p), ca_h, "continues_argument", c.theirs).await;
    edge(&pool, cl(ca_m), p, "continues_argument", c.mine).await;

    // 9. atom-atom links of atom_m, and 10. the far atom's parents.
    let aa_h = leveled(&pool, &c, "rce: hidden linked atom", 3).await;
    let aa_m = leveled(&pool, &c, "rce: my linked atom", 3).await;
    edge(&pool, cl(atom_m), aa_h, "supports", c.theirs).await;
    edge(&pool, cl(aa_m), atom_m, "supports", c.mine).await;
    let par_h = leveled(&pool, &c, "rce: hidden far parent", 2).await;
    let par_m = leveled(&pool, &c, "rce: my far parent", 2).await;
    edge(&pool, cl(par_h), aa_m, "decomposes_to", c.theirs).await;
    edge(&pool, cl(par_m), aa_m, "decomposes_to", c.mine).await;

    let ctx = tools::recall::__test_only::fetch_batched_context(&pool, &c.viewer, &[p, q], 8, 8, 8)
        .await
        .expect("batched context");

    // Negative arms are collected rather than asserted one by one, so a single
    // run names EVERY statement that walks a hidden edge (the red run on the
    // unfiltered code is the per-statement proof). Calibrations assert at once.
    let mut walked_hidden: Vec<&str> = Vec::new();
    let mut check = |ok: bool, which: &'static str| {
        if !ok {
            walked_hidden.push(which);
        }
    };

    // 3. section parents.
    assert_eq!(
        ctx.section_meta.get(&q).map(|s| s.section_id),
        Some(sec_m),
        "CALIBRATION: section by my edge"
    );
    check(!ctx.section_meta.contains_key(&p), "3 section parent");
    // 6. siblings.
    let sibs: Vec<Uuid> = ctx
        .siblings_by_paragraph
        .get(&q)
        .map(|v| v.iter().map(|s| s.paragraph_id).collect())
        .unwrap_or_default();
    assert!(
        sibs.contains(&sib_m),
        "CALIBRATION: sibling by my edge; got {sibs:?}"
    );
    check(!sibs.contains(&sib_h), "6 sibling paragraph");
    // 4. atoms, and their window total.
    let atoms: Vec<Uuid> = ctx
        .atoms_by_paragraph
        .get(&p)
        .map(|v| v.iter().map(|a| a.atom_id).collect())
        .unwrap_or_default();
    assert!(
        atoms.contains(&atom_m),
        "CALIBRATION: atom by my edge; got {atoms:?}"
    );
    check(
        atoms == vec![atom_m] && ctx.atoms_total_by_paragraph.get(&p) == Some(&1),
        "4 atom children / atom total",
    );
    // 5. bridge_to_paragraphs.
    let bridges: Vec<Uuid> = ctx
        .atoms_by_paragraph
        .get(&p)
        .and_then(|v| v.iter().find(|a| a.atom_id == atom_m))
        .map(|a| a.bridge_to_paragraphs.clone())
        .unwrap_or_default();
    assert!(
        bridges.contains(&other_m),
        "CALIBRATION: bridge by my edge; got {bridges:?}"
    );
    check(bridges == vec![other_m], "5 bridge_to_paragraphs");
    // 7. corroborates, its total, and a neighbour's paper attribution.
    let cors = ctx
        .corroborates_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    let cor_ids: Vec<Uuid> = cors.iter().map(|e| e.claim_id).collect();
    assert!(
        cor_ids.contains(&cor_m) && cor_ids.contains(&cor_m2),
        "CALIBRATION: corroborators by my edges; got {cor_ids:?}"
    );
    check(
        !cor_ids.contains(&cor_h) && ctx.corroborates_total_by_paragraph.get(&p) == Some(&2),
        "7 corroborates neighbour / total",
    );
    let doi = |id: Uuid| {
        cors.iter()
            .find(|e| e.claim_id == id)
            .and_then(|e| e.paper_doi.clone())
    };
    assert_eq!(
        doi(cor_m2).as_deref(),
        Some("10.9999/rce-mine"),
        "CALIBRATION: attribution by my edge"
    );
    check(doi(cor_m).is_none(), "7 corroborates paper_doi");
    // 2. paper attribution of the paragraphs.
    assert!(
        ctx.paper_meta
            .get(&q)
            .is_some_and(|m| m.paper_id == paper_mq),
        "CALIBRATION: paper attribution by my edge"
    );
    check(
        !ctx.paper_meta.contains_key(&p),
        "2 paragraph paper attribution",
    );
    // 8. continues_argument.
    let cas = ctx
        .continues_argument_by_paragraph
        .get(&p)
        .cloned()
        .unwrap_or_default();
    assert!(
        cas.contains(&ca_m),
        "CALIBRATION: continuation by my edge; got {cas:?}"
    );
    check(cas == vec![ca_m], "8 continues_argument");
    // 9. atom-atom links.
    let links: Vec<Uuid> = ctx
        .atom_atom_links_by_atom
        .get(&atom_m)
        .map(|v| v.iter().map(|(b, _)| *b).collect())
        .unwrap_or_default();
    assert!(
        links.contains(&aa_m),
        "CALIBRATION: atom link by my edge; got {links:?}"
    );
    check(links == vec![aa_m], "9 atom-atom link");
    // 10. the far atom's parent paragraphs.
    let pars = ctx
        .paragraphs_by_atom
        .get(&aa_m)
        .cloned()
        .unwrap_or_default();
    assert!(
        pars.contains(&par_m),
        "CALIBRATION: far parent by my edge; got {pars:?}"
    );
    check(pars == vec![par_m], "10 far atom parent");

    assert!(
        walked_hidden.is_empty(),
        "these statements walked an edge the viewer cannot read: {walked_hidden:?}"
    );
}
