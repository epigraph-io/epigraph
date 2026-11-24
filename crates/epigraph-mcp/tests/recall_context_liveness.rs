//! `fetch_batched_context` hands back only LIVE context (backlog bc76b481).
//!
//! `recall_with_context` decorates each hit with its section, atoms, sibling
//! paragraphs, corroborating neighbours and neighbour paragraphs. A superseded
//! claim (`is_current = false`) is retired content, and a `corroborates` edge
//! whose `valid_to` has passed has been retracted; neither is live support.
//! Before the fix the sibling and CORROBORATES legs returned both, as did the
//! section, atom, bridge-parent and neighbour-paragraph legs for superseded
//! claims, so a caller read retired content as a hit's current context. The
//! epistemic-neighbour leg (7b) already applied both predicates and is pinned
//! in `recall_with_context.rs`.
//!
//! Every retired row here has a LIVE calibration partner on the same leg that
//! must still be returned, so a predicate that drops a whole leg fails too.
//! Every violation is collected before the one assertion, so a run against the
//! unfixed code names each leg that leaks rather than stopping at the first.

#![allow(clippy::too_many_lines)]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::recall::__test_only::fetch_batched_context;
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

/// A public claim at `level` (`properties.level`). `retired` collects the
/// ones to supersede once every edge is in place, so the edges are written
/// onto current claims, as they were before the supersession.
async fn claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    level: i32,
    retired: Option<&mut Vec<Uuid>>,
) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
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
    if let Some(r) = retired {
        r.push(id);
    }
    id
}

/// A claim -> claim edge; `expired` sets `valid_to` one second in the past,
/// the state `delete_edge` leaves a retracted edge in.
async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str, expired: bool) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_to) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, \
                 CASE WHEN $4 THEN now() - interval '1 second' END)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(expired)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// Every violation, so one run names each leg that leaks.
fn check(violations: &mut Vec<String>, leg: &str, got: BTreeSet<Uuid>, want: BTreeSet<Uuid>) {
    if got != want {
        violations.push(format!("{leg}: got {got:?}, want {want:?}"));
    }
}

fn set<I: IntoIterator<Item = Uuid>>(ids: I) -> BTreeSet<Uuid> {
    ids.into_iter().collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_returns_no_superseded_claim_and_no_retracted_corroborates_edge(
    pool: PgPool,
) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "liveness").await;
    let viewer = fixture::public_viewer(&pool).await;
    let mut retired: Vec<Uuid> = Vec::new();

    // Two hits: `p` carries every per-paragraph leg; `q`'s ONLY section is
    // superseded.
    let p = claim(&pool, agent, "liveness: paragraph p", 2, None).await;
    let q = claim(&pool, agent, "liveness: paragraph q", 2, None).await;

    // 3. Section parents.
    let section = claim(&pool, agent, "liveness: live section", 1, None).await;
    let old_section = claim(
        &pool,
        agent,
        "liveness: superseded section",
        1,
        Some(&mut retired),
    )
    .await;
    edge(&pool, section, p, "decomposes_to", false).await;
    edge(&pool, old_section, q, "decomposes_to", false).await;

    // 6. Siblings under p's section.
    let sibling = claim(&pool, agent, "liveness: live sibling", 2, None).await;
    let old_sibling = claim(
        &pool,
        agent,
        "liveness: superseded sibling",
        2,
        Some(&mut retired),
    )
    .await;
    edge(&pool, section, sibling, "decomposes_to", false).await;
    edge(&pool, section, old_sibling, "decomposes_to", false).await;

    // 4. Atoms of p.
    let atom = claim(&pool, agent, "liveness: live atom", 3, None).await;
    let old_atom = claim(
        &pool,
        agent,
        "liveness: superseded atom",
        3,
        Some(&mut retired),
    )
    .await;
    edge(&pool, p, atom, "decomposes_to", false).await;
    edge(&pool, p, old_atom, "decomposes_to", false).await;

    // 5. Bridge parents: the live atom's OTHER parents.
    let bridge = claim(&pool, agent, "liveness: live bridge parent", 2, None).await;
    let old_bridge = claim(
        &pool,
        agent,
        "liveness: superseded bridge parent",
        2,
        Some(&mut retired),
    )
    .await;
    edge(&pool, bridge, atom, "decomposes_to", false).await;
    edge(&pool, old_bridge, atom, "decomposes_to", false).await;

    // 7. CORROBORATES, both directions: a live edge each way (calibration), a
    // retracted edge each way, and a live edge each way to a superseded claim.
    let cor_out = claim(&pool, agent, "liveness: corroborated (live)", 2, None).await;
    let cor_in = claim(&pool, agent, "liveness: corroborating (live)", 2, None).await;
    let cor_out_retracted = claim(&pool, agent, "liveness: corroborated, retracted", 2, None).await;
    let cor_in_retracted = claim(&pool, agent, "liveness: corroborating, retracted", 2, None).await;
    let cor_out_old = claim(
        &pool,
        agent,
        "liveness: corroborated, superseded",
        2,
        Some(&mut retired),
    )
    .await;
    let cor_in_old = claim(
        &pool,
        agent,
        "liveness: corroborating, superseded",
        2,
        Some(&mut retired),
    )
    .await;
    edge(&pool, p, cor_out, "corroborates", false).await;
    edge(&pool, cor_in, p, "CORROBORATES", false).await;
    edge(&pool, p, cor_out_retracted, "corroborates", true).await;
    edge(&pool, cor_in_retracted, p, "CORROBORATES", true).await;
    edge(&pool, p, cor_out_old, "corroborates", false).await;
    edge(&pool, cor_in_old, p, "corroborates", false).await;

    // 8. continues_argument neighbours, both directions.
    let next = claim(&pool, agent, "liveness: live continuation", 2, None).await;
    let old_next = claim(
        &pool,
        agent,
        "liveness: superseded continuation",
        2,
        Some(&mut retired),
    )
    .await;
    let old_prev = claim(
        &pool,
        agent,
        "liveness: superseded predecessor",
        2,
        Some(&mut retired),
    )
    .await;
    edge(&pool, p, next, "continues_argument", false).await;
    edge(&pool, p, old_next, "continues_argument", false).await;
    edge(&pool, old_prev, p, "continues_argument", false).await;

    // 9 + 10. Atom-atom bridge: the live atom supports an outside atom (live)
    // and a superseded one; the live outside atom has a live and a superseded
    // parent paragraph.
    let outside = claim(&pool, agent, "liveness: live outside atom", 3, None).await;
    let old_outside = claim(
        &pool,
        agent,
        "liveness: superseded outside atom",
        3,
        Some(&mut retired),
    )
    .await;
    edge(&pool, atom, outside, "supports", false).await;
    edge(&pool, atom, old_outside, "supports", false).await;
    let outside_parent = claim(&pool, agent, "liveness: outside parent", 2, None).await;
    let old_outside_parent = claim(
        &pool,
        agent,
        "liveness: old outside parent",
        2,
        Some(&mut retired),
    )
    .await;
    edge(&pool, outside_parent, outside, "decomposes_to", false).await;
    edge(&pool, old_outside_parent, outside, "decomposes_to", false).await;

    // Supersede the retired claims now that every edge is written.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = ANY($1)")
        .bind(&retired)
        .execute(&pool)
        .await
        .expect("retire the superseded claims");
    assert_eq!(
        retired.len(),
        10,
        "fixture: every superseded claim is retired"
    );

    let ctx = fetch_batched_context(&pool, &viewer, &[p, q], 50, 50, 50)
        .await
        .expect("fetch_batched_context");

    let mut violations: Vec<String> = Vec::new();

    // 3.
    check(
        &mut violations,
        "section of p (calibration)",
        set(ctx.section_meta.get(&p).map(|s| s.section_id)),
        set([section]),
    );
    check(
        &mut violations,
        "section of q (its only section is superseded)",
        set(ctx.section_meta.get(&q).map(|s| s.section_id)),
        set([]),
    );
    // 6.
    check(
        &mut violations,
        "siblings of p",
        set(ctx
            .siblings_by_paragraph
            .get(&p)
            .into_iter()
            .flatten()
            .map(|s| s.paragraph_id)),
        set([sibling]),
    );
    if ctx.siblings_total_by_paragraph.get(&p) != Some(&1) {
        violations.push(format!(
            "siblings_total of p: got {:?}, want Some(1)",
            ctx.siblings_total_by_paragraph.get(&p)
        ));
    }
    // 4.
    let atoms = ctx.atoms_by_paragraph.get(&p).cloned().unwrap_or_default();
    check(
        &mut violations,
        "atoms of p",
        set(atoms.iter().map(|a| a.atom_id)),
        set([atom]),
    );
    if ctx.atoms_total_by_paragraph.get(&p) != Some(&1) {
        violations.push(format!(
            "atoms_total of p: got {:?}, want Some(1)",
            ctx.atoms_total_by_paragraph.get(&p)
        ));
    }
    // 5.
    check(
        &mut violations,
        "bridge parents of the live atom",
        set(atoms
            .iter()
            .filter(|a| a.atom_id == atom)
            .flat_map(|a| a.bridge_to_paragraphs.iter().copied())),
        set([bridge]),
    );
    // 7.
    check(
        &mut violations,
        "corroborates of p",
        set(ctx
            .corroborates_by_paragraph
            .get(&p)
            .into_iter()
            .flatten()
            .map(|c| c.claim_id)),
        set([cor_out, cor_in]),
    );
    if ctx.corroborates_total_by_paragraph.get(&p) != Some(&2) {
        violations.push(format!(
            "corroborates_total of p: got {:?}, want Some(2)",
            ctx.corroborates_total_by_paragraph.get(&p)
        ));
    }
    // 8.
    check(
        &mut violations,
        "continues_argument neighbours of p",
        set(ctx
            .continues_argument_by_paragraph
            .get(&p)
            .into_iter()
            .flatten()
            .copied()),
        set([next]),
    );
    // 9.
    check(
        &mut violations,
        "atom-atom bridge targets of the live atom",
        set(ctx
            .atom_atom_links_by_atom
            .get(&atom)
            .into_iter()
            .flatten()
            .map(|(b, _)| *b)),
        set([outside]),
    );
    // 10.
    check(
        &mut violations,
        "parent paragraphs of the outside atom",
        set(ctx
            .paragraphs_by_atom
            .get(&outside)
            .into_iter()
            .flatten()
            .copied()),
        set([outside_parent]),
    );

    assert!(
        violations.is_empty(),
        "recall context returned superseded claims or retracted corroborates edges as live \
         context, or dropped a live one:\n  {}",
        violations.join("\n  ")
    );
}
