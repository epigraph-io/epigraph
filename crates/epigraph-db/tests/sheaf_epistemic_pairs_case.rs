//! `SheafRepository::get_epistemic_edge_pairs` must match the epistemic
//! relationship list case-insensitively, as its sibling
//! `get_claim_neighbor_betp_pairs` already does.
//!
//! `edges.relationship` carries the same relationship in more than one
//! spelling: MCP `link_epistemic` writes `supports` / `corroborates`, while the
//! HTTP edge route, the DS evidence writers and the cross-source matcher write
//! `SUPPORTS` / `CORROBORATES` (see `relationship_spelling_readers.rs`). The
//! pairs query backs MCP `sheaf_cohomology` and `reconcile_sheaf`; the sibling
//! backs `check_sheaf_consistency`. While the pairs query compared the stored
//! string exactly, cohomology and reconcile silently skipped every upper-case
//! edge that consistency counted, so the two halves of the sheaf tooling
//! described different graphs.
//!
//! The engine side already folds case (`restriction_kind_with_profile` matches
//! on `to_ascii_lowercase()`), so returning an upper-case row is enough for it
//! to get the right restriction kind.

use epigraph_db::repos::sheaf::SheafRepository;
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

/// A claim with a concrete belief interval. Both sheaf queries require
/// `pignistic_prob IS NOT NULL` on both endpoints, so a bare claim would drop
/// out for that reason and hide the case defect behind it.
async fn insert_believed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("sheaf case claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id,
                             belief, plausibility, pignistic_prob)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, 0.6, 0.9, 0.75)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Insert one claim->claim edge with an explicit relationship spelling.
/// `retracted` sets `valid_to` an hour in the past.
async fn insert_edge(pool: &PgPool, src: Uuid, tgt: Uuid, relationship: &str, retracted: bool) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship,
                            valid_to)
         VALUES ($1, $2, 'claim', $3, 'claim', $4,
                 CASE WHEN $5 THEN now() - interval '1 hour' ELSE NULL END)",
    )
    .bind(Uuid::new_v4())
    .bind(src)
    .bind(tgt)
    .bind(relationship)
    .bind(retracted)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"));
}

type Triple = (Uuid, Uuid, String);

/// The seeded graph. Every edge has its own pair of endpoints except the
/// dual-spelled pair, which carries `supports` and `SUPPORTS` between the same
/// two claims; a returned `(source, target, relationship)` therefore identifies
/// exactly one seeded edge.
struct Seed {
    /// In-force edges whose relationship, folded to lower case, is epistemic.
    epistemic: BTreeSet<Triple>,
    /// The lower-case `supports` edge: today's spelling, the live-read control.
    lower_control: Triple,
    /// An upper-case non-epistemic edge: must never be returned.
    non_epistemic: Triple,
    /// A retracted upper-case `SUPPORTS` edge: must never be returned.
    retracted: Triple,
    /// `supports` and `SUPPORTS` between ONE pair (also in `epistemic`): the
    /// documented contract is two rows, one per stored spelling.
    dual_spelled: [Triple; 2],
    /// Every claim the seed created.
    claims: BTreeSet<Uuid>,
}

async fn seed(pool: &PgPool) -> Seed {
    let agent = insert_agent(pool).await;
    let mut claims = BTreeSet::new();
    let pair = || async move {
        let a = insert_believed_claim(pool, agent).await;
        let b = insert_believed_claim(pool, agent).await;
        (a, b)
    };

    let mut epistemic = BTreeSet::new();
    let mut lower_control = None;
    // The lower-case control, then every member of the epistemic list in a
    // non-lower spelling (UPPER and Capitalised alternate), so the parity test
    // below covers the whole list: dropping any one name from either query's
    // list leaves an edge one query returns and the other does not.
    for rel in [
        "supports",
        "SUPPORTS",
        "Refutes",
        "CONTRADICTS",
        "Corroborates",
        "CORROBORATES",
        "Elaborates",
        "SPECIALIZES",
        "Generalizes",
        "FRAME_VALIDATES",
    ] {
        let (a, b) = pair().await;
        insert_edge(pool, a, b, rel, false).await;
        claims.extend([a, b]);
        let t = (a, b, rel.to_string());
        if rel == "supports" {
            lower_control = Some(t.clone());
        }
        epistemic.insert(t);
    }

    // Both spellings between one pair. The non-authored uniqueness index is on
    // the raw `(source_id, target_id, relationship)`, so writers can store both.
    let (a, b) = pair().await;
    insert_edge(pool, a, b, "supports", false).await;
    insert_edge(pool, a, b, "SUPPORTS", false).await;
    claims.extend([a, b]);
    let dual_spelled = [
        (a, b, "supports".to_string()),
        (a, b, "SUPPORTS".to_string()),
    ];
    epistemic.extend(dual_spelled.iter().cloned());

    let (a, b) = pair().await;
    insert_edge(pool, a, b, "DERIVED_FROM", false).await;
    claims.extend([a, b]);
    let non_epistemic = (a, b, "DERIVED_FROM".to_string());

    let (a, b) = pair().await;
    insert_edge(pool, a, b, "SUPPORTS", true).await;
    claims.extend([a, b]);
    let retracted = (a, b, "SUPPORTS".to_string());

    Seed {
        epistemic,
        lower_control: lower_control.expect("supports seeded"),
        non_epistemic,
        retracted,
        dual_spelled,
        claims,
    }
}

async fn edge_pairs(pool: &PgPool, claims: &BTreeSet<Uuid>) -> BTreeSet<Triple> {
    SheafRepository::get_epistemic_edge_pairs(pool, &fixture::public_viewer(pool).await, None)
        .await
        .expect("get_epistemic_edge_pairs")
        .into_iter()
        .filter(|r| claims.contains(&r.source_id) && claims.contains(&r.target_id))
        .map(|r| (r.source_id, r.target_id, r.relationship))
        .collect()
}

/// Upper- and mixed-case spellings of epistemic relationships are returned,
/// while the predicates that should still exclude an edge (a non-epistemic
/// relationship, a retracted edge) keep excluding it in upper case.
#[sqlx::test(migrations = "../../migrations")]
async fn uppercase_epistemic_edges_are_returned(pool: PgPool) {
    let s = seed(&pool).await;
    let got = edge_pairs(&pool, &s.claims).await;

    assert!(
        got.contains(&s.lower_control),
        "control: the lower-case `supports` edge must be read, otherwise this test \
         cannot tell a case defect from a dead query; got {got:?}"
    );

    let missing: Vec<&Triple> = s.epistemic.iter().filter(|t| !got.contains(t)).collect();
    assert!(
        missing.is_empty(),
        "every in-force epistemic edge must reach the cohomology scan whatever its \
         spelling; missing {missing:?}"
    );

    assert!(
        !got.contains(&s.non_epistemic),
        "folding case must not widen the relationship list: DERIVED_FROM is not epistemic"
    );
    assert!(
        !got.contains(&s.retracted),
        "a retracted SUPPORTS edge must stay out of the scan in upper case too"
    );
    assert_eq!(
        got.len(),
        s.epistemic.len(),
        "nothing beyond the in-force epistemic edges may be returned; got {got:?}"
    );
}

/// Cohomology / reconcile (the pairs query) and consistency (the neighbour
/// query) must see the same edge set. Each in-force epistemic edge appears
/// exactly once in the neighbour query as an `outgoing` row of its source, so
/// those rows, read as `(source, target, relationship)`, must equal the pairs
/// query's output.
#[sqlx::test(migrations = "../../migrations")]
async fn pairs_query_sees_the_same_edges_as_the_neighbour_query(pool: PgPool) {
    let s = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;

    let from_neighbours: BTreeSet<Triple> =
        SheafRepository::get_claim_neighbor_betp_pairs(&pool, &viewer, None)
            .await
            .expect("get_claim_neighbor_betp_pairs")
            .into_iter()
            .filter(|r| r.direction == "outgoing")
            .filter(|r| s.claims.contains(&r.claim_id) && s.claims.contains(&r.neighbor_id))
            .map(|r| (r.claim_id, r.neighbor_id, r.relationship))
            .collect();
    assert!(
        !from_neighbours.is_empty(),
        "control: the neighbour query must read the seeded edges"
    );

    let from_pairs = edge_pairs(&pool, &s.claims).await;
    assert_eq!(
        from_pairs, from_neighbours,
        "cohomology and consistency must describe the same graph: \
         left = pairs query, right = neighbour query (outgoing rows)"
    );
}

/// Two spellings of one relationship between the same pair are two rows in the
/// pairs query, and the neighbour query agrees. Folding them into one (e.g. a
/// `DISTINCT ON (source_id, target_id, lower(relationship))` in only one of the
/// queries) would make cohomology and consistency describe different graphs;
/// doing it in both is a deliberate change that must update this test.
#[sqlx::test(migrations = "../../migrations")]
async fn two_spellings_between_one_pair_are_two_rows(pool: PgPool) {
    let s = seed(&pool).await;
    let (a, b, _) = &s.dual_spelled[0];

    let stored: BTreeSet<String> = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2",
    )
    .bind(a)
    .bind(b)
    .fetch_all(&pool)
    .await
    .expect("read back")
    .into_iter()
    .collect();
    assert_eq!(
        stored,
        BTreeSet::from(["SUPPORTS".to_string(), "supports".to_string()]),
        "PREMISE: both spellings are stored as two edges between one pair"
    );

    let pair_rows: BTreeSet<Triple> = edge_pairs(&pool, &s.claims)
        .await
        .into_iter()
        .filter(|(src, tgt, _)| src == a && tgt == b)
        .collect();
    assert_eq!(
        pair_rows,
        BTreeSet::from(s.dual_spelled.clone()),
        "the pairs query returns one row per stored spelling"
    );

    let neighbour_rows: BTreeSet<Triple> = SheafRepository::get_claim_neighbor_betp_pairs(
        &pool,
        &fixture::public_viewer(&pool).await,
        None,
    )
    .await
    .expect("get_claim_neighbor_betp_pairs")
    .into_iter()
    .filter(|r| r.direction == "outgoing" && r.claim_id == *a && r.neighbor_id == *b)
    .map(|r| (r.claim_id, r.neighbor_id, r.relationship))
    .collect();
    assert_eq!(
        neighbour_rows, pair_rows,
        "the neighbour query reads the same two rows"
    );
}
