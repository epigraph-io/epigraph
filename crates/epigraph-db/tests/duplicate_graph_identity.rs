//! A duplicate as a graph fact: where a dedup leaves the duplicate's belief
//! inputs, and what record of the dedup it leaves behind.
//!
//! These arms were written FIRST, as measurements of the dedup on the tree
//! before this file's fixes:
//!
//! * V-1 (`a_dedup_pools_the_duplicates_non_edge_bbas_on_the_canonical`): the
//!   repair moved the duplicate's EDGE-keyed BBAs with their edges and left
//!   every other BBA (its auto-wired creation row, an assess row) on the
//!   now non-current duplicate, where no reader folds it.
//! * V-3 (`a_dedup_records_its_identity_as_an_attributed_same_as_edge`): the
//!   act wrote `supersedes` and bumped `updated_at`; it wrote no edge and no
//!   row naming who marked the duplicate or by which rule.
//!
//! Most arms run on the harness connection (the superuser, so the session is
//! privileged and the act and the repair run in one transaction, as the
//! semantic-duplicate sweep runs them). The act's arms run on a stamped
//! `epigraph_app` session, and one pooling arm runs the repair as
//! `epigraph_maintenance` (no BYPASSRLS, so RESTRICTIVE policies still bind it,
//! unlike the superuser).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DuplicateProvenance, FrameRepository, MassFunctionRepository};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    FrameRepository::create(
        pool,
        "binary_truth",
        Some("duplicate identity fixture"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("seed frame")
    .id
}

async fn seed_evidence(pool: &PgPool, claim: Uuid, tag: &str) -> Uuid {
    let hash: Vec<u8> = blake3::hash(format!("{claim}:{tag}").as_bytes())
        .as_bytes()
        .to_vec();
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'observation', $2, $3) RETURNING id",
    )
    .bind(claim)
    .bind(&hash)
    .bind(format!("duplicate identity evidence {tag}"))
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

/// A `supports` edge plus the `perspectives` row its edge-keyed BBA names,
/// as `ensure_edge_perspective` leaves them.
async fn seed_supports_edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed edge");
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("edge {id}"))
        .execute(pool)
        .await
        .expect("seed edge perspective");
    id
}

/// One BBA, through the repository writer every production path uses.
#[allow(clippy::too_many_arguments)]
async fn store_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    masses: serde_json::Value,
    method: &str,
    evidence: Option<Uuid>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        perspective,
        &masses,
        None,
        Some(method),
        None,
        None,
        "unknown",
        evidence,
    )
    .await
    .expect("store bba")
}

async fn bba_claim(pool: &PgPool, id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("bba row")
}

/// V-1. The duplicate holds four belief inputs: an auto-wired creation BBA
/// citing its own evidence row (`perspective_id` NULL, `evidence_id` set), an
/// assess row (no agent, no perspective), and a BBA keyed to an incoming
/// `supports` edge. After the dedup every one of the BBAs is folded on the
/// canonical, and the evidence ROW stays with the duplicate (it is the
/// duplicate's provenance; the moved BBA still cites it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_pools_the_duplicates_non_edge_bbas_on_the_canonical(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let other = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, author, "canonical").await;
    let dup = seed_claim(&pool, author, "duplicate").await;
    let third = seed_claim(&pool, other, "a supporter").await;
    let frame = seed_frame(&pool).await;
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});

    let evidence = seed_evidence(&pool, dup, "direct").await;
    let direct = store_bba(
        &pool,
        dup,
        frame,
        Some(author),
        None,
        m.clone(),
        "auto_wire",
        Some(evidence),
    )
    .await;
    let assess = store_bba(&pool, dup, frame, None, None, m.clone(), "discount", None).await;
    let edge = seed_supports_edge(&pool, third, dup).await;
    let edge_bba = store_bba(
        &pool,
        dup,
        frame,
        Some(other),
        Some(edge),
        m,
        "edge_factor",
        None,
    )
    .await;

    ClaimRepository::mark_duplicate_with_repair(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup");

    let landed = [
        ("auto-wired creation BBA", bba_claim(&pool, direct).await),
        ("assess BBA", bba_claim(&pool, assess).await),
        ("edge-keyed BBA", bba_claim(&pool, edge_bba).await),
    ];
    let evidence_on: Uuid = sqlx::query_scalar("SELECT claim_id FROM evidence WHERE id = $1")
        .bind(evidence)
        .fetch_one(&pool)
        .await
        .expect("evidence row");
    let name = |id: Uuid| {
        if id == canonical {
            "canonical"
        } else if id == dup {
            "duplicate"
        } else {
            "elsewhere"
        }
    };
    let table: Vec<String> = landed
        .iter()
        .map(|(what, on)| format!("{what} -> {}", name(*on)))
        .chain(std::iter::once(format!(
            "evidence row -> {}",
            name(evidence_on)
        )))
        .collect();
    for (what, on) in &landed {
        assert_eq!(
            *on, canonical,
            "{what} was not pooled on the canonical; landings: {table:?}"
        );
    }
    assert_eq!(
        evidence_on, dup,
        "the evidence row is the duplicate's provenance and stays with it; landings: {table:?}"
    );
}

/// V-3. The act records the identity it asserts: exactly one in-force
/// `same_as` edge `duplicate -> canonical` whose properties name the caller's
/// tool and rule and the agent that marked it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_records_its_identity_as_an_attributed_same_as_edge(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, author, "canonical").await;
    let dup = seed_claim(&pool, author, "duplicate").await;

    ClaimRepository::mark_duplicate_with_repair(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup");

    let (sup, current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup row");
    assert_eq!((sup, current), (Some(canonical), false), "the act itself");

    let edges: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT relationship, properties FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND valid_to IS NULL",
    )
    .bind(dup)
    .bind(canonical)
    .fetch_all(&pool)
    .await
    .expect("edges dup -> canonical");
    let same_as: Vec<&serde_json::Value> = edges
        .iter()
        .filter(|(r, _)| r == "same_as")
        .map(|(_, p)| p)
        .collect();
    assert_eq!(
        same_as.len(),
        1,
        "exactly one in-force same_as edge records the identity; edges dup -> canonical: {edges:?}"
    );
    let dedup = &same_as[0]["dedup"];
    for key in ["tool", "rule", "marked_at"] {
        assert!(
            dedup.get(key).is_some_and(|v| !v.is_null()),
            "the identity edge's provenance lacks {key}: {}",
            same_as[0]
        );
    }
}

/// B2 on the application role. A writer marks its own group-private claim a
/// duplicate of another of its group's claims on a STAMPED `epigraph_app`
/// session: the act's identity edge lands on that session (no privilege), takes
/// the endpoints' group, names the session principal as `marked_by` when the
/// caller named nobody, and is visible to the group and to no stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn the_identity_edge_lands_on_the_app_role_and_is_hidden_from_a_stranger(pool: PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(&pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(!bypassrls, "epigraph_app bypasses RLS; this arm is vacuous");
    let (w, group) = fixture::seed_agent_with_group(&pool, "dup-writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let canonical = fixture::seed_group_claim(&pool, w, group, "group canonical").await;
    let dup = fixture::seed_group_claim(&pool, w, group, "group duplicate").await;

    let p = pool.clone();
    let (edge, seen_by_writer, seen_by_stranger) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let edge = ClaimRepository::mark_duplicate_act_attributed_conn(
                &mut conn,
                ClaimId::from_uuid(dup),
                ClaimId::from_uuid(canonical),
                &DuplicateProvenance::unattributed(),
            )
            .await
            .expect("the act lands on the writer's stamped app session");
            let count = "SELECT count(*) FROM edges WHERE id = $1";
            let by_writer: i64 = sqlx::query_scalar(count)
                .bind(edge)
                .fetch_one(&mut *conn)
                .await
                .expect("writer reads");
            stamp(&mut conn, &p, stranger).await;
            let by_stranger: i64 = sqlx::query_scalar(count)
                .bind(edge)
                .fetch_one(&mut *conn)
                .await
                .expect("stranger reads");
            (conn, (edge, by_writer, by_stranger))
        })
        .await;
    assert_eq!(seen_by_writer, 1, "the group reads its identity edge");
    assert_eq!(
        seen_by_stranger, 0,
        "RLS hides the identity edge from a stranger"
    );

    let (rel, vis, owner, props): (String, String, Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT relationship, visibility::text, owner_group_id, properties \
           FROM edges WHERE id = $1 AND source_id = $2 AND target_id = $3",
    )
    .bind(edge)
    .bind(dup)
    .bind(canonical)
    .fetch_one(&pool)
    .await
    .expect("the identity edge, duplicate -> canonical");
    assert_eq!(rel, "same_as");
    assert_eq!(
        (vis.as_str(), owner),
        ("group", group),
        "the endpoints' group owns it"
    );
    assert_eq!(
        props["dedup"]["marked_by"],
        serde_json::json!(w),
        "marked_by falls back to the session principal: {props}"
    );
    assert_eq!(props["dedup"]["tool"], "repository");
}

/// A second mark of the same duplicate is refused and writes no second
/// identity edge (the act's existing "already superseded" refusal now also
/// guards the edge).
#[sqlx::test(migrations = "../../migrations")]
async fn a_re_mark_is_refused_and_writes_no_second_identity_edge(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, author, "canonical").await;
    let other = seed_claim(&pool, author, "another canonical").await;
    let dup = seed_claim(&pool, author, "duplicate").await;
    let prov = DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED);
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &prov,
    )
    .await
    .expect("first mark");
    let err = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(other),
        &prov,
    )
    .await
    .expect_err("a second mark is refused");
    assert!(format!("{err:?}").contains("already superseded"), "{err:?}");
    let identity_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(identity_edges, 1, "the refused re-mark wrote no edge");
}

async fn bba_masses(pool: &PgPool, id: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT masses FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("bba masses")
}

async fn mark_with_repair(pool: &PgPool, dup: Uuid, canonical: Uuid) -> epigraph_db::DedupRepair {
    ClaimRepository::mark_duplicate_with_repair(
        pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup")
}

/// B3, the same-source rule. The canonical already holds agent A's BBA on
/// the frame; the duplicate holds A's own BBA under the same key and B's.
/// B's moves; A's duplicate copy stays on the duplicate (A counted once, the
/// canonical's own row untouched, nothing deleted), and the repair says so.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_keeps_a_source_the_canonical_already_counts_on_the_duplicate(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let b = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let frame = seed_frame(&pool).await;
    let canon_a = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let dup_a = serde_json::json!({"1": 0.9, "0,1": 0.1});
    let a_on_canonical = store_bba(
        &pool,
        canonical,
        frame,
        Some(a),
        None,
        canon_a.clone(),
        "auto_wire",
        None,
    )
    .await;
    let a_on_dup = store_bba(
        &pool,
        dup,
        frame,
        Some(a),
        None,
        dup_a.clone(),
        "auto_wire",
        None,
    )
    .await;
    let b_on_dup = store_bba(
        &pool,
        dup,
        frame,
        Some(b),
        None,
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
        "auto_wire",
        None,
    )
    .await;

    let repair = mark_with_repair(&pool, dup, canonical).await;

    assert_eq!(
        bba_claim(&pool, b_on_dup).await,
        canonical,
        "B's row is pooled"
    );
    assert_eq!(
        bba_claim(&pool, a_on_dup).await,
        dup,
        "A's duplicate copy is kept on the duplicate"
    );
    assert_eq!(bba_masses(&pool, a_on_dup).await, dup_a, "and kept intact");
    assert_eq!(
        (
            bba_claim(&pool, a_on_canonical).await,
            bba_masses(&pool, a_on_canonical).await
        ),
        (canonical, canon_a),
        "the canonical's own row for A is untouched"
    );
    assert_eq!(repair.pooled_bbas, vec![b_on_dup]);
    assert_eq!(repair.kept_on_duplicate, vec![a_on_dup]);
    assert!(!repair.canonical_is_compound);
}

/// B3, the atom-level rule. An `attributed_v1` row is never moved by a dedup;
/// it stays on the duplicate and is reported, while the plain row beside it
/// pools.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_never_moves_an_attributed_v1_row(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let b = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let frame = seed_frame(&pool).await;
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let attributed = store_bba(
        &pool,
        dup,
        frame,
        Some(a),
        None,
        m.clone(),
        "attributed_v1",
        None,
    )
    .await;
    let plain = store_bba(&pool, dup, frame, Some(b), None, m, "auto_wire", None).await;

    let repair = mark_with_repair(&pool, dup, canonical).await;

    assert_eq!(
        bba_claim(&pool, attributed).await,
        dup,
        "the attributed_v1 row stays"
    );
    assert_eq!(
        bba_claim(&pool, plain).await,
        canonical,
        "the plain row pools"
    );
    assert_eq!(repair.kept_on_duplicate, vec![attributed]);
    assert_eq!(repair.pooled_bbas, vec![plain]);
}

/// B3, the compound rule. A canonical with an in-force `decomposes_to`
/// out-edge is a compound: none of the duplicate's non-edge rows is moved
/// onto it, and the repair says why.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_pools_nothing_onto_a_compound_canonical(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "compound canonical").await;
    let atom = seed_claim(&pool, a, "an atom of it").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(canonical)
    .bind(atom)
    .execute(&pool)
    .await
    .expect("decomposes_to");
    let frame = seed_frame(&pool).await;
    let row = store_bba(
        &pool,
        dup,
        frame,
        Some(a),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        "auto_wire",
        None,
    )
    .await;

    let repair = mark_with_repair(&pool, dup, canonical).await;

    assert_eq!(
        bba_claim(&pool, row).await,
        dup,
        "nothing moves onto a compound"
    );
    assert!(repair.canonical_is_compound);
    assert!(repair.pooled_bbas.is_empty());
    assert_eq!(repair.kept_on_duplicate, vec![row]);
}

/// B3, the derived-row rule. A cached combination row (no agent, no
/// perspective, a combination label) is the duplicate's OWN fold of its inputs.
/// Pooled as an input it would count that evidence a second time, so it stays
/// on the duplicate even when the canonical's slot for it is free.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_never_pools_the_duplicates_cached_combination(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let frame = seed_frame(&pool).await;
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let input = store_bba(
        &pool,
        dup,
        frame,
        Some(a),
        None,
        m.clone(),
        "auto_wire",
        None,
    )
    .await;
    let cache = store_bba(&pool, dup, frame, None, None, m, "Dempster", None).await;

    let repair = mark_with_repair(&pool, dup, canonical).await;

    assert_eq!(bba_claim(&pool, input).await, canonical, "the input pools");
    assert_eq!(bba_claim(&pool, cache).await, dup, "the cached fold stays");
    assert_eq!(repair.kept_on_duplicate, vec![cache]);
}

async fn tenancy_of_bba(pool: &PgPool, id: Uuid) -> (Uuid, String, Uuid) {
    sqlx::query_as(
        "SELECT claim_id, visibility::text, owner_group_id FROM mass_functions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("bba tenancy")
}

/// B3, the audience rule. A group-private duplicate's BBA is the group's
/// assessment. Pooled onto a PUBLIC canonical, or onto another group's
/// private canonical, it would be disclosed to a wider audience and move a
/// belief that audience reads, so it stays on the duplicate. Onto a canonical
/// of the SAME group it pools.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_duplicates_bba_pools_only_within_its_own_audience(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "private-writer").await;
    let (x, h) = fixture::seed_agent_with_group(&pool, "other-group").await;
    let frame = seed_frame(&pool).await;
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let mut cases = Vec::new();
    for (label, canonical) in [
        (
            "public canonical",
            fixture::seed_public_claim(&pool, x, "public canonical").await,
        ),
        (
            "other group's canonical",
            fixture::seed_group_claim(&pool, x, h, "h canonical").await,
        ),
        (
            "same group's canonical",
            fixture::seed_group_claim(&pool, w, g, "g canonical").await,
        ),
    ] {
        let dup = fixture::seed_group_claim(&pool, w, g, &format!("g dup for {label}")).await;
        let row = store_bba(
            &pool,
            dup,
            frame,
            Some(w),
            None,
            m.clone(),
            "auto_wire",
            None,
        )
        .await;
        assert_eq!(tenancy_of_bba(&pool, row).await, (dup, "group".into(), g));
        let repair = mark_with_repair(&pool, dup, canonical).await;
        cases.push((label, dup, canonical, row, repair));
    }
    for (label, dup, canonical, row, repair) in cases {
        let got = tenancy_of_bba(&pool, row).await;
        if label == "same group's canonical" {
            assert_eq!(got, (canonical, "group".into(), g), "{label}: pools");
            assert_eq!(repair.pooled_bbas, vec![row], "{label}");
        } else {
            assert_eq!(
                got,
                (dup, "group".into(), g),
                "{label}: stays private on the duplicate"
            );
            assert_eq!(repair.kept_on_duplicate, vec![row], "{label}");
            assert!(repair.pooled_bbas.is_empty(), "{label}");
        }
    }
}

/// FA07 parity with pooling. A writer's duplicate is bound to binary_truth
/// at FALSE and holds a BBA but no incoming edge; the canonical is a world
/// claim the writer cannot write. Pooling would hand the canonical that
/// binding's frame (or, with the repair's own skip, pooled rows on a frame the
/// canonical is not bound to), so the act refuses it as it refuses the
/// edge-triggered case.
#[sqlx::test(migrations = "../../migrations")]
async fn the_act_refuses_a_false_bound_duplicate_whose_bbas_would_pool(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, g) = fixture::seed_agent_with_group(&pool, "dedup-writer").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let dup = Uuid::new_v4();
    let hash: Vec<u8> = dup.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'a FALSE-bound duplicate', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(dup)
    .bind(&hash)
    .bind(w)
    .bind(g)
    .execute(&pool)
    .await
    .expect("seed the writer's public duplicate");
    let frame = seed_frame(&pool).await;
    FrameRepository::assign_claim(&pool, dup, frame, Some(1))
        .await
        .expect("bind FALSE");
    store_bba(
        &pool,
        dup,
        frame,
        Some(w),
        None,
        serde_json::json!({"1": 0.6, "0,1": 0.4}),
        "auto_wire",
        None,
    )
    .await;

    let p = pool.clone();
    let act = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let r = ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await;
    let err = act.expect_err("FA07: the act refuses");
    assert!(format!("{err:?}").contains("FA07"), "{err:?}");
    let (current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .expect("dup");
    assert!(current, "nothing was written");
}

/// The repair, pooling only (no edges), as production runs it: the act on the
/// writer's stamped `epigraph_app` session, the repair as `epigraph_maintenance`.
/// The duplicate's frame binding is copied to the canonical even though no edge
/// moved, because pooled rows need it.
#[sqlx::test(migrations = "../../migrations")]
async fn pooling_runs_as_the_maintenance_role_and_binds_the_canonical(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "dup-writer").await;
    let canonical = fixture::seed_group_claim(&pool, w, g, "group canonical").await;
    let dup = fixture::seed_group_claim(&pool, w, g, "group duplicate").await;
    let frame = seed_frame(&pool).await;
    FrameRepository::assign_claim(&pool, dup, frame, Some(0))
        .await
        .expect("bind the duplicate only");
    let row = store_bba(
        &pool,
        dup,
        frame,
        Some(w),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        "auto_wire",
        None,
    )
    .await;
    let p = pool.clone();
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("the act on the writer's session");
        (conn, ())
    })
    .await;
    let repair = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the repair as epigraph_maintenance");
    assert_eq!(repair.pooled_bbas, vec![row]);
    assert_eq!(bba_claim(&pool, row).await, canonical);
    assert_eq!(
        repair.revert.copied_frames,
        vec![frame],
        "pool-only frame copy"
    );
    let bound: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claim_frames WHERE claim_id = $1 AND frame_id = $2)",
    )
    .bind(canonical)
    .bind(frame)
    .fetch_one(&pool)
    .await
    .expect("binding");
    assert!(bound, "the canonical is bound to the pooled row's frame");
}

/// FA07's allowed arm: the same FALSE-bound duplicate with no BBA and no
/// incoming edge has nothing a repair could carry, and the act lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_act_allows_a_false_bound_duplicate_with_nothing_to_pool(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, g) = fixture::seed_agent_with_group(&pool, "dedup-writer").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let dup = Uuid::new_v4();
    let hash: Vec<u8> = dup.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'a FALSE-bound duplicate', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(dup)
    .bind(&hash)
    .bind(w)
    .bind(g)
    .execute(&pool)
    .await
    .expect("seed");
    let frame = seed_frame(&pool).await;
    FrameRepository::assign_claim(&pool, dup, frame, Some(1))
        .await
        .expect("bind FALSE");
    let p = pool.clone();
    let act = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let r = ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await;
    act.expect("nothing to pool or move: FA07 does not apply");
}

/// The compound rule's calibration: a RETRACTED `decomposes_to` out-edge does
/// not make the canonical a compound, so the duplicate's row pools.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_decomposes_to_does_not_make_a_compound(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "once a compound").await;
    let atom = seed_claim(&pool, a, "an atom").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            valid_to) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to', now())",
    )
    .bind(canonical)
    .bind(atom)
    .execute(&pool)
    .await
    .expect("retracted decomposes_to");
    let frame = seed_frame(&pool).await;
    let row = store_bba(
        &pool,
        dup,
        frame,
        Some(a),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        "auto_wire",
        None,
    )
    .await;
    let repair = mark_with_repair(&pool, dup, canonical).await;
    assert!(!repair.canonical_is_compound);
    assert_eq!(repair.pooled_bbas, vec![row]);
}

/// The audience rule's other half: a PUBLIC row pools onto a group-private
/// canonical (narrowing, never widening), as that claim's own row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_duplicates_bba_pools_onto_a_private_canonical_as_its_own(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let canonical = fixture::seed_group_claim(&pool, w, g, "private canonical").await;
    let dup = fixture::seed_public_claim(&pool, w, "public duplicate").await;
    let frame = seed_frame(&pool).await;
    let row = store_bba(
        &pool,
        dup,
        frame,
        Some(w),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        "auto_wire",
        None,
    )
    .await;
    let repair = mark_with_repair(&pool, dup, canonical).await;
    assert_eq!(repair.pooled_bbas, vec![row]);
    let (on, vis, owner, wo): (Uuid, String, Uuid, bool) = sqlx::query_as(
        "SELECT claim_id, visibility::text, owner_group_id, writer_owned \
           FROM mass_functions WHERE id = $1",
    )
    .bind(row)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(
        (on, vis.as_str(), owner, wo),
        (canonical, "group", g, false)
    );
}

/// The identity edge never becomes a belief factor between the pair: it is
/// written after the duplicate is retired, so `auto_create_factor_from_edge`
/// skips it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_identity_edge_creates_no_factor(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    // Calibration: an ordinary same_as between two CURRENT claims does make one.
    let x = seed_claim(&pool, a, "x").await;
    let y = seed_claim(&pool, a, "y").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'same_as')",
    )
    .bind(x)
    .bind(y)
    .execute(&pool)
    .await
    .expect("plain same_as");
    let factors = |pool: PgPool, l: Uuid, r: Uuid| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM factors WHERE $1 = ANY(variable_ids) AND $2 = ANY(variable_ids)",
        )
        .bind(l)
        .bind(r)
        .fetch_one(&pool)
        .await
        .expect("factors")
    };
    assert!(
        factors(pool.clone(), x, y).await > 0,
        "calibration: same_as makes a factor"
    );
    mark_with_repair(&pool, dup, canonical).await;
    assert_eq!(factors(pool.clone(), dup, canonical).await, 0);
}

/// Provenance: `marked_by` is the caller's agent when named (not overwritten
/// by the session principal), and a reason is cut at MAX_REASON_CHARS.
#[sqlx::test(migrations = "../../migrations")]
async fn the_identity_edge_keeps_the_named_agent_and_a_bounded_reason(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let named = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let long = "r".repeat(DuplicateProvenance::MAX_REASON_CHARS + 50);
    let prov = DuplicateProvenance::new("a-tool", "a-rule")
        .marked_by(Some(named))
        .reason(Some(&long));
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
        .bind(a.to_string())
        .execute(&mut *conn)
        .await
        .expect("a different session principal");
    ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &prov,
    )
    .await
    .expect("mark");
    let props: serde_json::Value = sqlx::query_scalar(
        "SELECT properties FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("edge");
    let d = &props["dedup"];
    assert_eq!(d["marked_by"], serde_json::json!(named), "{props}");
    assert_eq!(d["tool"], "a-tool");
    assert_eq!(d["rule"], "a-rule");
    assert_eq!(
        d["reason"].as_str().map(|r| r.chars().count()),
        Some(DuplicateProvenance::MAX_REASON_CHARS)
    );
}

async fn edge_target(pool: &PgPool, edge: Uuid) -> (Uuid, Uuid, bool) {
    sqlx::query_as("SELECT source_id, target_id, valid_to IS NULL FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge row")
}

async fn duplicates_listed_under(pool: &PgPool, canonical: Uuid) -> Vec<Uuid> {
    let viewer = fixture::bypass(pool).await.1;
    ClaimRepository::marked_duplicates_of(pool, &viewer, &[canonical], 50)
        .await
        .expect("index view")
        .rows
        .into_iter()
        .map(|r| r.id)
        .collect()
}

/// Superseding a canonical moves other writers' edges onto its replacement,
/// but not its duplicates' identity edges: each names the claim that
/// duplicate's `supersedes` names, so the un-mark (which looks the edge up by
/// `supersedes`) and the index view (which walks the edges) keep agreeing
/// with the duplicate's own row. Both supersede paths share the migration;
/// this arm runs the request path's act + deferred migration.
#[sqlx::test(migrations = "../../migrations")]
async fn superseding_a_canonical_leaves_its_duplicates_identity_edge(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let supporter = seed_claim(&pool, a, "supporter").await;
    let support = seed_supports_edge(&pool, supporter, canonical).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let r = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark");
    let identity = r.revert.identity_edge.expect("the act's identity edge");

    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(canonical)
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (replacement, _) = ClaimRepository::supersede_act_conn(
        &mut conn,
        ClaimId::from_uuid(canonical),
        "canonical, revised",
        epigraph_core::TruthValue::clamped(0.5),
        "revision",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede act");
    ClaimRepository::migrate_superseded_edges_conn(&mut conn, canonical, replacement)
        .await
        .expect("edge migration");

    assert_eq!(
        edge_target(&pool, support).await,
        (supporter, replacement, true),
        "calibration: an ordinary edge on the canonical moved to its replacement"
    );
    assert_eq!(
        edge_target(&pool, identity).await,
        (dup, canonical, true),
        "the identity edge keeps naming the claim the duplicate supersedes"
    );
    assert!(
        !duplicates_listed_under(&pool, replacement)
            .await
            .contains(&dup),
        "the index view must not list the duplicate under a claim it does not supersede"
    );
    assert!(
        duplicates_listed_under(&pool, canonical)
            .await
            .contains(&dup),
        "the index view lists the duplicate under the claim it supersedes"
    );
    // The un-mark reads the same pointer: it finds the identity edge, and
    // follows the canonical's supersession to its replacement (operator ruling
    // R-11) instead of refusing while the canonical is retired.
    let bypass = fixture::bypass(&pool).await.1;
    let (unmarked, reversal) = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass,
        ClaimId::from_uuid(dup),
        &r.revert,
    )
    .await
    .expect("the un-mark follows the canonical's replacement");
    assert_eq!(unmarked.canonical, canonical, "the claim the mark named");
    assert!(
        reversal.stale_claims.contains(&replacement),
        "the reversal ran against the current canonical: {:?}",
        reversal.stale_claims
    );
    assert!(reversal.drifted.is_empty(), "{:?}", reversal.drifted);
    let (identity_source, identity_target, identity_in_force) = edge_target(&pool, identity).await;
    assert_eq!(
        (identity_source, identity_target, identity_in_force),
        (dup, canonical, false),
        "the un-mark retracts the identity edge it found"
    );
    let dup_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .expect("dup");
    assert!(dup_current, "the duplicate is current again");
}

/// The outgoing direction of the same migration: a claim that was itself a
/// marked duplicate and was un-marked keeps its retracted identity edge (the
/// record that the mark happened) as its source. Superseding that claim later
/// moves its other outgoing edges onto the replacement, never that record.
/// The outgoing UPDATE has no `valid_to` filter, so without the exclusion it
/// would re-source the retracted row.
#[sqlx::test(migrations = "../../migrations")]
async fn superseding_an_unmarked_duplicate_leaves_its_retracted_identity_edge(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let target = seed_claim(&pool, a, "the claim it was once marked onto").await;
    let claim = seed_claim(&pool, a, "a duplicate, un-marked since").await;
    let supported = seed_claim(&pool, a, "supported").await;
    let support = seed_supports_edge(&pool, claim, supported).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let r = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(claim),
        ClaimId::from_uuid(target),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark");
    let identity = r.revert.identity_edge.expect("the act's identity edge");
    let bypass = fixture::bypass(&pool).await.1;
    ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass,
        ClaimId::from_uuid(claim),
        &r.revert,
    )
    .await
    .expect("un-mark");
    assert_eq!(
        edge_target(&pool, identity).await,
        (claim, target, false),
        "calibration: the un-mark retracted the identity edge and left it in place"
    );

    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (replacement, _) = ClaimRepository::supersede_act_conn(
        &mut conn,
        ClaimId::from_uuid(claim),
        "a duplicate, revised",
        epigraph_core::TruthValue::clamped(0.5),
        "revision",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede act");
    ClaimRepository::migrate_superseded_edges_conn(&mut conn, claim, replacement)
        .await
        .expect("edge migration");

    assert_eq!(
        edge_target(&pool, support).await,
        (replacement, supported, true),
        "calibration: an ordinary outgoing edge moved to the replacement"
    );
    assert_eq!(
        edge_target(&pool, identity).await,
        (claim, target, false),
        "the retracted identity edge keeps its source and stays retracted"
    );
}

/// The same for a consolidation of the canonical: the identity edge is
/// neither re-pointed onto the merged claim nor retracted.
#[sqlx::test(migrations = "../../migrations")]
async fn consolidating_a_canonical_leaves_its_duplicates_identity_edge(pool: PgPool) {
    let a = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, a, "canonical").await;
    let other = seed_claim(&pool, a, "another source").await;
    let dup = seed_claim(&pool, a, "duplicate").await;
    let supporter = seed_claim(&pool, a, "supporter").await;
    let support = seed_supports_edge(&pool, supporter, canonical).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let r = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark");
    let identity = r.revert.identity_edge.expect("the act's identity edge");

    let merged = ClaimRepository::consolidate(
        &pool,
        &[canonical, other],
        "the merged claim",
        0.5,
        epigraph_db::ConsolidateMode::Merge,
        "test",
        a,
    )
    .await
    .expect("consolidate")
    .merged_id;

    assert_eq!(
        edge_target(&pool, support).await,
        (supporter, merged, true),
        "calibration: an ordinary edge on the canonical moved to the merged claim"
    );
    assert_eq!(
        edge_target(&pool, identity).await,
        (dup, canonical, true),
        "the identity edge keeps naming the claim the duplicate supersedes, in force"
    );
    assert!(
        !duplicates_listed_under(&pool, merged).await.contains(&dup),
        "the index view must not list the duplicate under the merged claim"
    );
}

/// Supersede `old` through the act, as the supersede routes do (edges carried
/// on); returns the replacement.
async fn supersede_canonical(pool: &PgPool, old: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_one(&mut *conn)
            .await
            .expect("the superseded claim's author");
    let (replacement, _) = ClaimRepository::supersede_act_conn(
        &mut conn,
        ClaimId::from_uuid(old),
        &format!("revised {old} {}", Uuid::new_v4()),
        epigraph_core::TruthValue::clamped(0.5),
        "revision",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await
    .expect("supersede act");
    ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, replacement)
        .await
        .expect("edge migration");
    replacement
}

/// The un-mark's act holds the claims of the canonical's chain against a
/// concurrent retirement until it commits (operator ruling R-11): the reversal
/// re-mints BP factors on the chain's head, so a supersession of the head that
/// committed between the chain read and the reversal would leave factors on a
/// retired claim after its `claims_deactivate_factors` trigger ran. While the
/// act's transaction is open, retiring the head waits (here: times out).
#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_act_holds_the_chain_against_a_concurrent_retirement(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "r11-lock").await;
    let canonical = fixture::seed_public_claim(&pool, a, "r11 lock canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "r11 lock duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark");
    drop(conn);
    let head = supersede_canonical(&pool, canonical).await;
    let retire_head = "UPDATE claims SET is_current = false, embedding = NULL, \
                       embedding_3072 = NULL WHERE id = $1";

    // CALIBRATION: with no un-mark in flight the head can be retired at once.
    let mut other = pool.acquire().await.expect("acquire");
    sqlx::query("SET lock_timeout = '500ms'")
        .execute(&mut *other)
        .await
        .expect("lock_timeout");
    let mut probe = sqlx::Acquire::begin(&mut *other).await.expect("begin");
    sqlx::query(retire_head)
        .bind(head)
        .execute(&mut *probe)
        .await
        .expect("calibration: nothing holds the head");
    probe.rollback().await.expect("rollback");

    let bypass = fixture::bypass(&pool).await.1;
    let mut act = pool.begin().await.expect("begin the act's transaction");
    let unmarked =
        ClaimRepository::unmark_duplicate_act_conn(&mut act, &bypass, ClaimId::from_uuid(dup))
            .await
            .expect("the act follows the chain");
    assert_eq!(unmarked.chain, vec![canonical, head], "calibration");

    let err = sqlx::query(retire_head)
        .bind(head)
        .execute(&mut *other)
        .await
        .expect_err("the head is held until the un-mark commits");
    let code = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some("55P03"),
        "a lock wait, not another refusal: {err}"
    );
    act.rollback().await.expect("rollback the act");
}

/// The un-mark act's refusal of `dup`, as text.
async fn unmark_refusal(pool: &PgPool, dup: Uuid) -> String {
    let bypass = fixture::bypass(pool).await.1;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::unmark_duplicate_act_conn(&mut conn, &bypass, ClaimId::from_uuid(dup))
        .await
        .expect_err("refused")
        .to_string()
}

/// A canonical retired since the mark with NO replacement (deprecated) leaves
/// no current canonical to follow to (operator ruling R-11): the un-mark is
/// refused, saying so, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_over_a_deprecated_canonical_is_refused(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "r11-deprecated").await;
    let canonical = fixture::seed_public_claim(&pool, a, "r11 canonical deprecated since").await;
    let dup = fixture::seed_public_claim(&pool, a, "r11 its duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark");
    drop(conn);
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(canonical)
    .execute(&pool)
    .await
    .expect("deprecate the canonical");

    let e = unmark_refusal(&pool, dup).await;
    assert!(
        e.contains(&format!("supersedes {canonical}"))
            && e.contains("retired with no replacement")
            && e.contains("no current canonical"),
        "{e}"
    );
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!((sup, cur), (Some(canonical), false), "nothing written");
}

/// A canonical with TWO replacements (here a supersession N1, and a
/// consolidation-shaped replacement N2: `C.supersedes = N2` with N2's
/// `supersedes` edge) has no single current canonical: the un-mark refuses to
/// pick one, naming both, and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_over_a_canonical_with_two_replacements_is_refused(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "r11-fork").await;
    let canonical = fixture::seed_public_claim(&pool, a, "r11 forked canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "r11 its duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark");
    drop(conn);
    let n1 = supersede_canonical(&pool, canonical).await;
    let n2 = fixture::seed_public_claim(&pool, a, "r11 a second replacement").await;
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(n2)
        .bind(canonical)
        .execute(&pool)
        .await
        .expect("C points at N2, as a consolidation source does");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supersedes')",
    )
    .bind(n2)
    .bind(canonical)
    .execute(&pool)
    .await
    .expect("N2's supersedes edge");

    let e = unmark_refusal(&pool, dup).await;
    assert!(
        e.contains("has 2 replacements")
            && e.contains(&n1.to_string())
            && e.contains(&n2.to_string())
            && e.contains("refusing to pick"),
        "{e}"
    );
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!((sup, cur), (Some(canonical), false), "nothing written");
}
