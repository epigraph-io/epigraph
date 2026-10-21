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
//! The arms run on the harness connection (the superuser, so the session is
//! privileged and the act and the repair run in one transaction, as the
//! semantic-duplicate sweep runs them). The tenancy arms of the same
//! behaviour, on `epigraph_app` and `epigraph_maintenance`, are below them.

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
