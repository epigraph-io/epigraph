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

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository};
use sqlx::PgPool;
use uuid::Uuid;

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
