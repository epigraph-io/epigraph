//! MCP `submit_ds_evidence` honours `EPIGRAPH_COMPOUND_WRITE_GUARD`
//! (backlog 7435772c, SPEC §4.1 W3). Its masses carry no evidence text, so on
//! a COMPOUND (a claim with an in-force `decomposes_to` out-edge) they could
//! never be attributed to the compound's atoms:
//!
//! - `refuse`: the call is refused with `invalid_params`, `data.error =
//!   compound_target` and the atoms the caller can see, and NOTHING is
//!   written (no BBA, no frame assignment, no Beta update, no divergence
//!   row, the claim row untouched);
//! - `warn`: the BBA is stored, the response carries
//!   `deprecated_compound_target` with the visible atoms and a warning, and
//!   the compound's cached belief is not moved, neither by the call nor by a
//!   later owner-rule recompute;
//! - an atom target is written as before, in either mode, with no field.
//!
//! The server's mode is set with `with_compound_write_guard`, so both modes
//! run in one process. The app-role half of the role decision (a compound
//! whose decomposition the caller cannot see) is pinned in
//! `epigraph-engine/tests/compound_write_guard_app_role.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_engine::belief_modes::CompoundWriteGuard;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::SubmitDsEvidenceParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool, guard: CompoundWriteGuard) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x74u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_compound_write_guard(guard)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), '7435772c-author', 'system', \
                 ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn insert_claim(pool: &PgPool, agent: Uuid, what: &str) -> Uuid {
    let content = format!("7435772c mcp {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(&content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to");
}

/// A compound with two atoms: `(compound, [atom_a, atom_b])`, the atoms
/// sorted by id (the order `visible_atoms` lists them in).
async fn compound_with_atoms(pool: &PgPool, agent: Uuid) -> (Uuid, Vec<Uuid>) {
    let compound = insert_claim(pool, agent, "compound").await;
    let mut atoms = vec![
        insert_claim(pool, agent, "atom a").await,
        insert_claim(pool, agent, "atom b").await,
    ];
    for a in &atoms {
        decomposes_to(pool, compound, *a).await;
    }
    atoms.sort();
    (compound, atoms)
}

fn params(claim: Uuid, frame: Uuid) -> SubmitDsEvidenceParams {
    serde_json::from_value(serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
    }))
    .expect("params")
}

/// Everything a `submit_ds_evidence` call can write for `claim`: its BBA
/// rows, its frame assignments, its divergence rows, and its whole claims
/// row (belief cache and Beta parameters included).
async fn footprint(pool: &PgPool, claim: Uuid) -> (i64, i64, i64, Value) {
    let count = |table: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT count(*) FROM {table} WHERE claim_id = $1"
            ))
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count")
        }
    };
    let row: Value =
        sqlx::query_scalar("SELECT to_jsonb(c) - 'updated_at' FROM claims c WHERE c.id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("claims row");
    (
        count("mass_functions").await,
        count("claim_frames").await,
        count("ds_bayesian_divergence").await,
        row,
    )
}

/// A cache no fold of the submitted BBA produces, recorded on `frame`.
async fn sentinel_cache(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                belief_frame_id = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
}

async fn cache(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<Uuid>) {
    sqlx::query_as("SELECT belief, pignistic_prob, belief_frame_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

#[sqlx::test(migrations = "../../migrations")]
async fn refuse_refuses_a_compound_and_writes_nothing_but_an_atom_is_unchanged(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone(), CompoundWriteGuard::Refuse).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();
    let author = seed_agent(&pool).await;
    let (compound, atoms) = compound_with_atoms(&pool, author).await;

    let before = footprint(&pool, compound).await;
    let err = tools::ds::submit_ds_evidence(&server, &viewer, params(compound, frame), None)
        .await
        .expect_err("refuse must refuse a textless BBA on a compound");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(
        err.message.contains("is a compound") && err.message.contains("nothing was written"),
        "{err:?}"
    );
    let data = err.data.clone().expect("a machine-keyed refusal body");
    assert_eq!(data["error"], "compound_target", "{data}");
    assert_eq!(data["claim_id"], compound.to_string(), "{data}");
    assert_eq!(data["flag"], "EPIGRAPH_COMPOUND_WRITE_GUARD", "{data}");
    let listed: Vec<String> = data["visible_atoms"]
        .as_array()
        .expect("visible_atoms")
        .iter()
        .map(|a| a["id"].as_str().expect("atom id").to_string())
        .collect();
    assert_eq!(
        listed,
        atoms.iter().map(Uuid::to_string).collect::<Vec<_>>(),
        "{data}"
    );
    assert_eq!(
        footprint(&pool, compound).await,
        before,
        "a refused write must leave no BBA, frame assignment, divergence row or claim-row \
         change"
    );

    // An atom of the same compound is not guarded: written as before.
    let atom = atoms[0];
    let ok = first_text(
        &tools::ds::submit_ds_evidence(&server, &viewer, params(atom, frame), None)
            .await
            .expect("an atom target is accepted under refuse"),
    );
    assert!(ok.get("deprecated_compound_target").is_none(), "{ok}");
    let (bbas, _, _, _) = footprint(&pool, atom).await;
    assert_eq!(bbas, 1, "the atom's BBA is stored");
}

#[sqlx::test(migrations = "../../migrations")]
async fn warn_stores_the_bba_inert_and_tells_the_caller_where_to_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone(), CompoundWriteGuard::Warn).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();
    let author = seed_agent(&pool).await;
    let (compound, atoms) = compound_with_atoms(&pool, author).await;
    sentinel_cache(&pool, compound, frame).await;
    let cache_before = cache(&pool, compound).await;

    let resp = first_text(
        &tools::ds::submit_ds_evidence(&server, &viewer, params(compound, frame), None)
            .await
            .expect("warn accepts a textless BBA on a compound"),
    );
    let target = resp
        .get("deprecated_compound_target")
        .unwrap_or_else(|| panic!("warn must report the compound target: {resp}"));
    assert_eq!(target["claim_id"], compound.to_string(), "{resp}");
    assert_eq!(target["guard"], "warn", "{resp}");
    assert_eq!(target["visible_atom_count"], 2, "{resp}");
    let listed: Vec<String> = target["visible_atoms"]
        .as_array()
        .expect("visible_atoms")
        .iter()
        .map(|a| a["id"].as_str().expect("atom id").to_string())
        .collect();
    assert_eq!(
        listed,
        atoms.iter().map(Uuid::to_string).collect::<Vec<_>>(),
        "{resp}"
    );
    assert!(
        resp["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.contains("is a compound")
                && w.contains("never folded into the compound's cached belief"))),
        "{resp}"
    );
    let (bbas, _, _, _) = footprint(&pool, compound).await;
    assert_eq!(bbas, 1, "warn stores the BBA");

    // Inert: the compound's cache did not move, and a later owner-rule
    // recompute (the one every bulk and per-request refresh resolves through)
    // does not fold the stored row into it either.
    assert_eq!(cache(&pool, compound).await, cache_before);
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, &viewer, compound)
        .await
        .expect("owner-rule recompute");
    drop(conn);
    assert_eq!(
        cache(&pool, compound).await,
        cache_before,
        "no cache fold of the compound may read the warn-mode row"
    );

    // A non-compound under warn carries no field.
    let atom_resp = first_text(
        &tools::ds::submit_ds_evidence(&server, &viewer, params(atoms[1], frame), None)
            .await
            .expect("atom submit"),
    );
    assert!(
        atom_resp.get("deprecated_compound_target").is_none(),
        "{atom_resp}"
    );
}
