//! PR-21 — the seal ceremony over its own HTTP surface.
//!
//! `crates/epigraph-db/tests/seal_side_channels.rs` is where the §6.5.4 TCB
//! mutation is measured, corpus-wide, against a `pg_dump`. This file measures
//! the other half: the ROUTE contract — who may ask for a manifest, what a
//! commit must contain, and what happens when it does not contain it.
//!
//! # It plays the client, because there is no other way to test this
//!
//! Seal is client-driven and the server holds no key, so an end-to-end test has
//! to derive an epoch key, pad, and produce field-tagged ciphertext exactly as
//! `epigraph-privatize` does. It uses `epigraph-privacy` rather than
//! hand-rolled bytes for the reason the CLI's own tests give: hand-rolled bytes
//! would assert this file's idea of the wire format instead of the one the tool
//! writes.

#[path = "privatization_fixture.rs"]
mod fx;

use epigraph_api::errors::ApiError;
use epigraph_api::routes::privatization as routes;
use epigraph_crypto::EncryptedPayload;
use epigraph_privacy::{decrypt_content, encrypt_content, encryptor::FieldTag, pad, unpad};
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

use base64::Engine as _;

/// The base key the fixture stands in for a KMS handle with.
const BASE_KEY: [u8; 32] = [0x7c; 32];

/// The bucket every plan here is created at.
const PAD_TO: u32 = 256;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Promote the fixture's target group to a keyed `team` with an active epoch.
///
/// Migration 081's plan guard refuses `mode='seal'` against anything else, and
/// `groups_public_key_shape` requires 32 bytes on a keyed group. Done here
/// rather than in `World::seed` because every other test in this slice is about
/// `restrict` and must keep exercising the ordinary shape.
async fn make_keyed(pool: &PgPool, group: Uuid) {
    sqlx::query(
        "UPDATE groups SET kind = 'team', public_key = decode(repeat('ab', 32), 'hex') \
          WHERE id = $1",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("promote the target group");
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the active key epoch");
}

/// A claim owned by the seal target, with one version and one evidence row.
async fn seed_subject(pool: &PgPool, world: &fx::World, content: &str) -> Uuid {
    let claim = viewer_fixture::seed_public_claim(pool, world.actor, content).await;
    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         SELECT $1, 1, $2, 0.8, $3, c.visibility, c.owner_group_id \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(content)
    .bind(world.actor)
    .execute(pool)
    .await
    .expect("seed a version");
    let evidence = viewer_fixture::seed_evidence(pool, claim, "document").await;
    sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
        .bind(evidence)
        .bind(content)
        .execute(pool)
        .await
        .expect("give the evidence plaintext");
    claim
}

/// Create a `seal` plan through the ROUTE and apply it.
///
/// Through the route, because "the route no longer answers 501 for
/// `mode='seal'`" is one of the things this file is here to assert, and a plan
/// persisted through the repository would prove nothing about it.
async fn applied_seal_plan(pool: &PgPool, world: &fx::World, seeds: &[Uuid]) -> Uuid {
    let state = fx::split_state(pool).await;
    let auth = fx::auth_for(world.actor);

    let (status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(auth.clone())),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: seeds.to_vec(),
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(i32::try_from(PAD_TO).unwrap()),
        }),
    )
    .await
    .expect("create a seal plan");
    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert_eq!(preview.0.mode, "seal");
    // §6.5.4 requires the preview to say what a seal destroys BEFORE the admin
    // clicks. A seal plan whose side_effects block is silent about the deleted
    // extractions is a consent the operator did not give.
    let effects = &preview.0.side_effects;
    assert!(
        effects
            .destroys_derived_rows
            .is_some_and(|t| t.contains(&"entity_mentions")),
        "the seal preview must name the derived tables it destroys"
    );
    assert!(effects.unrecoverable.is_some());
    assert!(effects.reversibility.is_some());

    let plan = preview.0.plan_id;
    let scoped = fx::scoped(pool).await;
    let correlation = fx::dispatch(pool, world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply the restrict pass");
    assert_eq!(
        fx::plan_state(pool, plan).await,
        "applied",
        "restrict first, then seal: 081 refuses to seal a still-public claim"
    );
    plan
}

/// Fetch a manifest page and turn it into a commit body.
///
/// This is `epigraph-privatize seal`, inlined.
async fn seal_body(manifest: &routes::SealManifest) -> routes::SealCommitRequest {
    let epoch = u32::try_from(manifest.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let pad_to = u32::try_from(manifest.pad_to).unwrap();

    let seal = |plaintext: &[u8], id: Uuid, tag: FieldTag| -> Vec<u8> {
        let padded = pad(plaintext, pad_to).expect("pad");
        encrypt_content(&padded, &epoch_key, id, epoch, tag)
            .expect("encrypt")
            .to_bytes()
    };

    routes::SealCommitRequest {
        manifest_digest: manifest.manifest_digest.clone(),
        items: manifest
            .items
            .iter()
            .map(|item| {
                let content_ct = seal(item.content.as_bytes(), item.claim_id, FieldTag::Content);
                routes::SealCommitEntry {
                    claim_id: item.claim_id,
                    content_hash_b64: b64(blake3::hash(&content_ct).as_bytes()),
                    content_ct_b64: b64(&content_ct),
                    labels_ct_b64: b64(&seal(
                        serde_json::to_vec(&item.labels).unwrap().as_slice(),
                        item.claim_id,
                        FieldTag::Labels,
                    )),
                    properties_ct_b64: b64(&seal(
                        serde_json::to_vec(&item.properties).unwrap().as_slice(),
                        item.claim_id,
                        FieldTag::Properties,
                    )),
                    versions: item
                        .versions
                        .iter()
                        .map(|v| routes::CommitVersion {
                            id: v.id,
                            ct_b64: b64(&seal(
                                v.content.as_bytes(),
                                v.id,
                                FieldTag::VersionContent,
                            )),
                        })
                        .collect(),
                    evidence: item
                        .evidence
                        .iter()
                        .map(|e| routes::CommitEvidence {
                            id: e.id,
                            ct_b64: b64(&seal(
                                serde_json::to_vec(&e.raw_content).unwrap().as_slice(),
                                e.id,
                                FieldTag::EvidenceContent,
                            )),
                            props_ct_b64: b64(&seal(
                                serde_json::to_vec(&e.properties).unwrap().as_slice(),
                                e.id,
                                FieldTag::EvidenceProperties,
                            )),
                        })
                        .collect(),
                }
            })
            .collect(),
    }
}

async fn fetch_seal_manifest(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
) -> Result<routes::SealManifest, ApiError> {
    let state = fx::split_state(pool).await;
    routes::seal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery {
            cursor: None,
            limit: None,
        }),
    )
    .await
    .map(|json| json.0)
}

async fn post_seal_commit(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    body: routes::SealCommitRequest,
) -> Result<routes::CommitResponse, ApiError> {
    let state = fx::split_state(pool).await;
    routes::seal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(body),
    )
    .await
    .map(|json| json.0)
}

// =========================================================================

/// The whole ceremony, both directions, through the routes.
#[sqlx::test(migrations = "../../migrations")]
async fn the_seal_ceremony_round_trips_through_its_own_routes(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a confidential result about a catalyst";
    let claim = seed_subject(&pool, &world, plaintext).await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    // --- seal ---
    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    assert_eq!(manifest.items.len(), 1);
    assert_eq!(
        manifest.items[0].content, plaintext,
        "the manifest is the one response that carries plaintext, and it must carry the WHOLE \
         plaintext or the commit that follows it seals a subset"
    );
    assert_eq!(manifest.items[0].versions.len(), 1);
    assert_eq!(manifest.items[0].evidence.len(), 1);
    assert_eq!(manifest.pad_to, i32::try_from(PAD_TO).unwrap());

    let body = seal_body(&manifest).await;
    let resp = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect("seal commit");
    assert_eq!(resp.committed, 1);
    assert_eq!(resp.already_done, 0);

    let sealed_content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read the sealed claim");
    assert_eq!(sealed_content, format!("[sealed:x{}]", claim.simple()));

    // The manifest read is DUAL-LOGGED — §6.5.6 requires both, and neither
    // substitutes for the other: `security_events` is principal-keyed and
    // `privatization_audit` is plan-keyed.
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'plan.seal_manifest' \
           AND agent_id = $1",
    )
    .bind(world.actor)
    .fetch_one(&pool)
    .await
    .expect("count security events");
    assert_eq!(events, 1);
    let actions = fx::audit_actions(&pool, plan).await;
    assert!(actions.contains(&"plan.seal_manifest".to_string()));
    assert!(actions.contains(&"item.seal".to_string()));

    // --- unseal ---
    let state = fx::split_state(&pool).await;
    let unseal = routes::unseal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery {
            cursor: None,
            limit: None,
        }),
    )
    .await
    .expect("unseal manifest")
    .0;
    assert_eq!(unseal.items.len(), 1);

    let entry = &unseal.items[0];
    let epoch = u32::try_from(entry.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let open = |ct_b64: &str, id: Uuid, tag: FieldTag| -> Vec<u8> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .expect("base64");
        let payload = EncryptedPayload::from_bytes(&bytes).expect("payload");
        let padded = decrypt_content(&payload, &epoch_key, id, epoch, tag).expect("decrypt");
        unpad(&padded, u32::try_from(entry.pad_to).unwrap()).expect("unpad")
    };

    let recovered = String::from_utf8(open(
        &entry.content_ct_b64,
        entry.claim_id,
        FieldTag::Content,
    ))
    .unwrap();
    assert_eq!(
        recovered, plaintext,
        "the ceremony must round-trip the plaintext, or the seal is a delete"
    );

    let commit = routes::UnsealCommitRequest {
        items: vec![routes::UnsealCommitEntry {
            claim_id: entry.claim_id,
            content_hash_b64: b64(blake3::hash(recovered.as_bytes()).as_bytes()),
            content: recovered.clone(),
            labels: serde_json::from_slice(&open(
                entry.labels_ct_b64.as_deref().unwrap(),
                entry.claim_id,
                FieldTag::Labels,
            ))
            .unwrap(),
            properties: serde_json::from_slice(&open(
                entry.properties_ct_b64.as_deref().unwrap(),
                entry.claim_id,
                FieldTag::Properties,
            ))
            .unwrap(),
            versions: entry
                .versions
                .iter()
                .map(|v| routes::UnsealCommitVersionEntry {
                    id: v.id,
                    content: String::from_utf8(open(&v.ct_b64, v.id, FieldTag::VersionContent))
                        .unwrap(),
                })
                .collect(),
            evidence: entry
                .evidence
                .iter()
                .map(|e| routes::UnsealCommitEvidenceEntry {
                    id: e.id,
                    raw_content: serde_json::from_slice(&open(
                        &e.ct_b64,
                        e.id,
                        FieldTag::EvidenceContent,
                    ))
                    .unwrap(),
                    properties: serde_json::from_slice(&open(
                        &e.props_ct_b64,
                        e.id,
                        FieldTag::EvidenceProperties,
                    ))
                    .unwrap(),
                })
                .collect(),
        }],
    };

    let resp = routes::unseal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(commit),
    )
    .await
    .expect("unseal commit")
    .0;
    assert_eq!(resp.committed, 1);

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the unsealed claim");
    assert_eq!(content, plaintext);
    assert_eq!(ciphertext_rows, 0);

    // ops F14: the vector was destroyed by the seal, so unseal must ASK for it
    // back rather than leaving the claim to the un-prioritised backfill.
    //
    // THE PAYLOAD IS EXTERNALLY TAGGED. `EpiGraphJob` carries no serde tag
    // attribute, so `EmbeddingGeneration { claim_id }` serialises as
    // `{"EmbeddingGeneration": {"claim_id": "…"}}` and NOT as a flat object with
    // a top-level `claim_id`. FINAL-PLAN §6.5.4's audit clause reads
    // `payload->>'claim_id'`, which matches nothing on that shape; the CLAUDE.md
    // clause is written against the real one and this assertion is what pins the
    // two together.
    let jobs: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM jobs WHERE job_type = 'embedding_generation' \
           AND payload #>> '{EmbeddingGeneration,claim_id}' = $1::text",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("read embedding jobs");
    assert_eq!(
        jobs.len(),
        1,
        "unseal-commit enqueues one embedding job per claim; jobs = {jobs:?}"
    );
}

/// A commit that omits a TCB member is refused, and NOTHING is sealed.
///
/// The second half is the assertion that matters: §6.5.4's indictment of the
/// previous revision is not that it refused badly, it is that it succeeded
/// partially.
#[sqlx::test(migrations = "../../migrations")]
async fn a_commit_missing_a_tcb_member_is_refused_and_seals_nothing(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a subject with a version the commit will forget";
    let claim = seed_subject(&pool, &world, plaintext).await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    let mut body = seal_body(&manifest).await;
    assert_eq!(body.items[0].versions.len(), 1);
    body.items[0].versions.clear();

    let err = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect_err("a commit missing a claim_versions row must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("claim_versions")),
        "expected a refusal naming the uncovered table, got {err:?}"
    );

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the claim");
    assert_eq!(
        content, plaintext,
        "a refused commit must leave the plaintext exactly as it was; a partially applied seal \
         reports success over a row that is still readable"
    );
    assert_eq!(ciphertext_rows, 0);
}

/// A stale manifest digest is a 409, and it is stale because the TCB GREW.
///
/// This is the whole reason the digest is recomputed from the database rather
/// than compared against the manifest the server served: a version row inserted
/// after the manifest would otherwise keep its plaintext through a commit that
/// called itself complete.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_added_after_the_manifest_makes_the_commit_stale(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "a subject that grows a version").await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    let body = seal_body(&manifest).await;

    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         SELECT $1, 2, 'a later revision', 0.8, $2, c.visibility, c.owner_group_id \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(world.actor)
    .execute(&pool)
    .await
    .expect("insert a late version");

    let err = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect_err("a commit against a TCB that has moved must be refused");
    assert!(
        matches!(&err, ApiError::Conflict { .. }),
        "expected a 409, got {err:?}"
    );

    let ciphertext_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(ciphertext_rows, 0);
}

/// `mode='seal'` with `pad_to = 0` is a 400 at the route, not a 500 from a
/// CHECK.
///
/// Migration 080's `pp_seal_needs_pad` is the real control and it is applied and
/// frozen; this asserts the route answers before the database has to, which is
/// also what settles §6.5.4's "`pad_to = 0` requires an explicit override":
/// there is no override to build.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unpadded_seal_is_refused_with_a_sentence(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "unpadded subject").await;
    let state = fx::split_state(&pool).await;

    let err = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: vec![claim],
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(0),
        }),
    )
    .await
    .expect_err("mode=seal with pad_to=0 must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("pad_to")),
        "expected a 400 naming pad_to, got {err:?}"
    );
}

/// A manifest is refused before the plan has been applied.
///
/// Restrict first, then seal. Migration 081's `claim_encryption_no_public_sealed`
/// is the backstop and raises `42501`; this asserts the surface refuses earlier,
/// with a sentence, and — the part that matters — that it refuses on the PLAN's
/// state rather than discovering the problem one row at a time.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_manifest_is_refused_before_the_plan_is_applied(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "not yet restricted").await;
    let state = fx::split_state(&pool).await;

    let (_status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: vec![claim],
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(i32::try_from(PAD_TO).unwrap()),
        }),
    )
    .await
    .expect("create the plan");

    let err = fetch_seal_manifest(&pool, &world, preview.0.plan_id)
        .await
        .expect_err("a manifest for a plan that has not been applied must be refused");
    assert!(
        matches!(&err, ApiError::Conflict { reason } if reason.contains("applied")),
        "expected a 409 about the plan's state, got {err:?}"
    );

    // CALIBRATION: the claim really is still public, so the refusal is about
    // the ordering and not about an empty plan.
    let visibility: String = sqlx::query_scalar("SELECT visibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read visibility");
    assert_eq!(visibility, "public");
}

/// Seal a whole plan through the routes, and assert it sealed everything.
async fn seal_through_routes(pool: &PgPool, world: &fx::World, plan: Uuid, expect: usize) {
    let manifest = fetch_seal_manifest(pool, world, plan)
        .await
        .expect("seal manifest");
    assert_eq!(manifest.items.len(), expect);
    let body = seal_body(&manifest).await;
    let resp = post_seal_commit(pool, world, plan, body)
        .await
        .expect("seal commit");
    assert_eq!(resp.committed, expect);
}

/// One page of a plan's unseal manifest, through the route.
async fn fetch_unseal_manifest(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
) -> routes::UnsealManifest {
    let state = fx::split_state(pool).await;
    routes::unseal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery {
            cursor: None,
            limit: None,
        }),
    )
    .await
    .expect("unseal manifest")
    .0
}

/// The client's half of unseal: decrypt one manifest entry into a commit entry.
fn unseal_entry(entry: &routes::UnsealManifestEntry) -> routes::UnsealCommitEntry {
    let epoch = u32::try_from(entry.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let pad_to = u32::try_from(entry.pad_to).unwrap();
    let open = |ct_b64: &str, id: Uuid, tag: FieldTag| -> Vec<u8> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .expect("base64");
        let payload = EncryptedPayload::from_bytes(&bytes).expect("payload");
        let padded = decrypt_content(&payload, &epoch_key, id, epoch, tag).expect("decrypt");
        unpad(&padded, pad_to).expect("unpad")
    };
    let content = String::from_utf8(open(
        &entry.content_ct_b64,
        entry.claim_id,
        FieldTag::Content,
    ))
    .unwrap();
    routes::UnsealCommitEntry {
        claim_id: entry.claim_id,
        content_hash_b64: b64(blake3::hash(content.as_bytes()).as_bytes()),
        content,
        labels: serde_json::from_slice(&open(
            entry.labels_ct_b64.as_deref().unwrap(),
            entry.claim_id,
            FieldTag::Labels,
        ))
        .unwrap(),
        properties: serde_json::from_slice(&open(
            entry.properties_ct_b64.as_deref().unwrap(),
            entry.claim_id,
            FieldTag::Properties,
        ))
        .unwrap(),
        versions: entry
            .versions
            .iter()
            .map(|v| routes::UnsealCommitVersionEntry {
                id: v.id,
                content: String::from_utf8(open(&v.ct_b64, v.id, FieldTag::VersionContent))
                    .unwrap(),
            })
            .collect(),
        evidence: entry
            .evidence
            .iter()
            .map(|e| routes::UnsealCommitEvidenceEntry {
                id: e.id,
                raw_content: serde_json::from_slice(&open(
                    &e.ct_b64,
                    e.id,
                    FieldTag::EvidenceContent,
                ))
                .unwrap(),
                properties: serde_json::from_slice(&open(
                    &e.props_ct_b64,
                    e.id,
                    FieldTag::EvidenceProperties,
                ))
                .unwrap(),
            })
            .collect(),
    }
}

async fn post_unseal_commit(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    body: routes::UnsealCommitRequest,
) -> Result<routes::CommitResponse, ApiError> {
    let state = fx::split_state(pool).await;
    routes::unseal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(body),
    )
    .await
    .map(|json| json.0)
}

/// An unseal-commit may only name claims its own plan froze.
///
/// The authority §6.6 grants is over the plan's TARGET GROUP, so the set of rows
/// a commit may mutate has to be the set that authority was granted over. The
/// seal direction has always checked it; this asserts the reverse direction does
/// too, because an unseal writes CALLER-SUPPLIED plaintext and then drops the
/// ciphertext — and the server holds no key with which to tell the supplied
/// plaintext from any other string.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unseal_commit_is_scoped_to_its_own_plan(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;

    let mine = seed_subject(&pool, &world, "the claim this plan froze").await;
    let theirs = seed_subject(&pool, &world, "a claim another ceremony sealed").await;

    let my_plan = applied_seal_plan(&pool, &world, &[mine]).await;
    seal_through_routes(&pool, &world, my_plan, 1).await;
    let other_plan = applied_seal_plan(&pool, &world, &[theirs]).await;
    seal_through_routes(&pool, &world, other_plan, 1).await;

    let sentinel = format!("[sealed:x{}]", theirs.simple());
    let injected = routes::UnsealCommitRequest {
        items: vec![routes::UnsealCommitEntry {
            claim_id: theirs,
            content_hash_b64: b64(blake3::hash(b"substituted").as_bytes()),
            content: "substituted".to_string(),
            labels: Vec::new(),
            properties: serde_json::json!({}),
            versions: Vec::new(),
            evidence: Vec::new(),
        }],
    };
    let err = post_unseal_commit(&pool, &world, my_plan, injected)
        .await
        .expect_err("an unseal-commit naming a claim outside its plan must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("not items of plan")),
        "expected a refusal naming the plan, got {err:?}"
    );

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(theirs)
    .fetch_one(&pool)
    .await
    .expect("read the other plan's claim");
    assert_eq!(
        content, sentinel,
        "a refused unseal must leave the other plan's claim exactly as it was"
    );
    assert_eq!(
        ciphertext_rows, 1,
        "the ciphertext is the only remaining copy of that plaintext; a refused commit must not \
         delete it"
    );
}

/// An unseal-commit that omits a sealed row is refused, and the ciphertext lives.
///
/// The mirror of `a_commit_missing_a_tcb_member_is_refused_and_seals_nothing`,
/// and the stakes are higher in this direction: the seal already destroyed the
/// plaintext, so a version row whose ciphertext is dropped without its plaintext
/// being restored is unrecoverable by anyone, key-holder included.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unseal_commit_that_omits_a_sealed_row_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "a subject whose version the unseal forgets").await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;
    seal_through_routes(&pool, &world, plan, 1).await;

    let manifest = fetch_unseal_manifest(&pool, &world, plan).await;
    assert_eq!(manifest.items.len(), 1);
    let mut entry = unseal_entry(&manifest.items[0]);
    assert_eq!(entry.versions.len(), 1);
    entry.versions.clear();

    let err = post_unseal_commit(
        &pool,
        &world,
        plan,
        routes::UnsealCommitRequest { items: vec![entry] },
    )
    .await
    .expect_err("an unseal-commit that leaves a ciphertext row uncovered must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message }
                 if message.contains("claim_version_encryption")),
        "expected a refusal naming the uncovered table, got {err:?}"
    );

    let (versions, heads): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM claim_version_encryption WHERE claim_id = $1), \
                (SELECT count(*) FROM claim_encryption WHERE claim_id = $1)",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count ciphertext rows");
    assert_eq!(
        (versions, heads),
        (1, 1),
        "a refused unseal must leave every ciphertext row in place"
    );
    let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read the claim");
    assert_eq!(content, format!("[sealed:x{}]", claim.simple()));
}

/// The preview's list and the mutation's list are the SAME set.
///
/// `routes::SEAL_DESTROYS` is what the operator is told a seal destroys;
/// `epigraph_db::repos::privatization::SEAL_DELETE_TABLES` is what it actually
/// deletes. They are deliberately two constants — one is a consent surface and
/// the other is a statement — and this is what keeps them honest. A table added
/// to the mutation without being added to the preview is a seal that destroys
/// something the admin was not warned about; the reverse is a warning about a
/// loss that does not happen.
#[test]
fn the_preview_names_exactly_the_tables_the_seal_deletes() {
    let told: std::collections::BTreeSet<&str> = routes::SEAL_DESTROYS.iter().copied().collect();
    let done: std::collections::BTreeSet<&str> =
        epigraph_db::repos::privatization::SEAL_DELETE_TABLES
            .iter()
            .copied()
            .collect();
    assert_eq!(
        told, done,
        "the seal preview's destroyed-table list and the seal mutation's DELETE list disagree"
    );
    assert!(
        told.len() >= 6,
        "the list shrank to {}; a seal that stopped deleting a derived extraction would pass a \
         set-equality check while leaving plaintext behind",
        told.len()
    );
}
