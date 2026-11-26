//! Migration 349 (backlog b62ae3f2): the database, not only the ingest
//! writers, refuses a verbatim source passage in `evidence.raw_content` for a
//! paper whose licence does not permit retention.
//!
//! Before 349 the licence gate lived only in Rust
//! (`epigraph_ingest::common::licence::passage_retention_permitted`, applied by
//! `literature_evidence_body` and the `ingest_literature` CLI). Migration 255
//! made `papers.licence` operator-only, but any holder of the application DSN,
//! or a request-path bug (`POST /api/v1/evidence` and `/api/v1/submit` store
//! whatever body a client sends), could still write publisher text straight
//! into a literature or figure evidence row, and nothing refused it.
//!
//! Every write under test runs on an `epigraph_app` pool stamped (session
//! scope) as a seeded agent writing its own group, the way `ScopedPool`
//! stamps a request. Fixtures (papers, licences, claims) are seeded on the
//! superuser pool.
//!
//! The accepted bodies are built by the PRODUCTION writer
//! (`literature_evidence_body`), so the SQL shape the guard admits cannot
//! drift from what ingest writes without a test here failing.
//!
//! # Verified to fail
//!
//! Without migration 349, 7 of the 8 tests fail (measured). Every refusal
//! test fails (the write succeeds); `a_permitting_licence_admits_the_passage`
//! fails at its case-differing suffix (`10.5555/guard.case`, which nothing
//! then refuses);
//! `a_stored_passage_stays_writable_and_strippable_after_its_licence_is_withdrawn`
//! fails at its "still refused" check; and
//! `the_sql_allowlist_matches_the_rust_allowlist` fails (the SQL function does
//! not exist). Only `the_locator_and_hash_bodies_are_accepted_whatever_the_licence`
//! passes with or without it.
//! Each mutation of 349 alone fails the test named (measured):
//!
//! * the unseal arm removed: the withdrawn-licence test, at the unseal;
//! * the `Passage: '` check removed: the refusal test, at the passage carried
//!   inside a locator;
//! * the figure caption ignored: the figure test, at the caption;
//! * the update trigger not firing on a caption change: the rewrite test, at
//!   the caption set on a figure stored with neither image nor caption;
//! * the guard made SECURITY DEFINER (it then reads every group's papers):
//!   `another_groups_paper_licence_permits_nothing`;
//! * the update trigger not firing on a DOI change: the rewrite test, at the
//!   re-pointed DOI;
//! * the `-NC` / `-ND` / `-SA` port exclusion dropped from the SQL allowlist:
//!   the parity test, at `CC-BY-3.0-NC`;
//! * the case-variant arm removed: `a_permitting_licence_admits_the_passage`,
//!   at the `HTTPS://DOI.ORG/...`-keyed paper;
//! * that arm's exact-suffix condition removed: the same test, at the DOI
//!   whose suffix differs in case.
//!
//! `another_groups_paper_licence_permits_nothing` also writes as the owning
//! group, whose passage is admitted, so its refusal is not merely "no group
//! paper row is readable by anyone".

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::ContentHasher;
use epigraph_ingest::common::plan::PlannedClaim;
use epigraph_mcp::tools::ingestion::{literature_evidence_body, passage_retention_permitted};
use sqlx::PgPool;
use uuid::Uuid;

const TITLE: &str = "A Paywalled Study (2024)";
const PASSAGE: &str = "Publisher prose that must not be republished in an evidence row, verbatim.";

/// An `epigraph_app` pool stamped, for the whole session, as a seeded agent
/// that reads and writes its own group (the five GUCs `ScopedPool` stamps).
/// Returns the pool, the agent and its group.
async fn app_pool(pool: &PgPool, label: &str) -> (PgPool, Uuid, Uuid) {
    let (agent, group) = fixture::seed_agent_with_group(pool, label).await;
    (stamped_app_pool(pool, agent, group).await, agent, group)
}

/// An `epigraph_app` pool stamped as `agent` reading and writing `group`.
async fn stamped_app_pool(pool: &PgPool, agent: Uuid, group: Uuid) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query(
                    "SELECT set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $1, false), \
                            set_config('epigraph.principal_id', $2, false), \
                            set_config('epigraph.elevation_id', '', false), \
                            set_config('epigraph.family_id', '', false)",
                )
                .bind(group.to_string())
                .bind(agent.to_string())
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("stamped app pool")
}

/// A public `papers` row for `doi` (246's tenancy declared), with `licence`
/// written on the superuser pool, standing in for the operator definer.
async fn seed_paper(pool: &PgPool, doi: &str, licence: Option<&str>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO papers (doi, title, licence, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 'public', '00000000-0000-0000-0000-000000000000') RETURNING id",
    )
    .bind(doi)
    .bind(TITLE)
    .bind(licence)
    .fetch_one(pool)
    .await
    .expect("seed paper")
}

async fn set_licence(pool: &PgPool, paper: Uuid, licence: Option<&str>) {
    sqlx::query("UPDATE papers SET licence = $2 WHERE id = $1")
        .bind(paper)
        .bind(licence)
        .execute(pool)
        .await
        .expect("set licence");
}

fn planned() -> PlannedClaim {
    PlannedClaim {
        id: Uuid::new_v4(),
        content: "Evidence rows carry a passage hash".to_string(),
        level: 2,
        properties: serde_json::json!({}),
        content_hash: [0u8; 32],
        confidence: 0.7,
        methodology: None,
        evidence_type: None,
        axis: None,
        supporting_text: Some(PASSAGE.to_string()),
        supporting_locator: Some(
            r#"sections[0].paragraphs[2] ("Results (main)"), bytes 120..340"#.to_string(),
        ),
        enrichment: serde_json::json!({}),
    }
}

/// What the document-ingest writer stores for `doi` under `licence`.
fn ingest_body(doi: &str, licence: Option<&str>) -> String {
    literature_evidence_body(TITLE, doi, &planned(), licence)
}

/// The `ingest_literature` CLI's not-retained body (its `passage_evidence_body`,
/// a private function of the binary), byte for byte.
fn cli_locator_body(doi: &str, licence: &str) -> String {
    let hash = hex::encode(ContentHasher::hash(PASSAGE.as_bytes()));
    format!(
        "Source: {TITLE} (DOI: {doi}). Locator: page 4, section \"Results\". \
         Passage BLAKE3: {hash}. Passage not retained ({licence})."
    )
}

fn literature(doi: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "literature",
        "doi": doi,
        "extraction_target": "level_2",
        "page_range": null
    })
}

fn figure(doi: &str, caption: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "type": "figure",
        "doi": doi,
        "figure_id": "Figure 2",
        "caption": caption,
        "mime_type": "image/png",
        "page": 4
    })
}

fn document() -> serde_json::Value {
    serde_json::json!({
        "type": "document",
        "source_url": null,
        "mime_type": "text/plain",
        "checksum": null
    })
}

/// INSERT one evidence row as the application role. `evidence_type` is the
/// stored column (`reference` for literature, as `EvidenceRepository` writes).
async fn insert(
    app: &PgPool,
    claim: Uuid,
    evidence_type: &str,
    body: Option<&str>,
    properties: &serde_json::Value,
) -> Result<Uuid, sqlx::Error> {
    let hash = ContentHasher::hash(body.unwrap_or("").as_bytes());
    let salt = Uuid::new_v4();
    let mut digest = hash.to_vec();
    // Distinct digests per row: the per-owner de-duplication is not under test.
    for (d, s) in digest.iter_mut().zip(salt.as_bytes().iter().cycle()) {
        *d ^= s;
    }
    sqlx::query_scalar(
        "INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id, properties) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&digest)
    .bind(evidence_type)
    .bind(body)
    .bind(claim)
    .bind(properties)
    .fetch_one(app)
    .await
}

/// The refusal is the guard's: SQLSTATE 23514 naming its constraint, which
/// the API maps to a 400 (`DbError::CheckViolation`).
fn assert_refused<T: std::fmt::Debug>(r: Result<T, sqlx::Error>, what: &str) {
    let err = match r {
        Ok(v) => panic!("{what}: expected the passage guard to refuse, got Ok({v:?})"),
        Err(e) => e,
    };
    let db = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{what}: not a database error: {err}"));
    assert_eq!(db.code().as_deref(), Some("23514"), "{what}: {db}");
    assert_eq!(
        db.constraint(),
        Some("evidence_passage_licence"),
        "{what}: {db}"
    );
}

async fn group_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    fixture::seed_group_claim(
        pool,
        agent,
        group,
        &format!("guard host {}", Uuid::new_v4()),
    )
    .await
}

// ---------------------------------------------------------------------------
// Refused
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_store_a_verbatim_passage_for_a_paper_without_a_permitting_licence(
    pool: PgPool,
) {
    let unknown = "10.5555/guard.unknown";
    let restricted = "10.5555/guard.nc";
    let unregistered = "10.5555/guard.no-paper-row";
    seed_paper(&pool, unknown, None).await;
    seed_paper(&pool, restricted, Some("CC-BY-NC-4.0")).await;
    let (app, agent, group) = app_pool(&pool, "b62-refuse").await;
    let claim = group_claim(&pool, agent, group).await;

    for doi in [unknown, restricted, unregistered] {
        // The ingest writer's retained-passage body, with a licence the paper
        // does not carry: the body's own "Licence:" is not evidence of one.
        let forged = ingest_body(doi, Some("CC-BY-4.0"));
        assert!(forged.contains("Passage: '"), "{forged}");
        assert_refused(
            insert(&app, claim, "reference", Some(&forged), &literature(doi)).await,
            &format!("ingest-shaped passage for {doi}"),
        );
        // The CLI's verbatim body: the bare passage.
        assert_refused(
            insert(&app, claim, "reference", Some(PASSAGE), &literature(doi)).await,
            &format!("bare passage for {doi}"),
        );
        // A locator-shaped body that smuggles the passage in after it.
        let smuggled = format!("{} Passage: '{PASSAGE}'", ingest_body(doi, None));
        assert_refused(
            insert(&app, claim, "reference", Some(&smuggled), &literature(doi)).await,
            &format!("locator body with a passage appended for {doi}"),
        );
        // ... or inside its locator, where the rest of the shape still holds.
        let mut inside = planned();
        inside.supporting_locator = Some(format!("sections[0] Passage: '{PASSAGE}'"));
        let inside = literature_evidence_body(TITLE, doi, &inside, None);
        assert!(
            inside.ends_with("Passage not retained (licence unknown)."),
            "{inside}"
        );
        assert_refused(
            insert(&app, claim, "reference", Some(&inside), &literature(doi)).await,
            &format!("locator-shaped body with the passage in its locator for {doi}"),
        );
    }

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "a refused write leaves nothing behind");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_store_a_figure_or_its_caption_for_a_paper_without_a_permitting_licence(
    pool: PgPool,
) {
    let doi = "10.5555/guard.figure";
    seed_paper(&pool, doi, None).await;
    let (app, agent, group) = app_pool(&pool, "b62-figure").await;
    let claim = group_claim(&pool, agent, group).await;

    assert_refused(
        insert(
            &app,
            claim,
            "figure",
            Some("iVBORw0KGgoAAAANSUhEUg"),
            &figure(doi, None),
        )
        .await,
        "figure image",
    );
    assert_refused(
        insert(&app, claim, "figure", None, &figure(doi, Some(PASSAGE))).await,
        "figure caption",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_rewrite_evidence_into_a_verbatim_passage(pool: PgPool) {
    let doi = "10.5555/guard.update";
    seed_paper(&pool, doi, None).await;
    let (app, agent, group) = app_pool(&pool, "b62-update").await;
    let claim = group_claim(&pool, agent, group).await;

    // A locator-and-hash row, then its body replaced by the passage.
    let locator = ingest_body(doi, None);
    let id = insert(&app, claim, "reference", Some(&locator), &literature(doi))
        .await
        .expect("the locator-and-hash body is accepted");
    assert_refused(
        sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
            .bind(id)
            .bind(PASSAGE)
            .execute(&app)
            .await,
        "UPDATE raw_content to the passage",
    );

    // A document row holding the passage, then re-typed as the paper's
    // literature evidence.
    let doc = insert(&app, claim, "document", Some(PASSAGE), &document())
        .await
        .expect("a document row is not a paper's evidence");
    assert_refused(
        sqlx::query("UPDATE evidence SET properties = $2 WHERE id = $1")
            .bind(doc)
            .bind(literature(doi))
            .execute(&app)
            .await,
        "UPDATE properties to tie a passage to the paper",
    );

    // An open-licensed paper's passage row re-pointed at the paywalled DOI.
    let open = "10.5555/guard.update-open";
    seed_paper(&pool, open, Some("CC-BY-4.0")).await;
    let open_row = insert(&app, claim, "reference", Some(PASSAGE), &literature(open))
        .await
        .expect("a passage of an open-licensed paper is accepted");
    assert_refused(
        sqlx::query("UPDATE evidence SET properties = $2 WHERE id = $1")
            .bind(open_row)
            .bind(literature(doi))
            .execute(&app)
            .await,
        "UPDATE the DOI of a passage row onto a paywalled paper",
    );

    // A figure stored with neither image nor caption (admitted whatever the
    // licence), then given the publisher's caption by an UPDATE that touches
    // nothing else: the update trigger must fire on the caption alone.
    let bare_figure = insert(&app, claim, "figure", None, &figure(doi, None))
        .await
        .expect("a figure with no image and no caption is accepted");
    assert_refused(
        sqlx::query(
            "UPDATE evidence \
             SET properties = jsonb_set(properties, '{caption}', to_jsonb($2::text)) \
             WHERE id = $1",
        )
        .bind(bare_figure)
        .bind(PASSAGE)
        .execute(&app)
        .await,
        "UPDATE only the caption of a paywalled paper's figure",
    );
}

/// A group's own paper row grants nothing to a session that cannot read it:
/// the guard reads `papers` as the writer (SECURITY INVOKER), so another
/// group's licence is neither consulted nor disclosed. The owning group's own
/// session reads the row, so ITS passage is admitted (a private ingest of an
/// open-licensed paper is not refused).
#[sqlx::test(migrations = "../../migrations")]
async fn another_groups_paper_licence_permits_nothing(pool: PgPool) {
    let doi = "10.5555/guard.private";
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "b62-owner").await;
    sqlx::query(
        "INSERT INTO papers (doi, title, licence, visibility, owner_group_id) \
         VALUES ($1, $2, 'CC-BY-4.0', 'group', $3)",
    )
    .bind(doi)
    .bind(TITLE)
    .bind(owner_group)
    .execute(&pool)
    .await
    .expect("seed a group's paper");

    let (app, agent, group) = app_pool(&pool, "b62-outsider").await;
    let claim = group_claim(&pool, agent, group).await;
    assert_refused(
        insert(&app, claim, "reference", Some(PASSAGE), &literature(doi)).await,
        "passage permitted only by a paper row the writer cannot read",
    );

    let owner_app = stamped_app_pool(&pool, owner, owner_group).await;
    let owner_claim = group_claim(&pool, owner, owner_group).await;
    insert(
        &owner_app,
        owner_claim,
        "reference",
        Some(PASSAGE),
        &literature(doi),
    )
    .await
    .expect("the owning group's passage under its own open-licensed paper row is admitted");
}

// ---------------------------------------------------------------------------
// Accepted
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_locator_and_hash_bodies_are_accepted_whatever_the_licence(pool: PgPool) {
    let unknown = "10.5555/guard.ok-unknown";
    let restricted = "10.5555/guard.ok-nc";
    let unregistered = "10.5555/guard.ok-no-paper-row";
    seed_paper(&pool, unknown, None).await;
    seed_paper(&pool, restricted, Some("CC-BY-NC-4.0")).await;
    let (app, agent, group) = app_pool(&pool, "b62-accept").await;
    let claim = group_claim(&pool, agent, group).await;

    for doi in [unknown, restricted, unregistered] {
        for body in [
            ingest_body(doi, None),
            ingest_body(doi, Some("CC-BY-NC-4.0")),
            cli_locator_body(doi, "licence unknown"),
            cli_locator_body(doi, "licence: CC-BY-ND-4.0"),
        ] {
            assert!(!body.contains("Passage: '"), "{body}");
            insert(&app, claim, "reference", Some(&body), &literature(doi))
                .await
                .unwrap_or_else(|e| panic!("locator-and-hash body refused for {doi}: {e}\n{body}"));
        }
        insert(&app, claim, "reference", None, &literature(doi))
            .await
            .unwrap_or_else(|e| panic!("external (NULL body) literature row refused: {e}"));
        insert(&app, claim, "figure", None, &figure(doi, None))
            .await
            .unwrap_or_else(|e| panic!("a figure row with no image or caption refused: {e}"));
    }

    // Evidence that is not a paper's (no literature or figure type) is not the
    // guard's business, whatever its text.
    insert(&app, claim, "document", Some(PASSAGE), &document())
        .await
        .expect("a document row is accepted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_permitting_licence_admits_the_passage(pool: PgPool) {
    let open = "10.5555/guard.open";
    let cc0 = "10.5555/guard.cc0";
    seed_paper(&pool, open, Some("CC-BY-4.0")).await;
    seed_paper(&pool, cc0, Some("cc0 1.0")).await;
    let (app, agent, group) = app_pool(&pool, "b62-open").await;
    let claim = group_claim(&pool, agent, group).await;

    for (doi, licence) in [(open, "CC-BY-4.0"), (cc0, "cc0 1.0")] {
        let body = ingest_body(doi, Some(licence));
        assert!(body.contains(&format!("Passage: '{PASSAGE}'")), "{body}");
        insert(&app, claim, "reference", Some(&body), &literature(doi))
            .await
            .unwrap_or_else(|e| panic!("ingest passage under {licence} refused: {e}"));
        insert(&app, claim, "reference", Some(PASSAGE), &literature(doi))
            .await
            .unwrap_or_else(|e| panic!("bare (CLI) passage under {licence} refused: {e}"));
        insert(
            &app,
            claim,
            "figure",
            Some("iVBORw0KGgoAAAANSUhEUg"),
            &figure(doi, Some(PASSAGE)),
        )
        .await
        .unwrap_or_else(|e| panic!("figure under {licence} refused: {e}"));
    }

    // A legacy paper keyed on a case variant of a resolver prefix, which
    // `PaperRepository` finds for the canonical DOI (backlog f3a3ca54).
    let legacy = "10.5555/guard.legacy-key";
    seed_paper(
        &pool,
        &format!("HTTPS://DOI.ORG/{legacy}"),
        Some("CC-BY-4.0"),
    )
    .await;
    insert(&app, claim, "reference", Some(PASSAGE), &literature(legacy))
        .await
        .unwrap_or_else(|e| panic!("passage of a case-variant-keyed open paper refused: {e}"));
    // ... but only for the same DOI: the canonical key must match exactly.
    seed_paper(
        &pool,
        "HTTPS://DOI.ORG/10.5555/GUARD.CASE",
        Some("CC-BY-4.0"),
    )
    .await;
    assert_refused(
        insert(
            &app,
            claim,
            "reference",
            Some(PASSAGE),
            &literature("10.5555/guard.case"),
        )
        .await,
        "a DOI whose suffix differs in case from the open paper's key",
    );

    // The CLI sends the DOI as the extraction spells it; the paper row holds
    // the canonical key. A resolver-prefixed spelling finds the same paper.
    for spelled in [
        format!("https://doi.org/{open}"),
        format!("DOI: {open}"),
        format!("  {open}  "),
    ] {
        insert(
            &app,
            claim,
            "reference",
            Some(PASSAGE),
            &literature(&spelled),
        )
        .await
        .unwrap_or_else(|e| panic!("passage under DOI spelling {spelled:?} refused: {e}"));
    }
}

/// Rows stored before 349 (or under a licence since withdrawn) are not
/// bricked: a write that leaves the body and the paper tie alone passes, the
/// strip repair (rewrite to the locator-and-hash body) passes, and so does an
/// unseal restoring the body a seal replaced.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stored_passage_stays_writable_and_strippable_after_its_licence_is_withdrawn(
    pool: PgPool,
) {
    let doi = "10.5555/guard.withdrawn";
    let paper = seed_paper(&pool, doi, Some("CC-BY-4.0")).await;
    let (app, agent, group) = app_pool(&pool, "b62-legacy").await;
    let claim = group_claim(&pool, agent, group).await;
    let stored = ingest_body(doi, Some("CC-BY-4.0"));
    let row = insert(&app, claim, "reference", Some(&stored), &literature(doi))
        .await
        .expect("stored under an open licence");
    let sealed_row = insert(&app, claim, "reference", Some(PASSAGE), &literature(doi))
        .await
        .expect("stored under an open licence");
    set_licence(&pool, paper, None).await;

    // Still refused for a NEW passage, so the withdrawal took.
    assert_refused(
        insert(&app, claim, "reference", Some(PASSAGE), &literature(doi)).await,
        "a new passage after the licence was withdrawn",
    );

    // A properties write that keeps the tie, and a labels write.
    let mut props = literature(doi);
    props["page_range"] = serde_json::json!("1-2");
    sqlx::query("UPDATE evidence SET properties = $2, labels = ARRAY['kept'] WHERE id = $1")
        .bind(row)
        .bind(&props)
        .execute(&app)
        .await
        .expect("a write that leaves the body and the paper tie alone");

    // The strip repair.
    let stripped = ingest_body(doi, None);
    sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
        .bind(row)
        .bind(&stripped)
        .execute(&app)
        .await
        .expect("rewriting a stored passage to the locator-and-hash body");

    // Seal (the sentinel body, the properties emptied) and unseal (both
    // restored from the ciphertext row), as `PrivatizationRepository` does.
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch) VALUES ($1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed epoch");
    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(sealed_row)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed ciphertext row");
    sqlx::query("UPDATE evidence SET raw_content = '[sealed]', properties = '{}' WHERE id = $1")
        .bind(sealed_row)
        .execute(&app)
        .await
        .expect("seal");
    sqlx::query("UPDATE evidence SET raw_content = $2, properties = $3 WHERE id = $1")
        .bind(sealed_row)
        .bind(PASSAGE)
        .bind(literature(doi))
        .execute(&app)
        .await
        .expect("unseal restores the body the seal replaced");
}

// ---------------------------------------------------------------------------
// The SQL allowlist is the Rust allowlist
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_sql_allowlist_matches_the_rust_allowlist(pool: PgPool) {
    let corpus: Vec<Option<&str>> = vec![
        None,
        Some(""),
        Some(" "),
        Some("CC-BY-4.0"),
        Some("cc-by-4.0"),
        Some("CC BY 4.0"),
        Some("cc_by_sa_4.0"),
        Some("CC-BY-SA-4.0"),
        Some("CC-BY-SA"),
        Some("CC-BY"),
        Some("CC0"),
        Some("CC0-1.0"),
        Some("cc0 1.0"),
        Some("PD"),
        Some("pd"),
        Some("public-domain"),
        Some("Public Domain"),
        Some("public_domain"),
        Some("CC-BY-3.0-IGO"),
        Some("CC-BY-3.0-US"),
        Some("CC-BY-SA-3.0-AU"),
        Some("CC-BY-3.0-igo"),
        Some("CC-BY-3.0-ABCDE"),
        Some("CC-BY-3.0-A"),
        Some("CC-BY-3.0-NC"),
        Some("CC-BY-3.0-ND"),
        Some("CC-BY-3.0-SA"),
        Some("CC-BY-4.0-NC-ND"),
        Some("CC-BY-NC-4.0"),
        Some("CC-BY-ND-4.0"),
        Some("CC-BY-NC-SA-4.0"),
        Some("CC-BY-SA-4.0-ND"),
        Some("CC0-1.0-NC"),
        Some("CC-BY-40"),
        Some("CC-BY-4.00"),
        Some("CC-BY-4.0."),
        Some("CC-BY-a.b"),
        Some("CC-BY-SA-"),
        Some("CC-BY-"),
        Some("CC-BYX"),
        Some("CC-BY-NonCommercial-4.0"),
        Some("CC BY 4.0 (non-commercial)"),
        Some("CC-BY-PROPRIETARY"),
        Some("all-rights-reserved"),
        Some("Elsevier user license"),
        Some(" CC-BY-4.0 "),
        Some("\tCC-BY-4.0\n"),
        Some("CC-BY-4.0\u{a0}"),
        Some("\u{a0}PD"),
        Some("CC-BY-\u{17f}A-4.0"),
        Some("cc-by-\u{17f}a"),
        Some("CC-BY-4\u{ff0e}0"),
        Some("CC-BY-\u{661}.0"),
        Some("CC\u{2010}BY\u{2010}4.0"),
    ];
    for licence in corpus {
        let sql: bool =
            sqlx::query_scalar("SELECT public.epigraph_passage_retention_permitted($1)")
                .bind(licence)
                .fetch_one(&pool)
                .await
                .expect("epigraph_passage_retention_permitted");
        assert_eq!(
            sql,
            passage_retention_permitted(licence),
            "the SQL mirror (migration 349) and the Rust allowlist disagree on {licence:?}"
        );
    }
}
