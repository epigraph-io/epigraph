//! `harvester_enriched_concepts` is under tenancy, with the row security of
//! the tier-A `harvester_fragments` (migration 313, backlog f214b84e).
//!
//! # What is measured
//!
//! The table used to carry no tenancy columns and no row security, so every
//! application session read every concept (name, canonical name, latent
//! definition, embedding), whatever group wrote it. It is a PARENTLESS root:
//! it has no foreign key in or out, so there is no fragment, source or claim
//! to derive a row's owner from. The posture is therefore
//! `harvester_sources`'s (173), not `harvester_audit_reports`'s: a writer
//! declares both columns or the INSERT is refused, and an `epigraph_app`
//! session reads a row only when it is public or owned by one of the
//! session's groups. Rows written before 313 had no owner to derive, and every
//! reader read them; 313 stamps them `('public', world)`, which is what every
//! reader saw (246's precedent for `papers`), so nothing becomes more or less
//! readable on upgrade.
//!
//! # The instrument
//!
//! The harness connects as a superuser, which bypasses row security even on a
//! FORCEd table, so every read below runs as `epigraph_app` through
//! `viewer_fixture::as_role` (`SET SESSION AUTHORIZATION`) with the session
//! GUCs stamped the way `ScopedPool` stamps them. A private
//! `harvester_fragments` row is read the same way as the CONTROL: its
//! non-member answer holds on any database that has run 077, so a failure on
//! the table under test is a fact about that table and not about the harness.
//!
//! The fixture writes rows on the superuser pool (the application role holds
//! no write on the table, migration 118 section 6). A concept is declared
//! `(visibility, owner)` when the table carries the tenancy columns, and
//! written undeclared before then, the only shape that schema can hold.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// The migration under test.
const MIGRATION: i64 = 313;

/// Bind the three session GUCs on a connection, the way `ScopedPool` does.
async fn set_gucs(conn: &mut sqlx::PgConnection, groups: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $1, false), \
                set_config('epigraph.principal_id', $2, false)",
    )
    .bind(groups)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("set session gucs");
}

/// Does `harvester_enriched_concepts` carry the tenancy columns?
async fn has_tenancy_columns(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT count(*) = 2 FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'harvester_enriched_concepts' \
            AND column_name IN ('owner_group_id', 'visibility')",
    )
    .fetch_one(pool)
    .await
    .expect("column probe")
}

/// A concept declared `(visibility, owner)` where the schema can hold it.
async fn seed_concept(pool: &PgPool, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let q = if has_tenancy_columns(pool).await {
        sqlx::query(
            "INSERT INTO harvester_enriched_concepts \
                 (id, concept_name, latent_definition, owner_group_id, visibility) \
             VALUES ($1, $2, 'a confidential definition', $3, $4)",
        )
        .bind(id)
        .bind(format!("concept-{id}"))
        .bind(owner)
        .bind(visibility)
    } else {
        sqlx::query(
            "INSERT INTO harvester_enriched_concepts (id, concept_name, latent_definition) \
             VALUES ($1, $2, 'a confidential definition')",
        )
        .bind(id)
        .bind(format!("concept-{id}"))
    };
    q.execute(pool).await.expect("seed harvester concept");
    id
}

/// A private `harvester_fragments` row (and its source) of `owner`: the
/// control, whose row security every database past 077 enforces.
async fn seed_private_fragment(pool: &PgPool, owner: Uuid) -> Uuid {
    let source = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harvester_sources \
             (id, content_hash, modality, owner_group_id, visibility) \
         VALUES ($1, $2, 'text', $3, 'group')",
    )
    .bind(source)
    .bind(source.as_bytes().to_vec())
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed harvester source");
    let fragment = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harvester_fragments \
             (id, source_id, content_hash, content_text, owner_group_id, visibility) \
         VALUES ($1, $2, $3, 'fragment text', $4, 'group')",
    )
    .bind(fragment)
    .bind(source)
    .bind(fragment.as_bytes().to_vec())
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed harvester fragment");
    fragment
}

/// `(control fragments read, concepts read)` for an `epigraph_app` session
/// stamped with `(groups, principal)`.
async fn read_as_app(
    pool: &PgPool,
    groups: String,
    principal: String,
    fragment: Uuid,
    concept: Uuid,
) -> (i64, i64) {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, &groups, &principal).await;
        let f: i64 = sqlx::query_scalar("SELECT count(*) FROM harvester_fragments WHERE id = $1")
            .bind(fragment)
            .fetch_one(&mut *conn)
            .await
            .expect("read harvester_fragments as epigraph_app");
        let c: i64 =
            sqlx::query_scalar("SELECT count(*) FROM harvester_enriched_concepts WHERE id = $1")
                .bind(concept)
                .fetch_one(&mut *conn)
                .await
                .expect("read harvester_enriched_concepts as epigraph_app");
        (conn, (f, c))
    })
    .await
}

/// A session stamped with a stranger's own group reads none of another
/// group's private concepts, and still reads a public one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_another_groups_private_concept(pool: PgPool) {
    let (_owner, owner_group) = fixture::seed_agent_with_group(&pool, "hec-owner").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "hec-stranger").await;
    let fragment = seed_private_fragment(&pool, owner_group).await;
    let private = seed_concept(&pool, owner_group, "group").await;
    let public = seed_concept(&pool, owner_group, "public").await;

    let (control, leaked) = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        fragment,
        private,
    )
    .await;
    assert_eq!(
        control, 0,
        "CONTROL: the stranger reads another group's private fragment, so this connection is \
         not filtered and nothing below is measured"
    );
    assert_eq!(
        leaked, 0,
        "a non-member application session read another group's private enriched concept"
    );

    // Not over-restricted: a public concept stays readable to the same session.
    let (_, public_seen) = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        fragment,
        public,
    )
    .await;
    assert_eq!(
        public_seen, 1,
        "a public concept is readable by any application session"
    );
}

/// A member of the owning group reads its group's private concept. Passes on a
/// database without row security on the table too: it is the pin that the
/// policy does not filter too much.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_reads_its_own_groups_private_concept(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "hec-member").await;
    let fragment = seed_private_fragment(&pool, owner_group).await;
    let private = seed_concept(&pool, owner_group, "group").await;

    let (control, _) = read_as_app(&pool, String::new(), String::new(), fragment, private).await;
    assert_eq!(
        control, 0,
        "CONTROL: an unstamped session reads a private fragment, so row security is not \
         filtering this connection and the member read below proves nothing"
    );

    let seen = read_as_app(
        &pool,
        owner_group.to_string(),
        owner.to_string(),
        fragment,
        private,
    )
    .await;
    assert_eq!(
        seen,
        (1, 1),
        "a member of the owning group reads its own private fragment and concept"
    );
}

/// A concept has no parent to inherit from, so outside the seed escape hatch
/// an undeclared INSERT is refused by 074's root body (23502), as for
/// `harvester_sources`. The maintenance role holds INSERT, so the refusal is
/// the trigger's and not a missing grant; the message distinguishes it from
/// the NOT NULL backstop, which raises the same code.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_concept_is_refused(pool: PgPool) {
    let (code, message) = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let err = sqlx::query(
            "INSERT INTO harvester_enriched_concepts (concept_name) VALUES ('undeclared')",
        )
        .execute(&mut *conn)
        .await
        .expect_err("an undeclared concept must be refused");
        let db = err.as_database_error();
        let code = db.and_then(|d| d.code().map(|c| c.to_string()));
        let message = db.map(|d| d.message().to_string()).unwrap_or_default();
        (conn, (code, message))
    })
    .await;
    assert_eq!(
        code.as_deref(),
        Some("23502"),
        "undeclared concept: {code:?} {message}"
    );
    assert!(
        message.contains(
            "epigraph tenancy: INSERT INTO harvester_enriched_concepts without an explicit"
        ),
        "the refusal is 074's root trigger, not the NOT NULL backstop: {message}"
    );
}

// ===========================================================================
// Migration 313 on a database that already holds concepts
// ===========================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The migrator holding every migration for which `keep` is true.
fn migrator_where(keep: impl Fn(i64) -> bool) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| keep(m.version))
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection; 001's pg_dump header leaves session-level
/// SETs behind, so a successful run is followed by `RESET ALL`.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// Rows written before 313 have no parent to derive an owner from, and every
/// application session read them. 313 stamps them `('public', world)`, so
/// after the upgrade a stranger still reads them (nothing narrowed without an
/// owner to narrow to) and the row carries a declared pair, NOT NULL. The
/// cut is "every migration below 313", not a fixed predecessor, so the test
/// holds whichever lower slots land first.
#[sqlx::test(migrations = false)]
async fn migration_313_stamps_existing_concepts_with_what_every_reader_saw(pool: PgPool) {
    migrate(&pool, &migrator_where(|v| v < MIGRATION)).await;
    assert!(
        !has_tenancy_columns(&pool).await,
        "CALIBRATION: the table already carries tenancy columns below {MIGRATION}, so this \
         test does not measure the upgrade"
    );
    let (_a, group_a) = fixture::seed_agent_with_group(&pool, "hec-313").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "hec-313-x").await;
    // Written below 313, so `seed_concept` takes its undeclared arm.
    let old = seed_concept(&pool, group_a, "group").await;

    migrate(&pool, &MIGRATOR).await;

    let world = fixture::world_group(&pool).await;
    let pair: (Uuid, String) = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM harvester_enriched_concepts WHERE id = $1",
    )
    .bind(old)
    .fetch_one(&pool)
    .await
    .expect("read the upgraded concept's tenancy");
    assert_eq!(
        pair,
        (world, "public".to_string()),
        "a concept written before {MIGRATION} is stamped with what every reader saw"
    );

    let fragment = seed_private_fragment(&pool, group_a).await;
    let (control, seen) = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        fragment,
        old,
    )
    .await;
    assert_eq!(control, 0, "CONTROL: the stranger's session is filtered");
    assert_eq!(
        seen, 1,
        "the upgrade does not hide a concept every reader read before it"
    );
}
