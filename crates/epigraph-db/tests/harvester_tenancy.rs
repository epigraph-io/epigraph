//! `harvester_sources` and `harvester_audit_reports` are under tenancy, with
//! the row security of the tier-A `harvester_fragments` (ruling R-66, backlog
//! 90d7baf0; closes 154efca2).
//!
//! # What is measured
//!
//! Both tables used to carry no tenancy columns and no row security, so every
//! application session read every row, whichever group the source document or
//! the extraction audit belonged to. A `tenancy_exempt` row per table recorded
//! that as an open residual. The posture now matches `harvester_fragments`'s:
//! an `epigraph_app` session reads a row only when it is public or owned by
//! one of the session's groups.
//!
//! # The instrument
//!
//! The harness connects as a superuser, which bypasses row security even on a
//! FORCEd table, so every read below runs as `epigraph_app` through
//! `viewer_fixture::as_role` (`SET SESSION AUTHORIZATION`) with the session
//! GUCs stamped the way `ScopedPool` stamps them. `harvester_fragments` is
//! read the same way as the CONTROL: its non-member and member answers hold
//! on any database that has run 077, so a failure on the two tables under
//! test is a fact about those tables and not about the harness.
//!
//! The fixture writes rows on the superuser pool (the application role holds
//! no write on either table, migration 118 section 6). A source is declared
//! `('group', <owner>)` when the table carries the tenancy columns; an audit
//! report is never declared, because its tenancy is its fragment's.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// Bind the three session GUCs on a connection, the way `ScopedPool` does.
async fn set_gucs(conn: &mut sqlx::PgConnection, groups: &str, writable: &str, principal: &str) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(principal)
    .execute(&mut *conn)
    .await
    .expect("set session gucs");
}

/// Does `table` carry the tenancy columns? False before migration 173 gave
/// them to the two harvester tables; the fixture then writes the row without
/// a declaration, which is the only shape that schema can hold.
async fn has_tenancy_columns(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar(
        "SELECT count(*) = 2 FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = $1 \
            AND column_name IN ('owner_group_id', 'visibility')",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("column probe")
}

/// A `harvester_sources` row declared `(visibility, owner)` where the schema
/// can hold it. `content_hash` is UNIQUE, so it is derived from the id.
async fn seed_source(pool: &PgPool, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let q = if has_tenancy_columns(pool, "harvester_sources").await {
        sqlx::query(
            "INSERT INTO harvester_sources \
                 (id, content_hash, modality, owner_group_id, visibility) \
             VALUES ($1, $2, 'text', $3, $4)",
        )
        .bind(id)
        .bind(id.as_bytes().to_vec())
        .bind(owner)
        .bind(visibility)
    } else {
        sqlx::query(
            "INSERT INTO harvester_sources (id, content_hash, modality) VALUES ($1, $2, 'text')",
        )
        .bind(id)
        .bind(id.as_bytes().to_vec())
    };
    q.execute(pool).await.expect("seed harvester source");
    id
}

async fn seed_fragment(pool: &PgPool, source: Uuid, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harvester_fragments \
             (id, source_id, content_hash, content_text, owner_group_id, visibility) \
         VALUES ($1, $2, $3, 'fragment text', $4, $5)",
    )
    .bind(id)
    .bind(source)
    .bind(id.as_bytes().to_vec())
    .bind(owner)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("seed harvester fragment");
    id
}

/// An audit report on `fragment`, written without a tenancy declaration.
async fn seed_report(pool: &PgPool, fragment: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO harvester_audit_reports (fragment_id, extraction_id, passed_audit) \
         VALUES ($1, $2, true) RETURNING id",
    )
    .bind(fragment)
    .bind(Uuid::new_v4())
    .fetch_one(pool)
    .await
    .expect("seed harvester audit report")
}

/// One source, one fragment and one audit report, all owned by one group with
/// one visibility (the report through its fragment).
struct Pipeline {
    source: Uuid,
    fragment: Uuid,
    report: Uuid,
}

async fn seed_pipeline(pool: &PgPool, group: Uuid, visibility: &str) -> Pipeline {
    let source = seed_source(pool, group, visibility).await;
    let fragment = seed_fragment(pool, source, group, visibility).await;
    let report = seed_report(pool, fragment).await;
    Pipeline {
        source,
        fragment,
        report,
    }
}

/// How many of `p`'s three rows an `epigraph_app` session stamped with
/// `(groups, principal)` reads, as `[(table, count)]`, control first.
async fn read_as_app(
    pool: &PgPool,
    groups: String,
    principal: String,
    p: &Pipeline,
) -> Vec<(&'static str, i64)> {
    let (source, fragment, report) = (p.source, p.fragment, p.report);
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_gucs(&mut conn, &groups, &groups, &principal).await;
        let mut out = Vec::new();
        for (table, id) in [
            ("harvester_fragments", fragment),
            ("harvester_sources", source),
            ("harvester_audit_reports", report),
        ] {
            let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE id = $1"))
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .unwrap_or_else(|e| panic!("read {table} as epigraph_app: {e}"));
            out.push((table, n));
        }
        (conn, out)
    })
    .await
}

/// A session stamped with a stranger's own group reads none of another
/// group's private harvester rows, and still reads public ones.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_another_groups_harvester_rows(pool: PgPool) {
    let (_owner, owner_group) = fixture::seed_agent_with_group(&pool, "harv-owner").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "harv-stranger").await;
    let private = seed_pipeline(&pool, owner_group, "group").await;
    let public = seed_pipeline(&pool, owner_group, "public").await;

    let private_seen = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        &private,
    )
    .await;
    assert_eq!(
        private_seen[0],
        ("harvester_fragments", 0),
        "CONTROL: the stranger reads another group's private fragment, so this connection is \
         not filtered and nothing below is measured"
    );
    let leaked: Vec<&(&str, i64)> = private_seen.iter().filter(|(_, n)| *n != 0).collect();
    assert!(
        leaked.is_empty(),
        "a non-member session read another group's private harvester rows: {leaked:?}"
    );

    // Not over-restricted: a public row stays readable to the same session.
    let public_seen = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        &public,
    )
    .await;
    assert_eq!(
        public_seen,
        vec![
            ("harvester_fragments", 1),
            ("harvester_sources", 1),
            ("harvester_audit_reports", 1),
        ],
        "a public harvester row is readable by any application session"
    );
}

/// A member of the owning group reads every one of its group's private
/// harvester rows. Passes on a database without row security on the two
/// tables too: it is the pin that the policy does not filter too much.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_reads_its_own_groups_harvester_rows(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "harv-member").await;
    let private = seed_pipeline(&pool, owner_group, "group").await;

    let unstamped = read_as_app(&pool, String::new(), String::new(), &private).await;
    assert_eq!(
        unstamped[0],
        ("harvester_fragments", 0),
        "CONTROL: an unstamped session reads a private fragment, so row security is not \
         filtering this connection and the member read below proves nothing"
    );

    let seen = read_as_app(&pool, owner_group.to_string(), owner.to_string(), &private).await;
    assert_eq!(
        seen,
        vec![
            ("harvester_fragments", 1),
            ("harvester_sources", 1),
            ("harvester_audit_reports", 1),
        ],
        "a member of the owning group reads its own private harvester rows"
    );
}

/// The two tables are covered, so neither keeps a `tenancy_exempt` row (the
/// registry is for tables WITHOUT a tenancy posture).
#[sqlx::test(migrations = "../../migrations")]
async fn the_harvester_tables_carry_no_tenancy_exemption(pool: PgPool) {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM tenancy_exempt \
          WHERE table_name IN ('harvester_sources', 'harvester_audit_reports') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("registry read");
    assert!(
        rows.is_empty(),
        "a covered table keeps no tenancy_exempt row: {rows:?}"
    );

    // Not vacuous: the registry itself is still there and populated.
    let total: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM tenancy_exempt")
        .fetch_one(&pool)
        .await
        .expect("registry count");
    assert!(total > 0, "the tenancy_exempt registry is empty");
}

// ===========================================================================
// Migration 173 on a database that already holds harvester rows
// ===========================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The migrator cut at `max`.
fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
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
async fn migrate(
    pool: &PgPool,
    migrator: &sqlx::migrate::Migrator,
) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await?;
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    Ok(())
}

async fn tenancy_of(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("tenancy of {table} {id}: {e}"))
}

/// Migration 173 is safe on non-empty tables. Rows written at 172 (no tenancy
/// columns) are DERIVED, never defaulted: an audit report takes its fragment's
/// pair, a source its fragments' pair when they agree. A source with no
/// fragment, or with fragments of two owners or of one owner and two
/// visibilities, has no pair the migration can
/// name: it refuses with HVT01, names the count, and leaves the schema as it
/// was; once those sources are resolved, a re-run derives the rest.
#[sqlx::test(migrations = false)]
async fn migration_173_derives_existing_rows_from_their_fragments_or_refuses(pool: PgPool) {
    migrate(&pool, &up_to(172)).await.expect("migrate to 172");
    let (_a, group_a) = fixture::seed_agent_with_group(&pool, "harv-173-a").await;
    let (_b, group_b) = fixture::seed_agent_with_group(&pool, "harv-173-b").await;

    // Written at 172, so `seed_source` takes its undeclared arm.
    let agreeing = seed_source(&pool, group_a, "group").await;
    seed_fragment(&pool, agreeing, group_a, "group").await;
    let agreeing_frag = seed_fragment(&pool, agreeing, group_a, "group").await;
    let report = seed_report(&pool, agreeing_frag).await;
    let public = seed_source(&pool, group_b, "public").await;
    let public_frag = seed_fragment(&pool, public, group_b, "public").await;
    let public_report = seed_report(&pool, public_frag).await;
    let orphan = seed_source(&pool, group_a, "group").await;
    let mixed = seed_source(&pool, group_a, "group").await;
    seed_fragment(&pool, mixed, group_a, "group").await;
    let mixed_frag_b = seed_fragment(&pool, mixed, group_b, "group").await;
    // One owner, two visibilities: the pair, not the owner alone, must agree.
    let split = seed_source(&pool, group_a, "group").await;
    let split_public_frag = seed_fragment(&pool, split, group_a, "public").await;
    seed_fragment(&pool, split, group_a, "group").await;

    let refused = migrate(&pool, &up_to(173))
        .await
        .expect_err("173 must refuse a source it cannot derive an owner for");
    let msg = refused.to_string();
    assert!(
        msg.contains("HVT01")
            && msg.contains("for 3 harvester_sources")
            && msg.contains("and 0 harvester_audit_reports"),
        "the refusal names the three underivable sources and no report: {msg}"
    );
    assert!(
        !has_tenancy_columns(&pool, "harvester_sources").await
            && !has_tenancy_columns(&pool, "harvester_audit_reports").await,
        "a refused 173 changes nothing"
    );

    // Resolve the three: the orphan goes, the mixed source's fragments agree
    // on an owner and the split source's on a visibility.
    sqlx::query("DELETE FROM harvester_sources WHERE id = $1")
        .bind(orphan)
        .execute(&pool)
        .await
        .expect("delete the orphan source");
    sqlx::query("UPDATE harvester_fragments SET owner_group_id = $1 WHERE id = $2")
        .bind(group_a)
        .bind(mixed_frag_b)
        .execute(&pool)
        .await
        .expect("make the mixed source's fragments agree");
    sqlx::query("UPDATE harvester_fragments SET visibility = 'group' WHERE id = $1")
        .bind(split_public_frag)
        .execute(&pool)
        .await
        .expect("make the split source's fragments agree");

    migrate(&pool, &up_to(173))
        .await
        .expect("173 applies once every source is derivable");
    let group = "group".to_string();
    let public_vis = "public".to_string();
    assert_eq!(
        tenancy_of(&pool, "harvester_sources", agreeing).await,
        (group_a, group.clone())
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_audit_reports", report).await,
        (group_a, group.clone())
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_sources", public).await,
        (group_b, public_vis.clone())
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_audit_reports", public_report).await,
        (group_b, public_vis)
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_sources", mixed).await,
        (group_a, group.clone())
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_sources", split).await,
        (group_a, group)
    );
}

/// After 173 an audit report takes its fragment's tenancy whatever its writer
/// declared, and a source is declared or refused like `harvester_fragments`:
/// an undeclared INSERT outside the seed escape hatch raises 23502.
#[sqlx::test(migrations = "../../migrations")]
async fn the_write_side_stamps_a_report_and_requires_a_declared_source(pool: PgPool) {
    let (_a, group_a) = fixture::seed_agent_with_group(&pool, "harv-write").await;
    let world = fixture::world_group(&pool).await;
    let source = seed_source(&pool, group_a, "group").await;
    let fragment = seed_fragment(&pool, source, group_a, "group").await;

    let declared_public: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_audit_reports \
             (fragment_id, extraction_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, 'public') RETURNING id",
    )
    .bind(fragment)
    .bind(Uuid::new_v4())
    .bind(world)
    .fetch_one(&pool)
    .await
    .expect("insert a report declared public");
    assert_eq!(
        tenancy_of(&pool, "harvester_audit_reports", declared_public).await,
        (group_a, "group".to_string()),
        "a report is never more readable than the fragment it audits"
    );

    // Outside the seed escape hatch (`SET SESSION AUTHORIZATION` makes the
    // session a non-member of `epigraph_seed`), an undeclared source is refused
    // by 074's root body. The maintenance role holds INSERT, so the refusal is
    // the trigger's and not a missing grant.
    let refusal = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let err = sqlx::query(
            "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text')",
        )
        .bind(Uuid::new_v4().as_bytes().to_vec())
        .execute(&mut *conn)
        .await
        .expect_err("an undeclared source must be refused");
        let db = err.as_database_error();
        let code = db.and_then(|d| d.code().map(|c| c.to_string()));
        let message = db.map(|d| d.message().to_string()).unwrap_or_default();
        (conn, (code, message))
    })
    .await;
    let (code, message) = refusal;
    assert_eq!(
        code.as_deref(),
        Some("23502"),
        "undeclared source: {code:?} {message}"
    );
    // 23502 alone is also what the NOT NULL columns raise with no trigger at
    // all; the text is 074's root body's.
    assert!(
        message.contains("epigraph tenancy: INSERT INTO harvester_sources without an explicit"),
        "the refusal is 074's root trigger, not the NOT NULL backstop: {message}"
    );
}

/// An audit report keeps its fragment's tenancy when the FRAGMENT's tenancy
/// changes, not only at INSERT. Driven through the real path: a public claim
/// is narrowed to its group, 070 arm (d) carries that to the fragment its
/// provenance names, and the fragment's audit report must follow, or the
/// first privatization leaves the audit of a now-private fragment readable to
/// every application session.
#[sqlx::test(migrations = "../../migrations")]
async fn an_audit_report_follows_its_fragment_when_a_claim_is_narrowed(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "harv-follow").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "harv-follow-x").await;
    let pipeline = seed_pipeline(&pool, owner_group, "public").await;

    let claim = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'harvested claim', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(claim)
    .bind(
        claim
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(32)
            .collect::<Vec<u8>>(),
    )
    .bind(owner)
    .bind(owner_group)
    .execute(&pool)
    .await
    .expect("seed a public claim of the owner's group");
    sqlx::query("INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)")
        .bind(claim)
        .bind(pipeline.fragment)
        .execute(&pool)
        .await
        .expect("link the fragment to the claim");

    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("narrow the claim to its group");

    assert_eq!(
        tenancy_of(&pool, "harvester_fragments", pipeline.fragment).await,
        (owner_group, "group".to_string()),
        "CONTROL: arm (d) carries the narrowing to the fragment"
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_audit_reports", pipeline.report).await,
        (owner_group, "group".to_string()),
        "the audit report follows its fragment"
    );
    let seen = read_as_app(
        &pool,
        stranger_group.to_string(),
        stranger.to_string(),
        &pipeline,
    )
    .await;
    assert_eq!(
        seen[2],
        ("harvester_audit_reports", 0),
        "a non-member no longer reads the audit of a now-private fragment: {seen:?}"
    );
}

/// Two `epigraph_app` reads of `p`, as the old and the new owner group, after
/// `p`'s fragment changed owner: `(old, new)`.
async fn read_as_old_and_new_owner(
    pool: &PgPool,
    old: (Uuid, Uuid),
    new: (Uuid, Uuid),
    p: &Pipeline,
) -> (Vec<(&'static str, i64)>, Vec<(&'static str, i64)>) {
    let old_seen = read_as_app(pool, old.1.to_string(), old.0.to_string(), p).await;
    let new_seen = read_as_app(pool, new.1.to_string(), new.0.to_string(), p).await;
    (old_seen, new_seen)
}

/// An audit report follows its fragment when the fragment changes OWNER, not
/// only visibility. A maintenance session re-owns the fragment alone, as the
/// operator's re-own and restrict commands and the tenancy backfill do: the
/// report must move to the new group with it, or the old group keeps reading
/// the audit of a fragment it no longer owns.
#[sqlx::test(migrations = "../../migrations")]
async fn an_audit_report_follows_its_fragment_when_the_fragment_is_re_owned(pool: PgPool) {
    let old = fixture::seed_agent_with_group(&pool, "harv-reown-old").await;
    let new = fixture::seed_agent_with_group(&pool, "harv-reown-new").await;
    let pipeline = seed_pipeline(&pool, old.1, "group").await;

    let fragment = pipeline.fragment;
    let new_group = new.1;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("UPDATE harvester_fragments SET owner_group_id = $1 WHERE id = $2")
            .bind(new_group)
            .bind(fragment)
            .execute(&mut *conn)
            .await
            .expect("a maintenance session re-owns the fragment");
        (conn, ())
    })
    .await;

    assert_eq!(
        tenancy_of(&pool, "harvester_fragments", pipeline.fragment).await,
        (new.1, "group".to_string()),
        "CONTROL: the fragment was re-owned"
    );
    assert_eq!(
        tenancy_of(&pool, "harvester_audit_reports", pipeline.report).await,
        (new.1, "group".to_string()),
        "the audit report moves to its fragment's new owner"
    );
    let (old_seen, new_seen) = read_as_old_and_new_owner(&pool, old, new, &pipeline).await;
    assert_eq!(
        (old_seen[0], new_seen[0]),
        (("harvester_fragments", 0), ("harvester_fragments", 1)),
        "CONTROL: the fragment is read by its new owner only"
    );
    assert_eq!(
        (old_seen[2], new_seen[2]),
        (
            ("harvester_audit_reports", 0),
            ("harvester_audit_reports", 1)
        ),
        "the old owner no longer reads the audit report and the new owner does"
    );
}
