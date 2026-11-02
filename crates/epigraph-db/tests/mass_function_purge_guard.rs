//! SPEC §11 phase 1, S-1 (migration 194; H10, rulings R-79 / R-103): a
//! RETRACTED mass function is never deleted except by the audited purge
//! definer `epigraph_purge_mass_functions`. That includes the deletes the
//! `ON DELETE CASCADE` foreign keys from `claims` and `frames` perform.
//!
//! The guard tests ONLY a table-backed purge grant (SPEC §2.8), never a
//! session setting or `epigraph_definer_bypass()`: PostgreSQL runs an FK
//! referential action as the owner of the referencing table, so any session
//! can set a setting, and a definer-bypass test can be true inside a cascade an
//! application session started (SPEC §7.1, "No setting where an FK action can
//! act"). Test (a) reproduces that attack under both table-owner shapes: the
//! tables owned by a superuser migration runner (the harness), and the tables
//! owned by a NOSUPERUSER role that is not a maintenance member.
//!
//! Lettered as SPEC §11 phase 1 "S-1 (slot 194) and K4b" lists them:
//! (a)-(k) here; (l) in `epigraph-api/tests/supersede_refusal_codes_http.rs`
//! and `epigraph-mcp/tests/supersede_refusal_codes_mcp.rs`; (m) in
//! `epigraph-cli/tests/operator_delete_frames.rs`; (n) in
//! `fk_action_guard_ratchet.rs`; (o) is the mutation probe recorded with the
//! batch.
//!
//! Every retracted row is made by migration 184's definer on the application
//! role (`support/retracted_bba_fixture.rs`). The privileged cases run on a
//! NOSUPERUSER `epigraph_maintenance` session (SPEC §12), checked before use.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

#[path = "viewer_fixture.rs"]
mod fixture;
#[path = "support/retracted_bba_fixture.rs"]
mod retracted;

use epigraph_db::repos::mass_function::{delete_edge_bbas, EdgeBbaCascade, MassFunctionRepository};
use epigraph_db::visibility::Viewer;
use sqlx::migrate::Migrator;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::borrow::Cow;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// `md5(prosrc)` of migration 117's body of
/// `epigraph_cascade_delete_edge_bbas(uuid[], text)`, measured on a database
/// migrated to the last migration before 194
/// (`the_cascade_definer_before_194_is_117s_body`).
const MD5_117: &str = "39f3eacd53e7717a323759ec91b5c2c0";

const CASCADE_DEFINER: &str = "public.epigraph_cascade_delete_edge_bbas(uuid[], text)";
const PURGE_DEFINER: &str = "public.epigraph_purge_mass_functions(uuid[], text)";
const GRANT_HELPER: &str = "public.epigraph_mf_purge_granted(uuid)";
const GUARD_FN: &str = "public.mass_functions_retracted_delete_guard()";

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{rel} must exist (SPEC §10.1 S-1): {e}"))
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A NOSUPERUSER maintenance pool, checked privileged and not superuser.
async fn maintenance(pool: &PgPool) -> PgPool {
    let m = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let (superuser, privileged): (bool, bool) = sqlx::query_as(
        "SELECT r.rolsuper, public.epigraph_bypass() FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&m)
    .await
    .expect("read the maintenance session's role");
    assert!(
        !superuser,
        "the maintenance session must not be a superuser"
    );
    assert!(
        privileged,
        "the maintenance session must be privileged (epigraph_bypass)"
    );
    m
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A dedicated connection acting as the application role (`epigraph_app`),
/// stamped as `agent` with its resolved groups, as the request path stamps a
/// caller. Never returned to a pool.
async fn app_conn(pool: &PgPool, agent: Uuid) -> PgConnection {
    let viewer = Viewer::resolve(pool, agent)
        .await
        .expect("resolve the writer");
    let url = fixture::database_url_for(pool).await;
    let mut conn = PgConnection::connect(&url).await.expect("app connection");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION epigraph_app");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(viewer.group_bind().expect("a scoped viewer")))
    .bind(csv(viewer.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut conn)
    .await
    .expect("stamp the writer");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&mut conn)
        .await
        .expect("read bypass");
    assert!(!bypass, "the application connection must not be privileged");
    conn
}

async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("h10-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// A public claim owned by `group`, authored by `agent`.
async fn claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("h10 fixture {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A claim-to-claim edge and its edge-factor perspective.
async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'corroborates') RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
    id
}

/// `agent`'s BBA on (claim, frame), keyed on `perspective`, through the
/// repository upsert every BBA writer uses (on the harness).
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    perspective: Option<Uuid>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        perspective,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
}

async fn exists(pool: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM public.{table} WHERE id = $1)"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table} {id}: {e}"))
}

/// `(sqlstate, message)` of a database error; panics on `Ok`.
fn refusal<T: std::fmt::Debug>(r: Result<T, sqlx::Error>, what: &str) -> (String, String) {
    match r {
        Ok(v) => panic!("{what}: expected a database refusal, got Ok({v:?})"),
        Err(e) => {
            let db = e
                .as_database_error()
                .unwrap_or_else(|| panic!("{what}: not a database error: {e:?}"));
            (
                db.code().map(|c| c.to_string()).unwrap_or_default(),
                db.message().to_string(),
            )
        }
    }
}

fn assert_sr09(r: (String, String), what: &str) {
    let (code, message) = r;
    assert!(
        message.starts_with("SR09: "),
        "{what}: the refusal must be H10's SR09, got {code} {message:?}"
    );
    assert_eq!(code, "42501", "{what}: SR09 is a 42501 denial (SPEC §7.2)");
}

/// One writer, its group and claim, a frame, and two BBAs on (claim, frame)
/// from two source agents: `live` and `retracted` (retracted through 184's
/// definer).
struct World {
    writer: Uuid,
    claim: Uuid,
    frame: Uuid,
    live: Uuid,
    retracted: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let (writer, group) = fixture::seed_agent_with_group(pool, "h10-writer").await;
    let (second, _) = fixture::seed_agent_with_group(pool, "h10-second-source").await;
    let f = frame(pool).await;
    let c = claim(pool, writer, group).await;
    let live = bba(pool, c, f, writer, None).await;
    let r = bba(pool, c, f, second, None).await;
    retracted::retract_through_definer(pool, r).await;
    World {
        writer,
        claim: c,
        frame: f,
        live,
        retracted: r,
    }
}

// ---------------------------------------------------------------------------
// (a) The B1 attack, under both table-owner shapes
// ---------------------------------------------------------------------------

/// The attack itself, against a database already migrated to head: a writer
/// of the claim's group sets the discarded design's setting to the retracted
/// row's id and deletes its own claim. A control claim holding only a live BBA
/// must delete cleanly on the same session first, so a refusal is the
/// retracted row's and nothing else's. Returns the attack's result unjudged.
async fn b1_attack(pool: &PgPool) -> (Result<u64, sqlx::Error>, World) {
    let w = world(pool).await;
    let group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(pool)
        .await
        .expect("the claim's group");
    let control_claim = claim(pool, w.writer, group).await;
    let control_bba = bba(pool, control_claim, w.frame, w.writer, None).await;

    let mut app = app_conn(pool, w.writer).await;
    let n = sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(control_claim)
        .execute(&mut app)
        .await
        .expect("control: the writer deletes its own claim that holds only a live BBA")
        .rows_affected();
    assert_eq!(n, 1, "control: the writer's claim delete takes its claim");
    assert!(
        !exists(pool, "mass_functions", control_bba).await,
        "control: the claim's live BBA goes with it (ON DELETE CASCADE)"
    );

    sqlx::query("SELECT set_config('epigraph.mf_purge_ids', $1, false)")
        .bind(w.retracted.to_string())
        .execute(&mut app)
        .await
        .expect("any session can set a custom setting");
    let r = sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(w.claim)
        .execute(&mut app)
        .await
        .map(|d| d.rows_affected());
    (r, w)
}

async fn assert_nothing_deleted(pool: &PgPool, w: &World) {
    assert!(
        exists(pool, "claims", w.claim).await,
        "the claim must survive the refused delete"
    );
    assert!(
        exists(pool, "mass_functions", w.retracted).await,
        "the retracted BBA must survive"
    );
    assert!(
        exists(pool, "mass_functions", w.live).await,
        "the live BBA rolls back with the delete"
    );
}

/// (a), shape 1: the tables belong to the migration runner, a superuser (the
/// harness). The cascade onto `mass_functions` runs as that owner.
#[sqlx::test(migrations = "../../migrations")]
async fn a_b1_attack_is_refused_sr09_when_a_superuser_owns_the_tables(pool: PgPool) {
    let owner_is_super: bool = sqlx::query_scalar(
        "SELECT r.rolsuper FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
          WHERE c.oid = 'public.mass_functions'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        owner_is_super,
        "fixture: shape 1 is a superuser-owned mass_functions"
    );
    let (r, w) = b1_attack(&pool).await;
    assert_sr09(refusal(r, "shape 1 attack"), "shape 1 (superuser owner)");
    assert_nothing_deleted(&pool, &w).await;
}

/// Every migration below 194, on one connection, then reset (001's pg_dump
/// header leaves session-level SETs behind).
async fn migrate_below_194(pool: &PgPool) {
    let below = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 194)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    below.run(&mut *conn).await.expect("migrate below 194");
    conn.execute("RESET ALL").await.expect("RESET ALL");
}

/// The rest of the migration set (194 and anything after it), as a deploy
/// applies it to a database at the previous head.
async fn migrate_rest(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = MIGRATOR.run(&mut *conn).await;
    conn.execute("RESET ALL").await.expect("RESET ALL");
    r
}

/// (a), shape 2: `claims`, `frames` and `mass_functions` are owned by a
/// NOSUPERUSER role that is NOT a maintenance member when 194 is applied (the
/// table owner on a production deployment is not measured; SPEC §14, M0-21).
/// The cascade then runs as that role, for which `epigraph_definer_bypass()`
/// is false and the grant helper must still answer.
#[sqlx::test(migrations = false)]
async fn a_b1_attack_is_refused_sr09_when_a_nosuperuser_non_maintenance_role_owns_the_tables(
    pool: PgPool,
) {
    migrate_below_194(&pool).await;
    let owner = format!("h10_owner_{}", Uuid::new_v4().simple());
    let harness: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.execute(format!("CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOBYPASSRLS").as_str())
        .await
        .expect("create the owner role");
    for t in ["claims", "frames", "mass_functions"] {
        pool.execute(format!("ALTER TABLE public.{t} OWNER TO {owner}").as_str())
            .await
            .unwrap_or_else(|e| panic!("re-own {t}: {e}"));
    }
    let migrated = migrate_rest(&pool).await;

    let shape: (bool, bool, String) = sqlx::query_as(
        "SELECT r.rolsuper, pg_has_role(r.oid, 'epigraph_maintenance', 'MEMBER'), r.rolname::text \
           FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
          WHERE c.oid = 'public.mass_functions'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let attack = if migrated.is_ok() {
        Some(b1_attack(&pool).await)
    } else {
        None
    };

    // Put the tables back and drop the role before asserting, so a failure
    // does not leave a cluster-level role behind.
    pool.execute(format!("REASSIGN OWNED BY {owner} TO {harness}").as_str())
        .await
        .expect("reassign");
    pool.execute(format!("DROP OWNED BY {owner}").as_str())
        .await
        .expect("drop owned");
    pool.execute(format!("DROP ROLE {owner}").as_str())
        .await
        .expect("drop role");

    migrated.expect("the rest of the migrations apply over a NOSUPERUSER table owner");
    assert_eq!(
        (shape.0, shape.1, shape.2.as_str()),
        (false, false, owner.as_str()),
        "fixture: shape 2 is a NOSUPERUSER, non-maintenance owner"
    );
    let (r, w) = attack.expect("the attack ran");
    assert_sr09(
        refusal(r, "shape 2 attack"),
        "shape 2 (NOSUPERUSER, non-maintenance owner)",
    );
    assert_nothing_deleted(&pool, &w).await;
}

// ---------------------------------------------------------------------------
// (b) (c) (d) (f): direct deletes
// ---------------------------------------------------------------------------

/// (b) A writer of the row's owning group deletes its retracted BBA directly
/// (row security admits the delete): SR09, the row stays.
#[sqlx::test(migrations = "../../migrations")]
async fn b_an_app_session_cannot_delete_a_retracted_bba(pool: PgPool) {
    let w = world(&pool).await;
    let mut app = app_conn(&pool, w.writer).await;
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&mut app)
        .await;
    assert_sr09(refusal(r, "app delete of a retracted BBA"), "(b)");
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted BBA stays"
    );
    // The same writer still deletes its LIVE row: the guard is for retracted rows.
    let n = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.live)
        .execute(&mut app)
        .await
        .expect("a live row deletes as before")
        .rows_affected();
    assert_eq!(n, 1);
}

/// (c) A NOSUPERUSER maintenance session holding no purge grant: SR09.
#[sqlx::test(migrations = "../../migrations")]
async fn c_a_maintenance_session_without_a_grant_cannot_delete_a_retracted_bba(pool: PgPool) {
    let w = world(&pool).await;
    let m = maintenance(&pool).await;
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&m)
        .await;
    assert_sr09(refusal(r, "maintenance delete without a grant"), "(c)");
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted BBA stays"
    );
    // A bulk delete that names a retracted row is refused as a whole.
    let r = sqlx::query("DELETE FROM mass_functions WHERE claim_id = $1")
        .bind(w.claim)
        .execute(&m)
        .await;
    assert_sr09(
        refusal(r, "maintenance bulk delete over a retracted row"),
        "(c) bulk",
    );
    assert!(
        exists(&pool, "mass_functions", w.live).await,
        "the bulk delete rolled back"
    );
}

/// (c2) The FRAME cascade (`mass_functions_frame_id_fkey ON DELETE CASCADE`,
/// SPEC §7.3 H10's second delete path): a NOSUPERUSER maintenance session's
/// `DELETE FROM frames` over a frame holding a retracted BBA, with no purge
/// first, is refused SR09, and the frame and both its BBAs survive. A control
/// frame holding only a live BBA deletes cleanly on the same session first,
/// so the refusal is the retracted row's and not another FK's.
#[sqlx::test(migrations = "../../migrations")]
async fn c2_a_frame_delete_that_cascades_onto_a_retracted_bba_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let control_frame = frame(&pool).await;
    let control_bba = bba(&pool, w.claim, control_frame, w.writer, None).await;
    let m = maintenance(&pool).await;

    let n = sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(control_frame)
        .execute(&m)
        .await
        .expect("control: a frame holding only a live BBA deletes")
        .rows_affected();
    assert_eq!(n, 1, "control: the frame delete takes its frame");
    assert!(
        !exists(&pool, "mass_functions", control_bba).await,
        "control: the frame's live BBA goes with it (ON DELETE CASCADE)"
    );

    let r = sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(w.frame)
        .execute(&m)
        .await;
    assert_sr09(
        refusal(r, "a frame delete cascading onto a retracted BBA"),
        "(c2)",
    );
    assert!(exists(&pool, "frames", w.frame).await, "the frame survives");
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted BBA survives"
    );
    assert!(
        exists(&pool, "mass_functions", w.live).await,
        "the live BBA rolls back with the delete"
    );
}

async fn grant_table_exists(pool: &PgPool) {
    let t: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.mass_function_purge_grants')::text")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        t.as_deref(),
        Some("mass_function_purge_grants"),
        "migration 194 creates public.mass_function_purge_grants (SPEC §2.8)"
    );
}

/// (d) THE RESIDUAL, pinned as documented (SPEC §2.8, §7.1 "Maintenance
/// logins", SF-18): the maintenance role holds INSERT on the grant table
/// because its definers need it, so a maintenance session that writes a grant
/// row for the current transaction can then delete the retracted row,
/// outside the audited definer. H10 defends against every non-maintenance
/// session; it does not defend against this (OD-9 is the tightening).
#[sqlx::test(migrations = "../../migrations")]
async fn d_residual_a_maintenance_session_that_writes_a_grant_row_can_delete(pool: PgPool) {
    grant_table_exists(&pool).await;
    let w = world(&pool).await;
    let m = maintenance(&pool).await;
    let mut tx = m.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO public.mass_function_purge_grants (mf_id, reason) VALUES ($1, 'residual')",
    )
    .bind(w.retracted)
    .execute(&mut *tx)
    .await
    .expect("the maintenance role holds INSERT on the grant table");
    let n = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&mut *tx)
        .await
        .expect("a grant for this transaction admits the delete")
        .rows_affected();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
    assert!(!exists(&pool, "mass_functions", w.retracted).await);
}

/// (d2) A grant admits ONLY the row it names: the helper matches
/// `mf_id = p_id` as well as the transaction. A maintenance transaction that
/// grants one retracted row and then deletes two is refused SR09 as a whole,
/// and both rows survive. Without the row predicate, any grant in the
/// transaction would admit every retracted row the statement reaches.
#[sqlx::test(migrations = "../../migrations")]
async fn d2_a_grant_admits_only_the_row_it_names(pool: PgPool) {
    grant_table_exists(&pool).await;
    let w = world(&pool).await;
    let (third, _) = fixture::seed_agent_with_group(&pool, "h10-third-source").await;
    let r2 = bba(&pool, w.claim, w.frame, third, None).await;
    retracted::retract_through_definer(&pool, r2).await;

    let m = maintenance(&pool).await;
    let mut tx = m.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO public.mass_function_purge_grants (mf_id, reason) VALUES ($1, 'one row')",
    )
    .bind(w.retracted)
    .execute(&mut *tx)
    .await
    .expect("the maintenance role holds INSERT on the grant table");
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = ANY($1)")
        .bind(vec![w.retracted, r2])
        .execute(&mut *tx)
        .await;
    assert_sr09(
        refusal(r, "a delete of two retracted rows under a grant for one"),
        "(d2)",
    );
    tx.rollback().await.unwrap();
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the granted row rolls back with the refused statement"
    );
    assert!(
        exists(&pool, "mass_functions", r2).await,
        "the ungranted retracted row survives"
    );
}

/// (f) A grant written by an EARLIER transaction admits nothing: the helper
/// matches `xact_id = pg_current_xact_id()`.
#[sqlx::test(migrations = "../../migrations")]
async fn f_a_grant_from_an_earlier_transaction_admits_no_delete(pool: PgPool) {
    grant_table_exists(&pool).await;
    let w = world(&pool).await;
    let m = maintenance(&pool).await;
    sqlx::query(
        "INSERT INTO public.mass_function_purge_grants (mf_id, reason) VALUES ($1, 'stale')",
    )
    .bind(w.retracted)
    .execute(&m)
    .await
    .expect("a grant row committed in its own transaction");
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&m)
        .await;
    assert_sr09(refusal(r, "delete under a stale grant"), "(f)");
    assert!(exists(&pool, "mass_functions", w.retracted).await);
}

// ---------------------------------------------------------------------------
// (e) (g): the purge definer and the application role
// ---------------------------------------------------------------------------

async fn proc_exists(pool: &PgPool, sig: &str) {
    let found: Option<String> = sqlx::query_scalar("SELECT to_regprocedure($1)::text")
        .bind(sig)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(found.is_some(), "migration 194 creates {sig}");
}

/// (e) The purge definer deletes the rows it is given (retracted or live),
/// writes ONE `mass_functions.purge` row carrying each deleted row (id, claim,
/// frame, perspective, retracted_at) and the reason, and leaves no grant row.
/// Purging first is the documented order for a claim hard-delete: afterwards
/// the claim deletes.
#[sqlx::test(migrations = "../../migrations")]
async fn e_the_purge_definer_deletes_audits_and_leaves_no_grant(pool: PgPool) {
    proc_exists(&pool, PURGE_DEFINER).await;
    let w = world(&pool).await;
    let m = maintenance(&pool).await;

    // A reason outside 1..2000 characters is refused with nothing deleted.
    for bad in ["   ", &"x".repeat(2001)] {
        let r = sqlx::query_scalar::<_, i32>("SELECT public.epigraph_purge_mass_functions($1, $2)")
            .bind(vec![w.retracted])
            .bind(bad)
            .fetch_one(&m)
            .await;
        let (code, _) = refusal(r, "a purge without a valid reason");
        assert_eq!(code, "22023", "a bad reason is 22023");
    }
    assert!(exists(&pool, "mass_functions", w.retracted).await);

    // A third, edge-keyed row, so the audit's perspective field is checked
    // against a real value rather than for presence.
    let group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&pool)
        .await
        .expect("the claim's group");
    let source = claim(&pool, w.writer, group).await;
    let e1 = edge(&pool, source, w.claim).await;
    let (third, _) = fixture::seed_agent_with_group(&pool, "h10-purge-edge-source").await;
    let edge_row = bba(&pool, w.claim, w.frame, third, Some(e1)).await;

    // The purge on a STAMPED maintenance transaction: the audit row names the
    // session principal (SPEC §2.8, "the purge definer's caller stamp").
    let mut tx = m.begin().await.unwrap();
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(w.writer.to_string())
        .execute(&mut *tx)
        .await
        .expect("stamp the maintenance transaction");
    let n: i32 = sqlx::query_scalar("SELECT public.epigraph_purge_mass_functions($1, $2)")
        .bind(vec![w.retracted, w.live, edge_row, Uuid::new_v4()])
        .bind("h10 test purge")
        .fetch_one(&mut *tx)
        .await
        .expect("the maintenance role purges");
    tx.commit().await.unwrap();
    assert_eq!(
        n, 3,
        "three rows existed and all went; an unknown id deletes nothing"
    );
    assert!(!exists(&pool, "mass_functions", w.retracted).await);
    assert!(!exists(&pool, "mass_functions", w.live).await);
    assert!(!exists(&pool, "mass_functions", edge_row).await);

    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mass_function_purge_grants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        grants, 0,
        "the definer deletes its grant rows in its own transaction"
    );

    let audits: Vec<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "SELECT agent_id, details FROM security_events WHERE event_type = 'mass_functions.purge'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audits.len(), 1, "one audit row per purge call: {audits:?}");
    let (agent, a) = &audits[0];
    assert_eq!(
        *agent,
        Some(w.writer),
        "the audit row names the purging session's principal: {a}"
    );
    assert_eq!(a["reason"], "h10 test purge", "{a}");
    assert_eq!(a["requested"], 4, "four distinct ids were passed: {a}");
    assert_eq!(a["deleted"], 3, "{a}");
    let rows = a["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("rows array: {a}"));
    assert_eq!(rows.len(), 3, "{a}");
    let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});
    for (id, retracted, perspective) in [
        (w.retracted, true, None),
        (w.live, false, None),
        (edge_row, false, Some(e1)),
    ] {
        let row = rows
            .iter()
            .find(|r| r["id"] == id.to_string())
            .unwrap_or_else(|| panic!("the audit names {id}: {a}"));
        assert_eq!(row["claim_id"], w.claim.to_string(), "{row}");
        assert_eq!(row["frame_id"], w.frame.to_string(), "{row}");
        assert_eq!(
            row["perspective_id"],
            perspective.map_or(serde_json::Value::Null, |p| p.to_string().into()),
            "{row}"
        );
        assert_eq!(!row["retracted_at"].is_null(), retracted, "{row}");
        assert_eq!(
            row["masses"], masses,
            "the audit keeps the purged assessment: {row}"
        );
    }

    // Purge, then delete: the claim now deletes on the writer's own session.
    let mut app = app_conn(&pool, w.writer).await;
    let n = sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(w.claim)
        .execute(&mut app)
        .await
        .expect("after the purge the claim delete cascades onto nothing retracted")
        .rows_affected();
    assert_eq!(n, 1);
}

/// (g) The application role cannot read, insert or delete purge grants, and
/// cannot execute the purge definer (42501). It can call the grant helper (the
/// guard runs as the invoker), which answers false.
#[sqlx::test(migrations = "../../migrations")]
async fn g_the_app_role_cannot_touch_the_grant_table_or_run_the_purge(pool: PgPool) {
    grant_table_exists(&pool).await;
    proc_exists(&pool, PURGE_DEFINER).await;
    let w = world(&pool).await;
    let mut app = app_conn(&pool, w.writer).await;
    for (what, sql) in [
        (
            "SELECT",
            "SELECT count(*) FROM public.mass_function_purge_grants WHERE mf_id = $1",
        ),
        (
            "INSERT",
            "INSERT INTO public.mass_function_purge_grants (mf_id, reason) VALUES ($1, 'x')",
        ),
        (
            "DELETE",
            "DELETE FROM public.mass_function_purge_grants WHERE mf_id = $1",
        ),
        (
            "EXECUTE",
            "SELECT public.epigraph_purge_mass_functions(ARRAY[$1]::uuid[], 'x')",
        ),
    ] {
        let r = sqlx::query(sql).bind(w.retracted).execute(&mut app).await;
        let (code, message) = refusal(r, what);
        assert_eq!(code, "42501", "{what} as epigraph_app: {message}");
    }
    let granted: bool = sqlx::query_scalar("SELECT public.epigraph_mf_purge_granted($1)")
        .bind(w.retracted)
        .fetch_one(&mut app)
        .await
        .expect("the app role executes the helper");
    assert!(!granted);
    assert!(exists(&pool, "mass_functions", w.retracted).await);
}

// ---------------------------------------------------------------------------
// (h) (i): the re-bodied cascade definer
// ---------------------------------------------------------------------------

/// (h) The owner arm on an application session skips a retracted row: it is
/// neither deleted (no SR09) nor counted toward CD02. CD02 still refuses
/// another writer's live row, and its count no longer includes the session's
/// own retracted row.
#[sqlx::test(migrations = "../../migrations")]
async fn h_the_owner_arm_skips_retracted_rows_and_still_refuses_cd02(pool: PgPool) {
    let (writer, group) = fixture::seed_agent_with_group(&pool, "h10-owner").await;
    let (other, other_group) = fixture::seed_agent_with_group(&pool, "h10-other").await;
    let (third, _) = fixture::seed_agent_with_group(&pool, "h10-third").await;
    let f = frame(&pool).await;
    let a = claim(&pool, writer, group).await;
    let b = claim(&pool, writer, group).await;
    let o = claim(&pool, other, other_group).await;

    // Edge 1: the writer's own live and retracted edge-keyed rows.
    let e1 = edge(&pool, a, b).await;
    let own_live = bba(&pool, b, f, writer, Some(e1)).await;
    let own_retracted = bba(&pool, b, f, third, Some(e1)).await;
    retracted::retract_through_definer(&pool, own_retracted).await;

    let mut app = app_conn(&pool, writer).await;
    let n = delete_edge_bbas(&mut app, &[e1], EdgeBbaCascade::RetractionCascade)
        .await
        .expect("the owner arm deletes the session's own live rows and is not refused");
    assert_eq!(n, 1, "only the live row is deleted");
    assert!(!exists(&pool, "mass_functions", own_live).await);
    assert!(
        exists(&pool, "mass_functions", own_retracted).await,
        "the retracted row is kept"
    );

    // Edge 2: another writer's live (public) row and the writer's retracted one.
    let e2 = edge(&pool, a, o).await;
    let foreign_live = bba(&pool, o, f, other, Some(e2)).await;
    let own_retracted_2 = bba(&pool, b, f, writer, Some(e2)).await;
    retracted::retract_through_definer(&pool, own_retracted_2).await;
    let r = delete_edge_bbas(&mut app, &[e2], EdgeBbaCascade::RetractionCascade).await;
    let (code, message) = refusal(r, "another writer's live row");
    assert_eq!(code, "42501");
    assert!(
        message.starts_with("CD02: 1 of 1 "),
        "CD02 counts the foreign live row only, not the retracted one: {message:?}"
    );
    assert!(exists(&pool, "mass_functions", foreign_live).await);
    assert!(exists(&pool, "mass_functions", own_retracted_2).await);
}

/// (h2) The CD02-count half of the owner-arm predicate on its own: an edge
/// whose ONLY row is another group's public RETRACTED row. 117's owner arm
/// counted it as a readable row the session cannot delete and refused the
/// whole call `CD02: 1 of 1`; after 194 the candidate select skips it, so the
/// call deletes nothing, is not refused, and the row stays.
#[sqlx::test(migrations = "../../migrations")]
async fn h2_the_owner_arm_neither_counts_nor_deletes_another_writers_retracted_row(pool: PgPool) {
    let (writer, group) = fixture::seed_agent_with_group(&pool, "h10-h2-owner").await;
    let (other, other_group) = fixture::seed_agent_with_group(&pool, "h10-h2-other").await;
    let f = frame(&pool).await;
    let a = claim(&pool, writer, group).await;
    let o = claim(&pool, other, other_group).await;
    let e = edge(&pool, a, o).await;
    let foreign_retracted = bba(&pool, o, f, other, Some(e)).await;
    retracted::retract_through_definer(&pool, foreign_retracted).await;
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM mass_functions WHERE id = $1")
            .bind(foreign_retracted)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        owner,
        Some(other_group),
        "fixture: the retracted row belongs to the other writer's group"
    );

    let mut app = app_conn(&pool, writer).await;
    let n = delete_edge_bbas(&mut app, &[e], EdgeBbaCascade::RetractionCascade)
        .await
        .expect("another writer's retracted row is not counted toward CD02");
    assert_eq!(n, 0, "nothing on the edge is the session's to delete");
    assert!(
        exists(&pool, "mass_functions", foreign_retracted).await,
        "the retracted row is kept"
    );
}

/// (i) The privileged arm (a maintenance session calling the definer) deletes
/// the edges' live rows and keeps the retracted ones, of every owner.
#[sqlx::test(migrations = "../../migrations")]
async fn i_the_privileged_arm_skips_retracted_rows(pool: PgPool) {
    let (writer, group) = fixture::seed_agent_with_group(&pool, "h10-priv").await;
    let (second, _) = fixture::seed_agent_with_group(&pool, "h10-priv-2").await;
    let f = frame(&pool).await;
    let a = claim(&pool, writer, group).await;
    let b = claim(&pool, writer, group).await;
    let e = edge(&pool, a, b).await;
    let live = bba(&pool, b, f, writer, Some(e)).await;
    let r = bba(&pool, b, f, second, Some(e)).await;
    retracted::retract_through_definer(&pool, r).await;

    let m = maintenance(&pool).await;
    let n: i64 = sqlx::query_scalar(
        "SELECT public.epigraph_cascade_delete_edge_bbas($1, 'retraction_cascade')",
    )
    .bind(vec![e])
    .fetch_one(&m)
    .await
    .expect("the privileged arm completes with a retracted row on the edge");
    assert_eq!(n, 1, "only the live row is deleted");
    assert!(!exists(&pool, "mass_functions", live).await);
    assert!(
        exists(&pool, "mass_functions", r).await,
        "the retracted row is kept"
    );
}

// ---------------------------------------------------------------------------
// (j): the precondition
// ---------------------------------------------------------------------------

async fn cascade_definer_facts(pool: &PgPool) -> (String, Vec<String>) {
    sqlx::query_as(
        "SELECT md5(p.prosrc), COALESCE(p.proconfig, ARRAY[]::text[]) FROM pg_proc p \
          WHERE p.oid = $1::regprocedure",
    )
    .bind(CASCADE_DEFINER)
    .fetch_one(pool)
    .await
    .expect("the cascade definer exists")
}

fn assert_precondition_refusal(r: Result<(), sqlx::migrate::MigrateError>, what: &str) {
    let e = r.expect_err(&format!("194 must refuse {what}"));
    let text = format!("{e}");
    let code = match &e {
        sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(db))
        | sqlx::migrate::MigrateError::ExecuteMigration(sqlx::Error::Database(db), _) => {
            db.code().map(|c| c.to_string())
        }
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("55000"), "{what}: {text}");
    assert!(
        text.contains("194:"),
        "{what}: the refusal names 194: {text}"
    );
}

async fn applied_194(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 194)")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The measurement behind [`MD5_117`]: below 194 the definer is 117's body on
/// 117's (pre-190) path.
#[sqlx::test(migrations = false)]
async fn the_cascade_definer_before_194_is_117s_body(pool: PgPool) {
    migrate_below_194(&pool).await;
    let (md5, config) = cascade_definer_facts(&pool).await;
    assert_eq!(md5, MD5_117, "md5(prosrc) of the definer below 194");
    assert_eq!(config, vec!["search_path=pg_catalog, public".to_string()]);
}

/// (j) 194 refuses (55000, nothing changed) over a body whose md5 is not
/// 117's, and over a `proconfig` other than the pre- and post-190 paths; it
/// applies over the post-190 path (slot 190 changes `proconfig` only) and
/// states `pg_catalog, public, pg_temp` either way. The pre-190 path is every
/// fresh database's (each `#[sqlx::test]` above).
#[sqlx::test(migrations = false)]
async fn j_the_precondition_accepts_only_117s_body_on_the_two_paths(pool: PgPool) {
    migrate_below_194(&pool).await;
    let original: String = sqlx::query_scalar("SELECT pg_get_functiondef($1::regprocedure)")
        .bind(CASCADE_DEFINER)
        .fetch_one(&pool)
        .await
        .unwrap();

    // A different body (one added comment), same path.
    let edited = original.replacen("BEGIN", "BEGIN\n    -- another migration's edit", 1);
    assert_ne!(edited, original);
    pool.execute(edited.as_str())
        .await
        .expect("re-body the definer");
    assert_precondition_refusal(migrate_rest(&pool).await, "a body other than 117's");
    assert!(!applied_194(&pool).await, "nothing was applied");
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('public.mass_function_purge_grants')::text"
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .is_none(),
        "the refused migration created nothing"
    );
    pool.execute(original.as_str())
        .await
        .expect("restore 117's body");

    // 117's body on a third path.
    pool.execute(
        format!("ALTER FUNCTION {CASCADE_DEFINER} SET search_path = public, pg_temp").as_str(),
    )
    .await
    .unwrap();
    assert_precondition_refusal(migrate_rest(&pool).await, "a third proconfig");
    assert!(!applied_194(&pool).await);

    // 117's body with NO search_path at all (a re-body that dropped the SET
    // clause): proconfig is NULL, which is neither accepted value.
    pool.execute(format!("ALTER FUNCTION {CASCADE_DEFINER} RESET search_path").as_str())
        .await
        .unwrap();
    assert_eq!(
        cascade_definer_facts(&pool).await,
        (MD5_117.to_string(), Vec::<String>::new()),
        "fixture: 117's body with no proconfig"
    );
    assert_precondition_refusal(migrate_rest(&pool).await, "a NULL proconfig");
    assert!(!applied_194(&pool).await);

    // 117's body on 190's path: applies.
    pool.execute(
        format!("ALTER FUNCTION {CASCADE_DEFINER} SET search_path = pg_catalog, public, pg_temp")
            .as_str(),
    )
    .await
    .unwrap();
    assert_eq!(
        cascade_definer_facts(&pool).await.0,
        MD5_117,
        "190's change keeps the md5"
    );
    migrate_rest(&pool)
        .await
        .expect("194 applies over the post-190 path");
    assert!(applied_194(&pool).await);
    let (md5, config) = cascade_definer_facts(&pool).await;
    assert_ne!(md5, MD5_117, "194 re-bodied the definer");
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()]
    );
}

/// (j2) 194 refuses (55000, nothing created) when the definer it re-bodies
/// does not exist at all: an absent function has no md5 to match.
#[sqlx::test(migrations = false)]
async fn j2_the_precondition_refuses_an_absent_definer(pool: PgPool) {
    migrate_below_194(&pool).await;
    pool.execute(format!("DROP FUNCTION {CASCADE_DEFINER}").as_str())
        .await
        .expect("drop the cascade definer");
    assert_precondition_refusal(migrate_rest(&pool).await, "an absent definer");
    assert!(!applied_194(&pool).await, "nothing was applied");
    let created: Option<String> = sqlx::query_scalar("SELECT to_regprocedure($1)::text")
        .bind(CASCADE_DEFINER)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        created.is_none(),
        "the refused migration did not create the definer"
    );
}

/// At head (over the pre-190 path every fresh database has), the re-body
/// states `pg_catalog, public, pg_temp` (SPEC §7.1 SF-12) and the new objects
/// are on 172's form.
#[sqlx::test(migrations = "../../migrations")]
async fn at_head_the_rebody_and_the_new_definers_pin_pg_temp_last(pool: PgPool) {
    proc_exists(&pool, PURGE_DEFINER).await;
    let (_, config) = cascade_definer_facts(&pool).await;
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()]
    );
    for (sig, definer, volatility) in [
        (PURGE_DEFINER, true, "v"),
        (GRANT_HELPER, true, "s"),
        (GUARD_FN, false, "v"),
    ] {
        let (secdef, cfg, owner, vol): (bool, Vec<String>, String, String) = sqlx::query_as(
            "SELECT p.prosecdef, COALESCE(p.proconfig, ARRAY[]::text[]), \
                    pg_get_userbyid(p.proowner)::text, p.provolatile::text \
               FROM pg_proc p WHERE p.oid = $1::regprocedure",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{sig}: {e}"));
        assert_eq!(secdef, definer, "{sig} SECURITY DEFINER = {definer}");
        assert_eq!(vol, volatility, "{sig} volatility");
        assert_eq!(
            cfg,
            vec!["search_path=pg_catalog, pg_temp".to_string()],
            "{sig}"
        );
        if definer {
            assert_eq!(owner, "epigraph_maintenance", "{sig} owner");
        }
    }
    let trigger: (String, bool) = sqlx::query_as(
        "SELECT pg_get_triggerdef(t.oid), t.tgenabled = 'O' FROM pg_trigger t \
          WHERE t.tgrelid = 'public.mass_functions'::regclass \
            AND t.tgname = 'mass_functions_retracted_delete_guard'",
    )
    .fetch_one(&pool)
    .await
    .expect("the H10 trigger exists");
    assert!(trigger.1, "the trigger is enabled");
    assert!(
        trigger.0.contains("BEFORE DELETE")
            && trigger.0.contains("FOR EACH ROW")
            && trigger.0.contains("WHEN ((old.retracted_at IS NOT NULL))"),
        "{}",
        trigger.0
    );
}

// ---------------------------------------------------------------------------
// (k): undo
// ---------------------------------------------------------------------------

/// (k) `docs/runbooks/194-undo.sql` removes every object 194 created, restores
/// 117's body (its md5) stating `pg_catalog, public, pg_temp`, after which a
/// retracted row is deletable again; and 194's own text then applies again
/// over the undone state (its precondition accepts it).
#[sqlx::test(migrations = "../../migrations")]
async fn k_the_undo_restores_117s_body_and_removes_every_new_object(pool: PgPool) {
    let undo = repo_file("docs/runbooks/194-undo.sql");
    let m194 = repo_file("migrations/194_retracted_bba_delete_guard.sql");
    let w = world(&pool).await;

    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo runs");
    let (md5, config) = cascade_definer_facts(&pool).await;
    assert_eq!(md5, MD5_117, "117's body is restored");
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()]
    );
    let (owner, acl_app): (String, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = $1::regprocedure",
    )
    .bind(CASCADE_DEFINER)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        owner, "epigraph_maintenance",
        "CREATE OR REPLACE keeps the owner"
    );
    assert!(acl_app, "and the ACL");
    for sig in [PURGE_DEFINER, GRANT_HELPER, GUARD_FN] {
        let found: Option<String> = sqlx::query_scalar("SELECT to_regprocedure($1)::text")
            .bind(sig)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(found.is_none(), "the undo drops {sig}");
    }
    let table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.mass_function_purge_grants')::text")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(table.is_none(), "the undo drops the grant table");
    let m = maintenance(&pool).await;
    let n = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&m)
        .await
        .expect("with the guard gone a retracted row deletes again")
        .rows_affected();
    assert_eq!(n, 1);

    // Round trip: 194's text applies again over the undone state.
    sqlx::raw_sql(&format!("BEGIN;\n{m194}\nCOMMIT;"))
        .execute(&pool)
        .await
        .expect("194 re-applies after its undo");
    proc_exists(&pool, PURGE_DEFINER).await;
    let w2 = world(&pool).await;
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w2.retracted)
        .execute(&m)
        .await;
    assert_sr09(refusal(r, "after the re-apply"), "(k) re-apply");
}
