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
//! The test-lens follow-ups (backlog 129f99ad): T-N3, arms (c) and (d) as a
//! real member login (since 251: the member's own grant is refused); T-N6,
//! the guard's fail mode after the ledger consumer (194's grant helper
//! before 251) is re-owned; T-N7, every test that creates a cluster role removes it even
//! when it panics ([`with_cluster_role`]). T-N9 is in
//! `fk_action_guard_ratchet.rs`.
//!
//! Every retracted row is made by migration 184's definer on the application
//! role (`support/retracted_bba_fixture.rs`). The privileged cases run on a
//! NOSUPERUSER `epigraph_maintenance` session (SPEC §12), checked before use.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

#[path = "viewer_fixture.rs"]
mod fixture;
#[path = "support/maintenance_login.rs"]
mod login;
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
/// Migration 251's ledger consumer, the one call the delete guard makes.
const GRANT_CONSUMER: &str = "public.epigraph_mf_guard_consume(text, uuid, jsonb)";
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
    match perspective {
        Some(edge) => {
            MassFunctionRepository::store_in_slot(
                pool,
                claim,
                frame,
                Some(agent),
                epigraph_db::BbaSlot::Edge(edge),
                &serde_json::json!({"0": 0.6, "0,1": 0.4}),
                None,
                None,
                Some(1.0),
                None,
                "unknown",
                None,
            )
            .await
        }
        None => {
            MassFunctionRepository::store_with_perspective(
                pool,
                claim,
                frame,
                Some(agent),
                None,
                &serde_json::json!({"0": 0.6, "0,1": 0.4}),
                None,
                None,
                Some(1.0),
                None,
                "unknown",
                None,
            )
            .await
        }
    }
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

/// A future that catches a panic raised while polling the future it wraps
/// and returns it as `Err` (the `catch_unwind` of `futures`, which this
/// crate does not depend on). It polls on the caller's task, so the wrapped
/// future need not be `Send`.
struct CatchUnwind<F>(std::pin::Pin<Box<F>>);

impl<F: std::future::Future> std::future::Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let inner = self.0.as_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(v)) => std::task::Poll::Ready(Ok(v)),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    }
}

/// Run `body` with the cluster-level role `role` created first (by `ddl`,
/// which names it), and ALWAYS remove that role afterwards: everything it
/// owns in this database is reassigned to the harness login and its grants
/// dropped, then the role is dropped. A panic inside `body` (an `expect` in a
/// fixture, a failed assertion) is caught, the cleanup still runs, and the
/// panic is then resumed. A test database is thrown away after the test, but
/// a ROLE is cluster-wide: without this a mid-test panic leaks it into every
/// later test on the cluster (T-N7).
async fn with_cluster_role<T, F, Fut>(pool: &PgPool, role: &str, ddl: &str, body: F) -> T
where
    F: FnOnce(PgPool) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let harness: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(pool)
        .await
        .expect("the harness login");
    pool.execute(ddl).await.expect("create the cluster role");
    let caught = CatchUnwind(Box::pin(body(pool.clone()))).await;
    // Fresh statements on the pool: a panic may have dropped a connection
    // mid-transaction, which the pool then discards.
    pool.execute(format!("REASSIGN OWNED BY {role} TO {harness}").as_str())
        .await
        .expect("reassign the role's objects");
    pool.execute(format!("DROP OWNED BY {role}").as_str())
        .await
        .expect("drop the role's grants");
    pool.execute(format!("DROP ROLE {role}").as_str())
        .await
        .expect("drop the role");
    match caught {
        Ok(t) => t,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn role_exists(pool: &PgPool, role: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(role)
        .fetch_one(pool)
        .await
        .expect("read pg_roles")
}

/// (a), shape 2: `claims`, `frames` and `mass_functions` are owned by a
/// NOSUPERUSER role that is NOT a maintenance member when 194 is applied (the
/// deployed table-owner shape is not fixed by the schema, so both shapes are
/// pinned). The cascade then runs as that role, for which
/// `epigraph_definer_bypass()` is false and the grant helper must still answer.
/// The role is created and removed by [`with_cluster_role`], so a panic in
/// the migration or the attack never leaks it.
#[sqlx::test(migrations = false)]
async fn a_b1_attack_is_refused_sr09_when_a_nosuperuser_non_maintenance_role_owns_the_tables(
    pool: PgPool,
) {
    migrate_below_194(&pool).await;
    let owner = format!("h10_owner_{}", Uuid::new_v4().simple());
    let o = owner.clone();
    let (migrated, shape, attack) = with_cluster_role(
        &pool,
        &owner,
        &format!("CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOBYPASSRLS"),
        |pool| async move {
            for t in ["claims", "frames", "mass_functions"] {
                pool.execute(format!("ALTER TABLE public.{t} OWNER TO {o}").as_str())
                    .await
                    .unwrap_or_else(|e| panic!("re-own {t}: {e}"));
            }
            let migrated = migrate_rest(&pool).await;
            let shape: (bool, bool, String) = sqlx::query_as(
                "SELECT r.rolsuper, pg_has_role(r.oid, 'epigraph_maintenance', 'MEMBER'), \
                        r.rolname::text \
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
            (migrated.map_err(|e| e.to_string()), shape, attack)
        },
    )
    .await;

    assert!(!role_exists(&pool, &owner).await, "the owner role is gone");
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

/// T-N7: [`with_cluster_role`] removes its role when the body PANICS part
/// way, after re-owning a table to it (as shape 2 does), and then resumes
/// the panic. The table is owned by the harness again.
#[sqlx::test(migrations = "../../migrations")]
async fn t_n7_a_panicking_body_still_drops_its_cluster_role(pool: PgPool) {
    let role = format!("h10_leak_probe_{}", Uuid::new_v4().simple());
    let (p, r) = (pool.clone(), role.clone());
    let outcome = CatchUnwind(Box::pin(async move {
        let r2 = r.clone();
        with_cluster_role(
            &p,
            &r,
            &format!("CREATE ROLE {r} NOLOGIN NOSUPERUSER NOBYPASSRLS"),
            |pool| async move {
                pool.execute(format!("ALTER TABLE public.frames OWNER TO {r2}").as_str())
                    .await
                    .expect("re-own frames");
                panic!("a fixture fails mid-way");
            },
        )
        .await
    }))
    .await;
    let err = outcome.expect_err("the body's panic is resumed after the cleanup");
    assert_eq!(
        err.downcast_ref::<&str>().copied(),
        Some("a fixture fails mid-way"),
        "the body's own panic is the one resumed"
    );
    assert!(
        !role_exists(&pool, &role).await,
        "the role does not outlive the panicking body"
    );
    let owner: String = sqlx::query_scalar(
        "SELECT r.rolname::text FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner \
          WHERE c.oid = 'public.frames'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let harness: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(owner, harness, "frames is owned by the harness again");
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

/// The statements a session could run on the grant ledger, each of which 251
/// refuses every maintenance session (42501, nothing written or read).
const GRANT_TABLE_STATEMENTS: &[(&str, &str)] = &[
    (
        "INSERT",
        "INSERT INTO public.mass_function_purge_grants (mf_id, kind, reason) \
         VALUES ($1, 'purge', 'forged')",
    ),
    (
        "UPDATE",
        "UPDATE public.mass_function_purge_grants SET reason = 'x' WHERE mf_id = $1",
    ),
    (
        "DELETE",
        "DELETE FROM public.mass_function_purge_grants WHERE mf_id = $1",
    ),
    (
        "SELECT",
        "SELECT count(*) FROM public.mass_function_purge_grants WHERE mf_id = $1",
    ),
];

/// One maintenance session's attempt on the residual 194 recorded: write a
/// purge grant for the retracted row itself, then delete the row, in ONE
/// transaction. Every grant-table statement must be refused 42501 and the
/// delete SR09, with the row left in place.
async fn assert_no_forged_purge(session: &PgPool, pool: &PgPool, w: &World, who: &str) {
    for (what, sql) in GRANT_TABLE_STATEMENTS {
        let mut tx = session.begin().await.unwrap();
        let r = sqlx::query(sql).bind(w.retracted).execute(&mut *tx).await;
        let (code, message) = refusal(r, &format!("{who}: {what} on the grant table"));
        assert_eq!(
            code, "42501",
            "{who}: {what} on the grant table is a privilege refusal: {message}"
        );
        assert!(
            message.contains("mass_function_purge_grants"),
            "{who}: {what}: {message}"
        );
        tx.rollback().await.unwrap();
    }
    // The attack as one transaction: whatever the grant attempt did, the
    // delete that follows it in the same transaction is refused SR09.
    let mut tx = session.begin().await.unwrap();
    sqlx::query("SAVEPOINT forge")
        .execute(&mut *tx)
        .await
        .unwrap();
    let forged = sqlx::query(GRANT_TABLE_STATEMENTS[0].1)
        .bind(w.retracted)
        .execute(&mut *tx)
        .await;
    assert!(forged.is_err(), "{who}: the forged grant is refused");
    sqlx::query("ROLLBACK TO SAVEPOINT forge")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&mut *tx)
        .await;
    assert_sr09(
        refusal(r, &format!("{who}: delete after a forged grant")),
        who,
    );
    tx.rollback().await.unwrap();
    assert!(
        exists(pool, "mass_functions", w.retracted).await,
        "{who}: the retracted row survives"
    );
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'mass_functions.purge'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audits, 0, "{who}: nothing was purged");
}

/// (d) THE RESIDUAL 194 RECORDED, CLOSED BY 251 (backlog 6bdac68f): before
/// 251 the maintenance role held INSERT on the grant table (its definers
/// needed it), so any maintenance session could write a grant row for the
/// current transaction and then delete a retracted row outside the audited
/// definer. Since 251 only `epigraph_bba_guard_owner`, a NOLOGIN role no login
/// can act as, holds anything on the table, and it writes it only through
/// `epigraph_mf_guard_grant` (d4). Checked on BOTH maintenance shapes: a REAL NOSUPERUSER login
/// that is a member of it, connected with its own password (its
/// `current_user` is the login, as in production), and the role itself
/// (`SET SESSION AUTHORIZATION epigraph_maintenance`).
#[sqlx::test(migrations = "../../migrations")]
async fn d_a_maintenance_session_cannot_forge_a_purge_grant(pool: PgPool) {
    grant_table_exists(&pool).await;
    let w = world(&pool).await;

    // The real login first: it is the credential production hands out, so it
    // is the shape whose refusal on the pre-251 schema must be observed.
    let (role, login) = login::maintenance_login(&pool, "t63d").await;
    assert_no_forged_purge(&login, &pool, &w, "a maintenance login").await;
    login::drop_login(&pool, &role, login).await;

    let m = maintenance(&pool).await;
    assert_no_forged_purge(&m, &pool, &w, "the maintenance role").await;
}

/// (d3) The purge definer still works for a REAL maintenance login after 251:
/// it deletes the retracted row, writes one `mass_functions.purge` row, and
/// keeps its grant in the ledger, consumed by the guard with the row and
/// naming the login.
#[sqlx::test(migrations = "../../migrations")]
async fn d3_a_maintenance_login_still_purges_through_the_definer(pool: PgPool) {
    proc_exists(&pool, PURGE_DEFINER).await;
    let w = world(&pool).await;
    let (role, login) = login::maintenance_login(&pool, "t63p").await;
    let n = sqlx::query_scalar::<_, i32>("SELECT public.epigraph_purge_mass_functions($1, $2)")
        .bind(vec![w.retracted])
        .bind("t63 login purge")
        .fetch_one(&login)
        .await;
    login::drop_login(&pool, &role, login).await;
    assert_eq!(n.expect("the maintenance login purges"), 1);
    assert!(!exists(&pool, "mass_functions", w.retracted).await);
    let (grants, audits): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM public.mass_function_purge_grants \
                  WHERE mf_id = $1 AND kind = 'purge' AND reason = 't63 login purge' \
                    AND grant_login = $2 AND consumed_login = $2 \
                    AND consumed_row->>'id' = $1::text), \
                (SELECT count(*) FROM security_events \
                  WHERE event_type = 'mass_functions.purge' \
                    AND details->>'reason' = 't63 login purge')",
    )
    .bind(w.retracted)
    .bind(&role)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (grants, audits),
        (1, 1),
        "one consumed ledger grant naming the login, one audit row"
    );
}

/// `(kind, reason, grant_login, consumed_login, consumed_row)` of a ledger row.
type LedgerRow = (
    String,
    String,
    String,
    Option<String>,
    Option<serde_json::Value>,
);

/// (d4) What a maintenance login CAN still do, and what it leaves: call the
/// ledger's grant function itself (its role must, since the maintenance-owned
/// purge and un-retract definers call it), then delete the retracted row
/// directly. That is the audited purge without the definer's event, and the
/// ledger keeps a row the login cannot remove: the kind, the row id, the
/// reason, the login as granter and consumer, and the row's content as the
/// guard saw it. Before 251 this delete left nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn d4_a_maintenance_login_that_grants_itself_leaves_a_ledger_row_it_cannot_remove(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let (role, login) = login::maintenance_login(&pool, "t63g").await;
    let mut tx = login.begin().await.unwrap();
    let granted: i32 = sqlx::query_scalar(
        "SELECT public.epigraph_mf_guard_grant('purge', ARRAY[$1]::uuid[], 'by hand', NULL)",
    )
    .bind(w.retracted)
    .fetch_one(&mut *tx)
    .await
    .expect("the maintenance role executes the ledger's grant function");
    assert_eq!(granted, 1);
    let n = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&mut *tx)
        .await
        .expect("the grant admits the delete")
        .rows_affected();
    assert_eq!(n, 1);
    tx.commit().await.unwrap();

    let mut erase = Vec::new();
    for sql in [
        "DELETE FROM public.mass_function_purge_grants WHERE mf_id = $1",
        "UPDATE public.mass_function_purge_grants SET consumed_row = NULL WHERE mf_id = $1",
        "SELECT public.epigraph_mf_guard_consume('purge', $1, '{}'::jsonb)",
    ] {
        erase.push((
            sql,
            sqlx::query(sql).bind(w.retracted).execute(&login).await,
        ));
    }
    login::drop_login(&pool, &role, login).await;

    let rows: Vec<LedgerRow> = sqlx::query_as(
        "SELECT kind, reason, grant_login::text, consumed_login::text, consumed_row \
               FROM public.mass_function_purge_grants WHERE mf_id = $1",
    )
    .bind(w.retracted)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (kind, reason, granter, consumer, row) = &rows[0];
    assert_eq!(
        (kind.as_str(), reason.as_str()),
        ("purge", "by hand"),
        "{rows:?}"
    );
    assert_eq!(granter, &role, "the ledger names the login that granted");
    assert_eq!(consumer.as_deref(), Some(role.as_str()));
    let row = row.as_ref().expect("the guard recorded the deleted row");
    assert_eq!(row["id"], w.retracted.to_string(), "{row}");
    assert!(!row["retracted_at"].is_null(), "the row as deleted: {row}");
    assert_eq!(row["claim_id"], w.claim.to_string(), "{row}");

    for (sql, r) in erase {
        match r {
            Err(e) => assert_eq!(
                e.as_database_error().and_then(|d| d.code()).as_deref(),
                Some("42501"),
                "{sql}: {e}"
            ),
            // The consume function answers false: the grant is spent.
            Ok(done) => assert_eq!(done.rows_affected(), 1, "{sql}"),
        }
    }
    let still: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT consumed_row FROM public.mass_function_purge_grants WHERE mf_id = $1",
    )
    .bind(w.retracted)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        still.as_ref().map(|r| r["id"].clone()),
        Some(serde_json::Value::String(w.retracted.to_string())),
        "nothing the login ran erased or rewrote the ledger row"
    );
}

/// Write a purge grant for `id` the way the purge definer does since 251:
/// through `epigraph_mf_guard_grant`, as the maintenance role, on the harness
/// transaction, which stays the maintenance role for what follows.
async fn grant_through_ledger(tx: &mut PgConnection, id: Uuid, reason: &str) {
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_maintenance")
        .execute(&mut *tx)
        .await
        .expect("act as the maintenance role");
    sqlx::query("SELECT public.epigraph_mf_guard_grant('purge', ARRAY[$1]::uuid[], $2, NULL)")
        .bind(id)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .expect("the maintenance role writes a grant through the ledger");
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

    let mut tx = pool.begin().await.unwrap();
    grant_through_ledger(&mut tx, w.retracted, "one row").await;
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
    let mut tx = pool.begin().await.unwrap();
    grant_through_ledger(&mut tx, w.retracted, "stale").await;
    tx.commit()
        .await
        .expect("a grant row committed in its own transaction");
    let r = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(w.retracted)
        .execute(&m)
        .await;
    assert_sr09(refusal(r, "delete under a stale grant"), "(f)");
    assert!(exists(&pool, "mass_functions", w.retracted).await);
}

/// T-N3: arms (c) and (d) as a REAL login that is a MEMBER of
/// `epigraph_maintenance` (NOSUPERUSER, INHERIT), the shape a deployed
/// maintenance session has. [`maintenance`] reaches the role by `SET SESSION
/// AUTHORIZATION epigraph_maintenance`, where `session_user` IS the role;
/// here `session_user` is the member login, so every check keyed on role
/// membership (`epigraph_bypass()`'s `pg_has_role(session_user, ...)`, the
/// inherited grants on the grant table and on `mass_functions`) is
/// exercised as production runs it. (c): with no grant the delete is SR09
/// and the row survives; (d): the residual 194 documented (a grant row a
/// maintenance login writes for its own transaction admitted the delete) is
/// CLOSED for a member login since migration 251: the ledger is owned by
/// `epigraph_bba_guard_owner` and the maintenance role holds no INSERT on
/// it, so the login's own grant row is refused 42501 and nothing is deleted.
#[sqlx::test(migrations = "../../migrations")]
async fn t_n3_arms_c_and_d_hold_for_a_real_maintenance_member_login(pool: PgPool) {
    grant_table_exists(&pool).await;
    let w = world(&pool).await;
    let login = format!("h10_member_{}", Uuid::new_v4().simple());
    let url = fixture::database_url_for(&pool).await;
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{login}:probe-only@{host}");
    let (retracted, live) = (w.retracted, w.live);
    let (who, c_refusal, d_grant) = with_cluster_role(
        &pool,
        &login,
        &format!(
            "CREATE ROLE {login} LOGIN PASSWORD 'probe-only' NOSUPERUSER NOBYPASSRLS INHERIT \
             IN ROLE epigraph_maintenance"
        ),
        |_pool| async move {
            let mut conn = PgConnection::connect(&dsn)
                .await
                .expect("the member logs in");
            let who: (String, bool, bool) = sqlx::query_as(
                "SELECT session_user::text, \
                        (SELECT rolsuper FROM pg_roles WHERE rolname = session_user), \
                        public.epigraph_bypass()",
            )
            .fetch_one(&mut conn)
            .await
            .expect("who is this session");
            // (c) no grant: SR09, as a single row and as a bulk delete.
            let c = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
                .bind(retracted)
                .execute(&mut conn)
                .await
                .map(|d| d.rows_affected());
            let c = refusal(c, "a member login's delete without a grant");
            let bulk = sqlx::query("DELETE FROM mass_functions WHERE id = ANY($1)")
                .bind(vec![retracted, live])
                .execute(&mut conn)
                .await
                .map(|d| d.rows_affected());
            assert_sr09(
                refusal(bulk, "a member login's bulk delete over a retracted row"),
                "(c) bulk, member login",
            );
            // (d) the residual, closed since 251: the login cannot write a
            // grant row for its own transaction.
            let mut tx = conn.begin().await.expect("begin");
            let d = sqlx::query(
                "INSERT INTO public.mass_function_purge_grants (mf_id, reason) \
                 VALUES ($1, 'residual, member login')",
            )
            .bind(retracted)
            .execute(&mut *tx)
            .await
            .map(|d| d.rows_affected())
            .map_err(|e| {
                e.as_database_error()
                    .map(|d| {
                        (
                            d.code().map(|c| c.to_string()).unwrap_or_default(),
                            d.message().to_string(),
                        )
                    })
                    .unwrap_or_default()
            });
            tx.rollback().await.expect("rollback");
            conn.close().await.expect("close");
            (who, c, d)
        },
    )
    .await;

    assert!(!role_exists(&pool, &login).await, "the login is gone");
    assert_eq!(
        who,
        (login.clone(), false, true),
        "fixture: a NOSUPERUSER member login, privileged through membership only"
    );
    assert_sr09(c_refusal, "(c), member login");
    let (code, message) = d_grant.expect_err("(d), member login: 251 closed the residual");
    assert_eq!(code, "42501", "(d), member login: {message}");
    assert!(
        message.starts_with("permission denied for table mass_function_purge_grants"),
        "(d), member login: the ledger refuses the login's own grant: {message}"
    );
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted row survives"
    );
}

/// T-N6: the guard FAILS CLOSED after a later ownership change. Since
/// migration 251 the delete guard admits a retracted row's delete only
/// through the ledger consumer `epigraph_mf_guard_consume`, a definer owned
/// by `epigraph_bba_guard_owner` (194's helper `epigraph_mf_purge_granted`
/// is no longer on the guard's path). If the consumer is later re-owned by
/// another role (a careless `ALTER FUNCTION ... OWNER TO`, a `REASSIGN
/// OWNED`), its body runs as a role that holds nothing on the ledger. Pinned here: a maintenance delete of the
/// retracted row is then refused with a 42501 PERMISSION error (not SR09,
/// and never an admission), and so is the audited purge, and the row
/// survives both; a LIVE row still deletes (the guard fires only on
/// retracted rows). A guard that swallowed that error would fail open; this
/// test is what catches it. The ownership change is undone with the role.
#[sqlx::test(migrations = "../../migrations")]
async fn t_n6_the_guard_fails_closed_after_the_helper_is_re_owned(pool: PgPool) {
    proc_exists(&pool, GRANT_CONSUMER).await;
    let w = world(&pool).await;
    let role = format!("h10_reowner_{}", Uuid::new_v4().simple());
    let (r, retracted, live) = (role.clone(), w.retracted, w.live);
    let (direct, purge, live_deleted, helper_owner) = with_cluster_role(
        &pool,
        &role,
        &format!("CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"),
        |pool| async move {
            pool.execute(format!("ALTER FUNCTION {GRANT_CONSUMER} OWNER TO {r}").as_str())
                .await
                .expect("re-own the ledger consumer");
            let helper_owner: String = sqlx::query_scalar(
                "SELECT r.rolname::text FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
                  WHERE p.oid = $1::regprocedure",
            )
            .bind(GRANT_CONSUMER)
            .fetch_one(&pool)
            .await
            .expect("helper owner");
            let m = maintenance(&pool).await;
            let direct = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
                .bind(retracted)
                .execute(&m)
                .await
                .map(|d| d.rows_affected())
                .map_err(|e| {
                    let db = e.as_database_error().map(|d| {
                        (
                            d.code().map(|c| c.to_string()).unwrap_or_default(),
                            d.message().to_string(),
                        )
                    });
                    db.unwrap_or_default()
                });
            let purge = sqlx::query_scalar::<_, i32>(
                "SELECT public.epigraph_purge_mass_functions($1, 'T-N6 probe')",
            )
            .bind(vec![retracted])
            .fetch_one(&m)
            .await
            .map_err(|e| {
                let db = e.as_database_error().map(|d| {
                    (
                        d.code().map(|c| c.to_string()).unwrap_or_default(),
                        d.message().to_string(),
                    )
                });
                db.unwrap_or_default()
            });
            let live_deleted = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
                .bind(live)
                .execute(&m)
                .await
                .expect("a live row still deletes")
                .rows_affected();
            m.close().await;
            (direct, purge, live_deleted, helper_owner)
        },
    )
    .await;

    assert!(
        !role_exists(&pool, &role).await,
        "the re-owner role is gone"
    );
    assert_eq!(
        helper_owner, role,
        "fixture: the ledger consumer was re-owned"
    );
    let (code, message) = direct.expect_err("the direct delete must not be admitted");
    assert_eq!(code, "42501", "a privilege error, fail closed: {message}");
    assert!(
        message.starts_with("permission denied"),
        "the helper's privilege failure, not SR09: {message}"
    );
    let (code, message) = purge.expect_err("the purge must not be admitted either");
    assert_eq!(code, "42501", "the purge fails closed too: {message}");
    assert!(message.starts_with("permission denied"), "{message}");
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted row survives both"
    );
    assert_eq!(live_deleted, 1, "CONTROL: a live row is not guarded");
}

/// T-N6, the other half: the PURGE DEFINER re-owned. If
/// `epigraph_purge_mass_functions` is later owned by another role (an
/// `ALTER FUNCTION ... OWNER TO`, or the definer's share of a `REASSIGN
/// OWNED BY epigraph_maintenance`, whose helper share the test above pins),
/// the purge fails closed with 42501 twice over, and each is pinned:
/// * as re-owned: 194 granted EXECUTE to `epigraph_maintenance` while it
///   was the owner, so that grant was an owner's privilege and moved to the
///   new owner; the maintenance session can no longer call the purge;
/// * after EXECUTE is granted back to the maintenance role (the obvious
///   "repair"): the body now runs as the new owner, which may not write a
///   purge grant, so the purge is still refused.
/// Either way nothing is deleted and no `mass_functions.purge` event is
/// written. The guard itself is SECURITY INVOKER, so re-owning it changes
/// nothing to pin. The ownership change is undone with the role.
#[sqlx::test(migrations = "../../migrations")]
async fn t_n6_the_purge_fails_closed_after_the_purge_definer_is_re_owned(pool: PgPool) {
    proc_exists(&pool, PURGE_DEFINER).await;
    let w = world(&pool).await;
    let role = format!("h10_reowner_{}", Uuid::new_v4().simple());
    let (r, retracted) = (role.clone(), w.retracted);
    let (purge, regranted, definer_owner, events) = with_cluster_role(
        &pool,
        &role,
        &format!("CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"),
        |pool| async move {
            pool.execute(format!("ALTER FUNCTION {PURGE_DEFINER} OWNER TO {r}").as_str())
                .await
                .expect("re-own the purge definer");
            let definer_owner: String = sqlx::query_scalar(
                "SELECT r.rolname::text FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
                  WHERE p.oid = $1::regprocedure",
            )
            .bind(PURGE_DEFINER)
            .fetch_one(&pool)
            .await
            .expect("definer owner");
            let m = maintenance(&pool).await;
            let purge = sqlx::query_scalar::<_, i32>(
                "SELECT public.epigraph_purge_mass_functions($1, 'T-N6 definer probe')",
            )
            .bind(vec![retracted])
            .fetch_one(&m)
            .await
            .map_err(|e| {
                let db = e.as_database_error().map(|d| {
                    (
                        d.code().map(|c| c.to_string()).unwrap_or_default(),
                        d.message().to_string(),
                    )
                });
                db.unwrap_or_default()
            });
            pool.execute(
                format!("GRANT EXECUTE ON FUNCTION {PURGE_DEFINER} TO epigraph_maintenance")
                    .as_str(),
            )
            .await
            .expect("grant the purge back to the maintenance role");
            let regranted = sqlx::query_scalar::<_, i32>(
                "SELECT public.epigraph_purge_mass_functions($1, 'T-N6 definer probe, re-granted')",
            )
            .bind(vec![retracted])
            .fetch_one(&m)
            .await
            .map_err(|e| {
                let db = e.as_database_error().map(|d| {
                    (
                        d.code().map(|c| c.to_string()).unwrap_or_default(),
                        d.message().to_string(),
                    )
                });
                db.unwrap_or_default()
            });
            m.close().await;
            let events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM security_events WHERE event_type = 'mass_functions.purge'",
            )
            .fetch_one(&pool)
            .await
            .expect("purge events");
            (purge, regranted, definer_owner, events)
        },
    )
    .await;

    assert!(
        !role_exists(&pool, &role).await,
        "the re-owner role is gone"
    );
    assert_eq!(
        definer_owner, role,
        "fixture: the purge definer was re-owned"
    );
    let (code, message) = purge.expect_err("the purge must not be admitted");
    assert_eq!(code, "42501", "a privilege error, fail closed: {message}");
    assert!(message.starts_with("permission denied"), "{message}");
    let (code, message) =
        regranted.expect_err("the purge must not be admitted with EXECUTE granted back");
    assert_eq!(
        code, "42501",
        "the body, run as the new owner, is refused: {message}"
    );
    assert!(message.starts_with("permission denied"), "{message}");
    assert!(
        exists(&pool, "mass_functions", w.retracted).await,
        "the retracted row survives"
    );
    assert_eq!(events, 0, "no purge event is written");
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
/// frame, perspective, retracted_at) and the reason, and keeps its grants in
/// the ledger (251): one per distinct id, only the retracted row's consumed
/// (the guard fires on retracted rows only), with that row's content.
/// Purging first is the documented order for a claim hard-delete: afterwards
/// the claim deletes.
#[sqlx::test(migrations = "../../migrations")]
async fn e_the_purge_definer_deletes_audits_and_keeps_its_grants(pool: PgPool) {
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

    let grants: Vec<(Uuid, String, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT mf_id, kind, consumed_row FROM public.mass_function_purge_grants ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(grants.len(), 4, "one grant per distinct id: {grants:?}");
    assert!(grants.iter().all(|(_, k, _)| k == "purge"), "{grants:?}");
    let consumed: Vec<&Uuid> = grants
        .iter()
        .filter(|(_, _, r)| r.is_some())
        .map(|(id, _, _)| id)
        .collect();
    assert_eq!(
        consumed,
        vec![&w.retracted],
        "only the retracted row's grant is consumed: {grants:?}"
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
        assert_eq!(row["perspective_id"], serde_json::Value::Null, "{row}");
        assert_eq!(
            row["slot_id"],
            perspective.map_or(serde_json::Value::Null, |p| p.to_string().into()),
            "the audit keeps the edge slot: {row}"
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
            "INSERT INTO public.mass_function_purge_grants (mf_id, kind, reason) \
             VALUES ($1, 'purge', 'x')",
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
/// slot 190's path. Slot 190 is in the set below 194, and its sweep changes
/// the definer's `proconfig` only (`pg_catalog, public` -> `pg_catalog,
/// public, pg_temp`), so the md5 is 117's either way.
#[sqlx::test(migrations = false)]
async fn the_cascade_definer_before_194_is_117s_body(pool: PgPool) {
    migrate_below_194(&pool).await;
    let (md5, config) = cascade_definer_facts(&pool).await;
    assert_eq!(md5, MD5_117, "md5(prosrc) of the definer below 194");
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()],
        "below 194 the definer is on slot 190's path"
    );
}

/// (j) 194 refuses (55000, nothing changed) over a body whose md5 is not
/// 117's, and over a `proconfig` other than the pre- and post-190 paths; it
/// applies over the post-190 path (slot 190 changes `proconfig` only) and
/// states `pg_catalog, public, pg_temp` either way. The post-190 path is every
/// fresh database's (slot 190 is below 194); the pre-190 path is
/// [`j3_the_precondition_accepts_117s_body_on_the_pre_190_path`].
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

/// (j3) 194 applies over 117's own path (`pg_catalog, public`, the
/// `proconfig` a database has where slot 190's sweep never ran or was undone),
/// the other value SPEC §7.1 SF-19 admits, and states `pg_catalog, public,
/// pg_temp` afterwards (SF-12: the re-body never keeps a path without
/// `pg_temp`). A fresh database no longer reaches 194 on this path, because
/// slot 190 is below it, so the fixture restores 117's path explicitly.
#[sqlx::test(migrations = false)]
async fn j3_the_precondition_accepts_117s_body_on_the_pre_190_path(pool: PgPool) {
    migrate_below_194(&pool).await;
    pool.execute(
        format!("ALTER FUNCTION {CASCADE_DEFINER} SET search_path = pg_catalog, public").as_str(),
    )
    .await
    .unwrap();
    assert_eq!(
        cascade_definer_facts(&pool).await,
        (
            MD5_117.to_string(),
            vec!["search_path=pg_catalog, public".to_string()]
        ),
        "fixture: 117's body on 117's (pre-190) path"
    );
    migrate_rest(&pool)
        .await
        .expect("194 applies over the pre-190 path");
    assert!(applied_194(&pool).await);
    let (md5, config) = cascade_definer_facts(&pool).await;
    assert_ne!(md5, MD5_117, "194 re-bodied the definer");
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()],
        "the re-body states pg_temp last over the pre-190 path too"
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

/// At head (194 applied over slot 190's path, as on every fresh database), the re-body
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
            // 251 (backlog 6bdac68f): the helper reads the ledger, which only
            // its NOLOGIN owner may; the purge definer stays the maintenance
            // role's.
            let want = if sig == GRANT_HELPER {
                "epigraph_bba_guard_owner"
            } else {
                "epigraph_maintenance"
            };
            assert_eq!(owner, want, "{sig} owner");
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
