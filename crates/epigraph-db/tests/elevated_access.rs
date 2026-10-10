//! Migration 127's ELEVATED-ACCESS LOG (elevation plan EL-8): what the
//! recorder writes, who may call it, and who reads its rows.
//!
//! THE WORLD. P is a custodian (a registered human holding an `elevates`
//! role, with a passkey and a refresh family) with a confirmed session seeded
//! through migration 125's definers. B is another person with its own
//! personal group (B is its ADMIN member) and B-private rows. R is a READER
//! member of B's group, W a WRITER member, A an unrelated agent.
//!
//! EVERY AUTHORITY PROBE runs as `epigraph_app` (`SET SESSION
//! AUTHORIZATION`), with all five tenancy settings and the recorder
//! declaration stamped per call ([`stamped`]), and asserts its own
//! `current_user` / elevation state first. The harness (superuser) only
//! seeds and counts.
//!
//! Each test names the mutation it was run against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{DbError, ElevatedAccess, ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

// =====================================================================
// fixtures (the subset of elevated_arms.rs's this file needs)
// =====================================================================

/// The stamp of one application-role connection.
#[derive(Clone, Copy)]
struct Stamp {
    principal: Option<Uuid>,
    /// `(session, family)`: the elevation pair, or none.
    elevation: Option<(Uuid, Uuid)>,
    /// Whether the connection declares the per-access recorder.
    recorder: bool,
}

impl Stamp {
    fn plain(p: Uuid) -> Self {
        Self {
            principal: Some(p),
            elevation: None,
            recorder: true,
        }
    }
    fn elevated(p: &Holder, session: Uuid) -> Self {
        Self {
            principal: Some(p.person),
            elevation: Some((session, p.family)),
            recorder: true,
        }
    }
}

/// Run `f` as `epigraph_app` with `stamp` applied (session scope), then clear
/// every setting.
async fn stamped<F, Fut, T>(pool: &PgPool, stamp: Stamp, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let principal = stamp.principal.map(|p| p.to_string()).unwrap_or_default();
    let (elv, fam) = stamp
        .elevation
        .map(|(s, f)| (s.to_string(), f.to_string()))
        .unwrap_or_default();
    let recorder = if stamp.recorder { "on" } else { "" };
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.elevation_id', $2, false), \
                    set_config('epigraph.family_id', $3, false), \
                    set_config('epigraph.access_recorder', $4, false)",
        )
        .bind(&principal)
        .bind(&elv)
        .bind(&fam)
        .bind(recorder)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await
            .expect("current_user");
        assert_eq!(role, "epigraph_app", "CALIBRATION: the application role");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false), \
                    set_config('epigraph.access_recorder', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

struct Holder {
    person: Uuid,
    group: Uuid,
    client: Uuid,
    cred: Vec<u8>,
    family: Uuid,
}

/// A holder. Its sessions are live on a database at head (migration 132
/// opened 125's gate) and confirm, but are never live, on one cut before 132.
async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    holder_behind_the_gate(pool, label, n).await
}

/// [`holder`], named for a database cut before 132 (the gate closed): its
/// sessions confirm (and audit) but are never live.
async fn holder_behind_the_gate(pool: &PgPool, label: &str, n: u8) -> Holder {
    let (person, group) = fixture::seed_human_operator(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    fixture::make_custodian(pool, person).await;
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'elevated access test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    let mut cred = vec![0xB7_u8; 16];
    cred[0] = n;
    let c = cred.clone();
    stamped(
        pool,
        Stamp {
            principal: None,
            elevation: None,
            recorder: false,
        },
        |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
            )
            .bind(e)
            .execute(&mut *conn)
            .await
            .expect("enrollment challenge");
            sqlx::query(
                "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                        '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                        'none', true, false)",
            )
            .bind(e)
            .bind(c)
            .execute(&mut *conn)
            .await
            .expect("complete the enrollment");
            (conn, ())
        },
    )
    .await;
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token");
    Holder {
        person,
        group,
        client,
        cred,
        family,
    }
}

/// A confirmed grant-mode session for `h`, opened with `reason`; its id.
async fn session(pool: &PgPool, h: &Holder, reason: &'static str) -> Uuid {
    let (client, fam) = (h.client, h.family);
    let ticket: Uuid = stamped(pool, Stamp::plain(h.person), |mut conn| async move {
        let t = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', $3, \
                    sha256('an elevated access secret'::bytea))",
        )
        .bind(client)
        .bind(fam)
        .bind(reason)
        .fetch_one(&mut *conn)
        .await
        .expect("a ticket");
        (conn, t)
    })
    .await;
    let cred = h.cred.clone();
    stamped(
        pool,
        Stamp {
            principal: None,
            elevation: None,
            recorder: false,
        },
        |mut conn| async move {
            sqlx::query(
                "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
            )
            .bind(ticket)
            .execute(&mut *conn)
            .await
            .expect("the ceremony's challenge");
            let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
                "SELECT outcome, session_id \
                   FROM public.epigraph_confirm_elevation($1, $2, 0, false, '{\"ev\": 1}'::jsonb)",
            )
            .bind(ticket)
            .bind(cred)
            .fetch_one(&mut *conn)
            .await
            .expect("confirm");
            assert_eq!(outcome, "confirmed", "CALIBRATION: the ceremony confirms");
            (conn, session.expect("a session"))
        },
    )
    .await
}

/// A membership of `agent` in `group` with `role` (`reader` / `writer`).
async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3) RETURNING id",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("a membership")
}

/// Call the recorder on `stamp`'s connection: the row id, or the SQLSTATE.
async fn record(
    pool: &PgPool,
    stamp: Stamp,
    surface: &'static str,
    row_count: i32,
    ids: Vec<Uuid>,
) -> Result<Uuid, String> {
    stamped(pool, stamp, |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_record_elevated_access($1, $2, $3, $4)",
        )
        .bind(surface)
        .bind(serde_json::json!({"path": surface}))
        .bind(row_count)
        .bind(&ids)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code())
                .map_or_else(|| e.to_string(), |c| c.to_string())
        });
        (conn, r)
    })
    .await
}

/// The rows of `elevated_access` the stamped application connection reads.
async fn visible(pool: &PgPool, principal: Uuid) -> Vec<Uuid> {
    stamped(pool, Stamp::plain(principal), |mut conn| async move {
        let ids = sqlx::query_scalar("SELECT id FROM public.elevated_access ORDER BY id")
            .fetch_all(&mut *conn)
            .await
            .expect("read the log");
        (conn, ids)
    })
    .await
}

async fn log_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM elevated_access")
        .fetch_one(pool)
        .await
        .expect("count the log")
}

// =====================================================================
// The recorder
// =====================================================================

/// An elevated read of B's private claim is recorded as ONE row naming B's
/// group (the claim's owner; B's group row, which the response also names,
/// adds nothing new), carrying the session's person, assignment and reason
/// and the caller's row count. P's own private claim, a public claim and an
/// id that names no row add nothing.
///
/// Verified to fail with the recorder's `foreign_row` filter dropped (P's own
/// group is attributed), with the `claims` arm of the attribution removed
/// (caught by the `claims`-only probe at the end: the group row alone would
/// still name B's group), and with the session's reason not copied.
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_read_of_a_foreign_private_claim_is_recorded_for_its_group(pool: PgPool) {
    let p = holder(&pool, "access-rec-p", 21).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "access-rec-b").await;
    let b_claim = fixture::seed_group_claim(&pool, b, b_group, "B's private claim").await;
    let p_claim = fixture::seed_group_claim(&pool, p.person, p.group, "P's own claim").await;
    let public = fixture::seed_public_claim(&pool, b, "a public claim").await;
    let live = session(&pool, &p, "audit request 42").await;

    let row = record(
        &pool,
        Stamp::elevated(&p, live),
        "GET /api/v1/claims/:id",
        1,
        vec![b_claim, b_group, p_claim, p.group, public, Uuid::new_v4()],
    )
    .await
    .expect("an elevated connection records");

    let (elevation, person, assignment, reason, surface, rows, groups, by): (
        Uuid,
        Uuid,
        Uuid,
        String,
        String,
        i32,
        Vec<Uuid>,
        String,
    ) = sqlx::query_as(
        "SELECT elevation_id, person_agent_id, assignment_id, reason, surface, row_count, \
                owner_group_ids, recorded_by FROM elevated_access WHERE id = $1",
    )
    .bind(row)
    .fetch_one(&pool)
    .await
    .expect("the row");
    let live_assignment: Uuid =
        sqlx::query_scalar("SELECT assignment_id FROM elevation_sessions WHERE id = $1")
            .bind(live)
            .fetch_one(&pool)
            .await
            .expect("the session's assignment");
    assert_eq!(log_rows(&pool).await, 1, "exactly one row per request");
    assert_eq!(elevation, live);
    assert_eq!(person, p.person);
    assert_eq!(assignment, live_assignment);
    assert_eq!(reason, "audit request 42", "the session's reason, copied");
    assert_eq!(surface, "GET /api/v1/claims/:id");
    assert_eq!(rows, 1, "the caller's row count");
    assert_eq!(groups, vec![b_group], "B's group, and only B's");
    assert_eq!(by, "epigraph_app", "stamped by the login that recorded it");

    // The claim alone (no group row named) still attributes B's group.
    let only_claim = record(
        &pool,
        Stamp::elevated(&p, live),
        "GET /api/v1/claims/:id",
        1,
        vec![b_claim],
    )
    .await
    .expect("records");
    let groups: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_ids FROM elevated_access WHERE id = $1")
            .bind(only_claim)
            .fetch_one(&pool)
            .await
            .expect("the row");
    assert_eq!(groups, vec![b_group], "attributed through the claim itself");
}

/// Attribution follows each table's own tenancy rule: an edge names its
/// co-owner group too; another agent's recall event is attributed to its
/// owner group even when that group is the elevator's own (its policy admits
/// only its agent), and so is an agent-less one; a membership of another
/// agent in a foreign group names that group; the elevator's own recall event
/// and its own membership name nothing.
///
/// Verified to fail with the edge's co-owner dropped from the attribution,
/// with the recall pass removed, and with the recall pass filtered by the
/// elevator's groups (the shared-group event goes unattributed).
#[sqlx::test(migrations = "../../migrations")]
async fn attribution_follows_each_tables_tenancy_rule(pool: PgPool) {
    let p = holder(&pool, "access-attr-p", 22).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "access-attr-b").await;
    let (c, c_group) = fixture::seed_agent_with_group(&pool, "access-attr-c").await;
    let (d, _d_group) = fixture::seed_agent_with_group(&pool, "access-attr-d").await;
    // An edge between a B-private and a C-private claim: 070's trigger makes
    // it private to one group and co-owned by the other (072).
    let src = fixture::seed_group_claim(&pool, b, b_group, "edge source").await;
    let dst = fixture::seed_group_claim(&pool, c, c_group, "edge target").await;
    let edge = fixture::seed_edge(&pool, src, dst).await;
    let (vis, owner, co): (String, Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(&pool)
    .await
    .expect("the edge's tenancy");
    assert_eq!(vis, "group", "CALIBRATION: a private edge");
    let mut pair = vec![owner, co.expect("CALIBRATION: a co-owned edge")];
    pair.sort();
    let mut want = vec![b_group, c_group];
    want.sort();
    assert_eq!(pair, want, "CALIBRATION: owned by B's and C's groups");
    let recall = |agent: Option<Uuid>, group: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO recall_events (agent_id, tool, query_text, params, \
                                            returned_claim_ids, owner_group_id, visibility) \
                 VALUES ($1, 'recall', 'q', '{}'::jsonb, ARRAY[]::uuid[], $2, 'group') \
                 RETURNING id",
            )
            .bind(agent)
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("a recall event")
        }
    };
    // D's event, owned by P's OWN group (D is a member there).
    add_member(&pool, p.group, d, "reader").await;
    let shared_recall = recall(Some(d), p.group).await;
    let orphan_recall = recall(None, c_group).await;
    let own_recall = recall(Some(p.person), p.group).await;
    let foreign_membership = add_member(&pool, c_group, b, "reader").await;
    let own_membership: Uuid = sqlx::query_scalar(
        "SELECT id FROM group_memberships WHERE agent_id = $1 AND group_id = $2",
    )
    .bind(p.person)
    .bind(p.group)
    .fetch_one(&pool)
    .await
    .expect("P's own membership");
    let live = session(&pool, &p, "attribution").await;

    let attributed = |ids: Vec<Uuid>| {
        let pool = pool.clone();
        let stamp = Stamp::elevated(&p, live);
        async move {
            let row = record(&pool, stamp, "probe", 0, ids)
                .await
                .expect("records");
            sqlx::query_scalar::<_, Vec<Uuid>>(
                "SELECT owner_group_ids FROM elevated_access WHERE id = $1",
            )
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("the row")
        }
    };
    let mut both = vec![b_group, c_group];
    both.sort();
    assert_eq!(attributed(vec![edge]).await, both, "owner and co-owner");
    assert_eq!(
        attributed(vec![shared_recall]).await,
        vec![p.group],
        "another agent's event in the elevator's own group"
    );
    assert_eq!(
        attributed(vec![orphan_recall]).await,
        vec![c_group],
        "an agent-less event"
    );
    assert_eq!(
        attributed(vec![foreign_membership]).await,
        vec![c_group],
        "another agent's membership of a foreign group"
    );
    assert!(
        attributed(vec![own_recall, own_membership, p.group])
            .await
            .is_empty(),
        "the elevator's own rows name nothing"
    );
}

/// An aggregate answer names no row: its request is still recorded, with an
/// empty group list (the stated limit).
///
/// Verified to fail with the recorder returning early on an empty candidate
/// list (no row written).
#[sqlx::test(migrations = "../../migrations")]
async fn an_aggregate_is_recorded_with_no_groups(pool: PgPool) {
    let p = holder(&pool, "access-agg-p", 23).await;
    let live = session(&pool, &p, "aggregate").await;
    let row = record(
        &pool,
        Stamp::elevated(&p, live),
        "GET /api/v1/stats",
        0,
        vec![],
    )
    .await
    .expect("records");
    let groups: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_ids FROM elevated_access WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("the row");
    assert!(groups.is_empty());
    assert_eq!(log_rows(&pool).await, 1);
}

/// The application cannot forge a log row: the recorder refuses (ELV07) a
/// connection that is not elevated — no elevation stamped, another person's
/// session, a forged session id, the right pair on a connection that does not
/// declare the recorder, and an ENDED session — and writes nothing. The
/// application has no INSERT on the table either (42501).
///
/// Verified to fail with the recorder's `epigraph_is_elevated()` check
/// removed (the unelevated call records), and with INSERT granted to the
/// application in 127's grant block.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_cannot_record_without_an_elevation(pool: PgPool) {
    let p = holder(&pool, "access-forge-p", 24).await;
    let q = holder(&pool, "access-forge-q", 25).await;
    let live = session(&pool, &p, "forge").await;

    let refused = [
        ("unelevated", Stamp::plain(p.person)),
        (
            "another person's session",
            Stamp {
                principal: Some(q.person),
                elevation: Some((live, p.family)),
                recorder: true,
            },
        ),
        (
            "a forged session id",
            Stamp {
                principal: Some(p.person),
                elevation: Some((Uuid::new_v4(), p.family)),
                recorder: true,
            },
        ),
        (
            "no recorder declared",
            Stamp {
                recorder: false,
                ..Stamp::elevated(&p, live)
            },
        ),
    ];
    for (what, stamp) in refused {
        assert_eq!(
            record(&pool, stamp, "probe", 0, vec![]).await,
            Err("ELV07".to_string()),
            "{what}"
        );
    }
    assert!(
        record(&pool, Stamp::elevated(&p, live), "probe", 0, vec![])
            .await
            .is_ok(),
        "CALIBRATION: the live session records"
    );
    stamped(&pool, Stamp::plain(p.person), |mut conn| async move {
        let ended: bool = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(live)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        assert!(ended);
        (conn, ())
    })
    .await;
    assert_eq!(
        record(&pool, Stamp::elevated(&p, live), "probe", 0, vec![]).await,
        Err("ELV07".to_string()),
        "an ended session"
    );
    assert_eq!(log_rows(&pool).await, 1, "only the calibration row");

    let assignment: Uuid =
        sqlx::query_scalar("SELECT assignment_id FROM elevation_sessions WHERE id = $1")
            .bind(live)
            .fetch_one(&pool)
            .await
            .expect("the session's assignment");
    let person = p.person;
    let direct = stamped(&pool, Stamp::elevated(&p, live), |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO elevated_access (elevation_id, person_agent_id, assignment_id, reason, \
                                          surface, args, row_count) \
             VALUES ($1, $2, $3, 'forge', 'x', '{}'::jsonb, 0)",
        )
        .bind(live)
        .bind(person)
        .bind(assignment)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.to_string())
        });
        (conn, r)
    })
    .await;
    assert_eq!(direct.err(), Some(Some("42501".to_string())));
    // Two layers refuse that INSERT (no grant, and the definer-only policy);
    // pin the grant layer on its own.
    let grants: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_app', 'public.elevated_access', 'SELECT'), \
                has_table_privilege('epigraph_app', 'public.elevated_access', 'INSERT'), \
                has_table_privilege('epigraph_app', 'public.elevated_access', 'UPDATE'), \
                has_table_privilege('epigraph_app', 'public.elevated_access', 'DELETE')",
    )
    .fetch_one(&pool)
    .await
    .expect("grants");
    assert_eq!(
        grants,
        (true, false, false, false),
        "the application reads only"
    );
}

// =====================================================================
// Who reads a row
// =====================================================================

/// B (an ADMIN member of B's group) reads the row that names it, with the
/// reason; R and W (reader and writer members of B's group), an unrelated A,
/// and P itself unelevated read none. The audit reader serves P while
/// elevated and a `reads_audit` holder, and nobody else.
///
/// Verified to fail with the subject policy reading every live membership
/// rather than admin ones (R and W read the row), and with the audit reader's
/// entitlement clause dropped (A reads every row through it).
#[sqlx::test(migrations = "../../migrations")]
async fn the_subject_group_admin_reads_the_row_and_no_one_else_does(pool: PgPool) {
    let p = holder(&pool, "access-read-p", 26).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "access-read-b").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "access-read-r").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "access-read-w").await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "access-read-a").await;
    add_member(&pool, b_group, r, "reader").await;
    add_member(&pool, b_group, w, "writer").await;
    let b_claim = fixture::seed_group_claim(&pool, b, b_group, "B's private claim").await;
    let live = session(&pool, &p, "read who sees it").await;
    let row = record(&pool, Stamp::elevated(&p, live), "probe", 1, vec![b_claim])
        .await
        .expect("records");

    assert_eq!(visible(&pool, b).await, vec![row], "B, the subject's admin");
    let reason: String = stamped(&pool, Stamp::plain(b), |mut conn| async move {
        let reason = sqlx::query_scalar("SELECT reason FROM public.elevated_access")
            .fetch_one(&mut *conn)
            .await
            .expect("B reads the reason");
        (conn, reason)
    })
    .await;
    assert_eq!(reason, "read who sees it");
    for (who, agent) in [
        ("R (reader)", r),
        ("W (writer)", w),
        ("A", a),
        ("P", p.person),
    ] {
        assert!(
            visible(&pool, agent).await.is_empty(),
            "{who} reads nothing"
        );
    }

    let audit = |stamp: Stamp| {
        let pool = pool.clone();
        async move {
            stamped(&pool, stamp, |mut conn| async move {
                let n: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM public.epigraph_elevated_access_audit(NULL, 100)",
                )
                .fetch_one(&mut *conn)
                .await
                .expect("the audit reader");
                (conn, n)
            })
            .await
        }
    };
    assert_eq!(audit(Stamp::elevated(&p, live)).await, 1, "P elevated");
    assert_eq!(audit(Stamp::plain(a)).await, 0, "A");
    assert_eq!(
        audit(Stamp::plain(b)).await,
        0,
        "B (the policy is its door)"
    );
    // P holds the custodian role, which reads the audit trail (123's seed).
    assert_eq!(
        audit(Stamp::plain(p.person)).await,
        1,
        "P unelevated, as a reads_audit holder"
    );
}

// =====================================================================
// The table
// =====================================================================

/// The log is append-only for EVERY login: an UPDATE or DELETE as the
/// maintenance role or the superuser is refused (ELV03), and a direct
/// maintenance INSERT naming another session's person is refused (ELV03).
///
/// Verified to fail with the change guard's trigger dropped (the superuser
/// DELETE lands) and with the insert guard's person check removed.
#[sqlx::test(migrations = "../../migrations")]
async fn the_log_is_append_only(pool: PgPool) {
    let p = holder(&pool, "access-ao-p", 27).await;
    let q = holder(&pool, "access-ao-q", 28).await;
    let live = session(&pool, &p, "append only").await;
    let row = record(&pool, Stamp::elevated(&p, live), "probe", 0, vec![])
        .await
        .expect("records");
    let code = |e: sqlx::Error| {
        e.as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string())
    };
    for sql in [
        "UPDATE elevated_access SET row_count = 99 WHERE id = $1",
        "DELETE FROM elevated_access WHERE id = $1",
    ] {
        let su = sqlx::query(sql).bind(row).execute(&pool).await;
        assert_eq!(
            su.err().and_then(code),
            Some("ELV03".into()),
            "superuser: {sql}"
        );
        let m = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(sql).bind(row).execute(&mut *conn).await;
            (conn, r)
        })
        .await;
        assert!(m.is_err(), "maintenance: {sql}");
    }
    let forged = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO elevated_access (elevation_id, person_agent_id, assignment_id, reason, \
                                          surface, args, row_count) \
             SELECT s.id, $2, s.assignment_id, s.reason, 'x', '{}'::jsonb, 0 \
               FROM elevation_sessions s WHERE s.id = $1",
        )
        .bind(live)
        .bind(q.person)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_eq!(forged.err().and_then(code), Some("ELV03".into()));
    assert_eq!(log_rows(&pool).await, 1);
}

// =====================================================================
// Migration 132 opens the gate
// =====================================================================

/// What migration 125's recorder gate answers on this database.
async fn gate(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT public.epigraph_elevated_access_ready()")
        .fetch_one(pool)
        .await
        .expect("the gate")
}

/// Whether `session` of `p` is elevated on an application connection that
/// declares the recorder (the second key, held fixed here).
async fn is_elevated(pool: &PgPool, p: &Holder, session: Uuid) -> bool {
    stamped(pool, Stamp::elevated(p, session), |mut conn| async move {
        let e: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
            .fetch_one(&mut *conn)
            .await
            .expect("is_elevated");
        (conn, e)
    })
    .await
}

/// The gate function's owner and ACL, which `CREATE OR REPLACE` must keep.
async fn gate_owner_and_acl(pool: &PgPool) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT p.proowner::regrole::text, p.proacl::text FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_elevated_access_ready()'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("the gate's owner and ACL")
}

/// 127 installs the recorder and LEAVES migration 125's gate closed, and so
/// do 128 to 131: on a database cut at 131 a confirmed session is not live.
/// Migration 132 opens it: the SAME session, on the same declaring
/// application connection, is elevated once the database reaches 132, and
/// the function keeps its owner and ACL (no EXECUTE for the application).
///
/// Verified to fail: 132's body shipped `SELECT false` (not elevated at
/// 132); the gate opened in 131 instead (open at 131).
#[sqlx::test(migrations = false)]
async fn the_gate_is_closed_through_131_and_opened_by_132(pool: PgPool) {
    migrate(&pool, &up_to(131)).await;
    assert!(!gate(&pool).await, "the gate is still closed at 131");
    let recorder: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_record_elevated_access(text, jsonb, integer, \
                                 uuid[])') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("the recorder");
    assert!(recorder, "CALIBRATION: the recorder is installed at 131");
    let acl_at_131 = gate_owner_and_acl(&pool).await;
    let p = holder(&pool, "gate-132-p", 41).await;
    let live = session(&pool, &p, "gate 132").await;
    assert!(
        !is_elevated(&pool, &p, live).await,
        "behind the closed gate the confirmed session is not elevated"
    );

    migrate(&pool, &up_to(132)).await;
    assert!(gate(&pool).await, "132 opens the gate");
    assert!(
        is_elevated(&pool, &p, live).await,
        "once 132 is applied the same session is elevated"
    );
    assert_eq!(
        gate_owner_and_acl(&pool).await,
        acl_at_131,
        "132 keeps the gate's owner and ACL"
    );
}

/// 132's gate is a READINESS TEST, not a constant: it answers true only while
/// the recorder (the `elevated_access` table and
/// `epigraph_record_elevated_access`) is installed, so a database whose
/// recorder is gone (127 taken back out) has no live session whatever 132
/// says.
///
/// Verified to fail with 132's body `SELECT true` (the gate stays open with
/// the recorder renamed away).
#[sqlx::test(migrations = "../../migrations")]
async fn the_opened_gate_follows_the_recorder(pool: PgPool) {
    let p = holder(&pool, "gate-ready-p", 42).await;
    let live = session(&pool, &p, "gate readiness").await;
    assert!(gate(&pool).await, "CALIBRATION: open at head");
    assert!(is_elevated(&pool, &p, live).await, "CALIBRATION: elevated");

    for (away, back, what) in [
        (
            "ALTER FUNCTION public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]) \
             RENAME TO epigraph_record_elevated_access_moved",
            "ALTER FUNCTION public.epigraph_record_elevated_access_moved(text, jsonb, integer, \
             uuid[]) RENAME TO epigraph_record_elevated_access",
            "the recorder function",
        ),
        (
            "ALTER TABLE public.elevated_access RENAME TO elevated_access_moved",
            "ALTER TABLE public.elevated_access_moved RENAME TO elevated_access",
            "the log table",
        ),
    ] {
        sqlx::query(away).execute(&pool).await.expect(what);
        assert!(!gate(&pool).await, "without {what} the gate is closed");
        assert!(
            !is_elevated(&pool, &p, live).await,
            "without {what} the session is not elevated"
        );
        sqlx::query(back).execute(&pool).await.expect(what);
        assert!(gate(&pool).await, "with {what} back the gate reopens");
    }
}

/// The opened gate answers from the recorder the MAINTENANCE role owns, not
/// from whatever carries its names: on a database whose recorder is gone
/// (`127-undo.sql` applied, 132's and 160's undos skipped), an application
/// login that holds CREATE on `public` re-creates a stub `elevated_access`
/// table and a stub `SECURITY DEFINER` recorder that records nothing. The
/// gate stays closed and the session is not elevated.
///
/// Verified to fail: 160's gate body reverted to 132's existence test ->
/// the application's stubs reopen the gate and the session is elevated
/// behind a recorder that records nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_recorder_the_maintenance_role_does_not_own_opens_nothing(pool: PgPool) {
    let p = holder(&pool, "gate-owner-p", 44).await;
    let live = session(&pool, &p, "gate owner").await;
    assert!(gate(&pool).await, "CALIBRATION: open at head");
    sqlx::raw_sql(&undo_127())
        .execute(&pool)
        .await
        .expect("127-undo applies at head");
    assert!(!gate(&pool).await, "CALIBRATION: 127-undo closes the gate");

    sqlx::query("GRANT CREATE ON SCHEMA public TO epigraph_app")
        .execute(&pool)
        .await
        .expect("the application may CREATE in public");
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        for stmt in [
            "CREATE TABLE public.elevated_access (x integer)",
            "CREATE FUNCTION public.epigraph_record_elevated_access(text, jsonb, integer, uuid[]) \
             RETURNS uuid LANGUAGE sql SECURITY DEFINER AS 'SELECT gen_random_uuid()'",
        ] {
            sqlx::query(stmt)
                .execute(&mut *conn)
                .await
                .unwrap_or_else(|e| panic!("CALIBRATION: the application creates {stmt}: {e}"));
        }
        (conn, ())
    })
    .await;
    let stubs: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.elevated_access') IS NOT NULL \
            AND to_regprocedure('public.epigraph_record_elevated_access(text, jsonb, integer, \
                                 uuid[])') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert!(stubs, "CALIBRATION: both names exist again");
    assert!(
        !gate(&pool).await,
        "a recorder the application owns does not open the gate"
    );
    assert!(
        !is_elevated(&pool, &p, live).await,
        "behind an application-owned recorder the session is not elevated"
    );
}

/// The recorder's attribution covers every table an elevated session reads
/// whose rows carry an owner group and a uuid `id`: each such table with a
/// 126 read arm is named in the recorder's body, or listed here as not
/// attributable with the reason. A new owner-group table that gains a read
/// arm fails this until it is placed.
///
/// Verified to fail with `public.triples` removed from the recorder.
#[sqlx::test(migrations = "../../migrations")]
async fn every_readable_owner_group_table_is_attributed(pool: PgPool) {
    /// Read-armed owner-group tables keyed by something other than a uuid
    /// `id`: their rows are named in a response by the claim or cluster ids
    /// they hang off, which ARE attributed.
    const KEYED_BY_PARENT: &[&str] = &[
        "claim_cluster_membership",
        "claim_frames",
        "claim_neighborhood_membership",
        "harvester_claim_provenance",
    ];
    let body: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_record_elevated_access(text, jsonb, \
                                    integer, uuid[])'::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .expect("the recorder's body");
    let tables: Vec<(String, bool)> = sqlx::query_as(
        "SELECT c.relname::text, \
                EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                           AND a.attname = 'id' AND a.atttypid = 'uuid'::regtype) \
           FROM pg_class c \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid \
                           AND p.polname = c.relname || '_elevated_read') \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                           AND a.attname = 'owner_group_id' AND NOT a.attisdropped) \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("read-armed owner-group tables");
    assert!(tables.len() >= 20, "CALIBRATION: {} tables", tables.len());
    for (t, uuid_id) in &tables {
        let named =
            body.contains(&format!("public.{t} ")) || body.contains(&format!("public.{t}\n"));
        if KEYED_BY_PARENT.contains(&t.as_str()) {
            assert!(!uuid_id, "{t} is listed as parent-keyed but has a uuid id");
            continue;
        }
        assert!(
            named,
            "{t}: an elevated session reads it; the recorder must attribute it"
        );
    }
    for t in ["groups", "group_memberships", "recall_events", "edges"] {
        assert!(body.contains(&format!("public.{t}")), "{t} (its own rule)");
    }
}

// =====================================================================
// The undo
// =====================================================================

/// The migrator cut at `max` (a later migration is undone before this one).
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

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind (viewer_fixture::db_at_122_then_head).
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// The catalog facts 127 could leave behind, by name: relations, functions
/// (body and owner), policies, triggers and constraints in `public`.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn undo_127() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/127-undo.sql"),
    )
    .expect("127-undo.sql")
}

/// `docs/runbooks/127-undo.sql`, applied to a database that went 126 -> 127
/// and holds a log row, returns its catalog (relations, function bodies and
/// owners, policies, triggers, constraints) to the same database's at 126;
/// the row survives as one `platform.elevated_access` event carrying it; and a
/// second run changes nothing. Cut at 127, not head: a later migration is
/// undone before this one.
///
/// Verified to fail: the undo's DROP of `epigraph_admin_group_ids` removed
/// (left behind); the archival INSERT removed (the history is lost).
#[sqlx::test(migrations = false)]
async fn the_rollback_returns_the_catalog_to_126_and_keeps_the_history(pool: PgPool) {
    migrate(&pool, &up_to(126)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(127)).await;
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 127 changed the catalog"
    );

    // A log row, written directly (the gate stays closed here, so no session
    // records; the insert guard still binds it to a real session).
    let p = holder_behind_the_gate(&pool, "access-undo-p", 29).await;
    let live = session(&pool, &p, "undo history").await;
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO elevated_access (elevation_id, person_agent_id, assignment_id, reason, \
                                      surface, args, row_count, owner_group_ids) \
         SELECT s.id, s.person_agent_id, s.assignment_id, s.reason, 'GET /x', '{}'::jsonb, 3, \
                ARRAY[$2]::uuid[] \
           FROM elevation_sessions s WHERE s.id = $1 RETURNING id",
    )
    .bind(live)
    .bind(p.group)
    .fetch_one(&pool)
    .await
    .expect("a log row");

    for run in 1..=2 {
        sqlx::raw_sql(&undo_127())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 126's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    let (n, reason, surface, by): (i64, Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT count(*), max(details->>'reason'), max(details->>'surface'), \
                    max(details->>'archived_by') \
               FROM security_events \
              WHERE event_type = 'platform.elevated_access' AND details->>'id' = $1",
        )
        .bind(row.to_string())
        .fetch_one(&pool)
        .await
        .expect("the archived row");
    assert_eq!(n, 1, "archived once, across two runs");
    assert_eq!(reason.as_deref(), Some("undo history"));
    assert_eq!(surface.as_deref(), Some("GET /x"));
    assert_eq!(by.as_deref(), Some("127-undo"));
}

// =====================================================================
// The registers know every 127 object.
// =====================================================================

/// The functions a migration file creates in `public`, read from its text:
/// `(SECURITY DEFINER ones, all)`.
fn functions_of(migration: &str) -> (Vec<String>, Vec<String>) {
    let mut definers = Vec::new();
    let mut all = Vec::new();
    let mut rest = migration;
    while let Some(i) = rest.find("CREATE OR REPLACE FUNCTION public.") {
        let after = &rest[i + "CREATE OR REPLACE FUNCTION public.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let body_end = after.find("$$;").unwrap_or(after.len());
        let header_end = after.find(" AS $$").unwrap_or(body_end);
        if after[..header_end].contains("SECURITY DEFINER") {
            definers.push(name.clone());
        }
        all.push(name);
        rest = &after[body_end..];
    }
    definers.sort();
    definers.dedup();
    all.sort();
    all.dedup();
    (definers, all)
}

/// Every SECURITY DEFINER migration 127 creates is on
/// `epigraph-tenancy-backfill verify`'s ownership list at 127 (a silently
/// no-opped `OWNER TO` is invisible to every behavioural test, because the
/// harness migrates as a superuser), every function it creates is dropped by
/// `docs/runbooks/127-undo.sql`, and the table is in the API's FORCE register
/// and the 079 kill switch.
///
/// Verified to fail: the `("epigraph_record_elevated_access", 127)` entry
/// removed from `DEFERRED_DEFINER_FUNCTIONS` -> named here.
#[test]
fn every_127_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/127_elevated_access.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let state = read("crates/epigraph-api/src/state.rs");
    let kill_switch = read("docs/runbooks/079-undo.sql");
    let undo = read("docs/runbooks/127-undo.sql");

    let (definers, all) = functions_of(&migration);
    assert_eq!(
        definers.len(),
        5,
        "CALIBRATION: 127 creates 5 SECURITY DEFINER functions; the scan found {definers:?}"
    );
    assert_eq!(definers, all, "every function 127 creates is a definer");
    let missing: Vec<&String> = definers
        .iter()
        .filter(|n| !backfill.contains(&format!("(\"{n}\", 127)")))
        .collect();
    assert!(
        missing.is_empty(),
        "migration 127 definers missing from tenancy_backfill.rs's ownership list at 127: \
         {missing:?}"
    );
    let undropped: Vec<&String> = all
        .iter()
        .filter(|n| !undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")))
        .collect();
    assert!(
        undropped.is_empty(),
        "127-undo.sql does not drop: {undropped:?}"
    );
    assert!(
        state.contains("\"elevated_access\""),
        "state.rs FORCE_PROTECTED_SET lacks elevated_access"
    );
    assert!(
        kill_switch.contains("'elevated_access'"),
        "079-undo.sql lacks elevated_access"
    );
}

// =====================================================================
// 132's undo, and the registers know 132's one object.
// =====================================================================

fn undo_132() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/132-undo.sql"),
    )
    .expect("132-undo.sql")
}

/// The gate's full definition (`pg_get_functiondef`: body, volatility,
/// security, search_path).
async fn gate_def(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_elevated_access_ready()'::regprocedure)",
    )
    .fetch_one(pool)
    .await
    .expect("the gate's definition")
}

/// `docs/runbooks/132-undo.sql`, applied to a database that went 131 -> 132
/// with a live session, closes the gate: the session is no longer elevated,
/// the gate's definition, owner and ACL are BYTE-EQUAL to the same database's
/// at 131, the catalog is 131's, and the session row stays (history). A
/// second run changes nothing. Cut at 132, not head: a later migration is
/// undone before this one.
///
/// Verified to fail: the undo's body `SELECT true` (still elevated); the undo
/// emptied (the definition is 132's).
#[sqlx::test(migrations = false)]
async fn the_132_rollback_closes_the_gate_and_restores_125s_body(pool: PgPool) {
    migrate(&pool, &up_to(131)).await;
    let (def_131, acl_131, catalog_131) = (
        gate_def(&pool).await,
        gate_owner_and_acl(&pool).await,
        catalog(&pool).await,
    );
    migrate(&pool, &up_to(132)).await;
    assert_ne!(
        gate_def(&pool).await,
        def_131,
        "CALIBRATION: 132 re-bodied the gate"
    );
    let p = holder(&pool, "gate-undo-p", 43).await;
    let live = session(&pool, &p, "gate undo").await;
    assert!(
        is_elevated(&pool, &p, live).await,
        "CALIBRATION: elevated at 132"
    );

    for run in 1..=2 {
        sqlx::raw_sql(&undo_132())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    assert!(!gate(&pool).await, "the undo closes the gate");
    assert!(
        !is_elevated(&pool, &p, live).await,
        "after the undo the session is not elevated"
    );
    assert_eq!(
        gate_def(&pool).await,
        def_131,
        "125's definition, byte for byte"
    );
    assert_eq!(
        gate_owner_and_acl(&pool).await,
        acl_131,
        "owner and ACL kept"
    );
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&catalog_131).collect();
    let lost: Vec<&String> = catalog_131.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 131's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM elevation_sessions WHERE id = $1")
        .bind(live)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(kept, 1, "the session row stays");
}

/// Migration 132 creates no new function: it re-bodies exactly one definer,
/// 125's recorder gate, which stays on `epigraph-tenancy-backfill verify`'s
/// ownership list at its own migration (125) and on the grant register as
/// NOT application-callable; `docs/runbooks/132-undo.sql` restores it; and no
/// migration but 125 (closed), 132 (opened) and 160 (the final review's
/// owner test on the recorder; its undo restores 132's body) defines it
/// (125's header: nothing else may replace it).
///
/// Verified to fail: a second `CREATE OR REPLACE` of the gate planted in
/// 131 (named here).
#[test]
fn every_132_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/132_open_elevation.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let undo = read("docs/runbooks/132-undo.sql");
    let (definers, all) = functions_of(&migration);
    assert_eq!(
        (definers.clone(), all),
        (
            vec!["epigraph_elevated_access_ready".to_string()],
            vec!["epigraph_elevated_access_ready".to_string()]
        ),
        "132 re-bodies the gate and nothing else"
    );
    assert!(
        backfill.contains("(\"epigraph_elevated_access_ready\", 125)"),
        "the gate stays on the ownership list at its own migration"
    );
    assert!(
        undo.contains("CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready()")
            && undo.contains("SELECT false"),
        "132-undo restores 125's closed body"
    );
    let mut replacing: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(root.join("migrations")).expect("migrations") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("migration");
        if text.contains("CREATE OR REPLACE FUNCTION public.epigraph_elevated_access_ready(") {
            replacing.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    replacing.sort();
    assert_eq!(
        replacing,
        vec![
            "125_elevation.sql",
            "132_open_elevation.sql",
            "160_elevation_final_review.sql"
        ],
        "only 125 (closed), 132 (open) and 160 (owner-checked) define the recorder gate"
    );
}

// =====================================================================
// The Rust recording path (ScopedPool::record_elevated_access)
// =====================================================================

/// An application-role pool that declares the recorder (the test stand-in for
/// a recording build), in `mode`.
async fn recording_pool(pool: &PgPool, mode: SessionGucMode) -> ScopedPool {
    ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        mode,
        ScopedPoolOptions {
            max_connections: 2,
            ..ScopedPoolOptions::default()
        },
        Some("epigraph_app"),
    )
    .await
    .expect("a recording application-role pool")
}

fn access(ids: Vec<Uuid>) -> ElevatedAccess {
    ElevatedAccess {
        surface: "GET /api/v1/claims/:id".to_string(),
        args: serde_json::json!({"path": "/api/v1/claims/x"}),
        row_count: 1,
        candidate_ids: ids,
    }
}

/// `ScopedPool::record_elevated_access` records an elevated viewer's access in
/// ONE row, attributed by the database, in BOTH session-setting modes (in
/// transaction mode an elevated viewer otherwise gets only `BEGIN READ ONLY`,
/// where the recorder's insert would fail with 25006).
///
/// Verified to fail with the record path opening `BEGIN READ ONLY` (25006 in
/// both modes) and with its stamp skipped (ELV07: the connection is not
/// elevated).
#[sqlx::test(migrations = "../../migrations")]
async fn the_recording_path_writes_one_row_in_both_modes(pool: PgPool) {
    let p = holder(&pool, "access-path-p", 31).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "access-path-b").await;
    let b_claim = fixture::seed_group_claim(&pool, b, b_group, "B's private claim").await;
    let live = session(&pool, &p, "recording path").await;
    for mode in [SessionGucMode::Session, SessionGucMode::Transaction] {
        let s = recording_pool(&pool, mode).await;
        assert!(s.records_elevated_access(), "CALIBRATION: a recording pool");
        let v = Viewer::resolve_elevated(&s, p.person, Some(live), p.family)
            .await
            .expect("resolve");
        assert!(
            v.is_elevated(),
            "CALIBRATION: P resolves elevated ({mode:?})"
        );
        let row = s
            .record_elevated_access(&v, &access(vec![b_claim]))
            .await
            .unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        let (groups, surface, rows): (Vec<Uuid>, String, i32) = sqlx::query_as(
            "SELECT owner_group_ids, surface, row_count FROM elevated_access WHERE id = $1",
        )
        .bind(row)
        .fetch_one(&pool)
        .await
        .expect("the row");
        assert_eq!(groups, vec![b_group], "{mode:?}");
        assert_eq!(surface, "GET /api/v1/claims/:id");
        assert_eq!(rows, 1);
    }
    assert_eq!(log_rows(&pool).await, 2);
}

/// The recording path refuses, and writes nothing, for a viewer that is not
/// elevated, on a pool that does not declare the recorder (even with an
/// elevated viewer in hand), and for a session ended between its resolution
/// and the record (the database's ELV07, surfaced as
/// `ElevatedAccessUnrecorded`): the caller withholds the response.
///
/// Verified to fail with the pool's declaration check removed (the
/// non-declaring pool's connection is not elevated, so the definer refuses
/// with ELV07 instead: caught by the reason assertion) and with the viewer
/// check removed (the plain viewer reaches the definer: caught likewise).
#[sqlx::test(migrations = "../../migrations")]
async fn the_recording_path_refuses_what_it_cannot_record(pool: PgPool) {
    let p = holder(&pool, "access-refuse-p", 32).await;
    let live = session(&pool, &p, "refusals").await;
    let s = recording_pool(&pool, SessionGucMode::Session).await;
    let elevated = Viewer::resolve_elevated(&s, p.person, Some(live), p.family)
        .await
        .expect("resolve");
    let plain = Viewer::resolve_elevated(&s, p.person, None, p.family)
        .await
        .expect("resolve");
    assert!(
        elevated.is_elevated() && !plain.is_elevated(),
        "CALIBRATION"
    );

    let reason = |r: Result<Uuid, DbError>| match r {
        Err(DbError::ElevatedAccessUnrecorded { reason }) => reason,
        other => panic!("expected ElevatedAccessUnrecorded, got {other:?}"),
    };
    assert_eq!(
        reason(s.record_elevated_access(&plain, &access(vec![])).await),
        "the viewer is not elevated"
    );
    let bare = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("a non-recording pool");
    assert!(!bare.records_elevated_access(), "CALIBRATION");
    assert_eq!(
        reason(
            bare.record_elevated_access(&elevated, &access(vec![]))
                .await
        ),
        "this pool does not declare the per-access recorder"
    );
    stamped(&pool, Stamp::plain(p.person), |mut conn| async move {
        sqlx::query("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(live)
            .execute(&mut *conn)
            .await
            .expect("end");
        (conn, ())
    })
    .await;
    let ended = reason(s.record_elevated_access(&elevated, &access(vec![])).await);
    assert!(ended.contains("ELV07"), "the database's refusal: {ended}");
    assert_eq!(log_rows(&pool).await, 0, "nothing recorded");
}

/// Only `ScopedPool::connect_recording_elevated_access` among the PRODUCTION
/// constructors declares the recorder: its connections carry
/// `epigraph.access_recorder = on`, `connect` and `connect_with_options` leave
/// it unset.
///
/// Verified to fail with the recording constructor passing `false` to the
/// shared builder.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_recording_constructor_declares_the_recorder(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let probe = |s: ScopedPool| async move {
        let v = Viewer::resolve(s.inner(), Uuid::new_v4())
            .await
            .expect("an empty viewer");
        let mut conn = s.acquire_as(&v).await.expect("acquire_as");
        let declared: String = sqlx::query_scalar("SELECT COALESCE(current_setting($1, true), '')")
            .bind(epigraph_db::ACCESS_RECORDER_GUC)
            .fetch_one(&mut *conn)
            .await
            .expect("the declaration");
        (declared, s.records_elevated_access())
    };
    let recording = ScopedPool::connect_recording_elevated_access(
        &url,
        SessionGucMode::Session,
        ScopedPoolOptions::default(),
    )
    .await
    .expect("recording pool");
    assert_eq!(probe(recording).await, ("on".to_string(), true));
    let plain = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("plain pool");
    assert_eq!(probe(plain).await, (String::new(), false));
    let sized = ScopedPool::connect_with_options(
        &url,
        SessionGucMode::Session,
        ScopedPoolOptions::default(),
    )
    .await
    .expect("sized pool");
    assert_eq!(probe(sized).await, (String::new(), false));
}

// =====================================================================
// Pinned (operator-hidden) evidence (operator ruling 2026-10-04, interim)
// =====================================================================

/// Hide `evidence` the way `epigraph-operator hide-evidence --apply` leaves
/// it (migration 110): pinned, then `('group', the hiding operator's group)`.
async fn hide(pool: &PgPool, evidence: Uuid, group: Uuid, operator: Uuid) {
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'el8 test: hidden by the operator')",
    )
    .bind(evidence)
    .bind(operator)
    .execute(pool)
    .await
    .expect("pin");
    sqlx::query("UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE id = $1")
        .bind(evidence)
        .bind(group)
        .execute(pool)
        .await
        .expect("hide");
}

/// The operator's interim ruling (2026-10-04): an elevated session that reads
/// claims MAY read their evidence, operator-hidden (pinned) evidence included,
/// and every such read is recorded where its owner sees it. An elevated read
/// of a PINNED evidence row of a PUBLIC claim is recorded against the row's
/// owning group (the hiding operator H's), and H, that group's admin, reads
/// the row; B (the claim's author) does not. Calibrations: the elevated
/// session reads the pinned row through 126's arm; P unelevated does not.
///
/// Verified to fail with `public.evidence` removed from the recorder's
/// attribution (no group named).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_read_of_pinned_evidence_is_recorded_for_its_owner(pool: PgPool) {
    let p = holder(&pool, "access-pin-p", 33).await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "access-pin-b").await;
    let (h, h_group) = fixture::seed_agent_with_group(&pool, "access-pin-h").await;
    let claim = fixture::seed_public_claim(&pool, b, "a public claim with hidden evidence").await;
    let evidence = fixture::seed_evidence(&pool, claim, "observation").await;
    hide(&pool, evidence, h_group, h).await;
    let live = session(&pool, &p, "pinned evidence").await;

    let read = |stamp: Stamp| {
        let pool = pool.clone();
        async move {
            stamped(&pool, stamp, |mut conn| async move {
                let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE id = $1")
                    .bind(evidence)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("read the evidence");
                (conn, n)
            })
            .await
        }
    };
    assert_eq!(
        read(Stamp::plain(p.person)).await,
        0,
        "CALIBRATION: hidden from P"
    );
    assert_eq!(
        read(Stamp::elevated(&p, live)).await,
        1,
        "CALIBRATION: the elevated session reads the pinned row (the ruling)"
    );

    let row = record(
        &pool,
        Stamp::elevated(&p, live),
        "GET /api/v1/claims/:id/evidence",
        1,
        vec![claim, evidence],
    )
    .await
    .expect("records");
    let groups: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_ids FROM elevated_access WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .expect("the row");
    assert_eq!(groups, vec![h_group], "the pinned row's owning group");
    assert_eq!(visible(&pool, h).await, vec![row], "H reads it");
    assert!(visible(&pool, b).await.is_empty(), "B does not");
}
