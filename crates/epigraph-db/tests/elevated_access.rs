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

async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    // 125 ships the gate closed and 127 leaves it closed; these tests are
    // about what the recorder does for a LIVE session.
    fixture::open_elevated_access_gate(pool).await;
    holder_behind_the_gate(pool, label, n).await
}

/// [`holder`] without opening the gate: its sessions confirm (and audit) but
/// are never live.
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

/// 127 installs the recorder and does NOT open migration 125's gate: on a
/// database migrated to head with no test stand-in, the gate still answers
/// false and a confirmed session is not live (the opening waits on the
/// preconditions 125's header lists).
///
/// Verified to fail with `CREATE OR REPLACE FUNCTION
/// epigraph_elevated_access_ready() ... SELECT true` appended to 127.
#[sqlx::test(migrations = "../../migrations")]
async fn the_recorder_leaves_the_gate_closed(pool: PgPool) {
    let gate: bool = sqlx::query_scalar("SELECT public.epigraph_elevated_access_ready()")
        .fetch_one(&pool)
        .await
        .expect("the gate");
    assert!(!gate, "the gate is still closed at 127");
    let recorder: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_record_elevated_access(text, jsonb, integer, \
                                 uuid[])') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("the recorder");
    assert!(recorder, "CALIBRATION: the recorder is installed");
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
