//! Migration 116 (batch HTTP-id): the ATTESTED retire of a former shared HTTP
//! signer, `epigraph_link_retired_shared_signer`.
//!
//! 107's `epigraph_link_retired_agent` refuses an agent whose OPERATED_BY
//! auth-lineage names more than one principal (the shared-signer fingerprint).
//! 116 admits such an agent only when every lineage principal other than the
//! agent itself and the operator is attested by the maintenance caller, and
//! keeps every other refusal of 107's retire.
//!
//! Every call runs on a genuine `epigraph_maintenance` session
//! (`fixture::as_role`, which changes `session_user`), so the grant, the
//! definer's ownership and the `security_events` append policy are all
//! exercised; the superuser harness connection would skip all three.
//!
//! Load-bearing, verified by editing the migration on a scratch database:
//! dropping the unattested-principal check makes
//! `an_unattested_lineage_principal_refuses_and_an_attested_one_links_retired`
//! link on the empty attestation; dropping the audit INSERT fails its audit
//! count; dropping the NULL-element refusal fails
//! `a_null_in_the_attested_set_refuses_and_writes_nothing` (the NULL-safe filter
//! alone refuses with 55000, not 22004, and with only the refusal reverted AND
//! the filter written the old way, `ARRAY[NULL]` links); dropping the self-loop
//! exclusion fails
//! `a_self_loop_on_a_schema_without_the_constraint_is_not_a_lineage_principal`
//! (the signer then has to attest itself).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, DbError, RetiredLinkOutcome};
use sqlx::PgPool;
use uuid::Uuid;

fn hash32(id: Uuid) -> Vec<u8> {
    id.as_bytes().iter().copied().cycle().take(32).collect()
}

/// Registered as a HUMAN OPERATOR: since migration 122 a link (retired ones
/// included) can be recorded only to one, and this file measures 116's own
/// refusals, not 122's.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(hash32(agent))
        .execute(pool)
        .await
        .expect("seed agent");
    fixture::make_human_operator(pool, agent).await;
    agent
}

/// What `EpiGraphMcpFull::record_auth_lineage` writes for each caller.
async fn lineage_edge(pool: &PgPool, signer: Uuid, principal: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
    )
    .bind(signer)
    .bind(principal)
    .execute(pool)
    .await
    .expect("auth-lineage edge");
}

/// A former shared signer: lineage to the operator and to one more principal.
///
/// A database whose `edges` predates `edges_no_self_loop` can also carry the
/// signer's SELF-loop (the principal-less listener's injected principal IS the
/// signer); a database migrated from 001 refuses one, so it is not seeded here.
/// `a_self_loop_on_a_schema_without_the_constraint_is_not_a_lineage_principal`
/// covers that shape.
async fn former_signer(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let signer = seed_agent(pool).await;
    let operator = seed_agent(pool).await;
    let other = seed_agent(pool).await;
    for target in [operator, other] {
        lineage_edge(pool, signer, target).await;
    }
    (signer, operator, other)
}

async fn as_maint<T, F, Fut>(pool: &PgPool, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    fixture::as_role(pool, "epigraph_maintenance", f).await
}

async fn retire_shared(
    pool: &PgPool,
    agent: Uuid,
    operator: Uuid,
    attested: Vec<Uuid>,
) -> Result<RetiredLinkOutcome, DbError> {
    as_maint(pool, |mut conn| async move {
        let r = AgentRepository::link_retired_shared_signer(&mut conn, agent, operator, &attested)
            .await;
        (conn, r)
    })
    .await
}

async fn links_of(pool: &PgPool, agent: Uuid) -> Vec<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_all(pool)
        .await
        .expect("links")
}

async fn audits_of(pool: &PgPool, agent: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'operator.shared_signer_retired' AND agent_id = $1",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("audits")
}

fn uuids(v: &serde_json::Value) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = v
        .as_array()
        .expect("a JSON array")
        .iter()
        .map(|x| x.as_str().expect("a string").parse().expect("a uuid"))
        .collect();
    out.sort();
    out
}

/// The request DSN cannot call it; the maintenance login can (calibration).
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_maintenance_login_can_record_the_attested_retire(pool: PgPool) {
    let (signer, operator, other) = former_signer(&pool).await;
    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = AgentRepository::link_retired_shared_signer(&mut conn, signer, operator, &[other])
            .await;
        (conn, r)
    })
    .await;
    let err = refused.expect_err("epigraph_app must not record operator links");
    assert!(err.to_string().contains("permission denied"), "{err}");
    assert!(links_of(&pool, signer).await.is_empty(), "nothing written");

    let ok = retire_shared(&pool, signer, operator, vec![other])
        .await
        .expect("the maintenance login records it");
    assert!(ok.link_created && ok.link_retired);
}

/// 107 refuses the fingerprint; 116 refuses an UNATTESTED lineage principal,
/// naming it and writing nothing; with the principal attested it records a
/// RETIRED link with NO membership, the OPERATED_BY edge, and exactly one
/// audit row carrying the attestation and the lineage it was checked against.
/// The operator then owns the signer's claims
/// (`operator_of_author`), and the signer can never act for it
/// (`operator_actor` is None).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unattested_lineage_principal_refuses_and_an_attested_one_links_retired(pool: PgPool) {
    let (signer, operator, other) = former_signer(&pool).await;

    let e107 = as_maint(&pool, |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, signer, operator).await;
        (conn, r)
    })
    .await
    .expect_err("107's retire refuses the shared-signer fingerprint");
    assert!(e107.to_string().contains("shared HTTP signer"), "{e107}");

    let e = retire_shared(&pool, signer, operator, vec![])
        .await
        .expect_err("an unattested lineage principal refuses");
    let text = e.to_string();
    // The unattested set is exactly `{other}`: the operator is not in it.
    assert!(
        text.contains("not attested") && text.contains(&format!("{{{other}}}")),
        "names exactly the unattested principal: {text}"
    );
    assert!(links_of(&pool, signer).await.is_empty(), "nothing written");
    assert!(audits_of(&pool, signer).await.is_empty(), "no audit row");

    let ok = retire_shared(&pool, signer, operator, vec![other])
        .await
        .expect("attested: linked");
    assert!(ok.link_created && ok.link_retired);
    assert!(
        !ok.edge_created,
        "the (signer, operator) OPERATED_BY edge already existed as lineage"
    );
    assert!(
        !ok.membership_live,
        "a retired identity holds no membership"
    );
    assert_eq!(links_of(&pool, signer).await, vec![(operator, true)]);

    let audits = audits_of(&pool, signer).await;
    assert_eq!(audits.len(), 1, "exactly one attestation on the record");
    assert_eq!(uuids(&audits[0]["attested"]), vec![other]);
    let mut lineage = vec![operator, other];
    lineage.sort();
    assert_eq!(
        uuids(&audits[0]["lineage_targets"]),
        lineage,
        "the lineage it was checked against"
    );
    assert_eq!(audits[0]["operator_id"], serde_json::json!(operator));

    // The (signer, operator) lineage edge pre-existed, so 116 must not add a
    // second one (`the_recorded_edge_carries_the_attestation` covers the case
    // where it records the edge itself).
    let pair_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(signer)
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(pair_edges, 1, "no duplicate OPERATED_BY edge for the pair");

    let mut conn = pool.acquire().await.expect("acquire");
    let author_op = AgentRepository::operator_of_author(&mut conn, signer)
        .await
        .expect("author read")
        .expect("the operator now owns the signer's claims");
    assert_eq!((author_op.operator_id, author_op.retired), (operator, true));
    assert!(
        AgentRepository::operator_actor(&mut conn, signer)
            .await
            .expect("actor read")
            .is_none(),
        "a retired former signer can never act for the operator"
    );
}

/// When the operator had NO lineage edge from the signer, 116 records one,
/// tagged with its source and the attestation.
#[sqlx::test(migrations = "../../migrations")]
async fn the_recorded_edge_carries_the_attestation(pool: PgPool) {
    let signer = seed_agent(&pool).await;
    let operator = seed_agent(&pool).await;
    let (p1, p2) = (seed_agent(&pool).await, seed_agent(&pool).await);
    lineage_edge(&pool, signer, p1).await;
    lineage_edge(&pool, signer, p2).await;

    let ok = retire_shared(&pool, signer, operator, vec![p1, p2])
        .await
        .expect("both attested");
    assert!(ok.edge_created);
    let (source, attested): (String, serde_json::Value) = sqlx::query_as(
        "SELECT properties->>'source', properties->'attested' FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(signer)
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("the link edge");
    assert_eq!(source, "epigraph_link_retired_shared_signer");
    let mut want = vec![p1, p2];
    want.sort();
    assert_eq!(uuids(&attested), want);
}

/// An exact relink records nothing new and audits nothing new, and a lineage
/// edge added AFTER the link (forgeable by any app session) cannot turn that
/// idempotent re-run into a refusal: the lineage check is first-link only.
#[sqlx::test(migrations = "../../migrations")]
async fn an_exact_relink_is_idempotent_and_audits_once(pool: PgPool) {
    let (signer, operator, other) = former_signer(&pool).await;
    retire_shared(&pool, signer, operator, vec![other])
        .await
        .expect("first link");
    let forged = seed_agent(&pool).await;
    lineage_edge(&pool, signer, forged).await;

    let again = retire_shared(&pool, signer, operator, vec![other])
        .await
        .expect("an exact relink is not refused");
    assert!(!again.link_created && again.link_retired);
    assert_eq!(audits_of(&pool, signer).await.len(), 1, "audited once");
}

/// Every other refusal of 107's retire still holds: an operator that itself
/// fronted many principals, and a signer that still holds write authority in
/// the operator's group. Both write nothing.
///
/// Since migration 122 (review SEC-5) the operator-side fingerprint applies
/// only to an operator that is NOT a registered human operator (those edges are
/// app-forgeable; a registered human is never a shared signer), so the
/// fingerprinted operator here is an unregistered agent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rest_of_107s_retire_still_refuses(pool: PgPool) {
    // Operator-side fingerprint.
    // The former signer's own lineage names `first` too, so it is attested.
    let (signer, first, other) = former_signer(&pool).await;
    let operator = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(operator)
        .bind(hash32(operator))
        .execute(&pool)
        .await
        .expect("an unregistered operator");
    let (x, y) = (seed_agent(&pool).await, seed_agent(&pool).await);
    lineage_edge(&pool, operator, x).await;
    lineage_edge(&pool, operator, y).await;
    let e = retire_shared(&pool, signer, operator, vec![other, first, x, y])
        .await
        .expect_err("an operator with the shared-signer fingerprint is refused");
    assert!(e.to_string().contains("refusing it as an operator"), "{e}");
    assert!(links_of(&pool, signer).await.is_empty());

    // A live writer membership in the operator's group.
    let (signer2, operator2, other2) = former_signer(&pool).await;
    let group: Uuid = sqlx::query_scalar("SELECT public.epigraph_ensure_personal_group($1)")
        .bind(operator2)
        .fetch_one(&pool)
        .await
        .expect("operator group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, '\\x00', 0, 'writer')",
    )
    .bind(group)
    .bind(signer2)
    .execute(&pool)
    .await
    .expect("writer row");
    let e = retire_shared(&pool, signer2, operator2, vec![other2])
        .await
        .expect_err("a live writer membership refuses the retire");
    assert!(e.to_string().contains("live writer/admin"), "{e}");
    assert!(links_of(&pool, signer2).await.is_empty());
    assert!(audits_of(&pool, signer2).await.is_empty());
}

/// A NULL element in the attested set refuses (22004) and writes nothing.
///
/// Without that refusal, `t = ANY (ARRAY[NULL])` is NULL for an unmatched
/// lineage principal, `NOT NULL` is NULL, and the principal would drop out of
/// the unattested set: the call would link on an attestation of nobody. The
/// Rust binding (`&[Uuid]`) cannot send a NULL, so this drives the function
/// directly, as a maintenance login at a psql prompt would.
#[sqlx::test(migrations = "../../migrations")]
async fn a_null_in_the_attested_set_refuses_and_writes_nothing(pool: PgPool) {
    let (signer, operator, _other) = former_signer(&pool).await;
    let stranger = seed_agent(&pool).await;
    for (label, attested) in [
        ("ARRAY[NULL]", vec![None]),
        ("ARRAY[stranger, NULL]", vec![Some(stranger), None]),
    ] {
        let r = as_maint(&pool, |mut conn| async move {
            let r =
                sqlx::query("SELECT * FROM public.epigraph_link_retired_shared_signer($1, $2, $3)")
                    .bind(signer)
                    .bind(operator)
                    .bind(attested)
                    .fetch_one(&mut *conn)
                    .await;
            (conn, r)
        })
        .await;
        let err = r.expect_err("a NULL attestation must refuse");
        let code = err
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.into_owned()));
        assert_eq!(
            code.as_deref(),
            Some("22004"),
            "{label}: refused by the NULL-element check itself: {err}"
        );
        assert!(links_of(&pool, signer).await.is_empty(), "{label}: no link");
        assert!(
            audits_of(&pool, signer).await.is_empty(),
            "{label}: no audit"
        );
    }
}

/// On a schema WITHOUT `edges_no_self_loop` (one whose `edges` predates it), the
/// principal-less listener's lineage attempt leaves a `signer -> signer`
/// OPERATED_BY self-loop. 116 excludes it from the lineage set, so the operator
/// attests only the OTHER principals, and the audit row's lineage omits the
/// signer. (Dropping the exclusion would refuse, naming the signer.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_self_loop_on_a_schema_without_the_constraint_is_not_a_lineage_principal(pool: PgPool) {
    sqlx::query("ALTER TABLE edges DROP CONSTRAINT edges_no_self_loop")
        .execute(&pool)
        .await
        .expect("model the older schema (this throwaway database only)");
    let (signer, operator, other) = former_signer(&pool).await;
    lineage_edge(&pool, signer, signer).await;

    let ok = retire_shared(&pool, signer, operator, vec![other])
        .await
        .expect("the self-loop is not a principal to attest");
    assert!(ok.link_created && ok.link_retired);
    let audits = audits_of(&pool, signer).await;
    assert_eq!(audits.len(), 1);
    let mut lineage = vec![operator, other];
    lineage.sort();
    assert_eq!(
        uuids(&audits[0]["lineage_targets"]),
        lineage,
        "the signer's self-loop is not in the lineage it was checked against"
    );
}
