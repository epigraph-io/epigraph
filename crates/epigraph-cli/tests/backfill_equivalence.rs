//! OB6: the set-based tenancy backfill produces EXACTLY the outcome the per-row
//! definitions produce, row for row.
//!
//! * `claims`: the owner the backfill stamps equals, for every claim, the
//!   per-row definition evaluated on that claim (the author's operator link
//!   group, any state, else its personal group: the canonical
//!   `did:epigraph:personal:<id>` key first, else its EARLIEST personal group
//!   under another key), although the binary now resolves it once per distinct
//!   author of a batch. The batch size is 3 so the walk spans many batches and
//!   authors straddle batch boundaries.
//! * the 17 claim-derived tables (rows seeded in evidence, reasoning_traces,
//!   challenges and claim_versions): every row takes its claim's tenancy, except a
//!   WRITER-OWNED row (kept, the claim being public) and a PINNED evidence row
//!   (owner kept, visibility `group`): 110/114's rules, unchanged.
//! * `edges`: every edge equals the meet 120's body computed, recomputed here
//!   with the ORIGINAL `epigraph_node_tenancy` function that body called: for
//!   a meet that is `group` the edge takes it (a stale public edge onto a
//!   private claim is repaired, as before), otherwise it keeps its prior state.
//!   Migration 122 replaced the OR join and the per-endpoint function calls
//!   with equi-joins; this pins that nothing else changed.
//! * `perspectives` / `recall_events`: the same per-row definition on their
//!   agent column.
//!
//! Verified to fail:
//! * `owner_group_sql`'s personal-group branch replaced by the canonical key
//!   alone -> the non-canonical author's claims stay world-owned;
//! * the edges meet in 122 with the evidence LEFT JOIN on the source side
//!   dropped -> the evidence->claim edge onto the private claim takes the wrong
//!   meet;
//! * `'challenges'` removed from 122 section 8's `derived` array -> the
//!   challenge row stays world-owned while its claim moves.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-tenancy-backfill");
const WORLD: Uuid = Uuid::nil();

async fn run_backfill(pool: &PgPool, args: &[&str]) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn epigraph-tenancy-backfill");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn exec(pool: &PgPool, sql: &str) {
    sqlx::query(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn bare_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(id.as_bytes().repeat(2))
        .execute(pool)
        .await
        .expect("agent");
    id
}

/// A personal group for `agent` under `did_key`, created at `age` ago.
async fn personal_group(pool: &PgPool, agent: Uuid, did_key: &str, age_days: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id, created_at) \
         VALUES ($1, $1, ''::bytea, 'personal', $2, now() - make_interval(days => $3)) RETURNING id",
    )
    .bind(did_key)
    .bind(agent)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("personal group")
}

async fn world_claims(pool: &PgPool, agent: Uuid, n: usize) -> Vec<Uuid> {
    let mut out = Vec::new();
    for i in 0..n {
        out.push(fixture::seed_public_claim(pool, agent, &format!("equiv {agent} {i}")).await);
    }
    out
}

/// The per-row owner definition, in SQL, for an `{agent}` expression.
fn per_row_owner(agent: &str) -> String {
    format!(
        "COALESCE((SELECT l.operator_group_id FROM operator_links l WHERE l.agent_id = {agent}),
                  (SELECT g.id FROM groups g
                    WHERE (g.did_key = 'did:epigraph:personal:' || {agent}::text)
                       OR (g.kind = 'personal' AND g.created_by_agent_id = {agent})
                    ORDER BY (g.did_key = 'did:epigraph:personal:' || {agent}::text) DESC,
                             g.created_at ASC
                    LIMIT 1))"
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_set_based_backfill_matches_the_per_row_definitions(pool: PgPool) {
    // ---- authors ----
    let (human, _) = fixture::seed_human_operator(&pool, "operator").await;
    let (canon, _) = fixture::seed_agent_with_group(&pool, "canon").await;
    // Both keys: an OLDER non-canonical group and the canonical one; canonical wins.
    let both = bare_agent(&pool).await;
    personal_group(&pool, both, &format!("did:epigraph:test:old:{both}"), 30).await;
    personal_group(&pool, both, &format!("did:epigraph:personal:{both}"), 1).await;
    // Only non-canonical groups: the EARLIEST wins.
    let noncanon = bare_agent(&pool).await;
    personal_group(
        &pool,
        noncanon,
        &format!("did:epigraph:test:b:{noncanon}"),
        5,
    )
    .await;
    personal_group(
        &pool,
        noncanon,
        &format!("did:epigraph:test:a:{noncanon}"),
        9,
    )
    .await;
    let (live, _) = fixture::seed_agent_with_group(&pool, "live").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired").await;
    // No group at all: phase 0 mints the canonical one.
    let nogroup = bare_agent(&pool).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, live, human)
            .await
            .expect("live link");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
    }

    // ---- world-owned claims, derived rows, edges ----
    let mut claims = Vec::new();
    for a in [canon, both, noncanon, live, retired, nogroup] {
        claims.extend(world_claims(&pool, a, 4).await);
    }
    let c0 = claims[0];
    // An ordinary derived row of a moved claim (checked by the derived-rows rule).
    let _normal_ev = fixture::seed_evidence(&pool, c0, "testimony").await;
    let writer_ev = fixture::seed_evidence(&pool, claims[1], "testimony").await;
    let pinned_ev = fixture::seed_evidence(&pool, claims[2], "testimony").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    sqlx::query(
        "UPDATE evidence SET owner_group_id = $2, writer_owned = true, signer_id = $3, \
                             signature = $4 WHERE id = $1",
    )
    .bind(writer_ev)
    .bind(writer_group)
    .bind(writer)
    .bind(vec![9u8; 64])
    .execute(&pool)
    .await
    .expect("writer-owned evidence");
    // A pinned row keeps its OWNER and is forced to `group`, so it must have a
    // real owner (hide-evidence pins rows of re-owned claims); `('group',
    // world)` is not a row the schema can hold, under either body.
    sqlx::query("UPDATE evidence SET owner_group_id = $2 WHERE id = $1")
        .bind(pinned_ev)
        .bind(writer_group)
        .execute(&pool)
        .await
        .expect("pinned row's own owner");
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) VALUES ($1, $2, 'equiv')",
    )
    .bind(pinned_ev)
    .bind(human)
    .execute(&pool)
    .await
    .expect("pin");
    fixture::seed_reasoning_trace(&pool, claims[3], "deductive").await;
    // Two more derived tables with rows (review C8: the comparison below spans
    // all 17, and a table with no rows proves nothing about its arm).
    exec(
        &pool,
        &format!(
            "INSERT INTO challenges (claim_id, challenge_type, explanation) \
             VALUES ('{}', 'factual', 'equivalence probe')",
            claims[6]
        ),
    )
    .await;
    exec(
        &pool,
        &format!(
            "INSERT INTO claim_versions (claim_id, version_number, content, truth_value) \
             VALUES ('{}', 1, 'equivalence probe v1', 0.5)",
            claims[7]
        ),
    )
    .await;
    exec(
        &pool,
        &format!(
            "INSERT INTO mass_functions (claim_id, frame_id, masses, source_agent_id) \
             SELECT '{}', f.id, '{{}}'::jsonb, NULL FROM frames f LIMIT 1",
            claims[4]
        ),
    )
    .await;
    // A private claim in another group, and edges onto it: public->private
    // (stored STALE as world/public, so the meet must repair it), evidence->
    // private, claim->claim public, claim->agent.
    let (other, other_group) = fixture::seed_agent_with_group(&pool, "other").await;
    let private = fixture::seed_group_claim(&pool, other, other_group, "private endpoint").await;
    let stale = fixture::seed_edge(&pool, claims[5], private).await;
    exec(
        &pool,
        &format!(
            "UPDATE edges SET owner_group_id = '{WORLD}', visibility = 'public', co_owner_group_id = NULL \
              WHERE id = '{stale}'"
        ),
    )
    .await;
    // A PRIVATE evidence row (on the private claim) pointing at a claim the
    // backfill moves, stored stale: the meet reads the evidence endpoint.
    let private_ev = fixture::seed_evidence(&pool, private, "testimony").await;
    let ev_edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'evidence', $2, 'claim', 'SUPPORTS') RETURNING id",
    )
    .bind(private_ev)
    .bind(claims[9])
    .fetch_one(&pool)
    .await
    .expect("evidence edge");
    exec(
        &pool,
        &format!(
            "UPDATE edges SET owner_group_id = '{WORLD}', visibility = 'public', co_owner_group_id = NULL \
              WHERE id = '{ev_edge}'"
        ),
    )
    .await;
    fixture::seed_edge(&pool, claims[6], claims[7]).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'agent', 'AUTHORED_BY')",
    )
    .bind(claims[8])
    .bind(canon)
    .execute(&pool)
    .await
    .expect("claim->agent edge");
    // Agent-keyed rows.
    for a in [canon, noncanon, live, retired] {
        sqlx::query(
            "INSERT INTO recall_events (tool, query_text, agent_id, owner_group_id, visibility) \
             VALUES ('recall', 'q', $1, $2, 'public')",
        )
        .bind(a)
        .bind(WORLD)
        .execute(&pool)
        .await
        .expect("recall event");
    }

    // Derived/edge prior state, for the rows the rules say must be KEPT.
    let writer_prior: (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
            .bind(writer_ev)
            .fetch_one(&pool)
            .await
            .expect("prior");
    let pinned_prior_owner: Uuid =
        sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE id = $1")
            .bind(pinned_ev)
            .fetch_one(&pool)
            .await
            .expect("prior");
    let edges_prior: Vec<(Uuid, Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, co_owner_group_id FROM edges ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("edges prior");

    // ---- run: many tiny batches ----
    let (code, stderr) = run_backfill(
        &pool,
        &["run", "--legacy-owner", "operator", "--batch-size", "3"],
    )
    .await;
    assert_eq!(code, 0, "run must complete:\n{stderr}");

    // ---- claims: set-based == per-row ----
    let mismatched: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT c.id, c.owner_group_id, {def} AS expected FROM claims c
          WHERE c.id = ANY($1)
            AND (c.owner_group_id IS DISTINCT FROM {def} OR c.visibility <> 'public')",
        def = per_row_owner("c.agent_id")
    ))
    .bind(&claims)
    .fetch_all(&pool)
    .await
    .expect("claims compare");
    assert!(
        mismatched.is_empty(),
        "claims whose owner differs from the per-row definition: {mismatched:?}"
    );
    // The definition itself is exercised on every branch (not vacuous).
    let owner_of = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT DISTINCT owner_group_id FROM claims WHERE agent_id = $1",
            )
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("owner")
        }
    };
    let did = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT did_key FROM groups WHERE id = $1")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("did")
        }
    };
    assert_eq!(
        did(owner_of(both).await).await,
        format!("did:epigraph:personal:{both}")
    );
    assert_eq!(
        did(owner_of(noncanon).await).await,
        format!("did:epigraph:test:a:{noncanon}")
    );
    assert_eq!(
        did(owner_of(nogroup).await).await,
        format!("did:epigraph:personal:{nogroup}")
    );
    let human_group: Uuid =
        sqlx::query_scalar("SELECT operator_group_id FROM operator_links WHERE agent_id = $1")
            .bind(live)
            .fetch_one(&pool)
            .await
            .expect("link group");
    assert_eq!(owner_of(live).await, human_group);
    assert_eq!(owner_of(retired).await, human_group);

    // ---- derived rows: the trigger's rules, over ALL 17 claim-derived tables
    // (review C8: this compared three while the doc said seventeen). A
    // writer-owned row (114) and a pinned evidence row (110) are the stated
    // exceptions, checked by name below.
    const DERIVED: &[(&str, &str)] = &[
        (
            "evidence",
            "NOT d.writer_owned AND NOT EXISTS (SELECT 1 FROM evidence_visibility_pins p \
             WHERE p.evidence_id = d.id)",
        ),
        ("mass_functions", "NOT d.writer_owned"),
        ("reasoning_traces", "NOT d.writer_owned"),
        ("triples", "TRUE"),
        ("entity_mentions", "TRUE"),
        ("claim_versions", "TRUE"),
        ("ds_combined_beliefs", "TRUE"),
        ("ds_bayesian_divergence", "TRUE"),
        ("claim_frames", "TRUE"),
        ("harvester_claim_provenance", "TRUE"),
        ("challenges", "TRUE"),
        ("experiment_triples", "TRUE"),
        ("experiment_entity_mentions", "TRUE"),
        ("claim_clusters", "TRUE"),
        ("claim_cluster_membership", "TRUE"),
        ("claim_neighborhood_membership", "TRUE"),
        ("claim_signature_revocations", "TRUE"),
    ];
    let union = DERIVED
        .iter()
        .map(|(t, keep)| {
            format!("SELECT d.claim_id, d.owner_group_id, d.visibility FROM {t} d WHERE {keep}")
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let seeded: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM ({union}) d WHERE d.claim_id = ANY($1)"
    ))
    .bind(&claims)
    .fetch_one(&pool)
    .await
    .expect("derived rows seeded");
    assert!(
        seeded >= 4,
        "the fixture seeds derived rows in several tables to compare, got {seeded}"
    );
    let derived_off: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM ({union}) d JOIN claims c ON c.id = d.claim_id
         WHERE c.id = ANY($1)
           AND (d.owner_group_id, d.visibility) IS DISTINCT FROM (c.owner_group_id, c.visibility)"
    ))
    .bind(&claims)
    .fetch_one(&pool)
    .await
    .expect("derived compare");
    assert_eq!(
        derived_off, 0,
        "a derived row did not take its claim's tenancy"
    );
    let writer_after: (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
            .bind(writer_ev)
            .fetch_one(&pool)
            .await
            .expect("after");
    assert_eq!(
        writer_after, writer_prior,
        "a writer-owned row keeps its writer"
    );
    let pinned_after: (Uuid, String) =
        sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
            .bind(pinned_ev)
            .fetch_one(&pool)
            .await
            .expect("after");
    assert_eq!(
        pinned_after,
        (pinned_prior_owner, "group".to_string()),
        "a pinned row"
    );

    // ---- edges: the meet 120's body computed, via its own function ----
    let expected_edges: Vec<(Uuid, Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT e.id,
                CASE WHEN s.v = 'public' AND t.v = 'public' THEN '00000000-0000-0000-0000-000000000000'::uuid
                     WHEN s.v = 'public' THEN t.g WHEN t.v = 'public' THEN s.g ELSE s.g END,
                CASE WHEN s.v = 'public' AND t.v = 'public' THEN 'public' ELSE 'group' END,
                CASE WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g THEN t.g ELSE NULL END
           FROM edges e
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t
          ORDER BY e.id",
    )
    .fetch_all(&pool)
    .await
    .expect("meets");
    let edges_after: Vec<(Uuid, Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, co_owner_group_id FROM edges ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("edges after");
    let touched: std::collections::HashSet<Uuid> = sqlx::query_scalar(
        "SELECT id FROM edges WHERE (source_type = 'claim' AND source_id = ANY($1))
                                 OR (target_type = 'claim' AND target_id = ANY($1))",
    )
    .bind(&claims)
    .fetch_all(&pool)
    .await
    .expect("touched")
    .into_iter()
    .collect();
    let mut repaired = 0;
    for ((after, meet), prior) in edges_after.iter().zip(&expected_edges).zip(&edges_prior) {
        assert_eq!(after.0, meet.0);
        let expect = if touched.contains(&after.0) && meet.2 == "group" {
            meet.clone()
        } else {
            prior.clone()
        };
        if expect != *prior {
            repaired += 1;
        }
        assert_eq!(
            *after, expect,
            "edge {} is not what 120's meet gives",
            after.0
        );
    }
    assert!(
        repaired >= 2,
        "both stale edges (claim side and evidence side) must be repaired, got {repaired}"
    );

    // ---- agent-keyed ----
    let recall_off: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM recall_events r
          WHERE r.agent_id IS NOT NULL
            AND r.owner_group_id IS DISTINCT FROM {}",
        per_row_owner("r.agent_id")
    ))
    .fetch_one(&pool)
    .await
    .expect("recall compare");
    assert_eq!(
        recall_off, 0,
        "recall_events differ from the per-row definition"
    );
}
