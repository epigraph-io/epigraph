//! Web search for experimental method evidence.
//!
//! Usage: method_search <hypothesis_id> (--public | --group UUID) [--agent-id UUID]
//!                       [--gaps-only] [--gap "PEG-silane SAM on HfO2"]

use clap::Parser;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "method_search",
    about = "Search web for method evidence to fill gaps",
    group(clap::ArgGroup::new("tenancy").required(true).multiple(false))
)]
struct Args {
    /// Hypothesis claim UUID
    hypothesis_id: Uuid,

    /// Readable by every authenticated agent; owned by the author's personal
    /// group.
    #[arg(long, group = "tenancy")]
    public: bool,

    /// Readable only by live members of this group.
    #[arg(long, group = "tenancy", value_name = "UUID")]
    group: Option<Uuid>,

    /// Agent UUID that authors the ingested claims.
    ///
    /// REQUIRED, and this is a BUG FIX, not a new obligation. Before PR-16 the
    /// INSERT below named no `agent_id` at all, and `claims.agent_id` is
    /// `NOT NULL` with no `DEFAULT` (migration 001), so **every invocation of
    /// this binary that reached the insert already raised 23502**. There was
    /// no working path to preserve. Naming the author is also what makes a
    /// tenancy declaration possible: `--public` owns the row with the author's
    /// personal group, and without an author there is no group to name.
    #[arg(long, env = "EPIGRAPH_AGENT_ID", hide_env_values = true)]
    agent_id: Uuid,

    /// Only process methods with evidence_score < 0.3
    #[arg(long)]
    gaps_only: bool,

    /// Search for a specific gap description instead of auto-detecting
    #[arg(long)]
    gap: Option<String>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("method_search")
        .await
        .expect("maintenance pool");
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::SchemaContractTest)
        .await
        .expect("maintenance viewer");
    let viewer = session.viewer();
    let exit_code = match run(args, maint.pool().clone(), viewer).await {
        Ok(all_filled) => {
            if all_filled {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    };
    std::process::exit(exit_code);
}

/// Returns true if all gaps filled, false if gaps remain.
async fn run(
    args: Args,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<bool, Box<dyn std::error::Error>> {
    let embedder = epigraph_cli::embedding_service()
        .ok_or("OPENAI_API_KEY not set — embeddings required for method_search ingestion")?;

    // Tenancy declaration (PR-16), resolved once for the whole run: every claim
    // this binary ingests is the same operator's answer to the same gap, so a
    // per-claim choice would be a distinction with no caller to make it.
    // clap's ArgGroup guarantees exactly one flag was given; the `None` arm is
    // a hard error rather than a default, for the reason spelled out in
    // `hypothesis.rs`.
    let decl = match (args.public, args.group) {
        (_, Some(g)) => epigraph_core::TenancyDecl::group(g),
        (true, None) => {
            let mut conn = pool.acquire().await?;
            epigraph_db::ClaimRepository::default_decl_for_author(&mut conn, args.agent_id).await?
        }
        (false, None) => return Err("exactly one of --public / --group <uuid> is required".into()),
    };

    // 1. Load hypothesis
    let (statement,): (String,) = sqlx::query_as("SELECT content FROM claims WHERE id = $1")
        .bind(args.hypothesis_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("Hypothesis {}: {e}", args.hypothesis_id))?;

    // 2. Load methods for hypothesis's experiments
    let experiments =
        epigraph_db::ExperimentRepository::get_for_hypothesis(&pool, args.hypothesis_id).await?;

    let mut gaps: Vec<(Uuid, String, f64)> = Vec::new(); // (method_id, description, evidence_score)

    for exp in &experiments {
        if let Some(method_ids) = &exp.method_ids {
            for mid in method_ids {
                if let Some(method) = epigraph_db::MethodRepository::get(&pool, *mid).await? {
                    let evidence = epigraph_db::MethodRepository::get_evidence_strength(
                        &pool, viewer, method.id,
                    )
                    .await
                    .ok();
                    let score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);

                    let is_gap = method.source_claim_ids.is_empty() || score < 0.3;
                    if is_gap || (!args.gaps_only && args.gap.is_some()) {
                        gaps.push((method.id, method.name.clone(), score));
                    }
                }
            }
        }
    }

    if gaps.is_empty() {
        println!(
            "No evidence gaps found for hypothesis {}",
            args.hypothesis_id
        );
        return Ok(true);
    }

    println!("Found {} gap(s) to fill:", gaps.len());
    for (_, name, score) in &gaps {
        println!("  - {name} (evidence: {score:.3})");
    }

    // 3. Search for each gap
    use epigraph_cli::enrichment::llm_client::create_llm_client;

    let client = create_llm_client("epigraph").map_err(|e| e.to_string())?;

    let mut all_filled = true;

    for (method_id, method_name, _score) in &gaps {
        let gap_desc = args
            .gap
            .clone()
            .unwrap_or_else(|| format!("{method_name} for {statement}"));

        let prompt = format!(
            r#"Search for published papers about: {gap_desc}
Context: This method is part of an experimental protocol for: {statement}

Return a JSON array of discovered claims. Each claim object:
{{
  "content": "One-sentence quantitative claim from the paper",
  "doi": "10.xxxx/yyyy or null",
  "journal": "Journal name",
  "year": 2024,
  "truth_value": 0.85,
  "is_preprint": false,
  "protocol_parameters": {{
    "concentration": "2 mM",
    "temperature": "25°C"
  }}
}}

Focus on: specific concentrations, temperatures, thicknesses, performance metrics, and protocol parameters.
Only include claims with quantitative data.
Return 3-8 claims."#,
        );

        tracing::info!("Searching for: {gap_desc}");
        let response = match client.complete_json(&prompt).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Web search failed for {method_name}: {e}");
                all_filled = false;
                continue;
            }
        };

        // Parse claims array (response might be the array directly or wrapped)
        let claims = if response.is_array() {
            response.as_array().unwrap().clone()
        } else if let Some(arr) = response.get("claims").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            eprintln!("Unexpected response format for {method_name}: not a JSON array");
            all_filled = false;
            continue;
        };

        // 4. Ingest claims
        let mut ingested = 0;
        for claim in &claims {
            let content = match claim.get("content").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => continue,
            };

            // Compute content_hash via BLAKE3 (matches all other claims in the DB)
            let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());

            // Cheap pre-check, before the embedding call: content that is
            // already in the graph is skipped without paying for an embedding.
            // `insert_unless_hash_exists` repeats the find, so this check is an
            // optimization, not the dedup.
            if content_hash_exists(&pool, content_hash.as_slice()).await? {
                tracing::info!(
                    "Duplicate claim skipped: {}",
                    &content[..content.len().min(60)]
                );
                continue;
            }

            let truth_value = claim
                .get("truth_value")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.85);
            let is_preprint = claim
                .get("is_preprint")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tv = if is_preprint {
                truth_value.min(0.78)
            } else {
                truth_value
            };

            let doi = claim.get("doi").and_then(|v| v.as_str());
            let journal = claim.get("journal").and_then(|v| v.as_str());
            let year = claim.get("year").and_then(|v| v.as_i64());

            // Embed inline (matches hypothesis.rs pattern; embedding policy requires
            // is_current=true claims to have an embedding).
            let embedding = embedder
                .generate(content)
                .await
                .map_err(|e| format!("Embedding failed: {e}"))?;
            let embedding_str = format!(
                "[{}]",
                embedding
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );

            // Insert claim
            let new_claim = WebSearchClaim {
                content,
                truth_value: tv,
                properties: serde_json::json!({
                    "source": "web_search",
                    "doi": doi,
                    "journal": journal,
                    "year": year,
                    "protocol_parameters": claim.get("protocol_parameters"),
                }),
                embedding: &embedding_str,
            };
            let claim_id = {
                let mut conn = pool.acquire().await?;
                insert_unless_hash_exists(&mut conn, args.agent_id, decl, &new_claim)
                    .await
                    .map_err(|e| e as Box<dyn std::error::Error>)?
            };
            let Some(claim_id) = claim_id else {
                tracing::info!(
                    "Duplicate claim skipped: {}",
                    &content[..content.len().min(60)]
                );
                continue;
            };

            // Create SUPPORTS edge from claim to hypothesis
            sqlx::query(
                r#"
                INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
                VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS', '{}')
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(claim_id)
            .bind(args.hypothesis_id)
            .execute(&pool)
            .await
            .ok();

            // Update method's source_claim_ids
            sqlx::query(
                "UPDATE methods SET source_claim_ids = source_claim_ids || ARRAY[$1] WHERE id = $2",
            )
            .bind(claim_id)
            .bind(method_id)
            .execute(&pool)
            .await
            .ok();

            ingested += 1;
        }

        println!("  {method_name}: ingested {ingested} new claims");
    }

    // 5. Report updated evidence scores
    println!("\nUpdated evidence scores:");
    for (method_id, method_name, old_score) in &gaps {
        let evidence =
            epigraph_db::MethodRepository::get_evidence_strength(&pool, viewer, *method_id)
                .await
                .ok();
        let new_score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);
        let filled = if new_score >= 0.3 { "FILLED" } else { "GAP" };
        println!("  {method_name}: {old_score:.3} → {new_score:.3} [{filled}]");
        if new_score < 0.3 {
            all_filled = false;
        }
    }

    Ok(all_filled)
}

/// One web-search result to persist as a claim.
struct WebSearchClaim<'a> {
    content: &'a str,
    truth_value: f64,
    properties: serde_json::Value,
    /// pgvector text literal, `[x,y,...]`.
    embedding: &'a str,
}

/// Whether any claim (by any author) has this `content_hash`. The ONE
/// existence probe of this binary: the run loop's unlocked pre-check and
/// [`insert_unless_hash_exists`]'s check under the dedup lock both call it.
/// `SELECT 1` is an INT4, so it decodes as `i32`; decoding it as anything
/// wider failed every time a match existed and aborted the run.
async fn content_hash_exists<'e, E>(exec: E, content_hash: &[u8]) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM claims WHERE content_hash = $1")
        .bind(content_hash)
        .fetch_optional(exec)
        .await?;
    Ok(exists.is_some())
}

/// Insert `claim` authored by `agent_id`, unless a claim with its
/// `content_hash` already exists. Returns the new row's id, or `None` when the
/// content was already present.
///
/// **Concurrency:** the find and the INSERT run in one scope (a real `BEGIN`
/// on a bare connection, a SAVEPOINT in a caller's transaction) under
/// `ClaimRepository::lock_content_hash_agent` for the pair the INSERT writes,
/// the lock the repository's find-then-insert writers take (backlog
/// 00f1a517). Two concurrent runs over the same content by one author, or a
/// run racing a repository create of that pair, therefore yield one row. One
/// lock per short transaction: nothing else is held while it waits. The find
/// stays content-hash-only (any author), as before.
async fn insert_unless_hash_exists(
    conn: &mut sqlx::PgConnection,
    agent_id: Uuid,
    decl: epigraph_core::TenancyDecl,
    claim: &WebSearchClaim<'_>,
) -> Result<Option<Uuid>, Box<dyn std::error::Error + Send + Sync>> {
    use sqlx::Acquire;

    let content_hash = epigraph_crypto::ContentHasher::hash(claim.content.as_bytes());

    // Dropped without commit on any error path below, which rolls the scope
    // (and the lock, when it is a real transaction) back.
    let mut scope = conn.begin().await?;

    // Taken before the find: without it, a concurrent writer's uncommitted
    // row is invisible to the find and both insert.
    epigraph_db::ClaimRepository::lock_content_hash_agent(
        &mut scope,
        content_hash.as_slice(),
        agent_id,
    )
    .await?;

    if content_hash_exists(&mut *scope, content_hash.as_slice()).await? {
        scope.commit().await?;
        return Ok(None);
    }

    let (id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO claims (content, content_hash, truth_value, agent_id, labels, properties, embedding, visibility, owner_group_id)
        VALUES ($1, $2, $3, $4, ARRAY['experimental', 'web_search'], $5, $6::vector, $7, $8)
        RETURNING id
        "#,
    )
    .bind(claim.content)
    .bind(content_hash.as_slice())
    .bind(claim.truth_value)
    .bind(agent_id)
    .bind(&claim.properties)
    .bind(claim.embedding)
    .bind(decl.visibility_bind())
    .bind(decl.owner_group_bind())
    .fetch_one(&mut *scope)
    .await?;
    scope.commit().await?;
    Ok(Some(id))
}

/// Concurrency cover for [`insert_unless_hash_exists`] (backlog 00f1a517):
/// two writers of one `(content_hash, agent_id)` must yield one row.
///
/// Held-open shape, as in `epigraph-db`'s `claim_repo_helpers` race arms:
/// caller 1 writes inside a transaction it keeps OPEN, so its row exists but is
/// invisible to every other snapshot. Caller 2 then writes the same content by
/// the same author on its own connection (the binary's shape). No sleep decides
/// the outcome: the arm waits until caller 2 either finished (nothing made it
/// wait, so its find missed caller 1's row and it inserted a second one) or is
/// blocked on a two-key advisory lock, and panics if neither happens.
#[cfg(test)]
mod dedup_race_tests {
    use super::{content_hash_exists, insert_unless_hash_exists, WebSearchClaim};
    use epigraph_core::{AgentId, Claim, TenancyDecl, TruthValue};
    use epigraph_crypto::ContentHasher;
    use epigraph_db::ClaimRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    /// Who holds the pair first, in the open transaction.
    #[derive(Debug, Clone, Copy)]
    enum First {
        /// Another run of this binary.
        MethodSearch,
        /// The repository's legacy content-hash create (`ingest_document`
        /// atoms, the conventions routes). Proves the binary takes the SAME
        /// key as the repository writers, not merely some lock.
        RepositoryCreateConn,
    }

    async fn seed_author(pool: &PgPool) -> (Uuid, TenancyDecl) {
        // The production shape: no unique constraint on the pair (migration
        // 150). Explicit, so the arm cannot pass on a constraint.
        sqlx::query("ALTER TABLE claims DROP CONSTRAINT IF EXISTS uq_claims_content_hash_agent")
            .execute(pool)
            .await
            .expect("drop the pair constraint");
        let agent_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agents (id, public_key, created_at, updated_at) \
             VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
        )
        .bind(agent_id)
        .execute(pool)
        .await
        .expect("insert the author");
        // Mint the author's personal group NOW, committed: left to the racers,
        // caller 2 would wait on caller 1's uncommitted group upsert (a row
        // lock, not the dedup lock).
        let mut conn = pool.acquire().await.expect("acquire for the group mint");
        let decl = ClaimRepository::default_decl_for_author(&mut conn, agent_id)
            .await
            .expect("mint the author's personal group");
        (agent_id, decl)
    }

    fn embedding_literal() -> String {
        format!("[{}]", vec!["0.1"; 1536].join(","))
    }

    async fn settle_on_the_dedup_lock<T>(pool: &PgPool, task: &tokio::task::JoinHandle<T>) -> bool {
        for _ in 0..600 {
            if task.is_finished() {
                return false;
            }
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_locks \
                  WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted \
                  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .fetch_one(pool)
            .await
            .expect("read pg_locks");
            if waiting > 0 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "caller 2 neither finished nor blocked on a dedup lock while caller 1's transaction \
             was open; it is waiting on something else, so the arm cannot tell serialized from not"
        );
    }

    async fn race_held_open(pool: &PgPool, first: First) {
        let (agent_id, decl) = seed_author(pool).await;
        let content = format!("method_search held-open after {first:?} {}", Uuid::new_v4());
        let embedding = embedding_literal();

        let mut tx_1 = pool.begin().await.expect("begin caller 1's transaction");
        let r1: Uuid = match first {
            First::MethodSearch => {
                let claim = WebSearchClaim {
                    content: &content,
                    truth_value: 0.8,
                    properties: serde_json::json!({ "source": "web_search" }),
                    embedding: &embedding,
                };
                insert_unless_hash_exists(&mut tx_1, agent_id, decl, &claim)
                    .await
                    .expect("caller 1 insert")
                    .expect("caller 1 is the first write of the pair")
            }
            First::RepositoryCreateConn => {
                let claim = Claim::new(
                    content.clone(),
                    AgentId::from_uuid(agent_id),
                    [0u8; 32],
                    TruthValue::new(0.5).unwrap(),
                );
                ClaimRepository::create_conn(&mut tx_1, &claim, decl)
                    .await
                    .expect("caller 1 create_conn")
                    .id
                    .into()
            }
        };

        let caller_2 = {
            let pool = pool.clone();
            let content = content.clone();
            let embedding = embedding.clone();
            tokio::spawn(async move {
                let mut conn = pool.acquire().await.expect("acquire caller 2's connection");
                let claim = WebSearchClaim {
                    content: &content,
                    truth_value: 0.8,
                    properties: serde_json::json!({ "source": "web_search" }),
                    embedding: &embedding,
                };
                insert_unless_hash_exists(&mut conn, agent_id, decl, &claim)
                    .await
                    .expect("caller 2 insert")
            })
        };
        let blocked = settle_on_the_dedup_lock(pool, &caller_2).await;

        tx_1.commit().await.expect("commit caller 1's transaction");
        let r2 = caller_2.await.expect("caller 2 must not panic");

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2",
        )
        .bind(ContentHasher::hash(content.as_bytes()).as_slice())
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .expect("count rows for the pair");
        assert_eq!(
            rows, 1,
            "method_search racing an open {first:?} of one (content_hash, agent_id) left {rows} \
             rows: its find could not see caller 1's uncommitted row and nothing made it wait. \
             Caller 1 wrote {r1}, caller 2 answered {r2:?}"
        );
        assert!(
            blocked,
            "caller 2 finished while caller 1's transaction was open: nothing made it wait"
        );
        assert_eq!(
            r2, None,
            "caller 2 ran after caller 1 committed, so it must skip the existing content"
        );
    }

    /// A run over content that is already in the graph skips it, at BOTH
    /// places a run checks: the run loop's unlocked pre-check
    /// (`content_hash_exists` on the pool, before the embedding call) and
    /// `insert_unless_hash_exists`. Both go through the one probe,
    /// `content_hash_exists`, whose `SELECT 1` is an INT4: decoding it as
    /// anything wider failed every time a match existed, so a known result
    /// aborted the run instead of being skipped.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_second_run_over_known_content_skips_it(pool: PgPool) {
        let (agent_id, decl) = seed_author(&pool).await;
        let content = format!("method_search sequential {}", Uuid::new_v4());
        let hash = ContentHasher::hash(content.as_bytes());
        let embedding = embedding_literal();
        let claim = WebSearchClaim {
            content: &content,
            truth_value: 0.8,
            properties: serde_json::json!({ "source": "web_search" }),
            embedding: &embedding,
        };
        assert!(
            !content_hash_exists(&pool, hash.as_slice())
                .await
                .expect("the run loop's pre-check over new content"),
            "new content is not reported as known"
        );
        let mut conn = pool.acquire().await.expect("acquire");
        let first = insert_unless_hash_exists(&mut conn, agent_id, decl, &claim)
            .await
            .expect("first run");
        assert!(first.is_some(), "the first run inserts the new content");
        assert!(
            content_hash_exists(&pool, hash.as_slice())
                .await
                .expect("the run loop's pre-check over known content must not error"),
            "the run loop's pre-check reports the committed content as known"
        );
        let second = insert_unless_hash_exists(&mut conn, agent_id, decl, &claim)
            .await
            .expect("a second run over known content must not error");
        assert_eq!(second, None, "the second run skips the known content");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content_hash = $1")
            .bind(ContentHasher::hash(content.as_bytes()).as_slice())
            .fetch_one(&pool)
            .await
            .expect("count rows");
        assert_eq!(rows, 1);
    }

    const RACE_BARRIER_KEY: i64 = 424_243;

    /// Two runs of the binary, BOTH on bare connections (its real shape), with
    /// caller 1 parked inside its INSERT by a `BEFORE INSERT` trigger that
    /// takes a session advisory lock the test holds. A transaction-scoped lock
    /// taken in autocommit is released at the end of its own statement, so an
    /// implementation that locks without opening a scope passes the held-open
    /// arms (caller 1 runs in a transaction there) and still mints a duplicate
    /// here. No sleep decides the outcome: the handshakes are read from
    /// `pg_locks`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn two_bare_connection_runs_serialize_across_the_insert(pool: PgPool) {
        let (agent_id, decl) = seed_author(&pool).await;
        let content = format!("method_search bare race {}", Uuid::new_v4());
        let embedding = embedding_literal();

        // Fires only for caller 1's row, which carries the marker property.
        sqlx::query(
            &"CREATE OR REPLACE FUNCTION zz_ms_race_barrier() RETURNS trigger
              LANGUAGE plpgsql AS $$
              BEGIN
                  PERFORM pg_advisory_lock(KEY);
                  PERFORM pg_advisory_unlock(KEY);
                  RETURN NEW;
              END $$"
                .replace("KEY", &RACE_BARRIER_KEY.to_string()),
        )
        .execute(&pool)
        .await
        .expect("create the barrier function");
        sqlx::query(
            "CREATE TRIGGER zz_ms_race_barrier BEFORE INSERT ON claims FOR EACH ROW \
             WHEN (NEW.properties->>'race_barrier' = 'hold') \
             EXECUTE FUNCTION zz_ms_race_barrier()",
        )
        .execute(&pool)
        .await
        .expect("install the barrier trigger");

        let mut holder = pool.acquire().await.expect("acquire the barrier holder");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(RACE_BARRIER_KEY)
            .execute(&mut *holder)
            .await
            .expect("take the barrier");

        let spawn_run = |marker: &'static str| {
            let pool = pool.clone();
            let content = content.clone();
            let embedding = embedding.clone();
            tokio::spawn(async move {
                let mut conn = pool.acquire().await.expect("acquire a racer connection");
                let claim = WebSearchClaim {
                    content: &content,
                    truth_value: 0.8,
                    properties: serde_json::json!({ "race_barrier": marker }),
                    embedding: &embedding,
                };
                insert_unless_hash_exists(&mut conn, agent_id, decl, &claim)
                    .await
                    .expect("racer insert")
            })
        };

        let caller_1 = spawn_run("hold");
        // Caller 1 is parked inside its INSERT.
        let mut parked = false;
        for _ in 0..600 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_locks \
                  WHERE locktype = 'advisory' AND objid = $1::bigint AND NOT granted \
                  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .bind(RACE_BARRIER_KEY)
            .fetch_one(&pool)
            .await
            .expect("read pg_locks");
            if waiting > 0 {
                parked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            parked,
            "caller 1 never reached the barrier trigger, so this arm would prove nothing"
        );

        let caller_2 = spawn_run("go");
        let blocked = settle_on_the_dedup_lock(&pool, &caller_2).await;

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(RACE_BARRIER_KEY)
            .execute(&mut *holder)
            .await
            .expect("release the barrier");
        drop(holder);

        let r1 = caller_1.await.expect("caller 1 must not panic");
        let r2 = caller_2.await.expect("caller 2 must not panic");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM claims WHERE content_hash = $1 AND agent_id = $2",
        )
        .bind(ContentHasher::hash(content.as_bytes()).as_slice())
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .expect("count rows for the pair");
        assert_eq!(
            rows, 1,
            "two bare-connection runs of one (content_hash, agent_id) left {rows} rows: caller \
             2's find ran while caller 1's INSERT was in flight. Outcomes: {r1:?}, {r2:?}"
        );
        assert!(
            blocked,
            "caller 2 finished while caller 1 was parked in its INSERT"
        );
        assert!(r1.is_some() && r2.is_none(), "outcomes: {r1:?}, {r2:?}");
    }

    /// Two runs of the binary over the same search result.
    #[sqlx::test(migrations = "../../migrations")]
    async fn two_runs_of_one_content_by_one_author_insert_one_row(pool: PgPool) {
        race_held_open(&pool, First::MethodSearch).await;
    }

    /// The binary waits on the lock the repository's writers hold.
    #[sqlx::test(migrations = "../../migrations")]
    async fn waits_on_the_repository_writers_dedup_lock(pool: PgPool) {
        race_held_open(&pool, First::RepositoryCreateConn).await;
    }
}
