//! `decompose_claims` — split standalone compound claims into atomic
//! propositions + wire parent -decomposes_to-> atom edges.
//!
//! The decompose primitive the dead `decomposition-cycle` schedule needs.
//! Enumerates via `ClaimRepository::list_undecomposed`, decomposes each batch
//! through the prepaid Claude path (`create_llm_client("epigraph")`, which
//! prefers CLAUDE_CODE_OAUTH_TOKEN — NEVER the Anthropic-SDK pay-per-token
//! variant the V2 `_api.py`/`_openai.py` scripts used), parses with
//! `epigraph_cli::decompose::parse_batch_response`, and persists atoms through
//! the canonical API claim path so embedding + DS auto-wire + signing happen
//! on write.
//!
//! Required: DATABASE_URL, and CLAUDE_CODE_OAUTH_TOKEN.
//! API base: EPIGRAPH_API (primary) or EPIGRAPH_API_URL (container fallback),
//! default http://127.0.0.1:8080. Auth token: EPIGRAPH_TOKEN if set, otherwise
//! minted via client_credentials from EPIGRAPH_SERVICE_CLIENT_ID +
//! EPIGRAPH_SERVICE_SECRET.
//! Use `--provider mock` for a dry compile/smoke without credentials.

use clap::Parser;
use epigraph_cli::decompose::{build_batch_prompt, parse_batch_response, persist_decomposition};
use epigraph_db::ClaimRepository;

#[derive(Parser)]
#[command(
    name = "decompose_claims",
    about = "Decompose undecomposed compound claims into atoms"
)]
struct Cli {
    /// Max claims to process this run.
    #[arg(long, default_value_t = 200)]
    limit: i64,
    /// Claims per LLM call.
    #[arg(long, default_value_t = 10)]
    batch_size: usize,
    /// LLM provider selector for create_llm_client ("epigraph" auto, or "mock").
    #[arg(long, default_value = "epigraph")]
    provider: String,
    /// Parse/enumerate only — do not call the LLM or write anything.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// API base precedence: `EPIGRAPH_API` (explicit override) first,
/// `EPIGRAPH_API_URL` (the container-standard name epiclaw-host exposes)
/// second, `http://127.0.0.1:8080` otherwise. Takes already-read env values
/// (rather than reading `std::env::var` itself) so it's a pure function —
/// testable without mutating global process env, which races under
/// parallel test execution.
fn resolve_api_base(epigraph_api: Option<String>, epigraph_api_url: Option<String>) -> String {
    epigraph_api
        .or(epigraph_api_url)
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// `None` unless both service-client credential env values are present.
/// Split out from `mint_service_token` as a pure guard so the "don't even
/// attempt a mint without both creds" behavior is unit-testable without an
/// HTTP mock.
fn resolve_service_credentials(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Option<(String, String)> {
    Some((client_id?, client_secret?))
}

/// Mint a bearer token from service-client credentials via the OAuth
/// client_credentials flow. Returns `None` if either credential env var is
/// absent or the request fails — callers fall back to an empty token (which
/// will produce a 401 on the first API call, surfacing the problem clearly).
async fn mint_service_token(api_base: &str) -> Option<String> {
    let (client_id, client_secret) = resolve_service_credentials(
        std::env::var("EPIGRAPH_SERVICE_CLIENT_ID").ok(),
        std::env::var("EPIGRAPH_SERVICE_SECRET").ok(),
    )?;
    let url = format!("{}/oauth/token", api_base.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "claims:write"),
        ])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    json["access_token"].as_str().map(str::to_owned)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let pool = epigraph_cli::db_connect().await?;

    let claims = ClaimRepository::list_undecomposed(&pool, cli.limit, 0).await?;
    eprintln!("found {} undecomposed claims", claims.len());
    if cli.dry_run || claims.is_empty() {
        for c in &claims {
            println!("{}\t{}", c.id.as_uuid(), c.content);
        }
        return Ok(());
    }

    // Prepaid Claude path. create_llm_client("epigraph") returns the first
    // active provider (Anthropic-from-env, OAuth-preferred); "mock" for smoke.
    let llm = epigraph_cli::enrichment::llm_client::create_llm_client(&cli.provider)?;
    let embedder = epigraph_cli::embedding_service();

    // API submit closure — canonical claim create (embed + DS + sign on write).
    // EPIGRAPH_API takes precedence; EPIGRAPH_API_URL is the container-standard
    // name exposed by epiclaw-host. If neither is set we fall back to localhost.
    let api_base = resolve_api_base(
        std::env::var("EPIGRAPH_API").ok(),
        std::env::var("EPIGRAPH_API_URL").ok(),
    );

    eprintln!("api_base={api_base}");

    // EPIGRAPH_TOKEN if present; otherwise attempt client_credentials mint so
    // container deployments work without a token-mint preamble in the schedule.
    // Diagnostic-only: never log the token value itself, only its provenance
    // and length (distinguishes "empty" from "present but wrong" without
    // leaking the credential — backlog a422da87's reported non-determinism
    // needs exactly this to disambiguate an auth failure from a URL-builder
    // failure across repeated scheduled runs).
    let token = {
        let t = std::env::var("EPIGRAPH_TOKEN").unwrap_or_default();
        if t.is_empty() {
            match mint_service_token(&api_base).await {
                Some(minted) => {
                    eprintln!(
                        "token: minted via client_credentials (len={})",
                        minted.len()
                    );
                    minted
                }
                None => {
                    eprintln!(
                        "token: EPIGRAPH_TOKEN unset AND client_credentials mint failed \
                         (missing creds or mint request error) — proceeding with an EMPTY \
                         bearer token, every API write below will 401"
                    );
                    String::new()
                }
            }
        } else {
            eprintln!("token: using EPIGRAPH_TOKEN from env (len={})", t.len());
            t
        }
    };
    let http = reqwest::Client::new();

    let mut total_atoms = 0usize;
    let mut total_edges = 0usize;
    for chunk in claims.chunks(cli.batch_size) {
        let indexed: Vec<(usize, &str)> = chunk
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.content.as_str()))
            .collect();
        let prompt = build_batch_prompt(&indexed);
        // SCAFFOLD BOUNDARY: this network call cannot run in the CI box.
        let raw = match llm.complete_json(&prompt).await {
            Ok(v) => v.to_string(),
            Err(e) => {
                eprintln!("  LLM call failed for batch: {e}; skipping");
                continue;
            }
        };
        let parsed = parse_batch_response(&raw);
        for (local_idx, decomp) in parsed {
            let Some(parent) = chunk.get(local_idx) else {
                continue;
            };
            let parent_id = parent.id.as_uuid();
            // Atoms inherit the parent compound claim's author. `agent_id` is a
            // REQUIRED field of CreateClaimRequest (POST /api/v1/claims) — omitting
            // it returns 422, which silently dropped every decomposition atom.
            let parent_agent_id = parent.agent_id.as_uuid();
            let http = http.clone();
            let api_base = api_base.clone();
            let token = token.clone();
            let outcome = persist_decomposition(
                &pool,
                parent_id,
                &decomp,
                embedder.clone(),
                move |atom_text, generality| {
                    let http = http.clone();
                    let api_base = api_base.clone();
                    let token = token.clone();
                    async move {
                        // Canonical create via API: signing + DS + embed-on-write.
                        // methodology/evidence_type belong in `properties` (JSONB);
                        // top-level they were unknown fields and silently dropped.
                        // if_not_exists=true: when a prior run already decomposed
                        // the same parent, identical atom text produces the same
                        // content_hash. Without this flag the API returns 409;
                        // with it, create_or_get returns the existing claim ID so
                        // persist_decomposition can re-wire edges idempotently.
                        // Diagnostic-only (backlog a422da87): build+log the URL BEFORE
                        // sending, so a RelativeUrlWithoutBase-style construction bug
                        // is visible even if the request itself never reaches the wire.
                        let url = format!("{api_base}/api/v1/claims");
                        eprintln!("POST {url}");
                        let resp = match http
                            .post(&url)
                            .bearer_auth(&token)
                            .json(&serde_json::json!({
                                "content": atom_text,
                                "agent_id": parent_agent_id,
                                "initial_truth": 0.5,
                                "if_not_exists": true,
                                "properties": {
                                    "methodology": "inductive_generalization",
                                    "evidence_type": "logical"
                                },
                                "labels": ["atom", format!("generality:{generality}")],
                            }))
                            .send()
                            .await
                        {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!(
                                    "POST {url} FAILED before a response was received: \
                                     is_builder={} is_request={} is_connect={} is_timeout={} \
                                     detail={e}",
                                    e.is_builder(),
                                    e.is_request(),
                                    e.is_connect(),
                                    e.is_timeout()
                                );
                                return Err(e.into());
                            }
                        };
                        let status = resp.status();
                        if !status.is_success() {
                            let body = resp.text().await.unwrap_or_default();
                            eprintln!("POST {url} -> HTTP {status}, body={body}");
                            return Err(format!("POST {url} -> HTTP {status}: {body}").into());
                        }
                        let v: serde_json::Value = resp.json().await?;
                        let id = v
                            .get("id")
                            .or_else(|| v.get("claim_id"))
                            .and_then(|x| x.as_str())
                            .ok_or("API create returned no claim id")?;
                        Ok(uuid::Uuid::parse_str(id)?)
                    }
                },
            )
            .await?;
            total_atoms += outcome.atom_claim_ids.len();
            total_edges += outcome.edges_created;
        }
    }
    eprintln!("decompose complete: {total_atoms} atoms, {total_edges} decomposes_to edges");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{resolve_api_base, resolve_service_credentials};

    #[test]
    fn resolve_api_base_prefers_epigraph_api_when_both_set() {
        assert_eq!(
            resolve_api_base(
                Some("https://explicit.example".to_string()),
                Some("http://container-standard.example".to_string()),
            ),
            "https://explicit.example"
        );
    }

    #[test]
    fn resolve_api_base_falls_back_to_epigraph_api_url() {
        assert_eq!(
            resolve_api_base(None, Some("http://container-standard.example".to_string())),
            "http://container-standard.example"
        );
    }

    #[test]
    fn resolve_api_base_defaults_to_localhost_when_neither_set() {
        assert_eq!(resolve_api_base(None, None), "http://127.0.0.1:8080");
    }

    #[test]
    fn resolve_service_credentials_none_when_client_id_missing() {
        assert_eq!(
            resolve_service_credentials(None, Some("secret".to_string())),
            None
        );
    }

    #[test]
    fn resolve_service_credentials_none_when_client_secret_missing() {
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), None),
            None
        );
    }

    #[test]
    fn resolve_service_credentials_some_when_both_present() {
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), Some("secret".to_string())),
            Some(("id".to_string(), "secret".to_string()))
        );
    }
}
