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
//! Use `--provider mock` for a dry compile/smoke without credentials (it
//! returns an empty batch, so nothing is written). Use `--provider fixture`
//! plus `DECOMPOSE_FIXTURE_PATH=<file.json>` to exercise the atom/edge WRITE
//! path deterministically without an LLM call — see [`FixtureLlmClient`] for
//! the file format.

use clap::Parser;
use epigraph_cli::decompose::{run_decomposition_batches, BatchClaim};
use epigraph_cli::enrichment::llm_client::{FixtureLlmClient, LlmProvider};
use epigraph_db::ClaimRepository;
use std::sync::Arc;

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
    /// LLM provider selector for create_llm_client ("epigraph" auto, or
    /// "mock"), or "fixture" for the deterministic test provider (requires
    /// DECOMPOSE_FIXTURE_PATH).
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

/// Env var naming the JSON fixture file consumed by `--provider fixture`.
const FIXTURE_PATH_ENV: &str = "DECOMPOSE_FIXTURE_PATH";

/// Resolve the `--provider` selector to a concrete client.
///
/// `epigraph` / `mock` / any registered name go through the kernel factory
/// unchanged. `fixture` is handled HERE rather than in `create_llm_client`
/// because `epigraph_interfaces::default_llm_provider` skips only the literal
/// name `"mock"`: any *registered* active provider is eligible for `--provider
/// epigraph` auto-detect when Anthropic credentials are absent, so registering
/// a fixture provider would make canned atoms silently writable in production.
/// Keeping it out of the registry means it is reachable only via this explicit
/// branch, and only when `DECOMPOSE_FIXTURE_PATH` is also set — two locks, both
/// opt-in.
///
/// Takes the already-read env value rather than reading it here so the guard is
/// a pure function, testable without mutating global process env.
fn resolve_llm_client(
    provider: &str,
    fixture_path: Option<String>,
) -> Result<Arc<dyn LlmProvider>, Box<dyn std::error::Error>> {
    if provider == "fixture" {
        let path = fixture_path.ok_or(
            "--provider fixture requires DECOMPOSE_FIXTURE_PATH=<file.json> (a JSON object \
             keyed by claim text)",
        )?;
        return Ok(Arc::new(FixtureLlmClient::from_path(
            std::path::Path::new(&path),
        )?));
    }
    Ok(epigraph_cli::enrichment::llm_client::create_llm_client(
        provider,
    )?)
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

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool` for why that earns a
    // bypass and a request handler does not.
    //
    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure. And `_maint_conn` is held for the
    // whole run — the lease attests to THAT connection, and the pre-PR-15
    // template dropped it while the viewer lived on.
    let maint = epigraph_cli::MaintenancePool::connect("decompose_claims").await?;
    let (_maint_conn, viewer) = maint
        .viewer(epigraph_db::visibility::SystemReason::TenancyBackfill)
        .await?;
    let viewer = &viewer;
    let pool = maint.pool();

    let claims = ClaimRepository::list_undecomposed(pool, viewer, cli.limit, 0).await?;
    eprintln!("found {} undecomposed claims", claims.len());
    if cli.dry_run || claims.is_empty() {
        for c in &claims {
            println!("{}\t{}", c.id.as_uuid(), c.content);
        }
        return Ok(());
    }

    // Prepaid Claude path. create_llm_client("epigraph") returns the first
    // active provider (Anthropic-from-env, OAuth-preferred); "mock" for smoke;
    // "fixture" for a deterministic, credential-free write-path exercise.
    let llm = resolve_llm_client(&cli.provider, std::env::var(FIXTURE_PATH_ENV).ok())?;
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

    // The parent claims the runner iterates. `agent_id` rides along because
    // atoms inherit their parent compound claim's author, and the parent
    // varies across a batch.
    let batch_claims: Vec<BatchClaim> = claims
        .iter()
        .map(|c| BatchClaim {
            claim_id: c.id.as_uuid(),
            agent_id: c.agent_id.as_uuid(),
            content: c.content.clone(),
        })
        .collect();

    let totals = run_decomposition_batches(
        pool,
        viewer,
        &batch_claims,
        llm.as_ref(),
        cli.batch_size,
        embedder,
        move |atom_text, generality, parent_agent_id| {
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
    eprintln!(
        "decompose complete: {} atoms, {} decomposes_to edges",
        totals.atoms, totals.edges
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{resolve_api_base, resolve_llm_client, resolve_service_credentials};

    /// `--provider fixture` without `DECOMPOSE_FIXTURE_PATH` must fail, not
    /// fall back to some default fixture: selecting the canned-response
    /// provider requires two deliberate acts, so a production run can never
    /// reach it by omission.
    #[test]
    fn fixture_provider_requires_an_explicit_fixture_path() {
        let err = match resolve_llm_client("fixture", None) {
            Ok(_) => panic!("fixture provider must not resolve without DECOMPOSE_FIXTURE_PATH"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("DECOMPOSE_FIXTURE_PATH"),
            "error must name the missing env var: {err}"
        );
    }

    /// A stray `DECOMPOSE_FIXTURE_PATH` in the environment must not divert any
    /// other selector — `mock` still resolves to `mock`, and the fixture path
    /// is ignored entirely.
    #[test]
    fn fixture_path_does_not_divert_other_providers() {
        let client = resolve_llm_client("mock", Some("/nonexistent/fixture.json".to_string()))
            .expect("mock must resolve regardless of DECOMPOSE_FIXTURE_PATH");
        assert_eq!(client.name(), "mock");
    }

    /// The `fixture` provider must never be reachable through the kernel
    /// factory, because registry membership is what makes a provider eligible
    /// for `--provider epigraph` auto-detect (which skips only the literal name
    /// `mock`). If this ever starts returning `Ok`, canned atoms have become
    /// silently writable in production whenever Anthropic credentials are
    /// absent.
    #[test]
    fn fixture_is_not_reachable_through_the_kernel_factory() {
        let err = match epigraph_cli::enrichment::llm_client::create_llm_client("fixture") {
            Ok(_) => panic!("`fixture` must not be a registered provider"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("Unknown LLM provider"),
            "fixture must be unknown to the registry: {err}"
        );
    }

    /// An unreadable fixture file is a hard error — never a silent empty batch
    /// that would look like a clean no-op run.
    #[test]
    fn fixture_provider_rejects_a_missing_fixture_file() {
        let err = match resolve_llm_client(
            "fixture",
            Some("/nonexistent/decompose-fixture.json".to_string()),
        ) {
            Ok(_) => panic!("a missing fixture file must not resolve"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("unreadable"),
            "error must explain the file could not be read: {err}"
        );
    }

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
