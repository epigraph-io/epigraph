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
//! API base: EPIGRAPH_API (primary) or EPIGRAPH_API_URL (container fallback,
//! a set-but-empty value in either is treated as absent), default
//! http://127.0.0.1:8080.
//!
//! Auth token: EPIGRAPH_TOKEN if set and non-empty, used as-is (a caller-
//! supplied token always wins — this binary never forces a mint over it).
//! Otherwise minted via the OAuth client_credentials grant from
//! EPIGRAPH_SERVICE_CLIENT_ID + EPIGRAPH_SERVICE_SECRET, posted to
//! EPIGRAPH_OAUTH_TOKEN_URL if set, else `{api_base}/oauth/token`. If neither
//! an explicit token nor a client-credentials pair is available, the binary
//! fails fast at startup with a clear error instead of proceeding with an
//! empty bearer token (which would otherwise only surface as a 401 once the
//! run reaches its first non-empty batch).
//!
//! Use `--dry-run` for a credential-free smoke test (enumerates and prints
//! undecomposed claims, returns before auth resolution and before any LLM or
//! API call). `--provider mock` still requires either EPIGRAPH_TOKEN or a
//! client-credentials pair to pass auth resolution before it can reach the
//! mock LLM provider — it is no longer credential-free on its own now that
//! auth resolution fails fast.

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

/// Treats a set-but-empty string the same as absent. Container/schedule
/// templating can export an env var with an unresolved-to-empty value
/// (`EPIGRAPH_API=""`) rather than leaving it unset; `Option::or` alone does
/// NOT catch that case since `Some("")` is not `None`. This is the hardening
/// for the (unverified) RelativeUrlWithoutBase hypothesis in backlog
/// a422da87: an empty `api_base` turns `format!("{api_base}/api/v1/claims")`
/// into the relative path "/api/v1/claims", which `reqwest` rejects.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

/// API base precedence: `EPIGRAPH_API` (explicit override) first,
/// `EPIGRAPH_API_URL` (the container-standard name epiclaw-host exposes)
/// second, `http://127.0.0.1:8080` otherwise. Takes already-read env values
/// (rather than reading `std::env::var` itself) so it's a pure function —
/// testable without mutating global process env, which races under
/// parallel test execution. Set-but-empty values are treated as absent
/// (see `non_empty`).
fn resolve_api_base(epigraph_api: Option<String>, epigraph_api_url: Option<String>) -> String {
    non_empty(epigraph_api)
        .or_else(|| non_empty(epigraph_api_url))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// `None` unless both service-client credential env values are present AND
/// non-empty. Split out from `mint_service_token` as a pure guard so the
/// "don't even attempt a mint without both creds" behavior is unit-testable
/// without an HTTP mock. Set-but-empty is treated as absent (see
/// `non_empty`) so `EPIGRAPH_SERVICE_CLIENT_ID=""` fails fast via
/// `AuthError::NoCredentials` instead of attempting (and failing) a mint
/// with an empty client_id.
fn resolve_service_credentials(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Option<(String, String)> {
    Some((non_empty(client_id)?, non_empty(client_secret)?))
}

/// OAuth token endpoint precedence: explicit `EPIGRAPH_OAUTH_TOKEN_URL`
/// first (matches the epiclaw-host container.rs convention of constructing
/// it as `{api_url}/oauth/token` and exporting it directly), falling back to
/// `{api_base}/oauth/token` when that specific env var isn't set. Set-but-
/// empty is treated as absent, same as `resolve_api_base`.
fn resolve_token_url(oauth_token_url: Option<String>, api_base: &str) -> String {
    non_empty(oauth_token_url)
        .unwrap_or_else(|| format!("{}/oauth/token", api_base.trim_end_matches('/')))
}

/// The decided authentication strategy for the claims-POST calls: either
/// reuse a caller-supplied token verbatim, or mint a fresh one from
/// service-client credentials. Never a bare empty string — `resolve_auth_plan`
/// only returns this once at least one usable auth path exists.
#[derive(Debug, PartialEq, Eq)]
enum AuthPlan {
    UseToken(String),
    Mint {
        client_id: String,
        client_secret: String,
    },
}

/// Fail-fast reason: neither an explicit token nor a client-credentials pair
/// was available. Surfaced as a hard error instead of silently sending an
/// empty bearer token and 401ing partway through a run (point 3 of the
/// decompose_claims token-mint deliverable, backlog a422da87).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum AuthError {
    #[error(
        "no auth material available: EPIGRAPH_TOKEN is unset/empty and \
         EPIGRAPH_SERVICE_CLIENT_ID/EPIGRAPH_SERVICE_SECRET are not both set; \
         cannot authenticate claims-POST calls"
    )]
    NoCredentials,
}

/// Decide how to authenticate: reuse an already-set non-empty token (point 2
/// of the deliverable — never force a mint over a caller-supplied token),
/// otherwise plan a mint from service-client credentials, otherwise fail
/// fast rather than proceeding with an empty bearer token.
fn resolve_auth_plan(
    env_token: Option<String>,
    credentials: Option<(String, String)>,
) -> Result<AuthPlan, AuthError> {
    if let Some(token) = non_empty(env_token) {
        return Ok(AuthPlan::UseToken(token));
    }
    match credentials {
        Some((client_id, client_secret)) => Ok(AuthPlan::Mint {
            client_id,
            client_secret,
        }),
        None => Err(AuthError::NoCredentials),
    }
}

/// Why a mint attempt failed. Distinguishes "server reachable but rejected
/// us" from "response body wasn't a usable token" so callers (and tests) get
/// a clear signal instead of a panic or a silently-empty string.
#[derive(Debug, thiserror::Error)]
enum MintError {
    #[error("token endpoint request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("token endpoint returned HTTP {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("token endpoint response was not a usable token: {0}")]
    MalformedResponse(String),
}

/// Mint a bearer token from service-client credentials via the OAuth
/// client_credentials flow. Pure aside from the network call: takes the
/// already-resolved endpoint/credentials/client rather than reading env or
/// constructing its own `reqwest::Client`, so it's unit-testable against a
/// mock HTTP server (wiremock) without touching process env.
async fn mint_service_token(
    client_id: &str,
    client_secret: &str,
    token_url: &str,
    http: &reqwest::Client,
) -> Result<String, MintError> {
    let resp = http
        .post(token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "claims:write"),
        ])
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(MintError::HttpStatus(status));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| MintError::MalformedResponse(e.to_string()))?;
    json.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            MintError::MalformedResponse(format!(
                "no string 'access_token' field in response body: {json}"
            ))
        })
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

    let http = reqwest::Client::new();

    // EPIGRAPH_TOKEN if present (non-empty) and used as-is; otherwise mint a
    // fresh bearer token from service-client credentials via client_credentials.
    // If neither is available, fail fast here rather than proceeding with an
    // empty bearer token that would only surface as a 401 once the run reaches
    // the first real (non-empty) batch — see backlog a422da87.
    let auth_plan = resolve_auth_plan(
        std::env::var("EPIGRAPH_TOKEN").ok(),
        resolve_service_credentials(
            std::env::var("EPIGRAPH_SERVICE_CLIENT_ID").ok(),
            std::env::var("EPIGRAPH_SERVICE_SECRET").ok(),
        ),
    )?;
    let token = match auth_plan {
        AuthPlan::UseToken(t) => t,
        AuthPlan::Mint {
            client_id,
            client_secret,
        } => {
            let token_url =
                resolve_token_url(std::env::var("EPIGRAPH_OAUTH_TOKEN_URL").ok(), &api_base);
            mint_service_token(&client_id, &client_secret, &token_url, &http).await?
        }
    };

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
                        let resp = http
                            .post(format!("{api_base}/api/v1/claims"))
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
                            .await?;
                        let v: serde_json::Value = resp.error_for_status()?.json().await?;
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
    use super::{
        mint_service_token, resolve_api_base, resolve_auth_plan, resolve_service_credentials,
        resolve_token_url, AuthError, AuthPlan, MintError,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    // Backlog eccfff31 / a422da87's RelativeUrlWithoutBase hypothesis: a
    // container that exports EPIGRAPH_API="" (set, but empty — e.g. an
    // unresolved template variable) previously survived `.or()` because
    // `Some("")` is not `None`. `format!("{api_base}/api/v1/claims")` then
    // produces the relative path "/api/v1/claims", which `reqwest::Url::parse`
    // rejects as RelativeUrlWithoutBase. UNVERIFIED against the live
    // container (no access from this worktree) — this test hardens the
    // leading hypothesis, it does not confirm it caused the reported bug.
    #[test]
    fn resolve_api_base_treats_set_but_empty_epigraph_api_as_absent() {
        assert_eq!(
            resolve_api_base(
                Some(String::new()),
                Some("http://container.example".to_string())
            ),
            "http://container.example"
        );
    }

    #[test]
    fn resolve_api_base_treats_set_but_empty_epigraph_api_url_as_absent_too() {
        assert_eq!(
            resolve_api_base(Some(String::new()), Some(String::new())),
            "http://127.0.0.1:8080"
        );
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

    #[test]
    fn resolve_service_credentials_none_when_client_id_set_but_empty() {
        // Consistency with resolve_api_base/resolve_token_url's set-but-empty
        // handling: an empty EPIGRAPH_SERVICE_CLIENT_ID should fail fast via
        // AuthError::NoCredentials, not attempt a doomed mint with "".
        assert_eq!(
            resolve_service_credentials(Some(String::new()), Some("secret".to_string())),
            None
        );
    }

    #[test]
    fn resolve_service_credentials_none_when_client_secret_set_but_empty() {
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), Some(String::new())),
            None
        );
    }

    // --- resolve_token_url: EPIGRAPH_OAUTH_TOKEN_URL precedence ---

    #[test]
    fn resolve_token_url_prefers_explicit_oauth_token_url_when_set() {
        assert_eq!(
            resolve_token_url(
                Some("https://auth.example/oauth/token".to_string()),
                "https://api.example",
            ),
            "https://auth.example/oauth/token"
        );
    }

    #[test]
    fn resolve_token_url_falls_back_to_api_base_oauth_token() {
        assert_eq!(
            resolve_token_url(None, "https://api.example"),
            "https://api.example/oauth/token"
        );
    }

    #[test]
    fn resolve_token_url_falls_back_when_explicit_is_set_but_empty() {
        assert_eq!(
            resolve_token_url(Some(String::new()), "https://api.example/"),
            "https://api.example/oauth/token"
        );
    }

    // --- resolve_auth_plan: fail-fast decision (point 3 of the deliverable) ---

    #[test]
    fn resolve_auth_plan_uses_existing_token_when_present_even_if_creds_also_present() {
        // Point 2: don't force a mint when a caller already supplies a token.
        let plan = resolve_auth_plan(
            Some("caller-supplied-token".to_string()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("existing token is a valid plan");
        assert_eq!(
            plan,
            AuthPlan::UseToken("caller-supplied-token".to_string())
        );
    }

    #[test]
    fn resolve_auth_plan_mints_when_no_token_but_creds_present() {
        let plan = resolve_auth_plan(None, Some(("id".to_string(), "secret".to_string())))
            .expect("creds without token should plan a mint");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    #[test]
    fn resolve_auth_plan_treats_set_but_empty_token_as_absent() {
        let plan = resolve_auth_plan(
            Some(String::new()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("empty token should not short-circuit the mint plan");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    #[test]
    fn resolve_auth_plan_fails_fast_when_neither_token_nor_creds_available() {
        let err =
            resolve_auth_plan(None, None).expect_err("no auth material at all must fail fast");
        assert_eq!(err, AuthError::NoCredentials);
    }

    // --- mint_service_token: HTTP mock coverage (TDD-mandated) ---

    #[tokio::test]
    async fn mint_service_token_returns_parsed_token_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "minted-jwt-value"})),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let token = mint_service_token("client-id", "client-secret", &token_url, &http)
            .await
            .expect("mock server returns a valid token");
        assert_eq!(token, "minted-jwt-value");
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_on_non_200_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client"
            })))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token("client-id", "wrong-secret", &token_url, &http)
            .await
            .expect_err("401 must surface as an Err, not panic or silently empty-string");
        assert!(matches!(err, MintError::HttpStatus(status) if status == 401));
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_on_malformed_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token("client-id", "client-secret", &token_url, &http)
            .await
            .expect_err("malformed JSON body must surface as an Err, not panic");
        assert!(matches!(err, MintError::MalformedResponse(_)));
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_when_access_token_field_missing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token_type": "bearer"})),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token("client-id", "client-secret", &token_url, &http)
            .await
            .expect_err("response with no access_token field must be a clear error");
        assert!(matches!(err, MintError::MalformedResponse(_)));
    }
}
