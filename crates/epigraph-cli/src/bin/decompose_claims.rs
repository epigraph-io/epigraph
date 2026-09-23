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
//! EPIGRAPH_SERVICE_SECRET against EPIGRAPH_OAUTH_TOKEN_URL (default
//! `{api_base}/oauth/token`). If NEITHER is available the run aborts before
//! the first write — it does NOT proceed with an empty bearer token.
//! Use `--provider mock` for a dry compile/smoke without credentials (it
//! returns an empty batch, so nothing is written, and auth is therefore not
//! resolved at all). Use `--provider fixture`
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

/// Treat a set-but-empty env var as absent.
///
/// Shell templating can export an env var with an unresolved-to-empty value
/// (`EPIGRAPH_API=""`) rather than leaving it unset; `Option::or` alone does
/// NOT catch that case since `Some("")` is not `None`. An empty `api_base`
/// turns `format!("{api_base}/api/v1/claims")` into the relative path
/// "/api/v1/claims", which `reqwest` rejects with `RelativeUrlWithoutBase` —
/// the hardening for that hypothesis in backlog a422da87.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

/// API base precedence: `EPIGRAPH_API` (explicit override) first,
/// `EPIGRAPH_API_URL` (the container-standard name epiclaw-host exposes)
/// second, `http://127.0.0.1:8080` otherwise. Takes already-read env values
/// (rather than reading `std::env::var` itself) so it's a pure function —
/// testable without mutating global process env, which races under
/// parallel test execution. Set-but-empty values are treated as absent
/// (see [`non_empty`]).
fn resolve_api_base(epigraph_api: Option<String>, epigraph_api_url: Option<String>) -> String {
    non_empty(epigraph_api)
        .or_else(|| non_empty(epigraph_api_url))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// OAuth token endpoint precedence: explicit `EPIGRAPH_OAUTH_TOKEN_URL`
/// first (matches the epiclaw-host `container.rs` convention of constructing
/// it as `{api_url}/oauth/token` and exporting it directly), falling back to
/// `{api_base}/oauth/token` when that specific env var isn't set. Set-but-
/// empty is treated as absent, same as [`resolve_api_base`].
fn resolve_token_url(oauth_token_url: Option<String>, api_base: &str) -> String {
    non_empty(oauth_token_url)
        .unwrap_or_else(|| format!("{}/oauth/token", api_base.trim_end_matches('/')))
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

/// `None` unless both service-client credential env values are present AND
/// non-empty. Split out from `mint_service_token` as a pure guard so the
/// "don't even attempt a mint without both creds" behavior is unit-testable
/// without an HTTP mock. Set-but-empty is treated as absent (see
/// [`non_empty`]) so `EPIGRAPH_SERVICE_CLIENT_ID=""` fails fast via
/// [`AuthError::NoCredentials`] instead of attempting (and failing) a mint
/// with an empty client_id.
fn resolve_service_credentials(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Option<(String, String)> {
    Some((non_empty(client_id)?, non_empty(client_secret)?))
}

/// The decided authentication strategy for the claims-POST calls: either
/// reuse a caller-supplied token verbatim, or mint a fresh one from
/// service-client credentials. Never a bare empty string —
/// [`resolve_auth_plan`] only returns this once at least one usable auth
/// path exists.
#[derive(Debug, PartialEq, Eq)]
enum AuthPlan {
    UseToken(String),
    Mint {
        client_id: String,
        client_secret: String,
    },
}

/// Fail-fast reason: neither an explicit token nor a client-credentials pair
/// was available.
///
/// This binary previously chose the opposite: it logged "proceeding with an
/// EMPTY bearer token, every API write below will 401" and ran anyway. That
/// fail-open is what gh-375 tracks — the LLM calls (which cost money and
/// time) all completed and only then did every write 401, so a whole
/// scheduled run was burned to produce nothing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum AuthError {
    #[error(
        "no auth material available: EPIGRAPH_TOKEN is unset/empty and \
         EPIGRAPH_SERVICE_CLIENT_ID/EPIGRAPH_SERVICE_SECRET are not both set; \
         cannot authenticate claims-POST calls"
    )]
    NoCredentials,
}

/// Decide how to authenticate: reuse an already-set non-empty token (never
/// force a mint over a caller-supplied token), otherwise plan a mint from
/// service-client credentials, otherwise fail fast rather than proceeding
/// with an empty bearer token.
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
/// a clear signal instead of a silently-empty string.
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

/// Whether a run under `provider` can reach the claims-POST path at all.
///
/// `mock` resolves to [`epigraph_cli::enrichment::llm_client::MockLlmClient`]
/// built with NO pre-configured responses, which returns an empty JSON array
/// for every `complete_json` call; `parse_batch_response` then yields zero
/// decompositions and the submit closure is never invoked. So a `--provider
/// mock` run provably performs no authenticated request, and the module doc
/// promises exactly that ("a dry compile/smoke without credentials").
/// Requiring auth for it would break that documented smoke path.
///
/// `fixture` is deliberately NOT exempt: its whole purpose is to exercise
/// the atom/edge WRITE path deterministically, so it does POST and does need
/// a token.
fn provider_writes_to_api(provider: &str) -> bool {
    provider != "mock"
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
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::TenancyBackfill)
        .await?;
    let viewer = session.viewer();
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

    let http = reqwest::Client::new();

    // EPIGRAPH_TOKEN if present (non-empty) and used as-is; otherwise mint a
    // fresh bearer token from service-client credentials via
    // client_credentials, so container deployments work without a token-mint
    // preamble in the schedule. If NEITHER is available, fail fast HERE —
    // before the LLM batches run — rather than proceeding with an empty
    // bearer token that only surfaces as a 401 after every batch has already
    // been paid for (gh-375).
    //
    // Skipped entirely for a provider that cannot reach the write path; see
    // `provider_writes_to_api`.
    //
    // Diagnostic-only logging: never the token value itself, only its
    // provenance and length (distinguishes "empty" from "present but wrong"
    // without leaking the credential — backlog a422da87's reported
    // non-determinism needs exactly this to disambiguate an auth failure from
    // a URL-builder failure across repeated scheduled runs).
    let token = if provider_writes_to_api(&cli.provider) {
        let plan = resolve_auth_plan(
            std::env::var("EPIGRAPH_TOKEN").ok(),
            resolve_service_credentials(
                std::env::var("EPIGRAPH_SERVICE_CLIENT_ID").ok(),
                std::env::var("EPIGRAPH_SERVICE_SECRET").ok(),
            ),
        )?;
        match plan {
            AuthPlan::UseToken(t) => {
                eprintln!("token: using EPIGRAPH_TOKEN from env (len={})", t.len());
                t
            }
            AuthPlan::Mint {
                client_id,
                client_secret,
            } => {
                let token_url =
                    resolve_token_url(std::env::var("EPIGRAPH_OAUTH_TOKEN_URL").ok(), &api_base);
                eprintln!("token: minting via client_credentials at {token_url}");
                let minted =
                    mint_service_token(&client_id, &client_secret, &token_url, &http).await?;
                eprintln!(
                    "token: minted via client_credentials (len={})",
                    minted.len()
                );
                minted
            }
        }
    } else {
        eprintln!(
            "token: not resolved — --provider {} performs no API write",
            cli.provider
        );
        String::new()
    };

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
    use super::{
        mint_service_token, provider_writes_to_api, resolve_api_base, resolve_auth_plan,
        resolve_llm_client, resolve_service_credentials, resolve_token_url, AuthError, AuthPlan,
        MintError,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // --- fail-fast auth resolution (gh-375) ---
    //
    // Re-landed from PR #337, which was merged and reverted 12 minutes later
    // by PR #341 with a body of exactly "Reverts epigraph-io/epigraph#337"
    // and no comments. The revert was a process correction, not a functional
    // one: CI was green on the merge commit 284a20f9 ("test success",
    // "Security audit (advisory) success"), no commit landed between the
    // merge and the revert, the same account merged and reverted, and #337's
    // own body ends "DO NOT MERGE — flagging for manual review".

    /// A caller-supplied `EPIGRAPH_TOKEN` is used verbatim and is never
    /// overridden by a mint, even when service-client credentials are also
    /// present. An operator who exports a specific token means that token.
    #[test]
    fn resolve_auth_plan_prefers_an_explicit_token_over_available_credentials() {
        let plan = resolve_auth_plan(
            Some("caller-supplied-token".to_string()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("an explicit token is sufficient auth material");
        assert_eq!(
            plan,
            AuthPlan::UseToken("caller-supplied-token".to_string())
        );
    }

    /// No token but a complete credential pair ⇒ plan a mint.
    #[test]
    fn resolve_auth_plan_mints_when_no_token_but_credentials_present() {
        let plan = resolve_auth_plan(None, Some(("id".to_string(), "secret".to_string())))
            .expect("credentials alone are sufficient auth material");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    /// `EPIGRAPH_TOKEN=""` (shell templating that resolved to empty rather
    /// than leaving the var unset) must be treated as absent, not as a
    /// zero-length bearer token.
    #[test]
    fn resolve_auth_plan_treats_a_set_but_empty_token_as_absent() {
        let plan = resolve_auth_plan(
            Some(String::new()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("an empty token must fall through to the credential path");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    /// THE gh-375 REGRESSION GUARD. With neither a token nor credentials the
    /// binary must refuse to start. The reverted behaviour was to log
    /// "proceeding with an EMPTY bearer token, every API write below will
    /// 401" and continue — burning a full LLM batch run before failing.
    #[test]
    fn resolve_auth_plan_fails_fast_when_no_auth_material_is_available() {
        let err = resolve_auth_plan(None, None)
            .expect_err("no auth material at all must fail fast, not yield an empty token");
        assert_eq!(err, AuthError::NoCredentials);
    }

    /// A set-but-empty credential must not trigger a doomed mint attempt;
    /// it fails fast the same way a missing one does.
    #[test]
    fn resolve_service_credentials_treats_set_but_empty_as_absent() {
        assert_eq!(
            resolve_service_credentials(Some(String::new()), Some("secret".to_string())),
            None
        );
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), Some(String::new())),
            None
        );
    }

    /// `EPIGRAPH_API=""` must not win over a usable `EPIGRAPH_API_URL`:
    /// an empty base makes `format!("{api_base}/api/v1/claims")` a relative
    /// path, which reqwest rejects with `RelativeUrlWithoutBase`.
    #[test]
    fn resolve_api_base_skips_a_set_but_empty_override() {
        assert_eq!(
            resolve_api_base(Some(String::new()), Some("https://api.example".to_string())),
            "https://api.example"
        );
        assert_eq!(
            resolve_api_base(Some(String::new()), Some(String::new())),
            "http://127.0.0.1:8080"
        );
    }

    // --- resolve_token_url: EPIGRAPH_OAUTH_TOKEN_URL precedence ---

    /// epiclaw-host's `container.rs` documents `EPIGRAPH_OAUTH_TOKEN_URL` as
    /// the manual-flow env var; the shipped mint never read it and always
    /// hardcoded `{api_base}/oauth/token`.
    #[test]
    fn resolve_token_url_prefers_an_explicit_oauth_token_url() {
        assert_eq!(
            resolve_token_url(
                Some("https://auth.example/token".to_string()),
                "https://api.example"
            ),
            "https://auth.example/token"
        );
    }

    #[test]
    fn resolve_token_url_falls_back_to_api_base_and_strips_a_trailing_slash() {
        assert_eq!(
            resolve_token_url(None, "https://api.example/"),
            "https://api.example/oauth/token"
        );
        assert_eq!(
            resolve_token_url(Some(String::new()), "https://api.example"),
            "https://api.example/oauth/token"
        );
    }

    /// `--provider mock` must stay usable with zero credentials: the module
    /// doc promises "a dry compile/smoke without credentials", and a mock
    /// run provably issues no authenticated request. `fixture` DOES write,
    /// so it is not exempt.
    #[test]
    fn only_the_mock_provider_is_exempt_from_auth_resolution() {
        assert!(!provider_writes_to_api("mock"));
        assert!(provider_writes_to_api("epigraph"));
        assert!(provider_writes_to_api("fixture"));
    }

    // --- mint_service_token: HTTP mock coverage ---

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
            .expect_err("401 must surface as an Err, not a silently empty string");
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
            .expect_err("a malformed JSON body must surface as an Err");
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
            .expect_err("a response with no access_token field must be a clear error");
        assert!(matches!(err, MintError::MalformedResponse(_)));
    }

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
