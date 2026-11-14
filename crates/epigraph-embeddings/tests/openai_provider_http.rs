//! `OpenAiProvider` against a local HTTP fixture: truncation and bounded retry.
//!
//! The MCP server and the HTTP API used to embed through two different OpenAI
//! clients. MCP clipped an over-limit input and embedded it; the API's provider
//! refused it with `TextTooLong`, so the same long claim got a vector on one
//! surface and NULL on the other. Neither retried, and the API mapped every 429
//! to a hard-coded `retry_after_secs: 60` (backlog ef32cdeb). The MCP embedder now
//! delegates to this provider, so these tests pin the behaviour both surfaces get.
//!
//! No network: every request goes to a `wiremock` server through
//! `ProviderConfig::OpenAi::api_base_url`.
#![cfg(feature = "openai")]

use std::time::{Duration, Instant};

use epigraph_embeddings::config::ProviderConfig;
use epigraph_embeddings::{
    EmbeddingConfig, EmbeddingError, EmbeddingService, OpenAiProvider, RetryPolicy, Tokenizer,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DIM: usize = 4;

/// A config aimed at `server`, with the cache off so every call reaches it.
fn config_for(server: &MockServer, max_tokens: usize) -> EmbeddingConfig {
    let mut config = EmbeddingConfig::openai(DIM)
        .with_cache(false)
        .with_max_tokens(max_tokens);
    config.provider = ProviderConfig::OpenAi {
        model: "text-embedding-3-small".to_string(),
        api_base_url: Some(server.uri()),
    };
    config
}

/// Millisecond waits, so a retry test costs nothing.
const FAST: RetryPolicy = RetryPolicy {
    max_attempts: 3,
    base_delay: Duration::from_millis(1),
    max_delay: Duration::from_millis(20),
};

fn provider(server: &MockServer, max_tokens: usize) -> OpenAiProvider {
    OpenAiProvider::new(config_for(server, max_tokens), "test-key".to_string())
        .expect("provider")
        .with_retry_policy(FAST)
}

/// An OpenAI-shaped success body with one vector per input.
fn ok_body(n: usize) -> serde_json::Value {
    let data: Vec<serde_json::Value> = (0..n)
        .map(|i| serde_json::json!({"embedding": [1.0, 0.0, 0.0, 0.0], "index": i}))
        .collect();
    serde_json::json!({"data": data, "usage": {"total_tokens": 7}})
}

/// The `input` field of every request the server received, flattened.
async fn received_inputs(server: &MockServer) -> Vec<String> {
    let mut out = Vec::new();
    for req in server.received_requests().await.expect("recording is on") {
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        match &body["input"] {
            serde_json::Value::Array(items) => out.extend(
                items
                    .iter()
                    .map(|v| v.as_str().expect("string input").to_string()),
            ),
            serde_json::Value::String(s) => out.push(s.clone()),
            other => panic!("unexpected input shape: {other}"),
        }
    }
    out
}

/// Dense text: CJK characters cost more than one token each, so a cut made by
/// "about 4 characters per token" lands far over the token limit.
fn dense_text() -> String {
    "漢字のテストは密度が高い".repeat(120)
}

/// An over-limit input is clipped to the model's limit and embedded, instead of
/// failing with `TextTooLong` before any request is made.
#[tokio::test]
async fn an_over_limit_input_is_truncated_to_the_token_limit_and_embedded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    let max_tokens = 50;
    let text = dense_text();
    let tokenizer = Tokenizer::new(max_tokens);
    assert!(
        tokenizer.count_tokens(&text) > max_tokens * 4,
        "CALIBRATION: the input must be far over the limit for this test to mean anything"
    );

    let embedding = provider(&server, max_tokens)
        .generate(&text)
        .await
        .expect("an over-limit input must be truncated and embedded, not refused");
    assert_eq!(embedding.len(), DIM);

    let inputs = received_inputs(&server).await;
    assert_eq!(inputs.len(), 1);
    let sent = &inputs[0];
    assert!(!sent.is_empty(), "the truncated input must not be empty");
    assert!(
        text.starts_with(sent.as_str()),
        "truncation must send a prefix of the caller's text"
    );
    let sent_tokens = tokenizer.count_tokens(sent);
    assert!(
        sent_tokens <= max_tokens,
        "the provider sent {sent_tokens} tokens against a limit of {max_tokens}; the API would \
         answer 400"
    );
}

/// A batch truncates per text and keeps short texts byte-for-byte.
#[tokio::test]
async fn a_batch_truncates_only_its_over_limit_members() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(2)))
        .expect(1)
        .mount(&server)
        .await;

    let max_tokens = 50;
    let long = dense_text();
    let short = "The Earth orbits the Sun.";
    let vectors = provider(&server, max_tokens)
        .batch_generate(&[short, long.as_str()])
        .await
        .expect("a batch with one over-limit member must still embed");
    assert_eq!(vectors.len(), 2);

    let inputs = received_inputs(&server).await;
    assert_eq!(inputs.len(), 2);
    assert_eq!(
        inputs[0], short,
        "a text within the limit is sent unchanged"
    );
    assert!(long.starts_with(inputs[1].as_str()) && !inputs[1].is_empty());
    assert!(Tokenizer::new(max_tokens).count_tokens(&inputs[1]) <= max_tokens);
}

/// A 429 followed by a success succeeds, in exactly two requests.
#[tokio::test]
async fn a_rate_limited_request_is_retried_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    provider(&server, 8191)
        .generate("retry me")
        .await
        .expect("one 429 must be retried, not returned");
    server.verify().await;
}

/// A 5xx is transient too.
#[tokio::test]
async fn a_server_error_is_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    provider(&server, 8191)
        .generate("retry me")
        .await
        .expect("a 503 must be retried");
    server.verify().await;
}

/// The retry is BOUNDED: a provider that always answers 429 sees exactly
/// `max_attempts` requests, and the error carries the server's `Retry-After`
/// rather than an invented 60 s.
#[tokio::test]
async fn a_persistent_rate_limit_stops_after_max_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .expect(u64::from(FAST.max_attempts))
        .mount(&server)
        .await;

    let err = provider(&server, 8191)
        .generate("never succeeds")
        .await
        .expect_err("a provider that only answers 429 must fail");
    assert!(
        matches!(
            err,
            EmbeddingError::RateLimitExceeded {
                retry_after_secs: 7
            }
        ),
        "expected the server's Retry-After (7 s) in the error, got {err:?}"
    );
    server.verify().await;
}

/// A server-requested wait is capped at `max_delay`: a `Retry-After: 120` must
/// not hold the caller for two minutes.
#[tokio::test]
async fn a_long_retry_after_is_capped() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "120"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1)))
        .mount(&server)
        .await;

    let started = Instant::now();
    provider(&server, 8191)
        .generate("capped wait")
        .await
        .expect("succeeds on the retry");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the 120 s Retry-After was not capped: waited {:?}",
        started.elapsed()
    );
}

/// A client error is final: a 400 is sent once and returned with its status.
#[tokio::test]
async fn a_client_error_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .expect(1)
        .mount(&server)
        .await;

    let err = provider(&server, 8191)
        .generate("malformed")
        .await
        .expect_err("a 400 must fail");
    assert!(
        matches!(
            err,
            EmbeddingError::ApiError {
                status_code: Some(400),
                ..
            }
        ),
        "got {err:?}"
    );
    server.verify().await;
}
