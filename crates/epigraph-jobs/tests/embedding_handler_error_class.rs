//! `ConfigurableEmbeddingHandler` classifies its errors for the runners' retry
//! decision (`JobError::should_retry`): an error a later run will hit again is
//! PERMANENT, so the job is failed on its first occurrence instead of spending
//! its whole retry budget, one drain run (and one exit 1) per attempt; a
//! provider or database error stays TRANSIENT, so the budget the unseal's
//! `embedding_generation` jobs carry still absorbs a 429 or a 503.
//!
//! Before this classification every service error became
//! `JobError::ProcessingFailed`, which `should_retry` treats as transient.

use epigraph_jobs::{
    async_trait, ConfigurableEmbeddingHandler, EmbeddingJobError, EmbeddingJobService,
    EmbeddingTokenUsage, EpiGraphJob, Job, JobHandler,
};
use std::sync::Arc;
use uuid::Uuid;

/// A service that has text for every claim (unless `text` is `None`), whose
/// `already_embedded` pre-check fails with `check` (or answers `false` when it
/// is `None`), and whose store fails with `error` (or succeeds when it is
/// `None`).
struct Service {
    text: Option<String>,
    check: Option<EmbeddingJobError>,
    error: Option<EmbeddingJobError>,
}

#[async_trait]
impl EmbeddingJobService for Service {
    async fn get_claim_text(&self, _claim_id: Uuid) -> Option<String> {
        self.text.clone()
    }

    async fn already_embedded(&self, _claim_id: Uuid) -> Result<bool, EmbeddingJobError> {
        match &self.check {
            Some(e) => Err(e.clone()),
            None => Ok(false),
        }
    }

    async fn generate_and_store(
        &self,
        _claim_id: Uuid,
        _text: &str,
    ) -> Result<Vec<f32>, EmbeddingJobError> {
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(vec![0.0; 4]),
        }
    }

    fn dimension(&self) -> usize {
        4
    }

    fn token_usage(&self) -> EmbeddingTokenUsage {
        EmbeddingTokenUsage::default()
    }
}

fn embedding_job(claim_id: Uuid) -> Job {
    Job::new(
        "embedding_generation",
        serde_json::to_value(EpiGraphJob::EmbeddingGeneration { claim_id }).unwrap(),
    )
}

/// Whether the handler's error for this service is retryable.
async fn retryable(text: Option<&str>, error: Option<EmbeddingJobError>) -> bool {
    let handler = ConfigurableEmbeddingHandler::new(Arc::new(Service {
        text: text.map(str::to_string),
        check: None,
        error,
    }));
    handler
        .handle(&embedding_job(Uuid::new_v4()))
        .await
        .expect_err("the handler was expected to fail")
        .should_retry()
}

#[tokio::test]
async fn an_error_a_later_run_would_hit_again_is_permanent() {
    let claim_id = Uuid::new_v4();
    for (name, error) in [
        // `store_embedding_if_unsealed` wrote no row: the claim is sealed,
        // retired or gone, and a re-run reads the same row.
        ("NotFound", EmbeddingJobError::NotFound { claim_id }),
        (
            "ClaimNotFound",
            EmbeddingJobError::ClaimNotFound { claim_id },
        ),
        ("EmptyText", EmbeddingJobError::EmptyText),
        (
            "DimensionMismatch",
            EmbeddingJobError::DimensionMismatch {
                expected: 1536,
                actual: 4,
            },
        ),
    ] {
        assert!(
            !retryable(Some("text"), Some(error)).await,
            "{name} was retryable: the job spends its whole budget on an error that recurs"
        );
    }
}

#[tokio::test]
async fn a_provider_or_database_error_stays_transient() {
    for (name, error) in [
        (
            "ApiError",
            EmbeddingJobError::ApiError {
                message: "503".to_string(),
            },
        ),
        (
            "RateLimitExceeded",
            EmbeddingJobError::RateLimitExceeded {
                retry_after_secs: 30,
            },
        ),
    ] {
        assert!(
            retryable(Some("text"), Some(error)).await,
            "{name} was permanent: one transient provider error fails the restore for good"
        );
    }
    // `get_claim_text` answers `None` for a missing connection or a failed
    // read as well as for a missing claim, so it is not proof of permanence.
    assert!(
        retryable(None, None).await,
        "no claim text was permanent, but it also means a failed read"
    );
}

#[tokio::test]
async fn a_payload_of_another_job_variant_is_permanent() {
    let handler = ConfigurableEmbeddingHandler::new(Arc::new(Service {
        text: Some("text".to_string()),
        check: None,
        error: None,
    }));
    let job = Job::new(
        "embedding_generation",
        serde_json::to_value(EpiGraphJob::TruthPropagation {
            source_claim_id: Uuid::new_v4(),
        })
        .unwrap(),
    );
    let err = handler.handle(&job).await.expect_err("wrong variant");
    assert!(
        !err.should_retry(),
        "a payload that will never be an embedding job was retryable: {err}"
    );
}

/// `AlreadyEmbedded` from the store means a vector landed during the provider
/// call: the job has what it was for, so it completes as a skip.
#[tokio::test]
async fn a_store_that_finds_a_vector_completes_as_a_skip() {
    let claim_id = Uuid::new_v4();
    let handler = ConfigurableEmbeddingHandler::new(Arc::new(Service {
        text: Some("text".to_string()),
        check: None,
        error: Some(EmbeddingJobError::AlreadyEmbedded { claim_id }),
    }));
    let result = handler
        .handle(&embedding_job(claim_id))
        .await
        .expect("a vector that landed during the provider call fails the job");
    assert_eq!(result.output["skipped"], "already_embedded");
    assert_eq!(result.output["claim_id"], claim_id.to_string());
}

/// `AlreadyEmbedded` from anywhere but the store (here the pre-check) is not
/// turned into a skip; it reaches the classifier, and a re-run would find the
/// same vector, so it is PERMANENT rather than spending the retry budget.
#[tokio::test]
async fn already_embedded_outside_the_store_is_permanent() {
    let claim_id = Uuid::new_v4();
    let handler = ConfigurableEmbeddingHandler::new(Arc::new(Service {
        text: Some("text".to_string()),
        check: Some(EmbeddingJobError::AlreadyEmbedded { claim_id }),
        error: None,
    }));
    let err = handler
        .handle(&embedding_job(claim_id))
        .await
        .expect_err("the pre-check failed, so the job must fail");
    assert!(
        !err.should_retry(),
        "AlreadyEmbedded was retryable: the job spends its whole budget on a vector that stays"
    );
}
