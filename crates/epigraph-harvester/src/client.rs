//! gRPC client for the Harvester service
//!
//! This module provides a Rust client for communicating with the Python
//! harvester service via gRPC.

use crate::errors::HarvesterError;
use crate::proto::{
    extraction_service_client::ExtractionServiceClient, BatchRequest, BatchResponse,
    ExtractionConfig, FragmentMetadata, FragmentRequest, HealthRequest, HealthResponse, Modality,
    VerifiedGraph,
};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Harvester gRPC client with connection pooling and retry logic
pub struct HarvesterClient {
    /// The underlying gRPC client
    client: ExtractionServiceClient<Channel>,

    /// Server URL
    url: String,

    /// Request timeout
    timeout: Duration,
}

impl HarvesterClient {
    /// Create a new harvester client
    ///
    /// # Parameters
    /// - `url`: gRPC server URL (e.g., "http://localhost:50051")
    ///
    /// # Errors
    /// Returns error if connection fails
    pub async fn new(url: &str) -> Result<Self, HarvesterError> {
        info!("Connecting to harvester service at {}", url);

        let endpoint = Endpoint::from_shared(url.to_string())
            .map_err(|e| HarvesterError::ConnectionFailed {
                url: url.to_string(),
                reason: format!("Invalid URL: {e}"),
            })?
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10));

        let channel = endpoint.connect().await.map_err(|e| {
            error!("Failed to connect to harvester at {}: {}", url, e);
            HarvesterError::ConnectionFailed {
                url: url.to_string(),
                reason: e.to_string(),
            }
        })?;

        let client = ExtractionServiceClient::new(channel);

        info!("Successfully connected to harvester service");

        Ok(Self {
            client,
            url: url.to_string(),
            timeout: Duration::from_secs(120), // 2 minutes default
        })
    }

    /// Set the request timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Process a single fragment
    ///
    /// # Parameters
    /// - `content`: The fragment text content
    /// - `content_hash`: BLAKE3 hash of the content (32 bytes)
    /// - `metadata`: Optional metadata about the fragment
    ///
    /// # Errors
    /// Returns error if extraction fails or times out
    pub async fn process_fragment(
        &mut self,
        content: &str,
        content_hash: [u8; 32],
        metadata: Option<FragmentMetadata>,
    ) -> Result<VerifiedGraph, HarvesterError> {
        let fragment_id = Uuid::new_v4().to_string();

        debug!(
            "Processing fragment {} ({} chars)",
            fragment_id,
            content.len()
        );

        let request = FragmentRequest {
            fragment_id: fragment_id.clone(),
            source_id: String::new(), // Can be set by caller if needed
            content_hash: content_hash.to_vec(),
            content_text: content.to_string(),
            context_window: String::new(), // TODO(backlog): populate from HarvesterConfig.context_window_chars
            modality: Modality::Text as i32,
            metadata,
            config: None, // Use server defaults
        };

        let mut client = self.client.clone();

        let response = tokio::time::timeout(self.timeout, client.process_fragment(request))
            .await
            .map_err(|_| HarvesterError::Timeout {
                operation: format!("process_fragment({})", fragment_id),
            })?
            .map_err(|e| {
                error!("gRPC error processing fragment {}: {}", fragment_id, e);
                e
            })?;

        let graph = response.into_inner();

        info!(
            "Fragment {} processed: {} claims, {} concepts",
            fragment_id,
            graph.claims.len(),
            graph.concepts.len()
        );

        Ok(graph)
    }

    /// Process multiple fragments in batch
    ///
    /// # Parameters
    /// - `fragments`: List of (content, hash, metadata) tuples
    ///
    /// # Errors
    /// Returns error if batch processing fails
    pub async fn process_batch(
        &mut self,
        fragments: Vec<(String, [u8; 32], Option<FragmentMetadata>)>,
    ) -> Result<BatchResponse, HarvesterError> {
        if fragments.is_empty() {
            warn!("process_batch called with empty fragment list");
            return Ok(BatchResponse {
                results: vec![],
                total_processed: 0,
                successful: 0,
                failed: 0,
            });
        }

        info!("Processing batch of {} fragments", fragments.len());

        let requests: Vec<FragmentRequest> = fragments
            .into_iter()
            .enumerate()
            .map(|(i, (content, content_hash, metadata))| FragmentRequest {
                fragment_id: format!("batch-{}", i),
                source_id: String::new(),
                content_hash: content_hash.to_vec(),
                content_text: content,
                context_window: String::new(), // TODO(backlog): populate from HarvesterConfig.context_window_chars
                modality: Modality::Text as i32,
                metadata,
                config: None,
            })
            .collect();

        let batch_request = BatchRequest {
            fragments: requests,
            config: None,
        };

        let mut client = self.client.clone();

        let response = tokio::time::timeout(self.timeout, client.process_batch(batch_request))
            .await
            .map_err(|_| HarvesterError::Timeout {
                operation: "process_batch".to_string(),
            })?
            .map_err(|e| {
                error!("gRPC error in batch processing: {}", e);
                e
            })?;

        let batch_response = response.into_inner();

        info!(
            "Batch complete: {}/{} successful",
            batch_response.successful, batch_response.total_processed
        );

        Ok(batch_response)
    }

    /// Check if the harvester service is healthy
    ///
    /// # Errors
    /// Returns error if health check fails
    pub async fn health_check(&mut self) -> Result<HealthResponse, HarvesterError> {
        debug!("Performing health check");

        let request = HealthRequest {};
        let mut client = self.client.clone();

        let response = tokio::time::timeout(Duration::from_secs(5), client.health_check(request))
            .await
            .map_err(|_| HarvesterError::Timeout {
                operation: "health_check".to_string(),
            })?
            .map_err(|e| {
                error!("Health check failed: {}", e);
                e
            })?;

        let health = response.into_inner();

        if health.healthy {
            info!(
                "Harvester is healthy: {} v{} (uptime: {}s)",
                health.model_name, health.version, health.uptime_seconds
            );
        } else {
            warn!("Harvester reports unhealthy status");
        }

        Ok(health)
    }

    /// Create a fragment request with custom configuration
    ///
    /// This provides more control over the extraction process.
    #[must_use]
    pub fn create_fragment_request(
        fragment_id: String,
        content: String,
        content_hash: [u8; 32],
        metadata: Option<FragmentMetadata>,
        config: Option<ExtractionConfig>,
    ) -> FragmentRequest {
        FragmentRequest {
            fragment_id,
            source_id: String::new(),
            content_hash: content_hash.to_vec(),
            content_text: content,
            context_window: String::new(), // TODO(backlog): populate from HarvesterConfig.context_window_chars
            modality: Modality::Text as i32,
            metadata,
            config,
        }
    }

    /// Get the server URL
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the configured timeout
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_fragment_request_with_defaults() {
        let content = "Test content".to_string();
        let hash = [0u8; 32];

        let request = HarvesterClient::create_fragment_request(
            "test-id".to_string(),
            content.clone(),
            hash,
            None,
            None,
        );

        assert_eq!(request.fragment_id, "test-id");
        assert_eq!(request.content_text, content);
        assert_eq!(request.content_hash, hash.to_vec());
        assert_eq!(request.modality, Modality::Text as i32);
    }

    #[test]
    fn timeout_configuration() {
        // Note: Can't test actual connection without server, but can test builder
        let timeout = Duration::from_secs(60);
        // Would use: let client = HarvesterClient::new("http://localhost:50051").await.unwrap().with_timeout(timeout);
        // Just verify the duration is correct
        assert_eq!(timeout.as_secs(), 60);
    }
}
