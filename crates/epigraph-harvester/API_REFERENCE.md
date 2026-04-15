# epigraph-harvester API Reference

## Quick Start

```rust
use epigraph_harvester::{HarvesterClient, TextFragmenter, Fragmenter};

// Connect to service
let mut client = HarvesterClient::new("http://localhost:50051").await?;

// Fragment text
let fragmenter = TextFragmenter::default();
let fragments = fragmenter.fragment(text).await?;

// Process
let graph = client.process_fragment(&fragments[0].content,
                                    fragments[0].content_hash,
                                    None).await?;
```

---

## HarvesterClient

### Constructor

```rust
pub async fn new(url: &str) -> Result<Self, HarvesterError>
```

Connect to harvester gRPC service.

**Parameters:**
- `url`: Server URL (e.g., `"http://localhost:50051"`)

**Returns:** Connected client or connection error

**Example:**
```rust
let client = HarvesterClient::new("http://localhost:50051").await?;
```

---

### with_timeout

```rust
pub fn with_timeout(self, timeout: Duration) -> Self
```

Configure request timeout (default: 120 seconds).

**Example:**
```rust
let client = HarvesterClient::new(url)
    .await?
    .with_timeout(Duration::from_secs(60));
```

---

### process_fragment

```rust
pub async fn process_fragment(
    &mut self,
    content: &str,
    content_hash: [u8; 32],
    metadata: Option<FragmentMetadata>,
) -> Result<VerifiedGraph, HarvesterError>
```

Extract claims from a single text fragment.

**Parameters:**
- `content`: Fragment text
- `content_hash`: BLAKE3 hash (32 bytes)
- `metadata`: Optional metadata (filename, page, offsets)

**Returns:** Extraction results with claims, concepts, relations, audit trail

**Example:**
```rust
use epigraph_crypto::ContentHasher;

let hasher = ContentHasher::new();
let hash = hasher.hash_str(content);

let graph = client.process_fragment(content, hash, None).await?;

println!("Extracted {} claims", graph.claims.len());
println!("Confidence: {:.2}", graph.overall_confidence);
```

---

### process_batch

```rust
pub async fn process_batch(
    &mut self,
    fragments: Vec<(String, [u8; 32], Option<FragmentMetadata>)>,
) -> Result<BatchResponse, HarvesterError>
```

Process multiple fragments in batch.

**Parameters:**
- `fragments`: Vec of (content, hash, metadata) tuples

**Returns:** Batch response with success/failure counts

**Example:**
```rust
let batch = vec![
    (content1, hash1, None),
    (content2, hash2, None),
];

let response = client.process_batch(batch).await?;
println!("{}/{} successful",
    response.successful,
    response.total_processed
);
```

---

### health_check

```rust
pub async fn health_check(&mut self) -> Result<HealthResponse, HarvesterError>
```

Check service health and get version info.

**Example:**
```rust
let health = client.health_check().await?;

if health.healthy {
    println!("Healthy: {} v{} (uptime: {}s)",
        health.model_name,
        health.version,
        health.uptime_seconds
    );
}
```

---

## TextFragmenter

### Constructors

```rust
pub fn new(target_size: usize, overlap: usize) -> Self
pub fn default() -> Self  // 6000 chars, 600 overlap
```

Create fragmenter with size/overlap configuration.

**Parameters:**
- `target_size`: Target fragment size in characters (~4 chars = 1 token)
- `overlap`: Overlap between fragments in characters

**Example:**
```rust
// Default: ~1500 tokens per fragment, ~150 token overlap
let fragmenter = TextFragmenter::default();

// Custom: ~500 tokens per fragment, ~50 token overlap
let fragmenter = TextFragmenter::new(2000, 200);
```

---

### fragment

```rust
pub async fn fragment(&self, content: &str)
    -> Result<Vec<Fragment>, HarvesterError>
```

Split document into semantically coherent fragments.

**Strategy:**
1. Prefer paragraph boundaries (`\n\n`)
2. Fall back to sentence boundaries (`. ` `? ` `! `)
3. Fall back to word boundaries (` `)
4. Last resort: split at target

**Returns:** Ordered fragments with hashes and offsets

**Example:**
```rust
let fragmenter = TextFragmenter::default();
let fragments = fragmenter.fragment(document).await?;

for fragment in fragments {
    println!("Fragment {}: {} chars at offset {}",
        fragment.sequence_number,
        fragment.content.len(),
        fragment.start_offset
    );

    // Fragment is content-addressed
    println!("Hash: {:?}", fragment.content_hash);
}
```

---

### estimate_tokens

```rust
pub fn estimate_tokens(text: &str) -> usize
```

Estimate token count (rough: 1 token ≈ 4 chars).

**Example:**
```rust
let tokens = TextFragmenter::estimate_tokens("Some text...");
println!("Estimated {} tokens", tokens);
```

---

## Fragment

```rust
pub struct Fragment {
    pub content: String,
    pub content_hash: [u8; 32],
    pub start_offset: usize,
    pub end_offset: usize,
    pub sequence_number: u32,
}
```

A document fragment ready for processing.

**Fields:**
- `content`: Fragment text
- `content_hash`: BLAKE3 hash (deterministic, content-addressed)
- `start_offset`: Character position in original document
- `end_offset`: End position in original document
- `sequence_number`: 0-indexed order in document

---

## PartialClaim

```rust
pub struct PartialClaim {
    pub content: String,
    pub methodology: Methodology,
    pub confidence: f64,
    pub citations: Vec<Citation>,
    pub agent_name: Option<String>,
    pub reasoning_trace: Option<String>,
    pub low_confidence_flag: bool,
}
```

A claim extracted by harvester (unsigned, needs agent signature).

**Fields:**
- `content`: The claim statement
- `methodology`: Reasoning type (Deductive, Inductive, etc.)
- `confidence`: [0.0, 1.0] confidence score
- `citations`: References to source text
- `agent_name`: Author/source name (if extracted)
- `reasoning_trace`: Explanation
- `low_confidence_flag`: True if flagged for review

---

## Citation

```rust
pub struct Citation {
    pub quote: String,
    pub char_start: usize,
    pub char_end: usize,
}
```

Reference to source text supporting a claim.

---

## Conversion Functions

### proto_claim_to_domain

```rust
pub fn proto_claim_to_domain(proto: &ExtractedClaim)
    -> Result<PartialClaim, HarvesterError>
```

Convert protobuf claim to domain type.

**Validates:**
- Confidence in [0.0, 1.0]

---

### proto_graph_to_claims

```rust
pub fn proto_graph_to_claims(graph: &VerifiedGraph)
    -> Result<Vec<PartialClaim>, HarvesterError>
```

Extract all claims from verified graph.

**Example:**
```rust
let graph = client.process_fragment(content, hash, None).await?;
let claims = proto_graph_to_claims(&graph)?;

for claim in claims {
    println!("Claim: {}", claim.content);
    println!("Confidence: {:.2}", claim.confidence);
    println!("Citations: {}", claim.citations.len());

    if claim.low_confidence_flag {
        println!("⚠️  Flagged for review");
    }
}
```

---

### methodology_from_proto / methodology_to_proto

```rust
pub fn methodology_from_proto(m: i32) -> Methodology
pub fn methodology_to_proto(m: Methodology) -> i32
```

Convert between proto and domain methodology enums.

**Methodologies:**
- `Deductive`: Conclusion follows from premises
- `Inductive`: Generalization from observations
- `Abductive`: Inference to best explanation
- `Instrumental`: Measurement/calculation
- `Extraction`: Extracted from literature

---

## HarvesterError

```rust
pub enum HarvesterError {
    ConnectionFailed { url: String, reason: String },
    ExtractionFailed { fragment_id: String, reason: String },
    FragmentationFailed { reason: String },
    InvalidResponse { reason: String },
    Timeout { operation: String },
    Transport(tonic::transport::Error),
    Status(tonic::Status),
    InvalidContentHash { expected: usize, actual: usize },
    InvalidConfidence { value: f64 },
    MissingField { field: String },
}
```

### is_retryable

```rust
pub fn is_retryable(&self) -> bool
```

Check if error is transient and retry-able.

**Returns true for:**
- `ConnectionFailed`
- `Timeout`
- `Transport`

**Example:**
```rust
match client.process_fragment(content, hash, None).await {
    Ok(graph) => { /* handle success */ }
    Err(e) if e.is_retryable() => {
        // Retry with backoff
        tokio::time::sleep(Duration::from_secs(1)).await;
        // retry...
    }
    Err(e) => {
        // Permanent error
        return Err(e.into());
    }
}
```

---

## Proto Types

Common protobuf types re-exported for convenience:

### ExtractionStatus

```rust
pub enum ExtractionStatus {
    Success,
    LowConfidence,
    PartialSuccess,
    Failed,
    NoContent,
    TransientError,
}
```

### VerifiedGraph

```rust
pub struct VerifiedGraph {
    pub fragment_id: String,
    pub status: ExtractionStatus,
    pub claims: Vec<ExtractedClaim>,
    pub concepts: Vec<ExtractedConcept>,
    pub relations: Vec<ExtractedRelation>,
    pub audit_trail: Option<AuditTrail>,
    pub overall_confidence: f32,
    pub error_message: String,
}
```

### AuditTrail

```rust
pub struct AuditTrail {
    pub extraction_id: String,
    pub skeptic_report: Option<SkepticReport>,
    pub logician_report: Option<LogicianReport>,
    pub variance_report: Option<VarianceReport>,
    pub synthesis_iterations: i32,
    pub fixes_applied: Vec<String>,
    pub token_usage: Option<TokenUsage>,
    pub processing_time_ms: i64,
}
```

---

## Complete Example

```rust
use epigraph_harvester::{
    HarvesterClient, TextFragmenter, Fragmenter,
    proto_graph_to_claims,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let mut client = HarvesterClient::new("http://localhost:50051")
        .await?
        .with_timeout(Duration::from_secs(120));

    // Verify service
    let health = client.health_check().await?;
    println!("Connected to: {} v{}", health.model_name, health.version);

    // Load document
    let document = std::fs::read_to_string("paper.txt")?;
    println!("Document: {} chars", document.len());

    // Fragment
    let fragmenter = TextFragmenter::default();
    let fragments = fragmenter.fragment(&document).await?;
    println!("Created {} fragments", fragments.len());

    // Process each fragment
    let mut all_claims = Vec::new();

    for fragment in fragments {
        println!("\nProcessing fragment {}...", fragment.sequence_number);

        let graph = client.process_fragment(
            &fragment.content,
            fragment.content_hash,
            None,
        ).await?;

        println!("  Status: {:?}", graph.status);
        println!("  Claims: {}", graph.claims.len());
        println!("  Concepts: {}", graph.concepts.len());
        println!("  Overall confidence: {:.2}", graph.overall_confidence);

        // Extract claims
        let claims = proto_graph_to_claims(&graph)?;
        all_claims.extend(claims);

        // Show audit trail
        if let Some(audit) = graph.audit_trail {
            println!("  Processing time: {}ms", audit.processing_time_ms);

            if let Some(tokens) = audit.token_usage {
                println!("  Tokens: {} (${:.4})",
                    tokens.total_tokens,
                    tokens.estimated_cost_usd
                );
            }
        }
    }

    // Summary
    println!("\n=== Summary ===");
    println!("Total claims: {}", all_claims.len());

    let low_conf = all_claims.iter()
        .filter(|c| c.low_confidence_flag)
        .count();
    println!("Low confidence: {}", low_conf);

    let avg_conf = all_claims.iter()
        .map(|c| c.confidence)
        .sum::<f64>() / all_claims.len() as f64;
    println!("Average confidence: {:.2}", avg_conf);

    Ok(())
}
```

---

## Error Handling Patterns

### Basic

```rust
let graph = client.process_fragment(content, hash, None).await?;
```

### With Retry

```rust
let mut retries = 3;
let graph = loop {
    match client.process_fragment(content, hash, None).await {
        Ok(g) => break g,
        Err(e) if e.is_retryable() && retries > 0 => {
            retries -= 1;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(e) => return Err(e.into()),
    }
};
```

### With Logging

```rust
use tracing::{info, warn, error};

match client.process_fragment(content, hash, None).await {
    Ok(graph) => {
        info!("Extracted {} claims", graph.claims.len());
        // process...
    }
    Err(e) => {
        error!("Extraction failed: {}", e);
        if e.is_retryable() {
            warn!("Error is retryable - consider retry");
        }
        return Err(e.into());
    }
}
```

---

## Performance Tips

1. **Batch Processing**: Use `process_batch()` for multiple fragments
2. **Fragment Size**: Balance context (larger) vs processing time (smaller)
3. **Overlap**: More overlap = better context, but more processing
4. **Timeouts**: Adjust based on fragment size and model speed
5. **Connection Reuse**: Keep client alive across multiple requests
6. **Parallel Processing**: Process independent fragments concurrently

```rust
// Parallel processing
use futures::future::join_all;

let futures: Vec<_> = fragments.into_iter()
    .map(|frag| {
        let mut c = client.clone();
        async move {
            c.process_fragment(&frag.content, frag.content_hash, None).await
        }
    })
    .collect();

let results = join_all(futures).await;
```
