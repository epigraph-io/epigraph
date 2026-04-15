# epigraph-harvester

Rust client for the EpiGraph Harvester intelligence worker.

## Overview

The harvester is a Python service that extracts epistemic claims from documents using LLMs with a Council of Critics validation layer. This crate provides:

- **gRPC Client**: Communicate with the Python harvester service
- **Document Fragmenter**: Split large documents into processable chunks
- **Type Conversions**: Map between protobuf and domain types

## Build Requirements

This crate requires the Protocol Buffers compiler (`protoc`) to generate Rust code from `.proto` files.

### Installing protoc

**Debian/Ubuntu:**
```bash
sudo apt-get install protobuf-compiler
```

**macOS:**
```bash
brew install protobuf
```

**Windows:**
Download from https://github.com/protocolbuffers/protobuf/releases

Alternatively, set the `PROTOC` environment variable to point to your protoc binary.

## Usage

### Basic Example

```rust
use epigraph_harvester::{HarvesterClient, TextFragmenter, Fragmenter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to harvester service
    let mut client = HarvesterClient::new("http://localhost:50051").await?;

    // Check health
    let health = client.health_check().await?;
    println!("Harvester: {} v{}", health.model_name, health.version);

    // Fragment document
    let fragmenter = TextFragmenter::default();
    let text = "Your long document text here...";
    let fragments = fragmenter.fragment(text).await?;

    // Process each fragment
    for fragment in fragments {
        let graph = client.process_fragment(
            &fragment.content,
            fragment.content_hash,
            None,
        ).await?;

        println!("Extracted {} claims from fragment {}",
            graph.claims.len(),
            fragment.sequence_number
        );
    }

    Ok(())
}
```

### Document Fragmentation

The `TextFragmenter` splits documents intelligently:
- Targets 1000-2000 tokens per fragment (~6000 chars)
- Preserves semantic boundaries (paragraphs, sentences)
- Includes 100-200 token overlap for context
- Each fragment is BLAKE3 content-addressed

```rust
use epigraph_harvester::{TextFragmenter, Fragmenter};

let fragmenter = TextFragmenter::new(
    6000,  // target size in chars
    600,   // overlap in chars
);

let fragments = fragmenter.fragment(document).await?;

for fragment in fragments {
    println!("Fragment {}: {} chars at offset {}",
        fragment.sequence_number,
        fragment.content.len(),
        fragment.start_offset
    );
}
```

### Processing Results

The harvester returns `VerifiedGraph` containing:
- **Claims**: Extracted assertions with confidence scores
- **Concepts**: Entities, processes, properties
- **Relations**: Links between claims/concepts
- **Audit Trail**: Council reports, token usage, metrics

```rust
let graph = client.process_fragment(&content, hash, None).await?;

// Convert proto claims to domain types
use epigraph_harvester::{proto_graph_to_claims, PartialClaim};

let claims: Vec<PartialClaim> = proto_graph_to_claims(&graph)?;

for claim in claims {
    println!("Claim: {} (confidence: {:.2})",
        claim.content,
        claim.confidence
    );

    if claim.low_confidence_flag {
        println!("⚠️  Low confidence - requires review");
    }
}
```

## Architecture

```
┌─────────────────┐         gRPC          ┌──────────────────┐
│  Rust Client    │◄────────────────────►│  Python Server   │
│                 │                       │                  │
│ - Fragmenter    │   FragmentRequest    │ - Extractor      │
│ - gRPC Client   │   ───────────►       │ - Skeptic        │
│ - Type Convert  │                       │ - Logician       │
│                 │   VerifiedGraph      │ - Variance       │
│                 │   ◄───────────       │                  │
└─────────────────┘                       └──────────────────┘
```

## Proto Schema

The gRPC protocol is defined in `/proto/harvester.proto`. Key messages:

- `FragmentRequest`: Input document fragment
- `VerifiedGraph`: Extraction results with audit trail
- `ExtractedClaim`: A single claim with citations
- `AuditTrail`: Quality assurance reports

## Testing

```bash
# Run tests
cargo test -p epigraph-harvester

# Run with logging
RUST_LOG=epigraph_harvester=debug cargo test -p epigraph-harvester
```

## Development

Generated proto code is placed in `src/proto/` by the build script.
If you modify `proto/harvester.proto`, run:

```bash
cargo clean -p epigraph-harvester
cargo build -p epigraph-harvester
```

## Dependencies

- `tonic`: gRPC framework
- `prost`: Protocol Buffers
- `epigraph-core`: Domain types
- `epigraph-crypto`: BLAKE3 hashing
- `tokio`: Async runtime
