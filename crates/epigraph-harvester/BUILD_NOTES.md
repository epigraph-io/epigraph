# Build Notes for epigraph-harvester

## Current Status

✅ **Created**: All source files and project structure
❌ **Blocked**: Build requires `protoc` (Protocol Buffers compiler)

## What Was Created

### Project Structure
```
crates/epigraph-harvester/
├── Cargo.toml              ✅ Dependencies configured
├── build.rs                ✅ Proto compilation setup
├── README.md               ✅ Usage documentation
├── .gitignore              ✅ Ignore generated proto files
└── src/
    ├── lib.rs              ✅ Public API exports
    ├── errors.rs           ✅ HarvesterError types
    ├── client.rs           ✅ gRPC client implementation
    ├── convert.rs          ✅ Proto ↔ Domain conversions
    ├── fragmenter/
    │   ├── mod.rs          ✅ Fragmenter trait
    │   └── text.rs         ✅ TextFragmenter with semantic chunking
    └── proto/
        └── mod.rs          ✅ Proto include (will contain generated code)
```

### Key Components

#### 1. HarvesterClient (`client.rs`)
- `new(url)`: Connect to harvester gRPC service
- `process_fragment()`: Send single fragment for extraction
- `process_batch()`: Process multiple fragments
- `health_check()`: Verify service availability
- Built-in timeout handling and retry logic

#### 2. TextFragmenter (`fragmenter/text.rs`)
- Semantic chunking with configurable size/overlap
- Splits on paragraph/sentence boundaries
- BLAKE3 content hashing for each fragment
- Default: 6000 chars (~1500 tokens) with 600 char overlap
- Comprehensive test suite (11 tests)

#### 3. Type Conversions (`convert.rs`)
- `proto_claim_to_domain()`: ExtractedClaim → PartialClaim
- `proto_graph_to_claims()`: VerifiedGraph → Vec<PartialClaim>
- `methodology_from_proto()` / `methodology_to_proto()`: Enum conversions
- `PartialClaim`: Unsigned claim ready for agent signature
- `Citation`: Source text references

#### 4. Error Types (`errors.rs`)
- `ConnectionFailed`: gRPC connection errors
- `ExtractionFailed`: Harvester processing errors
- `FragmentationFailed`: Document splitting errors
- `InvalidResponse`: Protocol validation errors
- `Timeout`: Operation timeouts
- `is_retryable()`: Helper to identify transient errors

## Next Steps to Complete Build

### Option 1: Install protoc (Recommended)

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install protobuf-compiler
```

**macOS:**
```bash
brew install protobuf
```

**From source:**
```bash
# Download from https://github.com/protocolbuffers/protobuf/releases
wget https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-linux-x86_64.zip
unzip protoc-25.1-linux-x86_64.zip -d $HOME/.local
export PATH="$HOME/.local/bin:$PATH"
```

Then build:
```bash
cargo build -p epigraph-harvester
```

### Option 2: Pre-generate Proto Files

If protoc is available on another machine:
1. Run `cargo build -p epigraph-harvester` there
2. Copy generated files from `target/debug/build/epigraph-harvester-*/out/`
3. Place in `src/proto/` directory
4. Modify `build.rs` to skip generation

### Option 3: Use Docker

```bash
docker run --rm -v $(pwd):/workspace rust:latest bash -c "
  apt-get update && apt-get install -y protobuf-compiler
  cd /workspace
  cargo build -p epigraph-harvester
"
```

## Testing

Once built, run the test suite:

```bash
# All tests
cargo test -p epigraph-harvester

# Fragmenter tests only (11 tests)
cargo test -p epigraph-harvester --lib fragmenter

# With debug output
RUST_LOG=epigraph_harvester=debug cargo test -p epigraph-harvester

# Specific test
cargo test -p epigraph-harvester fragments_have_overlap
```

## Integration with Existing Crates

The harvester integrates with:

- **epigraph-core**: Uses `Methodology` enum, domain types
- **epigraph-crypto**: Uses `ContentHasher` for fragment hashing
- **epigraph-engine**: (Future) Will use PartialClaims for truth propagation

## Proto Generation Details

When protoc is available, `build.rs` will:
1. Read `/proto/harvester.proto`
2. Generate Rust code via `tonic-build`
3. Place generated files in `src/proto/`
4. Include via `tonic::include_proto!("harvester")`

Generated code includes:
- `ExtractionServiceClient` - gRPC client stub
- Message types (requests, responses, domain objects)
- Enum types (status codes, methodologies, etc.)
- Serialization/deserialization implementations

## Dependencies Added to Workspace

Updated `/Cargo.toml`:
- Added `crates/epigraph-harvester` to workspace members
- Added to workspace dependencies for use by other crates

## Known Limitations

1. **Requires protoc**: Not pure-Rust build (could use prost-reflect in future)
2. **Client-only**: Server is Python (by design)
3. **No streaming yet**: Client has `process_fragment` and `process_batch`, but not `ProcessStream` from proto
4. **Text only**: PDF fragmenter (`fragmenter/pdf.rs`) not implemented yet

## Future Enhancements

- [ ] Add streaming support for large documents
- [ ] Implement PDF fragmenter
- [ ] Add connection pooling and load balancing
- [ ] Metrics and observability instrumentation
- [ ] Automatic retry with exponential backoff
- [ ] Circuit breaker pattern for fault tolerance
