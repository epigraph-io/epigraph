//! JWT validation and claim types — moved to the shared `epigraph-auth` crate
//! so `epigraph-mcp` can validate the same tokens.

pub use epigraph_auth::{EpiGraphClaims, JwtConfig};
