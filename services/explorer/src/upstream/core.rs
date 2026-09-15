//! Upstream DTOs and typed calls for the core area (search, and the claim
//! page's evidence / challenges / provenance sub-calls). OWNED BY THE CORE
//! AREA.
//!
//! Add `impl Api<'_> { pub async fn …(&self, …) -> Result<T, UpstreamError> }`
//! blocks here, built on `Api::get` / `get_query` / `post`.
