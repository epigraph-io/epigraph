//! Upstream DTOs and typed calls for the entities area (history, agents,
//! frames, evidence). OWNED BY THE ENTITIES AREA.
//!
//! Add `impl Api<'_> { pub async fn …(&self, …) -> Result<T, UpstreamError> }`
//! blocks here, built on `Api::get` / `get_query` / `post`.
