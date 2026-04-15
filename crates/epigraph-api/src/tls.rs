//! TLS configuration for the EpiGraph API server

use std::path::PathBuf;

/// TLS configuration options
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate (PEM format)
    pub cert_path: PathBuf,
    /// Path to TLS private key (PEM format)
    pub key_path: PathBuf,
}

#[cfg(feature = "tls")]
impl TlsConfig {
    /// Create an axum-server RustlsConfig from this configuration
    pub async fn into_rustls_config(
        self,
    ) -> Result<axum_server::tls_rustls::RustlsConfig, std::io::Error> {
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&self.cert_path, &self.key_path).await
    }
}
