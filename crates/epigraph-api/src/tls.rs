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
    /// Create an axum-server RustlsConfig from this configuration.
    ///
    /// The certificate file holds the chain, leaf first. The key file holds
    /// one private key as PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`)
    /// or SEC1 (`EC PRIVATE KEY`). PEM is parsed with `rustls-pki-types`'
    /// `PemObject` API (the maintained replacement for `rustls-pemfile`).
    ///
    /// The `ServerConfig` is built on an EXPLICIT crypto provider instead of
    /// `ServerConfig::builder()`. That builder reads the process-level
    /// provider, which rustls cannot infer when both its `ring` and
    /// `aws-lc-rs` features are compiled in, as they are under `tls` (reqwest
    /// and hyper-rustls bring `ring`): it panics. So the loader uses the
    /// process-level provider when an embedder installed one (for example a
    /// FIPS provider), and otherwise aws-lc-rs, the one axum-server's
    /// `tls-rustls` selects. It never installs a process-wide default itself:
    /// that would override an embedder's later choice.
    pub async fn into_rustls_config(
        self,
    ) -> Result<axum_server::tls_rustls::RustlsConfig, std::io::Error> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{Error, ErrorKind};
        use std::sync::Arc;

        let invalid = |what: String| Error::new(ErrorKind::InvalidData, what);

        let cert_pem = tokio::fs::read(&self.cert_path).await?;
        let key_pem = tokio::fs::read(&self.key_path).await?;

        let chain = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(format!("{}: {e}", self.cert_path.display())))?;
        if chain.is_empty() {
            return Err(invalid(format!(
                "{}: no PEM certificate found",
                self.cert_path.display()
            )));
        }
        let key = PrivateKeyDer::from_pem_slice(&key_pem)
            .map_err(|e| invalid(format!("{}: {e}", self.key_path.display())))?;

        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(Error::other)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| {
                invalid(format!(
                    "{} / {}: certificate/key rejected: {e}",
                    self.cert_path.display(),
                    self.key_path.display()
                ))
            })?;
        // What axum-server's own PEM loader sets: keep HTTP/2 over ALPN.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(axum_server::tls_rustls::RustlsConfig::from_config(
            Arc::new(config),
        ))
    }
}
