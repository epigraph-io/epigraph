//! `TlsConfig::into_rustls_config` uses the process-level rustls
//! `CryptoProvider` when an embedder installed one, and falls back to
//! aws-lc-rs only when none is installed (backlog 8157bd62, operator ruling
//! R-26; council follow-up).
//!
//! The fallback half is `tests/tls_pem_loading.rs`, which installs no
//! provider. This half lives in its own test binary because
//! `install_default` is process-global: in the same binary it would void that
//! file's "no provider installed" premise.
//!
//! The check is identity, not equality: the config must hold the very `Arc`
//! the process default holds. A loader that builds its own aws-lc-rs provider
//! produces an equal-looking but distinct `Arc` and fails.

use std::sync::Arc;

use epigraph_api::tls::TlsConfig;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Name, X509};
use rustls::crypto::CryptoProvider;

#[tokio::test]
async fn an_installed_process_provider_is_the_one_the_config_uses() {
    assert!(
        CryptoProvider::get_default().is_none(),
        "CALIBRATION: nothing installed a process provider before this test"
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install the process-level provider");
    let installed = CryptoProvider::get_default()
        .expect("a process provider is installed")
        .clone();

    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();

    let dir = std::env::temp_dir().join(format!("epigraph-tls-provider-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let config = TlsConfig {
        cert_path,
        key_path,
    }
    .into_rustls_config()
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    let config = config.expect("a valid self-signed pair loads");

    assert!(
        Arc::ptr_eq(config.get_inner().crypto_provider(), &installed),
        "the ServerConfig must be built on the embedder's installed provider, \
         not on a provider the loader constructs itself"
    );
}
