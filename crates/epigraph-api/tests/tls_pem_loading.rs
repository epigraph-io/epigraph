//! `TlsConfig::into_rustls_config` loads the PEM files the server is given
//! (`EPIGRAPH_TLS_CERT` / `EPIGRAPH_TLS_KEY`) — backlog 8157bd62 item (3),
//! operator ruling R-26.
//!
//! The PEM parser under it moved from `rustls-pemfile` to `rustls-pki-types`'
//! `PemObject` API (axum-server 0.7 -> 0.8). This pins the formats the old
//! loader accepted: a certificate CHAIN, and a private key as PKCS#8, PKCS#1
//! (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`). It also pins that garbage,
//! and a key that does not match the leaf, is refused with an `InvalidData`
//! error that names the file(s) at fault, not a panic and not an empty config.
//!
//! "Loads" is proved by a real TLS handshake against the loaded config, not by
//! `is_ok()`: the client trusts only the test root, so the handshake succeeds
//! only if the whole chain was read and the key matches the leaf, and the
//! client then sees both certificates of the chain, leaf first. ALPN must
//! still negotiate `h2`, as axum-server's own loader configured it.
//!
//! The test installs NO process-level rustls `CryptoProvider`: the server
//! binary does not either, so the loader has to work without one.
//!
//! Keys and certificates are generated per run with OpenSSL (already this
//! crate's dev-dependency); no key material is committed.

use std::path::PathBuf;
use std::sync::Arc;

use epigraph_api::tls::TlsConfig;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Name, X509};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn name(cn: &str) -> X509Name {
    let mut n = X509Name::builder().unwrap();
    n.append_entry_by_text("CN", cn).unwrap();
    n.build()
}

fn serial() -> openssl::asn1::Asn1Integer {
    let mut bn = BigNum::new().unwrap();
    bn.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    bn.to_asn1_integer().unwrap()
}

/// A certificate for `subject_key`, signed by `issuer_key` (self-signed when
/// `issuer` is `None`).
fn cert(
    cn: &str,
    subject_key: &PKeyRef<Private>,
    issuer: Option<(&X509, &PKeyRef<Private>)>,
) -> X509 {
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial()).unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_pubkey(subject_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    let signing_key = match issuer {
        Some((ca, ca_key)) => {
            b.set_issuer_name(ca.subject_name()).unwrap();
            let san = SubjectAlternativeName::new()
                .dns("localhost")
                .build(&b.x509v3_context(Some(ca), None))
                .unwrap();
            b.append_extension(san).unwrap();
            ca_key
        }
        None => {
            b.set_issuer_name(&name(cn)).unwrap();
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            subject_key
        }
    };
    b.sign(signing_key, MessageDigest::sha256()).unwrap();
    b.build()
}

/// A test CA, and a leaf for `leaf_key` that it signs. Returns
/// (root, chain PEM = leaf then root).
fn chain_for(leaf_key: &PKeyRef<Private>) -> (X509, Vec<u8>) {
    let ca_key = PKey::from_ec_key(EcKey::generate(&p256()).unwrap()).unwrap();
    let ca = cert("epigraph test root", &ca_key, None);
    let leaf = cert("localhost", leaf_key, Some((&ca, &ca_key)));
    let mut pem = leaf.to_pem().unwrap();
    pem.extend(ca.to_pem().unwrap());
    (ca, pem)
}

fn p256() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()
}

/// Writes `cert` and `key` to fresh files and loads them the way the server
/// binary does.
async fn load(cert: &[u8], key: &[u8]) -> std::io::Result<axum_server::tls_rustls::RustlsConfig> {
    load_at(cert, key).await.0
}

/// [`load`], also returning the certificate and key paths the loader was
/// given, so a refusal can be checked for the file it blames.
async fn load_at(
    cert: &[u8],
    key: &[u8],
) -> (
    std::io::Result<axum_server::tls_rustls::RustlsConfig>,
    String,
    String,
) {
    let dir = std::env::temp_dir().join(format!("epigraph-tls-pem-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path: PathBuf = dir.join("cert.pem");
    let key_path: PathBuf = dir.join("key.pem");
    std::fs::write(&cert_path, cert).unwrap();
    std::fs::write(&key_path, key).unwrap();
    let (cert_name, key_name) = (
        cert_path.display().to_string(),
        key_path.display().to_string(),
    );
    let out = TlsConfig {
        cert_path,
        key_path,
    }
    .into_rustls_config()
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    (out, cert_name, key_name)
}

/// Handshakes against `config` with a client that trusts only `root`, sends a
/// byte through the tunnel, and returns the chain the server presented.
async fn handshake(
    config: &axum_server::tls_rustls::RustlsConfig,
    root: &X509,
) -> Vec<CertificateDer<'static>> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config.get_inner());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server handshake");
        let mut b = [0u8; 1];
        tls.read_exact(&mut b).await.unwrap();
        tls.write_all(&b).await.unwrap();
        tls.shutdown().await.ok();
    });

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_der().unwrap()))
        .unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("client handshake against the loaded config");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the server still offers HTTP/2 over ALPN, as axum-server's loader did"
    );
    tls.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    tls.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"x", "a byte round-trips through the tunnel");
    let presented = tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("server presented certificates")
        .iter()
        .map(|c| c.clone().into_owned())
        .collect();
    server.await.unwrap();
    presented
}

/// The chain is served whole, leaf first, under `key_pem`'s key.
///
/// `pem_label` is the PEM type label the key file must carry (`PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `EC PRIVATE KEY`); the BEGIN line is assembled from it,
/// so this file holds no literal PEM key header for a secret scanner to match.
async fn assert_serves(label: &str, key_pem: &[u8], leaf_key: &PKeyRef<Private>, pem_label: &str) {
    let begin = format!("-----BEGIN {pem_label}-----");
    assert!(
        String::from_utf8_lossy(key_pem).starts_with(&begin),
        "CALIBRATION ({label}): the key file is in the {pem_label} form under test"
    );
    let (root, chain) = chain_for(leaf_key);
    let config = load(&chain, key_pem)
        .await
        .unwrap_or_else(|e| panic!("{label}: the loader refused a valid chain + key: {e}"));
    let presented = handshake(&config, &root).await;
    assert_eq!(presented.len(), 2, "{label}: the whole chain is served");
    assert_eq!(
        presented[1].as_ref(),
        root.to_der().unwrap().as_slice(),
        "{label}: the root is the second certificate of the chain"
    );
    let leaf = X509::from_der(presented[0].as_ref()).unwrap();
    assert!(
        leaf.public_key().unwrap().public_eq(leaf_key),
        "{label}: the served leaf is the one for the loaded key"
    );
}

#[tokio::test]
async fn rsa_keys_load_as_pkcs8_and_pkcs1() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkcs1 = rsa.private_key_to_pem().unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let pkcs8 = key.private_key_to_pem_pkcs8().unwrap();
    assert_serves("RSA PKCS#8", &pkcs8, &key, "PRIVATE KEY").await;
    assert_serves("RSA PKCS#1", &pkcs1, &key, "RSA PRIVATE KEY").await;
}

#[tokio::test]
async fn ec_keys_load_as_pkcs8_and_sec1() {
    let ec = EcKey::generate(&p256()).unwrap();
    let sec1 = ec.private_key_to_pem().unwrap();
    let key = PKey::from_ec_key(ec).unwrap();
    let pkcs8 = key.private_key_to_pem_pkcs8().unwrap();
    assert_serves("EC PKCS#8", &pkcs8, &key, "PRIVATE KEY").await;
    assert_serves("EC SEC1", &sec1, &key, "EC PRIVATE KEY").await;
}

/// A PEM frame with `label` around a literal `body`.
fn pem_frame(label: &str, body: &str) -> Vec<u8> {
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n").into_bytes()
}

/// A cert/key pair that loads, so each refusal below differs from a working
/// input in exactly the file it corrupts.
fn valid_pair() -> (Vec<u8>, Vec<u8>) {
    let key = PKey::from_ec_key(EcKey::generate(&p256()).unwrap()).unwrap();
    let (_, chain) = chain_for(&key);
    (chain, key.private_key_to_pem_pkcs8().unwrap())
}

/// Which input file a refusal must name.
#[derive(Clone, Copy, Debug)]
enum Blame {
    Cert,
    Key,
    Both,
}

#[tokio::test]
async fn garbage_and_empty_inputs_are_refused() {
    let (chain, key) = valid_pair();
    load(&chain, &key)
        .await
        .expect("CALIBRATION: the unmodified pair loads");

    let not_pem = b"this is not a PEM file\n".to_vec();
    // PEM frames whose body is not base64: framing alone must not pass.
    let corrupt_key = pem_frame("PRIVATE KEY", "!!!not base64!!!");
    let corrupt_cert = pem_frame("CERTIFICATE", "!!!not base64!!!");
    // Well-formed PEM of the wrong kind in each file.
    let cert_as_key = chain.clone();
    let key_as_cert = key.clone();
    // A well-formed PKCS#8 key for a DIFFERENT keypair than the leaf's.
    let other_key = PKey::from_ec_key(EcKey::generate(&p256()).unwrap())
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();

    let cases: [(&str, &[u8], &[u8], Blame); 9] = [
        ("key file is not PEM", &chain, &not_pem, Blame::Key),
        ("key file is empty", &chain, b"", Blame::Key),
        (
            "key PEM body is not base64",
            &chain,
            &corrupt_key,
            Blame::Key,
        ),
        (
            "key file holds only certificates",
            &chain,
            &cert_as_key,
            Blame::Key,
        ),
        ("cert file is not PEM", &not_pem, &key, Blame::Cert),
        ("cert file is empty", b"", &key, Blame::Cert),
        (
            "cert PEM body is not base64",
            &corrupt_cert,
            &key,
            Blame::Cert,
        ),
        (
            "cert file holds only a private key",
            &key_as_cert,
            &key,
            Blame::Cert,
        ),
        (
            "key does not match the leaf",
            &chain,
            &other_key,
            Blame::Both,
        ),
    ];
    for (label, cert, key, blame) in cases {
        let (out, cert_path, key_path) = load_at(cert, key).await;
        let err = match out {
            Ok(_) => panic!("{label}: the loader must refuse it with an error"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "{label}: refused as invalid data, not as an I/O failure: {err}"
        );
        let msg = err.to_string();
        let (names_cert, names_key) = (msg.contains(&cert_path), msg.contains(&key_path));
        let expected = match blame {
            Blame::Cert => (true, false),
            Blame::Key => (false, true),
            Blame::Both => (true, true),
        };
        assert_eq!(
            (names_cert, names_key),
            expected,
            "{label}: the error must name the file(s) at fault ({blame:?}); got: {msg}"
        );
    }
}
