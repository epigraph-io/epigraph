//! RSA keypair + wiremock JWKS server + JWT signing helper.

use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::json;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const TEST_KID: &str = "test-key-1";

pub struct ProviderFixture {
    #[allow(dead_code)] // shared across test binaries; not all use the mock_server handle.
    pub mock_server: MockServer,
    pub jwks_url: String,
    private_key: RsaPrivateKey,
}

impl ProviderFixture {
    pub async fn new() -> Self {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks_body = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": TEST_KID,
                "n": n_b64,
                "e": e_b64,
            }]
        });

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body))
            .mount(&mock_server)
            .await;

        let jwks_url = format!("{}/jwks", mock_server.uri());

        Self {
            mock_server,
            jwks_url,
            private_key,
        }
    }

    /// Sign arbitrary JSON claims with the fixture key, matching the JWKS kid.
    pub fn sign<C: Serialize>(&self, claims: &C) -> String {
        let pem = self
            .private_key
            .to_pkcs1_pem(pkcs1::LineEnding::LF)
            .unwrap()
            .to_string();
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.into());
        encode(&header, claims, &key).expect("sign jwt")
    }
}
