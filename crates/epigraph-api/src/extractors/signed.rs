use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, Request},
    http::header::AUTHORIZATION,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use epigraph_crypto::{ContentHasher, SignatureVerifier, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use serde::de::DeserializeOwned;

use crate::errors::ApiError;

/// Header name for the public key
const PUBLIC_KEY_HEADER: &str = "X-Public-Key";

/// Authorization header prefix for signatures
const SIGNATURE_PREFIX: &str = "Signature ";

/// Extractor for signature-verified requests
///
/// Validates Ed25519 signatures over request bodies before deserializing.
///
/// # Security Model
///
/// 1. Extracts signature from `Authorization: Signature <base64>` header
/// 2. Extracts public key from `X-Public-Key: <hex>` header
/// 3. Reads entire request body and hashes with BLAKE3
/// 4. Verifies Ed25519 signature using epigraph-crypto
/// 5. Deserializes body as JSON into type T
///
/// # Error Responses
///
/// - **401 Unauthorized**: Missing headers, invalid signature, or verification failure
/// - **400 Bad Request**: Malformed base64/hex encoding, wrong key/signature length
///
/// # Example
///
/// ```ignore
/// async fn submit_claim(
///     SignedRequest { payload, signature, public_key }: SignedRequest<ClaimSubmission>,
/// ) -> impl IntoResponse {
///     // payload is already verified to be signed by public_key
/// }
/// ```
pub struct SignedRequest<T> {
    /// The deserialized and verified payload
    pub payload: T,
    /// The Ed25519 signature (64 bytes)
    pub signature: [u8; SIGNATURE_SIZE],
    /// The Ed25519 public key that created the signature (32 bytes)
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

#[async_trait]
impl<T, S> FromRequest<S> for SignedRequest<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Step 1: Extract Authorization header
        let auth_header = request
            .headers()
            .get(AUTHORIZATION)
            .ok_or_else(|| ApiError::Unauthorized {
                reason: "Missing Authorization header".to_string(),
            })?
            .to_str()
            .map_err(|_| ApiError::BadRequest {
                message: "Authorization header contains invalid characters".to_string(),
            })?;

        // Step 2: Validate "Signature " prefix and extract base64
        if auth_header.is_empty() {
            return Err(ApiError::Unauthorized {
                reason: "Empty Authorization header".to_string(),
            });
        }

        let signature_base64 =
            auth_header
                .strip_prefix(SIGNATURE_PREFIX)
                .ok_or_else(|| ApiError::Unauthorized {
                    reason: format!(
                        "Authorization header must start with '{}', got: {}",
                        SIGNATURE_PREFIX,
                        &auth_header[..auth_header.len().min(20)]
                    ),
                })?;

        // Step 3: Decode base64 signature
        let signature_bytes =
            STANDARD
                .decode(signature_base64)
                .map_err(|e| ApiError::BadRequest {
                    message: format!("Invalid base64 in signature: {}", e),
                })?;

        // Step 4: Validate signature length (Ed25519 = 64 bytes)
        let signature: [u8; SIGNATURE_SIZE] =
            signature_bytes
                .try_into()
                .map_err(|v: Vec<u8>| ApiError::BadRequest {
                    message: format!(
                        "Invalid signature length: expected {} bytes, got {}",
                        SIGNATURE_SIZE,
                        v.len()
                    ),
                })?;

        // Step 5: Extract X-Public-Key header
        let public_key_hex = request
            .headers()
            .get(PUBLIC_KEY_HEADER)
            .ok_or_else(|| ApiError::Unauthorized {
                reason: "Missing X-Public-Key header".to_string(),
            })?
            .to_str()
            .map_err(|_| ApiError::BadRequest {
                message: "X-Public-Key header contains invalid characters".to_string(),
            })?;

        // Step 6: Validate non-empty public key
        if public_key_hex.is_empty() {
            return Err(ApiError::BadRequest {
                message: "Empty X-Public-Key header".to_string(),
            });
        }

        // Step 7: Decode hex public key
        let public_key_bytes = hex::decode(public_key_hex).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex in public key: {}", e),
        })?;

        // Step 8: Validate public key length (Ed25519 = 32 bytes)
        let public_key: [u8; PUBLIC_KEY_SIZE] =
            public_key_bytes
                .try_into()
                .map_err(|v: Vec<u8>| ApiError::BadRequest {
                    message: format!(
                        "Invalid public key length: expected {} bytes, got {}",
                        PUBLIC_KEY_SIZE,
                        v.len()
                    ),
                })?;

        // Step 9: Read request body
        let body_bytes =
            Bytes::from_request(request, state)
                .await
                .map_err(|e| ApiError::BadRequest {
                    message: format!("Failed to read request body: {}", e),
                })?;

        // Step 10: Hash body with BLAKE3
        let body_hash = ContentHasher::hash(&body_bytes);

        // Step 11: Verify Ed25519 signature
        // Uses constant-time comparison internally via ed25519-dalek
        let is_valid =
            SignatureVerifier::verify(&public_key, &body_hash, &signature).map_err(|e| {
                ApiError::SignatureError {
                    reason: format!("Signature verification error: {}", e),
                }
            })?;

        if !is_valid {
            return Err(ApiError::InvalidSignature);
        }

        // Step 12: Deserialize body as JSON
        let payload: T = serde_json::from_slice(&body_bytes).map_err(|e| ApiError::BadRequest {
            message: format!("Failed to deserialize request body: {}", e),
        })?;

        Ok(SignedRequest {
            payload,
            signature,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_request_stores_payload() {
        let payload = "test payload data".to_string();
        let signed = SignedRequest {
            payload: payload.clone(),
            signature: [0u8; 64],
            public_key: [0u8; 32],
        };
        assert_eq!(signed.payload, payload);
    }

    #[test]
    fn signed_request_stores_signature() {
        let mut signature = [0u8; 64];
        signature[0] = 0xDE;
        signature[63] = 0xAD;

        let signed = SignedRequest {
            payload: (),
            signature,
            public_key: [0u8; 32],
        };

        assert_eq!(signed.signature[0], 0xDE);
        assert_eq!(signed.signature[63], 0xAD);
        assert_eq!(signed.signature.len(), 64); // Ed25519 signature size
    }

    #[test]
    fn signed_request_stores_public_key() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xCA;
        public_key[31] = 0xFE;

        let signed = SignedRequest {
            payload: (),
            signature: [0u8; 64],
            public_key,
        };

        assert_eq!(signed.public_key[0], 0xCA);
        assert_eq!(signed.public_key[31], 0xFE);
        assert_eq!(signed.public_key.len(), 32); // Ed25519 public key size
    }

    #[test]
    fn signed_request_with_complex_payload() {
        #[derive(Debug, Clone, PartialEq)]
        struct ComplexPayload {
            id: u64,
            name: String,
        }

        let payload = ComplexPayload {
            id: 42,
            name: "test".to_string(),
        };

        let signed = SignedRequest {
            payload: payload.clone(),
            signature: [1u8; 64],
            public_key: [2u8; 32],
        };

        assert_eq!(signed.payload, payload);
        assert_eq!(signed.payload.id, 42);
        assert_eq!(signed.payload.name, "test");
    }
}
