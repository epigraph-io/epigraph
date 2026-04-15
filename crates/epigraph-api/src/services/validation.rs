//! Validation Service for EpiGraph API
//!
//! Centralizes validation logic that was previously scattered across handlers.
//! This ensures consistent validation behavior and reduces code duplication.

use crate::errors::ApiError;
use epigraph_crypto::ContentHasher;

/// Maximum number of evidence items per submission packet.
/// Prevents DoS attacks via memory exhaustion from oversized payloads.
pub const MAX_EVIDENCE_PER_PACKET: usize = 100;

/// Centralized validation service for API requests
pub struct ValidationService;

impl ValidationService {
    /// Parse and validate a hex-encoded Ed25519 public key (32 bytes)
    ///
    /// # Arguments
    /// * `hex_key` - Hex-encoded public key string (expected: 64 chars)
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - The decoded public key bytes
    /// * `Err(ApiError)` - Validation error with details
    pub fn parse_public_key(hex_key: &str) -> Result<[u8; 32], ApiError> {
        if hex_key.len() != 64 {
            return Err(ApiError::ValidationError {
                field: "public_key".to_string(),
                reason: format!(
                    "Public key must be 64 hex characters (32 bytes), got {} characters",
                    hex_key.len()
                ),
            });
        }

        let bytes = hex::decode(hex_key).map_err(|_| ApiError::ValidationError {
            field: "public_key".to_string(),
            reason: "Public key contains invalid hex characters".to_string(),
        })?;

        let key: [u8; 32] = bytes.try_into().map_err(|_| ApiError::ValidationError {
            field: "public_key".to_string(),
            reason: "Public key must be exactly 32 bytes".to_string(),
        })?;

        Ok(key)
    }

    /// Validate a hex-encoded BLAKE3 content hash
    ///
    /// # Arguments
    /// * `hex_hash` - Hex-encoded hash string (expected: 64 chars for BLAKE3)
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - Hash is valid
    /// * `Err(ApiError)` - Validation error with details
    pub fn validate_content_hash(hex_hash: &str, field_name: &str) -> Result<(), ApiError> {
        if hex_hash.len() != 64 {
            return Err(ApiError::ValidationError {
                field: field_name.to_string(),
                reason: format!(
                    "Content hash must be 64 hex characters, got {}",
                    hex_hash.len()
                ),
            });
        }

        ContentHasher::from_hex(hex_hash).map_err(|_| ApiError::ValidationError {
            field: field_name.to_string(),
            reason: "Content hash contains invalid hex characters".to_string(),
        })?;

        Ok(())
    }

    /// Verify that raw content matches its claimed hash
    ///
    /// # Arguments
    /// * `raw_content` - The raw content bytes
    /// * `claimed_hash` - The claimed hex-encoded hash
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - Hash matches
    /// * `Err(ApiError)` - Hash mismatch error
    pub fn verify_content_hash(
        raw_content: &[u8],
        claimed_hash: &str,
        field_name: &str,
    ) -> Result<(), ApiError> {
        let computed_hash = ContentHasher::hash(raw_content);
        let computed_hex = ContentHasher::to_hex(&computed_hash);

        if computed_hex != claimed_hash {
            return Err(ApiError::IntegrityError {
                field: field_name.to_string(),
                expected: claimed_hash.to_string(),
                actual: computed_hex,
            });
        }

        Ok(())
    }

    /// Validate a truth value is within bounds [0.0, 1.0]
    ///
    /// # Arguments
    /// * `value` - The truth value to validate
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - Value is valid
    /// * `Err(ApiError)` - Validation error
    pub fn validate_truth_value(value: f64, field_name: &str) -> Result<(), ApiError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ApiError::ValidationError {
                field: field_name.to_string(),
                reason: "Truth value must be between 0.0 and 1.0".to_string(),
            });
        }
        Ok(())
    }

    /// Validate a confidence value is within bounds [0.0, 1.0]
    ///
    /// # Arguments
    /// * `value` - The confidence value to validate
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - Value is valid
    /// * `Err(ApiError)` - Validation error
    pub fn validate_confidence(value: f64, field_name: &str) -> Result<(), ApiError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ApiError::ValidationError {
                field: field_name.to_string(),
                reason: "Confidence must be between 0.0 and 1.0".to_string(),
            });
        }
        Ok(())
    }

    /// Validate that a string is not empty or whitespace-only
    ///
    /// # Arguments
    /// * `value` - The string to validate
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - String is non-empty
    /// * `Err(ApiError)` - Validation error
    pub fn validate_non_empty(value: &str, field_name: &str) -> Result<(), ApiError> {
        if value.trim().is_empty() {
            return Err(ApiError::ValidationError {
                field: field_name.to_string(),
                reason: format!("{} cannot be empty", field_name),
            });
        }
        Ok(())
    }

    /// Validate an Ed25519 signature format (64 bytes, hex-encoded)
    ///
    /// # Arguments
    /// * `signature` - Hex-encoded signature (expected: 128 chars)
    /// * `field_name` - Field name for error messages
    ///
    /// # Returns
    /// * `Ok(())` - Signature format is valid
    /// * `Err(ApiError)` - Validation error
    pub fn validate_signature_format(signature: &str, _field_name: &str) -> Result<(), ApiError> {
        if signature.len() != 128 {
            return Err(ApiError::SignatureError {
                reason: format!(
                    "Signature must be 128 hex characters (64 bytes), got {}",
                    signature.len()
                ),
            });
        }

        if signature.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(ApiError::SignatureError {
                reason: "Signature contains invalid hex characters".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_public_key_valid() {
        let valid_hex = "0".repeat(64);
        let result = ValidationService::parse_public_key(&valid_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_parse_public_key_invalid_length() {
        let short_hex = "0".repeat(32);
        let result = ValidationService::parse_public_key(&short_hex);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "public_key");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_parse_public_key_invalid_hex() {
        let invalid_hex = "g".repeat(64);
        let result = ValidationService::parse_public_key(&invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_truth_value_valid() {
        assert!(ValidationService::validate_truth_value(0.0, "test").is_ok());
        assert!(ValidationService::validate_truth_value(0.5, "test").is_ok());
        assert!(ValidationService::validate_truth_value(1.0, "test").is_ok());
    }

    #[test]
    fn test_validate_truth_value_invalid() {
        assert!(ValidationService::validate_truth_value(-0.1, "test").is_err());
        assert!(ValidationService::validate_truth_value(1.1, "test").is_err());
        assert!(ValidationService::validate_truth_value(f64::NAN, "test").is_err());
        assert!(ValidationService::validate_truth_value(f64::INFINITY, "test").is_err());
    }

    #[test]
    fn test_validate_non_empty() {
        assert!(ValidationService::validate_non_empty("hello", "test").is_ok());
        assert!(ValidationService::validate_non_empty("  ", "test").is_err());
        assert!(ValidationService::validate_non_empty("", "test").is_err());
    }

    #[test]
    fn test_validate_signature_format_valid() {
        let valid_sig = "0".repeat(128);
        assert!(ValidationService::validate_signature_format(&valid_sig, "test").is_ok());
    }

    #[test]
    fn test_validate_signature_format_invalid_length() {
        let short_sig = "0".repeat(64);
        assert!(ValidationService::validate_signature_format(&short_sig, "test").is_err());
    }

    #[test]
    fn test_validate_signature_format_invalid_hex() {
        let invalid_sig = "g".repeat(128);
        assert!(ValidationService::validate_signature_format(&invalid_sig, "test").is_err());
    }
}
