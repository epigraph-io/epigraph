//! Vector normalization utilities
//!
//! Provides functions to normalize embeddings to unit vectors,
//! ensuring consistent cosine similarity calculations.

use crate::errors::EmbeddingError;

/// Utility for normalizing embedding vectors
pub struct Normalizer;

impl Normalizer {
    /// Normalize a vector to unit length (L2 normalization)
    ///
    /// # Arguments
    /// * `vector` - The vector to normalize
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The normalized vector with magnitude 1.0
    /// * `Err(EmbeddingError::NormalizationError)` - If the vector is zero
    ///
    /// # Example
    /// ```rust,ignore
    /// let normalized = Normalizer::normalize(&[3.0, 4.0])?;
    /// // Result: [0.6, 0.8] (magnitude = 1.0)
    /// ```
    pub fn normalize(vector: &[f32]) -> Result<Vec<f32>, EmbeddingError> {
        let magnitude = Self::magnitude(vector);

        if magnitude < f32::EPSILON {
            return Err(EmbeddingError::NormalizationError);
        }

        Ok(vector.iter().map(|v| v / magnitude).collect())
    }

    /// Normalize a vector in place
    ///
    /// # Arguments
    /// * `vector` - The vector to normalize (mutated in place)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully normalized
    /// * `Err(EmbeddingError::NormalizationError)` - If the vector is zero
    pub fn normalize_in_place(vector: &mut [f32]) -> Result<(), EmbeddingError> {
        let magnitude = Self::magnitude(vector);

        if magnitude < f32::EPSILON {
            return Err(EmbeddingError::NormalizationError);
        }

        for v in vector.iter_mut() {
            *v /= magnitude;
        }

        Ok(())
    }

    /// Calculate the L2 magnitude of a vector
    ///
    /// # Arguments
    /// * `vector` - The vector
    ///
    /// # Returns
    /// The Euclidean length of the vector
    #[must_use]
    pub fn magnitude(vector: &[f32]) -> f32 {
        vector.iter().map(|v| v * v).sum::<f32>().sqrt()
    }

    /// Check if a vector is normalized (magnitude ~= 1.0)
    ///
    /// # Arguments
    /// * `vector` - The vector to check
    /// * `tolerance` - Maximum deviation from 1.0
    ///
    /// # Returns
    /// `true` if the vector's magnitude is within tolerance of 1.0
    #[must_use]
    pub fn is_normalized(vector: &[f32], tolerance: f32) -> bool {
        let mag = Self::magnitude(vector);
        (mag - 1.0).abs() < tolerance
    }

    /// Calculate cosine similarity between two vectors
    ///
    /// # Arguments
    /// * `a` - First vector (should be normalized)
    /// * `b` - Second vector (should be normalized)
    ///
    /// # Returns
    /// Cosine similarity in range [-1.0, 1.0]
    ///
    /// # Note
    /// For normalized vectors, this is simply the dot product.
    ///
    /// # Panics
    /// Panics if the two vectors have different dimensions.
    #[must_use]
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        assert_eq!(a.len(), b.len(), "Vectors must have same dimension");
        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }

    /// Calculate cosine distance (1 - `cosine_similarity`)
    ///
    /// # Arguments
    /// * `a` - First vector
    /// * `b` - Second vector
    ///
    /// # Returns
    /// Cosine distance in range [0.0, 2.0]
    #[must_use]
    pub fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
        1.0 - Self::cosine_similarity(a, b)
    }

    /// Format a vector as a pgvector string literal.
    ///
    /// Converts a slice of f32 to the format "[0.1,0.2,0.3,...]" expected by
    /// `PostgreSQL`'s pgvector extension.
    ///
    /// # Arguments
    /// * `vector` - The vector to format
    ///
    /// # Returns
    /// A string in pgvector format suitable for SQL queries
    ///
    /// # Example
    /// ```rust,ignore
    /// let vec = [0.1, 0.2, 0.3];
    /// let formatted = Normalizer::format_as_pgvector(&vec);
    /// assert_eq!(formatted, "[0.1,0.2,0.3]");
    /// ```
    #[must_use]
    pub fn format_as_pgvector(vector: &[f32]) -> String {
        format!(
            "[{}]",
            vector
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Parse a pgvector string representation to Vec<f32>.
    ///
    /// Converts a pgvector string literal "[0.1,0.2,0.3]" back to a Vec<f32>.
    ///
    /// # Arguments
    /// * `pgvector_str` - The pgvector string to parse
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The parsed vector
    /// * `Err(EmbeddingError)` - If parsing fails
    ///
    /// # Example
    /// ```rust,ignore
    /// let parsed = Normalizer::parse_pgvector("[0.1,0.2,0.3]")?;
    /// assert_eq!(parsed, vec![0.1, 0.2, 0.3]);
    /// ```
    pub fn parse_pgvector(pgvector_str: &str) -> Result<Vec<f32>, EmbeddingError> {
        let trimmed = pgvector_str.trim_start_matches('[').trim_end_matches(']');

        trimmed
            .split(',')
            .map(|s| {
                s.trim().parse::<f32>().map_err(|e| {
                    EmbeddingError::DatabaseError(format!("Invalid vector element: {e}"))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_simple() {
        let result = Normalizer::normalize(&[3.0, 4.0]).unwrap();
        assert!((result[0] - 0.6).abs() < 1e-6);
        assert!((result[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_zero_vector_fails() {
        let result = Normalizer::normalize(&[0.0, 0.0, 0.0]);
        assert!(matches!(result, Err(EmbeddingError::NormalizationError)));
    }

    #[test]
    fn test_is_normalized() {
        let normalized = Normalizer::normalize(&[1.0, 1.0, 1.0]).unwrap();
        assert!(Normalizer::is_normalized(&normalized, 1e-6));

        let not_normalized = vec![1.0, 2.0, 3.0];
        assert!(!Normalizer::is_normalized(&not_normalized, 1e-6));
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let v = Normalizer::normalize(&[1.0, 2.0, 3.0]).unwrap();
        let sim = Normalizer::cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = Normalizer::normalize(&[1.0, 0.0]).unwrap();
        let b = Normalizer::normalize(&[0.0, 1.0]).unwrap();
        let sim = Normalizer::cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn test_format_as_pgvector() {
        let vec = [0.1, 0.2, 0.3];
        let formatted = Normalizer::format_as_pgvector(&vec);
        assert!(formatted.starts_with('['));
        assert!(formatted.ends_with(']'));
        assert!(formatted.contains("0.1"));
        assert!(formatted.contains("0.2"));
        assert!(formatted.contains("0.3"));
    }

    #[test]
    fn test_format_as_pgvector_empty() {
        let vec: [f32; 0] = [];
        let formatted = Normalizer::format_as_pgvector(&vec);
        assert_eq!(formatted, "[]");
    }

    #[test]
    fn test_parse_pgvector_valid() {
        let parsed = Normalizer::parse_pgvector("[0.1,0.2,0.3]").unwrap();
        assert_eq!(parsed.len(), 3);
        assert!((parsed[0] - 0.1).abs() < 1e-6);
        assert!((parsed[1] - 0.2).abs() < 1e-6);
        assert!((parsed[2] - 0.3).abs() < 1e-6);
    }

    #[test]
    fn test_parse_pgvector_with_spaces() {
        let parsed = Normalizer::parse_pgvector("[ 0.1 , 0.2 , 0.3 ]").unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn test_pgvector_roundtrip() {
        let original = [0.123, 0.456, 0.789];
        let formatted = Normalizer::format_as_pgvector(&original);
        let parsed = Normalizer::parse_pgvector(&formatted).unwrap();

        for (a, b) in original.iter().zip(parsed.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }
}
