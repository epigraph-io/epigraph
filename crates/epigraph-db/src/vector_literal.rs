//! The one pgvector text literal formatter.
//!
//! Every embedding this workspace writes or searches with is bound as text and
//! cast in SQL (`$N::vector`). The text is `[v1,v2,...]`: each element in
//! Rust's shortest round-trip `Display` form, comma-separated, no spaces.
//! It used to be hand-written at a few dozen production sites under five names
//! (backlog b72be4e2). `embedding_stack_ratchet::pgvector_literals_come_from_one_helper`
//! in `epigraph-embeddings` keeps it that way.

use std::fmt::Write as _;

/// Format `v` as a pgvector text literal, `[v1,v2,...]`, for a `$N::vector` bind.
///
/// Elements use their `Display`, which for `f32` and `f64` is the shortest text
/// that parses back to the same value, so the database receives exactly the
/// vector the caller holds (pgvector stores `f32`; an `f64` input, such as a
/// caller-supplied theme centroid, is rounded by the cast, not here). A NaN or
/// infinite element renders as `NaN` / `inf`, which pgvector rejects at the
/// cast; callers embed provider output, which is always finite.
#[must_use]
pub fn pgvector_literal<T: std::fmt::Display>(v: &[T]) -> String {
    let mut out = String::with_capacity(v.len() * 12 + 2);
    out.push('[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Writing to a String cannot fail.
        let _ = write!(out, "{x}");
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::pgvector_literal;

    #[test]
    fn formats_comma_separated_without_spaces_in_brackets() {
        assert_eq!(pgvector_literal(&[0.1, -2.0, 3.5, 0.0]), "[0.1,-2,3.5,0]");
    }

    #[test]
    fn an_empty_vector_is_an_empty_literal() {
        assert_eq!(pgvector_literal::<f32>(&[]), "[]");
    }

    /// An `f64` centroid is formatted at `f64` precision, as the hand-written
    /// copy it replaced did; the `::vector` cast does the rounding.
    #[test]
    fn an_f64_vector_keeps_its_own_precision() {
        assert_eq!(
            pgvector_literal(&[0.1_f64, 1.0 / 3.0]),
            "[0.1,0.3333333333333333]"
        );
    }

    /// Every element survives the text round trip bit for bit, so what is stored
    /// is what the provider returned.
    #[test]
    fn every_element_round_trips_exactly() {
        let v: Vec<f32> = (0..1536_u16)
            .map(|i| (f32::from(i) * 0.618_034).sin() / 7.0)
            .chain([f32::MIN_POSITIVE, f32::MAX, -f32::MIN_POSITIVE, 1e-38])
            .collect();
        let text = pgvector_literal(&v);
        let inner = text
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .expect("brackets");
        let parsed: Vec<f32> = inner.split(',').map(|s| s.parse().expect("f32")).collect();
        assert_eq!(parsed.len(), v.len());
        for (a, b) in v.iter().zip(&parsed) {
            assert_eq!(a.to_bits(), b.to_bits(), "{a} did not round-trip");
        }
        assert!(!text.contains(' '), "pgvector literals carry no spaces");
    }
}
