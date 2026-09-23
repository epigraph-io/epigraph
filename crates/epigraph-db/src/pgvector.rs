//! The one pgvector literal formatter.
//!
//! `pgvector` accepts a vector as a text literal of the form `[v1,v2,...]`,
//! cast with `$n::vector`. Every write of a claim or evidence vector goes
//! through a repo helper that takes `&[f32]` and calls this function, so no
//! route handler builds the literal itself (deferred-commitment key
//! `embed-on-write-helper`; `crates/epigraph-api/tests/embedding_write_path_lint.rs`
//! pins that).
//!
//! It lives here rather than in `epigraph-embeddings` because the repo helpers
//! that format and write the vector are in this crate, and `epigraph-db` does
//! not depend on `epigraph-embeddings`.

/// Format `vector` as a pgvector text literal: `"[0.1,0.2,0.3]"`.
///
/// Each component is written with `f32`'s `Display`, which round-trips: the
/// shortest decimal that parses back to the same `f32`. An empty slice formats
/// as `"[]"`, which pgvector rejects; callers never hold an empty embedding,
/// and a zero-dimension vector reaching SQL is an error worth surfacing.
#[must_use]
pub fn format_pgvector(vector: &[f32]) -> String {
    let mut out = String::with_capacity(vector.len() * 12 + 2);
    out.push('[');
    for (i, v) in vector.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&v.to_string());
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::format_pgvector;

    #[test]
    fn formats_the_bracketed_comma_list_pgvector_parses() {
        assert_eq!(format_pgvector(&[0.1, -0.25, 3.0]), "[0.1,-0.25,3]");
    }

    #[test]
    fn matches_the_join_based_spelling_it_replaced() {
        // Byte-for-byte what the eight private copies in epigraph-api produced,
        // so replacing them changes no statement's bind value.
        let v = [0.123_456_79_f32, 1e-7, -0.0, 42.5];
        let old = format!(
            "[{}]",
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(format_pgvector(&v), old);
    }

    #[test]
    fn a_single_component_has_no_separator() {
        assert_eq!(format_pgvector(&[0.5]), "[0.5]");
    }
}
