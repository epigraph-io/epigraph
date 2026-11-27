//! The boot-time rules for an operator-supplied RFC 9728 resource-metadata
//! URL, the value both kernel servers advertise in a 401's
//! `WWW-Authenticate: Bearer resource_metadata="..."` challenge (the HTTP
//! API's `EPIGRAPH_RESOURCE_METADATA_URL`, the MCP server's
//! `--resource-metadata-url`).
//!
//! # Why the header round trip alone is not enough
//!
//! Each server also builds the challenge the URL would produce and refuses a
//! value `http::HeaderValue` rejects (control characters, an embedded CR/LF).
//! That round trip does not check what it appears to: `HeaderValue`'s byte
//! predicate (`http` 1.x, `src/header/value.rs`) is
//! `b >= 32 && b != 127 || b == b'\t'`, so it **accepts every byte >= 0x80**.
//! `https://exämple.test/...` would pass, boot, and produce a non-ASCII
//! challenge that strict clients reject and `.to_str()` cannot decode. An
//! empty value would advertise `resource_metadata=""`, a TAB would produce a
//! malformed challenge, and a scheme-less value is unfetchable by the client
//! that reads it out of the challenge.
//!
//! [`resource_metadata_url_rule`] names which of those four rules a value
//! breaks. It runs BEFORE each server's own round trip, which stays in the
//! server (this crate has no `http` dependency) as the backstop for control
//! characters and header injection. Each server words its refusal itself,
//! because the message names the knob the operator set.

/// A rule an operator-supplied resource-metadata URL breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceMetadataUrlRule {
    /// The value is set but empty: the challenge would advertise
    /// `resource_metadata=""`.
    Empty,
    /// The value holds a byte >= 0x80, which `HeaderValue` accepts and strict
    /// clients reject.
    NonAscii,
    /// The value holds a TAB: a legal header byte, not a legal URL character.
    Tab,
    /// The value is not an absolute `http://` or `https://` URL.
    NotHttp,
}

/// The first rule `url` breaks, checked in the order empty, non-ASCII, TAB,
/// scheme; `None` when it breaks none of them (the caller's header round trip
/// still decides control characters).
#[must_use]
pub fn resource_metadata_url_rule(url: &str) -> Option<ResourceMetadataUrlRule> {
    if url.is_empty() {
        Some(ResourceMetadataUrlRule::Empty)
    } else if !url.is_ascii() {
        Some(ResourceMetadataUrlRule::NonAscii)
    } else if url.contains('\t') {
        Some(ResourceMetadataUrlRule::Tab)
    } else if !(url.starts_with("https://") || url.starts_with("http://")) {
        Some(ResourceMetadataUrlRule::NotHttp)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ResourceMetadataUrlRule::{Empty, NonAscii, NotHttp, Tab};

    #[test]
    fn each_rule_is_named_in_order() {
        for (url, want) in [
            ("https://api.example/.well-known/x", None),
            ("http://127.0.0.1:8080/.well-known/x", None),
            // Control characters are the header round trip's to refuse.
            ("https://api.example/\r\nX-Evil: 1", None),
            ("", Some(Empty)),
            ("https://exämple.test/.well-known/x", Some(NonAscii)),
            ("https://api.example/\tx", Some(Tab)),
            ("api.example/.well-known/x", Some(NotHttp)),
            ("/.well-known/x", Some(NotHttp)),
            ("ftp://api.example/x", Some(NotHttp)),
            ("HTTPS://api.example/x", Some(NotHttp)),
            // Order: non-ASCII before TAB before scheme.
            ("exä\tmple", Some(NonAscii)),
            ("api.example/\tx", Some(Tab)),
        ] {
            assert_eq!(resource_metadata_url_rule(url), want, "{url:?}");
        }
    }
}
