//! Embedder routes mounted inside the kernel's authenticated router.
//!
//! A program that runs `epigraph-api` as a library, rather than the stock
//! binary, passes [`RouterExtension`]s to
//! [`crate::routes::create_router_with_extensions`]. Each is nested at
//! `/api/v1/ext/<name>` ([`EXTENSION_PREFIX`]); no first-party route is
//! registered under that prefix (`tests/router_extension_seam_lint.rs`), so a
//! kernel upgrade cannot collide with an extension.
//!
//! # What an extension route inherits
//!
//! It is mounted into the authenticated router before its layers are applied,
//! so it receives exactly what a first-party authenticated route receives:
//!
//! * bearer authentication, revocation included: a missing, malformed,
//!   expired or revoked token is refused 401 before the handler runs;
//! * the caller's `AuthContext` in the request extensions;
//! * (db builds) the per-access recorder: a token carrying an elevation claim
//!   is refused (`ELEVATED READ-ONLY`) any method but `GET`, `HEAD` and
//!   `OPTIONS`, and its reads are recorded, under the raw request path rather
//!   than a route template (`mount_all`'s doc says why). The refusal is keyed
//!   on the method, not on what the handler does: it keeps an elevated token
//!   from writing only if the extension never writes on those three methods
//!   (see "Read-only methods" below). `ELEVATED_NON_GET_ALLOWLIST` names
//!   first-party route templates, and an extension's raw request path never
//!   matches one, so an extension `POST` that only reads is refused for an
//!   elevated token too: fail-closed, by design;
//! * the request body limit (`ApiConfig::max_request_size`) and the rate
//!   limiter.
//!
//! # What it does NOT inherit — the embedder owns these
//!
//! * **Read-only methods.** An elevated token's `GET`, `HEAD` and `OPTIONS`
//!   requests reach the extension's handlers (recorded, not refused), on every
//!   path under the mount, unmatched ones included. A handler must never write
//!   on `GET`, `HEAD` or `OPTIONS`. That includes a `.fallback()` handler and
//!   an `any()` route, which answer every method, and a `get()` route, which
//!   also answers `HEAD`. First-party routes rest on reviewed method routers;
//!   nothing in this crate reviews an extension's.
//! * **Scopes.** Authentication is not authorization. Check scopes in the
//!   handler: `crate::middleware::check_scopes`, or a
//!   `crate::middleware::bearer::RequireScope*` extractor (generic over state).
//! * **Tenancy.** A kernel-state extension ([`RouterExtension::new`]) can take
//!   `ViewerExtractor` and read through the scoped pool. An own-state extension
//!   ([`RouterExtension::with_state`]) cannot, because `ViewerExtractor`
//!   requires `AppState`; it must apply its own visibility rules.
//! * **The crate's lints.** `no_unscoped_pool`, `public_router_allowlist` and
//!   the handler audits scan this crate's source only.
//! * **OpenAPI.** Extension routes are not listed in `/api/v1/openapi.json`.

use axum::Router;

use crate::state::AppState;

/// The prefix every extension is nested under: `/api/v1/ext/<name>`.
pub const EXTENSION_PREFIX: &str = "/api/v1/ext";

/// The longest extension name, in bytes.
const MAX_NAME_LEN: usize = 32;

/// Why an extension name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionNameError {
    #[error("router extension name is empty")]
    Empty,
    #[error("router extension name {0:?} is longer than 32 bytes")]
    TooLong(String),
    #[error("router extension name {0:?} must match [a-z][a-z0-9-]*")]
    InvalidCharacters(String),
}

/// An embedder-supplied router, mounted at `/api/v1/ext/<name>` inside the
/// authenticated router.
pub struct RouterExtension {
    name: String,
    router: Router<AppState>,
}

impl RouterExtension {
    /// An extension whose handlers take the kernel's `State<AppState>` (and so
    /// may use `ViewerExtractor`).
    ///
    /// # Errors
    /// [`ExtensionNameError`] when `name` is empty, longer than 32 bytes, or
    /// not `[a-z][a-z0-9-]*`.
    pub fn new(name: &str, router: Router<AppState>) -> Result<Self, ExtensionNameError> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_owned(),
            router,
        })
    }

    /// An extension whose handlers take the embedder's own state `S`. The state
    /// is bound here, so the kernel never sees `S`.
    ///
    /// # Errors
    /// As [`RouterExtension::new`].
    pub fn with_state<S>(
        name: &str,
        router: Router<S>,
        state: S,
    ) -> Result<Self, ExtensionNameError>
    where
        S: Clone + Send + Sync + 'static,
    {
        Self::new(name, router.with_state(state))
    }

    /// The validated name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where this extension is nested: `/api/v1/ext/<name>`.
    #[must_use]
    pub fn mount_path(&self) -> String {
        format!("{EXTENSION_PREFIX}/{}", self.name)
    }
}

fn validate_name(name: &str) -> Result<(), ExtensionNameError> {
    if name.is_empty() {
        return Err(ExtensionNameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ExtensionNameError::TooLong(name.to_owned()));
    }
    let mut bytes = name.bytes();
    let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
    let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(ExtensionNameError::InvalidCharacters(name.to_owned()))
    }
}

/// Panic if two extensions share a name. A second registration under one
/// prefix is a startup bug in the embedder, and refusing it loudly is the
/// contract axum applies to an overlapping route.
fn assert_unique_names(extensions: &[RouterExtension]) {
    let mut seen = std::collections::BTreeSet::new();
    for ext in extensions {
        assert!(
            seen.insert(ext.name.as_str()),
            "router extension {:?} is registered twice; each name mounts exactly one prefix",
            ext.name
        );
    }
}

/// Mount every extension into `protected` at its mount path, bound to `state`.
///
/// Called by `create_router_with_extensions` at the head of the statement that
/// applies the authenticated router's layers, so the mounted routes are
/// wrapped by them.
///
/// `nest_service`, not `nest`: axum 0.7's `nest` moves a nested router's custom
/// fallback into the outer router's fallback, which `route_layer` (the
/// per-access recorder) does not wrap. `nest_service` registers the prefix
/// and everything under it as ordinary routes, so the extension's fallback
/// runs inside both layers too.
///
/// The cost is in the audit record. Below the mount path, a request matches
/// the wildcard route `nest_service` registers, for which axum 0.7.9 inserts
/// `MatchedNestedPath`, not `MatchedPath`, so `record_elevated_access` finds
/// no route template and falls back to the raw request path (at the mount
/// path itself the template is that path, which comes to the same thing).
/// An elevated access through an extension is therefore
/// recorded with the surface `<METHOD> <request path>`: the concrete path,
/// ids included, not a template such as `GET /api/v1/claims/:id` (the query
/// string goes in the args, not the surface). Such surfaces do not group by
/// route and have unbounded cardinality; an auditor groups extension accesses
/// by the mount prefix instead.
///
/// # Panics
/// When two extensions share a name.
pub(crate) fn mount_all(
    protected: Router<AppState>,
    extensions: Vec<RouterExtension>,
    state: &AppState,
) -> Router<AppState> {
    assert_unique_names(&extensions);
    extensions.into_iter().fold(protected, |router, ext| {
        let path = ext.mount_path();
        router.nest_service(&path, ext.router.with_state(state.clone()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_lowercase_digits_and_hyphens() {
        for ok in ["eln", "e", "eln-2", "a0-b1", &"a".repeat(32)] {
            assert!(
                RouterExtension::new(ok, Router::new()).is_ok(),
                "{ok:?} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_each_bad_name_with_its_reason() {
        let cases: [(&str, ExtensionNameError); 7] = [
            ("", ExtensionNameError::Empty),
            ("Eln", ExtensionNameError::InvalidCharacters("Eln".into())),
            (
                "eln/x",
                ExtensionNameError::InvalidCharacters("eln/x".into()),
            ),
            ("..", ExtensionNameError::InvalidCharacters("..".into())),
            ("-x", ExtensionNameError::InvalidCharacters("-x".into())),
            ("1x", ExtensionNameError::InvalidCharacters("1x".into())),
            (
                "e\u{301}",
                ExtensionNameError::InvalidCharacters("e\u{301}".into()),
            ),
        ];
        for (name, want) in cases {
            assert_eq!(
                RouterExtension::new(name, Router::new()).err(),
                Some(want),
                "{name:?}"
            );
        }
        let long = "a".repeat(33);
        assert_eq!(
            RouterExtension::new(&long, Router::new()).err(),
            Some(ExtensionNameError::TooLong(long.clone()))
        );
    }

    #[test]
    fn with_state_validates_the_name_too() {
        #[derive(Clone)]
        struct Own;
        assert_eq!(
            RouterExtension::with_state("Bad", Router::<Own>::new(), Own).err(),
            Some(ExtensionNameError::InvalidCharacters("Bad".into()))
        );
        let ext = RouterExtension::with_state("eln", Router::<Own>::new(), Own)
            .expect("a legal name must still construct through with_state");
        assert_eq!(ext.name(), "eln");
        assert_eq!(ext.mount_path(), "/api/v1/ext/eln");
    }

    #[test]
    fn mount_path_is_under_the_reserved_prefix() {
        let ext = RouterExtension::new("eln", Router::new()).unwrap();
        assert_eq!(ext.mount_path(), "/api/v1/ext/eln");
        assert_eq!(ext.name(), "eln");
    }

    #[test]
    #[should_panic(expected = "router extension \"eln\" is registered twice")]
    fn duplicate_names_panic_with_the_name() {
        let a = RouterExtension::new("eln", Router::new()).unwrap();
        let other = RouterExtension::new("other", Router::new()).unwrap();
        let b = RouterExtension::new("eln", Router::new()).unwrap();
        assert_unique_names(&[a, other, b]);
    }

    #[test]
    fn distinct_names_pass_the_uniqueness_check() {
        let a = RouterExtension::new("eln", Router::new()).unwrap();
        let b = RouterExtension::new("eln-2", Router::new()).unwrap();
        assert_unique_names(&[a, b]);
    }
}
