//! The error a service operation returns, and how a front end classifies it.
//!
//! A service operation does not know which transport will answer it, so it
//! returns a [`ServiceError`] naming the CLASS of failure, and each front end
//! maps it onto its own error type:
//!
//! | [`ServiceError`]                    | MCP (JSON-RPC code) | HTTP ([`HttpClass`]) |
//! |-------------------------------------|---------------------|----------------------|
//! | [`InvalidParams`](ServiceError::InvalidParams) | `INVALID_PARAMS`  | 400 |
//! | [`Denied`](ServiceError::Denied)    | `INVALID_REQUEST`   | 403                  |
//! | [`Internal`](ServiceError::Internal) | `INTERNAL_ERROR`   | 500                  |
//!
//! The mapping was `epigraph_mcp::errors::http_class` (backlog fff61b9e), which
//! classified a JSON-RPC error by its code so the MCP tools and their HTTP
//! twins (`epigraph-api`'s `routes::mcp_twins`) answer a refusal alike. It
//! lives here now so a front end that is not the MCP server can classify a
//! service error without depending on `epigraph-mcp`; `epigraph-mcp` re-exports
//! [`HttpClass`] and keeps classifying its own errors through it.

/// The failure of a service operation, by class. The message is the text the
/// caller reads: designed, caller-facing text, never a driver or provider
/// error's `Display` (which can name SQL, internal hosts or another tenant's
/// rows; a front end keeps that in its server log).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// The caller's input is wrong; a different request can succeed.
    #[error("{0}")]
    InvalidParams(String),
    /// A denial of authority: the request is well formed, but this caller may
    /// not do it. Not a server fault, and not something a parameter change
    /// fixes.
    #[error("{0}")]
    Denied(String),
    /// A server fault.
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// The caller-facing message.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidParams(m) | Self::Denied(m) | Self::Internal(m) => m,
        }
    }

    /// The [`HttpClass`] an HTTP front end answers this error with.
    #[must_use]
    pub const fn http_class(&self) -> HttpClass {
        match self {
            Self::InvalidParams(_) => HttpClass::BadRequest,
            Self::Denied(_) => HttpClass::Forbidden,
            Self::Internal(_) => HttpClass::Internal,
        }
    }
}

/// How an HTTP front end answers a [`ServiceError`] (and, through
/// `epigraph_mcp::errors::http_class`, an MCP tool's error in an HTTP twin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    /// [`ServiceError::InvalidParams`] (`INVALID_PARAMS`): the caller's input
    /// is wrong; a 400.
    BadRequest,
    /// [`ServiceError::Denied`] (`INVALID_REQUEST`): a denial of authority; a
    /// 403.
    Forbidden,
    /// [`ServiceError::Internal`], and every code a front end does not
    /// classify: a server fault; a 500.
    Internal,
}

/// The [`HttpClass`] of `e`.
#[must_use]
pub const fn http_class(e: &ServiceError) -> HttpClass {
    e.http_class()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each class of service error maps to its own HTTP class: a caller error
    /// is a 400, a denial a 403, and a fault a 500, never a caller error.
    #[test]
    fn each_service_error_maps_to_its_own_http_class() {
        assert_eq!(
            http_class(&ServiceError::InvalidParams("bad".into())),
            HttpClass::BadRequest
        );
        assert_eq!(
            http_class(&ServiceError::Denied("not yours".into())),
            HttpClass::Forbidden
        );
        assert_eq!(
            http_class(&ServiceError::Internal("fault".into())),
            HttpClass::Internal
        );
    }

    /// The message is the caller-facing text, unchanged, in `Display` too.
    #[test]
    fn the_message_is_the_text_the_caller_reads() {
        for e in [
            ServiceError::InvalidParams("a".into()),
            ServiceError::Denied("b".into()),
            ServiceError::Internal("c".into()),
        ] {
            assert_eq!(e.to_string(), e.message());
        }
        assert_eq!(ServiceError::Denied("no".into()).message(), "no");
    }
}
