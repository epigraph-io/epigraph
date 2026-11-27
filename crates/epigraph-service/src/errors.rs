//! The error a service operation returns, and how a front end classifies it.
//!
//! A service operation does not know which transport will answer it, so it
//! returns a [`ServiceError`] naming the CLASS of failure, and each front end
//! maps it onto its own error type:
//!
//! | [`ServiceError`]                     | MCP (JSON-RPC code) | HTTP ([`HttpClass`]) |
//! |--------------------------------------|---------------------|----------------------|
//! | [`InvalidParams`](ServiceError::InvalidParams) | `INVALID_PARAMS` | 400 |
//! | [`Denied`](ServiceError::Denied)     | `INVALID_REQUEST`   | 403                  |
//! | [`Internal`](ServiceError::Internal), [`InternalLogged`](ServiceError::InternalLogged), [`Fault`](ServiceError::Fault) | `INTERNAL_ERROR` | 500 |
//! | [`Repository`](ServiceError::Repository) | by the repository error | by [`repository_class`] |
//!
//! The mapping was the MCP crate's `errors::http_class` (backlog fff61b9e), which
//! classified a JSON-RPC error by its code so the MCP tools and their HTTP
//! twins (`epigraph-api`'s `routes::mcp_twins`) answer a refusal alike. It
//! lives here now so a front end that is not the MCP server can classify a
//! service error without depending on `epigraph-mcp`; `epigraph-mcp` re-exports
//! [`HttpClass`] and keeps classifying its own errors through it.
//!
//! # Why two variants carry the typed cause
//!
//! A front end decides what a caller may read of a fault, and how a repository
//! error is classified, from the error's TYPE (the MCP server's
//! `internal_error` forwards a coded database refusal and redacts everything
//! else; its `db_caller_error` turns an authority refusal into a denial). A
//! service operation that rendered the error into a string first would turn a
//! designed refusal into "internal error", so [`ServiceError::Repository`] and
//! [`ServiceError::Fault`] hand the error itself to the front end.

/// The failure of a service operation, by class.
///
/// The `String` of [`InvalidParams`](Self::InvalidParams),
/// [`Denied`](Self::Denied), [`Internal`](Self::Internal) and
/// [`InternalLogged`](Self::InternalLogged)'s `message` is the text the caller
/// reads: designed, caller-facing text, never a driver or provider error's
/// `Display` (which can name SQL, internal hosts or another tenant's rows).
/// The `Display` of [`Repository`](Self::Repository) and [`Fault`](Self::Fault)
/// IS the underlying error's, and is for the server log only: a front end maps
/// those two by type, never by forwarding their text.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The caller's input is wrong; a different request can succeed.
    #[error("{0}")]
    InvalidParams(String),
    /// A denial of authority: the request is well formed, but this caller may
    /// not do it. Not a server fault, and not something a parameter change
    /// fixes.
    #[error("{0}")]
    Denied(String),
    /// A server fault whose message is designed text, sent as written.
    #[error("{0}")]
    Internal(String),
    /// A server fault whose `message` (designed text) goes to the caller and
    /// whose `cause` (an error's rendering) goes to the server log only.
    #[error("{message}")]
    InternalLogged {
        /// What the caller reads.
        message: String,
        /// What the server log keeps.
        cause: String,
    },
    /// A repository error that may be the CALLER's (a repository refusal, a
    /// row the caller cannot see, an authority refusal), classified by the
    /// front end from its type; [`repository_class`] is the HTTP class.
    #[error(transparent)]
    Repository(epigraph_db::DbError),
    /// A repository or driver fault. The front end keeps its detail in the
    /// server log and answers a server fault, except for a refusal the
    /// codebase itself authored, which it may forward as written.
    #[error(transparent)]
    Fault(Fault),
}

/// The typed cause of a [`ServiceError::Fault`].
#[derive(Debug, thiserror::Error)]
pub enum Fault {
    /// A repository error.
    #[error(transparent)]
    Db(epigraph_db::DbError),
    /// A driver error (a pool that could not hand out a connection, say).
    #[error(transparent)]
    Sqlx(sqlx::Error),
}

impl ServiceError {
    /// The designed, caller-facing message, for the four variants that carry
    /// one; `None` for [`Repository`](Self::Repository) and
    /// [`Fault`](Self::Fault), whose text is the server log's.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::InvalidParams(m) | Self::Denied(m) | Self::Internal(m) => Some(m),
            Self::InternalLogged { message, .. } => Some(message),
            Self::Repository(_) | Self::Fault(_) => None,
        }
    }

    /// The [`HttpClass`] an HTTP front end answers this error with.
    #[must_use]
    pub fn http_class(&self) -> HttpClass {
        match self {
            Self::InvalidParams(_) => HttpClass::BadRequest,
            Self::Denied(_) => HttpClass::Forbidden,
            Self::Internal(_) | Self::InternalLogged { .. } | Self::Fault(_) => HttpClass::Internal,
            Self::Repository(e) => repository_class(e),
        }
    }
}

/// The [`HttpClass`] of a repository error a caller may have caused
/// ([`ServiceError::Repository`]): the classification the MCP server's
/// `visibility_caller_error` / `db_caller_error` make by JSON-RPC code, and
/// `epigraph-api`'s `From<DbError> for ApiError` by status.
///
/// * a repository refusal of the caller's input, a row the caller cannot see
///   (answered as missing), and invalid data: the caller's input, a 400;
/// * every other repository refusal, an authority refusal
///   ([`DbError::is_write_authority_refusal`](epigraph_db::DbError::is_write_authority_refusal)),
///   a write row security refused, and a coded supersede refusal: a denial,
///   a 403;
/// * anything else: a server fault, a 500.
#[must_use]
pub fn repository_class(e: &epigraph_db::DbError) -> HttpClass {
    use epigraph_db::errors::RefusalKind;
    use epigraph_db::DbError;
    match e {
        DbError::Refused {
            kind: RefusalKind::Input,
            ..
        }
        | DbError::NotFound { .. }
        | DbError::InvalidData { .. } => HttpClass::BadRequest,
        DbError::Refused { .. } | DbError::WriteRefused { .. } => HttpClass::Forbidden,
        e if e.is_write_authority_refusal() => HttpClass::Forbidden,
        DbError::QueryFailed {
            source: sqlx::Error::Database(db),
        } if epigraph_db::supersede_refusal_code(db.message()).is_some() => HttpClass::Forbidden,
        _ => HttpClass::Internal,
    }
}

/// How an HTTP front end answers a [`ServiceError`] (and, through
/// the MCP crate's `errors::http_class`, an MCP tool's error in an HTTP twin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    /// [`ServiceError::InvalidParams`] (`INVALID_PARAMS`): the caller's input
    /// is wrong; a 400.
    BadRequest,
    /// [`ServiceError::Denied`] (`INVALID_REQUEST`): a denial of authority; a
    /// 403.
    Forbidden,
    /// A server fault, and every code a front end does not classify; a 500.
    Internal,
}

/// The [`HttpClass`] of `e`.
#[must_use]
pub fn http_class(e: &ServiceError) -> HttpClass {
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
        assert_eq!(
            http_class(&ServiceError::InternalLogged {
                message: "fault".into(),
                cause: "driver text".into()
            }),
            HttpClass::Internal
        );
        assert_eq!(
            http_class(&ServiceError::Fault(Fault::Sqlx(sqlx::Error::PoolTimedOut))),
            HttpClass::Internal
        );
    }

    /// A repository error is classified by what it is: an authority refusal is
    /// a denial, a missing row the caller's input, and a connection fault a
    /// server fault.
    #[test]
    fn a_repository_error_is_classified_by_its_type() {
        use epigraph_db::errors::RefusalKind;
        use epigraph_db::DbError;
        let class = |e| ServiceError::Repository(e).http_class();
        assert_eq!(class(DbError::ElevatedReadOnly), HttpClass::Forbidden);
        assert_eq!(
            class(DbError::Refused {
                kind: RefusalKind::Input,
                message: "x".into()
            }),
            HttpClass::BadRequest
        );
        assert_eq!(
            class(DbError::Refused {
                kind: RefusalKind::Authority,
                message: "x".into()
            }),
            HttpClass::Forbidden
        );
        assert_eq!(
            class(DbError::NotFound {
                entity: "claim".into(),
                id: uuid::Uuid::nil()
            }),
            HttpClass::BadRequest
        );
        assert_eq!(
            class(DbError::QueryFailed {
                source: sqlx::Error::PoolTimedOut
            }),
            HttpClass::Internal
        );
    }

    /// The designed message is the caller-facing text, unchanged, in `Display`
    /// too; a fault's text is not a caller message.
    #[test]
    fn the_message_is_the_text_the_caller_reads() {
        for e in [
            ServiceError::InvalidParams("a".into()),
            ServiceError::Denied("b".into()),
            ServiceError::Internal("c".into()),
            ServiceError::InternalLogged {
                message: "d".into(),
                cause: "secret driver text".into(),
            },
        ] {
            assert_eq!(Some(e.to_string().as_str()), e.message());
        }
        assert_eq!(
            ServiceError::Fault(Fault::Sqlx(sqlx::Error::PoolTimedOut)).message(),
            None
        );
    }
}
