//! OAuth2 authorization server module.

pub mod authorize;
pub mod device;
pub mod introspect;
pub mod jwt;
pub mod metadata;
pub mod providers;
pub mod register;
pub mod revoke;
pub mod token;

pub use authorize::{authorize_endpoint, AuthorizeQuery};
#[cfg(feature = "db")]
pub use authorize::{callback_endpoint, consent_endpoint};
pub use device::{auth_url_endpoint, exchange_endpoint};
pub use introspect::introspect_endpoint;
pub use jwt::{EpiGraphClaims, JwtConfig};
pub use metadata::{authorization_server_metadata, protected_resource_metadata};
pub use register::{register_endpoint, RegisterRequest, RegisterResponse};
pub use revoke::revoke_endpoint;
pub use token::{token_endpoint, TokenRequest, TokenResponse};
