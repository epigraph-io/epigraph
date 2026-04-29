//! OAuth2 authorization server module.

pub mod device;
pub mod introspect;
pub mod jwt;
pub mod providers;
pub mod register;
pub mod revoke;
pub mod token;

pub use device::{auth_url_endpoint, exchange_endpoint};
pub use introspect::introspect_endpoint;
pub use jwt::{EpiGraphClaims, JwtConfig};
pub use register::{register_endpoint, RegisterRequest, RegisterResponse};
pub use revoke::revoke_endpoint;
pub use token::{token_endpoint, TokenRequest, TokenResponse};
