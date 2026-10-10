//! THE MINT CHOKEPOINT for admin-only scopes (elevation plan EL-9, DESIGN
//! 6.5): every grant the token endpoint serves builds its token's scopes
//! through [`grantable`], and nowhere else.
//!
//! # What it decides
//!
//! * Every grant but the elevate grant drops `platform:admin` (only an
//!   elevated token carries it; `epigraph_auth::JwtConfig::issue_access_token`
//!   drops it too, the inner chokepoint).
//! * The admin-only scopes (`epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`)
//!   follow migration 128's switch:
//!   - ARMED: stripped from every token. An admin act then needs elevation.
//!   - UNARMED (the shipped state): kept, exactly as before, and the mint
//!     records one `oauth.admin_scope_would_strip` event (client, grant, the
//!     scopes an armed database would have stripped; at most one per client
//!     per hour, the database decides). Those events are the measurement that
//!     says when arming will break no one.
//!   - A database WITHOUT 128 (`AdminScopeSwitch::Absent`): kept, nothing
//!     recorded. Such a database cannot have been armed.
//!   - The switch cannot be READ (any other error): stripped, with a warning.
//!     Fail closed: a database that cannot answer "unarmed" does not hand out
//!     standing admin authority.
//! * The elevate grant keeps the client's READ scopes and adds
//!   `platform:admin` ([`crate::oauth::token::elevated_scopes`]), armed or
//!   not, and reads nothing: it reaches no database and, in particular, never
//!   the principal provisioning the other grants go through (elevation plan
//!   EL-5 hand-off).
//!
//! The switch is read only when the scopes about to be minted hold an
//! admin-only entry, so an ordinary mint costs nothing.
//!
//! A failure to RECORD the measurement only warns: the measurement is not
//! authority, and the mint proceeds unarmed.

// UNSCOPED-POOL-EXEMPT: Pre-authentication. The mint chokepoint runs inside token issuance,
// before the principal it mints exists; it reads one control row and records one measurement.

use epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES;

/// Every grant the token endpoint mints with. The label is what the would-strip
/// measurement names (migration 128 accepts exactly these labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintGrant {
    /// `grant_type=authorization_code` (the connector's code exchange).
    AuthorizationCode,
    /// `grant_type=refresh_token`.
    RefreshToken,
    /// `grant_type=client_credentials`, agent (Ed25519) and service (secret).
    ClientCredentials,
    /// An external identity provider's assertion grant (`google_id_token`,
    /// `cloudflare_access_jwt`, ...): `oauth/token.rs::handle_external_grant`.
    ExternalAssertion,
    /// The browser redirect exchange, `POST /oauth/{provider}/exchange`
    /// (`oauth/device.rs`): the provider's code is exchanged for an identity
    /// assertion and minted like [`Self::ExternalAssertion`].
    Device,
    /// `grant_type=urn:epigraph:grant:elevate`.
    Elevate,
}

impl MintGrant {
    /// The measurement's label for this grant.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::ExternalAssertion => "external_assertion",
            Self::Device => "device",
            Self::Elevate => "elevate",
        }
    }
}

/// The admin-only entries of `scopes`, each once, in order.
#[must_use]
pub fn admin_only_in(scopes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in scopes {
        if ADMIN_ONLY_SCOPES.contains(&s.as_str()) && !out.contains(s) {
            out.push(s.clone());
        }
    }
    out
}

/// Whether `scope` may be handed out only while the switch is unarmed: an
/// admin-only scope, or `platform:admin` (which no client may hold at all).
#[must_use]
pub fn is_admin_only(scope: &str) -> bool {
    ADMIN_ONLY_SCOPES.contains(&scope)
        || scope == epigraph_core::canonical_scopes::PLATFORM_ADMIN_SCOPE
}

/// The scopes `grant` may mint for the client whose `oauth_clients.id` is
/// `client`, from `scopes` (what the grant would otherwise mint: the client's
/// `granted_scopes`, the request's intersection with them, or a code's
/// consented set). See the module doc for every rule. Never fails: a failure
/// to read the switch strips, a failure to record warns.
#[cfg(feature = "db")]
pub async fn grantable(
    state: &crate::state::AppState,
    client: uuid::Uuid,
    scopes: Vec<String>,
    grant: MintGrant,
) -> Vec<String> {
    use epigraph_db::{AdminScopeEnforcement, AdminScopeSwitch};

    if grant == MintGrant::Elevate {
        return crate::oauth::token::elevated_scopes(&scopes);
    }
    let scopes = epigraph_auth::without_elevated_only_scope(scopes);
    let admin = admin_only_in(&scopes);
    if admin.is_empty() {
        return scopes;
    }
    let pool = &state.db_pool;
    match AdminScopeEnforcement::read(pool).await {
        Ok(AdminScopeSwitch::Armed) => {
            tracing::info!(
                client = %client,
                grant = grant.label(),
                stripped = ?admin,
                "admin-only scopes stripped at mint (admin-scope enforcement is armed)"
            );
            scopes.into_iter().filter(|s| !admin.contains(s)).collect()
        }
        Ok(AdminScopeSwitch::Unarmed) => {
            if let Err(e) =
                AdminScopeEnforcement::record_would_strip(pool, client, grant.label(), &admin).await
            {
                tracing::warn!(
                    client = %client,
                    grant = grant.label(),
                    error = %e,
                    "could not record the admin-scope would-strip measurement; minting unarmed"
                );
            }
            scopes
        }
        Ok(AdminScopeSwitch::Absent) => scopes,
        Err(e) => {
            tracing::warn!(
                client = %client,
                grant = grant.label(),
                error = %e,
                stripped = ?admin,
                "the admin-scope switch could not be read; admin-only scopes stripped (fail closed)"
            );
            scopes.into_iter().filter(|s| !admin.contains(s)).collect()
        }
    }
}

/// What a path that HANDS OUT scopes (client approval, registration's
/// request, the operator CLI's grant) may do with the admin-only ones it was
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandOut {
    /// None of the scopes is admin-only.
    Allowed,
    /// Unarmed (or no switch on this database): hand them out as before, and
    /// say so in the log. These are the admin-only scopes asked for.
    Warned(Vec<String>),
    /// Armed, or the switch could not be read (fail closed): refuse. These are
    /// the admin-only scopes asked for.
    Refused(Vec<String>),
}

/// Decide [`HandOut`] for `scopes` against migration 128's switch, read on
/// `pool` only when one of them is admin-only ([`is_admin_only`]: the
/// admin-only set plus `platform:admin`).
#[cfg(feature = "db")]
pub async fn hand_out(pool: &sqlx::PgPool, scopes: &[String]) -> HandOut {
    use epigraph_db::{AdminScopeEnforcement, AdminScopeSwitch};

    let mut admin: Vec<String> = Vec::new();
    for s in scopes {
        if is_admin_only(s) && !admin.contains(s) {
            admin.push(s.clone());
        }
    }
    if admin.is_empty() {
        return HandOut::Allowed;
    }
    match AdminScopeEnforcement::read(pool).await {
        Ok(AdminScopeSwitch::Armed) => HandOut::Refused(admin),
        Ok(AdminScopeSwitch::Unarmed | AdminScopeSwitch::Absent) => HandOut::Warned(admin),
        Err(e) => {
            tracing::warn!(
                error = %e,
                scopes = ?admin,
                "the admin-scope switch could not be read; refusing to hand out admin-only \
                 scopes (fail closed)"
            );
            HandOut::Refused(admin)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn admin_only_in_keeps_every_admin_scope_once_and_nothing_else() {
        let mut all: Vec<&str> = ADMIN_ONLY_SCOPES.to_vec();
        all.extend([
            "claims:read",
            "claims:write",
            "platform:admin",
            "claims:admin",
        ]);
        assert_eq!(admin_only_in(&v(&all)), v(ADMIN_ONLY_SCOPES));
        assert!(admin_only_in(&v(&["claims:read", "claims:admin "])).is_empty());
    }

    #[test]
    fn platform_admin_is_admin_only_for_handing_out() {
        assert!(is_admin_only("platform:admin"));
        for s in ADMIN_ONLY_SCOPES {
            assert!(is_admin_only(s), "{s}");
        }
        assert!(!is_admin_only("claims:read"));
    }

    #[test]
    fn every_label_but_elevate_is_one_migration_128_accepts() {
        // 128's recorder accepts exactly these labels (ADS03 otherwise).
        let accepted = [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "external_assertion",
            "device",
        ];
        for g in [
            MintGrant::AuthorizationCode,
            MintGrant::RefreshToken,
            MintGrant::ClientCredentials,
            MintGrant::ExternalAssertion,
            MintGrant::Device,
        ] {
            assert!(accepted.contains(&g.label()), "{g:?}");
        }
    }
}
