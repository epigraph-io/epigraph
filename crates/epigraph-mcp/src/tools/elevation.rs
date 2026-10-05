//! MCP `sudo` and `unsudo`, and who the manifest shows them to (elevation
//! plan EL-11; operator rulings D2 and D5).
//!
//! # What the two tools do
//!
//! * `sudo(reason)` opens a CONNECTOR-mode elevation ticket for the calling
//!   token's own principal, client and refresh family (migration 125's
//!   principal-bound `epigraph_create_elevation_ticket`, on a connection
//!   stamped with the caller's PLAIN scoped viewer) and returns ONLY the
//!   ceremony page's URL. The human opens it on the device that holds their
//!   passkey; once the ceremony lands, every later request of that family
//!   resolves elevated (read-only, recorded) for at most 15 minutes. No token,
//!   secret or session id is returned: a connector-mode ticket has no redeem
//!   secret, and the token endpoint refuses to redeem it.
//! * `unsudo()` ends the family's live elevation now
//!   (`epigraph_end_elevation`, reason `unsudo`): the session the token's
//!   elevation claim names, or the family's connector-mode session.
//!
//! # Who may (D2), and where it is served
//!
//! The DATABASE decides who may elevate: the ticket definer refuses (ELV02)
//! anyone who is not a registered human holding a LIVE assignment of an
//! elevating role, with a live passkey, on a live family of its own human
//! client. Agents never hold a role, so an agent's `sudo` is always refused.
//! Over stdio there is no token, no family and no principal of the caller's
//! own: both tools refuse.
//!
//! **Connector mode is OFF by default** (operator ruling: plan EQ-7 is unruled
//! and M-E2, whether one refresh family spans every chat of a connector
//! install, is unmeasured). Off, `sudo` refuses and points at the CLI elevate
//! path (`POST /api/v1/elevation/tickets` and the
//! `urn:epigraph:grant:elevate` grant), which is the served path. `unsudo`
//! is served either way: ending an elevation only ever narrows.
//!
//! # Neither tool acts AS the elevation
//!
//! `call_tool` does not resolve, strip or record these two at dispatch
//! ([`acts_on_the_elevation`]): `sudo` needs the family a not-elevated
//! request would have stripped, and `unsudo` would otherwise be recorded by
//! the session it just ended (refused, so its result withheld). Both stamp
//! the caller's plain scoped viewer (`Viewer::detach_scoped`), read no corpus
//! row and write only through 125's principal-bound definers.
//!
//! # The manifest (D2)
//!
//! [`listed`] is the one rule `list_tools` and `list_mcp_tools` apply: `sudo`
//! and `unsudo` are listed only to a principal that holds a live elevating
//! role (and `sudo` only while connector mode is on), and an admin-only-scoped
//! tool only to a request whose scope gate would admit it
//! (`AuthContext::has_scope`: armed, that is an elevated request).

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use rmcp::model::{CallToolResult, Content};

use crate::errors::McpError;
use crate::server::EpiGraphMcpFull;

/// The two tools that act ON the caller's elevation rather than AS it:
/// `call_tool` neither resolves nor strips their elevation at dispatch, and
/// never records them.
pub const ELEVATION_ACTS: &[&str] = &["sudo", "unsudo"];

/// The longest `sudo` reason accepted, in characters (the REST ticket
/// route's bound): it is shown on the ceremony page and kept in the audit
/// trail.
pub const MAX_REASON_CHARS: usize = 500;

/// Whether `tool` is one of [`ELEVATION_ACTS`].
#[must_use]
pub fn acts_on_the_elevation(tool: &str) -> bool {
    ELEVATION_ACTS.contains(&tool)
}

/// Who is asking for the manifest, as [`listed`] needs it.
#[derive(Debug, Clone, Copy)]
pub struct ManifestCaller<'a> {
    /// The HTTP transport (stdio: `false`).
    pub http: bool,
    /// The request's `AuthContext`, with the admin-scope switch and the
    /// database-checked elevation already stamped (`None` on stdio).
    pub auth: Option<&'a AuthContext>,
    /// Whether the principal holds a live elevating role (the database's
    /// answer; `false` when it could not be asked).
    pub holds_elevating_role: bool,
    /// Whether this server serves connector-mode elevation.
    pub connector_elevation: bool,
}

/// Whether `tool` is listed to `caller` (elevation plan EL-11).
///
/// * `sudo`: only over HTTP, to a holder of a live elevating role, while
///   connector mode is on (off, it could only refuse).
/// * `unsudo`: only over HTTP, to a holder of a live elevating role.
/// * An admin-only-scoped tool, over HTTP: only when the request's scope gate
///   would admit it (`has_scope`, which armed is "the request is elevated"
///   and unarmed is "the token carries the scope"). Over stdio, as before:
///   stdio has no scope gate.
/// * Everything else: listed. General per-scope filtering is out of scope.
#[must_use]
pub fn listed(tool: &str, caller: &ManifestCaller<'_>) -> bool {
    match tool {
        "sudo" => caller.http && caller.holds_elevating_role && caller.connector_elevation,
        "unsudo" => caller.http && caller.holds_elevating_role,
        _ => match crate::scope_map::required_scope(tool) {
            Some(scope) if caller.http && epigraph_auth::is_admin_only_scope(scope) => {
                caller.auth.is_some_and(|a| a.has_scope(scope))
            }
            _ => true,
        },
    }
}

/// Whether a token could belong to a principal that holds an elevating role:
/// a HUMAN client's token naming its principal. Only such a token is worth a
/// database round trip in [`EpiGraphMcpFull::holds_elevating_role`]; any
/// other answers `false` without asking (an agent never holds a role, CUS01,
/// and a non-human client's family can never be elevated).
#[must_use]
pub fn may_hold_an_elevating_role(auth: &AuthContext) -> bool {
    auth.client_type == ClientType::Human && auth.agent_id.is_some()
}

/// The two tools' transport gate: the HTTP `AuthContext`, or the refusal.
///
/// # Errors
/// `INVALID_REQUEST` on stdio (no `AuthContext`).
pub fn over_http<'a>(
    auth: Option<&'a AuthContext>,
    tool: &str,
) -> Result<&'a AuthContext, McpError> {
    auth.ok_or_else(|| {
        McpError::invalid_request(
            format!(
                "{tool} is served only over the HTTP transport with a bearer token: over stdio \
                 there is no token, no refresh family and no principal of the caller's own, and \
                 stdio never elevates"
            ),
            None,
        )
    })
}

/// The SQLSTATE a definer raised, and its message, when the error has one.
fn db_refusal(e: &epigraph_db::DbError) -> Option<(String, String)> {
    match e {
        epigraph_db::DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(|d| d.code().map(|c| (c.to_string(), d.message().to_string()))),
        _ => None,
    }
}

fn internal(tool: &str, what: &str, e: &dyn std::fmt::Display) -> McpError {
    tracing::error!(target: "elevation", tool, error = %e, "{what}");
    McpError::internal_error(format!("{tool}: could not {what}"), None)
}

/// The caller's PLAIN scoped viewer: both tools are the principal's acts,
/// never the elevation's.
fn as_principal(viewer: &Viewer, tool: &str) -> Result<Viewer, McpError> {
    viewer.detach_scoped().ok_or_else(|| {
        McpError::invalid_request(format!("{tool}: this request has no principal"), None)
    })
}

fn scoped<'a>(
    server: &'a EpiGraphMcpFull,
    tool: &str,
) -> Result<&'a epigraph_db::ScopedPool, McpError> {
    server.scoped.as_ref().ok_or_else(|| {
        McpError::internal_error(
            format!("{tool}: this server was not built with a tenancy-aware pool"),
            None,
        )
    })
}

fn json_result(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string(value).map_err(crate::errors::internal_error)?,
    )]))
}

/// `sudo(reason)`: open a connector-mode elevation ticket for the caller and
/// return the ceremony page's URL, and nothing else.
///
/// # Errors
/// `INVALID_REQUEST` when connector mode is off (the CLI path is the served
/// one), no public base URL is configured, the token names no refresh family,
/// the reason is missing or too long, the database refuses the principal
/// (ELV02) or the family is already elevated (ELV06).
pub async fn sudo(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    auth: &AuthContext,
    reason: &str,
) -> Result<CallToolResult, McpError> {
    if !server.connector_elevation {
        return Err(McpError::invalid_request(
            "sudo: connector-mode elevation is OFF on this server (the operator has not \
             enabled it). Elevate through the CLI path instead: POST /api/v1/elevation/tickets \
             with a reason, complete the passkey ceremony at the page it names, then redeem \
             the ticket at /oauth/token with grant_type=urn:epigraph:grant:elevate"
                .to_string(),
            None,
        ));
    }
    let Some(base) = server.public_base_url.as_deref() else {
        return Err(McpError::invalid_request(
            "sudo: this server has no public base URL configured (EPIGRAPH_PUBLIC_BASE_URL), \
             so it cannot name a ceremony page"
                .to_string(),
            None,
        ));
    };
    let family = auth.family_id.ok_or_else(|| {
        McpError::invalid_request(
            "sudo: this token names no refresh family; elevation needs a human token minted \
             together with a refresh token"
                .to_string(),
            None,
        )
    })?;
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(McpError::invalid_params(
            "sudo: a reason is required".to_string(),
            None,
        ));
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(McpError::invalid_params(
            format!("sudo: the reason is longer than {MAX_REASON_CHARS} characters"),
            None,
        ));
    }
    let mut tx = scoped(server, "sudo")?
        .begin_as(&as_principal(viewer, "sudo")?)
        .await
        .map_err(|e| internal("sudo", "begin a stamped transaction", &e))?;
    let ticket = match epigraph_db::ElevationCeremony::create_ticket(
        &mut tx,
        auth.client_id,
        family,
        reason,
        epigraph_db::TicketMode::Connector,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return Err(match db_refusal(&e) {
                Some((code, message)) if code == "ELV02" => {
                    tracing::info!(
                        target: "elevation",
                        principal = ?auth.agent_id,
                        client = %auth.client_id,
                        "sudo refused (ELV02)"
                    );
                    McpError::invalid_request(format!("sudo refused: {message}"), None)
                }
                Some((code, _)) if code == "ELV06" => McpError::invalid_request(
                    "sudo: this refresh family is already elevated; call unsudo first".to_string(),
                    None,
                ),
                Some((code, message)) if code == "22004" => McpError::invalid_params(message, None),
                _ => internal("sudo", "open the ticket", &e),
            })
        }
    };
    tx.commit()
        .await
        .map_err(|e| internal("sudo", "commit the ticket", &e))?;
    tracing::info!(
        target: "elevation",
        ticket = %ticket,
        principal = ?auth.agent_id,
        client = %auth.client_id,
        "elevation ticket opened (connector mode)"
    );
    json_result(&serde_json::json!({
        "url": format!("{}/elevate/{ticket}", base.trim_end_matches('/')),
    }))
}

/// `unsudo()`: end the caller's family's live elevation now. `{"ended":
/// false}` when there was nothing of the caller's to end (no oracle).
///
/// # Errors
/// `INVALID_REQUEST` when the token names no refresh family; internal errors
/// from the database.
pub async fn unsudo(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    auth: &AuthContext,
) -> Result<CallToolResult, McpError> {
    let family = auth.family_id.ok_or_else(|| {
        McpError::invalid_request(
            "unsudo: this token names no refresh family, so it has no elevation to end".to_string(),
            None,
        )
    })?;
    let mut tx = scoped(server, "unsudo")?
        .begin_as(&as_principal(viewer, "unsudo")?)
        .await
        .map_err(|e| internal("unsudo", "begin a stamped transaction", &e))?;
    // The session the request resolved, else the one its claim names, else
    // the family's connector-mode session whatever the switch says (ending
    // only ever narrows).
    let session = match viewer
        .elevation()
        .map(|e| e.session_id)
        .or(auth.elevation_claim)
    {
        Some(s) => Some(s),
        None => epigraph_db::ElevationCeremony::live(&mut tx, None, family)
            .await
            .map_err(|e| internal("unsudo", "find the family's elevation", &e))?
            .map(|l| l.session_id),
    };
    let ended = match session {
        Some(s) => epigraph_db::ElevationCeremony::end(&mut tx, s, epigraph_db::EndReason::Unsudo)
            .await
            .map_err(|e| internal("unsudo", "end the elevation", &e))?,
        None => false,
    };
    tx.commit()
        .await
        .map_err(|e| internal("unsudo", "commit the end", &e))?;
    tracing::info!(
        target: "elevation",
        principal = ?auth.agent_id,
        ended,
        "unsudo"
    );
    json_result(&serde_json::json!({ "ended": ended }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn auth(client_type: ClientType, scopes: &[&str], elevated: bool) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(Uuid::new_v4()),
            owner_id: None,
            client_type,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
            family_id: Some(Uuid::new_v4()),
            elevation_claim: None,
            elevation: elevated.then(|| epigraph_auth::ElevationRef {
                session_id: Uuid::new_v4(),
                family_id: Uuid::new_v4(),
            }),
            admin_scopes: epigraph_auth::AdminScopePosture::Armed,
        }
    }

    /// The dispatch exemption is EXACTLY the two elevation acts: any other
    /// tool is resolved, stripped and recorded as before. Mutation: a third
    /// name added (or the check answering true) -> this fails.
    #[test]
    fn only_sudo_and_unsudo_act_on_the_elevation() {
        assert_eq!(ELEVATION_ACTS, &["sudo", "unsudo"]);
        let all = EpiGraphMcpFull::all_tools_json();
        let mut exempt: Vec<&str> = all
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .filter(|n| acts_on_the_elevation(n))
            .collect();
        exempt.sort_unstable();
        assert_eq!(exempt, vec!["sudo", "unsudo"], "registered and exempt");
    }

    /// The listing rule, apart from the database: `sudo` needs HTTP, a holder
    /// and the connector switch; `unsudo` needs HTTP and a holder; an
    /// admin-only tool needs the scope gate's yes over HTTP (armed: an
    /// elevated request); stdio lists every admin tool and neither elevation
    /// act. Mutations: `sudo` listed regardless of the switch; the holder
    /// test dropped; admin tools listed to every HTTP caller.
    #[test]
    fn the_listing_rule() {
        let p = auth(ClientType::Human, &["claims:read"], false);
        let caller = |http, auth, holder, connector| ManifestCaller {
            http,
            auth,
            holds_elevating_role: holder,
            connector_elevation: connector,
        };
        assert!(listed("sudo", &caller(true, Some(&p), true, true)));
        assert!(
            !listed("sudo", &caller(true, Some(&p), true, false)),
            "switch off"
        );
        assert!(
            !listed("sudo", &caller(true, Some(&p), false, true)),
            "not a holder"
        );
        assert!(!listed("sudo", &caller(false, None, true, true)), "stdio");
        assert!(listed("unsudo", &caller(true, Some(&p), true, false)));
        assert!(!listed("unsudo", &caller(true, Some(&p), false, true)));
        assert!(!listed("unsudo", &caller(false, None, true, true)));

        // The scope `delete_edge` requires, read from SCOPE_MAP (an
        // admin-only one), so this test spells no admin scope itself.
        let admin = crate::scope_map::required_scope("delete_edge").expect("mapped");
        assert!(
            epigraph_auth::is_admin_only_scope(admin),
            "CALIBRATION: admin-only"
        );
        let standing = auth(ClientType::Human, &[admin], false);
        let elevated = auth(ClientType::Human, &["platform:admin"], true);
        assert!(
            !listed("delete_edge", &caller(true, Some(&standing), false, false)),
            "armed, a standing admin scope lists no admin tool"
        );
        assert!(
            listed("delete_edge", &caller(true, Some(&elevated), false, false)),
            "armed and elevated: listed"
        );
        let mut unarmed = standing.clone();
        unarmed.admin_scopes = epigraph_auth::AdminScopePosture::Unarmed;
        assert!(
            listed("delete_edge", &caller(true, Some(&unarmed), false, false)),
            "unarmed, the standing holder keeps it"
        );
        assert!(
            !listed("delete_edge", &caller(true, Some(&p), false, false)),
            "a caller without the scope never sees it"
        );
        assert!(
            listed("delete_edge", &caller(false, None, false, false)),
            "stdio"
        );
        assert!(listed("get_claim", &caller(true, Some(&p), false, false)));
    }

    /// Only a human client's token that names its principal is worth asking
    /// the database about. Mutation: answering true for an agent token.
    #[test]
    fn only_a_human_principal_may_hold_an_elevating_role() {
        assert!(may_hold_an_elevating_role(&auth(
            ClientType::Human,
            &[],
            false
        )));
        assert!(!may_hold_an_elevating_role(&auth(
            ClientType::Agent,
            &[],
            false
        )));
        assert!(!may_hold_an_elevating_role(&auth(
            ClientType::Service,
            &[],
            false
        )));
        let mut nameless = auth(ClientType::Human, &[], false);
        nameless.agent_id = None;
        assert!(!may_hold_an_elevating_role(&nameless));
    }
}
