//! Group management endpoints for encrypted subgraphs.
//!
//! **Every route here is protected.** `GET /api/v1/groups/:id` was public until
//! PR-02; it now requires a bearer token carrying `groups:read` AND live
//! membership in the group. Group membership is the tenancy boundary, so its
//! roster and epoch state are not public metadata.
//!
//! | Route | Scope | Additional check |
//! |---|---|---|
//! | `POST /api/v1/groups` | `groups:write` | — (creator becomes sole admin) |
//! | `POST /api/v1/groups/:id/members` | `groups:admin` | `role='admin'` in this group |
//! | `DELETE /api/v1/groups/:id/members/:agent_id` | `groups:admin` | `role='admin'` in this group; not the last admin |
//! | `GET /api/v1/groups/:id` | `groups:read` | live member of this group |
//! | `POST /api/v1/groups/:id/rotate` | `groups:admin` | `role='admin'` in this group |
//!
//! The rotate route is spelled `/rotate`, which is what FINAL-PLAN §6.7, its
//! §6.5.7 interface table and its PR-20 *Files* line all say. Two comments in
//! this workspace previously wrote `/rotate-key`; that spelling was never
//! served by anything and has been corrected here and in `routes/mod.rs`.
//!
//! Scope AND membership, never OR: a `groups:admin` token must still be an
//! admin of the specific target group.

use crate::errors::ApiError;
use crate::middleware::bearer::{RequireScopeGroupsAdmin, RequireScopeGroupsWrite};
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use epigraph_db::{GroupKeyEpochRepository, GroupMembershipRepository, GroupRepository};
// Key rotation is client-side work with a server-side bookkeeping half. The
// client half ships: the `epigraph-group` binary mints the next epoch's key and
// re-wraps it for each member. PR-20 adds the server half below — `rotate_key`
// retires the outgoing epoch, creates the next one and admits the new shares in
// ONE transaction, and refuses a submission that does not cover every live
// member, because a rotation that advanced the epoch without the re-wrapped
// shares would strand them.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request to create a new encrypted group
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    /// Human-readable group name
    pub name: String,
    /// The GROUP's public key (hex-encoded, 32 bytes) — generated client-side
    /// in the `--init-group` ceremony, NOT the creator's identity key.
    ///
    /// Renamed from `creator_public_key` in PR-02 (the old name is still
    /// accepted). The old name was not merely misleading: `did_key` is derived
    /// from this value and `groups.did_key` is UNIQUE, so a client that
    /// honestly sent its own identity key could create exactly one group ever —
    /// the second attempt collided and surfaced as a 500.
    #[serde(alias = "creator_public_key")]
    pub group_public_key: String,
    /// Optional PRE public key for proxy re-encryption (hex-encoded)
    pub pre_public_key: Option<String>,
}

/// Response after creating a group (metadata only — keys generated client-side)
#[derive(Debug, Serialize)]
pub struct CreateGroupResponse {
    pub group_id: Uuid,
    /// DID key identifier for the group
    pub did_key: String,
    /// Starting epoch number
    pub epoch: u32,
}

/// Request to add a member to a group
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    /// Agent UUID to add
    pub agent_id: Uuid,
    /// Member's wrapped key share (hex-encoded encrypted payload)
    pub wrapped_key_share: String,
    /// Role: "admin", "writer", or "reader".
    ///
    /// BREAKING (PR-01): "member" is no longer accepted. It was never storable
    /// — `group_memberships_role_check` (migration 060) admits only
    /// admin|writer|reader — so a request that omitted `role`, or sent
    /// "member", passed route validation and then raised 23514, which
    /// `add_member` maps to HTTP 500. The default is the least-privileged role,
    /// matching the column DEFAULT.
    ///
    /// This vocabulary has FOUR homes that must agree, and
    /// `tests/group_lifecycle.rs::the_four_role_vocabularies_agree` pins them:
    /// `group_memberships_role_check`, the column DEFAULT, `valid_roles` in
    /// `add_member` below, and `middleware/group_authz.rs` (which accepts
    /// exactly `admin`).
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "reader".to_string()
}

/// Response after adding a member
#[derive(Debug, Serialize)]
pub struct AddMemberResponse {
    pub membership_id: Uuid,
    pub group_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    pub epoch: i32,
}

/// Response for group info
#[derive(Debug, Serialize)]
pub struct GroupInfoResponse {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub did_key: String,
    pub public_key: String,
    pub current_epoch: Option<i32>,
    pub member_count: usize,
    pub created_at: String,
    /// When a member removal last left this group owing a re-key and a re-seal
    /// (FINAL-PLAN §6.7), RFC 3339, or `null` when nothing is outstanding.
    ///
    /// Surfaced here because the obligation is the group admin's to discharge
    /// and they are the only principal who can: the server holds no group key.
    /// The `epigraph_groups_reseal_required` gauge is the operator-side view of
    /// the same column.
    pub reseal_required_at: Option<String>,
}

/// One member's re-wrapped share for the incoming epoch.
#[derive(Debug, Deserialize)]
pub struct RotateShare {
    /// The live member this share was wrapped for.
    pub agent_id: Uuid,
    /// The wrapped group key for `agent_id` at the NEW epoch (hex-encoded,
    /// 60 bytes: 12-byte nonce + 32-byte wrapped key + 16-byte GCM tag).
    pub wrapped_key_share: String,
}

/// Request to rotate a group's key epoch.
///
/// The server mints nothing. The `epigraph-group` CLI generates the next
/// epoch's base key locally and re-wraps it for each member; this request is
/// the result of that ceremony being submitted for bookkeeping.
///
/// The previous revision of this file declared a `RotateKeyResponse` carrying a
/// `new_epoch_key` the server was supposed to return. That type had no handler
/// and could never have one: by FINAL-PLAN §6.5.6 the server holds no group key
/// material, so there is no correct value for that field. It has been replaced
/// by these types rather than filled in.
///
/// It carries no escrow field, and an earlier revision of this PR added one.
/// See [`epigraph_db::GroupKeyEpochRepository::rotate_conn`] for why it was
/// withdrawn rather than validated: the recoverability gate must not be
/// satisfiable by a value the server cannot check.
#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    /// A re-wrapped share for EVERY live member, and for no one else.
    ///
    /// A partial roster is refused rather than partially applied: an epoch
    /// advance that skipped a member would leave them holding a share for a
    /// retired epoch and unable to read anything written after the rotation.
    pub shares: Vec<RotateShare>,
}

/// Response after key rotation.
#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub group_id: Uuid,
    /// The epoch that was retired.
    pub previous_epoch: i32,
    /// The epoch that is now active.
    pub new_epoch: i32,
    /// How many live memberships were re-wrapped at `new_epoch`.
    pub members_rewrapped: usize,
    /// FINAL-PLAN §6.7's disclosure, verbatim. See
    /// [`crate::tenancy_disclosure`] for why it is a constant and why it is
    /// carried on the response at all.
    pub revocation: &'static str,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Create a new encrypted group.
///
/// Persists group metadata, the epoch-0 row and the creator's own
/// `role='admin'` membership — no key material is generated or stored
/// server-side. The client generates the base key and epoch key locally in the
/// `--init-group` CLI ceremony.
///
/// Any principal holding `groups:write` may create a group and becomes its sole
/// admin by construction. That is why PR-18's privatization guard cannot treat
/// "is an admin of the target group" as an authorization condition — an
/// attacker manufactures a compliant group in one request.
pub async fn create_group(
    State(state): State<AppState>,
    RequireScopeGroupsWrite(auth_ctx): RequireScopeGroupsWrite,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<CreateGroupResponse>), ApiError> {
    // Unreachable for a token minted since PR-02 (`ensure_for_client` populates
    // the claim at every mint site), but explicit: a group with no admin is
    // permanently unadministrable, so refuse rather than create one.
    let creator = auth_ctx.agent_id.ok_or(ApiError::Forbidden {
        reason: "token carries no agent principal; re-authenticate to obtain one".to_string(),
    })?;

    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest {
            message: "Group name cannot be empty".to_string(),
        });
    }

    let public_key_bytes =
        hex::decode(&req.group_public_key).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex public key: {e}"),
        })?;

    let public_key_32: [u8; 32] =
        public_key_bytes
            .clone()
            .try_into()
            .map_err(|_| ApiError::BadRequest {
                message: format!(
                    "Public key must be 32 bytes, got {}",
                    public_key_bytes.len()
                ),
            })?;

    let pre_public_key_bytes = req
        .pre_public_key
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex PRE public key: {e}"),
        })?;

    let group_id = Uuid::new_v4();
    // `did:key:z<base58btc(0xed01 || pubkey)>` — the multibase form the kernel's
    // own parser accepts. This was `format!("did:key:{hex}")`, which
    // `DidKey::to_public_key` rejects outright (it requires the `did:key:z`
    // prefix), so no did emitted by this route could be read back by the code
    // that consumes it.
    let did_key = epigraph_crypto::DidKey::from_public_key(&public_key_32)
        .as_str()
        .to_string();

    // Group + epoch 0 + creator's admin membership, in ONE transaction. The
    // membership is what makes the caller's first `add_member` succeed; before
    // PR-02 no membership row was ever written, so `require_group_admin` 403'd
    // the creator on their own group.
    GroupRepository::create_with_admin(
        &state.db_pool,
        group_id,
        Some(req.name.trim()),
        &did_key,
        &public_key_bytes,
        pre_public_key_bytes.as_deref(),
        creator,
    )
    .await
    .map_err(|e| match e {
        // A repeat submission of the same group public key collides on
        // groups_did_key_key. That is a client error, not a server fault — it
        // used to surface as a 23505 -> HTTP 500.
        epigraph_db::DbError::DuplicateKey { .. } => ApiError::Conflict {
            reason: "A group with this public key already exists".to_string(),
        },
        // `groups.created_by_agent_id` FKs to `agents`, and `creator` comes
        // straight from the token. A hand-minted token, or an agent deleted
        // between mint and call, raises 23503 — a 403, not a 500. This is the
        // same case the `agent_id.ok_or(Forbidden)` guard above handles for
        // `None`; only the shape of the bad value differs.
        epigraph_db::DbError::ForeignKeyViolation { .. } => ApiError::Forbidden {
            reason: "token names an unknown agent principal".to_string(),
        },
        other => ApiError::DatabaseError {
            message: format!("Failed to create group: {other}"),
        },
    })?;

    tracing::info!(
        group_id = %group_id,
        creator_agent_id = %creator,
        "Created encrypted group (metadata only) with creator as admin"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateGroupResponse {
            group_id,
            did_key,
            epoch: 0,
        }),
    ))
}

/// Add a member to a group.
///
/// The caller must have already wrapped the group base key for the new member
/// using ECDH key exchange (`wrap_key_for_member`).
///
/// # Authorization
/// `groups:admin` scope AND a live `role='admin'` membership in this group.
/// Both, never either: the scope says the token class may manage groups, the
/// membership says which ones.
pub async fn add_member(
    State(state): State<AppState>,
    RequireScopeGroupsAdmin(auth_ctx): RequireScopeGroupsAdmin,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<AddMemberResponse>), ApiError> {
    crate::middleware::group_authz::require_group_admin(&auth_ctx, group_id, &state.db_pool)
        .await?;

    // Verify group exists
    let group = GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    // Validate role. MUST stay in lockstep with group_memberships_role_check
    // (migrations/060_group_tenancy_tables.sql); anything this list admits and
    // the CHECK rejects becomes a 23514 -> HTTP 500 instead of a 400.
    // The vocabulary also lives in group_authz.rs (which accepts exactly
    // "admin") and in the column DEFAULT.
    let valid_roles = ["admin", "writer", "reader"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(ApiError::BadRequest {
            message: format!(
                "Invalid role '{}'. Must be one of: {}",
                req.role,
                valid_roles.join(", ")
            ),
        });
    }

    // Decode and STRUCTURALLY validate the wrapped key share.
    //
    // A wrapped group key is `wrap_group_key`'s output on the wire: 12-byte
    // AES-GCM nonce + 32-byte key ciphertext + 16-byte GCM tag = exactly 60
    // bytes. `EncryptedPayload::from_bytes` alone only enforces >= 28, so a
    // truncated or padded share would be stored happily and fail at UNWRAP time
    // — on the member's machine, long after the admin who submitted it has
    // moved on. Reject at the boundary instead.
    //
    // Length is all this can check, and the residual is wider than it used to
    // be: a share is now bound to the group, the epoch and the member it was
    // wrapped for, and the server holds no key with which to verify any of the
    // three. A well-formed share bound to the wrong tuple is stored and fails
    // closed on the member's machine. That is the cost of the server never
    // holding a group key, not an oversight. Neither side verifies the tuple:
    // the operator supplies it to the ceremony tool, which contacts no server
    // and so cannot know the group's live state, and this route stamps the
    // membership row with the epoch it reads from the database.
    const WRAPPED_KEY_SHARE_BYTES: usize = 12 + 32 + 16;

    let wrapped_key_bytes =
        hex::decode(&req.wrapped_key_share).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex wrapped_key_share: {e}"),
        })?;

    if wrapped_key_bytes.len() != WRAPPED_KEY_SHARE_BYTES {
        return Err(ApiError::BadRequest {
            message: format!(
                "wrapped_key_share must be {WRAPPED_KEY_SHARE_BYTES} bytes \
                 (12-byte nonce + 32-byte wrapped key + 16-byte GCM tag), got {}",
                wrapped_key_bytes.len()
            ),
        });
    }
    epigraph_crypto::EncryptedPayload::from_bytes(&wrapped_key_bytes).map_err(|e| {
        ApiError::BadRequest {
            message: format!("wrapped_key_share is not a valid encrypted payload: {e}"),
        }
    })?;

    // Get current epoch. A group with no current epoch is a broken group — it
    // cannot have been created by `create_group` (which writes epoch 0 in the
    // same transaction), and pinning the new member to a fabricated epoch 0
    // would hand them a share that decrypts nothing. "Current" and not "active":
    // the row may be `rotating` while a removal's re-key obligation is
    // outstanding, and a newcomer is pinned to it in that state too.
    let current_epoch = GroupKeyEpochRepository::get_current_epoch(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query current epoch: {e}"),
        })?
        .ok_or_else(|| ApiError::Conflict {
            reason: "Group has no current key epoch; rotate or re-provision it \
                 before adding members"
                .to_string(),
        })?;

    let epoch = current_epoch.epoch;

    // Persist membership
    let membership_id = GroupMembershipRepository::add_member(
        &state.db_pool,
        group_id,
        req.agent_id,
        &wrapped_key_bytes,
        epoch,
        &req.role,
    )
    .await
    .map_err(|e| match e {
        // Same defect class this handler's `valid_roles` comment exists to
        // prevent, and which `create_group` and `remove_member` already fixed:
        // an ordinary client error surfacing as a 500. Adding an agent who is
        // already a live member violates the partial unique index
        // `group_memberships_one_live` (23505); naming an agent that does not
        // exist violates `group_memberships_agent_id_fkey` (23503).
        epigraph_db::DbError::DuplicateKey { .. } => ApiError::Conflict {
            reason: "Agent is already a live member of this group".to_string(),
        },
        epigraph_db::DbError::ForeignKeyViolation { .. } => ApiError::NotFound {
            entity: "Agent".to_string(),
            id: req.agent_id.to_string(),
        },
        other => ApiError::DatabaseError {
            message: format!("Failed to add member: {other}"),
        },
    })?;

    tracing::info!(
        group_id = %group_id,
        agent_id = %req.agent_id,
        role = %req.role,
        "Added member to group"
    );

    // Suppress unused variable warning for group row (used for existence check)
    let _ = group;

    Ok((
        StatusCode::CREATED,
        Json(AddMemberResponse {
            membership_id,
            group_id,
            agent_id: req.agent_id,
            role: req.role,
            epoch,
        }),
    ))
}

/// Remove a member from a group (revoke access).
///
/// Revocation alone does not re-key the group: the removed member can still
/// decrypt anything they already hold. PR-20 makes that obligation explicit —
/// `revoke_member_unless_last_admin` sets `groups.reseal_required_at` and moves
/// the group's current key epoch to `status = 'rotating'`, in the same
/// transaction as the revoke and only when a revoke actually happened. It
/// MARKS; it does not enqueue a re-seal, because re-sealing needs the group key
/// and by FINAL-PLAN §6.5.6 the server does not have one.
///
/// # Authorization
/// `groups:admin` scope AND a live `role='admin'` membership in this group.
/// Refuses (409) to remove the group's LAST live admin — that would leave the
/// group permanently unadministrable, since `require_group_admin` is the only
/// way in and there is no break-glass path.
pub async fn remove_member(
    State(state): State<AppState>,
    RequireScopeGroupsAdmin(auth_ctx): RequireScopeGroupsAdmin,
    Path((group_id, agent_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::group_authz::require_group_admin(&auth_ctx, group_id, &state.db_pool)
        .await?;

    // Verify group exists
    GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    // Last-admin guard AND the revoke, in ONE transaction, over rows the same
    // transaction locked before it decided.
    //
    // This was three separate round-trips on the pool — get_member_role, then
    // count_live_admins_excluding, then remove_member — guarded by the claim
    // that "a concurrent second removal is bounded by the fact that both would
    // have to pass this check against a roster that includes the other". That
    // was the reasoning error, not a bound: with admins A and B and one
    // concurrent DELETE for each, both DO pass, precisely because each sees the
    // other, and the group ends with zero admins — the exact outcome the guard
    // exists to prevent, with no break-glass path.
    //
    // Folding the three round-trips into one statement narrowed that window
    // but did not close it — an UPDATE locks the row it writes, not the rows
    // its WHERE clause reads. The repo function now locks the group's live
    // roster first; see its doc comment. This route is unchanged by that:
    // the three outcomes and their statuses are exactly as before.
    let outcome = GroupMembershipRepository::revoke_member_unless_last_admin(
        &state.db_pool,
        group_id,
        agent_id,
    )
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to remove member: {e}"),
    })?;

    match outcome {
        epigraph_db::RevokeOutcome::Revoked => {}
        epigraph_db::RevokeOutcome::LastAdmin => {
            return Err(ApiError::Conflict {
                reason: "Cannot remove the group's last admin; promote another member \
                     to admin first"
                    .to_string(),
            });
        }
        epigraph_db::RevokeOutcome::NotAMember => {
            return Err(ApiError::NotFound {
                entity: "GroupMembership".to_string(),
                id: format!("{group_id}/{agent_id}"),
            });
        }
    }

    tracing::info!(
        group_id = %group_id,
        agent_id = %agent_id,
        "Removed member from group"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Get group info including member count.
///
/// PROTECTED as of PR-02 (it was in the anonymous `public` router). Requires
/// `groups:read` AND live membership: the roster size and epoch state of a
/// tenancy boundary are not public metadata, and an anonymous caller could
/// previously enumerate every group on the instance by id.
pub async fn get_group(
    State(state): State<AppState>,
    axum::Extension(auth_ctx): axum::Extension<crate::middleware::bearer::AuthContext>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupInfoResponse>, ApiError> {
    crate::middleware::scopes::check_scopes(&auth_ctx, &["groups:read"])?;

    let agent_id = auth_ctx.agent_id.ok_or(ApiError::Forbidden {
        reason: "token carries no agent principal; re-authenticate to obtain one".to_string(),
    })?;

    // Membership is checked before existence is confirmed, so a non-member
    // learns nothing about whether the id names a real group.
    let is_member = GroupMembershipRepository::is_member(&state.db_pool, group_id, agent_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query membership: {e}"),
        })?;

    if !is_member {
        return Err(ApiError::Forbidden {
            reason: "Not a member of this group".to_string(),
        });
    }

    let group = GroupRepository::get_by_id(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query group: {e}"),
        })?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Group".to_string(),
            id: group_id.to_string(),
        })?;

    let members = GroupMembershipRepository::get_members(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query members: {e}"),
        })?;

    let current_epoch = GroupKeyEpochRepository::get_current_epoch(&state.db_pool, group_id)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to query current epoch: {e}"),
        })?;

    Ok(Json(GroupInfoResponse {
        id: group.id,
        display_name: group.display_name,
        did_key: group.did_key,
        public_key: hex::encode(&group.public_key),
        current_epoch: current_epoch.map(|e| e.epoch),
        member_count: members.len(),
        created_at: group.created_at.to_rfc3339(),
        reseal_required_at: group.reseal_required_at.map(|t| t.to_rfc3339()),
    }))
}

/// Rotate a group's key epoch: retire N, create N+1, re-wrap every live member.
///
/// FINAL-PLAN §6.7's server half. The client half is the `epigraph-group`
/// binary, which mints the next base key and re-wraps it per member; this route
/// accepts that ceremony's output and commits it atomically.
///
/// # Authorization
/// `groups:admin` scope AND a live `role='admin'` membership in this group.
/// Both, never either — the same rule as `add_member` and `remove_member`. The
/// membership half is checked ON THE ROTATION'S OWN TRANSACTION, so the
/// decision and the writes it authorises cannot be taken on different
/// connections.
///
/// # Why the whole body runs on `ScopedPool::begin_as`
///
/// Every table this touches — `group_key_epochs` and `group_memberships` —
/// carries a FORCEd RLS policy from migrations 077/079 that keys on the
/// connection's tenancy GUCs. A rotation on the raw application pool writes
/// correctly today (the connecting role still bypasses) and writes NOTHING from
/// §9.2 step 11d onward, with no error. It also keeps this file at the exact
/// site count `crates/epigraph-db/tests/no_unscoped_pool.rs` records for it —
/// that register is at its ceiling and a new raw-pool read here would be a
/// regression the ratchet exists to stop. Note the asymmetry this creates and
/// does not resolve: rotation is stamped, while the other four group routes
/// (including the removal that sets `reseal_required_at`) still run unstamped,
/// as all 391 unconverted sites do.
///
/// # The refusals, and why each is a refusal rather than a best effort
///
/// * **409, unrecoverable retiring key.** Retiring epoch N when nobody can
///   produce N's key strands every claim sealed under it, permanently. Either
///   the epoch row already carries a `wrapped_key` or the group names an
///   external `kms_key_ref`, or the rotation does not happen. This request
///   carries no key material of its own: a gate satisfiable by a value the
///   server cannot check is not a gate.
/// * **400, roster mismatch.** The submission must cover exactly the live
///   roster the transaction locked. A missing member would be advanced past a
///   key they do not hold; an extra share names someone who is not a member.
/// * **400, duplicate shares.** One agent named twice is two contradictory
///   answers to the same question, not a submission to disambiguate.
/// * **409, no current epoch.** A group with no `active` or `rotating` epoch is
///   broken, not rotatable.
///
/// The response carries §6.7's sentence verbatim. A caller who has just
/// rotated is precisely the caller most likely to believe they have revoked
/// something, and this is the moment to say that they have not.
///
/// # Errors
/// `403` scope or membership; `400` a malformed share or a roster mismatch;
/// `409` an unrecoverable retiring key or a group with no current epoch;
/// `500` a database fault or a process that was not built from a `ScopedPool`.
pub async fn rotate_key(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    RequireScopeGroupsAdmin(auth_ctx): RequireScopeGroupsAdmin,
    Path(group_id): Path<Uuid>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, ApiError> {
    // Same structural check `add_member` applies, for the same reason: length
    // is all the server can verify, and rejecting at the boundary beats failing
    // on the member's machine long after the admin has moved on.
    const WRAPPED_KEY_SHARE_BYTES: usize = 12 + 32 + 16;

    if req.shares.is_empty() {
        return Err(ApiError::BadRequest {
            message: "shares must carry a re-wrapped share for every live member; \
                      an empty rotation would strand the whole group"
                .to_string(),
        });
    }

    let mut shares: Vec<(Uuid, Vec<u8>)> = Vec::with_capacity(req.shares.len());
    for share in &req.shares {
        let bytes = hex::decode(&share.wrapped_key_share).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid hex wrapped_key_share for {}: {e}", share.agent_id),
        })?;
        if bytes.len() != WRAPPED_KEY_SHARE_BYTES {
            return Err(ApiError::BadRequest {
                message: format!(
                    "wrapped_key_share for {} must be {WRAPPED_KEY_SHARE_BYTES} bytes \
                     (12-byte nonce + 32-byte wrapped key + 16-byte GCM tag), got {}",
                    share.agent_id,
                    bytes.len()
                ),
            });
        }
        epigraph_crypto::EncryptedPayload::from_bytes(&bytes).map_err(|e| {
            ApiError::BadRequest {
                message: format!(
                    "wrapped_key_share for {} is not a valid encrypted payload: {e}",
                    share.agent_id
                ),
            }
        })?;
        shares.push((share.agent_id, bytes));
    }

    let scoped = state.scoped.as_ref().ok_or_else(|| {
        tracing::error!(
            target: "tenancy.scoped_write",
            handler = "groups::rotate_key",
            "rotation refused: this process was not built from a ScopedPool"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped transaction".to_string(),
        }
    })?;

    let mut tx = scoped.begin_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_write",
            error = %e,
            handler = "groups::rotate_key",
            "could not begin a viewer-stamped transaction"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped transaction".to_string(),
        }
    })?;

    crate::middleware::group_authz::require_group_admin_conn(&auth_ctx, group_id, &mut tx).await?;

    let outcome = GroupKeyEpochRepository::rotate_conn(&mut tx, group_id, &shares)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to rotate group key: {e}"),
        })?;

    // Every arm below except `Rotated` returns without committing, so the
    // transaction rolls back on drop and the refusal leaves no partial epoch.
    let (previous_epoch, new_epoch, members_rewrapped) = match outcome {
        epigraph_db::RotateOutcome::Rotated {
            previous_epoch,
            new_epoch,
            members_rewrapped,
        } => (previous_epoch, new_epoch, members_rewrapped),
        epigraph_db::RotateOutcome::NoCurrentEpoch => {
            return Err(ApiError::Conflict {
                reason: "Group has no current key epoch to retire; re-provision it \
                         rather than rotating"
                    .to_string(),
            });
        }
        epigraph_db::RotateOutcome::RetiringKeyUnrecoverable => {
            return Err(ApiError::Conflict {
                reason: "Refusing to retire an epoch whose key is not recoverable: the \
                         content sealed under it would become permanently unreadable. \
                         Record a `kms_key_ref` in the group's properties naming the \
                         external escrow that holds the base key, and retry."
                    .to_string(),
            });
        }
        epigraph_db::RotateOutcome::RosterMismatch { missing, unknown } => {
            return Err(ApiError::BadRequest {
                message: format!(
                    "shares must cover exactly the live roster: {} live member(s) have no \
                     share ({:?}) and {} submitted share(s) name a non-member ({:?})",
                    missing.len(),
                    missing,
                    unknown.len(),
                    unknown
                ),
            });
        }
        epigraph_db::RotateOutcome::DuplicateShares { agent_ids } => {
            return Err(ApiError::BadRequest {
                message: format!(
                    "shares names {} agent(s) more than once ({agent_ids:?}); two shares for one \
                     member is an ambiguity the server will not resolve by picking the last one",
                    agent_ids.len()
                ),
            });
        }
    };

    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit rotation: {e}"),
    })?;

    tracing::info!(
        group_id = %group_id,
        previous_epoch,
        new_epoch,
        members_rewrapped,
        "Rotated group key epoch"
    );

    Ok(Json(RotateKeyResponse {
        group_id,
        previous_epoch,
        new_epoch,
        members_rewrapped,
        revocation: crate::tenancy_disclosure::ROTATION_DOES_NOT_REVOKE_PAST_ACCESS,
    }))
}
