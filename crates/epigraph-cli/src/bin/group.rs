//! `epigraph-group` — the client-side group key ceremony.
//!
//! This is the tool the group HTTP surface documents and assumes: it mints a
//! group's keys, wraps the group key for each member, unwraps a member's own
//! share, rotates the key, and re-wraps a share for a different holder. It
//! prints request bodies and hex blobs; it never talks to a server, and it
//! never talks to a database.
//!
//! # Why it holds no connection
//!
//! The server does not have, and must not acquire, group keys. Sealed content
//! is sealed *against* the operator of the database as much as against another
//! tenant, and that property survives exactly as long as the key never reaches
//! a process the operator controls. So this binary opens no pool, reads no
//! `DATABASE_URL`, and names no database type. The keys live wherever the
//! operator puts the output.
//!
//! # Key material on stdout
//!
//! Every secret this prints is a secret the caller must keep: there is nowhere
//! else for it to go. The struct `Debug` impls below redact, so key bytes
//! cannot reach a log through a stray trace, but a shell history and a
//! terminal scrollback are the caller's problem and the tool says so on
//! stderr.

use std::fmt;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use epigraph_crypto::{
    derive_epoch_key, ecdh_shared_secret, unwrap_group_key, wrap_group_key, DidKey,
    EncryptedPayload,
};
use epigraph_privacy::{rewrap_for_recipient, GroupRole, PrivacyError, ShareBinding};
use rand::RngCore;
use uuid::Uuid;

/// Redaction placeholder.
///
/// Spelled `<redacted>` rather than the bracketed upper-case form this codebase
/// used for its deleted response-blanking oracle. That spelling is banned in
/// production sources by `epigraph-api/tests/no_redaction_sentinel.rs`, whose
/// own doc comment anticipates this case: *"A crate with a legitimate unrelated
/// use (masking a secret in a log line, say) is not what this lint is about:
/// give the placeholder a different spelling."* Re-spelling is the fix the lint
/// asks for; narrowing its walk would trade a whole-tree property for one
/// crate's convenience.
const REDACTION: &str = "<redacted>";

/// A new group's cryptographic material.
struct GroupKeys {
    /// Random 32-byte base key for the group.
    base_key: [u8; 32],
    /// Epoch-0 derived key (ready for immediate use).
    epoch_key: [u8; 32],
    /// Starting epoch number (always 0 for new groups).
    epoch: u32,
}

impl fmt::Debug for GroupKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupKeys")
            .field("base_key", &REDACTION)
            .field("epoch_key", &REDACTION)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// The result of rotating a group key.
struct RotatedKeys {
    /// New random base key replacing the old one.
    new_base_key: [u8; 32],
    /// Derived key for the new epoch.
    new_epoch_key: [u8; 32],
    /// The new epoch number.
    new_epoch: u32,
}

impl fmt::Debug for RotatedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatedKeys")
            .field("new_base_key", &REDACTION)
            .field("new_epoch_key", &REDACTION)
            .field("new_epoch", &self.new_epoch)
            .finish()
    }
}

/// Generate fresh symmetric material for a new group.
fn create_group_keys() -> GroupKeys {
    let mut base_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut base_key);
    let epoch = 0u32;
    let epoch_key = derive_epoch_key(&base_key, epoch);
    GroupKeys {
        base_key,
        epoch_key,
        epoch,
    }
}

/// Wrap the group base key for one member, bound to `(group, epoch, member)`.
fn wrap_key_for_member(
    base_key: &[u8; 32],
    admin_signing_key: &SigningKey,
    member_verifying_key: &VerifyingKey,
    binding: ShareBinding,
) -> Result<EncryptedPayload, PrivacyError> {
    let shared = ecdh_shared_secret(admin_signing_key, member_verifying_key)?;
    Ok(wrap_group_key(
        base_key,
        &shared,
        binding.group_id,
        binding.epoch,
        binding.member_agent_id,
    )?)
}

/// Unwrap the group base key from a share issued to this member.
fn unwrap_key_as_member(
    wrapped: &EncryptedPayload,
    member_signing_key: &SigningKey,
    admin_verifying_key: &VerifyingKey,
    binding: ShareBinding,
) -> Result<[u8; 32], PrivacyError> {
    let shared = ecdh_shared_secret(member_signing_key, admin_verifying_key)?;
    Ok(unwrap_group_key(
        wrapped,
        &shared,
        binding.group_id,
        binding.epoch,
        binding.member_agent_id,
    )?)
}

/// Rotate the group key: an independent base key for `current_epoch + 1`.
///
/// The old base key is not an input — rotation produces an unrelated key, and
/// the caller must re-wrap it for every live member.
fn rotate_group_key(current_epoch: u32) -> Result<RotatedKeys, PrivacyError> {
    let new_epoch = current_epoch.checked_add(1).ok_or_else(|| {
        epigraph_crypto::CryptoError::EncryptionFailed {
            reason: "epoch counter overflow".to_string(),
        }
    })?;
    let mut new_base_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_base_key);
    let new_epoch_key = derive_epoch_key(&new_base_key, new_epoch);
    Ok(RotatedKeys {
        new_base_key,
        new_epoch_key,
        new_epoch,
    })
}

/// Convert an epoch as the API reports it into the width the crypto uses.
///
/// `group_key_epochs.epoch` is a signed 32-bit column with `CHECK (epoch >= 0)`
/// and every response carries it as `i32`; the AAD builders and
/// `derive_epoch_key` take `u32`. The conversion is total in the direction the
/// constraint allows and is refused in the direction it does not, rather than
/// wrapping a negative into a very large epoch that would silently derive a key
/// nobody else derives.
fn epoch_from_api(value: i32) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| {
        format!(
            "epoch must be >= 0 (the column's CHECK constraint admits nothing else), got {value}"
        )
    })
}

fn parse_key32(label: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("{label} is not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{label} must be 32 bytes, got {}", hex_str.trim().len() / 2))
}

fn parse_signing_key(label: &str, hex_str: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&parse_key32(label, hex_str)?))
}

fn parse_verifying_key(label: &str, hex_str: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&parse_key32(label, hex_str)?)
        .map_err(|e| format!("{label} is not a valid Ed25519 public key: {e}"))
}

fn parse_role(value: &str) -> Result<GroupRole, String> {
    GroupRole::from_db_str(value).ok_or_else(|| {
        format!(
            "invalid role '{value}'; the stored vocabulary is reader, writer, admin. \
             A role outside it is refused here rather than at INSERT time, after a \
             key share has already been produced for it."
        )
    })
}

#[derive(Parser)]
#[command(
    name = "epigraph-group",
    about = "Client-side group key ceremony: mint, wrap, unwrap, rotate, re-wrap",
    long_about = "Produces and consumes group key material on the caller's own machine. \
                  Opens no database connection and contacts no server: it prints the \
                  request bodies the group HTTP surface expects, and the operator sends them."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mint a new group: an Ed25519 group keypair plus the epoch-0 symmetric key.
    InitGroup {
        /// Group name, echoed into the POST /groups request body.
        #[arg(long)]
        name: String,
    },
    /// Wrap the group base key for a member; prints the POST members body.
    Wrap {
        /// Group base key (hex, 32 bytes).
        #[arg(long)]
        base_key: String,
        /// The wrapping admin's Ed25519 secret key (hex, 32 bytes).
        #[arg(long)]
        admin_secret: String,
        /// The member's Ed25519 public key (hex, 32 bytes).
        #[arg(long)]
        member_public: String,
        /// The group's id.
        #[arg(long)]
        group_id: Uuid,
        /// The key epoch this share is for, as the API reports it.
        #[arg(long)]
        epoch: i32,
        /// The member's agent id.
        #[arg(long)]
        member_agent_id: Uuid,
        /// Role to request: reader, writer or admin.
        #[arg(long, default_value = "reader")]
        role: String,
    },
    /// Unwrap the group base key from this member's own share.
    Unwrap {
        /// The wrapped share (hex, 60 bytes).
        #[arg(long)]
        wrapped_key_share: String,
        /// This member's Ed25519 secret key (hex, 32 bytes).
        #[arg(long)]
        member_secret: String,
        /// The wrapping admin's Ed25519 public key (hex, 32 bytes).
        #[arg(long)]
        admin_public: String,
        /// The group's id.
        #[arg(long)]
        group_id: Uuid,
        /// The key epoch the share was issued at.
        #[arg(long)]
        epoch: i32,
        /// This member's agent id.
        #[arg(long)]
        member_agent_id: Uuid,
    },
    /// Rotate: mint an independent base key for the next epoch.
    Rotate {
        /// The currently active epoch.
        #[arg(long)]
        current_epoch: i32,
    },
    /// Derive an epoch key from a base key.
    EpochKey {
        /// Group base key (hex, 32 bytes).
        #[arg(long)]
        base_key: String,
        /// Epoch to derive for.
        #[arg(long)]
        epoch: i32,
    },
    /// Re-wrap a share held by one agent for a different recipient.
    Rewrap {
        /// The share as issued to the holder (hex, 60 bytes).
        #[arg(long)]
        wrapped_key_share: String,
        /// The holder's Ed25519 secret key (hex, 32 bytes).
        #[arg(long)]
        holder_secret: String,
        /// The Ed25519 public key of whoever wrapped the holder's share.
        #[arg(long)]
        wrapped_by: String,
        /// Source binding: group id.
        #[arg(long)]
        from_group_id: Uuid,
        /// Source binding: epoch.
        #[arg(long)]
        from_epoch: i32,
        /// Source binding: member agent id.
        #[arg(long)]
        from_member_agent_id: Uuid,
        /// The recipient's Ed25519 public key (hex, 32 bytes).
        #[arg(long)]
        recipient_public: String,
        /// Destination binding: group id.
        #[arg(long)]
        to_group_id: Uuid,
        /// Destination binding: epoch.
        #[arg(long)]
        to_epoch: i32,
        /// Destination binding: member agent id.
        #[arg(long)]
        to_member_agent_id: Uuid,
        /// Role to request for the recipient: reader, writer or admin.
        ///
        /// Required in the emitted body for the same reason `wrap` needs it:
        /// the member route defaults an absent role to the least-privileged
        /// one, so a body without it is ACCEPTED and silently demotes whoever
        /// the share was re-wrapped for.
        #[arg(long, default_value = "reader")]
        role: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("epigraph-group: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::InitGroup { name } => {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            let group_signing = SigningKey::from_bytes(&seed);
            let group_public = group_signing.verifying_key();
            let keys = create_group_keys();

            eprintln!(
                "epigraph-group: this output contains secret key material. \
                 Store group_secret_key and base_key somewhere durable and private; \
                 neither can be recovered from the server."
            );
            Ok(pretty(&serde_json::json!({
                // Ready to POST to the group-creation endpoint. `did_key` is
                // derived from `group_public_key` server-side and is UNIQUE, so
                // this keypair identifies the group and must not be an
                // operator's own identity key.
                "create_group_request": {
                    "name": name,
                    "group_public_key": hex::encode(group_public.to_bytes()),
                },
                "did_key": DidKey::from_public_key(&group_public.to_bytes()).as_str(),
                "group_secret_key": hex::encode(group_signing.to_bytes()),
                "base_key": hex::encode(keys.base_key),
                "epoch": keys.epoch,
                "epoch_key": hex::encode(keys.epoch_key),
            })))
        }

        Command::Wrap {
            base_key,
            admin_secret,
            member_public,
            group_id,
            epoch,
            member_agent_id,
            role,
        } => {
            let role = parse_role(&role)?;
            let binding = ShareBinding::new(group_id, epoch_from_api(epoch)?, member_agent_id);
            let wrapped = wrap_key_for_member(
                &parse_key32("--base-key", &base_key)?,
                &parse_signing_key("--admin-secret", &admin_secret)?,
                &parse_verifying_key("--member-public", &member_public)?,
                binding,
            )
            .map_err(|e| e.to_string())?;

            Ok(pretty(&serde_json::json!({
                "add_member_request": {
                    "agent_id": member_agent_id,
                    "wrapped_key_share": hex::encode(wrapped.to_bytes()),
                    "role": role.as_db_str(),
                },
                "epoch": binding.epoch,
                "can_write": role.can_write(),
            })))
        }

        Command::Unwrap {
            wrapped_key_share,
            member_secret,
            admin_public,
            group_id,
            epoch,
            member_agent_id,
        } => {
            let binding = ShareBinding::new(group_id, epoch_from_api(epoch)?, member_agent_id);
            let base_key = unwrap_key_as_member(
                &parse_payload(&wrapped_key_share)?,
                &parse_signing_key("--member-secret", &member_secret)?,
                &parse_verifying_key("--admin-public", &admin_public)?,
                binding,
            )
            .map_err(|e| e.to_string())?;

            Ok(pretty(&serde_json::json!({
                "base_key": hex::encode(base_key),
                "epoch": binding.epoch,
                "epoch_key": hex::encode(derive_epoch_key(&base_key, binding.epoch)),
            })))
        }

        Command::Rotate { current_epoch } => {
            let rotated =
                rotate_group_key(epoch_from_api(current_epoch)?).map_err(|e| e.to_string())?;
            eprintln!(
                "epigraph-group: rotation does not revoke access to content already \
                 sealed under the retiring epoch. Re-wrap the new key for every live \
                 member before retiring the old epoch."
            );
            Ok(pretty(&serde_json::json!({
                "new_epoch": rotated.new_epoch,
                "new_base_key": hex::encode(rotated.new_base_key),
                "new_epoch_key": hex::encode(rotated.new_epoch_key),
            })))
        }

        Command::EpochKey { base_key, epoch } => {
            let epoch = epoch_from_api(epoch)?;
            let key = derive_epoch_key(&parse_key32("--base-key", &base_key)?, epoch);
            Ok(pretty(&serde_json::json!({
                "epoch": epoch,
                "epoch_key": hex::encode(key),
            })))
        }

        Command::Rewrap {
            wrapped_key_share,
            holder_secret,
            wrapped_by,
            from_group_id,
            from_epoch,
            from_member_agent_id,
            recipient_public,
            to_group_id,
            to_epoch,
            to_member_agent_id,
            role,
        } => {
            let role = parse_role(&role)?;
            let to = ShareBinding::new(to_group_id, epoch_from_api(to_epoch)?, to_member_agent_id);
            let rewrapped = rewrap_for_recipient(
                &parse_payload(&wrapped_key_share)?,
                &parse_signing_key("--holder-secret", &holder_secret)?,
                &parse_verifying_key("--wrapped-by", &wrapped_by)?,
                ShareBinding::new(
                    from_group_id,
                    epoch_from_api(from_epoch)?,
                    from_member_agent_id,
                ),
                &parse_verifying_key("--recipient-public", &recipient_public)?,
                to,
            )
            .map_err(|e| e.to_string())?;

            Ok(pretty(&serde_json::json!({
                "add_member_request": {
                    "agent_id": to_member_agent_id,
                    "wrapped_key_share": hex::encode(rewrapped.to_bytes()),
                    "role": role.as_db_str(),
                },
                "epoch": to.epoch,
                "can_write": role.can_write(),
            })))
        }
    }
}

/// Bytes a wrapped share must be on the wire: 12-byte nonce, 32-byte
/// ciphertext, 16-byte GCM tag. The member-addition route rejects any other
/// length outright, so a share that is not this long is refused here rather
/// than being sent and 400'd.
const WRAPPED_KEY_SHARE_BYTES: usize = 12 + 32 + 16;

fn parse_payload(hex_str: &str) -> Result<EncryptedPayload, String> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| format!("wrapped share is not hex: {e}"))?;
    if bytes.len() != WRAPPED_KEY_SHARE_BYTES {
        return Err(format!(
            "wrapped share must be {WRAPPED_KEY_SHARE_BYTES} bytes, got {}",
            bytes.len()
        ));
    }
    EncryptedPayload::from_bytes(&bytes).map_err(|e| format!("wrapped share is malformed: {e}"))
}

fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn binding() -> ShareBinding {
        ShareBinding::new(Uuid::new_v4(), 0, Uuid::new_v4())
    }

    // ---- the ported key-manager tests --------------------------------------

    #[test]
    fn test_create_group_keys() {
        let keys = create_group_keys();
        assert_eq!(keys.epoch, 0);
        assert_eq!(keys.epoch_key, derive_epoch_key(&keys.base_key, 0));
    }

    #[test]
    fn test_create_group_keys_randomness() {
        let k1 = create_group_keys();
        let k2 = create_group_keys();
        assert_ne!(
            k1.base_key, k2.base_key,
            "two groups must have different keys"
        );
    }

    #[test]
    fn test_wrap_unwrap_for_member() {
        let admin = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();
        let b = binding();

        let wrapped =
            wrap_key_for_member(&keys.base_key, &admin, &member.verifying_key(), b).unwrap();
        let recovered = unwrap_key_as_member(&wrapped, &member, &admin.verifying_key(), b).unwrap();

        assert_eq!(recovered, keys.base_key);
    }

    #[test]
    fn test_wrong_member_cannot_unwrap() {
        let admin = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let eve = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();
        let b = binding();

        let wrapped =
            wrap_key_for_member(&keys.base_key, &admin, &member.verifying_key(), b).unwrap();
        assert!(unwrap_key_as_member(&wrapped, &eve, &admin.verifying_key(), b).is_err());
    }

    #[test]
    fn test_rotate_group_key() {
        let initial = create_group_keys();
        let rotated = rotate_group_key(initial.epoch).unwrap();

        assert_eq!(rotated.new_epoch, 1);
        assert_ne!(rotated.new_base_key, initial.base_key);
        assert_eq!(
            rotated.new_epoch_key,
            derive_epoch_key(&rotated.new_base_key, rotated.new_epoch)
        );
    }

    #[test]
    fn test_rotate_preserves_epoch_sequence() {
        let r1 = rotate_group_key(0).unwrap();
        assert_eq!(r1.new_epoch, 1);
        let r2 = rotate_group_key(r1.new_epoch).unwrap();
        assert_eq!(r2.new_epoch, 2);
        let r3 = rotate_group_key(r2.new_epoch).unwrap();
        assert_eq!(r3.new_epoch, 3);
    }

    #[test]
    fn test_rotate_epoch_overflow_returns_error() {
        assert!(rotate_group_key(u32::MAX).is_err());
    }

    // The ported set had a ninth test, over a `get_epoch_key` wrapper that did
    // nothing but call `derive_epoch_key`. The wrapper is not carried across —
    // this binary calls `derive_epoch_key` directly — and with it gone the test
    // asserted that a function equals itself. Dropped rather than kept green.

    #[test]
    fn test_onboard_multiple_members() {
        let admin = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();
        let group_id = Uuid::new_v4();

        for _ in 0..3 {
            let member = SigningKey::generate(&mut OsRng);
            // Each member gets their OWN binding, which is the point: the three
            // shares are not interchangeable even though they wrap one key.
            let b = ShareBinding::new(group_id, 0, Uuid::new_v4());
            let wrapped =
                wrap_key_for_member(&keys.base_key, &admin, &member.verifying_key(), b).unwrap();
            let recovered =
                unwrap_key_as_member(&wrapped, &member, &admin.verifying_key(), b).unwrap();
            assert_eq!(recovered, keys.base_key);
        }
    }

    // ---- what this binary adds ---------------------------------------------

    #[test]
    fn the_debug_impls_do_not_render_key_bytes() {
        // Asserted as a property of the OUTPUT, not as the placeholder's
        // spelling: a test that pinned the spelling would have to contain it,
        // and the point is that no rendering of the struct contains the key.
        let keys = create_group_keys();
        let rendered = format!("{keys:?}");
        assert!(!rendered.contains(&format!("{:?}", keys.base_key)));
        assert!(!rendered.contains(&format!("{:?}", keys.epoch_key)));
        assert!(!rendered.contains(&hex::encode(keys.base_key)));
        assert!(
            rendered.contains("epoch: 0"),
            "non-secret fields still render"
        );

        let rotated = rotate_group_key(4).unwrap();
        let rendered = format!("{rotated:?}");
        assert!(!rendered.contains(&format!("{:?}", rotated.new_base_key)));
        assert!(!rendered.contains(&hex::encode(rotated.new_epoch_key)));
        assert!(rendered.contains("new_epoch: 5"));
    }

    #[test]
    fn a_wrapped_share_is_the_length_the_member_route_accepts() {
        let admin = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();

        let wrapped =
            wrap_key_for_member(&keys.base_key, &admin, &member.verifying_key(), binding())
                .unwrap();
        let hex_share = hex::encode(wrapped.to_bytes());

        assert_eq!(wrapped.to_bytes().len(), WRAPPED_KEY_SHARE_BYTES);
        assert_eq!(hex_share.len(), WRAPPED_KEY_SHARE_BYTES * 2);
        // And it round-trips through the parser this binary uses on the way back.
        assert!(parse_payload(&hex_share).is_ok());
    }

    #[test]
    fn the_epoch_seam_is_lossless_where_the_column_allows_it_and_refused_where_it_does_not() {
        // The API reports epochs as i32; the AAD and the KDF take u32. A known
        // byte vector, because a round trip through the conversion would not
        // notice a width or endianness change on the far side.
        assert_eq!(epoch_from_api(0).unwrap(), 0u32);
        assert_eq!(epoch_from_api(258).unwrap(), 258u32);
        assert_eq!(epoch_from_api(258).unwrap().to_le_bytes(), [2, 1, 0, 0]);
        assert_eq!(
            epoch_from_api(i32::MAX).unwrap().to_le_bytes(),
            [0xff, 0xff, 0xff, 0x7f]
        );
        assert!(epoch_from_api(-1).is_err());
        assert!(epoch_from_api(i32::MIN).is_err());
    }

    #[test]
    fn an_unstorable_role_is_refused_before_a_share_is_made_for_it() {
        assert_eq!(parse_role("reader").unwrap(), GroupRole::Reader);
        assert_eq!(parse_role("writer").unwrap(), GroupRole::Writer);
        assert_eq!(parse_role("admin").unwrap(), GroupRole::Admin);
        for bad in ["member", "creator", "Admin", "owner", ""] {
            assert!(parse_role(bad).is_err(), "role '{bad}' was accepted");
        }
    }

    #[test]
    fn the_init_group_public_key_is_what_the_creation_route_consumes() {
        // The route hex-decodes `group_public_key` to exactly 32 bytes and
        // derives the group's did:key from it. A ceremony that emitted anything
        // else would fail at the boundary, or worse, collide on the unique did.
        let out = run(Cli {
            command: Command::InitGroup {
                name: "fixture".to_string(),
            },
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();

        let pk = parsed["create_group_request"]["group_public_key"]
            .as_str()
            .unwrap();
        let bytes = hex::decode(pk).unwrap();
        assert_eq!(bytes.len(), 32);
        let arr = <[u8; 32]>::try_from(bytes.as_slice()).unwrap();
        assert!(VerifyingKey::from_bytes(&arr).is_ok());
        assert_eq!(
            parsed["did_key"].as_str().unwrap(),
            DidKey::from_public_key(&arr).as_str()
        );

        // The group keypair is the GROUP's, not an operator's identity: the
        // secret is emitted so the operator can keep it, and it must reproduce
        // the public key that was published.
        let secret = parse_signing_key(
            "group_secret_key",
            parsed["group_secret_key"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(secret.verifying_key().to_bytes(), arr);

        assert_eq!(parsed["epoch"].as_u64().unwrap(), 0);
    }

    #[test]
    fn the_wrap_subcommand_emits_a_body_the_member_route_would_accept() {
        let admin = SigningKey::generate(&mut OsRng);
        let member = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();
        let group_id = Uuid::new_v4();
        let member_agent_id = Uuid::new_v4();

        let out = run(Cli {
            command: Command::Wrap {
                base_key: hex::encode(keys.base_key),
                admin_secret: hex::encode(admin.to_bytes()),
                member_public: hex::encode(member.verifying_key().to_bytes()),
                group_id,
                epoch: 0,
                member_agent_id,
                role: "writer".to_string(),
            },
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let body = &parsed["add_member_request"];

        assert_eq!(body["role"].as_str().unwrap(), "writer");
        assert_eq!(
            body["agent_id"].as_str().unwrap(),
            member_agent_id.to_string()
        );
        let share = body["wrapped_key_share"].as_str().unwrap();
        assert_eq!(share.len(), WRAPPED_KEY_SHARE_BYTES * 2);

        // And the member can actually open it under the binding the request
        // implies — an emitted share that nobody can unwrap would look fine at
        // the boundary and fail on the member's machine.
        let recovered = unwrap_key_as_member(
            &parse_payload(share).unwrap(),
            &member,
            &admin.verifying_key(),
            ShareBinding::new(group_id, 0, member_agent_id),
        )
        .unwrap();
        assert_eq!(recovered, keys.base_key);
    }

    #[test]
    fn the_rewrap_subcommand_emits_the_role_too_and_the_recipient_can_open_it() {
        // The member route defaults an absent role to the least-privileged one,
        // so a re-wrap body without a role is accepted and quietly demotes the
        // recipient. Assert the field is present and carries what was asked
        // for, and that the emitted share opens under the destination binding —
        // a body that is well formed but unopenable fails on the recipient's
        // machine, where nobody is watching.
        let admin = SigningKey::generate(&mut OsRng);
        let holder = SigningKey::generate(&mut OsRng);
        let recipient = SigningKey::generate(&mut OsRng);
        let keys = create_group_keys();
        let group_id = Uuid::new_v4();
        let holder_agent_id = Uuid::new_v4();
        let recipient_agent_id = Uuid::new_v4();

        let held = wrap_key_for_member(
            &keys.base_key,
            &admin,
            &holder.verifying_key(),
            ShareBinding::new(group_id, 0, holder_agent_id),
        )
        .unwrap();

        let out = run(Cli {
            command: Command::Rewrap {
                wrapped_key_share: hex::encode(held.to_bytes()),
                holder_secret: hex::encode(holder.to_bytes()),
                wrapped_by: hex::encode(admin.verifying_key().to_bytes()),
                from_group_id: group_id,
                from_epoch: 0,
                from_member_agent_id: holder_agent_id,
                recipient_public: hex::encode(recipient.verifying_key().to_bytes()),
                to_group_id: group_id,
                to_epoch: 0,
                to_member_agent_id: recipient_agent_id,
                role: "admin".to_string(),
            },
        })
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let body = &parsed["add_member_request"];

        assert_eq!(body["role"].as_str().unwrap(), "admin");
        assert!(parsed["can_write"].as_bool().unwrap());
        assert_eq!(
            body["agent_id"].as_str().unwrap(),
            recipient_agent_id.to_string()
        );

        let share = body["wrapped_key_share"].as_str().unwrap();
        assert_eq!(share.len(), WRAPPED_KEY_SHARE_BYTES * 2);
        let recovered = unwrap_key_as_member(
            &parse_payload(share).unwrap(),
            &recipient,
            &holder.verifying_key(),
            ShareBinding::new(group_id, 0, recipient_agent_id),
        )
        .unwrap();
        assert_eq!(recovered, keys.base_key);

        // An unstorable role is refused before a share is produced for it, the
        // same way `wrap` refuses one.
        assert!(run(Cli {
            command: Command::Rewrap {
                wrapped_key_share: hex::encode(held.to_bytes()),
                holder_secret: hex::encode(holder.to_bytes()),
                wrapped_by: hex::encode(admin.verifying_key().to_bytes()),
                from_group_id: group_id,
                from_epoch: 0,
                from_member_agent_id: holder_agent_id,
                recipient_public: hex::encode(recipient.verifying_key().to_bytes()),
                to_group_id: group_id,
                to_epoch: 0,
                to_member_agent_id: recipient_agent_id,
                role: "creator".to_string(),
            },
        })
        .is_err());
    }

    #[test]
    fn a_negative_epoch_is_refused_by_every_subcommand_that_takes_one() {
        let err = run(Cli {
            command: Command::EpochKey {
                base_key: hex::encode([1u8; 32]),
                epoch: -1,
            },
        })
        .unwrap_err();
        assert!(err.contains("epoch must be >= 0"), "{err}");

        assert!(run(Cli {
            command: Command::Rotate { current_epoch: -5 },
        })
        .is_err());
    }

    #[test]
    fn malformed_hex_inputs_are_refused_with_the_flag_that_carried_them() {
        assert!(parse_key32("--base-key", "nothex").is_err());
        assert!(parse_key32("--base-key", &hex::encode([0u8; 31])).is_err());
        assert!(parse_verifying_key("--member-public", &hex::encode([0u8; 32])).is_ok());
        assert!(parse_payload(&hex::encode([0u8; 59])).is_err());
        assert!(parse_payload(&hex::encode([0u8; 61])).is_err());
    }

    #[test]
    fn the_cli_parses() {
        // clap's own invariants (duplicate flags, bad defaults) are checked at
        // build time only by this assertion.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
