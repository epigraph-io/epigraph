//! Explicit, client-side cross-group re-wrap of a group key.
//!
//! One operation: unwrap a group key that was wrapped for holder A, then wrap
//! the same key for holder B. Both halves happen on the machine that already
//! holds A's private key; the plaintext group key exists only there, and only
//! for the duration of the call.
//!
//! # Why it takes two full bindings
//!
//! A wrapped share is bound to `(group_id, epoch, member_agent_id)`. A re-wrap
//! crosses that binding on purpose, so it must be told both sides of the
//! crossing: what the source share claims to be, and what the destination
//! share is to become. Passing one binding and reusing it for both would
//! silently produce a share for the wrong tuple — which is exactly the class of
//! mistake the binding exists to catch.
//!
//! # Why the peer is an Ed25519 verifying key
//!
//! Every agent in this system is identified by a 32-byte Ed25519 public key,
//! and the X25519 key used for agreement is derived from it by the birational
//! map in `epigraph_crypto::key_exchange`. Taking a raw X25519 key here would
//! mean either asking callers for a key the directory does not hold, or
//! re-implementing the agreement and its KDF alongside the one canonical
//! implementation. There is exactly one Diffie-Hellman path in this workspace,
//! and this module goes through it.
//!
//! # What this does not do
//!
//! It does not re-encrypt content, and it grants no capability the holder of
//! the source share did not already have: anyone who can run it can already
//! read the group key. It replaces the delegated-sharing module of the source
//! repository, which tried to be a policy mechanism and was not one.

use ed25519_dalek::{SigningKey, VerifyingKey};
use epigraph_crypto::{ecdh_shared_secret, unwrap_group_key, wrap_group_key, EncryptedPayload};
use uuid::Uuid;

use crate::errors::PrivacyError;

/// The tuple a wrapped share is bound to.
///
/// A share only unwraps under the exact binding it was produced for. The type
/// exists so that the three components of ONE binding cannot be transposed by
/// argument position — a `(group, epoch, member)` triple travels as a named
/// value rather than as three positional arguments. It does not prevent
/// transposing a source binding with a destination one: `from` and `to` are the
/// same type, and swapping them at a call site compiles. Such a call fails
/// closed, at the unwrap under `from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareBinding {
    /// The group whose key is wrapped.
    pub group_id: Uuid,
    /// The key epoch the wrapped key belongs to.
    pub epoch: u32,
    /// The agent the share is for.
    pub member_agent_id: Uuid,
}

impl ShareBinding {
    /// Construct a binding.
    #[must_use]
    pub const fn new(group_id: Uuid, epoch: u32, member_agent_id: Uuid) -> Self {
        Self {
            group_id,
            epoch,
            member_agent_id,
        }
    }
}

/// Unwrap a share held by A and re-wrap the same group key for B.
///
/// * `wrapped` — the share as stored for A, bound to `from`.
/// * `holder_signing_key` — A's identity key; the only secret this needs.
/// * `wrapped_by` — the verifying key of whoever produced `wrapped` (the admin
///   who onboarded A), required to re-derive the agreement that protects it.
/// * `from` / `to` — the source and destination bindings.
/// * `recipient` — B's Ed25519 verifying key.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if the source share does not unwrap under
/// `from` — a wrong holder, a wrong producer, or a share that was never bound
/// to that `(group, epoch, member)` — or if either key agreement is
/// non-contributory, or if the re-wrap fails.
pub fn rewrap_for_recipient(
    wrapped: &EncryptedPayload,
    holder_signing_key: &SigningKey,
    wrapped_by: &VerifyingKey,
    from: ShareBinding,
    recipient: &VerifyingKey,
    to: ShareBinding,
) -> Result<EncryptedPayload, PrivacyError> {
    let inbound = ecdh_shared_secret(holder_signing_key, wrapped_by)?;
    let group_key = unwrap_group_key(
        wrapped,
        &inbound,
        from.group_id,
        from.epoch,
        from.member_agent_id,
    )?;

    let outbound = ecdh_shared_secret(holder_signing_key, recipient)?;
    Ok(wrap_group_key(
        &group_key,
        &outbound,
        to.group_id,
        to.epoch,
        to.member_agent_id,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    struct Fixture {
        admin: SigningKey,
        alice: SigningKey,
        bob: SigningKey,
        group_key: [u8; 32],
        from: ShareBinding,
        share: EncryptedPayload,
    }

    fn fixture() -> Fixture {
        let admin = SigningKey::generate(&mut OsRng);
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let group_key = [21u8; 32];
        let from = ShareBinding::new(Uuid::new_v4(), 2, Uuid::new_v4());

        let secret = ecdh_shared_secret(&admin, &alice.verifying_key()).unwrap();
        let share = wrap_group_key(
            &group_key,
            &secret,
            from.group_id,
            from.epoch,
            from.member_agent_id,
        )
        .unwrap();

        Fixture {
            admin,
            alice,
            bob,
            group_key,
            from,
            share,
        }
    }

    #[test]
    fn the_recipient_recovers_the_same_group_key_under_the_new_binding() {
        let f = fixture();
        let to = ShareBinding::new(Uuid::new_v4(), 7, Uuid::new_v4());

        let rewrapped = rewrap_for_recipient(
            &f.share,
            &f.alice,
            &f.admin.verifying_key(),
            f.from,
            &f.bob.verifying_key(),
            to,
        )
        .unwrap();

        // Bob unwraps with his own key against Alice, who did the re-wrap.
        let secret = ecdh_shared_secret(&f.bob, &f.alice.verifying_key()).unwrap();
        let recovered = unwrap_group_key(
            &rewrapped,
            &secret,
            to.group_id,
            to.epoch,
            to.member_agent_id,
        )
        .unwrap();
        assert_eq!(recovered, f.group_key);
    }

    #[test]
    fn the_rewrapped_share_is_still_sixty_bytes() {
        let f = fixture();
        let to = ShareBinding::new(Uuid::new_v4(), 7, Uuid::new_v4());
        let rewrapped = rewrap_for_recipient(
            &f.share,
            &f.alice,
            &f.admin.verifying_key(),
            f.from,
            &f.bob.verifying_key(),
            to,
        )
        .unwrap();
        assert_eq!(rewrapped.to_bytes().len(), 12 + 32 + 16);
    }

    #[test]
    fn the_new_share_is_bound_to_the_destination_and_not_the_source() {
        let f = fixture();
        let to = ShareBinding::new(Uuid::new_v4(), 7, Uuid::new_v4());
        let rewrapped = rewrap_for_recipient(
            &f.share,
            &f.alice,
            &f.admin.verifying_key(),
            f.from,
            &f.bob.verifying_key(),
            to,
        )
        .unwrap();

        let secret = ecdh_shared_secret(&f.bob, &f.alice.verifying_key()).unwrap();
        let result = unwrap_group_key(
            &rewrapped,
            &secret,
            f.from.group_id,
            f.from.epoch,
            f.from.member_agent_id,
        );
        assert!(
            result.is_err(),
            "re-wrapped share still accepts the source binding"
        );
    }

    #[test]
    fn a_holder_who_was_not_the_one_wrapped_for_cannot_rewrap() {
        let f = fixture();
        let mallory = SigningKey::generate(&mut OsRng);
        let to = ShareBinding::new(Uuid::new_v4(), 7, Uuid::new_v4());

        let result = rewrap_for_recipient(
            &f.share,
            &mallory,
            &f.admin.verifying_key(),
            f.from,
            &f.bob.verifying_key(),
            to,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_misstated_source_binding_refuses_the_unwrap() {
        let f = fixture();
        let to = ShareBinding::new(Uuid::new_v4(), 7, Uuid::new_v4());
        let wrong_source =
            ShareBinding::new(f.from.group_id, f.from.epoch + 1, f.from.member_agent_id);

        let result = rewrap_for_recipient(
            &f.share,
            &f.alice,
            &f.admin.verifying_key(),
            wrong_source,
            &f.bob.verifying_key(),
            to,
        );
        assert!(result.is_err());
    }
}
