//! Keyed LLM-agent identity (agent identity lineage design D1).
//!
//! The unkeyed identity seed `"llm-agent:{model}:{prompt_hash}"` is built from
//! public inputs, so anyone who can read an agent's prompt files can recompute
//! its private key. D1 keys the derivation with a 32-byte host secret:
//! `seed = blake3::keyed_hash(secret, "llm-agent:{model.trim()}:{prompt_hash}")`.
//!
//! The seed format is spelled out independently below, not read back from the
//! crate: the host side re-implements this derivation and must match it byte
//! for byte, so a silent change to the format has to fail here.

use epigraph_crypto::{
    keypair_from_llm_agent_keyed, keypair_from_llm_agent_prehashed, AgentSigner,
};

const SECRET_A: [u8; 32] = [0x41; 32];
const SECRET_B: [u8; 32] = [0x42; 32];
const MODEL: &str = "test-model-7";

fn prompt_hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// The key is exactly the Ed25519 key whose secret is the keyed BLAKE3 of the
/// documented seed string, with the model trimmed.
#[test]
fn keyed_derivation_is_the_keyed_blake3_of_the_documented_seed() {
    let hash = prompt_hash("identity files, concatenated");
    let seed = format!("llm-agent:{MODEL}:{hash}");
    let expected_secret = blake3::keyed_hash(&SECRET_A, seed.as_bytes());
    let expected = AgentSigner::from_bytes(expected_secret.as_bytes()).expect("32 bytes");

    let derived = keypair_from_llm_agent_keyed(&SECRET_A, &format!("  {MODEL}\n"), &hash);
    assert_eq!(
        derived.public_key(),
        expected.public_key(),
        "the keyed identity must be keyed_hash(secret, \"llm-agent:{{model.trim()}}:{{hash}}\")"
    );
}

/// A literal cross-implementation vector. The expected public key was
/// computed OUTSIDE this crate (Python `blake3` for the keyed hash, OpenSSL
/// for the Ed25519 seed-to-public step), so it also pins the Ed25519
/// convention: `AgentSigner::from_bytes` must treat the 32 bytes as an
/// RFC 8032 seed. The test above recomputes through the same functions as the
/// implementation and cannot see a change there; this one can. The host's
/// derivation (slice S4) asserts the same vector.
///
/// * secret: 32 bytes of 0x41
/// * model: `test-model-7` (passed padded, to pin the trim)
/// * prompt hash: BLAKE3 of `identity files, concatenated`
/// * seed input: `llm-agent:test-model-7:<prompt hash>`
#[test]
fn keyed_derivation_matches_the_literal_cross_implementation_vector() {
    const PROMPT_HASH: &str = "bf894787bd4ffd19eac89eb078b2e31fe03bb6c8a193812f6470745811153a91";
    const PUBLIC_KEY: &str = "ec8e33c03e1a31e8bfd30adb6169d972facb953cd75c3891e17ebea89e5b4002";
    assert_eq!(
        prompt_hash("identity files, concatenated"),
        PROMPT_HASH,
        "calibration: the prompt hash input is the documented one"
    );
    let derived = keypair_from_llm_agent_keyed(&SECRET_A, " test-model-7\t", PROMPT_HASH);
    let public_hex: String = derived
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(public_hex, PUBLIC_KEY);
}

/// Keying changes the identity: the same (model, hash) gives a different key
/// keyed than unkeyed, so a reader of the prompt files who computes the
/// unkeyed key does not hold the keyed one.
#[test]
fn keyed_derivation_differs_from_the_unkeyed_one() {
    let hash = prompt_hash("same files");
    let keyed = keypair_from_llm_agent_keyed(&SECRET_A, MODEL, &hash);
    let unkeyed = keypair_from_llm_agent_prehashed(MODEL, &hash);
    assert_ne!(keyed.public_key(), unkeyed.public_key());
}

/// Stable across calls for one secret, and a function of the secret: a second
/// secret gives a second identity for the same files.
#[test]
fn keyed_derivation_is_stable_per_secret_and_depends_on_it() {
    let hash = prompt_hash("stable files");
    let first = keypair_from_llm_agent_keyed(&SECRET_A, MODEL, &hash);
    let again = keypair_from_llm_agent_keyed(&SECRET_A, MODEL, &hash);
    let other_secret = keypair_from_llm_agent_keyed(&SECRET_B, MODEL, &hash);
    assert_eq!(first.public_key(), again.public_key());
    assert_eq!(first.secret_key(), again.secret_key());
    assert_ne!(first.public_key(), other_secret.public_key());
}

/// Both inputs still select the identity, as they do unkeyed.
#[test]
fn keyed_derivation_changes_with_model_or_prompt_hash() {
    let hash = prompt_hash("files v1");
    let base = keypair_from_llm_agent_keyed(&SECRET_A, MODEL, &hash);
    let other_model = keypair_from_llm_agent_keyed(&SECRET_A, "test-model-8", &hash);
    let other_files = keypair_from_llm_agent_keyed(&SECRET_A, MODEL, &prompt_hash("files v2"));
    assert_ne!(base.public_key(), other_model.public_key());
    assert_ne!(base.public_key(), other_files.public_key());
}
