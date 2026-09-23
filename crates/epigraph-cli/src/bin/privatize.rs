//! `epigraph-privatize` — the client half of the D4 seal ceremony.
//!
//! FINAL-PLAN §6.5.6: seal is two-phase and client-driven, and **the server
//! never sees a key**. This binary is the other end of that sentence. It reads
//! a plan's seal manifest over HTTP, pads and encrypts every member of the
//! §6.5.4 trusted computing base under a key derived locally, and posts the
//! ciphertext back. Unseal is the mirror; reseal is an unseal under the retiring
//! epoch's key followed by a seal under the new one.
//!
//! # It talks HTTP, and holds no database connection
//!
//! Deliberately, for the reason `epigraph-group`'s header gives about key
//! material: the property seal buys is that the plaintext and the key never
//! coexist in a process the database operator controls. A CLI that opened a
//! pool would put the key one `DATABASE_URL` away from the rows it protects,
//! and would also have to reimplement §6.6's three authorization conditions,
//! which live in the route. So the authority is the bearer token, the
//! server-side checks are the server's, and this process holds exactly one
//! thing the server does not: the key.
//!
//! A consequence worth stating rather than discovering: it reads no
//! `DATABASE_URL` and therefore has nothing for
//! `epigraph-db/tests/no_unmaintained_dsn.rs` to require a maintenance fallback
//! for.
//!
//! # Key material on the command line
//!
//! `--base-key-hex` is accepted for scripting and is the wrong way to do this
//! in production: an argument is visible in `ps` and in a shell history.
//! `--base-key-file` reads the same 32 bytes from a file. Neither is a KMS;
//! §6.5.6's preferred custody is a KMS handle in
//! `groups.properties->>'kms_key_ref'`, and wiring one is deployment-specific
//! work this binary deliberately does not guess at.
//!
//! # What the plaintext encoding is, and why it is JSON
//!
//! `labels`, `properties` and an evidence row's `raw_content` are encrypted as
//! their JSON encodings rather than as bare bytes. For `raw_content` that is
//! load-bearing: the column is NULLABLE, and `null` and `""` are different
//! states a ciphertext of the empty string could not tell apart. Restoring a
//! NULL as an empty string would fail `evidence`'s own consumers quietly, so
//! the nullness rides inside the plaintext where the AAD authenticates it.

use std::process::ExitCode;

use base64::Engine as _;
use clap::{Parser, Subcommand};
use epigraph_crypto::{derive_epoch_key, EncryptedPayload};
use epigraph_privacy::{
    decrypt_content, encrypt_content, encryptor::FieldTag, pad, unpad, PAD_BUCKETS,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The client half of the D4 seal ceremony.
#[derive(Parser, Debug)]
#[command(name = "epigraph-privatize", version, about, long_about = None)]
struct Cli {
    /// Base URL of the EpiGraph API, e.g. `https://epigraph.example/`.
    #[arg(long, env = "EPIGRAPH_API")]
    api: String,
    /// Bearer token for an instance admin who also administers the plan's
    /// target group (FINAL-PLAN §6.6).
    #[arg(long, env = "EPIGRAPH_TOKEN")]
    token: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Seal an applied `mode='seal'` plan: manifest, encrypt, commit.
    Seal {
        /// The plan.
        #[arg(long)]
        plan: Uuid,
        /// The group base key, 64 hex characters.
        #[arg(
            long,
            env = "EPIGRAPH_GROUP_BASE_KEY",
            conflicts_with = "base_key_file"
        )]
        base_key_hex: Option<String>,
        /// A file holding the group base key as 64 hex characters.
        #[arg(long)]
        base_key_file: Option<std::path::PathBuf>,
    },
    /// Unseal a sealed plan: manifest, decrypt, commit the plaintext back.
    Unseal {
        /// The plan.
        #[arg(long)]
        plan: Uuid,
        /// The group base key the content was sealed under.
        #[arg(
            long,
            env = "EPIGRAPH_GROUP_BASE_KEY",
            conflicts_with = "base_key_file"
        )]
        base_key_hex: Option<String>,
        /// A file holding that key.
        #[arg(long)]
        base_key_file: Option<std::path::PathBuf>,
    },
    /// Re-seal after a key rotation: unseal under the old base key, then seal
    /// under the new one.
    ///
    /// This is §6.7 point 3's ceremony, and it is the only thing that lets
    /// `groups.reseal_required_at` be cleared: rotation retires an epoch
    /// without re-encrypting anything, so every ciphertext row stays bound to
    /// the retired epoch until it is moved by a key holder.
    Reseal {
        /// The plan.
        #[arg(long)]
        plan: Uuid,
        /// The base key the content is currently sealed under.
        #[arg(long, env = "EPIGRAPH_GROUP_OLD_BASE_KEY")]
        old_base_key_hex: String,
        /// The base key to re-seal under.
        #[arg(long, env = "EPIGRAPH_GROUP_BASE_KEY")]
        new_base_key_hex: String,
    },
}

// ---------------------------------------------------------------------------
// Wire types. Mirrors of `epigraph_api::routes::privatization`'s, declared here
// rather than imported: `epigraph-cli` does not depend on `epigraph-api`, and
// making it do so to share four structs would link the whole server into the
// tool that holds the key.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct SealManifest {
    epoch: i32,
    pad_to: i32,
    manifest_digest: String,
    next_cursor: Option<Uuid>,
    items: Vec<SealManifestEntry>,
}

#[derive(Deserialize, Debug)]
struct SealManifestEntry {
    claim_id: Uuid,
    content: String,
    labels: Vec<String>,
    properties: serde_json::Value,
    versions: Vec<ManifestVersion>,
    evidence: Vec<ManifestEvidence>,
}

#[derive(Deserialize, Debug)]
struct ManifestVersion {
    id: Uuid,
    content: String,
}

#[derive(Deserialize, Debug)]
struct ManifestEvidence {
    id: Uuid,
    raw_content: Option<String>,
    properties: serde_json::Value,
}

#[derive(Serialize, Debug)]
struct SealCommitRequest {
    manifest_digest: String,
    items: Vec<SealCommitEntry>,
}

#[derive(Serialize, Debug)]
struct SealCommitEntry {
    claim_id: Uuid,
    content_ct_b64: String,
    labels_ct_b64: String,
    properties_ct_b64: String,
    content_hash_b64: String,
    versions: Vec<CommitVersion>,
    evidence: Vec<CommitEvidence>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommitVersion {
    id: Uuid,
    ct_b64: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommitEvidence {
    id: Uuid,
    ct_b64: String,
    props_ct_b64: String,
}

#[derive(Deserialize, Debug)]
struct UnsealManifest {
    next_cursor: Option<Uuid>,
    items: Vec<UnsealManifestEntry>,
}

#[derive(Deserialize, Debug)]
struct UnsealManifestEntry {
    claim_id: Uuid,
    epoch: i32,
    pad_to: i32,
    content_ct_b64: String,
    labels_ct_b64: Option<String>,
    properties_ct_b64: Option<String>,
    versions: Vec<CommitVersion>,
    evidence: Vec<CommitEvidence>,
}

#[derive(Serialize, Debug)]
struct UnsealCommitRequest {
    items: Vec<UnsealCommitEntry>,
}

#[derive(Serialize, Debug)]
struct UnsealCommitEntry {
    claim_id: Uuid,
    content: String,
    content_hash_b64: String,
    labels: Vec<String>,
    properties: serde_json::Value,
    versions: Vec<UnsealCommitVersion>,
    evidence: Vec<UnsealCommitEvidence>,
}

#[derive(Serialize, Debug)]
struct UnsealCommitVersion {
    id: Uuid,
    content: String,
}

#[derive(Serialize, Debug)]
struct UnsealCommitEvidence {
    id: Uuid,
    raw_content: Option<String>,
    properties: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct CommitResponse {
    committed: usize,
    already_done: usize,
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("epigraph-privatize: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<String, String> {
    let client = reqwest::Client::new();
    let ctx = Ctx {
        client,
        api: cli.api.trim_end_matches('/').to_string(),
        token: cli.token,
    };

    match cli.command {
        Command::Seal {
            plan,
            base_key_hex,
            base_key_file,
        } => {
            let key = load_base_key(base_key_hex.as_deref(), base_key_file.as_deref())?;
            let (claims, already) = seal_plan(&ctx, plan, &key).await?;
            Ok(format!(
                "sealed {claims} claim(s); {already} already carried ciphertext"
            ))
        }
        Command::Unseal {
            plan,
            base_key_hex,
            base_key_file,
        } => {
            let key = load_base_key(base_key_hex.as_deref(), base_key_file.as_deref())?;
            let (claims, already) = unseal_plan(&ctx, plan, &key).await?;
            Ok(format!(
                "unsealed {claims} claim(s); {already} were already plaintext"
            ))
        }
        Command::Reseal {
            plan,
            old_base_key_hex,
            new_base_key_hex,
        } => {
            let old = parse_base_key(&old_base_key_hex)?;
            let new = parse_base_key(&new_base_key_hex)?;
            // ORDER MATTERS AND THERE IS A WINDOW. Between the unseal and the
            // seal the plaintext is on the server. That window is unavoidable
            // — the server cannot transcode a ciphertext it cannot read — and
            // it is why §6.7 calls reseal an operator-initiated ceremony rather
            // than an automatic consequence of rotation. Run it when you can
            // watch it.
            let (unsealed, _) = unseal_plan(&ctx, plan, &old).await?;
            let (sealed, _) = seal_plan(&ctx, plan, &new).await?;
            Ok(format!(
                "resealed: {unsealed} claim(s) unsealed under the old key, {sealed} re-sealed \
                 under the new one"
            ))
        }
    }
}

/// Everything a request needs.
struct Ctx {
    client: reqwest::Client,
    api: String,
    token: String,
}

impl Ctx {
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{path}", self.api);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        decode(resp, &url).await
    }

    async fn post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let url = format!("{}{path}", self.api);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        decode(resp, &url).await
    }
}

/// Turn a response into `T`, or into a message that carries the server's own.
///
/// The server's refusals are the interesting output of this tool — a `409` on a
/// stale manifest digest and a `400` on a missing TCB member are both things the
/// operator must read, not a generic "request failed".
async fn decode<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    url: &str,
) -> Result<T, String> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("{url}: could not read the response body: {e}"))?;
    if !status.is_success() {
        return Err(format!("{url}: HTTP {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("{url}: unexpected response shape: {e}"))
}

/// Seal every page of a plan.
async fn seal_plan(ctx: &Ctx, plan: Uuid, base_key: &[u8; 32]) -> Result<(usize, usize), String> {
    let mut cursor: Option<Uuid> = None;
    let (mut committed, mut already) = (0usize, 0usize);

    loop {
        let path = manifest_path(plan, "seal-manifest", cursor);
        let page: SealManifest = ctx.get(&path).await?;
        if page.items.is_empty() {
            break;
        }
        let epoch = u32::try_from(page.epoch)
            .map_err(|_| format!("the server reported a negative epoch: {}", page.epoch))?;
        let pad_to = pad_bucket(page.pad_to)?;
        let epoch_key = derive_epoch_key(base_key, epoch);

        let mut items = Vec::with_capacity(page.items.len());
        for item in &page.items {
            let content_ct = seal_field(
                item.content.as_bytes(),
                &epoch_key,
                item.claim_id,
                epoch,
                FieldTag::Content,
                pad_to,
            )?;
            let content_hash = blake3::hash(&content_ct);
            items.push(SealCommitEntry {
                claim_id: item.claim_id,
                content_ct_b64: b64(&content_ct),
                labels_ct_b64: b64(&seal_json(
                    &item.labels,
                    &epoch_key,
                    item.claim_id,
                    epoch,
                    FieldTag::Labels,
                    pad_to,
                )?),
                properties_ct_b64: b64(&seal_json(
                    &item.properties,
                    &epoch_key,
                    item.claim_id,
                    epoch,
                    FieldTag::Properties,
                    pad_to,
                )?),
                content_hash_b64: b64(content_hash.as_bytes()),
                versions: item
                    .versions
                    .iter()
                    .map(|v| {
                        Ok(CommitVersion {
                            id: v.id,
                            ct_b64: b64(&seal_field(
                                v.content.as_bytes(),
                                &epoch_key,
                                v.id,
                                epoch,
                                FieldTag::VersionContent,
                                pad_to,
                            )?),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                evidence: item
                    .evidence
                    .iter()
                    .map(|e| {
                        Ok(CommitEvidence {
                            id: e.id,
                            // The NULLABILITY rides inside the plaintext. See
                            // the module doc.
                            ct_b64: b64(&seal_json(
                                &e.raw_content,
                                &epoch_key,
                                e.id,
                                epoch,
                                FieldTag::EvidenceContent,
                                pad_to,
                            )?),
                            props_ct_b64: b64(&seal_json(
                                &e.properties,
                                &epoch_key,
                                e.id,
                                epoch,
                                FieldTag::EvidenceProperties,
                                pad_to,
                            )?),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            });
        }

        let resp: CommitResponse = ctx
            .post(
                &format!("/api/v1/admin/privatization/plans/{plan}/seal-commit"),
                &SealCommitRequest {
                    manifest_digest: page.manifest_digest,
                    items,
                },
            )
            .await?;
        committed += resp.committed;
        already += resp.already_done;

        // The cursor advances even when the whole page was `already_done`, so a
        // re-run walks to the end instead of looping on the first page.
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok((committed, already))
}

/// Unseal every page of a plan.
async fn unseal_plan(ctx: &Ctx, plan: Uuid, base_key: &[u8; 32]) -> Result<(usize, usize), String> {
    let mut cursor: Option<Uuid> = None;
    let (mut committed, mut already) = (0usize, 0usize);

    loop {
        let path = manifest_path(plan, "unseal-manifest", cursor);
        let page: UnsealManifest = ctx.get(&path).await?;
        if page.items.is_empty() {
            break;
        }

        let mut items = Vec::with_capacity(page.items.len());
        for item in &page.items {
            // THE ROW'S OWN EPOCH, not the group's active one. A rotation
            // retires an epoch without re-encrypting anything, so a sealed row
            // outlives the epoch it was sealed under and deriving from the
            // active epoch would fail the GCM tag on every row.
            let epoch = u32::try_from(item.epoch)
                .map_err(|_| format!("claim {} reports a negative epoch", item.claim_id))?;
            let pad_to = pad_bucket(item.pad_to)?;
            let epoch_key = derive_epoch_key(base_key, epoch);

            let content = String::from_utf8(open_field(
                &item.content_ct_b64,
                &epoch_key,
                item.claim_id,
                epoch,
                FieldTag::Content,
                pad_to,
            )?)
            .map_err(|e| format!("claim {}: content is not UTF-8: {e}", item.claim_id))?;

            let labels: Vec<String> = match &item.labels_ct_b64 {
                Some(ct) => open_json(
                    ct,
                    &epoch_key,
                    item.claim_id,
                    epoch,
                    FieldTag::Labels,
                    pad_to,
                )?,
                None => Vec::new(),
            };
            let properties: serde_json::Value = match &item.properties_ct_b64 {
                Some(ct) => open_json(
                    ct,
                    &epoch_key,
                    item.claim_id,
                    epoch,
                    FieldTag::Properties,
                    pad_to,
                )?,
                None => serde_json::json!({}),
            };

            let mut versions = Vec::with_capacity(item.versions.len());
            for v in &item.versions {
                versions.push(UnsealCommitVersion {
                    id: v.id,
                    content: String::from_utf8(open_field(
                        &v.ct_b64,
                        &epoch_key,
                        v.id,
                        epoch,
                        FieldTag::VersionContent,
                        pad_to,
                    )?)
                    .map_err(|e| format!("version {}: content is not UTF-8: {e}", v.id))?,
                });
            }

            let mut evidence = Vec::with_capacity(item.evidence.len());
            for e in &item.evidence {
                evidence.push(UnsealCommitEvidence {
                    id: e.id,
                    raw_content: open_json(
                        &e.ct_b64,
                        &epoch_key,
                        e.id,
                        epoch,
                        FieldTag::EvidenceContent,
                        pad_to,
                    )?,
                    properties: open_json(
                        &e.props_ct_b64,
                        &epoch_key,
                        e.id,
                        epoch,
                        FieldTag::EvidenceProperties,
                        pad_to,
                    )?,
                });
            }

            items.push(UnsealCommitEntry {
                content_hash_b64: b64(blake3::hash(content.as_bytes()).as_bytes()),
                claim_id: item.claim_id,
                content,
                labels,
                properties,
                versions,
                evidence,
            });
        }

        let resp: CommitResponse = ctx
            .post(
                &format!("/api/v1/admin/privatization/plans/{plan}/unseal-commit"),
                &UnsealCommitRequest { items },
            )
            .await?;
        committed += resp.committed;
        already += resp.already_done;

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok((committed, already))
}

// ---------------------------------------------------------------------------
// Crypto helpers. Padding then encryption, in that order, always.
// ---------------------------------------------------------------------------

/// Pad and encrypt one field.
fn seal_field(
    plaintext: &[u8],
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
    pad_to: u32,
) -> Result<Vec<u8>, String> {
    let padded = pad(plaintext, pad_to).map_err(|e| format!("padding {field:?}: {e}"))?;
    Ok(encrypt_content(&padded, epoch_key, entity_id, epoch, field)
        .map_err(|e| format!("encrypting {field:?} for {entity_id}: {e}"))?
        .to_bytes())
}

/// [`seal_field`] over a value's JSON encoding.
fn seal_json<T: Serialize>(
    value: &T,
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
    pad_to: u32,
) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(value).map_err(|e| format!("encoding {field:?}: {e}"))?;
    seal_field(&json, epoch_key, entity_id, epoch, field, pad_to)
}

/// Decrypt and unpad one field.
fn open_field(
    ct_b64: &str,
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
    pad_to: u32,
) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .map_err(|e| format!("{field:?} for {entity_id} is not base64: {e}"))?;
    let payload = EncryptedPayload::from_bytes(&bytes)
        .map_err(|e| format!("{field:?} for {entity_id} is malformed: {e}"))?;
    let padded = decrypt_content(&payload, epoch_key, entity_id, epoch, field).map_err(|e| {
        format!(
            "decrypting {field:?} for {entity_id} at epoch {epoch} failed: {e}. A wrong base key, \
             a wrong epoch or a tampered row all land here"
        )
    })?;
    unpad(&padded, pad_to).map_err(|e| format!("unpadding {field:?} for {entity_id}: {e}"))
}

/// [`open_field`] parsed back out of JSON.
fn open_json<T: serde::de::DeserializeOwned>(
    ct_b64: &str,
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
    pad_to: u32,
) -> Result<T, String> {
    let bytes = open_field(ct_b64, epoch_key, entity_id, epoch, field, pad_to)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("decoding {field:?} for {entity_id}: {e}"))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn manifest_path(plan: Uuid, endpoint: &str, cursor: Option<Uuid>) -> String {
    match cursor {
        Some(c) => format!("/api/v1/admin/privatization/plans/{plan}/{endpoint}?cursor={c}"),
        None => format!("/api/v1/admin/privatization/plans/{plan}/{endpoint}"),
    }
}

/// Validate the server's `pad_to` against the buckets the schema admits.
///
/// The server is the authority on which bucket a plan uses, but a bucket
/// outside the admitted set means client and server disagree about the padding
/// scheme, and the failure mode of guessing is a ciphertext the server refuses
/// after the plaintext has already been on the wire.
fn pad_bucket(pad_to: i32) -> Result<u32, String> {
    let value = u32::try_from(pad_to).map_err(|_| format!("negative pad_to: {pad_to}"))?;
    if !PAD_BUCKETS.contains(&value) {
        return Err(format!(
            "the server reported pad_to={pad_to}, which is not one of {PAD_BUCKETS:?}"
        ));
    }
    Ok(value)
}

/// Read the group base key from a flag or a file.
fn load_base_key(
    hex_arg: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<[u8; 32], String> {
    match (hex_arg, file) {
        (Some(h), None) => parse_base_key(h),
        (None, Some(p)) => {
            let contents = std::fs::read_to_string(p)
                .map_err(|e| format!("reading the base key from {}: {e}", p.display()))?;
            parse_base_key(contents.trim())
        }
        (None, None) => Err(
            "supply the group base key with --base-key-hex or --base-key-file. The server does \
             not have it and cannot supply it"
                .to_string(),
        ),
        (Some(_), Some(_)) => {
            Err("give the base key once: --base-key-hex or --base-key-file".to_string())
        }
    }
}

fn parse_base_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("the base key is not hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "the base key must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_round_trips_through_pad_encrypt_decrypt_unpad() {
        // The property the whole binary rests on, asserted without a server:
        // what `seal_field` produces is what `open_field` recovers, and the
        // padding is invisible on both sides.
        let key = [3u8; 32];
        let id = Uuid::new_v4();
        let ct = seal_field(b"confidential", &key, id, 7, FieldTag::Content, 256).unwrap();
        assert_eq!(ct.len() % 256, 0, "the stored blob lands on the bucket");
        let recovered = open_field(&b64(&ct), &key, id, 7, FieldTag::Content, 256).unwrap();
        assert_eq!(recovered, b"confidential");
    }

    #[test]
    fn an_evidence_null_survives_the_round_trip_as_a_null() {
        // `evidence.raw_content` is NULLABLE, and a ciphertext of the empty
        // string could not distinguish NULL from "". The JSON encoding is what
        // keeps them apart.
        let key = [4u8; 32];
        let id = Uuid::new_v4();
        for original in [None, Some(String::new()), Some("text".to_string())] {
            let ct = seal_json(&original, &key, id, 0, FieldTag::EvidenceContent, 256).unwrap();
            let back: Option<String> =
                open_json(&b64(&ct), &key, id, 0, FieldTag::EvidenceContent, 256).unwrap();
            assert_eq!(back, original);
        }
    }

    #[test]
    fn a_field_tag_cannot_be_transplanted_into_another_field() {
        // The AAD binds the tag, so a `content` ciphertext offered as `labels`
        // fails the GCM tag rather than decrypting into the wrong column.
        let key = [5u8; 32];
        let id = Uuid::new_v4();
        let ct = seal_field(b"x", &key, id, 0, FieldTag::Content, 256).unwrap();
        assert!(open_field(&b64(&ct), &key, id, 0, FieldTag::Labels, 256).is_err());
        assert!(open_field(&b64(&ct), &key, id, 1, FieldTag::Content, 256).is_err());
        assert!(open_field(&b64(&ct), &key, Uuid::new_v4(), 0, FieldTag::Content, 256).is_err());
    }

    #[test]
    fn a_pad_bucket_the_schema_does_not_admit_is_refused() {
        assert!(pad_bucket(512).is_err());
        assert!(pad_bucket(-1).is_err());
        assert_eq!(pad_bucket(4096).unwrap(), 4096);
    }

    #[test]
    fn the_base_key_must_be_thirty_two_bytes() {
        assert!(parse_base_key("00").is_err());
        assert!(parse_base_key("zz").is_err());
        assert_eq!(parse_base_key(&"ab".repeat(32)).unwrap().len(), 32);
    }
}
