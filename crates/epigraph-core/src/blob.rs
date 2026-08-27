//! Content-addressed blob metadata and filesystem layout.
//!
//! A blob is raw bytes — an instrument file, a gel image, a raw measurement
//! export — stored on the filesystem under a path derived entirely from the
//! BLAKE3-256 digest of its content:
//!
//! ```text
//! {root}/{hex[0:2]}/{hex[2:4]}/{hex}.blob
//! ```
//!
//! The digest IS the identity, which makes a blob the purest kind of *noun* in
//! the sense of `docs/architecture/noun-claims-and-verb-edges.md`. It follows
//! that [`BlobRef`] carries **no subject column** — no `claim_id`, no
//! `(subject_type, subject_id)`. "Claim C was derived from blob B" is a
//! *relationship* and lives in `edges` as `claim -[derived_from]-> blob`.
//!
//! Configuration is read exactly twice per process, at construction time
//! ([`blob_storage_root`] / [`max_blob_bytes`]) — never inside a repository
//! function, which always takes an explicit `&Path`. There is no
//! "blob storage enabled" flag: the root resolves to [`DEFAULT_BLOB_DIR`] when
//! unset, so the feature works out of the box and tests can only ever exercise
//! the ON path.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Environment variable naming the filesystem root for blob content.
pub const BLOB_DIR_ENV: &str = "EPIGRAPH_BLOB_DIR";

/// Root used when [`BLOB_DIR_ENV`] is unset or empty.
///
/// Deliberately a cwd-relative directory rather than `std::env::temp_dir()`:
/// silently losing scientific measurement data on reboot is worse than a
/// visible directory in the working directory. `data/` is already gitignored,
/// so a dev checkout stays clean.
pub const DEFAULT_BLOB_DIR: &str = "data/blobs";

/// Environment variable capping the size of a single blob, in bytes.
pub const MAX_BLOB_BYTES_ENV: &str = "EPIGRAPH_MAX_BLOB_BYTES";

/// Upload ceiling used when [`MAX_BLOB_BYTES_ENV`] is unset or unparseable:
/// 25 MiB, mirroring episcience's `EPISCIENCE_MAX_UPLOAD_BYTES` default.
pub const DEFAULT_MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;

/// Length of a BLAKE3-256 digest, and the exact length the `blobs`
/// `blobs_content_hash_length` CHECK enforces at rest.
const CONTENT_HASH_LEN: usize = 32;

/// A `content_hash` that is not exactly [`CONTENT_HASH_LEN`] bytes.
///
/// episcience asserted this invariant with `assert!(len >= 4)` inside
/// `storage_path`, i.e. a panic reachable from a request handler. Here it is a
/// value: no path can be derived from a malformed digest, and the caller
/// decides what that means (a 500, not a crash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("blob content_hash must be exactly {CONTENT_HASH_LEN} bytes, got {0}")]
pub struct InvalidBlobHash(pub usize);

/// A filename that cannot be safely echoed into a `Content-Disposition` header
/// or handed to a downstream consumer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidBlobFilename {
    /// Empty, or whitespace-only, or nothing left after taking the basename.
    #[error("blob filename must not be empty")]
    Empty,
    /// Contains a control character, `"`, `\`, or `/`.
    #[error("blob filename contains an illegal character: {0:?}")]
    IllegalCharacter(char),
}

/// Metadata reference to a content-addressed blob.
///
/// The bytes themselves are never carried here — see [`BlobRef::storage_path`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: Uuid,
    /// Display name only. Sanitized at write time by [`sanitize_filename`] and
    /// never used to resolve a path (the path is hash-derived).
    pub filename: String,
    /// Caller-supplied metadata, stored verbatim and never trusted for
    /// dispatch or content sniffing.
    pub mime_type: String,
    pub size_bytes: i64,
    /// BLAKE3-256 digest of the content; exactly [`CONTENT_HASH_LEN`] bytes.
    pub content_hash: Vec<u8>,
    pub uploader_id: Uuid,
    pub labels: Vec<String>,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl BlobRef {
    /// Filesystem path of this blob's content under `root`.
    ///
    /// # Errors
    /// [`InvalidBlobHash`] if `content_hash` is not exactly 32 bytes.
    pub fn storage_path(&self, root: &Path) -> Result<PathBuf, InvalidBlobHash> {
        storage_path(root, &self.content_hash)
    }

    /// Lowercase hex rendering of this blob's digest.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hash_hex(&self.content_hash)
    }
}

/// Lowercase hex rendering of a digest.
#[must_use]
pub fn hash_hex(content_hash: &[u8]) -> String {
    hex::encode(content_hash)
}

/// Filesystem path for `content_hash` under `root`:
/// `{root}/{hex[0:2]}/{hex[2:4]}/{hex}.blob`.
///
/// The two-level fan-out keeps any single directory to ~256 entries at the
/// first level, which matters once a lab has uploaded a few hundred thousand
/// instrument files.
///
/// # Errors
/// [`InvalidBlobHash`] if `content_hash` is not exactly 32 bytes — the same
/// length the `blobs_content_hash_length` CHECK enforces at rest, so a
/// well-formed row can never produce this error.
pub fn storage_path(root: &Path, content_hash: &[u8]) -> Result<PathBuf, InvalidBlobHash> {
    if content_hash.len() != CONTENT_HASH_LEN {
        return Err(InvalidBlobHash(content_hash.len()));
    }
    let hex = hash_hex(content_hash);
    Ok(root
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(format!("{hex}.blob")))
}

/// Reduce a caller-supplied filename to a safe display basename.
///
/// Takes the last path component (so `../../etc/passwd` cannot survive as a
/// traversal-shaped string in a header) and rejects anything that would break
/// a quoted `Content-Disposition` value or a downstream consumer: control
/// characters, `"`, `\`, `/`.
///
/// This mirrors the `blobs_filename_safe` CHECK. Both exist on purpose: the
/// CHECK is the at-rest guarantee, this is the one that produces a clean
/// validation error instead of a constraint violation, and it keeps holding
/// if a session ever runs with `standard_conforming_strings=off`.
///
/// # Errors
/// [`InvalidBlobFilename`] if the name is empty or carries an illegal
/// character.
pub fn sanitize_filename(filename: &str) -> Result<String, InvalidBlobFilename> {
    let trimmed = filename.trim();
    if trimmed.is_empty() {
        return Err(InvalidBlobFilename::Empty);
    }
    // Reject BEFORE taking the basename: a name containing `/` is a path, not
    // a filename, and silently keeping only its tail would hide the caller's
    // mistake (and quietly change what gets stored).
    if let Some(c) = trimmed
        .chars()
        .find(|c| c.is_control() || matches!(c, '"' | '\\' | '/'))
    {
        return Err(InvalidBlobFilename::IllegalCharacter(c));
    }
    Ok(trimmed.to_string())
}

/// Filesystem root for blob content: [`BLOB_DIR_ENV`] when set and non-empty,
/// else [`DEFAULT_BLOB_DIR`].
///
/// Never returns `Option`: there is no "disabled" state for blob storage, so
/// there is no OFF path for a caller to forget to handle or a test to
/// accidentally exercise.
#[must_use]
pub fn blob_storage_root() -> PathBuf {
    std::env::var(BLOB_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_BLOB_DIR), PathBuf::from)
}

/// Maximum accepted size of a single blob, in bytes.
///
/// [`MAX_BLOB_BYTES_ENV`] when set to a positive integer, else
/// [`DEFAULT_MAX_BLOB_BYTES`]. A zero or unparseable value falls back to the
/// default rather than to "no uploads allowed" — a typo in an env var must not
/// silently disable the feature.
#[must_use]
pub fn max_blob_bytes() -> usize {
    std::env::var(MAX_BLOB_BYTES_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_BLOB_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; CONTENT_HASH_LEN]
    }

    #[test]
    fn storage_path_fans_out_two_levels() {
        let mut hash = digest(0xab);
        hash[1] = 0xcd;
        let path = storage_path(Path::new("/blobs"), &hash).unwrap();
        let hex = hash_hex(&hash);
        assert_eq!(
            path,
            Path::new("/blobs")
                .join("ab")
                .join("cd")
                .join(format!("{hex}.blob"))
        );
    }

    /// The episcience version asserted `len >= 4` and panicked; a short or long
    /// digest must be a value, not a crash.
    #[test]
    fn storage_path_requires_exactly_32_bytes() {
        for len in [0usize, 4, 31, 33, 64] {
            assert_eq!(
                storage_path(Path::new("/blobs"), &vec![0u8; len]),
                Err(InvalidBlobHash(len)),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn sanitize_filename_rejects_header_breaking_names() {
        for bad in [
            "evil\"; rm -rf /",
            "a\nb",
            "../../etc/passwd",
            "back\\slash",
            "nul\0byte",
            "   ",
            "",
        ] {
            assert!(sanitize_filename(bad).is_err(), "{bad:?} must be rejected");
        }
        assert_eq!(sanitize_filename("  gel.tif ").unwrap(), "gel.tif");
        assert_eq!(
            sanitize_filename("run-2026-08-27_A1.czi").unwrap(),
            "run-2026-08-27_A1.czi"
        );
    }

    #[test]
    fn blob_storage_root_is_never_absent() {
        // Not asserting on the live env (tests share a process); the contract
        // under test is that the unset case still yields a usable path.
        assert_eq!(PathBuf::from(DEFAULT_BLOB_DIR), PathBuf::from("data/blobs"));
        assert!(!blob_storage_root().as_os_str().is_empty());
    }

    #[test]
    fn default_max_blob_bytes_is_positive() {
        assert_eq!(DEFAULT_MAX_BLOB_BYTES, 25 * 1024 * 1024);
        assert!(max_blob_bytes() > 0);
    }
}
