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

/// The maximum length the `blobs.mime_type varchar(255)` column accepts,
/// **in bytes**.
///
/// The unit is load-bearing, which is why the name carries it. `varchar(255)`
/// counts characters, but against a `SQL_ASCII` server a character *is* a byte
/// — `length(repeat('—', 200))` is 600 there, not 200 — so a cap on
/// `chars().count()` admitted 200-character multi-byte values that the column
/// then refused, after `BlobRepository::store` had already fsynced the content.
/// Byte length is never below character length, so capping bytes keeps the
/// guard inside the column under either encoding.
const MAX_MIME_TYPE_BYTES: usize = 255;

/// A `mime_type` that cannot be safely echoed into a `Content-Type` response
/// header, or that the `blobs.mime_type` column cannot hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidBlobMimeType {
    /// Empty, or whitespace-only.
    #[error("blob mime_type must not be empty")]
    Empty,
    /// Contains a control character.
    #[error("blob mime_type contains an illegal character: {0:?}")]
    IllegalCharacter(char),
    /// Longer than `varchar(255)` can hold.
    #[error("blob mime_type must be at most {MAX_MIME_TYPE_BYTES} bytes, got {0}")]
    TooLong(usize),
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
/// character — including one at either end, which is checked before the
/// surrounding whitespace is trimmed away.
pub fn sanitize_filename(filename: &str) -> Result<String, InvalidBlobFilename> {
    // Scan the RAW input, before trimming. `str::trim` strips Unicode
    // `White_Space`, which includes several `Cc` characters (U+0009..U+000D,
    // U+0085), so trimming first would silently swallow a trailing NEL or TAB
    // instead of reporting it -- a rejected character must be reported, not
    // quietly removed.
    //
    // Reject BEFORE taking the basename too: a name containing `/` is a path,
    // not a filename, and silently keeping only its tail would hide the
    // caller's mistake (and quietly change what gets stored).
    if let Some(c) = filename
        .chars()
        .find(|c| c.is_control() || matches!(c, '"' | '\\' | '/'))
    {
        return Err(InvalidBlobFilename::IllegalCharacter(c));
    }
    let trimmed = filename.trim();
    if trimmed.is_empty() {
        return Err(InvalidBlobFilename::Empty);
    }
    Ok(trimmed.to_string())
}

/// Reduce a caller-supplied media type to a value that is safe to echo into a
/// `Content-Type` response header.
///
/// The twin of [`sanitize_filename`], with the character set moved from the
/// quoted-string grammar to the header-value grammar. A filename lands *inside*
/// a quoted string in `Content-Disposition`, so `"`, `\\` and `/` end it early;
/// a mime type is a whole header value in which `/`, `;`, `=` and space are
/// required syntax (`text/csv; charset=utf-8`). What the two share is that a
/// control character terminates the header itself, so that — and only that — is
/// the rejected class here.
///
/// The length cap mirrors the `blobs.mime_type varchar(255)` column and is
/// measured in **bytes** — see [`MAX_MIME_TYPE_BYTES`]. Without it an over-wide
/// value is caught only by the INSERT, i.e. *after* [`crate::BlobRef`]'s
/// repository has already fsynced the content, which leaves an orphan file with
/// no row and reports a caller mistake as an opaque database error.
///
/// This mirrors the `blobs_mime_type_not_empty` / `blobs_mime_type_safe`
/// CHECKs for the same reason [`sanitize_filename`] mirrors
/// `blobs_filename_safe`: the CHECK is the at-rest guarantee, this is the one
/// that produces a clean validation error instead of a constraint violation.
/// It is deliberately the stricter of the two — `char::is_control` is Unicode
/// `Cc` (U+0000..=U+001F, U+007F..=U+009F) while the CHECK rejects only C0 and
/// DEL — because the Rust guard runs first on every write path and the CHECK
/// only has to catch what bypasses it.
///
/// That direction is load-bearing and must not invert. `BlobRepository::store`
/// fsyncs the content *before* the INSERT, so a value this guard admits and the
/// CHECK then refuses leaves an orphan file with no row. The CHECK was
/// originally written `[[:cntrl:]]`, which is not Unicode `Cc`: Postgres
/// resolves a POSIX class through the database ctype, and against a
/// `SQL_ASCII` / `C` cluster it matches byte-wise, where `iscntrl` counts
/// 0x80..0x9F as control — so it rejected every character whose UTF-8 encoding
/// carries such a byte, i.e. all of General Punctuation, none of which is
/// `Cc`. Migration 076 narrowed both CHECKs to C0 and DEL to restore the
/// containment.
///
/// # Errors
/// [`InvalidBlobMimeType`] if the value is empty, carries a control character —
/// including one at either end, which is checked before the surrounding
/// whitespace is trimmed away — or exceeds [`MAX_MIME_TYPE_BYTES`] bytes.
pub fn sanitize_mime_type(mime_type: &str) -> Result<String, InvalidBlobMimeType> {
    // Scan the RAW input, before trimming -- see `sanitize_filename`: trimming
    // first turned `"text/plain\u{85}"` into `Ok("text/plain")`, contradicting
    // the contract documented above.
    if let Some(c) = mime_type.chars().find(|c| c.is_control()) {
        return Err(InvalidBlobMimeType::IllegalCharacter(c));
    }
    let trimmed = mime_type.trim();
    if trimmed.is_empty() {
        return Err(InvalidBlobMimeType::Empty);
    }
    let len = trimmed.len();
    if len > MAX_MIME_TYPE_BYTES {
        return Err(InvalidBlobMimeType::TooLong(len));
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
    fn sanitize_mime_type_rejects_header_breaking_values() {
        assert_eq!(
            sanitize_mime_type("text/plain\nX-Injected: yes"),
            Err(InvalidBlobMimeType::IllegalCharacter('\n'))
        );
        assert_eq!(
            sanitize_mime_type("text/plain\u{7f}"),
            Err(InvalidBlobMimeType::IllegalCharacter('\u{7f}'))
        );
        assert_eq!(sanitize_mime_type("  "), Err(InvalidBlobMimeType::Empty));
        assert_eq!(sanitize_mime_type(""), Err(InvalidBlobMimeType::Empty));

        // The column is varchar(255); the guard must fire one character before
        // the INSERT would, i.e. before any bytes are on disk.
        let over = format!("text/{}", "a".repeat(300));
        assert_eq!(
            sanitize_mime_type(&over),
            Err(InvalidBlobMimeType::TooLong(305))
        );
        let exact = format!("text/{}", "a".repeat(MAX_MIME_TYPE_BYTES - 5));
        assert_eq!(sanitize_mime_type(&exact).unwrap(), exact);
    }

    /// `/`, `;`, `=` and space are mime grammar, not header-breaking
    /// characters: unlike `sanitize_filename` this guard must let them through.
    #[test]
    fn sanitize_mime_type_keeps_real_media_types() {
        for good in [
            "text/plain",
            "application/octet-stream",
            "image/tiff",
            "text/csv; charset=utf-8",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "multipart/form-data; boundary=\"abc\"",
        ] {
            assert_eq!(sanitize_mime_type(good).unwrap(), good, "{good:?}");
        }
        assert_eq!(sanitize_mime_type("  image/png  ").unwrap(), "image/png");
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

    /// A control character at either end must be *rejected*, not silently
    /// trimmed away.
    ///
    /// `str::trim` strips Unicode `White_Space`, which includes U+0085 NEL and
    /// U+000B..U+000D — all of them `Cc`. Trimming before the scan therefore
    /// turned `"text/plain\u{85}"` into `Ok("text/plain")`, contradicting the
    /// documented contract that the guard rejects every control character. The
    /// outcome was safe either way; the contract was not true.
    #[test]
    fn sanitize_rejects_edge_control_characters_instead_of_trimming_them() {
        for c in ['\u{85}', '\u{0b}', '\u{0c}', '\r', '\n', '\t'] {
            assert_eq!(
                sanitize_mime_type(&format!("text/plain{c}")),
                Err(InvalidBlobMimeType::IllegalCharacter(c)),
                "trailing {c:?} must be rejected"
            );
            assert_eq!(
                sanitize_mime_type(&format!("{c}text/plain")),
                Err(InvalidBlobMimeType::IllegalCharacter(c)),
                "leading {c:?} must be rejected"
            );
            assert_eq!(
                sanitize_filename(&format!("gel{c}.tif")),
                Err(InvalidBlobFilename::IllegalCharacter(c)),
                "embedded {c:?} must be rejected"
            );
            assert_eq!(
                sanitize_filename(&format!("gel.tif{c}")),
                Err(InvalidBlobFilename::IllegalCharacter(c)),
                "trailing {c:?} must be rejected"
            );
        }

        // Ordinary space padding is still trimmed, not rejected: space is not
        // a control character and padding is a caller typo, not an injection.
        assert_eq!(sanitize_mime_type("  image/png  ").unwrap(), "image/png");
        assert_eq!(sanitize_filename("  gel.tif ").unwrap(), "gel.tif");
    }

    /// The guard must admit every non-control character, including the
    /// General Punctuation that `[[:cntrl:]]` rejected byte-wise.
    #[test]
    fn sanitize_admits_non_control_unicode() {
        for s in [
            "text/plain; x=a\u{2014}b",
            "text/plain; x=a\u{2019}b",
            "text/plain; x=a\u{200b}b",
        ] {
            assert_eq!(sanitize_mime_type(s).unwrap(), s, "{s:?}");
        }
        for s in ["em\u{2014}dash.csv", "M\u{fc}ller_gel.tif", "\u{3042}.czi"] {
            assert_eq!(sanitize_filename(s).unwrap(), s, "{s:?}");
        }
    }
}
