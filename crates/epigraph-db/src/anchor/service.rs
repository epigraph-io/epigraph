//! `AnchorService` — anchor a root, verify one, advance stragglers.
//!
//! # There is no enable flag
//!
//! Anchoring on seal is unconditional. `EPIGRAPH_ANCHOR_BACKEND` chooses WHICH
//! backend, and its default when unset is `mock`. Unset is the state of every
//! existing test and every dev machine, so the default path IS the on path,
//! and every manifest-seal test exercises it. A feature behind an
//! off-by-default flag is off everywhere that matters.
//!
//! # Best-effort, post-commit
//!
//! [`anchor_manifest_best_effort`] warns and returns on any failure. It never
//! fails, delays, or rolls back the seal it follows — matching the CLAUDE.md
//! embedding contract ("embed inline post-commit, best-effort; warn on
//! failure, never block the write") and the `RecallEventRepository::log`
//! precedent. The cost is that a real backend outage accumulates
//! `status = 'failed'` rows silently; `idx_anchors_open`, [`AnchorService::poll_pending`]
//! and `anchor_verify --all`'s non-zero exit are what surface that.
//!
//! # Verification never trusts a stored column
//!
//! [`AnchorService::verify`] re-derives the root from the published
//! `commitment_bytes` before comparing anything. An operator who edits
//! `anchors.root_hash` alone is caught by check (3), and one who edits the
//! bytes is caught by check (2) — both before the ledger is even consulted.

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use epigraph_crypto::{ContentHasher, HASH_SIZE};
use epigraph_interfaces::anchor::{AnchorBackend, AnchorCommitment, AnchorError};
use sqlx::PgPool;
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::anchor::{AnchorRepository, AnchorRow, NewAnchor, ROOT_TYPE_MANIFEST};

use super::cardano::CardanoBlockfrostBackend;
use super::mock::MockAnchorBackend;
use super::root_source::{AnchorRootSource, ManifestRootSource};

/// Environment variable naming the backend. Absent means [`BackendKind::Mock`].
pub const BACKEND_ENV: &str = "EPIGRAPH_ANCHOR_BACKEND";

/// `trust_basis` reported for a ledger the operator controls.
pub const TRUST_OPERATOR_HELD: &str = "operator-held";
/// `trust_basis` reported for a ledger outside the operator's control.
pub const TRUST_THIRD_PARTY: &str = "third-party";

/// Which backend `EPIGRAPH_ANCHOR_BACKEND` selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Mock,
    Cardano,
}

/// Parse the backend name, defaulting to [`BackendKind::Mock`].
///
/// Pure so the DEFAULT-IS-ON property is unit-testable without mutating
/// process-wide environment, which is racy under a threaded test runner.
///
/// # Errors
/// Returns the offending name if it is not a known backend. An unknown backend
/// is a hard error rather than a silent fall back to the mock: an operator who
/// typed `cardanno` must not be told everything is anchored on chain.
pub fn parse_backend_name(raw: Option<&str>) -> Result<BackendKind, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("mock") => Ok(BackendKind::Mock),
        Some("cardano") => Ok(BackendKind::Cardano),
        Some(other) => Err(other.to_string()),
    }
}

/// What [`AnchorService::verify`] concluded, cheapest-and-most-damning first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorVerdict {
    /// No anchor row for this root at all.
    Missing,
    /// The stored commitment does not hash to `commitment_hash`, or its
    /// decoded contents disagree with the row's own columns. THIS is what
    /// catches an operator who edits `root_hash` alone.
    CommitmentTampered,
    /// Anchored but not yet confirmed on the ledger.
    Unconfirmed,
    /// The ledger has no such transaction. The submission never landed, or the
    /// row points at an id the ledger never issued.
    LedgerMissing,
    /// The ledger's bytes differ from ours. The two stores disagree — the case
    /// this whole feature exists to detect.
    LedgerMismatch,
    /// The root can no longer be derived at all (every covered row is gone, or
    /// the sealed record itself was removed).
    RootUnresolvable,
    /// The root re-derives to a DIFFERENT value than the one anchored.
    /// Reported, not judged: whether this is benign label churn or an edit is
    /// the root source's semantic, not this layer's.
    Drift,
    /// Commitment intact, ledger agrees, live root matches.
    Verified,
}

impl AnchorVerdict {
    /// `true` when the verdict is anything other than [`Self::Verified`] —
    /// what `anchor_verify` turns into a non-zero exit code.
    #[must_use]
    pub const fn is_problem(self) -> bool {
        !matches!(self, Self::Verified)
    }
}

/// One root's verification report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnchorVerification {
    pub verdict: AnchorVerdict,
    pub root_type: String,
    pub root_id: Uuid,
    /// Hex root as anchored, re-derived from the published bytes rather than
    /// read off `anchors.root_hash`.
    pub anchored_root: Option<String>,
    /// Hex root as the rows stand now.
    pub live_root: Option<String>,
    pub anchor_id: Option<Uuid>,
    pub backend: Option<String>,
    pub network: Option<String>,
    pub status: Option<String>,
    pub tx_id: Option<String>,
    pub block_height: Option<i64>,
    pub block_time: Option<DateTime<Utc>>,
    /// Seal time as CLAIMED by the root.
    pub sealed_at: Option<DateTime<Utc>>,
    /// `true` when the claimed seal time is AFTER the block that proves
    /// existence — i.e. the seal was backdated relative to the ledger.
    /// `None` until there is a block to compare against.
    ///
    /// Compared at ONE-SECOND resolution, because that is what
    /// `PublishedAnchor::block_time_unix` carries. A sub-second overlap is
    /// therefore not distinguishable and is not reported; real backdating is
    /// minutes or days, not milliseconds.
    pub sealed_after_block: Option<bool>,
    /// `"operator-held"` for the mock, `"third-party"` otherwise. A green
    /// verdict on an operator-held ledger proves the mechanism, NOT third-party
    /// existence-at-a-time.
    pub trust_basis: &'static str,
    /// Human-readable elaboration of the verdict.
    pub detail: Option<String>,
}

/// Errors from the anchoring service proper (as opposed to a backend refusing).
#[derive(Debug, thiserror::Error)]
pub enum AnchorServiceError {
    #[error(transparent)]
    Db(#[from] DbError),

    #[error(transparent)]
    Backend(#[from] AnchorError),

    /// A root kind nothing in this build knows how to resolve. A hard error,
    /// never a silent skip: silently not anchoring is the failure mode.
    #[error("unknown anchor root type {root_type:?} (this build handles: {known})")]
    UnknownRootType { root_type: String, known: String },

    #[error("{root_type} {root_id} does not exist, so there is no root to anchor")]
    RootNotFound { root_type: String, root_id: Uuid },

    #[error(
        "{BACKEND_ENV}={0:?} is not a known anchor backend (expected \"mock\" or \"cardano\")"
    )]
    UnknownBackend(String),
}

/// Anchors roots and verifies them.
pub struct AnchorService {
    backend: Arc<dyn AnchorBackend>,
    source: Arc<dyn AnchorRootSource>,
}

impl AnchorService {
    /// Build over an explicit backend and root source.
    #[must_use]
    pub fn new(backend: Arc<dyn AnchorBackend>, source: Arc<dyn AnchorRootSource>) -> Self {
        Self { backend, source }
    }

    /// Build the manifest-anchoring service the kernel uses, reading
    /// [`BACKEND_ENV`].
    ///
    /// # Errors
    /// [`AnchorServiceError::UnknownBackend`] if the variable names a backend
    /// this build does not have.
    pub fn from_env(pool: &PgPool) -> Result<Self, AnchorServiceError> {
        let raw = std::env::var(BACKEND_ENV).ok();
        let kind =
            parse_backend_name(raw.as_deref()).map_err(AnchorServiceError::UnknownBackend)?;
        let backend: Arc<dyn AnchorBackend> = match kind {
            BackendKind::Mock => Arc::new(MockAnchorBackend::new(pool.clone())),
            BackendKind::Cardano => Arc::new(CardanoBlockfrostBackend::from_env()),
        };
        Ok(Self::new(backend, Arc::new(ManifestRootSource)))
    }

    /// `"operator-held"` unless the backend is somebody else's ledger.
    ///
    /// Describes THIS PROCESS's backend. For a report about a stored row use
    /// [`trust_basis_for_backend`] on `row.backend` instead — see its docs.
    #[must_use]
    pub fn trust_basis(&self) -> &'static str {
        trust_basis_for_backend(self.backend.name())
    }

    /// Anchor `root_id`, or return the anchor it already has.
    ///
    /// Idempotent: a root with a live (non-`failed`) anchor submits nothing and
    /// returns the existing row. Otherwise the row goes `pending` ->
    /// `submitted` -> `confirmed`, the last step driven by an immediate
    /// [`AnchorBackend::fetch`]. The mock confirms instantly; a real chain will
    /// leave the row `submitted` for [`Self::poll_pending`] to advance.
    ///
    /// A backend refusal is recorded as a `failed` row and returned as `Ok` —
    /// the caller is a post-commit hook that must not fail.
    ///
    /// # Errors
    /// - [`AnchorServiceError::UnknownRootType`] if `root_type` is not this
    ///   service's source kind.
    /// - [`AnchorServiceError::RootNotFound`] if there is no such sealed root.
    /// - [`AnchorServiceError::Db`] on a query failure.
    #[instrument(skip(self, pool), fields(backend = self.backend.name()))]
    pub async fn anchor(
        &self,
        pool: &PgPool,
        root_type: &str,
        root_id: Uuid,
    ) -> Result<AnchorRow, AnchorServiceError> {
        if root_type != self.source.kind() {
            return Err(AnchorServiceError::UnknownRootType {
                root_type: root_type.to_string(),
                known: self.source.kind().to_string(),
            });
        }

        let sealed = self.source.sealed(pool, root_id).await?.ok_or_else(|| {
            AnchorServiceError::RootNotFound {
                root_type: root_type.to_string(),
                root_id,
            }
        })?;

        let commitment = AnchorCommitment::new(
            root_type,
            *root_id.as_bytes(),
            sealed.root_hash,
            sealed.leaf_count,
            u64::try_from(sealed.sealed_at.timestamp()).unwrap_or(0),
        );
        let bytes = commitment.to_cbor()?;
        let commitment_hash = ContentHasher::hash(&bytes);

        let row = AnchorRepository::insert_pending(
            pool,
            &NewAnchor {
                root_type: root_type.to_string(),
                root_id,
                root_hash: sealed.root_hash.to_vec(),
                commitment_version: i16::try_from(commitment.version).unwrap_or(1),
                commitment_hash: commitment_hash.to_vec(),
                commitment_bytes: bytes,
                backend: self.backend.name().to_string(),
                network: self.backend.network().to_string(),
                sealed_at: sealed.sealed_at,
            },
        )
        .await?;

        // Already live: submit nothing. Two commitments over one root would let
        // an operator present whichever suited them at verify time.
        if row.status != "pending" {
            return Ok(row);
        }

        match self.backend.submit(&commitment).await {
            Ok(receipt) => {
                AnchorRepository::mark_submitted(pool, row.id, &receipt.tx_id).await?;
                self.confirm_from_ledger(pool, row.id, &receipt.tx_id)
                    .await?;
            }
            Err(e) => {
                warn!(root_id = %root_id, backend = self.backend.name(), "anchor submit failed: {e}");
                AnchorRepository::mark_failed(pool, row.id, &e.to_string()).await?;
            }
        }

        Ok(AnchorRepository::get_by_id(pool, row.id)
            .await?
            .unwrap_or(row))
    }

    /// Read the ledger's copy and confirm the row if it is there.
    async fn confirm_from_ledger(
        &self,
        pool: &PgPool,
        anchor_id: Uuid,
        tx_id: &str,
    ) -> Result<bool, AnchorServiceError> {
        match self.backend.fetch(tx_id).await {
            Ok(Some(published)) => {
                let block_time = unix_to_utc(published.block_time_unix);
                AnchorRepository::mark_confirmed(
                    pool,
                    anchor_id,
                    tx_id,
                    published.block_height,
                    block_time,
                )
                .await?;
                Ok(true)
            }
            // Not an error: a real chain simply has not included it yet.
            Ok(None) => Ok(false),
            Err(e) => {
                warn!(anchor_id = %anchor_id, "anchor confirmation fetch failed: {e}");
                Ok(false)
            }
        }
    }

    /// Advance `pending` / `submitted` anchors that the ledger has since
    /// included.
    ///
    /// Driven manually by `anchor_verify --poll`; there is no daemon in this
    /// track. Returns how many rows moved to `confirmed`.
    ///
    /// # Errors
    /// [`AnchorServiceError::Db`] on a query failure.
    #[instrument(skip(self, pool))]
    pub async fn poll_pending(&self, pool: &PgPool, limit: i64) -> Result<u64, AnchorServiceError> {
        let mut confirmed = 0u64;
        for row in AnchorRepository::list_open(pool, limit).await? {
            if row.backend != self.backend.name() || row.network != self.backend.network() {
                continue;
            }
            let Some(tx_id) = row.tx_id.as_deref() else {
                continue;
            };
            if self.confirm_from_ledger(pool, row.id, tx_id).await? {
                confirmed += 1;
            }
        }
        Ok(confirmed)
    }

    /// Verify one root's anchor. Writes nothing.
    ///
    /// Checks run cheapest-and-most-damning first; the first failure decides
    /// the verdict:
    ///
    /// 1. no `anchors` row -> [`AnchorVerdict::Missing`]
    /// 2. `blake3(commitment_bytes) != commitment_hash` -> `CommitmentTampered`
    /// 3. decoded `r`/`i`/`k` disagree with the row -> `CommitmentTampered`
    /// 4. status is not `confirmed` -> `Unconfirmed`
    /// 5. ledger has no such tx -> `LedgerMissing`; bytes differ -> `LedgerMismatch`
    /// 6. root no longer derivable -> `RootUnresolvable`; derives differently -> `Drift`
    /// 7. otherwise -> `Verified`
    ///
    /// # Errors
    /// - [`AnchorServiceError::UnknownRootType`] for a kind this build cannot
    ///   resolve.
    /// - [`AnchorServiceError::Db`] on a query failure.
    #[instrument(skip(self, pool))]
    pub async fn verify(
        &self,
        pool: &PgPool,
        root_type: &str,
        root_id: Uuid,
    ) -> Result<AnchorVerification, AnchorServiceError> {
        if root_type != self.source.kind() {
            return Err(AnchorServiceError::UnknownRootType {
                root_type: root_type.to_string(),
                known: self.source.kind().to_string(),
            });
        }

        let Some(row) = AnchorRepository::get_live(
            pool,
            root_type,
            root_id,
            self.backend.name(),
            self.backend.network(),
        )
        .await?
        else {
            return Ok(AnchorVerification {
                verdict: AnchorVerdict::Missing,
                root_type: root_type.to_string(),
                root_id,
                anchored_root: None,
                live_root: None,
                anchor_id: None,
                backend: Some(self.backend.name().to_string()),
                network: Some(self.backend.network().to_string()),
                status: None,
                tx_id: None,
                block_height: None,
                block_time: None,
                sealed_at: None,
                sealed_after_block: None,
                trust_basis: self.trust_basis(),
                detail: Some(format!(
                    "no live anchor for {root_type} {root_id} on {}/{}",
                    self.backend.name(),
                    self.backend.network()
                )),
            });
        };

        self.verify_row(pool, &row).await
    }

    /// Verify an anchor row already in hand — what `--all` sweeps over.
    ///
    /// # Errors
    /// As [`Self::verify`].
    #[instrument(skip(self, pool, row), fields(anchor_id = %row.id))]
    pub async fn verify_row(
        &self,
        pool: &PgPool,
        row: &AnchorRow,
    ) -> Result<AnchorVerification, AnchorServiceError> {
        let mut report = AnchorVerification {
            verdict: AnchorVerdict::Verified,
            root_type: row.root_type.clone(),
            root_id: row.root_id,
            anchored_root: None,
            live_root: None,
            anchor_id: Some(row.id),
            backend: Some(row.backend.clone()),
            network: Some(row.network.clone()),
            status: Some(row.status.clone()),
            tx_id: row.tx_id.clone(),
            block_height: row.block_height,
            block_time: row.block_time,
            sealed_at: Some(row.sealed_at),
            sealed_after_block: row
                .block_time
                .map(|bt| sealed_after_block(row.sealed_at, bt.timestamp())),
            trust_basis: trust_basis_for_backend(&row.backend),
            detail: None,
        };

        // (2) The stored payload must hash to the stored digest.
        let actual = ContentHasher::hash(&row.commitment_bytes);
        if actual.as_slice() != row.commitment_hash.as_slice() {
            report.verdict = AnchorVerdict::CommitmentTampered;
            report.detail = Some(format!(
                "blake3(commitment_bytes) is {} but commitment_hash is {}",
                ContentHasher::to_hex(&actual),
                hex_of(&row.commitment_hash)
            ));
            return Ok(report);
        }

        // (3) The payload's own contents must agree with the row's columns.
        // This is the check that catches an edited `root_hash` — the column is
        // never trusted on its own.
        let commitment = match AnchorCommitment::from_cbor(&row.commitment_bytes) {
            Ok(c) => c,
            Err(e) => {
                report.verdict = AnchorVerdict::CommitmentTampered;
                report.detail = Some(format!("commitment does not decode: {e}"));
                return Ok(report);
            }
        };
        report.anchored_root = Some(hex_of(&commitment.root_hash));

        if commitment.root_hash.as_slice() != row.root_hash.as_slice() {
            report.verdict = AnchorVerdict::CommitmentTampered;
            report.detail = Some(format!(
                "published root is {} but anchors.root_hash says {}",
                hex_of(&commitment.root_hash),
                hex_of(&row.root_hash)
            ));
            return Ok(report);
        }
        if commitment.root_id != *row.root_id.as_bytes() {
            report.verdict = AnchorVerdict::CommitmentTampered;
            report.detail = Some(format!(
                "published root_id is {} but the row says {}",
                Uuid::from_bytes(commitment.root_id),
                row.root_id
            ));
            return Ok(report);
        }
        if commitment.kind != row.root_type {
            report.verdict = AnchorVerdict::CommitmentTampered;
            report.detail = Some(format!(
                "published kind is {:?} but the row says {:?}",
                commitment.kind, row.root_type
            ));
            return Ok(report);
        }

        // (4) Nothing below is meaningful until the ledger has it.
        if row.status != "confirmed" {
            report.verdict = AnchorVerdict::Unconfirmed;
            report.detail = Some(match &row.failure_reason {
                Some(r) => format!("anchor status is {:?}: {r}", row.status),
                None => format!("anchor status is {:?}", row.status),
            });
            return Ok(report);
        }

        // (5) The ledger's own copy of the bytes.
        if let Some(tx_id) = row.tx_id.as_deref() {
            match self.backend.fetch(tx_id).await {
                Ok(None) => {
                    report.verdict = AnchorVerdict::LedgerMissing;
                    report.detail = Some(format!(
                        "{} has no transaction {tx_id}",
                        self.backend.name()
                    ));
                    return Ok(report);
                }
                Ok(Some(published)) => {
                    if published.metadata_cbor != row.commitment_bytes {
                        report.verdict = AnchorVerdict::LedgerMismatch;
                        report.detail = Some(format!(
                            "the ledger holds {} bytes that differ from the {} stored locally",
                            published.metadata_cbor.len(),
                            row.commitment_bytes.len()
                        ));
                        return Ok(report);
                    }
                    report.block_height = Some(published.block_height);
                    report.block_time = Some(unix_to_utc(published.block_time_unix));
                    report.sealed_after_block =
                        Some(sealed_after_block(row.sealed_at, published.block_time_unix));
                }
                Err(e) => {
                    // A transport failure is not evidence of tampering. Report
                    // it as unconfirmed-with-a-reason rather than convicting.
                    report.verdict = AnchorVerdict::Unconfirmed;
                    report.detail = Some(format!("could not read the ledger back: {e}"));
                    return Ok(report);
                }
            }
        }

        // (6) Does the root still derive to what we anchored?
        let live = self.source.live_root(pool, row.root_id).await?;
        match live {
            None => {
                report.verdict = AnchorVerdict::RootUnresolvable;
                report.detail = Some(format!(
                    "{} {} can no longer be re-derived from live rows",
                    row.root_type, row.root_id
                ));
            }
            Some(live_root) => {
                report.live_root = Some(hex_of(&live_root));
                if live_root != commitment.root_hash {
                    report.verdict = AnchorVerdict::Drift;
                    report.detail = Some(format!(
                        "anchored root {} but the live rows fold to {} — this layer reports the \
                         difference and does not judge it",
                        hex_of(&commitment.root_hash),
                        hex_of(&live_root)
                    ));
                }
            }
        }

        Ok(report)
    }

    /// Verify every anchor, newest first.
    ///
    /// # Errors
    /// As [`Self::verify`].
    #[instrument(skip(self, pool))]
    pub async fn verify_all(
        &self,
        pool: &PgPool,
        limit: i64,
    ) -> Result<Vec<AnchorVerification>, AnchorServiceError> {
        let mut out = Vec::new();
        for row in AnchorRepository::list_all(pool, limit).await? {
            out.push(self.verify_row(pool, &row).await?);
        }
        Ok(out)
    }
}

/// Anchor a freshly sealed manifest. Never fails the caller.
///
/// THE LIVE CALL SITE for this whole track: invoked immediately after the seal
/// transaction commits, so every sealed manifest gets an `anchors` row with no
/// operator action and no configuration. Failures warn and return — see the
/// module docs for why blocking a seal on a ledger would be the wrong trade.
#[instrument(skip(pool))]
pub async fn anchor_manifest_best_effort(pool: &PgPool, manifest_id: Uuid) {
    let service = match AnchorService::from_env(pool) {
        Ok(s) => s,
        Err(e) => {
            warn!(manifest_id = %manifest_id, "anchoring skipped, backend unusable: {e}");
            return;
        }
    };
    match service.anchor(pool, ROOT_TYPE_MANIFEST, manifest_id).await {
        Ok(row) => {
            tracing::debug!(
                manifest_id = %manifest_id, anchor_id = %row.id, status = %row.status,
                "manifest root anchored"
            );
        }
        Err(e) => warn!(manifest_id = %manifest_id, "anchoring failed: {e}"),
    }
}

/// `"operator-held"` for the in-Postgres mock ledger, `"third-party"` for any
/// other, keyed on the backend NAME AS RECORDED ON THE ROW.
///
/// `AnchorService::verify_all` sweeps `AnchorRepository::list_all`, which is
/// not filtered by backend, so a process configured for one ledger routinely
/// reports on rows another one wrote — the ordinary dev-mock -> prod-chain
/// migration leaves exactly that mixture behind. Deriving the label from the
/// process would make an honesty guard lie about itself in both directions,
/// including the dangerous one: stamping `"third-party"` on an anchor whose
/// ledger is a table in this same database.
#[must_use]
pub fn trust_basis_for_backend(backend: &str) -> &'static str {
    if backend == "mock" {
        TRUST_OPERATOR_HELD
    } else {
        TRUST_THIRD_PARTY
    }
}

/// Lowercase hex, matching every other digest this codebase prints.
fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Was the CLAIMED seal time later than the block that PROVES existence?
///
/// Compared as unix seconds, because a ledger block time is second-resolution
/// and `sealed_at` is a microsecond Postgres timestamp. Comparing the raw
/// values would flag every honest seal whose sub-second part happens to exceed
/// the block's truncated one — which is most of them.
fn sealed_after_block(sealed_at: DateTime<Utc>, block_time_unix: i64) -> bool {
    sealed_at.timestamp() > block_time_unix
}

/// Unix seconds -> UTC, saturating rather than panicking on a nonsense value.
fn unix_to_utc(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now)
}

/// Compile-time assurance that the hash width the schema enforces and the one
/// the commitment carries are the same number.
const _: () = assert!(HASH_SIZE == epigraph_interfaces::anchor::ROOT_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    /// THE DEFAULT-IS-ON PROPERTY. Unset must mean `mock`, not "off" — there is
    /// deliberately no `EPIGRAPH_ANCHOR_ENABLED`, so unset is the state of
    /// every existing test and every dev machine, and the default path is the
    /// live path. Pure, so no env mutation and no race with other tests.
    #[test]
    fn backend_from_env_defaults_to_mock() {
        assert_eq!(parse_backend_name(None), Ok(BackendKind::Mock));
        assert_eq!(parse_backend_name(Some("")), Ok(BackendKind::Mock));
        assert_eq!(parse_backend_name(Some("  ")), Ok(BackendKind::Mock));
        assert_eq!(parse_backend_name(Some("mock")), Ok(BackendKind::Mock));
        assert_eq!(
            parse_backend_name(Some(" cardano ")),
            Ok(BackendKind::Cardano)
        );

        // A typo must not silently fall back to the mock — an operator who
        // wrote `cardanno` must not be told their data is anchored on chain.
        assert_eq!(
            parse_backend_name(Some("cardanno")),
            Err("cardanno".to_string())
        );
    }

    #[test]
    fn every_verdict_but_verified_is_a_problem() {
        assert!(!AnchorVerdict::Verified.is_problem());
        for v in [
            AnchorVerdict::Missing,
            AnchorVerdict::CommitmentTampered,
            AnchorVerdict::Unconfirmed,
            AnchorVerdict::LedgerMissing,
            AnchorVerdict::LedgerMismatch,
            AnchorVerdict::RootUnresolvable,
            AnchorVerdict::Drift,
        ] {
            assert!(v.is_problem(), "{v:?} must exit non-zero");
        }
    }

    /// THE TRUNCATION TRAP. `block_time_unix` is second-resolution, so a
    /// microsecond `sealed_at` compared raw would flag almost every honest seal
    /// as backdated.
    #[test]
    fn sub_second_precision_does_not_look_like_backdating() {
        let block = 1_700_000_000i64;
        let same_second = Utc.timestamp_opt(block, 900_000_000).single().unwrap();
        assert!(
            !sealed_after_block(same_second, block),
            "a seal in the same second as the block is not backdated"
        );

        let before = Utc.timestamp_opt(block - 5, 0).single().unwrap();
        assert!(!sealed_after_block(before, block));

        let after = Utc.timestamp_opt(block + 60, 0).single().unwrap();
        assert!(
            sealed_after_block(after, block),
            "a seal a minute after the proving block IS backdated"
        );
    }

    #[test]
    fn verdicts_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_value(AnchorVerdict::CommitmentTampered).unwrap(),
            serde_json::json!("commitment_tampered")
        );
        assert_eq!(
            serde_json::to_value(AnchorVerdict::Drift).unwrap(),
            serde_json::json!("drift")
        );
    }
}
