# External Anchoring — Design

**Date:** 2026-08-27
**Status:** Implemented (kernel, v1 — mock ledger only; Cardano backend is a
selectable stub that publishes nothing).
**Backlog:** 94e62824
**Builds on:** migration 071 (Merkle manifests, backlog 6e2364b8)
**Repos touched:** `epigraph-io/epigraph`

## Problem

`provenance_log` is append-only against SQL and `manifests` carries an Ed25519
signature over a Merkle root. Both are tamper-**evident**. Neither is tamper-
**proof against the operator**: whoever controls this Postgres controls the log,
holds the signing key, and can drop the triggers. Every countersignature lives
in the same database as the thing it countersigns.

So a third party receiving an EpiGraph export today can verify *authorship* and
*set membership*, but must simply trust this instance about *when* the set
existed. The only way to fix that is for somebody who is not us to hold a copy
of the commitment.

## What is anchored, and why not `provenance_log`

The **Merkle root of a sealed manifest** — 32 bytes — not raw `provenance_log`
rows.

* The manifest root is already a redactable commitment over row digests, and
  (per backlog 6e2364b8) it commits only to the write-once subset of each row,
  so it survives ordinary label churn and belief recomputes.
* It has natural boundaries: one export run, one root.
* Anchoring it transitively anchors every row it commits to.

Anchoring `provenance_log` directly would require inventing a time-window
scheme with no natural edges, and would re-anchor on every write.

## Wire format

Deterministic CBOR per RFC 8949 §4.2.1: a definite-length 7-pair map (`0xa7`)
with single-char text keys in canonical order (length first, then bytewise, so
`i, k, n, r, s, t, v`).

| key | value | CBOR type | bytes |
|---|---|---|---|
| `i` | `root_id` | byte string | 16 |
| `k` | root kind (`"manifest"`) | text | 8 |
| `n` | `leaf_count` | uint | ≤ 8 |
| `r` | `root_hash` (BLAKE3) | byte string | 32 |
| `s` | `sealed_at`, unix seconds | uint | ≤ 8 |
| `t` | `"epigraph.anchor"` | text | 15 |
| `v` | commitment version (`1`) | uint | 1 |

**98 bytes** for a v1 manifest commitment. A pinned golden vector for a fixed
fixture lives in `crates/epigraph-interfaces/src/anchor.rs`:

```
a7 616950 0102030405060708090a0b0c0d0e0f10 616b686d616e6966657374 616e05
61725820 abab..ab 61731a68e77800 61746f65706967726170682e616e63686f72 617601
```

Three constraints are load-bearing and each has a test:

1. **Every value ≤ 64 bytes.** That is the Cardano transaction-metadata limit
   for a bytestring or text string. It is why the commitment is a flat map of
   short scalars, and why a future field that overflows it must fail loudly
   rather than at a wallet.
2. **The map is built by hand** as a `ciborium::value::Value::Map`, never by
   serde derive. Derive would encode `[u8; 32]` as a CBOR *array of 32 uints* —
   breaking both the wire format and the 64-byte limit, without failing to
   compile.
3. **Decoding is strict.** An unknown `v`, a foreign `t`, a wrong-width `r`, or
   a missing key is an error, not a lenient parse. Verification re-derives the
   root from these bytes and never trusts a stored column, so a decoder that
   guessed would hand back an attacker-chosen root.

`s` is included even though the ledger also timestamps: the commitment carries
the **claimed** seal time, the block carries the **proven** upper bound, and
verification surfaces both so `sealed_at > block_time` is detectable as a
backdated seal. The comparison is at one-second resolution, because that is
what a block time carries — a microsecond `sealed_at` compared raw would flag
almost every honest seal.

The commitment is **not separately signed**. The manifest is already
Ed25519-signed by the run's agent; a second signature by a key we also hold adds
no third-party property, and the third-party property is the entire point.

## Verify algorithm

Cheapest and most damning first; the first failure decides the verdict.

| # | Check | Verdict on failure |
|---|---|---|
| 1 | is there an `anchors` row for this root? | `missing` |
| 2 | `blake3(commitment_bytes) == commitment_hash`? | `commitment_tampered` |
| 3 | decoded `r` / `i` / `k` agree with the row's columns? | `commitment_tampered` |
| 4 | `status == 'confirmed'`? | `unconfirmed` |
| 5 | `backend.fetch(tx_id)` returns bytes, and they match ours? | `ledger_missing` / `ledger_mismatch` |
| 6 | does the root still re-derive from live rows, to the same value? | `root_unresolvable` / `drift` |
| 7 | — | `verified` |

Check **(3) is the one that matters most**: it is what catches an operator who
edits `anchors.root_hash` alone. Verification never trusts that column — the
reported `anchored_root` is decoded out of the published payload every time.

**Drift is reported, not judged.** Both hex roots come back and the caller
decides. Whether a divergence is benign (a legitimately deleted claim) or
malicious depends on what the manifest chose to commit to, which is the manifest
track's semantic, not this one's.

## THE MOCK LEDGER IS NOT A TRUST BOUNDARY

The kernel default `MockAnchorBackend` is a **real append-only ledger**: it
writes the exact published bytes to `anchor_mock_chain`, whose BEFORE UPDATE and
BEFORE DELETE triggers refuse every mutation, and verification reads them back
out of that table to compare byte-for-byte against `anchors.commitment_bytes`.
Two stores must agree and one of them cannot be edited at all.

**And it lives in the same Postgres as the anchors it attests to.** Whoever can
`DROP TRIGGER` can rewrite it. A green `verify_anchor` against `backend = "mock"`
proves the **mechanism** — commitment computed, published, read back, compared —
and does **not** remove the operator from the trust base.

Every report therefore carries `trust_basis`: `"operator-held"` for the mock,
`"third-party"` otherwise. The same statement is written into the migration
comments, the module docs, and the CLI's help. **A mock verification is not an
audit result.**

Why a mock at all, rather than the crate's usual `NoOp*` default? Because a
no-op anchor backend *is* the inert-feature failure mode: it would report
success while publishing nothing. `AnchorBackend` is the one trait in
`epigraph-interfaces` with deliberately no no-op implementation.

## No enable flag

There is no `EPIGRAPH_ANCHOR_ENABLED`. Anchoring on manifest seal is
unconditional. The only knob is `EPIGRAPH_ANCHOR_BACKEND`, whose default when
unset is `"mock"` — and unset is the state of every existing test and every dev
machine, so the default path *is* the on path.

The live call site is `epigraph_engine::export::manifest::anchor_manifest`,
immediately after its transaction commits. That is the single write path that
produces a sealed root; both the `export_subgraph_manifest` MCP tool and the
`export_provenance` CLI funnel through it, and a hook per caller would leave
whichever one was forgotten producing un-anchored manifests.

It is best-effort and post-commit, matching CLAUDE.md's embedding contract
verbatim: warn on failure, record a `status = 'failed'` row, never fail or
delay the seal. The cost is stated plainly — a real backend outage accumulates
failed rows silently. `idx_anchors_open`, `AnchorService::poll_pending`, and
`anchor_verify --all` exiting `2` are what surface it. There is no alerting in
this track.

## Idempotency

Partial unique index `uq_anchors_live_root (root_type, root_id, backend,
network) WHERE status <> 'failed'`, with an `ON CONFLICT ... DO NOTHING` whose
predicate matches so Postgres infers the index.

* A **successful** anchor can never be duplicated. Two live commitments over
  one root would let an operator keep both and present whichever suited them at
  verify time.
* A **failed** attempt is outside the index, so a retry after `NotConfigured` or
  a transport failure is allowed and gets a fresh row.

## Storage guards

`anchors` needs UPDATE for `pending -> submitted -> confirmed`, so a blanket
append-only trigger would break the feature. Instead a BEFORE UPDATE trigger
raises if any commitment-bearing column changes (`root_type`, `root_id`,
`root_hash`, `commitment_version`, `commitment_hash`, `commitment_bytes`,
`backend`, `network`, `sealed_at`, `created_at`), plus a BEFORE DELETE trigger
that blocks removal outright. `anchor_mock_chain` gets the blanket guard.

`tx_id` is deliberately **not** guarded: repointing an anchor at a different
ledger transaction is exactly what check (5) exists to catch, and the test that
covers `ledger_mismatch` does it that way.

A new generic `raise_append_only_error()` using `TG_TABLE_NAME` is added rather
than reusing migration 001's `raise_immutable_error()`, whose message is
hardcoded to `provenance_log`.

## Chain selection is DEFERRED, with a procedure

This track ships zero chain integration: no wallet, no key custody, no funding,
no HTTP client, no network I/O. `CardanoBlockfrostBackend` compiles, is
selectable, pins `METADATUM_LABEL = 40961` (per the OpenWater PoC), reads
`BLOCKFROST_PROJECT_ID`, and returns `NotConfigured` without it /
`Unimplemented` with it.

**The decision rule, to be executed rather than argued:**

1. Run mock-only for one month.
2. Read the volume straight off `SELECT count(*) FROM anchors`.
3. Price the three candidates against that number:

| Candidate | Cost | Third party is | Ordering guarantee |
|---|---|---|---|
| Cardano metadata, label 40961 | ~0.17 ADA/tx, plus a funded wallet and key custody | a public chain | strongest |
| Sigstore / Rekor | free | the log operator — a third party of a different kind | transparency log |
| Signed git tag pushed to a forge | free | GitHub | weakest |

`AnchorBackend` admits all three unchanged: each is submit-bytes-get-an-id plus
fetch-by-id. **Volume, not ideology, picks the winner.**

## Scale posture

One commitment per sealed manifest, deliberately. Batching many roots under one
checkpoint tree is the obvious cost lever on a real chain, and the commitment's
`k` field plus `anchors.root_type` already reserve `"checkpoint"` for it. The
tree is not built: optimising per-transaction cost against a mock that costs
nothing per transaction would be optimising a number nobody has measured.

## Out of scope for v1

Real chain integration of any kind; Sigstore/Rekor and git-tag backends;
checkpoint batching; a background confirmation daemon (`poll_pending` exists and
`anchor_verify --poll` drives it manually); HTTP routes under `/api/v1/anchors`;
persisted verification history; signing the commitment; anchoring
`provenance_log` rows; re-anchoring policy when a manifest is legitimately
re-sealed; automated remediation on drift; and — stated last because it is the
one that matters — **removing the operator from the trust base in practice**,
which only a configured real backend delivers.

## Surface

* Migration `072_anchors.sql` — `anchors`, `anchor_mock_chain`,
  `anchor_mock_chain_height_seq`, three triggers.
* `epigraph-interfaces/src/anchor.rs` — `AnchorBackend`, `AnchorCommitment`,
  `AnchorReceipt`, `PublishedAnchor`, `AnchorError`. Pure; no DB, no chrono.
* `epigraph-db/src/repos/anchor.rs` — **all SQL** (`AnchorRepository`,
  `MockChainRepository`), per CLAUDE.md.
* `epigraph-db/src/anchor/` — orchestration only, no SQL: `service.rs`,
  `mock.rs`, `cardano.rs`, `root_source.rs`. (Two modules named `anchor` in one
  crate is mildly confusing and documented in both; resolving it by moving SQL
  out of `repos/` would violate CLAUDE.md.)
* `root_source.rs` is **the only file coupled to the manifest track**.
  Verification is generic over `AnchorRootSource`.
* MCP: `anchor_manifest` (`claims:write`), `verify_anchor` (`claims:read`).
  Existing scope buckets; no new scope, so `canonical_scopes.rs` is untouched.
* CLI: `anchor_verify --root-id | --all | --poll`, exiting `0` / `2` / `1`.
