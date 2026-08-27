-- Migration 073: the obligation layer (backlog 4b48ffb5) — a record of what
-- an answer OWES, separate from what the agent should DO.
--
-- NUMBERING -- 070_blobs.sql, 071_manifests.sql and 072_anchors.sql landed
-- first on this same branch, and 060..069 are deliberately left clear for a
-- concurrently developed sibling branch that is also adding migrations. 073 is
-- the first free number above both.
--
-- EVIDENCE
-- epiclaw-host's emitter_contract.rs recorded a false TASK_SILENT on
-- 2026-08-05 and cost a day of propagation. The assertion "nothing was
-- emitted" was believed because nothing counted it. This table is where a
-- completeness assertion goes to be counted instead of trusted.
--
-- `anchors` deliberately has no foreign key: Postgres cannot FK an array
-- element. A retired or deleted anchor is dropped by the recheck join, which
-- is the correct arithmetic (coverage DECAYS when a claim is superseded), not
-- a dangling reference.
--
-- `missing_contract_fields` is the contract's self-report: what it has not yet
-- specified about ITSELF. Under this MVP a `material` contract always carries
-- ['materiality_criterion'] because no count can supply a materiality
-- judgement. Only `exhaustive` and `native_complete` are settled by counting;
-- the other three standards are recorded, not decided.

CREATE TABLE IF NOT EXISTS obligations (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Nullable so a library-level or unauthenticated path can still record an
    -- obligation, matching recall_events.agent_id.
    agent_id                UUID REFERENCES agents(id) ON DELETE SET NULL,
    -- Coverage standard read off the request's own grammar.
    standard                TEXT NOT NULL,
    -- What is being counted, e.g. 'claim', 'emitter', 'section'.
    unit                    TEXT NOT NULL,
    -- The denominator the answer bound itself to.
    declared_total          INTEGER NOT NULL,
    -- Countable evidence anchors actually recorded. Distinct ids only.
    anchors                 UUID[] NOT NULL DEFAULT ARRAY[]::UUID[],
    -- What kind of row `anchors` points at. 'claim' in this MVP.
    anchor_kind             TEXT NOT NULL DEFAULT 'claim',
    -- The numerator at `checked_at`. Recomputable from `anchors`.
    observed_total          INTEGER NOT NULL,
    verdict                 TEXT NOT NULL,
    verdict_reason          TEXT,
    -- What this contract has not specified about itself.
    missing_contract_fields TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- Which tool opened the obligation, e.g. 'batch_submit_claims'.
    source_tool             TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checked_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Fail closed on vocabulary: an unrecognised standard must not be stored
    -- and then silently treated as owing nothing.
    CONSTRAINT obligations_standard_vocab CHECK (
        standard IN ('exhaustive', 'native_complete', 'material',
                     'representative', 'summary')
    ),
    CONSTRAINT obligations_verdict_vocab CHECK (
        verdict IN ('satisfied', 'breach', 'indeterminate', 'not_applicable')
    ),
    CONSTRAINT obligations_declared_total_nonneg CHECK (declared_total >= 0),
    CONSTRAINT obligations_observed_total_nonneg CHECK (observed_total >= 0),
    CONSTRAINT obligations_unit_nonempty CHECK (length(btrim(unit)) > 0)
);

COMMENT ON TABLE obligations IS
    'What an answer owes: a declared coverage standard over a countable unit, '
    'closed by counting anchors rather than by trusting an assertion. '
    'Only exhaustive and native_complete are decidable by count in this MVP.';

COMMENT ON COLUMN obligations.missing_contract_fields IS
    'Fields this contract has not specified about itself. A material contract '
    'always carries materiality_criterion; a representative contract always '
    'carries sampling_frame; native_complete always carries declared_unit_keys '
    '(count equality does not prove the units are the same units).';

-- Recent obligations for one agent.
CREATE INDEX IF NOT EXISTS obligations_agent_created_idx
    ON obligations (agent_id, created_at DESC);

-- Partial index over the only rows anyone sweeps for: unmet obligations.
CREATE INDEX IF NOT EXISTS obligations_unmet_idx
    ON obligations (checked_at DESC)
    WHERE verdict IN ('breach', 'indeterminate');
