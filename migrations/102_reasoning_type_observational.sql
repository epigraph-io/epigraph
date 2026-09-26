-- Migration 102: allow `observational` in reasoning_traces.reasoning_type (ADDITIVE).
--
-- EVIDENCE
-- `reasoning_type_valid` (migration 001) permits only deductive, inductive,
-- abductive, analogical, statistical. MCP `submit_claim` collapses
-- direct_observation / observational / statistical / instrumental /
-- computational into Methodology::Instrumental, and the repository then writes
-- that as 'statistical', so the distinction between observation and statistics
-- is lost at write time.
--
-- CHANGE
-- Drop and recreate the CHECK with exactly one additional value,
-- 'observational' (read back as Methodology::Instrumental). No other values are
-- added; extend the set in a later migration if a mapping needs it.
--
-- Existing rows are NOT backfilled: every stored value remains valid under the
-- widened constraint, and the original observational intent is unrecoverable.

ALTER TABLE reasoning_traces DROP CONSTRAINT IF EXISTS reasoning_type_valid;

ALTER TABLE reasoning_traces
    ADD CONSTRAINT reasoning_type_valid CHECK (
        reasoning_type::text = ANY (ARRAY[
            'deductive', 'inductive', 'abductive', 'analogical',
            'statistical', 'observational'
        ]::text[])
    );
