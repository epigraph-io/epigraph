-- Migration 121: allow `observational` in reasoning_traces.reasoning_type (ADDITIVE).
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
--
-- LOCKS. `DROP CONSTRAINT` / `ADD CONSTRAINT ... CHECK` take ACCESS EXCLUSIVE
-- on `reasoning_traces`, and the ADD scans every row to validate the CHECK
-- while holding it, so reads and writes of the table queue behind this
-- migration. `lock_timeout` bounds the wait for that lock, as in 111-120: on a
-- busy table the migration fails fast (re-run it, in a maintenance window),
-- instead of queueing every request behind it. A `NOT VALID` + `VALIDATE
-- CONSTRAINT` split would buy nothing here, because the migrator runs this
-- file in ONE transaction and the ACCESS EXCLUSIVE taken by the DROP is held
-- through the VALIDATE until commit. The scan is a single CHECK over one text
-- column, so its hold time is short.
--
-- Undo: restore 001's constraint (the same name, without 'observational')
-- only after deleting or rewriting every row whose reasoning_type is
-- 'observational'; roll the binaries back first so nothing writes it.

SET LOCAL lock_timeout = '3s';

ALTER TABLE reasoning_traces DROP CONSTRAINT IF EXISTS reasoning_type_valid;

ALTER TABLE reasoning_traces
    ADD CONSTRAINT reasoning_type_valid CHECK (
        reasoning_type::text = ANY (ARRAY[
            'deductive', 'inductive', 'abductive', 'analogical',
            'statistical', 'observational'
        ]::text[])
    );
