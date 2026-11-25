-- no-transaction
--
-- Security review of 309 ("Addendum 5"; spec docs/superpowers/specs/
-- 2026-11-24-human-identity-visibility-design.md, sections 4 and 11): 316's
-- arm for BBAs counts only an ASSESSMENT slot, probing once per agent bound to
-- H `mass_functions.source_agent_id = b.agent_id AND slot_kind = 'assessment'
-- AND visibility = 'public' AND created_at >= b.since LIMIT 1`. 307's index
-- covers every public BBA (edge factors are the bulk of the table), so this
-- partial index carries the slot kind in its predicate. Text equality is
-- leakproof, so under the core's row security the probe is still an index
-- condition (pinned in tenancy_migration_shape.rs).
--
-- The predicate is written exactly as the arm writes it (partial-index
-- implication is proved syntactically).
--
-- INVALID-INDEX TRAP: a cancelled or failed CONCURRENTLY build leaves an
-- INVALID index of this name, and IF NOT EXISTS then skips it on a re-run.
-- Recovery: DROP INDEX CONCURRENTLY idx_mass_functions_public_assessments_by_source,
-- re-apply.
--
-- Exactly one statement (see 289).
-- Undo: DROP INDEX CONCURRENTLY IF EXISTS public.idx_mass_functions_public_assessments_by_source
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mass_functions_public_assessments_by_source
    ON public.mass_functions (source_agent_id, created_at)
    WHERE visibility = 'public' AND slot_kind = 'assessment';
