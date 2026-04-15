-- Migration 089: Add source strength and evidence type to mass_functions
--
-- Evidence:
-- - Stress test C2/C3: reliability discounting needs per-BBA strength metadata
-- - Currently mass_functions has no record of the original evidence strength
--
-- Reasoning:
-- - source_strength is the raw strength parameter from evidence submission
-- - evidence_type is the classification (empirical, testimonial, etc.)
-- - Both nullable: existing rows default to NULL → reliability=1.0 (no discount)

ALTER TABLE mass_functions ADD COLUMN source_strength DOUBLE PRECISION;
ALTER TABLE mass_functions ADD COLUMN evidence_type VARCHAR(50);
