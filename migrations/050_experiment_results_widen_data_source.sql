-- Widen experiment_results.data_source from varchar(30) to text
-- and add 'literature' and 'computed' to allowed values.
-- Applied live on 2026-03-17; this migration makes it reproducible.

ALTER TABLE experiment_results ALTER COLUMN data_source TYPE text;

ALTER TABLE experiment_results DROP CONSTRAINT IF EXISTS experiment_results_data_source_check;
ALTER TABLE experiment_results ADD CONSTRAINT experiment_results_data_source_check
  CHECK (data_source IN ('manual', 'simulation', 'instrument', 'literature', 'computed'));
