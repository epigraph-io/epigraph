-- 091_stop_truth_value_overwrite.sql
--
-- truth_value is evidence-derived and should not be overwritten by
-- belief propagation or DS recomputation. The update_claim_belief
-- Rust function has been fixed to stop setting truth_value = BetP.
-- This migration is a no-op marker for tracking purposes.
SELECT 1;
