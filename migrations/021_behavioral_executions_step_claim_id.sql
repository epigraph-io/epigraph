-- Migration 021: per-(execution, step) granularity for behavioral_executions (#34).
-- Adds nullable step_claim_id; existing rows stay NULL (one row per execution).
-- New hierarchical-workflow callers write N rows per execution where N=step count.
-- See spec section "Behavioral-executions extension".

ALTER TABLE behavioral_executions
    ADD COLUMN step_claim_id uuid REFERENCES claims(id);

CREATE INDEX behavioral_executions_step_claim_id_idx
    ON behavioral_executions (step_claim_id)
    WHERE step_claim_id IS NOT NULL;
