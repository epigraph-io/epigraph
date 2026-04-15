-- Bridge workflow_executions to workflow claim templates
-- workflow_id references the claim ID of the workflow template (labeled 'workflow')
-- This makes execution tracking traceable to its template definition.

-- Note: workflow_executions.workflow_id was initially nullable with no FK (migration 080
-- added FK to tasks.workflow_id -> workflow_executions.id, but workflow_executions itself
-- had no FK to the template). We add a template_claim_id column.

ALTER TABLE workflow_executions 
    ADD COLUMN IF NOT EXISTS template_claim_id UUID;

COMMENT ON COLUMN workflow_executions.template_claim_id IS 
    'References the claim ID of the workflow template (claims labeled workflow). NULL for ad-hoc executions.';
