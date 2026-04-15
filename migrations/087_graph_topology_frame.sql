-- Create the graph-topology frame for edge-derived DS evidence.
-- This frame has binary hypotheses: supported vs contradicted.
-- Edge-triggered DS recomputation submits evidence to this frame.
INSERT INTO frames (name, hypotheses)
VALUES ('graph-topology', ARRAY['supported', 'contradicted'])
ON CONFLICT (name) DO NOTHING;
