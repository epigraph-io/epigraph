-- Migration 016: Frames of discernment
--
-- A frame defines the set of mutually exclusive, exhaustive hypotheses
-- for a particular question. Claims belong to frames via the junction table.
--
-- Evidence:
-- - dekg-planning-doc.md: "Every claim belongs to at least one frame of discernment"
-- - DS theory requires frames for mass function definition
--
-- Reasoning:
-- - hypotheses stored as TEXT[] for ordered access (index = hypothesis position)
-- - Minimum 2 hypotheses enforced (a single hypothesis is trivial)
-- - claim_frames junction allows many-to-many (claims can appear in multiple frames)
-- - hypothesis_index nullable: a claim may span multiple hypotheses in a frame

CREATE TABLE frames (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL UNIQUE,
    description TEXT,
    hypotheses TEXT[] NOT NULL,       -- ordered list of hypothesis labels
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT frames_not_empty CHECK (array_length(hypotheses, 1) >= 2)
);

-- Junction: claims belong to frames
CREATE TABLE claim_frames (
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    frame_id UUID NOT NULL REFERENCES frames(id) ON DELETE CASCADE,
    hypothesis_index INT,  -- which hypothesis this claim maps to (nullable if claim spans multiple)
    PRIMARY KEY (claim_id, frame_id)
);

CREATE INDEX idx_claim_frames_frame ON claim_frames(frame_id);
CREATE INDEX idx_frames_name ON frames(name);
