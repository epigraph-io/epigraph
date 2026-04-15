-- Migration: 026_add_community_mass_override
-- Description: Add mass_override JSONB column to communities table
--
-- §1.1 COMMUNITY specifies community_mass_override — optional mass assignments
-- that override simple combination of member BBAs.
--
-- Evidence:
-- - dekg-planning-doc.md §1.1 COMMUNITY node type
-- - Phase 7 plan Step 6: community mass override
--
-- Reasoning:
-- - JSONB allows flexible storage of frame_id → mass assignment mappings
-- - NULL means "no override, use normal combination"
-- - Format: {"<frame_id>": {"0,1": 0.8, "": 0.2}} (frame → mass function)
--
-- Verification:
-- - Default NULL preserves existing community behavior

ALTER TABLE communities ADD COLUMN mass_override JSONB;
