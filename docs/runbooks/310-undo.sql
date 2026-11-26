-- Undo migration 310 (profile_visibility_setter): drop the self-service setter.
-- Run on a maintenance connection, AFTER rolling back any binary built against 310: the MCP
-- tool set_profile_visibility and PUT /api/v1/agents/:id's profile_visibility field call it
-- and fail (SQLSTATE 42883) without it. Values already set stay as they are. Idempotent.
DROP FUNCTION IF EXISTS public.epigraph_set_profile_visibility(text);
