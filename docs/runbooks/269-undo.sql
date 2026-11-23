-- Undo migration 269 (agent_card_disclosure_readers): drop the card's read definers.
-- Run on a maintenance connection, AFTER rolling back any binary built against 269:
-- such a binary calls these functions on every find_agent / get_agent card and fails
-- (SQLSTATE 42883) without them. Idempotent. No rows, tables or policies change.
DROP FUNCTION IF EXISTS public.epigraph_agents_linked_to_operator(uuid);
