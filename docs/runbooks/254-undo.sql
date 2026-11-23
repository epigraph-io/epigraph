-- Undo migration 254 (hierarchical_cycle_walk_definer): drop the cycle-walk definer.
-- Run on a maintenance connection, and only AFTER rolling every binary back to one whose
-- `EdgeRepository::reaches_in_force_conn` walks inline: a 254 binary refuses every
-- cycle-checked `link_hierarchical` call (42883) without it. Idempotent. Afterwards the
-- cycle guard is per viewer again (a cycle closed through an unreadable edge is admitted).
DROP FUNCTION IF EXISTS public.epigraph_edges_reach(uuid, uuid, text[]);
