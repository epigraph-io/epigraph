-- Undo migration 309 (human_identity_disclosure): drop the disclosure predicate, the
-- evidence guard and the allowance index.
-- Run on a maintenance connection, AFTER rolling back any binary built against 309 (or
-- 310/311, whose setter calls the core): such a binary calls these functions and fails
-- (SQLSTATE 42883) without them. Undo 311 and 310 first. Idempotent. No rows change.
DROP TRIGGER IF EXISTS epigraph_oauth_clients_human_evidence_guard ON public.oauth_clients;
DROP FUNCTION IF EXISTS public.epigraph_oauth_clients_human_evidence_guard();
DROP FUNCTION IF EXISTS public.epigraph_human_named_to_viewer(uuid);
DROP FUNCTION IF EXISTS public.epigraph_agent_disclosure(uuid);
DROP FUNCTION IF EXISTS public.epigraph_agent_disclosure_for(uuid, uuid, uuid[], boolean);
DROP FUNCTION IF EXISTS public.epigraph_is_human_principal(uuid);
DROP INDEX IF EXISTS public.idx_author_binding_clients_operator;
