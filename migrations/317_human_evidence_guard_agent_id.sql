-- 317: the human-evidence guard (309, HEV01) also pins a linked human
-- client's `agent_id` (review finding correctness#5; spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 6.1).
--
-- WHY. 309's `epigraph_is_human_principal(agent)` keys on
-- `oauth_clients.agent_id = agent AND client_type = 'human'`. 309's guard
-- refuses a DELETE or a retype of such a row, but an UPDATE that re-points
-- (or NULLs) `agent_id` removes the old agent's evidence just as well: that
-- agent then reads as a non-human and is NAMED to everyone, the one fail-open
-- direction 309's header calls out. Today only maintenance could do it (118
-- revoked UPDATE from the application role; `epigraph_oauth_client_link_agent`
-- writes only `WHERE agent_id IS NULL`), and no code on HEAD does.
--
-- CHANGE. The guard function is re-stated with one more refusal (a linked
-- human client's `agent_id` never changes), and the trigger watches
-- `UPDATE OF client_type, agent_id`. The FIRST link of an unlinked human
-- client (OLD.agent_id IS NULL) stays allowed. The function stays SECURITY
-- INVOKER on 271's `pg_catalog, public, pg_temp` path; CREATE OR REPLACE keeps
-- its owner and ACL.
--
-- UNDO: `docs/runbooks/317-undo.sql` (309's body and trigger).
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_oauth_clients_human_evidence_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.client_type = 'human' AND OLD.agent_id IS NOT NULL THEN
            RAISE EXCEPTION 'HEV01: a human OAuth client linked to an agent is that agent''s '
                            'human evidence and is never deleted; nothing was changed'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.client_type = 'human' AND OLD.agent_id IS NOT NULL
       AND NEW.client_type IS DISTINCT FROM OLD.client_type THEN
        RAISE EXCEPTION 'HEV01: a human OAuth client linked to an agent is that agent''s '
                        'human evidence and never changes type; nothing was changed'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.client_type = 'human' AND OLD.agent_id IS NOT NULL
       AND NEW.agent_id IS DISTINCT FROM OLD.agent_id THEN
        RAISE EXCEPTION 'HEV01: a human OAuth client linked to an agent is that agent''s '
                        'human evidence and is never re-pointed or unlinked; nothing was '
                        'changed'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_oauth_clients_human_evidence_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS epigraph_oauth_clients_human_evidence_guard ON public.oauth_clients;
CREATE TRIGGER epigraph_oauth_clients_human_evidence_guard
    BEFORE DELETE OR UPDATE OF client_type, agent_id ON public.oauth_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_oauth_clients_human_evidence_guard();
