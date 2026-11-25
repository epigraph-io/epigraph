-- Undo migration 282 (human_evidence_guard_agent_id): restore 274's evidence guard (no
-- agent_id refusal; the trigger watches client_type only). Run on a maintenance connection.
-- CREATE OR REPLACE keeps the owner and ACL. Idempotent.
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
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_oauth_clients_human_evidence_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS epigraph_oauth_clients_human_evidence_guard ON public.oauth_clients;
CREATE TRIGGER epigraph_oauth_clients_human_evidence_guard
    BEFORE DELETE OR UPDATE OF client_type ON public.oauth_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_oauth_clients_human_evidence_guard();
