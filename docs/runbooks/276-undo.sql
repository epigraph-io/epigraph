-- Undo migration 276 (human_profile_visibility_group): restore 077's provisioning body.
-- Run on a maintenance connection. The reset of existing humans to 'group' is NOT reversed:
-- the pre-state was the column default, not consent, and cannot be recovered. CREATE OR
-- REPLACE keeps the owner and ACL. Idempotent.
CREATE OR REPLACE FUNCTION public.epigraph_provision_oauth_agent(
    p_public_key bytea, p_display_name text, p_agent_type text)
RETURNS uuid LANGUAGE sql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    INSERT INTO public.agents (public_key, display_name, agent_type, key_kind, labels)
    VALUES (p_public_key, p_display_name, p_agent_type, 'derived',
            ARRAY['oauth-principal'])
    ON CONFLICT (public_key) DO UPDATE SET updated_at = now()
        WHERE agents.key_kind = 'derived'
    RETURNING id
$$;
