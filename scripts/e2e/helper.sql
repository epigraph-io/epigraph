CREATE OR REPLACE FUNCTION public.epigraph_is_visible_to_group(p_entity_id uuid, p_table text)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE
AS $function$
DECLARE
    gid uuid := epigraph_current_group_id();
    found boolean;
BEGIN
    IF p_table = 'claim' THEN
        SELECT EXISTS(
            SELECT 1 FROM claim_encryption ce
            WHERE ce.claim_id = p_entity_id
              AND ce.privacy_tier = 'fully_private'
              AND (gid IS NULL OR ce.group_id != gid)
        ) INTO found;
    ELSIF p_table = 'evidence' THEN
        SELECT EXISTS(
            SELECT 1 FROM evidence_encryption ee
            WHERE ee.evidence_id = p_entity_id
              AND ee.privacy_tier = 'fully_private'
              AND (gid IS NULL OR ee.group_id != gid)
        ) INTO found;
    ELSE
        found := false;
    END IF;
    RETURN NOT found;
END;
$function$

