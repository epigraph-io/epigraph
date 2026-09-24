CREATE OR REPLACE FUNCTION public.epigraph_current_group_id()
 RETURNS uuid
 LANGUAGE plpgsql
 STABLE
AS $function$
DECLARE
    raw text;
BEGIN
    raw := current_setting('app.group_id', true);
    IF raw IS NULL OR raw = '' THEN
        RETURN NULL;
    END IF;
    RETURN raw::uuid;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$function$;
