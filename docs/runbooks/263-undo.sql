-- ===================================================================
-- 263-undo.sql: take migration 263 (person-facing keyless team groups and
-- consented invitations) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES:
--   * refuses (55000, nothing changed) unless each of the two guards still
--     has 263's body or already has 176's (a re-run): a later migration that
--     re-bodied either one is not silently reverted;
--   * re-states 176's two team-group guards verbatim
--     (`epigraph_team_group_roster_verbs_only`,
--     `epigraph_team_group_row_verbs_only`; CREATE OR REPLACE keeps owner and
--     grants), so the roster and the group row of a verb-made group are
--     again written by the maintenance verbs alone;
--   * drops the six request-path functions and the grant check;
--   * drops `group_invitations`, `person_team_groups` and
--     `team_group_roster_grants`.
--
-- WHAT IT LOSES: every invitation row (pending, accepted, declined). Their
-- `group.invitation_*` and `group.member_added` audit rows stay (082:
-- immutable) and say who invited whom, and which membership an acceptance
-- wrote. List the pending ones first if they are to be re-sent:
--   SELECT id, group_id, invitee_agent_id, invited_by, role, created_at
--     FROM public.group_invitations WHERE status = 'pending';
--
-- WHAT IT LEAVES: every group a Person created and every membership an
-- acceptance wrote (the record of which groups a Person made goes with
-- `person_team_groups`; the `group.team_created` audit rows keep it). They
-- are ordinary verb-made team groups and rows; the operator's 164 verbs
-- (`group-member remove|set-role`) manage them after the undo exactly as
-- before it. 263's `_sqlx_migrations` row also stays:
-- re-introducing the surface is a NEW migration, never a re-run of 263.
--
-- Roll back every binary that calls the 263 functions (the REST
-- `/api/v1/groups/team`, `/api/v1/groups/mine`, invitation routes and the
-- MCP team-group tools) BEFORE running this file; after it they answer
-- 42883 (function does not exist).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

-- Refuse over any guard body that is neither 263's nor 176's.
DO $$
DECLARE
    v_roster text;
    v_row    text;
BEGIN
    SELECT md5(p.prosrc) INTO v_roster FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_roster_verbs_only()');
    SELECT md5(p.prosrc) INTO v_row FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_team_group_row_verbs_only()');
    -- 263's body, or 176's (this undo already ran).
    IF v_roster IS NULL OR v_roster NOT IN ('ed5f2a9a128232968427fb38f4c65660',
                                            'dcf4d5722ee28c8a3999fc6bc26ba911') THEN
        RAISE EXCEPTION '263-undo: epigraph_team_group_roster_verbs_only is neither 263''s body '
                        '(md5 ed5f2a9a128232968427fb38f4c65660) nor 176''s; found md5 %. A later '
                        'migration re-bodied it; nothing was changed', COALESCE(v_roster, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Undo the later migration first, or write an undo that re-states its body '
                         'without 263''s admission.';
    END IF;
    IF v_row IS NULL OR v_row NOT IN ('23639cf787d773df330453dabc050d0c',
                                      'f66b4e61de3a9528627b3a9de8a208a6') THEN
        RAISE EXCEPTION '263-undo: epigraph_team_group_row_verbs_only is neither 263''s body '
                        '(md5 23639cf787d773df330453dabc050d0c) nor 176''s; found md5 %. A later '
                        'migration re-bodied it; nothing was changed', COALESCE(v_row, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Undo the later migration first, or write an undo that re-states its body '
                         'without 263''s admission.';
    END IF;
END $$;

-- 176's bodies, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_team_group_roster_verbs_only()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    -- NEW.group_id alone: 109 refuses moving a row to another group outside
    -- a maintenance session, and a maintenance session has returned above.
    IF EXISTS (SELECT 1 FROM public.groups g
                WHERE g.id = NEW.group_id AND g.did_key LIKE 'did:epigraph:group:%') THEN
        RAISE EXCEPTION 'GRM05: group_memberships: the roster of team group % is written only by the '
                        'team-group verbs (epigraph-operator group-member, on the maintenance '
                        'DSN); nothing was changed', NEW.group_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_team_group_row_verbs_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF public.epigraph_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'GRM06: groups: a keyless team group, or any group in the did:epigraph:group: '
                    'namespace, is created and changed only by the team-group verbs '
                    '(epigraph-operator create-group, on the maintenance DSN); nothing was '
                    'changed (did_key %, kind %, % key bytes)',
                    NEW.did_key, NEW.kind, octet_length(NEW.public_key)
        USING ERRCODE = '42501';
END $$;

DROP FUNCTION IF EXISTS public.epigraph_my_group_invitations();
DROP FUNCTION IF EXISTS public.epigraph_my_groups();
DROP FUNCTION IF EXISTS public.epigraph_decline_group_invitation(uuid);
DROP FUNCTION IF EXISTS public.epigraph_accept_group_invitation(uuid);
DROP FUNCTION IF EXISTS public.epigraph_invite_to_team_group(uuid, uuid, text, text);
DROP FUNCTION IF EXISTS public.epigraph_person_create_team_group(text, text);
DROP FUNCTION IF EXISTS public.epigraph_team_group_roster_granted(uuid, uuid);
DROP TABLE IF EXISTS public.group_invitations;
DROP TABLE IF EXISTS public.person_team_groups;
DROP TABLE IF EXISTS public.team_group_roster_grants;

COMMIT;
