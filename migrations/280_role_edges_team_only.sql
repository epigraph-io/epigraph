-- 280: the role-holding projection edges are team-only, never public
-- (human-identity visibility spec
-- docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md,
-- section 7 row K1; operator ruling 2026-11-24, "Make the OCCUPIES role edges
-- team-only too").
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 123 projects every `role_assignments` row as one `holder -OCCUPIES-> role
-- node` edge, and 130's re-body of `epigraph_role_assignments_audit` writes it
-- `('public', world)` with `properties.role`. Only registered people hold role
-- assignments (CUS01), so the edge alone says "this id is a human holding role
-- X" to every reader, while the person's card, under 274's rule, shows an
-- unnamed agent with `roles: []`. That is a hidden-human marker plus the role.
--
-- ===================================================================
-- 2. THE OWNER RULE (`epigraph_role_edge_owner(role, holder)`)
-- ===================================================================
--
-- * Exactly ONE live `group_role_bindings` row for the role
--   (`revoked_at IS NULL`), and its group is `active` and a `team` or
--   `community`: that group owns the edge. Its direct members, its
--   role-derived members (the holder included) and privileged sessions read it.
-- * Otherwise (no live binding, more than one, or the one is not an active
--   team/community): the HOLDER's personal group owns it (the holder,
--   maintenance and elevated sessions read it). ORCHESTRATOR'S CALL, recorded
--   as such in the spec (section 16A): no multi-owner edge is invented.
-- * The personal group is found the way 105's `epigraph_ensure_personal_group`
--   finds it (by its `did:epigraph:personal:<id>` key) and minted by that same
--   function when absent: registration as a human operator does not guarantee
--   one, and a world fallback would republish exactly what the ruling hides.
--   105's RVK01 (only revoked personal rows) and RVK02 (a squatted key) still
--   REFUSE: the grant, the binding change or this migration fails with nothing
--   written. FIX-AGENT'S CALL (spec 16A): review correctness#1 asked for a
--   refusal when no personal group exists; minting instead never goes world,
--   keeps the refusal for the two broken states, and cannot fail a boot over
--   a holder that simply never had a personal group.
--
-- The edge's endpoints are both agents (tenancy-public), so 120's
-- `epigraph_edges_tenancy` keeps an explicit `('group', G)` declaration (its
-- no-widening early return) and 260's `edges_tenancy_declared` records G as
-- the declaration on INSERT. The UPDATEs below write the declaration too
-- (those triggers fire only on a re-point), so a later re-meet of two public
-- endpoints cannot widen the edge back to public.
--
-- ===================================================================
-- 3. WHAT CHANGES
-- ===================================================================
--
-- a. PRECONDITION (OCC01, 55000): `epigraph_role_assignments_audit`'s body is
--    still 130's (md5 of `prosrc`), so a concurrent re-body is never
--    overwritten blind.
-- b. NEW `epigraph_role_edge_owner(text, uuid) RETURNS uuid`: the rule above.
--    SECURITY DEFINER on 172's path, owned by the maintenance role, EXECUTE
--    revoked from PUBLIC (an application-callable owner rule would be a
--    binding oracle).
-- c. `epigraph_role_assignments_audit()` re-stated: 130's body, the
--    projection INSERT now `'group'` owned by (b). The revoke/expiry arm is
--    unchanged: it UPDATEs `valid_to` / `properties` only, so the owner stays.
--    CREATE OR REPLACE keeps owner, ACL and its `public, pg_temp` path (it
--    stays in `definer_search_path_ratchet`'s PUBLIC_PATH_REGISTER).
-- d. NEW `epigraph_group_role_bindings_reown_role_edges()` and its trigger
--    `group_role_bindings_reown_role_edges`, AFTER INSERT OR UPDATE OF
--    revoked_at ON group_role_bindings: a bind or an unbind re-owns every
--    projection edge of that role (ended assignments included) by (b), so
--    binding a role moves its edges into the team and unbinding moves them
--    back to each holder's personal group (an ex-team keeps nothing).
-- e. BACKFILL every existing projection edge by (b), under `lock_timeout`,
--    with one `security_events` summary row `edges.role_edges_team_only`
--    {migration, before, rows, after} (count shape only), and a
--    POST-CONDITION (OCC02, 55000): `edges` is FORCE RLS, so a runner that
--    is neither a superuser nor a maintenance member would move 0 rows
--    silently; any projection edge still public refuses the migration.
--
-- NOT CHANGED: a later change of a bound group's `status` or `kind` does not
-- re-own (recorded in the spec as a residual: a suspended team's members stop
-- reading its rows anyway); the backfill is not reversed by the undo.
--
-- UNDO: `docs/runbooks/280-undo.sql` (restores 130's body, drops (b) and
-- (d)); the backfilled owners stay team-only.
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_src text;
BEGIN
    SELECT p.prosrc INTO v_src
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure('public.epigraph_role_assignments_audit()');
    IF v_src IS NULL OR pg_catalog.md5(v_src) <> '52ba7c25a853d6b93aaa6cfeb9a05e6e' THEN
        RAISE EXCEPTION 'OCC01: epigraph_role_assignments_audit is absent or its body is not '
                        '130''s; 280 re-states 130''s body and would overwrite another one '
                        'blind; nothing was changed' USING ERRCODE = '55000';
    END IF;
END $$;

-- (b) The owner rule. The body must not spell the relationship's name:
-- `custodian_role.rs` pins the catalog functions that mention it.
CREATE OR REPLACE FUNCTION public.epigraph_role_edge_owner(p_role text, p_holder uuid)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_live  bigint;
    v_group uuid;
BEGIN
    SELECT pg_catalog.count(*),
           (pg_catalog.array_agg(b.group_id) FILTER (
                WHERE g.status = 'active' AND g.kind IN ('team', 'community')))[1]
      INTO v_live, v_group
      FROM public.group_role_bindings b
      JOIN public.groups g ON g.id = b.group_id
     WHERE b.role = p_role AND b.revoked_at IS NULL;
    IF v_live = 1 AND v_group IS NOT NULL THEN
        RETURN v_group;
    END IF;
    -- 105: found by its key, minted when absent, RVK01 / RVK02 refuse.
    RETURN public.epigraph_ensure_personal_group(p_holder);
END $$;
REVOKE ALL ON FUNCTION public.epigraph_role_edge_owner(text, uuid) FROM PUBLIC;

-- (c) 130's audit, the projection owned by (b).
CREATE OR REPLACE FUNCTION public.epigraph_role_assignments_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_node  uuid;
    v_act   uuid;
    v_owner uuid;
BEGIN
    SELECT r.role_node_id INTO v_node FROM public.platform_roles r WHERE r.key = NEW.role;
    IF TG_OP = 'INSERT' THEN
        -- Section 5 of 123: the projection, holder -> role node, in the edge's
        -- own validity columns. 280: owned by the role's single bound
        -- team/community, else the holder's personal group; never public.
        v_owner := public.epigraph_role_edge_owner(NEW.role, NEW.holder_person_id);
        INSERT INTO public.edges (source_id, source_type, target_id, target_type, relationship,
                                  properties, valid_from, valid_to, visibility, owner_group_id)
        VALUES (NEW.holder_person_id, 'agent', v_node, 'agent', 'OCCUPIES',
                jsonb_build_object('assignment_id', NEW.id::text, 'role', NEW.role,
                                   'source', 'role_assignments', 'projection', true),
                NEW.valid_from, NEW.valid_to, 'group', v_owner);
        v_act := NEW.grant_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_granted', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'valid_from', NEW.valid_from, 'valid_to', NEW.valid_to,
                                   'granted_by', NEW.granted_by,
                                   'granted_via', NEW.granted_via, 'reason', NEW.reason,
                                   'migrated', NEW.granted_via = 'migration 123',
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        -- The projection closes at the end (or keeps an earlier valid_to).
        -- An assignment ended before it began keeps a one-microsecond window
        -- marked never_effective: `temporal_ordering` requires
        -- valid_to > valid_from. The owner is not touched.
        UPDATE public.edges e
           SET valid_to = CASE
                            WHEN LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                                 <= NEW.valid_from
                            THEN NEW.valid_from + interval '1 microsecond'
                            ELSE LEAST(COALESCE(NEW.valid_to, NEW.revoked_at), NEW.revoked_at)
                          END,
               properties = e.properties
                   || jsonb_build_object('ended_at', NEW.revoked_at,
                                         'never_effective', NEW.revoked_at <= NEW.valid_from)
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.source_id = NEW.holder_person_id
           AND e.properties @> jsonb_build_object('assignment_id', NEW.id::text);
        -- Section 6: the end of the holder's LAST un-ended custodian
        -- assignment is mirrored into a live legacy `instance_admins` row, so a
        -- rollback to 083's body cannot resurrect an authority ended here.
        IF NEW.role = 'role:platform-custodian'
           AND NOT EXISTS (SELECT 1 FROM public.role_assignments ra
                            WHERE ra.holder_person_id = NEW.holder_person_id
                              AND ra.role = 'role:platform-custodian'
                              AND ra.revoked_at IS NULL AND ra.id <> NEW.id) THEN
            UPDATE public.instance_admins SET revoked_at = now()
             WHERE agent_id = NEW.holder_person_id AND revoked_at IS NULL;
        END IF;
        v_act := NEW.revoke_act_id;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('platform.role_ended', NEW.holder_person_id, true,
                jsonb_build_object('assignment_id', NEW.id, 'role', NEW.role,
                                   'holder', NEW.holder_person_id,
                                   'revoked_at', NEW.revoked_at, 'revoked_by', NEW.revoked_by,
                                   'revoked_reason', NEW.revoked_reason,
                                   'confirmation', CASE WHEN v_act IS NULL THEN 'none'
                                                        ELSE 'passkey' END,
                                   'act_id', v_act,
                                   'elevation_id', (SELECT a.elevation_id
                                                      FROM public.pending_admin_acts a
                                                     WHERE a.id = v_act)));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_role_assignments_audit() FROM PUBLIC;

-- (d) A bind or an unbind re-owns the role's projection edges.
CREATE OR REPLACE FUNCTION public.epigraph_group_role_bindings_reown_role_edges()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NOT (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) THEN
        RETURN NULL;
    END IF;
    WITH o AS (
        SELECT e.id, public.epigraph_role_edge_owner(NEW.role, e.source_id) AS g
          FROM public.edges e
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
           AND e.properties ->> 'role' = NEW.role
    )
    UPDATE public.edges e
       SET visibility = 'group', owner_group_id = o.g, co_owner_group_id = NULL,
           declared_owner_group_id = o.g, declared_co_owner_group_id = NULL
      FROM o
     WHERE e.id = o.id
       AND (e.visibility, e.owner_group_id, e.co_owner_group_id,
            e.declared_owner_group_id, e.declared_co_owner_group_id)
           IS DISTINCT FROM ('group'::varchar, o.g, NULL::uuid, o.g, NULL::uuid);
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.epigraph_group_role_bindings_reown_role_edges() FROM PUBLIC;

DROP TRIGGER IF EXISTS group_role_bindings_reown_role_edges ON public.group_role_bindings;
CREATE TRIGGER group_role_bindings_reown_role_edges
    AFTER INSERT OR UPDATE OF revoked_at ON public.group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_role_bindings_reown_role_edges();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_role_edge_owner(text, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_role_bindings_reown_role_edges() '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 280 functions '
                     'stay owned by the migration runner.';
    END IF;
END $$;

-- (e) The backfill, count shape only.
DO $$
DECLARE
    v_before bigint;
    v_rows   bigint;
    v_after  bigint;
BEGIN
    SELECT pg_catalog.count(*) INTO v_before
      FROM public.edges e
     WHERE e.relationship = 'OCCUPIES' AND e.visibility = 'public';

    WITH o AS (
        SELECT e.id,
               public.epigraph_role_edge_owner(e.properties ->> 'role', e.source_id) AS g
          FROM public.edges e
         WHERE e.relationship = 'OCCUPIES' AND e.source_type = 'agent'
    )
    UPDATE public.edges e
       SET visibility = 'group', owner_group_id = o.g, co_owner_group_id = NULL,
           declared_owner_group_id = o.g, declared_co_owner_group_id = NULL
      FROM o
     WHERE e.id = o.id
       AND (e.visibility, e.owner_group_id, e.co_owner_group_id,
            e.declared_owner_group_id, e.declared_co_owner_group_id)
           IS DISTINCT FROM ('group'::varchar, o.g, NULL::uuid, o.g, NULL::uuid);
    GET DIAGNOSTICS v_rows = ROW_COUNT;

    SELECT pg_catalog.count(*) INTO v_after
      FROM public.edges e
     WHERE e.relationship = 'OCCUPIES' AND e.visibility = 'public';

    IF v_after <> 0 THEN
        RAISE EXCEPTION 'OCC02: % role projection edge(s) are still public after the backfill '
                        '(% before, % moved): this migration runner cannot update edges under '
                        'its row security; run it as a superuser or a maintenance member; '
                        'nothing was changed', v_after, v_before, v_rows
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('edges.role_edges_team_only', NULL, true,
            pg_catalog.jsonb_build_object('migration', 280, 'before', v_before,
                                          'rows', v_rows, 'after', v_after));
END $$;
