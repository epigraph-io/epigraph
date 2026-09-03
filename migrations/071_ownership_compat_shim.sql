-- 071_ownership_compat_shim.sql -- `ownership` demoted to a write-through shim
-- PR-12 of the multi-user tenancy series. Plan §3 calls this file "067"; the
-- authoritative table in migrations/README.md pins it at 071. 067 on disk is
-- PR-04's session/bypass functions.
--
-- WHY. `ownership` is the pre-tenancy ACL table. POST /api/v1/ownership
-- (routes/ownership.rs), MCP assign_ownership / update_partition
-- (tools/perspectives.rs) and ~34 test fixture call sites still write it. Both
-- writers are deleted in PR-14 and the table itself is dropped in migration 084
-- (PR-22); this shim is what keeps them CORRECT in between, by transcribing
-- every write into the tenancy columns that are becoming the real control.
--
-- Without it, `ownership` and the tenancy columns diverge silently for a whole
-- release: a caller marks a claim `private`, the ACL table records it, and the
-- claim stays visibility='public' to every viewer predicate.
--
-- THIS FILE DOES NOT CREATE tenancy_transcription_log. Migration 062 already
-- did, along with tenancy_backfill_progress and tenancy_undeclared_writes;
-- crates/epigraph-db/tests/schema_contract.rs pins all three shapes exactly.
-- This file POPULATES it.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- THE LEDGER IS LAST-WRITE-WINS, AND THAT IS A KNOWN DEFECT, NOT AN OVERSIGHT.
--
-- tenancy_transcription_log is `node_id uuid PRIMARY KEY` -- one row per node,
-- ever. A node reclassified twice (private -> community, which the MCP
-- update_partition path and two test fixtures both do) can therefore either
-- 23505 or overwrite the first transition. It overwrites: an ON CONFLICT
-- (node_id) DO UPDATE below.
--
-- It cannot be fixed inside PR-12. Adding an `id`/sequence column would change
-- the table's shape, and schema_contract.rs asserts the observed column tuple
-- equals a pinned 6-element contract IN ORDER; a shape change needs a migration
-- number, and 072-084 are all allocated.
--
-- It does not block the consumer. Migration 080's (PR-18) pre-flight reads this
-- table for the EXISTENCE of a transcription row per non-public `ownership`
-- row, which last-write-wins still satisfies. What is lost is history, not the
-- gate.
-- ===================================================================

CREATE OR REPLACE FUNCTION public.epigraph_ownership_transcribe() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v text; may_transfer boolean;
BEGIN
    -- Same assertion as 070 arm (d) (sec F10). NOTE WHAT IT ACTUALLY CHECKS:
    -- epigraph_definer_bypass() is pg_has_role(CURRENT_USER, ...), and inside a
    -- SECURITY DEFINER frame current_user is the FUNCTION OWNER -- so this
    -- passes for an ordinary epigraph_app caller PROVIDED the ALTER FUNCTION at
    -- the foot of this file ran. It is a deploy-time assertion that the owner
    -- is right, not a runtime authorization check on the caller.
    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: ownership transcription requires a '
                        'maintenance-role owner; refusing to run RLS-filtered'
            USING ERRCODE = '42501';
    END IF;

    -- ===================================================================
    -- MAY THIS WRITE MOVE A NODE BETWEEN GROUPS?
    --
    -- Only when it is an UPDATE of an ownership row that ALREADY EXISTED, by
    -- the SAME owner_id it already carried. That is the owner of record
    -- re-declaring its own node, which is what `update_partition` does on the
    -- demotion path (community -> private) and what
    -- `community_partition.rs::demoting_out_of_community_clears_the_gate`
    -- exercises: the node moves from the community group to the owner's
    -- personal group, which is a NARROWING (many readers -> one) performed by
    -- the principal already recorded as its owner.
    --
    -- The attack this leaves closed is the INSERT: PR-11's
    -- `require_declassify_authority` permits a self-claim ONLY when there is no
    -- owner of record, so an attacker's write is always TG_OP = 'INSERT' and
    -- `may_transfer` is false. An attacker cannot reach the UPDATE arm either,
    -- because with an owner of record present that same function denies
    -- `(Some(victim), Some(attacker))`.
    -- ===================================================================
    may_transfer := (TG_OP = 'UPDATE' AND OLD.owner_id = NEW.owner_id);

    -- ===================================================================
    -- RESOLVE THE TARGET (visibility, owner_group_id).
    --
    -- THE RULE: never stamp a group that does not exist, and never stamp a
    -- group with no live members. Both are read-back BLACK HOLES -- 062's
    -- <table>_group_needs_real_group CHECK catches the world/seed cases, but it
    -- is a NOT IN list, so an EMPTY REAL GROUP sails straight through it. That
    -- is the failure mode this block is written against.
    --
    -- MATERIALIZE, DO NOT REFUSE. An earlier revision of this file RAISED when
    -- the owner had no personal group. That is the wrong trade: refusing leaves
    -- the claim PUBLIC when the caller explicitly asked for private, which is
    -- failing OPEN dressed up as strictness. Minting the agent's own personal
    -- group is not a "fallback" to some other principal's group -- it is the
    -- same idempotent act AgentRepository::ensure_personal_group performs on the
    -- OAuth mint path, and that epigraph-tenancy-backfill performs in bulk for
    -- the ~1,198 orphan agents migration 057 documents. The result is a real
    -- group whose only live member is the owner, which is exactly what
    -- 'private' means.
    --
    -- What is still forbidden, and is the thing the earlier revision was really
    -- reaching for: stamping world, stamping seed, or stamping any group the
    -- owner is not a live member of.
    -- ===================================================================
    IF NEW.partition_type = 'community' AND NEW.community_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.communities c WHERE c.id = NEW.community_id) THEN

        -- Migration 068 projects communities onto groups ID-PRESERVINGLY, so a
        -- community's group id IS its community id. Project on demand for a
        -- community created after 068's one-time snapshot ran.
        INSERT INTO public.groups (id, display_name, did_key, public_key, kind, created_at)
        SELECT c.id, c.name, 'did:epigraph:community:' || c.id::text, ''::bytea,
               'community', c.created_at
          FROM public.communities c WHERE c.id = NEW.community_id
        ON CONFLICT DO NOTHING;
        INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
        VALUES (NEW.community_id, 0, NULL, 'active')
        ON CONFLICT DO NOTHING;

        -- REPLAY 068's MEMBERSHIP PROJECTION. Projecting the group without its
        -- members would produce ('group', G) where G has ZERO live memberships
        -- -- unreadable by everyone including the community's own members.
        -- role='reader' for 068's stated reason: community_members attests read
        -- interest and says nothing about write authority, and Viewer::resolve
        -- puts admin|writer into the WRITABLE set.
        INSERT INTO public.group_memberships
            (group_id, agent_id, wrapped_key_share, epoch, role, joined_at)
        SELECT DISTINCT cm.community_id, p.owner_agent_id, ''::bytea, 0, 'reader', now()
          FROM public.community_members cm
          JOIN public.perspectives p ON p.id = cm.perspective_id
         WHERE cm.community_id = NEW.community_id AND p.owner_agent_id IS NOT NULL
        ON CONFLICT DO NOTHING;

        -- THE OWNER IS DELIBERATELY *NOT* ADDED TO THE COMMUNITY GROUP.
        --
        -- It is tempting: it guarantees the declaring agent can read back the
        -- node it just declared. But it would silently overturn a reviewed
        -- decision. `epigraph-mcp/tests/community_partition.rs::
        -- community_owner_who_is_not_a_member_is_redacted` states it in its own
        -- assertion message: *"on the community arm, ownership alone does NOT
        -- grant access once a community resolves -- membership is the whole
        -- test. If you are changing this, change it on purpose."* Projecting the
        -- owner in would change it by accident.
        --
        -- The black-hole risk that made it tempting is handled below instead, by
        -- declining to USE a community group that nobody is in.
        IF EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = NEW.community_id AND m.revoked_at IS NULL) THEN
            g := NEW.community_id;
            v := 'group';
        ELSE
            -- A community with no projectable members yields a group nobody is
            -- in. Stamping it would make the node unreadable by EVERYONE,
            -- permanently, and 062's _group_needs_real_group CHECK cannot catch
            -- it -- that is a NOT IN (world, seed) list, and an empty REAL group
            -- passes straight through. Fall through to the owner's personal
            -- group, which is fail-CLOSED (still 'group', still not public) and
            -- readable by at least the declaring owner.
            g := NULL;
        END IF;
    END IF;

    IF g IS NULL THEN
        -- Everything else resolves to the OWNER'S PERSONAL GROUP, and the arms
        -- differ only in visibility:
        --
        --   'private'                      -> ('group',  personal)
        --   'public'                       -> ('public', personal)   [D2]
        --   'community' with no resolvable community
        --                                  -> ('group',  personal)
        --
        -- THE THIRD CASE IS DELIBERATE AND IS NOT AN ERROR PATH. A
        -- `partition_type='community'` row with a NULL or dangling community_id
        -- is a LEGACY SHAPE: before migration 068 the gating community lived
        -- stringified in `ownership.encryption_key_id`, and 068 created the
        -- `ownership_key_id_quarantine` VIEW precisely to REPORT the ones that
        -- did not resolve. `tenancy_coverage.rs::quarantine_reports_a_dangling_community_uuid`
        -- states the reviewed decision in its own assertion: such a row "must be
        -- REPORTED, not swallowed and not fatal", and must still be WRITABLE.
        -- Raising here would break the quarantine's whole purpose.
        --
        -- Falling back to the owner's personal group with visibility='group' is
        -- the fail-CLOSED answer: strictly more restrictive than public, on a
        -- real group with a real live member, and the row stays writable so the
        -- quarantine view can do its job. The ledger still records
        -- from_partition = 'community', so PR-18's gate sees the transition.
        --
        -- TWO WAYS TO IDENTIFY A PERSONAL GROUP, AND BOTH ARE NEEDED. The
        -- canonical one is ensure_personal_group's deterministic
        -- 'did:epigraph:personal:<agent uuid>' key against groups_did_key_key.
        -- But that is a CONVENTION; the semantics are `kind='personal'` created
        -- by this agent, and there are personal groups in this tree that do not
        -- carry the canonical key -- every copy of
        -- tests/viewer_fixture.rs::seed_agent_with_group mints one as
        -- 'did:epigraph:test:<label>:<agent>'. Matching only the did_key would
        -- mint a SECOND personal group for an agent that already has one.
        -- ORDER BY puts the canonical key first so a database carrying both
        -- resolves deterministically.
        SELECT id INTO g FROM public.groups
         WHERE (did_key = 'did:epigraph:personal:' || NEW.owner_id::text)
            OR (kind = 'personal' AND created_by_agent_id = NEW.owner_id)
         ORDER BY (did_key = 'did:epigraph:personal:' || NEW.owner_id::text) DESC,
                  created_at ASC
         LIMIT 1;

        IF g IS NULL THEN
            -- Same shape as AgentRepository::ensure_personal_group: a personal
            -- group carries an EMPTY public_key (groups_public_key_shape, 060,
            -- requires octet_length = 0 for every kind <> 'team') and no
            -- group_key_epochs row at all.
            INSERT INTO public.groups
                (display_name, did_key, public_key, kind, created_by_agent_id)
            VALUES ('personal:' || NEW.owner_id::text,
                    'did:epigraph:personal:' || NEW.owner_id::text,
                    ''::bytea, 'personal', NEW.owner_id)
            ON CONFLICT (did_key) DO UPDATE SET updated_at = now()
            RETURNING id INTO g;
        END IF;

        -- The membership is not optional. Targeting the COMPOSITE
        -- (group_id, agent_id, epoch) and REVIVING on conflict, exactly as
        -- ensure_personal_group does and for the reason its comment gives: an
        -- untargeted DO NOTHING silently no-ops against a revoked row, leaving
        -- the agent with no live membership in its own personal group --
        -- permanently, because every later attempt hits the same conflict.
        INSERT INTO public.group_memberships
            (group_id, agent_id, wrapped_key_share, epoch, role)
        VALUES (g, NEW.owner_id, ''::bytea, 0, 'admin')
        ON CONFLICT (group_id, agent_id, epoch)
        DO UPDATE SET revoked_at = NULL, role = 'admin';

        v := CASE WHEN NEW.partition_type = 'public' THEN 'public' ELSE 'group' END;
    END IF;

    -- The invariant the whole block exists to guarantee. Cheap, and it is the
    -- only thing standing between a mis-resolution and a corpus nobody can read
    -- -- 062's CHECK cannot see this case because an empty REAL group is not in
    -- its NOT IN list.
    IF v = 'group' AND NOT EXISTS (
        SELECT 1 FROM public.group_memberships m
         WHERE m.group_id = g AND m.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to stamp ownership(%) as '
                        '(group, %) -- that group has no live members and the row '
                        'would be unreadable by everyone, including its owner',
                        NEW.node_id, g
            USING ERRCODE = '23514';
    END IF;

    -- ---------------------------------------------------------------
    -- Stamp the node itself.
    --
    -- ownership_node_type_check admits seven node_types. Six of them name a
    -- tier-A table with tenancy columns; `agent` names `agents`, which is
    -- deliberately tenancy_exempt (tier B -- authorship must render on a public
    -- claim, so the row stays readable and only its PII is projected away).
    -- An `agent` row is therefore LOGGED BELOW BUT NOT STAMPED.
    --
    -- The claims UPDATE fires 070 arm (d) (claims_propagate_tenancy), which is
    -- what carries the change to the 17 derived tables, harvester_fragments and
    -- edges IN THE SAME TRANSACTION. This trigger deliberately does not
    -- duplicate that walk.
    --
    -- ===============================================================
    -- THIS SHIM NEVER WIDENS *AND* NEVER TRANSFERS. Every UPDATE below carries
    --     AND NOT (visibility = 'group'
    --              AND (v = 'public' OR owner_group_id IS DISTINCT FROM g)
    --              AND NOT <the declarer is a live member of the CURRENT group>)
    -- so a node that is ALREADY group-private is never made public, and never
    -- moved into a group its current owners are not already in, by an
    -- `ownership` row.
    --
    -- ===============================================================
    -- THE TRANSFER HALF IS A CONFIDENTIALITY FIX, NOT SYMMETRY. READ THIS.
    --
    -- An earlier revision guarded only the group->public direction. That leaves
    -- group->DIFFERENT-group open, and PR-12 is what makes it exploitable:
    --
    --   1. `require_declassify_authority` (routes/ownership.rs and
    --      tools/perspectives.rs) resolves `(None, Some(requested)) if requested
    --      == principal.id()` to ALLOW -- a node with NO `ownership` row may be
    --      claimed to yourself. PR-11 filed that as a public->private DoS
    --      (`F-PR11-assign-ownership-self-claim-is-a-seizure`), harmless while
    --      the row landed in an ACL table nothing read.
    --   2. THIS FILE makes that write land on the LIVE tenancy columns.
    --   3. PR-12 also MANUFACTURES the victim population.
    --      `ClaimRepository::supersede` writes no `ownership` row, and 070 arm
    --      (a) then stamps the successor ('group', G) by inheritance -- so the
    --      CURRENT version of every superseded private claim is group-private
    --      with owner_of_record = None, i.e. self-claimable. Same for every
    --      `evidence` row (arm (c) stamps it from its parent; no production
    --      path ever gives evidence an `ownership` row), and evidence.raw_content
    --      is a full second copy of the claim text.
    --      `node_type` is caller-supplied and unvalidated, `ownership.node_id`
    --      carries no FK, and MCP `assign_ownership` is gated at `claims:write`,
    --      not `claims:admin`.
    --
    -- Without the transfer guard, one `claims:write` call with a harvested
    -- evidence UUID reads out a private claim's text. WITH it, the UPDATE
    -- matches no row: the attacker is not a live member of the victim's group.
    --
    -- THE TWO ESCAPE HATCHES ARE REQUIRED, NOT A SOFTENING. A bare
    -- `owner_group_id IS DISTINCT FROM g` forbids two LEGITIMATE re-declarations
    -- this file's own header describes, and MEASURED red tests found both:
    --
    --   (i) A LIVE MEMBER of the node's current group is a co-owner expressing
    --       the existing owners' intent, which is what a transcriber is for.
    --       A stranger is not.
    --  (ii) `may_transfer` -- the OWNER OF RECORD updating its own row. Found
    --       by `community_partition.rs::demoting_out_of_community_clears_the_gate`:
    --       the owner demotes its claim from `community` to `private`, and the
    --       shim must move it from the community group to the owner's personal
    --       group. Deliberately the owner is NOT projected into the community
    --       group (test 7 pins that), so hatch (i) does not cover it -- and
    --       blocking it would leave a demoted node readable by every member of
    --       a community it has just left. That is a WIDENING dressed as
    --       strictness, which is the failure mode this whole block exists
    --       against.
    --
    -- This turns PR-11's residual from a confidentiality break back into the
    -- denial-of-service it was filed as. It does NOT close the residual itself
    -- -- self-claiming an ownerless PUBLIC node still works, and that remains
    -- `F-PR11-assign-ownership-self-claim-is-a-seizure`, owned by PR-14.
    -- ===============================================================
    --
    -- MEASURED, not theorised. `epigraph-api/tests/structural_features_authz.rs::
    -- seed_corpus` stamps `partition_type = 'public'` ownership rows over all
    -- three of its claims for bookkeeping -- including the one it deliberately
    -- seeded as ('group', owner_group). Without this guard the shim honoured the
    -- 'public' row and DECLASSIFIED that claim, and
    -- `owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part`
    -- caught it: a stranger saw 3 claims where it must see 2.
    --
    -- A compat shim for a table on its way out (PR-14 deletes both writers, 084
    -- drops the table) must not be able to declassify content. Widening is the
    -- one direction that turns a bookkeeping write into a disclosure, and it is
    -- exactly what PR-16's migration 074 `claims_block_widening` trigger exists
    -- to forbid -- anticipating it here is fail-closed and costs nothing.
    --
    -- The ledger below still records what was REQUESTED, so a refused widening
    -- is visible rather than silent.
    -- ===============================================================
    -- ---------------------------------------------------------------
    IF NEW.node_type = 'claim' THEN
        UPDATE public.claims SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = claims.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    ELSIF NEW.node_type = 'evidence' THEN
        UPDATE public.evidence SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = evidence.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    ELSIF NEW.node_type = 'perspective' THEN
        UPDATE public.perspectives SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = perspectives.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    ELSIF NEW.node_type = 'community' THEN
        UPDATE public.communities SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = communities.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    ELSIF NEW.node_type = 'context' THEN
        UPDATE public.contexts SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = contexts.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    ELSIF NEW.node_type = 'frame' THEN
        UPDATE public.frames SET owner_group_id = g, visibility = v
         WHERE id = NEW.node_id
           -- never WIDEN
           AND NOT (visibility = 'group' AND v = 'public')
           -- never TRANSFER out of a group the declarer is not in
           AND NOT (visibility = 'group'
                    AND owner_group_id IS DISTINCT FROM g
                    AND NOT may_transfer
                    AND NOT EXISTS (SELECT 1 FROM public.group_memberships m
                                     WHERE m.group_id = frames.owner_group_id
                                       AND m.agent_id = NEW.owner_id
                                       AND m.revoked_at IS NULL))
           AND (owner_group_id, visibility) IS DISTINCT FROM (g, v::character varying(16));
    END IF;

    -- ---------------------------------------------------------------
    -- The ledger. Written for EVERY partition_type, including 'public': the
    -- plan's wording is "every mapping also writes a row", and migration 080's
    -- gate reads the non-public subset, so a superset satisfies it.
    -- ---------------------------------------------------------------
    INSERT INTO public.tenancy_transcription_log
        (node_id, node_type, from_partition, to_visibility, to_group_id, transcribed_at)
    VALUES (NEW.node_id, NEW.node_type, NEW.partition_type, v, g, now())
    ON CONFLICT (node_id) DO UPDATE
        SET node_type      = EXCLUDED.node_type,
            from_partition = EXCLUDED.from_partition,
            to_visibility  = EXCLUDED.to_visibility,
            to_group_id    = EXCLUDED.to_group_id,
            transcribed_at = EXCLUDED.transcribed_at;

    RETURN NULL;   -- AFTER trigger; return value is ignored.
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_ownership_transcribe() FROM PUBLIC;

DROP TRIGGER IF EXISTS ownership_transcribe ON public.ownership;
CREATE TRIGGER ownership_transcribe AFTER INSERT OR UPDATE ON public.ownership
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_ownership_transcribe();

-- SECURITY DEFINER OWNED BY epigraph_maintenance -- see 070 section 0 for why
-- the GRANT on epigraph_definer_bypass() is required alongside it, and why both
-- are guarded on role existence rather than assumed.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_definer_bypass() '
                'TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_ownership_transcribe() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;
