-- 241: reserve the `--allow-unauthenticated-http` reader agent, and refuse it
-- every live group membership (backlog 37844e1d, 14a38166).
--
-- ===================================================================
-- 1. WHY
--
-- The read-only unauthenticated MCP listener reads as one dedicated agent,
-- `mcp-unauthenticated-reader`, under a fixed 32-byte public key that nobody
-- holds a private key for (`epigraph-mcp/src/unauthenticated_reader.rs`,
-- `READER_PUBLIC_KEY` = the ASCII bytes `epigraph-mcp:unauthenticated-rdr`).
-- It must belong to no group: its reads are PUBLIC-ONLY. The listener fails
-- closed when it does hold one (it refuses every content call instead of
-- reading with that group). Two defects followed from the agent being an
-- ordinary row:
--
--   (a) 37844e1d. Any holder of `groups:admin` on any group could add the
--       reader to that group (077's `group_memberships_tenancy` admits an
--       admin's INSERT for any agent), which closes every read-only listener
--       on the database: a denial of service one INSERT away. Ignoring the
--       membership in the listener is not enough, because database helpers
--       keyed on the principal (077's `epigraph_is_group_admin`, every
--       `epigraph_live_memberships` read) would still honour it.
--   (b) 14a38166. The key was not reserved. The listener created the row on
--       its first boot, so anyone able to create an agent (`agents:write`,
--       `POST /api/v1/agents` with an arbitrary public key) could create it
--       first, with an OAuth client or memberships attached, and the listener
--       would adopt that row.
--
-- ===================================================================
-- 2. WHAT IT DOES
--
--   * Creates the reader's `agents` row if no row holds the key, with the
--     columns the listener's own create path wrote (key, display name, empty
--     labels; every other column its default), so the row is the same
--     whichever made it. An existing row is ADOPTED as it is, never changed
--     and never refused here: section 3.
--   * `agents_reserve_unauthenticated_reader_key` (BEFORE INSERT OR UPDATE OF
--     public_key): no other row may take the key, by INSERT or by key UPDATE,
--     on every path and every role (42501, `RDR01`). The reserved row is
--     created above before the trigger exists, so this file is the only
--     creator; the listener now only LOOKS the row up.
--   * `group_memberships_refuse_unauthenticated_reader` (BEFORE INSERT OR
--     UPDATE): a membership row of the reader agent may never be LIVE:
--     an INSERT of a live row (any role, any group, any epoch), an UPDATE
--     that revives a revoked one, and an UPDATE that moves any live row's
--     `agent_id` onto the reader are refused (42501, `RDR02`). Revoking a
--     legacy live row stays open, and so does every other UPDATE of a row that
--     is already live and keeps its agent (e.g.
--     `GroupKeyEpochRepository::rotate_conn`'s epoch and key-share writes), so
--     a group holding such a row is not wedged.
--
-- NEITHER TRIGGER HAS AN ESCAPE HATCH. 109's guards let
-- `epigraph_bypass()` / `epigraph_definer_bypass()` through; these do not.
-- The definer escape would reopen (a) exactly: definers the application role
-- may EXECUTE (077's `epigraph_ensure_personal_group`, 106's community
-- definers) run in a definer frame. And no maintenance session has a reason
-- to give the reader a group: its whole contract is that it holds none. A
-- superuser who must can disable the trigger in a recorded transaction.
--
-- Both triggers identify the reader by its KEY (`agents.public_key`), not by
-- an id, so the rule follows the row whatever id it was created with.
-- `agents` is readable by every role (077's `agents_identity ... USING (true)`), so
-- the INVOKER trigger's lookup sees the row on every connection.
--
-- ===================================================================
-- 3. A ROW THAT EXISTED BEFORE THIS FILE
--
-- On a deployed database the row usually exists already: the listener made it
-- on its first boot. It is adopted. A row planted ahead of the listener may
-- carry an un-revoked OAuth client or live memberships; this file does not
-- refuse to apply over it (a refusal would stop every later migration on a
-- database whose contents the file cannot judge), and the listener refuses to
-- read as such a row instead (`UnauthenticatedReader::resolve`: any live
-- membership, or any OAuth client whose status is not `revoked`). Measure
-- before deploying:
--     SELECT a.id,
--            (SELECT count(*) FROM public.group_memberships m
--              WHERE m.agent_id = a.id AND m.revoked_at IS NULL) AS live_memberships,
--            (SELECT count(*) FROM public.oauth_clients c
--              WHERE c.agent_id = a.id AND c.status <> 'revoked') AS unrevoked_clients
--       FROM public.agents a
--      WHERE a.public_key = '\x65706967726170682d6d63703a756e61757468656e746963617465642d726472'::bytea;
-- Expected: no row, or one row with 0 and 0. Otherwise revoke the memberships
-- (revoking stays open) and revoke the clients, on the maintenance DSN.
--
-- ===================================================================
-- 4. UNDO
--
-- `docs/runbooks/241-undo.sql`: drops both triggers and their functions. The
-- reader's row stays (a binary of this file only looks it up). Roll the
-- binaries back first only if the row is to go too.
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- The reserved row, created before the trigger that reserves its key.
INSERT INTO public.agents (public_key, display_name, labels)
VALUES ('\x65706967726170682d6d63703a756e61757468656e746963617465642d726472'::bytea,
        'mcp-unauthenticated-reader', '{}'::text[])
ON CONFLICT (public_key) DO NOTHING;

-- ===================================================================
-- agents: the key is the reserved row's alone.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_agents_reserve_unauthenticated_reader_key()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- An UPDATE that leaves the key as it was (the reserved row's own) passes.
    -- Nested, so OLD is read on UPDATE only.
    IF TG_OP = 'UPDATE' THEN
        IF OLD.public_key IS NOT DISTINCT FROM NEW.public_key THEN
            RETURN NEW;
        END IF;
    END IF;
    IF NEW.public_key = '\x65706967726170682d6d63703a756e61757468656e746963617465642d726472'::bytea THEN
        RAISE EXCEPTION 'RDR01: the public key % is reserved to the '
                        '--allow-unauthenticated-http reader agent (migration 241); no other '
                        'agent may hold it', encode(NEW.public_key, 'escape')
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agents_reserve_unauthenticated_reader_key()
    FROM PUBLIC;

DROP TRIGGER IF EXISTS agents_reserve_unauthenticated_reader_key ON public.agents;
CREATE TRIGGER agents_reserve_unauthenticated_reader_key
    BEFORE INSERT OR UPDATE OF public_key ON public.agents
    FOR EACH ROW
    EXECUTE FUNCTION public.epigraph_agents_reserve_unauthenticated_reader_key();

-- ===================================================================
-- group_memberships: the reader never holds a live row.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_refuse_unauthenticated_reader()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- The WHEN clause admits only a row that is live after the statement. An
    -- UPDATE of a row that was ALREADY live and stays the SAME agent's (a
    -- legacy row: an epoch rotation, a role change) passes; an INSERT, a
    -- revival, and an UPDATE that moves a live row onto another agent (which
    -- 109's identity guard lets through on a maintenance session) are judged.
    -- Nested, so OLD is read on UPDATE only.
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NULL
           AND OLD.agent_id IS NOT DISTINCT FROM NEW.agent_id THEN
            RETURN NEW;
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM public.agents a
                    WHERE a.id = NEW.agent_id
                      AND a.public_key = '\x65706967726170682d6d63703a756e61757468656e746963617465642d726472'::bytea)
    THEN
        RAISE EXCEPTION 'RDR02: agent % is the --allow-unauthenticated-http reader, which reads '
                        'public rows only and may hold no live group membership (migration 241)',
                        NEW.agent_id
            USING ERRCODE = '42501',
                  HINT = 'Group reads go through an authenticated listener; nothing needs the '
                         'reader in a group.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_memberships_refuse_unauthenticated_reader()
    FROM PUBLIC;

DROP TRIGGER IF EXISTS group_memberships_refuse_unauthenticated_reader
    ON public.group_memberships;
CREATE TRIGGER group_memberships_refuse_unauthenticated_reader
    BEFORE INSERT OR UPDATE ON public.group_memberships
    FOR EACH ROW
    WHEN (NEW.revoked_at IS NULL)
    EXECUTE FUNCTION public.epigraph_group_memberships_refuse_unauthenticated_reader();
