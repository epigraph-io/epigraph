-- 348: a self-registered agent client has no owner until an operator names
-- one at approval (backlog be024524).
--
-- ===================================================================
-- 1. WHY
--
-- `POST /oauth/register`'s agent arm stamped every self-registered agent
-- client's `owner_id` with the OLDEST ACTIVE HUMAN client (an inline
-- `SELECT id FROM oauth_clients WHERE client_type = 'human' AND status =
-- 'active' ORDER BY created_at LIMIT 1`, its error swallowed). Nothing about
-- the registration names that human: the request is unauthenticated. It ran
-- only because 001's `agents_must_have_owner` CHECK refuses an agent row with
-- a NULL owner. Consequences:
--
--   * LIVE: the token minted for the agent once approved carries that human's
--     `oauth_clients.id` as its `owner_id` (the `require_owner_or_admin`
--     principal, and the principal a few legacy routes fall back to);
--   * LATENT: `OAuthClientRepository::suspend_by_owner(<that human>)` would
--     suspend every approved self-registered agent with it. That function
--     has no caller in this repository today (the operator's
--     `suspend-client` suspends one row), so nothing has done so yet;
--   * when no human was active, the swallowed lookup returned NULL and the
--     CHECK made every agent registration a 500.
--
-- Agent registrations are `pending` since PR-02 and are approved only by a
-- maintenance session through `epigraph_oauth_client_approve` (188), so the
-- approval is the first point where a principal who can vouch for the agent
-- exists. That is where the owner is named now.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- (a) `agents_must_have_owner` (001) is re-stated as: an agent client that
--     is ACTIVE has an owner. A pending (or suspended, or revoked) agent may
--     have none, so `/oauth/register` writes `owner_id = NULL` and a pending
--     ownerless agent can still be revoked. Activation without an owner is
--     refused by the CHECK (23514) whatever path attempts it: 118's
--     three-argument approval, a status UPDATE, an INSERT.
--     PRECONDITION: the constraint still has 001's definition (55000,
--     nothing changed, otherwise).
-- (b) `public.epigraph_oauth_client_approve(p_id uuid, p_granted_scopes
--     text[], p_approved_by uuid, p_owner_id uuid) RETURNS boolean`: a NEW
--     OVERLOAD beside 118's three-argument definer (224's body, unchanged
--     here). It is 224's body plus the owner:
--       * an `agent` client's approval must name `p_owner_id` (22004
--         otherwise, nothing changed), even when the row already has an
--         owner: rows registered before this migration carry the oldest
--         human, and an approval that silently kept it would keep the
--         defect;
--       * any other client (human, service) is refused an owner (22023,
--         nothing changed) and keeps the one it was created with: an owner
--         is how an AGENT is answered for, and naming one on a service or
--         human client would make its tokens carry another principal's
--         `owner_id` (no path could set a non-agent's owner after creation
--         before 348, and this one does not open one);
--       * a named owner must be another `oauth_clients` row (22023 for the
--         client itself, 23503 for no such row) that is `active` (22023);
--         its client type is not restricted (`POST /api/v1/agents` gives an
--         agent its creating client, a human or a service, as owner);
--       * the `oauth.client_approved` audit row records `owner_id` and
--         `previous_owner_id`, and `migration` 348.
--     SECURITY DEFINER on 172's path `pg_catalog, pg_temp`, every relation
--     and function schema-qualified; owned by `epigraph_maintenance`; no
--     EXECUTE for PUBLIC or `epigraph_app` (188's rule: approval is a
--     maintenance act).
-- (c) Every PENDING agent client `/oauth/register` wrote before 348 loses
--     the owner that registration guessed: `owner_id` becomes NULL, and one
--     `oauth.client_owner_cleared` security event per row records the
--     cleared `previous_owner_id`. Those rows are told apart exactly:
--     `/oauth/register` creates an agent client with `agent_id` NULL, and
--     `POST /api/v1/agents` (the only other creator of an agent client)
--     always passes the agent it created; a client's `agent_id` is linked
--     only at its first token mint, which a pending client never reaches,
--     and nothing moves a client back to `pending`. A pending client never
--     held a token, so clearing its owner revokes nothing. Without (c), 118's
--     three-argument approval (an older CLI, a hand-written `SELECT`) on one
--     of those rows would activate it with the guessed owner, which is the
--     defect itself; with it, that approval fails on the CHECK (23514).
--
-- NOT CHANGED: 118's three-argument definer keeps its 224 body, owner and
-- ACL (224's ratchet pins it). For an ownerless agent it now fails on the
-- CHECK (23514, nothing changed): fail closed. For a pending agent
-- `POST /api/v1/agents` created, it keeps that row's owner (the creating
-- client, which is legitimate). An agent ALREADY ACTIVE with the oldest human
-- as its owner keeps it: the CHECK refuses an active ownerless agent, and
-- which client should answer for it is an operator's decision (re-owning an
-- active client has no verb yet). Such rows can be counted: an active agent
-- client whose `agent_id` is NULL or links a `derived` placeholder agent was
-- self-registered (`POST /api/v1/agents` links a real key at creation).
--
-- ===================================================================
-- 3. DEPLOY ORDER
--
-- Migrate BEFORE the API binary of this change: that binary registers an
-- agent with `owner_id = NULL`, which 001's CHECK refuses (every agent
-- registration a 500). An older API runs on 348 unchanged. The operator
-- CLI's `approve-client` of this change calls the four-argument definer
-- (42883 below 348). Approve agents with the four-argument form only: an
-- older CLI, or a hand-written three-argument `SELECT`, on 348 cannot
-- activate an ownerless agent (23514), and for an agent that has an owner it
-- keeps that owner without anyone naming it.
--
-- UNDO: `docs/runbooks/348-undo.sql` (drops the overload, restores 001's
-- CHECK; refuses while an agent row has no owner, including the rows (c)
-- cleared, whose previous owners are in their `oauth.client_owner_cleared`
-- rows).
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- (a) The CHECK: an ACTIVE agent client has an owner.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_def text;
BEGIN
    SELECT pg_catalog.pg_get_constraintdef(c.oid) INTO v_def
      FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'public.oauth_clients'::regclass
       AND c.conname = 'agents_must_have_owner';
    IF v_def IS DISTINCT FROM
       'CHECK ((((client_type)::text <> ''agent''::text) OR (owner_id IS NOT NULL)))' THEN
        RAISE EXCEPTION '348: oauth_clients.agents_must_have_owner is not 001''s CHECK '
                        '(found %); nothing was changed', COALESCE(v_def, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

ALTER TABLE public.oauth_clients DROP CONSTRAINT agents_must_have_owner;
ALTER TABLE public.oauth_clients ADD CONSTRAINT agents_must_have_owner
    CHECK (((client_type)::text <> 'agent'::text)
           OR (owner_id IS NOT NULL)
           OR ((status)::text <> 'active'::text));

-- -------------------------------------------------------------------
-- (c) Pending self-registered agents lose the owner their registration
--     guessed (after (a): 001's CHECK would refuse the NULL). The previous
--     owner is read BEFORE the UPDATE (`RETURNING` sees the new row) and
--     kept in one append-only security event per row.
-- -------------------------------------------------------------------
WITH guessed AS (
    SELECT c.id, c.owner_id
      FROM public.oauth_clients c
     WHERE c.client_type = 'agent'
       AND c.status = 'pending'
       AND c.agent_id IS NULL
       AND c.owner_id IS NOT NULL
       FOR UPDATE
), cleared AS (
    UPDATE public.oauth_clients o
       SET owner_id = NULL, updated_at = pg_catalog.now()
      FROM guessed g
     WHERE o.id = g.id
    RETURNING o.id, g.owner_id AS previous_owner_id
)
INSERT INTO public.security_events (event_type, agent_id, success, details)
SELECT 'oauth.client_owner_cleared', NULL, true,
       pg_catalog.jsonb_build_object('oauth_client_id', x.id,
                                     'previous_owner_id', x.previous_owner_id,
                                     'reason', 'owner guessed at /oauth/register (backlog be024524)',
                                     'migration', 348)
  FROM cleared x;

-- -------------------------------------------------------------------
-- (b) The approval that names the owner.
-- -------------------------------------------------------------------
CREATE FUNCTION public.epigraph_oauth_client_approve(
    p_id uuid, p_granted_scopes text[], p_approved_by uuid, p_owner_id uuid)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_prev text;
    v_type text;
    v_prev_owner uuid;
    v_owner_status text;
BEGIN
    SELECT c.status, c.client_type, c.owner_id INTO v_prev, v_type, v_prev_owner
      FROM public.oauth_clients c WHERE c.id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF v_type = 'agent' AND p_owner_id IS NULL THEN
        RAISE EXCEPTION 'agent client % is approved only with its owner named; nothing was '
                        'approved', p_id
            USING ERRCODE = '22004',
                  HINT = 'Pass the oauth_clients.id of the client that answers for this '
                         'agent as p_owner_id.';
    END IF;
    IF v_type IS DISTINCT FROM 'agent' AND p_owner_id IS NOT NULL THEN
        RAISE EXCEPTION 'oauth client % is a % client: only an agent client is given an owner '
                        'at approval; nothing was approved', p_id, v_type
            USING ERRCODE = '22023',
                  HINT = 'Pass NULL as p_owner_id; the client keeps the owner it was created '
                         'with.';
    END IF;
    IF p_owner_id IS NOT NULL THEN
        IF p_owner_id = p_id THEN
            RAISE EXCEPTION 'oauth client % cannot own itself; nothing was approved', p_id
                USING ERRCODE = '22023';
        END IF;
        SELECT o.status INTO v_owner_status
          FROM public.oauth_clients o WHERE o.id = p_owner_id FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'owner % is not an oauth client; nothing was approved', p_owner_id
                USING ERRCODE = '23503';
        END IF;
        IF v_owner_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'owner % is %, not active; nothing was approved',
                            p_owner_id, v_owner_status
                USING ERRCODE = '22023';
        END IF;
    END IF;
    UPDATE public.oauth_clients
       SET granted_scopes = COALESCE(p_granted_scopes, ARRAY[]::text[]), status = 'active',
           created_by = p_approved_by, owner_id = COALESCE(p_owner_id, v_prev_owner),
           updated_at = pg_catalog.now()
     WHERE id = p_id;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('oauth.client_approved', NULL, true,
            pg_catalog.jsonb_build_object('oauth_client_id', p_id, 'approved_by', p_approved_by,
                               'previous_status', v_prev,
                               'granted_scopes', pg_catalog.to_jsonb(COALESCE(p_granted_scopes, ARRAY[]::text[])),
                               'owner_id', COALESCE(p_owner_id, v_prev_owner),
                               'previous_owner_id', v_prev_owner,
                               'migration', 348));
    RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_client_approve(uuid, text[], uuid, uuid)
    FROM PUBLIC;

-- Ownership, guarded as every such block since 060. The ALTER names its
-- function literally (tenancy_backfill.rs's static re-own scan reads it).
-- No GRANT: approval is a maintenance act (188).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_oauth_client_approve(uuid, text[], uuid, uuid) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; '
                     'epigraph_oauth_client_approve(uuid, text[], uuid, uuid) stays owned by '
                     'the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_oauth_client_approve(uuid, text[], uuid, uuid) FROM epigraph_app';
    END IF;
END $$;
