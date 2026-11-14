-- Migration 213: an agent's client_credentials assertion is single use. Its
-- nonce is recorded, and a second presentation inside the freshness window is
-- refused (backlog 950696a1, step 1).
--
-- EVIDENCE
-- `oauth/token.rs::verify_agent_assertion` accepts
-- `timestamp(8) || nonce(16) || Ed25519(timestamp || nonce)` for 300 seconds
-- after its timestamp and kept no record of the nonce ("No nonce tracking
-- (stateless)"). A captured assertion therefore minted a fresh access token,
-- and a fresh 24-hour refresh token, as often as it was replayed for those
-- five minutes. The only defence was transport security.
--
-- CHANGE
--   1. `oauth_assertion_nonces(oauth_client_id, nonce, expires_at, used_at)`:
--      one row per assertion an agent presented, keyed by the client
--      (`oauth_clients.id`) and the assertion's 16-byte nonce. It holds no
--      credential: a nonce cannot be presented without a signature over it.
--      No FK to `oauth_clients`: the row is a short-lived replay record, it
--      dies with its window, and an FK would only add a lock on the client
--      row to every token mint.
--   2. `epigraph_oauth_assertion_nonce_consume(client, nonce, expires_at)`: the
--      ONLY write path, a SECURITY DEFINER on 172's form
--      (`pg_catalog, pg_temp`, every name qualified), owned by
--      `epigraph_maintenance`, EXECUTE revoked from PUBLIC and granted to
--      `epigraph_app`. It returns true when it recorded the nonce (the first
--      presentation) and false when the pair is already recorded (a replay).
--      The INSERT ... ON CONFLICT DO NOTHING is the whole decision, so two
--      concurrent presentations of one assertion record exactly one row: the
--      second waits on the first's unique-index entry and then sees the
--      conflict. The caller (`oauth/token.rs`) consumes a nonce only AFTER
--      the assertion's signature and freshness have verified, so an
--      unauthenticated request cannot write a row.
--      It also PRUNES, lazily: up to 1000 rows already past `expires_at` are
--      deleted on every call (`FOR UPDATE SKIP LOCKED`, so concurrent mints
--      never wait on each other's prune). The table grows only by agent token
--      mints and refreshes, and each one trims it; no timer is needed.
--      RETENTION. The caller sets `expires_at` to the assertion's timestamp
--      plus the freshness window (300 s) plus a 60 s margin. The application
--      refuses the assertion after timestamp + 300 s on ITS clock; the prune
--      deletes on the DATABASE clock, so the margin is the clock skew the
--      two may have before a pruned nonce could be presented again inside
--      the window. The definer refuses an `expires_at` more than one hour
--      ahead (22023), so a caller bug cannot pin rows indefinitely, and
--      answers false, recording nothing, for one already past.
--   3. The application role keeps SELECT only (`rls_enforcement.rs` requires
--      every public table to be readable by `epigraph_app`; nothing here is
--      secret). 077's default privileges granted it INSERT, UPDATE, DELETE and
--      TRUNCATE; they are revoked here, so no application session can delete
--      a recorded nonce (re-opening the replay) or plant one.
--
-- The table carries no tenancy columns and no row security: a used nonce is a
-- property of a credential, not tenant content (like `refresh_tokens` and
-- 141's `revoked_access_tokens`).
--
-- NOT CHANGED HERE: the signed message is still `timestamp || nonce`, with no
-- domain tag and no audience (backlog 950696a1, step 2). Binding the token
-- endpoint into the signature changes the wire format for every agent client
-- and needs a dual-format acceptance window; it is a separate change.
--
-- DEPLOY ORDER. Apply before (or with) the binary that calls the definer: a
-- current binary on a database without this file fails CLOSED (every agent
-- client_credentials and refresh grant is refused 500 while the call errors).
-- A binary that predates this file never calls it and is unaffected.
--
-- UNDO: docs/runbooks/213-undo.sql (roll the binaries back first).

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.oauth_assertion_nonces (
    oauth_client_id uuid        NOT NULL,
    nonce           bytea       NOT NULL
                        CONSTRAINT oauth_assertion_nonces_nonce_len
                        CHECK (octet_length(nonce) = 16),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (oauth_client_id, nonce)
);
COMMENT ON TABLE public.oauth_assertion_nonces IS
    'Migration 213: the nonces of agent client_credentials assertions already presented, '
    'kept until their freshness window (plus a skew margin) has passed. Written and pruned '
    'only by epigraph_oauth_assertion_nonce_consume; the application role may only read it.';

-- The prune's predicate.
CREATE INDEX IF NOT EXISTS idx_oauth_assertion_nonces_expires_at
    ON public.oauth_assertion_nonces (expires_at);

-- Record one presented assertion nonce. Returns true when this call recorded
-- it, false when the (client, nonce) pair was already recorded (a replay) or
-- when `p_expires_at` has already passed. Raises 22023 on a NULL argument, a
-- nonce that is not 16 bytes, or an expiry more than one hour ahead.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_assertion_nonce_consume(
    p_client_id uuid, p_nonce bytea, p_expires_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_now timestamptz := pg_catalog.now();
    v_n   integer;
BEGIN
    IF p_client_id IS NULL OR p_nonce IS NULL OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'AN01: an assertion nonce names a client, a nonce and an expiry'
            USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.octet_length(p_nonce) <> 16 THEN
        RAISE EXCEPTION 'AN02: an assertion nonce is 16 bytes (got %)',
                        pg_catalog.octet_length(p_nonce)
            USING ERRCODE = '22023';
    END IF;
    IF p_expires_at > v_now + interval '1 hour' THEN
        RAISE EXCEPTION 'AN03: an assertion nonce is kept for at most one hour'
            USING ERRCODE = '22023';
    END IF;

    DELETE FROM public.oauth_assertion_nonces d
     WHERE (d.oauth_client_id, d.nonce) IN (
           SELECT x.oauth_client_id, x.nonce
             FROM public.oauth_assertion_nonces x
            WHERE x.expires_at <= v_now
            ORDER BY x.expires_at
            LIMIT 1000
              FOR UPDATE SKIP LOCKED);

    IF p_expires_at <= v_now THEN
        RETURN false;
    END IF;

    INSERT INTO public.oauth_assertion_nonces (oauth_client_id, nonce, expires_at)
    VALUES (p_client_id, p_nonce, p_expires_at)
    ON CONFLICT (oauth_client_id, nonce) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n = 1;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_assertion_nonce_consume(uuid, bytea, timestamptz)
    FROM PUBLIC;

REVOKE ALL ON public.oauth_assertion_nonces FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        -- The definer records and prunes as its owner. UPDATE is the
        -- privilege the prune's `FOR UPDATE SKIP LOCKED` row lock needs; no
        -- statement in the definer updates a row.
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.oauth_assertion_nonces '
                'TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_oauth_assertion_nonce_consume('
                'uuid, bytea, timestamptz) OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 213 definer '
                     'stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_oauth_assertion_nonce_consume('
                'uuid, bytea, timestamptz) TO epigraph_app';
        EXECUTE 'REVOKE ALL ON public.oauth_assertion_nonces FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.oauth_assertion_nonces TO epigraph_app';
    END IF;
END $$;
