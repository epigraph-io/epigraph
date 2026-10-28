-- 184: retract ONE mass function (BBA) without deleting it (operator ruling
-- R-79, backlog f8ec73b7).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- A single bad BBA (a duplicate re-observation folded as independent mass, a
-- promotion copy left beside its original) had no remedy short of a hard
-- DELETE, which loses the row an audit needs, or a counter-BBA, which adds
-- mass instead of removing it. The ruling: mark that one row RETRACTED. A
-- retracted row is excluded from every fold and belief read and is kept, with
-- who retracted it, when and why, plus an audit row. Only the BBA's owner (a
-- writer of its owning group) or a live `claims:admin` holder may retract it.
--
-- ===================================================================
-- 1. THE COLUMNS
-- ===================================================================
--
-- `retracted_at`, `retracted_by` (the session principal that retracted it)
-- and `retract_reason`, all NULL on a live row and all set on a retracted
-- one (`mass_functions_retract_columns_together`). Readers exclude a row with
-- `retracted_at IS NULL`, spelled once in Rust
-- (`epigraph_db::repos::mass_function::not_retracted_predicate`) and pinned by
-- the read ratchet `epigraph-db/tests/bba_retract_read_lint.rs`.
--
-- A retracted row's upsert key `(claim, frame, source agent, perspective)`
-- (migration 034's unique key) stays HELD by it (operator ruling R-103): a
-- later write to that key, by the owner or by any automated writer (the
-- repository upsert `MassFunctionRepository::store_with_perspective`, which
-- every BBA writer goes through), is REFUSED with RT07 and changes nothing.
-- A retracted BBA becomes live again only through the explicit, audited
-- un-retract (section 2b), after which its key takes writes again.
--
-- ===================================================================
-- 2. THE DEFINER
-- ===================================================================
--
-- `epigraph_retract_mass_function(p_id, p_reason, p_admin_client,
-- p_admin_jti)` is the one path that sets the columns. It refuses, writing
-- nothing:
--   * RT01 (42501) no session principal: nobody to record as the retractor;
--   * RT05 (42501) an ELEVATED session: 126's `mass_functions_elevated_no_update`
--     refuses such a session every UPDATE of `mass_functions`, and this
--     definer must not be the way around it;
--   * RT04 (22023) an empty reason (after trimming) or one over 2000 chars;
--   * RT02 (P0002) "mass function not found" when the id does not exist OR the
--     session cannot read the row (public, or owned by one of
--     `epigraph_session_groups()`): ONE answer for both, so this is no
--     existence oracle. Readability filters the locking read, so such a
--     caller takes and waits on no lock;
--   * RT03 (42501) a readable row the caller may not retract: its owning
--     group is not in `epigraph_writable_groups()` AND no live `claims:admin`
--     grant is presented. The admin arm re-checks the grant against the token's
--     client record exactly as migration 111 does: `oauth_clients` row
--     `p_admin_client` is `active`, carries `claims:admin` in
--     `granted_scopes`, and is bound to the session principal.
-- Then, if the row is already retracted, it returns `already_retracted` with
-- the existing columns and writes NOTHING (no second audit row): a re-retract
-- is idempotent. Otherwise it sets the three columns and appends one
-- `security_events` row (`event_type = 'mass_functions.retract'`, `agent_id` =
-- the retractor) naming the row, its claim and frame, the owning group, the
-- arm (`owner` or `admin`), the admin's client and token id when that arm was
-- used, the reason, and `before` (the full row as `to_jsonb`).
--
-- A first retraction also DELETES the stored scoped beliefs of the row's
-- (claim, frame) in `ds_combined_beliefs` (written by `POST
-- /frames/:id/evidence` and `/claims/:id/assess`) that FOLDED the retracted
-- row, and only those: the global scope, the perspective scope of the row's
-- own `perspective_id`, and each community scope whose community counts that
-- perspective as a member (a community's `override` row is its own
-- assessment, not a fold of members, and stays). The scoped-belief reads
-- serve those rows as stored; no row is better than a stale one, and the next
-- evidence write on that (claim, frame) stores fresh ones. A perspective or
-- community that never included the row keeps its stored fold. The count is
-- in the audit row and the return value (`scoped_beliefs_cleared`).
--
-- EFFECTIVE REACH. That DELETE is why this file grants `epigraph_maintenance`
-- DELETE on `ds_combined_beliefs` (the definer's owner; 115's restrictive
-- DELETE policy admits its frame). The grant is on the role, not on the
-- definer: any session that acts as `epigraph_maintenance` (jobs, scripts and
-- logins on the maintenance DSN) can now DELETE any `ds_combined_beliefs` row.
-- Those rows are derived caches (each is rewritten by the next evidence write
-- that recomputes its scope), so the loss such a delete can cause is a stored
-- scoped belief served as absent until then. No application role
-- gains anything: `epigraph_app` holds no DELETE on the table.
--
-- The caller recomputes the claim's cached belief afterwards, on the same
-- transaction (the HTTP route and the MCP tool both do).
--
-- ===================================================================
-- 2b. THE UN-RETRACT DEFINER
-- ===================================================================
--
-- `epigraph_unretract_mass_function(p_id, p_reason, p_admin_client,
-- p_admin_jti)` is the one path that makes a retracted row live again
-- (ruling R-103). It takes the same authority as the retraction and refuses
-- with the same codes, writing nothing: RT01 (no principal), RT05 (an
-- elevated session), RT04 (a reason empty after trimming or over 2000
-- chars), RT02 (missing or unreadable: one answer), RT03 (readable, but the
-- caller writes neither the owning group nor presents a live `claims:admin`
-- grant). Authority is decided before state, so a caller that may not
-- un-retract a row learns nothing of it. A row that is not retracted answers
-- `not_retracted` and writes nothing. Otherwise it clears the three columns
-- (the masses are the ones that were retracted: section 3 refuses any change
-- to a retracted row's assessment), deletes the stored scoped beliefs of the
-- row's (claim, frame) that will fold it again (the same scopes a retraction
-- clears, now stale the other way), and appends one `security_events` row
-- (`mass_functions.unretract`, `agent_id` = the caller) naming the row, its
-- claim and frame, the owning group, the arm, the admin's client and token id
-- when that arm was used, the reason, `before` (the row as it was, retraction
-- included) and the count of stored scoped beliefs cleared. An owner may
-- un-retract a retraction a `claims:admin` holder made, and the reverse; the
-- audit row's arm says which.
--
-- The caller recomputes the claim's cached belief afterwards, on the same
-- transaction (the HTTP route and the MCP tool both do).
--
-- ===================================================================
-- 3. THE GUARDS
-- ===================================================================
--
-- The owner may UPDATE (and INSERT) its own rows under 077. Without guards it
-- could mark a row retracted with no audit row and a `retracted_by` of its
-- choosing, silently undo a retraction (including one a `claims:admin`
-- holder made), or overwrite what was retracted. Four row triggers close
-- that (all plain `BEFORE` triggers, so none depends on which columns a
-- statement's SET list names):
--   * `mass_functions_retract_guard` (UPDATE) refuses SETTING or CHANGING the
--     retract columns to a retracted state (RT06);
--   * `mass_functions_retract_insert_guard` (INSERT) refuses a new row that
--     arrives with any retract column set (RT06);
--   * `mass_functions_retracted_rewrite_guard` (UPDATE, ruling R-103) refuses
--     any change to a RETRACTED row's assessment: `masses`, `conflict_k`,
--     `combination_method`, `source_strength`, `locality_tag`, `evidence_id`
--     or `created_at` (RT07, SQLSTATE 42501, DETAIL = the row's id). This is
--     what an upsert onto a retracted key is (the repository upsert always
--     stamps a new `created_at`), whoever runs it: it has NO bypass, so an
--     application session, a backfill on the maintenance connection and a
--     maintenance-owned definer are all refused, and the statement (with the
--     transaction it runs in) writes nothing. Moving a retracted row with its
--     claim (114's dedup move, the dedup repair and restore), re-stamping its
--     tenancy and back-filling its `evidence_type` tag change no assessment
--     column and pass;
--   * `mass_functions_unretract_guard` (UPDATE, ruling R-103) refuses
--     CLEARING the retract columns anywhere but inside section 2b's definer
--     (RT06), with no session bypass: a clear is admitted only when the
--     statement runs as the maintenance role (`epigraph_definer_bypass()`,
--     true inside a maintenance-owned definer) AND the transaction-local
--     setting `epigraph.mf_unretract_id` names the row. The definer sets that
--     setting for its one UPDATE, and its `SET` clause makes it revert when the
--     definer returns. An application session can set the setting but is not
--     the maintenance role; a login on the maintenance role itself could set
--     both (as it could disable the trigger), which is outside what these
--     guards defend. Every clear is therefore section 2b's, and audited there.
-- Triggers of one event fire in name order, so a statement that both rewrites
-- and clears a retracted row is answered RT07.
-- The two guards on MARKING admit a privileged session (`epigraph_bypass()`:
-- the maintenance operator, and the dedup repair and restore, which run on
-- the maintenance connection) and a maintenance-owned definer frame
-- (`epigraph_definer_bypass()`: section 2's definer, 114's dedup move).
--
-- ===================================================================
-- 4. DEPLOY AND UNDO
-- ===================================================================
--
-- The migration runs in ONE transaction and holds ACCESS EXCLUSIVE on
-- `mass_functions` from the first `ALTER TABLE` to the commit: every read and
-- write of the table waits for it. `ADD COLUMN` of nullable columns with no
-- default is catalog-only; adding the CHECK constraint scans the table once
-- (sequentially, sized by its row count) under that same lock, as every
-- existing row has the three columns NULL and passes. Measure the row count
-- before the deploy window. Apply BEFORE a binary with the matching readers
-- serves: that binary selects `retracted_at` in its predicates. A binary
-- WITHOUT this change against a database WITH it keeps working, and folds
-- every row, as no row is retracted until a new binary's route or tool
-- retracts one.
--
-- UNDO (only while no row is retracted, or after deciding what a retracted row
-- should become): REVOKE DELETE ON ds_combined_beliefs FROM epigraph_maintenance;
-- DROP TRIGGER mass_functions_unretract_guard ON mass_functions;
-- DROP TRIGGER mass_functions_retracted_rewrite_guard ON mass_functions;
-- DROP TRIGGER mass_functions_retract_insert_guard ON mass_functions;
-- DROP TRIGGER mass_functions_retract_guard ON mass_functions;
-- DROP FUNCTION epigraph_mass_function_retract_guard(); DROP FUNCTION
-- epigraph_unretract_mass_function(uuid, text, uuid, uuid); DROP FUNCTION
-- epigraph_retract_mass_function(uuid, text, uuid, uuid); ALTER TABLE
-- mass_functions DROP CONSTRAINT mass_functions_retract_columns_together, DROP
-- COLUMN retract_reason, DROP COLUMN retracted_by, DROP COLUMN retracted_at.
--
-- Checked before claiming: no `origin/main` migration, open PR, origin branch
-- or local worktree carries a `184`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE COLUMNS
-- ===================================================================
ALTER TABLE public.mass_functions
    ADD COLUMN IF NOT EXISTS retracted_at   timestamptz,
    ADD COLUMN IF NOT EXISTS retracted_by   uuid,
    ADD COLUMN IF NOT EXISTS retract_reason text;

ALTER TABLE public.mass_functions
    DROP CONSTRAINT IF EXISTS mass_functions_retract_columns_together;
-- Validated as it is added: the table is already ACCESS EXCLUSIVE locked by
-- the ADD COLUMN above, so a NOT VALID / VALIDATE pair would gain nothing.
ALTER TABLE public.mass_functions
    ADD CONSTRAINT mass_functions_retract_columns_together
    CHECK ((retracted_at IS NULL) = (retracted_by IS NULL)
           AND (retracted_at IS NULL) = (retract_reason IS NULL));

COMMENT ON COLUMN public.mass_functions.retracted_at IS
    'Migration 184 (ruling R-79): when this BBA was retracted. A retracted row is excluded from '
    'every fold and belief read and kept for audit. Set only by epigraph_retract_mass_function.';
COMMENT ON COLUMN public.mass_functions.retracted_by IS
    'Migration 184: the session principal that retracted this BBA (the owner''s writer or a '
    'claims:admin holder).';
COMMENT ON COLUMN public.mass_functions.retract_reason IS
    'Migration 184: the reason given when this BBA was retracted.';

-- ===================================================================
-- 2. THE DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_retract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_at timestamptz;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record as the retractor; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session retracts no mass function; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: a retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability is in the WHERE: a caller that cannot read the row locks
    -- nothing and gets the answer a random id gets.
    SELECT mf.* INTO v_row
      FROM public.mass_functions mf
     WHERE mf.id = p_id
       AND (mf.visibility = 'public'
            OR mf.owner_group_id = ANY (public.epigraph_session_groups()))
       FOR UPDATE OF mf;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'RT02: mass function not found' USING ERRCODE = 'P0002';
    END IF;

    IF v_row.owner_group_id = ANY (COALESCE(public.epigraph_writable_groups(),
                                            ARRAY[]::uuid[])) THEN
        v_arm := 'owner';
    ELSIF p_admin_client IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.oauth_clients c
             WHERE c.id = p_admin_client
               AND c.agent_id = v_principal
               AND c.status = 'active'
               AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        v_arm := 'admin';
    ELSE
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'RT03: only a writer of the mass function''s owning group, or a '
                           'live claims:admin holder, retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NOT NULL THEN
        RETURN jsonb_build_object(
            'status',           'already_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'retracted_at',     v_row.retracted_at,
            'retracted_by',     v_row.retracted_by,
            'retract_reason',   v_row.retract_reason,
            'arm',              v_arm,
            'scoped_beliefs_cleared', 0);
    END IF;

    UPDATE public.mass_functions
       SET retracted_at = now(), retracted_by = v_principal, retract_reason = v_reason
     WHERE id = p_id
    RETURNING retracted_at INTO v_at;

    -- Only the stored folds that included this row: the global scope, its
    -- own perspective's, and each community counting that perspective (not
    -- a community's mass override, which folds no member row).
    DELETE FROM public.ds_combined_beliefs d
     WHERE d.claim_id = v_row.claim_id AND d.frame_id = v_row.frame_id
       AND (d.scope_type = 'global'
            OR (d.scope_type = 'perspective' AND d.scope_id = v_row.perspective_id)
            OR (d.scope_type = 'community'
                AND COALESCE(d.strategy_used, '') <> 'override'
                AND d.scope_id IN (SELECT cm.community_id
                                     FROM public.community_members cm
                                    WHERE cm.perspective_id = v_row.perspective_id)));
    GET DIAGNOSTICS v_scoped = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES ('mass_functions.retract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'retractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'retracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'retracted_at',     v_at,
        'retracted_by',     v_principal,
        'retract_reason',   v_reason,
        'arm',              v_arm,
        'scoped_beliefs_cleared', v_scoped);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_retract_mass_function(uuid, text, uuid, uuid)
    FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_retract_mass_function(uuid, text, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_retract_mass_function(uuid, text, uuid, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT DELETE ON public.ds_combined_beliefs TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_retract_mass_function(uuid, text, uuid, uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 2b. THE UN-RETRACT DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_unretract_mass_function(
    p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
-- Reverts the clear marker (section 3) when the function returns.
SET epigraph.mf_unretract_id = ''
AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_reason text := btrim(COALESCE(p_reason, ''));
        v_row public.mass_functions%ROWTYPE;
        v_arm text;
        v_scoped bigint;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'RT01: un-retracting a mass function needs a session principal '
            '(epigraph.principal_id) to record; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'RT05: an elevated session un-retracts no mass function; '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_reason = '' OR length(v_reason) > 2000 THEN
        RAISE EXCEPTION 'RT04: an un-retraction needs a reason of 1 to 2000 characters; '
            'nothing was written'
            USING ERRCODE = '22023';
    END IF;

    -- Readability in the WHERE, as in section 2.
    SELECT mf.* INTO v_row
      FROM public.mass_functions mf
     WHERE mf.id = p_id
       AND (mf.visibility = 'public'
            OR mf.owner_group_id = ANY (public.epigraph_session_groups()))
       FOR UPDATE OF mf;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'RT02: mass function not found' USING ERRCODE = 'P0002';
    END IF;

    IF v_row.owner_group_id = ANY (COALESCE(public.epigraph_writable_groups(),
                                            ARRAY[]::uuid[])) THEN
        v_arm := 'owner';
    ELSIF p_admin_client IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.oauth_clients c
             WHERE c.id = p_admin_client
               AND c.agent_id = v_principal
               AND c.status = 'active'
               AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        v_arm := 'admin';
    ELSE
        RAISE EXCEPTION 'new row violates row-level security policy for table "mass_functions"'
            USING ERRCODE = '42501',
                  DETAIL = 'RT03: only a writer of the mass function''s owning group, or a '
                           'live claims:admin holder, un-retracts it; nothing was written';
    END IF;

    -- After the authority checks, so a caller that may not un-retract the row
    -- learns nothing of its state.
    IF v_row.retracted_at IS NULL THEN
        RETURN jsonb_build_object(
            'status',           'not_retracted',
            'mass_function_id', v_row.id,
            'claim_id',         v_row.claim_id,
            'frame_id',         v_row.frame_id,
            'unretracted_by',   v_principal,
            'reason',           v_reason,
            'arm',              v_arm,
            'previously_retracted_at', NULL,
            'previously_retracted_by', NULL,
            'previous_retract_reason', NULL,
            'scoped_beliefs_cleared', 0);
    END IF;

    PERFORM set_config('epigraph.mf_unretract_id', p_id::text, true);
    UPDATE public.mass_functions
       SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL
     WHERE id = p_id;
    PERFORM set_config('epigraph.mf_unretract_id', '', true);

    -- The stored folds that will include this row again: the same scopes a
    -- retraction clears.
    DELETE FROM public.ds_combined_beliefs d
     WHERE d.claim_id = v_row.claim_id AND d.frame_id = v_row.frame_id
       AND (d.scope_type = 'global'
            OR (d.scope_type = 'perspective' AND d.scope_id = v_row.perspective_id)
            OR (d.scope_type = 'community'
                AND COALESCE(d.strategy_used, '') <> 'override'
                AND d.scope_id IN (SELECT cm.community_id
                                     FROM public.community_members cm
                                    WHERE cm.perspective_id = v_row.perspective_id)));
    GET DIAGNOSTICS v_scoped = ROW_COUNT;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES ('mass_functions.unretract', v_principal, true,
            jsonb_build_object(
                'mass_function_id', v_row.id,
                'claim_id',         v_row.claim_id,
                'frame_id',         v_row.frame_id,
                'owner_group_id',   v_row.owner_group_id,
                'arm',              v_arm,
                'unretractor_agent_id', v_principal,
                'admin_client_id',  CASE WHEN v_arm = 'admin' THEN p_admin_client END,
                'admin_token_jti',  CASE WHEN v_arm = 'admin' THEN p_admin_jti END,
                'reason',           v_reason,
                'before',           to_jsonb(v_row),
                'scoped_beliefs_cleared', v_scoped,
                'migration',        184),
            CASE WHEN v_arm = 'admin' THEN left(p_admin_jti::text, 64) END);

    RETURN jsonb_build_object(
        'status',           'unretracted',
        'mass_function_id', v_row.id,
        'claim_id',         v_row.claim_id,
        'frame_id',         v_row.frame_id,
        'unretracted_by',   v_principal,
        'reason',           v_reason,
        'arm',              v_arm,
        'previously_retracted_at', v_row.retracted_at,
        'previously_retracted_by', v_row.retracted_by,
        'previous_retract_reason', v_row.retract_reason,
        'scoped_beliefs_cleared', v_scoped);
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)
    FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_unretract_mass_function(uuid, text, uuid, uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 3. THE GUARDS
-- ===================================================================
-- SECURITY INVOKER on purpose: `epigraph_definer_bypass()` reads
-- `current_user`, which is the definer's owner inside section 2's frame (and
-- 114's dedup definers') and the session role everywhere else. TG_ARGV[0]
-- names what the firing trigger refuses.
CREATE OR REPLACE FUNCTION public.epigraph_mass_function_retract_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
    -- R-103: no session or frame re-writes a retracted row's assessment.
    IF TG_ARGV[0] = 'rewrite' THEN
        RAISE EXCEPTION 'RT07: mass function % is retracted; a write to its key (claim, frame, '
            'source agent, perspective) is refused until it is un-retracted; nothing was written',
            OLD.id
            USING ERRCODE = '42501', DETAIL = OLD.id::text;
    END IF;
    -- R-103: only section 2b's definer clears a retraction.
    IF TG_ARGV[0] = 'clear' THEN
        IF public.epigraph_definer_bypass()
           AND current_setting('epigraph.mf_unretract_id', true) = OLD.id::text THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'RT06: a retracted mass function is made live again only through '
            'epigraph_unretract_mass_function (which records who, why and an audit row); '
            'nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_bypass() OR public.epigraph_definer_bypass() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'RT06: a mass function is retracted only through '
        'epigraph_retract_mass_function (which records the retractor and an audit row); '
        'nothing was written'
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS mass_functions_retract_guard ON public.mass_functions;
CREATE TRIGGER mass_functions_retract_guard
    BEFORE UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (NEW.retracted_at IS NOT NULL
          AND (OLD.retracted_at, OLD.retracted_by, OLD.retract_reason)
              IS DISTINCT FROM (NEW.retracted_at, NEW.retracted_by, NEW.retract_reason))
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('mark');

DROP TRIGGER IF EXISTS mass_functions_retract_insert_guard ON public.mass_functions;
CREATE TRIGGER mass_functions_retract_insert_guard
    BEFORE INSERT ON public.mass_functions
    FOR EACH ROW
    WHEN (NEW.retracted_at IS NOT NULL OR NEW.retracted_by IS NOT NULL
          OR NEW.retract_reason IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('mark');

DROP TRIGGER IF EXISTS mass_functions_retracted_rewrite_guard ON public.mass_functions;
CREATE TRIGGER mass_functions_retracted_rewrite_guard
    BEFORE UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.retracted_at IS NOT NULL
          AND (NEW.masses, NEW.conflict_k, NEW.combination_method, NEW.source_strength,
               NEW.locality_tag, NEW.evidence_id, NEW.created_at)
              IS DISTINCT FROM
              (OLD.masses, OLD.conflict_k, OLD.combination_method, OLD.source_strength,
               OLD.locality_tag, OLD.evidence_id, OLD.created_at))
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('rewrite');

DROP TRIGGER IF EXISTS mass_functions_unretract_guard ON public.mass_functions;
CREATE TRIGGER mass_functions_unretract_guard
    BEFORE UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.retracted_at IS NOT NULL AND NEW.retracted_at IS NULL)
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('clear');
