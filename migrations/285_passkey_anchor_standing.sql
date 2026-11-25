-- 285: an anchored (`none`) passkey's row records the passkey that admitted
-- it, the ceremony readers serve that anchor beside the person's live
-- passkeys, and a refusal of an assertion on standing is audited while its
-- ticket or act and its passkey are still live (backlog 09ca9ab0).
--
-- ===================================================================
-- 1. WHY
--
-- 200's anchored path registers a later passkey WITHOUT attestation (a
-- synced passkey: recorded `none`) on a `passkey.register` act that a
-- hardware-attested passkey of the same person confirmed. Such a passkey
-- "holds only through its anchor". Two things fell short of that:
--
--   * Its STANDING. The API's assertion check
--     (`epigraph_passkey::Passkeys::assertion_standing`) re-reads the Android
--     attestation status list at every elevation and admin-act assertion, so
--     an `android-key` passkey whose certificate Google lists stops
--     asserting. A `none` passkey was simply in good standing: once its
--     anchor's certificate was listed, the anchor stopped elevating but the
--     synced passkey it admitted kept elevating, until an operator revoked
--     the anchor's ROW (200's cascade acts only on that revoke).
--   * The AUDIT. A standing refusal was logged by the API and written
--     nowhere durable; every other refusal of the ceremony (125's
--     `platform.elevation_refused`, 130's act refusal) is a `security_events`
--     row.
--
-- ===================================================================
-- 2. THE CHANGE
--
-- (a) `person_authenticators.anchor_authenticator_id` (uuid, NULL, FK to the
--     same table, ON DELETE RESTRICT): the passkey that ADMITTED this one.
--     Set for a `none` passkey enrolled on an act (`created_via =
--     'confirmed_act'`): the act's confirming passkey
--     (`pending_admin_acts.authenticator_id`), i.e. 200's lineage step 0.
--     NULL for every other row (an attested passkey stands on its own
--     attestation; a maintenance enrollment has no act). Two CHECKs: only a
--     `none` row carries one, and never itself.
-- (b) `epigraph_person_authenticators_anchor()`, two triggers:
--     * `person_authenticators_record_anchor`, BEFORE INSERT: sets the
--       column from the enrollment's act, OVERWRITING whatever the inserting
--       statement put there (124's completion definer names no such column;
--       a direct insert by a privileged login cannot choose it either). It
--       fires after 124's `person_authenticators_guard_insert` and 200's
--       `person_authenticators_guard_insert_act_confirmer` (triggers fire in
--       name order), so the enrollment is already locked and the confirmer
--       already read live.
--     * `person_authenticators_keep_anchor`, BEFORE UPDATE, WHEN the column
--       changes: refused (ELV03). The anchor is written once, at the insert.
--       124's update guard predates the column and does not list it.
-- (c) THE BACKFILL: every existing `none` row enrolled on an act gets that
--     act's confirming passkey, revoked rows included (the record is about
--     what admitted the passkey, not whether it is live). Run with row
--     security OFF, so a migration login that row security would filter
--     fails (42501) instead of backfilling nothing. 124's
--     `person_authenticators_guard_update` admits only a revoke or a use,
--     so it is DISABLED for this one statement and enabled again before the
--     file ends (the same transaction: a failure rolls both back). The
--     AFTER UPDATE triggers do nothing for it: 124's audit and 125's
--     `person_authenticators_end_elevations` act on a revoke only, and 200's
--     `person_authenticators_revoke_anchored` fires on `revoked_at` only.
--     NO GAP: the ADD COLUMN takes ACCESS EXCLUSIVE on the table first, so a
--     completion in flight either committed before (and is backfilled) or
--     waits and then inserts through (b)'s trigger.
-- (d) `epigraph_passkeys_for_ticket(ticket)` (125) and
--     `epigraph_passkeys_for_act(act)` (130), RE-CREATED with one more
--     column, `anchor_authenticator_id`. Same rows (the ceremony person's
--     live passkeys, only while the ticket or act is live), same gate, same
--     owner and grants, now on 172's form (`pg_catalog, pg_temp`, every name
--     qualified; 271's rule). A changed result type cannot be replaced, so
--     each is dropped and created in this transaction. The API finds a
--     `none` passkey's anchor AMONG THOSE ROWS: an anchor that is revoked
--     (or, on any rows, another person's) is not served, and the passkey is
--     refused. No new credential material is served to the request DSN.
-- (e) `epigraph_record_passkey_standing_refusal(ceremony, id, authenticator,
--     code, reason) -> uuid`: app-callable, SECURITY DEFINER, 172's form.
--     Writes ONE `platform.passkey_standing_refused` row (success false) and
--     returns its id. `ceremony` is `elevation` (a ticket) or `admin_act`
--     (an act); it answers only while that ticket or act is LIVE (unasserted,
--     unexpired: ELV06 / ELV08 otherwise, as 125's and 130's definers raise),
--     only for a LIVE passkey of its person (the ticket person, the act
--     proposer; ELV02 otherwise), and only for the two codes the API refuses
--     with (`attestation_not_in_good_standing`,
--     `attestation_status_unavailable`; 22023 otherwise). The person, the
--     credential id, the row's format and its recorded anchor come from the
--     rows, never from the caller. `reason` is optional, at most 2000
--     characters (22001): the API passes the refusal's words for a listed
--     certificate and NOTHING for an unknown standing (that reason names
--     server paths and settings, and stays in the API's log).
--     The ceremony leaves the ticket or act LIVE (a refreshed status list
--     lets the same one be retried), so nothing else changes.
--     WHAT THE REQUEST DSN CAN DO WITH IT: a holder of the application DSN
--     and a live ticket or act id (the ceremony's capability, which the
--     unauthenticated page already holds) can write such rows for that
--     ticket's or act's person while it lives: audit noise under the right
--     person, no authority, nothing read. The row is append-only (001's
--     `security_events_no_mutate`).
--
-- WHY `security_events`, NOT A NEW TABLE: the triage sketch asked for "an
-- append-only standing-refusal audit table". `security_events` already is
-- one for every `platform.` row (immutable, writable only from a privileged
-- session or a maintenance-owned definer frame, 123), and it is where the
-- elevation's other refusals are audited; 123's `epigraph_platform_audit`
-- returns every `platform.` row, these included. A separate table would split
-- one ceremony's trail in two and add a tenancy and row-security surface for
-- nothing.
--
-- OWNERS AND GRANTS (role-guarded as every such block since 060): every
-- function owned by `epigraph_maintenance`; EXECUTE revoked from PUBLIC; the
-- two readers granted to `epigraph_app` and `epigraph_maintenance` as before;
-- the audit definer granted to `epigraph_app`; the trigger function to
-- nobody. REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- (`DEFERRED_DEFINER_FUNCTIONS` at 285, the grant register, the exempt
-- triggers). Under a non-bypassing owner the trigger reads no enrollment or
-- act and records no anchor (every new anchored passkey is then refused at
-- its first assertion: fail CLOSED), and the audit definer reads no ticket
-- or act (ELV06 / ELV08: loud).
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
--
-- Apply BEFORE the API binary of this change: it selects the readers' new
-- column (42703 without it) and calls the audit definer (42883). An older
-- API binary runs on 285 unchanged (it selects the readers' old columns by
-- name, and never calls the definer).
--
-- UNDO: `docs/runbooks/285-undo.sql`, only after rolling the API back to a
-- build without this change. It restores 125's and 130's readers and drops
-- the column (and so the recorded anchors), the triggers and the definer.
-- The audit rows stay (`security_events` is append-only).
SET LOCAL lock_timeout = '3s';

-- (a) The column.
ALTER TABLE public.person_authenticators
    ADD COLUMN anchor_authenticator_id uuid
        CONSTRAINT person_authenticators_anchor_fk
            REFERENCES public.person_authenticators(id) ON DELETE RESTRICT,
    ADD CONSTRAINT person_authenticators_anchor_only_none
        CHECK (anchor_authenticator_id IS NULL OR attestation_format = 'none'),
    ADD CONSTRAINT person_authenticators_anchor_not_self
        CHECK (anchor_authenticator_id <> id);

-- (b) Recorded at the insert, from the enrollment's act; never changed.
CREATE OR REPLACE FUNCTION public.epigraph_person_authenticators_anchor()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'ELV03: passkey %: the passkey that admitted it is recorded once, at '
                        'its registration; nothing was changed', OLD.id
            USING ERRCODE = 'ELV03';
    END IF;
    NEW.anchor_authenticator_id := NULL;
    IF NEW.attestation_format = 'none' THEN
        SELECT a.authenticator_id INTO NEW.anchor_authenticator_id
          FROM public.passkey_enrollments en
          JOIN public.pending_admin_acts a ON a.id = en.act_id
         WHERE en.id = NEW.enrollment_id
           AND en.created_via = 'confirmed_act';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_person_authenticators_anchor() FROM PUBLIC;

DROP TRIGGER IF EXISTS person_authenticators_record_anchor ON public.person_authenticators;
CREATE TRIGGER person_authenticators_record_anchor
    BEFORE INSERT ON public.person_authenticators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_person_authenticators_anchor();

-- (c) The backfill, before the keep-anchor trigger exists.
SET LOCAL row_security = off;
ALTER TABLE public.person_authenticators DISABLE TRIGGER person_authenticators_guard_update;
UPDATE public.person_authenticators k
   SET anchor_authenticator_id = a.authenticator_id
  FROM public.passkey_enrollments en
  JOIN public.pending_admin_acts a ON a.id = en.act_id
 WHERE en.id = k.enrollment_id
   AND en.created_via = 'confirmed_act'
   AND k.attestation_format = 'none'
   AND k.anchor_authenticator_id IS NULL
   AND a.authenticator_id IS NOT NULL;
ALTER TABLE public.person_authenticators ENABLE TRIGGER person_authenticators_guard_update;
SET LOCAL row_security = on;

DROP TRIGGER IF EXISTS person_authenticators_keep_anchor ON public.person_authenticators;
CREATE TRIGGER person_authenticators_keep_anchor
    BEFORE UPDATE ON public.person_authenticators
    FOR EACH ROW
    WHEN (OLD.anchor_authenticator_id IS DISTINCT FROM NEW.anchor_authenticator_id)
    EXECUTE FUNCTION public.epigraph_person_authenticators_anchor();

-- (d) The ceremony readers, with each passkey's recorded anchor.
DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_ticket(uuid);
CREATE FUNCTION public.epigraph_passkeys_for_ticket(p_ticket uuid)
RETURNS TABLE (authenticator_id uuid, credential_id bytea, passkey jsonb, sign_count bigint,
               backup_eligible boolean, attestation_format text,
               anchor_authenticator_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.id, a.credential_id, a.passkey, a.sign_count, a.backup_eligible,
           a.attestation_format, a.anchor_authenticator_id
      FROM public.elevation_tickets t
      JOIN public.person_authenticators a ON a.person_agent_id = t.person_agent_id
     WHERE t.id = p_ticket
       AND t.outcome IS NULL
       AND pg_catalog.now() < t.expires_at
       AND a.revoked_at IS NULL
     ORDER BY a.created_at, a.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid) FROM PUBLIC;

DROP FUNCTION IF EXISTS public.epigraph_passkeys_for_act(uuid);
CREATE FUNCTION public.epigraph_passkeys_for_act(p_act uuid)
RETURNS TABLE (authenticator_id uuid, credential_id bytea, passkey jsonb, sign_count bigint,
               backup_eligible boolean, attestation_format text,
               anchor_authenticator_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT k.id, k.credential_id, k.passkey, k.sign_count, k.backup_eligible,
           k.attestation_format, k.anchor_authenticator_id
      FROM public.pending_admin_acts a
      JOIN public.person_authenticators k ON k.person_agent_id = a.proposed_by
     WHERE a.id = p_act
       AND a.outcome IS NULL
       AND pg_catalog.now() < a.expires_at
       AND k.revoked_at IS NULL
     ORDER BY k.created_at, k.id
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_passkeys_for_act(uuid) FROM PUBLIC;

-- (e) The audit of a standing refusal.
CREATE OR REPLACE FUNCTION public.epigraph_record_passkey_standing_refusal(
    p_ceremony text, p_id uuid, p_authenticator uuid, p_code text, p_reason text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_person     uuid;
    v_credential bytea;
    v_format     text;
    v_anchor     uuid;
    v_event      uuid;
BEGIN
    IF p_ceremony IS NULL OR p_id IS NULL OR p_authenticator IS NULL OR p_code IS NULL THEN
        RAISE EXCEPTION 'epigraph_record_passkey_standing_refusal: the ceremony, its id, the '
                        'passkey and the code are required'
            USING ERRCODE = '22004';
    END IF;
    IF p_code NOT IN ('attestation_not_in_good_standing', 'attestation_status_unavailable') THEN
        RAISE EXCEPTION 'epigraph_record_passkey_standing_refusal: unknown code %', p_code
            USING ERRCODE = '22023';
    END IF;
    IF p_reason IS NOT NULL AND pg_catalog.length(p_reason) > 2000 THEN
        RAISE EXCEPTION 'epigraph_record_passkey_standing_refusal: the reason is longer than '
                        '2000 characters'
            USING ERRCODE = '22001';
    END IF;
    IF p_ceremony = 'elevation' THEN
        SELECT t.person_agent_id INTO v_person
          FROM public.elevation_tickets t
         WHERE t.id = p_id AND t.outcome IS NULL AND pg_catalog.now() < t.expires_at;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'ELV06: ticket % is not live', p_id
                USING ERRCODE = 'ELV06';
        END IF;
    ELSIF p_ceremony = 'admin_act' THEN
        SELECT a.proposed_by INTO v_person
          FROM public.pending_admin_acts a
         WHERE a.id = p_id AND a.outcome IS NULL AND pg_catalog.now() < a.expires_at;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'ELV08: act % is not live', p_id
                USING ERRCODE = 'ELV08';
        END IF;
    ELSE
        RAISE EXCEPTION 'epigraph_record_passkey_standing_refusal: unknown ceremony %',
                        p_ceremony
            USING ERRCODE = '22023';
    END IF;
    SELECT k.credential_id, k.attestation_format, k.anchor_authenticator_id
      INTO v_credential, v_format, v_anchor
      FROM public.person_authenticators k
     WHERE k.id = p_authenticator AND k.person_agent_id = v_person AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV02: passkey % is not a live passkey of the % person', p_authenticator,
                        p_ceremony
            USING ERRCODE = 'ELV02';
    END IF;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('platform.passkey_standing_refused', v_person, false,
            pg_catalog.jsonb_build_object(
                'ceremony', p_ceremony,
                CASE p_ceremony WHEN 'elevation' THEN 'ticket_id' ELSE 'act_id' END, p_id,
                'person', v_person, 'authenticator_id', p_authenticator,
                'credential_id', pg_catalog.encode(v_credential, 'hex'),
                'attestation_format', v_format, 'anchor_authenticator_id', v_anchor,
                'code', p_code, 'reason', p_reason))
    RETURNING id INTO v_event;
    RETURN v_event;
END $$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_record_passkey_standing_refusal(text, uuid, uuid, text, text) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_person_authenticators_anchor() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_ticket(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_passkeys_for_act(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_record_passkey_standing_refusal(text, uuid, uuid, '
                'text, text) OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_passkeys_for_act(uuid) TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_passkeys_for_ticket(uuid), '
                'public.epigraph_passkeys_for_act(uuid), '
                'public.epigraph_record_passkey_standing_refusal(text, uuid, uuid, text, text) '
                'TO epigraph_app';
    END IF;
END $$;
