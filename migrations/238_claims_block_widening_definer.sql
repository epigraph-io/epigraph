-- 238: 074's sealed-claim widening guard reads `claim_encryption` with
-- definer rights (backlog b5f6883b).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 074's `epigraph_claims_block_widening` (the body of the BEFORE UPDATE OF
-- visibility trigger `claims_block_widening`) refuses `visibility = 'public'`
-- while a `claim_encryption` row exists for the claim (sec F11: a public
-- claim whose content is the seal sentinel is permanently unreadable). The
-- body was SECURITY INVOKER, so that EXISTS ran under the CALLER's row
-- security. `claim_encryption` is FORCEd under 077 section 5's policy, which
-- shows a row only to a session whose read set holds the row's `group_id`.
--
-- Measured as `epigraph_app` on a fresh database below this migration
-- (`epigraph-db/tests/sealed_claim_widening_definer.rs`): a session that
-- writes the claim's owner group but is not in the group the ciphertext is
-- keyed to saw no row, so the SEALED arm admitted, and arm (b)'s declassify
-- GUC is one any session can set. A raw `UPDATE claims SET visibility =
-- 'public'` moved the row and committed a PUBLIC sealed claim.
--
-- How a seal row comes to be keyed to a group other than its claim's owner:
-- 232 binds NEW application-role seal rows to the claim's owner group, but it
-- repairs no row written before it, and the maintenance role and definer
-- bodies bypass its policies. The shipped owner-moving paths (206/215's share
-- and publicize, the operator `regroup` and `restrict`) hold or refuse a
-- sealed claim, so they do not create the divergence today; this closes the
-- guard itself rather than relying on every writer.
--
-- 206's `epigraph_publicize_claims` is a definer already and classifies a
-- sealed claim `refused_sealed`; it is not affected.
--
-- ===================================================================
-- 1. THE CHANGE
-- ===================================================================
--
-- The trigger body becomes SECURITY DEFINER, owned by
-- `epigraph_maintenance`, on 172's form (`SET search_path = pg_catalog,
-- pg_temp`, every non-catalog object schema-qualified). That frame passes
-- 077's `epigraph_definer_bypass()` disjunct, so the EXISTS sees every
-- ciphertext row whatever the caller's groups. 212 reads the same table
-- through a maintenance-owned definer trigger for the same reason.
--
-- The body is 074's otherwise: the same two arms, the same RAISE texts and
-- SQLSTATE (42501), the same comments. Arm (b) reads the session GUC
-- `epigraph.allow_declassify`, which a definer frame does not change (pinned
-- by the test's non-regression check). The trigger is not re-created: its
-- name, timing, column list and table are 074's.
--
-- WHY NOT A CALLABLE HELPER. The backlog sketch named a SECURITY DEFINER
-- `claim_is_sealed(uuid)` boolean that the invoker trigger would call (193's
-- shape). The trigger runs as the caller, so the helper would need EXECUTE
-- granted to `epigraph_app`, and the application role could then ask "is
-- claim X sealed" of any id: a seal-existence oracle, the kind 232's header
-- declines to add. A trigger function cannot be called directly and firing
-- it needs no EXECUTE, so a definer trigger body adds no such surface.
-- EXECUTE stays revoked from PUBLIC (074).
--
-- Under READ COMMITTED the EXISTS is a fresh statement of a VOLATILE plpgsql
-- body, run after the claim row's lock is held, so 227's serialization
-- argument (a seal holding the row lock commits first, and this then sees
-- its ciphertext row) is unchanged.
--
-- COST: the function's `SET search_path` is applied and restored on each
-- fired row, as on every other pinned definer trigger (212). Only UPDATEs
-- that name `visibility` fire it.
--
-- REGISTERED in `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- `DEFERRED_DEFINER_FUNCTIONS` at 238: under a non-member, non-bypassing
-- owner its read is row-security filtered exactly as the caller's was, and it
-- fails OPEN (the defect above), so the owner is load-bearing.
--
-- ===================================================================
-- 2. RE-STATING A SHARED BODY, AND UNDO
-- ===================================================================
-- This re-states 074's body. A migration applied before this one that also
-- re-states `epigraph_claims_block_widening` would be silently reverted here,
-- so the GUARD below refuses unless the live body is exactly 074's (md5 of
-- `prosrc`). The migration that lands second must take the higher number,
-- re-state the MERGED body, and make its own undo restore the merged
-- predecessor. Undo: docs/runbooks/238-undo.sql (same guard, on this body).
--
-- Lock: CREATE OR REPLACE FUNCTION and ALTER FUNCTION take no lock on
-- `claims`; the timeout bounds the catalog locks only.

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE v_src text;
BEGIN
    SELECT md5(p.prosrc) INTO v_src FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_claims_block_widening()'::regprocedure;
    IF v_src IS DISTINCT FROM '7d9079127fe7ad6c7195047421e87c0e' THEN
        RAISE EXCEPTION '238: epigraph_claims_block_widening (prosrc md5 %) is not the body '
                        '238 builds on (074''s). A migration before 238 re-stated it; '
                        're-stating it here would revert that change. Re-state the MERGED '
                        'body in the later migration', v_src
              USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- (a) THE SEALED GUARD, UNCONDITIONAL AND WITH NO GUC OVERRIDE (sec F11).
    --     Seal-then-declassify would otherwise yield a PUBLIC row whose content
    --     is a '[sealed:uuid]' stub, embedding NULL, and ciphertext no reader is
    --     entitled to -- permanently unreadable, and with content_hash no longer
    --     agreeing with content. `epigraph.allow_declassify` does NOT reach this
    --     arm, by design: the admin declassification surface sets that GUC.
    --     238: read with definer rights, so a caller outside the ciphertext's
    --     group cannot pass it by not seeing the row.
    IF NEW.visibility = 'public'
       AND EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot be made '
                        'public. Unseal first, then declassify.', NEW.id
            USING ERRCODE = '42501';
    END IF;
    -- (b) Ordinary declassification guard.
    IF OLD.visibility = 'group' AND NEW.visibility = 'public'
       AND COALESCE(pg_catalog.current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to declassify claim % from group to '
                        'public. Use the admin declassification surface.', OLD.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_block_widening() FROM PUBLIC;

-- ===================================================================
-- 3. OWNERSHIP (074 section 6's guarded form)
-- ===================================================================
-- Guarded on the role: 060 creates it inside a DO block that only RAISE
-- NOTICEs on insufficient_privilege, and a hard failure here would turn a
-- missing role into a permanent deploy outage. Without the role the body
-- stays owned by the migration runner (a superuser on every deployment),
-- which also sees every ciphertext row.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_claims_block_widening() '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 238 trigger '
                     'body stays owned by the migration runner.';
    END IF;
END $$;
