-- ===================================================================
-- 238-undo.sql: take migration 238 (074's sealed-claim widening guard reads
-- `claim_encryption` with definer rights) back out, in ONE transaction, on
-- the migration (superuser) DSN.
--
-- WHAT IT DOES:
--   * re-states 074's `epigraph_claims_block_widening()` body byte for byte
--     (238 re-stated it SECURITY DEFINER with a pinned search_path and two
--     schema qualifications). `CREATE OR REPLACE` without SECURITY DEFINER or
--     a SET clause resets the function to SECURITY INVOKER with no
--     `proconfig`; it keeps the owner and ACL, so:
--   * hands the function back to CURRENT_USER, the migration runner that
--     owned it below 238 (run this as that role). The ACL follows the owner:
--     EXECUTE stays revoked from PUBLIC.
--   * refuses (55000) unless the live body is 238's or already 074's, so it
--     never reverts a later migration's re-statement of the function.
--
-- WHAT IT LEAVES:
--   * every claim and `claim_encryption` row as it stands;
--   * the trigger `claims_block_widening` (238 did not touch it);
--   * 238's `_sqlx_migrations` row. Re-introducing the definer read is a NEW
--     migration, never a re-run of 238.
--
-- WHAT COMES BACK: the fail-open guard 238 closed. A session that writes a
-- sealed claim's owner group but cannot see its ciphertext row (a seal row
-- keyed to another group) can again make the claim public with a raw UPDATE
-- and the self-settable declassify GUC.
-- Check for the state that leaves (expected 0):
--   SELECT count(*) FROM public.claims c
--    WHERE c.visibility = 'public'
--      AND EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = c.id);
--
-- No binary depends on 238, so there is no rollout order.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE v_src text;
BEGIN
    SELECT md5(p.prosrc) INTO v_src FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_claims_block_widening()'::regprocedure;
    -- 238's body, or 074's (a second run).
    IF v_src IS DISTINCT FROM '48728cf66ad07a7cae2d96a5f0577f5d'
       AND v_src IS DISTINCT FROM '7d9079127fe7ad6c7195047421e87c0e' THEN
        RAISE EXCEPTION '238-undo: epigraph_claims_block_widening (prosrc md5 %) is neither '
                        '238''s body nor 074''s. A later migration re-stated it; undo that '
                        'one first', v_src
              USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- (a) THE SEALED GUARD, UNCONDITIONAL AND WITH NO GUC OVERRIDE (sec F11).
    --     Seal-then-declassify would otherwise yield a PUBLIC row whose content
    --     is a '[sealed:uuid]' stub, embedding NULL, and ciphertext no reader is
    --     entitled to -- permanently unreadable, and with content_hash no longer
    --     agreeing with content. `epigraph.allow_declassify` does NOT reach this
    --     arm, by design: the admin declassification surface sets that GUC.
    IF NEW.visibility = 'public'
       AND EXISTS (SELECT 1 FROM public.claim_encryption WHERE claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot be made '
                        'public. Unseal first, then declassify.', NEW.id
            USING ERRCODE = '42501';
    END IF;
    -- (b) Ordinary declassification guard.
    IF OLD.visibility = 'group' AND NEW.visibility = 'public'
       AND COALESCE(current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to declassify claim % from group to '
                        'public. Use the admin declassification surface.', OLD.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
ALTER FUNCTION public.epigraph_claims_block_widening() OWNER TO CURRENT_USER;

COMMIT;
