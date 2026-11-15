-- ===================================================================
-- 227-undo.sql: take migration 227 (the seal trigger locks the claim row it
-- reads) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES:
--   * re-states 176's `epigraph_no_public_sealed()` body byte for byte (227
--     re-stated it with `FOR NO KEY UPDATE OF c` and an unlocked fallback
--     read); `CREATE OR REPLACE` keeps its owner, ACL and SECURITY INVOKER.
--   * refuses (55000) unless the live body is 227's or already 176's, so it
--     never reverts a later migration's re-statement of the function.
--
-- WHAT IT LEAVES:
--   * every claim and `claim_encryption` row as it stands;
--   * 227's `_sqlx_migrations` row. Re-introducing the lock is a NEW
--     migration, never a re-run of 227.
--
-- WHAT COMES BACK: the race 227 closed. A seal and a publicize of the same
-- claim that overlap can again both commit, leaving a public claim whose
-- content is the seal sentinel. After running this, nothing but the order of
-- the routes (restrict, then seal) keeps that from happening.
-- Check for the state the race leaves (expected 0):
--   SELECT count(*) FROM public.claims c
--    WHERE c.visibility = 'public'
--      AND EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = c.id);
--
-- No binary depends on 227, so there is no rollout order.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE v_src text;
BEGIN
    SELECT md5(p.prosrc) INTO v_src FROM pg_catalog.pg_proc p
     WHERE p.oid = 'public.epigraph_no_public_sealed()'::regprocedure;
    -- 227's body, or 176's (a second run).
    IF v_src IS DISTINCT FROM '706d3eda9209cccb7f6fe7134cc3d686'
       AND v_src IS DISTINCT FROM '0f48e208547eb393e1d4b5565f32571a' THEN
        RAISE EXCEPTION '227-undo: epigraph_no_public_sealed (prosrc md5 %) is neither 227''s '
                        'body nor 176''s. A later migration re-stated it; undo that one first',
                        v_src
              USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_no_public_sealed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    SELECT c.visibility INTO v FROM public.claims c WHERE c.id = NEW.claim_id;
    IF v = 'public' THEN
        RAISE EXCEPTION 'PRV01: privatization: refusing to seal claim % while it is '
                        'visibility=public. Restrict first, then seal.', NEW.claim_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

COMMIT;
