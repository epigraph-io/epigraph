-- 075_validate_tenancy_claims.sql -- VALIDATE the tenancy constraints on
-- `claims`, and on `claims` ONLY.
-- PR-16 of the multi-user tenancy series. Number per migrations/README.md.
--
-- WHY THIS IS A FILE OF ITS OWN (ops F16). `VALIDATE CONSTRAINT` takes
-- SHARE UPDATE EXCLUSIVE and performs a FULL SCAN of the table. `claims` is by
-- far the largest tier-A relation, so validating it in the same transaction as
-- the other 25 tables would hold that lock -- blocking autovacuum on `claims`
-- and pinning the xmin horizon -- for the sum of every scan rather than for
-- one. 075 and 076 are two deploy steps on purpose. Do not merge them.
--
-- THE PRE-FLIGHT GUARD IS NOT IN THIS FILE, ALSO ON PURPOSE. An earlier plan
-- revision put three count(*) queries in the same transaction as the VALIDATEs.
-- The guard's `count(*) FROM claims WHERE owner_group_id = <world>` is a full
-- seq scan (idx_claims_owner_group is partial `WHERE visibility <> 'public'`
-- and every world-owned row is public, so that index is structurally unusable
-- for it), which doubles the lock hold for no added safety. The guard is
-- `epigraph-tenancy-backfill verify`'s exit code, run as a deploy step BEFORE
-- this file. See docs/runbooks/.
--
-- Idempotent: VALIDATE CONSTRAINT on an already-validated constraint is a
-- no-op, and the catalog guard below skips a constraint that does not exist
-- (a database provisioned by scripts/prepare-engine-integration-db.sh, or one
-- where 062 was partially applied).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE c text;
BEGIN
    FOREACH c IN ARRAY ARRAY[
        'claims_visibility_check',
        'claims_owner_group_fkey',
        'claims_group_needs_real_group'] LOOP
        IF EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.claims'::regclass
                      AND conname = c
                      AND NOT convalidated) THEN
            EXECUTE format('ALTER TABLE public.claims VALIDATE CONSTRAINT %I', c);
        END IF;
    END LOOP;
END $$;
