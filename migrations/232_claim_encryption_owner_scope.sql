-- 232: bind a `claim_encryption` row to its claim's owner group
-- (backlog candidate B90-claim-encryption-write-scope, to be filed).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 077 section 5 gives `claim_encryption` one `FOR ALL` policy,
-- `claim_encryption_tenancy`, whose WITH CHECK is
-- `group_id = ANY (epigraph_writable_groups())`. It checks the SEALING group
-- and never the claim. Measured as `epigraph_app` on a fresh database at 229
-- (`epigraph-db/tests/claim_encryption_write_scope.rs`), a session that
-- writes group A was admitted to:
--
--   * seal a group-private claim of group B that it cannot read, under A
--     (081/176/227's PRV01 trigger reads no row and admits; the FK check
--     ignores row security);
--   * seal a claim of B that it reads but cannot write, under A;
--   * seal a claim of B under A's key while writing both groups, so B's
--     other members hold no share of the key;
--   * UPDATE an own seal row's `claim_id` onto B's claim, or its `group_id`
--     to another writable group.
--
-- `claim_encryption` is keyed by `claim_id` (060), so such a row squats on
-- the claim: the owner's seal (`INSERT … ON CONFLICT (claim_id) DO NOTHING`,
-- the redeliverable form `seal_claims_conn` uses) then writes nothing, and
-- the owner's sessions cannot see the row (077's USING is the sealing
-- group's read set) to remove it.
--
-- The shipped application writer, `POST /claims` with
-- `privacy_tier = 'fully_private'`, already stamps the claim's
-- `owner_group_id` from the same `group_id` it seals under, so it never
-- writes such a row. This makes that an invariant of the database rather
-- than of one route.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
-- Two RESTRICTIVE policies, the shape 115 section 8 used for the DELETE side
-- of the same four tables, `TO PUBLIC`, with 077's two bypass disjuncts:
--
--   * `claim_encryption_owner_scope_insert` FOR INSERT, WITH CHECK;
--   * `claim_encryption_owner_scope_update` FOR UPDATE, the same predicate
--     in USING (the row before) and WITH CHECK (the row after).
--
-- The predicate: the claim exists and its `owner_group_id` IS the row's
-- `group_id`. 077's permissive policy still requires that group to be in
-- the session's writable set, so together: the claim's owner group is a
-- group the session writes, and the seal is under that group's key. This is
-- tighter than "the owner group is writable" alone, which would still admit
-- the third case above.
--
-- The `claims` read is the CALLER's (no SECURITY DEFINER helper: one the
-- application role could EXECUTE would be a claim-owner oracle). A claim the
-- caller cannot see is therefore refused, which is the safe direction; a
-- claim owned by a group the caller writes is always readable to it. No
-- `claims` policy reads `claim_encryption`, so there is no policy recursion
-- (measured by the admitted controls in the test above).
--
-- The maintenance role and SECURITY DEFINER bodies keep 077's bypass, as on
-- every other policy of these tables. The privatization seal and unseal
-- (`seal_claims_conn`, `unseal_claims_conn`) run on a maintenance
-- connection, which this does not touch, and no shipped code UPDATEs
-- `claim_encryption` (grep of crates/*/src at the time of writing).
--
-- No function body is re-stated, so there is no md5 guard. No table,
-- column, function, trigger, index or grant changes. 126's restrictive
-- `claim_encryption_elevated_no_*` refusals are unchanged; these policies'
-- names avoid `_elevated_` and name no elevation helper, so the elevation
-- census does not count them.
--
-- NOT COVERED, and the same shape: `claim_version_encryption`,
-- `evidence_encryption` and `edge_encryption` keep 077's `group_id`-only
-- WITH CHECK. Each is a separate follow-up.
--
-- ===================================================================
-- 2. UNDO
-- ===================================================================
--
-- `docs/runbooks/232-undo.sql` drops exactly these two policies.

SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS claim_encryption_owner_scope_insert ON public.claim_encryption;
CREATE POLICY claim_encryption_owner_scope_insert ON public.claim_encryption
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claims c
                    WHERE c.id = claim_encryption.claim_id
                      AND c.owner_group_id = claim_encryption.group_id));

DROP POLICY IF EXISTS claim_encryption_owner_scope_update ON public.claim_encryption;
CREATE POLICY claim_encryption_owner_scope_update ON public.claim_encryption
    AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claims c
                    WHERE c.id = claim_encryption.claim_id
                      AND c.owner_group_id = claim_encryption.group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claims c
                    WHERE c.id = claim_encryption.claim_id
                      AND c.owner_group_id = claim_encryption.group_id));
