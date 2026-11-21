-- 233: bind a `claim_version_encryption`, `evidence_encryption` or
-- `edge_encryption` row to the owner group of the row it seals
-- (backlog candidate B102-other-encryption-tables, to be filed).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 077 section 5 gives each of the four ciphertext tables one `FOR ALL`
-- policy, `<table>_tenancy`, whose WITH CHECK is
-- `group_id = ANY (epigraph_writable_groups())`. It checks the SEALING group
-- and never the sealed row. 232 binds `claim_encryption` to its claim's
-- owner; the other three tables keep 077's check. Measured as `epigraph_app`
-- on a fresh database below this migration
-- (`epigraph-db/tests/sealed_row_encryption_write_scope.rs`), a session that
-- writes group A was admitted, on each of the three tables, to:
--
--   * seal a claim version, evidence row or edge of group B that it cannot
--     read, under A (the FK check ignores row security);
--   * seal such a row of B that it reads but cannot write, under A;
--   * seal such a row of B under A's key while writing both groups, so B's
--     other members hold no share of the key;
--   * UPDATE an own seal row's key column onto B's row, or its `group_id` to
--     another writable group.
--
-- Each table is keyed by the sealed row's id (060), so such a row squats on
-- it: the owner's privatization seal (`INSERT … ON CONFLICT (<id>) DO
-- NOTHING`, then blank the plaintext, in `seal_claims_conn`) writes no
-- ciphertext under the owner's key, and the owner's sessions cannot see the
-- row (077's USING is the sealing group's read set) to remove it.
--
-- `claim_version_encryption` also carries `claim_id`, which nothing tied to
-- the version's own claim: an own version's seal could name another group's
-- claim, which the row then follows on `ON DELETE CASCADE` and which the
-- operator tools (`reown_workflows`, `regroup`) read as "this claim has a
-- sealed version".
--
-- No shipped application-role code writes these tables. The privatization
-- seal and unseal (`seal_claims_conn`, `unseal_claims_conn`) run on a
-- maintenance connection, and `EvidenceEncryptionRepository::insert` and
-- `EdgeEncryptionRepository::insert` have no caller; no shipped code UPDATEs
-- any of the three (grep of crates/*/src at the time of writing). This makes
-- the binding an invariant of the database before an application writer
-- exists.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
-- Per table, two RESTRICTIVE policies, `TO PUBLIC`, with 077's two bypass
-- disjuncts (115 section 8's shape, and 232's):
--
--   * `<table>_owner_scope_insert` FOR INSERT, WITH CHECK;
--   * `<table>_owner_scope_update` FOR UPDATE, the same predicate in USING
--     (the row before) and WITH CHECK (the row after).
--
-- The predicate: the sealed row exists and its `owner_group_id` IS the seal
-- row's `group_id`:
--
--   * `claim_version_encryption`: the `claim_versions` row by
--     `claim_version_id`, which must also belong to the seal row's
--     `claim_id`. A version's tenancy is its claim's (070 arm (c) stamps it on
--     INSERT, arm (d) re-stamps it with the claim; `claim_versions` is not one
--     of 114's writer-owned tables), so this is the claim's owner too, which is
--     the group `seal_claims_conn` seals a version under.
--   * `evidence_encryption`: the `evidence` row by `evidence_id`. The
--     privatization seal covers only evidence whose owner is the claim's owner
--     (`SEAL_EVIDENCE_OWNER_PREDICATE`), sealed under that group, so this is
--     the group it writes.
--   * `edge_encryption`: the `edges` row by `edge_id`, its `owner_group_id`
--     only. A co-owned edge (072) is sealable under its owner group and not
--     under its co-owner; `edge_encryption` has no writer today, so this is
--     the narrow choice until one defines co-owned sealing.
--
-- 077's permissive policy still requires that group to be in the session's
-- writable set, so together: the sealed row's owner group is a group the
-- session writes, and the seal is under that group's key.
--
-- The owning-table read is the CALLER's (no SECURITY DEFINER helper: one the
-- application role could EXECUTE would be an owner oracle). A row the caller
-- cannot see is therefore refused, which is the safe direction; a row owned
-- by a group the caller writes is readable to it. No policy on
-- `claim_versions`, `evidence` or `edges` reads a ciphertext table, so there
-- is no policy recursion (measured by the admitted controls in the test
-- above).
--
-- The maintenance role and SECURITY DEFINER bodies keep 077's bypass, as on
-- every other policy of these tables. Measured: a NOLOGIN role that is only a
-- member of `epigraph_maintenance` (not a superuser, not BYPASSRLS) runs the
-- real `seal_claims_conn` through 233 and its version and evidence rows land
-- (`a_non_superuser_maintenance_member_still_seals_at_233`). This file
-- applies whether or not 232 is present: it names no `claim_encryption`
-- object.
--
-- No function body is re-stated, so there is no md5 guard. No table,
-- column, function, trigger, index or grant changes. 115's
-- `<table>_delete_writer` and 126's restrictive `<table>_elevated_no_*`
-- refusals are unchanged; these policies' names avoid `_elevated_` and name
-- no elevation helper, so the elevation census does not count them.
--
-- ===================================================================
-- 2. UNDO
-- ===================================================================
--
-- `docs/runbooks/233-undo.sql` drops exactly these six policies.

SET LOCAL lock_timeout = '3s';

-- claim_version_encryption ------------------------------------------

DROP POLICY IF EXISTS claim_version_encryption_owner_scope_insert
    ON public.claim_version_encryption;
CREATE POLICY claim_version_encryption_owner_scope_insert
    ON public.claim_version_encryption
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claim_versions v
                    WHERE v.id = claim_version_encryption.claim_version_id
                      AND v.claim_id = claim_version_encryption.claim_id
                      AND v.owner_group_id = claim_version_encryption.group_id));

DROP POLICY IF EXISTS claim_version_encryption_owner_scope_update
    ON public.claim_version_encryption;
CREATE POLICY claim_version_encryption_owner_scope_update
    ON public.claim_version_encryption
    AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claim_versions v
                    WHERE v.id = claim_version_encryption.claim_version_id
                      AND v.claim_id = claim_version_encryption.claim_id
                      AND v.owner_group_id = claim_version_encryption.group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claim_versions v
                    WHERE v.id = claim_version_encryption.claim_version_id
                      AND v.claim_id = claim_version_encryption.claim_id
                      AND v.owner_group_id = claim_version_encryption.group_id));

-- evidence_encryption -----------------------------------------------

DROP POLICY IF EXISTS evidence_encryption_owner_scope_insert
    ON public.evidence_encryption;
CREATE POLICY evidence_encryption_owner_scope_insert
    ON public.evidence_encryption
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.evidence e
                    WHERE e.id = evidence_encryption.evidence_id
                      AND e.owner_group_id = evidence_encryption.group_id));

DROP POLICY IF EXISTS evidence_encryption_owner_scope_update
    ON public.evidence_encryption;
CREATE POLICY evidence_encryption_owner_scope_update
    ON public.evidence_encryption
    AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.evidence e
                    WHERE e.id = evidence_encryption.evidence_id
                      AND e.owner_group_id = evidence_encryption.group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.evidence e
                    WHERE e.id = evidence_encryption.evidence_id
                      AND e.owner_group_id = evidence_encryption.group_id));

-- edge_encryption ---------------------------------------------------

DROP POLICY IF EXISTS edge_encryption_owner_scope_insert
    ON public.edge_encryption;
CREATE POLICY edge_encryption_owner_scope_insert
    ON public.edge_encryption
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = edge_encryption.edge_id
                      AND e.owner_group_id = edge_encryption.group_id));

DROP POLICY IF EXISTS edge_encryption_owner_scope_update
    ON public.edge_encryption;
CREATE POLICY edge_encryption_owner_scope_update
    ON public.edge_encryption
    AS RESTRICTIVE FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = edge_encryption.edge_id
                      AND e.owner_group_id = edge_encryption.group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.edges e
                    WHERE e.id = edge_encryption.edge_id
                      AND e.owner_group_id = edge_encryption.group_id));
