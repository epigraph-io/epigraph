-- 212: a sealed row never carries a vector, enforced by the database
-- (backlog f78526ad; closes tenancy register entry
-- D-SEAL-vector-column-row-guard).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- A sealed claim's content is ciphertext (`claim_encryption`), and so is a
-- sealed evidence row's (`evidence_encryption`). A vector computed from the
-- plaintext is approximately invertible to it, so the seal nulls `embedding`
-- and `embedding_3072` in the same transaction that writes the encryption row,
-- and CLAUDE.md's `sealed_with_embedding` audit treats a non-zero count as a
-- page-the-on-call condition.
--
-- Until now that invariant was enforced statement by statement: every writer
-- of the four vector columns had to carry a `NOT EXISTS (… _encryption …)`
-- predicate. The register entry recorded what that costs: a writer added
-- without the predicate is caught only by review or, after the fact, by the
-- audit. Backlog f78526ad found four such writers (`routes/assess.rs`, the two
-- `PUT …/embedding` routes, `EmbeddingRepository::store`) plus an uncalled
-- `EvidenceRepository::store_embedding`; the same branch fixes or deletes all
-- of them. This migration is the structural half, so the next one is refused.
--
-- ===================================================================
-- 1. WHAT IT REFUSES, AND WHAT IT DOES NOT
-- ===================================================================
--
-- `BEFORE UPDATE OF embedding, embedding_3072` on `claims` and on `evidence`,
-- `WHEN (NEW.embedding IS NOT NULL OR NEW.embedding_3072 IS NOT NULL)`:
--
--   * refused (42501, the code 074's sealed-claim widening guard uses): an
--     UPDATE that names a vector column and leaves a non-NULL vector on a row
--     that has an encryption row. Keyed on the ROW's own ciphertext:
--     `claim_encryption.claim_id` for a claim, `evidence_encryption.evidence_id`
--     for evidence. Never on `visibility` (a group-private row is ordinary
--     plaintext and is embedded), and never on the evidence row's parent claim
--     (a seal covers only the evidence its claim's owner holds, so a sealed
--     claim can keep another group's plaintext evidence, whose vector is
--     legitimate; the same per-table key as `epigraph-cli reembed`).
--   * admitted: the seal's own `SET embedding = NULL, embedding_3072 = NULL`
--     (the WHEN clause is false), every UPDATE that names neither vector
--     column (the trigger does not fire), and an INSERT (a row cannot have an
--     encryption row before it exists: both encryption tables reference it).
--
-- `UPDATE OF` rather than every UPDATE, deliberately: a sealed row that still
-- carries a vector from before this migration (the audit's violation) must not
-- turn every unrelated UPDATE of that row (labels, truth value, supersession)
-- into an error. Such a row is refused only when a writer touches its vectors,
-- and the remedy for it is the seal's own nulling, which this admits. How many
-- exist is a deployment measurement (the audit query), not something this
-- file can know.
--
-- The writers that already carry the predicate
-- (`ClaimRepository::store_embedding`, `store_embedding_if_unsealed`,
-- `EvidenceRepository::store_embedding_as`, the `reembed` and backfill
-- selections) filter the row out before the trigger could see it, so they
-- answer "nothing stored" exactly as before. The trigger is a backstop under
-- them, not a replacement.
--
-- ===================================================================
-- 2. WHY SECURITY DEFINER
-- ===================================================================
--
-- Both encryption tables are FORCEd under 077 section 5's policy, which shows
-- a row only to a session whose groups include its `group_id`. An INVOKER body
-- would therefore see the encryption row only when the writing session happens
-- to be a member of the sealing group, and would admit the vector otherwise:
-- a guard that fails OPEN on exactly the sessions it is for. Owned by
-- `epigraph_maintenance`, the body is admitted by the policy's
-- `epigraph_definer_bypass()` disjunct and sees every encryption row. It is on
-- 172's form (`definer_search_path_ratchet.rs`): `SET search_path =
-- pg_catalog, pg_temp`, every `public` object qualified, EXECUTE revoked from
-- PUBLIC (a trigger function is not called directly, and firing needs no
-- EXECUTE). It reads one key column and returns NEW unchanged; it writes
-- nothing and keeps no session state.
--
-- Under READ COMMITTED the lookup is a fresh statement inside the trigger, run
-- after the row lock is held, so it sees a seal that committed while the
-- UPDATE waited on that lock. The repository writers' separate lock statement
-- (`store_embedding_if_unsealed`'s doc) remains the primary control for that
-- interleaving; this file asserts no more than the statement it adds.
--
-- Idempotent: CREATE OR REPLACE FUNCTION, DROP TRIGGER IF EXISTS before each
-- CREATE TRIGGER. Undo: docs/runbooks/212-undo.sql.

CREATE OR REPLACE FUNCTION public.epigraph_refuse_sealed_claim_vector()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.claim_encryption ce WHERE ce.claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot carry an embedding; '
                        'nothing was written', NEW.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refuse_sealed_claim_vector() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_refuse_sealed_evidence_vector()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.evidence_encryption ee WHERE ee.evidence_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: evidence % is SEALED and cannot carry an embedding; '
                        'nothing was written', NEW.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_refuse_sealed_evidence_vector() FROM PUBLIC;

DROP TRIGGER IF EXISTS claims_refuse_sealed_vector ON public.claims;
CREATE TRIGGER claims_refuse_sealed_vector
    BEFORE UPDATE OF embedding, embedding_3072 ON public.claims
    FOR EACH ROW
    WHEN (NEW.embedding IS NOT NULL OR NEW.embedding_3072 IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_refuse_sealed_claim_vector();

DROP TRIGGER IF EXISTS evidence_refuse_sealed_vector ON public.evidence;
CREATE TRIGGER evidence_refuse_sealed_vector
    BEFORE UPDATE OF embedding, embedding_3072 ON public.evidence
    FOR EACH ROW
    WHEN (NEW.embedding IS NOT NULL OR NEW.embedding_3072 IS NOT NULL)
    EXECUTE FUNCTION public.epigraph_refuse_sealed_evidence_vector();

-- ===================================================================
-- 3. OWNERSHIP (074 section 6's guarded form)
-- ===================================================================
-- Guarded on the role: 060 creates it inside a DO block that only RAISE
-- NOTICEs on insufficient_privilege, and a hard failure here would turn a
-- missing role into a permanent deploy outage. Without the role the bodies
-- stay owned by the migration runner (a superuser on every deployment), which
-- also sees every encryption row.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_refuse_sealed_claim_vector() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_refuse_sealed_evidence_vector() '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 212 trigger '
                     'bodies stay owned by the migration runner.';
    END IF;
END $$;
