-- 093_claims_block_ownership_transfer.sql
-- Extend migration 074's `claims_block_widening` to ownership transfer: a
-- group-private claim may not change `owner_group_id` unless the session has
-- armed `epigraph.allow_declassify`, and a SEALED one may not change it at all.
--
-- Recorded as `D-PR16-ownership-transfer-is-unguarded` (COMPLETION-PLAN 3.2).
-- Version 093 is claimed from the reserved tenancy block 092-099 that the
-- operator authorized on 2026-09-15; `migrations/README.md` records the claim
-- in the SAME commit as this file. `074_tenancy_required.sql` is APPLIED and
-- therefore FROZEN: editing it changes its `_sqlx_migrations` checksum and the
-- next `sqlx migrate run` refuses to start, so the widening lands here.
--
-- Kept at mechanism level, deliberately: this repository is public.
--
-- ===================================================================
-- 1. THE GAP 074 LEFT
--
-- 074 armed the guard `BEFORE UPDATE OF visibility`, with two arms: (a) a
-- sealed claim never becomes public, and (b) group -> public needs the
-- declassification GUC. Neither arm reads `owner_group_id`, and a statement
-- that assigns only `owner_group_id` does not fire the trigger at all. So
-- `UPDATE claims SET owner_group_id = <B> WHERE id = <a claim private to A>`
-- was admitted on every connection. It changes who can read the claim as
-- surely as flipping `visibility` does: A's members lose it, B's members gain
-- it, and 070 arm (d) then propagates the new owner to all 17 derived tables
-- and to the edges meet in the same transaction.
--
-- RLS is no backstop. 077's `claims_tenancy` WITH CHECK admits the new row
-- whenever the writer may write to B, and it constrains WHICH row a statement
-- may touch rather than WHAT value it assigns. A maintenance or bypass
-- connection, which the privatization apply runs on, is not subject to it at
-- all.
--
-- THE REGISTER'S "UNREACHABLE" WAS WRONG WHEN IT WAS WRITTEN. The 2026-09-14
-- disposition found `privatization.rs::restrict_claims_conn` assigning
-- `owner_group_id` and set it aside because "migration 074's guard fires on
-- it". The guard FIRED, because the statement names `visibility`; no arm of it
-- REFUSED a group -> group move. `restrict_claims_conn` moved any frozen row
-- whose owner differed from the plan's target, and the selection closure it
-- consumes is walked under a bypass viewer with no visibility filter, so a row
-- private to an unrelated group could be re-owned into the target group. The
-- same commit fixes that caller; this file is the database half.
--
-- ===================================================================
-- 2. WHY A COLUMN LIST HERE, WHEN 081 ARGUES AGAINST ONE
--
-- 081 armed its privatization-plan guards UNQUALIFIED because their predicate
-- read a column (`created_by`) that was not in the `UPDATE OF` list, so the
-- guarded end state was reachable by a statement that named only that column.
-- The lesson is "the list must cover every column the predicate governs", not
-- "never use a list". This guard governs exactly `visibility` and
-- `owner_group_id`, and both are in the list, so no statement can reach a
-- governed change without naming a listed column.
--
-- The one way round a column list is a BEFORE UPDATE trigger that rewrites a
-- listed column, because PostgreSQL decides column-specific firing from the
-- statement's SET list, not from the final row. The only other BEFORE UPDATE
-- trigger on `claims` is `claims_updated_at`, which writes `updated_at` alone.
-- A future trigger that rewrites `visibility` or `owner_group_id` must re-arm
-- this one unqualified.
--
-- An unqualified trigger would also cost something here that it does not cost
-- 081. Arm (a) probes `claim_encryption`, and `claims` takes far more UPDATEs
-- than `privatization_plans` does: embedding backfill, belief recomputes and
-- `is_current` flips would all pay for that probe on every row.
--
-- The body still compares values with `IS DISTINCT FROM` rather than trusting
-- the firing condition. `UPDATE ... SET owner_group_id = owner_group_id` fires
-- the trigger and must be admitted.
--
-- ===================================================================
-- 3. WHY THE DECLASSIFICATION GUC, AND WHAT THAT DOES TO ITS MEANING
--
-- `epigraph.allow_declassify` is re-used rather than a second GUC being added.
-- Its one production setter is `PrivatizationRepository::restore_claims_conn`,
-- the privatization revert, which already restores `owner_group_id` together
-- with `visibility` from the pre-image the freeze recorded, and only on rows
-- that still carry this plan's own stamp. A second GUC would have to be set on
-- exactly that path and nowhere else, so it would add a name without adding a
-- boundary. The consequence is stated rather than left to be inferred: from
-- this migration on, arming `epigraph.allow_declassify` authorizes an OWNERSHIP
-- TRANSFER of a group-private claim as well as its declassification. `docs/
-- tenancy.md` says the same, and it repeats that this GUC is an interlock
-- against an ACCIDENTAL move and not an authorization boundary: it is
-- PGC_USERSET and any session can set it.
--
-- ===================================================================
-- 4. WHAT IS STILL ADMITTED, AND WHY
--
--   * public -> group, any owner. Privatization's restrict step. Narrowing.
--   * public -> public with a new owner. `tenancy_backfill` moves WORLD-owned
--     public rows to their author's personal group this way. The row is
--     readable by everyone before and after, so no reader gains or loses it.
--   * group -> public with the GUC, owner changing or not. That is 074 arm (b)'s
--     declassification, and it re-owns to the WORLD sentinel as a matter of
--     course.
--   * Any statement that names neither governed column. The trigger does not
--     fire.
--
-- A SEALED group-private claim may not change owner even WITH the GUC. Its
-- ciphertext is bound to the owning group's key epoch through
-- `claim_encryption.group_id`, so a new owner's members still could not read
-- it and the old owner's members would lose it: a row nobody can read, which
-- is the same outcome arm (a) exists to prevent. Arm (a) carries no GUC
-- override for that reason, and neither does this sub-arm. No production path
-- needs one. A seal-mode revert is refused until every item is unsealed, and
-- `restore_claims_conn` only moves rows this plan itself moved out of `public`.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- (a) THE SEALED GUARD, UNCONDITIONAL AND WITH NO GUC OVERRIDE (sec F11).
    --     Verbatim from 074.
    IF NEW.visibility = 'public'
       AND EXISTS (SELECT 1 FROM public.claim_encryption WHERE claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot be made '
                        'public. Unseal first, then declassify.', NEW.id
            USING ERRCODE = '42501';
    END IF;
    -- (b) Ordinary declassification guard. Verbatim from 074.
    IF OLD.visibility = 'group' AND NEW.visibility = 'public'
       AND COALESCE(current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to declassify claim % from group to '
                        'public. Use the admin declassification surface.', OLD.id
            USING ERRCODE = '42501';
    END IF;
    -- (c) OWNERSHIP TRANSFER of a group-private claim (093). Moving a private
    --     row from one group to another changes who can read it just as
    --     declassifying it does. See this file's header, sections 3 and 4.
    IF OLD.visibility = 'group'
       AND NEW.owner_group_id IS DISTINCT FROM OLD.owner_group_id THEN
        -- (c.1) Sealed: no GUC override, for arm (a)'s reason.
        IF EXISTS (SELECT 1 FROM public.claim_encryption WHERE claim_id = OLD.id) THEN
            RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED under its owning '
                            'group''s key and cannot change owner. Unseal first.', OLD.id
                USING ERRCODE = '42501';
        END IF;
        -- (c.2) Otherwise, only behind the admin surface's GUC.
        IF COALESCE(current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
            RAISE EXCEPTION 'epigraph tenancy: refusing to move group-private claim % '
                            'from group % to group %. Ownership transfer is an audited '
                            'operation.', OLD.id, OLD.owner_group_id, NEW.owner_group_id
                USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_block_widening() FROM PUBLIC;

DROP TRIGGER IF EXISTS claims_block_widening ON public.claims;
CREATE TRIGGER claims_block_widening
    BEFORE UPDATE OF visibility, owner_group_id ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_block_widening();

-- ===================================================================
-- UNDO. No runbook ships, on the same ground as 089, 090 and 092: reversing
-- this file is two statements and it creates no rows. Re-issue 074 section 4's
-- `CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening()` (arms
-- (a) and (b) only), then
--   DROP TRIGGER IF EXISTS claims_block_widening ON public.claims;
--   CREATE TRIGGER claims_block_widening BEFORE UPDATE OF visibility
--       ON public.claims FOR EACH ROW
--       EXECUTE FUNCTION public.epigraph_claims_block_widening();
-- Undoing it re-opens D-PR16-ownership-transfer-is-unguarded. The caller-side
-- filter in `restrict_claims_conn` does not depend on this file and stays.
--
-- `docs/runbooks/074-undo.sql` drops the trigger and the function by name, so
-- running it after this file removes 093's arm too. Its own warning about
-- losing the sealed guard applies to this arm as well.
-- ===================================================================
