-- ===================================================================
-- 084 — retire the legacy `ownership` table. ONE-WAY DOOR.
--
-- Version 084 per `migrations/README.md`, which is authoritative.
-- THE PLAN CARRIES THREE DIFFERENT NUMBERS FOR THIS FILE. `FINAL-PLAN.md` 7's
-- PR-22 section and 3's one-way-door list say 080 ("080_retire_ownership.sql",
-- `docs/runbooks/080-undo.sql`); 3.1's table row says
-- `| 081 | 080 | PR-22 | retire ownership |` under `| Shipped | (Planned) | ...`,
-- and the paragraph above that table declares the Shipped column authoritative
-- and separately notes the rename `080-undo.sql -> 081-undo.sql`. All three are
-- pre-shift. README's "Why 060-085 became 060-090" documents the +4 and is
-- authoritative over the plan; 080 is PR-18a's `privatization_plans`, applied
-- and frozen. The undo script for this file is `docs/runbooks/084-undo.sql`.
--
-- WHAT THE TABLE WAS. `ownership(node_id, node_type, partition_type, owner_id,
-- ...)` was the pre-tenancy partition model: one row per node, naming an agent
-- and a coarse partition. Migration 062 replaced it with per-table
-- `(visibility, owner_group_id)` columns; migration 071 installed a write-
-- through shim so any surviving writer transcribed into those columns and left
-- a row in `tenancy_transcription_log`; PR-14 deleted the HTTP route and the
-- three MCP tools that wrote it. Nothing in production writes it any more, and
-- this file removes the relation itself.
--
-- ORDERING. The two pre-flights run BEFORE anything is dropped, and they are
-- what makes the drop safe rather than merely final:
--
--   (1) the `encryption_key_id` quarantine view must be EMPTY. A non-empty
--       quarantine is an operator action item, not a condition to code around:
--       those rows name an encryption key that no longer resolves, and dropping
--       them destroys the only record that they were ever quarantined.
--   (2) every non-public row must already appear in `tenancy_transcription_log`
--       WITH A LEDGER ENTRY THAT RECORDS THE PARTITION THE ROW CURRENTLY HOLDS.
--       An untranscribed non-public row is a declaration that never reached a
--       visibility column, so dropping it would silently widen that node.
--       `migrations/062_tenancy_columns.sql` states this contract from the
--       other side: "Migration 084 REFUSES to DROP TABLE ownership unless every
--       non-public ownership row has a row here."
--
--       PRESENCE ALONE IS NOT ENOUGH, AND THE CONJUNCT ON `from_partition` IS
--       WHY. `tenancy_transcription_log` is `node_id PRIMARY KEY` and 071's
--       trigger writes it `ON CONFLICT (node_id) DO UPDATE SET from_partition =
--       EXCLUDED.from_partition`, so it holds only the MOST RECENT firing -- and
--       it is written for every `partition_type`, `public` included. A bare
--       `NOT EXISTS (... l.node_id = o.node_id)` is therefore satisfied by a
--       ledger row recording an OLDER partition: a node last transcribed while
--       it was public, then moved to a non-public partition without the trigger
--       firing, has a ledger row and a claim still stamped public. Dropping it
--       destroys the non-public declaration and leaves the node wide -- exactly
--       the harm this guard exists to prevent, on a one-way door. Requiring
--       `l.from_partition = o.partition_type` refuses precisely that state and
--       nothing else: `from_partition` is `text NOT NULL` (062) and the trigger
--       is its only writer, so on any database where the trigger saw the row in
--       its current state the two agree. `epigraph-tenancy-backfill run` is what
--       makes them agree -- its transcription pass re-fired the trigger with
--       `UPDATE ownership SET owner_id = owner_id`, which stamps
--       `from_partition = NEW.partition_type`. Any database that satisfies
--       `docs/deploy.md` steps 1-2 satisfies this guard.
--
--       WHAT THIS GUARD DOES NOT DO. `verify` carried a SECOND `ownership`
--       check -- a non-public row whose claim is still `visibility = 'public'`
--       -- and that check is NOT reproduced here, deliberately. As a third
--       pre-flight it would false-positive on a legitimate declassification,
--       which leaves a stale non-public `ownership` row behind by design. It is
--       discharged by deploy ORDER instead (`docs/deploy.md` steps 1-2), not by
--       this migration. An operator who skips step 2 loses a check that used to
--       exist.
--
-- Both RAISE EXCEPTION. A migration that logs and proceeds converts a data-loss
-- guard into a log line, which is the failure mode this file exists to avoid.
-- The blocks are delimited by the `-- >>> PRE-FLIGHT n` / `-- <<< PRE-FLIGHT n`
-- sentinels below so `crates/epigraph-db/tests/retire_ownership_preflight.rs`
-- can execute each one in isolation against a manufactured failing state --
-- once this file has applied there is no `ownership` table left to seed, so a
-- whole-file replay could not exercise either guard.
--
-- NO CASCADE, DELIBERATELY. `ownership_key_id_quarantine` is a VIEW over
-- `ownership` (migration 068). `DROP TABLE ownership CASCADE` would take it as
-- collateral -- destroying the very object pre-flight (1) inspects, so a later
-- reader could not tell whether the check had ever passed. The view is dropped
-- explicitly, after the pre-flights, in its own statement.
--
-- WHAT `DROP TABLE` TAKES WITH IT, AND WHAT IT DOES NOT. It drops
-- `ownership_pkey`, the four `idx_ownership_*` indexes, the six CHECK/FK
-- constraints, and both triggers (`ownership_updated_at` from 001,
-- `ownership_transcribe` from 071). It does NOT drop
-- `public.epigraph_ownership_transcribe()`, the SECURITY DEFINER body 071
-- installed behind that trigger. That function is dropped here too, explicitly:
-- a definer body that outlives the relation it guarded is exactly the shape
-- this series has been closing, and leaving it would keep a maintenance-owned
-- privilege escalation surface alive for no caller.
--
-- ONE-WAY DOOR. `migrations/` contains zero `.down.sql` files; there is no
-- `sqlx migrate revert` in this tree. `docs/runbooks/084-undo.sql` recreates the
-- empty shape and states precisely which columns are recoverable from
-- `tenancy_transcription_log` and which are gone. It does not bring the rows
-- back.
--
-- 070-undo. `docs/runbooks/070-undo.sql` drops `ownership_transcribe` ON
-- `public.ownership`; its `IF EXISTS` guards the trigger, not the table, so it
-- would raise 42P01 once this file has run. That script has been given an
-- explicit table-existence guard in the same change.
--
-- Transactional on purpose: no `-- no-transaction` header. Nothing here is
-- CONCURRENTLY, and `SET LOCAL lock_timeout` is only meaningful inside a
-- transaction block.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- >>> PRE-FLIGHT 1
DO $$
DECLARE n bigint;
BEGIN
    SELECT count(*) INTO n FROM public.ownership_key_id_quarantine;
    IF n > 0 THEN
        RAISE EXCEPTION
            'refusing to DROP ownership: % quarantined encryption_key_id row(s) are untriaged', n
            USING HINT = 'Resolve them first; SELECT * FROM public.ownership_key_id_quarantine.';
    END IF;
END $$;
-- <<< PRE-FLIGHT 1

-- >>> PRE-FLIGHT 2
DO $$
DECLARE n bigint;
BEGIN
    -- `epigraph-tenancy-backfill verify`'s `unlogged` check, STRENGTHENED by the
    -- `from_partition` conjunct. That check is retired in this change because
    -- this block supersedes it: the gate moves from a binary an operator has to
    -- remember to run into the migration that does the destructive thing. See
    -- "PRESENCE ALONE IS NOT ENOUGH" in the header for why matching on
    -- `node_id` alone would let a trigger-bypassed partition change through.
    SELECT count(*) INTO n
      FROM public.ownership o
     WHERE o.partition_type <> 'public'
       AND NOT EXISTS (SELECT 1 FROM public.tenancy_transcription_log l
                        WHERE l.node_id = o.node_id
                          AND l.from_partition = o.partition_type);
    IF n > 0 THEN
        RAISE EXCEPTION
            'refusing to DROP ownership: % non-public row(s) have no transcription recording their current partition', n
            USING HINT = 'Run epigraph-tenancy-backfill run to completion, confirm verify exits 0, then re-apply this migration. A row whose partition changed without firing the ownership_transcribe trigger must be re-fired by hand: UPDATE public.ownership SET owner_id = owner_id WHERE node_id = ...';
    END IF;
END $$;
-- <<< PRE-FLIGHT 2

-- The view first, explicitly, so it is removed by decision rather than by
-- CASCADE. See "NO CASCADE, DELIBERATELY" above.
DROP VIEW IF EXISTS public.ownership_key_id_quarantine;

DROP TABLE IF EXISTS public.ownership;

-- Orphaned by the table drop: 071's write-through body, still SECURITY DEFINER
-- and still owned by `epigraph_maintenance`.
DROP FUNCTION IF EXISTS public.epigraph_ownership_transcribe();
