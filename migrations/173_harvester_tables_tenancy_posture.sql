-- 173: declare the tenancy posture of the two harvester tables that had none
-- (backlog 154efca2, ledger finding F-089-B).
--
-- EVIDENCE
-- `harvester_sources` and `harvester_audit_reports` carry neither
-- `visibility` nor `owner_group_id`, are in no row-security array, and had no
-- `tenancy_exempt` row, so their posture was undeclared rather than decided.
-- Neither is found by `tenancy_coverage.rs`'s generators (no `claim_id`, no
-- FK to `claims`), but both are FK neighbours of `harvester_fragments`, the
-- tier-A table migration 062 registered by hand: a fragment belongs to a
-- source (`harvester_fragments.source_id`) and an audit report is about a
-- fragment (`harvester_audit_reports.fragment_id`). Migration 118 section 6
-- revoked every application write on both; the application role still
-- SELECTs every row.
--
-- CHANGE
-- One `tenancy_exempt` row per table, with the reason, the residual (stated
-- at class level) and the reviewing change, in 077's
-- `reviewed_by = 'PR-17'` form. No column, policy or grant changes: this
-- DECLARES the posture the tables have today, and the residual says what it
-- leaves open. `tenancy_coverage.rs::
-- every_fk_neighbour_of_harvester_fragments_is_covered_or_exempt` makes the
-- rule apply: a neighbour of `harvester_fragments` with neither tenancy
-- columns nor a row here now fails.
--
-- The registry now also holds these two FK neighbours of the manual tier-A
-- addition `harvester_fragments`, which no generator finds;
-- `tenancy_coverage.rs::the_registry_is_exactly_the_fourteen_measured_rows`
-- pins its full membership, so adding a row anywhere is a visible diff.
--
-- A later migration that gives either table a tenancy posture of its own
-- (columns plus 070/074/077 coverage, or row security) must rewrite or delete
-- its row here in the same file, as 077 did for the two views.
--
-- UNDO: DELETE FROM public.tenancy_exempt
--        WHERE table_name IN ('harvester_sources', 'harvester_audit_reports');
SET LOCAL lock_timeout = '3s';

INSERT INTO public.tenancy_exempt (table_name, reason, residual, reviewed_by) VALUES
 ('harvester_sources',
  'Source-document metadata for the harvester pipeline. No claim_id and no FK '
  'to claims; '
  'it is the parent of the tier-A harvester_fragments rows, which carry their '
  'own tenancy. No writer in this repository: migration 118 section 6 revoked '
  'every application write on it.',
  'NOT CLOSED: readable by every application session; tracked by backlog '
  '154efca2.',
  'backlog 154efca2'),
 ('harvester_audit_reports',
  'Per-fragment extraction audit results. FK to the tier-A harvester_fragments, no '
  'claim_id and no FK to claims. No writer in this repository: migration 118 '
  'section 6 revoked every application write on it.',
  'NOT CLOSED: readable by every application session; tracked by backlog '
  '154efca2.',
  'backlog 154efca2')
ON CONFLICT (table_name) DO NOTHING;
