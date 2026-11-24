-- ===================================================================
-- 272-marker-backfill.sql: re-run migration 272's marker backfill, once,
-- after 272 is deployed, on the migration (superuser) DSN.
--
-- WHY. 272 locks `bug_report_intake_settings` before it backfills, so every
-- report already past that read is in the backfill. A write definer call that
-- STARTS while 272 holds the lock has already loaded the old (211) body; it
-- waits on the settings read and, once 272 commits, files its report on that
-- body, with no marker. Such a report drops out of its reporter's list once
-- triage moves it (backlog e690866c). This file is 272's backfill statement,
-- unchanged: it marks every such report and nothing else.
--
-- WHEN. Once, a minute or more after 272 commits (every call that loaded the
-- old body has then finished). Running it again changes nothing
-- (`ON CONFLICT DO NOTHING`); it is safe at any later time.
--
-- WHO. A login whose reads `row_security = off` does not refuse (the
-- migration superuser): on a login row security would filter, the read fails
-- (42501) instead of silently missing reports. Below 272 it fails with 42P01
-- and writes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_uuid constant text :=
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
BEGIN
    -- Fail closed: on a migrating role that row security would filter, these
    -- reads error instead of silently missing reports.
    PERFORM pg_catalog.set_config('row_security', 'off', true);
    INSERT INTO public.bug_report_intake_marks (claim_id, reporter_id, intake_group_id,
                                                submitted_at, title, filed_labels)
    SELECT DISTINCT ON (c.id)
           c.id, e.agent_id,
           CASE WHEN (e.details ->> 'intake_group_id') ~ v_uuid
                THEN (e.details ->> 'intake_group_id')::uuid
                ELSE c.owner_group_id END,
           e.created_at,
           -- The title is only in the claim's properties (see the header).
           (c.properties -> 'bug_report' ->> 'title'),
           -- The labels the write put on the row, rebuilt from the audit row
           -- (definer-written only, 207 (b)), as the write composes them.
           ARRAY['backlog', 'bug-report', 'intake']::text[]
           || CASE WHEN (e.details ->> 'severity') IN ('blocker', 'major', 'minor')
                   THEN ARRAY['severity:' || (e.details ->> 'severity')]
                   ELSE '{}'::text[] END
           || CASE WHEN (e.details ->> 'component') ~ '^[a-z0-9][a-z0-9-]{0,47}$'
                   THEN ARRAY['component:' || (e.details ->> 'component')]
                   ELSE '{}'::text[] END
      FROM public.security_events e
      -- Joined on the uuid, so `claims_pkey` serves the probe (a cast on the
      -- claims side would read the whole heap); a malformed value joins nothing.
      JOIN public.claims c
        ON c.id = CASE WHEN (e.details ->> 'claim_id') ~ v_uuid
                       THEN (e.details ->> 'claim_id')::uuid END
     WHERE e.event_type = 'bug_report.submitted'
       AND e.agent_id IS NOT NULL
       AND c.agent_id = e.agent_id
       -- A second, independent condition, as 207's owner-group filter was:
       -- only a claim the write itself composed is a report, so an audit row
       -- naming a claim its agent authored by another path marks nothing.
       AND c.properties ? 'bug_report'
     ORDER BY c.id, e.created_at, e.id
    ON CONFLICT (claim_id) DO NOTHING;
    PERFORM pg_catalog.set_config('row_security', 'on', true);
END $$;

COMMIT;
