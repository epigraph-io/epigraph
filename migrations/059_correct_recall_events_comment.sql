-- Correct the retention rationale recorded on `recall_events` (migration 058).
--
-- 058's COMMENT claimed "recall volume >> claim volume", inherited from the
-- design doc and never checked against production. Measured on prod
-- 2026-07-28: recall runs ~30x/day (2,378 `tool.invoked` events over 79 days),
-- so 90-day retention stabilises this table around half a megabyte. Retention
-- here is housekeeping, not a disk-exhaustion control.
--
-- 058 is already applied in production, so its checksum must not change —
-- editing it would panic the API at boot on checksum mismatch. The correction
-- therefore lands as its own migration. COMMENT-only: no schema change, no
-- data touched.

COMMENT ON TABLE recall_events IS
    'Audit log of recall queries and the claims they returned (backlog 8cbffa0e). '
    'Written fire-and-forget after the response is built; never blocks a recall. '
    'Retention: prune-recall-events.timer daily at 04:10, window '
    'RECALL_EVENTS_RETENTION_DAYS (default 90). Measured prod volume 2026-07-28: '
    '~30 recalls/day, so ~0.5MB at steady state — retention is housekeeping, not '
    'a disk control. The unbounded table is `events`, pruned by the same job for '
    'telemetry types only.';
