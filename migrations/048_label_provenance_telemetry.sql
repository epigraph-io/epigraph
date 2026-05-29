-- 048: Back-fill the `telemetry` label onto existing host-provenance claims.
--
-- epiclaw-host's ProvenanceRecorder (epiclaw-host/src/host/provenance.rs) signs
-- every observable host event as an immutable claim for tamper-evidence. Since
-- 2026-04-27 it labels each one `telemetry` via a post-submit label PATCH, but
-- claims written before that — or whose label PATCH failed after the packet
-- committed — are unlabeled. These dominate the is_current embedding gap yet are
-- intentionally non-embedded. Label them so the embedding screen
-- (find_claims_needing_embeddings) and the live_missing audit can filter on the
-- label rather than brittle content-LIKE matching. Backlog: a4aaa487.
--
-- Idempotent: skips rows already carrying the label. Matches the modern
-- `properties->>'event'` marker (exact provenance event values) plus the exact
-- content formats provenance.rs emits, for pre-`event`-property rows.
UPDATE claims
SET labels = array_append(labels, 'telemetry')
WHERE NOT ('telemetry' = ANY(labels))
  AND (
        properties->>'event' IN (
            'message_received', 'message_sent',
            'container_spawned', 'container_exited',
            'agent_output', 'task_scheduled', 'task_executed'
        )
     OR content LIKE 'Received message from %'
     OR content LIKE 'Agent sent message to %'
     OR content LIKE 'Agent in % produced output'
     OR content LIKE 'Container % spawned for group %'
     OR content LIKE 'Container % exited code %'
     OR content LIKE 'Task % executed, status: %'
     OR content LIKE 'Task % scheduled: %'
  );
