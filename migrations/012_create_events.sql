-- Event sourcing table for the epistemic knowledge graph.
--
-- Every mutation to the graph is recorded as an immutable event,
-- enabling full auditability, time-travel queries, and replay-based
-- reconstruction of graph state at any point in history.
--
-- The graph_version column provides a total ordering that is cheaper
-- to compare than timestamps and guarantees no gaps when events are
-- inserted sequentially.

CREATE TABLE IF NOT EXISTS events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      VARCHAR(200) NOT NULL,
    actor_id        UUID        REFERENCES agents(id),
    payload         JSONB       NOT NULL DEFAULT '{}',
    graph_version   BIGINT      NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookups by event type (e.g. "claim.created", "edge.deleted")
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

-- Reverse-chronological listing for the event log endpoint
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);

-- Efficient "give me everything since version N" queries
CREATE INDEX IF NOT EXISTS idx_events_version ON events(graph_version);
