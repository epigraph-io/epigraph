-- Migration: 025_create_ownership
-- Description: Create ownership table for node partition assignment (§3 Ownership & Privacy)
--
-- The ownership table assigns every node to a partition (public, community, or private).
-- This is the foundation for partition-aware queries and future content encryption.
--
-- Evidence:
-- - dekg-planning-doc.md §3 specifies Ownership & Privacy Layer
-- - Phase 7 plan Step 2: ownership table + partition assignment
--
-- Reasoning:
-- - node_id + node_type together identify any entity (claim, agent, evidence, etc.)
-- - partition_type CHECK ensures only valid partition values
-- - owner_id references the agent who owns the node
-- - encryption_key_id is a placeholder for Phase 8+ content encryption
-- - ON DELETE CASCADE: if the owner agent is deleted, ownership records are cleaned up
--
-- Verification:
-- - CHECK constraint on partition_type prevents invalid partitions
-- - Unique index on node_id ensures one ownership record per node

CREATE TABLE ownership (
    node_id UUID NOT NULL,
    node_type VARCHAR(50) NOT NULL,
    partition_type VARCHAR(20) NOT NULL DEFAULT 'public',
    owner_id UUID NOT NULL,
    encryption_key_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ownership_pkey PRIMARY KEY (node_id),
    CONSTRAINT ownership_partition_check CHECK (
        partition_type IN ('public', 'community', 'private')
    ),
    CONSTRAINT ownership_node_type_check CHECK (
        node_type IN ('claim', 'agent', 'evidence', 'perspective', 'community', 'context', 'frame')
    ),
    CONSTRAINT ownership_owner_fk FOREIGN KEY (owner_id)
        REFERENCES agents(id) ON DELETE CASCADE
);

-- Index for looking up all nodes owned by an agent
CREATE INDEX idx_ownership_owner ON ownership(owner_id);

-- Index for partition-type filtering
CREATE INDEX idx_ownership_partition ON ownership(partition_type);

-- Index for node_type filtering
CREATE INDEX idx_ownership_node_type ON ownership(node_type);

-- Trigger to update updated_at timestamp
CREATE TRIGGER ownership_updated_at
    BEFORE UPDATE ON ownership
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
