-- Migration 045: Clean up orphan DID-keyed and test agents
--
-- After switching to content-addressed agent identity, the 263 DID-keyed
-- agents and 249 test agents are orphans. For each model, keep the most
-- recent agent row and reassign all claims/evidence/traces from duplicates.

-- Step 1: For each model, find the canonical agent (most recent DID agent)
-- and reassign claims from older duplicates.
DO $$
DECLARE
    r RECORD;
    canonical_id UUID;
BEGIN
    -- Process each model group
    FOR r IN
        SELECT DISTINCT properties->>'model' AS model
        FROM agents
        WHERE properties->>'source' = 'epigraph-nano-mcp'
          AND properties->>'model' IS NOT NULL
    LOOP
        -- Pick the most recent agent for this model as canonical
        SELECT id INTO canonical_id
        FROM agents
        WHERE properties->>'source' = 'epigraph-nano-mcp'
          AND properties->>'model' = r.model
        ORDER BY created_at DESC
        LIMIT 1;

        IF canonical_id IS NULL THEN
            CONTINUE;
        END IF;

        -- Reassign claims from duplicate agents to canonical
        UPDATE claims SET agent_id = canonical_id
        WHERE agent_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign evidence signer_id
        UPDATE evidence SET signer_id = canonical_id
        WHERE signer_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign edges referencing old agents
        UPDATE edges SET source_id = canonical_id
        WHERE source_type = 'agent' AND source_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        UPDATE edges SET target_id = canonical_id
        WHERE target_type = 'agent' AND target_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign analyses
        UPDATE analyses SET agent_id = canonical_id
        WHERE agent_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign mass_functions
        UPDATE mass_functions SET source_agent_id = canonical_id
        WHERE source_agent_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign activities
        UPDATE activities SET agent_id = canonical_id
        WHERE agent_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign perspectives
        UPDATE perspectives SET owner_agent_id = canonical_id
        WHERE owner_agent_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign challenges (challenger_id)
        UPDATE challenges SET challenger_id = canonical_id
        WHERE challenger_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign challenges (resolved_by)
        UPDATE challenges SET resolved_by = canonical_id
        WHERE resolved_by IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign events
        UPDATE events SET actor_id = canonical_id
        WHERE actor_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Reassign ownership
        UPDATE ownership SET owner_id = canonical_id
        WHERE owner_id IN (
            SELECT id FROM agents
            WHERE properties->>'source' = 'epigraph-nano-mcp'
              AND properties->>'model' = r.model
              AND id != canonical_id
        );

        -- Delete the duplicate agents
        DELETE FROM agents
        WHERE properties->>'source' = 'epigraph-nano-mcp'
          AND properties->>'model' = r.model
          AND id != canonical_id;

        RAISE NOTICE 'Consolidated model % agents to %', r.model, canonical_id;
    END LOOP;
END $$;

-- Also clean up test agents that have no claims
DELETE FROM agents
WHERE (display_name LIKE 'test-agent-%' OR display_name LIKE 'lca-test-%')
  AND id NOT IN (SELECT DISTINCT agent_id FROM claims)
  AND id NOT IN (SELECT DISTINCT signer_id FROM evidence WHERE signer_id IS NOT NULL);

-- Clean up "Agent 1" / "Agent 2" duplicates (keep oldest per name)
DELETE FROM agents a
WHERE display_name IN ('Agent 1', 'Agent 2')
  AND created_at > (
      SELECT min(created_at) FROM agents b WHERE b.display_name = a.display_name
  )
  AND id NOT IN (SELECT DISTINCT agent_id FROM claims);
