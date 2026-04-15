-- Migration 018: Stub tables for Perspective, Community, Context
--
-- These are DEKG node types that will be fully implemented in later phases.
-- Created now so the schema is ready and entity type constraints are satisfied.
--
-- Evidence:
-- - dekg-planning-doc.md: Perspective, Community, Context are core DEKG node types
-- - Entity types already added in migration 015
--
-- Reasoning:
-- - Minimal schema: id, name, description, properties JSONB (extensible)
-- - No foreign keys to claims yet — relationships use the edges table
-- - properties JSONB allows schema-free evolution during design phase

-- Stub: Perspectives (viewpoints that contextualize claims)
CREATE TABLE perspectives (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    owner_agent_id UUID REFERENCES agents(id),
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stub: Communities (groups of agents with shared epistemic standards)
CREATE TABLE communities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL UNIQUE,
    description TEXT,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stub: Contexts (temporal/situational scoping for claims)
CREATE TABLE contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    context_type VARCHAR(50) NOT NULL,  -- 'temporal', 'domain', 'experimental'
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_perspectives_owner ON perspectives(owner_agent_id);
CREATE INDEX idx_contexts_type ON contexts(context_type);
