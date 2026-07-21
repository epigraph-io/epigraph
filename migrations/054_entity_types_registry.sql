-- Migration 054: entity_types registry (ADDITIVE)
--
-- EVIDENCE
-- Edge entity-type validity + existence checking is currently hardcoded in
-- three drifting places: the Rust `VALID_ENTITY_TYPES` const + `entity_exists`
-- match in routes/edges.rs, the static CHECK `edges_entity_types_valid`
-- (migration 020), and the plpgsql `validate_edge_reference` trigger
-- (migration 025). synthesis/coalition/propaganda_technique fall through the
-- trigger's `ELSE FALSE`, so synthesis edges cannot be written end-to-end
-- (epigraph #344 follow-up).
--
-- DECISION
-- Introduce a single `entity_types` registry table as the one source of truth
-- for which entity types edges may reference and which backing table/id_column
-- each resolves to. This migration is PURELY ADDITIVE: it creates the table
-- and seeds it. It does NOT touch the `edges_entity_types_valid` CHECK or the
-- `validate_edge_reference` trigger — that is Phase 2 (migration 055), kept in
-- a separate file so the additive registry can land/lock independently.
--
-- INJECTION SAFETY (at rest)
-- The four CHECK regexes below guarantee no metacharacter can persist in any
-- identifier column: type_name / schema_name / table_name / id_column are all
-- constrained to `^[a-z_][a-z0-9_]*$` (postgres identifier shape). Only such
-- allowlist-shaped names ever reach dynamic SQL interpolation downstream.

CREATE TABLE entity_types (
    type_name     text PRIMARY KEY CHECK (type_name ~ '^[a-z][a-z0-9_]*$'),
    schema_name   text NOT NULL DEFAULT 'public' CHECK (schema_name ~ '^[a-z_][a-z0-9_]*$'),
    table_name    text CHECK (table_name IS NULL OR table_name ~ '^[a-z_][a-z0-9_]*$'),
    id_column     text NOT NULL DEFAULT 'id' CHECK (id_column ~ '^[a-z_][a-z0-9_]*$'),
    is_optional   boolean NOT NULL DEFAULT false,   -- true=foreign/absent-tolerant; false=owned/fail-loud
    is_core       boolean NOT NULL DEFAULT false,   -- epigraph-owned; API-immutable (hijack guard)
    registered_by uuid,                             -- oauth client_id of registrar; NULL for core seed
    description   text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- SEED: the 23-row UNION of every hardcoded list.
--
-- The 20 currently-accepted core types (CHECK migration 020 + trigger
-- migration 025) are owned tables (is_optional=false) EXCEPT `node`, which
-- has NO backing table (table_name NULL — its semantics stay `=> TRUE` in the
-- Phase-2 trigger fast-path; DO NOT CHANGE).
--
-- The 6 DB-only types the Rust VALID_ENTITY_TYPES omitted are load-bearing:
-- source_artifact->source_artifacts, span->agent_spans, entity->entities,
-- task->tasks, event->events, workflow->workflows. Omitting any would make the
-- Phase-2 FK / trigger REJECT edges the current CHECK/trigger accept.
--
-- synthesis/coalition/propaganda_technique are is_optional=true: their backing
-- tables (syntheses / coalitions / propaganda_techniques) exist only in shared
-- prod, not in epigraph migrations, so their absence must be tolerated
-- (entity_exists -> Ok(false), never a 500).
--
-- ALL seeded rows are is_core=true (API-immutable hijack guard) with
-- registered_by=NULL (core seed). ON CONFLICT DO NOTHING makes re-runs a no-op.
INSERT INTO entity_types (type_name, schema_name, table_name, id_column, is_optional, is_core) VALUES
    ('claim',                'public', 'claims',               'id', false, true),
    ('agent',                'public', 'agents',               'id', false, true),
    ('evidence',             'public', 'evidence',             'id', false, true),
    ('trace',                'public', 'reasoning_traces',     'id', false, true),
    ('paper',                'public', 'papers',               'id', false, true),
    ('analysis',             'public', 'analyses',             'id', false, true),
    ('activity',             'public', 'activities',           'id', false, true),
    ('source_artifact',      'public', 'source_artifacts',     'id', false, true),
    ('span',                 'public', 'agent_spans',          'id', false, true),
    ('entity',               'public', 'entities',             'id', false, true),
    ('task',                 'public', 'tasks',                'id', false, true),
    ('event',                'public', 'events',               'id', false, true),
    ('experiment',           'public', 'experiments',          'id', false, true),
    ('experiment_result',    'public', 'experiment_results',   'id', false, true),
    ('workflow',             'public', 'workflows',            'id', false, true),
    ('perspective',          'public', 'perspectives',         'id', false, true),
    ('community',            'public', 'communities',          'id', false, true),
    ('context',              'public', 'contexts',             'id', false, true),
    ('frame',                'public', 'frames',               'id', false, true),
    ('node',                 'public', NULL,                   'id', false, true),
    ('synthesis',            'public', 'syntheses',            'id', true,  true),
    ('coalition',            'public', 'coalitions',           'id', true,  true),
    ('propaganda_technique', 'public', 'propaganda_techniques','id', true,  true)
ON CONFLICT (type_name) DO NOTHING;
