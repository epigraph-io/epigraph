-- Migration 002: Add propaganda_techniques and coalitions tables
--
-- The pg_dump-derived 001_initial_schema.sql ships the validate_edge_reference()
-- function and the edges_entity_types_valid CHECK constraint with branches for
-- 'propaganda_technique' and 'coalition' entity types, but the backing tables
-- were not included in the dump. This causes lineage tests (and any edge insert
-- that fires the validator) to fail with: relation "propaganda_techniques" does
-- not exist.
--
-- Adds the two missing tables, their indexes, COMMENTs, cascade-delete triggers,
-- and the propagation-query indexes that depend on them. The validator function
-- and entity-type CHECK constraint are already present in 001 and are not
-- modified here.

-- ============================================================================
-- 1. propaganda_techniques table
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.propaganda_techniques (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name character varying(255) NOT NULL UNIQUE,
    category character varying(100),
    description text,
    detection_guidance text,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_propaganda_techniques_category
    ON public.propaganda_techniques(category);

CREATE INDEX IF NOT EXISTS idx_propaganda_techniques_name
    ON public.propaganda_techniques(name);

COMMENT ON TABLE public.propaganda_techniques IS
    'First-class propaganda technique nodes for USES_TECHNIQUE edge targets. '
    'Techniques are classified by category and carry detection guidance for LLM classifiers.';

-- ============================================================================
-- 2. coalitions table
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.coalitions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name character varying(255),
    archetype character varying(100),
    dominant_antagonist text,
    cognitive_shape character varying(100),
    member_count integer DEFAULT 0 NOT NULL,
    start_date timestamp with time zone,
    peak_date timestamp with time zone,
    end_date timestamp with time zone,
    reach_estimate bigint DEFAULT 0,
    is_active boolean DEFAULT true NOT NULL,
    detection_method character varying(50) DEFAULT 'embedding+time'::character varying NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coalitions_active
    ON public.coalitions(is_active) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_coalitions_archetype
    ON public.coalitions(archetype);

CREATE INDEX IF NOT EXISTS idx_coalitions_start_date
    ON public.coalitions(start_date DESC);

COMMENT ON TABLE public.coalitions IS
    'Narrative coalitions detected when multiple agents run structurally similar narratives '
    'within a sliding time window. Claims link to coalitions via MEMBER_OF edges.';

-- ============================================================================
-- 3. Cascade delete triggers (depend on cascade_delete_edges() from 001)
-- ============================================================================

CREATE TRIGGER propaganda_techniques_cascade_edges
    BEFORE DELETE ON public.propaganda_techniques
    FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('propaganda_technique');

CREATE TRIGGER coalitions_cascade_edges
    BEFORE DELETE ON public.coalitions
    FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('coalition');

CREATE TRIGGER propaganda_techniques_updated_at
    BEFORE UPDATE ON public.propaganda_techniques
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER coalitions_updated_at
    BEFORE UPDATE ON public.coalitions
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- ============================================================================
-- 4. Propagation-query indexes on edges (referenced by political.rs queries)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_edges_originated_by
    ON public.edges(target_id, target_type)
    WHERE relationship = 'ORIGINATED_BY';

CREATE INDEX IF NOT EXISTS idx_edges_amplified_by
    ON public.edges(source_id, source_type)
    WHERE relationship = 'AMPLIFIED_BY';

CREATE INDEX IF NOT EXISTS idx_edges_coordinated_with
    ON public.edges(source_id, target_id)
    WHERE relationship = 'COORDINATED_WITH';

CREATE INDEX IF NOT EXISTS idx_edges_uses_technique
    ON public.edges(source_id, target_id)
    WHERE relationship = 'USES_TECHNIQUE';

CREATE INDEX IF NOT EXISTS idx_edges_member_of_coalition
    ON public.edges(target_id, target_type)
    WHERE relationship = 'MEMBER_OF' AND target_type = 'coalition';

CREATE INDEX IF NOT EXISTS idx_edges_properties_date
    ON public.edges USING GIN (properties jsonb_path_ops);
