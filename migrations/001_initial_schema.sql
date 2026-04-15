-- Initial schema: epigraph-io/epigraph (open kernel)
--
-- Collapsed from EpiGraphV2 migrations 001–097 (kernel subset).
-- Authoritative source: EpiGraphV2 repo-split/kernel/ staging (tag repo-split/v0).
--
-- Apply on a fresh PostgreSQL 16+ database:
--   CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
--   CREATE EXTENSION IF NOT EXISTS vector;
--   \i 001_initial_schema.sql
--
-- Extensions (uuid-ossp, vector) must be created before running this file.
-- pg_trgm and btree_gist are created below; uuid-ossp and vector are assumed present.

--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;

--
-- Name: EXTENSION vector; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION vector IS 'vector data type and ivfflat and hnsw access methods';

--
-- Name: auto_create_factor_from_edge(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.auto_create_factor_from_edge() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    ft  VARCHAR;
    fwd DOUBLE PRECISION;
    rev DOUBLE PRECISION;
    pot JSONB;
    var_ids UUID[];
BEGIN
    IF NEW.source_type != 'claim' OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    -- Skip edges involving superseded claims
    IF EXISTS (SELECT 1 FROM claims WHERE id = NEW.source_id AND COALESCE(is_current, true) = false)
       OR EXISTS (SELECT 1 FROM claims WHERE id = NEW.target_id AND COALESCE(is_current, true) = false) THEN
        RETURN NEW;
    END IF;

    SELECT factor_type, forward_strength, reverse_strength
    INTO ft, fwd, rev
    FROM edge_to_factor_type(NEW.relationship);

    IF ft IS NULL THEN
        RETURN NEW;
    END IF;

    IF ft = 'mutual_exclusion' THEN
        pot := '{}';
    ELSIF ft = 'directional_support' THEN
        pot := jsonb_build_object(
            'forward_strength', fwd,
            'reverse_strength', rev,
            'source_var', NEW.source_id::text
        );
    ELSE
        pot := jsonb_build_object('strength', fwd);
    END IF;

    IF NEW.source_id < NEW.target_id THEN
        var_ids := ARRAY[NEW.source_id, NEW.target_id];
    ELSE
        var_ids := ARRAY[NEW.target_id, NEW.source_id];
    END IF;

    INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
    VALUES (
        ft,
        var_ids,
        pot,
        format('Auto-generated from %s edge %s', NEW.relationship, NEW.id),
        jsonb_build_object(
            'source_edge_id', NEW.id,
            'relationship', NEW.relationship,
            'edge_source_id', NEW.source_id,
            'edge_target_id', NEW.target_id
        )
    )
    ON CONFLICT DO NOTHING;

    RETURN NEW;
END;
$$;

--
-- Name: cascade_delete_edges(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cascade_delete_edges() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM edges
    WHERE (source_id = OLD.id AND source_type = TG_ARGV[0])
       OR (target_id = OLD.id AND target_type = TG_ARGV[0]);
    RETURN OLD;
END;
$$;

--
-- Name: deactivate_superseded_factors(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.deactivate_superseded_factors() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_current = false AND COALESCE(OLD.is_current, true) = true THEN
        DELETE FROM factors WHERE NEW.id = ANY(variable_ids);
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: edge_to_factor_type(character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.edge_to_factor_type(rel character varying) RETURNS TABLE(factor_type character varying, forward_strength double precision, reverse_strength double precision)
    LANGUAGE plpgsql IMMUTABLE
    AS $$
BEGIN
    RETURN QUERY SELECT t.ft, t.fwd::DOUBLE PRECISION, t.rev::DOUBLE PRECISION FROM (VALUES
        -- Symmetric positive (evidential_support: fwd = rev)
        ('CORROBORATES'::VARCHAR,       'evidential_support'::VARCHAR, 0.85, 0.85),
        ('same_as',                     'evidential_support', 0.95, 0.95),
        ('equivalent_to',              'evidential_support', 0.95, 0.95),
        ('evidential_support',         'evidential_support', 0.8,  0.8),
        ('variant_of',                 'evidential_support', 0.65, 0.65),
        ('definitional_variant_of',    'evidential_support', 0.9,  0.9),
        ('analogous',                  'evidential_support', 0.2,  0.2),

        -- Negative relationships (mutual_exclusion)
        ('CONTRADICTS',                'mutual_exclusion', 0.0, 0.0),
        ('contradicts',                'mutual_exclusion', 0.0, 0.0),
        ('REFUTES',                    'mutual_exclusion', 0.0, 0.0),
        ('challenges',                 'mutual_exclusion', 0.0, 0.0),

        -- Directional: parent → child (zero forward: parent truth does NOT push to children)
        ('decomposes_to',              'directional_support', 0.0, 0.6),

        -- Directional: evidence → conclusion
        ('supports',                   'directional_support', 0.7,  0.15),
        ('SUPPORTS',                   'directional_support', 0.7,  0.15),
        ('provides_evidence',          'directional_support', 0.7,  0.15),

        -- Directional: refined → general
        ('refines',                    'directional_support', 0.6,  0.2),

        -- Directional: derivative → source
        ('derived_from',               'directional_support', 0.5,  0.15),
        ('derives_from',               'directional_support', 0.5,  0.15),

        -- Directional: specific → general
        ('specializes',                'directional_support', 0.55, 0.15),

        -- Directional: prerequisite
        ('enables',                    'directional_support', 0.3,  0.6),

        -- Directional: method → capability
        ('has_method_capability',      'directional_support', 0.6,  0.4),

        -- Directional: weak informational
        ('INFORMS',                    'directional_support', 0.4,  0.1)
    ) AS t(rel_name, ft, fwd, rev)
    WHERE t.rel_name = rel;
END;
$$;

--
-- Name: raise_immutable_error(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.raise_immutable_error() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'provenance_log is append-only: UPDATE and DELETE are prohibited';
END;
$$;

--
-- Name: trigger_validate_edge_refs(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_validate_edge_refs() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT validate_edge_reference(NEW.source_id, NEW.source_type) THEN
        RAISE EXCEPTION 'Edge source references nonexistent % with id %',
            NEW.source_type, NEW.source_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NOT validate_edge_reference(NEW.target_id, NEW.target_type) THEN
        RAISE EXCEPTION 'Edge target references nonexistent % with id %',
            NEW.target_type, NEW.target_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    RETURN NEW;
END;
$$;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

--
-- Name: validate_edge_reference(text, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.validate_edge_reference(entity_type text, entity_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'                 THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'                 THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'              THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'                 THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'                 THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'              THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'              THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'       THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'propaganda_technique'  THEN EXISTS (SELECT 1 FROM propaganda_techniques WHERE id = entity_id)
        WHEN 'coalition'             THEN EXISTS (SELECT 1 FROM coalitions WHERE id = entity_id)
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;

--
-- Name: validate_edge_reference(uuid, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.validate_edge_reference(entity_id uuid, entity_type character varying) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'                 THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'                 THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'              THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'                 THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'                 THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'              THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'              THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'       THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'propaganda_technique'  THEN EXISTS (SELECT 1 FROM propaganda_techniques WHERE id = entity_id)
        WHEN 'coalition'             THEN EXISTS (SELECT 1 FROM coalitions WHERE id = entity_id)
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    activity_type character varying(100) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    agent_id uuid,
    description text,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: agent_capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_capabilities (
    agent_id uuid NOT NULL,
    can_submit_claims boolean DEFAULT true NOT NULL,
    can_provide_evidence boolean DEFAULT true NOT NULL,
    can_challenge_claims boolean DEFAULT false NOT NULL,
    can_invoke_tools boolean DEFAULT false NOT NULL,
    can_spawn_agents boolean DEFAULT false NOT NULL,
    can_modify_policies boolean DEFAULT false NOT NULL,
    privileged_access boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: agent_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    public_key bytea NOT NULL,
    key_type character varying(50) DEFAULT 'signing'::character varying NOT NULL,
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    revocation_reason text,
    revoked_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: agent_spans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_spans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trace_id character varying(32) NOT NULL,
    span_id character varying(16) NOT NULL,
    parent_span_id character varying(16),
    span_name character varying(200) NOT NULL,
    span_kind character varying(20) DEFAULT 'INTERNAL'::character varying NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ended_at timestamp with time zone,
    duration_ms double precision,
    status character varying(10) DEFAULT 'UNSET'::character varying NOT NULL,
    status_message text,
    agent_id uuid,
    user_id uuid,
    session_id uuid,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    generated_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    consumed_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_spans_parent_span_id_hex CHECK (((parent_span_id IS NULL) OR ((parent_span_id)::text ~ '^[0-9a-f]{16}$'::text))),
    CONSTRAINT agent_spans_span_id_hex CHECK (((span_id)::text ~ '^[0-9a-f]{16}$'::text)),
    CONSTRAINT agent_spans_span_kind_valid CHECK (((span_kind)::text = ANY ((ARRAY['SERVER'::character varying, 'CLIENT'::character varying, 'INTERNAL'::character varying, 'PRODUCER'::character varying, 'CONSUMER'::character varying])::text[]))),
    CONSTRAINT agent_spans_status_valid CHECK (((status)::text = ANY ((ARRAY['UNSET'::character varying, 'OK'::character varying, 'ERROR'::character varying])::text[]))),
    CONSTRAINT agent_spans_trace_id_hex CHECK (((trace_id)::text ~ '^[0-9a-f]{32}$'::text))
);

--
-- Name: agent_state_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_state_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    previous_state character varying(50) NOT NULL,
    new_state character varying(50) NOT NULL,
    reason jsonb,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    public_key bytea NOT NULL,
    display_name character varying(255),
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    agent_type character varying(50) DEFAULT 'human'::character varying,
    orcid character varying(19),
    ror_id character varying(9),
    role character varying(50) DEFAULT 'custom'::character varying NOT NULL,
    state character varying(50) DEFAULT 'active'::character varying NOT NULL,
    state_reason jsonb,
    parent_agent_id uuid,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    rate_limit_rpm integer DEFAULT 60 NOT NULL,
    concurrency_limit integer DEFAULT 10 NOT NULL,
    CONSTRAINT agents_display_name_not_empty CHECK (((display_name IS NULL) OR (length(TRIM(BOTH FROM display_name)) > 0))),
    CONSTRAINT agents_public_key_length CHECK ((octet_length(public_key) = 32)),
    CONSTRAINT orcid_format CHECK (((orcid IS NULL) OR ((orcid)::text ~ '^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$'::text))),
    CONSTRAINT ror_format CHECK (((ror_id IS NULL) OR ((ror_id)::text ~ '^0[a-z0-9]{6}\d{2}$'::text)))
);

--
-- Name: COLUMN agents.properties; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agents.properties IS 'For human authors: full_name, orcid, affiliations, email, type=human_author. For digital agents: source, model, etc.';

--
-- Name: analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analyses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    analysis_type character varying(50) NOT NULL,
    method_description text NOT NULL,
    inference_path character varying(30) DEFAULT 'novel'::character varying NOT NULL,
    constraints text,
    coverage_context jsonb DEFAULT '{}'::jsonb,
    input_evidence_ids uuid[] DEFAULT '{}'::uuid[],
    agent_id uuid NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: analysis_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_methods (
    analysis_id uuid NOT NULL,
    method_id uuid NOT NULL,
    role character varying(30) DEFAULT 'primary'::character varying,
    conditions_used jsonb
);

--
-- Name: authorization_votes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_votes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provenance_log_id uuid,
    authorizer_id uuid NOT NULL,
    voter_client_id uuid NOT NULL,
    vote character varying(10) NOT NULL,
    signature bytea NOT NULL,
    voted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT authorization_votes_vote_check CHECK (((vote)::text = ANY ((ARRAY['approve'::character varying, 'reject'::character varying, 'abstain'::character varying])::text[])))
);

--
-- Name: authorizers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorizers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    authorizer_type character varying(30) NOT NULL,
    display_name character varying(255) NOT NULL,
    client_id uuid,
    quorum_threshold integer,
    policy_rule jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT authorizers_authorizer_type_check CHECK (((authorizer_type)::text = ANY ((ARRAY['individual'::character varying, 'council'::character varying, 'policy'::character varying])::text[])))
);

--
-- Name: bp_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bp_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    direction character varying(20) NOT NULL,
    factor_id uuid NOT NULL,
    variable_id uuid NOT NULL,
    message jsonb NOT NULL,
    iteration integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT bp_messages_direction_check CHECK (((direction)::text = ANY ((ARRAY['factor_to_var'::character varying, 'var_to_factor'::character varying])::text[])))
);

--
-- Name: challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    challenger_id uuid,
    challenge_type character varying(50) NOT NULL,
    explanation text NOT NULL,
    state character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    resolution_details jsonb,
    gap_analysis_id uuid
);

--
-- Name: claim_clusters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.claim_clusters (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    cluster_id integer NOT NULL,
    centroid_distance double precision NOT NULL,
    second_centroid_dist double precision NOT NULL,
    boundary_ratio double precision NOT NULL,
    silhouette_score double precision NOT NULL,
    cluster_run_id uuid NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    centroid_distances double precision[]
);

--
-- Name: claim_frames; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.claim_frames (
    claim_id uuid NOT NULL,
    frame_id uuid NOT NULL,
    hypothesis_index integer
);

--
-- Name: claim_themes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.claim_themes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    label text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    centroid public.vector(1536),
    claim_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: claim_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.claim_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    version_number integer NOT NULL,
    content text NOT NULL,
    truth_value double precision NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: claims; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.claims (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    content text NOT NULL,
    content_hash bytea NOT NULL,
    truth_value double precision DEFAULT 0.5 NOT NULL,
    agent_id uuid NOT NULL,
    trace_id uuid,
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    belief double precision,
    plausibility double precision,
    mass_on_empty double precision DEFAULT 0.0,
    pignistic_prob double precision,
    beta_alpha double precision DEFAULT 1.0,
    beta_beta double precision DEFAULT 1.0,
    mass_on_missing double precision DEFAULT 0.0,
    supersedes uuid,
    is_current boolean DEFAULT true NOT NULL,
    open_world_mass double precision DEFAULT 0.0 NOT NULL,
    signature bytea,
    signer_id uuid,
    theme_id uuid,
    CONSTRAINT claims_bel_pl_order CHECK (((belief IS NULL) OR (plausibility IS NULL) OR (belief <= plausibility))),
    CONSTRAINT claims_belief_bounds CHECK (((belief IS NULL) OR ((belief >= (0.0)::double precision) AND (belief <= (1.0)::double precision)))),
    CONSTRAINT claims_content_hash_length CHECK ((octet_length(content_hash) = 32)),
    CONSTRAINT claims_content_not_empty CHECK ((length(TRIM(BOTH FROM content)) > 0)),
    CONSTRAINT claims_mass_empty_bounds CHECK (((mass_on_empty >= (0.0)::double precision) AND (mass_on_empty <= (1.0)::double precision))),
    CONSTRAINT claims_plausibility_bounds CHECK (((plausibility IS NULL) OR ((plausibility >= (0.0)::double precision) AND (plausibility <= (1.0)::double precision)))),
    CONSTRAINT claims_signature_length CHECK (((signature IS NULL) OR (octet_length(signature) = 64))),
    CONSTRAINT claims_signature_requires_signer CHECK ((((signature IS NULL) AND (signer_id IS NULL)) OR ((signature IS NOT NULL) AND (signer_id IS NOT NULL)))),
    CONSTRAINT claims_truth_value_bounds CHECK (((truth_value >= (0.0)::double precision) AND (truth_value <= (1.0)::double precision)))
);

--
-- Name: COLUMN claims.properties; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.claims.properties IS 'Structured metadata: methodology, section, reasoning_chain, asserted_by_authors, source_doi, extraction_persona';

--
-- Name: cluster_centroids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cluster_centroids (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cluster_run_id uuid NOT NULL,
    cluster_id integer NOT NULL,
    centroid public.vector(1536) NOT NULL,
    claim_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: communities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.communities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    governance_type text DEFAULT 'open'::text,
    ownership_type text DEFAULT 'public'::text,
    mass_override jsonb
);

--
-- Name: community_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.community_members (
    community_id uuid NOT NULL,
    perspective_id uuid NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: contexts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contexts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(200) NOT NULL,
    context_type character varying(50) NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    description text,
    applicable_frame_ids uuid[] DEFAULT '{}'::uuid[],
    parameters jsonb DEFAULT '{}'::jsonb,
    modifier_type text DEFAULT 'filter'::text
);

--
-- Name: counterfactual_scenarios; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.counterfactual_scenarios (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    conflict_event_id uuid,
    claim_a_id uuid,
    claim_b_id uuid,
    scenario_a jsonb NOT NULL,
    scenario_b jsonb NOT NULL,
    discriminating_tests jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: ds_bayesian_divergence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ds_bayesian_divergence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    frame_id uuid NOT NULL,
    pignistic_prob double precision NOT NULL,
    bayesian_posterior double precision NOT NULL,
    kl_divergence double precision NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    frame_version integer DEFAULT 1
);

--
-- Name: ds_combined_beliefs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ds_combined_beliefs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    frame_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    scope_type text NOT NULL,
    scope_id uuid,
    belief double precision NOT NULL,
    plausibility double precision NOT NULL,
    mass_on_empty double precision DEFAULT 0.0 NOT NULL,
    conflict_k double precision,
    strategy_used text,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    pignistic_prob double precision,
    mass_on_missing double precision DEFAULT 0.0,
    CONSTRAINT ds_combined_beliefs_scope_type_check CHECK ((scope_type = ANY (ARRAY['global'::text, 'community'::text, 'perspective'::text])))
);

--
-- Name: edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    target_id uuid NOT NULL,
    source_type character varying(50) NOT NULL,
    target_type character varying(50) NOT NULL,
    relationship character varying(100) NOT NULL,
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    prov_type character varying(100),
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    signature bytea,
    signer_id uuid,
    content_hash bytea,
    CONSTRAINT edges_content_hash_length CHECK (((content_hash IS NULL) OR (octet_length(content_hash) = 32))),
    CONSTRAINT edges_entity_types_valid CHECK ((((source_type)::text = ANY (ARRAY['claim'::text, 'agent'::text, 'evidence'::text, 'trace'::text, 'node'::text, 'activity'::text, 'paper'::text, 'perspective'::text, 'community'::text, 'context'::text, 'frame'::text, 'analysis'::text, 'experiment'::text, 'experiment_result'::text, 'propaganda_technique'::text, 'coalition'::text, 'source_artifact'::text, 'span'::text, 'entity'::text, 'task'::text, 'event'::text])) AND ((target_type)::text = ANY (ARRAY['claim'::text, 'agent'::text, 'evidence'::text, 'trace'::text, 'node'::text, 'activity'::text, 'paper'::text, 'perspective'::text, 'community'::text, 'context'::text, 'frame'::text, 'analysis'::text, 'experiment'::text, 'experiment_result'::text, 'propaganda_technique'::text, 'coalition'::text, 'source_artifact'::text, 'span'::text, 'entity'::text, 'task'::text, 'event'::text])))),
    CONSTRAINT edges_no_self_loop CHECK (((source_id <> target_id) OR ((source_type)::text <> (target_type)::text))),
    CONSTRAINT edges_relationship_not_empty CHECK ((length(TRIM(BOTH FROM relationship)) > 0)),
    CONSTRAINT edges_signature_length CHECK (((signature IS NULL) OR (octet_length(signature) = 64))),
    CONSTRAINT edges_signature_requires_signer CHECK ((((signature IS NULL) AND (signer_id IS NULL)) OR ((signature IS NOT NULL) AND (signer_id IS NOT NULL)))),
    CONSTRAINT temporal_ordering CHECK (((valid_to IS NULL) OR (valid_from IS NULL) OR (valid_to > valid_from)))
);

--
-- Name: TABLE edges; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.edges IS 'LPG-style edges table for flexible graph relationships. This table complements the fixed schema FK relationships and enables dynamic graph queries. Use this for relationships that don''t fit the core schema (e.g., claim supports/refutes another claim, agent endorses claim, etc.).';

--
-- Name: COLUMN edges.properties; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.edges.properties IS 'Edge-level metadata: for AUTHORED edges: position, is_corresponding, contributions (CRediT roles)';

--
-- Name: edges_staging; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edges_staging (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    source_type character varying(50) DEFAULT 'claim'::character varying NOT NULL,
    target_id uuid NOT NULL,
    target_type character varying(50) DEFAULT 'claim'::character varying NOT NULL,
    relationship character varying(100) DEFAULT 'CORROBORATES'::character varying NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    review_status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    reviewed_at timestamp with time zone,
    reviewed_by text,
    review_notes text,
    CONSTRAINT edges_staging_review_status_check CHECK (((review_status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'reclassified'::character varying, 'promoted'::character varying])::text[])))
);

--
-- Name: TABLE edges_staging; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.edges_staging IS 'Proposed edges from universal_match_staging.py awaiting human review. Approved rows are promoted to the production edges table by promote_staged_edges.py.';

--
-- Name: entities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    canonical_name text NOT NULL,
    type_top character varying(50) NOT NULL,
    type_sub text,
    embedding public.vector(1536),
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_canonical boolean DEFAULT true NOT NULL,
    merged_into uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entities_canonical_or_merged CHECK (((is_canonical = true) OR (merged_into IS NOT NULL))),
    CONSTRAINT entities_type_top_valid CHECK (((type_top)::text = ANY ((ARRAY['Material'::character varying, 'Molecule'::character varying, 'Method'::character varying, 'Instrument'::character varying, 'Property'::character varying, 'Measurement'::character varying, 'Condition'::character varying, 'Organism'::character varying, 'Software'::character varying, 'Person'::character varying, 'Organization'::character varying, 'Location'::character varying, 'Concept'::character varying, 'BusinessFunction'::character varying])::text[])))
);

--
-- Name: entity_mentions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entity_mentions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    entity_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    surface_form text NOT NULL,
    mention_role character varying(20) NOT NULL,
    confidence double precision NOT NULL,
    extractor character varying(50) NOT NULL,
    span_start integer,
    span_end integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entity_mentions_role_valid CHECK (((mention_role)::text = ANY ((ARRAY['subject'::character varying, 'object'::character varying, 'modifier'::character varying])::text[])))
);

--
-- Name: entity_merge_candidates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entity_merge_candidates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    entity_a uuid NOT NULL,
    entity_b uuid NOT NULL,
    score double precision NOT NULL,
    auto_threshold_used double precision NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    reviewed_by character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT merge_candidates_ordered CHECK ((entity_a < entity_b)),
    CONSTRAINT merge_candidates_status_valid CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[])))
);

--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(200) NOT NULL,
    actor_id uuid,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    graph_version bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: events_graph_version_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_graph_version_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    content_hash bytea NOT NULL,
    evidence_type character varying(50) NOT NULL,
    source_url text,
    raw_content text,
    claim_id uuid NOT NULL,
    signature bytea,
    signer_id uuid,
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    embedding public.vector(1536),
    modality character varying(50) DEFAULT 'text'::character varying,
    CONSTRAINT evidence_content_hash_length CHECK ((octet_length(content_hash) = 32)),
    CONSTRAINT evidence_signature_length CHECK (((signature IS NULL) OR (octet_length(signature) = 64))),
    CONSTRAINT evidence_signature_requires_signer CHECK ((((signature IS NULL) AND (signer_id IS NULL)) OR ((signature IS NOT NULL) AND (signer_id IS NOT NULL)))),
    CONSTRAINT evidence_type_valid CHECK (((evidence_type)::text = ANY ((ARRAY['document'::character varying, 'observation'::character varying, 'testimony'::character varying, 'computation'::character varying, 'reference'::character varying, 'figure'::character varying, 'conversational'::character varying])::text[])))
);

--
-- Name: experiment_entities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.experiment_entities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    canonical_name text NOT NULL,
    entity_type character varying(50) NOT NULL,
    aliases text[] DEFAULT '{}'::text[],
    embedding public.vector(1536),
    properties jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: experiment_entity_mentions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.experiment_entity_mentions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    surface_form text NOT NULL,
    mention_role character varying(20) DEFAULT 'context'::character varying NOT NULL,
    confidence double precision DEFAULT 1.0 NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: experiment_triples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.experiment_triples (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    subject_entity_id uuid NOT NULL,
    predicate text NOT NULL,
    object_entity_id uuid NOT NULL,
    context_entity_ids uuid[] DEFAULT '{}'::uuid[],
    confidence double precision DEFAULT 1.0 NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: factors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.factors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    factor_type character varying(100) NOT NULL,
    variable_ids uuid[] NOT NULL,
    potential jsonb DEFAULT '{}'::jsonb NOT NULL,
    description text,
    frame_id uuid,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT factors_min_variables CHECK ((array_length(variable_ids, 1) >= 2))
);

--
-- Name: frames; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frames (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    hypotheses text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    parent_frame_id uuid,
    is_refinable boolean DEFAULT true,
    version integer DEFAULT 1 NOT NULL,
    CONSTRAINT frames_not_empty CHECK ((array_length(hypotheses, 1) >= 2))
);

--
-- Name: gap_analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gap_analyses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    question text NOT NULL,
    analysis_a_id uuid,
    analysis_b_id uuid,
    graph_claims_count integer NOT NULL,
    unconstrained_claims_count integer NOT NULL,
    matched_count integer NOT NULL,
    gap_count integer NOT NULL,
    proprietary_count integer NOT NULL,
    confidence_boundary text,
    gaps jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: harvester_audit_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.harvester_audit_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    fragment_id uuid NOT NULL,
    extraction_id uuid NOT NULL,
    skeptic_passed boolean,
    hallucinations_detected integer DEFAULT 0,
    skeptic_findings jsonb,
    logician_passed boolean,
    contradictions_found integer DEFAULT 0,
    logician_findings jsonb,
    variance_passed boolean,
    similarity_score double precision,
    variance_report jsonb,
    final_confidence double precision,
    passed_audit boolean,
    attempts integer DEFAULT 1,
    model_used text,
    token_usage jsonb,
    processing_time_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT harvester_audit_attempts_positive CHECK ((attempts >= 1)),
    CONSTRAINT harvester_audit_confidence_bounds CHECK (((final_confidence IS NULL) OR ((final_confidence >= (0.0)::double precision) AND (final_confidence <= (1.0)::double precision)))),
    CONSTRAINT harvester_audit_similarity_bounds CHECK (((similarity_score IS NULL) OR ((similarity_score >= (0.0)::double precision) AND (similarity_score <= (1.0)::double precision))))
);

--
-- Name: TABLE harvester_audit_reports; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.harvester_audit_reports IS 'Council of Critics audit results per fragment extraction';

--
-- Name: harvester_claim_provenance; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.harvester_claim_provenance (
    claim_id uuid NOT NULL,
    fragment_id uuid NOT NULL,
    audit_report_id uuid,
    extraction_confidence double precision,
    CONSTRAINT harvester_provenance_confidence_bounds CHECK (((extraction_confidence IS NULL) OR ((extraction_confidence >= (0.0)::double precision) AND (extraction_confidence <= (1.0)::double precision))))
);

--
-- Name: TABLE harvester_claim_provenance; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.harvester_claim_provenance IS 'Links extracted claims to source fragments and audit trails';

--
-- Name: harvester_enriched_concepts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.harvester_enriched_concepts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    concept_name text NOT NULL,
    canonical_name text,
    latent_definition text,
    source_model text,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: TABLE harvester_enriched_concepts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.harvester_enriched_concepts IS 'Concepts enriched with latent knowledge and embeddings';

--
-- Name: harvester_fragments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.harvester_fragments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_id uuid NOT NULL,
    content_hash bytea NOT NULL,
    content_text text NOT NULL,
    context_window text,
    char_offset_start bigint,
    char_offset_end bigint,
    page_number integer,
    section_title text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT harvester_fragments_offsets_valid CHECK (((char_offset_start IS NULL) OR (char_offset_end IS NULL) OR (char_offset_end >= char_offset_start))),
    CONSTRAINT harvester_fragments_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text])))
);

--
-- Name: TABLE harvester_fragments; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.harvester_fragments IS 'Text fragments chunked from source documents';

--
-- Name: harvester_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.harvester_sources (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    content_hash bytea NOT NULL,
    filename text,
    mime_type text,
    file_size bigint,
    modality text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT harvester_sources_file_size_positive CHECK (((file_size IS NULL) OR (file_size >= 0))),
    CONSTRAINT harvester_sources_modality_check CHECK ((modality = ANY (ARRAY['text'::text, 'pdf'::text, 'audio'::text]))),
    CONSTRAINT harvester_sources_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text, 'failed'::text])))
);

--
-- Name: TABLE harvester_sources; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.harvester_sources IS 'Source documents submitted for harvester extraction';

--
-- Name: jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jobs (
    id uuid NOT NULL,
    job_type character varying(255) NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    state character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    max_retries integer DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    CONSTRAINT jobs_max_retries_non_negative CHECK ((max_retries >= 0)),
    CONSTRAINT jobs_retry_count_non_negative CHECK ((retry_count >= 0)),
    CONSTRAINT jobs_state_check CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);

--
-- Name: TABLE jobs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.jobs IS 'Background job queue with persistent storage';

--
-- Name: COLUMN jobs.id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.id IS 'Unique job identifier (UUID v4)';

--
-- Name: COLUMN jobs.job_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.job_type IS 'Job type for routing to handlers';

--
-- Name: COLUMN jobs.payload; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.payload IS 'JSONB payload with job-specific data';

--
-- Name: COLUMN jobs.state; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.state IS 'Job state: pending, running, completed, failed, cancelled';

--
-- Name: COLUMN jobs.retry_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.retry_count IS 'Number of retry attempts made';

--
-- Name: COLUMN jobs.max_retries; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.max_retries IS 'Maximum allowed retry attempts';

--
-- Name: COLUMN jobs.started_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.started_at IS 'Timestamp when job started running';

--
-- Name: COLUMN jobs.completed_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.completed_at IS 'Timestamp when job finished (success or failure)';

--
-- Name: COLUMN jobs.error_message; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.jobs.error_message IS 'Error message if job failed';

--
-- Name: learning_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.learning_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    challenge_id uuid NOT NULL,
    conflict_claim_a uuid,
    conflict_claim_b uuid,
    resolution text NOT NULL,
    lesson text NOT NULL,
    extraction_adjustments jsonb,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: mass_functions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mass_functions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    frame_id uuid NOT NULL,
    source_agent_id uuid,
    masses jsonb NOT NULL,
    conflict_k double precision,
    combination_method character varying(50),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    perspective_id uuid,
    source_strength double precision,
    evidence_type character varying(50)
);

--
-- Name: method_capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.method_capabilities (
    method_id uuid NOT NULL,
    capability text NOT NULL,
    specificity smallint DEFAULT 1,
    evidence_count integer DEFAULT 0
);

--
-- Name: methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    canonical_name text NOT NULL,
    technique_type character varying(50) NOT NULL,
    measures text,
    resolution text,
    sensitivity text,
    limitations text[],
    required_equipment text[],
    typical_conditions jsonb,
    source_claim_ids uuid[],
    properties jsonb DEFAULT '{}'::jsonb,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: oauth_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id character varying(64) NOT NULL,
    client_secret_hash bytea,
    client_name character varying(255) NOT NULL,
    client_type character varying(20) NOT NULL,
    redirect_uris text[],
    allowed_scopes text[] NOT NULL,
    granted_scopes text[] DEFAULT '{}'::text[] NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    agent_id uuid,
    owner_id uuid,
    legal_entity_name character varying(255),
    legal_entity_id character varying(100),
    legal_contact_email character varying(255),
    legal_accepted_tos_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agents_must_have_owner CHECK ((((client_type)::text <> 'agent'::text) OR (owner_id IS NOT NULL))),
    CONSTRAINT oauth_clients_client_type_check CHECK (((client_type)::text = ANY ((ARRAY['agent'::character varying, 'human'::character varying, 'service'::character varying])::text[]))),
    CONSTRAINT oauth_clients_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'pending'::character varying, 'suspended'::character varying, 'revoked'::character varying])::text[]))),
    CONSTRAINT services_must_have_legal_entity CHECK ((((client_type)::text <> 'service'::text) OR ((legal_entity_name IS NOT NULL) AND (legal_contact_email IS NOT NULL))))
);

--
-- Name: ownership; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ownership (
    node_id uuid NOT NULL,
    node_type character varying(50) NOT NULL,
    partition_type character varying(20) DEFAULT 'public'::character varying NOT NULL,
    owner_id uuid NOT NULL,
    encryption_key_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ownership_node_type_check CHECK (((node_type)::text = ANY ((ARRAY['claim'::character varying, 'agent'::character varying, 'evidence'::character varying, 'perspective'::character varying, 'community'::character varying, 'context'::character varying, 'frame'::character varying])::text[]))),
    CONSTRAINT ownership_partition_check CHECK (((partition_type)::text = ANY ((ARRAY['public'::character varying, 'community'::character varying, 'private'::character varying])::text[])))
);

--
-- Name: papers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.papers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    doi text NOT NULL,
    title text,
    journal text,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: perspectives; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.perspectives (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    owner_agent_id uuid,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    perspective_type text DEFAULT 'analytical'::text,
    frame_ids uuid[] DEFAULT '{}'::uuid[],
    extraction_method text DEFAULT 'ai_generated'::text,
    confidence_calibration double precision DEFAULT 0.5
);

--
-- Name: provenance_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provenance_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    record_type character varying(50) NOT NULL,
    record_id uuid NOT NULL,
    action character varying(20) NOT NULL,
    submitted_by uuid NOT NULL,
    principal_id uuid NOT NULL,
    authorization_chain uuid[] NOT NULL,
    authorization_type character varying(30) NOT NULL,
    content_hash bytea NOT NULL,
    provenance_sig bytea NOT NULL,
    token_jti uuid NOT NULL,
    scopes_used text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    patch_payload jsonb,
    CONSTRAINT provenance_log_authorization_type_check CHECK (((authorization_type)::text = ANY ((ARRAY['auto_policy'::character varying, 'mod_approved'::character varying, 'council_approved'::character varying, 'escalated'::character varying])::text[])))
);

--
-- Name: reasoning_traces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reasoning_traces (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    reasoning_type character varying(50) NOT NULL,
    confidence double precision DEFAULT 0.5 NOT NULL,
    explanation text NOT NULL,
    labels text[] DEFAULT '{}'::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT reasoning_confidence_bounds CHECK (((confidence >= (0.0)::double precision) AND (confidence <= (1.0)::double precision))),
    CONSTRAINT reasoning_explanation_not_empty CHECK ((length(TRIM(BOTH FROM explanation)) > 0)),
    CONSTRAINT reasoning_type_valid CHECK (((reasoning_type)::text = ANY ((ARRAY['deductive'::character varying, 'inductive'::character varying, 'abductive'::character varying, 'analogical'::character varying, 'statistical'::character varying])::text[])))
);

--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash bytea NOT NULL,
    client_id uuid NOT NULL,
    scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(50) NOT NULL,
    agent_id uuid,
    success boolean,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_address inet,
    user_agent text,
    correlation_id character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: source_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_artifacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    artifact_type text DEFAULT 'generic'::text NOT NULL,
    source_url text,
    content_hash bytea,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tasks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    description text NOT NULL,
    task_type character varying(100) NOT NULL,
    input jsonb DEFAULT '{}'::jsonb NOT NULL,
    output_schema jsonb,
    assigned_agent uuid,
    priority integer DEFAULT 0 NOT NULL,
    state character varying(50) DEFAULT 'created'::character varying NOT NULL,
    parent_task_id uuid,
    workflow_id uuid,
    timeout_seconds integer,
    retry_max integer DEFAULT 3 NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    result jsonb,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone
);

--
-- Name: trace_parents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trace_parents (
    trace_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    CONSTRAINT trace_parents_no_self_reference CHECK ((trace_id <> parent_id))
);

--
-- Name: TABLE trace_parents; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.trace_parents IS 'DAG edges for reasoning trace dependencies. Cycle detection must be performed at application layer before inserting new edges. See epigraph-engine DAG validator.';

--
-- Name: triples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.triples (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    predicate text NOT NULL,
    object_id uuid,
    object_literal text,
    confidence double precision NOT NULL,
    extractor character varying(50) NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT triples_has_object CHECK (((object_id IS NOT NULL) OR (object_literal IS NOT NULL)))
);

--
-- Name: workflow_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_executions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    state character varying(50) DEFAULT 'created'::character varying NOT NULL,
    created_by uuid NOT NULL,
    task_count integer DEFAULT 0 NOT NULL,
    tasks_completed integer DEFAULT 0 NOT NULL,
    tasks_failed integer DEFAULT 0 NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    template_claim_id uuid
);

--
-- Name: COLUMN workflow_executions.template_claim_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.workflow_executions.template_claim_id IS 'References the claim ID of the workflow template (claims labeled workflow). NULL for ad-hoc executions.';

--
-- Name: activities activities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activities
    ADD CONSTRAINT activities_pkey PRIMARY KEY (id);

--
-- Name: agent_capabilities agent_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_capabilities
    ADD CONSTRAINT agent_capabilities_pkey PRIMARY KEY (agent_id);

--
-- Name: agent_keys agent_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_keys
    ADD CONSTRAINT agent_keys_pkey PRIMARY KEY (id);

--
-- Name: agent_spans agent_spans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_spans
    ADD CONSTRAINT agent_spans_pkey PRIMARY KEY (id);

--
-- Name: agent_state_history agent_state_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_state_history
    ADD CONSTRAINT agent_state_history_pkey PRIMARY KEY (id);

--
-- Name: agents agents_orcid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_orcid_key UNIQUE (orcid);

--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);

--
-- Name: agents agents_public_key_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_public_key_unique UNIQUE (public_key);

--
-- Name: agents agents_ror_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_ror_id_key UNIQUE (ror_id);

--
-- Name: analyses analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyses
    ADD CONSTRAINT analyses_pkey PRIMARY KEY (id);

--
-- Name: analysis_methods analysis_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_methods
    ADD CONSTRAINT analysis_methods_pkey PRIMARY KEY (analysis_id, method_id);

--
-- Name: authorization_votes authorization_votes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_votes
    ADD CONSTRAINT authorization_votes_pkey PRIMARY KEY (id);

--
-- Name: authorizers authorizers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorizers
    ADD CONSTRAINT authorizers_pkey PRIMARY KEY (id);

--
-- Name: bp_messages bp_messages_factor_id_variable_id_direction_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bp_messages
    ADD CONSTRAINT bp_messages_factor_id_variable_id_direction_key UNIQUE (factor_id, variable_id, direction);

--
-- Name: bp_messages bp_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bp_messages
    ADD CONSTRAINT bp_messages_pkey PRIMARY KEY (id);

--
-- Name: challenges challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.challenges
    ADD CONSTRAINT challenges_pkey PRIMARY KEY (id);

--
-- Name: claim_clusters claim_clusters_claim_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_clusters
    ADD CONSTRAINT claim_clusters_claim_id_key UNIQUE (claim_id);

--
-- Name: claim_clusters claim_clusters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_clusters
    ADD CONSTRAINT claim_clusters_pkey PRIMARY KEY (id);

--
-- Name: claim_frames claim_frames_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_frames
    ADD CONSTRAINT claim_frames_pkey PRIMARY KEY (claim_id, frame_id);

--
-- Name: claim_themes claim_themes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_themes
    ADD CONSTRAINT claim_themes_pkey PRIMARY KEY (id);

--
-- Name: claim_versions claim_versions_claim_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_versions
    ADD CONSTRAINT claim_versions_claim_id_version_number_key UNIQUE (claim_id, version_number);

--
-- Name: claim_versions claim_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_versions
    ADD CONSTRAINT claim_versions_pkey PRIMARY KEY (id);

--
-- Name: claims claims_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_pkey PRIMARY KEY (id);

--
-- Name: cluster_centroids cluster_centroids_cluster_run_id_cluster_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cluster_centroids
    ADD CONSTRAINT cluster_centroids_cluster_run_id_cluster_id_key UNIQUE (cluster_run_id, cluster_id);

--
-- Name: cluster_centroids cluster_centroids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cluster_centroids
    ADD CONSTRAINT cluster_centroids_pkey PRIMARY KEY (id);

--
-- Name: communities communities_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.communities
    ADD CONSTRAINT communities_name_key UNIQUE (name);

--
-- Name: communities communities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.communities
    ADD CONSTRAINT communities_pkey PRIMARY KEY (id);

--
-- Name: community_members community_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.community_members
    ADD CONSTRAINT community_members_pkey PRIMARY KEY (community_id, perspective_id);

--
-- Name: contexts contexts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contexts
    ADD CONSTRAINT contexts_pkey PRIMARY KEY (id);

--
-- Name: counterfactual_scenarios counterfactual_scenarios_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.counterfactual_scenarios
    ADD CONSTRAINT counterfactual_scenarios_pkey PRIMARY KEY (id);

--
-- Name: ds_bayesian_divergence ds_bayesian_divergence_claim_id_frame_id_computed_at_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_bayesian_divergence
    ADD CONSTRAINT ds_bayesian_divergence_claim_id_frame_id_computed_at_key UNIQUE (claim_id, frame_id, computed_at);

--
-- Name: ds_bayesian_divergence ds_bayesian_divergence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_bayesian_divergence
    ADD CONSTRAINT ds_bayesian_divergence_pkey PRIMARY KEY (id);

--
-- Name: ds_combined_beliefs ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_combined_beliefs
    ADD CONSTRAINT ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key UNIQUE (frame_id, claim_id, scope_type, scope_id);

--
-- Name: ds_combined_beliefs ds_combined_beliefs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_combined_beliefs
    ADD CONSTRAINT ds_combined_beliefs_pkey PRIMARY KEY (id);

--
-- Name: edges edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edges
    ADD CONSTRAINT edges_pkey PRIMARY KEY (id);

--
-- Name: edges_staging edges_staging_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edges_staging
    ADD CONSTRAINT edges_staging_pkey PRIMARY KEY (id);

--
-- Name: edges_staging edges_staging_source_id_target_id_relationship_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edges_staging
    ADD CONSTRAINT edges_staging_source_id_target_id_relationship_key UNIQUE (source_id, target_id, relationship);

--
-- Name: entities entities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entities
    ADD CONSTRAINT entities_pkey PRIMARY KEY (id);

--
-- Name: entity_mentions entity_mentions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_mentions
    ADD CONSTRAINT entity_mentions_pkey PRIMARY KEY (id);

--
-- Name: entity_merge_candidates entity_merge_candidates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_merge_candidates
    ADD CONSTRAINT entity_merge_candidates_pkey PRIMARY KEY (id);

--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);

--
-- Name: evidence evidence_content_hash_claim_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_content_hash_claim_unique UNIQUE (content_hash, claim_id);

--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (id);

--
-- Name: experiment_entities experiment_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_entities
    ADD CONSTRAINT experiment_entities_pkey PRIMARY KEY (id);

--
-- Name: experiment_entity_mentions experiment_entity_mentions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_pkey PRIMARY KEY (id);

--
-- Name: experiment_triples experiment_triples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_pkey PRIMARY KEY (id);

--
-- Name: factors factors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.factors
    ADD CONSTRAINT factors_pkey PRIMARY KEY (id);

--
-- Name: frames frames_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frames
    ADD CONSTRAINT frames_name_key UNIQUE (name);

--
-- Name: frames frames_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frames
    ADD CONSTRAINT frames_pkey PRIMARY KEY (id);

--
-- Name: gap_analyses gap_analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gap_analyses
    ADD CONSTRAINT gap_analyses_pkey PRIMARY KEY (id);

--
-- Name: harvester_audit_reports harvester_audit_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_audit_reports
    ADD CONSTRAINT harvester_audit_reports_pkey PRIMARY KEY (id);

--
-- Name: harvester_claim_provenance harvester_claim_provenance_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_pkey PRIMARY KEY (claim_id, fragment_id);

--
-- Name: harvester_enriched_concepts harvester_enriched_concepts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_enriched_concepts
    ADD CONSTRAINT harvester_enriched_concepts_pkey PRIMARY KEY (id);

--
-- Name: harvester_fragments harvester_fragments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_fragments
    ADD CONSTRAINT harvester_fragments_pkey PRIMARY KEY (id);

--
-- Name: harvester_sources harvester_sources_content_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_sources
    ADD CONSTRAINT harvester_sources_content_hash_key UNIQUE (content_hash);

--
-- Name: harvester_sources harvester_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_sources
    ADD CONSTRAINT harvester_sources_pkey PRIMARY KEY (id);

--
-- Name: jobs jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);

--
-- Name: learning_events learning_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_events
    ADD CONSTRAINT learning_events_pkey PRIMARY KEY (id);

--
-- Name: mass_functions mass_functions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_pkey PRIMARY KEY (id);

--
-- Name: mass_functions mass_functions_unique_per_perspective; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_unique_per_perspective UNIQUE (claim_id, frame_id, source_agent_id, perspective_id);

--
-- Name: entity_merge_candidates merge_candidates_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_merge_candidates
    ADD CONSTRAINT merge_candidates_unique_pair UNIQUE (entity_a, entity_b);

--
-- Name: method_capabilities method_capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.method_capabilities
    ADD CONSTRAINT method_capabilities_pkey PRIMARY KEY (method_id, capability);

--
-- Name: methods methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.methods
    ADD CONSTRAINT methods_pkey PRIMARY KEY (id);

--
-- Name: oauth_clients oauth_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_client_id_key UNIQUE (client_id);

--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);

--
-- Name: ownership ownership_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership
    ADD CONSTRAINT ownership_pkey PRIMARY KEY (node_id);

--
-- Name: papers papers_doi_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.papers
    ADD CONSTRAINT papers_doi_key UNIQUE (doi);

--
-- Name: papers papers_doi_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.papers
    ADD CONSTRAINT papers_doi_unique UNIQUE (doi);

--
-- Name: papers papers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.papers
    ADD CONSTRAINT papers_pkey PRIMARY KEY (id);

--
-- Name: perspectives perspectives_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.perspectives
    ADD CONSTRAINT perspectives_pkey PRIMARY KEY (id);

--
-- Name: provenance_log provenance_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_log
    ADD CONSTRAINT provenance_log_pkey PRIMARY KEY (id);

--
-- Name: reasoning_traces reasoning_traces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reasoning_traces
    ADD CONSTRAINT reasoning_traces_pkey PRIMARY KEY (id);

--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);

--
-- Name: refresh_tokens refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);

--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);

--
-- Name: source_artifacts source_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_artifacts
    ADD CONSTRAINT source_artifacts_pkey PRIMARY KEY (id);

--
-- Name: tasks tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (id);

--
-- Name: trace_parents trace_parents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trace_parents
    ADD CONSTRAINT trace_parents_pkey PRIMARY KEY (trace_id, parent_id);

--
-- Name: triples triples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triples
    ADD CONSTRAINT triples_pkey PRIMARY KEY (id);

--
-- Name: workflow_executions workflow_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_pkey PRIMARY KEY (id);

--
-- Name: idx_activities_activity_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_activities_activity_type ON public.activities USING btree (activity_type);

--
-- Name: idx_activities_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_activities_agent_id ON public.activities USING btree (agent_id);

--
-- Name: idx_activities_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_activities_started_at ON public.activities USING btree (started_at);

--
-- Name: idx_agent_keys_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_agent_keys_active ON public.agent_keys USING btree (agent_id, key_type) WHERE ((status)::text = 'active'::text);

--
-- Name: idx_agent_keys_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_keys_agent ON public.agent_keys USING btree (agent_id);

--
-- Name: idx_agent_keys_public_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_keys_public_key ON public.agent_keys USING btree (public_key);

--
-- Name: idx_agent_keys_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_keys_status ON public.agent_keys USING btree (status);

--
-- Name: idx_agent_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_parent ON public.agents USING btree (parent_agent_id);

--
-- Name: idx_agent_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_role ON public.agents USING btree (role);

--
-- Name: idx_agent_spans_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_agent ON public.agent_spans USING btree (agent_id);

--
-- Name: idx_agent_spans_consumed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_consumed ON public.agent_spans USING gin (consumed_ids);

--
-- Name: idx_agent_spans_generated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_generated ON public.agent_spans USING gin (generated_ids);

--
-- Name: idx_agent_spans_inflight; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_inflight ON public.agent_spans USING btree (status) WHERE (ended_at IS NULL);

--
-- Name: idx_agent_spans_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_name ON public.agent_spans USING btree (span_name);

--
-- Name: idx_agent_spans_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_parent ON public.agent_spans USING btree (parent_span_id) WHERE (parent_span_id IS NOT NULL);

--
-- Name: idx_agent_spans_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_session ON public.agent_spans USING btree (session_id);

--
-- Name: idx_agent_spans_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_started ON public.agent_spans USING btree (started_at DESC);

--
-- Name: idx_agent_spans_trace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_trace ON public.agent_spans USING btree (trace_id);

--
-- Name: idx_agent_spans_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_spans_user ON public.agent_spans USING btree (user_id);

--
-- Name: idx_agent_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_state ON public.agents USING btree (state);

--
-- Name: idx_agent_state_history_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_state_history_agent ON public.agent_state_history USING btree (agent_id);

--
-- Name: idx_agent_state_history_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_state_history_time ON public.agent_state_history USING btree (changed_at);

--
-- Name: idx_agents_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_created_at ON public.agents USING btree (created_at DESC);

--
-- Name: idx_agents_did_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_did_key ON public.agents USING btree (((properties ->> 'did_key'::text))) WHERE ((properties ->> 'did_key'::text) IS NOT NULL);

--
-- Name: INDEX idx_agents_did_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON INDEX public.idx_agents_did_key IS 'Fast lookup of agents by W3C did:key identifier (deterministic from ORCID or name hash)';

--
-- Name: idx_agents_display_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_display_name ON public.agents USING btree (display_name) WHERE (display_name IS NOT NULL);

--
-- Name: idx_agents_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_labels ON public.agents USING gin (labels);

--
-- Name: idx_agents_properties; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_properties ON public.agents USING gin (properties);

--
-- Name: idx_agents_public_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_agents_public_key ON public.agents USING btree (public_key);

--
-- Name: idx_analyses_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_agent ON public.analyses USING btree (agent_id);

--
-- Name: idx_analyses_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_created ON public.analyses USING btree (created_at DESC);

--
-- Name: idx_analyses_inference; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_inference ON public.analyses USING btree (inference_path);

--
-- Name: idx_analyses_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_type ON public.analyses USING btree (analysis_type);

--
-- Name: idx_challenges_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_challenges_claim ON public.challenges USING btree (claim_id);

--
-- Name: idx_challenges_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_challenges_state ON public.challenges USING btree (state);

--
-- Name: idx_claim_clusters_boundary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_clusters_boundary ON public.claim_clusters USING btree (boundary_ratio);

--
-- Name: idx_claim_clusters_cluster; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_clusters_cluster ON public.claim_clusters USING btree (cluster_id);

--
-- Name: idx_claim_clusters_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_clusters_run ON public.claim_clusters USING btree (cluster_run_id);

--
-- Name: idx_claim_frames_frame; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_frames_frame ON public.claim_frames USING btree (frame_id);

--
-- Name: idx_claim_themes_centroid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_themes_centroid ON public.claim_themes USING hnsw (centroid public.vector_cosine_ops) WITH (m='16', ef_construction='64') WHERE (centroid IS NOT NULL);

--
-- Name: idx_claim_versions_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_versions_claim ON public.claim_versions USING btree (claim_id);

--
-- Name: idx_claim_versions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claim_versions_created ON public.claim_versions USING btree (created_at);

--
-- Name: idx_claims_agent_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_agent_created ON public.claims USING btree (agent_id, created_at DESC);

--
-- Name: idx_claims_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_agent_id ON public.claims USING btree (agent_id);

--
-- Name: idx_claims_agent_truth; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_agent_truth ON public.claims USING btree (agent_id, truth_value DESC);

--
-- Name: idx_claims_content_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_content_hash ON public.claims USING btree (content_hash);

--
-- Name: idx_claims_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_created_at ON public.claims USING btree (created_at DESC);

--
-- Name: idx_claims_embedding_hnsw; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_embedding_hnsw ON public.claims USING hnsw (embedding public.vector_cosine_ops) WITH (m='16', ef_construction='64') WHERE (embedding IS NOT NULL);

--
-- Name: INDEX idx_claims_embedding_hnsw; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON INDEX public.idx_claims_embedding_hnsw IS 'HNSW index for fast vector similarity search. For datasets > 1M claims, consider migrating to IVFFlat with lists = sqrt(num_rows). Monitor query performance with EXPLAIN ANALYZE on semantic search queries.';

--
-- Name: idx_claims_high_truth; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_high_truth ON public.claims USING btree (truth_value DESC) WHERE (truth_value >= (0.7)::double precision);

--
-- Name: idx_claims_is_current; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_is_current ON public.claims USING btree (is_current) WHERE (is_current = true);

--
-- Name: idx_claims_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_labels ON public.claims USING gin (labels);

--
-- Name: idx_claims_low_truth; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_low_truth ON public.claims USING btree (truth_value) WHERE (truth_value <= (0.3)::double precision);

--
-- Name: idx_claims_methodology; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_methodology ON public.claims USING gin (((properties -> 'methodology'::text)));

--
-- Name: idx_claims_properties; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_properties ON public.claims USING gin (properties);

--
-- Name: idx_claims_signer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_signer_id ON public.claims USING btree (signer_id) WHERE (signer_id IS NOT NULL);

--
-- Name: idx_claims_supersedes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_supersedes ON public.claims USING btree (supersedes) WHERE (supersedes IS NOT NULL);

--
-- Name: idx_claims_theme; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_theme ON public.claims USING btree (theme_id);

--
-- Name: idx_claims_trace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_trace_id ON public.claims USING btree (trace_id) WHERE (trace_id IS NOT NULL);

--
-- Name: idx_claims_truth_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_truth_value ON public.claims USING btree (truth_value DESC);

--
-- Name: idx_claims_verified_with_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_claims_verified_with_embedding ON public.claims USING btree (truth_value DESC, created_at DESC) WHERE ((embedding IS NOT NULL) AND (truth_value >= (0.7)::double precision));

--
-- Name: idx_cluster_centroids_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cluster_centroids_run ON public.cluster_centroids USING btree (cluster_run_id);

--
-- Name: idx_contexts_modifier_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contexts_modifier_type ON public.contexts USING btree (modifier_type);

--
-- Name: idx_contexts_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contexts_type ON public.contexts USING btree (context_type);

--
-- Name: idx_counterfactual_claims; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_counterfactual_claims ON public.counterfactual_scenarios USING btree (claim_a_id, claim_b_id);

--
-- Name: idx_divergence_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_divergence_claim ON public.ds_bayesian_divergence USING btree (claim_id);

--
-- Name: idx_divergence_kl; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_divergence_kl ON public.ds_bayesian_divergence USING btree (kl_divergence DESC);

--
-- Name: idx_edges_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_created_at ON public.edges USING btree (created_at DESC);

--
-- Name: idx_edges_frame_validates; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_frame_validates ON public.edges USING btree (source_id, target_id) WHERE ((relationship)::text = 'frame_validates'::text);

--
-- Name: idx_edges_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_labels ON public.edges USING gin (labels);

--
-- Name: idx_edges_properties; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_properties ON public.edges USING gin (properties);

--
-- Name: idx_edges_relationship; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_relationship ON public.edges USING btree (relationship);

--
-- Name: idx_edges_signer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_signer_id ON public.edges USING btree (signer_id) WHERE (signer_id IS NOT NULL);

--
-- Name: idx_edges_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_source ON public.edges USING btree (source_id, source_type);

--
-- Name: idx_edges_source_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_source_target ON public.edges USING btree (source_id, target_id);

--
-- Name: idx_edges_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_target ON public.edges USING btree (target_id, target_type);

--
-- Name: idx_edges_temporal; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_temporal ON public.edges USING btree (valid_from, valid_to) WHERE (valid_from IS NOT NULL);

--
-- Name: idx_edges_typed_relationship; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edges_typed_relationship ON public.edges USING btree (source_type, relationship, target_type);

--
-- Name: idx_edges_unique_triple; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_edges_unique_triple ON public.edges USING btree (source_id, target_id, relationship);

--
-- Name: idx_entities_canonical_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entities_canonical_name ON public.entities USING btree (canonical_name);

--
-- Name: idx_entities_canonical_pair; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_entities_canonical_pair ON public.entities USING btree (lower(canonical_name), type_top) WHERE (is_canonical = true);

--
-- Name: idx_entities_embedding_hnsw; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entities_embedding_hnsw ON public.entities USING hnsw (embedding public.vector_cosine_ops) WITH (m='16', ef_construction='64') WHERE (embedding IS NOT NULL);

--
-- Name: idx_entities_is_canonical; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entities_is_canonical ON public.entities USING btree (is_canonical) WHERE (is_canonical = true);

--
-- Name: idx_entities_merged_into; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entities_merged_into ON public.entities USING btree (merged_into) WHERE (merged_into IS NOT NULL);

--
-- Name: idx_entities_type_top; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entities_type_top ON public.entities USING btree (type_top);

--
-- Name: idx_entity_mentions_claim_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_mentions_claim_id ON public.entity_mentions USING btree (claim_id);

--
-- Name: idx_entity_mentions_entity_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_mentions_entity_claim ON public.entity_mentions USING btree (entity_id, claim_id);

--
-- Name: idx_entity_mentions_entity_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_mentions_entity_id ON public.entity_mentions USING btree (entity_id);

--
-- Name: idx_events_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_created ON public.events USING btree (created_at DESC);

--
-- Name: idx_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_type ON public.events USING btree (event_type);

--
-- Name: idx_events_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_version ON public.events USING btree (graph_version);

--
-- Name: idx_evidence_claim_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_claim_id ON public.evidence USING btree (claim_id);

--
-- Name: idx_evidence_claim_signer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_claim_signer ON public.evidence USING btree (claim_id, signer_id) WHERE (signer_id IS NOT NULL);

--
-- Name: idx_evidence_claim_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_claim_type ON public.evidence USING btree (claim_id, evidence_type);

--
-- Name: idx_evidence_content_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_content_hash ON public.evidence USING btree (content_hash);

--
-- Name: idx_evidence_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_created_at ON public.evidence USING btree (created_at DESC);

--
-- Name: idx_evidence_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_embedding ON public.evidence USING hnsw (embedding public.vector_cosine_ops) WHERE (embedding IS NOT NULL);

--
-- Name: idx_evidence_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_labels ON public.evidence USING gin (labels);

--
-- Name: idx_evidence_properties; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_properties ON public.evidence USING gin (properties);

--
-- Name: idx_evidence_signed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_signed ON public.evidence USING btree (created_at DESC) WHERE (signature IS NOT NULL);

--
-- Name: idx_evidence_signer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_signer_id ON public.evidence USING btree (signer_id) WHERE (signer_id IS NOT NULL);

--
-- Name: idx_evidence_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_evidence_type ON public.evidence USING btree (evidence_type);

--
-- Name: idx_experiment_entities_name_type; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_experiment_entities_name_type ON public.experiment_entities USING btree (lower(canonical_name), entity_type);

--
-- Name: idx_experiment_entities_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_entities_type ON public.experiment_entities USING btree (entity_type);

--
-- Name: idx_experiment_mentions_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_mentions_claim ON public.experiment_entity_mentions USING btree (claim_id);

--
-- Name: idx_experiment_mentions_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_mentions_entity ON public.experiment_entity_mentions USING btree (entity_id);

--
-- Name: idx_experiment_triples_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_triples_claim ON public.experiment_triples USING btree (claim_id);

--
-- Name: idx_experiment_triples_object; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_triples_object ON public.experiment_triples USING btree (object_entity_id);

--
-- Name: idx_experiment_triples_predicate; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_triples_predicate ON public.experiment_triples USING btree (predicate);

--
-- Name: idx_experiment_triples_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_experiment_triples_subject ON public.experiment_triples USING btree (subject_entity_id);

--
-- Name: idx_factors_frame; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_factors_frame ON public.factors USING btree (frame_id) WHERE (frame_id IS NOT NULL);

--
-- Name: idx_factors_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_factors_type ON public.factors USING btree (factor_type);

--
-- Name: idx_factors_type_vars_frame; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_factors_type_vars_frame ON public.factors USING btree (factor_type, variable_ids, COALESCE(frame_id, '00000000-0000-0000-0000-000000000000'::uuid));

--
-- Name: idx_factors_variables; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_factors_variables ON public.factors USING gin (variable_ids);

--
-- Name: idx_frames_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_frames_name ON public.frames USING btree (name);

--
-- Name: idx_gap_analyses_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gap_analyses_created ON public.gap_analyses USING btree (created_at DESC);

--
-- Name: idx_harvester_audit_fragment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_audit_fragment ON public.harvester_audit_reports USING btree (fragment_id);

--
-- Name: idx_harvester_audit_passed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_audit_passed ON public.harvester_audit_reports USING btree (passed_audit) WHERE (passed_audit IS NOT NULL);

--
-- Name: idx_harvester_concepts_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_concepts_embedding ON public.harvester_enriched_concepts USING hnsw (embedding public.vector_cosine_ops);

--
-- Name: idx_harvester_concepts_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_concepts_name ON public.harvester_enriched_concepts USING btree (concept_name);

--
-- Name: idx_harvester_fragments_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_fragments_source ON public.harvester_fragments USING btree (source_id);

--
-- Name: idx_harvester_fragments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_fragments_status ON public.harvester_fragments USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));

--
-- Name: idx_harvester_provenance_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_provenance_claim ON public.harvester_claim_provenance USING btree (claim_id);

--
-- Name: idx_harvester_provenance_fragment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_provenance_fragment ON public.harvester_claim_provenance USING btree (fragment_id);

--
-- Name: idx_harvester_sources_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_sources_hash ON public.harvester_sources USING btree (content_hash);

--
-- Name: idx_harvester_sources_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_harvester_sources_status ON public.harvester_sources USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));

--
-- Name: idx_jobs_completed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_completed_at ON public.jobs USING btree (completed_at) WHERE ((state)::text = ANY ((ARRAY['completed'::character varying, 'failed'::character varying])::text[]));

--
-- Name: idx_jobs_pending_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_pending_created ON public.jobs USING btree (created_at) WHERE ((state)::text = 'pending'::text);

--
-- Name: idx_jobs_running_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_running_started ON public.jobs USING btree (started_at) WHERE ((state)::text = 'running'::text);

--
-- Name: idx_jobs_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_state ON public.jobs USING btree (state);

--
-- Name: idx_jobs_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_type ON public.jobs USING btree (job_type);

--
-- Name: idx_learning_events_challenge; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_learning_events_challenge ON public.learning_events USING btree (challenge_id);

--
-- Name: idx_learning_events_claims; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_learning_events_claims ON public.learning_events USING btree (conflict_claim_a, conflict_claim_b);

--
-- Name: idx_mass_functions_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mass_functions_claim ON public.mass_functions USING btree (claim_id);

--
-- Name: idx_mass_functions_frame; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mass_functions_frame ON public.mass_functions USING btree (frame_id);

--
-- Name: idx_merge_candidates_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_merge_candidates_status ON public.entity_merge_candidates USING btree (status) WHERE ((status)::text = 'pending'::text);

--
-- Name: idx_methods_canonical; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_methods_canonical ON public.methods USING btree (canonical_name);

--
-- Name: idx_methods_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_methods_embedding ON public.methods USING hnsw (embedding public.vector_cosine_ops) WITH (m='16', ef_construction='64');

--
-- Name: idx_methods_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_methods_type ON public.methods USING btree (technique_type);

--
-- Name: idx_oauth_clients_agent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_clients_agent_id ON public.oauth_clients USING btree (agent_id);

--
-- Name: idx_oauth_clients_owner_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_clients_owner_id ON public.oauth_clients USING btree (owner_id);

--
-- Name: idx_oauth_clients_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_clients_status ON public.oauth_clients USING btree (status);

--
-- Name: idx_oauth_clients_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_clients_type ON public.oauth_clients USING btree (client_type);

--
-- Name: idx_ownership_node_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_node_type ON public.ownership USING btree (node_type);

--
-- Name: idx_ownership_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_owner ON public.ownership USING btree (owner_id);

--
-- Name: idx_ownership_partition; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_partition ON public.ownership USING btree (partition_type);

--
-- Name: idx_perspectives_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_perspectives_owner ON public.perspectives USING btree (owner_agent_id);

--
-- Name: idx_provenance_log_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provenance_log_created ON public.provenance_log USING btree (created_at);

--
-- Name: idx_provenance_log_principal; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provenance_log_principal ON public.provenance_log USING btree (principal_id);

--
-- Name: idx_provenance_log_record; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provenance_log_record ON public.provenance_log USING btree (record_type, record_id);

--
-- Name: idx_provenance_log_submitted_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provenance_log_submitted_by ON public.provenance_log USING btree (submitted_by);

--
-- Name: idx_reasoning_traces_claim_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_claim_id ON public.reasoning_traces USING btree (claim_id);

--
-- Name: idx_reasoning_traces_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_confidence ON public.reasoning_traces USING btree (confidence DESC);

--
-- Name: idx_reasoning_traces_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_created_at ON public.reasoning_traces USING btree (created_at DESC);

--
-- Name: idx_reasoning_traces_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_labels ON public.reasoning_traces USING gin (labels);

--
-- Name: idx_reasoning_traces_properties; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_properties ON public.reasoning_traces USING gin (properties);

--
-- Name: idx_reasoning_traces_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reasoning_traces_type ON public.reasoning_traces USING btree (reasoning_type);

--
-- Name: idx_refresh_tokens_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_client ON public.refresh_tokens USING btree (client_id);

--
-- Name: idx_refresh_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_expires ON public.refresh_tokens USING btree (expires_at) WHERE (revoked_at IS NULL);

--
-- Name: idx_refresh_tokens_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_hash ON public.refresh_tokens USING btree (token_hash) WHERE (revoked_at IS NULL);

--
-- Name: idx_scoped_beliefs_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scoped_beliefs_claim ON public.ds_combined_beliefs USING btree (claim_id, scope_type);

--
-- Name: idx_scoped_beliefs_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scoped_beliefs_scope ON public.ds_combined_beliefs USING btree (scope_type, scope_id);

--
-- Name: idx_security_events_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_agent ON public.security_events USING btree (agent_id);

--
-- Name: idx_security_events_correlation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_correlation ON public.security_events USING btree (correlation_id);

--
-- Name: idx_security_events_failures; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_failures ON public.security_events USING btree (event_type, created_at) WHERE (success = false);

--
-- Name: idx_security_events_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_time ON public.security_events USING btree (created_at);

--
-- Name: idx_security_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_security_events_type ON public.security_events USING btree (event_type);

--
-- Name: idx_staging_relationship; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_staging_relationship ON public.edges_staging USING btree (relationship);

--
-- Name: idx_staging_review_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_staging_review_status ON public.edges_staging USING btree (review_status);

--
-- Name: idx_staging_similarity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_staging_similarity ON public.edges_staging USING btree ((((properties ->> 'similarity'::text))::double precision));

--
-- Name: idx_tasks_assigned; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_assigned ON public.tasks USING btree (assigned_agent);

--
-- Name: idx_tasks_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_parent ON public.tasks USING btree (parent_task_id);

--
-- Name: idx_tasks_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_priority ON public.tasks USING btree (priority DESC, created_at);

--
-- Name: idx_tasks_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_state ON public.tasks USING btree (state);

--
-- Name: idx_tasks_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_type ON public.tasks USING btree (task_type);

--
-- Name: idx_tasks_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tasks_workflow ON public.tasks USING btree (workflow_id);

--
-- Name: idx_trace_parents_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trace_parents_parent_id ON public.trace_parents USING btree (parent_id);

--
-- Name: idx_trace_parents_trace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trace_parents_trace_id ON public.trace_parents USING btree (trace_id);

--
-- Name: idx_traces_claim_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_traces_claim_type ON public.reasoning_traces USING btree (claim_id, reasoning_type);

--
-- Name: idx_traces_high_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_traces_high_confidence ON public.reasoning_traces USING btree (confidence DESC) WHERE (confidence >= (0.7)::double precision);

--
-- Name: idx_triples_claim_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_triples_claim_id ON public.triples USING btree (claim_id);

--
-- Name: idx_triples_object_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_triples_object_id ON public.triples USING btree (object_id) WHERE (object_id IS NOT NULL);

--
-- Name: idx_triples_predicate_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_triples_predicate_trgm ON public.triples USING gist (predicate public.gist_trgm_ops);

--
-- Name: idx_triples_subject_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_triples_subject_id ON public.triples USING btree (subject_id);

--
-- Name: idx_triples_subject_predicate; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_triples_subject_predicate ON public.triples USING btree (subject_id, predicate);

--
-- Name: idx_wf_exec_creator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_exec_creator ON public.workflow_executions USING btree (created_by);

--
-- Name: idx_wf_exec_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_exec_state ON public.workflow_executions USING btree (state);

--
-- Name: source_artifacts_agent_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX source_artifacts_agent_id_idx ON public.source_artifacts USING btree (agent_id);

--
-- Name: agents agents_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agents_cascade_edges BEFORE DELETE ON public.agents FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('agent');

--
-- Name: agents agents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agents_updated_at BEFORE UPDATE ON public.agents FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: analyses analyses_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER analyses_cascade_edges BEFORE DELETE ON public.analyses FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('analysis');

--
-- Name: claims claims_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER claims_cascade_edges BEFORE DELETE ON public.claims FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('claim');

--
-- Name: claims claims_deactivate_factors; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER claims_deactivate_factors AFTER UPDATE OF is_current ON public.claims FOR EACH ROW EXECUTE FUNCTION public.deactivate_superseded_factors();

--
-- Name: claims claims_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER claims_updated_at BEFORE UPDATE ON public.claims FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: edges edges_auto_factor; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER edges_auto_factor AFTER INSERT ON public.edges FOR EACH ROW EXECUTE FUNCTION public.auto_create_factor_from_edge();

--
-- Name: edges edges_validate_refs; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER edges_validate_refs BEFORE INSERT OR UPDATE ON public.edges FOR EACH ROW EXECUTE FUNCTION public.trigger_validate_edge_refs();

--
-- Name: evidence evidence_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER evidence_cascade_edges BEFORE DELETE ON public.evidence FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('evidence');

--
-- Name: ownership ownership_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER ownership_updated_at BEFORE UPDATE ON public.ownership FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: papers papers_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER papers_cascade_edges BEFORE DELETE ON public.papers FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('paper');

--
-- Name: provenance_log provenance_log_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER provenance_log_immutable BEFORE DELETE OR UPDATE ON public.provenance_log FOR EACH ROW EXECUTE FUNCTION public.raise_immutable_error();

--
-- Name: reasoning_traces traces_cascade_edges; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER traces_cascade_edges BEFORE DELETE ON public.reasoning_traces FOR EACH ROW EXECUTE FUNCTION public.cascade_delete_edges('trace');

--
-- Name: activities activities_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activities
    ADD CONSTRAINT activities_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);

--
-- Name: agent_capabilities agent_capabilities_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_capabilities
    ADD CONSTRAINT agent_capabilities_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

--
-- Name: agent_keys agent_keys_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_keys
    ADD CONSTRAINT agent_keys_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

--
-- Name: agent_keys agent_keys_revoked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_keys
    ADD CONSTRAINT agent_keys_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES public.agents(id);

--
-- Name: agent_spans agent_spans_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_spans
    ADD CONSTRAINT agent_spans_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);

--
-- Name: agent_spans agent_spans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_spans
    ADD CONSTRAINT agent_spans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.agents(id);

--
-- Name: agent_state_history agent_state_history_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_state_history
    ADD CONSTRAINT agent_state_history_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

--
-- Name: agent_state_history agent_state_history_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_state_history
    ADD CONSTRAINT agent_state_history_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.agents(id);

--
-- Name: agents agents_parent_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_parent_agent_id_fkey FOREIGN KEY (parent_agent_id) REFERENCES public.agents(id);

--
-- Name: analyses analyses_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyses
    ADD CONSTRAINT analyses_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);

--
-- Name: analysis_methods analysis_methods_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_methods
    ADD CONSTRAINT analysis_methods_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id);

--
-- Name: analysis_methods analysis_methods_method_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_methods
    ADD CONSTRAINT analysis_methods_method_id_fkey FOREIGN KEY (method_id) REFERENCES public.methods(id);

--
-- Name: authorization_votes authorization_votes_authorizer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_votes
    ADD CONSTRAINT authorization_votes_authorizer_id_fkey FOREIGN KEY (authorizer_id) REFERENCES public.authorizers(id);

--
-- Name: authorization_votes authorization_votes_voter_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_votes
    ADD CONSTRAINT authorization_votes_voter_client_id_fkey FOREIGN KEY (voter_client_id) REFERENCES public.oauth_clients(id);

--
-- Name: authorizers authorizers_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorizers
    ADD CONSTRAINT authorizers_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);

--
-- Name: bp_messages bp_messages_factor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bp_messages
    ADD CONSTRAINT bp_messages_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES public.factors(id) ON DELETE CASCADE;

--
-- Name: challenges challenges_challenger_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.challenges
    ADD CONSTRAINT challenges_challenger_id_fkey FOREIGN KEY (challenger_id) REFERENCES public.agents(id);

--
-- Name: challenges challenges_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.challenges
    ADD CONSTRAINT challenges_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id);

--
-- Name: challenges challenges_gap_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.challenges
    ADD CONSTRAINT challenges_gap_analysis_id_fkey FOREIGN KEY (gap_analysis_id) REFERENCES public.gap_analyses(id);

--
-- Name: challenges challenges_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.challenges
    ADD CONSTRAINT challenges_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES public.agents(id);

--
-- Name: claim_clusters claim_clusters_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_clusters
    ADD CONSTRAINT claim_clusters_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id);

--
-- Name: claim_frames claim_frames_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_frames
    ADD CONSTRAINT claim_frames_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: claim_frames claim_frames_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_frames
    ADD CONSTRAINT claim_frames_frame_id_fkey FOREIGN KEY (frame_id) REFERENCES public.frames(id) ON DELETE CASCADE;

--
-- Name: claim_versions claim_versions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claim_versions
    ADD CONSTRAINT claim_versions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.agents(id);

--
-- Name: claims claims_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE RESTRICT;

--
-- Name: claims claims_signer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_signer_id_fkey FOREIGN KEY (signer_id) REFERENCES public.agents(id) ON DELETE SET NULL;

--
-- Name: claims claims_supersedes_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_supersedes_fkey FOREIGN KEY (supersedes) REFERENCES public.claims(id);

--
-- Name: claims claims_theme_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_theme_id_fkey FOREIGN KEY (theme_id) REFERENCES public.claim_themes(id);

--
-- Name: claims claims_trace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.claims
    ADD CONSTRAINT claims_trace_id_fkey FOREIGN KEY (trace_id) REFERENCES public.reasoning_traces(id) ON DELETE SET NULL;

--
-- Name: community_members community_members_community_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.community_members
    ADD CONSTRAINT community_members_community_id_fkey FOREIGN KEY (community_id) REFERENCES public.communities(id) ON DELETE CASCADE;

--
-- Name: community_members community_members_perspective_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.community_members
    ADD CONSTRAINT community_members_perspective_id_fkey FOREIGN KEY (perspective_id) REFERENCES public.perspectives(id) ON DELETE CASCADE;

--
-- Name: counterfactual_scenarios counterfactual_scenarios_claim_a_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.counterfactual_scenarios
    ADD CONSTRAINT counterfactual_scenarios_claim_a_id_fkey FOREIGN KEY (claim_a_id) REFERENCES public.claims(id);

--
-- Name: counterfactual_scenarios counterfactual_scenarios_claim_b_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.counterfactual_scenarios
    ADD CONSTRAINT counterfactual_scenarios_claim_b_id_fkey FOREIGN KEY (claim_b_id) REFERENCES public.claims(id);

--
-- Name: ds_bayesian_divergence ds_bayesian_divergence_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_bayesian_divergence
    ADD CONSTRAINT ds_bayesian_divergence_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: ds_bayesian_divergence ds_bayesian_divergence_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_bayesian_divergence
    ADD CONSTRAINT ds_bayesian_divergence_frame_id_fkey FOREIGN KEY (frame_id) REFERENCES public.frames(id) ON DELETE CASCADE;

--
-- Name: ds_combined_beliefs ds_combined_beliefs_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ds_combined_beliefs
    ADD CONSTRAINT ds_combined_beliefs_frame_id_fkey FOREIGN KEY (frame_id) REFERENCES public.frames(id) ON DELETE CASCADE;

--
-- Name: edges edges_signer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edges
    ADD CONSTRAINT edges_signer_id_fkey FOREIGN KEY (signer_id) REFERENCES public.agents(id) ON DELETE SET NULL;

--
-- Name: entities entities_merged_into_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entities
    ADD CONSTRAINT entities_merged_into_fkey FOREIGN KEY (merged_into) REFERENCES public.entities(id) ON DELETE SET NULL;

--
-- Name: entity_mentions entity_mentions_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_mentions
    ADD CONSTRAINT entity_mentions_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: entity_mentions entity_mentions_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_mentions
    ADD CONSTRAINT entity_mentions_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.entities(id) ON DELETE RESTRICT;

--
-- Name: entity_merge_candidates entity_merge_candidates_entity_a_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_merge_candidates
    ADD CONSTRAINT entity_merge_candidates_entity_a_fkey FOREIGN KEY (entity_a) REFERENCES public.entities(id) ON DELETE CASCADE;

--
-- Name: entity_merge_candidates entity_merge_candidates_entity_b_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_merge_candidates
    ADD CONSTRAINT entity_merge_candidates_entity_b_fkey FOREIGN KEY (entity_b) REFERENCES public.entities(id) ON DELETE CASCADE;

--
-- Name: events events_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.agents(id);

--
-- Name: evidence evidence_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: evidence evidence_signer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_signer_id_fkey FOREIGN KEY (signer_id) REFERENCES public.agents(id) ON DELETE SET NULL;

--
-- Name: experiment_entity_mentions experiment_entity_mentions_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: experiment_entity_mentions experiment_entity_mentions_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;

--
-- Name: experiment_triples experiment_triples_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: experiment_triples experiment_triples_object_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_object_entity_id_fkey FOREIGN KEY (object_entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;

--
-- Name: experiment_triples experiment_triples_subject_entity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_subject_entity_id_fkey FOREIGN KEY (subject_entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;

--
-- Name: factors factors_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.factors
    ADD CONSTRAINT factors_frame_id_fkey FOREIGN KEY (frame_id) REFERENCES public.frames(id);

--
-- Name: authorization_votes fk_authorization_votes_provenance; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_votes
    ADD CONSTRAINT fk_authorization_votes_provenance FOREIGN KEY (provenance_log_id) REFERENCES public.provenance_log(id);

--
-- Name: learning_events fk_learning_events_challenge; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_events
    ADD CONSTRAINT fk_learning_events_challenge FOREIGN KEY (challenge_id) REFERENCES public.challenges(id);

--
-- Name: tasks fk_tasks_workflow; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT fk_tasks_workflow FOREIGN KEY (workflow_id) REFERENCES public.workflow_executions(id) ON DELETE CASCADE;

--
-- Name: frames frames_parent_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frames
    ADD CONSTRAINT frames_parent_frame_id_fkey FOREIGN KEY (parent_frame_id) REFERENCES public.frames(id);

--
-- Name: gap_analyses gap_analyses_analysis_a_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gap_analyses
    ADD CONSTRAINT gap_analyses_analysis_a_id_fkey FOREIGN KEY (analysis_a_id) REFERENCES public.analyses(id);

--
-- Name: gap_analyses gap_analyses_analysis_b_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gap_analyses
    ADD CONSTRAINT gap_analyses_analysis_b_id_fkey FOREIGN KEY (analysis_b_id) REFERENCES public.analyses(id);

--
-- Name: harvester_audit_reports harvester_audit_reports_fragment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_audit_reports
    ADD CONSTRAINT harvester_audit_reports_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE;

--
-- Name: harvester_claim_provenance harvester_claim_provenance_audit_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_audit_report_id_fkey FOREIGN KEY (audit_report_id) REFERENCES public.harvester_audit_reports(id) ON DELETE SET NULL;

--
-- Name: harvester_claim_provenance harvester_claim_provenance_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: harvester_claim_provenance harvester_claim_provenance_fragment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE;

--
-- Name: harvester_fragments harvester_fragments_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.harvester_fragments
    ADD CONSTRAINT harvester_fragments_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.harvester_sources(id) ON DELETE CASCADE;

--
-- Name: learning_events learning_events_conflict_claim_a_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_events
    ADD CONSTRAINT learning_events_conflict_claim_a_fkey FOREIGN KEY (conflict_claim_a) REFERENCES public.claims(id);

--
-- Name: learning_events learning_events_conflict_claim_b_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.learning_events
    ADD CONSTRAINT learning_events_conflict_claim_b_fkey FOREIGN KEY (conflict_claim_b) REFERENCES public.claims(id);

--
-- Name: mass_functions mass_functions_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: mass_functions mass_functions_frame_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_frame_id_fkey FOREIGN KEY (frame_id) REFERENCES public.frames(id) ON DELETE CASCADE;

--
-- Name: mass_functions mass_functions_perspective_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_perspective_id_fkey FOREIGN KEY (perspective_id) REFERENCES public.perspectives(id);

--
-- Name: mass_functions mass_functions_source_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mass_functions
    ADD CONSTRAINT mass_functions_source_agent_id_fkey FOREIGN KEY (source_agent_id) REFERENCES public.agents(id);

--
-- Name: method_capabilities method_capabilities_method_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.method_capabilities
    ADD CONSTRAINT method_capabilities_method_id_fkey FOREIGN KEY (method_id) REFERENCES public.methods(id);

--
-- Name: oauth_clients oauth_clients_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);

--
-- Name: oauth_clients oauth_clients_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.oauth_clients(id);

--
-- Name: oauth_clients oauth_clients_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.oauth_clients(id);

--
-- Name: ownership ownership_owner_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership
    ADD CONSTRAINT ownership_owner_fk FOREIGN KEY (owner_id) REFERENCES public.agents(id) ON DELETE CASCADE;

--
-- Name: perspectives perspectives_owner_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.perspectives
    ADD CONSTRAINT perspectives_owner_agent_id_fkey FOREIGN KEY (owner_agent_id) REFERENCES public.agents(id);

--
-- Name: provenance_log provenance_log_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_log
    ADD CONSTRAINT provenance_log_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.oauth_clients(id);

--
-- Name: provenance_log provenance_log_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_log
    ADD CONSTRAINT provenance_log_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES public.oauth_clients(id);

--
-- Name: reasoning_traces reasoning_traces_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reasoning_traces
    ADD CONSTRAINT reasoning_traces_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: refresh_tokens refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);

--
-- Name: security_events security_events_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);

--
-- Name: source_artifacts source_artifacts_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_artifacts
    ADD CONSTRAINT source_artifacts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

--
-- Name: tasks tasks_assigned_agent_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_assigned_agent_fkey FOREIGN KEY (assigned_agent) REFERENCES public.agents(id);

--
-- Name: tasks tasks_parent_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_parent_task_id_fkey FOREIGN KEY (parent_task_id) REFERENCES public.tasks(id);

--
-- Name: trace_parents trace_parents_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trace_parents
    ADD CONSTRAINT trace_parents_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.reasoning_traces(id) ON DELETE CASCADE;

--
-- Name: trace_parents trace_parents_trace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trace_parents
    ADD CONSTRAINT trace_parents_trace_id_fkey FOREIGN KEY (trace_id) REFERENCES public.reasoning_traces(id) ON DELETE CASCADE;

--
-- Name: triples triples_claim_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triples
    ADD CONSTRAINT triples_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;

--
-- Name: triples triples_object_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triples
    ADD CONSTRAINT triples_object_id_fkey FOREIGN KEY (object_id) REFERENCES public.entities(id) ON DELETE RESTRICT;

--
-- Name: triples triples_subject_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.triples
    ADD CONSTRAINT triples_subject_id_fkey FOREIGN KEY (subject_id) REFERENCES public.entities(id) ON DELETE RESTRICT;

--
-- Name: workflow_executions workflow_executions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.agents(id);

--
--

