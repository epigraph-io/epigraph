-- ===================================================================
-- 001-restore-missing-tables.sql
--
-- Creates the eight tables that `migrations/001_initial_schema.sql` defines
-- but that are ABSENT from a database provisioned outside the public migration
-- series. On such a database `_sqlx_migrations` claims 001 was applied
-- (execution_time = 0 -- the row was inserted by hand, the SQL never ran), so
-- sqlx will never create them, and migrations 062/070/071/072/074/076/077/079
-- /089 then ALTER tables that do not exist.
--
-- RUN IT IMMEDIATELY BEFORE `epigraph-migrate`, after 060-pre-reconcile.sql.
--
-- The tables are created EMPTY. That is correct: on this database they never
-- existed, so there is nothing to carry over. Four of the eight
-- (harvester_fragments, harvester_claim_provenance, experiment_triples,
-- experiment_entity_mentions) are what the tenancy series touches; the other
-- four are included because they are the FK targets of those, and creating a
-- table without its foreign keys is its own divergence.
--
-- PROVENANCE: dumped with `pg_dump --schema-only` from a reference database
-- built by applying migrations 001-059 to an empty cluster, so it is the
-- repository's own DDL rather than hand-written. Every FK target is either
-- inside this set or `public.claims`.
--
-- IDEMPOTENT via the transaction + IF NOT EXISTS rewrite below; re-running on a
-- database that already has these tables is a no-op.
-- ===================================================================

-- Idempotency is a psql \if on a sentinel table rather than IF NOT EXISTS on
-- every statement: the ADD CONSTRAINT clauses below have no IF NOT EXISTS form,
-- so a second run would abort on a duplicate constraint. All eight tables are
-- created together or not at all.
SELECT NOT EXISTS (
    SELECT 1 FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = 'harvester_fragments'
) AS need_restore \gset

\if :need_restore
BEGIN;
SET LOCAL lock_timeout = '3s';


\restrict z8JMM6cmoyoIEV1CTSc3Hb6AGkNocW2AXMoGvuduHqwDDNaXvw6jK3s2bW6Fdvm






CREATE TABLE IF NOT EXISTS public.experiment_entities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    canonical_name text NOT NULL,
    entity_type character varying(50) NOT NULL,
    aliases text[] DEFAULT '{}'::text[],
    embedding public.vector(1536),
    properties jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);



CREATE TABLE IF NOT EXISTS public.experiment_entity_mentions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    claim_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    surface_form text NOT NULL,
    mention_role character varying(20) DEFAULT 'context'::character varying NOT NULL,
    confidence double precision DEFAULT 1.0 NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);



CREATE TABLE IF NOT EXISTS public.experiment_triples (
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



CREATE TABLE IF NOT EXISTS public.harvester_audit_reports (
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



COMMENT ON TABLE public.harvester_audit_reports IS 'Council of Critics audit results per fragment extraction';



CREATE TABLE IF NOT EXISTS public.harvester_claim_provenance (
    claim_id uuid NOT NULL,
    fragment_id uuid NOT NULL,
    audit_report_id uuid,
    extraction_confidence double precision,
    CONSTRAINT harvester_provenance_confidence_bounds CHECK (((extraction_confidence IS NULL) OR ((extraction_confidence >= (0.0)::double precision) AND (extraction_confidence <= (1.0)::double precision))))
);



COMMENT ON TABLE public.harvester_claim_provenance IS 'Links extracted claims to source fragments and audit trails';



CREATE TABLE IF NOT EXISTS public.harvester_enriched_concepts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    concept_name text NOT NULL,
    canonical_name text,
    latent_definition text,
    source_model text,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);



COMMENT ON TABLE public.harvester_enriched_concepts IS 'Concepts enriched with latent knowledge and embeddings';



CREATE TABLE IF NOT EXISTS public.harvester_fragments (
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



COMMENT ON TABLE public.harvester_fragments IS 'Text fragments chunked from source documents';



CREATE TABLE IF NOT EXISTS public.harvester_sources (
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



COMMENT ON TABLE public.harvester_sources IS 'Source documents submitted for harvester extraction';



ALTER TABLE ONLY public.experiment_entities
    ADD CONSTRAINT experiment_entities_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.harvester_audit_reports
    ADD CONSTRAINT harvester_audit_reports_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_pkey PRIMARY KEY (claim_id, fragment_id);



ALTER TABLE ONLY public.harvester_enriched_concepts
    ADD CONSTRAINT harvester_enriched_concepts_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.harvester_fragments
    ADD CONSTRAINT harvester_fragments_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.harvester_sources
    ADD CONSTRAINT harvester_sources_content_hash_key UNIQUE (content_hash);



ALTER TABLE ONLY public.harvester_sources
    ADD CONSTRAINT harvester_sources_pkey PRIMARY KEY (id);



CREATE UNIQUE INDEX idx_experiment_entities_name_type ON public.experiment_entities USING btree (lower(canonical_name), entity_type);



CREATE INDEX idx_experiment_entities_type ON public.experiment_entities USING btree (entity_type);



CREATE INDEX idx_experiment_mentions_claim ON public.experiment_entity_mentions USING btree (claim_id);



CREATE INDEX idx_experiment_mentions_entity ON public.experiment_entity_mentions USING btree (entity_id);



CREATE INDEX idx_experiment_triples_claim ON public.experiment_triples USING btree (claim_id);



CREATE INDEX idx_experiment_triples_object ON public.experiment_triples USING btree (object_entity_id);



CREATE INDEX idx_experiment_triples_predicate ON public.experiment_triples USING btree (predicate);



CREATE INDEX idx_experiment_triples_subject ON public.experiment_triples USING btree (subject_entity_id);



CREATE INDEX idx_harvester_audit_fragment ON public.harvester_audit_reports USING btree (fragment_id);



CREATE INDEX idx_harvester_audit_passed ON public.harvester_audit_reports USING btree (passed_audit) WHERE (passed_audit IS NOT NULL);



CREATE INDEX idx_harvester_concepts_embedding ON public.harvester_enriched_concepts USING hnsw (embedding public.vector_cosine_ops);



CREATE INDEX idx_harvester_concepts_name ON public.harvester_enriched_concepts USING btree (concept_name);



CREATE INDEX idx_harvester_fragments_source ON public.harvester_fragments USING btree (source_id);



CREATE INDEX idx_harvester_fragments_status ON public.harvester_fragments USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));



CREATE INDEX idx_harvester_provenance_claim ON public.harvester_claim_provenance USING btree (claim_id);



CREATE INDEX idx_harvester_provenance_fragment ON public.harvester_claim_provenance USING btree (fragment_id);



CREATE INDEX idx_harvester_sources_hash ON public.harvester_sources USING btree (content_hash);



CREATE INDEX idx_harvester_sources_status ON public.harvester_sources USING btree (status) WHERE (status = ANY (ARRAY['pending'::text, 'processing'::text]));



ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.experiment_entity_mentions
    ADD CONSTRAINT experiment_entity_mentions_entity_id_fkey FOREIGN KEY (entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_object_entity_id_fkey FOREIGN KEY (object_entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.experiment_triples
    ADD CONSTRAINT experiment_triples_subject_entity_id_fkey FOREIGN KEY (subject_entity_id) REFERENCES public.experiment_entities(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.harvester_audit_reports
    ADD CONSTRAINT harvester_audit_reports_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_audit_report_id_fkey FOREIGN KEY (audit_report_id) REFERENCES public.harvester_audit_reports(id) ON DELETE SET NULL;



ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.claims(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.harvester_claim_provenance
    ADD CONSTRAINT harvester_claim_provenance_fragment_id_fkey FOREIGN KEY (fragment_id) REFERENCES public.harvester_fragments(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.harvester_fragments
    ADD CONSTRAINT harvester_fragments_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.harvester_sources(id) ON DELETE CASCADE;



\unrestrict z8JMM6cmoyoIEV1CTSc3Hb6AGkNocW2AXMoGvuduHqwDDNaXvw6jK3s2bW6Fdvm

COMMIT;
\echo '001-restore-missing-tables: created 8 tables from the 001 schema.'
\else
\echo '001-restore-missing-tables: tables already present -- no-op.'
\endif
