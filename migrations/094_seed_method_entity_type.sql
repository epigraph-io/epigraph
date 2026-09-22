-- Migration 094: seed `method` as a CORE entity type (ADDITIVE, one row).
--
-- EVIDENCE
-- The kernel has owned `public.methods` since migration 001
-- (`CREATE TABLE public.methods`, `id uuid DEFAULT gen_random_uuid()`), and
-- method edges were writable under the old static CHECK
-- `edges_entity_types_valid` (migration 020), whose 20-type allowlist the
-- trigger in migration 025 mirrored.
--
-- Migration 054 seeded the `entity_types` registry with 23 rows — claim, agent,
-- evidence, trace, paper, analysis, activity, source_artifact, span, entity,
-- task, event, experiment, experiment_result, workflow, perspective, community,
-- context, frame, node, synthesis, coalition, propaganda_technique — and NO
-- `method` row. Migration 055 then DROPPED the static CHECK and replaced it with
-- `edges_source_type_fkey` / `edges_target_type_fkey` REFERENCES
-- entity_types(type_name).
--
-- Net effect: since 055, every edge with source_type or target_type = 'method'
-- is refused — for a table the kernel itself created. `git grep "'method'" --
-- migrations/` returns zero hits, confirming the row was never seeded anywhere
-- in this repo.
--
-- Two gates refuse it, and the ORDER matters for anyone diagnosing this from a
-- log. The backlog item named `edges_source_type_fkey`; measured on a fresh
-- migrated database with the row deleted, the actual first error is
-- `Edge source references nonexistent method`, because `validate_edge_reference`
-- is a BEFORE-INSERT trigger and its registry-driven `ELSE` arm (added by 055)
-- finds no backing table for an unregistered type. The FK fires only if the
-- trigger is bypassed. Both gates are satisfied by this one row.
--
-- DECISION
-- Seed the missing row, matching how 054 seeds the other kernel-owned types:
--   * schema/table/id_column = public.methods(id) — the table from 001;
--   * is_optional = false — the table is kernel-owned and always present, so a
--     dangling method reference must fail loud, not be tolerated. (Contrast
--     synthesis/coalition/propaganda_technique, which are is_optional=true
--     precisely because their backing tables live only in shared prod.)
--   * is_core = true — `EntityTypeRepository::register` carries
--     `WHERE entity_types.is_core = false`, so marking it core makes the row
--     API-immutable (the hijack guard) exactly like the other 23.
--
-- Downstream consequence, intended: episcience registers `method` as a
-- NON-core downstream row in its `5000_register_entity_types.sql` as a stopgap.
-- Its INSERT is `ON CONFLICT DO NOTHING`, so once this core row exists that
-- statement becomes a harmless no-op. Registering a kernel-owned table's type
-- from a product repo was the ownership smell this seed resolves.
--
-- WHY 094 AND NOT 056
-- The original backlog item said "056+". That is no longer available:
-- migrations/README.md RESERVES 060-090 for the multi-user tenancy series, and
-- 056-059 plus 091 and 093 are already taken on main. 094 is the first free
-- version.
--
-- IDEMPOTENT — AND IT ASSERTS ITS END STATE, NOT MERELY THE ROW'S PRESENCE
-- This migration originally used `ON CONFLICT (type_name) DO NOTHING`. That was
-- wrong, and MEASURED to be wrong, not hypothetically: on the local `epigraph`
-- database (at migration 59),
--   SELECT type_name, schema_name, table_name, id_column, is_optional, is_core
--     FROM entity_types WHERE type_name='method';
-- returns `method|public|methods|id|f|f` — the row ALREADY EXISTS with
-- is_core = FALSE, acquired from episcience's downstream stopgap
-- (episcience `migrations/5000_register_entity_types.sql`, which registers
-- ('method','public','methods','id',false,false)). On any such database
-- DO NOTHING makes this migration a silent no-op and leaves is_core = false —
-- while the DECISION section above claims the row is API-immutable because
-- `EntityTypeRepository::register` carries `WHERE entity_types.is_core = false`.
-- With DO NOTHING that hijack guard does not exist there: any client holding the
-- registry scope can re-point a kernel-owned table's type.
--
-- `ON CONFLICT (type_name) DO UPDATE` fixes that by asserting the END STATE,
-- which is correct whether or not the row pre-exists. Every column is set from
-- EXCLUDED rather than only is_core, because ownership of the type name is what
-- transfers: schema/table/id_column are what `validate_edge_reference`
-- interpolates, and a downstream row pointing them elsewhere is exactly the
-- ownership smell this seed resolves. In the one pre-existing shape actually
-- observed (episcience's) those three columns already match, so the update
-- narrows to is_core plus the description/registered_by provenance.
--
-- Deliberately NOT guarded on `WHERE is_core = false`: the statement must be
-- re-runnable to the same end state, and there is no state in which the kernel
-- wants its own `method` row left non-core.
--
-- PROD IS UNVERIFIED FROM THE DEV HOST. Do not assume either shape there. After
-- deploying, confirm the end state directly:
--   SELECT type_name, schema_name, table_name, id_column, is_optional, is_core
--     FROM entity_types WHERE type_name = 'method';   -- expect: … |f|t
-- and confirm `SELECT version FROM _sqlx_migrations WHERE version = 94` is
-- absent BEFORE migrating (the deprecating internal-main carries a DIFFERENT
-- 094_stop_truth_value_overwrite.sql; a checksum collision crash-loops the API).
--
-- The `validate_edge_reference` trigger needs no change: 'method' is absent from
-- its hardcoded fast-path arms and therefore resolves through the
-- registry-driven `ELSE` arm added by 055, which reads schema/table/id_column
-- from this very row. Verified by
-- `crates/epigraph-db/tests/method_entity_type_edge.rs`, which inserts a real
-- method->claim edge end-to-end (so both gates are exercised, not just the row's
-- presence) and includes a delete-the-row control that reproduces the refusal.

INSERT INTO entity_types (
    type_name, schema_name, table_name, id_column,
    is_optional, is_core, registered_by, description
)
VALUES (
    'method', 'public', 'methods', 'id',
    false, true, NULL,
    'Research method entity; kernel-owned public.methods (migration 001). '
    'Seeded core by kernel migration 094, superseding episcience''s '
    'non-core downstream stopgap registration.'
)
ON CONFLICT (type_name) DO UPDATE SET
    schema_name   = EXCLUDED.schema_name,
    table_name    = EXCLUDED.table_name,
    id_column     = EXCLUDED.id_column,
    is_optional   = EXCLUDED.is_optional,
    is_core       = EXCLUDED.is_core,
    registered_by = EXCLUDED.registered_by,
    description   = EXCLUDED.description,
    updated_at    = now();
