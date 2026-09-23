-- 060_group_tenancy_tables.sql
--
-- LIVE INCIDENT FIXED HERE: crates/epigraph-api/src/routes/claims.rs:841
-- (get_claim) and :1000 (list_claims) call
-- ClaimEncryptionRepository::get_by_claim_id_conn UNCONDITIONALLY, so on a stock
-- kernel database GET /api/v1/claims/:id and GET /claims return HTTP 500 for
-- EVERY claim. The kernel's own harness documents this at
-- crates/epigraph-api/tests/common/mod.rs and works around it with an FK-less,
-- CHECK-less stand-in. Both are deleted in this PR.
--
-- NOT created here, deliberately: embedding_shares and re_encryption_keys.
-- Their repos are DELETED in the same PR. On a database provisioned from the
-- epigraph-enterprise schema those two tables already exist with CASCADEing FKs
-- to groups and now have no owning code; they are tombstoned in
-- migrations/README.md and are scheduled for an explicit DROP inside the
-- reserved 060-085 range, NOT dropped here (dropping MPC share material
-- unattended is not a thing a migration should do).
--
-- HEADER NOTE (plan section 11, Completeness S10): group_memberships_role_check
-- constrains role to admin|writer|reader. PR-01 ALSO narrows
-- routes/groups.rs default_role()/valid_roles to the same vocabulary, so the
-- CHECK and the only write path that feeds it agree as of this commit. PR-02
-- still owns middleware/group_authz.rs (the dead 'creator' branch) and the
-- bootstrap-admin membership; neither can violate this CHECK.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- DRIFT GUARD. Run BEFORE any DDL.
--
-- Every CREATE TABLE below is `IF NOT EXISTS`, which is silent about a table
-- that exists in a DIFFERENT shape. epigraph-enterprise's
-- migrations/001_initial_schema.sql creates seven of these eight tables with:
--   * groups              lacking kind/status/properties/reseal_required_at/
--                         created_by_agent_id (7 columns, not 12)
--   * claim_encryption    lacking encrypted_properties, privacy_tier CHECK
--                         still admitting 'encrypted_content', and
--                         group_id FK ON DELETE CASCADE, not RESTRICT
--   * evidence_encryption lacking encrypted_properties, same tier CHECK
--   * edge_encryption     same tier CHECK, no epoch FK
--   * group_memberships   role DEFAULT 'writer', not 'reader'
--   * group_key_epochs    no epoch>=0, no FK to groups
-- On such a database an unguarded 060 either dies inside CREATE UNIQUE INDEX on
-- pre-existing duplicate rows (two 'active' epochs per group, which create_epoch
-- produces because it never retires its predecessor; or two live memberships per
-- (group, agent), which the enterprise UNIQUE (group_id, agent_id, epoch)
-- explicitly permits) -- or, worse, SUCCEEDS while applying none of its
-- guarantees, leaving RESTRICT/tier/least-privilege intentions silently unmet
-- and routes/claims.rs rejecting a tier the database still accepts.
--
-- We refuse loudly instead. Auto-repairing (retiring epochs, revoking
-- memberships) is a destructive write to someone's production rows and is an
-- operator decision, not a migration's. schema_contract.rs CANNOT catch this
-- class: #[sqlx::test] always builds a fresh database, where 060 created the
-- tables itself, so the only place the check can see a legacy database is here.
--
-- Sentinel per table = a constraint only THIS file creates. Re-running 060
-- against a database 060 already migrated finds every sentinel and is a no-op.
-- ===================================================================
DO $$
DECLARE
    rec record;
    -- Resolved into a variable first: SQL `AND` does not short-circuit, so
    -- inlining ('public.' || tbl)::regclass beside the IS NOT NULL test makes
    -- the guard itself raise 42P01 on the very databases where every table is
    -- legitimately absent (i.e. every fresh install).
    rel regclass;
BEGIN
    FOR rec IN
        SELECT * FROM (VALUES
            ('groups',                   'groups_kind_check'),
            ('group_key_epochs',         'group_key_epochs_epoch_nonneg'),
            ('group_memberships',        'group_memberships_epoch_nonneg'),
            ('claim_encryption',         'claim_encryption_epoch_nonneg'),
            ('claim_version_encryption', 'claim_version_encryption_epoch_nonneg'),
            ('evidence_encryption',      'evidence_encryption_epoch_nonneg'),
            ('edge_encryption',          'edge_encryption_epoch_nonneg')
        ) AS v(tbl, sentinel)
    LOOP
        rel := to_regclass('public.' || rec.tbl);
        IF rel IS NOT NULL
           AND NOT EXISTS (
               SELECT 1 FROM pg_constraint
                WHERE conrelid = rel
                  AND conname  = rec.sentinel)
        THEN
            RAISE EXCEPTION
                'migration 060: table public.% already exists in a pre-060 shape (constraint % is absent)',
                rec.tbl, rec.sentinel
              USING HINT =
                'This database was provisioned outside the public migration series '
                '(most likely from epigraph-enterprise 001_initial_schema.sql). '
                'Reconcile the table to the 060 shape by hand -- ALTER TABLE ... ADD COLUMN, '
                'drop and re-add the divergent CHECK/FK constraints, and resolve duplicate '
                'active epochs and duplicate live memberships -- then re-run this migration. '
                'Do NOT force past this by hand-inserting a _sqlx_migrations row: the '
                'RESTRICT FKs, the fully_private tier CHECK and the least-privilege '
                'membership default would all silently not exist.';
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- ROLES FIRST, AND GUARDED.
-- Roles are CLUSTER-scoped; databases are not. Verified counts: 8 crates and
-- 696 `#[sqlx::test]` occurrences, plus 15 direct `sqlx::migrate!` call sites,
-- each applying all migrations to its own template DB in one cluster. The
-- second one to reach an unguarded CREATE ROLE fails -- 42710 duplicate_object
-- when it merely lost, 23505 unique_violation when the two genuinely raced.
-- Both are caught below; see the note on the EXCEPTION arms.
-- Roles are created HERE, not in the RLS migration, because 070's seed arm
-- calls pg_has_role(session_user,'epigraph_seed','MEMBER'), and pg_has_role on
-- a NONEXISTENT role RAISES 42704 rather than returning false.
-- On managed Postgres the migration role has neither SUPERUSER nor CREATEROLE,
-- so the DO block catches insufficient_privilege and only NOTICEs; the fatal
-- check moves to AppState::with_db in PR-17.
-- ===================================================================
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['epigraph_app','epigraph_maintenance','epigraph_seed'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I NOLOGIN', r);
            EXCEPTION
                WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Cannot CREATE ROLE %: provision it out of band before deploying PR-17.', r;
                -- Both arms below are "lost a race with a parallel test DB".
                -- CreateRole() does a get_role_oid pre-check and THEN inserts
                -- into pg_authid, so two backends that both pass the pre-check
                -- leave the loser failing on pg_authid_rolname_index -> 23505
                -- unique_violation, NOT 42710 duplicate_object. Catching only
                -- duplicate_object leaves the actual race unhandled.
                WHEN duplicate_object THEN NULL;
                WHEN unique_violation THEN NULL;
            END;
        END IF;
    END LOOP;
END $$;
-- Every GRANT/REVOKE anywhere in 060..080 is likewise wrapped in
--   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epigraph_app') THEN ... END IF;
-- because an unguarded GRANT to a missing role hard-fails the migration.
-- (060 itself issues no GRANT.)

CREATE TABLE IF NOT EXISTS public.groups (
    id                  uuid DEFAULT gen_random_uuid() NOT NULL,
    display_name        character varying(255),
    did_key             text NOT NULL,
    public_key          bytea NOT NULL,
    pre_public_key      bytea,
    -- KERNEL ADDITION: routes/groups.rs logs creator_agent_id and persists it
    -- nowhere, leaving no basis to reconstruct a bootstrap admin.
    created_by_agent_id uuid,
    -- KERNEL ADDITION: only kind='team' carries key material.
    kind                character varying(16) DEFAULT 'team' NOT NULL,
    status              character varying(16) DEFAULT 'active' NOT NULL,
    properties          jsonb DEFAULT '{}'::jsonb NOT NULL,   -- holds kms_key_ref (section 6.5.6)
    reseal_required_at  timestamptz,                          -- section 6.7
    created_at          timestamp with time zone DEFAULT now() NOT NULL,
    updated_at          timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_did_key_key UNIQUE (did_key),
    CONSTRAINT groups_kind_check   CHECK (kind IN ('world','personal','community','team','seed')),
    CONSTRAINT groups_status_check CHECK (status IN ('active','suspended','deprovisioned')),
    CONSTRAINT groups_public_key_shape CHECK (
        (kind = 'team' AND octet_length(public_key) = 32)
     OR (kind <> 'team' AND octet_length(public_key) = 0)),
    CONSTRAINT groups_created_by_fkey FOREIGN KEY (created_by_agent_id)
        REFERENCES public.agents(id) ON DELETE SET NULL
);
-- groups_created_by_fkey is ON DELETE SET NULL, so DELETE FROM agents scans
-- this column. groups is small, but an unindexed FK referencing the busiest
-- parent table in the schema is a cheap thing to get right now.
CREATE INDEX IF NOT EXISTS idx_groups_created_by_agent
    ON public.groups (created_by_agent_id);
DROP TRIGGER IF EXISTS groups_updated_at ON public.groups;
CREATE TRIGGER groups_updated_at BEFORE UPDATE ON public.groups
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Deprovisioning is a status transition, never a DELETE. Every FK below
-- CASCADEs from groups, so one DELETE FROM groups would hard-delete every
-- membership, epoch and ciphertext.
CREATE OR REPLACE FUNCTION public.epigraph_block_group_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(current_setting('epigraph.allow_group_delete', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'refusing DELETE FROM groups (id=%). Set groups.status = ''deprovisioned''. To force: SET LOCAL epigraph.allow_group_delete = ''yes''.', OLD.id;
    END IF;
    RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS groups_block_delete ON public.groups;
CREATE TRIGGER groups_block_delete BEFORE DELETE ON public.groups
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_block_group_delete();

CREATE TABLE IF NOT EXISTS public.group_key_epochs (
    id          uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id    uuid NOT NULL,
    epoch       integer NOT NULL,
    wrapped_key bytea,
    status      character varying(20) DEFAULT 'active' NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    retired_at  timestamp with time zone,
    CONSTRAINT group_key_epochs_pkey PRIMARY KEY (id),
    CONSTRAINT group_key_epochs_group_id_epoch_key UNIQUE (group_id, epoch),
    CONSTRAINT group_key_epochs_status_check CHECK (status IN ('active','rotating','retired')),
    -- epoch is i32 in the repos but u32 in crypto: epigraph-crypto/src/epoch.rs
    -- does epoch.to_le_bytes() on u32.
    CONSTRAINT group_key_epochs_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT group_key_epochs_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE
);
-- Nothing enforced at-most-one active epoch, and create_epoch
-- (repos/group_key_epoch.rs) never retires its predecessor; get_active_epoch
-- masks duplicates with ORDER BY epoch DESC LIMIT 1.
--
-- ROTATION CONTRACT (binding on whoever implements rotation): with this index
-- in place, `create_epoch` inserting a second row at status='active' raises
-- 23505. Rotation MUST therefore run `retire_epoch(N)` and `create_epoch(N+1)`
-- inside ONE transaction, retire first. There is no rotation caller today --
-- create_group inserts epoch 0 and nothing else ever inserts -- so nothing
-- regresses here; the index exists so that the first rotation implementation
-- cannot quietly produce the ambiguous state get_active_epoch was masking.
CREATE UNIQUE INDEX IF NOT EXISTS group_key_epochs_one_active
    ON public.group_key_epochs (group_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_group_key_epochs_group_status
    ON public.group_key_epochs (group_id, status);

CREATE TABLE IF NOT EXISTS public.group_memberships (
    id                uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id          uuid NOT NULL,
    agent_id          uuid NOT NULL,
    -- repos/group_membership.rs binds Vec<u8>, not Option<Vec<u8>>.
    wrapped_key_share bytea NOT NULL,
    epoch             integer NOT NULL,
    -- ONE role vocabulary: admin|writer|reader. routes/groups.rs is narrowed to
    -- the same three in this PR (it previously defaulted to 'member', which
    -- VIOLATES this CHECK and turned the documented happy path into 23514 -> 500).
    -- middleware/group_authz.rs still honours admin|creator; 'creator' is
    -- UNSTORABLE here, so that branch is unreachable dead code -- harmless, and
    -- PR-02 removes it.
    role              character varying(20) DEFAULT 'reader' NOT NULL,
    joined_at         timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at        timestamp with time zone,
    CONSTRAINT group_memberships_pkey PRIMARY KEY (id),
    CONSTRAINT group_memberships_group_id_agent_id_epoch_key UNIQUE (group_id, agent_id, epoch),
    CONSTRAINT group_memberships_role_check  CHECK (role IN ('admin','writer','reader')),
    CONSTRAINT group_memberships_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT group_memberships_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT group_memberships_agent_id_fkey FOREIGN KEY (agent_id)
        REFERENCES public.agents(id) ON DELETE CASCADE
);
-- get_member_role (repos/group_membership.rs) has NO ORDER BY. Once rotation
-- inserts a second row per agent at epoch N+1 (which the UNIQUE above permits)
-- admin authorization becomes nondeterministic. At most one live row makes its
-- LIMIT 1 deterministic without touching the repo.
--
-- ROTATION CONTRACT: this makes the epoch component of
-- group_memberships_group_id_agent_id_epoch_key unreachable for LIVE rows --
-- you can never hold two. Re-wrapping a member at epoch N+1 must therefore
-- either UPDATE the live row's (epoch, wrapped_key_share) in place, or set
-- revoked_at on the epoch-N row in the same transaction as the epoch-N+1
-- insert. The composite UNIQUE still does real work for revoked history.
CREATE UNIQUE INDEX IF NOT EXISTS group_memberships_one_live
    ON public.group_memberships (group_id, agent_id) WHERE revoked_at IS NULL;
-- The hot path: "which live groups is this agent in?" -- one index-only scan
-- per request in Viewer::resolve (PR-04).
CREATE INDEX IF NOT EXISTS idx_group_memberships_agent_live
    ON public.group_memberships (agent_id, group_id, role) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_group_memberships_group ON public.group_memberships (group_id);

CREATE TABLE IF NOT EXISTS public.claim_encryption (
    claim_id             uuid NOT NULL,
    group_id             uuid NOT NULL,
    epoch                integer NOT NULL,
    privacy_tier         character varying(20) NOT NULL,
    encrypted_content    bytea NOT NULL,
    encrypted_labels     bytea,
    encrypted_properties bytea,          -- section 6.5.6 TCB: claims.properties
    created_at           timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT claim_encryption_pkey PRIMARY KEY (claim_id),
    -- 'encrypted_content' is NOT accepted as a tier: it stored the PLAINTEXT in
    -- claims.content next to the ciphertext (routes/claims.rs), feeding
    -- content_tsv (migration 050, GENERATED ALWAYS + GIN) and the BLAKE3
    -- content_hash. routes/claims.rs validate_privacy_fields is narrowed in the
    -- same PR so that tier 400s instead of 23514-ing into a 500.
    CONSTRAINT claim_encryption_privacy_tier_check CHECK (privacy_tier = 'fully_private'),
    CONSTRAINT claim_encryption_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT claim_encryption_claim_id_fkey FOREIGN KEY (claim_id)
        REFERENCES public.claims(id) ON DELETE CASCADE,
    -- RESTRICT, not the enterprise CASCADE: ciphertext must not evaporate.
    CONSTRAINT claim_encryption_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT claim_encryption_epoch_fkey FOREIGN KEY (group_id, epoch)
        REFERENCES public.group_key_epochs (group_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_claim_encryption_group ON public.claim_encryption (group_id);

-- The section 6.5.6 seal TCB needs more ciphertext homes. Created here so
-- schema_contract covers them from day one and PR-21 adds no DDL.
-- No repository exists for this one yet (grep ClaimVersionEncryption -> 0 hits).
CREATE TABLE IF NOT EXISTS public.claim_version_encryption (
    claim_version_id  uuid PRIMARY KEY REFERENCES public.claim_versions(id) ON DELETE CASCADE,
    claim_id          uuid NOT NULL REFERENCES public.claims(id) ON DELETE CASCADE,
    group_id          uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    -- Named, not inline-anonymous: a later ALTER TABLE ... DROP CONSTRAINT must
    -- not have to guess at a server-generated name, and the drift guard above
    -- uses these names as its sentinels. Same for evidence_encryption and
    -- edge_encryption below; the other four tables already named theirs.
    epoch             integer NOT NULL CONSTRAINT claim_version_encryption_epoch_nonneg CHECK (epoch >= 0),
    encrypted_content bytea NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT claim_version_encryption_epoch_fkey FOREIGN KEY (group_id, epoch)
        REFERENCES public.group_key_epochs (group_id, epoch)
);
-- Both FK columns need an index, and the PK on claim_version_id covers neither.
-- claim_id CASCADEs from claims (the largest table in the schema, exercised by
-- crates/epigraph-db/tests/cascade_delete_tests.rs) and would otherwise force a
-- seq scan per DELETE; (group_id, epoch) serves both the RESTRICT FK to groups
-- and the composite FK to group_key_epochs. The other three ciphertext tables
-- get idx_*_encryption_group; this one had nothing.
CREATE INDEX IF NOT EXISTS idx_claim_version_encryption_claim
    ON public.claim_version_encryption (claim_id);
CREATE INDEX IF NOT EXISTS idx_claim_version_encryption_group
    ON public.claim_version_encryption (group_id, epoch);

-- Column set is dictated by EvidenceEncryptionRepository: it SELECTs
-- evidence_id, group_id, epoch, privacy_tier, encrypted_content,
-- encrypted_labels, created_at and INSERTs the same. encrypted_properties is
-- the section 6.5.6 addition.
CREATE TABLE IF NOT EXISTS public.evidence_encryption (
    evidence_id          uuid PRIMARY KEY REFERENCES public.evidence(id) ON DELETE CASCADE,
    group_id             uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    epoch                integer NOT NULL CONSTRAINT evidence_encryption_epoch_nonneg CHECK (epoch >= 0),
    privacy_tier         character varying(20) NOT NULL,
    encrypted_content    bytea NOT NULL,
    encrypted_labels     bytea,
    encrypted_properties bytea,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evidence_encryption_privacy_tier_check CHECK (privacy_tier = 'fully_private'),
    CONSTRAINT evidence_encryption_epoch_fkey FOREIGN KEY (group_id, epoch)
        REFERENCES public.group_key_epochs (group_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_evidence_encryption_group ON public.evidence_encryption (group_id);

-- edge_encryption has zero callers today but a live repository; created so
-- repos/edge_encryption.rs stops being a runtime landmine. Column set from
-- repos/edge_encryption.rs (edge_id, group_id, epoch, privacy_tier,
-- encrypted_labels, encrypted_properties, created_at). Same RESTRICT correction.
CREATE TABLE IF NOT EXISTS public.edge_encryption (
    edge_id              uuid PRIMARY KEY REFERENCES public.edges(id) ON DELETE CASCADE,
    group_id             uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    epoch                integer NOT NULL CONSTRAINT edge_encryption_epoch_nonneg CHECK (epoch >= 0),
    privacy_tier         character varying(20) NOT NULL,
    encrypted_labels     bytea,
    encrypted_properties bytea,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT edge_encryption_privacy_tier_check CHECK (privacy_tier = 'fully_private'),
    CONSTRAINT edge_encryption_epoch_fkey FOREIGN KEY (group_id, epoch)
        REFERENCES public.group_key_epochs (group_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_edge_encryption_group ON public.edge_encryption (group_id);

-- pattern_templates: MUST be created. PatternTemplateRepository is re-exported
-- UNCONDITIONALLY from crates/epigraph-db/src/lib.rs:85 (via repos/mod.rs:136),
-- so it is part of every build of epigraph-db and cannot be deleted alongside
-- the MPC repos.
-- Correction to an earlier note here and to the plan: the callers in
-- crates/epigraph-api/src/routes/isomorphism.rs do NOT make this load-bearing.
-- That module is #[cfg(all(feature = "db", feature = "episcience"))]
-- (routes/mod.rs:61) and `cargo check -p epigraph-api --features episcience`
-- does not compile in this checkout at all -- E0432 unresolved import
-- epigraph_isomorphism, because the dependency is commented out in Cargo.toml.
-- The route is also not registered.
CREATE TABLE IF NOT EXISTS public.pattern_templates (
    id             uuid DEFAULT gen_random_uuid() NOT NULL,
    name           character varying(255) NOT NULL,
    category       character varying(50) NOT NULL,
    description    text,
    skeleton       jsonb NOT NULL,
    min_confidence double precision DEFAULT 0.7 NOT NULL,
    created_at     timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pattern_templates_pkey PRIMARY KEY (id),
    CONSTRAINT pattern_templates_name_key UNIQUE (name)
);
