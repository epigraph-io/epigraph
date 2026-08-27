-- 062_tenancy_columns.sql -- no table rewrite. Does NOT rewrite claims.
-- PR-04 of the multi-user tenancy series. Plan §3/061, shipped as 062.
-- STAGE 1 OF TWO. Every DEFAULT below is a transition artifact and is DROPped
-- by migration 074 (plan's 071). Idempotent so a lock_timeout abort is retried
-- by re-running the file (sqlx records no row for a failed migration).
--
-- LOCK PROFILE -- READ THIS BEFORE RUNNING IT ON A LIVE CLUSTER.
-- `ADD COLUMN ... NOT NULL DEFAULT ...` is metadata-only on PostgreSQL 11+, so
-- no table is rewritten (measured: 3.5 ms on a 5,000,000-row / 1028 MB `claims`
-- clone, `pg_relation_size` unchanged). That is about DURATION, not about
-- LOCKS. Each `ALTER TABLE` still takes ACCESS EXCLUSIVE, sqlx wraps this whole
-- file in ONE transaction, and a lock is held until COMMIT -- so by the last
-- table this migration holds ACCESS EXCLUSIVE on 25 tables SIMULTANEOUSLY,
-- `claims` among them. `lock_timeout` below bounds how long each ALTER WAITS,
-- not how long the transaction HOLDS: worst case is a series of 3-second stalls
-- on new queries against each table, then a rollback and a restart from table 1.
-- Run it in a quiet window and expect to retry. Pre-check with:
--   SELECT max(now() - xact_start) FROM pg_stat_activity
--    WHERE state <> 'idle' AND datname = current_database();
SET LOCAL lock_timeout = '3s';

-- DRIFT GUARD (mirrors 060/061). ADD COLUMN IF NOT EXISTS is silent about a
-- column that already exists in a DIFFERENT shape, and a nullable
-- claims.visibility would make every later predicate silently drop rows.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT table_name, column_name, data_type, is_nullable
               FROM information_schema.columns
              WHERE table_schema='public'
                AND column_name IN ('owner_group_id','visibility')
    LOOP
        IF (r.column_name='owner_group_id' AND (r.data_type<>'uuid' OR r.is_nullable<>'NO'))
        OR (r.column_name='visibility' AND (r.data_type<>'character varying' OR r.is_nullable<>'NO'))
        THEN RAISE EXCEPTION
            'public.%.% already exists in a shape 062 did not create (data_type=%, is_nullable=%). Reconcile by hand, then re-run.',
            r.table_name, r.column_name, r.data_type, r.is_nullable;
        END IF;
    END LOOP;
END $$;

-- The world group. Nil UUID so it is unmistakable in a psql dump. It is a
-- SHAPE CONSTANT and nothing more -- it is NOT the owner of public content
-- (plan §2.3), and after migration 074 nothing may own anything with it. It has
-- no group_memberships rows, by design. kind<>'team' => groups_public_key_shape
-- (migration 060:164) requires octet_length(public_key)=0, hence ''::bytea.
-- ON CONFLICT DO NOTHING (not ON CONFLICT (id)): groups_did_key_key is a second
-- unique constraint and a pre-existing row under either one must be tolerated.
INSERT INTO public.groups (id, display_name, did_key, public_key, kind)
VALUES ('00000000-0000-0000-0000-000000000000'::uuid,
        'world', 'did:epigraph:world', ''::bytea, 'world')
ON CONFLICT DO NOTHING;
INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
VALUES ('00000000-0000-0000-0000-000000000000'::uuid, 0, NULL, 'active')
ON CONFLICT DO NOTHING;

-- The SEED group. Migration 074 arm 4 stamps THIS, never world, so that
-- plan §8.2 A4 (count(*) FROM claims WHERE owner_group_id = world must be 0)
-- and the deferred strong CHECK (owner_group_id <> world) are both achievable
-- on a database where the test suite has run.
INSERT INTO public.groups (id, display_name, did_key, public_key, kind)
VALUES ('00000000-0000-0000-0000-00000000dead'::uuid,
        'seed', 'did:epigraph:seed', ''::bytea, 'seed')
ON CONFLICT DO NOTHING;
INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
VALUES ('00000000-0000-0000-0000-00000000dead'::uuid, 0, NULL, 'active')
ON CONFLICT DO NOTHING;

-- ===================================================================
-- Tier-A widening. The array is the plan §2.4 generator's output at 3948445,
-- pinned so the migration is deterministic; tenancy_coverage.rs (PR-05) re-runs
-- the generator at test time and fails the build if the two ever diverge.
-- All 25 tables verified present in the migrated schema.
--
-- THE 25 FKs BELOW ARE UNINDEXED, DELIBERATELY. Each is `ON DELETE RESTRICT`
-- to groups(id), and PostgreSQL's RI check for a RESTRICT parent delete is an
-- unqualified `owner_group_id = $1` lookup on the child. The only partial
-- indexes leading on owner_group_id (063-065) predicate on `visibility`, so
-- none can serve it: a DELETE FROM groups would be 25 sequential scans, one on
-- `claims`, inside the deleting transaction with row locks held throughout.
-- That is acceptable ONLY because migration 060's trigger blocks
-- DELETE FROM groups outright. Taking its documented escape hatch
-- (`SET LOCAL epigraph.allow_group_delete = 'yes'`) is therefore a
-- MAINTENANCE-WINDOW operation with a stated table-scan cost -- see
-- docs/deploy.md. A deprovisioning path that needs to be online must first add
-- plain `(owner_group_id)` indexes on the tables it touches.
-- ===================================================================
DO $$
DECLARE t text;
        tier_a text[] := ARRAY[
          -- roots
          'claims','evidence','edges',
          -- claim-derived (Generator A: information_schema, column_name='claim_id')
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          -- Generator B misses this one: no claim_id, no FK. Registered by hand.
          'harvester_fragments',
          -- D1 roots
          'frames','contexts','perspectives','communities',
          -- keyed on the QUERYING agent, not on a claim
          'recall_events'
        ];
BEGIN
    FOREACH t IN ARRAY tier_a LOOP
        EXECUTE format(
          'ALTER TABLE public.%I
             ADD COLUMN IF NOT EXISTS owner_group_id uuid NOT NULL
               DEFAULT ''00000000-0000-0000-0000-000000000000''::uuid,
             ADD COLUMN IF NOT EXISTS visibility character varying(16)
               NOT NULL DEFAULT ''public''', t);
        -- ADD CONSTRAINT has no IF NOT EXISTS; guard on the catalog.
        -- CONRELID-QUALIFIED, always. pg_constraint.conname is unique per
        -- RELATION, not per database, so a bare `WHERE conname = ...` lookup is
        -- satisfied by a same-named constraint on ANY other table in ANY schema
        -- -- and this migration would then silently skip creating the real one.
        -- The tests that check these constraints share the same blind spot, so
        -- the guard and its check could never disagree. Both were fixed.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_visibility_check') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I
                 CHECK (visibility IN (''public'',''group'')) NOT VALID',
              t, t || '_visibility_check');
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_owner_group_fkey') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (owner_group_id)
                 REFERENCES public.groups(id) ON DELETE RESTRICT NOT VALID',
              t, t || '_owner_group_fkey');
        END IF;
        -- THE PAIRING INVARIANT. A 'group'-visible row owned by the world group
        -- is a BLACK HOLE: world has no group_memberships rows by design, so
        -- owner_group_id = ANY(<viewer groups>) can never match and NOBODY,
        -- including the author, can read it back. A TABLE CHECK, not only an RLS
        -- WITH CHECK arm: WITH CHECK is inert for the table owner until 079's
        -- FORCE and inert entirely for the maintenance role.
        --
        -- THE SEED GROUP IS EXCLUDED FOR THE IDENTICAL REASON. It has no
        -- group_memberships rows either, by design (see its INSERT above), so
        -- ('group', seed) is the same black hole -- and it is the *likelier*
        -- one, because migration 074 arm 4 deliberately stamps seed as the owner
        -- of legacy rows. Those rows are and stay `visibility = 'public'`, which
        -- this CHECK permits; what it forbids is ever pairing seed with 'group'.
        -- If a future PR wants group-visible content owned by seed, it must
        -- first give seed real memberships and then DROP this arm explicitly.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = t || '_group_needs_real_group') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (
                  visibility <> ''group''
                  OR owner_group_id NOT IN (
                       ''00000000-0000-0000-0000-000000000000''::uuid,
                       ''00000000-0000-0000-0000-00000000dead''::uuid)
               ) NOT VALID', t, t || '_group_needs_real_group');
        END IF;
    END LOOP;
END $$;

-- TIER B (identity): agents stay readable so authorship renders on a public
-- claim, but agents.properties holds full_name / orcid / affiliations / email
-- (migration 001). Declare the exemption out loud rather than by omission.
-- This is the column plan §2.4 describes as existing and §3.1 never scheduled.
ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS profile_visibility character varying(16)
        NOT NULL DEFAULT 'public';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.agents'::regclass
                      AND conname = 'agents_profile_visibility_check')
    THEN ALTER TABLE public.agents ADD CONSTRAINT agents_profile_visibility_check
             CHECK (profile_visibility IN ('public','group')) NOT VALID; END IF;
END $$;

-- agents gains a default write target. key_kind shipped in 061; the statements
-- below no-op against a database that has it (they exist so 062 is complete
-- against a database that somehow skipped 061).
ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS default_group_id uuid,
    ADD COLUMN IF NOT EXISTS key_kind character varying(16) NOT NULL DEFAULT 'ed25519';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.agents'::regclass
                      AND conname = 'agents_default_group_fkey')
    THEN ALTER TABLE public.agents ADD CONSTRAINT agents_default_group_fkey
             FOREIGN KEY (default_group_id) REFERENCES public.groups(id)
             ON DELETE SET NULL; END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.agents'::regclass
                      AND conname = 'agents_key_kind_check')
    THEN ALTER TABLE public.agents ADD CONSTRAINT agents_key_kind_check
             CHECK (key_kind IN ('ed25519','derived')) NOT VALID; END IF;
END $$;
-- agents_default_group_fkey is ON DELETE SET NULL, so DELETE FROM groups scans
-- this column; groups is blocked from DELETE by 060's trigger, but the index is
-- cheap and the FK is unindexed otherwise.
CREATE INDEX IF NOT EXISTS idx_agents_default_group
    ON public.agents (default_group_id) WHERE default_group_id IS NOT NULL;

-- Resumable backfill progress. DEMOTED TO OBSERVABILITY: migration 075's guard
-- is LIVE COUNTS, not this table's boolean, because a boolean `complete` flag is
-- hand-flippable by an on-call trying to unblock a deploy at 2 a.m.
CREATE TABLE IF NOT EXISTS public.tenancy_backfill_progress (
    entity     text PRIMARY KEY,
    last_id    uuid,
    rows_done  bigint NOT NULL DEFAULT 0,
    complete   boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);
-- Seeded from the SAME tier_a array above. (The plan also names
-- 'personal_groups', which is not a table in this tree and is not seeded.)
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['claims','evidence','edges','triples','entity_mentions',
        'claim_versions','mass_functions','ds_combined_beliefs','ds_bayesian_divergence',
        'claim_frames','harvester_claim_provenance','challenges','reasoning_traces',
        'experiment_triples','experiment_entity_mentions','claim_clusters',
        'claim_cluster_membership','claim_neighborhood_membership',
        'claim_signature_revocations','harvester_fragments','frames','contexts',
        'perspectives','communities','recall_events'] LOOP
        INSERT INTO public.tenancy_backfill_progress (entity) VALUES (t)
        ON CONFLICT (entity) DO NOTHING;
    END LOOP;
END $$;

-- The undeclared-write counter (ops F10). Migration 070's transition trigger
-- bumps this instead of silently inheriting, and plan §9.2's deploy gate
-- requires it FLAT FOR 24 HOURS before migration 074 runs.
CREATE TABLE IF NOT EXISTS public.tenancy_undeclared_writes (
    table_name text NOT NULL,
    day        date NOT NULL DEFAULT current_date,
    n          bigint NOT NULL DEFAULT 0,
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (table_name, day)
);

-- Transcription ledger. Migration 084 REFUSES to DROP TABLE ownership unless
-- every non-public ownership row has a row here. to_group_id carries the FK
-- every other group reference in this migration carries: without it a row
-- naming a group that does not exist would SATISFY that gate, which is exactly
-- the failure the gate exists to catch.
CREATE TABLE IF NOT EXISTS public.tenancy_transcription_log (
    node_id        uuid PRIMARY KEY,
    node_type      text NOT NULL,
    from_partition text NOT NULL,
    to_visibility  text NOT NULL,
    to_group_id    uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    transcribed_at timestamp with time zone NOT NULL DEFAULT now()
);
-- CREATE TABLE IF NOT EXISTS is silent about a table that already exists in the
-- pre-FK shape (a database that ran an earlier draft of this file), so add the
-- constraint separately as well. Guarded on the COLUMN, not on a constraint
-- name: the inline REFERENCES above is auto-named
-- `tenancy_transcription_log_to_group_id_fkey`, so a name guard would miss it
-- and add a duplicate FK on every fresh database.
DO $$
DECLARE col smallint;
BEGIN
    SELECT attnum INTO col FROM pg_attribute
     WHERE attrelid = 'public.tenancy_transcription_log'::regclass
       AND attname = 'to_group_id' AND NOT attisdropped;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.tenancy_transcription_log'::regclass
                      AND contype = 'f' AND conkey = ARRAY[col])
    THEN ALTER TABLE public.tenancy_transcription_log
             ADD CONSTRAINT tenancy_transcription_log_to_group_id_fkey
             FOREIGN KEY (to_group_id) REFERENCES public.groups(id)
             ON DELETE RESTRICT; END IF;
END $$;

COMMENT ON COLUMN public.claims.visibility IS
  'public|group. DEFAULT ''public'' is a TRANSITION ARTIFACT dropped by migration 074.';
COMMENT ON COLUMN public.claims.owner_group_id IS
  'FK groups(id). DEFAULT = the world group, a SHAPE CONSTANT, not an owner. Dropped by migration 074.';
