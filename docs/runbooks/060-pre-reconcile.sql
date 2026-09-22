-- ===================================================================
-- 060-pre-reconcile.sql — bring an enterprise-provisioned database to the
-- shape migration 060 expects, WITHOUT losing the rows already in it.
--
-- WHY THIS IS A RUNBOOK AND NOT A MIGRATION
-- ------------------------------------------------------------------
-- It must run BETWEEN 059 and 060, and sqlx migration versions are integers
-- parsed from the filename: there is no version between 59 and 60. Folding
-- this into 060 itself is worse -- it would change 060's checksum and every
-- database that has already applied it would fail
-- `validate_applied_migrations` on next boot.
--
-- So this is the path 060's own HINT prescribes:
--     "Reconcile the table to the 060 shape by hand -- ALTER TABLE ...
--      ADD COLUMN, drop and re-add the divergent CHECK/FK constraints ...
--      then re-run this migration."
--
-- RUN IT IMMEDIATELY BEFORE `epigraph-migrate`, against a database whose
-- ledger head is 59.
--
-- WHAT IT REFUSES TO DO
-- ------------------------------------------------------------------
-- 060's hint also says, and this script obeys it:
--     "Do NOT force past this by hand-inserting a _sqlx_migrations row: the
--      RESTRICT FKs, the fully_private tier CHECK and the least-privilege
--      membership default would all silently not exist."
-- Every one of those three is established below, explicitly.
--
-- IDEMPOTENT. Safe to re-run; safe on a database that is already 060-shaped
-- (every step is catalog-guarded and becomes a no-op), and safe on a fresh
-- install where these tables do not exist yet (§0.1 exits early).
--
-- CONSTRAINT GUARDS ARE conrelid-QUALIFIED, ALWAYS. `pg_constraint.conname`
-- is unique per RELATION, not per database; a bare `WHERE conname = ...`
-- lookup is satisfied by a same-named constraint on any other table and this
-- script would then silently skip creating the real one. That exact bug is
-- documented in migration 062.
-- ===================================================================

\set ON_ERROR_STOP on

BEGIN;

-- Fail fast rather than queue behind a long-running writer. This script takes
-- ACCESS EXCLUSIVE on small tables only; if it cannot get them promptly the
-- deploy window is not actually quiet and the operator needs to know.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- §0  PRE-FLIGHTS
--     Everything here RAISEs. A step that "logs and proceeds" converts a
--     data-loss decision into a silent one.
-- ===================================================================

-- §0.1 Nothing to reconcile on a fresh install: 060 will CREATE all eight
--      tables itself. Bail out cleanly rather than ALTER a missing table.
DO $$
BEGIN
    IF to_regclass('public.groups') IS NULL THEN
        RAISE NOTICE '060-pre-reconcile: public.groups absent -- fresh install, nothing to do.';
    END IF;
END $$;

-- §0.2 The unique index the composite epoch FKs in §4-§6 point at. A FK to
--      (group_id, epoch) cannot be created without it, and the failure mode is
--      a confusing 42830 rather than anything that names this cause.
-- The existence test is NESTED, not conjoined. SQL `AND` does not
-- short-circuit, so `to_regclass(...) IS NOT NULL AND NOT EXISTS (<subquery
-- naming that relation>)` still evaluates the subquery and raises 42P01 on
-- exactly the fresh installs the guard is there to skip. Migration 060
-- documents this same trap; it is easy to reintroduce.
DO $$
BEGIN
    IF to_regclass('public.group_key_epochs') IS NULL THEN RETURN; END IF;

    IF NOT EXISTS (
           SELECT 1 FROM pg_index i
            WHERE i.indrelid = 'public.group_key_epochs'::regclass
              AND i.indisunique
              AND i.indkey::int2[] @> ARRAY[
                    (SELECT attnum FROM pg_attribute
                      WHERE attrelid='public.group_key_epochs'::regclass AND attname='group_id'),
                    (SELECT attnum FROM pg_attribute
                      WHERE attrelid='public.group_key_epochs'::regclass AND attname='epoch')]::int2[])
    THEN
        RAISE EXCEPTION
            '060-pre-reconcile: group_key_epochs has no UNIQUE index on (group_id, epoch)'
          USING HINT = 'The composite epoch FKs cannot be created. Add: '
                       'CREATE UNIQUE INDEX group_key_epochs_group_id_epoch_key '
                       'ON public.group_key_epochs (group_id, epoch);';
    END IF;
END $$;

-- §0.3 `groups_public_key_shape` (added in §1) is the one new CHECK that can
--      reject EXISTING rows: team groups must carry a 32-byte key, non-team
--      groups an empty one. §1 assigns kind='team' to every pre-existing row
--      (see the note there), so every pre-existing row must have a 32-byte key.
--
-- SCOPED TO THE UNRECONCILED CASE, deliberately. Once 060 has run, `kind`
-- exists and non-team groups (world, seed, personal) legitimately carry a
-- ZERO-length key -- so a blanket "every group is 32 bytes" assertion is true
-- only before reconciliation, and re-running this script would fail on the
-- groups 060 itself created. Presence of `kind` is the discriminator: if it is
-- there, this database is already past the point this check guards.
DO $$
DECLARE n bigint;
BEGIN
    IF to_regclass('public.groups') IS NULL THEN RETURN; END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema='public' AND table_name='groups' AND column_name='kind')
    THEN RETURN; END IF;

    SELECT count(*) INTO n FROM public.groups WHERE octet_length(public_key) <> 32;
    IF n > 0 THEN
        RAISE EXCEPTION
            '060-pre-reconcile: % group(s) have a public_key that is not 32 bytes; groups_public_key_shape would reject them', n
          USING HINT = 'Inspect: SELECT id, did_key, octet_length(public_key) FROM public.groups '
                       'WHERE octet_length(public_key) <> 32;  A non-team group must have a '
                       'ZERO-length key. Decide each row''s kind by hand before re-running.';
    END IF;
END $$;

-- §0.4 The partial UNIQUE indexes 060 creates (group_key_epochs_one_active,
--      group_memberships_one_live) will fail on pre-existing duplicates. 060's
--      hint calls these out by name. Check them HERE, where the message can
--      say what to do, rather than letting 060 fail with a bare 23505.
DO $$
DECLARE n bigint;
BEGIN
    IF to_regclass('public.group_key_epochs') IS NOT NULL THEN
        SELECT count(*) INTO n FROM (
            SELECT group_id FROM public.group_key_epochs
             WHERE status = 'active' GROUP BY group_id HAVING count(*) > 1) d;
        IF n > 0 THEN
            RAISE EXCEPTION '060-pre-reconcile: % group(s) have more than one ACTIVE key epoch', n
              USING HINT = 'group_key_epochs_one_active is UNIQUE. Retire the superseded epochs '
                           '(status=''retired'') before re-running.';
        END IF;
    END IF;

    IF to_regclass('public.group_memberships') IS NOT NULL THEN
        SELECT count(*) INTO n FROM (
            SELECT group_id, agent_id FROM public.group_memberships
             WHERE revoked_at IS NULL GROUP BY group_id, agent_id HAVING count(*) > 1) d;
        IF n > 0 THEN
            RAISE EXCEPTION '060-pre-reconcile: % (group, agent) pair(s) have more than one LIVE membership', n
              USING HINT = 'group_memberships_one_live is UNIQUE. Revoke the superseded rows '
                           '(set revoked_at) before re-running.';
        END IF;
    END IF;
END $$;

-- §0.5 THE ONE DECISION THIS SCRIPT WILL NOT MAKE FOR YOU.
--
-- 060 narrows privacy_tier to 'fully_private' ONLY. The enterprise schema also
-- admitted 'encrypted_content', and that tier is not a weaker cipher -- per
-- 060's own comment it "stored the PLAINTEXT in claims.content next to the
-- ciphertext", feeding content_tsv (migration 050, GENERATED ALWAYS + GIN) and
-- the BLAKE3 content_hash. A row on that tier is therefore NOT sealed: its
-- content is readable, indexed, and embeddable.
--
-- Two dispositions, both defensible, with different consequences. Choose one
-- explicitly by setting the GUC before running this script:
--
--   SET epigraph.reconcile_tier = 'drop_encryption_rows';
--       DELETEs the claim/evidence/edge_encryption rows on that tier. The
--       claims themselves are untouched and stay exactly as readable as they
--       already are -- the deleted row was providing no confidentiality. The
--       ciphertext blob is discarded (it remains in backups).
--
--   SET epigraph.reconcile_tier = 'keep_wide_check';
--       Leaves the wider CHECK in place on this database. 060's GUARD STILL
--       PASSES -- its sentinel is *_epoch_nonneg, not the tier check -- so the
--       deploy proceeds, but this database KNOWINGLY diverges from 060 and
--       `fully_private` is not enforced. Record it as an accepted divergence.
--
-- There is deliberately no 'seal' option. Converting a row to fully_private
-- means destroying the plaintext in claims.content, nulling both embedding
-- columns and reconciling content_hash -- a privatization operation, not a
-- schema reconciliation. Use the privatization flow for that.
-- Counted per-table through EXECUTE, for the §0.2 reason: a static UNION over
-- three relations is parsed as a whole, so it raises 42P01 on a fresh install
-- where none of them exist yet.
DO $$
DECLARE n bigint := 0; k bigint; t text; choice text;
BEGIN
    FOREACH t IN ARRAY ARRAY['claim_encryption','evidence_encryption','edge_encryption'] LOOP
        CONTINUE WHEN to_regclass('public.' || t) IS NULL;
        EXECUTE format('SELECT count(*) FROM public.%I WHERE privacy_tier <> ''fully_private''', t)
           INTO k;
        n := n + k;
    END LOOP;

    IF n = 0 THEN RETURN; END IF;   -- nothing on the legacy tier: no decision needed

    choice := current_setting('epigraph.reconcile_tier', true);
    IF choice IS NULL OR choice NOT IN ('drop_encryption_rows','keep_wide_check') THEN
        RAISE EXCEPTION
            '060-pre-reconcile: % row(s) are on the legacy ''encrypted_content'' tier; an explicit disposition is required', n
          USING HINT = 'Read §0.5 of this file, then re-run with either '
                       'SET epigraph.reconcile_tier = ''drop_encryption_rows''; or '
                       'SET epigraph.reconcile_tier = ''keep_wide_check'';';
    END IF;
    RAISE NOTICE '060-pre-reconcile: % legacy-tier row(s), disposition = %', n, choice;
END $$;

-- ===================================================================
-- §1  groups  — 7 columns -> 12, plus the four constraints 060 defines
-- ===================================================================
-- kind DEFAULT 'team' is load-bearing, not cosmetic. Every pre-existing
-- enterprise group is a real keyed group (§0.3 proved all carry a 32-byte
-- public_key), and 'team' is the only kind whose groups_public_key_shape arm
-- accepts a 32-byte key. Assigning any other kind here would reject them.
-- Wrapped in a DO block, not written as a bare ALTER: on a fresh install
-- `public.groups` does not exist yet and a bare ALTER raises 42P01 -- which
-- would make this script fail on exactly the databases that need none of it.
DO $$
BEGIN
    IF to_regclass('public.groups') IS NULL THEN RETURN; END IF;

    ALTER TABLE public.groups
        ADD COLUMN IF NOT EXISTS created_by_agent_id uuid,
        ADD COLUMN IF NOT EXISTS kind                character varying(16) NOT NULL DEFAULT 'team',
        ADD COLUMN IF NOT EXISTS status              character varying(16) NOT NULL DEFAULT 'active',
        ADD COLUMN IF NOT EXISTS properties          jsonb NOT NULL DEFAULT '{}'::jsonb,
        ADD COLUMN IF NOT EXISTS reseal_required_at  timestamp with time zone;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.groups'::regclass AND conname='groups_kind_check') THEN
        ALTER TABLE public.groups ADD CONSTRAINT groups_kind_check
            CHECK (kind IN ('world','personal','community','team','seed'));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.groups'::regclass AND conname='groups_status_check') THEN
        ALTER TABLE public.groups ADD CONSTRAINT groups_status_check
            CHECK (status IN ('active','suspended','deprovisioned'));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.groups'::regclass AND conname='groups_public_key_shape') THEN
        ALTER TABLE public.groups ADD CONSTRAINT groups_public_key_shape
            CHECK ((kind =  'team' AND octet_length(public_key) = 32)
                OR (kind <> 'team' AND octet_length(public_key) =  0));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.groups'::regclass AND conname='groups_created_by_fkey') THEN
        ALTER TABLE public.groups ADD CONSTRAINT groups_created_by_fkey
            FOREIGN KEY (created_by_agent_id) REFERENCES public.agents(id) ON DELETE SET NULL;
    END IF;
END $$;

-- ===================================================================
-- §2  group_key_epochs  — the 060 sentinel
-- ===================================================================
DO $$
BEGIN
    IF to_regclass('public.group_key_epochs') IS NULL THEN RETURN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.group_key_epochs'::regclass
                      AND conname='group_key_epochs_epoch_nonneg') THEN
        ALTER TABLE public.group_key_epochs
            ADD CONSTRAINT group_key_epochs_epoch_nonneg CHECK (epoch >= 0);
    END IF;
END $$;

-- ===================================================================
-- §3  group_memberships  — sentinel + THE LEAST-PRIVILEGE DEFAULT
-- ===================================================================
-- The enterprise schema defaults `role` to 'writer'. 060 defaults it to
-- 'reader'. This is one of the three things 060's hint says would "silently
-- not exist" if you forced past the guard -- an omitted role on an INSERT
-- would grant write access instead of read access. Existing rows keep their
-- stored role; only the default for future inserts changes.
DO $$
BEGIN
    IF to_regclass('public.group_memberships') IS NULL THEN RETURN; END IF;

    ALTER TABLE public.group_memberships ALTER COLUMN role SET DEFAULT 'reader';

    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid='public.group_memberships'::regclass
                      AND conname='group_memberships_epoch_nonneg') THEN
        ALTER TABLE public.group_memberships
            ADD CONSTRAINT group_memberships_epoch_nonneg CHECK (epoch >= 0);
    END IF;
END $$;

-- ===================================================================
-- §4-§6  the three *_encryption tables
--        Same three corrections on each: the missing column, the RESTRICT FK,
--        the composite epoch FK, the sentinel, and the tier CHECK.
-- ===================================================================
-- ON DELETE RESTRICT, not the enterprise CASCADE. 060's own words:
-- "ciphertext must not evaporate." Under CASCADE, deleting a group silently
-- destroys every sealed payload that group holds.
DO $$
DECLARE
    t         text;
    choice    text := current_setting('epigraph.reconcile_tier', true);
    has_content boolean;
BEGIN
    FOREACH t IN ARRAY ARRAY['claim_encryption','evidence_encryption','edge_encryption'] LOOP
        CONTINUE WHEN to_regclass('public.' || t) IS NULL;

        -- 6.5.6 TCB column; edge_encryption has no encrypted_content but does
        -- take encrypted_properties, so this is unconditional.
        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS encrypted_properties bytea', t);

        -- CASCADE -> RESTRICT on the group FK.
        IF EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = format('public.%I', t)::regclass
                      AND conname  = t || '_group_id_fkey'
                      AND confdeltype = 'c')          -- 'c' = CASCADE
        THEN
            EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', t, t || '_group_id_fkey');
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname  = t || '_group_id_fkey')
        THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (group_id) '
              'REFERENCES public.groups(id) ON DELETE RESTRICT', t, t || '_group_id_fkey');
        END IF;

        -- Composite epoch FK: a payload must name an epoch its group actually has.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname  = t || '_epoch_fkey')
        THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (group_id, epoch) '
              'REFERENCES public.group_key_epochs(group_id, epoch)', t, t || '_epoch_fkey');
        END IF;

        -- The 060 sentinel. Adding this is what makes 060's guard pass.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname  = t || '_epoch_nonneg')
        THEN
            EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (epoch >= 0)',
                           t, t || '_epoch_nonneg');
        END IF;

        -- Tier CHECK, per the §0.5 disposition.
        IF choice = 'drop_encryption_rows' THEN
            EXECUTE format('DELETE FROM public.%I WHERE privacy_tier <> ''fully_private''', t);
        END IF;

        IF choice IS DISTINCT FROM 'keep_wide_check' THEN
            EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE privacy_tier <> ''fully_private'')', t)
               INTO has_content;
            IF NOT has_content THEN
                EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT IF EXISTS %I',
                               t, t || '_privacy_tier_check');
                EXECUTE format(
                  'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (privacy_tier = ''fully_private'')',
                  t, t || '_privacy_tier_check');
            END IF;
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- §7  VERIFY — 060's own guard predicate, run here so a failure is reported
--     by THIS script with context, not by the migrator as a bare abort.
-- ===================================================================
DO $$
DECLARE rec record; rel regclass; missing text := '';
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
           AND NOT EXISTS (SELECT 1 FROM pg_constraint
                            WHERE conrelid = rel AND conname = rec.sentinel)
        THEN missing := missing || ' ' || rec.tbl;
        END IF;
    END LOOP;

    IF missing <> '' THEN
        RAISE EXCEPTION '060-pre-reconcile: FAILED -- 060 would still refuse on:%', missing;
    END IF;
    RAISE NOTICE '060-pre-reconcile: OK -- every 060 sentinel present or table absent. Safe to run epigraph-migrate.';
END $$;

COMMIT;
