-- 068_communities_to_groups.sql
-- PR-05 of the multi-user tenancy series. Plan §3/064, shipped as 068 (see
-- migrations/README.md — THAT table is authoritative, not the plan's §3.1).
--
-- Resolves the collision the audit flagged: ownership.encryption_key_id is a
-- text column whose NAME and whose intended consumer both mean "key id", but
-- which TODAY holds a stringified COMMUNITY UUID --
--   crates/epigraph-db/src/repos/ownership.rs:101
--     let encryption_key_id = community_id.map(|id| id.to_string());
--   crates/epigraph-db/src/access_control.rs:57, :78-86 (the reading side)
--
-- Idempotent: a lock_timeout abort is retried by re-running the file (sqlx
-- records no _sqlx_migrations row for a failed migration).
SET LOCAL lock_timeout = '3s';

-- ------------------------------------------------------------------
-- 1. A TYPED column for what encryption_key_id was actually holding.
-- ------------------------------------------------------------------
ALTER TABLE public.ownership ADD COLUMN IF NOT EXISTS community_id uuid;

-- CONRELID-QUALIFIED guard. pg_constraint.conname is unique per RELATION, not
-- per database (062's own comment makes this point); an unqualified lookup is
-- satisfied by a same-named constraint on any other table and would silently
-- skip creating the real one.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_community_fkey')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_community_fkey
           FOREIGN KEY (community_id) REFERENCES public.communities(id)
           ON DELETE SET NULL NOT VALID; END IF;
END $$;

-- ------------------------------------------------------------------
-- 2. Drain the parseable AND RESOLVABLE values into the typed column.
--
-- THE `EXISTS` GUARD IS LOAD-BEARING AND IS NOT IN THE PLAN. `NOT VALID` on a
-- FOREIGN KEY skips the back-check of EXISTING rows; it does NOT exempt rows
-- the same transaction UPDATEs. A well-formed UUID naming a community that has
-- since been deleted therefore aborts the whole migration:
--   ERROR: insert or update on table "ownership" violates foreign key
--          constraint "ownership_community_fkey"
-- (reproduced against a throwaway database). `communities` has no cascade to
-- `ownership`, so a deleted community leaves exactly this value behind, and
-- the plan's unguarded UPDATE would have hard-failed the deploy. A dangling
-- UUID belongs in the quarantine with the rest of the unparseable set.
UPDATE public.ownership o
   SET community_id = o.encryption_key_id::uuid,
       -- CLEAR THE SOURCE IN THE SAME STATEMENT. Draining without clearing
       -- would leave the SAME UUID in two columns, which is precisely the
       -- two-sources-of-truth this migration exists to remove. It also has a
       -- concrete failure attached: `ownership_key_id_is_uuid` (added below)
       -- is `NOT VALID`, and NOT VALID exempts the initial back-scan but NOT
       -- rows a later statement UPDATEs. A drained row that still carried a
       -- string would re-check that CHECK on every subsequent
       -- `update_partition`, and would enter `ownership_key_id_quarantine` the
       -- moment `community_id` went back to NULL. After this clear, the
       -- quarantine means exactly one thing: "did not resolve".
       encryption_key_id = NULL
 WHERE o.partition_type = 'community'
   AND o.community_id IS NULL
   AND o.encryption_key_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND EXISTS (SELECT 1 FROM public.communities c
                WHERE c.id = o.encryption_key_id::uuid);

-- Same clear for a row that ALREADY carried a typed `community_id` — an
-- out-of-tree writer, or a database where a previous attempt drained but did
-- not clear. Idempotent, and a no-op on a database this migration has already
-- run against.
UPDATE public.ownership
   SET encryption_key_id = NULL
 WHERE community_id IS NOT NULL
   AND encryption_key_id IS NOT NULL;

-- A `community_id` on a row that is not on the community partition is a gate
-- with nothing to gate, and a trap: `update_partition` (repos/ownership.rs)
-- argues that demoting a node must clear the gate "or a later re-promotion
-- inherits a community the caller never named", but `assign_with_community`
-- accepts the (partition='private', community_id=Some(..)) pair, so the
-- invariant one writer enforces the other could pre-load. Enforce it ONCE,
-- structurally, for every writer. `NOT VALID`: no drained row can violate it
-- (the drain filters on partition_type='community'), and a legacy row that
-- does is reported by the constraint the first time it is UPDATEd rather than
-- aborting this deploy.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_community_needs_community_partition')
  THEN ALTER TABLE public.ownership
           ADD CONSTRAINT ownership_community_needs_community_partition
           CHECK (community_id IS NULL OR partition_type = 'community')
           NOT VALID; END IF;
END $$;

-- `ownership_community_fkey` is ON DELETE SET NULL, so every `DELETE FROM
-- communities` scans `ownership` for referencing rows while holding a
-- row-exclusive lock; the 084 pre-flight (`SELECT count(*) FROM
-- ownership_key_id_quarantine`) scans it too. PARTIAL, because `community_id`
-- is NULL on every non-community row and a full index would be mostly nulls.
-- Built in-transaction rather than CONCURRENTLY: `ownership` holds one row per
-- owned node, not one per claim version.
CREATE INDEX IF NOT EXISTS idx_ownership_community
    ON public.ownership (community_id) WHERE community_id IS NOT NULL;

-- ------------------------------------------------------------------
-- 3. QUARANTINE anything left. A VIEW, NOT A CTAS SNAPSHOT (ops F20).
--    A snapshot taken at 068 time cannot see a row that becomes unparseable
--    afterwards, and migration 084's pre-flight would then pass while the
--    value was discarded. A view is always current.
-- ------------------------------------------------------------------
--
--    `security_invoker = true` IS NOT DECORATION. Migration 069 registers
--    `alternative_set` and `alt_set_decisions` in `tenancy_exempt` precisely
--    BECAUSE they are views with this option unset, which after 079's FORCE
--    makes them execute as the view owner and bypass the invoker's policies.
--    Creating a third such view in the same PR that files that finding would
--    be indefensible. This one exposes ownership metadata (node, partition,
--    owner), so it gets the option at birth rather than owing it to 077.
CREATE OR REPLACE VIEW public.ownership_key_id_quarantine
    WITH (security_invoker = true) AS
    SELECT node_id, node_type, partition_type, owner_id, encryption_key_id
      FROM public.ownership
     WHERE encryption_key_id IS NOT NULL AND community_id IS NULL;
COMMENT ON VIEW public.ownership_key_id_quarantine IS
  'Rows whose ownership.encryption_key_id does not resolve to a live communities.id. '
  'Must be empty before migration 084 drops the table. Non-empty is an operator '
  'action item, not an error — it is REPORTED, never swallowed.';

-- Belt and braces: no NEW unparseable value can be written. The kernel writer
-- (repos/ownership.rs) stops writing this column in the same PR, so this
-- constraint's remaining job is to stop an out-of-tree writer.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.ownership'::regclass
                    AND conname  = 'ownership_key_id_is_uuid')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_key_id_is_uuid
           CHECK (encryption_key_id IS NULL
                  OR encryption_key_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
           NOT VALID; END IF;
END $$;

-- ------------------------------------------------------------------
-- 4. Project each community into a group, ID-PRESERVING so no mapping table
--    is needed. kind='community' => key-free => groups_public_key_shape
--    (060:164) REQUIRES octet_length(public_key)=0, hence ''::bytea.
--    Untargeted ON CONFLICT: groups_did_key_key is a SECOND unique constraint
--    and a pre-existing row under either one must be tolerated (062 does the
--    same for the world/seed groups, and for the same reason).
-- ------------------------------------------------------------------
INSERT INTO public.groups (id, display_name, did_key, public_key, kind, created_at)
SELECT c.id, c.name, 'did:epigraph:community:' || c.id::text, ''::bytea,
       'community', c.created_at
  FROM public.communities c
ON CONFLICT DO NOTHING;

-- Epoch 0, key-free. Selected FROM groups (not communities) so a re-run cannot
-- try to give an epoch to a group that was never created by the arm above.
INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
SELECT g.id, 0, NULL, 'active'
  FROM public.groups g
 WHERE g.kind = 'community'
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------------
-- 5. community_members ⋈ perspectives.owner_agent_id  ->  group_memberships.
--    This is the 2-hop membership path from access_control.rs:99-113,
--    collapsed into one agent-level table with roles and revocation.
--    perspectives.owner_agent_id is NULLABLE, hence the IS NOT NULL filter.
--    The join to groups guarantees the group_memberships_group_id_fkey holds
--    and that a same-id group of another kind can never be targeted.
--    Untargeted ON CONFLICT covers BOTH group_memberships_group_id_agent_id_epoch_key
--    AND the partial unique group_memberships_one_live (060:262).
--
--    ROLE = 'reader', WHICH IS THE COLUMN'S OWN DEFAULT (060:240) AND THE LEAST
--    PRIVILEGE THE SOURCE DATA SUPPORTS. `community_members` records that a
--    perspective may READ a community's content — `check_content_access`
--    consults it and nothing else — and says nothing whatever about write
--    authority. `Viewer::resolve` (crates/epigraph-db/src/visibility.rs) puts
--    `admin|writer` into the WRITABLE set that feeds
--    `epigraph_writable_groups`, so projecting 'writer' here would silently
--    hand every historical community member write authority over the whole
--    projected group's corpus at PR-11/PR-17, and eligibility to enqueue
--    privatization/reseal against it at PR-18. Nothing in `community_members`
--    justifies that; 'reader' is what the row actually attests.
--
--    NOTE FOR PR-12/PR-18: no member is projected as 'admin', and
--    `groups.created_by_agent_id` is left NULL because `communities` carries no
--    creator column to derive it from. A projected community group therefore
--    has ZERO administrators until PR-12 gives it one — `POST
--    /groups/:id/members` cannot be used on it, and PR-18's "≥2 other live
--    admins" precondition is unsatisfiable by construction. Recorded in
--    docs/tenancy/HANDOFF.md.
-- ------------------------------------------------------------------
INSERT INTO public.group_memberships
    (group_id, agent_id, wrapped_key_share, epoch, role, joined_at)
SELECT DISTINCT ON (cm.community_id, p.owner_agent_id)
       cm.community_id, p.owner_agent_id, ''::bytea, 0, 'reader', now()
  FROM public.community_members cm
  JOIN public.perspectives p ON p.id = cm.perspective_id
  JOIN public.groups       g ON g.id = cm.community_id AND g.kind = 'community'
 WHERE p.owner_agent_id IS NOT NULL
 ORDER BY cm.community_id, p.owner_agent_id, cm.joined_at
ON CONFLICT DO NOTHING;

COMMENT ON COLUMN public.ownership.encryption_key_id IS
  'DEPRECATED. Held stringified community UUIDs until migration 068, which '
  'drained them into ownership.community_id AND CLEARED THE SOURCE. Written by '
  'nothing after PR-05, read by nothing after PR-05. A NON-NULL value here is '
  'therefore a value that did not resolve to a live communities.id: see '
  'ownership_key_id_quarantine. Dropped with the table in migration 084.';
COMMENT ON COLUMN public.ownership.community_id IS
  'The gating community for partition_type=''community''. Replaces the '
  'encryption_key_id overload. Read by access_control.rs.';
