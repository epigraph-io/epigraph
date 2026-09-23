-- 069_entity_types_tenancy_tier.sql
-- PR-05. Plan §3/065, shipped as 069 (migrations/README.md is authoritative).
-- D1 for types that do not exist yet: a type registered after this migration
-- must SAY what tenancy shape its backing table has, and cannot be silent.
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.entity_types
    ADD COLUMN IF NOT EXISTS tenancy_tier text NOT NULL DEFAULT 'unclassified';

-- DELIBERATELY WIDER THAN `entity_types_no_unclassified` BELOW. This CHECK must
-- admit 'unclassified' because the ADD COLUMN above defaults every existing row
-- to it, and both constraints live in the same transaction as the seed: a vocab
-- CHECK that excluded it would fail at ADD CONSTRAINT time, before the seed runs.
-- The two constraints disagree ON PURPOSE — vocab says what the column may ever
-- have held, `entity_types_no_unclassified` says what it may hold NOW. Do not
-- "fix" this by narrowing the list.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.entity_types'::regclass
                    AND conname  = 'entity_types_tier_vocab')
  THEN ALTER TABLE public.entity_types ADD CONSTRAINT entity_types_tier_vocab
           CHECK (tenancy_tier IN ('unclassified','columns','derived','identity')); END IF;
END $$;

-- Seed the 23 known types (migration 054:59-82) explicitly. No row is left
-- 'unclassified'. The six 'columns' types are exactly the six whose backing
-- tables 062 gave (visibility, owner_group_id) NOT NULL as D1 roots.
UPDATE public.entity_types SET tenancy_tier = 'columns'
 WHERE type_name IN ('claim','evidence','frame','context','perspective','community');
UPDATE public.entity_types SET tenancy_tier = 'identity' WHERE type_name = 'agent';
UPDATE public.entity_types SET tenancy_tier = 'derived'
 WHERE tenancy_tier = 'unclassified';

-- AFTER the seed, 'unclassified' becomes UN-REGISTERABLE (sec F16). A table
-- CHECK cannot distinguish new rows from old; it is unconditional and correct
-- only because the seed above ran first.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'public.entity_types'::regclass
                    AND conname  = 'entity_types_no_unclassified')
  THEN ALTER TABLE public.entity_types ADD CONSTRAINT entity_types_no_unclassified
           CHECK (tenancy_tier <> 'unclassified'); END IF;
END $$;

-- DROP DEFAULT is what makes tenancy_tier REQUIRED. Verified: after this,
-- an INSERT INTO entity_types that omits the column raises 23502
-- null value in column "tenancy_tier" ... violates not-null constraint.
-- EntityTypeRepository::upsert_non_core MUST therefore supply it — the
-- handler change in this PR is mandatory, not cosmetic.
ALTER TABLE public.entity_types ALTER COLUMN tenancy_tier DROP DEFAULT;

COMMENT ON COLUMN public.entity_types.tenancy_tier IS
  'How this entity type carries tenancy. ''columns'' = the backing table has '
  'NOT NULL (visibility, owner_group_id) and RLS; ''identity'' = an identity '
  'table rendered on public content (agents); ''derived'' = content derived '
  'from a tier-A row, gated by the row it derives from. ''unclassified'' is '
  'forbidden by entity_types_no_unclassified — there is no default.';

-- ------------------------------------------------------------------
-- The exemption registry (§2.4). A member of the GENERATED protected set that
-- carries no tenancy columns must have a row here, with a named reviewer and
-- a residual stated out loud. Adding a row is a visible diff.
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.tenancy_exempt (
    table_name  text PRIMARY KEY,
    reason      text NOT NULL,
    residual    text NOT NULL,   -- what an attacker still learns
    reviewed_by text NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);

-- DRIFT GUARD, the pattern migration 060 established at its head: `CREATE TABLE
-- IF NOT EXISTS` is SILENT about a table that already exists in a DIFFERENT
-- shape. On such a database the seed INSERT below would fail on an unknown
-- column — a 42703 with no explanation of what actually went wrong. Fail loudly
-- with the reason instead. `tenancy_exempt` is new in this reserved range, so
-- the only way to reach this is an out-of-tree table squatting on the name.
DO $$
DECLARE missing text;
BEGIN
  SELECT string_agg(c, ', ' ORDER BY c) INTO missing
    FROM unnest(ARRAY['table_name','reason','residual','reviewed_by','reviewed_at']) AS c
   WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns
                      WHERE table_schema = 'public' AND table_name = 'tenancy_exempt'
                        AND column_name = c);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'public.tenancy_exempt exists in a different shape: missing column(s) %. '
                    'Migration 069 will not seed into an unknown table.', missing;
  END IF;
END $$;

COMMENT ON TABLE public.tenancy_exempt IS
  'Members of the §2.4 generated protected set that carry no tenancy columns. '
  'Every row is an argued, reviewed exemption; crates/epigraph-db/tests/'
  'tenancy_coverage.rs fails if a generated member is neither covered nor '
  'registered here, and fails if a row states no residual.';

-- THE PLAN'S THREE-ROW SEED IS WRONG IN BOTH DIRECTIONS AND IS CORRECTED HERE.
-- Measured against this schema, §2.4's Generator A ∪ Generator B returns 27
-- relations. NONE of claim_themes / agents / jobs is among them (no claim_id,
-- no FK to claims), and NINE that ARE among them carry no tenancy columns.
-- Seeded with the plan's three (harmless, and they document tier-B/F5
-- decisions the coverage test's manual-addition arm does check) PLUS the nine
-- the generators actually find, without which tenancy_coverage.rs assertion
-- (b) fails on its first run with nine violations.
INSERT INTO public.tenancy_exempt (table_name, reason, residual, reviewed_by) VALUES
 ('claim_themes',
  'Corpus-wide aggregate: no claim_id, no per-claim key. centroid vector(1536) '
  'and claim_count span tenants by construction. NOT found by either generator; '
  'registered by hand (§2.4).',
  'A centroid computed over a mixed public/private set reveals topical '
  'adjacency. Control is PR-09 viewer-scoped clustering, not a column.',
  'PENDING'),
 ('agents',
  'Identity must render authorship on a public claim (tier B).',
  'display_name and public_key are always readable; agents.profile_visibility '
  '(migration 062) governs properties/orcid/ror_id only.',
  'PENDING'),
 ('jobs',
  'Queue metadata; carries no claim content.',
  'Payload jsonb can name a plan_id. Closed by the 077 policy + the handler '
  're-validation in §6.5.5, not by columns.',
  'PENDING'),
 ('claim_encryption',
  'Created by migration 060 and already keyed on group_id + epoch; a second '
  'owner_group_id would be a redundant second source of truth.',
  'Row presence discloses THAT a claim is sealed and to which group, without '
  'disclosing content. Closed by the 077 policy on group_id.',
  'PENDING'),
 ('claim_version_encryption',
  'As claim_encryption: keyed on group_id + epoch by migration 060.',
  'Row presence discloses that a claim VERSION is sealed. Closed by the 077 '
  'policy on group_id.',
  'PENDING'),
 ('experiments',
  'Generator B hit via experiments_hypothesis_id_fkey. Carries protocol text '
  'derived from a claim but was not in 062''s tier-A list; adding columns now '
  'would give it coverage that 070/074/077 do not extend, which is worse than '
  'a stated exemption.',
  'protocol / protocol_source disclose the design of an experiment whose '
  'hypothesis is a private claim. NOT CLOSED IN V1. Must become tier A before '
  'PR-18 ships privatization.',
  'PENDING'),
 ('counterfactual_scenarios',
  'Generator B hit via claim_a_id / claim_b_id. Same reasoning as experiments.',
  'scenario_a / scenario_b jsonb are reasoning derived from two claims. '
  'NOT CLOSED IN V1.',
  'PENDING'),
 ('learning_events',
  'Generator B hit via conflict_claim_a / conflict_claim_b. Same reasoning.',
  'lesson and resolution are free text derived from a challenge over two '
  'claims. NOT CLOSED IN V1.',
  'PENDING'),
 ('match_candidates',
  'Generator B hit via claim_a / claim_b. Same reasoning.',
  'verifier_rationale is free text about two claims, and the (claim_a, claim_b) '
  'pair alone is a near-duplicate oracle over the private corpus. NOT CLOSED IN V1.',
  'PENDING'),
 ('behavioral_executions',
  'Generator B hit via behavioral_executions_step_claim_id (nullable). '
  'Workflow telemetry, not claim content.',
  'goal_text and goal_embedding vector(1536) are workflow-goal text; a private '
  'workflow step''s goal is disclosed. Low value, ledgered.',
  'PENDING'),
 ('alternative_set',
  'A VIEW over edges, not a table — there is no row to carry a column. Found by '
  'Generator A because information_schema.columns does not distinguish relkind.',
  'relkind=''v'' with security_invoker UNSET: after migration 079''s FORCE it '
  'executes as the view OWNER and BYPASSES the invoker''s RLS on edges. '
  'Migration 077 MUST set security_invoker=true on it or drop it. '
  'THIS IS AN OPEN RLS BYPASS, RECORDED HERE SO PR-17 CANNOT MISS IT.',
  'PENDING'),
 ('alt_set_decisions',
  'A VIEW over alternative_set ⋈ claims. Same as alternative_set.',
  'relkind=''v'' with security_invoker UNSET: bypasses the invoker''s RLS on '
  'claims after 079 and returns belief/plausibility/labels for claims the '
  'caller cannot read. Migration 077 MUST set security_invoker=true. '
  'THIS IS AN OPEN RLS BYPASS.',
  'PENDING')
ON CONFLICT (table_name) DO NOTHING;
