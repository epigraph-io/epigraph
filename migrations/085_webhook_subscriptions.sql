-- 085_webhook_subscriptions.sql
-- PR-10. `migrations/README.md` is authoritative for the number: the plan's
-- PR-10 note says "081 if nothing else has claimed it", and 081 IS claimed —
-- by PR-18's privatization guards. The README reserves 085-090 as headroom for
-- exactly this migration. 085 it is; the README table is updated in this same
-- commit.
--
-- WHY THIS TABLE EXISTS. Not the reason the plan gives.
--
-- The plan argues a migration is required because "its `owner_id` is an
-- `oauth_clients.id`, not an `agents.id` ... There is nothing to join". That
-- justification is stale: `AuthContext.agent_id` has been non-null on every
-- authenticated request since PR-02 (`oauth/token.rs::principal_agent_id`), so
-- the join key was already reachable at `register_webhook` time and re-pointing
-- the in-memory field at it is a one-line change, not a migration.
--
-- The reasons that survive:
--
--   1. DURABILITY. `AppState::webhook_store` is an
--      `Arc<RwLock<HashMap<..>>>`. Every deploy silently empties every
--      subscriber's registration, and the failure mode is silence — a webhook
--      that stops firing looks identical to a corpus with no events. A
--      tenancy filter over a store that evaporates is a control over nothing.
--   2. PR-18 (plan §3484) requires `privatization.applied` to fan out "only to
--      subscriptions owned by an agent in `target_group_id`". Resolving that
--      needs subscriptions that outlive the process that registered them.
--
-- TENANCY SHAPE — deliberate, and deliberately NOT (visibility, owner_group_id).
--
-- `crates/epigraph-db/tests/tenancy_coverage.rs::protected_set` derives the
-- §2.4 protected set from live catalogs: Generator A = any `public` relation
-- with a `claim_id` COLUMN; Generator B = any `public` relation with a FOREIGN
-- KEY whose `constraint_column_usage.table_name = 'claims'`. This table has
-- neither: no `claim_id`, and its only FK references `agents`. It is therefore
-- outside the protected set by construction, not by exemption.
--
-- It gets NO `tenancy_exempt` row either, and that is not an oversight.
-- `tenancy_exempt` is the registry for relations the GENERATORS find and 062
-- did not widen — `tenancy_coverage.rs::migration_068_and_069_apply_twice`
-- asserts the registry holds exactly the 12 seeded rows, and
-- `the_generated_exemptions_are_exactly_the_nine_measured` asserts the
-- generated-but-uncovered set is exactly nine. A row here for a relation no
-- generator returns would be an exemption from a rule that never applied.
--
-- What carries tenancy instead is `agent_id`. It is an `agents.id`, which is
-- precisely the argument `epigraph_db::Viewer::resolve` takes, so the fan-out
-- resolves a real per-subscription reading authority and drops any event whose
-- payload names a claim that authority cannot read
-- (`routes/webhooks.rs::deliver_event` →
-- `ClaimRepository::hidden_claim_ids`). The tenancy predicate is applied to the
-- EVENT against the SUBSCRIBER'S viewer, not to this table's rows.
--
-- Transactional on purpose: no `-- no-transaction` header, no
-- `CREATE INDEX CONCURRENTLY`, so `tenancy_migration_shape.rs`'s
-- `INDEX_MIGRATIONS` set (063-066) is untouched.

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.webhook_subscriptions (
    id          UUID PRIMARY KEY,
    -- ON DELETE CASCADE: a deleted agent's delivery endpoints must not outlive
    -- it IN THIS TABLE holding a signing secret. There is no "orphan the
    -- subscription" reading that fails closed.
    --
    -- Scoped claim, deliberately. The cascade removes the ROW; it does not
    -- reach `AppState::webhook_store`, which is written only by
    -- `register_webhook`, `delete_webhook` and boot hydration. A process
    -- already running when the agent is deleted keeps delivering to the
    -- endpoint until it restarts, and `Viewer::resolve` does not error for a
    -- principal with no `agents` row — it returns a Scoped viewer with no
    -- groups — so the fan-out demotes that subscription to public-only rather
    -- than dropping it. Filed in `docs/tenancy/progress.json` under
    -- `open_findings`; not fixed here, because cache invalidation on agent
    -- deletion is a mechanism this table does not own.
    agent_id    UUID        NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    url         TEXT        NOT NULL,
    event_types TEXT[]      NOT NULL DEFAULT ARRAY[]::text[],
    secret      TEXT        NOT NULL,
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT webhook_subscriptions_url_not_blank CHECK (btrim(url) <> ''),
    -- Mirrors `MIN_SECRET_LENGTH` in `routes/webhooks.rs`. The handler already
    -- rejects a short secret with 400; this is the same rule stated where a
    -- direct writer cannot route around it.
    --
    -- `octet_length`, NOT `length`. The handler tests `registration.secret.len()`,
    -- which is Rust's BYTE count; SQL `length()` counts CHARACTERS. They disagree
    -- on any multibyte secret: 'é' || repeat('a', 30) is 31 characters and 32
    -- bytes, so it passes the handler's 400 gate and would then violate a
    -- `length()` constraint — turning a valid registration into a 500 on the one
    -- handler this migration makes db-dependent. `octet_length` is exactly what
    -- `str::len()` measures, so the two statements of the rule are one rule.
    CONSTRAINT webhook_subscriptions_secret_min_len CHECK (octet_length(secret) >= 32)
);

-- Ownership lookups: `list_webhooks` and the delete path both filter on the
-- caller's principal.
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_agent
    ON public.webhook_subscriptions (agent_id);

-- Boot hydration reads only the live rows.
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_active
    ON public.webhook_subscriptions (created_at)
 WHERE active;

COMMENT ON TABLE public.webhook_subscriptions IS
  'Durable HTTP webhook subscriptions (PR-10). Registered by '
  'POST /api/v1/webhooks and hydrated into the in-process store at boot. '
  'Deliberately outside the §2.4 protected set: no claim_id column, no FK to '
  'claims. Tenancy is carried by agent_id, which the fan-out resolves into an '
  'epigraph_db::Viewer to decide which events this subscriber may see.';

COMMENT ON COLUMN public.webhook_subscriptions.agent_id IS
  'The agents.id that registered this subscription. This is the JOIN KEY the '
  'plan said did not exist; it is the argument Viewer::resolve takes, and the '
  'fan-out filter is meaningless without it. NOT NULL by design — a '
  'subscription with no resolvable reading authority must not exist, because '
  'the fan-out would then have to choose between failing open and dropping it.';

COMMENT ON COLUMN public.webhook_subscriptions.secret IS
  'HMAC-SHA256 signing secret. Stored in plaintext, exactly as the in-memory '
  'store held it — this migration moves the secret from process memory to disk '
  'and does not pretend to improve its handling. It is never serialised into '
  'an API response (#[serde(skip_serializing)] on WebhookSubscription.secret). '
  'Encrypting it at rest is a separate, unowned obligation.';
