//! Repository for durable webhook subscriptions (migration 085, PR-10).
//!
//! # Why there is no `&Viewer` on any function here
//!
//! `webhook_subscriptions` holds no claim content. It holds a delivery URL, an
//! event-type filter, an HMAC secret and the `agents.id` that registered it —
//! and it is outside the §2.4 protected set by construction, because
//! `tenancy_coverage.rs::protected_set` selects relations with a `claim_id`
//! column (Generator A) or a foreign key onto `claims` (Generator B) and this
//! table has neither.
//!
//! Tenancy for webhooks is not "which subscription rows may I read"; it is
//! "which EVENTS may this subscriber be told about". That predicate is applied
//! one level up, in `epigraph-api`'s `routes/webhooks.rs::deliver_event`, which
//! turns each row's `agent_id` into a real
//! [`Viewer`](crate::visibility::Viewer) via
//! [`Viewer::resolve`](crate::visibility::Viewer::resolve) and drops any event
//! whose payload names a claim that viewer cannot read
//! ([`ClaimRepository::hidden_claim_ids`](crate::repos::claim::ClaimRepository::hidden_claim_ids)).
//!
//! Taking a `&Viewer` here and not spending it would be the precise fail-open
//! `visibility_lint.rs` exists to catch, and a `-- VISIBILITY-EXEMPT:`
//! annotation would be worse: an exemption implies a rule was set aside. No
//! rule applies. Ownership is enforced positionally instead:
//! [`WebhookSubscriptionRepository::delete_owned`] takes the caller's principal
//! and puts it in the `WHERE` clause, and the two functions that carry no
//! principal — [`WebhookSubscriptionRepository::list_active`] (process boot) and
//! [`WebhookSubscriptionRepository::delete_as_admin`] (`claims:admin` only) —
//! say so on themselves and are named so a reviewer greps them.
//!
//! Reads that serve a request never come through here at all: `list_webhooks`
//! and `get_webhook` answer from `AppState::webhook_store`, filtered on the
//! caller's `agent_id` in `routes/webhooks.rs`.
//!
//! # Runtime `sqlx::query`, not the macros
//!
//! Deliberate, and the same choice PR-07 made for the same reason: the
//! `query!`/`query_as!` macros need a `.sqlx/` offline cache entry, CI runs
//! `SQLX_OFFLINE=true`, and adding entries drags `cargo sqlx prepare` into
//! every future edit of this file. `migrate_on_startup.rs`, `schema_contract.rs`
//! and `tenancy_coverage.rs` all set the same precedent.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// One row of `public.webhook_subscriptions`.
///
/// Primitives only, so `epigraph-db` need not know about `epigraph-api`'s
/// `WebhookSubscription` (which additionally carries the serde attributes that
/// keep `secret` out of API responses).
#[derive(Debug, Clone)]
pub struct WebhookSubscriptionRow {
    pub id: Uuid,
    /// The `agents.id` that registered this subscription. NOT NULL in the
    /// schema: a subscription whose reading authority cannot be resolved has no
    /// fail-closed behaviour available to it that is not simply "delete it".
    pub agent_id: Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    pub secret: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

/// Persistence for [`WebhookSubscriptionRow`].
pub struct WebhookSubscriptionRepository;

impl WebhookSubscriptionRepository {
    /// Persist a newly registered subscription.
    ///
    /// The caller supplies `id` so the row that lands on disk and the row that
    /// lands in the in-process store are the same identity.
    ///
    /// # Errors
    /// [`DbError`] on any database error, including the `agent_id` foreign-key
    /// violation raised when the principal names no `agents` row — which is a
    /// real condition, not a fixture artefact: a token minted for an agent that
    /// was since deleted must not be able to register a delivery endpoint.
    pub async fn insert(pool: &PgPool, row: &WebhookSubscriptionRow) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO webhook_subscriptions \
                 (id, agent_id, url, event_types, secret, active, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(row.id)
        .bind(row.agent_id)
        .bind(&row.url)
        .bind(&row.event_types)
        .bind(&row.secret)
        .bind(row.active)
        .bind(row.created_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Every active subscription, for **process boot only**.
    ///
    /// Unfiltered by design and by necessity. The in-process store is a
    /// per-process cache of the whole table; hydrating it "as some viewer"
    /// would silently drop every other principal's subscriptions and the
    /// symptom — webhooks that stop firing after a deploy — is indistinguishable
    /// from an idle corpus. This is the same category as
    /// `claim.rs::find_claims_needing_embeddings`: a corpus-wide enumerator
    /// where a `Scoped` viewer is not safer, it is wrong.
    ///
    /// The rows it returns are not disclosed to a caller **as rows**. They go
    /// into `AppState::webhook_store`, and every path out of that store that
    /// serialises subscription CONTENT — `routes/webhooks.rs::list_webhooks`
    /// and `::get_webhook` — is ownership-filtered by the handler.
    ///
    /// One path out of the store is NOT ownership-filtered, and stating the
    /// invariant without it would be stating a falsehood:
    /// `routes/admin.rs::system_stats` takes no auth extractor and no scope
    /// check and returns `WebhookStats { webhook_count: store.len() }` to any
    /// authenticated principal. It discloses a CARDINALITY, never a url, a
    /// secret or an owner — but hydrating from this function does widen what
    /// that cardinality means, from "subscriptions registered during this
    /// process's lifetime" to "rows in `webhook_subscriptions`, across every
    /// tenant". That widening is recorded in `docs/tenancy/progress.json`
    /// (`behaviour_changes`) and the scope gate is left to a follow-up rather
    /// than bolted on here: `SystemStats` is a fourteen-field aggregate whose
    /// other thirteen fields have their own callers and two of whose tests
    /// assert on `webhook_count`.
    ///
    /// # Errors
    /// [`DbError`] on any database error.
    pub async fn list_active(pool: &PgPool) -> Result<Vec<WebhookSubscriptionRow>, DbError> {
        let rows =
            sqlx::query_as::<_, (Uuid, Uuid, String, Vec<String>, String, bool, DateTime<Utc>)>(
                "SELECT id, agent_id, url, event_types, secret, active, created_at \
               FROM webhook_subscriptions WHERE active ORDER BY created_at",
            )
            .fetch_all(pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, agent_id, url, event_types, secret, active, created_at)| {
                    WebhookSubscriptionRow {
                        id,
                        agent_id,
                        url,
                        event_types,
                        secret,
                        active,
                        created_at,
                    }
                },
            )
            .collect())
    }

    /// Delete `id` **only if** `agent_id` owns it. Returns the rows affected.
    ///
    /// The ownership test is in the `WHERE` clause rather than in a read-then-
    /// delete pair on purpose: a caller that has to compare two values can
    /// forget to, and the forgetting compiles.
    ///
    /// # Errors
    /// [`DbError`] on any database error.
    pub async fn delete_owned(pool: &PgPool, id: Uuid, agent_id: Uuid) -> Result<u64, DbError> {
        let res = sqlx::query("DELETE FROM webhook_subscriptions WHERE id = $1 AND agent_id = $2")
            .bind(id)
            .bind(agent_id)
            .execute(pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Delete `id` regardless of owner. **`claims:admin` only.**
    ///
    /// Separated from [`Self::delete_owned`] rather than expressed as an
    /// `Option<Uuid>` owner parameter, so that "delete anyone's subscription"
    /// is a distinct function name a reviewer greps for, not a `None` at a call
    /// site.
    ///
    /// # Errors
    /// [`DbError`] on any database error.
    pub async fn delete_as_admin(pool: &PgPool, id: Uuid) -> Result<u64, DbError> {
        let res = sqlx::query("DELETE FROM webhook_subscriptions WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(res.rows_affected())
    }
}
