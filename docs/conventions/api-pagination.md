# List endpoints: pagination convention

How a REST list endpoint under `/api/v1` takes a page and says where the next
one starts. New list endpoints follow it. Existing endpoints keep the shapes
their clients already parse (see [Legacy](#legacy)). The code side is
`crates/epigraph-api/src/routes/pagination.rs`.

## The request

- `after`: optional and opaque. It is the previous page's `next_cursor`,
  passed back unchanged. If absent, the endpoint serves the first page. A token
  the endpoint did not issue gets a 400 that names the bad cursor.
- `limit`: optional. It defaults to **20** and is clamped into **`[1, 100]`**,
  unless the endpoint documents its own bounds. A clamp is not an error.

An endpoint may also take filters, for example a time window or a claim id.
A filter can only narrow the set a page is cut from, never widen it.

Do not add an `offset` or `page` query parameter to a new endpoint. Under
concurrent writes an offset page drifts, so it skips or repeats rows.

## The response

```json
{"items": [ ... ], "next_cursor": "k1.1790000000000000.0f1e2d3c4b5a69788796a5b4c3d2e1f0"}
```

- A **new** endpoint answers with `Page<T> { items, next_cursor }`
  (`routes/pagination.rs::Page`).
- `next_cursor` is `null` on the last page. The usual way to know there is a
  next page is to read one row past `limit`, which `Page::from_overfetch` does.
  Then a client never has to fetch an empty page to learn that it is done.
- Existing endpoints keep their own envelope names (`claims`, `results`, ...).
  Renaming a field that clients parse is a breaking change. This is the same
  rule the MCP tools follow (backlog 5179afe6): keep response shapes, and add
  new behaviour only as explicit opt-ins.

## The cursor

- **Default: an unsigned, versioned keyset position.** The format is
  `k1.<created_at micros>.<id simple>`, read in `(created_at DESC, id DESC)`
  order. That is `epigraph_db::repos::claim::LabelCursor` (`encode` and
  `decode`). `decode` refuses a foreign prefix and any position Postgres
  cannot represent, so every decoded cursor binds.
  - The `k1.` prefix is the version. A later format takes a new prefix, and
    the old one is then refused rather than half-parsed.
  - The id breaks the tie between rows that share a `created_at`, for example
    rows written by one statement.
- **Why no signature.** A position names a row the caller was already served,
  and every page re-runs the caller's viewer-filtered read. A forged position
  only moves where that read starts, so signing it would add no safety.
- **Sign a cursor (HMAC) only when it carries state beyond a position.**
  `routes/search.rs::semantic_search` is the one such endpoint: its cursor
  holds walk state (the query hash, the distance, the limit), so it is signed
  (`search.rs::sign_key_cursor_body`, checked against
  `search.rs::key_cursor_mac`).
- **Never encode an id that the caller may only count.** If a response may
  report some rows only as a count, then neither its cursor nor any query
  parameter may carry their ids. `routes/privatization.rs::get_plan_items`
  pages by a position in the plan's frozen order, never by an entity id
  (`privatization.rs::parse_cursor`). `seal_manifest` and `unseal_manifest`
  in the same file are the documented carve-out: they serve the full rows
  they page over, so their claim-id keyset cursor discloses nothing that the
  body has not already disclosed.

## Endpoints today

Following the convention (`after`, `next_cursor`):

- `routes/recall_events.rs::list_own_recall_events` (`GET /api/v1/recall-events`).
  This is the first endpoint on `Page<T>`. Its `limit` defaults to 20 and is
  clamped to `[1, 200]`.
- `routes/claims_query.rs::list_claims_query` (`GET /api/v1/claims`).
- `routes/graph.rs::themes_overview`, `routes/guest.rs::themes_overview`.
- `routes/sources.rs::sources_overview`.
- `routes/claim_context.rs::claim_context` (one cursor per list, with `list`).
- `routes/agent_prompt_history.rs::get_prompt_history`. It also returns
  `truncated`, because a page can stop at a byte budget.
- `routes/claims.rs::list_by_labels` (`GET /api/v1/claims/by-labels`) takes
  `after`, but it returns the next cursor in the `X-Next-Cursor` response
  header rather than in the body.

Different by design (see [The cursor](#the-cursor)):

- `routes/search.rs::semantic_search`: `cursor`, signed.
- `routes/privatization.rs::get_plan_items`: `cursor`, a position.
  `seal_manifest` and `unseal_manifest` use `cursor`, a claim-id keyset.

## Legacy

These page by `limit` + `offset`. They keep working, and none of them is a
model for new code:

- `routes/crud.rs::list_evidence` (`GET /api/v1/evidence`).
- `routes/events.rs::list_events`: `offset` beside its `since` + `after_id`
  keyset, which is the correct way to poll that endpoint.
- `routes/claims.rs::list_by_labels`: `offset`, kept for compatibility. Prefer
  `after`; the two cannot be combined.
- `routes/claims_query.rs::list_claims_query`: `offset`, beside `after`.

Not pagination: the `page` field of `routes/edges.rs`'s evidence payload is a
figure's page number in a source document.
