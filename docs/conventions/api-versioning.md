# REST routes: `/api/v1` and the unversioned aliases

Every REST route lives under `/api/v1`. A few older routes were first
registered without the prefix. They still answer, but they are deprecated
aliases (backlog f2938a03), and new code and clients use the `/api/v1` path.

## What an alias answers

An alias answers exactly as it did before, with two more response headers:

```
Deprecation: true
Link: </api/v1/agents/7c2e.../reputation>; rel="successor-version"
```

The `Link` target is the request path under `/api/v1`, so a path parameter
carries over. A 401 from bearer authentication is answered before the alias's
route runs, so it does not carry the headers.

| Alias | Successor | Same handler |
|-------|-----------|--------------|
| `POST /claims` | `POST /api/v1/claims` | yes |
| `GET /claims` | `GET /api/v1/claims` | **no**, see below |
| `GET /claims/:id` | `GET /api/v1/claims/:id` | yes |
| `POST /agents`, `GET /agents` | `POST /api/v1/agents`, `GET /api/v1/agents` | yes |
| `GET /agents/:id` | `GET /api/v1/agents/:id` | yes |
| `GET /agents/:id/reputation` | `GET /api/v1/agents/:id/reputation` | yes |
| `GET /agents/:id/perspectives` | `GET /api/v1/agents/:id/perspectives` | yes |
| `GET /lineage/:claim_id` | `GET /api/v1/lineage/:claim_id` | yes |

The last three successors were added with the deprecation; before it those
routes existed only unversioned. Each successor takes the same token and
answers the same body.

## `GET /claims` is a different list

`GET /claims` is the legacy list (`routes/claims.rs::list_claims_route`). It
takes `limit`, `offset`, `search` and `group_id` and answers
`{items, total, limit, offset}`. Its successor, `GET /api/v1/claims`
(`routes/claims_query.rs::list_claims_query_route`), is a different
implementation with more filters and its own envelope (`claims`, `total`, ...;
see [api-pagination.md](api-pagination.md)). A client that moves from one to
the other must change how it reads the response. `GET /claims` keeps its
body until a later deprecation window retires it.

## Adding a route

Register it under `/api/v1` only. Do not add an unversioned alias.
