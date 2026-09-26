# EpiScience: human OAuth -> operated agent -> DB authority (design, batch W-own Part B)

Status: design only, no code. Operator decision 2026-09-26: *"Episcience should carry
the same 'human oauth to agent' pipeline. If the human has superuser access, so do
their agents."* Companion to migration 114 (writer-owned derived rows, same batch).

Live measurements behind this document (which principal holds what, on which
deployment) are kept out of tree; this file states only what the code and the
schema determine, plus the conclusions those measurements support.

## 1. Where EpiScience is today

| Concern | Today (what the code determines) |
|---|---|
| DB credential and session role | a deployment detail, recorded out of tree; the design below does not depend on it |
| Epigraph crates | pinned to a pre-tenancy revision (`4a93f038`): no `ScopedPool`, no `Viewer`, no stamping |
| Identity of MCP writes | a configured service identity, not the calling human |
| Identity of HTTP writes | the bearer's `agent_id` (falls back to `sub`), validated with the kernel's JWT key (`episcience-api/src/middleware.rs`) |
| Kernel writes | `add_observation` inserts `claims` directly, undeclared (no `visibility` / `owner_group_id`); other kernel writes go through the kernel API with a service token |
| Federation | `epigraph-mcp` forwards the CALLER's bearer verbatim to `episcience-mcp` on every `tools/call` (`federation/client.rs::invoke_once`) -- and `episcience-mcp` ignores it |

So the human's OAuth token already reaches EpiScience on the MCP path; nothing
consumes it, and no record says which human asked for an MCP write.

## 2. The pipeline, stated once

```
human --OAuth (kernel /oauth/token)--> bearer
  bearer --epigraph-mcp gateway (verbatim)--> episcience-mcp
    episcience validates the bearer (kernel JWT key; aud; exp; client status)
    principal H := token.agent_id
    operated agent A := deterministic_agent("episcience", H)        [#361's shape]
    link A OPERATED_BY H (epigraph_link_operator, 107)               [first use]
    stamp the request transaction from A's viewer (ScopedPool::begin_as)
    write as A; the kernel's #503 rule owns A's claims by H's personal group
```

The same four pieces epigraph already has, reused rather than re-invented:

1. **Identify the human from the kernel's token, per call.** `episcience-mcp`
   runs the validation its HTTP middleware already runs on the forwarded bearer
   (signature, `exp`, `aud = epigraph-api` when configured) and additionally
   asks the kernel whether the client is still `active` (the same
   `oauth_clients` record 111's definer re-reads). No token, or a token the
   kernel no longer honours: the call is refused. The service identity is
   retired from the request path (it stays only as the author of background
   jobs, section 5).
2. **One operated agent per (deployment, human).** Deterministic from the
   human's agent id (the #361 identity shape), `agent_type = 'ai'`, never given
   a token of its own: the kernel's token endpoint already refuses an operated
   agent, and that refusal is what keeps "an agent acts only under its human's
   live token" true.
3. **Link it to the operator** with `epigraph_link_operator(A, H)` (107). The
   link gives A a `writer` row in H's personal group; `epigraph_operator_actor`
   reports H's group only while the link is not retired AND H's own membership
   there is live (107 section 5). `epigraph_link_operator` is EXECUTE-able by a
   maintenance login only, so provisioning is either a kernel endpoint the human
   calls with its own token ("link my EpiScience agent"), or EpiScience holds a
   maintenance DSN used for that one call. The kernel endpoint is preferred: it
   keeps maintenance credentials out of an extension.
4. **Stamp and write as A** on the application role: `ScopedPool::begin_as`
   with `Viewer::resolve(A)`, declared tenancy from
   `ClaimRepository::default_decl_for_author(A)` (= H's personal group, public).

## 3. "Their agents have the human's authority": what that maps to

EpiGraph has four distinct things a person can mean by "superuser access". They
are not interchangeable, and only the first two are per-human:

| Authority | Where it lives | Per human? | Inherited by an operated agent today? |
|---|---|---|---|
| Write to a GROUP | `group_memberships.role IN ('admin','writer')`, surfaced as `epigraph_writable_groups()` by the stamp | yes | **only H's personal group** (the link's writer row). `epigraph_live_memberships(A)` does not follow `operator_links`: A's viewer never includes H's team groups, and not H's `admin` role anywhere |
| `claims:admin` | an OAuth scope on H's client (`oauth_clients.granted_scopes`), exercised through 111's audited `epigraph_admin_patch_claim` | yes | **no**: 111 binds the client to the session principal (`agent_id = epigraph_principal_id()`), and A is not the client's agent |
| Instance admin | `instance_admins` (083): privatization approvals | yes | no |
| Maintenance / bypass | DB role `epigraph_maintenance`, or a superuser / BYPASSRLS login | **no** -- a property of a DSN, not of a person | only by running on such a DSN, which is exactly the escape R2 / 113 closes |

The design therefore gives an operated agent **H's per-human authorities and
never a DSN authority**:

* **Groups.** At stamp time, A's writable set is A's own live memberships PLUS
  H's live `writer`/`admin` memberships, while `epigraph_operator_actor(A)` names
  H. This is a stamping rule (`Viewer::resolve_operated`), not a schema change:
  the GUCs are application-asserted today. It is re-read on every session, so a
  revocation of H's membership, or of the link, narrows A on the next call.
  (Group ADMIN acts -- roster changes, key rotation -- stay with H itself.)
* **`claims:admin`.** 111's definer is extended to accept an operated principal
  whose live operator IS the client's agent, recording BOTH the operated agent
  and the operator in the `claims.admin_write` event. The scope check stays
  server-side against H's client record, so withdrawing the scope from H's
  client withdraws it from every agent H operates, immediately.
* **Instance admin.** Not delegated. Privatization approval is a human act by
  design (083); an agent that could approve its own operator's privatization
  plan would defeat the two-person rule.
* **Maintenance.** Never. Background jobs (synthesis, embeddings) keep a
  separate maintenance DSN and author as the service agent, as the kernel's own
  jobs do.

"If the human has superuser access, so do their agents" is therefore read as:
*whatever H could do through the kernel with its own token, A can do while H's
token and link are live* -- not *A runs on a superuser DSN*.

## 4. Revocation

| What is revoked | Effect on A | Where it is enforced |
|---|---|---|
| H's OAuth client suspended / token expired | every call refused | EpiScience's per-call validation + client-status check |
| `claims:admin` withdrawn from H's client | A's admin path refused on the next call | 111's definer re-reads `oauth_clients` |
| H's membership in a team group revoked | A loses that group on the next session | `Viewer::resolve_operated` reads live memberships |
| H's own personal-group membership revoked | `epigraph_operator_actor(A)` returns nothing: EpiScience refuses (fail closed; A exists only to act for H) | 107 section 5 + EpiScience |
| the link retired (`epigraph_link_retired_agent`) | as above | 107 |

## 5. Interim for the 113 deploy (before the port)

113 makes a superuser session that is not an EXPLICIT `epigraph_seed` member
declare an undeclared `claims` insert as the author's own write (the author's
acting operator's personal group, else its personal group, minted if absent),
and REFUSE an undeclared root-table insert (23502).

* `add_observation` is EpiScience's one direct kernel write; it is a `claims`
  insert, so under 113 on a privileged, non-seed login its rows land owned by
  the **service identity's personal group** (public) instead of the seed group.
  That is correct attribution for what the code actually does (one service
  author), and it is the only kernel table EpiScience writes directly (no direct
  INSERT into any root or derived table elsewhere in its crates).
* Of R2's options: **E2 (a dedicated non-seed login for EpiScience)** is
  preferred over *keep* -- same 113 behaviour, but EpiScience's sessions become
  attributable to EpiScience alone. **E3 (a seed login)** is rejected: it keeps
  stamping the seed group, which is the defect 113 exists to end. E1 is the port
  below.
* **The interim is time-limited, and it is not the design.** E2 is still a
  privileged login held by an extension. A privileged session is left on the
  old path by 114 (section 2(b) of that migration), so EpiScience's attachments
  keep the pre-114 claim-owned shape and none of the writer-owned rule applies to
  them. The interim ends when the E1 port (section 6) lands; its deadline and
  owner are recorded in the operator's private notes, and E1 is re-reviewed if
  the deadline passes rather than letting the interim become permanent.

## 6. The port work list (E1)

1. Bump the epigraph pins from `4a93f038` to the kernel's current main (EpiScience
   already moved to sqlx 0.8); take `ScopedPool`, `Viewer`, `TenancyDecl`.
2. `episcience-mcp`: validate the forwarded bearer per call; derive and cache
   the operated agent; refuse without a live link.
3. Link provisioning: a kernel endpoint, authenticated by H's bearer, that runs
   `epigraph_link_operator(A, H)` on the kernel's maintenance pool (preferred),
   or a maintenance DSN held by EpiScience for that call only.
4. `add_observation` (and any future direct write): run on
   `ScopedPool::begin_as(Viewer::resolve_operated(A))` with
   `default_decl_for_author(A)`; the DSN becomes the application role.
5. Engine / repo reads viewer-scoped (`Viewer` spliced reads) so an agent sees
   what its human can see and no more; syntheses keep their own visibility.
6. Kernel: `Viewer::resolve_operated` (union with the operator's live
   memberships while the link is live) and 111's operated-principal arm.
7. Background jobs: a maintenance DSN, authored by the service agent.
8. Tests on the application role (as `epigraph-db/tests/writer_owned_derived_rows.rs`
   does): the human's write lands in its groups; revocation of each row of the
   table in section 4 narrows or refuses on the next call.

## 7. Does "agents inherit the operator's authority" alone fix Part A?

**No.** Part A's refusals are writes onto claims owned by the WORLD group, and
the world group is memberless by design (`locked_decisions.rs::
d2_world_and_seed_remain_memberless`): it is in no human's writable set, so no
amount of inheriting a human's groups reaches it. The human's per-person admin
authority does not reach it either: `claims:admin` (111) is an audited path for
labels / properties / trace on a claim, not for attaching evidence rows, and it
requires the scope on the client (which is not granted by default). The only
"authority" that writes world-owned rows is a DSN authority (maintenance /
superuser), which is exactly what the 113 move and the move of agents to the
application role take away. Migration 114's writer-owned rule is what lets any
agent -- operated or not -- attach to a public claim; inheriting the operator's
authority is complementary (it widens which GROUPS an operated agent writes),
not a substitute.
