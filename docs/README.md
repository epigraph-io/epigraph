# EpiGraph documentation

What each part of `docs/` holds. A new reader should start with
[`intro/`](intro/01-quickstart.md); the repository [`README.md`](../README.md)
lists the same starting points.

`crates/epigraph-core/tests/doc_links.rs` checks that this page links every
entry directly under `docs/`, so a new directory or top-level file must be
added here with a line saying what it is for.

## Reading in order

- [`intro/`](intro/): the numbered onboarding path (quickstart, concepts,
  walkthroughs, glossary, next steps). Follow it from `01` in order.

## Running an instance

- [`deploy.md`](deploy.md): the production install and operations runbook:
  processes and their database logins, configuration, migrations, upgrade
  notes per migration, and rollback.
- [`tenancy.md`](tenancy.md): groups, visibility, operator binding, the
  custodian role and elevation, in depth.
- [`runbooks/`](runbooks/): per-migration undo scripts (`NNN-undo.sql`) and
  the runbooks for scheduled jobs. The migration ledger that names each undo
  script is [`migrations/README.md`](../migrations/README.md).
- [`ops/`](ops/): one-off operational procedures, each dated at its top.

## Design and conventions

- [`architecture/`](architecture/): living design notes for how the system
  is built (noun-claims and verb-edges, edge provenance, memory features).
  A doc with a `**Status:**` line at its top says there whether it is
  canonical or informational; one without that line (the memory-features
  design) makes no claim to match the current code.
- [`conventions/`](conventions/): how recurring work is done: backlog
  retirement, duplicates versus index hygiene, label-family dedup.
- [`governance/`](governance/): policy notes and preregistrations (the
  release gate; the experiment preregistrations).
- [`decisions/`](decisions/README.md): decision records. Retrospective
  records give the reasoning, from the surviving pull request bodies and
  specs, for invariant-setting changes made before the commit protocol
  (2026-05-31), each tied to the `CLAUDE.md` rule it grounds.
- [`tenancy/`](tenancy/): the multi-user tenancy plan, its completion plan
  and handoff record, and follow-up notes. Historical working documents;
  [`tenancy.md`](tenancy.md) is the current reference.

## Point-in-time records

- [`audits/`](audits/): dated audits of the code at one commit. Each opens
  with a status line giving its date; they are not maintained, so check the
  current source before acting on one.
- [`superpowers/`](superpowers/): agent-session working documents: `plans/`
  and `specs/` (dated design specs and the implementation plans written from
  them), `reports/` and `artifacts/`. Plans and specs name files that were
  still to be written and are not kept current; they are not checked for
  broken links.
