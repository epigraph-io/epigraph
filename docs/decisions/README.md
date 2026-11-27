# Decision records

Why the system is the way it is, for decisions whose reasoning would
otherwise be lost. Each record names the decision, the sources it is
reconstructed from (commit, pull request, design spec), and the rule it
grounds in [`CLAUDE.md`](../../CLAUDE.md) or the code.

## Kinds of record

- **Retrospective records (`NNNN-*.md`).** Invariant-setting changes made
  before the Epistemic Commit Protocol was adopted (pull request #223,
  2026-05-31). Commits from that period mostly have no Evidence, Reasoning or
  Verification sections, so a rule that `CLAUDE.md` now treats as an
  invariant can trace back to a commit with an empty body. A retrospective
  record collects the reasoning from the pull request body and the design
  spec that do survive. It adds no rationale of its own: where the sources
  are silent, the record says so.
- **Ruling register (reserved).** Operator rulings that the code cites will
  get a register here too, in its own file, so both kinds share one home.

A record is written after the fact and is not kept current. Each one has a
"Later changes" section listing what changed since, as of the date it was
written. Where a record and the current code disagree, the code is right.

## Record format

Each record has these parts:

- a header with the decision date, the date the record was written, and its
  sources (commits and pull requests are cited by sha or number, and only
  where they are on `main`);
- **Rule it grounds**: the `CLAUDE.md` section or code location that states
  the rule today;
- **Decision**, then **Context** and **Reasoning** taken from the sources,
  each point attributed to one of them;
- **Not recorded**: questions the sources do not answer;
- **Later changes**.

## Records

| # | Decision | Decided |
|---|----------|---------|
| [0001](0001-null-embedding-when-claim-stops-being-current.md) | A claim that stops being current loses its embeddings | 2026-05-18 |
| [0002](0002-retire-backlog-items-by-label.md) | Backlog items are retired with a `resolved` label in one call, not by supersession | 2026-05-16/17 |
| [0003](0003-evidence-reliability-is-the-ds-discount-authority.md) | Evidence-type reliability, not agent confidence, sets the Dempster-Shafer discount | 2026-05-03, 2026-05-28 |
| [0004](0004-workflows-as-hierarchical-claim-graphs.md) | Workflows are hierarchical claim graphs whose steps share ids with document atoms | 2026-04-30 |

Filing these records into the knowledge graph is a separate step for the
operator. A file here is the source text for that.
