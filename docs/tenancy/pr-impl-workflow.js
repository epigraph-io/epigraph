export const meta = {
  name: 'tenancy-pr-implement',
  description: 'Implement one PR from the EpiGraph multi-user tenancy plan, verify it against a live local Postgres, and commit only if green',
  phases: [
    { title: 'Analyze', detail: 'exact change inventory + blast-radius check' },
    { title: 'Implement', detail: 'apply the edits' },
    { title: 'Verify', detail: 'migrations, cargo check, tests, sqlx prepare' },
    { title: 'Review', detail: 'correctness + plan-conformance critics' },
    { title: 'Land', detail: 'fix findings, re-verify, commit if green' },
  ],
}

const PR = (args && args.pr) || 'PR-01'
const S = '/private/tmp/claude-501/-Users-jeremynano-Projects-epigraph/6e343bd8-4322-4255-b803-c10131bb6624/scratchpad'
const REPO = '/Users/jeremynano/Projects/epigraph'
const PLAN = S + '/plan/FINAL-PLAN.md'

const ENV = `
# Environment (source this in EVERY Bash call — it is not inherited)
    source ${S}/env.sh

That gives you:
- \`cargo\` / \`rustc\` 1.98 on PATH, and \`sqlx\` (sqlx-cli 0.8.6)
- \`psql\` and friends from a bundled Postgres 16.2 on PATH
- \`DATABASE_URL=postgresql://postgres@127.0.0.1:55432/epigraph_db_repo_test\` — a LIVE local
  database with migrations 001..059 already applied (80 tables), pgvector 0.6.2.
- \`$REPO\` = ${REPO}, \`$PLAN\` = ${PLAN}

## Local database environment — read before trusting a result
- Extensions are REAL, not stubs: \`pg_trgm\` 1.6 was compiled from PostgreSQL 16.2
  upstream source against this server and installed; \`vector\` is 0.6.2; \`plpgsql\` is
  stock. Only \`uuid-ossp\` is a shim (its generators map onto \`gen_random_uuid()\`),
  which is safe because it provides functions only — no operator classes, no index
  support. Migrations therefore apply UNFILTERED and \`#[sqlx::test]\` works normally.
- \`_sqlx_migrations\` IS populated (head = the highest applied version). Always apply
  migrations with \`sqlx migrate run --source migrations\`, NEVER by piping files
  through \`psql\` — psql does not record them, and every test that calls
  \`sqlx::migrate!\` against DATABASE_URL then fails with a duplicate-object error.
- To rebuild the test database from scratch:
      dropdb -h 127.0.0.1 -p 55432 -U postgres epigraph_db_repo_test
      createdb -h 127.0.0.1 -p 55432 -U postgres epigraph_db_repo_test
      cd $REPO && sqlx migrate run --source migrations
- pgvector is 0.6.2 locally. \`hnsw.iterative_scan\` (needs >= 0.8) is NOT available.
  Do not write code that depends on it without gating; note it instead.
- This is NOT a production database and there is no access to one. NEVER attempt to
  reach a remote database. Applying migrations to THIS local database is expected.
`

const RULES = `
# Hard rules
1. Work on branch \`feat/multi-user-tenancy\` in ${REPO}. Do not switch branches. Do not push. Do not open a PR.
2. Follow ${REPO}/CLAUDE.md exactly: all SQL in \`crates/epigraph-db/src/repos/\`; run
   \`cargo sqlx prepare --workspace -- --tests\` after touching any \`sqlx::query!\`/\`query_as!\`
   and commit \`.sqlx/\`; never widen \`claim_from_row\`'s signature; a new kernel MCP tool
   needs BOTH the \`#[tool_router]\` impl in \`epigraph-mcp/src/server.rs\` AND a \`SCOPE_MAP\`
   entry (a coverage test fails otherwise); honour the embedding invariant on write AND
   cleanup paths.
3. Migrations are numbered from 060 upward and are FORWARD-ONLY (there are no \`.down.sql\`
   files in this repo — do not invent one).
4. Where the plan leaves a decision open, take the plan's own recommendation and note it.
   Do not stop to ask. The standing decisions already taken are in ${S}/progress.json.
5. If something in the plan is WRONG about the code as it actually exists, trust the code,
   implement the correct thing, and report the discrepancy. The plan was written by
   analysis, not by compilation.
`

phase('Analyze')

const ANALYSIS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['pr_title','changes','risks','verification_commands'],
  properties: {
    pr_title: { type: 'string' },
    changes: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['path','action','detail'],
      properties: { path:{type:'string'}, action:{type:'string',enum:['create','edit','delete']}, detail:{type:'string'} } } },
    risks: { type: 'array', items: { type: 'string' } },
    verification_commands: { type: 'array', items: { type: 'string' } },
    plan_discrepancies: { type: 'array', items: { type: 'string' } },
  },
}

const [inventory, blast] = await parallel([
  () => agent(`${ENV}\n${RULES}\n\n# Task\nProduce the EXACT change inventory for **${PR}** of the EpiGraph multi-user tenancy plan.\n\nFind ${PR}'s specification in $PLAN (section 7, "Work breakdown"). Read its Evidence / Files / Acceptance / Tests lines in full. Then read EVERY file it names in ${REPO} and confirm the plan's claims against the real code.\n\nReturn a precise, ordered inventory: for each file, whether it is created / edited / deleted and exactly what changes. Include the full SQL for any new migration. List the commands that will prove the work correct. Note every place the plan's description does not match the code as it exists.\n\nDo NOT make any edits — this is analysis only.`,
    { label: `analyze:${PR}`, phase: 'Analyze', schema: ANALYSIS_SCHEMA, effort: 'high' }),
  () => agent(`${ENV}\n${RULES}\n\n# Task\nBlast-radius check for **${PR}** of the tenancy plan (spec in $PLAN section 7).\n\n${PR} deletes and changes things other code depends on. Your job is to find everything that will BREAK, before it breaks.\n\nFor every file ${PR} deletes or changes: \`rg\` for every importer, every caller, every re-export, every test fixture and every \`mod\` declaration referencing it. Check \`Cargo.toml\` feature flags. Check test helpers under \`crates/*/tests/\`. Check the 26 CLI binaries in \`crates/epigraph-cli/src/bin\`. Check \`scripts/\`.\n\nReturn a concrete list: file:line, what references the removed thing, and what has to change there. Be exhaustive — a missed reference is a broken build. Do NOT make edits.`,
    { label: `blast:${PR}`, phase: 'Analyze', effort: 'high' }),
])

const invText = inventory
  ? `## Change inventory\n\n${(inventory.changes||[]).map(c => `- **${c.action}** \`${c.path}\` — ${c.detail}`).join('\n')}\n\n## Risks\n${(inventory.risks||[]).map(r=>`- ${r}`).join('\n')}\n\n## Plan discrepancies found\n${(inventory.plan_discrepancies||[]).map(d=>`- ${d}`).join('\n') || '- none'}\n\n## Verification commands\n${(inventory.verification_commands||[]).map(v=>`- \`${v}\``).join('\n')}`
  : '(analysis failed)'

log(`${PR}: ${(inventory && inventory.changes || []).length} file changes planned; blast radius mapped`)

phase('Implement')

await agent(`${ENV}\n${RULES}\n\n# Task\nImplement **${PR}** in ${REPO}, on branch \`feat/multi-user-tenancy\`.\n\n${invText}\n\n## Blast-radius report — everything below must keep compiling\n\n${blast || '(none)'}\n\n## Method\nRead ${PR}'s full spec in $PLAN section 7 yourself before starting; the inventory above is a guide, not a substitute.\n\nMake the edits. Write the migration file(s). Write the tests the spec names. Fix every reference the blast-radius report found.\n\nDo NOT commit. Do NOT run the full verification suite — a later phase does that. Just get the change in place, coherently and completely.\n\nWhen done, report what you changed and anything you deliberately deviated from.`,
  { label: `implement:${PR}`, phase: 'Implement', effort: 'high' })

phase('Verify')

const VERIFY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['green','results','failures'],
  properties: {
    green: { type: 'boolean', description: 'true only if EVERY check passed' },
    results: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['check','passed','detail'],
      properties: { check:{type:'string'}, passed:{type:'boolean'}, detail:{type:'string'} } } },
    failures: { type: 'array', items: { type: 'string' } },
  },
}

const verify = await agent(`${ENV}\n${RULES}\n\n# Task\nVerify **${PR}** in ${REPO}. You MAY fix what you find — iterate until green or genuinely stuck.\n\nRun, in order, and report each:\n1. **Migration applies to a FRESH database.** Create a scratch DB (\`createdb -h 127.0.0.1 -p 55432 -U postgres epigraph_verify_${PR.toLowerCase().replace('-','_')}\`), then \`sqlx migrate run --source migrations\` (unfiltered — all extensions are installed). Report any error verbatim. Drop the scratch DB afterwards.\n2. **Idempotence** — apply the new migration(s) a SECOND time to the same database. The spec requires this to succeed.\n3. \`SQLX_OFFLINE=true cargo check --workspace --all-targets\` — must be clean.\n4. \`cargo sqlx prepare --workspace -- --tests\` then \`git status --porcelain .sqlx\` — if \`.sqlx\` changed, that is CORRECT and must be kept; report how many files changed.\n5. \`cargo test --workspace\` (against DATABASE_URL). Report pass/fail counts. Pre-existing failures unrelated to ${PR} are NOT your problem — identify them as such by checking whether they fail on \`git stash\` too.\n6. \`cargo clippy --workspace --all-targets\` — report new warnings introduced by this change.\n7. Every acceptance criterion ${PR}'s spec names in $PLAN — check each explicitly and say how you checked it.\n\nSet \`green: true\` ONLY if 1-6 pass and every acceptance criterion is met or explicitly justified. Be honest — a false green is far worse than a red.`,
  { label: `verify:${PR}`, phase: 'Verify', effort: 'high' })

log(`${PR} verification: ${verify && verify.green ? 'GREEN' : 'RED'} — ${(verify && verify.failures || []).length} failures`)

phase('Review')

const reviews = await parallel([
  () => agent(`${ENV}\n${RULES}\n\n# Task\nAdversarial CORRECTNESS review of the uncommitted **${PR}** changes in ${REPO}.\n\nRun \`git diff\` and \`git status\` to see exactly what changed. Then attack it: does the migration do what the plan intended? Are there SQL errors that only show at runtime (missing indexes on FK columns, wrong types, missing NOT NULL, a CHECK that admits bad rows)? Does deleted code leave dangling references, dead \`mod\` lines, or unused imports? Are the new tests actually asserting the property they claim, or do they pass vacuously? Would this break on a database that already has data?\n\nEvery finding: file:line, what is wrong, why it matters, concrete fix. Do NOT make edits — report only.`,
    { label:`review:correctness:${PR}`, phase:'Review', effort:'high' }),
  () => agent(`${ENV}\n${RULES}\n\n# Task\nPLAN-CONFORMANCE and CONVENTION review of the uncommitted **${PR}** changes in ${REPO}.\n\nRead ${PR}'s spec in $PLAN section 7 and \`git diff\`. Check every Files entry the spec names was actually touched, and that nothing extra crept in that belongs to a later PR. Check every Acceptance criterion is genuinely met. Check every Test the spec names exists and runs.\n\nThen check ${REPO}/CLAUDE.md compliance: SQL only in \`repos/\`; \`.sqlx\` regenerated and staged if macros changed; \`claim_from_row\` signature untouched; MCP tools in BOTH the router and SCOPE_MAP; embedding invariant honoured on write and cleanup paths; migration numbering correct and forward-only.\n\nEvery finding: what the spec or convention requires, what the diff does instead, and the fix. Do NOT make edits — report only.`,
    { label:`review:conformance:${PR}`, phase:'Review', effort:'high' }),
])

phase('Land')

const LAND_SCHEMA = {
  type:'object', additionalProperties:false,
  required:['committed','sha','summary','green','deferred'],
  properties:{
    committed:{type:'boolean'}, sha:{type:'string'}, summary:{type:'string'},
    green:{type:'boolean'},
    deferred:{type:'array',items:{type:'string'},description:'work intentionally left for a later PR or blocked on a production database'},
  },
}

const landed = await agent(`${ENV}\n${RULES}\n\n# Task\nFinish **${PR}**: fix the review findings, re-verify, and commit if and only if everything is green.\n\n## Verification report\n${verify ? JSON.stringify(verify, null, 1) : '(failed)'}\n\n## Correctness review\n${reviews[0] || '(none)'}\n\n## Conformance review\n${reviews[1] || '(none)'}\n\n## Steps\n1. Apply every review finding that is CORRECT. Ignore findings that are wrong or that belong to a later PR — say which you ignored and why.\n2. Re-run the full verification: fresh-database migration apply, idempotent re-apply, \`SQLX_OFFLINE=true cargo check --workspace --all-targets\`, \`cargo sqlx prepare --workspace -- --tests\`, \`cargo test --workspace\`, \`cargo clippy --workspace --all-targets\`.\n3. If and ONLY if all of that is green: \`git add -A\` (including \`.sqlx/\` if it changed) and commit. Do NOT push.\n\nThe commit message MUST follow ${REPO}/CLAUDE.md's Epistemic Commit Protocol exactly:\n\n\`\`\`\n<type>(<scope>): <imperative claim, one decision>\n\n**Evidence:**\n- <the concrete error / requirement that triggered this, with file:line>\n\n**Reasoning:**\n- <why this solution over the alternatives>\n\n**Verification:**\n- <the actual commands run and their results>\n\nCo-Authored-By: Claude Opus 5 <noreply@anthropic.com>\n\`\`\`\n\nUse ${PR}'s own title from the plan as the subject line. If verification is NOT green, do NOT commit — leave the tree dirty, set \`committed: false\`, and report exactly what is failing.\n\nReturn the commit sha (or empty string), whether it is green, a short summary, and anything deferred.`,
  { label:`land:${PR}`, phase:'Land', effort:'high' })

return { pr: PR, ...(landed || { committed:false, green:false, summary:'land phase failed' }) }
