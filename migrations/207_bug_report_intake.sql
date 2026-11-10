-- 207: a write-only bug-report intake for agents that are not members of the
-- group that triages bug reports.
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- Backlog and bug claims live in a private team group. An agent outside that
-- group can neither write a claim into it (the claims trigger's writer scope,
-- OPL02) nor read one there (`claims_tenancy`). Such an agent still needs a
-- way to report a defect. This file gives it one: a write-only intake whose
-- receipt is the new claim's id and a timestamp, and nothing else.
--
-- ===================================================================
-- 2. WHAT THIS FILE ADDS
-- ===================================================================
--
--   (a) `public.bug_report_intake_settings`: one row, the instance's intake
--       group and the per-reporter rate limits. Written only on a
--       maintenance session; nothing here is hard-coded, and a database
--       without the row has no intake (every call is refused, BUG03).
--   (b) a RESTRICTIVE INSERT policy on `security_events` that reserves the
--       `bug_report.` event prefix for privileged and definer sessions
--       (123's `platform.` and 117's `cascade.` shape). The
--       `bug_report.submitted` row is the intake's marker: the rate limit
--       counts it and `epigraph_my_bug_reports` reads it, so the application
--       role must not be able to forge one.
--   (c0) `public.epigraph_bug_report_gate(uuid, integer, integer, boolean)`:
--       the caller checks (BUG06, BUG07, BUG08, then 166's ROL01) and the
--       home group, shared by (c) and (c2). Maintenance only.
--   (c) `public.epigraph_submit_bug_report(...)`: the write definer.
--   (c2) `public.epigraph_bug_report_preflight()`: the write's refusals that
--       do not depend on the report, so the server can skip the embedding
--       provider for a caller the write would refuse.
--   (d) `public.epigraph_my_bug_reports(integer)`: the reporter's read of its
--       own intake rows.
--   (e) an audit trigger on (a).
--
-- (c0), (c), (c2) and (d) are SECURITY DEFINER, owned by
-- `epigraph_maintenance`, with `SET search_path = pg_catalog, pg_temp` and
-- every `public` object named qualified (172's form,
-- `definer_search_path_ratchet.rs`). EXECUTE is revoked from PUBLIC; (c), (c2)
-- and (d) are granted to `epigraph_app`, (c0) to no one. No body creates,
-- reads or writes a session temporary object: a temporary relation belongs to
-- the calling session, so nothing a definer does may depend on one.
--
-- WHO THE CALLER IS: `epigraph_principal_id()`, the session setting every 077
-- policy keys on, which only `ScopedPool::begin_as` sets from a resolved
-- viewer (docs/tenancy.md). No app-callable function takes the actor, the
-- intake group or the home group as an argument: each is read in the body, so
-- a holder of the application DSN cannot point the write at another group.
--
-- ===================================================================
-- 3. THE WRITE (epigraph_submit_bug_report)
-- ===================================================================
--
-- Refusals, in order; each carries a code and writes nothing:
--   BUG01 no authenticated principal;
--   BUG02 an elevated session (the definer frame skips the application
--         role's `*_elevated_no_insert` policies, so it refuses here);
--   BUG03 the intake is not configured, or its group is not an active team;
--   BUG04 a title or description with nothing visible in it (empty, or only
--         whitespace, format, control and blank filler characters: the
--         `c_invisible` list in (c)), a title over 200
--         characters, a description or repro over 20480 bytes, evidence over
--         51200 bytes, a severity outside blocker|major|minor, a component
--         that is not a short lower-case slug;
--   BUG05 the composed content or a digest the caller sent is malformed;
--   BUG06 the caller is a registered system agent (148);
--   BUG07 the caller is not bound to a human operator (122's OPL01 rule,
--         `epigraph_author_binding`), or its binding gives it no home group
--         (section (c0): a human operator's own personal group, a linked
--         agent's acting operator group, an allowlisted agent's human's
--         personal group);
--   BUG08 the caller's per-hour or per-day limit is reached;
--   ROL01 (166's code, raised by 166's own check, unchanged) the caller is
--         attached to a role that its own linked human does not hold now.
--         The staged insert's statement trigger refuses it anyway; section
--         (c0) asks the same check first so the preflight refuses it too.
-- Membership of the intake group is NOT required; that is the point.
--
-- THE ROW. One claim authored by the caller (`claims.agent_id`), owned by the
-- intake group with visibility 'group', labelled `backlog`, `bug-report`,
-- `intake` and, when given, `severity:<x>` and `component:<x>`. Never `bug`:
-- triage adds that label, and it routes the claim to automation. One
-- reasoning trace and one evidence row (the caller's evidence text, else its
-- description, as testimony), both owned like the claim. The claim's
-- embedding, when the server computed one (`p_embedding`, pgvector text), in
-- the same statement sequence: the reporter cannot write the row afterwards,
-- so the post-commit store every other write path uses would be refused
-- here. Operations search reads it; the reporter cannot read the row, so it
-- cannot read the vector either. One `bug_report.submitted`
-- `security_events` row naming the reporter, the claim and the intake group.
--
-- WHY THE CLAIM IS STAGED IN THE HOME GROUP. On an armed database the claims
-- trigger (122, 165, 166) checks every INSERT's writer scope, and its only
-- relief is a privileged SESSION (`epigraph_bypass()`, which reads
-- `session_user`); a definer frame does not change `session_user`. So the
-- INSERT is declared ('group', home), where home is a group the claims
-- trigger admits the caller's own write into: the operator's personal group
-- for an agent on a live link, a human operator's own personal group, the
-- allowlisted human's personal group for an agent on a 149 client allowance
-- (section (c0)). That insert meets every check the trigger makes (OPL01,
-- OPL02, ROL01) exactly as an ordinary write by the caller would. The same statement sequence then re-owns the row to
-- the intake group before anything else references it. The re-own is an
-- `UPDATE OF owner_group_id`, which the binding trigger does not fire on, and
-- which 115's owner-immutable guard admits in a definer frame
-- (`epigraph_session_is_privileged_writer` reads `current_user`, which is the
-- maintenance owner here). The claim is never
-- 'public' at any point, so no widening or narrowing guard is involved, and
-- the trace and evidence are inserted after the re-own, declared (intake,
-- 'group'). No other session can see the staged state: it never commits.
--
-- WHAT IT DOES NOT DO, deliberately:
--   * no novelty gate, no content-hash dedup, no similarity search. A report
--     that repeats another is a new row, and the answer has the same shape
--     either way, so the reporter learns nothing about the group's contents;
--   * no Dempster-Shafer wiring and no verb edges: a report is testimony for
--     triage, not an epistemic assertion, and an edge would be one more row
--     tenancy has to keep private;
--   * no signatures: the receipt is attested by the audit row, not by a key;
--   * no `claim.created` event: that is the repository layer's emit, and this
--     write does not go through it; the audit row is the intake's signal.
--
-- RATE LIMIT. A transaction-scoped advisory lock on the reporter serializes
-- its concurrent submissions, then its `bug_report.submitted` rows of the
-- last hour and the last day are counted against the settings' limits. The
-- count is the REPORTER's own: another reporter's filings neither count
-- against it nor appear in its BUG08 message.
--
-- ===================================================================
-- 4. THE READ (epigraph_my_bug_reports)
-- ===================================================================
--
-- The caller's reports, newest first: a `bug_report.submitted` row whose
-- agent is the caller, joined to its claim, kept only while that claim is
-- still authored by the caller AND owned by the configured intake group. The
-- event row is unforgeable by the application (2b); the two claim conditions
-- are a second, independent filter, so even a forged marker could only name
-- the caller's own intake rows, never a claim it authored elsewhere. A report
-- triage moved out of the intake group (or an intake group the operator
-- replaced) drops out of the list. Returned: claim id, title, submitted_at,
-- the claim's CURRENT labels (so the reporter sees triage status), whether it
-- is labelled `resolved`, and `is_current`. Everything triage puts on those
-- labels is therefore visible to the reporter.
--
-- ===================================================================
-- 5. UNDO
-- ===================================================================
--
-- docs/runbooks/207-undo.sql drops (e), (d), (c), the policy (b) and the
-- table (a). Claims written through the intake stay where they are.

-- ===================================================================
-- (a) THE SETTINGS ROW
-- ===================================================================
CREATE TABLE public.bug_report_intake_settings (
    singleton       boolean PRIMARY KEY DEFAULT true
                        CONSTRAINT bug_report_intake_settings_singleton CHECK (singleton),
    intake_group_id uuid NOT NULL
                        REFERENCES public.groups(id) ON DELETE RESTRICT,
    per_hour        integer NOT NULL DEFAULT 20
                        CONSTRAINT bug_report_intake_settings_per_hour
                        CHECK (per_hour BETWEEN 1 AND 10000),
    per_day         integer NOT NULL DEFAULT 200
                        CONSTRAINT bug_report_intake_settings_per_day
                        CHECK (per_day BETWEEN 1 AND 100000),
    updated_at      timestamptz NOT NULL DEFAULT pg_catalog.now(),
    updated_by      text NOT NULL DEFAULT session_user
);
COMMENT ON TABLE public.bug_report_intake_settings IS
    'Migration 207: the bug-report intake. One row (singleton = true): the group every report '
    'is owned by and the per-reporter limits. Absent means no intake (BUG03). Written on a '
    'maintenance session only; the application role may only read it.';

REVOKE ALL ON public.bug_report_intake_settings FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take it back and leave SELECT (every relation is
        -- app-readable; which group is the intake is not a secret, and reading
        -- it admits nothing). The definers read the row in their own frame.
        EXECUTE 'REVOKE ALL ON public.bug_report_intake_settings FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.bug_report_intake_settings TO epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.bug_report_intake_settings '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- (b) THE `bug_report.` EVENT PREFIX IS THE DEFINERS'
-- ===================================================================
-- 077 keeps INSERT on `security_events` open to the application role for its
-- own attributed rows (an actor must never be able to suppress its own audit
-- record). Without this, a reporter could write a `bug_report.submitted` row
-- naming any claim id. Case- and space-insensitive, as 123's `platform.` arm.
DROP POLICY IF EXISTS security_events_bug_report_privileged ON public.security_events;
CREATE POLICY security_events_bug_report_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 11)) <> 'bug_report.'
        OR (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));

-- ===================================================================
-- (c0) THE CALLER GATE (maintenance only)
-- ===================================================================
-- BUG06, BUG07 and BUG08 for `p_principal`, against the limits the caller
-- read from the settings row, then 166's ROL01 for it
-- (`epigraph_require_role_holder`, the check the claims trigger runs on the
-- staged insert, so the message and the rule are the trigger's own); returns
-- the caller's home group (section 3). ROL01 is last so every caller keeps
-- the refusal order the write had before the preflight existed.
-- One body for the write (c) and the preflight (c2), so the two cannot
-- disagree about who is admitted. It takes the principal as an ARGUMENT, so
-- it answers for anyone: EXECUTE is revoked from PUBLIC and never granted to
-- the application role (an app-callable copy would be an oracle for any
-- agent's binding and filing counts). The callers pass
-- `epigraph_principal_id()`.
--
-- THE HOME, per binding arm (`epigraph_author_binding`, 149):
--   'human_operator'   its own active personal group, where it holds a live
--                      writer/admin row;
--   'live_link'        107's `epigraph_operator_actor`: the operator's
--                      personal group, while the link is live AND the agent's
--                      own acting row there is live. Revoking that row is the
--                      deactivation lever for a linked agent, so a deactivated
--                      agent is refused here, not admitted on its link alone;
--   'client_allowlist' the allowlisted human's active personal group, where
--                      that human holds a live writer/admin row. The agent
--                      needs no membership of it: 122's writer scope for an
--                      allowlisted author asks only whether its human writes
--                      the group (`epigraph_require_writer_scope`), so the
--                      staged insert there meets OPL01, OPL02 and ROL01 as
--                      the agent's own write would. Revoking the allowance
--                      unbinds the agent, which is then refused BUG07.
-- In every arm the staged insert is checked by the claims trigger exactly as
-- an ordinary write by the caller into that group would be; this function
-- only chooses the group.
--
-- p_serialize: the write takes the reporter's transaction-scoped advisory
-- lock before counting, so concurrent submissions by one reporter cannot
-- both pass the limit. The preflight does not lock: it is advisory, and the
-- write repeats the count under the lock.
CREATE OR REPLACE FUNCTION public.epigraph_bug_report_gate(
    p_principal uuid, p_per_hour integer, p_per_day integer, p_serialize boolean)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_variable
DECLARE
    v_binding text;
    v_human   uuid;
    v_home    uuid;
    v_hour    bigint;
    v_day     bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM public.system_agents sa WHERE sa.agent_id = p_principal) THEN
        RAISE EXCEPTION 'BUG06: a system agent files no bug report; nothing was written'
            USING ERRCODE = '42501';
    END IF;

    v_binding := public.epigraph_author_binding(p_principal);
    IF v_binding = 'human_operator' THEN
        v_human := p_principal;
    ELSIF v_binding = 'live_link' THEN
        SELECT a.operator_group_id INTO v_home
          FROM public.epigraph_operator_actor(p_principal) a;
    ELSIF v_binding = 'client_allowlist' THEN
        v_human := public.epigraph_allowlisted_operator(p_principal);
    END IF;
    IF v_home IS NULL AND v_human IS NOT NULL THEN
        SELECT g.id INTO v_home
          FROM public.groups g
         WHERE g.kind = 'personal' AND g.created_by_agent_id = v_human
           AND g.status = 'active'
           AND public.epigraph_operator_writes_group(v_human, g.id)
         ORDER BY g.created_at, g.id
         LIMIT 1;
    END IF;
    IF v_home IS NULL THEN
        RAISE EXCEPTION 'BUG07: agent % is not bound to a human operator with a home group (no '
                        'live operator link it acts on, no live client allowance, and not a '
                        'registered human operator with its own personal group); nothing was '
                        'written', p_principal
            USING ERRCODE = '42501',
                  HINT = 'An operator links the agent: epigraph-operator link.';
    END IF;

    IF p_serialize THEN
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended('epigraph.bug_report:' || p_principal::text, 0));
    END IF;
    SELECT count(*) FILTER (WHERE e.created_at > pg_catalog.now() - interval '1 hour'),
           count(*)
      INTO v_hour, v_day
      FROM public.security_events e
     WHERE e.agent_id = p_principal
       AND e.event_type = 'bug_report.submitted'
       AND e.created_at > pg_catalog.now() - interval '1 day';
    IF v_hour >= p_per_hour OR v_day >= p_per_day THEN
        RAISE EXCEPTION 'BUG08: this reporter has filed % bug reports in the last hour and % '
                        'in the last day; the limits are % and %; nothing was written',
                        v_hour, v_day, p_per_hour, p_per_day
            USING ERRCODE = '54000';
    END IF;
    -- 166's ROL01: a role's agent writes only while its own linked human
    -- holds the role. The reporter is the staged claim's writer and author,
    -- the only acting agent of the write.
    PERFORM public.epigraph_require_role_holder(p_principal);
    RETURN v_home;
END $$;
COMMENT ON FUNCTION public.epigraph_bug_report_gate(uuid, integer, integer, boolean) IS
    'Migration 207: the bug-report intake''s caller checks (BUG06 system agent, BUG07 unbound '
    'or homeless, BUG08 limit, then 166''s ROL01 role holder) for the given principal; returns '
    'its home group. Maintenance only: called by epigraph_submit_bug_report and '
    'epigraph_bug_report_preflight.';
REVOKE EXECUTE ON FUNCTION public.epigraph_bug_report_gate(uuid, integer, integer, boolean)
    FROM PUBLIC;

-- ===================================================================
-- (c) THE WRITE
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_submit_bug_report(
    p_title         text,
    p_description   text,
    p_severity      text,
    p_component     text,
    p_repro         text,
    p_evidence      text,
    p_content       text,
    p_content_hash  bytea,
    p_evidence_hash bytea,
    p_embedding     text)
RETURNS TABLE (claim_id uuid, submitted_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_variable
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_now       timestamptz := pg_catalog.now();
    v_group     uuid;
    v_per_hour  integer;
    v_per_day   integer;
    v_home      uuid;
    v_repro     text;
    v_evidence  text;
    v_content   text;
    v_labels    text[];
    v_claim     uuid := pg_catalog.gen_random_uuid();
    v_trace     uuid := pg_catalog.gen_random_uuid();
    v_ev        uuid := pg_catalog.gen_random_uuid();
    -- Every character a reader cannot see, as one bracket: `[[:space:]]`
    -- (locale-dependent, so the Unicode White_Space characters are also
    -- listed: U+0020, U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029,
    -- U+202F, U+205F, U+3000), every Cc control (U+0001-U+001F,
    -- U+007F-U+009F; U+0000 cannot occur in `text`) and every Cf format
    -- character of Unicode 15.0 (U+00AD, U+0600-U+0605, U+061C, U+06DD,
    -- U+070F, U+0890-U+0891, U+08E2, U+180E, U+200B-U+200F, U+202A-U+202E,
    -- U+2060-U+2064, U+2066-U+206F, U+FEFF, U+FFF9-U+FFFB, U+110BD, U+110CD,
    -- U+13430-U+1343F, U+1BCA0-U+1BCA3, U+1D173-U+1D17A, U+E0001,
    -- U+E0020-U+E007F), and the characters that render as nothing although
    -- Unicode classes them as letters, marks or symbols: the Hangul fillers
    -- (U+115F, U+1160, U+3164, U+FFA0), U+2800 BRAILLE PATTERN BLANK, the
    -- combining grapheme joiner U+034F, the Khmer inherent vowels
    -- U+17B4-U+17B5, the Mongolian free variation selectors U+180B-U+180D and
    -- U+180F, and the variation selectors U+FE00-U+FE0F and
    -- U+E0100-U+E01EF. Adjacent ranges are merged. The MCP pre-check holds
    -- the same list (`epigraph_db::repos::bug_report::INVISIBLE`), and
    -- `malformed_input_is_refused_with_nothing_written` sends every endpoint
    -- of that list through this check.
    c_invisible constant text :=
        '^[[:space:]\u0001-\u0020\u007F-\u00A0\u00AD\u034F\u0600-\u0605\u061C\u06DD'
        '\u070F\u0890-\u0891\u08E2\u115F-\u1160\u1680\u17B4-\u17B5\u180B-\u180F'
        '\u2000-\u200F\u2028-\u202F\u205F-\u2064\u2066-\u206F\u2800\u3000\u3164'
        '\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB\U000110BD\U000110CD'
        '\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0001'
        '\U000E0020-\U000E007F\U000E0100-\U000E01EF]*$';
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'BUG01: submitting a bug report needs an authenticated principal; '
                        'nothing was written' USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'BUG02: an elevated session files no bug report; nothing was written'
            USING ERRCODE = '42501';
    END IF;

    SELECT s.intake_group_id, s.per_hour, s.per_day
      INTO v_group, v_per_hour, v_per_day
      FROM public.bug_report_intake_settings s
     WHERE s.singleton;
    IF v_group IS NULL
       OR NOT EXISTS (SELECT 1 FROM public.groups g
                       WHERE g.id = v_group AND g.status = 'active'
                         AND g.kind IN ('team', 'community')) THEN
        RAISE EXCEPTION 'BUG03: bug intake is not configured on this instance; nothing was '
                        'written' USING ERRCODE = '55000',
              HINT = 'An operator sets public.bug_report_intake_settings on a maintenance '
                     'session.';
    END IF;

    -- THE INPUT. Sizes in bytes except the title (characters). A title or
    -- description is blank when nothing VISIBLE is left once `c_invisible`'s
    -- characters are taken out: whitespace of any kind, not just spaces
    -- (`btrim` strips spaces only, and a title of a tab and a newline is as
    -- empty as ''), the zero-width, bidi, tag and other format (Cf) and
    -- control (Cc) characters, and the blank fillers and selectors listed
    -- with `c_invisible`, which no reader sees either.
    IF p_title IS NULL OR p_title ~ c_invisible THEN
        RAISE EXCEPTION 'BUG04: a bug report needs a non-empty title; nothing was written'
            USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.char_length(p_title) > 200 THEN
        RAISE EXCEPTION 'BUG04: the title is % characters; the maximum is 200; nothing was '
                        'written', pg_catalog.char_length(p_title) USING ERRCODE = '22023';
    END IF;
    IF p_description IS NULL OR p_description ~ c_invisible THEN
        RAISE EXCEPTION 'BUG04: a bug report needs a non-empty description; nothing was '
                        'written' USING ERRCODE = '22023';
    END IF;
    IF pg_catalog.octet_length(p_description) > 20480 THEN
        RAISE EXCEPTION 'BUG04: the description is % bytes; the maximum is 20480; nothing was '
                        'written', pg_catalog.octet_length(p_description)
            USING ERRCODE = '22023';
    END IF;
    v_repro := CASE WHEN p_repro IS NULL OR p_repro ~ '^[[:space:]]*$' THEN NULL
                    ELSE p_repro END;
    IF pg_catalog.octet_length(v_repro) > 20480 THEN
        RAISE EXCEPTION 'BUG04: the repro is % bytes; the maximum is 20480; nothing was '
                        'written', pg_catalog.octet_length(v_repro) USING ERRCODE = '22023';
    END IF;
    v_evidence := CASE WHEN p_evidence IS NULL OR p_evidence ~ '^[[:space:]]*$' THEN NULL
                       ELSE p_evidence END;
    IF pg_catalog.octet_length(v_evidence) > 51200 THEN
        RAISE EXCEPTION 'BUG04: the evidence is % bytes; the maximum is 51200; nothing was '
                        'written', pg_catalog.octet_length(v_evidence) USING ERRCODE = '22023';
    END IF;
    IF p_severity IS NOT NULL AND p_severity NOT IN ('blocker', 'major', 'minor') THEN
        RAISE EXCEPTION 'BUG04: severity must be blocker, major or minor; nothing was written'
            USING ERRCODE = '22023';
    END IF;
    IF p_component IS NOT NULL AND p_component !~ '^[a-z0-9][a-z0-9-]{0,47}$' THEN
        RAISE EXCEPTION 'BUG04: component must be a short lower-case slug (letters, digits and '
                        'hyphens, at most 48); nothing was written' USING ERRCODE = '22023';
    END IF;
    v_content := p_title || E'\n\n' || p_description
                 || COALESCE(E'\n\nRepro:\n' || v_repro, '');
    IF p_content IS DISTINCT FROM v_content
       OR p_content_hash IS NULL OR pg_catalog.octet_length(p_content_hash) <> 32
       OR p_evidence_hash IS NULL OR pg_catalog.octet_length(p_evidence_hash) <> 32 THEN
        RAISE EXCEPTION 'BUG05: the report''s composed content or a digest is malformed; '
                        'nothing was written' USING ERRCODE = '22023';
    END IF;

    -- THE CALLER (BUG06, BUG07, ROL01) AND THE LIMIT (BUG08), serialized per
    -- reporter: section (c0), the same gate the preflight (c2) runs.
    v_home := public.epigraph_bug_report_gate(v_principal, v_per_hour, v_per_day, true);

    v_labels := ARRAY['backlog', 'bug-report', 'intake']::text[];
    IF p_severity IS NOT NULL THEN
        v_labels := v_labels || ('severity:' || p_severity);
    END IF;
    IF p_component IS NOT NULL THEN
        v_labels := v_labels || ('component:' || p_component);
    END IF;

    -- THE ROWS. Staged in the home group, re-owned, then the rest (section 3).
    INSERT INTO public.claims (id, content, content_hash, truth_value, agent_id, labels,
                               properties, visibility, owner_group_id, created_at, updated_at)
    VALUES (v_claim, v_content, p_content_hash, 0.5, v_principal, v_labels,
            pg_catalog.jsonb_build_object(
                'bug_report', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                    'title', p_title, 'severity', p_severity, 'component', p_component,
                    'has_repro', v_repro IS NOT NULL, 'has_evidence', v_evidence IS NOT NULL,
                    'migration', 207))),
            'group', v_home, v_now, v_now);
    UPDATE public.claims c SET owner_group_id = v_group WHERE c.id = v_claim;

    INSERT INTO public.reasoning_traces (id, claim_id, reasoning_type, confidence, explanation,
                                         properties, visibility, owner_group_id)
    VALUES (v_trace, v_claim, 'observational', 0.5,
            'Bug report filed through the intake by its reporter',
            pg_catalog.jsonb_build_object('submitted_methodology', 'bug_report'),
            'group', v_group);
    INSERT INTO public.evidence (id, content_hash, evidence_type, raw_content, claim_id,
                                 properties, visibility, owner_group_id)
    VALUES (v_ev, p_evidence_hash, 'testimony', COALESCE(v_evidence, p_description), v_claim,
            pg_catalog.jsonb_build_object('source', 'bug_report_intake',
                                          'reporter_supplied_evidence', v_evidence IS NOT NULL),
            'group', v_group);
    UPDATE public.claims c
       SET trace_id = v_trace,
           embedding = CASE WHEN p_embedding IS NULL THEN NULL
                            ELSE p_embedding::public.vector END
     WHERE c.id = v_claim;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('bug_report.submitted', v_principal, true,
            pg_catalog.jsonb_build_object('claim_id', v_claim, 'intake_group_id', v_group,
                                          'severity', p_severity, 'component', p_component,
                                          'migration', 207,
                                          'session_user', session_user::text));

    RETURN QUERY SELECT v_claim, v_now;
END $$;
COMMENT ON FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, text, text,
                                                      bytea, bytea, text) IS
    'Migration 207: file one bug report into the configured intake group as the session '
    'principal, who need not be a member of it. Returns the receipt (claim id, submitted_at) '
    'and nothing about the group''s other contents.';
REVOKE EXECUTE ON FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, text,
                                                             text, bytea, bytea, text)
    FROM PUBLIC;

-- ===================================================================
-- (c2) THE PREFLIGHT
-- ===================================================================
-- What the write would refuse before it looks at the report: BUG01, BUG02,
-- BUG03, then the gate (c0) without its lock (BUG06, BUG07, BUG08, ROL01).
-- Raises the write's own refusal, or returns nothing. It writes nothing.
--
-- WHY. The server computes the claim's embedding before the write (a
-- provider round trip must not hold a transaction open), so without this a
-- caller the write refuses (unconfigured, system, unbound, a role's agent
-- its holder does not cover, over its limit) still costs one provider call
-- per attempt, and the rate limit would not cap provider spend (a refused
-- write leaves no marker to count). The MCP tool calls this first and embeds
-- only when it passes. It is ADVISORY and racy (a limit can be reached, a
-- link retired or a role assignment ended between the two calls), so the
-- write keeps every check. It does not repeat the staged insert's writer-
-- scope checks (OPL01, OPL02): the gate chooses the home group by the rules
-- those checks admit (section (c0)), so a caller it passes is not expected
-- to fail them; the input checks (BUG04, BUG05) need the report, which the
-- MCP tool checks itself before calling this.
--
-- WHAT IT REVEALS: nothing the write's refusals do not. It answers for the
-- session principal only (no argument names anyone), and a pass means only
-- "the write would not refuse you for who you are", which the write's
-- receipt says too.
CREATE OR REPLACE FUNCTION public.epigraph_bug_report_preflight()
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_variable
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_group     uuid;
    v_per_hour  integer;
    v_per_day   integer;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'BUG01: submitting a bug report needs an authenticated principal; '
                        'nothing was written' USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'BUG02: an elevated session files no bug report; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    SELECT s.intake_group_id, s.per_hour, s.per_day
      INTO v_group, v_per_hour, v_per_day
      FROM public.bug_report_intake_settings s
     WHERE s.singleton;
    IF v_group IS NULL
       OR NOT EXISTS (SELECT 1 FROM public.groups g
                       WHERE g.id = v_group AND g.status = 'active'
                         AND g.kind IN ('team', 'community')) THEN
        RAISE EXCEPTION 'BUG03: bug intake is not configured on this instance; nothing was '
                        'written' USING ERRCODE = '55000',
              HINT = 'An operator sets public.bug_report_intake_settings on a maintenance '
                     'session.';
    END IF;
    PERFORM public.epigraph_bug_report_gate(v_principal, v_per_hour, v_per_day, false);
END $$;
COMMENT ON FUNCTION public.epigraph_bug_report_preflight() IS
    'Migration 207: raise the refusal epigraph_submit_bug_report would raise for the session '
    'principal before it reads the report (BUG01-03, BUG06-08, ROL01), or return nothing. '
    'Advisory: the write repeats every check.';
REVOKE EXECUTE ON FUNCTION public.epigraph_bug_report_preflight() FROM PUBLIC;

-- ===================================================================
-- (d) THE READ
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_my_bug_reports(p_limit integer)
RETURNS TABLE (claim_id uuid, title text, submitted_at timestamptz, labels text[],
               resolved boolean, is_current boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_variable
DECLARE
    v_principal uuid := public.epigraph_principal_id();
    v_group     uuid;
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'BUG01: listing bug reports needs an authenticated principal'
            USING ERRCODE = '42501';
    END IF;
    SELECT s.intake_group_id INTO v_group
      FROM public.bug_report_intake_settings s WHERE s.singleton;
    IF v_group IS NULL THEN
        RAISE EXCEPTION 'BUG03: bug intake is not configured on this instance'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY
    SELECT c.id,
           (c.properties -> 'bug_report' ->> 'title'),
           e.created_at,
           c.labels,
           'resolved' = ANY (c.labels),
           c.is_current
      FROM public.security_events e
      JOIN public.claims c ON c.id = (e.details ->> 'claim_id')::uuid
     WHERE e.event_type = 'bug_report.submitted'
       AND e.agent_id = v_principal
       AND c.agent_id = v_principal
       AND c.owner_group_id = v_group
     ORDER BY e.created_at DESC, c.id
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);
END $$;
COMMENT ON FUNCTION public.epigraph_my_bug_reports(integer) IS
    'Migration 207: the session principal''s own intake reports (claim id, title, '
    'submitted_at, current labels, resolved, is_current), newest first, at most 200.';
REVOKE EXECUTE ON FUNCTION public.epigraph_my_bug_reports(integer) FROM PUBLIC;

-- ===================================================================
-- (e) THE SETTINGS AUDIT
-- ===================================================================
-- Only a maintenance session writes the table, so the invoker passes (b).
CREATE OR REPLACE FUNCTION public.epigraph_bug_report_intake_settings_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('bug_report.intake_configured', public.epigraph_principal_id(), true,
            pg_catalog.jsonb_build_object(
                'op', TG_OP,
                'before', CASE WHEN TG_OP = 'INSERT' THEN NULL
                               ELSE pg_catalog.to_jsonb(OLD) END,
                'after', CASE WHEN TG_OP = 'DELETE' THEN NULL
                              ELSE pg_catalog.to_jsonb(NEW) END,
                'migration', 207,
                'session_user', session_user::text));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_bug_report_intake_settings_audit() FROM PUBLIC;
DROP TRIGGER IF EXISTS bug_report_intake_settings_audit ON public.bug_report_intake_settings;
CREATE TRIGGER bug_report_intake_settings_audit
    AFTER INSERT OR UPDATE OR DELETE ON public.bug_report_intake_settings
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_bug_report_intake_settings_audit();

-- ===================================================================
-- OWNERSHIP AND GRANTS
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, '
                'text, text, bytea, bytea, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_my_bug_reports(integer) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_bug_report_gate(uuid, integer, integer, '
                'boolean) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_bug_report_preflight() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_bug_report_intake_settings_audit() '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_submit_bug_report(text, text, text, '
                'text, text, text, text, bytea, bytea, text) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_my_bug_reports(integer) '
                'TO epigraph_app';
        -- The preflight only; the gate (c0) is never the application's.
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_bug_report_preflight() '
                'TO epigraph_app';
    END IF;
END $$;
