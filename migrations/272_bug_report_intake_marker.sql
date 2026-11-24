-- 272: the bug-report intake records its marker at write time, and the
-- reporter's list reads it (backlog e690866c).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- 207's `epigraph_my_bug_reports` kept a report only while its claim was
-- owned by the intake group configured NOW (`c.owner_group_id = v_group`).
-- A report that triage moved out of that group dropped out of its
-- reporter's list, and when the operator named a different intake group
-- every earlier report did the same. The theme scripts' label exclusion
-- (`scripts/theme_lib.py::not_intake_owned`) had the same key, so such a
-- report was sampled for theme labels again under its new owner's rule.
--
-- Both now key on a marker recorded when the report is FILED:
-- `public.bug_report_intake_marks`, one row per report (claim id, reporter,
-- the intake group it was filed into, when, and the title and labels it was
-- filed with). The definer writes it in the same statement sequence as the
-- row; nothing else can.
--
-- WHY A TABLE, NOT 207's `bug_report.submitted` AUDIT ROW. That row is
-- already unforgeable, and the list could read it, but the theme scripts
-- cannot rely on it: `security_events` is under row security, so a login
-- that does not bypass it (a read-only role used for a dry run) reads NO
-- marker rows, and an exclusion written as "no marker exists" then passes
-- every claim, intake text included, with no error. A rowless table with no
-- grant for such a login fails it closed instead (42501), exactly as
-- `bug_report_intake_settings` already does, and is one primary-key probe
-- per claim.
--
-- ===================================================================
-- 2. WHAT CHANGES
-- ===================================================================
--
--   (a) `public.bug_report_intake_marks`: no row security; written only by
--       the maintenance-owned write definer. The application role holds
--       NOTHING on it (077's default privileges are taken back): which agent
--       reported which claim is not the application's to read, and
--       `security_events` shows an agent only its own rows. The maintenance
--       role holds SELECT and INSERT; no role but a superuser may change or
--       delete a marker.
--   (a2) a `tenancy_exempt` row for the table (it has a `claim_id`, so 069's
--       coverage rule needs columns or a row; why the row, and what a
--       maintenance login still reads, is stated in the row itself).
--   (b) the backfill: one marker per existing `bug_report.submitted` row
--       whose claim still exists, is still authored by the row's agent and
--       is a report the write composed (`properties ? 'bug_report'`), with
--       the event's timestamp as `submitted_at`, the claim's title and the
--       labels the write put on it rebuilt from the audit row's severity and
--       component, so every report a reporter sees before this migration it
--       still sees after it. The title can only come from the claim's
--       `properties`, which its owner can rewrite: a report triage had
--       already moved before 272 keeps whatever title it holds now. Read with
--       row security OFF: on a migration login that row security would
--       filter, the read fails instead of silently missing rows.
--       `bug_report_intake_settings` is locked ACCESS EXCLUSIVE first: every
--       write definer call reads that row before it writes anything and
--       holds its lock to commit, so a report already past that read commits
--       before the backfill reads.
--
--       ONE GAP the lock does not close: a call that STARTS while this
--       migration holds the lock has already loaded the old (211) body, waits
--       on the settings read, and resumes on that body once 272 commits, so
--       it files a report with NO marker, after the backfill ran. Such a
--       report is listed while it stays in the intake group (as under 207)
--       and drops out once moved. The operator closes it after deploying by
--       running `docs/runbooks/272-marker-backfill.sql` (this backfill,
--       idempotent) once, a minute or more after 272 commits.
--   (c) `epigraph_submit_bug_report`, redefined from 211's body with one
--       change: the marker INSERT after the audit row.
--   (d) `epigraph_my_bug_reports`, redefined from 207's body: it reads the
--       caller's markers (`reporter_id = principal`) joined to their claims,
--       still requiring the claim's author to be the caller (a second,
--       independent condition, as 207 had), and no longer the claim's
--       CURRENT owner. BUG01 and BUG03 are unchanged: an instance whose
--       operator removed the settings row has no intake, and lists nothing.
--       `submitted_at` is the marker's (the same `now()` the audit row was
--       stamped with).
--
--       WHAT A LISTED REPORT SHOWS does not widen 207's disclosure. While the
--       claim is owned by the CURRENT intake group the row shows its live
--       title and labels, exactly as 207 did. Once another group owns it
--       (triage moved it, or the operator named a different intake group),
--       207 did not list it at all; 272 lists it with only what was filed
--       (the marker's title and labels) and `resolved`/`is_current`, never
--       a label or title its new owner wrote.
--
-- NOT DECIDED HERE: the labels triage writes while the report is in the
-- current intake group are still shown to the reporter, as 207 showed them.
-- Whether that disclosure is acceptable, or the reporter view should filter
-- triage labels there too, is an open operator question (backlog e690866c
-- part 2).
--
-- (c) and (d) keep 172's form: SECURITY DEFINER, owned by
-- `epigraph_maintenance`, `SET search_path = pg_catalog, pg_temp`, every
-- `public` object qualified. `CREATE OR REPLACE` keeps owners and grants;
-- both are re-asserted at the end, as 211 does.
--
-- ===================================================================
-- 3. UNDO
-- ===================================================================
--
-- docs/runbooks/272-undo.sql: re-applies 211's write body and 207's list
-- body, then drops the marker table with its rows. Roll every binary and
-- script that reads the marker table back first (`scripts/theme_lib.py`).

SET LOCAL lock_timeout = '3s';

-- (b) first: no write definer call is past its settings read from here on,
-- and none gets past it until this transaction commits (one that has started
-- meanwhile resumes on the old body: the gap in section 2 (b)).
LOCK TABLE public.bug_report_intake_settings IN ACCESS EXCLUSIVE MODE;

-- ===================================================================
-- (a) THE MARKER TABLE
-- ===================================================================
CREATE TABLE public.bug_report_intake_marks (
    claim_id        uuid PRIMARY KEY,
    reporter_id     uuid NOT NULL,
    intake_group_id uuid NOT NULL,
    submitted_at    timestamptz NOT NULL,
    -- What the reporter FILED, which is all a report owned outside the
    -- current intake group shows it (section 2 (d)): the title it gave and the
    -- labels the definer put on the row. Kept here because the claim's own
    -- `properties` and `labels` are its owner's to rewrite.
    title           text,
    filed_labels    text[] NOT NULL
);
COMMENT ON TABLE public.bug_report_intake_marks IS
    'Migration 272: one row per bug report filed through the intake (207), written by '
    'epigraph_submit_bug_report in the report''s own transaction: the claim, its reporter, '
    'the intake group it was filed into and when, and the title and labels it was filed '
    'with. The reporter''s list and the theme scripts'' label exclusion key on it, not on '
    'the intake group configured now. No foreign keys: a marker outlives a claim or group '
    'delete (readers join to claims).';
CREATE INDEX bug_report_intake_marks_reporter
    ON public.bug_report_intake_marks (reporter_id, submitted_at DESC);

REVOKE ALL ON public.bug_report_intake_marks FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take all of it back (see (a) above: not even SELECT).
        EXECUTE 'REVOKE ALL ON public.bug_report_intake_marks FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT ON public.bug_report_intake_marks TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 272 marker '
                     'table is readable by its owner only.';
    END IF;
END $$;

-- ===================================================================
-- (a2) THE TENANCY DECLARATION
-- ===================================================================
-- The table has a `claim_id`, so it is in the generated protected set that
-- `crates/epigraph-db/tests/tenancy_coverage.rs` checks (Generator A): it must
-- carry both tenancy columns or a `tenancy_exempt` row (069). It gets the row,
-- not the columns. Tenancy columns would say a group owns a marker and that its
-- members may read it under row security; no session but the write and list
-- definers' owner reads it at all, and the claim each marker names keeps its
-- own tenancy, which every reader joins through (the list also requires the
-- claim's author to be the caller). `reviewed_by` is 'PENDING': nobody has
-- reviewed this exemption yet, and the registry's ratchet on unreviewed rows
-- (at most 12) still holds with it.
INSERT INTO public.tenancy_exempt (table_name, reason, residual, reviewed_by) VALUES
 ('bug_report_intake_marks',
  'Migration 272: a definer-only ledger of which agent filed which bug report through '
  'the intake (207), written by epigraph_submit_bug_report and read by '
  'epigraph_my_bug_reports and the maintenance-DSN theme scripts. No row security and '
  'no tenancy columns: the application role holds no privilege on it at all, so no '
  'tenant-scoped session reads it, and each marker names a claim whose own tenancy '
  'governs every join to it.',
  'A login holding the maintenance role (or a superuser) reads the whole reporter to '
  'report map and the title and labels each report was filed with, across every intake '
  'group, including reports later moved into a group it is not a member of. The '
  'application role learns nothing from the table; a reporter learns only its own '
  'reports, through the list definer.',
  'PENDING')
ON CONFLICT (table_name) DO NOTHING;

-- ===================================================================
-- (b) THE BACKFILL
-- ===================================================================
DO $$
DECLARE
    v_uuid constant text :=
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
BEGIN
    -- Fail closed: on a migrating role that row security would filter, these
    -- reads error instead of silently missing reports.
    PERFORM pg_catalog.set_config('row_security', 'off', true);
    INSERT INTO public.bug_report_intake_marks (claim_id, reporter_id, intake_group_id,
                                                submitted_at, title, filed_labels)
    SELECT DISTINCT ON (c.id)
           c.id, e.agent_id,
           CASE WHEN (e.details ->> 'intake_group_id') ~ v_uuid
                THEN (e.details ->> 'intake_group_id')::uuid
                ELSE c.owner_group_id END,
           e.created_at,
           -- The title is only in the claim's properties (see the header).
           (c.properties -> 'bug_report' ->> 'title'),
           -- The labels the write put on the row, rebuilt from the audit row
           -- (definer-written only, 207 (b)), as the write composes them.
           ARRAY['backlog', 'bug-report', 'intake']::text[]
           || CASE WHEN (e.details ->> 'severity') IN ('blocker', 'major', 'minor')
                   THEN ARRAY['severity:' || (e.details ->> 'severity')]
                   ELSE '{}'::text[] END
           || CASE WHEN (e.details ->> 'component') ~ '^[a-z0-9][a-z0-9-]{0,47}$'
                   THEN ARRAY['component:' || (e.details ->> 'component')]
                   ELSE '{}'::text[] END
      FROM public.security_events e
      -- Joined on the uuid, so `claims_pkey` serves the probe (a cast on the
      -- claims side would read the whole heap); a malformed value joins nothing.
      JOIN public.claims c
        ON c.id = CASE WHEN (e.details ->> 'claim_id') ~ v_uuid
                       THEN (e.details ->> 'claim_id')::uuid END
     WHERE e.event_type = 'bug_report.submitted'
       AND e.agent_id IS NOT NULL
       AND c.agent_id = e.agent_id
       -- A second, independent condition, as 207's owner-group filter was:
       -- only a claim the write itself composed is a report, so an audit row
       -- naming a claim its agent authored by another path marks nothing.
       AND c.properties ? 'bug_report'
     ORDER BY c.id, e.created_at, e.id
    ON CONFLICT (claim_id) DO NOTHING;
    PERFORM pg_catalog.set_config('row_security', 'on', true);
END $$;

-- ===================================================================
-- (c) THE WRITE (211's body plus the marker INSERT)
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
    -- 211: the evidence's stored `evidence -> claim` edge (backlog 2d60f619).
    -- Same definer frame, same statement sequence: the edge's tenancy is the
    -- meet of its endpoints (`epigraph_edges_tenancy`), both owned by the
    -- intake group with visibility 'group', so it is exactly as private as the
    -- evidence and the claim. Unsigned: a database function holds no key.
    -- The write window (206's pattern, pg_temp still last): the `edges`
    -- INVOKER triggers inherit this frame's path and name their helpers
    -- unqualified (`trigger_validate_edge_refs` -> `validate_edge_reference`),
    -- which the pinned path cannot resolve (42883, measured). The function's
    -- SET clause restores the pinned path at exit in any case.
    PERFORM pg_catalog.set_config('search_path', 'public, pg_temp', true);
    INSERT INTO public.edges (source_id, source_type, target_id, target_type, relationship,
                              properties)
    VALUES (v_ev, 'evidence', v_claim, 'claim', 'supports', '{}'::jsonb);
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
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
    -- 272: the intake marker (backlog e690866c), in the same statement
    -- sequence as the row: the reporter's list and the theme scripts' label
    -- exclusion key on it, so a report triage later moves out of the intake
    -- group, or one filed under an intake group the operator has since
    -- replaced, is still known for what it is.
    INSERT INTO public.bug_report_intake_marks (claim_id, reporter_id, intake_group_id,
                                                submitted_at, title, filed_labels)
    VALUES (v_claim, v_principal, v_group, v_now, p_title, v_labels);

    RETURN QUERY SELECT v_claim, v_now;
END $$;

COMMENT ON FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, text, text,
                                                      bytea, bytea, text) IS
    'Migration 207: file one bug report into the configured intake group as the session '
    'principal, who need not be a member of it. Returns the receipt (claim id, submitted_at) '
    'and nothing about the group''s other contents. 272: records the intake marker.';
REVOKE EXECUTE ON FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, text,
                                                             text, bytea, bytea, text)
    FROM PUBLIC;

-- ===================================================================
-- (d) THE READ, keyed on the marker
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
    -- 272: the reports the caller FILED (its markers), wherever triage has
    -- moved them since and whichever intake group they were filed into; the
    -- claim must still be authored by the caller. Which reports are listed is
    -- not keyed on `v_group`; what each one SHOWS is: the live title and
    -- labels only while the claim is owned by the CURRENT intake group (207's
    -- surface, unchanged), otherwise only what was filed (the marker's title
    -- and labels) plus `resolved`. A report another group now owns is that
    -- group's information, and 207 never showed it to the reporter at all.
    RETURN QUERY
    SELECT c.id,
           CASE WHEN c.owner_group_id = v_group
                THEN (c.properties -> 'bug_report' ->> 'title')
                ELSE m.title END,
           m.submitted_at,
           CASE WHEN c.owner_group_id = v_group THEN c.labels
                WHEN 'resolved' = ANY (c.labels)
                THEN m.filed_labels || ARRAY['resolved']::text[]
                ELSE m.filed_labels END,
           'resolved' = ANY (c.labels),
           c.is_current
      FROM public.bug_report_intake_marks m
      JOIN public.claims c ON c.id = m.claim_id
     WHERE m.reporter_id = v_principal
       AND c.agent_id = v_principal
     ORDER BY m.submitted_at DESC, c.id
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 50), 1), 200);
END $$;
COMMENT ON FUNCTION public.epigraph_my_bug_reports(integer) IS
    'Migration 207: the session principal''s own intake reports (claim id, title, '
    'submitted_at, current labels, resolved, is_current), newest first, at most 200. '
    '272: keyed on the intake marker recorded at filing, not on the current intake group; '
    'a report owned outside the current intake group shows only its filed title and labels '
    'plus resolved.';
REVOKE EXECUTE ON FUNCTION public.epigraph_my_bug_reports(integer) FROM PUBLIC;

-- `CREATE OR REPLACE` keeps owners and grants; re-asserted, as 211 does, so a
-- database whose 207 ran without the roles converges too.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, '
                'text, text, bytea, bytea, text) OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_my_bug_reports(integer) '
                'OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 272 function '
                     'bodies stay owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_submit_bug_report(text, text, text, '
                'text, text, text, text, bytea, bytea, text) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_my_bug_reports(integer) '
                'TO epigraph_app';
    END IF;
END $$;
