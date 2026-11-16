-- 211: a bug report's evidence carries its stored edge to the report's claim
-- (backlog 2d60f619).
--
-- ===================================================================
-- WHY
-- ===================================================================
--
-- Operator ruling on the Atlas leaf view: leaves draw stored evidence -> claim
-- edges only (no derived edge), so every evidence write must write that edge.
-- Every Rust writer does it through `EvidenceRepository::link_to_claims_signed_conn`.
-- `epigraph_submit_bug_report` (207) is the one SQL-side evidence writer, and
-- 207 deliberately wrote "no verb edges ... an edge would be one more row
-- tenancy has to keep private". The ruling supersedes that: the edge is
-- written here, in the same definer frame as the evidence row. It is owned
-- exactly like the evidence and the claim (the intake group, 'group'), so it
-- discloses nothing the evidence row does not, and the reporter (not a member
-- of the intake group) can no more read it than the evidence.
--
-- ===================================================================
-- WHAT CHANGES
-- ===================================================================
--
-- `epigraph_submit_bug_report` is redefined from 207 with ONE added
-- statement, the edge INSERT after the evidence INSERT, inside a
-- transaction-local search_path window (206's pattern) so the `edges`
-- triggers resolve their unqualified helpers. Nothing else in the function
-- changes. `CREATE OR REPLACE` keeps the function's owner and its grants
-- (207's EXECUTE grant to the application role); both are re-asserted at the
-- end, as 209 does.
--
-- Undo: re-apply 207's definition of `epigraph_submit_bug_report`.

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

-- `CREATE OR REPLACE` keeps 207's owner and grant; they are re-asserted here,
-- as 209 does, so a database whose 207 ran without the roles converges too.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_submit_bug_report(text, text, text, text, text, '
                'text, text, bytea, bytea, text) OWNER TO epigraph_maintenance';
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; the 211 function '
                     'body stays owned by the migration runner.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_submit_bug_report(text, text, text, '
                'text, text, text, text, bytea, bytea, text) TO epigraph_app';
    END IF;
END $$;
