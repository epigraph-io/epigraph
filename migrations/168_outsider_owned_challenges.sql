-- 168: an outsider's challenge is owned by the outsider (operator ruling
-- R-CH1, 2026-10-24; backlog 2f2eeaea).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- `challenges` is claim-derived: 074's `challenges_require_tenancy` (BEFORE
-- INSERT) fills `(owner_group_id, visibility)` from the CHALLENGED claim,
-- 070 arm (c) re-syncs it on every later insert for that claim, and arm (d)
-- (`claims_propagate_tenancy`) copies every change of the claim's tenancy onto
-- it. 077's WITH CHECK therefore asked for the CLAIM's group in the session's
-- writable set, and an objection by anyone who cannot write that group (an
-- "outsider") was refused with 42501. Most public claims are owned by the
-- memberless WORLD group, so on most of the corpus nobody could object at all.
--
-- The ruling: an outsider's challenge is owned by the outsider; with no
-- account it would be public (no challenge path admits a principal-less
-- caller, so that arm has no writer here). An outsider is a challenger that
-- cannot write the challenged claim's owning group.
--
-- ===================================================================
-- 1. THE RULE, BY REUSING 114's WRITER-OWNED MACHINERY
-- ===================================================================
--
-- No new function here (section 7's resolution definer is the file's one new
-- function). `challenges` joins 114's writer-owned rows:
--
--   * a `writer_owned` column (the name the operator CLI's table specs read
--     from the catalog, `epigraph_cli::operator::tables`);
--   * `challenges_attach_writer` (BEFORE INSERT ROW) runs 114's
--     `epigraph_attach_writer_owner()` unchanged: a privileged session, an
--     unreadable claim, a claim in a writable group (an INSIDER) and a
--     non-public claim are all left exactly as before (inherit, and 077
--     decides); a PUBLIC claim the session can read but not write gets the
--     writer's group (`epigraph_writer_group()`, the group a plain claim by
--     the same principal lands in), `visibility = 'public'` and
--     `writer_owned = true`, decided on the claim row locked against a
--     concurrent privatization (114's W6). It sorts before
--     `challenges_require_tenancy`, whose first arm keeps a declared row.
--   * `challenges_writer_owner_guard` (BEFORE UPDATE ROW) runs 114's
--     `epigraph_writer_owner_guard()` with 114's WHEN clause: no application
--     session changes `owner_group_id` or `writer_owned`, or the `claim_id` or
--     `visibility` of a writer-owned challenge. 115's
--     `challenges_owner_immutable` already guarded the owner.
--
-- Insiders keep today's behaviour: their challenge inherits the claim's
-- tenancy, public or not, and stays a projection of it.
--
-- ===================================================================
-- 2. THE TWO PROPAGATION ARMS, AND WHERE CHALLENGES DIFFER FROM 114
-- ===================================================================
--
-- Arm (c) `epigraph_inherit_tenancy_stmt`: 114's body with `challenges` added
-- to the writer-owned skip, so a later insert on the claim never re-stamps an
-- outsider's challenge.
--
-- Arm (d) `epigraph_propagate_tenancy`: 122's body with ONE added `IF` in the
-- loop that skips writer-owned `challenges` rows. `challenges` is NOT added to
-- `writer_tables`, so the narrowing statement that hands 114's writer-owned
-- evidence, BBAs and traces to the claim's owner when the claim narrows does
-- not touch an outsider's challenge: privatizing (or re-owning) the claim
-- never drags it into the claim's group (orchestrator ruling under R-CH1).
-- It stays the outsider's and stays public; section 6 keeps that from
-- becoming an existence oracle for the now private claim (R-CH1b): reading a
-- challenge requires reading its claim, in row security and in-query.
--
-- Byte-for-byte otherwise: the `derived text[]` literal (read by
-- `epigraph_cli::operator::tables::parse_derived_array`), the pin and
-- writer-owned arms, the fragments statement, and the edges meet (whose three
-- conditional expressions `tenancy_triggers.rs` counts; the added arm is an
-- `IF`, not an expression).
--
-- ===================================================================
-- 3. WHAT THIS FILE DOES NOT DO
-- ===================================================================
--
--   * It re-owns NO existing row. Every challenge row predates the rule and
--     was written by an insider or a privileged session; all get
--     `writer_owned = false` (the column default) and keep their tenancy. A
--     backfill, if one is ever ruled, is an operator script.
--   * It does not touch 126's elevated arms on `challenges` (read arm and the
--     three write refusals), 077's policy or 115's DELETE and owner guards; it
--     ADDS one restrictive read policy (section 6).
--   * It does not let the claim's owner EDIT or DELETE an outsider's
--     challenge: `ChallengeRepository::update_state` on a row the owner cannot
--     write is refused by 077 like any other cross-group UPDATE, and a DELETE
--     is filtered by 115. What the owner MAY do (ruling R-3) is set the row's
--     RESOLUTION STATUS, through the one definer of section 7, which changes
--     only the four resolution columns and audits the resolver. No HTTP or MCP
--     route calls it yet (`ChallengeRepository::resolve_as_claim_owner` is the
--     repo surface); that is a follow-up.
--
-- ===================================================================
-- 4. DEPLOY
-- ===================================================================
--
-- Depends on 114 (the attach and guard functions, `epigraph_writer_group`),
-- 115 and 122 (the bodies replaced here); independent of everything after 153.
-- `ADD COLUMN ... NOT NULL DEFAULT false` is a catalog-only change on
-- PostgreSQL 11+ (no table rewrite); `CREATE POLICY` and the trigger DDL take
-- short table locks on `challenges`, all under `lock_timeout`. Apply BEFORE a
-- binary built with this change serves: that binary admits an outsider in its
-- preflight, and without the attach rule the INSERT would inherit the claim's
-- group and be refused (MCP: "refused after the writer check"; HTTP: 403). A
-- binary WITHOUT this change against a database WITH it keeps working: its
-- insiders inherit as before, its outsiders are refused by name as before,
-- and its challenge reads are additionally narrowed by section 6.
--
-- UNDO: DROP FUNCTION epigraph_resolve_challenge(uuid, text, jsonb) (section
-- 7), DROP POLICY challenges_claim_readable (section 6), DROP the two
-- triggers, re-run 114's section 3b and 122's section 8 (`CREATE OR REPLACE`
-- from their text), then DROP COLUMN writer_owned on `challenges` (after
-- deciding what to do with any outsider-owned row).
--
-- Checked before claiming: no `origin/main` migration and no open PR carries a
-- `168`.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1a. THE MARKER COLUMN
-- ===================================================================
ALTER TABLE public.challenges
    ADD COLUMN IF NOT EXISTS writer_owned boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.challenges.writer_owned IS
    'Migration 168 (ruling R-CH1): true when an OUTSIDER (a challenger that cannot write the '
    'claim''s group) challenged a PUBLIC claim, so the row is owned by the challenger''s group, '
    'not the claim''s, and never follows the claim. Set only by challenges_attach_writer.';

-- ===================================================================
-- 1b. THE ATTACH RULE AND THE GUARD (114's functions, unchanged)
-- ===================================================================
DROP TRIGGER IF EXISTS challenges_attach_writer ON public.challenges;
CREATE TRIGGER challenges_attach_writer BEFORE INSERT ON public.challenges
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_attach_writer_owner();

DROP TRIGGER IF EXISTS challenges_writer_owner_guard ON public.challenges;
CREATE TRIGGER challenges_writer_owner_guard
    BEFORE UPDATE OF owner_group_id, writer_owned, claim_id, visibility ON public.challenges
    FOR EACH ROW
    WHEN (OLD.owner_group_id IS DISTINCT FROM NEW.owner_group_id
          OR OLD.writer_owned IS DISTINCT FROM NEW.writer_owned
          OR (OLD.writer_owned
              AND (OLD.claim_id IS DISTINCT FROM NEW.claim_id
                   OR OLD.visibility IS DISTINCT FROM NEW.visibility)))
    EXECUTE FUNCTION public.epigraph_writer_owner_guard();

-- ===================================================================
-- 2a. ARM (c): epigraph_inherit_tenancy_stmt (114's body + challenges)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_inherit_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE n_orphan bigint;
BEGIN
    -- ===============================================================
    -- THIS ARM IS INTENTIONALLY UNCONDITIONAL -- IT HAS NO NO-WIDENING GATE.
    -- A claim-DERIVED row is a projection of its parent claim, so "a derived
    -- row always equals its parent" IS the invariant (070's comment, in full
    -- in 110). The `IS DISTINCT FROM` below is an IDEMPOTENCE guard, not a
    -- direction guard.
    --
    -- THE TWO EXCEPTIONS:
    --   * 110: an `evidence` row an operator explicitly HID is PINNED in
    --     `evidence_visibility_pins`, and this re-sync skips it.
    --   * 114: an `evidence`, `mass_functions` or `reasoning_traces` row a
    --     writer ATTACHED to a public claim it could not write is
    --     `writer_owned`: it is the writer's, not a projection of the claim's
    --     owner, and this re-sync skips it. Only `<table>_attach_writer` sets
    --     the flag, and only a maintenance session can change it.
    --   * 168: an OUTSIDER's `challenges` row (ruling R-CH1) is writer-owned
    --     the same way, and skipped the same way.
    -- ===============================================================
    -- NO epigraph_definer_bypass() ASSERTION HERE, DELIBERATELY (070): arm (c)
    -- fires on every ordinary application INSERT.
    EXECUTE format(
      'UPDATE %I t SET owner_group_id = c.owner_group_id, visibility = c.visibility
         FROM public.claims c
        WHERE c.id = t.claim_id
          AND t.claim_id IN (SELECT n.claim_id FROM newrows n WHERE n.claim_id IS NOT NULL)
          AND (t.owner_group_id, t.visibility)
              IS DISTINCT FROM (c.owner_group_id, c.visibility)', TG_TABLE_NAME)
      || CASE WHEN TG_TABLE_NAME = 'evidence' THEN
             ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
             ' WHERE vp.evidence_id = t.id)'
         ELSE '' END
      || CASE WHEN TG_TABLE_NAME IN ('evidence', 'mass_functions', 'reasoning_traces',
                                     'challenges') THEN
             ' AND NOT t.writer_owned'
         ELSE '' END;
    -- Unresolvable parent => RAISE, never a default.
    EXECUTE 'SELECT count(*) FROM newrows n
              WHERE n.claim_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM public.claims c WHERE c.id = n.claim_id)'
      INTO n_orphan;
    IF n_orphan > 0 THEN
        RAISE EXCEPTION 'epigraph tenancy: % row(s) in % reference a nonexistent '
                        'parent claim', n_orphan, TG_TABLE_NAME
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_inherit_tenancy_stmt() FROM PUBLIC;

-- ===================================================================
-- 2b. ARM (d): epigraph_propagate_tenancy (122's body + one IF)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint; pin_skip text;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
        writer_tables text[] := ARRAY['evidence','mass_functions','reasoning_traces'];
BEGIN
    -- The firing gate. MUST stay ahead of the assertion below.
    IF NOT EXISTS (
        SELECT 1 FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.owner_group_id, ch.visibility)
               IS DISTINCT FROM (p.owner_group_id, p.visibility))
    THEN RETURN NULL; END IF;

    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: propagation requires a maintenance-role '
                        'owner; refusing to run RLS-filtered' USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY derived LOOP
        -- 110: a PINNED evidence row is left to the statement after the loop.
        -- (An IF, not a conditional expression: `tenancy_triggers.rs` counts
        -- this body's conditional expressions to pin the edges meet at three.)
        IF t = 'evidence' THEN
            pin_skip := ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
                        ' WHERE vp.evidence_id = d.id)';
        ELSE
            pin_skip := '';
        END IF;
        -- 114: a WRITER-OWNED row is left to the statement after the loop.
        IF t = ANY (writer_tables) THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        -- 168 (R-CH1): an OUTSIDER's challenge is the challenger's, and it
        -- never follows the claim, so it is not in `writer_tables` and the
        -- narrowing statement after the loop does not re-own it either.
        IF t = 'challenges' THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip;
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- 110: PINNED evidence. Never widened, owner never changed.
    SELECT count(*) INTO expected
      FROM public.evidence d
      JOIN changed ch ON ch.id = d.claim_id
      JOIN public.evidence_visibility_pins vp ON vp.evidence_id = d.id
     WHERE d.visibility IS DISTINCT FROM 'group'::character varying(16);
    IF expected > 0 THEN
        UPDATE public.evidence d
           SET visibility = 'group'::character varying(16)
          FROM changed ch, public.evidence_visibility_pins vp
         WHERE ch.id = d.claim_id
           AND vp.evidence_id = d.id
           AND d.visibility IS DISTINCT FROM 'group'::character varying(16);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to pinned evidence updated % '
                            'of % rows (RLS filtered?)', actual, expected;
        END IF;
    END IF;
    -- 114: WRITER-OWNED rows. While the claim stays public they are left
    -- alone: their owner is the writer's whoever the claim moves to, and their
    -- visibility is already the claim's (or narrower, for pinned evidence).
    -- When the claim NARROWS to non-public they become the claim's: owner and
    -- visibility follow the claim and the flag is cleared (review finding W5).
    -- Keeping the writer as owner there would leave rows about a private claim
    -- readable by the writer's group and hidden from the claim's own owner,
    -- which is sequestering evidence from the one party who now holds the
    -- claim; privatization's seal already encrypts every evidence row of the
    -- claim with the claim group's key, the writer's included. Pinned evidence
    -- is re-owned too (its visibility is 'group' either way, set above).
    -- Issued only when a count finds a row to change.
    FOREACH t IN ARRAY writer_tables LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE d.writer_owned
               AND ch.visibility IS DISTINCT FROM ''public''', t)
          INTO expected;
        IF expected > 0 THEN
            EXECUTE format(
              'UPDATE %I d SET owner_group_id = ch.owner_group_id,
                               visibility     = ch.visibility,
                               writer_owned   = false
                 FROM changed ch
                WHERE ch.id = d.claim_id
                  AND d.writer_owned
                  AND ch.visibility IS DISTINCT FROM ''public''', t);
            GET DIAGNOSTICS actual = ROW_COUNT;
            IF actual <> expected THEN
                RAISE EXCEPTION 'epigraph tenancy: propagation to writer-owned % updated % '
                                'of % rows (RLS filtered?)', t, actual, expected;
            END IF;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
    UPDATE public.edges e
       SET owner_group_id    = m.g,
           visibility        = m.v,
           co_owner_group_id = m.co
      FROM (
        SELECT DISTINCT e2.id,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN s.v = 'public' THEN t.g
                    WHEN t.v = 'public' THEN s.g
                    ELSE s.g END AS g,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN 'public'::character varying(16)
                    ELSE 'group'::character varying(16) END AS v,
               CASE WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g
                         THEN t.g
                    ELSE NULL END AS co
          FROM (SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.source_id = ch.id AND x.source_type = 'claim'
                UNION
                SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.target_id = ch.id AND x.target_type = 'claim') e2
          LEFT JOIN public.claims   sc ON e2.source_type = 'claim'    AND sc.id = e2.source_id
          LEFT JOIN public.evidence se ON e2.source_type = 'evidence' AND se.id = e2.source_id
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility,
                            'public'::character varying(16)) AS v) t
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND m.v = 'group'
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;

-- ===================================================================
-- 5. OWNERSHIP (CREATE OR REPLACE keeps it; re-set regardless, as 114/122 do)
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_inherit_tenancy_stmt() OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 6. READS FOLLOW THE CLAIM (ruling R-CH1b)
-- ===================================================================
--
-- Section 2 keeps an outsider's challenge where it is when its claim is
-- privatized: owned by the outsider, public. On its own that makes the row an
-- existence oracle for the now private claim: its `claim_id`, its explanation
-- and its mere presence in a per-claim list or count tell every reader that
-- this id names a claim, which must be indistinguishable from a random id to
-- anyone who cannot read the claim (R-CH1b). So OWNERSHIP stays with the
-- outsider, and READING a challenge additionally requires reading its claim.
--
-- Enforced here, in the database, so every reader is covered (the repo
-- functions, the corpus counts, and any query written later), not only the
-- reads that remember the predicate. `ChallengeRepository::{get,
-- list_for_claim, get_gap_challenges}` and `CorpusStatsRepository` carry the
-- same claim predicate in-query as well (`/* {VISIBILITY:c} */`), which is what
-- protects a privileged (row-security-bypassing) connection.
--
-- RESTRICTIVE, FOR SELECT: AND-ed with 077's `challenges_tenancy` and with
-- 126's `challenges_elevated_read`, it grants nothing and only narrows reads.
-- The claim arm is an EXISTS over `claims` evaluated with the reader's own
-- rights, so "can read the claim" is exactly the claims policies' answer for
-- that session, 126's `claims_elevated_read` included (an elevated session
-- that reads every claim keeps reading every challenge). The two session arms
-- keep the maintenance session and the definers (arm (d)'s propagation, the
-- operator CLI, the seal) unaffected. No policy on `claims` reads
-- `challenges`, so there is no recursion. Writes: PostgreSQL applies SELECT
-- policies to an UPDATE or DELETE that reads the row, so a challenge on a
-- claim the session cannot read is also not updatable or deletable by it,
-- which is the same fence; an INSERT without RETURNING is unaffected.
DROP POLICY IF EXISTS challenges_claim_readable ON public.challenges;
CREATE POLICY challenges_claim_readable ON public.challenges
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR EXISTS (SELECT 1 FROM public.claims c WHERE c.id = challenges.claim_id));

-- ===================================================================
-- 7. THE CLAIM'S OWNER SETS A CHALLENGE'S RESOLUTION STATUS (ruling R-3)
-- ===================================================================
--
-- An outsider's challenge is the outsider's (section 1), so 077's WITH CHECK
-- refuses the claim's owner any UPDATE of it, and 115's restrictive DELETE
-- policy any DELETE. The ruling (R-3, 2026-10-25): the challenged claim's
-- owner group may set the RESOLUTION STATUS of an outsider-owned challenge,
-- with an audit record naming the resolver, but may NOT edit or delete the
-- outsider's text, and the outsider keeps ownership.
--
-- So no policy arm is widened: a widened UPDATE arm would admit every column.
-- This definer is the one path, and it can change only the four resolution
-- columns because they are the only ones its UPDATE names:
--
--   * `state`, from the resolver's states only (`under_review`, `accepted`,
--     `rejected`; `withdrawn` is the challenger's act, `pending` is not a
--     resolution), else CR04 (22023);
--   * `resolved_by` := the SESSION PRINCIPAL, never a caller-supplied id;
--   * `resolved_at` := now() on `accepted` / `rejected`, as
--     `ChallengeRepository::update_state` sets it;
--   * `resolution_details` := the caller's JSON (may be NULL).
--
-- It refuses, before writing anything:
--   * CR01 (42501) no session principal: nothing to name as the resolver;
--   * CR05 (42501) an ELEVATED session: 126's `challenges_elevated_no_update`
--     refuses an elevated application session every UPDATE of `challenges`,
--     and this definer (whose owner 126's policy does not name) must not be
--     the way around it;
--   * CR02 (P0002) "challenge not found" when the challenge does not exist OR
--     the session cannot read its claim, with ONE text for both, so this is
--     no existence oracle for a private claim (R-CH1b);
--   * CR03 (42501) a session that cannot WRITE the claim's owning group (the
--     outsider itself, a stranger, a reader member of the claim's group).
--
-- Insiders' challenges (owned by the claim's group) take the same path: the
-- claim's owner can already UPDATE them directly, and through here the write
-- is attributed and audited the same way.
--
-- Each write appends one `security_events` row (`event_type =
-- 'challenges.claim_owner_resolution'`, `agent_id` = the resolver; details:
-- the challenge, its claim, both owning groups, the state before and after,
-- the resolver), in the same transaction. `security_events` is append-only
-- and immutable (077, 082), which the row's own `resolved_by` is not: the
-- outsider owns the row, so 077 lets it rewrite its own resolution columns.
--
-- Ownership and grants: owned by `epigraph_maintenance` (so the UPDATE runs
-- with `epigraph_definer_bypass()` true), EXECUTE revoked from PUBLIC and
-- granted to `epigraph_app` and `epigraph_maintenance`, in a guarded block
-- as every such block since 060 is. Registered in `tenancy_backfill`'s
-- `DEFERRED_DEFINER_FUNCTIONS`. Caller: `ChallengeRepository::
-- resolve_as_claim_owner`.
CREATE OR REPLACE FUNCTION public.epigraph_resolve_challenge(
    p_challenge uuid, p_state text, p_details jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_principal uuid := public.epigraph_principal_id();
        v_claim uuid; v_claim_owner uuid; v_claim_vis character varying(16);
        v_row_owner uuid; v_writer_owned boolean; v_before character varying(20);
BEGIN
    IF v_principal IS NULL THEN
        RAISE EXCEPTION 'CR01: setting a challenge''s resolution status needs a session '
            'principal (epigraph.principal_id) to name as the resolver; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'CR05: an elevated session writes no challenge; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    SELECT ch.claim_id, ch.owner_group_id, ch.writer_owned, ch.state,
           c.owner_group_id, c.visibility
      INTO v_claim, v_row_owner, v_writer_owned, v_before, v_claim_owner, v_claim_vis
      FROM public.challenges ch
      JOIN public.claims c ON c.id = ch.claim_id
     WHERE ch.id = p_challenge
       FOR UPDATE OF ch;
    -- Not found and not readable give the SAME answer: no existence oracle.
    IF NOT FOUND OR NOT (v_claim_vis = 'public'
                         OR v_claim_owner = ANY (public.epigraph_session_groups())) THEN
        RAISE EXCEPTION 'CR02: challenge not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT (v_claim_owner = ANY (public.epigraph_writable_groups())) THEN
        RAISE EXCEPTION 'new row violates row-level security policy for table "challenges"'
            USING ERRCODE = '42501',
                  DETAIL = 'CR03: only a writer of the challenged claim''s owning group sets '
                           'a challenge''s resolution status';
    END IF;
    IF p_state IS NULL OR p_state NOT IN ('under_review', 'accepted', 'rejected') THEN
        RAISE EXCEPTION 'CR04: % is not a resolution status (under_review, accepted, '
            'rejected); nothing was written', COALESCE(p_state, 'NULL')
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.challenges
       SET state = p_state,
           resolved_by = v_principal,
           resolution_details = p_details,
           resolved_at = CASE WHEN p_state IN ('accepted', 'rejected') THEN now()
                              ELSE resolved_at END
     WHERE id = p_challenge;
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('challenges.claim_owner_resolution', v_principal, true,
            jsonb_build_object(
                'challenge_id',             p_challenge,
                'claim_id',                 v_claim,
                'claim_owner_group_id',     v_claim_owner,
                'challenge_owner_group_id', v_row_owner,
                'writer_owned',             v_writer_owned,
                'state_before',             v_before,
                'state_after',              p_state,
                'resolver_agent_id',        v_principal,
                'migration',                168));
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_resolve_challenge(uuid, text, jsonb) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_resolve_challenge(uuid, text, jsonb) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_resolve_challenge(uuid, text, jsonb) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_resolve_challenge(uuid, text, jsonb) '
                'TO epigraph_app';
    END IF;
END $$;
