-- ===================================================================
-- 153-undo.sql: take migration 153 (an armed lineage stays in its owner
-- group) back out, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Once undone, an armed application session can again attach a
-- current successor, declared in its own group, to a claim another group
-- owns (migration 153's header, section 1). No binary depends on 153: it
-- only refuses writes, with SQLSTATE OPL02, which every surface already maps.
--
-- WHAT IT DOES
--   Restores migration 123's body of
--   `public.epigraph_claims_require_operator_binding()` byte for byte, and
--   re-asserts its owner. The trigger (122) is untouched.
--
-- ORDER: newest first. Run this BEFORE `123-undo.sql`, which restores 122's
-- body of the same function.
--
-- WHAT IT LEAVES: 153's `_sqlx_migrations` row. Re-introducing the rule is a
-- NEW migration, never a re-run of 153. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- Migration 123's body, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_writer uuid;
    v_inherited boolean := false;
    v_reopen boolean := false;
BEGIN
    -- 123 (round 4 DIS-R4-1): A CLAIM NEVER SUPERSEDES ITSELF, on every
    -- session, armed or not. The FIRST statement: the cheap early return
    -- below waves through `SET supersedes = id` on a claim that had none,
    -- which is exactly the first half of the two-statement self-loop. Only a
    -- statement that SETS the self-reference is refused, so a self-loop
    -- written before 123 can still be retired; its re-open is a fresh claim
    -- (`p.id <> NEW.id` in the inherited test below).
    IF NEW.supersedes = NEW.id
       AND (TG_OP = 'INSERT' OR NEW.supersedes IS DISTINCT FROM OLD.supersedes) THEN
        RAISE EXCEPTION 'OPL02: claim % names itself in supersedes; a claim never supersedes '
                        'itself', NEW.id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede it with a new claim (the supersede act).';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        -- A re-open is a re-open whatever else the statement changes: an
        -- UPDATE that also re-attributes is checked as an INSERT of NEW too.
        v_reopen := NOT COALESCE(OLD.is_current, true) AND COALESCE(NEW.is_current, true);
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        -- Only `supersedes` / `is_current` (the trigger's other columns) can
        -- have changed. Cheap OLD/NEW tests first: a retire or an untouched
        -- column returns before any table is read.
        IF NOT v_reopen
           AND (NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes OR OLD.supersedes IS NULL) THEN
            RETURN NEW;
        END IF;
        -- 123 (round 4 COR-R4-1 / SEC-R4-2): the lineage and re-open relief
        -- is the PRIVILEGED session's alone. 122 returned here for "the
        -- exemption", so an instance-admin principal (an application-session
        -- stamp) re-opened what its own INSERT of the row is refused, and
        -- cleared an inherited successor's lineage. Every application session
        -- now meets the lineage guard below, and its re-open is checked as an
        -- INSERT (with OQ-1 (b) the exemption is this same `epigraph_bypass()`).
        IF NOT public.epigraph_operator_binding_armed() OR public.epigraph_bypass() THEN
            RETURN NEW;
        END IF;
    ELSIF NOT public.epigraph_operator_binding_armed() THEN
        RETURN NEW;
    END IF;
    -- THE LINEAGE GUARD, on every non-privileged UPDATE that changes
    -- `supersedes`, whatever the statement does to `agent_id` (review
    -- COR-MTC-2: guarding only the same-author branch let a custodian clear a
    -- lineage by re-attributing in the same statement).
    IF TG_OP = 'UPDATE' AND NOT public.epigraph_bypass()
       AND NEW.supersedes IS DISTINCT FROM OLD.supersedes AND OLD.supersedes IS NOT NULL
       AND (NEW.supersedes IS NULL OR COALESCE(NEW.is_current, true)) THEN
        RAISE EXCEPTION 'OPL02: claim % records that it supersedes %; an application session '
                        'does not clear, or re-point on a current claim, the lineage of an '
                        'existing claim', NEW.id, OLD.supersedes
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead, or retire it in the same statement '
                         '(the dedup act). A custodial revision is made on the maintenance '
                         'DSN with epigraph-operator custodial-supersede.';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id
       AND NOT v_reopen THEN
        RETURN NEW;
    END IF;
    -- A RE-OPEN on a non-privileged session (and any re-attribution): checked
    -- below as an INSERT of NEW.
    -- RE-ATTRIBUTION. Every check below reads the NEW author only, so an
    -- UPDATE that changes it would let a writer take over (or hand off) a
    -- claim someone else said, including another human's claim in a group
    -- both humans write. No repository or route changes `claims.agent_id`;
    -- only the exemption (a privileged session: OQ-1 (b)) may, and it is then
    -- checked like an insert below. OPL02, keyed on the
    -- arming: it is attribution, which the valve never relieves.
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS DISTINCT FROM OLD.agent_id
       AND NOT public.epigraph_operator_scope_exempt() THEN
        RAISE EXCEPTION 'OPL02: claim % is attributed to %; an application session does not '
                        're-attribute an existing claim (here to %)', NEW.id, OLD.agent_id,
                        NEW.agent_id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead: the successor is written, and attributed, '
                         'by the writer. A custodial revision is made on the maintenance DSN '
                         'with epigraph-operator custodial-supersede.';
    END IF;
    v_writer := public.epigraph_principal_id();
    -- NO PRINCIPAL on an application session is an unbound writer, not a
    -- licence to be checked on the author column alone: a route that forgot
    -- to stamp its viewer would otherwise write as whatever bound author its
    -- request body named, into that author's group. Fail closed (OPL01, so
    -- the valve relieves it and nothing else does); with the valve open the
    -- author arm below still applies its OPL02.
    IF v_writer IS NULL AND NOT public.epigraph_bypass()
       AND public.epigraph_operator_binding_enforced() THEN
        RAISE EXCEPTION 'OPL01: this application session carries no authenticated principal, '
                        'so the writer of this claim (attributed to %) is not bound to a human '
                        'operator; once armed, a claim is written only by a bound, stamped '
                        'writer', NEW.agent_id
            USING ERRCODE = 'OPL01',
                  HINT = 'Write on a transaction stamped with the request''s viewer '
                         '(ScopedPool::begin_as). See docs/tenancy.md "Operator binding".';
    END IF;
    IF (TG_OP = 'INSERT' OR v_reopen) AND NEW.supersedes IS NOT NULL THEN
        v_inherited :=
            EXISTS (SELECT 1 FROM public.claims p
                     WHERE p.id = NEW.supersedes
                       AND p.id <> NEW.id  -- 123 (DIS-R4-1): never the row's own OLD version
                       AND p.agent_id IS NOT DISTINCT FROM NEW.agent_id
                       AND p.owner_group_id IS NOT DISTINCT FROM NEW.owner_group_id
                       AND NOT COALESCE(p.is_current, true))
            AND NOT EXISTS (SELECT 1 FROM public.claims s
                             WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                               AND COALESCE(s.is_current, true))
            -- 123 (round 4 SEC-R4-1): on a non-privileged session a retired
            -- identity's claim is restated AT MOST ONCE, ever. "No other
            -- CURRENT successor" alone re-admitted a predecessor whose
            -- successor had been retired, so retire-and-restate doubled the
            -- current claims under the identity each round. A privileged
            -- session keeps 122's rule: its custodial revision of a canonical
            -- claim that retired duplicates point at must still work.
            AND (public.epigraph_bypass()
                 OR NOT EXISTS (SELECT 1 FROM public.claims s
                                 WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                                   AND s.agent_id IS NOT DISTINCT FROM NEW.agent_id))
            -- 123 (review SEC-MTC-3): the at-most-once rule bounds BRANCHING;
            -- a RE-OPEN must not resurrect a version of a lineage that is
            -- current elsewhere either. On a non-privileged session a
            -- re-opened claim inherits nothing while ANY other version of its
            -- lineage, an ancestor up its `supersedes` chain or a descendant
            -- down it, is current. Testing only its own successor still let
            -- alternate versions of a chain be re-opened (S1 while S2 is
            -- retired and S3 current), one more current claim under the
            -- retired identity per two versions. Retiring the head and
            -- re-opening its predecessor (the undo) still works. UNION, not
            -- UNION ALL, so a legacy cycle terminates.
            AND (public.epigraph_bypass() OR NOT v_reopen
                 OR NOT EXISTS (
                     WITH RECURSIVE up(id, supersedes, cur) AS (
                         SELECT c.id, c.supersedes, COALESCE(c.is_current, true)
                           FROM public.claims c WHERE c.id = NEW.supersedes
                         UNION
                         SELECT c.id, c.supersedes, COALESCE(c.is_current, true)
                           FROM public.claims c JOIN up ON c.id = up.supersedes),
                     down(id, cur) AS (
                         SELECT c.id, COALESCE(c.is_current, true)
                           FROM public.claims c WHERE c.supersedes = NEW.id
                         UNION
                         SELECT c.id, COALESCE(c.is_current, true)
                           FROM public.claims c JOIN down ON c.supersedes = down.id)
                     SELECT 1 FROM up WHERE up.cur AND up.id <> NEW.id
                     UNION ALL
                     SELECT 1 FROM down WHERE down.cur AND down.id <> NEW.id));
    END IF;
    IF v_writer IS NULL OR v_writer = NEW.agent_id OR public.epigraph_bypass() THEN
        -- THE PLATFORM CORPUS'S EDIT PATH. A PRIVILEGED session (the
        -- maintenance role or a superuser: `epigraph_bypass()`, which no
        -- application session can forge) restating a retired predecessor
        -- carries that predecessor's author whatever its binding: world-owned
        -- legacy rows are authored by retired-linked or unlinked identities by
        -- construction, so the author check would refuse every such supersede.
        -- Nothing else is relieved: a fresh claim, or a posed successor, is
        -- checked on its author as always, and an instance-admin PRINCIPAL
        -- writing as itself is not relieved here (it is a stamp an application
        -- session sets). Its supersede of ANOTHER author's retired-linked claim
        -- takes the ELSE branch: the attribution check's inherited rule.
        IF NOT (v_inherited AND public.epigraph_bypass()) THEN
            PERFORM public.epigraph_require_bound_author(NEW.agent_id);
        END IF;
        PERFORM public.epigraph_require_writer_scope(NEW.agent_id, NEW.owner_group_id);
    ELSE
        PERFORM public.epigraph_require_bound_writer(v_writer);
        PERFORM public.epigraph_require_writer_scope(v_writer, NEW.owner_group_id);
        PERFORM public.epigraph_require_attributable(NEW.agent_id, v_writer, v_inherited);
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_operator_binding() FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_claims_require_operator_binding() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;

COMMIT;
