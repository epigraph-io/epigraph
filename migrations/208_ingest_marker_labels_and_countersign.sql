-- Migration 208: the legacy ingest-marker backfill's label form, the
-- `legacy-ingest` system role, and the authorship countersign route.
--
-- ===================================================================
-- 1. WHY LABELS
--
-- Migration 198 made `properties.ingest_written` = {"tool", "by"} the
-- document ingest's own mark on the edges it writes (`agent -authored->
-- paper`, `paper -asserts-> claim`, `agent -asserts-> claim`), and every
-- provenance reader (the agent card, query_paper, a claim's authored_by, the
-- walk's own dedup probe) trusts only marked edges. Edges written before the
-- marker carry none and read as nothing until an operator backfills them.
--
-- The backfill cannot add the marker to `properties` on a SIGNED row: the
-- edge attestation (epigraph_db::edge_signature, "epigraph-edge-attestation/1")
-- covers `properties`, so the row would read "changed since it was signed".
-- It does not cover `labels`, `valid_to` or `prov_type`. So a backfilled
-- edge carries its marker as two reserved LABELS:
--
--   `epigraph:ingest_written`              the sentinel (GIN-indexable)
--   `epigraph:ingest_written_by:<uuid>`    the principal whose ingest wrote it
--
-- and every reader's marker predicate (`ingest_written_edge_sql`,
-- `ingest_written_by_sql`) reads the property OR the labels. One form for
-- every backfilled row, signed or not.
--
-- The countersign route keeps the same rule: a pending authorship
-- (`properties.pending_countersign`, written and signed by the naming
-- ingest) is cleared or declined by a reserved label on that row, never by a
-- property edit:
--
--   `epigraph:countersigned_by:<uuid>`         confirmed by that principal
--   `epigraph:countersign_declined_by:<uuid>`  declined (the row is also
--                                              retracted, valid_to = now())
--
-- ===================================================================
-- 2. THE GUARD, RE-STATED (198's function body, CREATE OR REPLACE)
--
-- `epigraph_edges_ingest_written_guard()` keeps every rule 198 gave the
-- property, unchanged, and gives the same rules to every label starting with
-- `epigraph:` (the RESERVED LABEL PREFIX), under the SAME transaction-local
-- declaration `epigraph.ingest_written_edge` = 'on':
--
--   * INSERT carrying any reserved label: refused, IWE02 (SQLSTATE 42501),
--     unless declared;
--   * UPDATE that changes the SET of reserved labels (adds, removes or
--     rewrites one): refused the same way. An UPDATE that keeps them is not;
--   * UPDATE that moves an endpoint or changes the relationship: the
--     reserved labels are DROPPED with the property (unless declared), so a
--     re-pointed edge reads as no ingest's, exactly as 198 does for the key.
--
-- Removal is refused too (198 admits dropping the property): removing
-- `epigraph:countersign_declined_by:` or `epigraph:countersigned_by:` would
-- silently reverse a person's own decision, and removing a backfill marker
-- silently withdraws credit. Only a declared transaction (the backfill and
-- its reversal, the countersign definer) changes them.
--
-- No privileged arm, as in 198: a database login can set the declaration,
-- as it can write any row. The guarantee is against application callers.
--
-- The trigger itself (198's `edges_ingest_written_guard`, BEFORE INSERT OR
-- UPDATE, FOR EACH ROW) is unchanged; replacing the function body is enough.
--
-- EXISTING ROWS: this migration REFUSES to apply (55000) when any edge
-- already carries a label with the reserved prefix. Unlike 198's property
-- strip it does not remove them: such a label was written by someone for a
-- purpose this file cannot know. Measure first:
--   SELECT count(*) FROM edges e
--    WHERE EXISTS (SELECT 1 FROM unnest(e.labels) l WHERE l LIKE 'epigraph:%');
-- The check runs under SHARE ROW EXCLUSIVE on `edges`, taken first and held
-- to commit, so no insert lands between the check and the new guard body.
--
-- ===================================================================
-- 3. THE `legacy-ingest` SYSTEM ROLE
--
-- 148's closed vocabulary (`system_agents_role_known`) gains
-- 'legacy-ingest': the ONE registered principal every pre-marker ingest edge
-- that no real ingesting agent signed (unsigned, or signed by a bulk
-- attestation identity) is backfilled as written by, so all of them read as
-- one ingest. Registration is 148's own, unchanged: maintenance only,
-- audited, immutable (`epigraph-operator register-system-agent --role
-- legacy-ingest --create-agent`, which creates an agent holding a random
-- public key whose secret never existed). It writes nothing and signs
-- nothing; it is only ever a `by`.
--
-- ===================================================================
-- 4. THE COUNTERSIGN DEFINER
--
-- `epigraph_countersign_authorship(p_paper, p_agent, p_decision,
-- p_ingested_by)` RETURNS TABLE (edge_id uuid, ingested_by uuid, outcome
-- text). Maintenance-owned SECURITY DEFINER (public, pg_temp), EXECUTE
-- epigraph_app. An `agent -authored-> paper` row the document ingest wrote
-- is administrative (world-owned between public endpoints, migration 120),
-- so no application session may change it; this is the one way a person
-- acts on a naming of themselves.
--
--   * The caller is the session's principal (`epigraph_principal_id()`).
--     Refused (CSG01, 42501) with no principal.
--   * p_agent defaults to the caller. The caller may act only for ITSELF or
--     for an agent it is the LIVE operator of: the agent's operator link
--     while it is not retired (107), else, for an agent with no link, the
--     operator its unrevoked 149 client allowance names. Anyone else is
--     refused (CSG02, 42501), nothing written. Status is not read (the
--     same binding the agent card shows as `operator_human`).
--   * The rows acted on: in-force, ingest-marked `p_agent -authored->
--     p_paper` rows whose `pending_countersign` is true and which carry no
--     countersign label yet; with p_ingested_by, only that ingest's row.
--   * 'confirm': adds `epigraph:countersigned_by:<caller>`. Every reader of
--     the pending mark (`authorship_pending_sql`) then reads the row as
--     NOT pending: the agent card counts the paper as authored, the claim
--     block lists the person as a primary author where that ingest
--     recorded them, query_paper drops the pending flag.
--   * 'decline': adds `epigraph:countersign_declined_by:<caller>` and
--     retracts the row (valid_to = now(); `valid_to` is outside the
--     attestation). A declined row never stops a later ingest of the same
--     fact by another principal (the dedup probe excludes it), so the
--     person's own later ingest still writes its own row; the naming
--     ingest's own re-run still dedups onto its declined row and never
--     re-names them.
--   * Nothing pending: zero rows, nothing written, no audit row.
--   * One `security_events` row per act ('authorship.countersigned' or
--     'authorship.countersign_declined'), naming the caller, the agent, the
--     paper and every edge. A RESTRICTIVE insert policy reserves the
--     'authorship.countersign' prefix to bypass and definer frames.
--
-- The declaration is set around the definer's one UPDATE and cleared
-- before it returns, so no other statement of the caller's transaction can
-- carry a reserved label.
--
-- LIMIT (accepted, as for every definer here): `epigraph.principal_id` is
-- a session setting; a database login can set it and act as anyone.
--
-- ===================================================================
-- 5. UNDO (superuser), after rolling back every binary that reads the
-- label forms:
--   DROP POLICY IF EXISTS security_events_countersign_privileged ON public.security_events;
--   DROP FUNCTION IF EXISTS public.epigraph_countersign_authorship(uuid, uuid, text, uuid);
--   -- 198's guard body: re-run 198's section-4 CREATE OR REPLACE FUNCTION.
--   -- The role CHECK can be narrowed back only while no 'legacy-ingest' row
--   -- exists (a registration is immutable; 148 section 4):
--   ALTER TABLE public.system_agents DROP CONSTRAINT system_agents_role_known,
--     ADD CONSTRAINT system_agents_role_known CHECK (role IN ('workflow-ingest'));
-- Reserved labels already written stay on their rows (reverse a backfill
-- with its manifest first).
-- **Applied to throwaway databases only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 2. THE GUARD (taken first: the check below and the new body see the same
-- table, with no insert in between)
-- ===================================================================
LOCK TABLE public.edges IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    v_n bigint;
BEGIN
    -- Fail closed: on a migrating role that row security would filter, the
    -- count errors instead of silently missing rows it cannot see.
    PERFORM pg_catalog.set_config('row_security', 'off', true);
    SELECT pg_catalog.count(*) INTO v_n
      FROM public.edges e
     WHERE EXISTS (SELECT 1 FROM pg_catalog.unnest(e.labels) l WHERE l LIKE 'epigraph:%');
    IF v_n > 0 THEN
        RAISE EXCEPTION '208: % edge row(s) already carry a label with the reserved prefix '
                        '"epigraph:"; this migration does not remove them. Inspect them, '
                        'remove or rename them, and re-run', v_n
            USING ERRCODE = '55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_edges_ingest_written_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- COALESCE: an unset setting reads NULL on a session that never set it
    -- (and '' on one that did), and a NULL here would admit the write.
    v_declared boolean := COALESCE(
        pg_catalog.current_setting('epigraph.ingest_written_edge', true) = 'on', false);
    v_old_reserved text[] := '{}';
    v_new_reserved text[];
BEGIN
    IF TG_OP = 'UPDATE' THEN
        v_old_reserved := ARRAY(SELECT l FROM pg_catalog.unnest(OLD.labels) l
                                 WHERE l LIKE 'epigraph:%' ORDER BY l);
    END IF;
    IF TG_OP = 'UPDATE'
       AND (OLD.properties ? 'ingest_written' OR pg_catalog.cardinality(v_old_reserved) > 0)
       AND (NEW.source_id, NEW.source_type, NEW.target_id, NEW.target_type, NEW.relationship)
           IS DISTINCT FROM
           (OLD.source_id, OLD.source_type, OLD.target_id, OLD.target_type, OLD.relationship)
       AND NOT v_declared THEN
        NEW.properties := NEW.properties - 'ingest_written';
        NEW.labels := ARRAY(SELECT x.l FROM pg_catalog.unnest(NEW.labels) WITH ORDINALITY AS x(l, n)
                             WHERE x.l NOT LIKE 'epigraph:%' ORDER BY x.n);
        -- The strip is the guard's own change, so it is compared as kept.
        v_old_reserved := '{}';
    END IF;
    IF NEW.properties ? 'ingest_written'
       AND NOT v_declared
       AND (TG_OP = 'INSERT'
            OR NOT (OLD.properties ? 'ingest_written')
            OR (NEW.properties -> 'ingest_written')
               IS DISTINCT FROM (OLD.properties -> 'ingest_written')) THEN
        RAISE EXCEPTION 'IWE01: properties.ingest_written is reserved for the edges the '
                        'document ingest writes; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    v_new_reserved := ARRAY(SELECT l FROM pg_catalog.unnest(NEW.labels) l
                             WHERE l LIKE 'epigraph:%' ORDER BY l);
    IF NOT v_declared AND v_new_reserved IS DISTINCT FROM v_old_reserved THEN
        RAISE EXCEPTION 'IWE02: edge labels starting with "epigraph:" are reserved for the '
                        'ingest-marker backfill and the countersign route; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

-- ===================================================================
-- 3. THE `legacy-ingest` ROLE
-- ===================================================================
ALTER TABLE public.system_agents
    DROP CONSTRAINT system_agents_role_known,
    ADD CONSTRAINT system_agents_role_known CHECK (role IN ('workflow-ingest', 'legacy-ingest'));

-- ===================================================================
-- 4. THE COUNTERSIGN DEFINER
-- ===================================================================
-- length('authorship.countersign') = 22.
DROP POLICY IF EXISTS security_events_countersign_privileged ON public.security_events;
CREATE POLICY security_events_countersign_privileged ON public.security_events
    AS RESTRICTIVE FOR INSERT TO PUBLIC
    WITH CHECK (
        lower(left(btrim(event_type), 22)) <> 'authorship.countersign'
        OR (((SELECT public.epigraph_bypass()) OR (SELECT public.epigraph_definer_bypass()))
            AND created_at = now()));

CREATE OR REPLACE FUNCTION public.epigraph_countersign_authorship(
    p_paper       uuid,
    p_agent       uuid,
    p_decision    text,
    p_ingested_by uuid DEFAULT NULL)
RETURNS TABLE (edge_id uuid, ingested_by uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
-- `public` (pg_temp last, migration 190): the `edges` triggers its UPDATE
-- fires (`trigger_validate_edge_refs` and others) resolve their helpers
-- unqualified, through this frame's search_path.
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_caller   uuid := public.epigraph_principal_id();
    v_agent    uuid := COALESCE(p_agent, public.epigraph_principal_id());
    v_operator uuid;
    v_label    text;
    v_ids      uuid[];
    v_bys      text[];
BEGIN
    IF p_decision IS NULL OR p_decision NOT IN ('confirm', 'decline') THEN
        RAISE EXCEPTION 'epigraph_countersign_authorship: decision must be confirm or decline'
            USING ERRCODE = '22023';
    END IF;
    IF p_paper IS NULL THEN
        RAISE EXCEPTION 'epigraph_countersign_authorship: a paper is required'
            USING ERRCODE = '22023';
    END IF;
    IF v_caller IS NULL THEN
        RAISE EXCEPTION 'CSG01: countersigning needs an authenticated principal; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF v_agent <> v_caller THEN
        -- The live operator: the link while not retired (107); with no link,
        -- the unrevoked 149 allowance. Status is not read.
        IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = v_agent) THEN
            SELECT l.operator_id INTO v_operator
              FROM public.operator_links l
             WHERE l.agent_id = v_agent AND NOT l.retired
             LIMIT 1;
        ELSE
            SELECT r.operator_id INTO v_operator
              FROM public.author_binding_clients r
             WHERE r.agent_id = v_agent AND r.revoked_at IS NULL
             LIMIT 1;
        END IF;
        IF v_operator IS DISTINCT FROM v_caller THEN
            RAISE EXCEPTION 'CSG02: only the named agent itself or its live operator may '
                            'countersign its authorship; nothing was written'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    v_label := CASE p_decision
                   WHEN 'confirm' THEN 'epigraph:countersigned_by:'
                   ELSE 'epigraph:countersign_declined_by:' END || v_caller::text;

    SELECT pg_catalog.array_agg(e.id ORDER BY e.created_at, e.id),
           pg_catalog.array_agg(e.properties -> 'ingest_written' ->> 'by'
                                ORDER BY e.created_at, e.id)
      INTO v_ids, v_bys
      FROM (SELECT e.id, e.properties, e.created_at
              FROM public.edges e
             WHERE e.source_id = v_agent AND e.source_type = 'agent'
               AND e.target_id = p_paper AND e.target_type = 'paper'
               AND e.relationship = 'authored'
               AND (e.valid_to IS NULL OR e.valid_to > pg_catalog.now())
               AND e.properties ? 'ingest_written'
               AND COALESCE(e.properties ->> 'pending_countersign', 'false') = 'true'
               AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(e.labels) l
                                WHERE l LIKE 'epigraph:countersign%')
               AND (p_ingested_by IS NULL
                    OR e.properties -> 'ingest_written' ->> 'by' = p_ingested_by::text)
             ORDER BY e.created_at, e.id
             FOR UPDATE) e;

    IF v_ids IS NULL THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('epigraph.ingest_written_edge', 'on', true);
    IF p_decision = 'confirm' THEN
        UPDATE public.edges e SET labels = e.labels || ARRAY[v_label]
         WHERE e.id = ANY (v_ids);
    ELSE
        UPDATE public.edges e SET labels = e.labels || ARRAY[v_label],
                                  valid_to = pg_catalog.now()
         WHERE e.id = ANY (v_ids);
    END IF;
    PERFORM pg_catalog.set_config('epigraph.ingest_written_edge', '', true);

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES (CASE p_decision WHEN 'confirm' THEN 'authorship.countersigned'
                            ELSE 'authorship.countersign_declined' END,
            v_caller, true,
            pg_catalog.jsonb_build_object(
                'migration', 208,
                'paper_id', p_paper,
                'agent_id', v_agent,
                'decision', p_decision,
                'acting_as', CASE WHEN v_agent = v_caller THEN 'self' ELSE 'operator' END,
                'edges', pg_catalog.to_jsonb(v_ids),
                'ingested_by', pg_catalog.to_jsonb(v_bys)));

    RETURN QUERY
    SELECT u.id, u.by::uuid,
           CASE p_decision WHEN 'confirm' THEN 'confirmed' ELSE 'declined' END
      FROM unnest(v_ids, v_bys) AS u(id, by);
END $$;
REVOKE ALL ON FUNCTION public.epigraph_countersign_authorship(uuid, uuid, text, uuid) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_countersign_authorship(uuid, uuid, text, uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_countersign_authorship(uuid, uuid, text, uuid) TO epigraph_app';
    END IF;
END $$;
