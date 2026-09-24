-- ===================================================================
-- 078 — THE RLS CANARY. Its own table, not a synthetic claim.
--
-- Version 078 per `migrations/README.md`, which is authoritative; the plan
-- calls this file "074_rls_canary.sql". See 077's header for the full
-- numbering correction.
--
-- The canary reduces the entire security posture to one integer, checked at
-- boot and on the 60-second gauge tick. There is no app-layer equivalent — you
-- cannot assert at runtime that 85 MCP tools remembered to filter.
--
-- IT GETS ITS OWN TABLE. A synthetic row in `claims` is wrong regardless of
-- labelling: it would count in `system_stats`, need an exclusion in
-- `find_claims_needing_embeddings` and in the CLAUDE.md audit SQL, and pollute
-- an agent's authored set.
--
-- WHY IT IS `FORCE`d HERE AND NOT IN 079. This table is created empty of
-- meaning to the application and is read by nothing except the probe, so
-- FORCing it immediately costs nothing rather than waiting for the gated
-- terminal step. It is deliberately NOT in 079's array for that reason.
--
-- WHAT `FORCE` ACTUALLY BUYS, stated precisely because an operator reads this
-- header while executing step 11d. It subjects the table's OWNER to the
-- policies. It does NOT defeat `BYPASSRLS`, and a superuser has `BYPASSRLS`
-- implicitly — so MEASURED at head as the superuser `epigraph`, `SELECT count(*)
-- FROM public.rls_canary` returns **1**, not 0, and that is CORRECT. An earlier
-- draft of this comment claimed the opposite ("invisible even to the owner, or a
-- superuser-connected process would read the row and conclude RLS had failed"),
-- which would have told an operator to expect 0 on every cluster that exists
-- today. `1` means only "this connection is not subject to RLS", which before
-- the 11d credential split is the expected state; `metrics.rs`'s
-- `rls_canary_visible` documents the alert expression and
-- `state.rs::rls_verdict` stages the refusal on `current_user` for exactly this
-- reason. The property FORCE buys here is that the row is invisible to a
-- NON-superuser owner and to `epigraph_app` once the split happens.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.rls_canary (
    id         integer PRIMARY KEY,
    note       text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

INSERT INTO public.rls_canary (id, note) VALUES
    (1, 'Visible ONLY to a connection that bypasses row security. If an '
        'epigraph_app connection can SELECT this row, RLS is not in force.')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.rls_canary ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_canary_bypass_only ON public.rls_canary;
CREATE POLICY rls_canary_bypass_only ON public.rls_canary FOR ALL TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()));
ALTER TABLE public.rls_canary FORCE ROW LEVEL SECURITY;

-- 077's `GRANT … ON ALL TABLES` bound the tables that existed then, so this
-- table needs its own grant. SELECT only: the app must be able to ATTEMPT the
-- read, because a `42501` and an empty result set are different findings and
-- the probe has to be able to tell them apart. Without the grant the probe
-- would report "RLS is working" on a database where the policy had been
-- dropped, which is the exact failure it exists to detect.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT SELECT ON public.rls_canary TO epigraph_app';
    END IF;
END $$;
