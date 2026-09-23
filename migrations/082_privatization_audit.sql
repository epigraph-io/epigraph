-- ===================================================================
-- 082 — the privatization audit trail, append-only, plus the matching
-- `security_events` hardening.
--
-- Version 082 per `migrations/README.md`. `docs/tenancy/FINAL-PLAN.md` calls
-- this file "078_privatization_audit.sql"; 078 is PR-17's applied RLS canary.
-- Same +4 shift as 080; see that file's header.
--
-- WHERE THE RECORD OF AUTHORITY LIVES, SAID ONCE. `privatization_audit` is the
-- record of authority for every privatization action. `security_events` is the
-- cross-cutting actor log that a login, a token mint and a privatization all
-- land in, so an auditor can read one timeline per principal. Both become
-- immutable here. Neither is the weak copy of the other, and neither is ever
-- garbage-collected: `prune_recall_events` is the retention precedent and both
-- audit tables are explicitly exempt from it.
--
-- ===================================================================
-- THE READ POLICY IS IN 083, NOT HERE, AND THAT IS A NUMBERING CONSEQUENCE.
--
-- `privatization_audit_read` calls `public.epigraph_is_instance_admin(uuid)`,
-- which migration 083 creates. A policy referencing a function that does not
-- yet exist fails to create and takes the whole migration with it — exactly
-- what happened to 077, whose header records the same function as the reason it
-- had to drop a disjunct from `security_events_read`. So this file ships the
-- table, its indexes, both immutability triggers, the grants and the INSERT
-- policy; 083 adds the SELECT policy immediately after creating the function.
-- Between the two files the table has no SELECT policy, which is default-deny;
-- the register in `rls_enforcement.rs` measures the state at HEAD, where both
-- have run.
--
-- ORDER-INSENSITIVITY: see 080's header. Nothing here sweeps the catalog or
-- assumes 084–091 have or have not run.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.privatization_audit (
    id             bigserial PRIMARY KEY,
    plan_id        uuid NOT NULL REFERENCES public.privatization_plans(id) ON DELETE RESTRICT,
    actor_agent_id uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    action         text NOT NULL,   -- 'plan.create'|'plan.approve'|'plan.dispatch'
                                    -- |'item.apply'|'item.skip'|'item.reassign'
                                    -- |'item.seal'|'item.unseal'|'item.revert'
                                    -- |'plan.abort'|'plan.drift'
    kind           text,
    entity_id      uuid,
    before_visibility     text,
    before_owner_group_id uuid,
    before_sealed         boolean,
    after_visibility      text,
    after_owner_group_id  uuid,
    after_sealed          boolean,
    plan_digest    bytea,
    correlation_id varchar(64),     -- matches security_events.correlation_id
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_privatization_audit_entity
    ON public.privatization_audit (entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_privatization_audit_plan
    ON public.privatization_audit (plan_id, created_at DESC);

-- ===================================================================
-- IMMUTABILITY, AND EXACTLY WHAT IT COVERS.
--
-- A `BEFORE UPDATE OR DELETE … FOR EACH ROW` trigger is the only control that
-- also binds the TABLE OWNER, which RLS does not: `ENABLE` exempts the owner
-- and even `FORCE` does not defeat `BYPASSRLS`, which a superuser holds
-- implicitly. That is why the trigger and the REVOKE below are both here and
-- neither replaces the other.
--
-- STATED LIMIT: a row-level trigger does not fire on `TRUNCATE`, which is a
-- statement-level operation. `TRUNCATE` requires ownership of the table, which
-- `epigraph_app` does not have, so the app role cannot reach it — but a
-- maintenance or owner connection can, and no trigger here would say so.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only (attempted % on id=%)',
                    TG_TABLE_NAME, TG_OP, OLD.id
        USING ERRCODE = '42501';
END $$;

DROP TRIGGER IF EXISTS privatization_audit_no_mutate ON public.privatization_audit;
CREATE TRIGGER privatization_audit_no_mutate
    BEFORE UPDATE OR DELETE ON public.privatization_audit
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_immutable();

-- THE SAME TRIGGER ON `security_events`. The plaintext-egress record must not
-- live in a table the app role can mutate while the immutable table sits next
-- to it. 077 shipped the default-deny half (no UPDATE and no DELETE policy) and
-- named this file as the owner of the other half; the two
-- `DELIBERATELY_UNCOVERED` entries in `rls_enforcement.rs` that say so are
-- rewritten in this same commit. Both pairs stay uncovered — a trigger is not a
-- `pg_policy` row — so the register keeps both entries and only their reasons
-- change.
DROP TRIGGER IF EXISTS security_events_no_mutate ON public.security_events;
CREATE TRIGGER security_events_no_mutate
    BEFORE UPDATE OR DELETE ON public.security_events
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_immutable();

-- ===================================================================
-- RLS AND GRANTS.
--
-- `privatization_audit.entity_id` is a complete index of every private entity
-- id in the instance, so the read side is instance-admin-only and additionally
-- row-scoped — see 083.
--
-- THE REVOKE IS NOT BELT-AND-BRACES. 077 issues `ALTER DEFAULT PRIVILEGES FOR
-- ROLE epigraph … GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO
-- epigraph_app`, and that default binds every table the migration runner
-- creates afterwards — measured on `webhook_subscriptions` (085), which carries
-- all four. So without this statement `privatization_audit` would ship with a
-- DELETE grant and the trigger would be the only thing standing behind an
-- append-only table.
-- ===================================================================
ALTER TABLE public.privatization_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.privatization_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS privatization_audit_append ON public.privatization_audit;
CREATE POLICY privatization_audit_append ON public.privatization_audit FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE UPDATE, DELETE ON public.privatization_audit FROM epigraph_app';
        EXECUTE 'GRANT SELECT, INSERT ON public.privatization_audit TO epigraph_app';
        -- 077's ALTER DEFAULT PRIVILEGES covers TABLES, not SEQUENCES. Without
        -- this the app role's INSERT would fail on the `bigserial` with a
        -- permission error on the sequence rather than the policy denial the
        -- register describes — two different findings that must not be
        -- confusable.
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE public.privatization_audit_id_seq '
                'TO epigraph_app';
        -- The same posture on the actor log, for the same reason. No code path
        -- in this workspace updates or deletes `security_events`; the writers
        -- are inserts only.
        EXECUTE 'REVOKE UPDATE, DELETE ON public.security_events FROM epigraph_app';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'GRANT SELECT, INSERT ON public.privatization_audit TO epigraph_maintenance';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE public.privatization_audit_id_seq '
                'TO epigraph_maintenance';
    END IF;
END $$;

-- Convention alignment, as in 081: a new function is implicitly EXECUTE-able by
-- PUBLIC, and the explicit grants above are only the whole grant once that
-- default is removed.
REVOKE EXECUTE ON FUNCTION public.epigraph_audit_immutable() FROM PUBLIC;
