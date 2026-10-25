-- Migration 169: applied-cascade audit rows are read by instance admins
-- (custodians) only, never by the agent they name.
--
-- EVIDENCE
-- Backlog 9d6f21c5, part 2. `security_events_read` (077, recreated by 083 and
-- 129) admits a row whose `agent_id` is the session principal. A
-- `cascade.admin_applied` row names the agent whose act triggered the
-- administrative cascade (117), and so does the `cascade.belief_rederived`
-- row that follows it. Rows written before the agent-less companion rows
-- (`cascade.admin_applied_ids`, `cascade.belief_rederived_ids`) existed carry
-- on the row itself the ids the cascade touched: edges, BBAs and claims, most
-- of them other writers'. The triggering agent can read those id lists.
--
-- RULING
-- Operator ruling R-6 (2026-10-25): keep those rows intact (no redaction:
-- they are audit records, and 082's `security_events_no_mutate` makes every
-- row immutable anyway) and restrict READS of the two event types to instance
-- admins / custodians.
--
-- CHANGE
-- `security_events_read` is recreated from 129's body with ONE arm changed:
-- the own-row arm `agent_id = epigraph_principal_id()` now also requires that
-- the row is neither a `cascade.admin_applied` nor a
-- `cascade.belief_rederived` row. Every other arm is 129's, unchanged:
--   * the two session arms (`epigraph_bypass()`, `epigraph_definer_bypass()`):
--     the maintenance connection the cascade and its replay run on, and the
--     maintenance-owned definers, read every row as before;
--   * the standing admin arm, `CASE WHEN epigraph_admin_scopes_armed() THEN
--     epigraph_is_elevated() ELSE epigraph_is_instance_admin(principal) END`:
--     a custodian reads the two types unarmed, and armed only elevated. 126's
--     `security_events_elevated_read` (an elevated application session reads
--     every row) is untouched.
-- The event types are matched exactly (the names
-- `epigraph_db::repos::admin_cascade` writes). Only privileged sessions can
-- write a `cascade.` row at all (117's `security_events_cascade_privileged`).
-- The narrowed arm still keys on the principal, so it is not a row-only arm.
--
-- WHAT THE TRIGGERING AGENT STILL READS: every other row naming it, among
-- them its own `cascade.deferred` row (the record of its act that the replay
-- reads) and `cascade.admin_failed` rows; the ruling names the two types
-- above only. No read path depends on a non-privileged session seeing the two
-- types: the pending-cascade reads and the replay run on the maintenance
-- connection, and the two HTTP readers of this table (`/api/v1/audit/security`
-- and the agent timeline) leave the narrowing to this policy.
--
-- ROLLOUT. Policy DDL on a busy table: one transaction, 3 s `lock_timeout`,
-- drop-before-create, rerunnable. No data changes. A binary built before this
-- migration keeps working against it.
--
-- UNDO: `docs/runbooks/169-undo.sql` recreates `security_events_read` with
-- the body of the migration before 169 that last created it (129 today).
-- Run it BEFORE `docs/runbooks/129-undo.sql` if that is undone too: 129-undo
-- recreates 083's body, which has the unnarrowed own-row arm.

SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR (agent_id = (SELECT public.epigraph_principal_id())
            AND event_type <> ALL (ARRAY['cascade.admin_applied',
                                         'cascade.belief_rederived']))
        OR (SELECT CASE WHEN public.epigraph_admin_scopes_armed()
                        THEN public.epigraph_is_elevated()
                        ELSE public.epigraph_is_instance_admin(
                                 (SELECT public.epigraph_principal_id()))
                   END));
