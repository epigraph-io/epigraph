-- Enforce that agent-type OAuth clients always have an owner.
--
-- Evidence: oauth2 plan §Phase D — deferred from initial 060 migration because
-- backfill (064) inserted agents with owner_id = NULL.  All agents now have
-- owners assigned (either auto-provisioned via create_agent or manually
-- assigned by admin).
--
-- Reasoning: Without this constraint, agent clients could exist without a
-- human principal responsible for their actions.  The ownership chain
-- (agent → owner_id → human) is required for PROV-O provenance.

ALTER TABLE oauth_clients
    ADD CONSTRAINT agents_must_have_owner
    CHECK (client_type != 'agent' OR owner_id IS NOT NULL);
