-- 043_alt_set_decisions_view.sql
--
-- Operational lifecycle for alt-set members. Joins migration 042's
-- alternative_set view (transitive-closure equivalence classes) with
-- claims.labels and claims.properties to surface the current
-- decision state per member.
--
-- See docs/superpowers/specs/2026-05-27-alt-set-lifecycle-design.md.

CREATE OR REPLACE VIEW alt_set_decisions AS
SELECT
    a.claim_id,
    a.alt_members,
    CASE
        WHEN c.labels @> ARRAY['alt-chosen']   THEN 'chosen'
        WHEN c.labels @> ARRAY['alt-rejected'] THEN 'rejected'
        WHEN c.labels @> ARRAY['alt-deferred'] THEN 'deferred'
        ELSE 'active'
    END AS alt_state,
    c.properties -> 'alt_state_meta' AS alt_state_meta,
    c.pignistic_prob,
    c.belief,
    c.plausibility
FROM alternative_set a
JOIN claims c ON c.id = a.claim_id;

COMMENT ON VIEW alt_set_decisions IS
'Per-member lifecycle state for alt-set claims. alt_state is derived from the '
'first matching reserved label in priority order chosen > rejected > deferred > active. '
'alt_state_meta is the optional JSONB metadata bag (transitioned_at, transitioned_by, '
'rationale, score). pignistic_prob/belief/plausibility are included so operators can '
'rank candidates without a follow-up join.';
