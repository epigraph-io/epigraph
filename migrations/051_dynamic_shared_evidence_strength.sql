-- Replace create_shared_evidence_factor() with Jaccard similarity on method parameter keys.
-- Previously hardcoded strength = 0.7; now computes overlap of typical_conditions keys.

CREATE OR REPLACE FUNCTION create_shared_evidence_factor()
RETURNS TRIGGER AS $$
DECLARE
    other_claim_id UUID;
    hyp_frame_id UUID;
    var_ids UUID[];
    keys_new TEXT[];
    keys_other TEXT[];
    keys_union TEXT[];
    keys_intersect TEXT[];
    jaccard FLOAT;
    factor_strength FLOAT;
BEGIN
    -- Only for provides_evidence edges from analysis to claim
    IF NEW.relationship != 'provides_evidence'
       OR NEW.source_type != 'analysis'
       OR NEW.target_type != 'claim' THEN
        RETURN NEW;
    END IF;

    SELECT id INTO hyp_frame_id FROM frames WHERE name = 'hypothesis_assessment' LIMIT 1;

    -- Collect method parameter keys for the NEW claim (union across all experiments + methods)
    SELECT COALESCE(array_agg(DISTINCT k), ARRAY[]::TEXT[])
    INTO keys_new
    FROM experiments e
    CROSS JOIN LATERAL unnest(e.method_ids) AS mid
    JOIN methods m ON m.id = mid
    CROSS JOIN LATERAL jsonb_object_keys(COALESCE(m.typical_conditions, '{}'::jsonb)) AS k
    WHERE e.hypothesis_id = NEW.target_id;

    -- Find all other claims this analysis already provides_evidence to
    FOR other_claim_id IN
        SELECT target_id FROM edges
        WHERE source_id = NEW.source_id
          AND source_type = 'analysis'
          AND target_type = 'claim'
          AND relationship = 'provides_evidence'
          AND target_id != NEW.target_id
    LOOP
        -- Build sorted variable_ids
        IF NEW.target_id < other_claim_id THEN
            var_ids := ARRAY[NEW.target_id, other_claim_id];
        ELSE
            var_ids := ARRAY[other_claim_id, NEW.target_id];
        END IF;

        -- Collect method parameter keys for the OTHER claim
        SELECT COALESCE(array_agg(DISTINCT k), ARRAY[]::TEXT[])
        INTO keys_other
        FROM experiments e
        CROSS JOIN LATERAL unnest(e.method_ids) AS mid
        JOIN methods m ON m.id = mid
        CROSS JOIN LATERAL jsonb_object_keys(COALESCE(m.typical_conditions, '{}'::jsonb)) AS k
        WHERE e.hypothesis_id = other_claim_id;

        -- Compute Jaccard similarity
        IF array_length(keys_new, 1) IS NULL OR array_length(keys_other, 1) IS NULL THEN
            -- No method keys available, fall back to 0.7
            factor_strength := 0.7;
        ELSE
            -- Union = all distinct keys from both
            SELECT COALESCE(array_agg(DISTINCT x), ARRAY[]::TEXT[])
            INTO keys_union
            FROM (
                SELECT unnest(keys_new) AS x
                UNION
                SELECT unnest(keys_other)
            ) sub;

            -- Intersection = keys present in both
            SELECT COALESCE(array_agg(x), ARRAY[]::TEXT[])
            INTO keys_intersect
            FROM (
                SELECT unnest(keys_new) AS x
                INTERSECT
                SELECT unnest(keys_other)
            ) sub;

            IF array_length(keys_union, 1) IS NULL OR array_length(keys_union, 1) = 0 THEN
                factor_strength := 0.7;
            ELSE
                jaccard := array_length(keys_intersect, 1)::FLOAT / array_length(keys_union, 1)::FLOAT;
                factor_strength := GREATEST(0.3, jaccard);
            END IF;
        END IF;

        -- Create pairwise shared_evidence factor with computed strength
        INSERT INTO factors (factor_type, variable_ids, potential, description, properties, frame_id)
        VALUES (
            'shared_evidence',
            var_ids,
            jsonb_build_object('strength', factor_strength),
            format('Shared evidence via analysis %s (Jaccard=%s)', NEW.source_id, ROUND(COALESCE(jaccard, 0.7)::numeric, 3)),
            jsonb_build_object('analysis_id', NEW.source_id, 'jaccard_similarity', COALESCE(jaccard, 0.7)),
            hyp_frame_id
        )
        ON CONFLICT (factor_type, variable_ids, COALESCE(frame_id, '00000000-0000-0000-0000-000000000000'))
        DO UPDATE SET
            potential = jsonb_build_object('strength', factor_strength),
            description = format('Shared evidence via analysis %s (Jaccard=%s)', NEW.source_id, ROUND(COALESCE(jaccard, 0.7)::numeric, 3)),
            properties = jsonb_build_object('analysis_id', NEW.source_id, 'jaccard_similarity', COALESCE(jaccard, 0.7));
    END LOOP;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Recompute existing shared_evidence factors from current method data
UPDATE factors f
SET potential = jsonb_build_object('strength', sub.strength),
    properties = f.properties || jsonb_build_object('jaccard_similarity', sub.jaccard)
FROM (
    SELECT
        f2.id AS factor_id,
        CASE
            WHEN COALESCE(array_length(union_keys, 1), 0) = 0 THEN 0.7
            ELSE GREATEST(0.3, COALESCE(array_length(intersect_keys, 1), 0)::FLOAT / array_length(union_keys, 1)::FLOAT)
        END AS strength,
        CASE
            WHEN COALESCE(array_length(union_keys, 1), 0) = 0 THEN 0.7
            ELSE COALESCE(array_length(intersect_keys, 1), 0)::FLOAT / array_length(union_keys, 1)::FLOAT
        END AS jaccard
    FROM factors f2
    CROSS JOIN LATERAL (
        SELECT
            (SELECT COALESCE(array_agg(DISTINCT k), ARRAY[]::TEXT[])
             FROM experiments e
             CROSS JOIN LATERAL unnest(e.method_ids) AS mid
             JOIN methods m ON m.id = mid
             CROSS JOIN LATERAL jsonb_object_keys(COALESCE(m.typical_conditions, '{}'::jsonb)) AS k
             WHERE e.hypothesis_id = f2.variable_ids[1]
            ) AS keys_a,
            (SELECT COALESCE(array_agg(DISTINCT k), ARRAY[]::TEXT[])
             FROM experiments e
             CROSS JOIN LATERAL unnest(e.method_ids) AS mid
             JOIN methods m ON m.id = mid
             CROSS JOIN LATERAL jsonb_object_keys(COALESCE(m.typical_conditions, '{}'::jsonb)) AS k
             WHERE e.hypothesis_id = f2.variable_ids[2]
            ) AS keys_b
    ) keys
    CROSS JOIN LATERAL (
        SELECT
            (SELECT array_agg(DISTINCT x) FROM (SELECT unnest(keys.keys_a) AS x UNION SELECT unnest(keys.keys_b)) u) AS union_keys,
            (SELECT array_agg(x) FROM (SELECT unnest(keys.keys_a) AS x INTERSECT SELECT unnest(keys.keys_b)) i) AS intersect_keys
    ) computed
    WHERE f2.factor_type = 'shared_evidence'
) sub
WHERE f.id = sub.factor_id
  AND f.factor_type = 'shared_evidence';
