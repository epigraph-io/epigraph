-- 228: widen mass_functions.locality_tag from varchar(20) to varchar(64)
-- (backlog 01807a57).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 045 added `locality_tag varchar(20)` when the vocabulary was `intra`,
-- `cross` and `unknown`. The engine's own vocabulary has since grown past it:
-- `edge_factor.rs` names `intra_methodological_overlap` (28 characters) as the
-- tag a non-DOI intra heuristic writes, and the fold
-- (`effective_source_strength`) already treats any tag beginning with `intra`
-- as intra. Storing that tag through `submit_ds_evidence` reached the INSERT
-- and failed with 22001 (value too long), which the MCP surface reports as a
-- redacted internal error with nothing written.
--
-- 64 characters, not unbounded `text`: the tag is a short vocabulary key, an
-- unbounded column would let a caller store an arbitrarily large string on
-- every BBA row, and `submit_ds_evidence` refuses a longer tag as a parameter
-- error before the write (`edge_factor::LOCALITY_TAG_MAX_CHARS` names the same
-- number). A varchar(n) -> varchar(m) widening with m > n is binary-coercible,
-- so PostgreSQL rewrites neither the table nor
-- `idx_mass_functions_locality_tag`; the statement holds ACCESS EXCLUSIVE on
-- `mass_functions` only for the catalog update.
--
-- ===================================================================
-- 1. THE TRIGGER THAT NAMES THE COLUMN
-- ===================================================================
--
-- PostgreSQL refuses ALTER COLUMN TYPE on a column a trigger's WHEN clause
-- reads ("cannot alter type of a column used in a trigger definition").
-- 184's `mass_functions_retracted_rewrite_guard` reads `locality_tag` in its
-- WHEN, so it is dropped and re-created around the ALTER, in this one
-- transaction, with 184's definition verbatim: same name (so the firing order
-- among the BEFORE UPDATE triggers is unchanged), same WHEN, same function and
-- argument. Its function `epigraph_mass_function_retract_guard(text)` is not
-- touched. No view, rule or policy reads the column.
--
-- No function, grant, policy or index changes. Undo:
-- `docs/runbooks/228-undo.sql`.

SET LOCAL lock_timeout = '3s';

DROP TRIGGER mass_functions_retracted_rewrite_guard ON public.mass_functions;

ALTER TABLE public.mass_functions
    ALTER COLUMN locality_tag TYPE varchar(64);

-- 184's definition, verbatim.
CREATE TRIGGER mass_functions_retracted_rewrite_guard
    BEFORE UPDATE ON public.mass_functions
    FOR EACH ROW
    WHEN (OLD.retracted_at IS NOT NULL
          AND (NEW.masses, NEW.conflict_k, NEW.combination_method, NEW.source_strength,
               NEW.locality_tag, NEW.evidence_id, NEW.created_at)
              IS DISTINCT FROM
              (OLD.masses, OLD.conflict_k, OLD.combination_method, OLD.source_strength,
               OLD.locality_tag, OLD.evidence_id, OLD.created_at))
    EXECUTE FUNCTION public.epigraph_mass_function_retract_guard('rewrite');
