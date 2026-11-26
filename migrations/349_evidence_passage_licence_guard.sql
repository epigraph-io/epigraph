-- 349: the database refuses a verbatim source passage in a paper's evidence
-- row unless the paper's licence permits retention (backlog b62ae3f2).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- 226 gave `papers` a licence and 255 made it operator-only, but the rule it
-- gates ("keep the passage text only when the licence permits it, otherwise a
-- locator and a BLAKE3 hash") lived only in Rust:
-- `epigraph_ingest::common::licence::passage_retention_permitted`, applied by
-- the document-ingest writer (`literature_evidence_body`) and by the
-- `ingest_literature` CLI. The CLI is a CLIENT: it reads the licence from the
-- extraction file and posts finished bodies to `/api/v1/submit`, which, like
-- `POST /api/v1/evidence` and `PUT /api/v1/evidence/:id`, stores whatever body
-- a caller sends. So any holder of the application DSN, any API client, or a
-- request-path bug could write publisher text into a literature or figure
-- evidence row for a paper whose licence forbids it, and nothing refused it
-- (255 section 2 named this as the residual).
--
-- ===================================================================
-- 1. WHAT THIS FILE DOES
-- ===================================================================
--
--   1. `public.epigraph_passage_retention_permitted(licence text) -> boolean`,
--      IMMUTABLE: the SQL mirror of the Rust allowlist, case for case (ASCII
--      upper-casing only, spaces and underscores read as hyphens, Unicode
--      white space trimmed as Rust's `str::trim` does). NULL is false.
--      `the_sql_allowlist_matches_the_rust_allowlist`
--      (epigraph-mcp/tests/evidence_passage_licence_guard.rs) runs both over
--      one corpus; widening or narrowing the allowlist is now a migration
--      plus the Rust change, together.
--   2. `public.epigraph_evidence_passage_licence_guard()`, a SECURITY INVOKER
--      trigger function, attached as two BEFORE ROW triggers on `evidence`:
--      `evidence_passage_licence_insert` (every INSERT of a literature or
--      figure row) and `evidence_passage_licence_update` (an UPDATE of such a
--      row that changes its body, its type, its DOI or its caption). A row is
--      a PAPER's evidence when `properties->>'type'` is `literature` or
--      `figure` (the serde tag of `EvidenceType::Literature` / `::Figure`,
--      which carry the DOI). For such a row:
--        * a literature body passes when it is NULL (external evidence) or the
--          locator-and-hash shape both writers emit:
--            Source: <title> (DOI: <doi>). Locator: <locator>.
--            Passage BLAKE3: <64 lower-case hex>. Passage not retained
--            (licence unknown | licence: <licence>).
--          and carries no `Passage: '`;
--        * a figure passes when it has neither an image (`raw_content`) nor a
--          caption (`properties->>'caption'`, publisher text too);
--        * anything else is a passage, and passes only when a `papers` row the
--          WRITER can read, keyed on the row's DOI, carries a licence (1)
--          permits. The DOI is matched as `PaperRepository` finds a paper: as
--          given, its canonical key with any DOI-resolver prefix removed, and
--          that key under each resolver prefix (`document_key_spellings`), then
--          a legacy key spelled with a case variant of a resolver prefix
--          (`HTTPS://DOI.ORG/...`, the `case_variant_arm_sql` rule, backlog
--          f3a3ca54). Otherwise 23514, constraint `evidence_passage_licence`
--          (the API answers 400: `ApiError::from(DbError::CheckViolation)`
--          for the REST evidence routes, and the packet route maps it too).
--      INVOKER on purpose: `papers` has row security since 246, so a group's
--      own paper row counts for that group's writes only, and the refusal is
--      no oracle for whether another group holds a copy. Ingest reads the
--      licence of the paper row in its own scope, which the same session
--      reads here, so a passage the Rust gate keeps is admitted. The one
--      fail-closed exception: a locator-and-hash body whose free-text title or
--      locator itself contains `Passage: '` is read as a passage, so for a
--      non-permitting paper that evidence row (and the ingest writing it) is
--      refused rather than risk admitting a smuggled passage.
--      An UNSEAL (`PrivatizationRepository`: the row's body is the seal
--      sentinel `[sealed]` and its ciphertext row exists) restores what was
--      stored before the seal and is not re-judged.
--   3. Refuses to apply (`EVP09`, nothing applied) unless both triggers are
--      present and enabled afterwards, and `epigraph_app` may EXECUTE (1)
--      (granted by name: the guard runs as the writer).
--
-- No existing row is read or changed. Rows stored before 349, or under a
-- licence since withdrawn, keep their body; a write that leaves the body, the
-- type, the DOI and the caption alone does not fire the guard, and rewriting
-- such a body to the locator-and-hash shape (the strip repair, a separate
-- data item) passes.
--
-- ===================================================================
-- 2. WHAT IT CANNOT CLOSE
-- ===================================================================
--
--   * Text the database cannot tie to a paper. A row that is not typed
--     literature or figure (a document, testimony or observation row) may
--     hold any text, including a publisher's, and no trigger can tell. The
--     guard enforces the ingest contract on the rows that NAME a paper.
--   * Free-text fields inside the admitted shape. The guard is SHAPE-based:
--     the title, the locator and the `licence: <licence>` group of the
--     locator-and-hash body are free text (only the exact token `Passage: '`
--     is screened), so a writer set on it could still smuggle prose into them,
--     e.g. after `Passage not retained (licence: none). `. The shape check
--     stops a well-formed client or a bug (such as the CLI's
--     `--allow-verbatim`) storing the passage itself, not a determined holder
--     of the application DSN or a determined API client.
--   * The maintenance DSN and superuser. The guard fires for every role, but
--     a holder of the maintenance DSN can disable a trigger (as in 123 and
--     255, provenance against that DSN waits for the elevation batch).
--   * An unseal: the unseal arm trusts the sentinel plus a ciphertext row,
--     both of which the application writes, and the server cannot verify the
--     plaintext an unseal hands it (`PrivatizationRepository::unseal_claims_conn`).
--     So a caller with the `instance:admin` scope and authority over the
--     group (the unseal route's gate) can seal a claim whose literature row
--     holds the locator-and-hash body, then unseal it with a passage as the
--     body under a paywalled DOI, and the guard does not judge it again.
--
-- ===================================================================
-- 3. DEPLOY AND UNDO
-- ===================================================================
--
-- No binary depends on 349 and every binary runs on it: the document-ingest
-- writer already emits only the shapes admitted here (pinned by
-- `ingest_evidence_passage_retention.rs`). OPERATOR NOTE: the
-- `ingest_literature` CLI's `--allow-verbatim` flag and its extraction-declared
-- licence no longer override the paper's recorded licence. A CLI ingest whose
-- packets carry verbatim passages (or figures) for a DOI with no `papers` row,
-- or one with no permitting licence, is refused 400; set the licence first
-- through `epigraph_set_paper_licence` (255) on the maintenance DSN.
-- Measure after applying (prod, as a superuser so every paper row is read;
-- exact DOI spelling only): the stored literature/figure rows that carry a
-- passage, image or caption for a paper with no permitting licence. They stay
-- (see above); the strip repair is a separate data item.
--   SELECT count(*) FROM evidence e
--    WHERE e.properties->>'type' IN ('literature', 'figure')
--      AND (e.raw_content IS NOT NULL
--           OR btrim(COALESCE(e.properties->>'caption', '')) <> '')
--      AND NOT (e.properties->>'type' = 'literature'
--               AND e.raw_content ~ '^Source: .* \(DOI: .*\)\. Locator: .*\. Passage BLAKE3: [0-9a-f]{64}\. Passage not retained \((licence unknown|licence: .+)\)\.$'
--               AND strpos(e.raw_content, 'Passage: ''') = 0)
--      AND NOT EXISTS (SELECT 1 FROM papers p
--                       WHERE p.doi = e.properties->>'doi'
--                         AND epigraph_passage_retention_permitted(p.licence));
-- Undo: docs/runbooks/349-undo.sql.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 4. THE ALLOWLIST (mirror of passage_retention_permitted)
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_passage_retention_permitted(p_licence text)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN p_licence IS NULL THEN false ELSE (
        SELECT v.id IN ('PUBLIC-DOMAIN', 'PD', 'CC0', 'CC0-1.0', 'CC-BY', 'CC-BY-SA')
            OR (v.id ~ '^CC-BY-(SA-)?[0-9]\.[0-9](-[A-Z]{2,4})?$'
                AND v.id !~ '^CC-BY-(SA-)?[0-9]\.[0-9]-(NC|ND|SA)$')
          FROM (SELECT pg_catalog.translate(
                           pg_catalog.translate(
                               -- Rust `str::trim`: the White_Space set, as 250.
                               pg_catalog.regexp_replace(p_licence,
                                   '^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+'
                                   '|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$',
                                   '', 'g'),
                               -- Rust `to_ascii_uppercase`: ASCII letters only
                               -- (`upper()` would fold e.g. U+017F to `S`).
                               'abcdefghijklmnopqrstuvwxyz',
                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
                           ' _', '--') AS id) v)
    END
$$;

-- The guard below is SECURITY INVOKER, so the writing session calls this:
-- granted by name rather than left to PUBLIC's default (section 6 checks it).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_passage_retention_permitted(text) '
                'TO epigraph_app';
    END IF;
END $$;

COMMENT ON FUNCTION public.epigraph_passage_retention_permitted(text) IS
    'Whether a source under this licence may have its verbatim text kept in '
    'evidence.raw_content: the SQL mirror of '
    'epigraph_ingest::common::licence::passage_retention_permitted (migration 349, '
    'backlog b62ae3f2). Change both together; a parity test runs them over one corpus.';

-- ===================================================================
-- 5. THE GUARD
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_evidence_passage_licence_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- Rust's `str::trim` White_Space class (canonical_document_key), as 250.
    c_ws CONSTANT text := '[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]';
    -- `DOI_KEY_PREFIXES` (epigraph-db repos/paper.rs), in its order.
    c_prefixes CONSTANT text[] := ARRAY[
        'https://doi.org/', 'http://doi.org/', 'https://dx.doi.org/', 'http://dx.doi.org/',
        'https://www.doi.org/', 'http://www.doi.org/', 'doi.org/', 'dx.doi.org/',
        'www.doi.org/', 'doi:'];
    v_type      text := NEW.properties ->> 'type';
    v_body      text := NEW.raw_content;
    v_key       text;
    v_rest      text;
    v_spellings text[];
    v_prefix    text;
BEGIN
    IF v_type IS NULL OR v_type NOT IN ('literature', 'figure') THEN
        RETURN NEW;
    END IF;

    -- An unseal writes back the body and properties a seal replaced.
    IF TG_OP = 'UPDATE'
       AND OLD.raw_content IS NOT DISTINCT FROM '[sealed]'
       AND EXISTS (SELECT 1 FROM public.evidence_encryption ee
                    WHERE ee.evidence_id = NEW.id) THEN
        RETURN NEW;
    END IF;

    IF v_type = 'figure' THEN
        -- The image and the caption are both the publisher's.
        IF v_body IS NULL
           AND pg_catalog.btrim(COALESCE(NEW.properties ->> 'caption', '')) = '' THEN
            RETURN NEW;
        END IF;
    ELSIF v_body IS NULL
       OR (v_body ~ ('^Source: .* \(DOI: .*\)\. Locator: .*\. Passage BLAKE3: [0-9a-f]{64}\. '
                     'Passage not retained \((licence unknown|licence: .+)\)\.$')
           AND pg_catalog.strpos(v_body, 'Passage: ''') = 0) THEN
        RETURN NEW;
    END IF;

    -- A passage: admitted only under a permitting licence on a paper row this
    -- session reads, found by the row's DOI in every stored spelling.
    v_key := pg_catalog.regexp_replace(COALESCE(NEW.properties ->> 'doi', ''),
                                        '^' || c_ws || '+|' || c_ws || '+$', '', 'g');
    IF v_key <> '' THEN
        v_spellings := ARRAY[v_key];
        v_rest := (pg_catalog.regexp_match(
                       v_key, '^(?:(?:https?://)?(?:(?:dx|www)\.)?doi\.org/|doi:)(.*)$', 'i'))[1];
        IF v_rest IS NOT NULL THEN
            v_rest := pg_catalog.regexp_replace(v_rest, '^' || c_ws || '+', '');
            IF v_rest ~ '^10\.[0-9]{4,9}/'
               AND pg_catalog.substr(v_rest, pg_catalog.strpos(v_rest, '/') + 1)
                   !~ ('^' || c_ws || '*$') THEN
                v_key := v_rest;
            END IF;
        END IF;
        IF v_key ~ '^10\.[0-9]{4,9}/' THEN
            v_spellings := v_spellings || v_key;
            FOREACH v_prefix IN ARRAY c_prefixes LOOP
                v_spellings := v_spellings || (v_prefix || v_key);
            END LOOP;
        END IF;
        IF EXISTS (SELECT 1 FROM public.papers p
                    WHERE p.doi = ANY (v_spellings)
                      AND public.epigraph_passage_retention_permitted(p.licence)) THEN
            RETURN NEW;
        END IF;
        -- A legacy key spelled with a case variant of a resolver prefix: equal
        -- to a spelling ignoring case, and ending in the canonical key exactly
        -- (`case_variant_arm_sql`). No index serves it; it runs only for a
        -- passage the exact spellings did not admit.
        IF v_key ~ '^10\.[0-9]{4,9}/'
           AND EXISTS (SELECT 1 FROM public.papers p
                        WHERE pg_catalog.lower(p.doi) = ANY (
                                  SELECT pg_catalog.lower(s) FROM pg_catalog.unnest(v_spellings) s)
                          AND pg_catalog.right(p.doi, pg_catalog.char_length(v_key)) = v_key
                          AND public.epigraph_passage_retention_permitted(p.licence)) THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION 'EVP01: evidence for DOI % carries a verbatim source passage (or a figure '
                    'image or caption), and no paper you can read under that DOI has a licence '
                    'that permits keeping it; store the locator and BLAKE3 hash instead '
                    '(migration 349)', COALESCE(NEW.properties ->> 'doi', '<none>')
        USING ERRCODE = '23514', CONSTRAINT = 'evidence_passage_licence',
              TABLE = 'evidence', SCHEMA = 'public';
END $$;

COMMENT ON FUNCTION public.epigraph_evidence_passage_licence_guard() IS
    'Refuses a verbatim passage, figure image or caption in a literature or figure '
    'evidence row unless a papers row the writer reads under its DOI carries a licence '
    'epigraph_passage_retention_permitted admits (migration 349, backlog b62ae3f2).';

DROP TRIGGER IF EXISTS evidence_passage_licence_insert ON public.evidence;
CREATE TRIGGER evidence_passage_licence_insert
    BEFORE INSERT ON public.evidence
    FOR EACH ROW
    WHEN ((NEW.properties ->> 'type') IN ('literature', 'figure'))
    EXECUTE FUNCTION public.epigraph_evidence_passage_licence_guard();

DROP TRIGGER IF EXISTS evidence_passage_licence_update ON public.evidence;
CREATE TRIGGER evidence_passage_licence_update
    BEFORE UPDATE OF raw_content, properties ON public.evidence
    FOR EACH ROW
    WHEN ((NEW.properties ->> 'type') IN ('literature', 'figure')
          AND (OLD.raw_content IS DISTINCT FROM NEW.raw_content
               OR (OLD.properties ->> 'type') IS DISTINCT FROM (NEW.properties ->> 'type')
               OR (OLD.properties ->> 'doi') IS DISTINCT FROM (NEW.properties ->> 'doi')
               OR (OLD.properties ->> 'caption') IS DISTINCT FROM (NEW.properties ->> 'caption')))
    EXECUTE FUNCTION public.epigraph_evidence_passage_licence_guard();

-- ===================================================================
-- 6. THE END STATE
-- ===================================================================
DO $$
DECLARE
    v_n integer;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app')
       AND NOT has_function_privilege('epigraph_app',
               'public.epigraph_passage_retention_permitted(text)', 'EXECUTE') THEN
        RAISE EXCEPTION 'EVP09: epigraph_app cannot EXECUTE '
                        'epigraph_passage_retention_permitted, so every permitted passage would '
                        'fail 42501; nothing was applied' USING ERRCODE = '55000';
    END IF;
    SELECT count(*) INTO v_n
      FROM pg_catalog.pg_trigger t
     WHERE t.tgrelid = 'public.evidence'::regclass
       AND t.tgname IN ('evidence_passage_licence_insert', 'evidence_passage_licence_update')
       AND t.tgenabled = 'O'
       AND t.tgfoid = 'public.epigraph_evidence_passage_licence_guard()'::regprocedure;
    IF v_n <> 2 THEN
        RAISE EXCEPTION 'EVP09: 349 expected both evidence passage-licence triggers enabled on '
                        'public.evidence, found %; nothing was applied', v_n
            USING ERRCODE = '55000';
    END IF;
END $$;
