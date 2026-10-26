-- Migration 154: seed and verify the canonical `claim_validity` frame.
--
-- ===================================================================
-- 1. WHY
--
-- `POST /api/v1/claims/:id/assess` with no `frame_id` writes into the
-- canonical `claim_validity` frame (U027). That frame was resolved BY NAME
-- through the caller's viewer and created on a miss. `frames.name` is UNIQUE
-- (001 `frames_name_key`), so on any database without the row the first caller
-- to name a frame `claim_validity` (POST /frames will create any name) decided
-- what every later assess wrote into:
--   * over other hypotheses, every later assess was refused, and the right
--     frame could never be created beside it;
--   * with the right hypotheses under another id or owner, it received
--     everybody's evidence;
--   * a viewer that could not see the row fell into the create, hit the
--     UNIQUE name and failed.
-- The engine now resolves the frame by the fixed id of prod's row and never
-- creates it (`epigraph_engine::edge_factor::resolve_claim_validity_frame`).
-- This file gives every other database that row.
--
-- PROD (measured read-only 2026-10-13): the row already exists,
--   8a594393-c343-4f1a-b942-5c5b7862f792 | claim_validity |
--   {supported,refuted,uncertain} | owner_group_id = nil | public
-- so on prod this file must be, and is, a no-op: it never UPDATEs a row.
--
-- ===================================================================
-- 2. WHAT IT DOES
--
--   (a) REFUSE if a frame with ANOTHER id holds the name `claim_validity`.
--       `ON CONFLICT (id)` does not cover the UNIQUE name, so without this the
--       INSERT would fail with a bare 23505; with it the operator gets the
--       squatter's id. Resolve by hand (re-point or delete the squatter after
--       reviewing what was written into it), then re-apply.
--   (b) INSERT the canonical row, ON CONFLICT (id) DO NOTHING, declared public
--       over the nil world group (`TenancyDecl::instance_wide`), as prod's is.
--   (c) VERIFY the row with that id is exactly the canonical one (name,
--       ordered hypotheses, public, nil group) and RAISE otherwise. A row that
--       differs is never corrected here: correcting it would silently rewrite
--       the axis every stored BBA on it was written against.
--
-- ROW SECURITY. `frames` is under 077's registry policy (FORCE'd by 079). Its
-- USING admits every `visibility = 'public'` row to every role, and its WITH
-- CHECK admits `('public', world)`, so (b) and (c) work under ANY role: the
-- canonical row is public. What a role that does not bypass row security
-- loses is (a): it cannot see a NON-public squatter, so the INSERT then fails
-- with a bare 23505 on `frames_name_key` instead of (a)'s named error. That
-- still fails closed, but apply as a role that bypasses row security (the
-- superuser owner, as every migration is applied) so the error names the
-- squatter.
--
-- UNDO: `DELETE FROM frames WHERE id = '8a594393-c343-4f1a-b942-5c5b7862f792'`
-- on a database where THIS file inserted it and nothing references it yet.
-- Never on prod (the row predates this file and carries evidence).

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    squatter uuid;
BEGIN
    SELECT id INTO squatter
      FROM public.frames
     WHERE name = 'claim_validity'
       AND id <> '8a594393-c343-4f1a-b942-5c5b7862f792'::uuid;
    IF FOUND THEN
        RAISE EXCEPTION
            '154: frame % already holds the name claim_validity; the canonical claim_validity frame is 8a594393-c343-4f1a-b942-5c5b7862f792. Review and remove the other frame, then re-apply.',
            squatter;
    END IF;
END $$;

INSERT INTO public.frames (id, name, description, hypotheses, visibility, owner_group_id)
VALUES (
    '8a594393-c343-4f1a-b942-5c5b7862f792'::uuid,
    'claim_validity',
    'Canonical claim-assessment frame. Replaces the per-paper paper_validity_<slug> '
    'throwaway frames; index 0=supported, 1=refuted, 2=uncertain.',
    ARRAY['supported', 'refuted', 'uncertain']::text[],
    'public',
    '00000000-0000-0000-0000-000000000000'::uuid
)
ON CONFLICT (id) DO NOTHING;

DO $$
DECLARE
    r record;
BEGIN
    SELECT name, hypotheses, visibility, owner_group_id INTO r
      FROM public.frames
     WHERE id = '8a594393-c343-4f1a-b942-5c5b7862f792'::uuid;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            '154: the canonical claim_validity frame 8a594393-c343-4f1a-b942-5c5b7862f792 is not visible after the seed (apply as a role that bypasses row security)';
    END IF;
    IF r.name IS DISTINCT FROM 'claim_validity'
       OR r.hypotheses IS DISTINCT FROM ARRAY['supported', 'refuted', 'uncertain']::text[]
       OR r.visibility IS DISTINCT FROM 'public'
       OR r.owner_group_id IS DISTINCT FROM '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION
            '154: frame 8a594393-c343-4f1a-b942-5c5b7862f792 is not the canonical claim_validity frame (name %, hypotheses %, visibility %, owner_group_id %); it is never corrected here',
            r.name, r.hypotheses, r.visibility, r.owner_group_id;
    END IF;
END $$;
