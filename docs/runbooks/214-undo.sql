-- ===================================================================
-- 214-undo.sql: take migration 214 (the compromised revoke under READ
-- COMMITTED only) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- READ FIRST: no binary depends on 214, so nothing needs rolling back
-- first. Run this BEFORE `200-undo.sql` when taking 200 out as well (that
-- one drops the function whatever its body).
--
-- WHAT IT DOES: re-states 200's body of
-- `public.epigraph_revoke_passkey_compromised(uuid, text)` byte for byte.
-- `CREATE OR REPLACE` keeps its owner and grants. From then on the revoke
-- runs under any isolation level again and, under REPEATABLE READ or
-- SERIALIZABLE, can miss a passkey enrolled during its lock wait (214's
-- header, section 1).
--
-- PRECONDITION: the body in place must be 214's (md5 of `prosrc`
-- `2fb529a23cf5c19ac02576b12a874e21`) or already 200's
-- (`0dfedeb8a0dc722a743fe2299baae704`, a second run); over any other body it raises
-- 55000 and changes nothing (a later migration re-bodied it: undo that one
-- first).
--
-- WHAT IT LEAVES: every passkey and revoke as it stands, and 214's
-- `_sqlx_migrations` row. Re-introducing the change is a NEW migration,
-- never a re-run of 214. Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
                       'public.epigraph_revoke_passkey_compromised(uuid, text)');
    IF v_found IS NULL OR v_found NOT IN ('2fb529a23cf5c19ac02576b12a874e21',
                                          '0dfedeb8a0dc722a743fe2299baae704') THEN
        RAISE EXCEPTION '214-undo: public.epigraph_revoke_passkey_compromised(uuid, text) is '
                        'neither 214''s body nor 200''s; found md5 %. Nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000';
    END IF;
END $$;

-- 200's body, byte for byte (CREATE OR REPLACE keeps owner and grants).
CREATE OR REPLACE FUNCTION public.epigraph_revoke_passkey_compromised(p_id uuid, p_reason text)
RETURNS TABLE (revoked_id uuid, lineage_depth integer, revoked_now boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_person uuid;
    v_ids    uuid[];
    v_depths integer[];
    v_hit    uuid[];
BEGIN
    IF p_id IS NULL OR p_reason IS NULL OR pg_catalog.length(pg_catalog.btrim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_revoke_passkey_compromised: the passkey and a reason are '
                        'required'
            USING ERRCODE = '22004';
    END IF;
    SELECT k.person_agent_id INTO v_person
      FROM public.person_authenticators k WHERE k.id = p_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ELV04: no passkey %', p_id
            USING ERRCODE = 'ELV04';
    END IF;
    -- Lock every passkey of the person first (the lock the UPDATE takes
    -- anyway, which conflicts with (b)'s FOR SHARE): a completion in flight
    -- on an act one of them confirmed is waited for, and the walk below, a
    -- later statement with a later snapshot, then sees the passkey it
    -- recorded; a completion that starts later waits for this transaction
    -- and is refused (ELV04, its confirmer revoked).
    PERFORM 1 FROM public.person_authenticators k
      WHERE k.person_agent_id = v_person ORDER BY k.id FOR NO KEY UPDATE;
    -- The walk, down the acts each passkey confirmed: through revoked
    -- passkeys too, the same person's only, never round a cycle.
    WITH RECURSIVE down (id, depth, path) AS (
        SELECT p_id, 0, ARRAY[p_id]
        UNION ALL
        SELECT k.id, down.depth + 1, down.path || k.id
          FROM down
          JOIN public.pending_admin_acts a ON a.authenticator_id = down.id
          JOIN public.passkey_enrollments en
            ON en.act_id = a.id AND en.created_via = 'confirmed_act'
          JOIN public.person_authenticators k ON k.enrollment_id = en.id
         WHERE k.person_agent_id = v_person
           AND NOT (k.id = ANY (down.path))
    )
    SELECT pg_catalog.array_agg(w.id ORDER BY w.depth, w.id),
           pg_catalog.array_agg(w.depth ORDER BY w.depth, w.id)
      INTO v_ids, v_depths
      FROM (SELECT DISTINCT ON (down.id) down.id, down.depth
              FROM down ORDER BY down.id, down.depth) w;
    -- One statement: (c)'s per-row cascade then finds nothing of the walk
    -- still live, and the audit reads the mode.
    PERFORM pg_catalog.set_config('epigraph.passkey_revoke_mode', 'compromised', true);
    WITH hit AS (
        UPDATE public.person_authenticators k
           SET revoked_at = pg_catalog.now(), revoked_by = session_user::text,
               revoked_reason = CASE WHEN k.id = p_id THEN p_reason
                                     ELSE 'compromised anchor ' || p_id::text || ' (lineage): '
                                          || p_reason END
         WHERE k.id = ANY (v_ids) AND k.revoked_at IS NULL
        RETURNING k.id)
    SELECT pg_catalog.array_agg(hit.id) INTO v_hit FROM hit;
    PERFORM pg_catalog.set_config('epigraph.passkey_revoke_mode', '', true);
    RETURN QUERY
        SELECT w.id, w.depth, w.id = ANY (COALESCE(v_hit, '{}'::uuid[]))
          FROM ROWS FROM (pg_catalog.unnest(v_ids), pg_catalog.unnest(v_depths))
               WITH ORDINALITY AS w(id, depth, n)
         ORDER BY w.n;
END $$;

COMMIT;
