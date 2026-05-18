CREATE FUNCTION api.get_iam_jwt(message jsonb) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'api', 'sec', 'public'
    AS $$
DECLARE
  -- Claim del token interno (IGWN_JWT) dal contesto della richiesta PostgREST
  jcs        jsonb := current_setting('request.jwt.claims', true)::jsonb;
  now_epoch  integer := extract(epoch from now())::integer;

  -- Candidata riga mbox
  v_id       integer;
  v_igwn_bearer text;
  v_claims   jsonb;
  v_jbt      jsonb;    -- payload di igwn_bearer (IAM_JWT) decodificato
  v_expire   timestamp;

  -- Sub dell'utente
  v_sub      text;

  -- Evento
  ev_text    text;

-- per debuggare;
  dbg jsonb;
BEGIN
  /* 0) Validazioni input & utente */
  IF jcs IS NULL THEN
    RAISE EXCEPTION 'Missing request.jwt.claims (no IGWN_JWT provided)';
  END IF;

  -- jobid e runtime devono esistere nel messaggio
  IF message IS NULL OR NOT (message ? 'jobid') OR NOT (message ? 'runtime') THEN
    RAISE EXCEPTION 'Invalid message: "jobid" and "runtime" are required';
  END IF;

  v_sub := jcs->>'sub';
  IF v_sub IS NULL OR v_sub = '' THEN
    RAISE EXCEPTION 'Current IGWN_JWT has no "sub" claim';
  END IF;

  -- l’utente deve esistere in api.users
  PERFORM 1 FROM api.users WHERE sub = v_sub;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'User "%" is not registered in api.users', v_sub;
  END IF;

  /* 1) Cerca l’ultima riga "equivalente" in mbox */
  -- SELECT m.id, m.igwn_bearer, m.claims, m.expire
  --   INTO v_id, v_igwn_bearer, v_claims, v_expire
  -- FROM api.mbox AS m
  -- WHERE (jcs->>'sub') = (m.claims->>'sub') 
  --  AND (jcs->'wlcg.groups')::jsonb = (m.claims->'wlcg.groups')::jsonb
  --  AND (jcs->'scope')::jsonb = (m.claims->'scope')::jsonb
  --  -- AND (jcs - '{aud,iss,wlcg.ver,nbf,exp,iat,jti,client_id}'::text[]) = (m.claims - '{aud,iss,wlcg.ver,nbf,exp,iat,jti,client_id}'::text[])
  -- ORDER BY m.id DESC
  -- LIMIT 1;

WITH a AS (
         SELECT mbox.*,
            api.jwt_decode(mbox.igwn_bearer) AS jbt,
            api.jwt_decode(mbox.igwn_jwt) AS jwt,
            current_setting('request.jwt.claims'::text, true)::jsonb AS jcs,
            EXTRACT(epoch FROM now())::integer AS now_epoch
           FROM api.mbox
          ORDER BY mbox.id DESC
        ), b AS (
         SELECT a.*
           FROM a
          WHERE ((a.jbt ->> 'exp'::text)::integer) > (a.now_epoch + 600)
            AND (a.jbt - '{wlcg.ver,nbf,exp,iat,jti,client_id}'::text[]) = a.claims
            AND (a.jcs ->> 'sub'::text) = (a.claims ->> 'sub'::text)
          ORDER BY a.id DESC
         LIMIT 1
        )
 SELECT id,igwn_bearer,claims,expire
   INTO v_id, v_igwn_bearer, v_claims, v_expire
   FROM b;

 -- RAISE NOTICE 'id = %',v_id;

  IF v_id IS NULL THEN
    -- RAISE EXCEPTION 'No mbox entry found for subject "%"', v_sub;
   RAISE EXCEPTION 'NO MATCH: "%" , "%"', jcs::text, m.claims::text;
  END IF;

  /* 2) Verifica consistenza con l’IAM_JWT salvato (igwn_bearer) */
  v_jbt := api.jwt_decode(v_igwn_bearer);

  -- stesso controllo della view: exp > now + 600s e payload "ridotto" uguale a claims
  IF ( (v_jbt->>'exp')::integer <= (now_epoch + 600)
       OR (v_jbt - '{wlcg.ver,nbf,exp,iat,jti,client_id}'::text[]) <> v_claims ) THEN
    RAISE EXCEPTION 'No valid IAM_JWT found (expired or claims mismatch) for subject "%"', v_sub;
  END IF;

  /* 3) Evento di tracciamento */
  ev_text := format(
              'iam_jwt:served sub=%s, iss=%s, expires_in=%ss',
              v_sub, v_claims->>'iss', (v_jbt->>'exp')::integer - now_epoch
            );

  INSERT INTO api.events(user_id, event, json)
  VALUES (v_sub, ev_text, message);

  /* 4) Ritorna l’IAM_JWT */
  RETURN v_igwn_bearer;
END
$$;

ALTER FUNCTION api.get_iam_jwt(message jsonb) OWNER TO api_owner;
