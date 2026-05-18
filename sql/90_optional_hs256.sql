---------------------------------------
-- HS256 functions on namespace sec
---------------------------------------

-- derive_hs256_key(int)
CREATE OR REPLACE FUNCTION sec.derive_hs256_key(key_id integer)
RETURNS bytea
LANGUAGE sql SECURITY DEFINER
SET search_path TO 'sec','public'
AS $$
  SELECT pgsodium.derive_key(key_id, 32, 'JWT_HS26'::bytea);
$$;
ALTER FUNCTION sec.derive_hs256_key(key_id integer) OWNER TO postgres;

-- jwt_sign_hs256(json, int)
CREATE OR REPLACE FUNCTION sec.jwt_sign_hs256(payload json, key_id integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'sec','public'
AS $$
DECLARE
  secret bytea;
  header text := '{"alg":"HS256","typ":"JWT"}';
  b64header text;
  b64payload text;
  signing_input text;
  mac bytea;
  b64mac text;
BEGIN
  secret := sec.derive_hs256_key(key_id);
  b64header  := sec.base64url_encode(convert_to(header, 'UTF8'));
  b64payload := sec.base64url_encode(convert_to(payload::text, 'UTF8'));
  signing_input := b64header || '.' || b64payload;
  mac := pgsodium.crypto_auth_hmacsha256(convert_to(signing_input,'UTF8'), secret);
  b64mac := sec.base64url_encode(mac);
  RETURN signing_input || '.' || b64mac;
END;
$$;

-- jwt_sign_hs256(jsonb, int)
CREATE OR REPLACE FUNCTION sec.jwt_sign_hs256(payload jsonb, key_id integer)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'sec','public'
AS $$
DECLARE
  secret bytea;
  header text := '{"alg":"HS256","typ":"JWT"}';
  b64header text;
  b64payload text;
  signing_input text;
  mac bytea;
  b64mac text;
BEGIN
  secret := sec.derive_hs256_key(key_id);
  b64header  := sec.base64url_encode(convert_to(header, 'UTF8'));
  b64payload := sec.base64url_encode(convert_to(payload::text, 'UTF8'));
  signing_input := b64header || '.' || b64payload;
  mac := pgsodium.crypto_auth_hmacsha256(convert_to(signing_input,'UTF8'), secret);
  b64mac := sec.base64url_encode(mac);
  RETURN signing_input || '.' || b64mac;
END;
$$;

-- jwt_verify_hs256(text, int) (ritorna header, payload, valid)
CREATE OR REPLACE FUNCTION sec.jwt_verify_hs256(token text, key_id integer)
RETURNS TABLE(header json, payload json, valid boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'sec','public'
AS $$
DECLARE
  secret bytea;
  header_b64 text;
  payload_b64 text;
  sig_b64 text;
  signing_input text;
  sig bytea;
  h json;
  p json;
  alg text;
BEGIN
  secret := sec.derive_hs256_key(key_id);

  header_b64  := split_part(token,'.',1);
  payload_b64 := split_part(token,'.',2);
  sig_b64     := split_part(token,'.',3);
  IF header_b64 = '' OR payload_b64 = '' OR sig_b64 = '' THEN
    RETURN QUERY SELECT NULL::json, NULL::json, FALSE;
    RETURN;
  END IF;

  signing_input := header_b64 || '.' || payload_b64;

  -- base64url decode
  sig := (
    SELECT decode(
      replace(replace(sig_b64,'-','+'),'_','/') ||
      repeat('=', (4 - length(sig_b64)%4)%4), 'base64'
    )
  );

  valid := pgsodium.crypto_auth_hmacsha256_verify(
    sig, convert_to(signing_input,'UTF8'), secret
  );

  h := convert_from((
        SELECT decode(
          replace(replace(header_b64,'-','+'),'_','/') ||
          repeat('=', (4 - length(header_b64)%4)%4), 'base64'
        )
      ), 'UTF8')::json;
  p := convert_from((
        SELECT decode(
          replace(replace(payload_b64,'-','+'),'_','/') ||
          repeat('=', (4 - length(payload_b64)%4)%4), 'base64'
        )
      ), 'UTF8')::json;

  alg := h->>'alg';
  IF alg IS DISTINCT FROM 'HS256' THEN
    valid := FALSE;
  END IF;

  RETURN QUERY SELECT h, p, valid;
END;
$$;

-- jwt_secret_key_1() (just in case)
CREATE OR REPLACE FUNCTION sec.jwt_secret_key_1()
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT encode(pgsodium.derive_key(1, 32, 'JWT_HS26'::bytea),'base64');
$$;

---------------------------------------
-- API legacy functions (HS256)
---------------------------------------

-- mbox_insert() (trigger HS256)
CREATE OR REPLACE FUNCTION api.mbox_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
AS $$
DECLARE
  clear_jwt  jsonb := api.jwt_decode(NEW.igwn_bearer);
  claims_jwt jsonb := clear_jwt - '{nbf,exp,iat,jti,client_id,wlcg.ver}'::text[];
BEGIN
  NEW.claims := claims_jwt;
  NEW.expire := (claims_jwt->>'exp');
  NEW.igwn_jwt := public.sign(  -- richiede estensione pgjwt
    sec.add_jwt_claims( (claims_jwt || '{"aud":"vacct","iss":"gems","role":"virgo"}')::json, 7*86400 ),
    encode(sec.derive_hs256_key(1),'base64'),
    'HS256'
  );
  RETURN NEW;
END;
$$;

-- register_jwt(...) HS256 (old path)
CREATE OR REPLACE FUNCTION api.register_jwt(jwt text, email text, fname text, gname text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'api','sec','pg_temp'
AS $$
DECLARE
  jt jsonb := api.jwt_decode(jwt);
  iss text := jt->>'iss';
  sub text := jt->>'sub';
  scope_raw text := jt->>'scope';
  groups_json jsonb := jt->'wlcg.groups';
  scope_sorted text;
  normalized_claims jsonb;
  now_epoch bigint := floor(extract(epoch from now()));
  key_id int;
  existing_updated timestamptz;
  existing_igwn text;
  igwn_token text;
BEGIN
  IF iss IS NULL OR iss='' THEN RAISE EXCEPTION 'JWT iss claim missing'; END IF;
  IF sub IS NULL OR sub='' THEN RAISE EXCEPTION 'JWT sub claim missing'; END IF;
  IF scope_raw IS NULL OR btrim(scope_raw)='' THEN RAISE EXCEPTION 'JWT scope claim missing'; END IF;

  SELECT array_to_string(array_agg(part ORDER BY part), ' ')
    INTO scope_sorted
  FROM (
    SELECT DISTINCT trim(p) AS part
    FROM unnest(regexp_split_to_array(scope_raw, '\s+')) AS p
    WHERE trim(p) <> ''
  ) parts;

  normalized_claims := jsonb_build_object('iss',iss,'sub',sub,'scope',scope_sorted);
  IF groups_json IS NOT NULL THEN
    normalized_claims := normalized_claims || jsonb_build_object('wlcg.groups', groups_json);
  END IF;

  INSERT INTO api.iam_users (claims,email,fname,gname)
  VALUES (normalized_claims, email, fname, gname)
  ON CONFLICT (claims) DO UPDATE
    SET email=EXCLUDED.email, fname=EXCLUDED.fname, gname=EXCLUDED.gname
  RETURNING id INTO key_id;

  IF key_id IS NULL THEN
    SELECT id, updated, igwn_jwt INTO key_id, existing_updated, existing_igwn
    FROM api.iam_users WHERE claims = normalized_claims FOR UPDATE;
    IF existing_igwn IS NOT NULL AND existing_updated IS NOT NULL
       AND (now() - existing_updated) <= interval '5 days' THEN
      RETURN existing_igwn;
    ELSE
      igwn_token := public.sign(
        json_build_object('aud','vacct','sub',sub,'role','igwn','scope','get',
                          'iat',now_epoch,'nbf',now_epoch,'exp',now_epoch + 7*86400),
        encode(sec.derive_hs256_key(1),'base64'),
        'HS256'
      );
      UPDATE api.iam_users SET igwn_jwt = igwn_token, updated = now() WHERE id = key_id;
      RETURN igwn_token;
    END IF;
  ELSE
    igwn_token := public.sign(
      json_build_object('aud','vacct','sub',sub,'role','igwn','scope','get',
                        'iat',now_epoch,'nbf',now_epoch,'exp',now_epoch + 7*86400),
      encode(sec.derive_hs256_key(1),'base64'),
      'HS256'
    );
    UPDATE api.iam_users SET igwn_jwt = igwn_token, updated = now() WHERE id = key_id;
    RETURN igwn_token;
  END IF;
END;
$$;

-- Trigger legacy HS256 (DISABLED by default)
CREATE TRIGGER mbox_before_insert
BEFORE INSERT ON api.mbox
FOR EACH ROW EXECUTE FUNCTION api.mbox_insert();
ALTER TABLE api.mbox DISABLE TRIGGER mbox_before_insert;

-- If using **HS256** (only manually, if needed):
--   1) CREATE EXTENSION pgjwt;               -- se non presente
--   2) ALTER TABLE api.mbox ENABLE TRIGGER mbox_before_insert;
--   3) ALTER TABLE api.mbox DISABLE TRIGGER mbox_eddsa_bi; 
