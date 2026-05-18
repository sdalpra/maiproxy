CREATE FUNCTION api.jwt_decode(jwt text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
  -- Extract the payload segment (the middle part of header.payload.signature)
  t_enc TEXT := split_part(jwt, '.', 2);
  tpad  INT;
BEGIN
  -- 1) Remove any accidental whitespace/newlines (psql wrap, copy/paste, etc.)
  t_enc := regexp_replace(t_enc, '\s', '', 'g');

  -- 2) Convert base64url -> standard base64
  t_enc := replace(replace(t_enc, '-', '+'), '_', '/');

  -- 3) Add base64 padding if needed
  tpad := (4 - length(t_enc) % 4) % 4;
  IF tpad > 0 THEN
    t_enc := t_enc || repeat('=', tpad);
  END IF;

  -- 4) Decode and return as JSONB
  RETURN convert_from(decode(t_enc, 'base64'), 'UTF8')::jsonb;
END
$$;


ALTER FUNCTION api.jwt_decode(jwt text) OWNER TO sdp;
