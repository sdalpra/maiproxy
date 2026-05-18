-- Copyright (c) 2026 Stefano Dal Pra stefano.dalpra@cnaf.infn.it
-- Licensed under the EUPL 1.2 License. See LICENSE file in the
-- project root for full license information.

-- 00_database.sql (If You want to create a dedicated database)
-- CREATE DATABASE maiproxy WITH ENCODING 'UTF8';

-- 01_roles.sql (bare minimum)
CREATE ROLE api_owner      NOLOGIN INHERIT;
CREATE ROLE sec_owner      NOLOGIN INHERIT;
CREATE ROLE pgsodium_admin NOLOGIN INHERIT;

CREATE ROLE authenticator LOGIN NOINHERIT PASSWORD '***'; 
CREATE ROLE anon          NOLOGIN;

-- (example roles; add Your own for your specific cases)
-- CREATE ROLE virgo     NOLOGIN INHERIT;
-- CREATE ROLE virgosgm  NOLOGIN INHERIT;
-- CREATE ROLE ligo      NOLOGIN INHERIT;
-- CREATE ROLE hfdf      NOLOGIN INHERIT;
-- CREATE ROLE igwn      NOLOGIN INHERIT;

-- for details refer to refer to:
-- https://docs.postgrest.org/en/v14/references/auth.html#authentication
GRANT anon TO authenticator NOINHERIT;
-- (Optional: GRANT virgo/ligo/hfdf/igwn TO authenticator NOINHERIT);
