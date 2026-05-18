-- Copyright (c) 2026 Stefano Dal Pra stefano.dalpra@cnaf.infn.it
-- Licensed under the EUPL 1.2 License. See LICENSE file in the
-- project root for full license information.

-- core roles
CREATE ROLE api_owner      NOLOGIN INHERIT;
CREATE ROLE sec_owner      NOLOGIN INHERIT;
CREATE ROLE pgsodium_admin NOLOGIN INHERIT;

-- external roles
CREATE ROLE authenticator LOGIN NOINHERIT PASSWORD '***CHANGE_ME***';
CREATE ROLE anon          NOLOGIN;
CREATE ROLE virgo         NOLOGIN INHERIT;
CREATE ROLE igwn          NOLOGIN INHERIT;

-- “anon” user (no INHERIT)
GRANT anon TO authenticator WITH INHERIT FALSE;

