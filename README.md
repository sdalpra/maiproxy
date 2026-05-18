# MAIproxy

<p align="center">
  <img src="assets/LOGO_maiproxy_infn.svg" alt="Project logo" width="200"/>
</p>


A lightweight authentication proxy built on **PostgreSQL**, **PostgREST**, and **nginx**.
It accepts **external IAM JWTs**, persists normalized claims, and issues **internally signed EdDSA JWTs**
fit for batch/Grid jobs. A subsequent RPC lets clients obtain a short‑lived IAM bearer when needed.

> **Core design**: only **EdDSA (Ed25519)** is enabled by default. An **HS256** path is available as an optional SQL file.

---

## Table of Contents
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Database Installation](#database-installation)
- [JWKS.json (internal + external issuers)](#jwksjson-internal--external-issuers)
- [PostgREST Configuration](#postgrest-configuration)
- [nginx Reverse Proxy](#nginx-reverse-proxy)
- [Operational Flow](#operational-flow)
- [Usage Examples](#usage-examples)
- [Validation & Smoke Tests](#validation--smoke-tests)
- [Optional: HS256 Legacy Path](#optional-hs256-legacy-path)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
Client (OIDC/IAM) ──(Bearer ext)──> /rpc/register_my_jwt (role: anon)
                                   │
                                   ├─ verifies & persists claims in api.mbox
                                   └─ issues maiproxy JWT (EdDSA, 4–7 days)

Batch job ──(maiproxy JWT)──> /rpc/get_iam_jwt (role: virgo|igwn)
                               └─ returns a valid external IAM JWT (bearer)
```

Core DB objects (schema `api`):
- `users`, `mbox`, `events`
- `register_my_jwt()`, `get_iam_jwt(message jsonb)`, `jwt_decode(text)`
- trigger `mbox_eddsa_bi` → `mbox_eddsa_insert()`

Core crypto (schema `sec`):
- `sign_jwt_eddsa(...)`, `add_jwt_claims(...)`, base64url helpers
- `derive_eddsa_privkey/pubkey(...)`, `export_eddsa_jwk(...)`

---

## Prerequisites
- PostgreSQL **18+**
- PostgREST **14+**
- `pgsodium` extension (installed cluster‑wide)
- `pgcrypto` (standard)
- nginx with a valid TLS certificate for the public hostname
- Access to at least one IAM issuer (e.g. INFN‑CNAF Virgo IAM)

> Ensure the database user `authenticator` exists with a **strong password**.

---

## Database Installation

Load SQL files in this exact order:

1. `01_roles.sql`  – roles & memberships (no personal accounts)
2. `02_extensions.sql` – `pgsodium`, `pgcrypto`
3. `03_core.sql`   – schemas, tables, EdDSA functions, trigger, grants
4. *(Optional)* `90_optional_hs256.sql` – legacy HS256 path (disabled)

```bash
psql -U postgres -d maiproxy -f sql/01_roles.sql
psql -U postgres -d maiproxy -f sql/02_extensions.sql
psql -U postgres -d maiproxy -f sql/03_core.sql
# optional
psql -U postgres -d maiproxy -f sql/90_optional_hs256.sql
```

### Roles kept in the distributable
- Internal: `pgsodium_admin` (no login), `sec_owner` (no login), `api_owner` (no login)
- External: `authenticator` (login, **NOINHERIT**), `anon` (no login), `virgo` (no login), `igwn` (no login)

### Grants policy
- **No direct table grants** to client roles
- RPC is executed via **SECURITY DEFINER** functions owned by `api_owner`

---

## JWKS.json (internal + external issuers)

PostgREST loads a JWKS file to verify inbound JWTs. Combine:
- External issuers (e.g. INFN IAM JWKS)
- maiproxy’s internal **Ed25519** public key from DB (keypair id `2`)

1) Export maiproxy JWK from PostgreSQL:

```sql
SELECT sec.export_eddsa_jwk(2) AS jwk;  -- use the same keypair_id used to sign
```

2) Create `/etc/postgrest/JWKS.json`:

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<base64url_pubkey>", "kid": "ed25519-2", "use": "sig", "alg": "EdDSA" },
    { "kty": "RSA", "e": "AQAB", "n": "<...>", "kid": "iam-virgo-key", "alg": "RS256", "use": "sig" }
  ]
}
```

3) Secure permissions:

```bash
chmod 600 /etc/postgrest/JWKS.json
chown postgrest /etc/postgrest/JWKS.json
```

> You can automate external JWKS refresh with a cron job downloading the upstream JWKs and merging them with the local one.

---

## PostgREST Configuration

Create `prest_igwn.conf`:

```ini
db-uri = "postgres://authenticator:<db_secure_password>@<database_host>:5432/maiproxy"
db-anon-role = "anon"
db-schemas = "api"
server-host = "127.0.0.1"
server-port = "3000"
jwt-secret = "@/etc/postgrest/JWKS.json"
log-level = "debug"
```

**Notes**
- `db-anon-role = "anon"` allows calling `/rpc/register_my_jwt` even if the inbound IAM token has no `role` claim.
- maiproxy’s EdDSA JWT **does** include a `role` (e.g. `virgo` or `igwn`), so subsequent calls (e.g. `/rpc/get_iam_jwt`) will run under the mapped DB role after PostgREST verification.

---

## nginx Reverse Proxy

Expose PostgREST securely over TLS. Example snippets:

```nginx
# RPC endpoints: register_my_jwt, get_iam_jwt
location /rpc/ {
    default_type application/json;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Authorization $http_authorization;

    # Forwarding context (helpful for logs / auth)
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_pass http://postgrest;

    proxy_connect_timeout 5s;
    proxy_read_timeout    60s;
    proxy_send_timeout    60s;
    client_max_body_size  10m;

    # Inspect upstream (debug)
    add_header X-Upstream-Addr   $upstream_addr   always;
    add_header X-Upstream-Status $upstream_status always;
}

# to access views/tables if needed
location /api/ {
    default_type  application/json;
    proxy_hide_header Content-Location;
    add_header Content-Location  /api/$upstream_http_content_location;
    proxy_set_header  Connection "";
    proxy_http_version 1.1;
    proxy_pass http://postgrest/;
}
```

> Ensure an upstream `upstream postgrest { server 127.0.0.1:3000; }` block exists and the server listens on `:8443` with a valid certificate.

---

## Operational Flow

1. **Client obtains fresh IAM token** (external OIDC `oidc-token`, VOMS, etc.)
2. **Register** it to maiproxy via `/rpc/register_my_jwt` (executes as `anon` in DB)
3. maiproxy returns an **EdDSA JWT** (valid ~4–7 days) → store and distribute to batch jobs
4. The batch **uses maiproxy JWT** to call `/rpc/get_iam_jwt` when it needs a short‑lived IAM bearer

---

## Usage Examples

### Obtain a maiproxy JWT

```bash
# 1) Fetch fresh IAM token (repeat periodically, e.g. every 30 minutes)
BEARER_TOKEN=$(oidc-token -f myclient)
MAIPROXY_EP="https://<webservice_host>:8443"

touch maiproxy.jwt && chmod 600 maiproxy.jwt

# 2) Register IAM token with maiproxy
curl --capath /etc/grid-security/certificates -fsS -X POST \
  -H "Authorization: Bearer ${BEARER_TOKEN}" \
  -H "Content-Type: application/json" \
  ${MAIPROXY_EP}/rpc/register_my_jwt > maiproxy.jwt
```

### Use maiproxy JWT to obtain an IAM JWT

```bash
MAIPROXY_EP="https://<webservice_host>:8443"
IGWN_JWT=$(cat maiproxy.jwt)
MSG='{"message":{"jobid":"123.4","runtime":321,"reason":"Hi there!"}}'

touch iam.jwt && chmod 600 iam.jwt

curl --capath /etc/grid-security/certificates -sS -X POST \
  -H "Authorization: Bearer ${IGWN_JWT}" \
  -H "Content-Type: application/json" \
  --data "${MSG}" \
  ${MAIPROXY_EP}/rpc/get_iam_jwt > iam.jwt
```

---

## Validation & Smoke Tests

1. **Expired external IAM token** → `/rpc/register_my_jwt` must fail with a 4xx error.
2. **Old maiproxy JWT (>7 days)** → `/rpc/get_iam_jwt` should fail (expired or no valid match).
3. **Tampered `JWKS.json`** → PostgREST should reject inbound JWTs (401/403).
4. **Call `/rpc/get_iam_jwt` with `anon`** → forbidden (role must map to `virgo` or `igwn`).
5. **Event logging** → `api.events` should record renew/reuse/served events for auditing.

---

## Optional: HS256 Legacy Path

The repository includes `sql/90_optional_hs256.sql` which:
- Adds HS256 signing/verify helpers in `sec.*`
- Adds legacy `api.mbox_insert()` and a **disabled** trigger `mbox_before_insert`

**To enable HS256 (not recommended unless needed):**
```sql
CREATE EXTENSION IF NOT EXISTS pgjwt;  -- provide public.sign
ALTER TABLE api.mbox ENABLE TRIGGER mbox_before_insert;
ALTER TABLE api.mbox DISABLE TRIGGER mbox_eddsa_bi;  -- switch off EdDSA path
```

---

## Security Notes
- Use a **strong password** for `authenticator` and do not grant it extra privileges.
- Prefer **no direct table access** for external roles; use RPC with SECURITY DEFINER.
- Rotate Ed25519 keypair id if necessary; publish its JWK via `sec.export_eddsa_jwk(<id>)`.

---

## Troubleshooting

- **401/403 from PostgREST**: verify `jwt-secret` path, JWKS contents, and tokens’ `kid/alg`.
- **`register_my_jwt` fails for known users**: ensure the subject exists in `api.users` and that headers include `Authorization: Bearer ...`.
- **`get_iam_jwt` returns no match**: check that `api.mbox` contains a recent row with matching `sub/scope/wlcg.groups` and that the bearer is not near expiry (`exp > now + 600s`).
- **nginx shows 502**: inspect `X-Upstream-Status` headers and PostgREST logs; confirm `postgrest` is reachable at `127.0.0.1:3000`.

---

## License
EUPL 1.2 
