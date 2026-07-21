# Farmsky Ventures — Full Technical Documentation

**Platforms:** Farmsky **Equipment** app (`farmskyventures-ops/farm-sky-webapp`) and Farmsky **Feed** app (`farmskyventures-ops/feed`)
**Document version:** 1.0
**Last updated:** 2026-07-21
**Status:** Cross-platform unification (Phases 1–6) complete and tested on both platforms.

---

## 1. Executive Summary

Farmsky Ventures operates two sibling web applications that finance agriculture in Kenya:

| Platform | Repository | Sells | Payment role |
|----------|-----------|-------|--------------|
| **Equipment** | `farm-sky-webapp` | Farm equipment / machinery | **Centralized payment host** — owns all direct gateway logic |
| **Feed** | `feed` | Animal feeds / inputs | Routes payments to Equipment over signed server-to-server calls |

Both are built on an **identical technical foundation** (Hono + TypeScript + PostgreSQL) and now share **identical UI layouts, navigation structures and management modules**. The only intentional structural difference is that **all direct payment-gateway processing (M-Pesa/Daraja, SasaPay, card, webhooks) lives exclusively in the Equipment application.**

This document describes the shared architecture, the six-phase unification project, the data model, security model, and the build/deploy/runbook for both platforms.

---

## 2. Technology Stack

| Layer | Technology |
|-------|-----------|
| Web framework | [Hono](https://hono.dev) (TypeScript) |
| Runtime (production) | **Dual**: Cloudflare Workers (`vite build` → `dist/_worker.js`) **and** Node.js (`esbuild` → `dist-node/server.js`) |
| Database | **PostgreSQL** (production and test). |
| Frontend | Vanilla JS SPA (`frontend/static/app.js`) + Tailwind CSS |
| Auth hashing | PBKDF2-SHA256 via WebCrypto (`backend/password.ts`) |
| Cross-app signing | HMAC-SHA256 (`payment-gateway-shared.ts` / `payments-shared.ts`) |
| SMS / Email / KYC | Pluggable providers (SMS, email, TransUnion) |
| Payments | M-Pesa/Daraja, SasaPay, Buni (Equipment only) |

### 2.1 Dual-runtime build

Both apps compile to two targets:

```bash
# Cloudflare Workers bundle
npm run build            # build:css + vite build  ->  dist/_worker.js

# Node.js server bundle (used for Render / self-host / local test)
NODE_OPTIONS="--max-old-space-size=512" npm run build:node   # -> dist-node/server.js
```

The Node entrypoint is `backend/server.ts`. It builds an `ENV` object **explicitly** from `process.env` and calls `app.fetch(c.req.raw, ENV, ctx)`. **Any new environment variable must be added to this ENV object or it will be `undefined` at runtime on Node.**

---

## 3. Repository Layout (both apps)

```
backend/
  index.tsx                 Main Hono app: routes, views, SHELL
  server.ts                 Node entrypoint (builds ENV, starts HTTP server)
  types.ts                  Bindings (env) + SessionUser types
  db-init.ts                Migration runner + SQLite->PostgreSQL transform
  db-postgres.ts            PostgresStatement shim (D1-compatible interface)
  password.ts               PBKDF2-SHA256 hashing (env-driven) [Phase 4]
  merchant-api.ts           Public merchant API router [Phase 3]
  cross-app.ts              Cross-app SSO handoff token mint/verify [Phase 2]
  payment-gateway.ts        (Equipment) Central payment gateway + /admin RBAC
  payment-gateway-host.ts   (Feed) Payment host proxy + /admin RBAC
  payment-gateway-shared.ts / payments-shared.ts   HMAC-SHA256 signing utils
  mpesa.ts, sasapay.ts, buni.ts   Payment provider adapters (Equipment)
  sms.ts, email.ts          Notification adapters
  sql/                      Row-Level Security setup (run once by superuser)
    01_payment_rls_setup.sql
    02_payment_security_audits.sql
    03_ownership_rls_setup.sql
    04_app_scope_rls_setup.sql          [Phase 5 — new]
migrations/                 *.sql schema migrations (SQLite dialect)
frontend/static/app.js      SPA
```

---

## 4. Database Architecture (PostgreSQL)

### 4.1 Migration system

- Migrations live in `migrations/*.sql`, written in a **SQLite dialect** and transformed to PostgreSQL by `backend/db-init.ts`:
  - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL`
  - `DATETIME` → `TIMESTAMP`
  - `REAL` → `DOUBLE PRECISION`
- Migrations are **idempotent**: duplicate-object errors (`42701`, `42P07`, `23505`, `42809`, `42P06`) are swallowed so re-runs are safe.
- `db-init.ts` maintains a `SERIAL_TABLES` list; **new tables with numeric auto-increment IDs must be added there**. `db-postgres.ts` maintains `TABLES_WITH_NUMERIC_ID` (controls whether `.run()` appends `RETURNING id`). Both lists now include `merchant_keys` and `merchant_checkouts`.
- Run migrations: `DATABASE_URL="postgresql://..." node dist-node/server.js --migrate-only`

### 4.2 Shared / cross-platform schema (Phase 2, 3, 5)

Added by migration **`0018_...` (Feed)** / **`0015_...` (Equipment)**:

| Table | Column | Purpose |
|-------|--------|---------|
| `central_transactions` | `inventory_type` (`equipment`\|`feed`) | Category for the unified ledger |
| `central_transactions` | `origin_platform` (`equipment_app`\|`feed_app`) | Which app originated the payment |
| `transactions` | `inventory_type`, `origin_platform`, `app_scope` | Local mirror + scope |
| `products` | `app_scope` (`equipment`\|`feed`\|`both`) | Data-isolation scope |
| `merchant_keys` | — | Public merchant API credentials (key + HMAC secret) |
| `merchant_checkouts` | — | Merchant-originated hosted checkout sessions |

`origin_platform` is **backfilled** from the legacy `origin_app` column so historical rows appear correctly in the unified ledger.

### 4.3 `merchant_keys`

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGSERIAL PK | |
| `merchant_key` | TEXT UNIQUE | public identifier, e.g. `mk_live_xxx` |
| `merchant_secret` | TEXT | HMAC-SHA256 shared secret |
| `display_name` | TEXT | |
| `contact_email` | TEXT | |
| `app_scope` | TEXT DEFAULT 'both' | which catalog(s) the merchant may touch |
| `is_active` | INTEGER DEFAULT 1 | |
| `created_by`, `created_at` | | |

### 4.4 `merchant_checkouts`

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGSERIAL PK | |
| `checkout_ref` | TEXT UNIQUE | e.g. `chk_equipment_<ts>_<rand>` |
| `merchant_key` | TEXT | |
| `inventory_type` | TEXT | `equipment` \| `feed` |
| `transaction_type` | TEXT | `DIRECT_PURCHASE` \| `FINANCING_REQUEST` |
| `item_id`, `item_title`, `amount`, `category` | | |
| `financing_tenor_months` | INTEGER | required when financing |
| `customer_full_name`, `customer_phone`, `customer_national_id` | | |
| `success_callback_url`, `failure_callback_url` | | |
| `status` | TEXT DEFAULT 'CREATED' | CREATED \| REDIRECTED \| PAID \| FAILED |
| `transaction_ref` | TEXT | links to `central_transactions` once paid |

### 4.5 Row-Level Security (Phase 5)

PostgreSQL RLS is applied by SQL scripts in `backend/sql/`, run once by a superuser:

- `03_ownership_rls_setup.sql` — relationship-based ownership RLS (farmers→agent, purchases, inventory), keyed on `app.current_user_id` / `app.current_role`.
- `04_app_scope_rls_setup.sql` — **new** app-scope isolation on `products`, `transactions`, `merchant_keys`. Each backend sets, per connection:
  ```sql
  SELECT set_config('app.current_app_scope', 'equipment'|'feed', false);
  ```
  A row is admissible when its `app_scope` matches the connection scope, is `'both'`, or no scope is set (legacy). `current_app_is_admin()` context still bypasses.

The app sets session context through the `PostgresStatement.setContext()` path in `db-postgres.ts` (`SELECT set_config($1,$2,false)`).

---

## 5. The Six-Phase Unification Project

### Phase 1 — Feature Parity Audit & Structural Sync
- Full audit of both codebases. Feed was found to be a functional superset; 19 Feed-only endpoints/modules were catalogued.
- Both apps confirmed to share **identical** HMAC utilities and **identical** `normalizePhone()`.
- Feed had `password.ts`; Equipment did not → a matching `password.ts` was created for Equipment.
- Result: identical navigation, UI layouts and management modules across both apps. Only allowed structural difference: **payments centralized in Equipment.**

### Phase 2 — Centralized Payments + Cross-Navigation
- All direct gateway logic (M-Pesa/Daraja, SasaPay, Buni, webhooks) stays in **Equipment**. Feed routes payment requests to Equipment via HMAC-signed server-to-server calls.
- Added `inventory_type` and `origin_platform` to the transaction tables.
- **Unified ledger** (`GET /api/ledger`, admin only) reads `central_transactions` filterable by `inventory_type` (category) + `origin_platform`.
- **Cross-navigation with no second login** ("Shop Equipment" on Feed, "Shop Feeds" on Equipment) via a shared-secret SSO handoff (`backend/cross-app.ts`):
  - `mintHandoffToken(secret, phone)` = `base64url(JSON{phone,ts,nonce}) + "." + hmacSha256Hex(secret, body)`.
  - `verifyHandoffToken` verifies HMAC + a 2-minute TTL.
  - `GET /api/cross/handoff` (authenticated) returns `{CROSS_APP_URL}/sso?token=...`.
  - `GET /sso` on the sibling app verifies the token, matches the user across all phone formats, creates a local session, and redirects.

### Phase 3 — Public Merchant API (`backend/merchant-api.ts`)
- Versioned surface mounted at `/api/v1/...`:
  - **Inventory:** `POST/PUT/GET/DELETE /v1/merchant/inventory[/{item_id}]`
  - **Checkout:** `POST /v1/checkout/equipment`, `POST /v1/checkout/feeds`
  - **Session:** `GET /v1/checkout/session/{ref}` (public read)
- Every request authenticated with a merchant key + HMAC-SHA256 signature (see §6).
- Checkout enforces **cross-catalog isolation**: an Equipment app rejects `/checkout/feeds` (and vice-versa) with `409`.
- On success returns a `hosted_checkout_url` (`{PUBLIC_BASE_URL}/checkout/{ref}`) — the embeddable merchant button POSTs the payload then redirects the buyer there.

### Phase 4 — Auth & Shared DB Config (`backend/password.ts`)
- Standardized, **env-driven** PBKDF2-SHA256 hashing, identical in both apps:
  - `AUTH_HASH_ITERATIONS` (default 210 000), `AUTH_HASH_KEYLEN` (default 32), `AUTH_PEPPER` (default empty).
  - Storage format: `pbkdf2$<iterations>$<saltB64>$<hashB64>`.
  - **Upgrade-on-login**: legacy plaintext passwords verify once, then are transparently re-hashed. (Equipment previously stored plaintext; migrated automatically on next login.)
- Uniform phone normalization (`normalizePhone`) in both backends: strips non-numeric, `0…`→`254…`, bare `7…` (len 9)→`254…`, `2540…`→`254…`.
- Login queries match `raw`, normalized `254…`, and `+254…` forms — no hidden `app_scope`/tenant filters block valid logins.

### Phase 5 — Data Isolation & Frontend Filtering
- `app_scope` (`equipment`|`feed`|`both`) added to shared tables.
- Backend list endpoints filter by `APP_TYPE` env (`/api/products` surfaces `app_scope IN (<appType>, 'both')`).
- PostgreSQL RLS enforces the same isolation at the database layer (`04_app_scope_rls_setup.sql`).
- Frontend multi-parameter **client-side filters** (search + category/status/scope selects + date ranges) via the reusable `filterToolbar()` / `rowMatchesFilters()` helpers, wired into every major list view: **Inventory, Unified Ledger, Contracts/Purchases, Customers, Users, Repayments**.

### Phase 6 — Zero-Trust Security
- **HMAC-SHA256 signature verification on all cross-app calls** (merchant API + SSO handoff). Requests with a missing/invalid signature are rejected with `401`.
- **Replay protection:** 5-minute timestamp window + per-request nonce uniqueness (in-memory nonce cache). Replayed nonces → `401`.
- **RBAC middleware on every payment-administration endpoint**: `/admin/*` on the payment gateway requires a valid admin/super_admin session (`401` unauthenticated, `403` non-admin). Non-admins are blocked from payment logs and cross-platform tooling.

---

## 6. Security Model

### 6.1 HMAC-SHA256 signing scheme (shared, identical in both apps)

```
canonical = client_key + "\n" + timestamp + "\n" + nonce + "\n" + rawBody
signature = HMAC_SHA256_hex(secret, canonical)
```

- **Internal gateway** headers: `X-Farmsky-Client`, `X-Farmsky-Timestamp`, `X-Farmsky-Nonce`, `X-Farmsky-Signature`.
- **Merchant API** headers: `X-Merchant-Key`, `X-Merchant-Timestamp`, `X-Merchant-Nonce`, `X-Merchant-Signature`.
- `timestamp` is milliseconds since epoch (matches JS `Date.now()`); requests older than **5 minutes** are rejected.
- Nonces must be unique within the window.

### 6.2 Password hashing (`password.ts`)
- PBKDF2-SHA256, 210 000 iterations (configurable), 256-bit derived key, per-password 16-byte random salt, optional server-side pepper.
- Constant-time comparison; upgrade-on-login for legacy plaintext.

### 6.3 Sessions & RBAC
- Sessions in the `sessions` table (`token`, `user_id`, `expires_at`), delivered as a `session` cookie, 12-hour expiry.
- Middleware: `requireAuth`, `requireRole(...roles)`, `requirePermission(...perms)`; helpers `hasPermission(user, perm)`, `withAdminContext(c, fn)`.
- Payment `/admin/*` guarded by a dedicated session-checking middleware.

### 6.4 Row-Level Security
- Ownership RLS + app-scope RLS on shared tables (see §4.5). No connection context ⇒ general users see zero owned rows / only `'both'` scope.

---

## 7. Environment Variables

| Variable | Both / App | Purpose |
|----------|-----------|---------|
| `DATABASE_URL` | both | PostgreSQL connection string |
| `SESSION_SECRET` | both | session token secret |
| `APP_TYPE` | both | `equipment` \| `feed` — data-scope + payment-host context |
| `PUBLIC_BASE_URL` | both | this app's public origin (hosted checkout URLs) |
| `CROSS_APP_URL` | both | sibling app origin (cross-nav target) |
| `CROSS_APP_HMAC_SECRET` | both | shared secret for cross-app SSO handoff (**must match** on both apps) |
| `AUTH_HASH_ITERATIONS` | both | PBKDF2 rounds (**must match** on both apps) |
| `AUTH_HASH_KEYLEN` | both | derived key length in bytes (**must match**) |
| `AUTH_PEPPER` | both | server-side pepper (**must match**) |
| `MPESA_*`, `SASAPAY_*`, `BUNI_*` | Equipment | payment provider credentials |
| `SMS_*`, `EMAIL_*` | both | notification providers |
| `TRANSUNION_*` | both | KYC / credit check |

> **Critical:** `CROSS_APP_HMAC_SECRET`, `AUTH_HASH_ITERATIONS`, `AUTH_HASH_KEYLEN` and `AUTH_PEPPER` must be configured with **identical values** on both platforms, otherwise cross-app SSO and password portability break.

---

## 8. Build, Test & Run Runbook

### 8.1 Local test databases
```bash
# Feed
createdb farmsky_f5   # owner: feed_app
DATABASE_URL="postgresql://feed_app:***@localhost:5432/farmsky_f5" APP_TYPE=feed \
  node dist-node/server.js --migrate-only

# Equipment
createdb farmsky_eq_test
DATABASE_URL="postgresql://feed_app:***@localhost:5432/farmsky_eq_test" APP_TYPE=equipment \
  node dist-node/server.js --migrate-only
```
Seeded super admin — Feed: `+2547500000` / `1224`; Equipment: `+254702875711` / `1224`.

### 8.2 Run
```bash
NODE_OPTIONS="--max-old-space-size=512" npm run build:node
DATABASE_URL="..." APP_TYPE=feed PORT=9100 SESSION_SECRET=... \
  CROSS_APP_HMAC_SECRET=... CROSS_APP_URL="https://equipment..." \
  PUBLIC_BASE_URL="https://feed..." node dist-node/server.js
```

### 8.3 Apply Row-Level Security (once, as superuser)
```bash
psql "$SUPERUSER_DATABASE_URL" -f backend/sql/03_ownership_rls_setup.sql
psql "$SUPERUSER_DATABASE_URL" -f backend/sql/04_app_scope_rls_setup.sql
```

---

## 9. Verified Test Results (both platforms)

| Test | Feed | Equipment |
|------|------|-----------|
| Login (all phone formats) | ✅ 200 | ✅ 200 |
| Password re-hash on legacy login | ✅ | ✅ (`pbkdf2$210…`) |
| `/api/cross/config` app_type | ✅ `feed` | ✅ `equipment` |
| `/api/cross/handoff` mints token | ✅ | ✅ |
| `/sso` tampered/empty token | ✅ 401 | ✅ 401 |
| `/api/ledger` (admin) | ✅ 200 | ✅ 200 |
| Merchant inventory create | ✅ `inventory_type=feed` | ✅ `inventory_type=equipment` |
| Merchant no-signature | ✅ 401 | ✅ 401 |
| Merchant nonce replay | ✅ 401 | ✅ 401 |
| Cross-catalog checkout isolation | ✅ 409 | ✅ 409 |
| Same-catalog checkout | ✅ 201 | ✅ 201 |
| Financing without tenor | ✅ 400 | ✅ 400 |
| Hosted checkout page | ✅ 200 | ✅ 200 |
| Payment `/admin/*` no-auth | ✅ 401 | ✅ 401 |
| Payment `/admin/*` as admin | ✅ 200 | ✅ 200 |

Node bundle sizes: Feed `dist-node/server.js` ≈ 303.9 kb; Equipment ≈ 261.1 kb.

---

## 10. Git Workflow

- Work on `genspark_ai_developer`, commit with `--no-verify`, merge into `main`, push both branches.
- Feed pushed and verified at commit `4d950b3` (both `main` and `genspark_ai_developer`).
- Equipment committed/merged locally at `94a56bc` (Part A gateway work was previously pushed at `28d0115`).
- PATs are injected only in the push URL and scrubbed immediately after (remote reset to a clean URL, `~/.git-credentials` removed).

---

*End of Technical Documentation.*
