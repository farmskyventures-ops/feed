# Farmsky Feed — Sharia-Compliant Agri-Input Marketplace

The **Feed** marketplace lets farmers buy animal feed and farm inputs through two
Sharia-compliant rails only:

1. **Cash** — outright purchase (with an optional configurable deposit) plus a
   transparent cash markup.
2. **Murabaha credit** — a fixed **cost-plus-markup** financing model with
   **no interest (riba), no penalties, no compounding**. The markup is agreed up
   front and repaid in equal installments over the selected term.

Feed is a **client** of the **Farmsky Central Payment Gateway** hosted at
`equipment.farmsky.africa`. Feed never holds raw M-Pesa / SMS / OTP / email
provider credentials — it signs HMAC requests to the central processor, which
executes payments and dispatches SMS, OTP and email on its behalf.

> Feed shares the **same central PostgreSQL database** (hosted on Render) as
> `equipment.farmsky.africa`. Multi-tenancy is enforced in the database via
> Row-Level Security (see *Security*).

---

## Highlights

- **Roles & RBAC** — Super Admin, Admin, Agent, Customer/Farmer, Customer Support,
  Operations/Finance. Every capability is a named permission checked per route
  (`requirePermission(...)`), and finance-sensitive fields are additionally
  protected in the database.
- **Ownership Row-Level Security (RLS)** — agents see only the farmers they
  onboarded and those farmers' contracts; product listings are scoped to their
  creator; wallets/ledgers are scoped to their owner. With no session context,
  **zero rows** are returned (verified by `GET /api/security/rls-check`).
- **Agent Wallet System** — immutable double-entry `wallet_ledger`, per-agent
  `wallets`, configurable `earning_rules` (e.g. 2.5% commission on completed
  orders), admin payout batches and withdrawals. Balances can only move through a
  ledger entry (enforced by database triggers).
- **Sign-up, KYC & checkout** — customer self sign-up / sign-in / password reset
  with SMS OTP (via the central gateway); TransUnion credit check + live ID /
  liveness verification required before Murabaha financing.
- **Central Payment Gateway integration** — HMAC-SHA256 signed requests
  (`client_key\ntimestamp\nnonce\nbody`), replay protection (5-minute window +
  single-use nonce), idempotency keys, and a signed `/api/payments/incoming`
  settlement webhook.
- **Admin tooling** — financing approvals, finance settings (markup / processing
  fees), wallet assignment & earning rules, payout batches, pending-payment
  retrieval, data export (CSV / Excel), audit logs.

---

## Security

Security is layered so that a breach at any single layer does not leak data:

- **Passwords** — PBKDF2-SHA256 (WebCrypto, 210,000 iterations, per-user salt).
  Runs identically on Node and Cloudflare Workers. Any legacy plaintext password
  is transparently re-hashed on first successful login.
- **Sessions** — 256-bit random opaque tokens stored server-side in `sessions`
  (not JWTs); delivered via `HttpOnly` cookie or `Authorization: Bearer`.
- **Two RLS layers** (the app connects as a **non-superuser** role so
  `FORCE ROW LEVEL SECURITY` cannot be bypassed):
  - *Payment multi-tenancy* — `app.current_marketplace_id`, `app.is_admin`.
  - *Ownership* — `app.current_user_id`, `app.current_role`, `app.user_can_finance`.
- **Split-data protection** — a database trigger blocks anyone without
  `can_manage_finance_settings` from writing markup / financing columns, even via
  a crafted direct API call.
- **Gateway requests** — HMAC-signed, replay-protected, idempotent.
- **Transport / app hardening** — same-origin CORS with credentials, security
  headers, and per-endpoint sliding-window rate limiting (login, OTP, payments).
- **No secrets in the repo** — every credential is env-driven; `.env.example`
  contains only blank placeholders and documentation.

Verify RLS isolation at runtime:
```bash
curl -s http://localhost:8080/api/security/rls-check   # isolation_ok: true
```

---

## Configuration (environment variables)

All configuration is env-driven. On **Render**, set these under the
`equipment.farmsky.africa` project environment — **do not hardcode anything**.
See `.env.example` for the full annotated list.

### Database (shared central Postgres on Render)
| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres connection string for the **non-superuser** app role |
| `PGSSLMODE` | `require` on Render; `disable` for local dev |

### Central Payment Gateway (Feed is a client)
| Variable | Purpose |
|----------|---------|
| `FARMSKY_PAYMENTS_GATEWAY_URL` | e.g. `https://equipment.farmsky.africa/api/v1/payments` |
| `FARMSKY_PAYMENTS_CLIENT_KEY`  | This marketplace's client key — `feed` |
| `FARMSKY_PAYMENTS_HMAC_SECRET` | Shared HMAC secret issued by the gateway |
| `SESSION_SECRET` | Extra entropy for session/token hardening |

The gateway owns all downstream provider credentials (M-Pesa Daraja, SasaPay,
KCB Buni, TalkSASA SMS/OTP, Resend email). Feed does **not** set them directly.

> **Local dev fallback:** if the gateway variables are absent, payments fall back
> to direct M-Pesa Daraja simulation so checkout stays testable offline.

---

## Test credentials (seed / demo)

| Role | Phone | Password |
|------|-------|----------|
| Super Admin | `+2547500000` | `1224` |
| Agent | `+2547400000` | `1225` |
| Customer | `+2547300000` | `1226` |
| Support | `+2547200000` | `1227` |

Seed passwords are plaintext demo values that are **automatically upgraded to a
PBKDF2 hash on first login**.

---

## Run locally (Node — authoritative production runtime)

```bash
npm install

# 1. Point at a Postgres database (local or Render) via a NON-superuser role
export DATABASE_URL="postgresql://feed_app:feed_app_pw@127.0.0.1:5432/farmsky_feed"
export PGSSLMODE=disable          # 'require' against Render

# 2. Apply the two RLS setup scripts ONCE as a superuser
psql "$SUPERUSER_DATABASE_URL" -f backend/sql/01_payment_rls_setup.sql
psql "$SUPERUSER_DATABASE_URL" -f backend/sql/03_ownership_rls_setup.sql

# 3. Build + start (migrations + seed auto-apply on first boot)
npm run build:node
npm start                          # http://localhost:8080
```

Optionally set the gateway variables to route real payments; otherwise M-Pesa
runs in simulation.

## Run locally (Cloudflare Workers dev)

```bash
npm install
npm run build
npx wrangler pages dev dist --port 3000
```

## Deploy (Render)

1. Create a **PostgreSQL** instance (or reuse the central one shared with
   `equipment.farmsky.africa`).
2. Create the **non-superuser** app role and grant it table privileges (never
   run the app as a superuser — RLS would be bypassed).
3. Apply `backend/sql/01_payment_rls_setup.sql` and
   `backend/sql/03_ownership_rls_setup.sql` once as a superuser.
4. Deploy this repo as a **Web Service**:
   - Build: `npm install && npm run build:node`
   - Start: `npm start`
5. Set all environment variables (above) in the Render project. Migrations and
   the seed apply automatically on first boot.

---

## Tech stack

- **Hono** (TypeScript) — runs on Cloudflare Workers *and* Node
  (`@hono/node-server`).
- **PostgreSQL** via `pg` with a small D1-compatible adapter
  (`backend/db-postgres.ts`) that also sets the per-request RLS session GUCs.
- **PBKDF2-SHA256** password hashing (WebCrypto) — `backend/password.ts`.
- **HMAC-SHA256** gateway client — `backend/payment-gateway-client.ts`,
  `backend/payments-shared.ts`.
- Vanilla-JS SPA (Tailwind, FontAwesome, Axios).

## Project layout

```
backend/index.tsx                # Hono app — all API routes + HTML shell
backend/server.ts                # Node entry point (Render)
backend/password.ts              # PBKDF2 password hashing
backend/payment-gateway-client.ts# HMAC client to the central gateway
backend/payments-shared.ts       # HMAC sign / verify helpers
backend/db-postgres.ts           # D1-compatible Postgres adapter + RLS GUCs
backend/db-init.ts               # auto-applies migrations + seed on first boot
backend/sql/01_payment_rls_setup.sql   # payment multi-tenancy RLS (run as superuser)
backend/sql/03_ownership_rls_setup.sql # ownership RLS + wallet triggers (superuser)
frontend/static/                 # app.js, styles, logos
migrations/                      # Postgres schema (0001…0013)
seed.sql                         # demo data (no real secrets)
.env.example                     # annotated env template (no secrets)
Dockerfile                       # container build
```
