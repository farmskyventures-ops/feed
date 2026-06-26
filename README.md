# Farmsky — Sharia-Compliant Murabaha Agri-Finance

A demo lending platform for agriculture & livestock. Customers buy farm inputs
(feed, fertilizer, seeds, equipment, livestock) via **cash** or **Murabaha credit**
— a fixed cost-plus-markup model with **no interest, no penalties, no compounding**
(fully Sharia-compliant).

## Features
- 5 roles: Super Admin, Admin, Agent, Customer/Farmer, Customer Support
- **Customer self sign-up, sign-in & password reset with SMS OTP** — works with
  any OAuth 2.0 / Bearer-token SMS gateway (configured via env vars). If no SMS
  provider is set, runs in **demo mode** (OTP shown on screen) so flows stay testable.
- **Agent onboarding from the Admin dashboard** — set a password at creation (or
  auto-generate one) plus a **one-click "Reset Password"** button (auto-generates a
  new password and shows it to the admin to share). Agents then sign in normally.
- **Admin Data Export** — pick a dataset (users, customers, agents, products,
  contracts, repayments, transactions, audit logs), apply **filters** + date range,
  preview, then **download as CSV / Excel (.xlsx)** locally, or **share by email**
  (CSV attachment) when an email provider is configured.
- Agent-led customer onboarding (with GPS capture)
- **Complete User Registration**: TransUnion check + Live ID / liveness
  verification (camera). Required before Pay Later (Murabaha Financing) purchases.
- Inventory with **product images** (shown to buyers) + stock movements
- **Pay Later (Murabaha Financing)** quoting, application, approval, repayment tracking
- **M-Pesa Daraja STK Push** payments (live when keys set, simulated otherwise)
- Admin CRUD for users, agents, and inventory (edit / activate / deactivate / delete)
- Role-aware dashboards & analytics

## Configuration (env)
All integrations are env-driven — at deploy you just **copy-paste** the
tokens into `.env` (see `.env.example` for step-by-step instructions):
- **M-Pesa Daraja STK Push**: `MPESA_*` — sandbox defaults pre-filled; paste your
  sandbox Consumer Key/Secret to test, or leave blank for simulation. STK push
  is used for **both cash checkout and Pay Later (Murabaha) repayments**.
- **SMS OTP — TalkSASA** (`talksasa.com`): paste `SMS_API_TOKEN` + `SMS_SENDER_ID`
  (your Safaricom-registered NameID). Endpoint defaults automatically. Blank = demo
  mode (OTP shown on screen).
- **Email share — Resend** (`resend.com`): paste `EMAIL_API_TOKEN` (re_xxx) +
  `EMAIL_FROM` (verified address). Blank = email button disabled, local download
  still works.

## Test credentials
| Role | Phone | Password |
|------|-------|----------|
| Admin | `+2547500000` | `1224` |
| Agent | `+2547400000` | `1225` |
| Customer | `+2547300000` | `1226` |
| Support | `+2547200000` | `1227` |

## Run locally (Node server + PostgreSQL)
```bash
# 1. Start PostgreSQL and create the database/user (one-time)
#    createdb farmsky; createuser farmsky ... or:
#    CREATE DATABASE farmsky; CREATE USER farmsky WITH PASSWORD 'farmsky';

npm install
cp .env.example .env     # set DATABASE_URL or PG* vars; add M-Pesa keys (optional)

npm run db:migrate       # apply migrations-pg/*.sql
npm run db:seed          # load demo data (seed-pg.sql)
# or: npm run db:reset    # DROP schema, migrate + seed from scratch

npm run build:node
npm start                # http://localhost:8080
```
The server also auto-applies migrations + seed on first boot, so a fresh
database is initialised automatically the first time you run `npm start`.

### Database connection
Configure either a single connection string **or** discrete variables in `.env`:
```bash
# Option A (recommended for managed Postgres — RDS / Supabase / Neon)
DATABASE_URL=postgresql://farmsky:farmsky@127.0.0.1:5432/farmsky
# append ?sslmode=require for managed SSL endpoints

# Option B (used only when DATABASE_URL is unset)
PGHOST=127.0.0.1
PGPORT=5432
PGUSER=farmsky
PGPASSWORD=farmsky
PGDATABASE=farmsky
```

## Deploy
See **[AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md)** for:
- AWS EC2 (recommended easy path) — Nginx + free HTTPS
- AWS App Runner (Docker, no server management)
- Cloudflare Pages (free tier)
- Full M-Pesa Daraja credential setup (where to copy each key)

## Tech
- **Hono** (TypeScript) — runs on Node via `@hono/node-server`
- **PostgreSQL** via `pg` (node-postgres) connection pool, accessed through a
  small D1-compatible adapter in `src/db-postgres.ts` (the app code keeps the
  `prepare().bind().first()/.all()/.run()` API; the adapter converts `?`
  placeholders to `$1,$2,…` and surfaces `RETURNING id` as `last_row_id`)
- Vanilla JS SPA (Tailwind CDN, FontAwesome, Axios)

## Project layout
```
src/index.tsx     # Hono app (all API routes + HTML shell) — shared by both builds
src/mpesa.ts      # M-Pesa Daraja STK Push integration
src/server.ts       # Node entry point (opens PG pool, applies migrations)
src/db-postgres.ts  # D1-compatible PostgreSQL adapter (pg)
src/db-init-pg.ts   # auto-applies migrations-pg + seed-pg on first boot
scripts/pg.mjs      # CLI: db:migrate / db:seed / db:reset
public/static/      # app.js, style.css, farmsky-logo.png, favicon.png
migrations-pg/      # PostgreSQL schema migrations
seed-pg.sql         # demo data (PostgreSQL)
Dockerfile        # for App Runner / ECS
.env.example      # env + M-Pesa credential instructions
```
