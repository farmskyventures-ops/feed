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

## Run locally (Node server)
```bash
npm install
npm run build:node
cp .env.example .env     # add M-Pesa keys (optional; blank = simulation)
npm start                # http://localhost:8080
```

## Run locally (Cloudflare dev)
```bash
npm install
npm run build
npx wrangler d1 migrations apply webapp-production --local
npm run db:seed
npx wrangler pages dev dist --d1=webapp-production --local --port 3000
```

## Deploy
See **[AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md)** for:
- AWS EC2 (recommended easy path) — Nginx + free HTTPS
- AWS App Runner (Docker, no server management)
- Cloudflare Pages (free tier)
- Full M-Pesa Daraja credential setup (where to copy each key)

## Tech
- **Hono** (TypeScript) — runs on Cloudflare Workers *and* Node (`@hono/node-server`)
- **SQLite** via `better-sqlite3` on Node / **Cloudflare D1** on the edge
  (same SQL, via a small D1-compatible adapter in `src/db-sqlite.ts`)
- Vanilla JS SPA (Tailwind CDN, FontAwesome, Axios)

## Project layout
```
src/index.tsx     # Hono app (all API routes + HTML shell) — shared by both builds
src/mpesa.ts      # M-Pesa Daraja STK Push integration
src/server.ts     # Node entry point (AWS)
src/db-sqlite.ts  # D1-compatible SQLite adapter for Node
src/db-init.ts    # auto-applies migrations + seed on first boot
public/static/    # app.js, style.css, farmsky-logo.png, favicon.png
migrations/       # SQL schema
seed.sql          # demo data
Dockerfile        # for App Runner / ECS
.env.example      # env + M-Pesa credential instructions
```
