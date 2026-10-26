# Offtake Contracting & Produce Sourcing Module — Specification

> Operational write-up of the Offtake Contracting module across the Farmsky
> ecosystem (**Equipment**, **Nia** — crop/horticulture inputs, **Feed** —
> livestock), plus setup guidelines for every required third-party API.

---

## 1. Overview

The Offtake Contracting module extends the farmer input/feed/equipment financing
platform with an end-to-end **Produce Sourcing, Contracting & Supply-Chain**
layer. It closes the loop between input credit and produce off-take: a farmer
takes inputs on credit, a buyer issues a forward/spot contract, produce is
delivered & graded, and the system auto-deducts the outstanding input loan from
the gross proceeds before paying the farmer the net.

Every capability ships behind **Feature Management & QA** and is **Sandbox by
default** — hidden from end users (Super-Admin-only) until graduated to Testing
(whitelist) then Live/Global.

---

## 2. Architecture

- **Backend**: Hono + TypeScript (`backend/index.tsx`). Dual build — Node
  (`dist-node/server.js`, authoritative) and Cloudflare Worker (`dist/_worker.js`).
- **Database**: PostgreSQL with **FORCE Row-Level Security**; the app connects as
  a non-superuser. Privileged server-internal writes (e.g. public sign-up) run on
  a pinned admin connection via `DB.runAsAdmin(...)`.
- **Feature governance**: `feature_flags` (+ `feature_flag_users` whitelist).
  New features auto-register at `stage='sandbox'`.

### 2.1 Data model (additive, non-breaking)

| Table | Purpose |
|-------|---------|
| `offtake_contracts` | Spot/forward contracts (archetype, price basis, quality specs, escrow, milestone, buyer tenant, intake site). |
| `offtake_matches` | External (SMS/USSD) / internal / agent matches to out-growers. |
| `aggregation_batches` | Agent weigh/QR-tag batches. |
| `buyer_tenants` | Multi-tenant Produce Buyer enterprises. |
| `intake_sites` | Buyer intake sites / weighbridges. |
| `delivery_slots` | Time-slotting (inload/outload). |
| `freight_orders` | Freight / call-on-grain / request / pack orders. |
| `commodity_movements` | Farm-gate to site loads (gross/tare/net, GPS). |
| `freight_trucks` | Fleet registry + statutory mass limits. |
| `stock_ledger` | Multi-site owned/3rd-party commodity stock. |
| `cashboard_bids` | Live price boards & bids (accept -> auto contract). |
| `settlement_records` | RCTI + split-settlement (loan offset / fee / freight / net). |
| `cor_declarations` | Chain-of-Responsibility mass checks & declarations. |
| `container_packs` | Containerised export packing. |
| `logistics_shipments` / `telemetry_pings` | Live GPS + cold-chain tracking. |
| `traceability_events` | Immutable provenance (public QR lookup). |

---

## 3. Role-Based Access Control (RBAC)

Hierarchical roles (each inherits the scope below it, except Farmer/Aggregator):

| Role | Scope |
|------|-------|
| `super_admin` | Global — all features, all tenants, feature lifecycle, overrides. |
| `admin` | Operational global administrator. |
| `buyer_enterprise` | Buyer tenant admin (sites, teams, contract templates). |
| `commercial_manager` | Issues contracts, runs cashboards/bids, approves orders. |
| `site_manager` | Site hours/slots, weighbridge tickets, quality. |
| `logistics_provider` | Fleets/drivers, load allocation, mass compliance. |
| `driver` | Assigned loads, GPS logs, PoD signatures. |
| `agent` / `coop` | Act for farmers (bids only if `accept_bids` granted). |
| `customer` (Farmer) | Offers, bids, contracts, slots, payouts, loan offset. |

### 3.1 Dynamic sidebar (granular RBAC)

The sidebar renders a single collapsible **"Offtake Contracting"** group. Each
sub-module is gated by (a) its **feature flag availability** for the user and
(b) the user's **permission**. Non-Super-Admins see only the sub-modules they are
authorized for; if none are available the entire group is hidden.

| Sub-module | Feature flag | Permission(s) |
|-----------|--------------|---------------|
| Offtake Contracts | `offtake_contracting` | `manage_offtake`, `match_outgrowers` |
| Match Buyers & Outgrowers | `admin_matching_engine` | `match_outgrowers` |
| Produce Aggregation | `agent_aggregation` | `aggregate_produce` |
| Logistics & Tracking | `logistics_telemetry` | `manage_logistics` |
| Traceability | `traceability_ledger` | `view_traceability` |
| Buyer Portal & Sites | `buyer_portal` | `manage_buyer_tenant`, `manage_intake_sites` |
| Cashboards & Bids | `cashboards_bidding` | `manage_cashboards`, `accept_bids` |
| Time Slotting | `time_slotting` | `manage_slots`, `book_slots` |
| Orders & Freight | `order_management` | `manage_orders`, `manage_freight` |
| Movements | `movement_tracking` | `log_movements` |
| Settlement & RCTI | `closed_loop_settlement` | `manage_settlement` |
| Stocks & Ledger | `stock_ledger` | `manage_stock_ledger` |

---

## 4. Feature Lifecycle Management

New features auto-register at **Sandbox** on boot (migration `INSERT OR IGNORE …
stage='sandbox'`). Super-Admins graduate each feature through:

```
Sandbox  -->  Testing  -->  Live (Global / Production)
(Super-Admin   (whitelist     (global_enabled = true -> all users;
 only)          of pilot users) else selected users only)
```

- **Server gate**: `requireFeature(key)` -> 404 when unavailable.
- **Client gate**: `featureOn(key)` (from `/api/features/enabled`).
- **Admin UI**: Feature Management panel (stage selector + whitelist + Global toggle).

---

## 5. Closed-Loop Settlement

```
Net Payout = Gross Produce Value - (Input Loan Offset + Platform Fee + Freight Deductions)
```

- RCTI (Recipient-Created Tax Invoice) is generated on settlement.
- The input loan offset auto-resolves from the farmer's outstanding murabaha
  contracts (capped at gross). Configurable **system-wide or per contract**.
- Escrow modes: **Fully Pre-Delivery**, **Partially Pre-Delivery** (configurable
  upfront %), **On-Delivery Clearance** (PoD sign-off).

---

## 6. Real-Time Logistics Tracking

- Drivers stream GPS + speed + cold-chain temp/humidity (~10s cadence) to
  `POST /api/logistics/shipments/:id/ping`.
- `GET /api/logistics/shipments/:id/track` returns the breadcrumb **route**,
  **distance remaining** (haversine to destination) and **live ETA**
  (distance / current speed) — an Uber-like live updating system.
- The tracker UI renders a live map (canvas breadcrumb with route polyline,
  vehicle marker, destination pin). When a Maps API key is configured
  (`GET /api/logistics/map-config`) it also deep-links to Google Maps.

---

## 7. Automated Testing, QA & Self-Healing Pipeline

- `GET /api/health` — liveness probe (no auth).
- `POST /api/admin/self-test` (admin) — runs non-destructive checks: DB
  connectivity, **customers RLS sign-up INSERT** (transactional, rolled back),
  feature management, core-table reads, and payment-gateway config. Returns
  `200 healthy` / `503 degraded` with per-check diagnostics + remediation hints.
  Known failure modes (e.g. pkey/sequence desync) trigger **auto-healing**
  (sequence realignment) when `auto_heal` is on.
- `scripts/self_healing_qa.mjs` — external runner: black-box probes (sign-up
  e2e, auth), logs root-cause diagnostics, and emits remediation/rollback
  triggers for CI / uptime monitors. Exit `0` healthy, `1` degraded, `2` down.

```bash
node scripts/self_healing_qa.mjs --base https://<host> --phone <admin> --password <pw> [--watch 60]
```

---

## 8. Third-Party APIs — Setup Guidelines

All integrations degrade to **simulation mode** automatically when keys are
unset (so development & QA work with no credentials). Configure via environment
variables on each deployment.

### 8.1 M-Pesa (Safaricom Daraja) — STK Push
| Variable | Notes |
|----------|-------|
| `MPESA_CONSUMER_KEY` / `MPESA_CONSUMER_SECRET` | Daraja app credentials. |
| `MPESA_SHORTCODE` / `MPESA_PASSKEY` | Lipa-na-M-Pesa paybill/till + passkey. |
| `MPESA_ENV` | `sandbox` or `production`. |
| `MPESA_CALLBACK_URL` | `https://<host>/api/mpesa/callback`. |

Setup: create a Daraja app at https://developer.safaricom.co.ke, enable
Lipa-na-M-Pesa Online, register the callback URL.

### 8.2 SasaPay
| Variable | Notes |
|----------|-------|
| `SASAPAY_CLIENT_ID` / `SASAPAY_CLIENT_SECRET` | Merchant API credentials. |
| `SASAPAY_API_KEY` | API key (if issued). |
| `SASAPAY_CALLBACK_URL` | IPN / settlement callback. |

Setup: onboard as a SasaPay merchant, obtain API credentials, whitelist the
callback URL. The central payment gateway settles SYNCHRONOUSLY on the IPN.

### 8.3 KCB Buni (KCB Bank Payment Gateway)
| Variable | Notes |
|----------|-------|
| `BUNI_API_KEY` / `BUNI_CLIENT_ID` / `BUNI_CLIENT_SECRET` | KCB Buni API credentials. |
| `BUNI_CALLBACK_URL` | Funds-transfer / IPN callback. |

Setup: register on the KCB Buni developer portal, subscribe to the funds-transfer
/ STK product, configure the callback.

### 8.4 Google Maps (live tracking)
| Variable | Notes |
|----------|-------|
| `GOOGLE_MAPS_API_KEY` (or `MAPS_API_KEY`) | Maps JavaScript + Directions API. |

Setup: enable Maps JavaScript API & Directions API in Google Cloud, restrict the
key by HTTP referrer/host. When unset, the tracker falls back to the built-in
canvas breadcrumb renderer (no key required).

### 8.5 SMS / OTP gateway
| Variable | Notes |
|----------|-------|
| `SMS_API_KEY` / `SMS_SENDER_ID` / `SMS_USERNAME` | SMS provider (e.g. Africa's Talking). |

Setup: used for sign-up / password-reset OTPs and external SMS/USSD out-grower
match prompts. When unset, OTPs run in **demo mode** (the code is returned in the
API response as `demo_otp` for testing).

---

## 9. Key Endpoints (reference)

| Area | Endpoint |
|------|----------|
| Auth | `POST /api/signup/request-otp`, `/api/signup/verify`, `/api/login`, `/api/reset-password/request-otp`, `/api/reset-password/verify` |
| Offtake | `GET/POST /api/offtake/contracts`, `/api/offtake/contracts/:id/{match,candidates,escrow,milestone}` |
| Buyer portal | `GET/POST /api/produce/{buyer-tenants,intake-sites}` |
| Slotting | `GET/POST /api/produce/slots`, `PUT /api/produce/slots/:id` |
| Orders / movements | `GET/POST /api/produce/{orders,movements,trucks}` |
| CoR | `POST /api/produce/cor/check`, `GET /api/produce/cor` |
| Stock / containers | `GET/POST /api/produce/{stock,containers}` |
| Cashboards | `GET/POST /api/produce/cashboard`, `POST /api/produce/cashboard/:id/accept` |
| Settlement | `GET/POST /api/produce/settlement`, `PUT /api/produce/settlement/:id/pay` |
| Logistics | `GET/POST /api/logistics/shipments`, `/:id/{ping,track,pod}`, `GET /api/logistics/map-config` |
| Traceability | `POST /api/traceability/ingest`, `GET /api/traceability/public/:ref` |
| Health / QA | `GET /api/health`, `POST /api/admin/self-test` |
| Features | `GET /api/features`, `/api/features/enabled`, `PUT /api/features/:key` |

---

## 10. Cross-App Notes

- **Equipment** is the host/gateway tenant; **Nia** (crop) and **Feed**
  (livestock) are satellites that route payments through the Equipment central
  gateway. Branding is preserved per app.
- All migrations are **additive & idempotent**; nothing existing is replaced,
  ensuring zero regression.
