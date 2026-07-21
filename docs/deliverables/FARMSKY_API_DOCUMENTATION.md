# Farmsky Ventures — API Documentation

**Version:** 1.0
**Applies to:** Farmsky FEED app (`APP_TYPE=feed`) and Farmsky EQUIPMENT app (`APP_TYPE=equipment`)
**Base URLs:**
- Equipment: `https://<equipment-host>`  (owns centralized payment settlement)
- Feed: `https://<feed-host>`  (routes payments to Equipment via HMAC server-to-server)

---

## Table of Contents
1. [Authentication Overview](#1-authentication-overview)
2. [HMAC-SHA256 Signing Scheme](#2-hmac-sha256-signing-scheme)
3. [Public Merchant API — Inventory CRUD](#3-public-merchant-api--inventory-crud)
4. [Public Merchant API — Checkout](#4-public-merchant-api--checkout)
5. [Hosted Checkout Page](#5-hosted-checkout-page)
6. [Cross-App SSO Handoff](#6-cross-app-sso-handoff)
7. [Unified Payment Ledger](#7-unified-payment-ledger)
8. [Session Authentication & RBAC](#8-session-authentication--rbac)
9. [Phone Normalization](#9-phone-normalization)
10. [Error Reference](#10-error-reference)

---

## 1. Authentication Overview

Farmsky exposes three distinct authentication surfaces:

| Surface | Used by | Credential | Signature headers |
|---|---|---|---|
| **Merchant API** | Third-party merchants | Merchant key + secret | `X-Merchant-Key`, `X-Merchant-Timestamp`, `X-Merchant-Nonce`, `X-Merchant-Signature` |
| **Internal gateway** | Feed → Equipment server-to-server | Client key + shared secret | `X-Farmsky-Client`, `X-Farmsky-Timestamp`, `X-Farmsky-Nonce`, `X-Farmsky-Signature` |
| **Session / RBAC** | Browser dashboard users | `session` cookie (12h) | — |

All signed surfaces use the **same HMAC-SHA256 canonical scheme** (Section 2). Cross-app SSO handoff (Section 6) uses a compact self-contained HMAC token.

---

## 2. HMAC-SHA256 Signing Scheme

Identical on both apps (`backend/payment-gateway-shared.ts`).

### Canonical string
```
canonical = client_key + "\n" + timestamp + "\n" + nonce + "\n" + rawBody
signature = hex( HMAC-SHA256( secret, canonical ) )
```

- **`client_key`** — the merchant key (Merchant API) or internal client id (gateway).
- **`timestamp`** — Unix time in **MILLISECONDS** (JavaScript `Date.now()`). Requests outside a **5-minute** window are rejected.
- **`nonce`** — a unique random string per request. Reuse within the replay window → `401 Replay detected`.
- **`rawBody`** — the exact raw request body bytes (empty string for GET/DELETE with no body). Sign the bytes you send verbatim — do not re-serialize.

### Reference signer (Node.js)
```js
const crypto = require('crypto');
function sign(secret, clientKey, body) {
  const timestamp = String(Date.now());               // milliseconds
  const nonce = crypto.randomBytes(16).toString('hex');
  const canonical = `${clientKey}\n${timestamp}\n${nonce}\n${body}`;
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  return { timestamp, nonce, signature };
}
```

### Reference signer (bash)
```bash
nowms() { echo $(( $(date +%s) * 1000 )); }
NONCE=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')   # uuidgen NOT available
TS=$(nowms)
BODY='{"...":"..."}'
CANON=$(printf '%s\n%s\n%s\n%s' "$KEY" "$TS" "$NONCE" "$BODY")
SIG=$(printf '%s' "$CANON" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
```

---

## 3. Public Merchant API — Inventory CRUD

Base path: `/api/v1/merchant/inventory`. Every request is HMAC-authenticated (Section 2, merchant headers). Each item is tagged with `app_scope` and is scoped to the hosting app's `inventory_type` (`equipment` on Equipment, `feed` on Feed). A merchant scoped to `equipment` cannot touch the `feed` catalog (`403`).

### 3.1 Create item — `POST /api/v1/merchant/inventory`
Request body:
```json
{
  "title": "Napier Grass Seed 5kg",
  "amount": 1200,
  "category": "seeds",
  "quantity": 40,
  "unit": "bag",
  "credit_markup_pct": 20,
  "image": "https://.../seed.png"
}
```
`201 Created`:
```json
{ "success": true, "item_id": 57, "sku": "MK-1737450000-8123", "inventory_type": "feed" }
```

### 3.2 Update item — `PUT /api/v1/merchant/inventory/{item_id}`
Body: any subset of `title`, `amount`, `category`, `quantity`, `credit_markup_pct`, `image`.
`200 OK`: `{ "success": true, "item_id": 57 }`
`404` if not found; `403` if merchant scope disallows the item.

### 3.3 List items — `GET /api/v1/merchant/inventory`
Returns items where `app_scope IN (<app>, 'both')`, newest first, max 500.
```json
{ "success": true, "inventory_type": "feed",
  "items": [ { "id": 57, "sku": "MK-...", "name": "...", "category": "seeds",
               "cash_price": 1200, "credit_price": 1440, "quantity": 40,
               "unit": "bag", "image": "...", "app_scope": "feed" } ] }
```

### 3.4 Delete item — `DELETE /api/v1/merchant/inventory/{item_id}`
`200 OK`: `{ "success": true, "item_id": 57 }`. `404` / `403` as above.

---

## 4. Public Merchant API — Checkout

Creates a `merchant_checkouts` session and returns a Farmsky **hosted checkout URL** to redirect the buyer to.

- `POST /api/v1/checkout/equipment` — equipment catalog (hosted only by the Equipment app)
- `POST /api/v1/checkout/feeds` — feed catalog (hosted only by the Feed app)

**Data isolation:** each app only hosts checkouts for its own `inventory_type`. Calling `/checkout/equipment` on the Feed app (or vice-versa) returns `409` telling you which app to use.

### Request
```json
{
  "customer": {
    "full_name": "Jane Wanjiku",
    "phone": "0712345678",
    "national_id": "31234567"
  },
  "item": {
    "id": "57",
    "title": "Napier Grass Seed 5kg",
    "amount": 1200,
    "category": "seeds"
  },
  "transaction_type": "DIRECT_PURCHASE",
  "financing_tenor_months": 0,
  "success_callback_url": "https://merchant.example/success",
  "failure_callback_url": "https://merchant.example/failure"
}
```

**Field rules** (validated server-side):
- `customer.full_name`, `customer.phone`, `customer.national_id` — all **required**.
- `item.id`, `item.title` — required strings; `item.amount` — required positive number; `item.category` optional (default `general`).
- `transaction_type` — must be `DIRECT_PURCHASE` or `FINANCING_REQUEST`.
- `financing_tenor_months` — required and `> 0` **only when** `transaction_type = FINANCING_REQUEST`.
- `success_callback_url` / `failure_callback_url` — optional.

### Response `201 Created`
```json
{
  "success": true,
  "checkout_ref": "chk_feed_1737450000000_812345",
  "inventory_type": "feed",
  "origin_platform": "feed_app",
  "transaction_type": "DIRECT_PURCHASE",
  "amount": 1200,
  "hosted_checkout_url": "https://<feed-host>/checkout/chk_feed_1737450000000_812345"
}
```

### Embeddable merchant button
The merchant embeds a button that opens `hosted_checkout_url`:
```html
<a class="farmsky-buy" href="https://<feed-host>/checkout/chk_feed_1737450000000_812345">
  Buy on Farmsky
</a>
```
On the Feed app the hosted checkout forwards the actual payment to Equipment's centralized gateway over an HMAC server-to-server call; Equipment settles M-Pesa/Daraja, SasaPay, Buni, and card directly.

### Read a checkout session (no HMAC) — `GET /api/v1/checkout/session/{ref}`
Used by the hosted page:
```json
{ "success": true, "checkout": { "checkout_ref": "...", "inventory_type": "feed",
  "transaction_type": "DIRECT_PURCHASE", "item_title": "...", "amount": 1200,
  "category": "seeds", "financing_tenor_months": 0,
  "customer_full_name": "Jane Wanjiku", "status": "CREATED" } }
```

---

## 5. Hosted Checkout Page

`GET /checkout/{ref}` — renders the Farmsky-hosted checkout HTML for a `merchant_checkouts` session. `404` if the ref is unknown. This is the human-facing page the merchant button redirects to.

---

## 6. Cross-App SSO Handoff

Lets a signed-in user cross between Equipment and Feed with **no second login** (shared SSO). Cross-nav buttons: "Shop Equipment" on Feed, "Shop Feeds" on Equipment.

### Token format (`backend/cross-app.ts`)
```
body  = base64url( JSON { phone, ts, nonce } )
token = body + "." + hmacSha256Hex(CROSS_APP_HMAC_SECRET, body)
```
Verified against the shared secret with a **2-minute** TTL.

### 6.1 Mint handoff URL — `GET /api/cross/handoff?target=<app>`
Auth: session cookie required. Returns a URL into the sibling app:
```json
{ "url": "https://<sibling-host>/sso?token=<token>", "target": "equipment" }
```
`503` if `CROSS_APP_HMAC_SECRET` / `CROSS_APP_URL` are not configured.

### 6.2 Land & sign in — `GET /sso?token=<token>`
The sibling app verifies the HMAC token, matches the user by phone (across `254…`, `+254…`, and raw formats), issues a **local session**, and redirects to `/`.
- `401` — invalid/expired link
- `404` — no matching account on this platform
- `403` — account not active on this platform

### 6.3 Frontend config — `GET /api/cross/config`
Auth: session cookie. Tells the frontend whether to show cross-nav buttons:
```json
{ "app_type": "feed", "cross_app_configured": true, "cross_app_url": "https://<equipment-host>" }
```

---

## 7. Unified Payment Ledger

`GET /api/ledger` — RBAC: `admin` / `super_admin` only. Equipment's admin dashboard reads this to see BOTH `equipment_app` and `feed_app` transactions in one ledger.

### Query parameters (all optional, combinable)
| Param | Values | Meaning |
|---|---|---|
| `inventory_type` | `equipment` \| `feed` | filter by catalog category |
| `origin_platform` | `equipment_app` \| `feed_app` | filter by originating app |
| `status` | e.g. `SUCCESS`, `PENDING`, `FAILED` | transaction status |
| `method` | e.g. `mpesa`, `card`, `sasapay` | payment method |
| `q` | free text | matches `transaction_ref`, `phone`, or `description` |

### Response
```json
{ "transactions": [
  { "transaction_ref": "...", "origin_app": "...", "origin_platform": "feed_app",
    "inventory_type": "feed", "payment_method": "mpesa", "phone": "2547...",
    "amount": 1200, "currency": "KES", "status": "SUCCESS",
    "description": "...", "created_at": "...", "completed_at": "..." } ] }
```
Max 500 rows, newest first. Reads run inside an admin RLS context (`withAdminContext`).

Related: `GET /api/v1/payments-admin/summary` (admin/super_admin) proxies the gateway's admin summary.

---

## 8. Session Authentication & RBAC

- **Login** issues a `session` cookie (token stored in `sessions` table, 12-hour expiry).
- **Passwords** are hashed with PBKDF2-SHA256 (`pbkdf2$<iter>$<saltB64>$<hashB64>`, 210k iterations default), env-driven (`AUTH_HASH_ITERATIONS`, `AUTH_HASH_KEYLEN`, `AUTH_PEPPER`), with upgrade-on-login for legacy plaintext. Identical scheme on both apps.
- **RBAC middleware:** `requireAuth`, `requireRole(...roles)`, `requirePermission(...perms)`.
  - Merchant/cross-app endpoints and payment logs are blocked for non-admins.
  - `payment-gateway.ts` guards `/admin/*`: `401` with no session, `403` for non-admin.

### Zero-trust enforcement (Phase 6)
- HMAC-SHA256 signature verification on **all** cross-app / merchant calls.
- Reject unauthenticated, missing-signature, and replayed requests (`401`).
- Strict RBAC on payment logs and cross-platform endpoints.

---

## 9. Phone Normalization

Identical `normalizePhone()` in both backends — apply it when supplying `customer.phone`:
- strip all non-numeric characters
- leading `0` → `254`
- leading `7` (length 9) → `254`
- leading `2540` → `254`

Examples: `0712345678` → `254712345678`; `712345678` → `254712345678`; `+254712345678` → `254712345678`.

---

## 10. Error Reference

| Code | Meaning | Common cause |
|---|---|---|
| `400` | Bad request | Missing/invalid checkout or inventory fields |
| `401` | Unauthorized | Missing key/signature, bad signature, expired timestamp, replayed nonce, invalid SSO token, no session |
| `403` | Forbidden | Merchant scope disallows catalog/item; non-admin on admin route; inactive account |
| `404` | Not found | Unknown item/checkout ref; no matching SSO account |
| `409` | Conflict | Wrong app for the checkout catalog (use the sibling app) |
| `503` | Unavailable | Cross-app SSO not configured |

Error body shape (merchant API): `{ "success": false, "error": "<message>" }`.

---

*Farmsky Ventures — Feed & Equipment unified platform. See `FARMSKY_TECHNICAL_DOCUMENTATION.md` for architecture, database schema, RLS, build/test runbook, and the six-phase project detail.*
