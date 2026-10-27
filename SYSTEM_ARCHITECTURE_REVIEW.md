# Farmsky Multi-App System Architecture & Security Review

> **Scope:** Equipment (`farm-sky-webapp`, central host), Feed (`feed`, livestock
> satellite), Nia (`input`, crop/horticulture satellite).
> **Review type:** Cross-app duplication / conflict / parallel-mechanism audit +
> security gap assessment with remediation recommendations.
> **Status:** Findings only — this document changes NO runtime behaviour. It is the
> authoritative backlog for the hardening/consolidation work that follows.

---

## 0. Executive Summary

The three apps began as a single codebase and were forked into a central host
(Equipment) plus two satellites (Feed, Nia). Over successive feature rounds the
forks **drifted**: the same capability is now implemented under different file
names, with different internal sizes, and occasionally with subtly different
behaviour. This review flags:

- **9 duplicate / parallel / redundant mechanisms** (architectural redundancy,
  state-desync risk, maintenance cost).
- **4 conflicting / confusing / opposite-function patterns** (ambiguous source of
  truth, dual code paths).
- **8 security gaps / risks / exposures** (ranging from High to Low severity).

Each finding carries a concrete recommendation. Section 5 proposes a phased
consolidation plan that reduces complexity while preserving zero-regression
guarantees.

Severity legend: 🔴 High · 🟠 Medium · 🟡 Low.

---

## 1. System Topology (as-built)

| App | Repo | Role | Payment posture | Lines (index.tsx / app.js) |
|-----|------|------|-----------------|----------------------------|
| **Equipment** | `farm-sky-webapp` | Central HOST + its own marketplace | Hosts the central gateway; also a tenant | 8356 / 8091 |
| **Feed** | `feed` | Livestock satellite (tenant) | Routes payments to Equipment gateway | 8297 / 8083 |
| **Nia** | `input` | Crop/horticulture satellite (tenant) | Routes payments to Equipment gateway | 6440 / 5712 |

All three share: Hono + TypeScript backend, dual build (`dist-node/server.js`
authoritative + `dist/_worker.js` for Cloudflare), PostgreSQL with FORCE RLS,
`feature_flags` lifecycle (sandbox → testing → live), and a vanilla-JS SPA
(`frontend/static/app.js`).

---

## 2. Duplicate / Parallel / Redundant Functionalities

### 2.1 🔴 Payment-gateway module: three divergent copies of the same host
The central gateway logic exists in **differently-named, differently-sized files**
in each repo, despite implementing the same functions
(`candidateSecrets`, `genRef`, `loadClient`, `loadMarketplace`, `setTenantScope`,
`verifyIpn`, `settleCallback`, `notifyOriginApp`, …):

| App | Host-gateway file | Size | "Shared helper" file | Client file |
|-----|-------------------|------|----------------------|-------------|
| Equipment | `payment-gateway.ts` | **72 KB** | `payments-shared.ts` | *(none)* |
| Feed | `payment-gateway-host.ts` | **68 KB** | `payment-gateway-shared.ts` | `payment-gateway-client.ts` |
| Nia | `payment-gateway.ts` | **47 KB** | `payments-shared.ts` | `payments-client.ts` |

**Risk:** High architectural redundancy. A fix to IPN verification or settlement
must be hand-ported to 3 files with 3 different names and 3 different internal
states → high risk of **state desynchronization** (e.g. a terminal-failure-code
rule fixed in Equipment but not Nia). The satellites arguably should **not carry
a full 47–68 KB host gateway at all** — they only need the ~4 KB client.

**Recommendation:** Extract ONE canonical `@farmsky/payment-gateway` package
(host) and ONE `@farmsky/payment-client` package (tenant). Satellites import the
client only; the host lives in Equipment. If a monorepo is not viable short-term,
adopt **identical file names** and a byte-for-byte shared copy enforced by a CI
`diff` gate.

### 2.2 🔴 `wallet-gateway.ts` re-implements gateway primitives
`wallet-gateway.ts` (Equipment & Feed, **~24 KB**, absent in Nia) redefines
`genRef`, `loadClient`, `candidateSecrets`, `auditSecurity`, and `authenticate`
— functions that already exist in `payment-gateway.ts`. Two independent copies of
the HMAC authentication path now exist in the same repo.

**Risk:** A signing/auth change applied to the payment gateway but not the wallet
gateway creates an **auth-logic split-brain**. Nia lacking the file entirely means
wallet features silently differ by app.

**Recommendation:** Factor the shared auth/signing primitives
(`authenticate`, `candidateSecrets`, `loadClient`, `genRef`, `auditSecurity`)
into a single internal module imported by both gateways; make Nia's wallet posture
explicit (either add the module or document that wallets are unsupported on Nia).

### 2.3 🟠 Dual checkout endpoint aliases (`/api/murabaha/*` vs `/api/checkout/*`)
Both the legacy `/api/murabaha/{quote,apply,apply-bundle}` and the newer
`/api/checkout/{quote,apply,quote-bundle,kyc-check}` routes are registered and
point at the same handlers — **except the aliasing is inconsistent**:

- Equipment & Feed register **both** `/api/checkout/apply` and `/api/murabaha/apply`.
- **Nia registers only `/api/murabaha/apply`** (no `/api/checkout/apply` alias).

**Risk:** Confusing/parallel routes; a client coded against `/api/checkout/apply`
works on Equipment/Feed but **404s on Nia**. Two public names for one behaviour
doubles the documentation and test surface.

**Recommendation:** Pick ONE canonical namespace (`/api/checkout/*`), make the
legacy `/api/murabaha/*` names thin 308 redirects (or register the identical alias
set in all three), and schedule the legacy names for deprecation.

### 2.4 🟠 `financingQuote()` has drifted across apps
The single most important money function differs by app:
Equipment **146 lines** (tenure model + interest + PAYGO), Feed **106 lines**
(Murabaha, charge-free), Nia **85 lines** (interest, no tenure model). Each was
edited independently during the cart/checkout overhaul.

**Risk:** The "one source of truth for price" is actually **three sources**. A
rounding or deposit rule corrected in one app can silently differ in another,
re-introducing the cart-vs-contract class of bug this project already fixed once.

**Recommendation:** Promote `financingQuote` + `computeProcessingFee` +
`requiredNum` into a shared `pricing` module with a shared unit-test vector set
run in all three CIs. Per-app policy (e.g. Feed = always Murabaha) becomes a
**config flag**, not a forked function body.

### 2.5 🟠 `buni.ts` (KCB Bank gateway) drift
`buni.ts` is **367 lines in Equipment & Feed** but only **91 lines in Nia** —
Nia carries a stripped/older KCB integration.

**Risk:** KCB payments behave differently (or fail differently) on Nia vs the
others; a KCB bugfix lands in 2 of 3 apps.

**Recommendation:** Converge to the 367-line canonical `buni.ts` (or the shared
package from 2.1) and delete the divergent copy.

### 2.6 🟠 Parallel configuration mechanisms (env-var vs DB `app_settings`)
Configuration is read from **two parallel stores**: 547 `c.env.*` reads
(deployment env vars) AND a DB `app_settings` table via `getSetting/setSetting`.
Several values (processing fee, feature availability, payment creds) can be
influenced by **both** layers, and the precedence is implicit.

**Risk:** Exactly the "parallel configuration mechanism → high redundancy + state
desync" pattern called out in the request. An operator changing a DB setting may
be silently overridden by an env var (or vice-versa) with no visible precedence.

**Recommendation:** Define a single **config-resolution contract** (e.g. "env var
is the hard floor; DB setting may narrow but never widen; precedence logged").
Centralize all reads behind one `resolveConfig(key)` helper and document the
precedence table.

### 2.7 🟡 Processing-fee computed/normalized in multiple spots
`DEFAULT_PROCESSING_FEE`, `normalizeProcessingFee`, and `computeProcessingFee`
plus inline `getSetting(c,'processing_fee',…)` calls appear at several call sites
per app (and in all 3 apps).

**Recommendation:** Single `getProcessingFeeConfig(c)` accessor that normalizes
once; all callers use it. (Subsumed by 2.4's shared pricing module.)

### 2.8 🟡 Inconsistent `backend/middleware/` presence
Equipment and Nia have `backend/middleware/auth.ts`; **Feed has no middleware
directory** (its auth middleware is inline in `index.tsx`).

**Recommendation:** Standardize the middleware location across all three.

### 2.9 🟡 RLS-context helpers: `withAdminContext` (pooled) vs `runAsAdmin` (pinned)
Two mechanisms set the admin DB context: the older pooled `withAdminContext`
(sets a GUC, then issues a separate pooled query — racy under load) and the newer
`runAsAdmin` (pins one connection — correct). Both are still in use (~107
context-related lines in Equipment alone).

**Risk:** The pooled variant can route the follow-up query to a connection that
never saw the GUC → intermittent RLS denials. Having two patterns invites using
the wrong one.

**Recommendation:** Migrate all privileged writes to `runAsAdmin`; keep
`withAdminContext` only for read paths where the race is benign, or replace it
entirely. Add a lint rule forbidding `pool.query` inside a `withAdminContext`
block.

---

## 3. Conflicting / Confusing / Opposite-Function Patterns

### 3.1 🟠 Cross-marketplace checkout is "always CASH" while in-app financing exists
Feed's cross-marketplace purchase path (`ref('XMP')`) forces **cash only**
("Financing is scoped to the owning platform"), yet the same product in its home
app may be financable. The **same product can be cash-only or financable depending
on which app you check out from** — an opposite/confusing behaviour for users.

**Recommendation:** Make the rule explicit in the UI ("cross-marketplace items are
cash-only") and document it as intentional, OR route cross-marketplace financing
to the owning app's quote engine so terms are consistent (preferred; aligns with
the cross-marketplace pricing-origin rule already adopted in checkout).

### 3.2 🟠 Two KYC gates with different trigger logic
KYC is enforced in `checkoutApplyHandler`, again in `apply-bundle`, and surfaced
via `/api/checkout/kyc-check`. The "financing requires verified KYC; cash bypasses
KYC" rule is re-implemented at each site.

**Risk:** A change to the KYC rule must be applied in ≥3 places per app × 3 apps =
9 edit points; divergence here is a compliance risk.

**Recommendation:** One `assertCheckoutAllowed(customer, items)` guard used by all
checkout entry points.

### 3.3 🟡 Dual identity flags: `APP_TYPE` vs `APP_MARKETPLACE` vs `app_scope` vs `source_platform`
Four overlapping notions of "which app / which marketplace" coexist
(`APP_TYPE`, `APP_MARKETPLACE`, product `app_scope`, product `source_platform`),
with implicit mapping (`APP_TYPE==='feed' ? 'feed' : 'equipment'`).

**Risk:** Confusing; easy to filter on the wrong dimension (a data-isolation bug
waiting to happen).

**Recommendation:** Document the four-way relationship in one table (done below in
§6) and collapse to the minimum necessary set; add a single `appIdentity(c)`
helper returning the normalized tuple.

### 3.4 🟡 `demo_otp` returned in API responses
Several endpoints return `demo_otp` in the JSON when SMS is simulated. This is a
developer convenience that is **confusing in production** (looks like a leak) and
is a genuine exposure if simulation mode is ever on in prod (see 4.2).

**Recommendation:** Gate `demo_otp` behind an explicit `DEMO_MODE` flag that is
hard-off in production builds.

---

## 4. Security Gaps, Risks & Exposures

### 4.1 🔴 CORS reflects any origin **with credentials**
```js
app.use('/api/*', cors({ origin: (origin) => origin || '*', credentials: true, … }))
```
Reflecting the caller's `Origin` **and** allowing credentials effectively lets any
website make authenticated cross-site requests with the victim's cookie session.
Present in **all three apps**.

**Risk:** CSRF / cross-site credential theft against the cookie-based session.
**Recommendation:** Replace with an explicit allow-list of the known app origins
(`equipment/feed/nia .farmsky.africa` + sandbox hosts). Never combine wildcard/
reflected origin with `credentials: true`.

### 4.2 🟠 OTP exposure in responses + plaintext OTP storage
`demo_otp` is returned to the client in simulation mode, and OTP codes are stored
**in plaintext** in `otp_codes.code`. Mitigations exist (5-attempt cap, 5-min
expiry, single-use), but a DB read exposes live codes.

**Recommendation:** Hash OTPs at rest (same PBKDF2 util already used for
passwords, or a fast HMAC with a server pepper); strip `demo_otp` unless
`DEMO_MODE` is explicitly enabled.

### 4.3 🟠 HMAC "fallback secret" precedence drift
The gateway accepts **multiple candidate secrets** (`candidateSecrets`) and only
`console.warn`s when a request matches a *fallback* instead of the registered
secret ("align SCORE_HMAC_SECRET / CROSS_APP_HMAC_SECRET across deployments").

**Risk:** A stale/rotated secret keeps working silently; secret rotation is not
actually enforced, weakening the integrity guarantee of inter-app calls.
**Recommendation:** Make fallback-secret acceptance **time-boxed and alarmed**
(metric + alert, not just a log line); fail closed once the rotation window ends.

### 4.4 🟠 Session lifetime & cookie posture
Sessions last **12 hours** (`maxAge: 60*60*12`) with `httpOnly`, `sameSite:'Lax'`,
`secure` only when HTTPS is detected at runtime. No idle timeout, no rotation on
privilege change.

**Recommendation:** Shorten idle timeout (e.g. sliding 30–60 min) with absolute
cap; force `Secure` in production regardless of runtime detection; rotate the
session token on login and on role elevation.

### 4.5 🟠 Dynamic SQL built by string concatenation
Several queries interpolate identifiers/clauses:
`SELECT COUNT(*) FROM "${t}"`, `SELECT * FROM ${ds}`, `UPDATE users SET ${sets.join(', ')}`,
`WHERE ${keyCol}=?`. Values are parameterized, but **table/column/dataset names
are concatenated**. If any `${…}` ever derives from user input, it is injectable.

**Recommendation:** Whitelist every interpolated identifier against a fixed set
(the dataset/table registry); never pass request-derived strings into an
identifier position. Add a grep-based CI check for `FROM ${` / `SET ${`.

### 4.6 🟡 Randomness: `Math.random()` for receipts/scores
`Math.random()` is used for simulated receipts and the demo credit score. These
are non-security (simulation) values, but `generateOtp` must **not** drift to
`Math.random()`. (Session tokens correctly use `crypto.randomUUID()`.)

**Recommendation:** Confirm all security-relevant randomness uses WebCrypto; add a
comment/lint fence so simulation helpers are never reused for secrets.

### 4.7 🟡 Verbose operational logging
~25 `console.*` statements per app, some printing secret-precedence hints and
client keys. Low risk but noisy and potentially informative to an attacker with
log access.

**Recommendation:** Route through a leveled logger; suppress debug/secret-hint
logs in production.

### 4.8 🟡 Satellite apps carry full host-gateway code (attack surface)
Because Feed/Nia ship a full 47–68 KB host gateway (finding 2.1), the
settlement/IPN endpoints may be **reachable on the satellites** even though they
should only act as tenants — unnecessary attack surface.

**Recommendation:** Ensure host-only routes are not mounted on satellites (or
remove the host code from satellites per 2.1). Verify with a route inventory per
deployment.

---

## 5. Consolidation Roadmap (reduce complexity, resolve conflicts)

| Phase | Action | Resolves | Risk |
|-------|--------|----------|------|
| **P1 (now)** | Fix CORS allow-list (4.1); gate `demo_otp` behind `DEMO_MODE` (4.2/3.4); hash OTP at rest (4.2) | Highest-severity security | Low, additive |
| **P2** | Extract shared `pricing` module (`financingQuote`,`computeProcessingFee`,`requiredNum`) + shared test vectors | 2.4, 2.7 | Medium — behavioural parity tests required |
| **P3** | Unify payment gateway: one host package (Equipment) + one client package (satellites); delete host code from Feed/Nia | 2.1, 2.2, 2.5, 4.8 | Medium/High — stage behind feature flag |
| **P4** | Canonicalize endpoints to `/api/checkout/*`; alias-redirect legacy; add missing Nia alias | 2.3 | Low |
| **P5** | Single `resolveConfig()` precedence contract; single `appIdentity()` | 2.6, 3.3 | Low |
| **P6** | One `assertCheckoutAllowed()` KYC guard; make cross-marketplace cash-only rule explicit | 3.1, 3.2 | Low |
| **P7** | Migrate privileged writes to `runAsAdmin`; retire pooled `withAdminContext` writes; standardize middleware dir | 2.9, 2.8 | Low |
| **P8** | Session hardening (idle timeout, rotation, forced Secure); SQL identifier whitelist; leveled logging | 4.4, 4.5, 4.7 | Low |

**Guiding principle:** every phase is **additive-first and flag-gated** — the same
zero-regression discipline already used for the offtake/checkout work. No phase
removes a capability until its replacement is proven at parity in all three apps.

---

## 6. Reference — App-identity dimensions (clarifies §3.3)

| Dimension | Where set | Meaning | Example values |
|-----------|-----------|---------|----------------|
| `APP_TYPE` | deploy env | Coarse app family used for scope filtering | `equipment`, `feed`, `input` |
| `APP_MARKETPLACE` | deploy env | Isolation floor for the products a satellite may read | `equipment`, `feed`, `mazao` |
| `app_scope` (product col) | DB row | Which app family may surface this product | `equipment`, `feed`, `both` |
| `source_platform` (product col) | DB row | Which app originally listed the product | `equipment`, `feed`, `mazao`, `merchant` |
| `marketplace` (product col) | DB row | Storefront section / taxonomy tab | `equipment`, `feeds`, `inputs` |

---

*Generated by the Farmsky cross-app architecture & security review. This file is
documentation only and is mirrored verbatim into all three repositories so every
team sees the same backlog.*
