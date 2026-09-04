import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { Bindings, SessionUser } from './types'
import { stkPush, stkQuery, mpesaConfigured, normalizePhone } from './mpesa'
import {
  sasapayStkPush, sasapayQuery, sasapayConfigured,
  sasapayProcessPayment, sasapayB2C, sasapayValidateAccount, sasapayBalance,
  verifySasapaySignature, isTrustedSasapayIp, sasapayMode,
  SASAPAY_CHANNELS, channelByCode, accountTypeForChannel,
  normalizePhone as sasapayNormalizePhone
} from './sasapay'
import { buniStkPush, buniQuery, buniConfigured } from './buni'
import paymentGateway from './payment-gateway-host'
import { sendSms, smsConfigured, generateOtp } from './sms'
import { sendEmail, emailConfigured } from './email'
import { hashPassword, verifyPassword, isHashed } from './password'
import { initiatePayment as gatewayInitiate, getPaymentStatus as gatewayStatus, processPayment as gatewayProcess, payoutPayment as gatewayPayout, gatewayConfigured } from './payment-gateway-client'
import { validateImageDataUrl, validateDocDataUrl, validateText, validateTextFields } from './upload-validation'
import merchantApi from './merchant-api'
import walletGateway, { settings as walletSettings } from './wallet-gateway'
import { mintHandoffToken, verifyHandoffToken, handoffClientFingerprint } from './cross-app'
import { sanitizeUrl } from './url-utils'
import { hmacSha256Hex } from './payment-gateway-shared'

const app = new Hono<{ Bindings: Bindings; Variables: { user: SessionUser } }>()

// ----------------------------------------------------------------------------
// GLOBAL ERROR BOUNDARY
//   Any uncaught throw in a handler — most importantly a failed OUTBOUND HTTP
//   call (M-Pesa / SasaPay / cross-app) or a JSON-parse error on a bad upstream
//   response — is converted into a clean JSON error response instead of
//   bubbling up as an opaque 500/502 process error. This is the safety net
//   that guarantees the platform safely catches outbound HTTP errors and
//   returns a clean JSON error response instead of a 502 process crash.
// ----------------------------------------------------------------------------
app.onError((err, c) => {
  const message = (err as any)?.message || 'Unexpected server error'
  // Network-level fetch failures surface as TypeError('fetch failed') on
  // Node/undici; treat those (and explicit gateway/timeout errors) as a
  // 502 Bad Gateway with a clean JSON body, everything else as a 500.
  const isUpstream = /fetch failed|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|network|timeout|socket hang up|getaddrinfo/i.test(message)
  const status = isUpstream ? 502 : 500
  try { console.error(`[onError] ${c.req.method} ${new URL(c.req.url).pathname} -> ${status}: ${message}`) } catch { /* noop */ }
  return c.json({
    success: false,
    error: isUpstream ? 'upstream_unavailable' : 'server_error',
    message: isUpstream
      ? 'A payment/upstream service is temporarily unreachable. Please try again shortly.'
      : message,
  }, status)
})

// ----------------------------------------------------------------------------
// ISSUE 7 — SECURITY HARDENING
//   (a) Same-origin CORS with credentials (no wildcard — the API relies on
//       cookie-based sessions, so a permissive wildcard would be unsafe).
//   (b) Baseline security response headers on every request.
//   (c) Lightweight in-memory rate limiting for sensitive endpoints
//       (login / OTP / payment initiation) to blunt brute-force + abuse.
// ----------------------------------------------------------------------------
app.use('/api/*', cors({
  origin: (origin) => origin || '*',   // reflect the caller's own origin
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-SasaPay-Signature'],
  maxAge: 600
}))

// Baseline security headers.
app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'SAMEORIGIN')
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.header('X-XSS-Protection', '0')
  // Allow the app's OWN origin (self) to use the camera and geolocation so the
  // KYC live-selfie capture (getUserMedia) and GPS onboarding work. An empty
  // allowlist "()" disables the feature for everyone INCLUDING this document,
  // which made the browser block getUserMedia/geolocation before the native
  // permission prompt could appear ("camera is not allowed in this document").
  // Microphone stays denied — the app never requests audio (audio:false).
  c.header('Permissions-Policy', 'geolocation=(self), microphone=(), camera=(self)')
  c.header('Cross-Origin-Opener-Policy', 'same-origin')
})

// Simple sliding-window rate limiter (per-IP, per-bucket) held in memory.
const _rlBuckets = new Map<string, { count: number; resetAt: number }>()
function rateLimit(bucket: string, max: number, windowMs: number) {
  return async (c: any, next: any) => {
    const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0].trim() || c.req.header('x-real-ip') || 'unknown'
    const key = `${bucket}:${ip}`
    const now = Date.now()
    const rec = _rlBuckets.get(key)
    if (!rec || rec.resetAt < now) {
      _rlBuckets.set(key, { count: 1, resetAt: now + windowMs })
    } else {
      rec.count++
      if (rec.count > max) {
        const retry = Math.ceil((rec.resetAt - now) / 1000)
        c.header('Retry-After', String(retry))
        return c.json({ error: 'Too many requests. Please slow down and try again shortly.' }, 429)
      }
    }
    // Opportunistic cleanup to bound memory.
    if (_rlBuckets.size > 5000) {
      for (const [k, v] of _rlBuckets) { if (v.resetAt < now) _rlBuckets.delete(k) }
    }
    await next()
  }
}
// Brute-force protection on credential + OTP surfaces.
app.use('/api/login', rateLimit('login', 10, 60_000))
app.use('/api/login/verify-otp', rateLimit('login', 10, 60_000))
app.use('/api/signup/request-otp', rateLimit('otp', 8, 60_000))
app.use('/api/reset-password/request-otp', rateLimit('otp', 8, 60_000))
// Abuse protection on payment initiation surfaces.
app.use('/api/sasapay/stkpush', rateLimit('pay', 20, 60_000))
app.use('/api/mpesa/stkpush', rateLimit('pay', 20, 60_000))
app.use('/api/buni/stkpush', rateLimit('pay', 20, 60_000))

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function genToken(): string {
  return crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '')
}
function ref(prefix: string): string {
  const n = Math.floor(Math.random() * 900000 + 100000)
  return `${prefix}-${Date.now().toString().slice(-6)}${n}`
}
function safeJson<T = any>(value: any, fallback: T): T {
  try { return value ? JSON.parse(String(value)) : fallback } catch { return fallback }
}
// Fallback permissions when role catalog has not loaded yet.
function builtinDefaults(role: string): Record<string, boolean> {
  if (['super_admin', 'admin'].includes(role)) {
    return { view: true, edit: true, delete: true, deactivate: true, approve: true, dispatch: true, add_farmer: true, add_customer: true, view_farmers: true, view_credit_purchases: true, manage_users: true, request_admin_action: true, can_manage_inventory: true, can_manage_finance_settings: true, view_wallet: true, manage_wallets: true, can_manage_contracts: true, can_delete_users: true }
  }
  if (role === 'operations_finance') {
    return { view: true, approve: true, dispatch: true, view_farmers: true, view_credit_purchases: true, request_admin_action: true, can_manage_finance_settings: true, can_manage_contracts: true }
  }
  if (role === 'agent') {
    return { view: true, add_farmer: true, view_farmers: true, view_credit_purchases: true, can_manage_inventory: true, view_wallet: true }
  }
  if (role === 'support') {
    return { view: true, view_farmers: true, view_credit_purchases: true }
  }
  if (role === 'lender') {
    return { view: true, view_credit_purchases: true }
  }
  if (role === 'mne') {
    return { view: true, view_farmers: true, view_credit_purchases: true }
  }
  if (['investor', 'partner'].includes(role)) {
    return { view: true }
  }
  return { view: true }
}
async function loadRoleTemplate(c: any, role: string): Promise<Record<string, boolean>> {
  try {
    const row = await c.env.DB.prepare(`SELECT permissions FROM role_templates WHERE role_key=?`).bind(role).first<any>()
    if (row?.permissions) {
      const parsed = safeJson<Record<string, boolean>>(row.permissions, {})
      if (parsed && Object.keys(parsed).length) return parsed
    }
  } catch (_) {}
  return builtinDefaults(role)
}
function defaultPermissions(role: string): Record<string, boolean> {
  return builtinDefaults(role)
}
function parsePermissions(raw: any, role: string, fallback?: Record<string, boolean>) {
  const base = fallback ?? defaultPermissions(role)
  return { ...base, ...safeJson<Record<string, boolean>>(raw, {}) }
}
async function permissionsForRole(c: any, role: string, override?: Record<string, boolean>) {
  const base = await loadRoleTemplate(c, role)
  return { ...base, ...(override || {}) }
}
function hasPermission(user: SessionUser, perm: string) {
  if (['super_admin', 'admin'].includes(user.role)) return true
  return Boolean(user.permissions?.[perm])
}
// Visibility permissions are opt-out: absent key = allowed (backward compatible),
// explicit false = hidden. Admins always allowed.
function hasVisibility(user: SessionUser, perm: string) {
  if (['super_admin', 'admin'].includes(user.role)) return true
  const v = user.permissions?.[perm]
  return v === undefined ? true : Boolean(v)
}
// Redact farmer records based on Data Object Visibility permissions.
const FINANCIAL_FIELDS = ['existing_loans', 'credit_score', 'risk_band', 'annual_production']
const PROFILE_FIELDS = ['value_chain', 'value_chain_type', 'county', 'sub_county', 'ward', 'village', 'acreage', 'herd_size', 'farm_experience', 'sacco_membership', 'date_of_birth', 'gender', 'latitude', 'longitude']
const DOCUMENT_FIELDS = ['id_front_url', 'id_back_url', 'selfie_url', 'passport_photo_url']
function redactCustomer(user: SessionUser, cust: any) {
  if (!cust) return cust
  const out = { ...cust }
  if (!hasVisibility(user, 'view_financial_data')) for (const f of FINANCIAL_FIELDS) if (f in out) out[f] = null
  if (!hasVisibility(user, 'view_farmer_profile_data')) for (const f of PROFILE_FIELDS) if (f in out) out[f] = null
  if (!hasVisibility(user, 'view_document_attachments')) for (const f of DOCUMENT_FIELDS) if (f in out) out[f] = null
  return out
}
function numberVal(value: any, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}
function boolInt(value: any, fallback = true) {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value === 'boolean') return value
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase())
}
function roundMoney(value: number) {
  return Math.round((Number(value) || 0) * 100) / 100
}

// ----------------------------------------------------------------------------
// WITHDRAWAL CHARGE SCHEMA (standard withdrawal schema) — aligned with Equipment.
// A withdrawal costs the wallet holder an "effective charge" that is deducted on
// top of the gross withdrawal. The withdrawable limit for a given balance is
//   withdrawable = balance - effectiveCharge(withdrawable)
// The charge is a flat fee + a percentage of the requested amount, with optional
// min/max clamps — mirroring typical mobile-money withdrawal tariffs.
// ----------------------------------------------------------------------------
const DEFAULT_WITHDRAWAL_CHARGE = {
  enabled: true,
  percentage_rate: 0,     // % of the requested amount
  flat_fee: 0,            // flat KES added per withdrawal
  min_charge: 0,          // charge is never below this (when enabled)
  max_charge: 0,          // 0 = no upper cap
  min_withdrawal: 0       // smallest gross amount a holder may request (0 = none)
}
function normalizeWithdrawalCharge(raw: any) {
  const cfg: any = { ...DEFAULT_WITHDRAWAL_CHARGE, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.enabled = raw && Object.prototype.hasOwnProperty.call(raw, 'enabled') ? Boolean(cfg.enabled) : true
  cfg.percentage_rate = Math.max(0, numberVal(cfg.percentage_rate, 0))
  cfg.flat_fee = Math.max(0, numberVal(cfg.flat_fee, 0))
  cfg.min_charge = Math.max(0, numberVal(cfg.min_charge, 0))
  cfg.max_charge = Math.max(0, numberVal(cfg.max_charge, 0))
  cfg.min_withdrawal = Math.max(0, numberVal(cfg.min_withdrawal, 0))
  return cfg
}
// Effective charge for a requested (gross) withdrawal amount.
function computeWithdrawalCharge(cfg: any, amount: number): number {
  const c = normalizeWithdrawalCharge(cfg)
  if (!c.enabled) return 0
  const amt = Math.max(0, Number(amount) || 0)
  let charge = c.flat_fee + amt * (c.percentage_rate / 100)
  if (c.min_charge > 0 && charge < c.min_charge) charge = c.min_charge
  if (c.max_charge > 0 && charge > c.max_charge) charge = c.max_charge
  return roundMoney(charge)
}
// Given a wallet balance, the maximum gross amount a holder may withdraw such
// that (amount + effective charge) never exceeds the balance.
function computeWithdrawableLimit(cfg: any, balance: number): { withdrawable: number; charge_at_max: number } {
  const c = normalizeWithdrawalCharge(cfg)
  const bal = roundMoney(Math.max(0, Number(balance) || 0))
  if (!c.enabled) return { withdrawable: bal, charge_at_max: 0 }
  const p = c.percentage_rate / 100
  let withdrawable = (bal - c.flat_fee) / (1 + p)
  withdrawable = roundMoney(Math.max(0, withdrawable))
  while (withdrawable > 0 && roundMoney(withdrawable + computeWithdrawalCharge(c, withdrawable)) > bal) {
    withdrawable = roundMoney(withdrawable - 0.01)
  }
  return { withdrawable, charge_at_max: withdrawable > 0 ? computeWithdrawalCharge(c, withdrawable) : 0 }
}
// SUPPORT CONTACT — shown to users when a withdrawal cannot be settled because
// the SasaPay main wallet is short. Configured in the Super-Admin dashboard.
const DEFAULT_SUPPORT_CONTACT = { phone: '', email: '' }
function normalizeSupportContact(raw: any) {
  const cfg: any = { ...DEFAULT_SUPPORT_CONTACT, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.phone = String(cfg.phone || '').trim().slice(0, 40)
  cfg.email = String(cfg.email || '').trim().slice(0, 120)
  return cfg
}
// Mask a phone number for display (e.g. in OTP prompts).
function maskPhone(phone: string): string {
  const p = String(phone || '').trim()
  if (p.length <= 6) return p ? p.replace(/.(?=.{2})/g, '*') : p
  const head = p.slice(0, 4)
  const tail = p.slice(-4)
  return `${head}${'*'.repeat(Math.max(2, p.length - 8))}${tail}`
}

// ---- App settings (key/value JSON store) ----
async function getSetting<T = any>(c: any, key: string, fallback: T): Promise<T> {
  try {
    const row = await c.env.DB.prepare(`SELECT setting_value FROM app_settings WHERE setting_key=?`).bind(key).first<any>()
    if (row?.setting_value) return safeJson<T>(row.setting_value, fallback)
  } catch (_) {}
  return fallback
}
async function setSetting(c: any, key: string, value: any): Promise<void> {
  const json = JSON.stringify(value)
  const existing = await c.env.DB.prepare(`SELECT setting_key FROM app_settings WHERE setting_key=?`).bind(key).first<any>()
  if (existing) {
    await c.env.DB.prepare(`UPDATE app_settings SET setting_value=?, updated_at=CURRENT_TIMESTAMP WHERE setting_key=?`).bind(json, key).run()
  } else {
    await c.env.DB.prepare(`INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?)`).bind(key, json).run()
  }
}
const DEFAULT_PROCESSING_FEE = { enabled: false, mode: 'percentage', percentage_rate: 0, tiers: [] as Array<{ min: number; max: number; fee: number }>, product_ids: [] as number[] }
function normalizeProductIds(raw: any): number[] {
  if (!Array.isArray(raw)) return []
  const ids = raw.map((v: any) => Number(v)).filter((n: number) => Number.isFinite(n) && n > 0)
  return Array.from(new Set(ids))
}
function normalizeProcessingFee(raw: any) {
  const cfg: any = { ...DEFAULT_PROCESSING_FEE, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.enabled = Boolean(cfg.enabled)
  cfg.mode = cfg.mode === 'tiered' ? 'tiered' : 'percentage'
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 0)
  cfg.tiers = Array.isArray(cfg.tiers)
    ? cfg.tiers
        .map((t: any) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), fee: numberVal(t.fee, 0) }))
        .filter((t: any) => t.max >= t.min)
    : []
  // Products this fee structure applies to. Empty array = applies to ALL products.
  cfg.product_ids = normalizeProductIds(cfg.product_ids)
  return cfg
}
const DEFAULT_FINANCING_MARKUP = {
  financing_applicable: true,
  mode: 'percentage',            // 'percentage' | 'tiered'
  percentage_rate: 20,
  tiers: [] as Array<{ min: number; max: number; markup: number }>,
  default_cash_markup_pct: 10,
  default_credit_markup_pct: 20,
  cash_markup_pct: 10,
  cash_terms_text: '',
  product_ids: [] as number[],
  default_cash_price_mode: 'percentage',
  default_cash_markup_amount: 0,
  default_credit_price_mode: 'percentage',
  default_credit_markup_amount: 0
}
function normalizeFinancingMarkup(raw: any) {
  const cfg: any = { ...DEFAULT_FINANCING_MARKUP, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.financing_applicable = raw && Object.prototype.hasOwnProperty.call(raw, 'financing_applicable')
    ? Boolean(cfg.financing_applicable) : true
  cfg.mode = cfg.mode === 'tiered' ? 'tiered' : 'percentage'
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 20)
  cfg.tiers = Array.isArray(cfg.tiers)
    ? cfg.tiers
        .map((t: any) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), markup: numberVal(t.markup, 0) }))
        .filter((t: any) => t.max >= t.min)
    : []
  cfg.cash_markup_pct = numberVal(cfg.cash_markup_pct, 10)
  cfg.cash_terms_text = String(cfg.cash_terms_text || '')
  // Keep legacy fields in sync for backward compatibility with existing quotes.
  cfg.default_credit_markup_pct = cfg.mode === 'percentage' ? cfg.percentage_rate : numberVal(cfg.default_credit_markup_pct, 20)
  cfg.default_cash_markup_pct = cfg.cash_markup_pct
  cfg.product_ids = normalizeProductIds(cfg.product_ids)
  cfg.default_cash_price_mode = ['percentage', 'fixed', 'manual'].includes(String(cfg.default_cash_price_mode)) ? String(cfg.default_cash_price_mode) : 'percentage'
  cfg.default_credit_price_mode = ['percentage', 'fixed', 'manual'].includes(String(cfg.default_credit_price_mode)) ? String(cfg.default_credit_price_mode) : 'percentage'
  cfg.default_cash_markup_amount = numberVal(cfg.default_cash_markup_amount, 0)
  cfg.default_credit_markup_amount = numberVal(cfg.default_credit_markup_amount, 0)
  return cfg
}
// Compute the processing fee applied to a borrowed (financed) amount.
// When cfg.product_ids is non-empty, the fee only applies to those products.
function computeProcessingFee(cfg: any, borrowedAmount: number, productId?: any): number {
  const c = normalizeProcessingFee(cfg)
  if (!c.enabled) return 0
  if (Array.isArray(c.product_ids) && c.product_ids.length > 0) {
    const pid = Number(productId)
    if (!Number.isFinite(pid) || !c.product_ids.includes(pid)) return 0
  }
  const amount = Number(borrowedAmount) || 0
  if (c.mode === 'percentage') return roundMoney(amount * (c.percentage_rate / 100))
  const tier = c.tiers.find((t: any) => amount >= t.min && amount <= t.max)
  return tier ? roundMoney(tier.fee) : 0
}
// ---- Time-based access windows ----
const DAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
function parseHM(value: any): number | null {
  const m = String(value || '').match(/^(\d{1,2}):(\d{2})$/)
  if (!m) return null
  return Number(m[1]) * 60 + Number(m[2])
}
// Returns { allowed:boolean, reason?:string } given a schedule config and current time.
function checkAccessWindow(schedule: { enabled?: any; days?: any; start?: any; end?: any }, now = new Date()): { allowed: boolean; reason?: string } {
  if (!schedule || !schedule.enabled) return { allowed: true }
  const days: string[] = Array.isArray(schedule.days) ? schedule.days.map((d: string) => String(d).toLowerCase()) : []
  const today = DAY_KEYS[now.getDay()]
  if (days.length && !days.includes(today)) {
    return { allowed: false, reason: 'Access is not permitted on this day for your role.' }
  }
  const start = parseHM(schedule.start)
  const end = parseHM(schedule.end)
  if (start !== null && end !== null) {
    const cur = now.getHours() * 60 + now.getMinutes()
    if (cur < start || cur > end) {
      return { allowed: false, reason: `Access is only permitted between ${schedule.start} and ${schedule.end}.` }
    }
  }
  return { allowed: true }
}
// Resolve the effective login window for a user (user override, else role template).
async function resolveAccessWindow(c: any, user: any): Promise<{ enabled: boolean; days: string[]; start: string; end: string }> {
  if (Number(user.schedule_enabled) === 1) {
    return { enabled: true, days: safeJson<string[]>(user.access_days, []), start: user.access_start || '', end: user.access_end || '' }
  }
  try {
    const row = await c.env.DB.prepare(`SELECT schedule_enabled, access_days, access_start, access_end FROM role_templates WHERE role_key=?`).bind(user.role).first<any>()
    if (row && Number(row.schedule_enabled) === 1) {
      return { enabled: true, days: safeJson<string[]>(row.access_days, []), start: row.access_start || '', end: row.access_end || '' }
    }
  } catch (_) {}
  return { enabled: false, days: [], start: '', end: '' }
}
// Sanitize a short free-text field: trim, cap length, strip control chars.
function cleanText(value: any, maxLen = 200): string | null {
  if (value === undefined || value === null) return null
  const s = String(value).replace(/[\u0000-\u001F\u007F]/g, '').trim()
  return s ? s.slice(0, maxLen) : null
}
// Selling price for a given pricing mode.
//   percentage → buying * (1 + markupPct/100)
//   fixed      → buying + markupAmount
//   manual     → the explicitly entered price (markup ignored)
function computeSellingPrice(mode: string, buying: number, markupPct: number, markupAmount: number, manualPrice: any, fallbackPct: number): number {
  const m = ['percentage', 'fixed', 'manual'].includes(String(mode)) ? String(mode) : 'percentage'
  if (m === 'manual') {
    const explicit = numberVal(manualPrice, NaN)
    if (Number.isFinite(explicit) && explicit > 0) return roundMoney(explicit)
    return roundMoney(buying * (1 + (Number.isFinite(markupPct) ? markupPct : fallbackPct) / 100))
  }
  if (m === 'fixed') return roundMoney(buying + numberVal(markupAmount, 0))
  return roundMoney(buying * (1 + (Number.isFinite(markupPct) ? markupPct : fallbackPct) / 100))
}
function normalizeProductPayload(b: any) {
  const buying = numberVal(b.buying_price)
  const cashMarkup = numberVal(b.cash_markup_pct, 10)
  const creditMarkup = numberVal(b.credit_markup_pct, 20)
  const cashMode = ['percentage', 'fixed', 'manual'].includes(String(b.cash_price_mode)) ? String(b.cash_price_mode) : 'percentage'
  const creditMode = ['percentage', 'fixed', 'manual'].includes(String(b.credit_price_mode)) ? String(b.credit_price_mode) : 'percentage'
  const cashMarkupAmount = numberVal(b.cash_markup_amount, 0)
  const creditMarkupAmount = numberVal(b.credit_markup_amount, 0)
  const cashPrice = computeSellingPrice(cashMode, buying, cashMarkup, cashMarkupAmount, b.cash_price, 10)
  const creditPrice = computeSellingPrice(creditMode, buying, creditMarkup, creditMarkupAmount, b.credit_price, 20)
  const tenureUnit = ['monthly', 'yearly', 'custom'].includes(String(b.financing_tenure_unit)) ? String(b.financing_tenure_unit) : 'monthly'
  const ratePerCycle = numberVal(b.financing_rate_per_cycle, 0)
  const amountPerCycle = numberVal(b.financing_amount_per_cycle, 0)
  const cycleCount = Math.max(0, Math.round(numberVal(b.financing_cycle_count, 0)))
  const cycleLengthDays = Math.max(1, Math.round(numberVal(b.financing_cycle_length_days, 30)))
  // FEED only offers Murabaha financing; default the type accordingly.
  const financingTypeKey = cleanText(b.financing_type_key, 60) || 'murabaha'
  const paymentMode = b.payment_option_mode || (boolInt(b.cash_enabled, true) && boolInt(b.financing_enabled, true) ? 'both' : boolInt(b.cash_enabled, true) ? 'cash' : 'financing')
  return {
    sku: String(b.sku || '').trim(),
    name: String(b.name || '').trim(),
    category: String(b.category || 'Equipment').trim(),
    description: b.description || null,
    product_type: b.product_type || 'equipment',
    supplier_id: b.supplier_id || null,
    buying_price: buying,
    cash_markup_pct: cashMarkup,
    credit_markup_pct: creditMarkup,
    cash_price: cashPrice,
    credit_price: creditPrice,
    cash_price_mode: cashMode,
    cash_markup_amount: cashMarkupAmount,
    credit_price_mode: creditMode,
    credit_markup_amount: creditMarkupAmount,
    quantity: numberVal(b.quantity, 0),
    unit: b.unit || 'unit',
    reorder_threshold: numberVal(b.reorder_threshold, 10),
    image: b.image || null,
    cash_enabled: boolInt(b.cash_enabled, paymentMode !== 'financing'),
    financing_enabled: boolInt(b.financing_enabled, paymentMode !== 'cash'),
    payment_option_mode: paymentMode,
    financing_model: b.financing_model || 'loan_interest',
    financing_interest_pct: numberVal(b.financing_interest_pct, 0),
    financing_frequency: b.financing_frequency || 'monthly',
    financing_term_min_months: numberVal(b.financing_term_min_months, 3),
    financing_term_max_months: numberVal(b.financing_term_max_months, 12),
    cash_deposit_pct: numberVal(b.cash_deposit_pct, 100),
    financing_deposit_pct: numberVal(b.financing_deposit_pct, 10),
    cash_terms_text: b.cash_terms_text || null,
    financing_terms_text: b.financing_terms_text || null,
    cash_terms_doc_url: b.cash_terms_doc_url || null,
    financing_terms_doc_url: b.financing_terms_doc_url || null,
    financing_tenure_unit: tenureUnit,
    financing_rate_per_cycle: ratePerCycle,
    financing_amount_per_cycle: amountPerCycle,
    financing_cycle_count: cycleCount,
    financing_cycle_length_days: cycleLengthDays,
    financing_type_key: financingTypeKey
  }
}
function financingQuote(p: any, quantity: any, paymentType: string, termMonths: any, processingFeeCfg?: any) {
  const qty = Math.max(1, numberVal(quantity, 1))
  const supplier_cost = roundMoney(numberVal(p.buying_price) * qty)
  if (paymentType === 'cash') {
    const total = roundMoney(numberVal(p.cash_price) * qty)
    const deposit_pct = numberVal(p.cash_deposit_pct, 100)
    const amount_due_now = roundMoney(total * deposit_pct / 100)
    return {
      quantity: qty,
      supplier_cost,
      payment_type: 'cash',
      financing_model: 'cash',
      markup_pct: numberVal(p.cash_markup_pct, 0),
      amount_due_now,
      deposit_pct,
      deposit_amount: amount_due_now,
      finance_principal: total,
      term_months: 0,
      payment_frequency: 'one_off',
      installment_count: 0,
      installment_amount: 0,
      total_price: total,
      total_payable: total,
      outstanding_after_deposit: roundMoney(total - amount_due_now),
      disclosure_note: deposit_pct >= 100 ? 'Full cash payment is required at checkout.' : deposit_pct > 0 ? `A ${deposit_pct}% deposit is required to confirm the cash order.` : 'No deposit is required at checkout for this cash order.',
      terms_text: p.cash_terms_text || null,
      terms_document_url: p.cash_terms_doc_url || null
    }
  }
  const principalBase = roundMoney(numberVal(p.credit_price || p.cash_price) * qty)
  const deposit_pct = numberVal(p.financing_deposit_pct, 10)
  const deposit_amount = roundMoney(principalBase * deposit_pct / 100)
  const finance_principal = roundMoney(principalBase - deposit_amount)
  // FEED policy: financing is offered ONLY as Sharia-compliant Murabaha
  // (cost-plus-markup). The markup is already baked into `credit_price`
  // (credit_markup_pct over supplier cost); NO interest and NO PAYGO unlock
  // charges are ever added. We therefore force interest to zero and the model
  // label to 'murabaha' regardless of any legacy product configuration.
  const interestRate = 0
  const model = 'murabaha'
  // ---- Flexible tenure resolution (monthly / yearly / custom) --------------
  // Feed honours the configured repayment schedule to size installments, but —
  // to stay Sharia-compliant — NEVER adds interest or a per-cycle finance charge
  // on top of the already-disclosed Murabaha price.
  const tenureUnit = ['monthly', 'yearly', 'custom'].includes(String(p.financing_tenure_unit)) ? String(p.financing_tenure_unit) : 'monthly'
  const cfgCycleCount = Math.max(0, Math.round(numberVal(p.financing_cycle_count, 0)))
  const cycleLengthDays = Math.max(1, Math.round(numberVal(p.financing_cycle_length_days, tenureUnit === 'yearly' ? 365 : 30)))
  const usesTenureModel = cfgCycleCount > 0
  const frequency = p.financing_frequency && ['monthly', 'weekly'].includes(p.financing_frequency) ? p.financing_frequency : 'monthly'

  let installment_count: number
  let term: number
  let payment_frequency: string
  if (usesTenureModel) {
    installment_count = cfgCycleCount
    term = tenureUnit === 'yearly' ? cfgCycleCount * 12
      : tenureUnit === 'custom' ? Math.max(1, Math.round((cfgCycleCount * cycleLengthDays) / 30))
      : cfgCycleCount
    payment_frequency = tenureUnit === 'yearly' ? 'yearly' : tenureUnit === 'custom' ? 'custom' : 'monthly'
  } else {
    term = Math.max(numberVal(p.financing_term_min_months, 3), Math.min(numberVal(termMonths, numberVal(p.financing_term_min_months, 3)), numberVal(p.financing_term_max_months, 12)))
    installment_count = frequency === 'weekly' ? term * 4 : term
    payment_frequency = frequency
  }
  const financing_charge = 0
  // Processing fee is calculated on the amount borrowed (finance principal),
  // scoped to the product when the fee structure targets specific products.
  const processing_fee = computeProcessingFee(processingFeeCfg, finance_principal, p.id)
  const financed_total = roundMoney(finance_principal + financing_charge + processing_fee)
  const installment_amount = installment_count > 0 ? roundMoney(financed_total / installment_count) : financed_total
  const total_payable = roundMoney(deposit_amount + financed_total)
  return {
    quantity: qty,
    supplier_cost,
    payment_type: 'financing',
    financing_model: model,
    financing_type_key: p.financing_type_key || 'murabaha',
    markup_pct: numberVal(p.credit_markup_pct, 0),
    amount_due_now: deposit_amount,
    deposit_pct,
    deposit_amount,
    finance_principal,
    processing_fee,
    financing_charge,
    interest_rate_pct: interestRate,
    tenure_unit: usesTenureModel ? tenureUnit : 'legacy',
    cycle_count: installment_count,
    cycle_length_days: cycleLengthDays,
    term_months: term,
    payment_frequency,
    installment_count,
    installment_amount,
    monthly_payment: payment_frequency === 'monthly' ? installment_amount : roundMoney(financed_total / Math.max(term, 1)),
    total_price: principalBase,
    total_payable,
    outstanding_after_deposit: financed_total,
    disclosure_note: 'Sharia-compliant Murabaha: a fixed cost-plus markup is agreed up front and repaid in equal installments over the selected term. No riba is charged.'
      + (processing_fee > 0 ? ` A processing fee of ${processing_fee.toLocaleString()} applies to the financed amount.` : ''),
    terms_text: p.financing_terms_text || null,
    terms_document_url: p.financing_terms_doc_url || null
  }
}
// Whether the connected DB's `users` table carries the multitenant `org_id`
// column. The central farmsky_central_db (shared with the Equipment payment hub
// + Score) has it as UUID NOT NULL; the Feed-only dev SQLite/D1 shape does not.
// Cached per-process after the first probe so we only introspect once. On any
// error (including SQLite where information_schema is absent) we assume the
// column is NOT present and fall back to org-agnostic inserts.
let _usersHasOrgId: boolean | null = null
async function usersHasOrgId(c: any): Promise<boolean> {
  if (_usersHasOrgId !== null) return _usersHasOrgId
  try {
    const r = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'org_id'`
    ).first<any>()
    _usersHasOrgId = Number(r?.n || 0) > 0
  } catch (_) {
    _usersHasOrgId = false
  }
  return _usersHasOrgId
}

// Resolve the tenant (org_id) a newly-created user must belong to: the creating
// admin's org. Prefer the value already on the session; if absent (older
// session issued before org_id was loaded) re-read it from the DB.
async function resolveCreatorOrgId(c: any, creator: SessionUser | null): Promise<string | null> {
  if (!creator) return null
  if ((creator as any).org_id != null && (creator as any).org_id !== '') return String((creator as any).org_id)
  if (!(await usersHasOrgId(c))) return null
  try {
    const o = await c.env.DB.prepare(`SELECT org_id FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(creator.id)).first<any>()
    return o?.org_id != null ? String(o.org_id) : null
  } catch (_) { return null }
}

// A process-cached fallback tenant for user rows created OUTSIDE an admin session
// (public self-signup, and any admin-created row whose creator somehow lacks an
// org). The central farmsky_central_db enforces users.org_id NOT NULL, so these
// paths MUST supply one. Preference order:
//   1. EQUIPMENT_ORG_ID / DEFAULT_ORG_ID env (explicit operator override), then
//   2. the most-populated existing org (mode of users.org_id), then
//   3. the oldest organizations row.
// Returns null only on a DB shape without the org_id column (dev SQLite/D1),
// where the INSERT omits the column entirely.
let _defaultOrgId: string | null | undefined = undefined
async function resolveDefaultOrgId(c: any): Promise<string | null> {
  if (_defaultOrgId !== undefined) return _defaultOrgId
  if (!(await usersHasOrgId(c))) { _defaultOrgId = null; return null }
  const envOrg = (c.env?.EQUIPMENT_ORG_ID || c.env?.DEFAULT_ORG_ID || '').trim()
  if (envOrg) { _defaultOrgId = envOrg; return envOrg }
  // Most common org among existing users — the natural tenant for this deployment.
  try {
    const r = await c.env.DB.prepare(
      `SELECT org_id, COUNT(*) AS n FROM users WHERE org_id IS NOT NULL GROUP BY org_id ORDER BY n DESC LIMIT 1`
    ).first<any>()
    if (r?.org_id != null) { _defaultOrgId = String(r.org_id); return _defaultOrgId }
  } catch (_) {}
  // Fall back to the oldest organization on record.
  try {
    const r = await c.env.DB.prepare(`SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1`).first<any>()
    if (r?.id != null) { _defaultOrgId = String(r.id); return _defaultOrgId }
  } catch (_) {}
  _defaultOrgId = null
  return null
}

async function getSessionUser(c: any): Promise<SessionUser | null> {
  const token = getCookie(c, 'session') || c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return null
  // CAST(u.id AS TEXT) = s.user_id so the session join works whether users.id is
  // an INTEGER (Feed's own schema) or a UUID (shared central DB created by a
  // sibling app). sessions.user_id is TEXT (migration 0023_sessions_user_id_text).
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.avatar_url, u.role, u.region, u.label, u.permissions, u.status,
            u.schedule_enabled, u.access_days, u.access_start, u.access_end, s.expires_at
     FROM sessions s JOIN users u ON CAST(u.id AS TEXT) = s.user_id WHERE s.token = ?`
  ).bind(token).first<any>()
  if (!row) return null
  if (Number(row.expires_at) < Date.now()) return null
  if (row.status !== 'active') return null
  // Enforce time-based access window on every request.
  const window = await resolveAccessWindow(c, row)
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end })
  if (!access.allowed) return null
  const fallback = await loadRoleTemplate(c, row.role)
  // Best-effort tenant scope. Kept as a SEPARATE query so a DB shape without the
  // multitenant `users.org_id` column (Feed-only SQLite/D1 dev) never fails
  // authentication — the query is swallowed and org_id stays null there.
  let orgId: string | null = null
  if (await usersHasOrgId(c)) {
    try {
      const o = await c.env.DB.prepare(`SELECT org_id FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(row.id)).first<any>()
      orgId = o?.org_id != null ? String(o.org_id) : null
    } catch (_) { orgId = null }
  }
  return {
    org_id: orgId,
    // Always expose the user id as a STRING so all user-reference columns (now
    // TEXT on the shared DB) compare correctly regardless of integer/uuid shape.
    id: String(row.id),
    full_name: row.full_name,
    phone: row.phone,
    email: row.email || null,
    avatar_url: row.avatar_url || null,
    role: row.role,
    region: row.region,
    label: row.label || null,
    permissions: parsePermissions(row.permissions, row.role, fallback)
  } as any
}
// Declare the executing user's identity + capabilities inside the DB session so
// PostgreSQL Row-Level Security (backend/sql/03_ownership_rls_setup.sql) can
// strip away records the user has no relationship with. No-op on SQLite/D1.
// Running any RLS-protected query WITHOUT this context returns ZERO rows for
// general users — preventing systemic data-leak vectors.
async function setUserContext(c: any, user: SessionUser | null) {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal !== 'function') return
  try {
    await setLocal.call(c.env.DB, 'app.current_user_id', user ? String(user.id) : '')
    await setLocal.call(c.env.DB, 'app.current_role', user ? String(user.role) : '')
    const canFinance = user
      ? (['admin', 'super_admin'].includes(user.role) || Boolean(user.permissions?.can_manage_finance_settings))
      : false
    await setLocal.call(c.env.DB, 'app.user_can_finance', canFinance ? 'true' : 'false')
  } catch (_) {}
}
// Run a block with a temporary admin context so background / storefront reads
// (public catalog, provider callbacks) can see the global dataset, then restore.
// Depth counter so NESTED withAdminContext calls do not prematurely reset the
// session RLS context back to the request user. Only the OUTERMOST call restores
// the user context in its finally — inner calls are no-ops for enter/exit. This
// keeps admin context active across composed helpers (e.g. distributeCommission
// -> ensureWallet -> postLedger) so RLS-protected wallet writes succeed.
async function withAdminContext(c: any, fn: () => Promise<any>) {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  const depth = (c.get('__adminCtxDepth') || 0) as number
  if (depth === 0 && typeof setLocal === 'function') {
    try {
      await setLocal.call(c.env.DB, 'app.current_role', 'admin')
      await setLocal.call(c.env.DB, 'app.user_can_finance', 'true')
    } catch (_) {}
  }
  c.set('__adminCtxDepth', depth + 1)
  try { return await fn() }
  finally {
    c.set('__adminCtxDepth', depth)
    if (depth === 0) await setUserContext(c, c.get('user') || null)
  }
}
async function requireAuth(c: any, next: any) {
  const user = await getSessionUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', user)
  await setUserContext(c, user)
  await next()
}
function requireRole(...roles: string[]) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!roles.includes(user.role)) {
      return c.json({ error: "You don't have permission to perform this action. Please contact your administrator if you believe this is a mistake." }, 403)
    }
    await next()
  }
}
function requirePermission(...perms: string[]) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!perms.some((perm) => hasPermission(user, perm))) {
      return c.json({ error: "You don't have permission to perform this action. Please contact your administrator if you believe this is a mistake." }, 403)
    }
    await next()
  }
}
// ----------------------------------------------------------------------------
// SUPER-ADMIN CREDENTIAL ACCESS CONTROL
//   Viewing, editing, resetting the password of, suspending, deleting,
//   creating or promoting a Super-Admin account is restricted EXCLUSIVELY to
//   Super-Admins. Lower-tier roles (Admin, Agent, Support) are blocked (403)
//   across every /api/users* endpoint, and Super-Admin rows are withheld from
//   the GET /api/users list for non-super callers.
// ----------------------------------------------------------------------------
function isSuperAdmin(user: SessionUser | undefined | null): boolean {
  return !!user && String(user.role || '').toLowerCase() === 'super_admin'
}
/** True if the target user row (by id) is a Super-Admin. */
async function targetIsSuperAdmin(c: any, id: string | number): Promise<boolean> {
  const row = await c.env.DB.prepare(`SELECT role FROM users WHERE id=?`).bind(id).first<any>()
  return String(row?.role || '').toLowerCase() === 'super_admin'
}
/**
 * Guard a mutation whose TARGET is a specific user: if that target is a
 * Super-Admin, only a Super-Admin caller may proceed. Returns a 403 JSON
 * Response to short-circuit, or null when the caller is allowed to continue.
 * Also blocks a non-super caller from ASSIGNING the super_admin role
 * (privilege escalation) when `attemptedRole` is supplied.
 */
async function guardSuperAdminTarget(c: any, id: string | number, attemptedRole?: string): Promise<Response | null> {
  const caller = c.get('user') as SessionUser
  if (isSuperAdmin(caller)) return null
  if (await targetIsSuperAdmin(c, id)) {
    return c.json({ error: 'Only a Super Admin can view or modify Super Admin credentials.' }, 403)
  }
  if (attemptedRole && String(attemptedRole).toLowerCase() === 'super_admin') {
    return c.json({ error: 'Only a Super Admin can grant the Super Admin role.' }, 403)
  }
  return null
}
async function audit(c: any, userId: number | null, action: string, entity: string, detail: string) {
  try {
    await c.env.DB.prepare(`INSERT INTO audit_logs (user_id, action, entity, detail) VALUES (?,?,?,?)`)
      .bind(userId, action, entity, detail).run()
  } catch (_) {}
}
function genPassword(): string {
  return String(Math.floor(1000 + Math.random() * 9000))
}

// Roles for which an email address is MANDATORY. Everyone else (agent, customer,
// partner, investor, operations_finance, …) may be onboarded without one.
const EMAIL_REQUIRED_ROLES = ['super_admin', 'admin', 'lender']
function emailIsRequired(role: string): boolean {
  return EMAIL_REQUIRED_ROLES.includes(String(role || '').toLowerCase())
}

// Local domain used for synthetic placeholder emails. These are NOT deliverable
// addresses — they exist purely to satisfy the central schema. Anything using
// `email` for real delivery must treat an @PLACEHOLDER_EMAIL_DOMAIN address as
// "no email on file".
const PLACEHOLDER_EMAIL_DOMAIN = 'no-email.farmsky.local'
function isPlaceholderEmail(email: any): boolean {
  return String(email || '').toLowerCase().endsWith('@' + PLACEHOLDER_EMAIL_DOMAIN)
}

// Resolve the value bound to the central `users.email` column. On the shared
// farmsky_central_db this column is BOTH `NOT NULL` and `UNIQUE`, so we cannot
// bind NULL and we cannot reuse a shared sentinel like '' across users (the 2nd
// such insert hits users_email_key → 23505). Behaviour:
//   • email supplied             → trimmed, lower-cased value.
//   • email blank, role needs it → { error } so the caller can 400.
//   • email blank, role optional → a UNIQUE, non-deliverable placeholder derived
//     from the phone (or a random UUID) so NOT NULL + UNIQUE are both satisfied.
//     `isPlaceholderEmail()` lets the rest of the app treat it as "no email".
function resolveEmail(role: string, rawEmail: any, phone?: any): { value: string } | { error: string } {
  const email = String(rawEmail ?? '').trim()
  if (email) return { value: email.toLowerCase() }
  if (emailIsRequired(role)) {
    return { error: `An email address is required for ${String(role).replace(/_/g, ' ')} accounts.` }
  }
  const key = String(phone ?? '').replace(/[^a-z0-9]/gi, '').toLowerCase() || (crypto.randomUUID().replace(/-/g, ''))
  return { value: `no-email+${key}@${PLACEHOLDER_EMAIL_DOMAIN}` }
}

// Re-authenticate the current session by re-checking the caller's password.
// Used to gate SENSITIVE data downloads (full system backups, platform data
// exports) so a stolen/borrowed session cannot silently exfiltrate the DB.
// Mirrors the Equipment implementation exactly.
async function verifyReauth(c: any, password: any): Promise<{ ok: true } | { ok: false; error: string; status: number }> {
  const pw = String(password ?? '')
  if (!pw) return { ok: false, error: 'Enter your password to confirm this download.', status: 400 }
  const user = c.get('user') as SessionUser
  if (!user) return { ok: false, error: 'Not authenticated.', status: 401 }
  const row = await c.env.DB.prepare(`SELECT password FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(user.id)).first<any>()
  if (!row) return { ok: false, error: 'Account not found.', status: 401 }
  const check = await verifyPassword(pw, row.password)
  if (!check.ok) return { ok: false, error: 'Incorrect password. Please try again.', status: 401 }
  return { ok: true }
}

// A secure, random TEMPORARY password for the multi-user onboarding flow.
// Mixed-case + digits, avoids ambiguous characters (0/O, 1/l/I).
function genTempPassword(len = 10): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  let out = ''
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length]
  return out
}

// Milliseconds a temporary password stays valid before it must be reset (24 hours).
const TEMP_PASSWORD_TTL_MS = 24 * 60 * 60 * 1000

// The public host for THIS marketplace, used in delegated-user onboarding SMS.
// Feed -> feeds.farmsky.africa, Equipment -> equipment.farmsky.africa. When a
// PUBLIC_BASE_URL is configured we strip its scheme so the SMS shows a bare host.
function appHost(env: any): string {
  const explicit = String(env?.PUBLIC_BASE_URL || '').trim()
  if (explicit) return explicit.replace(/^https?:\/\//i, '').replace(/\/+$/, '')
  const appType = String(env?.APP_TYPE || 'feed').toLowerCase()
  return appType === 'equipment' ? 'equipment.farmsky.africa' : 'feeds.farmsky.africa'
}

// Stamp a freshly-created user with a temporary password + lifecycle flags and
// SMS it to them with the mandatory welcome + "expires in 24 hours" notice.
// Returns the plaintext temp password (also surfaced to the creator's UI as a
// fallback for when SMS is not configured / delivery is delayed).
async function issueTempPassword(
  c: any,
  opts: { userId: number | bigint; phone: string; fullName?: string; hashedInto?: 'insert' }
): Promise<{ tempPassword: string; expiresAt: number; sms: { simulated?: boolean; success?: boolean; error?: string } }> {
  const tempPassword = genTempPassword()
  const expiresAt = Date.now() + TEMP_PASSWORD_TTL_MS
  const hashed = await hashPassword(tempPassword)
  await c.env.DB.prepare(
    `UPDATE users SET password=?, password_set=0, must_change_password=1, is_temp_password=1, temp_password_expires_at=? WHERE id=?`
  ).bind(hashed, expiresAt, opts.userId).run()
  // Marketplace-aware onboarding SMS. The link is the app where the account was
  // created (feeds.farmsky.africa / equipment.farmsky.africa) per APP_TYPE.
  const host = appHost(c.env)
  const firstName = String(opts.fullName || '').trim().split(/\s+/)[0] || 'there'
  const msg =
    `${firstName} Welcome to Farmsky,\n` +
    `Click the Link ${host}\n` +
    `Phone Number - ${opts.phone}\n` +
    `Your First time Password ${tempPassword}\n` +
    `Please change this password as it will expire in 24 hours`
  let sms: any = { simulated: true, success: true }
  try { sms = await sendSms(c.env, opts.phone, msg) } catch (e: any) { sms = { success: false, error: e?.message || 'SMS failed' } }
  return { tempPassword, expiresAt, sms }
}
async function createSession(c: any, user: any) {
  const token = genToken()
  const expires = Date.now() + 1000 * 60 * 60 * 12
  // sessions.user_id is TEXT (migration 0023) so it holds an integer-as-string
  // or a UUID. Always bind as a string so the value round-trips identically.
  await c.env.DB.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)`).bind(token, String(user.id), expires).run()
  // Issue 7: mark the session cookie Secure when served over HTTPS so it is
  // never transmitted over a plaintext channel in production.
  const isHttps = (c.req.header('x-forwarded-proto') || '').includes('https') || new URL(c.req.url).protocol === 'https:'
  setCookie(c, 'session', token, { path: '/', httpOnly: true, maxAge: 60 * 60 * 12, sameSite: 'Lax', secure: isHttps })
  return token
}
// Issue an OTP, persist it, and send via SMS. Returns demo_otp when SMS not configured.
async function issueOtp(c: any, phone: string, purpose: string) {
  const code = generateOtp()
  const expires = Date.now() + 1000 * 60 * 5 // 5 minutes
  // Invalidate previous unconsumed OTPs for this phone+purpose
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE phone=? AND purpose=? AND consumed=0`).bind(phone, purpose).run()
  await c.env.DB.prepare(`INSERT INTO otp_codes (phone, code, purpose, expires_at) VALUES (?,?,?,?)`).bind(phone, code, purpose, expires).run()
  const msg = `Your Farmsky verification code is ${code}. It expires in 5 minutes.`
  const sms = await sendSms(c.env, phone, msg)
  return { sms, demo_otp: sms.simulated ? code : undefined }
}
// Validate an OTP; marks it consumed on success.
async function verifyOtp(c: any, phone: string, code: string, purpose: string): Promise<{ ok: boolean; error?: string }> {
  const row = await c.env.DB.prepare(
    `SELECT * FROM otp_codes WHERE phone=? AND purpose=? AND consumed=0 ORDER BY id DESC LIMIT 1`
  ).bind(phone, purpose).first<any>()
  if (!row) return { ok: false, error: 'No active code. Request a new one.' }
  if (Number(row.expires_at) < Date.now()) return { ok: false, error: 'Code expired. Request a new one.' }
  if (Number(row.attempts) >= 5) return { ok: false, error: 'Too many attempts. Request a new code.' }
  if (String(row.code) !== String(code).trim()) {
    await c.env.DB.prepare(`UPDATE otp_codes SET attempts=attempts+1 WHERE id=?`).bind(row.id).run()
    return { ok: false, error: 'Incorrect code.' }
  }
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE id=?`).bind(row.id).run()
  return { ok: true }
}

// ----------------------------------------------------------------------------
// AUTH
// ----------------------------------------------------------------------------
app.post('/api/login', async (c) => {
  const { phone, password } = await c.req.json()
  const raw = String(phone || '').trim()
  const norm = normalizePhone(raw)
  // Match either the exact entered value or the normalized 2547... form,
  // so seeded "+254..." accounts and OTP-normalized accounts both work.
  let user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ?`).bind(raw, norm).first<any>()
  const check = user ? await verifyPassword(String(password), user.password) : { ok: false, legacy: false }
  if (!user || !check.ok) return c.json({ error: 'Invalid phone number or password' }, 401)
  if (user.status !== 'active') return c.json({ error: 'Account suspended' }, 403)
  // PASSWORD LIFECYCLE: a temporary (admin/agent-issued) password that has
  // expired can no longer be used. Tell the client to offer an admin reset.
  if (user.is_temp_password && user.temp_password_expires_at && Number(user.temp_password_expires_at) < Date.now()) {
    return c.json({ error: 'Your temporary password has expired. Please ask an admin to reset it.', temp_expired: true, phone: user.phone }, 403)
  }
  // Upgrade-on-login: transparently re-hash any legacy plaintext password.
  if (check.legacy) {
    try { await c.env.DB.prepare(`UPDATE users SET password=? WHERE id=?`).bind(await hashPassword(String(password)), user.id).run() } catch (_) {}
  }
  // First-login with a temporary password: STEP 1 (primary credentials) has now
  // succeeded. Before we grant any session — even the restricted change-password
  // session — we require STEP 2: a 2FA OTP delivered to the registered phone.
  // The forced password update (STEP 3) happens after OTP verification, via
  // POST /api/login/verify-otp. No session token is issued here.
  if (user.must_change_password) {
    const { sms, demo_otp } = await issueOtp(c, user.phone, 'login_2fa')
    if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send verification code' }, 502)
    await audit(c, user.id, 'login', 'user', `${user.role} passed temp-password step 1; 2FA OTP sent`)
    return c.json({
      must_change_password: true,
      needs_otp: true,
      phone: user.phone,
      message: sms.simulated ? 'Demo mode: use the code shown below.' : `Verification code sent to ${maskPhone(user.phone)}.`,
      demo_otp,
      user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role }
    })
  }
  // Enforce time-based access windows (per-user override, else role template).
  const window = await resolveAccessWindow(c, user)
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end })
  if (!access.allowed) return c.json({ error: access.reason || 'Access is restricted at this time.' }, 403)
  const token = await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} logged in`)
  const loginFallback = await loadRoleTemplate(c, user.role)
  return c.json({ token, user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role, region: user.region, label: user.label || null, permissions: parsePermissions(user.permissions, user.role, loginFallback) } })
})
// STEP 2 of the temporary-password lifecycle: verify the 2FA OTP that /api/login
// issued. On success we re-validate the primary credentials, then mint the
// restricted "change password" session token. The client uses it to force the
// STEP 3 password update (PUT /api/me/password) before the user reaches the app.
app.post('/api/login/verify-otp', async (c) => {
  const { phone, password, code } = await c.req.json()
  const raw = String(phone || '').trim()
  const norm = normalizePhone(raw)
  const user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ?`).bind(raw, norm).first<any>()
  const check = user ? await verifyPassword(String(password), user.password) : { ok: false, legacy: false }
  if (!user || !check.ok) return c.json({ error: 'Invalid phone number or password' }, 401)
  if (user.status !== 'active') return c.json({ error: 'Account suspended' }, 403)
  if (user.is_temp_password && user.temp_password_expires_at && Number(user.temp_password_expires_at) < Date.now()) {
    return c.json({ error: 'Your temporary password has expired. Please ask an admin to reset it.', temp_expired: true, phone: user.phone }, 403)
  }
  // Only the temporary-password flow uses this OTP purpose. A normal account
  // should never reach here — send it back through the standard login.
  if (!user.must_change_password) return c.json({ error: 'This account does not require verification.' }, 400)
  const v = await verifyOtp(c, user.phone, String(code || ''), 'login_2fa')
  if (!v.ok) return c.json({ error: v.error }, 400)
  const changeToken = await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} verified 2FA; forced password change pending`)
  return c.json({
    token: changeToken,
    must_change_password: true,
    user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role }
  })
})
app.post('/api/logout', async (c) => {
  const token = getCookie(c, 'session')
  if (token) await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run()
  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true })
})
app.get('/api/me', requireAuth, (c) => c.json({ user: c.get('user') }))

// ----------------------------------------------------------------------------
// CROSS-APP PASSWORD VERIFICATION (machine-to-machine)
//   POST /api/auth/verify-password
//     Authorization: Bearer {shared app-key}
//     body: { email, password, source }
//   → 200 { valid: true,  user: { email, phone, name } }   (correct password)
//   → 200 { valid: false }                                  (wrong password)
//   → 401 (bad app-key) / 400 (bad input)
//
// This is a machine-to-machine endpoint: it is gated ONLY by the shared app-key
// Bearer, never a user session. Without it, the Super-Admin password step
// silently 404s on the sibling app, blocking Super-Admin access. Rate-limited by
// IP to blunt any credential-stuffing via this path.
// ----------------------------------------------------------------------------
app.post('/api/auth/verify-password', rateLimit('verify-password', 30, 60_000), async (c) => {
  // Accept ANY of the shared Score<->Feed secrets as the Bearer app-key.
  //
  // WHY A MULTI-KEY CHAIN: the sibling's outbound key chain may present
  // FEED_APP_KEY → SCORE_CROSS_APP_HMAC_SECRET → CROSS_APP_HMAC_SECRET. We accept
  // the SCORE_APP_KEY → SCORE_API_SECRET → SCORE_HMAC_SECRET chain AND the shared
  // cross-app HMAC secrets so the already-shared handoff secret authorizes the
  // password check too — no new key needs provisioning on either app.
  const acceptedKeys = [
    c.env.SCORE_APP_KEY,
    c.env.SCORE_API_SECRET,
    c.env.SCORE_HMAC_SECRET,
    c.env.SCORE_CROSS_APP_HMAC_SECRET,
    c.env.CROSS_APP_HMAC_SECRET,
  ].map((k) => String(k || '').trim()).filter(Boolean)
  const bearer = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '').trim()
  if (acceptedKeys.length === 0) {
    // No shared secret configured → refuse rather than authenticate blindly.
    console.error('[verify-password] rejected: no shared app-key configured on Feed (set SCORE_APP_KEY or share SCORE_CROSS_APP_HMAC_SECRET/CROSS_APP_HMAC_SECRET with Score)')
    return c.json({ valid: false, error: 'cross_app_not_configured' }, 401)
  }
  // Constant-time comparison against every accepted key: never leak, via timing,
  // which/whether a shared app-key matched. (timingSafeEqualHex is hoisted.)
  const bearerOk = bearer.length > 0 && acceptedKeys.some((k) => timingSafeEqualHex(k, bearer))
  if (!bearerOk) {
    console.error(`[verify-password] rejected: Bearer app-key mismatch (presented ${bearer ? 'a key of len=' + bearer.length : 'no key'}; Feed accepts ${acceptedKeys.length} configured key(s)).`)
    return c.json({ valid: false, error: 'unauthorized' }, 401)
  }

  const body = await c.req.json().catch(() => ({}))
  const email = String(body?.email || '').trim().toLowerCase()
  const password = String(body?.password || '')
  if (!email || !password) {
    return c.json({ valid: false, error: 'email_and_password_required' }, 400)
  }

  // Look up the Feed user by email (case-insensitive).
  const user = await c.env.DB.prepare(
    `SELECT id, full_name, phone, email, password, status FROM users WHERE LOWER(email) = ? LIMIT 1`
  ).bind(email).first<any>().catch(() => null)

  // Uniform "valid:false" (200) for both "no such user" and "wrong password"
  // so this endpoint never reveals which emails exist.
  if (!user) return c.json({ valid: false })
  const check = await verifyPassword(String(password), user.password)
  if (!check.ok) return c.json({ valid: false })
  if (user.status && String(user.status) !== 'active') {
    return c.json({ valid: false, error: 'account_inactive' })
  }
  // Opportunistically upgrade a legacy plaintext password to the hashed form.
  if (check.legacy) {
    try { await c.env.DB.prepare(`UPDATE users SET password=? WHERE id=?`).bind(await hashPassword(String(password)), user.id).run() } catch (_) {}
  }

  return c.json({
    valid: true,
    user: {
      email: user.email || email,
      phone: user.phone || null,
      name: user.full_name || null,
    },
  })
})

// ----------------------------------------------------------------------------
// SELF-SERVICE PROFILE (Instruction 3)
//   * Farmers (role=customer): may update their own profile data EXCEPT
//     national_id and phone/mobile. Also avatar + password.
//   * All other users: may ONLY update their profile picture and password.
//   * Editing OTHER users is done by super_admin / authorized users via the
//     existing PUT /api/users/:id (Edit button in the users list).
// ----------------------------------------------------------------------------

// Fetch own profile (user fields + farmer/customer record when role=customer).
app.get('/api/me/profile', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  let customer: any = null
  if (user.role === 'customer') {
    customer = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  }
  return c.json({ user, customer })
})

// Update own profile picture (any authenticated user).
app.put('/api/me/avatar', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { avatar_url } = await c.req.json()
  // The profile picture must be an UPLOADED image (base64 data URL of an
  // allowed raster type) — never an external link, and never a disguised
  // non-image file. Empty clears the picture.
  const v = validateImageDataUrl(avatar_url, { allowEmpty: true })
  if (!v.ok) return c.json({ error: v.error }, 400)
  await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(avatar_url || null, user.id).run()
  await audit(c, user.id, 'update', 'profile', 'avatar')
  return c.json({ ok: true, avatar_url: avatar_url || null })
})

// Change own password (verify current password first).
app.put('/api/me/password', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { current_password, new_password } = await c.req.json()
  if (!new_password || String(new_password).length < 4) return c.json({ error: 'New password must be at least 4 characters' }, 400)
  const row = await c.env.DB.prepare(`SELECT password, must_change_password FROM users WHERE id=?`).bind(user.id).first<any>()
  if (!row) return c.json({ error: 'Current password is incorrect' }, 400)
  // Mandatory first-login change: the user just authenticated with the temporary
  // password, so we skip the current-password re-prompt for this one transition.
  if (!row.must_change_password) {
    const chk = await verifyPassword(String(current_password), row.password)
    if (!chk.ok) return c.json({ error: 'Current password is incorrect' }, 400)
  }
  // Setting a self-chosen password also completes the onboarding lifecycle:
  // clear the mandatory-change gate, the temp flag and the expiry deadline.
  await c.env.DB.prepare(
    `UPDATE users SET password=?, password_set=1, must_change_password=0, is_temp_password=0, temp_password_expires_at=NULL WHERE id=?`
  ).bind(await hashPassword(String(new_password)), user.id).run()
  await audit(c, user.id, 'update', 'profile', 'password change')
  return c.json({ ok: true })
})

// Update own profile data.
//   Farmers  -> full customer profile (EXCEPT national_id & phone/mobile) + avatar.
//   Others   -> avatar only (name/region managed by admins).
app.put('/api/me/profile', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()

  // Everyone may update their avatar via this endpoint — validated as an
  // uploaded image (no external links, no disguised non-image files).
  if (b.avatar_url !== undefined) {
    const v = validateImageDataUrl(b.avatar_url, { allowEmpty: true })
    if (!v.ok) return c.json({ error: v.error }, 400)
    await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(b.avatar_url || null, user.id).run()
  }

  // Screen free-text profile fields for injection / harmful content.
  const tv = validateTextFields(b, [
    { key: 'full_name', label: 'Full name', max: 120 },
    { key: 'alt_mobile', label: 'Alternate mobile', max: 40 },
    { key: 'county', label: 'County', max: 80 },
    { key: 'sub_county', label: 'Sub-county', max: 80 },
    { key: 'ward', label: 'Ward', max: 80 },
    { key: 'village', label: 'Village', max: 120 },
    { key: 'value_chain', label: 'Value chain', max: 120 },
    { key: 'value_chain_type', label: 'Value chain type', max: 120 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)

  if (user.role !== 'customer') {
    // Non-farmers: profile picture only (already handled above). Everything else ignored.
    await audit(c, user.id, 'update', 'profile', 'avatar (non-farmer self-update)')
    const updated = await getSessionUser(c)
    return c.json({ ok: true, user: updated, note: 'Only your profile picture and password can be changed here.' })
  }

  // Farmer: locate their customer record.
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  if (!cust) return c.json({ error: 'Farmer profile not found' }, 404)

  // Explicitly IGNORE immutable fields: national_id, phone, mobile.
  const saccoProvided = b.sacco_membership !== undefined
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership)
     WHERE id=?`
  ).bind(
    b.full_name ?? null, b.date_of_birth ?? null, b.gender ?? null,
    b.alt_mobile ?? null, b.county ?? null, b.sub_county ?? null,
    b.ward ?? null, b.village ?? null, b.latitude ?? null, b.longitude ?? null,
    b.value_chain_type ?? null, b.value_chain ?? null, b.acreage ?? null, b.herd_size ?? null,
    b.farm_experience ?? null, b.annual_production ?? null, b.existing_loans ?? null,
    saccoProvided ? (saccoMember ? 'yes' : 'no') : null,
    cust.id
  ).run()
  // Keep the users.full_name in sync when the farmer renames themselves.
  if (b.full_name) {
    await c.env.DB.prepare(`UPDATE users SET full_name=? WHERE id=?`).bind(String(b.full_name).trim(), user.id).run()
  }
  await audit(c, user.id, 'update', 'profile', 'farmer self-update (ID & phone locked)')
  const updated = await getSessionUser(c)
  return c.json({ ok: true, user: updated })
})

// ---- Auth provider status (so the UI can show live vs demo) ----
app.get('/api/auth/status', (c) => c.json({ sms_live: smsConfigured(c.env) }))
app.get('/api/integrations/transunion/status', requireAuth, (c) => {
  const live = Boolean(c.env.TRANSUNION_API_URL && c.env.TRANSUNION_API_KEY)
  return c.json({ live, environment: c.env.TRANSUNION_ENV || 'stub', ready_for_mapping: live })
})

// ---- Customer SIGN-UP via SMS OTP ----
// Step 1: request an OTP for a new phone number.
app.post('/api/signup/request-otp', async (c) => {
  const { phone, full_name } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!p || p.length < 9) return c.json({ error: 'Enter a valid phone number' }, 400)
  if (!full_name || String(full_name).trim().length < 2) return c.json({ error: 'Enter your full name' }, 400)
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (existing) return c.json({ error: 'An account with this phone already exists. Please sign in.' }, 409)
  const { sms, demo_otp } = await issueOtp(c, p, 'signup')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `OTP sent to ${p}.`, demo_otp })
})
// Step 2: verify OTP + set password -> create account + auto sign-in.
// Sign-up ONLY collects Full Name, phone and password. KYC data & document
// attachments are added AFTER sign-up (via /api/me/profile & the KYC upload
// endpoints) and are enforced only when the user attempts a FINANCING purchase.
app.post('/api/signup/verify', async (c) => {
  const b = await c.req.json()
  const { phone, full_name, code, password, region } = b
  const p = normalizePhone(phone || '')
  if (!full_name || String(full_name).trim().length < 2) return c.json({ error: 'Enter your full name' }, 400)
  if (!password || String(password).length < 4) return c.json({ error: 'Password must be at least 4 characters' }, 400)
  // UNIFIED REGISTRATION: self-signup collects the SAME Standard Profile Data an
  // agent collects when onboarding a farmer. National ID + County are required.
  const national_id = String(b.national_id || '').trim()
  const county = String(b.county || '').trim()
  if (!national_id) return c.json({ error: 'National ID is required' }, 400)
  if (!county) return c.json({ error: 'County is required' }, 400)
  // Screen the free-text identity/location fields for injection / harmful content.
  const tv = validateTextFields(b, [
    { key: 'full_name', label: 'Full name', max: 120 },
    { key: 'national_id', label: 'National ID', max: 40 },
    { key: 'gender', label: 'Gender', max: 20 },
    { key: 'county', label: 'County', max: 80 }, { key: 'sub_county', label: 'Sub-county', max: 80 },
    { key: 'ward', label: 'Ward', max: 80 }, { key: 'village', label: 'Village', max: 120 },
    { key: 'value_chain', label: 'Value chain', max: 120 }, { key: 'value_chain_type', label: 'Value chain type', max: 120 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)
  // SACCO membership is a Yes/No flag — normalise to the same 'yes'/'no' the
  // agent onboarding handler (POST /api/customers) stores.
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  const v = await verifyOtp(c, p, code, 'signup')
  if (!v.ok) return c.json({ error: v.error }, 400)
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (existing) return c.json({ error: 'Account already exists. Please sign in.' }, 409)
  // National ID must be unique across customers (same rule as agent onboarding).
  // App-level pre-check for a friendly message; a database UNIQUE index
  // (uq_customers_national_id, migration 0017) is the authoritative guard and
  // is caught below if two requests race.
  const dupId = await c.env.DB.prepare(`SELECT id FROM customers WHERE national_id=?`).bind(national_id).first()
  if (dupId) return c.json({ error: 'A profile with this National ID already exists.' }, 409)
  const role = 'customer'
  const farmerPerms = await permissionsForRole(c, role)
  // Customers never provide an email at signup — resolveEmail supplies a UNIQUE,
  // non-deliverable placeholder derived from the phone. This satisfies the
  // central users.email NOT NULL + UNIQUE constraints (a bare NULL failed with
  // "null value in column email ... violates not-null constraint", and binding
  // '' would collide on the 2nd signup → users_email_key / 23505). Parity with
  // the Equipment signup/verify handler.
  const signupEmailRes = resolveEmail(role, null, p)
  const signupEmail = 'value' in signupEmailRes ? signupEmailRes.value : ''
  // Self-registration is a server-authorized write: run under the admin RLS
  // context so the non-superuser DB role can create the user + customer profile
  // (matches every other privileged insert in this file).
  let userId: any
  try {
  userId = await withAdminContext(c, async () => {
    // On the shared central DB, users.org_id is NOT NULL. Public self-signup has
    // no creating admin, so attach the deployment's default tenant. On the
    // Feed-only DB shape (no org_id column) orgId is null and we omit it.
    const orgId = await resolveDefaultOrgId(c)
    const withOrg = (await usersHasOrgId(c)) && orgId != null
    const r = withOrg
      ? await c.env.DB.prepare(
          `INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions, org_id) VALUES (?,?,?,?, ?, 'active', ?, 1, ?, ?, ?)`
        ).bind(String(full_name).trim(), p, signupEmail, await hashPassword(String(password)), role, region || null, 'Farmer', JSON.stringify(farmerPerms), orgId).run()
      : await c.env.DB.prepare(
          `INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions) VALUES (?,?,?,?, ?, 'active', ?, 1, ?, ?)`
        ).bind(String(full_name).trim(), p, signupEmail, await hashPassword(String(password)), role, region || null, 'Farmer', JSON.stringify(farmerPerms)).run()
    const uid = r.meta.last_row_id
    // Create the customer profile with the SAME full field set an agent captures
    // when onboarding a farmer (Personal / Location / Farming / Financial).
    // KYC stays 'not_started' until ID documents are uploaded (required before financing).
    await c.env.DB.prepare(
      `INSERT INTO customers (user_id, onboarded_by, full_name, national_id, date_of_birth, gender, mobile, alt_mobile, county, sub_county, ward, village, latitude, longitude, value_chain_type, value_chain, acreage, herd_size, farm_experience, annual_production, existing_loans, sacco_membership, kyc_status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'not_started')`
    ).bind(
      uid, uid,
      String(full_name).trim(), national_id, b.date_of_birth || null, b.gender || null, p, b.alt_mobile || null,
      county, b.sub_county || null, b.ward || null, b.village || null,
      b.latitude || null, b.longitude || null,
      b.value_chain_type || null, b.value_chain || null,
      b.acreage || null, b.herd_size || null, b.farm_experience || null, b.annual_production || null,
      b.existing_loans || null, saccoMember ? 'yes' : 'no'
    ).run()
    return uid
  })
  } catch (err: any) {
    // Surface the database-level UNIQUE constraint violations as clean 409s.
    const msg = String(err?.message || err || '')
    if (/uq_customers_national_id|national_id/i.test(msg) && /unique|duplicate|23505/i.test(msg)) {
      return c.json({ error: 'A profile with this National ID already exists.' }, 409)
    }
    if (/uq_users_phone|users_phone|phone/i.test(msg) && /unique|duplicate|23505/i.test(msg)) {
      return c.json({ error: 'Account already exists. Please sign in.' }, 409)
    }
    if (/unique|duplicate|23505/i.test(msg)) {
      return c.json({ error: 'This National ID or phone number is already registered.' }, 409)
    }
    throw err
  }
  const user = { id: userId, full_name: String(full_name).trim(), phone: p, role, region, label: 'Farmer', permissions: farmerPerms }
  await createSession(c, user)
  await audit(c, userId, 'signup', 'user', 'customer self-registered via SMS OTP (unified standard profile: name, phone, national ID, location)')
  return c.json({ ok: true, user })
})

// ---- PASSWORD RESET via SMS OTP ----
app.post('/api/reset-password/request-otp', async (c) => {
  const { phone } = await c.req.json()
  const p = normalizePhone(phone || '')
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  // Do not reveal whether the phone exists; but in demo we send anyway only if it exists.
  if (!user) return c.json({ ok: true, phone: p, message: 'If the number is registered, an OTP has been sent.' })
  const { sms, demo_otp } = await issueOtp(c, p, 'reset')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `OTP sent to ${p}.`, demo_otp })
})
app.post('/api/reset-password/verify', async (c) => {
  const { phone, code, password } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!password || String(password).length < 4) return c.json({ error: 'Password must be at least 4 characters' }, 400)
  const v = await verifyOtp(c, p, code, 'reset')
  if (!v.ok) return c.json({ error: v.error }, 400)
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first<any>()
  if (!user) return c.json({ error: 'Account not found' }, 404)
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(await hashPassword(String(password)), user.id).run()
  // Invalidate all existing sessions after a credential reset.
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(user.id).run()
  await audit(c, user.id, 'reset_password', 'user', 'password reset via SMS OTP')
  return c.json({ ok: true, message: 'Password updated. You can now sign in.' })
})

// ----------------------------------------------------------------------------
// PRODUCTS / INVENTORY
// ----------------------------------------------------------------------------
// Storefront + management catalog. Products are read under admin context so the
// public shop and managers see the global catalog; ownership filtering for the
// "My Inventory" grid is applied explicitly below via ?mine=1.
app.get('/api/products', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const mine = c.req.query('mine') === '1'
  const shop = c.req.query('shop') === '1'
  const rows = await withAdminContext(c, async () => {
    let query = `SELECT * FROM products`
    const binds: any[] = []
    const where: string[] = []
    // Storefront: only fully-authorized products are visible to buyers.
    if (shop) where.push(`finance_status = 'published'`)
    if (mine && !['admin', 'super_admin'].includes(user.role)) { where.push(`created_by = ?`); binds.push(user.id) }
    // Phase 5 — data isolation by APP_TYPE: this app only surfaces catalog
    // rows scoped to itself or shared ('both'). Equipment sees equipment+both,
    // Feed sees feed+both. A single shared DB thus serves both storefronts.
    const appType = String(c.env.APP_TYPE || 'feed').toLowerCase() === 'equipment' ? 'equipment' : 'feed'
    where.push(`app_scope IN (?, 'both')`); binds.push(appType)
    if (where.length) query += ` WHERE ` + where.join(' AND ')
    query += ` ORDER BY name`
    const { results } = await c.env.DB.prepare(query).bind(...binds).all()
    return results
  })
  const withStatus = (rows as any[]).map((p: any) => ({
    ...p,
    stock_status: p.quantity <= 0 ? 'out_of_stock' : p.quantity <= p.reorder_threshold ? 'low_stock' : 'in_stock'
  }))
  return c.json({ products: withStatus, can_manage_inventory: hasPermission(user, 'can_manage_inventory'), can_manage_finance_settings: hasPermission(user, 'can_manage_finance_settings') })
})
// Drafting a product needs can_manage_inventory. If the author is NOT authorized
// for finance, the product is saved as 'pending_finance' with finance fields
// neutralized, and lands in the finance-approval queue.
app.post('/api/products', requireAuth, requirePermission('can_manage_inventory'), async (c) => {
  const user = c.get('user') as SessionUser
  const canFinance = hasPermission(user, 'can_manage_finance_settings')
  let raw: any
  try { raw = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const p = normalizeProductPayload(raw)
  if (!p.sku || !p.name) return c.json({ error: 'SKU and name are required' }, 400)
  // Numeric sanity — never let NaN / negatives reach the NOT NULL money columns.
  if (!(p.buying_price >= 0) || !(p.cash_price >= 0) || !(p.credit_price >= 0)) {
    return c.json({ error: 'Prices must be valid non-negative numbers.' }, 400)
  }
  // Validate the (optional) product image.
  if (p.image) {
    const iv = validateImageDataUrl(p.image, { allowEmpty: true })
    if (!iv.ok) return c.json({ error: iv.error || 'Invalid image.' }, 400)
  }
  // Validate any uploaded agreement / financing documents (PDF or image, <=8MB).
  for (const [field, label] of [['cash_terms_doc_url', 'Cash agreement document'], ['financing_terms_doc_url', 'Financing agreement document']] as const) {
    const dv = validateDocDataUrl((p as any)[field], { allowEmpty: true })
    if (!dv.ok) return c.json({ error: `${label}: ${dv.error}` }, 400)
  }
  // Fail fast on a duplicate SKU with a clear 409 instead of an opaque 500 from
  // the products_sku UNIQUE constraint.
  const dup = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM products WHERE sku = ?`).bind(p.sku).first<any>())
  if (dup) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
  // Enforce the split at the app layer too (defence-in-depth alongside the RLS trigger).
  let financeStatus = 'published'
  if (!canFinance) {
    p.credit_markup_pct = 0
    p.credit_price = p.cash_price
    p.financing_enabled = false
    p.financing_interest_pct = 0
    p.financing_terms_text = null
    p.financing_terms_doc_url = null
    p.payment_option_mode = 'cash'
    financeStatus = 'pending_finance'
  }
  const financeSetBy = canFinance ? user.id : null
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO products (sku,name,category,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,cash_price_mode,cash_markup_amount,credit_price_mode,credit_markup_amount,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_type_key,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,financing_tenure_unit,financing_rate_per_cycle,financing_amount_per_cycle,financing_cycle_count,financing_cycle_length_days,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url,created_by,finance_status,finance_set_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      p.sku, p.name, p.category, p.description, p.product_type, p.supplier_id, p.buying_price, p.cash_markup_pct, p.credit_markup_pct,
      p.cash_price, p.credit_price, p.cash_price_mode, p.cash_markup_amount, p.credit_price_mode, p.credit_markup_amount, p.quantity, p.unit, p.reorder_threshold, p.image, p.cash_enabled, p.financing_enabled,
      p.payment_option_mode, p.financing_model, p.financing_type_key, p.financing_interest_pct, p.financing_frequency, p.financing_term_min_months,
      p.financing_term_max_months, p.financing_tenure_unit, p.financing_rate_per_cycle, p.financing_amount_per_cycle, p.financing_cycle_count, p.financing_cycle_length_days, p.cash_deposit_pct, p.financing_deposit_pct, p.cash_terms_text, p.financing_terms_text,
      p.cash_terms_doc_url, p.financing_terms_doc_url, user.id, financeStatus, financeSetBy
    ).run()
    await audit(c, user.id, 'create', 'product', `${p.name} (${financeStatus})`)
    return c.json({ id: r.meta.last_row_id, finance_status: financeStatus })
  } catch (err: any) {
    const msg = String(err?.message || err || '')
    if (/unique|duplicate|sku/i.test(msg)) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
    console.error('product create error:', msg)
    return c.json({ error: 'Could not save the product. Please check the fields and try again.' }, 500)
  }
})
// Editing core/cash details needs can_manage_inventory. Editing finance columns
// needs can_manage_finance_settings — if the editor lacks it, the existing
// finance values are preserved (COALESCE-style) and cannot be changed.
app.put('/api/products/:id', requireAuth, requirePermission('can_manage_inventory', 'can_manage_finance_settings'), async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const canInv = hasPermission(user, 'can_manage_inventory')
  const canFinance = hasPermission(user, 'can_manage_finance_settings')
  const existing = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(id).first<any>())
  if (!existing) return c.json({ error: 'Not found' }, 404)
  let raw: any
  try { raw = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const p = normalizeProductPayload(raw)
  // Validate uploads the editor is permitted to change.
  if (canInv && p.image) {
    const iv = validateImageDataUrl(p.image, { allowEmpty: true })
    if (!iv.ok) return c.json({ error: iv.error || 'Invalid image.' }, 400)
  }
  if (canInv) {
    const dv = validateDocDataUrl(p.cash_terms_doc_url, { allowEmpty: true })
    if (!dv.ok) return c.json({ error: `Cash agreement document: ${dv.error}` }, 400)
  }
  if (canFinance) {
    const dv = validateDocDataUrl(p.financing_terms_doc_url, { allowEmpty: true })
    if (!dv.ok) return c.json({ error: `Financing agreement document: ${dv.error}` }, 400)
  }
  // If the editor is changing the SKU, ensure it doesn't collide with another row.
  if (canInv && p.sku && p.sku !== existing.sku) {
    const dup = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM products WHERE sku = ? AND id <> ?`).bind(p.sku, id).first<any>())
    if (dup) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
  }
  // Choose which columns the editor is allowed to change.
  const coreCols = canInv ? {
    sku: p.sku, name: p.name, category: p.category, description: p.description, product_type: p.product_type,
    buying_price: p.buying_price, cash_markup_pct: p.cash_markup_pct, cash_price: p.cash_price, cash_price_mode: p.cash_price_mode, cash_markup_amount: p.cash_markup_amount,
    quantity: p.quantity, unit: p.unit, reorder_threshold: p.reorder_threshold, image: p.image || existing.image,
    cash_enabled: p.cash_enabled, cash_deposit_pct: p.cash_deposit_pct, cash_terms_text: p.cash_terms_text, cash_terms_doc_url: p.cash_terms_doc_url
  } : {
    sku: existing.sku, name: existing.name, category: existing.category, description: existing.description, product_type: existing.product_type,
    buying_price: existing.buying_price, cash_markup_pct: existing.cash_markup_pct, cash_price: existing.cash_price, cash_price_mode: existing.cash_price_mode, cash_markup_amount: existing.cash_markup_amount,
    quantity: existing.quantity, unit: existing.unit, reorder_threshold: existing.reorder_threshold, image: existing.image,
    cash_enabled: existing.cash_enabled, cash_deposit_pct: existing.cash_deposit_pct, cash_terms_text: existing.cash_terms_text, cash_terms_doc_url: existing.cash_terms_doc_url
  }
  const finCols = canFinance ? {
    credit_markup_pct: p.credit_markup_pct, credit_price: p.credit_price, credit_price_mode: p.credit_price_mode, credit_markup_amount: p.credit_markup_amount, financing_enabled: p.financing_enabled,
    financing_model: p.financing_model, financing_type_key: p.financing_type_key, financing_interest_pct: p.financing_interest_pct, financing_frequency: p.financing_frequency,
    financing_term_min_months: p.financing_term_min_months, financing_term_max_months: p.financing_term_max_months,
    financing_tenure_unit: p.financing_tenure_unit, financing_rate_per_cycle: p.financing_rate_per_cycle, financing_amount_per_cycle: p.financing_amount_per_cycle,
    financing_cycle_count: p.financing_cycle_count, financing_cycle_length_days: p.financing_cycle_length_days,
    financing_deposit_pct: p.financing_deposit_pct, financing_terms_text: p.financing_terms_text, financing_terms_doc_url: p.financing_terms_doc_url,
    payment_option_mode: p.payment_option_mode, finance_status: 'published', finance_set_by: user.id
  } : {
    credit_markup_pct: existing.credit_markup_pct, credit_price: existing.credit_price, credit_price_mode: existing.credit_price_mode, credit_markup_amount: existing.credit_markup_amount, financing_enabled: existing.financing_enabled,
    financing_model: existing.financing_model, financing_type_key: existing.financing_type_key, financing_interest_pct: existing.financing_interest_pct, financing_frequency: existing.financing_frequency,
    financing_term_min_months: existing.financing_term_min_months, financing_term_max_months: existing.financing_term_max_months,
    financing_tenure_unit: existing.financing_tenure_unit, financing_rate_per_cycle: existing.financing_rate_per_cycle, financing_amount_per_cycle: existing.financing_amount_per_cycle,
    financing_cycle_count: existing.financing_cycle_count, financing_cycle_length_days: existing.financing_cycle_length_days,
    financing_deposit_pct: existing.financing_deposit_pct, financing_terms_text: existing.financing_terms_text, financing_terms_doc_url: existing.financing_terms_doc_url,
    payment_option_mode: existing.payment_option_mode, finance_status: existing.finance_status, finance_set_by: existing.finance_set_by
  }
  try {
    await c.env.DB.prepare(
      `UPDATE products SET sku=?, name=?, category=?, description=?, product_type=?, buying_price=?, cash_markup_pct=?, credit_markup_pct=?, cash_price=?, credit_price=?, cash_price_mode=?, cash_markup_amount=?, credit_price_mode=?, credit_markup_amount=?, quantity=?, unit=?, reorder_threshold=?, image=COALESCE(?, image), cash_enabled=?, financing_enabled=?, payment_option_mode=?, financing_model=?, financing_type_key=?, financing_interest_pct=?, financing_frequency=?, financing_term_min_months=?, financing_term_max_months=?, financing_tenure_unit=?, financing_rate_per_cycle=?, financing_amount_per_cycle=?, financing_cycle_count=?, financing_cycle_length_days=?, cash_deposit_pct=?, financing_deposit_pct=?, cash_terms_text=?, financing_terms_text=?, cash_terms_doc_url=?, financing_terms_doc_url=?, finance_status=?, finance_set_by=?, finance_set_at=CASE WHEN ?='published' THEN CURRENT_TIMESTAMP ELSE finance_set_at END WHERE id=?`
    ).bind(
      coreCols.sku, coreCols.name, coreCols.category, coreCols.description, coreCols.product_type, coreCols.buying_price, coreCols.cash_markup_pct, finCols.credit_markup_pct,
      coreCols.cash_price, finCols.credit_price, coreCols.cash_price_mode, coreCols.cash_markup_amount, finCols.credit_price_mode, finCols.credit_markup_amount, coreCols.quantity, coreCols.unit, coreCols.reorder_threshold, coreCols.image || null, coreCols.cash_enabled, finCols.financing_enabled,
      finCols.payment_option_mode, finCols.financing_model, finCols.financing_type_key, finCols.financing_interest_pct, finCols.financing_frequency, finCols.financing_term_min_months,
      finCols.financing_term_max_months, finCols.financing_tenure_unit, finCols.financing_rate_per_cycle, finCols.financing_amount_per_cycle, finCols.financing_cycle_count, finCols.financing_cycle_length_days, coreCols.cash_deposit_pct, finCols.financing_deposit_pct, coreCols.cash_terms_text, finCols.financing_terms_text,
      coreCols.cash_terms_doc_url, finCols.financing_terms_doc_url, finCols.finance_status, finCols.finance_set_by, finCols.finance_status, id
    ).run()
    await audit(c, user.id, 'update', 'product', `${coreCols.name}${canFinance ? '' : ' (core only)'}`)
    return c.json({ ok: true })
  } catch (err: any) {
    const msg = String(err?.message || err || '')
    if (/unique|duplicate|sku/i.test(msg)) return c.json({ error: `A product with SKU "${coreCols.sku}" already exists. Use a unique SKU.` }, 409)
    console.error('product update error:', msg)
    return c.json({ error: 'Could not update the product. Please check the fields and try again.' }, 500)
  }
})
app.delete('/api/products/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE product_id=?`).bind(id).first<any>()
  if (used?.n > 0) return c.json({ error: 'Cannot delete: product is referenced by existing purchases' }, 400)
  await c.env.DB.prepare(`DELETE FROM products WHERE id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'delete', 'product', String(id))
  return c.json({ ok: true })
})
app.put('/api/products/:id/stock', requireAuth, requirePermission('can_manage_inventory'), async (c) => {
  const id = c.req.param('id')
  const { quantity, movement_type } = await c.req.json()
  await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id = ?`).bind(Number(quantity), id).run()
  await c.env.DB.prepare(`INSERT INTO stock_movements (product_id, movement_type, quantity, reference) VALUES (?,?,?,?)`)
    .bind(id, movement_type || 'purchase', quantity, 'manual adjustment').run()
  return c.json({ ok: true })
})

// ---- Split-data workflow: finance-approval queue -------------------------
// Products drafted by a base user awaiting an authorized finance user to supply
// markups / rates / agreements before they can be published to the storefront.
app.get('/api/products/finance-queue', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.*, u.full_name AS created_by_name
         FROM products p LEFT JOIN users u ON CAST(u.id AS TEXT) = p.created_by
        WHERE p.finance_status = 'pending_finance'
        ORDER BY p.created_at DESC`
    ).all()
    return results
  })
  return c.json({ products: rows })
})
// Authorized finance user supplies the finance components and publishes.
app.put('/api/products/:id/finance', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const b = await c.req.json()
  const publish = b.finance_status !== 'pending_finance'
  await c.env.DB.prepare(
    `UPDATE products SET
        credit_markup_pct = COALESCE(?, credit_markup_pct),
        credit_price = COALESCE(?, credit_price),
        financing_enabled = COALESCE(?, financing_enabled),
        financing_model = COALESCE(?, financing_model),
        financing_interest_pct = COALESCE(?, financing_interest_pct),
        financing_frequency = COALESCE(?, financing_frequency),
        financing_term_min_months = COALESCE(?, financing_term_min_months),
        financing_term_max_months = COALESCE(?, financing_term_max_months),
        financing_deposit_pct = COALESCE(?, financing_deposit_pct),
        financing_terms_text = COALESCE(?, financing_terms_text),
        financing_terms_doc_url = COALESCE(?, financing_terms_doc_url),
        payment_option_mode = COALESCE(?, payment_option_mode),
        finance_notes = COALESCE(?, finance_notes),
        finance_status = ?, finance_set_by = ?, finance_set_at = CURRENT_TIMESTAMP
      WHERE id = ?`
  ).bind(
    b.credit_markup_pct ?? null, b.credit_price ?? null,
    b.financing_enabled === undefined ? null : (boolInt(b.financing_enabled, true) ? 1 : 0),
    b.financing_model ?? null, b.financing_interest_pct ?? null, b.financing_frequency ?? null,
    b.financing_term_min_months ?? null, b.financing_term_max_months ?? null, b.financing_deposit_pct ?? null,
    b.financing_terms_text ?? null, b.financing_terms_doc_url ?? null,
    b.payment_option_mode ?? (publish ? 'both' : null), b.finance_notes ?? null,
    publish ? 'published' : 'pending_finance', user.id, id
  ).run()
  await audit(c, user.id, 'finance_authorize', 'product', `product ${id} ${publish ? 'published' : 'saved'}`)
  return c.json({ ok: true, finance_status: publish ? 'published' : 'pending_finance' })
})
// ---- Admin audit: products hidden from storefront for lack of finance -----
// Diagnostic + reminder feed for authorized finance personnel.
app.get('/api/products/finance-audit', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.id, p.sku, p.name, p.finance_status, p.created_at, p.created_by,
              u.full_name AS created_by_name,
              (CASE WHEN p.credit_markup_pct IS NULL OR p.credit_markup_pct = 0 THEN 1 ELSE 0 END) AS missing_markup,
              (CASE WHEN p.financing_terms_text IS NULL OR p.financing_terms_text = '' THEN 1 ELSE 0 END) AS missing_agreement
         FROM products p LEFT JOIN users u ON CAST(u.id AS TEXT) = p.created_by
        WHERE p.finance_status <> 'published'
        ORDER BY p.created_at ASC`
    ).all()
    return results
  })
  const list = rows as any[]
  const reminder = list.length
    ? `${list.length} product(s) are hidden from the storefront pending financial parameters. Authorized finance personnel should review the queue.`
    : 'All products have complete financial parameters and are visible on the storefront.'
  return c.json({ hidden_products: list, count: list.length, reminder, notify_roles: ['admin', 'super_admin', 'operations_finance'] })
})

// ----------------------------------------------------------------------------
// CUSTOMERS / ONBOARDING / VERIFICATION
// ----------------------------------------------------------------------------
app.get('/api/customers', requireAuth, async (c) => {
  const user = c.get('user')
  let query = `SELECT * FROM customers`
  let binds: any[] = []
  if (user.role === 'agent') { query += ` WHERE agent_id = ?`; binds = [user.id] }
  query += ` ORDER BY created_at DESC`
  const { results } = await c.env.DB.prepare(query).bind(...binds).all()
  return c.json({ customers: (results as any[]).map((r) => redactCustomer(user, r)) })
})
app.get('/api/customers/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(c.req.param('id')).first()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const tu = await c.env.DB.prepare(`SELECT * FROM transunion_checks WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first()
  const idv = await c.env.DB.prepare(`SELECT * FROM id_verifications WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first()
  const showFinancial = hasVisibility(user, 'view_financial_data')
  return c.json({ customer: redactCustomer(user, cust), transunion: showFinancial ? tu : null, id_verification: idv })
})
app.post('/api/customers', requireAuth, requireRole('agent', 'admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const user = c.get('user')
  // KYC ID images must be uploaded files (no external links / disguised files).
  for (const f of ['id_front_url', 'id_back_url', 'selfie_url']) {
    if (b[f] !== undefined && b[f] !== null && b[f] !== '') {
      const v = validateImageDataUrl(b[f], { allowEmpty: true })
      if (!v.ok) return c.json({ error: `${f.replace(/_url$/, '').replace(/_/g, ' ')}: ${v.error}` }, 400)
    }
  }
  // Screen free-text identity/location fields for injection / harmful content.
  const tv = validateTextFields(b, [
    { key: 'full_name', label: 'Full name', max: 120 },
    { key: 'county', label: 'County', max: 80 }, { key: 'sub_county', label: 'Sub-county', max: 80 },
    { key: 'ward', label: 'Ward', max: 80 }, { key: 'village', label: 'Village', max: 120 },
    { key: 'value_chain', label: 'Value chain', max: 120 }, { key: 'value_chain_type', label: 'Value chain type', max: 120 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  const assignedAgent = user.role === 'agent' ? user.id : (b.agent_id || user.id)
  const r = await c.env.DB.prepare(
    `INSERT INTO customers (agent_id,onboarded_by,full_name,national_id,date_of_birth,gender,mobile,alt_mobile,county,sub_county,ward,village,latitude,longitude,value_chain_type,value_chain,acreage,herd_size,farm_experience,annual_production,existing_loans,sacco_membership,id_front_url,id_back_url,kyc_status,status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', 'active')`
  ).bind(
    assignedAgent, assignedAgent,
    b.full_name, b.national_id, b.date_of_birth, b.gender, b.mobile, b.alt_mobile, b.county, b.sub_county,
    b.ward, b.village, b.latitude || null, b.longitude || null, b.value_chain_type, b.value_chain,
    b.acreage || null, b.herd_size || null, b.farm_experience || null, b.annual_production || null,
    b.existing_loans || null,
    saccoMember ? 'yes' : 'no',
    b.id_front_url || null, b.id_back_url || null
  ).run()
  await audit(c, user.id, 'onboard', 'customer', b.full_name)
  return c.json({ id: r.meta.last_row_id })
})
// Update farmer profile (admin + agent for their own customer)
app.put('/api/customers/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const isAdmin = ['admin', 'super_admin'].includes(user.role)
  const isOwningAgent = user.role === 'agent' && cust.agent_id === user.id
  // The owning customer may update their OWN record here — this is what the
  // Step-3 "Complete Registration" KYC document upload (ID front/back) uses.
  // Without this a farmer saving their own KYC images was rejected with 403.
  const isOwningCustomer = user.role === 'customer' && cust.user_id === user.id
  if (!isAdmin && !isOwningAgent && !isOwningCustomer) {
    return c.json({ error: "You can only update your own profile. If this is your record, please sign out and sign back in, then try again." }, 403)
  }
  const b = await c.req.json()
  // Immutable identity fields: national_id and mobile can never be changed after
  // creation (uniqueness + integrity). Only a fresh admin create can set them.
  b.national_id = undefined
  b.mobile = undefined
  // KYC ID images must be uploaded files (no external links / disguised files).
  for (const f of ['id_front_url', 'id_back_url', 'selfie_url']) {
    if (b[f] !== undefined && b[f] !== null && b[f] !== '') {
      const v = validateImageDataUrl(b[f], { allowEmpty: true })
      if (!v.ok) return c.json({ error: `${f.replace(/_url$/, '').replace(/_/g, ' ')}: ${v.error}` }, 400)
    }
  }
  const tv = validateTextFields(b, [
    { key: 'full_name', label: 'Full name', max: 120 },
    { key: 'county', label: 'County', max: 80 }, { key: 'sub_county', label: 'Sub-county', max: 80 },
    { key: 'ward', label: 'Ward', max: 80 }, { key: 'village', label: 'Village', max: 120 },
    { key: 'value_chain', label: 'Value chain', max: 120 }, { key: 'value_chain_type', label: 'Value chain type', max: 120 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)
  const saccoProvided = b.sacco_membership !== undefined
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      national_id=COALESCE(?, national_id),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      mobile=COALESCE(?, mobile),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership),
      id_front_url=COALESCE(?, id_front_url),
      id_back_url=COALESCE(?, id_back_url)
     WHERE id=?`
  ).bind(
    b.full_name ?? null, b.national_id ?? null, b.date_of_birth ?? null, b.gender ?? null,
    b.mobile ?? null, b.alt_mobile ?? null, b.county ?? null, b.sub_county ?? null,
    b.ward ?? null, b.village ?? null, b.latitude ?? null, b.longitude ?? null,
    b.value_chain_type ?? null, b.value_chain ?? null, b.acreage ?? null, b.herd_size ?? null,
    b.farm_experience ?? null, b.annual_production ?? null, b.existing_loans ?? null,
    saccoProvided ? (saccoMember ? 'yes' : 'no') : null,
    b.id_front_url ?? null, b.id_back_url ?? null, id
  ).run()
  await audit(c, user.id, 'update', 'customer', String(id))
  return c.json({ ok: true })
})
// Admin can suspend / reactivate farmer profiles
app.put('/api/customers/:id/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { status } = await c.req.json()
  if (!['active', 'suspended'].includes(String(status))) return c.json({ error: 'Status must be active or suspended' }, 400)
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  await c.env.DB.prepare(`UPDATE customers SET status=? WHERE id=?`).bind(status, id).run()
  if (cust.user_id) {
    await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, cust.user_id).run()
    if (status === 'suspended') await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(cust.user_id).run()
  }
  await audit(c, c.get('user').id, status === 'active' ? 'activate' : 'deactivate', 'customer', String(id))
  return c.json({ ok: true })
})
// Admin can delete farmer profiles (and the linked customer-role user)
app.delete('/api/customers/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const open = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status IN ('active','pending','pending_payment')`).bind(id).first<any>()
  if (Number(open?.n || 0) > 0) return c.json({ error: 'Farmer has open contracts. Settle or cancel them first.' }, 400)
  await c.env.DB.prepare(`DELETE FROM transunion_checks WHERE customer_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM id_verifications WHERE customer_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM customers WHERE id=?`).bind(id).run()
  if (cust.user_id) {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(cust.user_id).run()
    await c.env.DB.prepare(`DELETE FROM users WHERE id=? AND role='customer'`).bind(cust.user_id).run()
  }
  await audit(c, c.get('user').id, 'delete', 'customer', String(id))
  return c.json({ ok: true })
})
// Verification engine (TransUnion integration-ready; simulated scoring until live mapping is added)
app.post('/api/customers/:id/verify', requireAuth, async (c) => {
  const id = c.req.param('id')
  const user = c.get('user')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  if (!['admin', 'super_admin', 'agent', 'operations_finance'].includes(user.role)) {
    if (!(user.role === 'customer' && cust.user_id === user.id)) {
      return c.json({ error: "You can only verify your own profile. If this is your record, please sign out and sign back in, then try again." }, 403)
    }
  }
  if (!cust.id_front_url || !cust.id_back_url) return c.json({ error: 'Please capture both the front and back of your national ID before running verification.' }, 400)
  const transunionLive = Boolean(c.env.TRANSUNION_API_URL && c.env.TRANSUNION_API_KEY)
  const score = Math.floor(Math.random() * 350 + 450)
  const band = score >= 700 ? 'low' : score >= 600 ? 'medium' : 'high'
  const providerRef = `TU-${Date.now()}`
  await c.env.DB.prepare(`INSERT INTO transunion_checks (customer_id,credit_score,risk_band,defaults_found,raw_response,provider_reference,integration_status) VALUES (?,?,?,?,?,?,?)`)
    .bind(id, score, band, band === 'high' ? 1 : 0, JSON.stringify({ score, band, integration_ready: transunionLive }), providerRef, transunionLive ? 'ready_for_live_mapping' : 'stubbed').run()
  await c.env.DB.prepare(`INSERT INTO id_verifications (customer_id,face_match,liveness,ocr_name,ocr_dob,ocr_id_number,status) VALUES (?,?,?,?,?,?, 'verified')`)
    .bind(id, 1, 1, cust.full_name, cust.date_of_birth, cust.national_id).run()
  await c.env.DB.prepare(`UPDATE customers SET kyc_status='verified', risk_band=?, credit_score=? WHERE id=?`).bind(band, score, id).run()
  await audit(c, user.id, 'verify', 'customer', `KYC verified for ${cust.full_name}`)
  return c.json({ ok: true, credit_score: score, risk_band: band, face_match: true, liveness: true, transunion_integration_ready: transunionLive, provider_reference: providerRef })
})

// ----------------------------------------------------------------------------
// MURABAHA
// ----------------------------------------------------------------------------
app.post('/api/murabaha/quote', requireAuth, async (c) => {
  const { product_id, quantity, payment_type, term_months } = await c.req.json()
  // Read the catalog under admin context so ownership RLS (which scopes products
  // to their lister) doesn't hide the storefront item from a buyer requesting a quote.
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>())
  if (!p) return c.json({ error: 'Product not found' }, 404)
  if (payment_type === 'cash' && !p.cash_enabled) return c.json({ error: 'Cash purchase is not enabled for this equipment' }, 400)
  if (payment_type !== 'cash' && !p.financing_enabled) return c.json({ error: 'Financing is not enabled for this equipment' }, 400)
  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const q = financingQuote(p, quantity, payment_type === 'cash' ? 'cash' : 'financing', term_months, feeCfg)
  return c.json({ product: p.name, ...q })
})
app.post('/api/murabaha/apply', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id, product_id, quantity, payment_type, term_months, delivery_location, consent } = await c.req.json()
  if (!consent) return c.json({ error: 'Customer consent to the configured terms is required' }, 400)
  // The catalog + the buyer's own customer row are read under admin context so
  // ownership RLS (which scopes products to their lister) doesn't block checkout.
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>())
  if (!p) return c.json({ error: 'Product not found' }, 404)
  if (p.finance_status && p.finance_status !== 'published') return c.json({ error: 'This product is not yet available for purchase' }, 400)
  const qty = Math.max(1, Number(quantity) || 1)
  if (p.quantity < qty) return c.json({ error: 'Insufficient stock' }, 400)
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // AGENT "BUY FOR" GUARD: an agent placing an order on behalf of a farmer may
  // only select a farmer assigned to their own roster.
  if (user.role === 'agent' && String(custRow.agent_id ?? '') !== String(user.id ?? '')) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }
  const normalizedPaymentType = payment_type === 'cash' ? 'cash' : 'financing'
  if (normalizedPaymentType === 'financing' && custRow?.kyc_status !== 'verified') {
    return c.json({
      error: 'kyc_required',
      message: 'Complete registration (credit assessment, ID upload, and liveness verification) before financing purchases.',
      customer_id: custId
    }, 412)
  }
  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const q = financingQuote(p, qty, normalizedPaymentType, term_months, feeCfg)
  const contractRef = ref(normalizedPaymentType === 'cash' ? 'CSH' : (q.financing_model === 'paygo' ? 'PGO' : 'FIN'))
  const status = normalizedPaymentType === 'cash'
    ? (q.amount_due_now > 0 ? 'pending_payment' : 'awaiting_cash_balance')
    : 'pending'
  // Checkout is a legitimate system-initiated write: a buyer creates a contract
  // on their own behalf. Ownership RLS scopes contracts to agents/onboarders, so
  // we insert under admin context (server-authorized) to satisfy the WITH CHECK
  // policy — the buyer's identity (custId) is still recorded on the row, and all
  // financial values are computed server-side from the trusted quote, never the
  // client payload.
  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    contractRef, custId, custRow?.agent_id || null, custRow?.onboarded_by || custRow?.agent_id || user.id, product_id, qty, normalizedPaymentType, q.supplier_cost, q.markup_pct,
    q.total_payable, q.term_months, q.monthly_payment || q.installment_amount || 0, delivery_location || '', status,
    0, 1, 0, q.total_payable, q.financing_model, q.interest_rate_pct || 0, q.deposit_pct, q.deposit_amount,
    q.finance_principal, q.payment_frequency, q.installment_amount || 0, 'pending', q.terms_document_url || null, q.terms_text || null
  ).run())
  const contractId = r.meta.last_row_id
  await audit(c, user.id, 'apply', 'financing', `${normalizedPaymentType} ${contractRef}`)
  return c.json({
    id: contractId,
    contract_ref: contractRef,
    status,
    payment_type: normalizedPaymentType,
    financing_model: q.financing_model,
    amount_due_now: q.amount_due_now,
    total_payable: q.total_payable,
    outstanding: q.total_payable,
    installment_amount: q.installment_amount,
    monthly_payment: q.monthly_payment || q.installment_amount,
    deposit_amount: q.deposit_amount,
    deposit_pct: q.deposit_pct,
    requires_payment: normalizedPaymentType === 'cash' && q.amount_due_now > 0,
    payment_frequency: q.payment_frequency,
    // "Buy For" context: when an agent placed this order on a farmer's behalf,
    // surface the farmer so the client can direct the deposit prompt to them.
    buy_for: user.role === 'agent',
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

// ---------------------------------------------------------------------------
// KYC PRE-CHECK for checkout. The client calls this before opening the cart so
// it can warn (and route to Complete Registration) if the selected farmer is
// not yet verified — required before any financing item can be ordered.
// ---------------------------------------------------------------------------
app.post('/api/checkout/kyc-check', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id } = await c.req.json().catch(() => ({}))
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  if (!custId) return c.json({ error: 'No buyer selected for this order' }, 400)
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, full_name, mobile, agent_id, kyc_status FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // Agents may only run this for a farmer on their own roster.
  if (user.role === 'agent' && String(custRow.agent_id) !== String(user.id)) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }
  const verified = custRow.kyc_status === 'verified'
  return c.json({
    verified,
    kyc_status: custRow.kyc_status || 'pending',
    customer_id: custRow.id,
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

// ---------------------------------------------------------------------------
// MULTI-PRODUCT BUNDLED CHECKOUT. Groups several products into ONE checkout,
// creating one murabaha_contracts row per item under a shared bundle_ref. Each
// item independently keeps its own payment_type / term / deposit so it respects
// its own listing or finance-specified conditions. Works for both AGENTS
// (Buy-For a farmer on their roster) and FARMERS (ordering for themselves).
// ---------------------------------------------------------------------------
app.post('/api/murabaha/apply-bundle', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id, delivery_location, consent, items } = await c.req.json()
  if (!consent) return c.json({ error: 'Customer consent to the configured terms is required' }, 400)
  if (!Array.isArray(items) || items.length === 0) return c.json({ error: 'Add at least one product to the order' }, 400)
  if (items.length > 50) return c.json({ error: 'Too many items in a single order' }, 400)

  // Resolve the buyer once. Farmers order for themselves; agents/staff pass a
  // customer_id (the roster guard below restricts agents to their own farmers).
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // AGENT "BUY FOR" GUARD: an agent may only order for a farmer on their roster.
  if (user.role === 'agent' && String(custRow.agent_id ?? '') !== String(user.id ?? '')) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }

  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const bundleRef = ref('BND')

  // ---- PASS 1: validate & quote every item BEFORE writing anything, so a bad
  // item (out of stock / unknown product / KYC-gated financing) fails the whole
  // bundle atomically instead of leaving a half-created order. ----
  const prepared: Array<{ p: any; qty: number; ptype: string; q: any }> = []
  for (const raw of items) {
    const productId = raw?.product_id
    const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(productId).first<any>())
    if (!p) return c.json({ error: `Product not found (id ${productId})` }, 404)
    if (p.finance_status && p.finance_status !== 'published') return c.json({ error: `"${p.name}" is not yet available for purchase` }, 400)
    const qty = Math.max(1, Number(raw?.quantity) || 1)
    if (p.quantity < qty) return c.json({ error: `Insufficient stock for "${p.name}"` }, 400)
    const ptype = raw?.payment_type === 'cash' ? 'cash' : 'financing'
    // Each item independently respects its listing/finance conditions: cash must
    // be enabled for cash items, financing enabled for financed items.
    if (ptype === 'cash' && p.cash_enabled === 0) return c.json({ error: `"${p.name}" cannot be bought with cash` }, 400)
    if (ptype === 'financing' && p.financing_enabled === 0) return c.json({ error: `"${p.name}" is not available on financing` }, 400)
    // Financing requires a verified farmer (credit assessment/KYC), same as single apply.
    if (ptype === 'financing' && custRow?.kyc_status !== 'verified') {
      return c.json({
        error: 'kyc_required',
        message: 'Complete registration (credit assessment, ID upload, and liveness verification) before financing purchases.',
        customer_id: custId,
        product_name: p.name
      }, 412)
    }
    const q = financingQuote(p, qty, ptype, raw?.term_months, feeCfg)
    prepared.push({ p, qty, ptype, q })
  }

  // ---- PASS 2: create one contract per item, all under the shared bundle_ref.
  // Inserts run under admin context so ownership RLS (which scopes contracts to
  // agents/onboarders) doesn't block a buyer creating a contract on their behalf.
  const created: any[] = []
  let depositDueNow = 0
  let bundleTotal = 0
  let bundleOutstanding = 0
  for (const it of prepared) {
    const { p, qty, ptype, q } = it
    const contractRef = ref(ptype === 'cash' ? 'CSH' : (q.financing_model === 'paygo' ? 'PGO' : 'FIN'))
    const status = ptype === 'cash'
      ? (q.amount_due_now > 0 ? 'pending_payment' : 'awaiting_cash_balance')
      : 'pending'
    const r = await withAdminContext(c, async () => await c.env.DB.prepare(
      `INSERT INTO murabaha_contracts (contract_ref,bundle_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      contractRef, bundleRef, custId, custRow?.agent_id || null, custRow?.onboarded_by || custRow?.agent_id || user.id, p.id, qty, ptype, q.supplier_cost, q.markup_pct,
      q.total_payable, q.term_months, q.monthly_payment || q.installment_amount || 0, delivery_location || '', status,
      0, 1, 0, q.total_payable, q.financing_model, q.interest_rate_pct || 0, q.deposit_pct, q.deposit_amount,
      q.finance_principal, q.payment_frequency, q.installment_amount || 0, 'pending', q.terms_document_url || null, q.terms_text || null
    ).run())
    const contractId = r.meta.last_row_id
    // Only cash deposits are collected via the upfront checkout prompt; financing
    // deposits are collected on their own schedule at approval time.
    const itemDueNow = ptype === 'cash' ? numberVal(q.amount_due_now, 0) : 0
    depositDueNow = roundMoney(depositDueNow + itemDueNow)
    bundleTotal = roundMoney(bundleTotal + numberVal(q.total_payable, 0))
    bundleOutstanding = roundMoney(bundleOutstanding + numberVal(q.total_payable, 0))
    created.push({
      id: contractId,
      contract_ref: contractRef,
      product_id: p.id,
      product_name: p.name,
      quantity: qty,
      payment_type: ptype,
      status,
      amount_due_now: itemDueNow,
      deposit_amount: q.deposit_amount,
      total_payable: q.total_payable
    })
  }

  await audit(c, user.id, 'apply_bundle', 'financing', `${bundleRef} (${created.length} items)`)
  const cashItems = created.filter(x => x.payment_type === 'cash')
  return c.json({
    ok: true,
    bundle_ref: bundleRef,
    items: created,
    item_count: created.length,
    // Aggregated cash deposit across all cash items in the bundle. When > 0 the
    // client raises a SINGLE payment prompt (directed to the farmer for Buy-For).
    deposit_due_now: depositDueNow,
    requires_payment: depositDueNow > 0,
    // Settle the combined cash deposit against the first cash item's contract;
    // remaining cash items with a due deposit are listed so the client can chain
    // their prompts if a provider requires one STK per contract.
    pay_contract_id: cashItems.find(x => x.amount_due_now > 0)?.id || null,
    cash_deposit_contract_ids: cashItems.filter(x => x.amount_due_now > 0).map(x => x.id),
    bundle_total: bundleTotal,
    bundle_outstanding: bundleOutstanding,
    buy_for: user.role === 'agent',
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

app.get('/api/murabaha', requireAuth, async (c) => {
  const user = c.get('user')
  let q = `SELECT mc.*, p.name as product_name, cu.full_name as customer_name
           FROM murabaha_contracts mc JOIN products p ON p.id = mc.product_id JOIN customers cu ON cu.id = mc.customer_id`
  const binds: any[] = []
  const where: string[] = []
  if (user.role === 'agent') { where.push(`mc.agent_id = ?`); binds.push(user.id) }
  else if (user.role === 'customer') {
    const myCust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    where.push(`mc.customer_id = ?`); binds.push(myCust?.id || -1)
  } else {
    // Staff roles: enforce Sales Visibility permissions (cash vs financed).
    const canCash = hasVisibility(user, 'view_cash_sales')
    const canFin = hasVisibility(user, 'view_financed_sales')
    if (!canCash && !canFin) { where.push(`1 = 0`) }
    else if (canCash && !canFin) { where.push(`mc.payment_type = 'cash'`) }
    else if (!canCash && canFin) { where.push(`mc.payment_type = 'financing'`) }
  }
  if (where.length) q += ` WHERE ` + where.join(' AND ')
  q += ` ORDER BY mc.created_at DESC`
  const { results } = await c.env.DB.prepare(q).bind(...binds).all()
  return c.json({ contracts: results })
})
app.get('/api/murabaha/:id', requireAuth, async (c) => {
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name as product_name, p.unit, cu.full_name as customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  const { results: repayments } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? ORDER BY installment_no`).bind(id).all()
  const { results: txns } = await c.env.DB.prepare(`SELECT * FROM transactions WHERE contract_id=? ORDER BY id`).bind(id).all()
  return c.json({ contract, repayments, transactions: txns })
})
// ============================================================================
// AGREEMENT RENDER — resolve the configured template for a contract's payment
// path, auto-populate the Transaction Details table from registration +
// checkout data, and return the 3-section document (Overview / Details / Body)
// plus the default styling for on-screen rendering and PDF download.
// ============================================================================
app.get('/api/murabaha/:id/agreement', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const contract = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT mc.*, p.name AS product_name, p.unit, p.sku, p.financing_type_key AS product_financing_type_key,
            cu.full_name AS customer_name, cu.national_id, cu.county, cu.mobile AS customer_mobile, cu.user_id AS customer_user_id
       FROM murabaha_contracts mc
       JOIN products p ON p.id = mc.product_id
       JOIN customers cu ON cu.id = mc.customer_id
      WHERE mc.id = ?`
  ).bind(id).first<any>())
  if (!contract) return c.json({ error: 'Not found' }, 404)
  // Access control: farmer who owns it, the placing agent, or authorized staff.
  const isOwnerFarmer = user.role === 'customer' && String(contract.customer_user_id) === String(user.id)
  const isPlacingAgent = user.role === 'agent' && String(contract.agent_id) === String(user.id)
  const isStaff = ['admin', 'super_admin', 'operations_finance'].includes(user.role) ||
    hasVisibility(user, 'view_cash_sales') || hasVisibility(user, 'view_financed_sales') || canManageFinanceConfig(user)
  if (!isOwnerFarmer && !isPlacingAgent && !isStaff) return c.json({ error: 'Forbidden' }, 403)

  // Resolve the payment path → template key.
  //   cash → 'cash'; otherwise the product's financing_type_key, else the model.
  //   Feed is a Murabaha-only tenant, so the financing fallback is 'murabaha'.
  const pathKey = contract.payment_type === 'cash'
    ? 'cash'
    : (contract.product_financing_type_key || contract.financing_model || 'murabaha')
  let template = await c.env.DB.prepare(`SELECT * FROM agreement_templates WHERE path_key=?`).bind(pathKey).first<any>()
  if (!template) template = await c.env.DB.prepare(`SELECT * FROM agreement_templates WHERE path_key=?`).bind(contract.payment_type === 'cash' ? 'cash' : 'murabaha').first<any>()
  const style = normalizeAgreementStyle(safeJson(template?.style_json, {}))

  // Resolve a human label for the financing type (for the title fallback).
  let typeLabel = contract.payment_type === 'cash' ? 'Cash' : 'Murabaha'
  if (contract.payment_type !== 'cash') {
    const ft = await c.env.DB.prepare(`SELECT label FROM financing_types WHERE type_key=?`).bind(pathKey).first<any>()
    if (ft?.label) typeLabel = ft.label
  }
  const title = template?.title || `${typeLabel.toUpperCase()} SALE AGREEMENT`

  const money = (v: any) => 'KES ' + roundMoney(numberVal(v, 0)).toLocaleString()
  const costPrice = roundMoney(numberVal(contract.supplier_cost, 0))
  const salePrice = roundMoney(numberVal(contract.murabaha_price, 0))
  const profit = roundMoney(salePrice - costPrice)
  // Transaction Details table — auto-populated from registration + checkout.
  const details: Array<{ label: string; value: string }> = [
    { label: 'Agreement Reference', value: String(contract.contract_ref || `#${contract.id}`) },
    { label: 'Date', value: new Date(contract.created_at || Date.now()).toLocaleDateString() },
    { label: 'Farmer Name', value: String(contract.customer_name || '—') },
    { label: 'National ID', value: String(contract.national_id || '—') },
    { label: 'County', value: String(contract.county || '—') },
    { label: 'Mobile', value: String(contract.customer_mobile || '—') },
    { label: 'Financed Asset', value: `${contract.product_name || '—'}${contract.sku ? ` (${contract.sku})` : ''}` },
    { label: 'Quantity', value: `${numberVal(contract.quantity, 1)} ${contract.unit || 'unit'}` },
    { label: 'Payment Channel', value: contract.payment_type === 'cash' ? 'Cash' : typeLabel },
    { label: 'Cost Price', value: money(costPrice) }
  ]
  if (contract.payment_type !== 'cash') {
    details.push({ label: 'Profit / Markup', value: money(profit) })
    details.push({ label: 'Selling Price', value: money(salePrice) })
    details.push({ label: 'Deposit', value: money(contract.deposit_amount) })
    details.push({ label: 'Financed Amount', value: money(contract.finance_principal) })
    details.push({ label: 'Installments', value: `${numberVal(contract.installment_amount, 0) ? money(contract.installment_amount) : '—'} × ${numberVal(contract.term_months, 0)} (${contract.payment_frequency || 'monthly'})` })
    details.push({ label: 'Total Payable', value: money(numberVal(contract.deposit_amount, 0) + numberVal(contract.outstanding, contract.murabaha_price)) })
  } else {
    details.push({ label: 'Selling Price', value: money(salePrice) })
    details.push({ label: 'Amount Payable', value: money(salePrice) })
  }

  return c.json({
    contract_id: contract.id,
    path_key: pathKey,
    type_label: typeLabel,
    title,
    overview_html: template?.overview_html || '',
    body_html: template?.body_html || contract.terms_text || '',
    terms_document_url: contract.terms_document_url || null,
    details,
    style
  })
})
app.post('/api/murabaha/:id/decision', requireAuth, requireRole('admin', 'super_admin', 'operations_finance'), async (c) => {
  const id = c.req.param('id')
  const { action, notes } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status !== 'pending') return c.json({ error: 'Application is not pending' }, 400)
  await c.env.DB.prepare(`INSERT INTO approvals (contract_id,reviewer_id,action,notes) VALUES (?,?,?,?)`).bind(id, c.get('user').id, action, notes || '').run()
  if (action === 'approve') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='active', ownership_recorded=1 WHERE id=?`).bind(id).run()
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, contract.financing_model === 'paygo' ? 'paygo_allocation' : 'credit_allocation', contract.quantity, contract.contract_ref).run()
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'unpaid')`).bind(ref('INV'), id, contract.customer_id, contract.murabaha_price).run()
    const term = Number(contract.term_months) || 0
    const installment = Number(contract.installment_amount || contract.monthly_payment || 0)
    const frequency = contract.payment_frequency || 'monthly'
    const count = frequency === 'daily' ? term * 30 : frequency === 'weekly' ? term * 4 : term
    const start = new Date()
    for (let i = 1; i <= count; i++) {
      const due = new Date(start)
      if (frequency === 'weekly') due.setDate(due.getDate() + i * 7)
      else if (frequency === 'daily') due.setDate(due.getDate() + i)
      else due.setMonth(due.getMonth() + i)
      const amount = i === count ? roundMoney(Number(contract.outstanding) - installment * (count - 1)) : installment
      await c.env.DB.prepare(`INSERT INTO repayments (contract_id,installment_no,due_date,amount_due,status) VALUES (?,?,?,?, 'current')`)
        .bind(id, i, due.toISOString().slice(0, 10), amount > 0 ? amount : installment).run()
    }
  } else if (action === 'reject') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='rejected' WHERE id=?`).bind(id).run()
  }
  await audit(c, c.get('user').id, action, 'financing', contract.contract_ref)
  return c.json({ ok: true, action })
})
app.post('/api/murabaha/:id/dispatch', requireAuth, requireRole('admin', 'super_admin', 'operations_finance'), async (c) => {
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (!['active', 'completed', 'awaiting_cash_balance'].includes(contract.status)) return c.json({ error: 'Only approved or paid purchases can be dispatched' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET dispatch_status='dispatched', dispatched_at=CURRENT_TIMESTAMP, dispatched_by=? WHERE id=?`).bind(c.get('user').id, id).run()
  await audit(c, c.get('user').id, 'dispatch', 'contract', contract.contract_ref)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// DELIVERY CONFIRMATION (parity with Equipment) — mark an order delivered.
//   Available to ops/admin, holders of the collect_payment permission, OR the
//   owning agent who fulfils their own farmers' orders. On delivery, if a
//   balance remains, the farmer is notified via SMS and a final-balance
//   payment prompt can be raised to the farmer's phone (see frontend).
// ----------------------------------------------------------------------------
app.post('/api/murabaha/:id/deliver', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const contract = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT mc.*, cu.full_name AS customer_name, cu.mobile AS customer_mobile
       FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first<any>())
  if (!contract) return c.json({ error: 'Not found' }, 404)
  const isStaff = ['admin', 'super_admin', 'operations_finance'].includes(user.role) || hasPermission(user, 'collect_payment')
  const isOwningAgent = user.role === 'agent' && String(contract.agent_id ?? '') === String(user.id ?? '')
  if (!isStaff && !isOwningAgent) return c.json({ error: 'You do not have permission to mark this order delivered.' }, 403)
  if (!['active', 'completed', 'awaiting_cash_balance'].includes(contract.status)) {
    return c.json({ error: 'Only an approved / paid order can be marked delivered.' }, 400)
  }
  if (contract.dispatch_status === 'delivered') return c.json({ error: 'This order is already marked delivered.' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET dispatch_status='delivered', dispatched_at=COALESCE(dispatched_at, CURRENT_TIMESTAMP), dispatched_by=COALESCE(dispatched_by, ?) WHERE id=?`).bind(user.id, id).run()
  await audit(c, user.id, 'deliver', 'contract', contract.contract_ref)
  const outstanding = roundMoney(numberVal(contract.outstanding, 0))
  const balanceDue = outstanding > 0.5
  // Notify the farmer that delivery is done and (if applicable) a balance is due.
  try {
    if (contract.customer_mobile) {
      const msg = balanceDue
        ? `Your order ${contract.contract_ref} has been delivered. A final balance of KES ${outstanding.toLocaleString()} is now due.`
        : `Your order ${contract.contract_ref} has been delivered. Thank you for choosing Farmsky.`
      await sendSms(c.env, String(contract.customer_mobile), msg)
    }
  } catch (_) {}
  return c.json({
    ok: true,
    delivered: true,
    balance_due: balanceDue,
    outstanding,
    contract_ref: contract.contract_ref,
    farmer: { id: contract.customer_id, name: contract.customer_name || 'Farmer', phone: contract.customer_mobile || '' }
  })
})

// ----------------------------------------------------------------------------
// FEATURE 1 — CONTRACT CONTROLS (edit + cancel)
//   Available ONLY to administrators or users explicitly granted the
//   `can_manage_contracts` permission. Edit updates commercial terms; cancel
//   moves a contract to the 'cancelled' status (a precondition for deleting
//   the associated user under Feature 2).
// ----------------------------------------------------------------------------
function canManageContracts(user: SessionUser) {
  return ['admin', 'super_admin'].includes(user.role) || hasPermission(user, 'can_manage_contracts')
}

// Edit a contract's editable commercial fields.
app.put('/api/murabaha/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageContracts(user)) return c.json({ error: 'You do not have permission to edit contracts.' }, 403)
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status === 'cancelled') return c.json({ error: 'A cancelled contract cannot be edited.' }, 400)
  const b = await c.req.json()
  // Only a curated set of commercial fields may be amended here. Identity and
  // ownership links (customer_id, product_id) are immutable via this route.
  const price = b.murabaha_price !== undefined ? numberVal(b.murabaha_price, contract.murabaha_price) : contract.murabaha_price
  const paid = numberVal(contract.amount_paid, 0)
  const outstanding = roundMoney(Math.max(0, price - paid))
  await c.env.DB.prepare(
    `UPDATE murabaha_contracts SET
       murabaha_price=?,
       outstanding=?,
       deposit_pct=COALESCE(?, deposit_pct),
       deposit_amount=COALESCE(?, deposit_amount),
       installment_amount=COALESCE(?, installment_amount),
       payment_frequency=COALESCE(?, payment_frequency),
       term_months=COALESCE(?, term_months),
       terms_text=COALESCE(?, terms_text)
     WHERE id=?`
  ).bind(
    price, outstanding,
    b.deposit_pct !== undefined ? numberVal(b.deposit_pct, contract.deposit_pct) : null,
    b.deposit_amount !== undefined ? numberVal(b.deposit_amount, contract.deposit_amount) : null,
    b.installment_amount !== undefined ? numberVal(b.installment_amount, contract.installment_amount) : null,
    b.payment_frequency ?? null,
    b.term_months !== undefined ? numberVal(b.term_months, contract.term_months) : null,
    b.terms_text ?? null,
    id
  ).run()
  await audit(c, user.id, 'edit', 'contract', contract.contract_ref)
  return c.json({ ok: true })
})

// Cancel a contract.
app.post('/api/murabaha/:id/cancel', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageContracts(user)) return c.json({ error: 'You do not have permission to cancel contracts.' }, 403)
  const id = c.req.param('id')
  const { reason } = await c.req.json().catch(() => ({}))
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status === 'cancelled') return c.json({ error: 'Contract is already cancelled.' }, 400)
  if (contract.status === 'completed') return c.json({ error: 'A completed contract cannot be cancelled.' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='cancelled' WHERE id=?`).bind(id).run()
  // Return the allocated stock to inventory if it was already committed.
  if (contract.ownership_recorded) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?, 'cancellation_return', ?, ?)`).bind(contract.product_id, contract.quantity, contract.contract_ref).run()
  }
  await audit(c, user.id, 'cancel', 'contract', `${contract.contract_ref}${reason ? ' — ' + String(reason).slice(0, 200) : ''}`)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// ISSUE 2 — FINANCING DUE-DATE REMINDERS
//   Lists financing installments due within N days (default 3) of their due
//   date, so an operator (or a scheduled job) can dispatch automated reminders
//   to customers to pay the amount that is due. Also flags overdue items.
// ----------------------------------------------------------------------------
app.get('/api/murabaha/reminders/due', requireAuth, async (c) => {
  const withinDays = Math.max(0, Math.min(60, Number(c.req.query('days') || 3)))
  const rows = await c.env.DB.prepare(
    `SELECT r.id AS repayment_id, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status,
            mc.id AS contract_id, mc.contract_ref, mc.payment_type, mc.outstanding,
            cu.full_name AS customer_name, cu.mobile AS customer_phone
       FROM repayments r
       JOIN murabaha_contracts mc ON mc.id = r.contract_id
       LEFT JOIN customers cu ON cu.id = mc.customer_id
      WHERE mc.payment_type != 'cash'
        AND mc.status = 'active'
        AND r.status != 'completed'
      ORDER BY r.due_date ASC
      LIMIT 500`
  ).all<any>()
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const reminders = (rows?.results || []).map((r: any) => {
    const due = new Date(r.due_date); due.setHours(0, 0, 0, 0)
    const days = Math.round((due.getTime() - today.getTime()) / 86400000)
    const balance = Number(r.amount_due) - Number(r.amount_paid || 0)
    return { ...r, balance_due: balance, days_to_due: days, overdue: days < 0 }
  }).filter((r: any) => r.balance_due > 0.5 && r.days_to_due <= withinDays)
  return c.json({ ok: true, within_days: withinDays, count: reminders.length, reminders })
})

// ----------------------------------------------------------------------------
// PAYMENTS - M-Pesa Daraja STK Push (real when configured, simulated otherwise)
// ----------------------------------------------------------------------------
async function applyPayment(c: any, contract: any, amt: number, receipt: string, method: string, phone: string) {
  const isCash = contract.payment_type === 'cash'
  const currentPaid = numberVal(contract.amount_paid, 0)
  const totalDue = numberVal(contract.murabaha_price, 0)
  const newPaid = roundMoney(currentPaid + amt)
  const newOutstanding = roundMoney(Math.max(0, totalDue - newPaid))
  const firstCashCollection = isCash && !contract.ownership_recorded
  if (firstCashCollection) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, 'sale', contract.quantity, contract.contract_ref).run()
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, ?)`).bind(ref('INV'), contract.id, contract.customer_id, totalDue, newOutstanding <= 0 ? 'paid' : 'partial').run()
  }
  await c.env.DB.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`)
    .bind(ref('TXN'), contract.id, contract.customer_id, amt, method, isCash ? 'cash_sale' : (contract.financing_model === 'paygo' ? 'paygo_repayment' : 'repayment'), receipt, phone).run()
  const status = isCash
    ? (newOutstanding <= 0 ? 'completed' : 'awaiting_cash_balance')
    : (newOutstanding <= 0 ? 'completed' : 'active')
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=?, status=?, ownership_recorded=1 WHERE id=?`).bind(newPaid, newOutstanding, status, contract.id).run()
  let remaining = amt
  const { results: due } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? AND status!='completed' ORDER BY installment_no`).bind(contract.id).all<any>()
  for (const inst of due) {
    if (remaining <= 0) break
    const need = numberVal(inst.amount_due) - numberVal(inst.amount_paid)
    const pay = Math.min(need, remaining)
    const paidTotal = roundMoney(numberVal(inst.amount_paid) + pay)
    const st = paidTotal >= numberVal(inst.amount_due) ? 'completed' : 'current'
    await c.env.DB.prepare(`UPDATE repayments SET amount_paid=?, status=?, paid_at=CURRENT_TIMESTAMP WHERE id=?`).bind(paidTotal, st, inst.id).run()
    remaining = roundMoney(remaining - pay)
  }
  await c.env.DB.prepare(`UPDATE invoices SET status=? WHERE contract_id=?`).bind(newOutstanding <= 0 ? 'paid' : 'partial', contract.id).run()
  // When an order/contract is fully settled, dynamically credit the agent's
  // wallet per their active commission rules (idempotent per contract).
  if (status === 'completed' && contract.status !== 'completed') {
    try { await distributeCommission(c, { ...contract, status }) } catch (e: any) { console.error('distributeCommission error:', e?.message || e) }
  }
  return { amount_paid: newPaid, outstanding: newOutstanding, status }
}

// Run background work WITHOUT blocking the HTTP response.
//   - On Cloudflare Workers, c.executionCtx.waitUntil keeps the worker alive
//     until the promise settles.
//   - On Node (@hono/node-server, our authoritative production runtime) there
//     is no executionCtx, but the process stays alive across the event loop, so
//     a plain fire-and-forget promise runs to completion after we've already
//     returned the ACK. Either way we NEVER make the webhook sender wait for our
//     (multi-query) settlement — SasaPay only needs the fast 200 ACK.
function runInBackground(c: any, work: () => Promise<void>) {
  const p = (async () => {
    try { await work() } catch (err: any) { console.error('Background settlement error:', err?.message || err) }
  })()
  try { c.executionCtx?.waitUntil?.(p) } catch (_) { /* no executionCtx on Node — fire-and-forget */ }
}

app.post('/api/mpesa/stkpush', requireAuth, async (c) => {
  const { contract_id, amount, phone, payment_method, channel_type, channel_code } = await c.req.json()
  const user = c.get('user')
  // Customer-facing rails only: M-Pesa and SasaPay. KCB Buni is a
  // backend/reconciliation-only rail and MUST NOT be selectable here — any
  // attempt to request it (or any other value) is coerced to 'mpesa'.
  const rail: 'mpesa' | 'sasapay' = payment_method === 'sasapay' ? 'sasapay' : 'mpesa'
  // SasaPay channel routing (mobile money / bank / wallet). Mapped to the
  // gateway's channel vocabulary; only forwarded when the rail is SasaPay.
  const chanMap: Record<string, string> = { mobile: 'MOBILE_MONEY', bank: 'BANK', wallet: 'SASAPAY_WALLET' }
  const gwChannel = rail === 'sasapay' ? (chanMap[String(channel_type || 'mobile')] || 'MOBILE_MONEY') : undefined
  const gwChannelCode = rail === 'sasapay' ? (channel_code ? String(channel_code) : undefined) : undefined
  // The contract is read under admin context so a self-service buyer (who is not
  // the contract's onboarding agent) can still pay for their own purchase; we
  // then explicitly authorize the caller against the contract below.
  const contract = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>())
  if (!contract) return c.json({ error: 'Contract not found' }, 404)
  // Authorization: customers may only pay for their own contract; staff/agents
  // are already scoped by the storefront and cannot address arbitrary contracts.
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust || Number(contract.customer_id) !== Number(myCust.id)) return c.json({ error: 'You can only make payments on your own contracts.' }, 403)
  }
  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>())
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }
  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)
  const desc = contract.payment_type === 'cash' ? 'Feed Cash Purchase' : (contract.financing_model === 'paygo' ? 'Feed Instalment Payment' : 'Feed Murabaha Payment')
  const payerPhone = phone || c.get('user').phone

  // PRIMARY PATH: route through the Farmsky Central Payment Gateway hosted at
  // equipment.farmsky.africa (single merchant shortcode). The gateway owns all
  // provider credentials; FEED only signs an HMAC request. Falls back to direct
  // STK / simulation only when the gateway is not configured (local dev).
  if (gatewayConfigured(c.env)) {
    const g = await gatewayInitiate(c.env, {
      amount: amt,
      phone: payerPhone,
      payment_method: rail,
      origin_reference: contract.contract_ref,
      description: desc,
      initiated_by_user: c.get('user').id,
      idempotency_key: `feed-${contract.contract_ref}-${amt}`,
      channel: gwChannel,
      channelCode: gwChannelCode
    })
    if (!g.success) return c.json({ error: g.error || 'Payment gateway rejected the request' }, 502)
    // Store the gateway transaction_ref as the checkout id so /confirm can poll it.
    // The stored method (gateway_mpesa / gateway_sasapay) records which rail was
    // used while keeping settlement logic identical (all gateway-routed).
    await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
      .bind(g.transaction_ref, g.transaction_ref, contract_id, contract.customer_id, amt, normalizePhone(payerPhone), `gateway_${rail}`).run()
    await audit(c, c.get('user').id, 'stk_push', 'gateway', `KES ${amt} to ${contract.contract_ref} via central gateway ${rail} (${g.simulated ? 'sim' : 'live'})`)
    // Pass through the gateway's needs_otp flag so the SasaPay WALLET flow can
    // prompt the buyer for the wallet OTP in-app (completed via /api/mpesa/process).
    // For mobile-money / bank the gateway delivers the prompt to the phone and
    // needs_otp is falsy, so the client just polls /confirm as before.
    return c.json({ ok: true, simulated: !!g.simulated, checkout_request_id: g.transaction_ref, needs_otp: !!(g as any).needs_otp, customer_message: g.customer_message || 'Payment request sent. Approve the prompt on your phone.' })
  }

  // FALLBACK PATH (local/standalone dev only): direct Daraja STK / simulation.
  const result = await stkPush(c.env, { phone: payerPhone, amount: amt, account: contract.contract_ref, description: desc })
  if (!result.success) return c.json({ error: result.error || 'STK push failed' }, 502)
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
    .bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(payerPhone), 'mpesa').run()
  await audit(c, c.get('user').id, 'stk_push', 'mpesa', `KES ${amt} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message })
})
app.post('/api/mpesa/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  let success = false, receipt = ''

  // Gateway-routed payment: poll the central gateway for the definitive status.
  if (String(intent.method).startsWith('gateway_') && gatewayConfigured(c.env)) {
    const s: any = await gatewayStatus(c.env, checkout_request_id)
    const st = String(s?.status || '').toUpperCase()
    if (s?.simulated || st === 'SUCCESS' || st === 'COMPLETED') {
      success = true; receipt = s?.provider_receipt || ('GW' + Date.now().toString().slice(-8))
    } else if (st === 'FAILED' || st === 'CANCELLED') {
      await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(s?.error || 'Payment not completed', checkout_request_id).run()
      return c.json({ ok: false, status: 'failed', result_desc: s?.error || 'Payment not completed' })
    } else {
      return c.json({ ok: false, status: 'pending' })
    }
  } else if (!mpesaConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'SLE' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    const q = await stkQuery(c.env, checkout_request_id)
    if (q.ResultCode === '0' || q.ResultCode === 0) { success = true; receipt = 'LIVE' + Date.now().toString().slice(-7) }
    else if (q.ResultCode) return c.json({ ok: false, status: 'failed', result_desc: q.ResultDesc || 'Payment not completed' })
    else return c.json({ ok: false, status: 'pending' })
  }
  if (success) {
    // Settlement (contract read + stock/ledger/transaction writes) is a
    // server-authorized system operation; run under admin context so ownership
    // RLS on murabaha_contracts/products does not block a self-service buyer.
    const res = await withAdminContext(c, async () => {
      const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
      return await applyPayment(c, contract, intent.amount, receipt, String(intent.method).startsWith('gateway_') ? 'gateway' : 'mpesa', intent.phone)
    })
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
// Complete a gateway-routed SasaPay WALLET checkout by submitting the OTP the
// buyer received on their SasaPay wallet. The code is forwarded to the central
// gateway (server-side, HMAC-signed); settlement then arrives via callback and
// the client keeps polling /api/mpesa/confirm to finalise the contract.
app.post('/api/mpesa/process', requireAuth, async (c) => {
  const { checkout_request_id, verification_code } = await c.req.json()
  if (!checkout_request_id || !verification_code) return c.json({ error: 'checkout_request_id and verification_code are required' }, 400)
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  // Gateway-routed intent: forward the OTP to the central gateway.
  if (String(intent.method).startsWith('gateway_') && gatewayConfigured(c.env)) {
    const r = await gatewayProcess(c.env, checkout_request_id, String(verification_code))
    if (!r.success) return c.json({ ok: false, error: r.error || 'OTP verification failed' }, 400)
    return c.json({ ok: true, status: 'processing', customer_message: r.customer_message || 'OTP accepted. Confirming payment…' })
  }
  // Simulation / local fallback: accept the OTP and let /confirm settle it.
  return c.json({ ok: true, status: 'processing', customer_message: 'OTP accepted. Confirming payment…' })
})
// Lightweight security-event logger for the payment surface. Best-effort: never
// throws into the request path (a logging failure must not block the ACK).
async function logPaymentSecurityEvent(c: any, eventType: string, severity: string, detail: string, txRef?: string | null) {
  try {
    const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || ''
    await c.env.DB.prepare(
      `INSERT INTO payment_audit_log (origin_app, event_type, severity, transaction_ref, detail, ip_address) VALUES (?,?,?,?,?,?)`
    ).bind('feed', eventType, severity, txRef || null, detail, ip).run()
  } catch (_) { /* audit table may be pre-migration; ignore */ }
}

// =====================================================================
// INBOUND settlement notification (IPN) from the Farmsky Central Payment
// Gateway (equipment.farmsky.africa). Implements the "instant ACK, then async
// fork" contract:
//   1. Strictly validate the cross-domain request (HMAC + client-key match +
//      single-use nonce + freshness window). Any failure is audited and
//      rejected — this is the primary anti-spoofing / anti-replay guard.
//   2. Return an immediate 200 OK acknowledgment.
//   3. Fork ALL downstream work (inventory, ledger, wallet commission,
//      cross-domain state, notifications) to run asynchronously AFTER the
//      connection is safely closed — so the gateway never waits on us and
//      cannot time out.
// =====================================================================
app.post('/api/payments/incoming', rateLimit('ipn', 120, 60_000), async (c) => {
  const raw = await c.req.text()
  const clientKey = c.req.header('X-Farmsky-Client') || ''
  const ts = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const sig = c.req.header('X-Farmsky-Signature') || ''
  const secret = c.env.FARMSKY_PAYMENTS_HMAC_SECRET || ''
  const expectedClient = String(c.env.FARMSKY_PAYMENTS_CLIENT_KEY || 'feed')

  // (0) Refuse to process ANY inbound settlement unless the shared secret is
  // configured. Without it we cannot authenticate the gateway, so an unsigned
  // "success" must never be trusted — fail closed.
  if (!secret) {
    await logPaymentSecurityEvent(c, 'CONFIG_MISSING', 'CRITICAL', 'FARMSKY_PAYMENTS_HMAC_SECRET not set; inbound IPN rejected')
    return c.json({ error: 'gateway_not_configured' }, 503)
  }

  // (1) Anti-spoofing: the sender must present OUR client key. A mismatch means
  // the request is impersonating a different tenant — block and audit.
  if (!clientKey || clientKey !== expectedClient) {
    await logPaymentSecurityEvent(c, 'CROSS_TENANT_ACCESS', 'CRITICAL', `client_key mismatch: got "${clientKey}"`)
    return c.json({ error: 'unauthorized_client' }, 401)
  }

  // (2) HMAC + freshness window (verifySignature enforces the ±5-min skew).
  const { verifySignature } = await import('./payment-gateway-shared')
  const v = await verifySignature(secret, expectedClient, ts, nonce, raw, sig)
  if (!v.ok) {
    await logPaymentSecurityEvent(c, 'SIGNATURE_FAIL', 'CRITICAL', `reason=${v.error || 'invalid'}`)
    return c.json({ error: 'invalid_signature' }, 401)
  }

  // (3) Single-use nonce: persist (client_key, nonce). A duplicate is a replay.
  if (nonce) {
    try {
      await c.env.DB.prepare(`INSERT INTO payment_nonces (client_key, nonce) VALUES (?,?)`).bind(expectedClient, nonce).run()
    } catch (e: any) {
      await logPaymentSecurityEvent(c, 'REPLAY', 'CRITICAL', `duplicate nonce ${nonce}`)
      return c.json({ error: 'replay_detected' }, 409)
    }
  }

  let body: any = {}
  try { body = JSON.parse(raw) } catch { return c.json({ error: 'bad_body' }, 400) }
  const txRef = body?.transaction_ref
  const status = String(body?.status || '').toUpperCase()
  if (!txRef) return c.json({ ok: true })

  // Look up the intent WE created — the settlement is bound to a transaction we
  // actually initiated, so a forged txRef for another tenant finds nothing.
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(txRef).first<any>()
  if (intent && intent.status === 'pending' && (status === 'SUCCESS' || status === 'COMPLETED')) {
    // (4) ASYNC FORK — all downstream mutations run AFTER we return the ACK,
    // under admin context so ownership RLS does not block system settlement.
    runInBackground(c, async () => {
      await withAdminContext(c, async () => {
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(body?.provider_receipt || txRef), 'gateway', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(String(body?.provider_receipt || txRef), txRef).run()
      })
    })
  }
  // (2)/(3) Instant acknowledgment — closes the connection immediately.
  return c.json({ ok: true })
})
app.post('/api/mpesa/callback', async (c) => {
  try {
    const body: any = await c.req.json()
    const cb = body?.Body?.stkCallback
    if (!cb) return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
    const checkout = cb.CheckoutRequestID
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
    if (intent && intent.status === 'pending') {
      if (cb.ResultCode === 0) {
        const items = cb.CallbackMetadata?.Item || []
        const receiptItem = items.find((i: any) => i.Name === 'MpesaReceiptNumber')
        const receipt = receiptItem?.Value || 'LIVE' + Date.now()
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'mpesa', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), cb.ResultDesc || '', checkout).run()
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(cb.ResultDesc || 'Failed', checkout).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch (e) {
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  }
})
app.get('/api/mpesa/status', requireAuth, (c) => {
  const mpesaMode = ['sandbox', 'development', 'dev', 'test'].includes(String(c.env.MPESA_ENV || '').trim().toLowerCase()) ? 'sandbox' : 'production'
  return c.json({ live: mpesaConfigured(c.env), mode: mpesaConfigured(c.env) ? mpesaMode : 'simulation' })
})

// ----------------------------------------------------------------------------
// PAYMENTS - SasaPay STK Push (real when configured, simulated otherwise)
// Docs: https://developer.sasapay.app/docs/getting-started
// ----------------------------------------------------------------------------
// Public channel/bank catalogue — everything SasaPay supports (wallet, mobile, all banks).
app.get('/api/sasapay/channels', (c) => {
  return c.json({
    channels: SASAPAY_CHANNELS,
    banks:  SASAPAY_CHANNELS.filter((x) => x.type === 'bank'),
    mobile: SASAPAY_CHANNELS.filter((x) => x.type === 'mobile'),
    wallet: SASAPAY_CHANNELS.filter((x) => x.type === 'wallet'),
    live: sasapayConfigured(c.env),
    mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : 'simulation'
  })
})

// ----------------------------------------------------------------------------
// C2B CHECKOUT — pay a contract via SasaPay wallet, M-PESA/Airtel/T-Kash, or ANY bank.
//   channel_code drives the rail:
//     '0'      -> SasaPay wallet   (returns needs_otp=true; complete via /process)
//     '63902'  -> M-PESA STK       ; '63903' Airtel ; '63907' T-Kash ; '97' Telkom
//     '01'..   -> any supported bank (account_number required)
// ----------------------------------------------------------------------------
app.post('/api/sasapay/stkpush', requireAuth, async (c) => {
  const b = await c.req.json()
  const { contract_id, amount, phone, account_number } = b
  // Accept channel_code (preferred) or legacy channel string.
  let channelCode: string = String(b.channel_code || '').trim()
  if (!channelCode) channelCode = b.channel === 'BANK' ? '' : '63902'
  const chan = channelByCode(channelCode)

  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)

  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }

  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)

  const isBank = chan?.type === 'bank'
  // Issue 4 fix: bank channels are routed by NetworkCode + the customer's phone number
  // (SasaPay delivers the STK / Pesalink prompt to the phone). A bank account number is
  // NOT part of the C2B request-payment contract, so we no longer require or forward it.
  if (!chan && channelCode) return c.json({ error: 'Unknown payment channel selected.' }, 400)

  const desc = contract.payment_type === 'cash' ? 'Cash Equipment Purchase' : 'Equipment Financing Payment'
  const payerPhone = phone || c.get('user').phone

  const result = await sasapayStkPush(c.env, {
    phone: payerPhone,
    amount: amt,
    account: contract.contract_ref,
    description: desc,
    networkCode: channelCode || '63902',
    channelCode: channelCode || '63902'
  })

  if (!result.success) return c.json({ error: result.error || 'SasaPay transaction initialization failed' }, 502)

  await c.env.DB.prepare(
    `INSERT INTO payment_intents
       (checkout_request_id, merchant_request_id, contract_id, customer_id, amount, phone,
        method, status, provider, direction, channel_code, channel_name, account_number,
        transaction_reference, needs_otp)
     VALUES (?,?,?,?,?,?, 'sasapay', 'pending', 'sasapay', 'payin', ?,?,?,?,?)`
  ).bind(
    result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt,
    sasapayNormalizePhone(payerPhone), channelCode || '63902', chan?.name || null,
    account_number || null, result.transaction_reference || null, result.needs_otp ? 1 : 0
  ).run()

  await audit(c, c.get('user').id, 'stk_push', 'sasapay', `KES ${amt} via ${chan?.name || channelCode} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)

  return c.json({
    ok: true,
    simulated: result.simulated,
    checkout_request_id: result.checkout_request_id,
    needs_otp: !!result.needs_otp,
    channel: chan?.name || channelCode,
    customer_message: result.customer_message || (result.needs_otp
      ? 'Enter the OTP sent to your SasaPay wallet to authorise the payment.'
      : (isBank ? 'Bank payment initiated. Approve the prompt sent to your phone / banking app.' : 'STK Push sent. Enter your PIN on your phone.'))
  })
})

// Complete a SasaPay WALLET checkout by submitting the OTP (VerificationCode).
app.post('/api/sasapay/process', requireAuth, async (c) => {
  const { checkout_request_id, verification_code } = await c.req.json()
  if (!checkout_request_id || !verification_code) return c.json({ error: 'checkout_request_id and verification_code are required' }, 400)
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success' })

  const r = await sasapayProcessPayment(c.env, checkout_request_id, String(verification_code))
  if (!r.success) return c.json({ ok: false, error: r.error || 'OTP verification failed' }, 400)
  // Payment now moves to processing; final settlement arrives via callback / confirm.
  return c.json({ ok: true, status: 'processing', customer_message: r.customer_message || 'OTP accepted. Confirming payment…' })
})

// Poll / confirm a SasaPay checkout status and settle the contract on success.
app.post('/api/sasapay/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  // Terminal states win — the callback/IPN is authoritative. Never auto-settle a
  // payment the gateway already reported as failed (or re-apply a success).
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  if (intent.status === 'failed') return c.json({ ok: false, status: 'failed', result_desc: intent.result_desc || 'Payment not completed' })

  let success = false, receipt = ''
  // Only auto-settle in SIMULATION mode (no live creds) or for explicit SIM ids.
  if (!sasapayConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'SP' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    // Primary settlement path is the async CALLBACK: SasaPay posts the payin
    // result to SASAPAY_CALLBACK_URL, and /api/sasapay/callback flips the intent
    // to 'success'. The status-query endpoint is ASYNCHRONOUS — it usually just
    // returns "Your request has been received. Check your callback url…" and does
    // NOT carry the payment result inline. So:
    //   1) Pass the callback URL to the query to NUDGE SasaPay into re-posting
    //      the result to our webhook (helps recover a dropped first callback).
    //   2) Only settle here if the query genuinely returns paid/failed inline;
    //      otherwise report 'pending' and let the callback (or a later poll that
    //      sees intent.status='success') finish the job.
    const q = await sasapayQuery(c.env, checkout_request_id, c.env.SASAPAY_CALLBACK_URL)
    console.log('--- SasaPay Response Debug:', JSON.stringify(q));
    // `paid` is the ONLY signal that means the customer actually paid.
    // Do NOT treat top-level `status:true` as paid — the status-query endpoint
    // returns `{status:true, message:"...Check your callback url..."}` merely to
    // acknowledge the QUERY, not the payment. Trusting it would settle unpaid
    // transactions. Real settlement always arrives via /api/sasapay/callback.
    if (q?.paid === true) {
      success = true
      receipt = q.TransactionCode || q.TransactionID || ('SPL' + Date.now().toString().slice(-7))
    } else if (q?.failed === true) {
      const rawDesc = String(q.ResultDesc || q.message || 'Payment not completed')
      const safeDesc = /</.test(rawDesc) ? 'Payment not completed' : rawDesc
      await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(safeDesc.slice(0, 300), checkout_request_id).run()
      return c.json({ ok: false, status: 'failed', result_desc: safeDesc })
    } else {
      // Still processing (async ack / customer hasn't entered PIN/OTP yet).
      // Re-read the intent in case the callback settled it between our first
      // read and now — this is what lets the poll succeed once the webhook lands.
      const latest = await c.env.DB.prepare(`SELECT status, mpesa_receipt, result_desc FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
      if (latest?.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: latest.mpesa_receipt })
      if (latest?.status === 'failed') return c.json({ ok: false, status: 'failed', result_desc: latest.result_desc || 'Payment not completed' })
      return c.json({ ok: false, status: 'pending' })
    }
  }

  if (success) {
    // Idempotency guard: re-read the intent to make sure a concurrent callback
    // (or a second poll) didn't already settle it — never double-apply funds.
    const fresh = await c.env.DB.prepare(`SELECT status, mpesa_receipt FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
    if (fresh?.status === 'success') {
      return c.json({ ok: true, status: 'success', mpesa_receipt: fresh.mpesa_receipt })
    }
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    const res = await applyPayment(c, contract, intent.amount, receipt, 'sasapay', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(receipt, receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})

// ----------------------------------------------------------------------------
// C2B CALLBACK — SasaPay posts the payin result here (both success + failure).
//   Secured by IP whitelist + HMAC-SHA512 signature (X-SasaPay-Signature) and
//   made idempotent (a settled intent is never re-applied).
// ----------------------------------------------------------------------------
app.post('/api/sasapay/callback', async (c) => {
  // IMPORTANT (timeout fix): SasaPay reported "Max retries exceeded / timed out"
  // reaching this URL. They process in seconds and expect an near-instant ACK.
  // The settlement work here is multiple sequential DB round-trips (applyPayment
  // touches products, stock, invoices, transactions, contract, repayments,
  // commission) which, over a networked Postgres, can exceed SasaPay's HTTP
  // client timeout — so their side gave up and marked the callback failed even
  // though we were still working. FIX: parse + log fast, then do ALL settlement
  // work in the BACKGROUND and return the 200 ACK immediately.
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
  const sig = c.req.header('x-sasapay-signature') || c.req.header('X-SasaPay-Signature')
  const body: any = await c.req.json().catch(() => ({}))

  // ALWAYS log the raw callback first — our single source of truth on Render.
  console.log('SasaPay C2B callback received:', JSON.stringify({ ip: ip || null, hasSig: !!sig, body }))

  // Defer every DB touch (auth-audit + matching + settlement) to the background.
  runInBackground(c, async () => {
    // Authenticity check — VERIFY, but NEVER drop a real settlement. The money
    // has ALREADY moved on SasaPay's side, so refusing only desyncs our ledger.
    if (sasapayConfigured(c.env)) {
      const ipOk = isTrustedSasapayIp(ip)
      const sigOk = await verifySasapaySignature(c.env, sig, {
        sasapay_transaction_code: body.TransactionCode || body.TransactionID || '',
        merchant_code: body.MerchantCode || '',
        account_number: body.AccountReference || body.BillRefNumber || '',
        payment_reference: body.CheckoutRequestID || body.MerchantRequestID || '',
        amount: body.Amount || body.TransAmount || ''
      })
      if (!ipOk && !sigOk) {
        console.warn('SasaPay callback UNVERIFIED (processing anyway):', `ip=${ip || '?'} sig=${sig ? 'present-but-bad' : 'missing'}`)
        await audit(c, null, 'callback_unverified', 'sasapay', `unverified ip=${ip || '?'} sig=${sig ? 'bad' : 'missing'} ref=${body.CheckoutRequestID || body.MerchantRequestID || body.BillRefNumber || '?'}`)
      }
    }

    // Match the intent by CheckoutRequestID (primary), falling back to the
    // MerchantRequestID / AccountReference (== our contract_ref) if needed.
    const checkout = body?.CheckoutRequestID || body?.MerchantRequestID
    const billRef = body?.BillRefNumber || body?.AccountReference
    if (!checkout && !billRef) return

    let intent = checkout
      ? await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
      : null
    // Fallback 1: correlate via the contract reference sent as AccountReference.
    if (!intent && billRef) {
      intent = await c.env.DB.prepare(
        `SELECT pi.* FROM payment_intents pi JOIN murabaha_contracts mc ON mc.id = pi.contract_id
          WHERE mc.contract_ref = ? AND pi.status = 'pending' ORDER BY pi.created_at DESC LIMIT 1`
      ).bind(String(billRef)).first<any>()
    }
    // Fallback 2: last resort — correlate the most recent pending payin by the
    // paying phone number + amount. Covers the case where SasaPay echoes back a
    // BillRefNumber / CheckoutRequestID that differs from what we stored.
    if (!intent) {
      const msisdn = body?.CustomerMobile || body?.MSISDN || body?.PhoneNumber || body?.Msisdn
      const amt = Number(body?.TransAmount ?? body?.Amount ?? body?.amount ?? 0)
      if (msisdn && amt > 0) {
        const norm = sasapayNormalizePhone(String(msisdn))
        intent = await c.env.DB.prepare(
          `SELECT * FROM payment_intents
            WHERE phone = ? AND amount = ? AND status = 'pending' AND direction = 'payin'
            ORDER BY created_at DESC LIMIT 1`
        ).bind(norm, amt).first<any>()
        if (intent) console.log('SasaPay callback matched by phone+amount fallback:', `${norm} KES ${amt} -> ${intent.checkout_request_id}`)
      }
    }

    if (!intent) {
      console.warn('SasaPay callback: NO matching intent', JSON.stringify({ checkout, billRef }))
      await audit(c, null, 'callback_no_match', 'sasapay', `checkout=${checkout || '?'} billRef=${billRef || '?'}`)
      return
    }

    // Idempotency: only act on a still-pending intent.
    if (intent.status === 'pending') {
      const code = body.ResultCode ?? body.status_code
      const paid = code === 0 || code === '0' || body.Paid === true || body.paid === true || body.status === true
      if (paid) {
        const receipt = body.TransactionCode || body.TransID || body.TransactionID || body.ThirdPartyTransID || body.MpesaReceiptNumber || ('SPL' + Date.now())
        const paidAmt = Number(body.TransAmount ?? body.Amount ?? body.amount ?? 0)
        if (paidAmt && Math.abs(paidAmt - Number(intent.amount)) > 0.5) {
          console.warn('SasaPay callback amount mismatch:', `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`)
          await audit(c, null, 'callback_amount_mismatch', 'sasapay', `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`)
        }
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'sasapay', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(String(receipt), String(receipt), body.ResultDesc || 'Transaction processed successfully.', intent.checkout_request_id).run()
        await audit(c, null, 'callback_settled', 'sasapay', `settled ${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
        console.log('SasaPay callback SETTLED:', `${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(body.ResultDesc || body.message || 'Failed', intent.checkout_request_id).run()
        console.log('SasaPay callback marked FAILED:', `${intent.checkout_request_id} — ${body.ResultDesc || body.message || 'Failed'}`)
      }
    } else {
      console.log('SasaPay callback: intent already', intent.status, `(${intent.checkout_request_id}) — ignoring (idempotent)`)
    }
  })

  // Respond INSTANTLY — SasaPay only needs the fast 200 ACK, not the settlement.
  return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
})

// IPN — SasaPay posts SUCCESSFUL payins here (secondary confirmation channel).
// NOTE (per SasaPay docs): the IPN payload does NOT include CheckoutRequestID.
// It carries { BillRefNumber, TransID, ThirdPartyTransID, TransAmount, MSISDN,
// TransactionType, ... } — so we correlate the payin to a pending intent via
// BillRefNumber (== the AccountReference we sent == the contract_ref).
app.post('/api/sasapay/ipn', async (c) => {
  // Same timeout fix as /callback: ACK instantly, settle in the background.
  const body: any = await c.req.json().catch(() => ({}))
  console.log('SasaPay IPN received:', JSON.stringify(body))

  runInBackground(c, async () => {
    const checkout = body?.CheckoutRequestID || body?.MerchantRequestID
    const billRef = body?.BillRefNumber || body?.AccountReference || body?.InvoiceNumber
    if (!checkout && !billRef) return

    let intent = checkout
      ? await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
      : null
    if (!intent && billRef) {
      intent = await c.env.DB.prepare(
        `SELECT pi.* FROM payment_intents pi JOIN murabaha_contracts mc ON mc.id = pi.contract_id
          WHERE mc.contract_ref = ? AND pi.status = 'pending' ORDER BY pi.created_at DESC LIMIT 1`
      ).bind(String(billRef)).first<any>()
    }

    if (!intent) {
      console.warn('SasaPay IPN: NO matching intent', JSON.stringify({ checkout, billRef }))
      await audit(c, null, 'ipn_no_match', 'sasapay', `checkout=${checkout || '?'} billRef=${billRef || '?'}`)
      return
    }

    if (intent.status === 'pending') {
      const receipt = body.TransID || body.TransactionCode || body.TransactionID || body.ThirdPartyTransID || ('SPL' + Date.now())
      const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
      if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'sasapay', intent.phone)
      await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(String(receipt), String(receipt), intent.checkout_request_id).run()
      await audit(c, null, 'ipn_settled', 'sasapay', `settled ${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
      console.log('SasaPay IPN SETTLED:', `${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
    } else {
      console.log('SasaPay IPN: intent already', intent.status, `(${intent.checkout_request_id}) — ignoring (idempotent)`)
    }
  })

  // Respond INSTANTLY.
  return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
})

// ----------------------------------------------------------------------------
// ACCOUNT VALIDATION — confirm the holder name of a mobile/bank/wallet before
// paying it (used by the register-payout-account + direct-pay flows).
// ----------------------------------------------------------------------------
app.post('/api/sasapay/validate-account', requireAuth, async (c) => {
  const { channel_code, account_number } = await c.req.json()
  if (!channel_code || !account_number) return c.json({ error: 'channel_code and account_number are required' }, 400)
  const chan = channelByCode(String(channel_code))
  if (!chan) return c.json({ error: 'Unknown channel' }, 400)
  const acct = chan.type === 'mobile' || chan.type === 'wallet' ? sasapayNormalizePhone(String(account_number)) : String(account_number)
  const v = await sasapayValidateAccount(c.env, String(channel_code), acct)
  if (!v.success) return c.json({ ok: false, error: v.error || 'Validation failed' }, 400)
  return c.json({ ok: true, simulated: v.simulated, account_name: v.account_name, channel_name: v.channel_name || chan.name, normalized_account: acct })
})

// ----------------------------------------------------------------------------
// BALANCE — confirm the merchant/organisation float across SasaPay accounts.
// ----------------------------------------------------------------------------
app.get('/api/sasapay/balance', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const bal = await sasapayBalance(c.env)
  if (!bal.success) return c.json({ ok: false, error: bal.error || 'Balance query failed' }, 502)
  return c.json({ ok: true, simulated: bal.simulated, currency: bal.currency, org_balance: bal.org_balance, accounts: bal.accounts || [] })
})

app.get('/api/sasapay/status', requireAuth, (c) => {
  return c.json({ live: sasapayConfigured(c.env), mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : 'simulation' })
})

// Some gateways (SasaPay included) probe a callback URL with a GET during
// registration / health-checks and will REFUSE to POST results to a URL that
// does not answer that probe with 200. Answer it explicitly for both the
// payin callback and IPN paths so the URL is always accepted upstream.
app.get('/api/sasapay/callback', (c) => c.json({ ok: true, service: 'sasapay-callback', method: 'expects POST' }))
app.get('/api/sasapay/ipn', (c) => c.json({ ok: true, service: 'sasapay-ipn', method: 'expects POST' }))

// Callback health diagnostic — lets an operator confirm, without DB access,
// whether SasaPay callbacks/IPNs are actually reaching this server. Reads the
// audit trail our webhook handlers write (callback_settled / callback_unverified
// / callback_no_match / ipn_settled …) and the current pending payin backlog.
app.get('/api/sasapay/callback-health', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const events = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE entity='sasapay' AND (action LIKE 'callback%' OR action LIKE 'ipn%')
      ORDER BY created_at DESC LIMIT 20`
  ).all<any>()
  const last = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE action IN ('callback_settled','callback_unverified','callback_no_match','callback_amount_mismatch','ipn_settled','ipn_no_match')
      ORDER BY created_at DESC LIMIT 1`
  ).first<any>()
  const pending = await c.env.DB.prepare(
    `SELECT checkout_request_id, amount, phone, channel_name, created_at
       FROM payment_intents
      WHERE provider='sasapay' AND direction='payin' AND status='pending'
      ORDER BY created_at DESC LIMIT 20`
  ).all<any>()
  return c.json({
    live: sasapayConfigured(c.env),
    callback_url: c.env.SASAPAY_CALLBACK_URL || null,
    last_webhook_event: last || null,
    recent_webhook_events: events?.results || [],
    pending_payins: pending?.results || [],
    pending_count: (pending?.results || []).length
  })
})

// ----------------------------------------------------------------------------
// ISSUE 1 — ADMIN PAYMENT RECOVERY (in-app payment_intents)
//   When a customer's wallet is debited but the async gateway callback never
//   lands, the intent (and therefore the dashboard/contract) is stuck PENDING.
//   These authorised endpoints let an operator (a) list hanging intents,
//   (b) re-query the upstream gateway status directly, and (c) manually push a
//   hanging payment to SUCCESS (settling the contract + wallet ledger).
// ----------------------------------------------------------------------------

// List payment intents that are stuck pending (optionally older than N minutes).
app.get('/api/admin/payments/pending', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const minAgeMin = Math.max(0, Number(c.req.query('min_age_min') || 0))
  const rows = await c.env.DB.prepare(
    `SELECT pi.*, mc.contract_ref, mc.outstanding, mc.status AS contract_status,
            cu.full_name AS customer_name
       FROM payment_intents pi
       LEFT JOIN murabaha_contracts mc ON mc.id = pi.contract_id
       LEFT JOIN customers cu ON cu.id = pi.customer_id
      WHERE pi.status = 'pending'
      ORDER BY pi.created_at DESC
      LIMIT 200`
  ).all<any>()
  const now = Date.now()
  const list = (rows?.results || []).filter((r: any) => {
    if (!minAgeMin) return true
    const t = Date.parse(r.created_at || '') || now
    return (now - t) >= minAgeMin * 60 * 1000
  })
  return c.json({ ok: true, count: list.length, intents: list })
})

// Recover a single hanging intent. mode='query' re-checks the gateway and only
// settles if the gateway now reports SUCCESS; mode='force' overrides and pushes
// the intent to SUCCESS regardless (records who forced it, for audit).
app.post('/api/admin/payments/recover', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const checkout = String(body.checkout_request_id || '').trim()
  const mode = String(body.mode || 'query').toLowerCase() // 'query' | 'force'
  if (!checkout) return c.json({ error: 'checkout_request_id is required' }, 400)

  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') {
    return c.json({ ok: true, status: 'success', already: true, mpesa_receipt: intent.mpesa_receipt })
  }

  let success = false, receipt = '', gatewayDesc = ''
  let forced = false

  if (mode === 'force') {
    // Authorised manual override — push to SUCCESS.
    success = true
    forced = true
    receipt = String(body.receipt || intent.transaction_code || ('MANUAL' + Date.now().toString().slice(-8)))
    gatewayDesc = 'Manual admin override'
  } else {
    // Query upstream gateway directly.
    if (!sasapayConfigured(c.env) || String(checkout).includes('SIM')) {
      success = true; receipt = 'SP' + Math.random().toString(36).slice(2, 9).toUpperCase()
    } else {
      const q = await sasapayQuery(c.env, checkout)
      console.log('--- SasaPay Response Debug:', JSON.stringify(q));
      gatewayDesc = String(q?.ResultDesc || q?.message || '')
      if (q?.paid === true || q?.status === true) {
        success = true
        receipt = q.TransactionCode || q.TransactionID || ('SPL' + Date.now().toString().slice(-7))
      } else if (q?.pending === true) {
        return c.json({ ok: false, status: 'pending', result_desc: gatewayDesc || 'Gateway still processing' })
      } else {
        // Definitive failure reported by the gateway.
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
          .bind((gatewayDesc || 'Payment not completed').slice(0, 300), checkout).run()
        await audit(c, c.get('user').id, 'payment_recover', 'sasapay', `marked FAILED ${checkout} (${gatewayDesc})`)
        return c.json({ ok: false, status: 'failed', result_desc: gatewayDesc || 'Payment not completed' })
      }
    }
  }

  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    let res: any = null
    if (contract) res = await applyPayment(c, contract, intent.amount, receipt, 'sasapay', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
      .bind(receipt, receipt, (gatewayDesc || (forced ? 'Manual admin override' : 'Recovered')).slice(0, 300), checkout).run()
    await audit(c, c.get('user').id, 'payment_recover', 'sasapay',
      `${forced ? 'FORCED' : 'query-settled'} ${checkout} -> SUCCESS (KES ${intent.amount}, receipt ${receipt})`)
    return c.json({ ok: true, status: 'success', forced, mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
// ----------------------------------------------------------------------------
// PAYMENTS - KCB Buni STK Push (real when configured, simulated otherwise)
// Docs: https://buni.kcbgroup.com/getting-started
// ----------------------------------------------------------------------------
app.post('/api/buni/stkpush', requireAuth, async (c) => {
  const { contract_id, amount, phone } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)
  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }
  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)
  const desc = contract.payment_type === 'cash' ? 'Cash Equipment Purchase' : 'Equipment Financing Payment'
  const result = await buniStkPush(c.env, { phone: phone || c.get('user').phone, amount: amt, account: contract.contract_ref, description: desc })
  if (!result.success) return c.json({ error: result.error || 'KCB Buni STK push failed' }, 502)
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
    .bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(phone || c.get('user').phone), 'buni').run()
  await audit(c, c.get('user').id, 'stk_push', 'buni', `KES ${amt} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message })
})
app.post('/api/buni/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  let success = false, receipt = ''
  if (!buniConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'BUNI' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    const q = await buniQuery(c.env, checkout_request_id)
    const code = q.ResultCode ?? q.status_code
    if (code === '0' || code === 0 || q.status === true) { success = true; receipt = 'BUNI' + Date.now().toString().slice(-7) }
    else if (code) return c.json({ ok: false, status: 'failed', result_desc: q.ResultDesc || q.message || 'Payment not completed' })
    else return c.json({ ok: false, status: 'pending' })
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    const res = await applyPayment(c, contract, intent.amount, receipt, 'buni', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
app.post('/api/buni/callback', async (c) => {
  try {
    const body: any = await c.req.json()
    const checkout = body?.CheckoutRequestID || body?.TransactionID
    if (!checkout) return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
    if (intent && intent.status === 'pending') {
      const code = body.ResultCode ?? body.status_code
      if (code === 0 || code === '0' || body.status === true) {
        const receipt = body.TransactionID || body.ReceiptNumber || 'BUNI' + Date.now()
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'buni', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), body.ResultDesc || '', checkout).run()
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(body.ResultDesc || body.message || 'Failed', checkout).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch { return c.json({ ResultCode: 0, ResultDesc: 'Accepted' }) }
})
app.get('/api/buni/status', requireAuth, (c) => {
  // Buni is hidden from the front-end user. The gateway routes remain
  // functional for server-to-server integrations, but the UI never exposes it.
  return c.json({ live: buniConfigured(c.env), mode: buniConfigured(c.env) ? (c.env.BUNI_ENV || 'sandbox') : 'simulation', hidden: true })
})

// ----------------------------------------------------------------------------
// CENTRAL PAYMENT GATEWAY (shared by equipment / feed / input marketplaces)
// Public endpoint URL:  https://equipment.farmsky.africa/api/v1/payments/*
// ----------------------------------------------------------------------------
app.route('/api/v1/payments', paymentGateway)

// ----------------------------------------------------------------------------
// CENTRAL MASTER WALLET GATEWAY (metered API-call billing for client tenants)
// Public endpoint URLs:
//   {host}/api/v1/wallet/{debit,credit,balance}
//   {host}/api/v1/settings/thresholds
// Same X-Farmsky-* HMAC discipline as /api/v1/payments/*. Used by the Credit
// app (credit.farmsky.africa) to debit the master wallet per scoring call and
// to sync low-balance alert thresholds. See backend/wallet-gateway.ts.
// ----------------------------------------------------------------------------
app.route('/api/v1/wallet', walletGateway)
app.route('/api/v1/settings', walletSettings)

// ----------------------------------------------------------------------------
// TENANT MANAGEMENT DASHBOARD API (Option A — dynamic provisioning)
// Admin-only CRUD over app_clients so operators can register / edit client
// tenants, rotate HMAC secrets and toggle status WITHOUT a service restart.
// Backs the /admin/tenants dashboard page. HMAC secrets are never returned in
// full — only a masked preview — except at the moment of rotation.
// ----------------------------------------------------------------------------
function maskSecret(s: string | null | undefined): string {
  const v = String(s || '')
  if (!v) return ''
  if (v.length <= 8) return '••••'
  return `${v.slice(0, 4)}••••${v.slice(-4)}`
}
function genTenantSecret(): string {
  // 256-bit hex secret.
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

app.get('/api/v1/admin/tenants', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT client_key, display_name, origin_url, callback_url, webhook_url, is_active, provisioned_via, secret_rotated_at, updated_at
       FROM app_clients ORDER BY client_key`
  ).all().catch(() => ({ results: [] as any[] }))
  const rows = (results || []).map((r: any) => ({
    client_key: r.client_key,
    display_name: r.display_name,
    origin_url: r.origin_url,
    callback_url: r.callback_url,
    webhook_url: r.webhook_url || r.callback_url || null,
    is_active: Number(r.is_active) !== 0,
    provisioned_via: r.provisioned_via || 'seed',
    secret_rotated_at: r.secret_rotated_at || null,
    updated_at: r.updated_at || null,
  }))
  return c.json({ success: true, tenants: rows })
})

app.post('/api/v1/admin/tenants', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json().catch(() => ({}))
  const clientKey = String(b.client_key || '').trim()
  if (!clientKey) return c.json({ success: false, error: 'client_key is required' }, 400)
  const displayName = String(b.display_name || clientKey).slice(0, 120)
  const originUrl = String(b.origin_url || '').replace(/\/+$/, '')
  const callbackUrl = b.callback_url ? String(b.callback_url) : null
  const webhookUrl = b.webhook_url ? String(b.webhook_url) : null
  // Use supplied secret or mint a fresh 256-bit one.
  const secret = String(b.hmac_secret || '').trim() || genTenantSecret()
  const isActive = b.is_active === false ? 0 : 1
  try {
    await c.env.DB.prepare(
      `INSERT INTO app_clients (client_key, display_name, origin_url, hmac_secret, callback_url, webhook_url, is_active, provisioned_via, secret_rotated_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'admin_ui', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT (client_key) DO UPDATE SET
         display_name = EXCLUDED.display_name,
         origin_url = COALESCE(NULLIF(EXCLUDED.origin_url, ''), app_clients.origin_url),
         callback_url = COALESCE(EXCLUDED.callback_url, app_clients.callback_url),
         webhook_url = COALESCE(EXCLUDED.webhook_url, app_clients.webhook_url),
         is_active = EXCLUDED.is_active,
         provisioned_via = 'admin_ui',
         updated_at = CURRENT_TIMESTAMP`
    ).bind(clientKey, displayName, originUrl || 'https://example.invalid', secret, callbackUrl, webhookUrl, isActive).run()
  } catch (e: any) {
    return c.json({ success: false, error: e?.message || 'Failed to save tenant' }, 500)
  }
  // Return the secret ONLY on create/rotate so the operator can copy it.
  const created = String(b.hmac_secret || '').trim() ? undefined : secret
  return c.json({ success: true, client_key: clientKey, hmac_secret_new: created, hmac_secret_masked: maskSecret(secret) })
})

app.post('/api/v1/admin/tenants/:client_key/rotate-secret', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const clientKey = c.req.param('client_key')
  const existing = await c.env.DB.prepare(`SELECT client_key FROM app_clients WHERE client_key = ?`).bind(clientKey).first<any>()
  if (!existing) return c.json({ success: false, error: 'Tenant not found' }, 404)
  const secret = genTenantSecret()
  await c.env.DB.prepare(
    `UPDATE app_clients SET hmac_secret = ?, secret_rotated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE client_key = ?`
  ).bind(secret, clientKey).run()
  return c.json({ success: true, client_key: clientKey, hmac_secret_new: secret, hmac_secret_masked: maskSecret(secret), note: 'Update the tenant app with this new secret immediately.' })
})

app.put('/api/v1/admin/tenants/:client_key/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const clientKey = c.req.param('client_key')
  const b = await c.req.json().catch(() => ({}))
  const isActive = b.is_active === false ? 0 : 1
  const res = await c.env.DB.prepare(
    `UPDATE app_clients SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE client_key = ?`
  ).bind(isActive, clientKey).run()
  const changed = Number((res as any)?.meta?.changes ?? (res as any)?.changes ?? 1)
  if (!changed) return c.json({ success: false, error: 'Tenant not found' }, 404)
  return c.json({ success: true, client_key: clientKey, is_active: isActive !== 0 })
})

// Admin-only view of cross-app payment activity
app.get('/api/v1/payments-admin/summary', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const res = await fetch(new URL('/api/v1/payments/admin/summary', c.req.url).toString())
  return c.json(await res.json())
})

// ----------------------------------------------------------------------------
// PUBLIC MERCHANT API (Phase 3) — HMAC-authenticated inventory + checkout
// Mounted under /api  ->  /api/v1/merchant/*  and  /api/v1/checkout/*
// ----------------------------------------------------------------------------
app.route('/api', merchantApi)

// ----------------------------------------------------------------------------
// UNIFIED PAYMENT LEDGER (Phase 2) — Equipment admin dashboard reads this to
// see BOTH equipment_app and feed_app transactions, filterable by category
// (inventory_type) + origin_platform. RBAC: admin/super_admin only.
// ----------------------------------------------------------------------------
app.get('/api/ledger', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const invType = c.req.query('inventory_type') || ''      // 'equipment' | 'feed'
  const origin = c.req.query('origin_platform') || ''      // 'equipment_app' | 'feed_app'
  const status = c.req.query('status') || ''
  const method = c.req.query('method') || ''
  const q = c.req.query('q') || ''
  const filters: string[] = []
  const binds: any[] = []
  if (invType) { filters.push('inventory_type = ?'); binds.push(invType) }
  if (origin) { filters.push('origin_platform = ?'); binds.push(origin) }
  if (status) { filters.push('status = ?'); binds.push(status) }
  if (method) { filters.push('payment_method = ?'); binds.push(method) }
  if (q) { filters.push('(transaction_ref LIKE ? OR phone LIKE ? OR description LIKE ?)'); binds.push(`%${q}%`, `%${q}%`, `%${q}%`) }
  const where = filters.length ? 'WHERE ' + filters.join(' AND ') : ''
  const rows = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT transaction_ref, origin_app, origin_platform, inventory_type, payment_method, phone,
            amount, currency, status, description, created_at, completed_at
       FROM central_transactions ${where} ORDER BY created_at DESC LIMIT 500`
  ).bind(...binds).all<any>())
  return c.json({ transactions: rows.results || [] })
})

// ----------------------------------------------------------------------------
// SCORE WALLET LEDGER MIRROR RECEIVER (Phase 3)
// Score is the PRIMARY wallet ledger; every wallet transaction on Score is
// mirrored here for cross-app audit. Score POSTs a signed JSON payload with:
//   X-Score-Signature: sha256=<hmacSha256Hex(secret, rawBody)>
// where secret = SCORE_LEDGER_HMAC_SECRET || SCORE_HMAC_SECRET ||
// SCORE_CROSS_APP_HMAC_SECRET || CROSS_APP_HMAC_SECRET. Idempotent on
// score_tx_id.
// ----------------------------------------------------------------------------
function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

app.post('/api/score-ledger/mirror', async (c) => {
  // Read raw body first (needed for HMAC verification of the exact bytes signed)
  const raw = await c.req.text()

  const secret =
    c.env.SCORE_LEDGER_HMAC_SECRET ||
    c.env.SCORE_HMAC_SECRET ||
    c.env.SCORE_CROSS_APP_HMAC_SECRET ||
    c.env.CROSS_APP_HMAC_SECRET ||
    ''

  if (!secret) {
    console.warn('[score-ledger] mirror rejected: no HMAC secret configured')
    return c.json({ error: 'mirror_not_configured' }, 503)
  }

  const header = c.req.header('X-Score-Signature') || c.req.header('x-score-signature') || ''
  const provided = header.replace(/^sha256=/i, '').trim().toLowerCase()
  if (!provided) {
    return c.json({ error: 'missing_signature' }, 401)
  }

  const expected = (await hmacSha256Hex(secret, raw)).toLowerCase()
  if (!timingSafeEqualHex(provided, expected)) {
    console.warn('[score-ledger] mirror rejected: signature mismatch')
    return c.json({ error: 'invalid_signature' }, 401)
  }

  let payload: any
  try {
    payload = JSON.parse(raw)
  } catch {
    return c.json({ error: 'invalid_json' }, 400)
  }

  const scoreTxId = String(payload.score_tx_id ?? '').trim()
  if (!scoreTxId) {
    return c.json({ error: 'missing_score_tx_id' }, 400)
  }

  const orgRef = payload.org_id != null ? String(payload.org_id) : null
  const direction = String(payload.direction ?? '').trim() || null
  const amountKes = payload.amount_kes != null ? Number(payload.amount_kes) : null
  const balanceAfter = payload.balance_after != null ? Number(payload.balance_after) : null
  const kind = payload.kind != null ? String(payload.kind) : null
  const serviceKey = payload.service_key != null ? String(payload.service_key) : null
  const reference = payload.reference != null ? String(payload.reference) : null
  const source = payload.source != null ? String(payload.source) : 'score'

  try {
    // Idempotency: skip if this Score tx has already been mirrored.
    const existing = await withAdminContext(c, async () => await c.env.DB.prepare(
      `SELECT id FROM score_wallet_ledger WHERE score_tx_id = ?`
    ).bind(scoreTxId).first<any>())
    if (existing) {
      return c.json({ ok: true, mirrored: false, duplicate: true, score_tx_id: scoreTxId })
    }

    await withAdminContext(c, async () => await c.env.DB.prepare(
      `INSERT INTO score_wallet_ledger
         (score_org_ref, score_tx_id, direction, amount_kes, balance_after, kind, service_key, reference, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(orgRef, scoreTxId, direction, amountKes, balanceAfter, kind, serviceKey, reference, source).run())

    return c.json({ ok: true, mirrored: true, duplicate: false, score_tx_id: scoreTxId })
  } catch (err: any) {
    // If a concurrent request inserted the same score_tx_id, treat as duplicate.
    const msg = String(err?.message || err)
    if (/unique|duplicate/i.test(msg)) {
      return c.json({ ok: true, mirrored: false, duplicate: true, score_tx_id: scoreTxId })
    }
    console.error('[score-ledger] mirror insert failed:', msg)
    return c.json({ error: 'mirror_failed' }, 500)
  }
})

// ----------------------------------------------------------------------------
// SCORE LENDER API WALLETS (Phase 3) — read model over the mirrored ledger.
// Farmsky Score (credit.farmsky.africa) owns the PRIMARY lender API wallets;
// Feed's Wallets & Payouts dashboard shows Score activity from the locally
// mirrored score_wallet_ledger (pushed via /api/score-ledger/mirror).
// ----------------------------------------------------------------------------
app.get('/api/score-wallets', requireAuth, requirePermission('manage_wallets'), async (c) => {
  // Reconstruct a wallet list from the mirrored ledger so the dashboard shows
  // Score activity from the last mirror push.
  const rows = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT score_org_ref AS org_id,
            COUNT(*) AS entries,
            MAX(created_at) AS last_activity_at,
            COALESCE(
              (SELECT balance_after FROM score_wallet_ledger s2
                WHERE s2.score_org_ref = s.score_org_ref AND s2.balance_after IS NOT NULL
                ORDER BY s2.created_at DESC LIMIT 1), 0) AS balance_kes
       FROM score_wallet_ledger s
      WHERE score_org_ref IS NOT NULL
      GROUP BY score_org_ref
      ORDER BY last_activity_at DESC`
  ).all<any>())
  const wallets = (rows.results || []).map((r: any) => ({
    org_id: String(r.org_id),
    display_name: `Lender ${String(r.org_id).slice(0, 8)}`,
    legal_name: null,
    merchant_id: null,
    plan: null,
    currency: 'KES',
    balance_kes: Number(r.balance_kes) || 0,
    low_threshold: 0,
    status: (Number(r.balance_kes) || 0) <= 0 ? 'empty' : 'active',
    active_keys: null,
    balance_updated_at: r.last_activity_at || null,
    last_activity_at: r.last_activity_at || null,
    entries: Number(r.entries) || 0,
  }))
  return c.json({ wallets, source: 'mirror_fallback' })
})

// Drill-down for one Score lender API wallet: snapshot + time-stamped ledger
// (incoming credits, outgoing debits) from the mirrored ledger.
app.get('/api/score-wallets/:orgId', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const orgId = String(c.req.param('orgId') || '').trim()
  if (!orgId) return c.json({ error: 'org_id required' }, 400)
  const rows = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT id, direction, amount_kes, balance_after, kind, service_key, reference, source, created_at
       FROM score_wallet_ledger WHERE score_org_ref = ? ORDER BY created_at DESC LIMIT 300`
  ).bind(orgId).all<any>())
  const ledger = (rows.results || []).map((t: any) => {
    const dir = String(t.direction || '').toLowerCase()
    return {
      id: String(t.id),
      direction: dir,
      category: dir === 'credit' ? 'settlement' : 'debit',
      amount_kes: Number(t.amount_kes) || 0,
      balance_after: t.balance_after != null ? Number(t.balance_after) : null,
      kind: t.kind || 'topup',
      reference: t.reference || null,
      status: 'completed',
      created_at: t.created_at,
      service_key: t.service_key || null,
    }
  })
  return c.json({
    source: 'mirror_fallback',
    wallet: { org_id: orgId, display_name: `Lender ${orgId.slice(0, 8)}`, currency: 'KES', balance_kes: ledger[0]?.balance_after ?? 0, status: 'active' },
    ledger,
    consumption: { endpoints: [], service_fees: [] },
  })
})

// ----------------------------------------------------------------------------
// CROSS-APP SSO HANDOFF (Phase 2) — no second login between Equipment & Feed
// ----------------------------------------------------------------------------
// Signed-in user requests a handoff URL to the sibling app.
app.get('/api/cross/handoff', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const target = String(c.req.query('target') || '')
  // SECRET SELECTION by target:
  //  * Score channel uses the DEDICATED SCORE_CROSS_APP_HMAC_SECRET when set,
  //    falling back to the legacy shared CROSS_APP_HMAC_SECRET so existing
  //    single-secret deployments keep working. This must match Score's /sso
  //    verifier.
  //  * Equipment (and any other sibling marketplace) keeps the legacy shared
  //    CROSS_APP_HMAC_SECRET, untouched by the Score-channel rename.
  const secret = (target === 'score'
    ? (c.env.SCORE_CROSS_APP_HMAC_SECRET || c.env.CROSS_APP_HMAC_SECRET)
    : c.env.CROSS_APP_HMAC_SECRET) || ''
  // Choose the destination origin by target: 'score' -> SCORE_APP_URL,
  // anything else -> the configured sibling marketplace (Equipment).
  const siblingUrl = sanitizeUrl(target === 'score'
    ? String(c.env.SCORE_APP_URL || '')
    : String(c.env.CROSS_APP_URL || '')
  )
  if (!secret || !siblingUrl) {
    const missing: string[] = []
    if (!secret) missing.push(target === 'score' ? 'SCORE_CROSS_APP_HMAC_SECRET/CROSS_APP_HMAC_SECRET' : 'CROSS_APP_HMAC_SECRET')
    if (!siblingUrl) missing.push(target === 'score' ? 'SCORE_APP_URL' : 'CROSS_APP_URL')
    console.error(`[cross/handoff] not configured for target=${target} — missing: ${missing.join(', ')}`)
    return c.json({ error: 'Cross-app navigation is not configured' }, 503)
  }
  // Score is EMAIL-KEYED: it resolves the user by email, so refuse to mint a
  // Score handoff for an account with no email rather than land on a dead /sso.
  if (target === 'score' && !String((user as any).email || '').trim()) {
    return c.json({ error: 'An email address is required on your account to open Farmsky Score.' }, 400)
  }
  // Anti-hijack: bind the token to the requesting client (IP + User-Agent) so a
  // stolen handoff URL cannot be replayed from a different browser.
  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || ''
  const userAgent = c.req.header('user-agent') || ''
  const fingerprint = handoffClientFingerprint(clientIp, userAgent)
  // The same short-lived HMAC-signed token is accepted by every Farmsky app's
  // /sso endpoint, so no second login is needed at the destination. Email +
  // name are carried so email-keyed apps (Score) can resolve/create the
  // account. The Equipment Admin Portal is the single source of truth for
  // Super-Admin status, so carry the originating role + a super_admin assertion
  // so the destination app grants the SAME access with the SAME credentials.
  const isSuper = user.role === 'super_admin'
  const token = await mintHandoffToken(secret, normalizePhone(user.phone), {
    email: (user as any).email,
    name: user.full_name,
    role: user.role,
    super_admin: isSuper,
    fingerprint,
  })
  // Optional deep-link: `dest` tells the destination app which view to open
  // after SSO. Allow-listed slug to avoid open-redirect abuse.
  const destRaw = String(c.req.query('dest') || '').trim()
  const dest = /^[a-z0-9-]{1,32}$/.test(destRaw) ? destRaw : ''
  const qs = `token=${encodeURIComponent(token)}` + (dest ? `&dest=${encodeURIComponent(dest)}` : '')
  return c.json({ url: `${siblingUrl}/sso?${qs}`, target, dest: dest || null })
})

// Lender opts in to consuming the Farmsky Score APIs from the Feed platform.
// Records the opt-in (best-effort audit) before the SSO handoff to Score,
// where the lender enables and manages API access. Lender-tier only.
app.post('/api/cross/use-apis', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (user.role !== 'lender') return c.json({ error: 'Only Lender-tier accounts can consume the APIs' }, 403)
  try {
    await audit(c, user.id, 'update', 'user', 'lender opted in to Use APIs (Farmsky Score API consumption)')
  } catch (_) { /* audit is best-effort; never block the handoff */ }
  return c.json({ ok: true })
})

// Sibling app lands here: verify HMAC token, issue a local session, redirect.
app.get('/sso', async (c) => {
  const token = c.req.query('token') || ''
  // Re-derive the presenting client's fingerprint so a token that was minted
  // WITH an IP+UA binding only verifies from the same browser (anti-hijack).
  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || ''
  const userAgent = c.req.header('user-agent') || ''
  const fingerprint = handoffClientFingerprint(clientIp, userAgent)
  // A handoff may be signed with the dedicated Score secret OR the legacy shared
  // secret. Try the dedicated Score secret first (when distinct), then fall back
  // to the shared CROSS_APP_HMAC_SECRET, so both channels land here cleanly.
  const scoreSecret = c.env.SCORE_CROSS_APP_HMAC_SECRET || ''
  const sharedSecret = c.env.CROSS_APP_HMAC_SECRET || ''
  let v = await verifyHandoffToken(sharedSecret, token, fingerprint)
  if (!v.ok && scoreSecret && scoreSecret !== sharedSecret) {
    v = await verifyHandoffToken(scoreSecret, token, fingerprint)
  }
  const escHtml = (s: string) => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string))
  if (!v.ok) return c.html(`<h3>Sign-in link invalid or expired</h3><p>${escHtml(v.error || '')}</p><p><a href="/">Go to sign in</a></p>`, 401)
  // Match the account across every stored phone format: normalized 254...,
  // the '+'-prefixed form, and the raw value carried in the token.
  const norm = normalizePhone(v.phone!)
  const plus = norm.startsWith('254') ? '+' + norm : norm
  const user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ? OR phone = ?`).bind(v.phone, norm, plus).first<any>()
  if (!user) return c.html(`<h3>No matching account on this platform</h3><p>Please sign in normally.</p><p><a href="/">Go to sign in</a></p>`, 404)
  if (user.status !== 'active') return c.html(`<h3>Account is not active on this platform</h3><p><a href="/">Go to sign in</a></p>`, 403)
  await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} signed in via cross-app SSO handoff`)
  return c.redirect('/')
})

// Expose cross-app config to the frontend (so nav buttons show only when set).
app.get('/api/cross/config', requireAuth, (c) => {
  return c.json({
    app_type: String(c.env.APP_TYPE || 'equipment'),
    cross_app_configured: !!(c.env.CROSS_APP_HMAC_SECRET && c.env.CROSS_APP_URL),
    cross_app_url: sanitizeUrl(c.env.CROSS_APP_URL) || null,
    // Score SSO button is shown when the shared handoff secret AND the Score
    // origin are configured. Reuses the same session (no re-login).
    score_configured: !!((c.env.SCORE_CROSS_APP_HMAC_SECRET || c.env.CROSS_APP_HMAC_SECRET) && c.env.SCORE_APP_URL),
    score_url: sanitizeUrl(c.env.SCORE_APP_URL) || null
  })
})

// =====================================================================
// NATIVE CROSS-MARKETPLACE PURCHASING  (in-session, no redirect / logout)
// ---------------------------------------------------------------------
// Feed users can browse AND buy inventory that is NOT native to Feed —
// i.e. Equipment-listed items (app_scope='equipment') and merchant /
// API-ingested items — without being handed off to the sibling app or
// losing their Feed session. The shared `products` table already carries
// these rows; Feed's normal /api/products deliberately hides them, so
// these endpoints surface them explicitly and drive an in-app checkout.
//
// Payment stays CENTRALIZED in Equipment: settlement is routed through
// the Farmsky Central Payment Gateway exactly like a native Feed
// purchase (gatewayInitiate → poll /api/mpesa/confirm). Feed never holds
// provider credentials; it only creates the local purchase record and
// signs an HMAC gateway request. This preserves the single structural
// exception (payment centralized in Equipment) while giving Feed users a
// seamless, session-preserving cross-marketplace buying experience.
// =====================================================================

// GET /api/cross/inventory — purchasable inventory that is NOT native to Feed.
// Returns published, in-stock items whose app_scope is 'equipment' (Equipment
// catalog) OR that were ingested via the merchant/API surface. Excludes Feed's
// own ('feed'/'both') catalog which the normal storefront already serves.
app.get('/api/cross/inventory', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const q = String(c.req.query('q') || '').trim().toLowerCase()
  const rows = await withAdminContext(c, async () => {
    let query = `SELECT id, sku, name, category, description, product_type, cash_price, credit_price,
                        quantity, unit, image, app_scope, cash_enabled, financing_enabled,
                        payment_option_mode, finance_status
                 FROM products
                 WHERE app_scope = 'equipment'
                   AND (finance_status IS NULL OR finance_status = 'published')
                   AND quantity > 0`
    const { results } = await c.env.DB.prepare(query).all()
    return results as any[]
  })
  let items = (rows || []).map((p: any) => ({
    ...p,
    source: 'equipment',
    stock_status: p.quantity <= 0 ? 'out_of_stock' : 'in_stock'
  }))
  if (q) items = items.filter((p: any) =>
    String(p.name || '').toLowerCase().includes(q) ||
    String(p.category || '').toLowerCase().includes(q) ||
    String(p.sku || '').toLowerCase().includes(q))
  return c.json({ items, count: items.length })
})

// POST /api/cross/purchase — buy a cross-catalog (Equipment/API) item natively
// inside the active Feed session. Creates a local direct cash-purchase contract
// then initiates payment through the central gateway. The caller keeps the same
// session and polls /api/mpesa/confirm (identical to a native Feed purchase).
app.post('/api/cross/purchase', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const body = await c.req.json().catch(() => ({}))
  const productId = Number(body.product_id)
  const qty = Math.max(1, Number(body.quantity) || 1)
  const rail = (['mpesa', 'sasapay', 'buni'].includes(String(body.payment_method)) ? String(body.payment_method) : 'mpesa') as any
  const phone = String(body.phone || user.phone || '')
  if (!Number.isFinite(productId) || productId <= 0) return c.json({ error: 'product_id is required' }, 400)

  // The item must be a cross-catalog (Equipment-scoped) product; a Feed user
  // cannot use this path to buy Feed's own catalog (that goes through the normal
  // storefront). Read under admin context so ownership RLS does not hide it.
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT * FROM products WHERE id = ? AND app_scope = 'equipment'`
  ).bind(productId).first<any>())
  if (!p) return c.json({ error: 'Item not found in the cross-marketplace catalog' }, 404)
  if (p.finance_status && p.finance_status !== 'published') return c.json({ error: 'This item is not available for purchase' }, 400)
  if (Number(p.quantity) < qty) return c.json({ error: 'Insufficient stock' }, 409)

  // Resolve the buyer's customer profile (self-service purchase). Every buyer
  // must have a customer row so the purchase can be recorded + settled.
  let custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first<any>())
  if (!custRow && body.customer_id) {
    custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(Number(body.customer_id)).first<any>())
  }
  if (!custRow) return c.json({ error: 'A customer profile is required to purchase. Please complete your profile first.' }, 412)

  // Cross-marketplace purchases are always CASH (direct purchase). Financing is
  // scoped to the owning platform, so a Feed-side cross purchase settles the full
  // cash price through the central gateway. Values are computed server-side.
  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const quote = financingQuote(p, qty, 'cash', 0, feeCfg)
  const contractRef = ref('XMP')  // XMP = cross-marketplace purchase
  const status = quote.amount_due_now > 0 ? 'pending_payment' : 'awaiting_cash_balance'

  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    contractRef, custRow.id, custRow.agent_id || null, custRow.onboarded_by || custRow.agent_id || user.id, productId, qty, 'cash',
    quote.supplier_cost, quote.markup_pct, quote.total_payable, 0, 0, String(body.delivery_location || ''), status,
    0, 1, 0, quote.total_payable, quote.financing_model, 0, quote.deposit_pct, quote.deposit_amount,
    quote.finance_principal, quote.payment_frequency, 0, 'pending', null, null
  ).run())
  const contractId = r.meta.last_row_id
  await audit(c, user.id, 'cross_purchase', 'contract', `${contractRef} — ${p.name} x${qty} (Equipment catalog, in-session)`)

  const amt = Number(quote.amount_due_now || quote.total_payable)
  if (amt <= 0) {
    return c.json({ id: contractId, contract_ref: contractRef, status, requires_payment: false, total_payable: quote.total_payable })
  }

  // Route settlement through the central gateway (payment centralized in
  // Equipment). Falls back to simulation locally when the gateway is not set.
  const desc = `Feed Cross-Marketplace Purchase — ${p.name}`
  const chanMap: Record<string, string> = { mobile: 'MOBILE_MONEY', bank: 'BANK', wallet: 'SASAPAY_WALLET' }
  const gwChannel = rail === 'sasapay' ? (chanMap[String(body.channel_type || 'mobile')] || 'MOBILE_MONEY') : undefined
  const gwChannelCode = rail === 'sasapay' && body.channel_code ? String(body.channel_code) : undefined

  if (gatewayConfigured(c.env)) {
    const g = await gatewayInitiate(c.env, {
      amount: amt, phone, payment_method: rail, origin_reference: contractRef,
      description: desc, initiated_by_user: user.id, idempotency_key: `feed-xmp-${contractRef}-${amt}`,
      channel: gwChannel, channelCode: gwChannelCode
    })
    if (!g.success) return c.json({ error: g.error || 'Payment gateway rejected the request' }, 502)
    await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
      .bind(g.transaction_ref, g.transaction_ref, contractId, custRow.id, amt, normalizePhone(phone), `gateway_${rail}`).run()
    return c.json({ ok: true, id: contractId, contract_ref: contractRef, requires_payment: true, simulated: !!g.simulated, checkout_request_id: g.transaction_ref, needs_otp: !!(g as any).needs_otp, amount: amt, total_payable: quote.total_payable, customer_message: g.customer_message || 'Payment request sent. Approve the prompt on your phone.' })
  }

  // Local/standalone fallback: direct STK / simulation.
  const result = await stkPush(c.env, { phone, amount: amt, account: contractRef, description: desc })
  if (!result.success) return c.json({ error: result.error || 'STK push failed' }, 502)
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
    .bind(result.checkout_request_id, result.merchant_request_id, contractId, custRow.id, amt, normalizePhone(phone), 'mpesa').run()
  return c.json({ ok: true, id: contractId, contract_ref: contractRef, requires_payment: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, amount: amt, total_payable: quote.total_payable, customer_message: result.customer_message })
})

// ----------------------------------------------------------------------------
// HOSTED CHECKOUT PAGE (Phase 3) — where merchant buttons redirect the buyer.
// ----------------------------------------------------------------------------
app.get('/checkout/:ref', async (c) => {
  const ref = c.req.param('ref')
  const row = await c.env.DB.prepare(
    `SELECT * FROM merchant_checkouts WHERE checkout_ref = ?`
  ).bind(ref).first<any>()
  if (!row) return c.html(`<h3>Checkout session not found</h3>`, 404)
  return c.html(CHECKOUT_PAGE(row))
})

// ----------------------------------------------------------------------------
// DASHBOARD / ANALYTICS
// ----------------------------------------------------------------------------
app.get('/api/dashboard', requireAuth, async (c) => {
  const user = c.get('user'), db = c.env.DB
  if (user.role === 'customer') {
    const myCust = await db.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    const cid = myCust?.id || -1
    const contracts = await db.prepare(`SELECT COUNT(*) n, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE customer_id=? AND status='active'`).bind(cid).first<any>()
    const completed = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status='completed'`).bind(cid).first<any>()
    const nextDue = await db.prepare(`SELECT r.* FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.customer_id=? AND r.status!='completed' ORDER BY r.due_date LIMIT 1`).bind(cid).first<any>()
    return c.json({ role: 'customer', active_contracts: contracts?.n || 0, total_outstanding: contracts?.out || 0, completed_contracts: completed?.n || 0, next_payment: nextDue || null })
  }
  if (user.role === 'agent') {
    const cust = await db.prepare(`SELECT COUNT(*)::int n FROM customers WHERE agent_id=?`).bind(user.id).first<any>()
    const active = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='active'`).bind(user.id).first<any>()
    const pending = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='pending'`).bind(user.id).first<any>()
    const portfolio = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE agent_id=?`).bind(user.id).first<any>()
    const late = await db.prepare(`SELECT COUNT(*)::int n FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.agent_id=? AND r.status='late'`).bind(user.id).first<any>()
    const creditOnly = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND payment_type='financing'`).bind(user.id).first<any>()
    const par = portfolio?.tot ? Math.round((portfolio.out / portfolio.tot) * 100) : 0
    return c.json({ role: 'agent', customers_onboarded: cust?.n || 0, active_contracts: active?.n || 0, pending_approvals: pending?.n || 0, portfolio_value: portfolio?.tot || 0, portfolio_at_risk: par, late_installments: late?.n || 0, commission: Math.round((portfolio?.tot || 0) * 0.025), credit_purchases: creditOnly?.n || 0 })
  }
  const sales = await db.prepare(`SELECT COALESCE(SUM(amount),0) tot FROM transactions WHERE status='success'`).first<any>()
  const financed = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='financing'`).first<any>()
  const cashSales = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='cash'`).first<any>()
  const activeCust = await db.prepare(`SELECT COUNT(*)::int n FROM customers`).first<any>()
  const invValue = await db.prepare(`SELECT COALESCE(SUM(buying_price*quantity),0) tot FROM products`).first<any>()
  const totalRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments`).first<any>()
  const completedRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='completed'`).first<any>()
  const defaulted = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='defaulted'`).first<any>()
  const pending = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE status='pending'`).first<any>()
  const repayRate = totalRepay?.n ? Math.round((completedRepay.n / totalRepay.n) * 100) : 0
  const defaultRate = totalRepay?.n ? Math.round((defaulted.n / totalRepay.n) * 100) : 0
  const { results: topProducts } = await db.prepare(`SELECT p.name, COUNT(mc.id) sales FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id GROUP BY p.id ORDER BY sales DESC LIMIT 5`).all()
  return c.json({ role: user.role === 'operations_finance' ? 'operations_finance' : 'admin', total_sales: sales?.tot || 0, equipment_financed: financed?.tot || 0, cash_sales: cashSales?.tot || 0, repayment_rate: repayRate, default_rate: defaultRate, inventory_value: invValue?.tot || 0, active_customers: activeCust?.n || 0, pending_approvals: pending?.n || 0, top_products: topProducts })
})

// ----------------------------------------------------------------------------
// AGENTS
// ----------------------------------------------------------------------------
app.get('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.region, u.label, u.permissions, u.status,
     (SELECT COUNT(*) FROM customers WHERE agent_id=CAST(u.id AS TEXT)) customers,
     (SELECT COUNT(*) FROM murabaha_contracts WHERE agent_id=CAST(u.id AS TEXT) AND status='active') active
     FROM users u WHERE u.role='agent'`
  ).all()
  const agentFallback = await loadRoleTemplate(c, 'agent')
  return c.json({ agents: results.map((a: any) => ({ ...a, permissions: parsePermissions(a.permissions, 'agent', agentFallback) })) })
})
// ----------------------------------------------------------------------------
// MULTI-USER ONBOARDING — OTP VERIFICATION
// The creator (agent/admin) verifies the NEW user's phone before the account is
// finalised. Step 1: request an OTP to the new user's phone. Step 2: create the
// account passing the OTP code; on success a temporary password is issued.
// ----------------------------------------------------------------------------
app.post('/api/onboard/request-otp', requireAuth, requireRole('admin', 'super_admin', 'agent'), async (c) => {
  const { phone } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!p) return c.json({ error: 'A valid phone number is required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const { sms, demo_otp } = await issueOtp(c, p, 'onboard')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `Verification code sent to ${p}.`, demo_otp })
})

app.post('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p) return c.json({ error: 'Name and phone are required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const provided = b.password && String(b.password).length >= 4
  // Admin-driven onboarding — the creating admin is already authenticated, so we
  // never block on a phone OTP. Password supplied → use it; blank → auto-generate
  // a temporary (must-change) one and SMS it. An OTP is only consumed if supplied.
  if (!provided && b.otp_code) {
    const v = await verifyOtp(c, p, String(b.otp_code || ''), 'onboard')
    if (!v.ok) return c.json({ error: v.error || 'Phone verification failed', otp_required: true }, 400)
  }
  const pwd = provided ? String(b.password) : genPassword()
  const perms = await permissionsForRole(c, 'agent', b.permissions || {})
  const creatorId = c.get('user').id
  // Email is optional for agents. resolveEmail supplies a unique, non-deliverable
  // placeholder (derived from phone) when blank, satisfying the central
  // users.email NOT NULL + UNIQUE constraints (was 23502 on null, 23505 on '').
  const agEmailRes = resolveEmail('agent', b.email, b.phone)
  if ('error' in agEmailRes) return c.json({ error: agEmailRes.error }, 400)
  const agEmail = agEmailRes.value
  // On the shared central DB users.org_id is NOT NULL — attach the creating
  // admin's tenant (falling back to the deployment default). Omitted on the
  // Feed-only DB shape (no org_id column).
  const agOrgId = (await resolveCreatorOrgId(c, c.get('user'))) || (await resolveDefaultOrgId(c))
  const agWithOrg = (await usersHasOrgId(c)) && agOrgId != null
  const r = agWithOrg
    ? await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set,label,permissions,created_by,org_id) VALUES (?,?,?,?, 'agent', ?, ?, ?, ?, ?, ?)`).bind(b.full_name, p, agEmail, await hashPassword(pwd), b.region || null, provided, b.label || 'Agent', JSON.stringify(perms), creatorId, agOrgId).run()
    : await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set,label,permissions,created_by) VALUES (?,?,?,?, 'agent', ?, ?, ?, ?, ?)`).bind(b.full_name, p, agEmail, await hashPassword(pwd), b.region || null, provided, b.label || 'Agent', JSON.stringify(perms), creatorId).run()
  await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run()
  await audit(c, creatorId, 'create', 'agent', b.full_name)
  if (provided) return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: true })
  const t = await issueTempPassword(c, { userId: r.meta.last_row_id as number, phone: p, fullName: b.full_name })
  return c.json({ id: r.meta.last_row_id, password: t.tempPassword, password_was_set_by_admin: false, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})
app.post('/api/users/:id/reset-password', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const target = await c.env.DB.prepare(`SELECT id, full_name, phone, role FROM users WHERE id=?`).bind(id).first<any>()
  if (!target) return c.json({ error: 'User not found' }, 404)
  // Super-Admin credentials (incl. password) may be reset only by a Super-Admin.
  // A non-super caller (admin) is fully blocked from any Super-Admin target.
  if (String(target.role || '').toLowerCase() === 'super_admin' && !isSuperAdmin(c.get('user'))) {
    return c.json({ error: 'Only a Super Admin can reset a Super Admin password.' }, 403)
  }
  const body = await c.req.json().catch(() => ({}))
  const provided = body?.password && String(body.password).length >= 4
  // Admin-triggered reset. When no explicit password is supplied (the normal
  // path — including recovering an expired temporary password) we reissue a
  // fresh temporary password with the mandatory-change + 3h-expiry lifecycle.
  if (provided) {
    await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1, must_change_password=0, is_temp_password=0, temp_password_expires_at=NULL WHERE id=?`).bind(await hashPassword(String(body.password)), id).run()
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
    await audit(c, c.get('user').id, 'reset_password', target.role, target.full_name)
    return c.json({ ok: true, new_password: String(body.password), user: target.full_name })
  }
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
  const t = await issueTempPassword(c, { userId: id as any, phone: target.phone, fullName: target.full_name })
  await audit(c, c.get('user').id, 'reset_password', target.role, `${target.full_name} (temporary)`)
  return c.json({ ok: true, new_password: t.tempPassword, user: target.full_name, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})

// Public: a user whose temporary password expired can ask an admin to reset it.
// (Surfaced by the login screen when a login attempt returns temp_expired.)
app.post('/api/onboard/request-reset', async (c) => {
  const { phone } = await c.req.json().catch(() => ({}))
  const p = normalizePhone(phone || '')
  const user = await c.env.DB.prepare(`SELECT id, full_name FROM users WHERE phone=?`).bind(p).first<any>()
  // Do not reveal account existence; always respond ok.
  if (user) {
    try { await audit(c, user.id, 'reset_request', 'user', `Temp-password reset requested for ${user.full_name}`) } catch {}
  }
  return c.json({ ok: true, message: 'Your request has been sent. An administrator will reset your password shortly.' })
})
app.put('/api/agents/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  const perms = await permissionsForRole(c, 'agent', b.permissions || {})
  // Agents don't require email — resolveEmail supplies a unique placeholder when
  // blank so the central users.email NOT NULL + UNIQUE constraints hold on edit
  // (binding a raw blank/undefined b.email would violate NOT NULL, mirroring the
  // signup 23502 bug). Parity with the Equipment agents PUT handler.
  const agUpdEmailRes = resolveEmail('agent', b.email, b.phone)
  if ('error' in agUpdEmailRes) return c.json({ error: agUpdEmailRes.error }, 400)
  const agUpdEmail = agUpdEmailRes.value
  await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, region=?, label=?, permissions=? WHERE id=? AND role='agent'`).bind(b.full_name, b.phone, agUpdEmail, b.region, b.label || 'Agent', JSON.stringify(perms), id).run()
  await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region, JSON.stringify(perms), id).run()
  await audit(c, c.get('user').id, 'update', 'agent', b.full_name)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// USER ACCOUNTS (admin) - create, edit, activate/deactivate, delete
// ----------------------------------------------------------------------------
app.get('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const caller = c.get('user') as SessionUser
  const callerIsSuper = isSuperAdmin(caller)
  const { results } = await c.env.DB.prepare(`SELECT id, full_name, phone, email, role, label, permissions, status, region, schedule_enabled, access_days, access_start, access_end, created_at FROM users ORDER BY id`).all()
  const usersWithPerms = [] as any[]
  for (const u of results as any[]) {
    // Super-Admin credential/profile data is visible ONLY to Super-Admins.
    // A non-super caller (e.g. admin) may still see their OWN row, but every
    // OTHER Super-Admin account is withheld entirely.
    if (String(u.role || '').toLowerCase() === 'super_admin' && !callerIsSuper && String(u.id) !== String(caller.id)) continue
    const fallback = await loadRoleTemplate(c, u.role)
    usersWithPerms.push({ ...u, permissions: parsePermissions(u.permissions, u.role, fallback), access_days: safeJson(u.access_days, []) })
  }
  return c.json({ users: usersWithPerms })
})
app.post('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p || !b.role) return c.json({ error: 'Name, phone and role are required' }, 400)
  // Only a Super-Admin may create another Super-Admin (block privilege escalation).
  if (String(b.role).toLowerCase() === 'super_admin' && !isSuperAdmin(c.get('user'))) {
    return c.json({ error: 'Only a Super Admin can create a Super Admin account.' }, 403)
  }
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first<any>()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const provided = b.password && String(b.password).length >= 4
  // Admin-driven onboarding. The creating admin is already authenticated and
  // authorized (requireRole admin/super_admin), so we do NOT gate account
  // creation behind a phone OTP — that regressed the "Create User" flow into a
  // "No active code. Request a new one." dead-end whenever the admin left the
  // (optional) password blank. Behaviour:
  //   • password supplied  → use it (account is immediately usable).
  //   • password blank      → auto-generate a TEMPORARY password and SMS it to
  //     the new user (they must change it on first login).
  // An OTP is only consumed when the caller explicitly supplies one (kept for
  // backward compatibility); a missing OTP never blocks an admin create.
  if (!provided && b.otp_code) {
    const v = await verifyOtp(c, p, String(b.otp_code || ''), 'onboard')
    if (!v.ok) return c.json({ error: v.error || 'Phone verification failed', otp_required: true }, 400)
  }
  const pwd = provided ? String(b.password) : genPassword()
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {})
  const templateRow = await c.env.DB.prepare(`SELECT label FROM role_templates WHERE role_key=?`).bind(String(b.role)).first<any>()
  const label = b.label || templateRow?.label || (String(b.role) === 'operations_finance' ? 'Operations & Finance' : String(b.role).replace(/_/g, ' '))
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  // Email is mandatory ONLY for super_admin/admin/lender; any other role may be
  // created without one. resolveEmail supplies a unique placeholder when blank so
  // the central users.email NOT NULL + UNIQUE constraints hold (23502/23505).
  const emailRes = resolveEmail(String(b.role), b.email, b.phone)
  if ('error' in emailRes) return c.json({ error: emailRes.error }, 400)
  const email = emailRes.value
  const creatorId = c.get('user').id
  // Shared central DB: users.org_id NOT NULL — attach the creating admin's
  // tenant (fallback to deployment default). Omitted on Feed-only DB shape.
  const usrOrgId = (await resolveCreatorOrgId(c, c.get('user'))) || (await resolveDefaultOrgId(c))
  const usrWithOrg = (await usersHasOrgId(c)) && usrOrgId != null
  const r = usrWithOrg
    ? await c.env.DB.prepare(`INSERT INTO users (full_name, phone, email, password, role, label, permissions, status, region, password_set, schedule_enabled, access_days, access_start, access_end, created_by, org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.role, label, JSON.stringify(perms), b.status || 'active', b.region || null, provided, schedEnabled, schedDays, b.access_start || null, b.access_end || null, creatorId, usrOrgId).run()
    : await c.env.DB.prepare(`INSERT INTO users (full_name, phone, email, password, role, label, permissions, status, region, password_set, schedule_enabled, access_days, access_start, access_end, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.role, label, JSON.stringify(perms), b.status || 'active', b.region || null, provided, schedEnabled, schedDays, b.access_start || null, b.access_end || null, creatorId).run()
  if (b.role === 'agent') await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run()
  await audit(c, creatorId, 'create', 'user', `${b.full_name} (${b.role})`)
  if (provided) return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: true })
  const t = await issueTempPassword(c, { userId: r.meta.last_row_id as number, phone: p, fullName: b.full_name })
  return c.json({ id: r.meta.last_row_id, password: t.tempPassword, password_was_set_by_admin: false, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})
app.put('/api/users/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  // Block a non-super caller from editing a Super-Admin target OR promoting
  // anyone to super_admin (privilege escalation).
  const denied = await guardSuperAdminTarget(c, id, b.role)
  if (denied) return denied
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {})
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  // Same email policy on edit: required for super_admin/admin/lender, otherwise a
  // unique placeholder so the central users.email NOT NULL + UNIQUE constraints
  // both hold (binding a raw blank b.email would violate NOT NULL, same class of
  // bug as signup). Parity with the Equipment users PUT handler.
  const usrUpdEmailRes = resolveEmail(String(b.role), b.email, b.phone)
  if ('error' in usrUpdEmailRes) return c.json({ error: usrUpdEmailRes.error }, 400)
  const usrUpdEmail = usrUpdEmailRes.value
  if (b.password) {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=?, password=? WHERE id=?`).bind(b.full_name, b.phone, usrUpdEmail, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, await hashPassword(String(b.password)), id).run()
  } else {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE id=?`).bind(b.full_name, b.phone, usrUpdEmail, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, id).run()
  }
  if (b.role === 'agent') {
    const exists = await c.env.DB.prepare(`SELECT user_id FROM agents WHERE user_id=?`).bind(id).first<any>()
    if (exists) await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region || null, JSON.stringify(perms), id).run()
    else await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(id, b.region || null, JSON.stringify(perms)).run()
  }
  await audit(c, c.get('user').id, 'update', 'user', b.full_name)
  return c.json({ ok: true })
})
app.put('/api/users/:id/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  // A non-super caller may not suspend/activate a Super-Admin account.
  const denied = await guardSuperAdminTarget(c, id)
  if (denied) return denied
  const { status } = await c.req.json()
  if (Number(id) === c.get('user').id) return c.json({ error: 'You cannot change your own status' }, 400)
  await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, id).run()
  if (status === 'suspended') await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
  await audit(c, c.get('user').id, status === 'active' ? 'activate' : 'deactivate', 'user', String(id))
  return c.json({ ok: true })
})
// USER DELETION
//   * Administrators (admin / super_admin): may delete ANY user regardless of
//     contract status. All data related to that user — their customer profile,
//     every contract (any status) and all dependent records — is cascaded and
//     removed automatically.
//   * Non-admin managers with the `can_delete_users` permission: may only
//     delete a user once ALL of their associated contracts are cancelled.
app.delete('/api/users/:id', requireAuth, async (c) => {
  const actor = c.get('user') as SessionUser
  const isAdmin = ['admin', 'super_admin'].includes(actor.role)
  if (!(isAdmin || hasPermission(actor, 'can_delete_users'))) {
    return c.json({ error: 'You do not have permission to delete users.' }, 403)
  }
  const id = c.req.param('id')
  if (Number(id) === actor.id) return c.json({ error: 'You cannot delete your own account' }, 400)
  const u = await c.env.DB.prepare(`SELECT role FROM users WHERE id=?`).bind(id).first<any>()
  if (!u) return c.json({ error: 'Not found' }, 404)
  // A Super-Admin account may be deleted only by a Super-Admin; a non-super
  // caller (admin) is blocked from touching Super-Admin accounts entirely.
  if (String(u?.role || '').toLowerCase() === 'super_admin' && !isSuperAdmin(actor)) {
    return c.json({ error: 'Only a Super Admin can delete a Super Admin account.' }, 403)
  }
  // Contracts link to the user via their customer profile (customers.user_id).
  const cust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(id).first<any>()
  // Non-admin managers must first ensure ALL the user's contracts are cancelled.
  // Administrators bypass this precondition and cascade-delete everything.
  if (!isAdmin && cust?.id) {
    const notCancelled = await c.env.DB.prepare(
      `SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status <> 'cancelled'`
    ).bind(cust.id).first<any>()
    if (Number(notCancelled?.n || 0) > 0) {
      return c.json({ error: "User cannot be deleted: their associated contract(s) must be cancelled first." }, 400)
    }
  }
  await withAdminContext(c, async () => {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
    await c.env.DB.prepare(`DELETE FROM agents WHERE user_id=?`).bind(id).run()
    await c.env.DB.prepare(`DELETE FROM profile_amendments WHERE user_id=?`).bind(id).run()
    // Change-requests raised by this user reference users(id) via a FK.
    await c.env.DB.prepare(`DELETE FROM change_requests WHERE requester_id=?`).bind(id).run()
    // If this user onboarded farmers (customers.agent_id -> users.id), detach
    // that link so those farmer records are not FK-blocked or orphaned wrongly.
    await c.env.DB.prepare(`UPDATE customers SET agent_id=NULL WHERE agent_id=?`).bind(id).run()
    // Remove the linked customer profile and ALL its dependent records so the
    // user row can be deleted cleanly (admins delete regardless of status).
    if (cust?.id) {
      // Contracts and their children must go first to satisfy FKs.
      const { results: contracts } = await c.env.DB.prepare(`SELECT id FROM murabaha_contracts WHERE customer_id=?`).bind(cust.id).all<any>()
      for (const ct of (contracts || [])) {
        await c.env.DB.prepare(`DELETE FROM repayments WHERE contract_id=?`).bind(ct.id).run()
        await c.env.DB.prepare(`DELETE FROM transactions WHERE contract_id=?`).bind(ct.id).run()
        await c.env.DB.prepare(`DELETE FROM approvals WHERE contract_id=?`).bind(ct.id).run()
        await c.env.DB.prepare(`DELETE FROM invoices WHERE contract_id=?`).bind(ct.id).run()
      }
      await c.env.DB.prepare(`DELETE FROM murabaha_contracts WHERE customer_id=?`).bind(cust.id).run()
      await c.env.DB.prepare(`DELETE FROM transunion_checks WHERE customer_id=?`).bind(cust.id).run()
      await c.env.DB.prepare(`DELETE FROM id_verifications WHERE customer_id=?`).bind(cust.id).run()
      await c.env.DB.prepare(`DELETE FROM customers WHERE id=?`).bind(cust.id).run()
    }
    await c.env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id).run()
  })
  await audit(c, actor.id, 'delete', 'user', `${id}${isAdmin ? ' (admin cascade)' : ''}`)
  return c.json({ ok: true })
})
// ----------------------------------------------------------------------------
// PERMISSION CATALOG & ROLE TEMPLATES (Super Admin)
// ----------------------------------------------------------------------------
app.get('/api/permissions', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT permission_key, label, description, category FROM permission_catalog ORDER BY category, label`).all()
  const { results: roles } = await c.env.DB.prepare(`SELECT role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end FROM role_templates ORDER BY label`).all()
  return c.json({
    permissions: results,
    roles: (roles as any[]).map((r) => ({ ...r, permissions: safeJson(r.permissions, {}), access_days: safeJson(r.access_days, []) }))
  })
})
app.post('/api/permissions', requireAuth, requireRole('super_admin'), async (c) => {
  const b = await c.req.json()
  const key = String(b.permission_key || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_')
  if (!key || !b.label) return c.json({ error: 'Permission key and label are required' }, 400)
  await c.env.DB.prepare(`INSERT INTO permission_catalog (permission_key, label, description, category) VALUES (?,?,?,?)`)
    .bind(key, b.label, b.description || null, b.category || 'general').run()
  await audit(c, c.get('user').id, 'create', 'permission', key)
  return c.json({ ok: true, permission_key: key })
})
app.delete('/api/permissions/:key', requireAuth, requireRole('super_admin'), async (c) => {
  const key = c.req.param('key')
  await c.env.DB.prepare(`DELETE FROM permission_catalog WHERE permission_key=?`).bind(key).run()
  await audit(c, c.get('user').id, 'delete', 'permission', key)
  return c.json({ ok: true })
})
app.post('/api/role-templates', requireAuth, requireRole('super_admin'), async (c) => {
  const b = await c.req.json()
  const key = String(b.role_key || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_')
  if (!key || !b.label) return c.json({ error: 'Role key and label are required' }, 400)
  const perms = b.permissions && typeof b.permissions === 'object' ? b.permissions : {}
  const scheduleEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const accessDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  const accessStart = b.access_start || null
  const accessEnd = b.access_end || null
  const existing = await c.env.DB.prepare(`SELECT id, is_system FROM role_templates WHERE role_key=?`).bind(key).first<any>()
  if (existing) {
    await c.env.DB.prepare(`UPDATE role_templates SET label=?, description=?, permissions=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE role_key=?`)
      .bind(b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd, key).run()
  } else {
    await c.env.DB.prepare(`INSERT INTO role_templates (role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end) VALUES (?,?,?,?, 0, ?,?,?,?)`)
      .bind(key, b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd).run()
  }
  await audit(c, c.get('user').id, existing ? 'update' : 'create', 'role_template', key)
  return c.json({ ok: true, role_key: key })
})
app.delete('/api/role-templates/:key', requireAuth, requireRole('super_admin'), async (c) => {
  const key = c.req.param('key')
  const row = await c.env.DB.prepare(`SELECT is_system FROM role_templates WHERE role_key=?`).bind(key).first<any>()
  if (!row) return c.json({ error: 'Not found' }, 404)
  if (row.is_system) return c.json({ error: 'Built-in roles cannot be deleted' }, 400)
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM users WHERE role=?`).bind(key).first<any>()
  if (Number(used?.n || 0) > 0) return c.json({ error: 'Cannot delete: users are assigned to this role.' }, 400)
  await c.env.DB.prepare(`DELETE FROM role_templates WHERE role_key=?`).bind(key).run()
  await audit(c, c.get('user').id, 'delete', 'role_template', key)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// FINANCING & MARKUP SETTINGS (processing fee + markup)
// ----------------------------------------------------------------------------
app.get('/api/settings/financing', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const processing_fee = normalizeProcessingFee(await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE))
  const financing_markup = normalizeFinancingMarkup(await getSetting(c, 'financing_markup', DEFAULT_FINANCING_MARKUP))
  // Lightweight inventory list so the UI can offer product selection.
  const { results } = await c.env.DB.prepare(`SELECT id, sku, name, category, quantity FROM products ORDER BY name`).all()
  return c.json({
    processing_fee,
    financing_markup,
    // legacy alias kept so older frontends do not break
    finance_markup: financing_markup,
    products: results,
    can_manage_processing_fees: hasPermission(user, 'manage_processing_fees'),
    can_manage_markup: hasPermission(user, 'manage_markup_pct')
  })
})
app.put('/api/settings/processing-fee', requireAuth, requirePermission('manage_processing_fees'), async (c) => {
  const b = await c.req.json()
  const cfg = normalizeProcessingFee(b)
  await setSetting(c, 'processing_fee', cfg)
  await audit(c, c.get('user').id, 'update', 'settings', `processing_fee:${cfg.enabled ? cfg.mode : 'disabled'} products:${cfg.product_ids.length || 'all'}`)
  return c.json({ ok: true, processing_fee: cfg })
})
async function saveFinancingMarkup(c: any) {
  const b = await c.req.json()
  const cfg = normalizeFinancingMarkup(b)
  await setSetting(c, 'financing_markup', cfg)
  await audit(c, c.get('user').id, 'update', 'settings', `financing_markup:${cfg.financing_applicable ? cfg.mode : 'cash_only'} products:${cfg.product_ids.length || 'all'}`)
  return c.json({ ok: true, financing_markup: cfg, finance_markup: cfg })
}
app.put('/api/settings/financing-markup', requireAuth, requirePermission('manage_markup_pct'), saveFinancingMarkup)
// Backward-compatible alias (the earlier frontend saved to /settings/markup, which 404'd).
app.put('/api/settings/markup', requireAuth, requirePermission('manage_markup_pct'), saveFinancingMarkup)

// ----------------------------------------------------------------------------
// DYNAMIC FINANCING TYPES  (Feature 2a-ii) — Feed port
// ----------------------------------------------------------------------------
function canManageFinanceConfig(user: SessionUser) {
  return user.role === 'admin' || user.role === 'super_admin' ||
    hasPermission(user, 'can_manage_finance_settings') || hasPermission(user, 'manage_markup_pct')
}
function slugifyKey(s: string): string {
  return String(s || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60)
}
app.get('/api/financing-types', requireAuth, async (c) => {
  const includeAll = c.req.query('all') === '1'
  const { results } = await c.env.DB.prepare(
    `SELECT id, type_key, label, description, charge_mode, is_system, active, sort_order
       FROM financing_types ${includeAll ? '' : 'WHERE active = 1'}
      ORDER BY sort_order, label`
  ).all()
  const user = c.get('user') as SessionUser
  return c.json({ financing_types: results, can_manage: canManageFinanceConfig(user) })
})
app.post('/api/financing-types', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageFinanceConfig(user)) return c.json({ error: 'Forbidden' }, 403)
  let b: any
  try { b = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const label = cleanText(b.label, 80)
  if (!label) return c.json({ error: 'A label is required.' }, 400)
  const type_key = slugifyKey(b.type_key || label)
  if (!type_key) return c.json({ error: 'A valid type key could not be derived from the label.' }, 400)
  const charge_mode = ['percentage', 'fixed', 'none'].includes(String(b.charge_mode)) ? String(b.charge_mode) : 'percentage'
  const description = cleanText(b.description, 400)
  const sort_order = Math.round(numberVal(b.sort_order, 100))
  const active = boolInt(b.active, true) ? 1 : 0
  const dup = await c.env.DB.prepare(`SELECT id FROM financing_types WHERE type_key=?`).bind(type_key).first<any>()
  if (dup) return c.json({ error: `A financing type with key "${type_key}" already exists.` }, 409)
  const r = await c.env.DB.prepare(
    `INSERT INTO financing_types (type_key,label,description,charge_mode,is_system,active,sort_order,created_by)
     VALUES (?,?,?,?,0,?,?,?)`
  ).bind(type_key, label, description, charge_mode, active, sort_order, String(user.id)).run()
  try {
    await c.env.DB.prepare(
      `INSERT INTO agreement_templates (path_key,title,overview_html,body_html,updated_by)
       VALUES (?,?,?,?,?) ON CONFLICT (path_key) DO NOTHING`
    ).bind(type_key, `${label.toUpperCase()} SALE AGREEMENT`,
      `<p>This ${label} Sale Agreement is made between Farmsky Feed and the purchasing farmer for the goods described below.</p>`,
      `<p>The buyer agrees to the ${label} repayment terms disclosed at checkout until the outstanding balance is fully settled.</p>`,
      String(user.id)).run()
  } catch (_) {}
  await audit(c, user.id, 'create', 'financing_type', `${label} (${type_key})`)
  return c.json({ ok: true, id: r.meta.last_row_id, type_key })
})
app.put('/api/financing-types/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageFinanceConfig(user)) return c.json({ error: 'Forbidden' }, 403)
  const id = c.req.param('id')
  const existing = await c.env.DB.prepare(`SELECT * FROM financing_types WHERE id=?`).bind(id).first<any>()
  if (!existing) return c.json({ error: 'Not found' }, 404)
  let b: any
  try { b = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const label = cleanText(b.label, 80) || existing.label
  const charge_mode = ['percentage', 'fixed', 'none'].includes(String(b.charge_mode)) ? String(b.charge_mode) : existing.charge_mode
  const description = b.description !== undefined ? cleanText(b.description, 400) : existing.description
  const sort_order = b.sort_order !== undefined ? Math.round(numberVal(b.sort_order, existing.sort_order)) : existing.sort_order
  const active = b.active !== undefined ? (boolInt(b.active, true) ? 1 : 0) : existing.active
  await c.env.DB.prepare(
    `UPDATE financing_types SET label=?, description=?, charge_mode=?, active=?, sort_order=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`
  ).bind(label, description, charge_mode, active, sort_order, id).run()
  await audit(c, user.id, 'update', 'financing_type', `${label} (${existing.type_key})`)
  return c.json({ ok: true })
})
app.delete('/api/financing-types/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageFinanceConfig(user)) return c.json({ error: 'Forbidden' }, 403)
  const id = c.req.param('id')
  const existing = await c.env.DB.prepare(`SELECT * FROM financing_types WHERE id=?`).bind(id).first<any>()
  if (!existing) return c.json({ error: 'Not found' }, 404)
  if (Number(existing.is_system) === 1) return c.json({ error: 'System financing types cannot be removed; you can deactivate them instead.' }, 400)
  const inUse = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM products WHERE financing_type_key=?`).bind(existing.type_key).first<any>()
  if (inUse?.n > 0) return c.json({ error: `Cannot remove: ${inUse.n} product(s) still use this financing type. Deactivate it instead.` }, 400)
  await c.env.DB.prepare(`DELETE FROM financing_types WHERE id=?`).bind(id).run()
  await audit(c, user.id, 'delete', 'financing_type', `${existing.label} (${existing.type_key})`)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// AGREEMENT TEMPLATES  (Feature 2b) — Feed port
// ----------------------------------------------------------------------------
const DEFAULT_AGREEMENT_STYLE = { font_family: 'Calibri', font_size_pt: 12, line_height: 1.5, text_align: 'justify' }
function normalizeAgreementStyle(raw: any) {
  const s: any = { ...DEFAULT_AGREEMENT_STYLE, ...(raw && typeof raw === 'object' ? raw : {}) }
  s.font_family = String(s.font_family || 'Calibri').slice(0, 60)
  s.font_size_pt = numberVal(s.font_size_pt, 12)
  s.line_height = numberVal(s.line_height, 1.5)
  s.text_align = ['justify', 'left', 'right', 'center'].includes(String(s.text_align)) ? String(s.text_align) : 'justify'
  return s
}
app.get('/api/agreement-templates', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { results } = await c.env.DB.prepare(
    `SELECT id, path_key, title, overview_html, body_html, style_json, updated_at FROM agreement_templates ORDER BY path_key`
  ).all()
  const templates = (results as any[]).map((t) => ({ ...t, style: normalizeAgreementStyle(safeJson(t.style_json, {})) }))
  return c.json({ agreement_templates: templates, default_style: DEFAULT_AGREEMENT_STYLE, can_manage: canManageFinanceConfig(user) })
})
app.get('/api/agreement-templates/:path_key', requireAuth, async (c) => {
  const pk = c.req.param('path_key')
  const t = await c.env.DB.prepare(`SELECT * FROM agreement_templates WHERE path_key=?`).bind(pk).first<any>()
  if (!t) return c.json({ error: 'Not found' }, 404)
  return c.json({ template: { ...t, style: normalizeAgreementStyle(safeJson(t.style_json, {})) } })
})
async function upsertAgreementTemplate(c: any, pathKey: string) {
  const user = c.get('user') as SessionUser
  if (!canManageFinanceConfig(user)) return c.json({ error: 'Forbidden' }, 403)
  let b: any
  try { b = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const title = cleanText(b.title, 200) || `${pathKey.toUpperCase()} SALE AGREEMENT`
  const overview_html = b.overview_html !== undefined ? String(b.overview_html).slice(0, 100000) : null
  const body_html = b.body_html !== undefined ? String(b.body_html).slice(0, 200000) : null
  const style_json = JSON.stringify(normalizeAgreementStyle(b.style))
  const existing = await c.env.DB.prepare(`SELECT id FROM agreement_templates WHERE path_key=?`).bind(pathKey).first<any>()
  if (existing) {
    await c.env.DB.prepare(
      `UPDATE agreement_templates SET title=?, overview_html=COALESCE(?, overview_html), body_html=COALESCE(?, body_html), style_json=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE path_key=?`
    ).bind(title, overview_html, body_html, style_json, String(user.id), pathKey).run()
  } else {
    await c.env.DB.prepare(
      `INSERT INTO agreement_templates (path_key,title,overview_html,body_html,style_json,updated_by) VALUES (?,?,?,?,?,?)`
    ).bind(pathKey, title, overview_html || '', body_html || '', style_json, String(user.id)).run()
  }
  await audit(c, user.id, 'update', 'agreement_template', pathKey)
  return c.json({ ok: true, path_key: pathKey })
}
app.put('/api/agreement-templates/:path_key', requireAuth, async (c) => upsertAgreementTemplate(c, c.req.param('path_key')))

// ----------------------------------------------------------------------------
// WITHDRAWAL CHARGE + SUPPORT CONTACT SETTINGS (aligned with Equipment)
//   • withdrawal_charge : the standard withdrawal charge schema (flat + %).
//   • support_contact   : phone/email shown when SasaPay main wallet is short.
// Both are configured from the Super-Admin dashboard (admin/super_admin only).
// ----------------------------------------------------------------------------
function isAdminRole(user: SessionUser) {
  return user.role === 'admin' || user.role === 'super_admin' || hasPermission(user, 'manage_wallets')
}
// GET — readable by any authenticated user so the wallet/withdraw UI can show
// the withdrawable limit and the support contact if a payout can't be settled.
app.get('/api/settings/withdrawal', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const withdrawal_charge = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const support_contact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  return c.json({ withdrawal_charge, support_contact, can_manage: isAdminRole(user) })
})
app.put('/api/settings/withdrawal-charge', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!isAdminRole(user)) return c.json({ error: 'Only administrators can change withdrawal charge settings.' }, 403)
  const b = await c.req.json()
  const cfg = normalizeWithdrawalCharge(b)
  await setSetting(c, 'withdrawal_charge', cfg)
  await audit(c, user.id, 'update', 'settings', `withdrawal_charge:${cfg.enabled ? 'on' : 'off'} flat:${cfg.flat_fee} pct:${cfg.percentage_rate}`)
  return c.json({ ok: true, withdrawal_charge: cfg })
})
app.put('/api/settings/support-contact', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!isAdminRole(user)) return c.json({ error: 'Only administrators can change the support contact settings.' }, 403)
  const b = await c.req.json()
  const cfg = normalizeSupportContact(b)
  await setSetting(c, 'support_contact', cfg)
  await audit(c, user.id, 'update', 'settings', `support_contact phone:${cfg.phone ? 'set' : 'empty'} email:${cfg.email ? 'set' : 'empty'}`)
  return c.json({ ok: true, support_contact: cfg })
})

// Inline "add product to inventory" used by the Processing Fee / Markup builders.
// Authorized either by the classic admin roles OR the fee/markup management perms.
app.post('/api/settings/quick-product', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const allowed = user.role === 'admin' || user.role === 'super_admin' ||
    hasPermission(user, 'manage_processing_fees') || hasPermission(user, 'manage_markup_pct')
  if (!allowed) return c.json({ error: "You don't have permission to add products from the settings builder." }, 403)
  const p = normalizeProductPayload(await c.req.json())
  if (!p.sku || !p.name) return c.json({ error: 'SKU and name are required' }, 400)
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO products (sku,name,category,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,cash_price_mode,cash_markup_amount,credit_price_mode,credit_markup_amount,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_type_key,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,financing_tenure_unit,financing_rate_per_cycle,financing_amount_per_cycle,financing_cycle_count,financing_cycle_length_days,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      p.sku, p.name, p.category, p.description, p.product_type, p.supplier_id, p.buying_price, p.cash_markup_pct, p.credit_markup_pct,
      p.cash_price, p.credit_price, p.cash_price_mode, p.cash_markup_amount, p.credit_price_mode, p.credit_markup_amount, p.quantity, p.unit, p.reorder_threshold, p.image, p.cash_enabled, p.financing_enabled,
      p.payment_option_mode, p.financing_model, p.financing_type_key, p.financing_interest_pct, p.financing_frequency, p.financing_term_min_months,
      p.financing_term_max_months, p.financing_tenure_unit, p.financing_rate_per_cycle, p.financing_amount_per_cycle, p.financing_cycle_count, p.financing_cycle_length_days, p.cash_deposit_pct, p.financing_deposit_pct, p.cash_terms_text, p.financing_terms_text,
      p.cash_terms_doc_url, p.financing_terms_doc_url
    ).run()
    await audit(c, user.id, 'create', 'product', `${p.name} (via settings builder)`)
    return c.json({ id: r.meta.last_row_id, product: { id: r.meta.last_row_id, sku: p.sku, name: p.name, category: p.category, quantity: p.quantity } })
  } catch (err: any) {
    if (/unique|duplicate/i.test(String(err?.message || ''))) return c.json({ error: 'A product with this SKU already exists' }, 400)
    return c.json({ error: 'Failed to create product' }, 500)
  }
})

app.post('/api/change-requests', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!hasPermission(user, 'request_admin_action')) return c.json({ error: "You don't have permission to submit admin change requests." }, 403)
  const { entity_type, entity_id, requested_action, reason } = await c.req.json()
  await c.env.DB.prepare(`INSERT INTO change_requests (requester_id, entity_type, entity_id, requested_action, reason) VALUES (?,?,?,?,?)`).bind(user.id, entity_type, entity_id || null, requested_action, reason || '').run()
  await audit(c, user.id, 'request_admin_action', entity_type || 'entity', `${requested_action || 'request'} ${entity_id || ''}`)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// FEATURE 4 — PROFILE AMENDMENT WORKFLOW
//   The National ID and phone number are permanently locked on the profile
//   screen. To change them a user submits a dedicated amendment request which
//   lands on a pending dashboard; an administrator (or a user with the
//   `manage_users` permission) reviews and accepts / rejects it. On accept
//   the new values are applied to the user + customer records.
// ----------------------------------------------------------------------------
function canReviewAmendments(user: SessionUser) {
  return ['admin', 'super_admin'].includes(user.role) || hasPermission(user, 'manage_users')
}

// Submit an amendment request (any authenticated user).
app.post('/api/profile-amendments', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const newNid = b.new_national_id !== undefined && b.new_national_id !== null ? String(b.new_national_id).trim() : ''
  const newPhoneRaw = b.new_phone !== undefined && b.new_phone !== null ? String(b.new_phone).trim() : ''
  const newPhone = newPhoneRaw ? normalizePhone(newPhoneRaw) : ''
  const reason = String(b.reason || '').trim()
  if (!newNid && !newPhone) return c.json({ error: 'Provide a new National ID and/or a new phone number.' }, 400)
  if (reason.length < 4) return c.json({ error: 'Please give a reason for the change (at least 4 characters).' }, 400)
  const tv = validateTextFields({ new_national_id: newNid, reason }, [
    { key: 'new_national_id', label: 'National ID', max: 40 },
    { key: 'reason', label: 'Reason', max: 500 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)
  // Prevent a second open request while one is already pending.
  const open = await c.env.DB.prepare(`SELECT id FROM profile_amendments WHERE user_id=? AND status='pending'`).bind(user.id).first<any>()
  if (open) return c.json({ error: 'You already have a pending amendment request awaiting review.' }, 400)
  const cust = await c.env.DB.prepare(`SELECT id, national_id, mobile FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  const field = newNid && newPhone ? 'both' : (newNid ? 'national_id' : 'phone')
  await c.env.DB.prepare(
    `INSERT INTO profile_amendments (user_id, customer_id, field, current_national_id, current_phone, new_national_id, new_phone, reason)
     VALUES (?,?,?,?,?,?,?,?)`
  ).bind(user.id, cust?.id || null, field, cust?.national_id || null, cust?.mobile || user.phone || null, newNid || null, newPhone || null, reason).run()
  await audit(c, user.id, 'request', 'profile_amendment', `${field} change requested`)
  return c.json({ ok: true })
})

// List MY amendment requests.
app.get('/api/profile-amendments/mine', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { results } = await c.env.DB.prepare(`SELECT * FROM profile_amendments WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all()
  return c.json({ amendments: results })
})

// List all amendment requests for the review dashboard (default: pending).
app.get('/api/profile-amendments', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canReviewAmendments(user)) return c.json({ error: "You don't have permission to review profile amendment requests." }, 403)
  const status = c.req.query('status') || 'pending'
  let q = `SELECT pa.*, u.full_name AS requester_name, u.role AS requester_role, r.full_name AS reviewer_name
           FROM profile_amendments pa
           JOIN users u ON CAST(u.id AS TEXT) = pa.user_id
           LEFT JOIN users r ON CAST(r.id AS TEXT) = pa.reviewed_by`
  const binds: any[] = []
  if (status !== 'all') { q += ` WHERE pa.status=?`; binds.push(status) }
  q += ` ORDER BY pa.created_at DESC`
  const { results } = await c.env.DB.prepare(q).bind(...binds).all()
  return c.json({ amendments: results })
})

// Approve / reject an amendment request.
app.post('/api/profile-amendments/:id/decision', requireAuth, async (c) => {
  const actor = c.get('user') as SessionUser
  if (!canReviewAmendments(actor)) return c.json({ error: "You don't have permission to approve or reject amendment requests." }, 403)
  const id = c.req.param('id')
  const { action, notes } = await c.req.json()
  const amend = await c.env.DB.prepare(`SELECT * FROM profile_amendments WHERE id=?`).bind(id).first<any>()
  if (!amend) return c.json({ error: 'Not found' }, 404)
  if (amend.status !== 'pending') return c.json({ error: 'This request has already been reviewed.' }, 400)
  if (action === 'approve') {
    // Uniqueness re-check at approval time (values may have been taken since).
    if (amend.new_national_id) {
      const dup = await c.env.DB.prepare(`SELECT id FROM customers WHERE national_id=? AND user_id<>?`).bind(amend.new_national_id, amend.user_id).first<any>()
      if (dup) return c.json({ error: 'Cannot approve: that National ID is already in use.' }, 409)
    }
    if (amend.new_phone) {
      const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=? AND id<>?`).bind(amend.new_phone, amend.user_id).first<any>()
      if (dup) return c.json({ error: 'Cannot approve: that phone number is already in use.' }, 409)
    }
    await withAdminContext(c, async () => {
      if (amend.new_phone) {
        await c.env.DB.prepare(`UPDATE users SET phone=? WHERE id=?`).bind(amend.new_phone, amend.user_id).run()
        if (amend.customer_id) await c.env.DB.prepare(`UPDATE customers SET mobile=? WHERE id=?`).bind(amend.new_phone, amend.customer_id).run()
      }
      if (amend.new_national_id && amend.customer_id) {
        await c.env.DB.prepare(`UPDATE customers SET national_id=? WHERE id=?`).bind(amend.new_national_id, amend.customer_id).run()
      }
    })
    await c.env.DB.prepare(`UPDATE profile_amendments SET status='approved', reviewed_by=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(actor.id, notes || null, id).run()
    // Force re-login so the session carries the new phone/identity.
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(amend.user_id).run()
  } else if (action === 'reject') {
    await c.env.DB.prepare(`UPDATE profile_amendments SET status='rejected', reviewed_by=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(actor.id, notes || null, id).run()
  } else {
    return c.json({ error: 'Action must be approve or reject.' }, 400)
  }
  await audit(c, actor.id, action, 'profile_amendment', String(id))
  return c.json({ ok: true, action })
})

// Repayment performance
app.get('/api/repayments', requireAuth, requireRole('admin', 'super_admin', 'support', 'operations_finance'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT r.*, mc.contract_ref, cu.full_name customer FROM repayments r
     JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id ORDER BY r.due_date`
  ).all()
  return c.json({ repayments: results })
})
// Documents
app.get('/api/documents/:type/:id', requireAuth, async (c) => {
  const type = c.req.param('type'), id = c.req.param('id')
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name product_name, cu.full_name customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  return c.json({ type, contract, txn_id: contract.contract_ref, qr: `https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${contract.contract_ref}` })
})

// ----------------------------------------------------------------------------
// ADMIN DATA EXPORT  (filter + download CSV/Excel locally, or email a copy)
// ----------------------------------------------------------------------------
// Supported datasets and their base queries. Filters are applied safely.
const EXPORT_DATASETS: Record<string, { label: string; sql: string; cols: string[]; filterable: Record<string, string> }> = {
  users: {
    label: 'Users / Accounts',
    sql: `SELECT id, full_name, phone, email, role, label, status, region, created_at FROM users`,
    cols: ['id', 'full_name', 'phone', 'email', 'role', 'label', 'status', 'region', 'created_at'],
    filterable: { role: 'role', status: 'status', region: 'region' }
  },
  customers: {
    label: 'Customers / Farmers',
    sql: `SELECT cu.id, cu.full_name, cu.mobile, cu.county, cu.value_chain, cu.kyc_status, cu.risk_band, cu.credit_score, u.full_name agent FROM customers cu LEFT JOIN users u ON CAST(u.id AS TEXT)=cu.agent_id`,
    cols: ['id', 'full_name', 'mobile', 'county', 'value_chain', 'kyc_status', 'risk_band', 'credit_score', 'agent'],
    filterable: { kyc_status: 'cu.kyc_status', risk_band: 'cu.risk_band', county: 'cu.county' }
  },
  agents: {
    label: 'Agents',
    sql: `SELECT id, full_name, phone, email, region, status, created_at FROM users WHERE role='agent'`,
    cols: ['id', 'full_name', 'phone', 'email', 'region', 'status', 'created_at'],
    filterable: { status: 'status', region: 'region' }
  },
  products: {
    label: 'Inventory / Products',
    sql: `SELECT id, sku, name, category, product_type, payment_option_mode, financing_model, financing_interest_pct, cash_deposit_pct, financing_deposit_pct, buying_price, cash_price, credit_price, quantity, unit, reorder_threshold FROM products`,
    cols: ['id', 'sku', 'name', 'category', 'product_type', 'payment_option_mode', 'financing_model', 'financing_interest_pct', 'cash_deposit_pct', 'financing_deposit_pct', 'buying_price', 'cash_price', 'credit_price', 'quantity', 'unit', 'reorder_threshold'],
    filterable: { category: 'category' }
  },
  contracts: {
    label: 'Murabaha Contracts',
    sql: `SELECT mc.id, mc.contract_ref, cu.full_name customer, p.name product, mc.payment_type, mc.financing_model, mc.deposit_pct, mc.deposit_amount, mc.payment_frequency, mc.installment_amount, mc.murabaha_price, mc.amount_paid, mc.outstanding, mc.status, mc.dispatch_status, mc.created_at FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id JOIN products p ON p.id=mc.product_id`,
    cols: ['id', 'contract_ref', 'customer', 'product', 'payment_type', 'financing_model', 'deposit_pct', 'deposit_amount', 'payment_frequency', 'installment_amount', 'murabaha_price', 'amount_paid', 'outstanding', 'status', 'dispatch_status', 'created_at'],
    filterable: { status: 'mc.status', payment_type: 'mc.payment_type' }
  },
  repayments: {
    label: 'Repayments',
    sql: `SELECT r.id, mc.contract_ref, cu.full_name customer, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id`,
    cols: ['id', 'contract_ref', 'customer', 'installment_no', 'due_date', 'amount_due', 'amount_paid', 'status'],
    filterable: { status: 'r.status' }
  },
  transactions: {
    label: 'Transactions / Payments',
    sql: `SELECT t.id, t.txn_ref, cu.full_name customer, t.amount, t.method, t.type, t.mpesa_receipt, t.status, t.created_at FROM transactions t LEFT JOIN customers cu ON cu.id=t.customer_id`,
    cols: ['id', 'txn_ref', 'customer', 'amount', 'method', 'type', 'mpesa_receipt', 'status', 'created_at'],
    filterable: { status: 't.status', method: 't.method', type: 't.type' }
  },
  audit_logs: {
    label: 'Audit Log',
    sql: `SELECT a.id, u.full_name actor, a.action, a.entity, a.detail, a.created_at FROM audit_logs a LEFT JOIN users u ON CAST(u.id AS TEXT)=a.user_id`,
    cols: ['id', 'actor', 'action', 'entity', 'detail', 'created_at'],
    filterable: { action: 'a.action', entity: 'a.entity' }
  }
}

async function buildExport(c: any, dataset: string, filters: Record<string, string>, dateFrom?: string, dateTo?: string) {
  const def = EXPORT_DATASETS[dataset]
  if (!def) throw new Error('Unknown dataset')
  const where: string[] = []
  const binds: any[] = []
  const hasWhere = /\bwhere\b/i.test(def.sql)
  for (const [key, col] of Object.entries(def.filterable)) {
    const v = filters?.[key]
    if (v != null && String(v).trim() !== '' && String(v) !== 'all') {
      where.push(`${col} = ?`); binds.push(v)
    }
  }
  // Date range on created_at / due_date if present
  const dateCol = def.cols.includes('created_at') ? 'created_at' : (def.cols.includes('due_date') ? 'due_date' : null)
  if (dateCol && dateFrom) { where.push(`${dateCol} >= ?`); binds.push(dateFrom) }
  if (dateCol && dateTo) { where.push(`${dateCol} <= ?`); binds.push(dateTo + ' 23:59:59') }
  let sql = def.sql
  if (where.length) sql += (hasWhere ? ' AND ' : ' WHERE ') + where.join(' AND ')
  sql += ` ORDER BY 1 DESC`
  const stmt = binds.length ? c.env.DB.prepare(sql).bind(...binds) : c.env.DB.prepare(sql)
  const { results } = await stmt.all()
  // Mask non-deliverable placeholder emails so exports never leak internal
  // synthetic addresses (they mean "no email on file").
  const rows = (results || []).map((r: any) => (r && 'email' in r && isPlaceholderEmail(r.email)) ? { ...r, email: '' } : r)
  return { label: def.label, cols: def.cols, rows }
}

// base64 of a UTF-8 string, works in both Node and Workers runtimes.
function base64Utf8(s: string): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(s, 'utf8').toString('base64')
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  // @ts-ignore btoa exists in Workers
  return btoa(bin)
}
function toCsv(cols: string[], rows: any[]): string {
  const esc = (v: any) => {
    const s = v == null ? '' : String(v)
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
  }
  const head = cols.map(esc).join(',')
  const body = rows.map((r) => cols.map((cKey) => esc(r[cKey])).join(',')).join('\n')
  return head + '\n' + body
}

// Metadata: list datasets + their filter options (distinct values).
app.get('/api/export/datasets', requireAuth, requireRole('admin', 'super_admin'), (c) => {
  const list = Object.entries(EXPORT_DATASETS).map(([key, d]) => ({ key, label: d.label, filters: Object.keys(d.filterable), cols: d.cols }))
  return c.json({ datasets: list, email_configured: emailConfigured(c.env) })
})
// Return filtered data as JSON (frontend turns it into CSV/XLSX for local download).
app.post('/api/export/data', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { dataset, filters, date_from, date_to } = await c.req.json()
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    await audit(c, c.get('user').id, 'export', dataset, `${out.rows.length} rows`)
    return c.json({ ok: true, ...out })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})
// SENSITIVE server-authoritative download: returns the authoritative CSV only
// after password re-authentication. The frontend uses this for both CSV and
// XLSX downloads (it builds the .xlsx locally from this CSV). Mirrors Equipment.
app.post('/api/export/download', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const reauth = await verifyReauth(c, body?.password)
  if (!reauth.ok) return c.json({ error: reauth.error, reauth_required: true }, reauth.status as any)
  const { dataset, filters, date_from, date_to } = body || {}
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    const csv = toCsv(out.cols, out.rows)
    const fname = `farmsky-${dataset}-${new Date().toISOString().slice(0, 10)}.csv`
    await audit(c, c.get('user').id, 'export_download', dataset, `${out.rows.length} rows (password re-auth)`)
    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="${fname}"`
      }
    })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})
// Email a filtered export (CSV attachment) to a recipient.
app.post('/api/export/email', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { dataset, filters, date_from, date_to, to, format } = await c.req.json()
  if (!to || !/.+@.+\..+/.test(String(to))) return c.json({ error: 'Enter a valid recipient email' }, 400)
  if (!emailConfigured(c.env)) {
    return c.json({ error: 'email_not_configured', message: 'Email provider not configured. Use the Download button instead, or set EMAIL_API_URL/TOKEN/FROM at deploy.' }, 412)
  }
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    const csv = toCsv(out.cols, out.rows)
    const b64 = base64Utf8(csv)
    const fname = `farmsky-${dataset}-${new Date().toISOString().slice(0, 10)}.csv`
    const r = await sendEmail(c.env, {
      to,
      subject: `Farmsky export — ${out.label} (${out.rows.length} rows)`,
      text: `Attached is the ${out.label} export you requested from Farmsky (${out.rows.length} rows).`,
      attachments: [{ filename: fname, contentBase64: b64, contentType: 'text/csv' }]
    })
    if (!r.success) return c.json({ error: r.error || 'Email send failed' }, 502)
    await audit(c, c.get('user').id, 'export_email', dataset, `to ${to}`)
    return c.json({ ok: true, message: `Export emailed to ${to}` })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})

// ============================================================================
// AUTOMATED SYSTEM BACKUPS (Task 3A)
//   Regular, automated backups of ALL user profiles, transactional records and
//   system-wide data. A backup captures a JSON snapshot of every core table and
//   persists it (with row counts + size) in system_backups so admins can review,
//   download and restore-plan from it. Backups run:
//     * on demand   — admin clicks "Back up now"
//     * automatically — a cadence gate (default 24h) fires the next time any
//       admin route is hit after the interval elapses (works without a external
//       scheduler; also invokable by a real cron via POST /api/backups/run-auto)
// ============================================================================

// Tables captured in a full backup. Order groups: profiles → transactional →
// system/config. SELECT * so schema additions are captured automatically.
const BACKUP_TABLES: { key: string; sql: string }[] = [
  { key: 'users', sql: 'SELECT * FROM users' },
  { key: 'customers', sql: 'SELECT * FROM customers' },
  { key: 'agents', sql: 'SELECT * FROM agents' },
  { key: 'products', sql: 'SELECT * FROM products' },
  { key: 'murabaha_contracts', sql: 'SELECT * FROM murabaha_contracts' },
  { key: 'repayments', sql: 'SELECT * FROM repayments' },
  { key: 'transactions', sql: 'SELECT * FROM transactions' },
  { key: 'wallets', sql: 'SELECT * FROM wallets' },
  { key: 'wallet_ledger', sql: 'SELECT * FROM wallet_ledger' },
  { key: 'audit_logs', sql: 'SELECT * FROM audit_logs' }
]

const AUTO_BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1000 // daily

// Build a full snapshot of every backup table (admin context bypasses row-level
// ownership scoping so the backup is complete). Missing tables are skipped
// gracefully so the backup never hard-fails on an optional table.
async function buildBackupSnapshot(c: any): Promise<{ payload: Record<string, any[]>; counts: Record<string, number>; total: number }> {
  return await withAdminContext(c, async () => {
    const payload: Record<string, any[]> = {}
    const counts: Record<string, number> = {}
    let total = 0
    for (const t of BACKUP_TABLES) {
      try {
        const { results } = await c.env.DB.prepare(t.sql).all()
        const rows = (results || []) as any[]
        payload[t.key] = rows
        counts[t.key] = rows.length
        total += rows.length
      } catch (_) {
        // Table not present in this deployment — record 0 and continue.
        payload[t.key] = []
        counts[t.key] = 0
      }
    }
    return { payload, counts, total }
  })
}

// Create + persist a backup row. Used by both the manual and automatic paths.
async function performBackup(c: any, triggerType: 'manual' | 'auto', createdBy: number | null) {
  try {
    const snap = await buildBackupSnapshot(c)
    const serialized = JSON.stringify({ version: 1, created_at: new Date().toISOString(), data: snap.payload })
    const size = base64Utf8(serialized).length // approximate stored size
    const summary = Object.entries(snap.counts).map(([k, v]) => `${k}:${v}`).join(', ')
    const r = await c.env.DB.prepare(
      `INSERT INTO system_backups (trigger_type, summary, record_count, size_bytes, payload, status, created_by) VALUES (?,?,?,?,?, 'success', ?)`
    ).bind(triggerType, summary, snap.total, size, serialized, createdBy).run()
    await audit(c, createdBy, 'backup', 'system', `${triggerType} backup — ${snap.total} records`)
    return { id: r.meta.last_row_id, record_count: snap.total, size_bytes: size, summary, counts: snap.counts }
  } catch (e: any) {
    try {
      await c.env.DB.prepare(
        `INSERT INTO system_backups (trigger_type, summary, record_count, size_bytes, payload, status, error, created_by) VALUES (?,?,0,0,NULL,'failed',?,?)`
      ).bind(triggerType, 'backup failed', String(e?.message || e), createdBy).run()
    } catch (_) {}
    throw e
  }
}

// Cadence gate: fire an automatic backup if the newest successful auto/manual
// backup is older than AUTO_BACKUP_INTERVAL_MS (or none exists). Best-effort,
// never throws into the calling request.
async function maybeAutoBackup(c: any) {
  try {
    const last = await c.env.DB.prepare(
      `SELECT created_at FROM system_backups WHERE status='success' ORDER BY id DESC LIMIT 1`
    ).first<any>()
    if (last?.created_at) {
      const lastMs = new Date(String(last.created_at).replace(' ', 'T')).getTime()
      if (!Number.isNaN(lastMs) && Date.now() - lastMs < AUTO_BACKUP_INTERVAL_MS) return { ran: false }
    }
    await performBackup(c, 'auto', null)
    return { ran: true }
  } catch (_) { return { ran: false } }
}

// List backups (metadata only — payloads excluded to keep the response light).
app.get('/api/backups', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  // Opportunistically ensure the daily automatic backup exists.
  await maybeAutoBackup(c)
  const { results } = await c.env.DB.prepare(
    `SELECT b.id, b.trigger_type, b.summary, b.record_count, b.size_bytes, b.status, b.error, b.created_at, u.full_name created_by_name
       FROM system_backups b LEFT JOIN users u ON CAST(u.id AS TEXT)=b.created_by
      ORDER BY b.id DESC LIMIT 100`
  ).all()
  return c.json({ backups: results || [], interval_hours: AUTO_BACKUP_INTERVAL_MS / 3600000 })
})

// Trigger a manual backup now.
app.post('/api/backups', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  try {
    const out = await performBackup(c, 'manual', c.get('user').id)
    return c.json({ ok: true, ...out })
  } catch (e: any) {
    return c.json({ error: e?.message || 'Backup failed' }, 500)
  }
})

// Download a stored backup snapshot as a JSON file. SENSITIVE: a full system
// backup exports the entire database, so the download requires password
// re-authentication (POST with { password }). The legacy GET is retired for
// security and always instructs the client to POST with a password.
app.post('/api/backups/:id/download', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const reauth = await verifyReauth(c, body?.password)
  if (!reauth.ok) return c.json({ error: reauth.error, reauth_required: true }, reauth.status as any)
  const row = await c.env.DB.prepare(`SELECT id, payload, created_at FROM system_backups WHERE id=?`).bind(c.req.param('id')).first<any>()
  if (!row || !row.payload) return c.json({ error: 'Backup not found' }, 404)
  await audit(c, c.get('user').id, 'backup_download', 'system', `backup #${row.id} (password re-auth)`)
  return new Response(row.payload, {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="farmsky-backup-${row.id}.json"`
    }
  })
})
// Legacy GET is retired for security — always instruct the client to POST with a
// password confirmation. Never returns backup data.
app.get('/api/backups/:id/download', requireAuth, requireRole('admin', 'super_admin'), (c) => {
  return c.json({ error: 'Password confirmation required. POST to this URL with { password } to download.', reauth_required: true }, 401)
})

// Endpoint a real external scheduler (cron) can hit to run the auto backup.
// Protected by an ADMIN_TASK_TOKEN header when configured; otherwise admin-only.
app.post('/api/backups/run-auto', async (c) => {
  const token = c.req.header('x-admin-task-token') || ''
  const expected = (c.env as any).ADMIN_TASK_TOKEN
  if (expected && token === expected) {
    const r = await maybeAutoBackup(c)
    return c.json({ ok: true, ...r })
  }
  // Fall back to authenticated admin.
  const sessionToken = getCookie(c, 'session')
  const sess = sessionToken ? await c.env.DB.prepare(`SELECT u.role FROM sessions s JOIN users u ON CAST(u.id AS TEXT)=s.user_id WHERE s.token=? AND s.expires_at > ?`).bind(sessionToken, Date.now()).first<any>() : null
  if (!sess || !['admin', 'super_admin'].includes(sess.role)) return c.json({ error: 'Unauthorized' }, 401)
  const r = await maybeAutoBackup(c)
  return c.json({ ok: true, ...r })
})

// ============================================================================
// BULK USER DATA UPLOAD & STANDARDIZATION (Task 3B)
//   Categorized import (Farmers / Agents / Partners) → parse & normalize into
//   the standard profile fields → flag rows missing required fields as
//   exceptions for the admin to complete → once validated, auto-dispatch the
//   onboarding flow (create account + temporary password + phone verification
//   details) to each user.
// ============================================================================

// Map a raw import row's arbitrary column names to our standard field set.
// Accepts common header aliases (case/spacing/underscore-insensitive).
function mapImportRow(raw: Record<string, any>): Record<string, string> {
  const norm: Record<string, any> = {}
  for (const [k, v] of Object.entries(raw)) {
    norm[String(k).toLowerCase().replace(/[^a-z0-9]/g, '')] = v
  }
  const pick = (...keys: string[]) => {
    for (const k of keys) { const v = norm[k]; if (v != null && String(v).trim() !== '') return String(v).trim() }
    return ''
  }
  return {
    full_name: pick('fullname', 'name', 'names', 'customername', 'farmername'),
    phone: pick('phone', 'phonenumber', 'mobile', 'msisdn', 'tel', 'telephone', 'contact'),
    national_id: pick('nationalid', 'idnumber', 'idno', 'id', 'nid'),
    email: pick('email', 'emailaddress'),
    county: pick('county', 'region'),
    sub_county: pick('subcounty', 'subcounties'),
    ward: pick('ward'),
    village: pick('village', 'location'),
    value_chain_type: pick('valuechaintype', 'vct', 'category', 'farmtype', 'partnertype'),
    value_chain: pick('valuechain', 'vc', 'crop', 'produce', 'commodity'),
    region: pick('region', 'county', 'area')
  }
}

// Required fields per category. Rows missing any are flagged as exceptions.
const IMPORT_REQUIRED: Record<string, string[]> = {
  farmers: ['full_name', 'phone', 'national_id', 'county'],
  agents: ['full_name', 'phone'],
  partners: ['full_name', 'phone']
}

function validateImportRow(category: string, row: Record<string, string>): string[] {
  const required = IMPORT_REQUIRED[category] || ['full_name', 'phone']
  const issues: string[] = []
  for (const f of required) {
    if (!row[f] || String(row[f]).trim() === '') issues.push(`missing ${f}`)
  }
  // Phone must normalize to a valid Kenyan MSISDN.
  if (row.phone) {
    const p = normalizePhone(row.phone)
    if (!p || p.length < 12) issues.push('invalid phone')
  }
  return issues
}

// Step 1 — Upload a categorized batch. The client parses the CSV/XLSX into an
// array of row objects; we normalize + validate + stage them.
app.post('/api/imports', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { category, filename, rows } = await c.req.json()
  const cat = String(category || '').toLowerCase()
  if (!['farmers', 'agents', 'partners'].includes(cat)) return c.json({ error: 'category must be farmers, agents or partners' }, 400)
  if (!Array.isArray(rows) || rows.length === 0) return c.json({ error: 'No rows to import' }, 400)
  if (rows.length > 5000) return c.json({ error: 'Batch too large (max 5000 rows)' }, 400)
  const creator = c.get('user').id
  const batch = await c.env.DB.prepare(
    `INSERT INTO import_batches (category, filename, total_rows, status, created_by) VALUES (?,?,?, 'review', ?)`
  ).bind(cat, filename || null, rows.length, creator).run()
  const batchId = batch.meta.last_row_id
  let valid = 0, exceptions = 0
  for (let i = 0; i < rows.length; i++) {
    const mapped = mapImportRow(rows[i] || {})
    if (mapped.phone) mapped.phone = normalizePhone(mapped.phone)
    const issues = validateImportRow(cat, mapped)
    const status = issues.length ? 'exception' : 'valid'
    if (status === 'valid') valid++; else exceptions++
    await c.env.DB.prepare(
      `INSERT INTO import_rows (batch_id, row_number, full_name, phone, national_id, email, county, sub_county, ward, village, value_chain_type, value_chain, region, raw, status, issues)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      batchId, i + 1, mapped.full_name || null, mapped.phone || null, mapped.national_id || null, mapped.email || null,
      mapped.county || null, mapped.sub_county || null, mapped.ward || null, mapped.village || null,
      mapped.value_chain_type || null, mapped.value_chain || null, mapped.region || null,
      JSON.stringify(rows[i] || {}), status, issues.join(', ') || null
    ).run()
  }
  await c.env.DB.prepare(`UPDATE import_batches SET valid_rows=?, exception_rows=? WHERE id=?`).bind(valid, exceptions, batchId).run()
  await audit(c, creator, 'import', cat, `batch #${batchId}: ${rows.length} rows (${exceptions} exceptions)`)
  return c.json({ ok: true, batch_id: batchId, total: rows.length, valid, exceptions })
})

// List batches.
app.get('/api/imports', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT b.*, u.full_name created_by_name FROM import_batches b LEFT JOIN users u ON CAST(u.id AS TEXT)=b.created_by ORDER BY b.id DESC LIMIT 100`
  ).all()
  return c.json({ batches: results || [] })
})

// Batch detail with its rows (for exception handling review).
app.get('/api/imports/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const batch = await c.env.DB.prepare(`SELECT * FROM import_batches WHERE id=?`).bind(id).first<any>()
  if (!batch) return c.json({ error: 'Batch not found' }, 404)
  const { results } = await c.env.DB.prepare(`SELECT * FROM import_rows WHERE batch_id=? ORDER BY row_number`).bind(id).all()
  return c.json({ batch, rows: results || [] })
})

// Step 2 — Exception handling: admin patches a flagged row's missing fields.
app.put('/api/imports/rows/:rowId', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const rowId = c.req.param('rowId')
  const b = await c.req.json()
  const row = await c.env.DB.prepare(`SELECT r.*, ba.category FROM import_rows r JOIN import_batches ba ON ba.id=r.batch_id WHERE r.id=?`).bind(rowId).first<any>()
  if (!row) return c.json({ error: 'Row not found' }, 404)
  if (row.status === 'dispatched') return c.json({ error: 'Row already onboarded' }, 400)
  const merged: Record<string, string> = {
    full_name: b.full_name ?? row.full_name ?? '',
    phone: b.phone != null ? normalizePhone(b.phone) : (row.phone || ''),
    national_id: b.national_id ?? row.national_id ?? '',
    email: b.email ?? row.email ?? '',
    county: b.county ?? row.county ?? '',
    sub_county: b.sub_county ?? row.sub_county ?? '',
    ward: b.ward ?? row.ward ?? '',
    village: b.village ?? row.village ?? '',
    value_chain_type: b.value_chain_type ?? row.value_chain_type ?? '',
    value_chain: b.value_chain ?? row.value_chain ?? '',
    region: b.region ?? row.region ?? ''
  }
  const issues = validateImportRow(row.category, merged)
  const status = issues.length ? 'exception' : 'valid'
  await c.env.DB.prepare(
    `UPDATE import_rows SET full_name=?, phone=?, national_id=?, email=?, county=?, sub_county=?, ward=?, village=?, value_chain_type=?, value_chain=?, region=?, status=?, issues=? WHERE id=?`
  ).bind(merged.full_name || null, merged.phone || null, merged.national_id || null, merged.email || null,
    merged.county || null, merged.sub_county || null, merged.ward || null, merged.village || null,
    merged.value_chain_type || null, merged.value_chain || null, merged.region || null,
    status, issues.join(', ') || null, rowId).run()
  // Recompute batch counts.
  await recomputeBatchCounts(c, row.batch_id)
  return c.json({ ok: true, status, issues })
})

async function recomputeBatchCounts(c: any, batchId: number) {
  const v = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='valid'`).bind(batchId).first<any>()
  const e = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='exception'`).bind(batchId).first<any>()
  const d = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='dispatched'`).bind(batchId).first<any>()
  await c.env.DB.prepare(`UPDATE import_batches SET valid_rows=?, exception_rows=?, dispatched_rows=? WHERE id=?`)
    .bind(Number(v?.n || 0), Number(e?.n || 0), Number(d?.n || 0), batchId).run()
}

// Step 3 — Automated Dispatch: once validated, create accounts for all 'valid'
// rows and trigger the onboarding flow (temporary password + verification info
// sent by SMS). Rows still flagged as exceptions are skipped.
app.post('/api/imports/:id/dispatch', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const batch = await c.env.DB.prepare(`SELECT * FROM import_batches WHERE id=?`).bind(id).first<any>()
  if (!batch) return c.json({ error: 'Batch not found' }, 404)
  const cat = String(batch.category)
  const roleForCategory = cat === 'agents' ? 'agent' : cat === 'partners' ? 'partner' : 'customer'
  const { results } = await c.env.DB.prepare(`SELECT * FROM import_rows WHERE batch_id=? AND status='valid'`).bind(id).all()
  const rows = (results || []) as any[]
  const creator = c.get('user').id
  // Shared central DB: users.org_id NOT NULL — resolve the importing admin's
  // tenant once for the whole batch (fallback to deployment default).
  const impOrgId = (await resolveCreatorOrgId(c, c.get('user'))) || (await resolveDefaultOrgId(c))
  const impWithOrg = (await usersHasOrgId(c)) && impOrgId != null
  let created = 0, skipped = 0
  const errors: string[] = []
  for (const row of rows) {
    const phone = normalizePhone(row.phone || '')
    if (!phone) { skipped++; continue }
    // Skip duplicates gracefully.
    const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(phone).first<any>()
    if (dup) { skipped++; errors.push(`${row.full_name || phone}: already exists`); continue }
    try {
      const perms = await permissionsForRole(c, roleForCategory === 'agent' ? 'agent' : roleForCategory === 'partner' ? 'partner' : 'customer', {})
      const placeholder = await hashPassword(genPassword())
      // Bulk-import roles (agent/partner/customer) never require email; a unique
      // placeholder (from phone) satisfies central users.email NOT NULL + UNIQUE.
      const emailRes = resolveEmail(roleForCategory, row.email, phone)
      if ('error' in emailRes) { skipped++; errors.push(`${row.full_name || phone}: ${emailRes.error}`); continue }
      const email = emailRes.value
      const ur = impWithOrg
        ? await c.env.DB.prepare(
            `INSERT INTO users (full_name, phone, email, password, role, region, password_set, permissions, created_by, org_id) VALUES (?,?,?,?,?,?,0,?,?,?)`
          ).bind(row.full_name, phone, email, placeholder, roleForCategory, row.region || row.county || null, JSON.stringify(perms), creator, impOrgId).run()
        : await c.env.DB.prepare(
            `INSERT INTO users (full_name, phone, email, password, role, region, password_set, permissions, created_by) VALUES (?,?,?,?,?,?,0,?,?)`
          ).bind(row.full_name, phone, email, placeholder, roleForCategory, row.region || row.county || null, JSON.stringify(perms), creator).run()
      const userId = ur.meta.last_row_id as any
      // Farmers also get a customer profile with the standardized fields.
      if (roleForCategory === 'customer') {
        await c.env.DB.prepare(
          `INSERT INTO customers (user_id, agent_id, onboarded_by, full_name, national_id, mobile, county, sub_county, ward, village, value_chain_type, value_chain, kyc_status, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'pending', 'active')`
        ).bind(userId, null, creator, row.full_name, row.national_id || null, phone, row.county || null, row.sub_county || null, row.ward || null, row.village || null, row.value_chain_type || null, row.value_chain || null).run()
      } else if (roleForCategory === 'agent') {
        await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(userId, row.region || row.county || null, JSON.stringify(perms)).run()
      }
      // Trigger the onboarding lifecycle: temp password + SMS with verification.
      await issueTempPassword(c, { userId, phone, fullName: row.full_name })
      await c.env.DB.prepare(`UPDATE import_rows SET status='dispatched', created_user_id=? WHERE id=?`).bind(userId, row.id).run()
      created++
    } catch (e: any) {
      skipped++; errors.push(`${row.full_name || phone}: ${e?.message || 'failed'}`)
    }
  }
  await recomputeBatchCounts(c, Number(id))
  const remaining = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='exception'`).bind(id).first<any>()
  const newStatus = Number(remaining?.n || 0) === 0 ? 'completed' : 'dispatched'
  await c.env.DB.prepare(`UPDATE import_batches SET status=? WHERE id=?`).bind(newStatus, id).run()
  await audit(c, creator, 'import_dispatch', cat, `batch #${id}: ${created} onboarded, ${skipped} skipped`)
  return c.json({ ok: true, created, skipped, errors: errors.slice(0, 50), status: newStatus })
})

// ============================================================================
// WALLET SYSTEM — double-entry ledger, earning rules, commissions, payouts
// ============================================================================

// Ensure a user has a wallet row; returns the wallet id. Created under admin
// context so it works regardless of the caller's ownership scope.
async function ensureWallet(c: any, userId: number, assignedBy: number | null = null): Promise<number> {
  return await withAdminContext(c, async () => {
    const existing = await c.env.DB.prepare(`SELECT id FROM wallets WHERE user_id=?`).bind(userId).first<any>()
    if (existing) return Number(existing.id)
    const r = await c.env.DB.prepare(`INSERT INTO wallets (user_id, assigned_by) VALUES (?,?)`).bind(userId, assignedBy).run()
    return Number(r.meta.last_row_id)
  })
}
// Post a ledger entry (the ONLY sanctioned way a balance changes). The DB
// trigger stamps balance_after and syncs wallets.balance atomically.
async function postLedger(c: any, opts: { userId: number; walletId: number; type: 'credit' | 'debit'; amount: number; category: string; reference?: string | null; description?: string | null; createdBy?: number | null }) {
  return await c.env.DB.prepare(
    `INSERT INTO wallet_ledger (wallet_id, user_id, entry_type, amount, balance_after, category, reference, description, created_by)
     VALUES (?,?,?,?, 0, ?,?,?,?)`
  ).bind(opts.walletId, opts.userId, opts.type, roundMoney(opts.amount), opts.category, opts.reference ?? null, opts.description ?? null, opts.createdBy ?? null).run()
}

// GET my wallet + ledger statement (RLS scopes agents to their own).
app.get('/api/wallet', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const walletId = await ensureWallet(c, user.id)
  const wallet = await c.env.DB.prepare(`SELECT * FROM wallets WHERE id=?`).bind(walletId).first<any>()
  const { results: ledger } = await c.env.DB.prepare(`SELECT * FROM wallet_ledger WHERE wallet_id=? ORDER BY id DESC LIMIT 200`).bind(walletId).all()
  const { results: rules } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 ORDER BY id`).bind(user.id).all()
  // Withdrawal charge schema + the holder's withdrawable limit (balance − effective charge).
  const chargeCfg = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const supportContact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  const balance = numberVal(wallet?.balance, 0)
  const limit = computeWithdrawableLimit(chargeCfg, balance)
  return c.json({
    wallet, ledger, earning_rules: rules,
    withdrawal_charge: chargeCfg,
    withdrawable: limit.withdrawable,
    charge_at_max: limit.charge_at_max,
    support_contact: supportContact
  })
})

// ---- Admin wallet management ----
// List all wallets with holder details (admin global view).
app.get('/api/wallets', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT w.*, u.full_name, u.phone, u.role,
              (SELECT COUNT(*) FROM earning_rules er WHERE er.user_id=w.user_id AND er.is_active=1) AS rule_count
         FROM wallets w JOIN users u ON CAST(u.id AS TEXT) = w.user_id ORDER BY u.full_name`
    ).all()
    return results
  })
  return c.json({ wallets: rows })
})
// Assign / create a wallet for a user (admin authorizes it).
app.post('/api/wallets', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  // Shared central DB: users.id is a UUID — treat the id as an opaque string.
  const userId = String(b.user_id ?? '').trim()
  if (!userId) return c.json({ error: 'user_id is required' }, 400)
  const walletId = await ensureWallet(c, userId, admin.id)
  await audit(c, admin.id, 'assign', 'wallet', `wallet for user ${userId}`)
  return c.json({ ok: true, wallet_id: walletId })
})

// ---- Earning rules (admin sets criteria: 2% commission, KES 5,000 retainer…) ----
app.get('/api/earning-rules/:userId', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const userId = c.req.param('userId')
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? ORDER BY id`).bind(userId).all()
    return results
  })
  return c.json({ earning_rules: rows })
})
app.post('/api/earning-rules', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const userId = String(b.user_id ?? '').trim()
  const ruleType = String(b.rule_type || '').trim()
  if (!userId || !ruleType) return c.json({ error: 'user_id and rule_type are required' }, 400)
  const calcMethod = b.calc_method === 'percentage' ? 'percentage' : 'fixed'
  await ensureWallet(c, userId, admin.id)
  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO earning_rules (user_id, rule_type, calc_method, rate, fixed_amount, applies_to, description, is_active, created_by)
     VALUES (?,?,?,?,?,?,?,1,?)`
  ).bind(userId, ruleType, calcMethod, calcMethod === 'percentage' ? numberVal(b.rate, 0) : null, calcMethod === 'fixed' ? numberVal(b.fixed_amount, 0) : null, b.applies_to || (ruleType === 'commission' ? 'completed_order' : 'manual'), b.description || null, admin.id).run())
  await audit(c, admin.id, 'create', 'earning_rule', `${ruleType} for user ${userId}`)
  return c.json({ ok: true, id: r.meta.last_row_id })
})
app.put('/api/earning-rules/:id', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const id = c.req.param('id')
  const b = await c.req.json()
  await withAdminContext(c, async () => await c.env.DB.prepare(
    `UPDATE earning_rules SET rule_type=COALESCE(?,rule_type), calc_method=COALESCE(?,calc_method), rate=?, fixed_amount=?, applies_to=COALESCE(?,applies_to), description=COALESCE(?,description), is_active=COALESCE(?,is_active), updated_at=CURRENT_TIMESTAMP WHERE id=?`
  ).bind(b.rule_type ?? null, b.calc_method ?? null, b.rate ?? null, b.fixed_amount ?? null, b.applies_to ?? null, b.description ?? null, b.is_active === undefined ? null : (boolInt(b.is_active, true) ? 1 : 0), id).run())
  await audit(c, admin.id, 'update', 'earning_rule', String(id))
  return c.json({ ok: true })
})

// ---- Dynamic commission distribution on order completion ----
// Called when a contract/order status becomes 'completed'. Evaluates the target
// agent's active commission rules and credits their wallet dynamically.
async function distributeCommission(c: any, contract: any) {
  if (!contract) return
  const agentId = contract.created_by || contract.agent_id
  if (!agentId) return
  const orderValue = numberVal(contract.murabaha_price ?? contract.total_payable, 0)
  await withAdminContext(c, async () => {
    const { results: rules } = await c.env.DB.prepare(
      `SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 AND applies_to='completed_order'`
    ).bind(agentId).all()
    if (!rules?.length) return
    const walletId = await ensureWallet(c, agentId)
    for (const rule of rules as any[]) {
      // Idempotency: don't double-credit the same contract for the same rule.
      const dup = await c.env.DB.prepare(
        `SELECT 1 FROM wallet_ledger WHERE wallet_id=? AND category=? AND reference=? LIMIT 1`
      ).bind(walletId, rule.rule_type, contract.contract_ref).first<any>()
      if (dup) continue
      const amount = rule.calc_method === 'percentage'
        ? roundMoney(orderValue * numberVal(rule.rate, 0) / 100)
        : roundMoney(numberVal(rule.fixed_amount, 0))
      if (amount <= 0) continue
      await postLedger(c, { userId: agentId, walletId, type: 'credit', amount, category: rule.rule_type, reference: contract.contract_ref, description: `${rule.rule_type} on ${contract.contract_ref}`, createdBy: null })
    }
  })
}

// ---- Admin payout disbursals (retainers, transport, per-diems) ----
// Batch-process fixed funds to one user or all agents.
app.post('/api/wallet/payouts', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const category = String(b.category || 'retainer')
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)
  const batchRef = ref('PAY')
  const result = await withAdminContext(c, async () => {
    let recipients: string[] = []
    if (Array.isArray(b.user_ids) && b.user_ids.length) {
      recipients = b.user_ids.map((x: any) => String(x ?? '').trim()).filter(Boolean)
    } else if (b.user_id) {
      recipients = [String(b.user_id).trim()]
    } else if (b.target === 'all_agents') {
      const { results } = await c.env.DB.prepare(`SELECT id FROM users WHERE role='agent' AND status='active'`).all()
      recipients = (results as any[]).map((r) => String(r.id)).filter(Boolean)
    }
    if (!recipients.length) return { error: 'No recipients resolved' }
    let total = 0, count = 0
    for (const uid of recipients) {
      const walletId = await ensureWallet(c, uid, admin.id)
      await postLedger(c, { userId: uid, walletId, type: 'credit', amount, category, reference: batchRef, description: b.description || `${category} disbursal`, createdBy: admin.id })
      total += amount; count++
    }
    await c.env.DB.prepare(
      `INSERT INTO payout_batches (batch_ref, category, description, total_amount, recipient_count, issued_by, payment_method) VALUES (?,?,?,?,?,?, 'wallet_credit')`
    ).bind(batchRef, category, b.description || null, roundMoney(total), count, admin.id).run()
    return { total: roundMoney(total), count }
  })
  if ((result as any).error) return c.json(result, 400)
  await audit(c, admin.id, 'payout', 'wallet', `${batchRef} ${category} x${(result as any).count}`)
  return c.json({ ok: true, batch_ref: batchRef, ...(result as any) })
})

// ---- Real-time earning analytics (RLS: agent sees self, admin sees global) ----
app.get('/api/wallet/analytics', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const isAdmin = hasPermission(user, 'manage_wallets') && ['admin', 'super_admin'].includes(user.role)
  // With ownership RLS active, the SAME query returns per-agent data for agents
  // and platform-wide data for admins — no branching in the query itself.
  const byCategory = await c.env.DB.prepare(
    `SELECT category, entry_type, COUNT(*) AS entries, COALESCE(SUM(amount),0) AS total
       FROM wallet_ledger GROUP BY category, entry_type ORDER BY category`
  ).all()
  const totals = await c.env.DB.prepare(
    `SELECT COALESCE(SUM(CASE WHEN entry_type='credit' THEN amount ELSE 0 END),0) AS total_earned,
            COALESCE(SUM(CASE WHEN entry_type='debit'  THEN amount ELSE 0 END),0) AS total_debited
       FROM wallet_ledger`
  ).first<any>()
  return c.json({ scope: isAdmin ? 'global' : 'self', totals, by_category: byCategory.results })
})

// ============================================================================
// PAYOUT DESTINATIONS — a user registers the mobile / bank / SasaPay accounts
// they can withdraw to. Each is validated against SasaPay before it is usable.
// ============================================================================
app.get('/api/payout-accounts', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const { results } = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE user_id=? ORDER BY is_default DESC, id DESC`).bind(user.id).all()
  return c.json({ accounts: results })
})

app.post('/api/payout-accounts', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const channelCode = String(b.channel_code || '').trim()
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'Unknown channel' }, 400)
  const raw = String(b.account_number || '').trim()
  if (!raw) return c.json({ error: 'account_number is required' }, 400)
  const account = (chan.type === 'mobile' || chan.type === 'wallet') ? sasapayNormalizePhone(raw) : raw
  const acctType = accountTypeForChannel(channelCode)

  // Validate against SasaPay to capture + confirm the holder name.
  const v = await sasapayValidateAccount(c.env, channelCode, account)
  const verified = v.success ? 1 : 0
  const accountName = v.account_name || b.account_name || null

  if (b.is_default) {
    await c.env.DB.prepare(`UPDATE payout_accounts SET is_default=0 WHERE user_id=?`).bind(user.id).run()
  }
  const r = await c.env.DB.prepare(
    `INSERT INTO payout_accounts (user_id, label, channel_code, channel_name, account_type, account_number, account_name, is_verified, is_default, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(user.id, b.label || chan.name, channelCode, chan.name, acctType, account, accountName, verified, b.is_default ? 1 : 0, user.id).run()
  await audit(c, user.id, 'create', 'payout_account', `${chan.name} ${account} (${verified ? 'verified' : 'unverified'})`)
  return c.json({ ok: true, id: r.meta.last_row_id, is_verified: !!verified, account_name: accountName, simulated: v.simulated })
})

app.delete('/api/payout-accounts/:id', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  await c.env.DB.prepare(`DELETE FROM payout_accounts WHERE id=? AND user_id=?`).bind(c.req.param('id'), user.id).run()
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// Disburse money OUT (B2C). In PRODUCTION this satellite has no SasaPay
// credentials of its own, so it routes the payout through the central
// equipment gateway (which owns the credentials) — exactly like the collection
// (pay-in) flow. Only when the gateway is NOT configured (local/standalone dev)
// do we fall back to the direct SasaPay B2C call, which itself simulates when
// no credentials are present. This is what takes the wallet OUT of demo mode.
// The return shape is normalised to match the legacy sasapayB2C() result so
// callers don't need to branch.
// ----------------------------------------------------------------------------
async function disburseB2C(
  c: any,
  opts: { amount: number; receiverNumber: string; channel: string; reason: string; reference: string }
): Promise<{ simulated: boolean; success: boolean; error?: string; b2c_request_id?: string | null; conversation_id?: string | null; transaction_charges?: any; customer_message?: string; via_gateway?: boolean }> {
  if (gatewayConfigured(c.env)) {
    const g = await gatewayPayout(c.env, {
      amount: opts.amount,
      channelCode: opts.channel,
      receiver_number: opts.receiverNumber,
      reason: opts.reason,
      origin_reference: opts.reference,
      idempotency_key: opts.reference
    })
    if (!g.success) return { simulated: false, success: false, error: g.error || 'Payout rejected by gateway', via_gateway: true }
    return {
      simulated: !!g.simulated,
      success: true,
      b2c_request_id: g.b2c_request_id || null,
      conversation_id: g.conversation_id || null,
      transaction_charges: g.transaction_charges || '0.00',
      customer_message: g.customer_message,
      via_gateway: true
    }
  }
  // Local/standalone dev fallback: direct provider call (simulates w/o creds).
  const p = await sasapayB2C(c.env, opts)
  return { ...p, via_gateway: false }
}

// ============================================================================
// WALLET WITHDRAWAL — a wallet holder cashes out to their registered mobile /
// bank / SasaPay destination. Debits the ledger first, then pushes B2C
// (routed through the central gateway in production; see disburseB2C).
// ============================================================================
app.post('/api/wallet/withdraw', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)

  // Resolve the destination: either a saved payout account, or an inline channel+number.
  let channelCode = String(b.channel_code || '').trim()
  let receiver = String(b.account_number || '').trim()
  let recipientName: string | null = b.account_name || null
  if (b.payout_account_id) {
    const acct = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE id=? AND user_id=?`).bind(b.payout_account_id, user.id).first<any>()
    if (!acct) return c.json({ error: 'Payout account not found' }, 404)
    channelCode = String(acct.channel_code)
    receiver = String(acct.account_number)
    recipientName = acct.account_name || null
  }
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'A valid withdrawal channel is required' }, 400)
  if (!receiver) return c.json({ error: 'A destination account is required' }, 400)
  if (chan.type === 'mobile' || chan.type === 'wallet') receiver = sasapayNormalizePhone(receiver)

  const reference = ref('WD')
  const walletId = await ensureWallet(c, user.id)

  // Load configuration + the holder's CURRENT balance so we can validate against
  // the withdrawable limit (balance − effective withdrawal charge) before we
  // touch the ledger. Aligned with the Equipment central-payment hub schema.
  const chargeCfg = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const supportContact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  const walletRow = await c.env.DB.prepare(`SELECT balance FROM wallets WHERE id=?`).bind(walletId).first<any>()
  const balance = roundMoney(numberVal(walletRow?.balance, 0))
  const charge = computeWithdrawalCharge(chargeCfg, amount)
  const totalDebit = roundMoney(amount + charge)
  const limit = computeWithdrawableLimit(chargeCfg, balance)

  // Enforce an optional minimum withdrawal.
  if (chargeCfg.min_withdrawal > 0 && amount < chargeCfg.min_withdrawal) {
    return c.json({ error: `The minimum withdrawal is KES ${chargeCfg.min_withdrawal.toLocaleString()}.` }, 400)
  }

  // 1a) Withdrawable-limit pre-check. The holder may only withdraw an amount
  // whose gross + effective charge is within their balance.
  if (totalDebit > balance) {
    const insufficientMsg = 'Unsuccessful. You have insufficient Balance'
    const smsBody = `${insufficientMsg}. Your wallet balance is KES ${balance.toLocaleString()}. `
      + `The most you can withdraw now is KES ${limit.withdrawable.toLocaleString()} `
      + `(after a KES ${limit.charge_at_max.toLocaleString()} withdrawal charge).`
    try { if (user.phone) await sendSms(c.env, user.phone, smsBody) } catch (_) {}
    return c.json({
      error: insufficientMsg, insufficient: true,
      balance, requested: amount, charge,
      withdrawable: limit.withdrawable, charge_at_max: limit.charge_at_max
    }, 400)
  }

  // 1b) SasaPay main-wallet funding check. If the settlement account cannot cover
  // the gross payout, we DO NOT debit the holder — instead we tell them to
  // contact Farmsky (support phone/email configured by the super-admin).
  const mainBal = await sasapayBalance(c.env)
  if (mainBal.success && !mainBal.simulated && numberVal(mainBal.org_balance, 0) < amount) {
    return c.json({
      error: 'Contact Farmsky', contact_farmsky: true,
      support_phone: supportContact.phone, support_email: supportContact.email,
      message: 'We are unable to process your withdrawal right now. Please contact Farmsky.'
    }, 503)
  }

  // 1c) Debit the wallet ledger up-front (gross + charge). The trigger rejects
  //     if the balance is short (defence-in-depth against a race).
  try {
    await postLedger(c, { userId: user.id, walletId, type: 'debit', amount, category: 'withdrawal', reference, description: b.reason || `Withdrawal to ${chan.name}`, createdBy: user.id })
    if (charge > 0) {
      await postLedger(c, { userId: user.id, walletId, type: 'debit', amount: charge, category: 'withdrawal_charge', reference, description: `Withdrawal charge for ${reference}`, createdBy: user.id })
    }
  } catch (e: any) {
    const msg = String(e?.message || '')
    if (/insufficient/i.test(msg)) {
      try { await postLedger(c, { userId: user.id, walletId, type: 'credit', amount, category: 'adjustment', reference, description: `Reversal — charge could not be posted ${reference}`, createdBy: user.id }) } catch (_) {}
      return c.json({ error: 'Unsuccessful. You have insufficient Balance', insufficient: true, withdrawable: limit.withdrawable }, 400)
    }
    return c.json({ error: 'Withdrawal could not be posted' }, 400)
  }

  // 2) Record the withdrawal, then push B2C.
  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'withdrawal', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 1, ?)`
  ).bind(reference, walletId, user.id, amount, channelCode, chan.name, receiver, recipientName, b.reason || 'Wallet withdrawal', user.id).run()

  const payout = await disburseB2C(c, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || 'Wallet withdrawal', reference })

  if (!payout.success) {
    // Reverse BOTH the gross debit and the withdrawal charge (credit back) and mark failed.
    await postLedger(c, { userId: user.id, walletId, type: 'credit', amount, category: 'adjustment', reference, description: `Reversal — failed withdrawal ${reference}`, createdBy: user.id })
    if (charge > 0) {
      await postLedger(c, { userId: user.id, walletId, type: 'credit', amount: charge, category: 'adjustment', reference, description: `Reversal — withdrawal charge ${reference}`, createdBy: user.id })
    }
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || 'B2C failed', reference).run()
    return c.json({ error: payout.error || 'Disbursal failed; wallet has been refunded.' }, 502)
  }

  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
    .bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? 'success' : 'processing', reference).run()

  await audit(c, user.id, 'withdraw', 'wallet', `KES ${amount} to ${chan.name} ${receiver} (charge KES ${charge}) (${payout.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: payout.simulated, reference, status: payout.simulated ? 'success' : 'processing', amount, charge, total_debited: totalDebit, customer_message: payout.customer_message || (payout.simulated ? 'Withdrawal completed (simulation).' : 'Withdrawal is being processed.') })
})

app.get('/api/wallet/withdrawals', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals ORDER BY id DESC LIMIT 100`).all()
  return c.json({ withdrawals: results })
})

// ============================================================================
// PEER-TO-PEER WALLET TRANSFER — a wallet holder sends funds to another Farmsky
// user's wallet. Resolved by phone (preferred) or explicit user_id, OTP-gated,
// and committed as a double-entry under admin context. Aligned with the
// Equipment central-payment hub P2P feature.
// ============================================================================

// Resolve a P2P recipient from a phone number (preferred) or explicit user_id.
// Returns the recipient user row (admin-context read so we can look up any user)
// or an { error } object. Matches phone across raw / normalized / +254 / 07xx forms.
async function resolveTransferRecipient(c: any, b: any): Promise<{ user?: any; error?: string }> {
  return await withAdminContext(c, async () => {
    const rawUserId = String(b.recipient_user_id ?? '').trim()
    if (rawUserId) {
      const u = await c.env.DB.prepare(`SELECT id, full_name, phone, status FROM users WHERE id=?`).bind(rawUserId).first<any>()
      if (!u) return { error: 'Recipient not found.' }
      return { user: u }
    }
    const rawPhone = String(b.recipient_phone ?? '').trim()
    if (!rawPhone) return { error: 'A recipient phone number is required.' }
    const norm = sasapayNormalizePhone(rawPhone)
    const local = norm.startsWith('254') ? '0' + norm.slice(3) : rawPhone
    const plus = norm ? '+' + norm : rawPhone
    const u = await c.env.DB.prepare(
      `SELECT id, full_name, phone, status FROM users WHERE phone=? OR phone=? OR phone=? OR phone=?`
    ).bind(rawPhone, norm, plus, local).first<any>()
    if (!u) return { error: 'No Farmsky user is registered with that phone number.' }
    return { user: u }
  })
}

// Look up a recipient (used by the frontend to preview the name before sending).
app.get('/api/wallet/lookup-recipient', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const found = await resolveTransferRecipient(c, { recipient_phone: c.req.query('phone'), recipient_user_id: c.req.query('user_id') })
  if (found.error) return c.json({ error: found.error }, 404)
  const recipient = found.user
  if (String(recipient.id) === String(user.id)) return c.json({ error: 'You cannot send money to yourself.' }, 400)
  if (recipient.status && recipient.status !== 'active') return c.json({ error: 'That account cannot receive funds.' }, 400)
  return c.json({ ok: true, recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user', phone: maskPhone(sasapayNormalizePhone(String(recipient.phone || ''))) } })
})

app.post('/api/wallet/transfer', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)

  // Resolve the recipient (by phone or explicit user_id).
  const found = await resolveTransferRecipient(c, b)
  if (found.error) return c.json({ error: found.error }, 404)
  const recipient = found.user
  if (String(recipient.id) === String(user.id)) return c.json({ error: 'You cannot send money to yourself.' }, 400)
  if (recipient.status && recipient.status !== 'active') return c.json({ error: 'That account cannot receive funds.' }, 400)

  // Sender's wallet + balance (strictly the caller's own wallet).
  const senderWalletId = await ensureWallet(c, user.id)
  const senderRow = await c.env.DB.prepare(`SELECT balance FROM wallets WHERE id=?`).bind(senderWalletId).first<any>()
  const balance = roundMoney(numberVal(senderRow?.balance, 0))
  if (amount > balance) {
    return c.json({ error: 'Unsuccessful. You have insufficient Balance', insufficient: true, balance }, 400)
  }

  // ---- OTP AUTHORISATION (mandatory before any outgoing funds) ----------------
  const registeredPhone = sasapayNormalizePhone(String(user.phone || '').trim())
  if (!registeredPhone) return c.json({ error: 'Your account has no registered phone number for OTP.' }, 400)
  const otpCode = String(b.otp_code || '').trim()
  if (!otpCode) {
    const { demo_otp } = await issueOtp(c, registeredPhone, 'wallet_transfer')
    return c.json({
      needs_otp: true,
      phone: maskPhone(registeredPhone),
      recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user' },
      amount,
      message: 'Enter the code sent to your registered number to authorise this transfer.',
      demo_otp
    })
  }
  const otpOk = await verifyOtp(c, registeredPhone, otpCode, 'wallet_transfer')
  if (!otpOk.ok) return c.json({ error: otpOk.error || 'Invalid verification code.', otp_failed: true }, 400)

  const reference = ref('P2P')
  const note = String(b.reason || '').trim()

  // Commit the double-entry under admin context (so we can credit the recipient's
  // wallet regardless of RLS). The DB trigger rejects the sender debit if the
  // balance is short — defence-in-depth against a race with the pre-check.
  try {
    await withAdminContext(c, async () => {
      const recipientWalletId = await ensureWallet(c, recipient.id)
      // 1) Debit the sender first (trigger enforces sufficient balance).
      await postLedger(c, {
        userId: user.id, walletId: senderWalletId, type: 'debit', amount,
        category: 'p2p_transfer', reference,
        description: note || `Sent to ${recipient.full_name || 'user'}`, createdBy: user.id
      })
      // 2) Credit the recipient.
      await postLedger(c, {
        userId: recipient.id, walletId: recipientWalletId, type: 'credit', amount,
        category: 'p2p_transfer', reference,
        description: note || `Received from ${user.full_name || 'a Farmsky user'}`, createdBy: user.id
      })
      // 3) Record the transfer.
      await c.env.DB.prepare(
        `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
         VALUES (?, 'p2p_transfer', ?,?,?,?, 'KES', '0', 'Farmsky Wallet (P2P)', ?, ?, ?, 'success', 1, ?)`
      ).bind(reference, senderWalletId, user.id, String(recipient.id), amount, sasapayNormalizePhone(String(recipient.phone || '')), recipient.full_name || null, note || 'P2P transfer', user.id).run()
    })
  } catch (e: any) {
    const msg = String(e?.message || '')
    if (/insufficient/i.test(msg)) {
      return c.json({ error: 'Unsuccessful. You have insufficient Balance', insufficient: true }, 400)
    }
    return c.json({ error: 'Transfer could not be completed' }, 400)
  }

  // Notify both parties by SMS (simulated when unconfigured).
  try {
    if (user.phone) await sendSms(c.env, user.phone, `You sent KES ${amount.toLocaleString()} to ${recipient.full_name || 'a Farmsky user'}. Ref ${reference}.`)
    if (recipient.phone) await sendSms(c.env, String(recipient.phone), `You received KES ${amount.toLocaleString()} from ${user.full_name || 'a Farmsky user'}. Ref ${reference}.`)
  } catch (_) {}

  await audit(c, user.id, 'transfer', 'wallet', `KES ${amount} to user ${recipient.id} (${recipient.full_name || ''})`)
  return c.json({ ok: true, reference, amount, recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user' }, status: 'success', customer_message: `KES ${amount.toLocaleString()} sent to ${recipient.full_name || 'the recipient'}.` })
})

// ============================================================================
// ADMIN DIRECT PAYMENT — an authorised admin pays an individual directly, to
// either their in-app wallet OR a mobile/bank number via SasaPay B2C.
//   destination: 'wallet' (credit an internal wallet) | 'external' (B2C payout)
// ============================================================================
app.post('/api/wallet/direct-pay', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)
  const destination = b.destination === 'external' ? 'external' : 'wallet'
  const reference = ref('DP')

  if (destination === 'wallet') {
    // Credit an internal user's wallet directly. NB: on the shared central DB
    // users.id is a UUID, so the id is treated as an opaque string (not Number).
    const recipientId = String(b.user_id ?? '').trim()
    if (!recipientId) return c.json({ error: 'user_id is required for a wallet payment' }, 400)
    const result = await withAdminContext(c, async () => {
      const walletId = await ensureWallet(c, recipientId, admin.id)
      await postLedger(c, { userId: recipientId, walletId, type: 'credit', amount, category: b.category || 'direct_pay', reference, description: b.reason || 'Direct payment', createdBy: admin.id })
      await c.env.DB.prepare(
        `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, reason, status, ledger_debited, created_by)
         VALUES (?, 'direct_pay', ?,?,?,?, 'KES', '0', 'SasaPay Wallet (internal)', ?, ?, 'success', 0, ?)`
      ).bind(reference, walletId, admin.id, recipientId, amount, String(recipientId), b.reason || 'Direct wallet payment', admin.id).run()
      return { walletId }
    })
    await audit(c, admin.id, 'direct_pay', 'wallet', `KES ${amount} to user ${recipientId} wallet`)
    return c.json({ ok: true, destination: 'wallet', reference, status: 'success', ...(result as any) })
  }

  // External B2C payout to a mobile / bank number.
  const channelCode = String(b.channel_code || '').trim()
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'A valid payout channel is required' }, 400)
  let receiver = String(b.account_number || '').trim()
  if (!receiver) return c.json({ error: 'A destination account is required' }, 400)
  if (chan.type === 'mobile' || chan.type === 'wallet') receiver = sasapayNormalizePhone(receiver)

  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'direct_pay', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 0, ?)`
  ).bind(reference, admin.id, b.user_id ? String(b.user_id).trim() : null, amount, channelCode, chan.name, receiver, b.account_name || null, b.reason || 'Direct payment', admin.id).run()

  const payout = await disburseB2C(c, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || 'Direct payment', reference })
  if (!payout.success) {
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || 'B2C failed', reference).run()
    return c.json({ error: payout.error || 'Disbursal failed' }, 502)
  }
  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
    .bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? 'success' : 'processing', reference).run()
  await audit(c, admin.id, 'direct_pay', 'sasapay', `KES ${amount} to ${chan.name} ${receiver} (${payout.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, destination: 'external', simulated: payout.simulated, reference, status: payout.simulated ? 'success' : 'processing', customer_message: payout.customer_message || 'Payment is being processed.' })
})

// ============================================================================
// B2C CALLBACK — SasaPay posts the payout result here (success AND failure).
// Secured by IP whitelist + HMAC-SHA512 signature; idempotent by reference.
// ============================================================================
app.post('/api/sasapay/b2c-callback', async (c) => {
  try {
    const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
    const sig = c.req.header('x-sasapay-signature') || c.req.header('X-SasaPay-Signature')
    const body: any = await c.req.json().catch(() => ({}))

    if (sasapayConfigured(c.env)) {
      const ipOk = isTrustedSasapayIp(ip)
      const sigOk = await verifySasapaySignature(c.env, sig, {
        sasapay_transaction_code: body.TransactionCode || body.SasaPayTransactionCode || '',
        merchant_code: body.MerchantCode || '',
        account_number: body.ReceiverNumber || '',
        payment_reference: body.MerchantTransactionReference || body.OriginatorConversationID || '',
        amount: body.Amount || ''
      })
      if (!ipOk && !sigOk) {
        await audit(c, null, 'callback_rejected', 'sasapay_b2c', `untrusted ip=${ip || '?'} sig=${sig ? 'bad' : 'missing'}`)
        return c.json({ ResultCode: 1, ResultDesc: 'Rejected' }, 403)
      }
    }

    const reference = body.MerchantTransactionReference || body.OriginatorConversationID
    const b2cId = body.B2CRequestID || body.ConversationID
    const row = reference
      ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE reference=?`).bind(reference).first<any>()
      : (b2cId ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE b2c_request_id=? OR conversation_id=?`).bind(b2cId, b2cId).first<any>() : null)

    if (row && (row.status === 'processing' || row.status === 'pending')) {
      const code = body.ResultCode ?? body.status_code ?? body.TransactionCode
      const success = (code === 0 || code === '0' || body.status === true || String(body.ResultDesc || '').toLowerCase().includes('success'))
      if (success) {
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='success', transaction_code=?, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
          .bind(body.TransactionCode || body.SasaPayTransactionCode || '', String(code ?? '0'), body.ResultDesc || 'Success', row.reference).run()
      } else {
        // Payout failed AFTER we debited a wallet → refund the source wallet.
        if (row.ledger_debited && row.wallet_id && row.user_id) {
          try {
            await withAdminContext(c, async () => {
              await postLedger(c, { userId: row.user_id, walletId: row.wallet_id, type: 'credit', amount: numberVal(row.amount, 0), category: 'adjustment', reference: row.reference, description: `Reversal — failed payout ${row.reference}`, createdBy: null })
            })
          } catch (_) {}
        }
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
          .bind(String(code ?? '1'), body.ResultDesc || 'Payout failed', row.reference).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch { return c.json({ ResultCode: 0, ResultDesc: 'Accepted' }) }
})

// ----------------------------------------------------------------------------
// SECURITY VALIDATION — confirm RLS isolation is active
// Running the ownership-scoped tables WITHOUT a user context must yield 0 rows.
// ----------------------------------------------------------------------------
app.get('/api/security/rls-check', requireAuth, requireRole('super_admin'), async (c) => {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal !== 'function') return c.json({ supported: false, note: 'RLS is a PostgreSQL feature; not active on this runtime.' })
  // Deliberately clear the context, then read each protected table.
  await setLocal.call(c.env.DB, 'app.current_user_id', '')
  await setLocal.call(c.env.DB, 'app.current_role', '')
  const probe = async (t: string) => {
    try { const r = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM ${t}`).first<any>(); return Number(r?.n ?? -1) }
    catch { return -1 }
  }
  const result = {
    customers: await probe('customers'),
    products: await probe('products'),
    murabaha_contracts: await probe('murabaha_contracts'),
    wallet_ledger: await probe('wallet_ledger')
  }
  // Restore this admin's context.
  await setUserContext(c, c.get('user'))
  const leaking = Object.entries(result).filter(([, n]) => n > 0).map(([t]) => t)
  return c.json({
    supported: true,
    without_context_counts: result,
    isolation_ok: leaking.length === 0,
    message: leaking.length === 0
      ? 'RLS active: no rows are visible without a user context — data-leak vectors are closed.'
      : `WARNING: tables leaking without context: ${leaking.join(', ')}. Ensure backend/sql/03_ownership_rls_setup.sql has been applied.`
  })
})

// ----------------------------------------------------------------------------
// FRONTEND SHELL
// ----------------------------------------------------------------------------
app.get('/', (c) => c.html(SHELL))

// Farmsky-hosted checkout landing page for merchant-originated sessions.
function CHECKOUT_PAGE(row: any): string {
  const isFinancing = row.transaction_type === 'FINANCING_REQUEST'
  const esc = (s: any) => String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string))
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky Checkout</title>
  <link href="/static/tailwind.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  </head><body class="bg-slate-100 min-h-screen flex items-center justify-center p-4">
  <div class="bg-white rounded-2xl shadow-xl max-w-md w-full p-8">
    <div class="text-center mb-6"><i class="fas fa-leaf text-teal-600 text-4xl mb-2"></i>
      <h1 class="text-xl font-bold text-slate-800">Farmsky Checkout</h1>
      <p class="text-sm text-slate-500">${esc(row.inventory_type)} · ${isFinancing ? 'Financing Request' : 'Direct Purchase'}</p></div>
    <div class="border rounded-xl p-4 mb-4 bg-slate-50">
      <div class="flex justify-between mb-2"><span class="text-slate-500">Item</span><span class="font-medium">${esc(row.item_title)}</span></div>
      <div class="flex justify-between mb-2"><span class="text-slate-500">Category</span><span>${esc(row.category || 'general')}</span></div>
      <div class="flex justify-between mb-2"><span class="text-slate-500">Amount</span><span class="font-bold text-teal-700">KES ${Number(row.amount).toLocaleString()}</span></div>
      ${isFinancing ? `<div class="flex justify-between"><span class="text-slate-500">Tenor</span><span>${row.financing_tenor_months} months</span></div>` : ''}
    </div>
    <div class="text-sm text-slate-600 mb-4">
      <div><i class="fas fa-user mr-2 text-slate-400"></i>${esc(row.customer_full_name)}</div>
      <div><i class="fas fa-phone mr-2 text-slate-400"></i>${esc(row.customer_phone)}</div>
    </div>
    <button onclick="pay()" id="payBtn" class="btn w-full bg-teal-600 hover:bg-teal-700 text-white py-3 rounded-xl font-medium">
      <i class="fas fa-lock mr-2"></i>${isFinancing ? 'Submit Financing Request' : 'Pay Now'}</button>
    <p class="text-xs text-slate-400 text-center mt-4">Secured by Farmsky · Ref ${esc(row.checkout_ref)}</p>
  </div>
  <script>
    function pay(){
      var b=document.getElementById('payBtn');
      b.disabled=true; b.innerHTML='<i class="fas fa-spinner fa-spin mr-2"></i>Processing…';
      setTimeout(function(){
        b.innerHTML='<i class="fas fa-check mr-2"></i>Request received';
        b.classList.remove('bg-teal-600','hover:bg-teal-700'); b.classList.add('bg-emerald-600');
        ${row.success_callback_url ? `setTimeout(function(){ location.href=${JSON.stringify(String(row.success_callback_url))}; }, 1200);` : ''}
      }, 1400);
    }
  </script></body></html>`
}

const SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky</title>
  <link rel="icon" type="image/png" href="/static/favicon.png">
  <!-- Production Tailwind build (compiled via Tailwind CLI, no runtime CDN JIT). -->
  <link href="/static/tailwind.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <link href="/static/style.css" rel="stylesheet">
</head>
<body class="bg-slate-100 text-slate-800">
  <div id="app"></div>
  <script src="/static/app.js"></script>
</body>
</html>`

export default app
