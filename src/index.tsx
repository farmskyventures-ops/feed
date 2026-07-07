import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { Bindings, SessionUser } from './types'
import { stkPush, stkQuery, mpesaConfigured, normalizePhone } from './mpesa'
import { sasapayPush, sasapayQuery, sasapayConfigured } from './sasapay'
import { kcbPush, kcbQuery, kcbConfigured } from './kcb'
import { sendSms, smsConfigured, generateOtp } from './sms'
import { sendEmail, emailConfigured } from './email'

const app = new Hono<{ Bindings: Bindings; Variables: { user: SessionUser } }>()

app.use('/api/*', cors())

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
async function getSessionUser(c: any): Promise<SessionUser | null> {
  const token = getCookie(c, 'session') || c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return null
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.role, u.region, u.status, u.custom_role, u.permissions, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first()
  if (!row) return null
  if (Number(row.expires_at) < Date.now()) return null
  if (row.status !== 'active') return null
  let permissions: string[] = []
  try { permissions = row.permissions ? JSON.parse(row.permissions) : [] } catch { permissions = [] }
  return { id: row.id, full_name: row.full_name, phone: row.phone, role: row.role, region: row.region, custom_role: row.custom_role, permissions }
}
async function requireAuth(c: any, next: any) {
  const user = await getSessionUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', user)
  await next()
}
function requireRole(...roles: string[]) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!roles.includes(user.role)) return c.json({ error: 'Forbidden' }, 403)
    await next()
  }
}
// Does this user hold a specific granular permission? Super Admins always do.
function hasPerm(user: SessionUser, perm: string): boolean {
  if (!user) return false
  if (user.role === 'super_admin') return true
  return Array.isArray(user.permissions) && user.permissions.includes(perm)
}
// Middleware: require a granular permission (Super Admin bypasses).
function requirePerm(perm: string) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!hasPerm(user, perm)) return c.json({ error: 'Forbidden: missing permission "' + perm + '"' }, 403)
    await next()
  }
}
// Read a JSON app_setting by key, returning a parsed object (or fallback).
async function getSetting(c: any, key: string, fallback: any): Promise<any> {
  try {
    const row = await c.env.DB.prepare(`SELECT value FROM app_settings WHERE key=?`).bind(key).first<any>()
    if (!row || !row.value) return fallback
    return JSON.parse(row.value)
  } catch { return fallback }
}
async function setSetting(c: any, key: string, value: any, userId: number) {
  const json = JSON.stringify(value)
  await c.env.DB.prepare(
    `INSERT INTO app_settings (key, value, updated_by, updated_at) VALUES (?,?,?, CURRENT_TIMESTAMP)
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=CURRENT_TIMESTAMP`
  ).bind(key, json, userId).run()
}
// Compute the processing fee for a borrowed amount using the global config.
//   percentage: amount * rate%
//   tiered:     the flat fee of the matching [min,max] bracket
function computeProcessingFee(cfg: any, amount: number): number {
  if (!cfg || cfg.mode === 'none' || !cfg.mode) return 0
  const amt = Number(amount) || 0
  if (cfg.mode === 'percentage') {
    const rate = Number(cfg.percentage_rate) || 0
    return Math.round(amt * rate / 100)
  }
  if (cfg.mode === 'tiered') {
    const tiers = Array.isArray(cfg.tiers) ? cfg.tiers : []
    for (const t of tiers) {
      const min = Number(t.min) || 0
      const max = (t.max === null || t.max === undefined || t.max === '') ? Infinity : Number(t.max)
      if (amt >= min && amt <= max) return Number(t.fee) || 0
    }
  }
  return 0
}
// Is the user currently inside their allowed login window? Enforced at login.
// Returns { allowed, message }.
function checkAccessWindow(user: any): { allowed: boolean; message?: string } {
  // Super Admin is never locked out (avoids self-lockout).
  if (user.role === 'super_admin') return { allowed: true }
  let days: number[] = []
  try { days = user.access_days ? JSON.parse(user.access_days) : [] } catch { days = [] }
  const start = user.access_start, end = user.access_end
  // No restriction configured => 24/7 access.
  if ((!days || days.length === 0) && !start && !end) return { allowed: true }
  // Evaluate in East Africa Time (UTC+3) so windows match local expectation.
  const now = new Date(Date.now() + 3 * 3600 * 1000)
  const dow = now.getUTCDay()            // 0=Sun .. 6=Sat
  const mins = now.getUTCHours() * 60 + now.getUTCMinutes()
  if (days && days.length > 0 && !days.includes(dow)) {
    return { allowed: false, message: 'Your account is not permitted to sign in today. Please try during your assigned days.' }
  }
  const toMins = (hhmm: string) => {
    const [h, m] = String(hhmm).split(':').map(Number)
    return (h || 0) * 60 + (m || 0)
  }
  if (start && end) {
    const s = toMins(start), e = toMins(end)
    if (mins < s || mins > e) {
      return { allowed: false, message: `Access is only allowed between ${start} and ${end} (EAT). Please try again during your assigned hours.` }
    }
  }
  return { allowed: true }
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
async function createSession(c: any, user: any) {
  const token = genToken()
  const expires = Date.now() + 1000 * 60 * 60 * 12
  await c.env.DB.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)`).bind(token, user.id, expires).run()
  setCookie(c, 'session', token, { path: '/', httpOnly: true, maxAge: 60 * 60 * 12, sameSite: 'Lax' })
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
  if (!user || user.password !== String(password)) return c.json({ error: 'Invalid phone number or password' }, 401)
  if (user.status !== 'active') return c.json({ error: 'Account suspended' }, 403)
  // Time-Based Access Control: block sign-in outside the user's allowed window.
  const access = checkAccessWindow(user)
  if (!access.allowed) return c.json({ error: access.message || 'Access not allowed at this time' }, 403)
  const token = await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} logged in`)
  let permissions: string[] = []
  try { permissions = user.permissions ? JSON.parse(user.permissions) : [] } catch { permissions = [] }
  return c.json({ token, user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role, region: user.region, custom_role: user.custom_role, permissions } })
})
app.post('/api/logout', async (c) => {
  const token = getCookie(c, 'session')
  if (token) await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run()
  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true })
})
app.get('/api/me', requireAuth, (c) => c.json({ user: c.get('user') }))

// ----------------------------------------------------------------------------
// SELF-SERVICE PROFILE  (any authenticated user manages their OWN data)
// Administrative attributes (permissions, credit approvals, custom groupings,
// role) are intentionally NOT editable here to prevent privilege escalation.
// ----------------------------------------------------------------------------
app.get('/api/profile', requireAuth, async (c) => {
  const u = c.get('user')
  const row = await c.env.DB.prepare(
    `SELECT id, full_name, phone, email, region, role, custom_role,
            id_front_url, id_back_url, passport_selfie_url,
            farming_profile, output_tonnage, herd_count, current_loan_amount, sacco_member
     FROM users WHERE id=?`
  ).bind(u.id).first<any>()
  if (!row) return c.json({ error: 'Not found' }, 404)
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(u.id).first<any>()
  return c.json({ profile: row, customer: cust || null })
})
app.put('/api/profile', requireAuth, async (c) => {
  const u = c.get('user')
  const b = await c.req.json()
  // Only personal identifiers + farming/financial data variables. No role,
  // permissions, status, supervisor, or credit fields are accepted here.
  const farmingProfile = b.farming_profile || null
  const saccoMember = (b.sacco_member === true || b.sacco_member === 1 || String(b.sacco_member).toLowerCase() === 'yes') ? 1 : 0
  await c.env.DB.prepare(
    `UPDATE users SET full_name=COALESCE(?,full_name), email=COALESCE(?,email), region=COALESCE(?,region),
       id_front_url=COALESCE(?,id_front_url), id_back_url=COALESCE(?,id_back_url), passport_selfie_url=COALESCE(?,passport_selfie_url),
       farming_profile=?, output_tonnage=?, herd_count=?, current_loan_amount=?, sacco_member=?
     WHERE id=?`
  ).bind(b.full_name || null, b.email || null, b.region || null,
    b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || null,
    farmingProfile, b.output_tonnage ?? null, b.herd_count ?? null, Number(b.current_loan_amount || 0), saccoMember, u.id).run()
  // Mirror to the linked customer profile if present.
  await c.env.DB.prepare(
    `UPDATE customers SET full_name=COALESCE(?,full_name), farming_profile=?, value_chain_type=?, output_tonnage=?, herd_count=?, herd_size=?, current_loan_amount=?, sacco_member=?,
       id_front_url=COALESCE(?,id_front_url), id_back_url=COALESCE(?,id_back_url), selfie_url=COALESCE(?,selfie_url), passport_selfie_url=COALESCE(?,passport_selfie_url)
     WHERE user_id=?`
  ).bind(b.full_name || null, farmingProfile, farmingProfile, b.output_tonnage ?? null, b.herd_count ?? null, b.herd_count ?? null,
    Number(b.current_loan_amount || 0), saccoMember,
    b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || null, b.passport_selfie_url || null, u.id).run()
  await audit(c, u.id, 'update', 'profile', 'self-service profile update')
  return c.json({ ok: true })
})
// Change own password (requires current password).
app.put('/api/profile/password', requireAuth, async (c) => {
  const u = c.get('user')
  const { current_password, new_password } = await c.req.json()
  if (!new_password || String(new_password).length < 4) return c.json({ error: 'New password must be at least 4 characters' }, 400)
  const row = await c.env.DB.prepare(`SELECT password FROM users WHERE id=?`).bind(u.id).first<any>()
  if (!row || row.password !== String(current_password)) return c.json({ error: 'Current password is incorrect' }, 400)
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(String(new_password), u.id).run()
  await audit(c, u.id, 'update', 'profile', 'self-service password change')
  return c.json({ ok: true })
})

// ---- Auth provider status (so the UI can show live vs demo) ----
app.get('/api/auth/status', (c) => c.json({ sms_live: smsConfigured(c.env) }))

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
app.post('/api/signup/verify', async (c) => {
  const b = await c.req.json()
  const { phone, full_name, code, password, region } = b
  const p = normalizePhone(phone || '')
  if (!password || String(password).length < 4) return c.json({ error: 'Password must be at least 4 characters' }, 400)
  const v = await verifyOtp(c, p, code, 'signup')
  if (!v.ok) return c.json({ error: v.error }, 400)
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (existing) return c.json({ error: 'Account already exists. Please sign in.' }, 409)
  // KYC images + dynamic agri metrics + pruned financial profile (optional at
  // signup; can be completed later via the self-service profile).
  const farmingProfile = b.farming_profile || null
  const saccoMember = (b.sacco_member === true || b.sacco_member === 1 || String(b.sacco_member).toLowerCase() === 'yes') ? 1 : 0
  const r = await c.env.DB.prepare(
    `INSERT INTO users (full_name, phone, password, role, status, region, password_set, id_front_url, id_back_url, passport_selfie_url, farming_profile, output_tonnage, herd_count, current_loan_amount, sacco_member)
     VALUES (?,?,?, 'customer', 'active', ?, 1, ?,?,?,?,?,?,?,?)`
  ).bind(String(full_name).trim(), p, String(password), region || null,
    b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || null,
    farmingProfile, b.output_tonnage || null, b.herd_count || null,
    Number(b.current_loan_amount || 0), saccoMember).run()
  const userId = r.meta.last_row_id
  // Create a linked customer profile (KYC pending until registration completed)
  await c.env.DB.prepare(
    `INSERT INTO customers (user_id, full_name, mobile, farming_profile, value_chain_type, output_tonnage, herd_count, herd_size, current_loan_amount, sacco_member, id_front_url, id_back_url, selfie_url, passport_selfie_url, kyc_status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')`
  ).bind(userId, String(full_name).trim(), p, farmingProfile, farmingProfile,
    b.output_tonnage || null, b.herd_count || null, b.herd_count || null,
    Number(b.current_loan_amount || 0), saccoMember,
    b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || null, b.passport_selfie_url || null).run()
  const user = { id: userId, full_name: String(full_name).trim(), phone: p, role: 'customer', region }
  await createSession(c, user)
  await audit(c, userId, 'signup', 'user', 'customer self-registered via SMS OTP')
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
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(String(password), user.id).run()
  await audit(c, user.id, 'reset_password', 'user', 'password reset via SMS OTP')
  return c.json({ ok: true, message: 'Password updated. You can now sign in.' })
})

// ----------------------------------------------------------------------------
// PRODUCTS / INVENTORY
// ----------------------------------------------------------------------------
app.get('/api/products', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT * FROM products ORDER BY name`).all()
  const withStatus = results.map((p: any) => ({
    ...p,
    stock_status: p.quantity <= 0 ? 'out_of_stock' : p.quantity <= p.reorder_threshold ? 'low_stock' : 'in_stock'
  }))
  return c.json({ products: withStatus })
})
app.post('/api/products', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  // Payment eligibility: cash | finance | both. Markups default sensibly.
  const eligibility = ['cash', 'finance', 'both'].includes(b.payment_eligibility) ? b.payment_eligibility : 'both'
  const cashMk = Number(b.cash_markup_pct || 0)
  const finMk = Number(b.finance_markup_pct ?? b.credit_markup_pct ?? 0)
  const finDep = Number(b.finance_deposit_pct || 0)
  const cash = Number(b.buying_price) * (1 + cashMk / 100)
  const credit = Number(b.buying_price) * (1 + finMk / 100)
  const r = await c.env.DB.prepare(
    `INSERT INTO products (sku,name,category,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,finance_markup_pct,finance_deposit_pct,payment_eligibility,cash_terms,finance_terms,cash_price,credit_price,quantity,unit,reorder_threshold,image)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(b.sku, b.name, b.category, b.supplier_id || null, b.buying_price, cashMk, finMk, finMk, finDep, eligibility,
    b.cash_terms || null, b.finance_terms || null,
    Math.round(cash), Math.round(credit), b.quantity || 0, b.unit || 'unit', b.reorder_threshold || 10, b.image || null).run()
  await audit(c, c.get('user').id, 'create', 'product', b.name)
  return c.json({ id: r.meta.last_row_id })
})
app.put('/api/products/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  const eligibility = ['cash', 'finance', 'both'].includes(b.payment_eligibility) ? b.payment_eligibility : 'both'
  const cashMk = Number(b.cash_markup_pct || 0)
  const finMk = Number(b.finance_markup_pct ?? b.credit_markup_pct ?? 0)
  const finDep = Number(b.finance_deposit_pct || 0)
  const cash = Number(b.buying_price) * (1 + cashMk / 100)
  const credit = Number(b.buying_price) * (1 + finMk / 100)
  await c.env.DB.prepare(
    `UPDATE products SET sku=?, name=?, category=?, buying_price=?, cash_markup_pct=?, credit_markup_pct=?, finance_markup_pct=?, finance_deposit_pct=?, payment_eligibility=?, cash_terms=?, finance_terms=?, cash_price=?, credit_price=?, quantity=?, unit=?, reorder_threshold=?, image=COALESCE(?, image) WHERE id=?`
  ).bind(b.sku, b.name, b.category, b.buying_price, cashMk, finMk, finMk, finDep, eligibility,
    b.cash_terms || null, b.finance_terms || null,
    Math.round(cash), Math.round(credit), b.quantity, b.unit, b.reorder_threshold, b.image || null, id).run()
  await audit(c, c.get('user').id, 'update', 'product', b.name)
  return c.json({ ok: true })
})
app.delete('/api/products/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const used = await c.env.DB.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE product_id=?`).bind(id).first<any>()
  if (used?.n > 0) return c.json({ error: 'Cannot delete: product is referenced by existing contracts' }, 400)
  await c.env.DB.prepare(`DELETE FROM products WHERE id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'delete', 'product', String(id))
  return c.json({ ok: true })
})
app.put('/api/products/:id/stock', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { quantity, movement_type } = await c.req.json()
  await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id = ?`).bind(Number(quantity), id).run()
  await c.env.DB.prepare(`INSERT INTO stock_movements (product_id, movement_type, quantity, reference) VALUES (?,?,?,?)`)
    .bind(id, movement_type || 'purchase', quantity, 'manual adjustment').run()
  return c.json({ ok: true })
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
  return c.json({ customers: results })
})
app.get('/api/customers/:id', requireAuth, async (c) => {
  const user = c.get('user')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(c.req.param('id')).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const tu = await c.env.DB.prepare(`SELECT * FROM transunion_checks WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first<any>()
  const idv = await c.env.DB.prepare(`SELECT * FROM id_verifications WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first()
  // Data Object Visibility: redact sensitive data types for users who do not
  // hold the corresponding permission. A customer viewing their OWN record and
  // super admins are never redacted.
  const isSelf = user.role === 'customer' && cust.user_id === user.id
  let transunion = tu
  if (!isSelf && !hasPerm(user, 'view_financial_data')) {
    // Redact financial data types (loan, credit score, risk, financials).
    ;['current_loan_amount', 'credit_score', 'risk_band', 'sacco_member', 'output_tonnage', 'herd_count', 'herd_size', 'acreage'].forEach((k) => { if (k in cust) cust[k] = null })
    cust._financial_hidden = true
    transunion = null
  }
  if (!isSelf && !hasPerm(user, 'view_documents')) {
    // Redact document attachments (ID front, ID back, passport/selfie).
    ;['id_front_url', 'id_back_url', 'selfie_url', 'passport_selfie_url'].forEach((k) => { if (k in cust) cust[k] = null })
    cust._documents_hidden = true
  }
  if (!isSelf && !hasPerm(user, 'view_farmer_profile')) {
    // Redact core farmer profile fields (identity + farm profile), keeping
    // only the name and id for reference.
    ;['national_id', 'date_of_birth', 'gender', 'alt_mobile', 'county', 'sub_county', 'ward', 'village', 'latitude', 'longitude', 'value_chain', 'value_chain_type', 'farming_profile', 'farm_experience'].forEach((k) => { if (k in cust) cust[k] = null })
    cust._profile_hidden = true
  }
  return c.json({ customer: cust, transunion, id_verification: idv })
})
app.post('/api/customers', requireAuth, requireRole('agent', 'admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const user = c.get('user')
  // farming_profile drives which agri metric is captured (output_tonnage for
  // crop, herd_count/herd_size for livestock). Pruned financial profile keeps
  // exactly two points: current_loan_amount + sacco_member (truth value).
  const farmingProfile = b.farming_profile || b.value_chain_type || null
  const saccoMember = (b.sacco_member === true || b.sacco_member === 1 || String(b.sacco_member).toLowerCase() === 'yes') ? 1 : 0
  const r = await c.env.DB.prepare(
    `INSERT INTO customers (agent_id,full_name,national_id,date_of_birth,gender,mobile,alt_mobile,county,sub_county,ward,village,latitude,longitude,value_chain_type,value_chain,farming_profile,acreage,herd_size,herd_count,output_tonnage,farm_experience,current_loan_amount,sacco_member,id_front_url,id_back_url,selfie_url,passport_selfie_url,kyc_status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')`
  ).bind(
    user.role === 'agent' ? user.id : (b.agent_id || user.id),
    b.full_name, b.national_id, b.date_of_birth, b.gender, b.mobile, b.alt_mobile, b.county, b.sub_county,
    b.ward, b.village, b.latitude || null, b.longitude || null, farmingProfile, b.value_chain, farmingProfile,
    b.acreage || null, b.herd_size || b.herd_count || null, b.herd_count || b.herd_size || null,
    b.output_tonnage || null, b.farm_experience || null,
    Number(b.current_loan_amount || 0), saccoMember,
    b.id_front_url || null, b.id_back_url || null, b.selfie_url || b.passport_selfie_url || null, b.passport_selfie_url || b.selfie_url || null
  ).run()
  await audit(c, user.id, 'onboard', 'customer', b.full_name)
  return c.json({ id: r.meta.last_row_id })
})
// Store the three KYC validation images (ID front, ID back, passport selfie)
// captured during the sequential camera funnel. Accepts data-URL / path refs.
app.post('/api/customers/:id/kyc-images', requireAuth, async (c) => {
  const id = c.req.param('id')
  const user = c.get('user')
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  if (!['admin', 'super_admin', 'agent'].includes(user.role)) {
    if (!(user.role === 'customer' && cust.user_id === user.id)) return c.json({ error: 'Forbidden' }, 403)
  }
  const b = await c.req.json()
  await c.env.DB.prepare(
    `UPDATE customers SET id_front_url=COALESCE(?,id_front_url), id_back_url=COALESCE(?,id_back_url), selfie_url=COALESCE(?,selfie_url), passport_selfie_url=COALESCE(?,passport_selfie_url) WHERE id=?`
  ).bind(b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || b.selfie_url || null, b.passport_selfie_url || b.selfie_url || null, id).run()
  if (cust.user_id) {
    await c.env.DB.prepare(
      `UPDATE users SET id_front_url=COALESCE(?,id_front_url), id_back_url=COALESCE(?,id_back_url), passport_selfie_url=COALESCE(?,passport_selfie_url) WHERE id=?`
    ).bind(b.id_front_url || null, b.id_back_url || null, b.passport_selfie_url || b.selfie_url || null, cust.user_id).run()
  }
  return c.json({ ok: true })
})
// Verification engine (mocked) - agents/admins, or a customer verifying their own profile
app.post('/api/customers/:id/verify', requireAuth, async (c) => {
  const id = c.req.param('id')
  const user = c.get('user')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  if (!['admin', 'super_admin', 'agent'].includes(user.role)) {
    if (!(user.role === 'customer' && cust.user_id === user.id)) return c.json({ error: 'Forbidden' }, 403)
  }
  const score = Math.floor(Math.random() * 350 + 450)
  const band = score >= 700 ? 'low' : score >= 600 ? 'medium' : 'high'
  await c.env.DB.prepare(`INSERT INTO transunion_checks (customer_id,credit_score,risk_band,defaults_found,raw_response) VALUES (?,?,?,?,?)`)
    .bind(id, score, band, band === 'high' ? 1 : 0, JSON.stringify({ score, band })).run()
  await c.env.DB.prepare(`INSERT INTO id_verifications (customer_id,face_match,liveness,ocr_name,ocr_dob,ocr_id_number,status) VALUES (?,?,?,?,?,?, 'verified')`)
    .bind(id, 1, 1, cust.full_name, cust.date_of_birth, cust.national_id).run()
  await c.env.DB.prepare(`UPDATE customers SET kyc_status='verified', risk_band=?, credit_score=? WHERE id=?`).bind(band, score, id).run()
  await audit(c, user.id, 'verify', 'customer', `KYC verified for ${cust.full_name}`)
  return c.json({ ok: true, credit_score: score, risk_band: band, face_match: true, liveness: true })
})

// ----------------------------------------------------------------------------
// MURABAHA
// ----------------------------------------------------------------------------
app.post('/api/murabaha/quote', requireAuth, async (c) => {
  const { product_id, quantity, payment_type, term_months } = await c.req.json()
  const p = await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>()
  if (!p) return c.json({ error: 'Product not found' }, 404)
  const qty = Number(quantity) || 1
  const supplier_cost = p.buying_price * qty
  const isCash = payment_type === 'cash'
  // Checkout calculations per configured rules:
  //  Cash:     base * cash_markup%
  //  Financed: base * finance_markup%  (total long-term debt)
  //  Deposit:  finance_deposit% of the financed total
  const markup_pct = isCash ? p.cash_markup_pct : (p.finance_markup_pct ?? p.credit_markup_pct)
  const unit_price = isCash ? p.cash_price : p.credit_price
  const murabaha_price = unit_price * qty
  const depositPct = isCash ? 0 : Number(p.finance_deposit_pct || 0)
  const deposit_required = isCash ? murabaha_price : Math.round(murabaha_price * depositPct / 100)
  const term = payment_type === 'credit' ? (Number(term_months) || 6) : 0
  const monthly = term > 0 ? Math.round(Math.max(0, murabaha_price - deposit_required) / term) : 0
  // Processing fee applies to the amount BORROWED (financed) — i.e. the amount
  // due after the deposit. Cash purchases carry no processing fee.
  const amount_borrowed = isCash ? 0 : Math.max(0, murabaha_price - deposit_required)
  const feeCfg = await getSetting(c, 'processing_fee', { mode: 'none' })
  const processing_fee = isCash ? 0 : computeProcessingFee(feeCfg, amount_borrowed)
  return c.json({
    product: p.name, quantity: qty, supplier_cost, markup_pct, murabaha_price, term_months: term, monthly_payment: monthly,
    deposit_pct: depositPct, deposit_required,
    amount_borrowed, processing_fee, processing_fee_mode: feeCfg?.mode || 'none',
    payment_eligibility: p.payment_eligibility || 'both',
    terms: isCash ? (p.cash_terms || '') : (p.finance_terms || ''),
    sharia_note: 'Price becomes FIXED once the contract is signed. No interest, penalties, or compounding.'
  })
})
app.post('/api/murabaha/apply', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id, product_id, quantity, payment_type, term_months, delivery_location, consent, terms_accepted } = await c.req.json()
  if (!consent) return c.json({ error: 'Customer consent is required (Sharia requirement)' }, 400)
  if (!terms_accepted) return c.json({ error: 'You must accept the terms and conditions to proceed.' }, 400)
  const p = await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>()
  if (!p) return c.json({ error: 'Product not found' }, 404)
  // Enforce the product's payment-eligibility rule.
  const eligibility = p.payment_eligibility || 'both'
  if (eligibility === 'cash' && payment_type !== 'cash') return c.json({ error: 'This item is available for Cash purchase only.' }, 400)
  if (eligibility === 'finance' && payment_type !== 'credit') return c.json({ error: 'This item is available for Financing only.' }, 400)
  const qty = Number(quantity) || 1
  if (p.quantity < qty) return c.json({ error: 'Insufficient stock' }, 400)
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  const custRow = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first<any>()
  if (payment_type === 'credit' && custRow?.kyc_status !== 'verified') {
    return c.json({
      error: 'kyc_required',
      message: 'Complete user registration (TransUnion credit check + liveness/ID verification) is required before Pay Later (Murabaha Financing) purchases.',
      customer_id: custId
    }, 412)
  }
  const supplier_cost = p.buying_price * qty
  const isCash = payment_type === 'cash'
  const markup_pct = isCash ? p.cash_markup_pct : (p.finance_markup_pct ?? p.credit_markup_pct)
  const unit_price = isCash ? p.cash_price : p.credit_price
  const murabaha_price = unit_price * qty
  const depositPct = isCash ? 0 : Number(p.finance_deposit_pct || 0)
  const deposit_required = isCash ? murabaha_price : Math.round(murabaha_price * depositPct / 100)
  const term = payment_type === 'credit' ? (Number(term_months) || 6) : 0
  const monthly = term > 0 ? Math.round(Math.max(0, murabaha_price - deposit_required) / term) : 0
  const acceptedTerms = isCash ? (p.cash_terms || '') : (p.finance_terms || '')
  // Processing fee on the amount financed (after deposit). Cash = no fee.
  const amountBorrowed = isCash ? 0 : Math.max(0, murabaha_price - deposit_required)
  const feeCfg = await getSetting(c, 'processing_fee', { mode: 'none' })
  const processingFee = isCash ? 0 : computeProcessingFee(feeCfg, amountBorrowed)
  const contractRef = ref('MRB')
  // Cash purchases now go through an M-Pesa STK Push at checkout, so they
  // start as 'pending_payment' (stock reserved on successful payment, not
  // here). Credit (Pay Later) purchases start as 'pending' for approval.
  const status = payment_type === 'cash' ? 'pending_payment' : 'pending'
  const r = await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,accepted_terms,terms_accepted,deposit_required,processing_fee)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(contractRef, custId, custRow?.agent_id || null, product_id, qty, payment_type, supplier_cost, markup_pct,
    murabaha_price, term, monthly, delivery_location || '', status,
    0, 1, 0, murabaha_price, acceptedTerms, 1, deposit_required, processingFee).run()
  const contractId = r.meta.last_row_id
  await audit(c, user.id, 'apply', 'murabaha', `${payment_type} ${contractRef}`)
  // For cash, tell the frontend to start the M-Pesa checkout immediately.
  return c.json({
    id: contractId, contract_ref: contractRef, status, murabaha_price, monthly_payment: monthly,
    deposit_required, processing_fee: processingFee,
    requires_payment: payment_type === 'cash', outstanding: murabaha_price, payment_type
  })
})
app.get('/api/murabaha', requireAuth, async (c) => {
  const user = c.get('user')
  let q = `SELECT mc.*, p.name as product_name, cu.full_name as customer_name
           FROM murabaha_contracts mc JOIN products p ON p.id = mc.product_id JOIN customers cu ON cu.id = mc.customer_id`
  const binds: any[] = []
  const wheres: string[] = []
  if (user.role === 'agent') { wheres.push(`mc.agent_id = ?`); binds.push(user.id) }
  else if (user.role === 'customer') {
    const myCust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    wheres.push(`mc.customer_id = ?`); binds.push(myCust?.id || -1)
  } else {
    // Sales Visibility: staff who hold an explicit sales-permission grid only
    // see the sale type they are allowed to. Legacy admins with empty grids and
    // super admins keep full visibility.
    const canCash = hasPerm(user, 'view_cash_sales')
    const canFin = hasPerm(user, 'view_financed_sales')
    const hasSalesGrid = Array.isArray(user.permissions) && (user.permissions.includes('view_cash_sales') || user.permissions.includes('view_financed_sales'))
    if (user.role !== 'super_admin' && hasSalesGrid) {
      if (canCash && !canFin) wheres.push(`mc.payment_type = 'cash'`)
      else if (canFin && !canCash) wheres.push(`mc.payment_type = 'credit'`)
    }
  }
  if (wheres.length) q += ` WHERE ` + wheres.join(' AND ')
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
app.post('/api/murabaha/:id/decision', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { action, notes } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status !== 'pending') return c.json({ error: 'Contract is not pending' }, 400)
  await c.env.DB.prepare(`INSERT INTO approvals (contract_id,reviewer_id,action,notes) VALUES (?,?,?,?)`).bind(id, c.get('user').id, action, notes || '').run()
  if (action === 'approve') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='active', ownership_recorded=1 WHERE id=?`).bind(id).run()
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, 'credit_allocation', contract.quantity, contract.contract_ref).run()
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'unpaid')`).bind(ref('INV'), id, contract.customer_id, contract.murabaha_price).run()
    const term = contract.term_months, monthly = contract.monthly_payment, start = new Date()
    for (let i = 1; i <= term; i++) {
      const due = new Date(start.getFullYear(), start.getMonth() + i, 1)
      const amount = i === term ? contract.murabaha_price - monthly * (term - 1) : monthly
      await c.env.DB.prepare(`INSERT INTO repayments (contract_id,installment_no,due_date,amount_due,status) VALUES (?,?,?,?, 'current')`)
        .bind(id, i, due.toISOString().slice(0, 10), amount).run()
    }
  } else if (action === 'reject') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='rejected' WHERE id=?`).bind(id).run()
  }
  await audit(c, c.get('user').id, action, 'murabaha', contract.contract_ref)
  return c.json({ ok: true, action })
})

// ----------------------------------------------------------------------------
// PAYMENTS - Centralized Orchestration Routing Layer
// ----------------------------------------------------------------------------
async function applyPayment(c: any, contract: any, amt: number, receipt: string, method: string, phone: string) {
  // Direct interaction target switched to Central DB for tracking unified financial state
  const centralDb = c.env.CENTRAL_DB || c.env.DB
  
  // A cash purchase paid via STK push at checkout: settle the sale —
  // deduct stock, mark completed, log a cash_sale transaction + paid invoice.
  const isCashCheckout = contract.payment_type === 'cash' && contract.status === 'pending_payment'
  if (isCashCheckout) {
    // Inventory adjustments remain contextual to the product catalog source
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, 'sale', contract.quantity, contract.contract_ref).run()
    
    // Invoices and unified multi-channel transaction ledgers route directly to the Central DB
    await centralDb.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'paid')`).bind(ref('INV'), contract.id, contract.customer_id, contract.murabaha_price).run()
    await centralDb.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`)
      .bind(ref('TXN'), contract.id, contract.customer_id, amt, method, 'cash_sale', receipt, phone).run()
    await centralDb.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=0, status='completed', ownership_recorded=1 WHERE id=?`).bind(amt, contract.id).run()
    return { amount_paid: amt, outstanding: 0, status: 'completed' }
  }
  
  // Route general repayments and collection runs to Central DB allocations
  await centralDb.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`)
    .bind(ref('TXN'), contract.id, contract.customer_id, amt, method, 'repayment', receipt, phone).run()
    
  const newPaid = contract.amount_paid + amt
  const newOutstanding = Math.max(0, contract.murabaha_price - newPaid)
  const status = newOutstanding <= 0 ? 'completed' : 'active'
  await centralDb.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=?, status=? WHERE id=?`).bind(newPaid, newOutstanding, status, contract.id).run()
  
  let remaining = amt
  const { results: due } = await centralDb.prepare(`SELECT * FROM repayments WHERE contract_id=? AND status!='completed' ORDER BY installment_no`).bind(contract.id).all<any>()
  for (const inst of due) {
    if (remaining <= 0) break
    const need = inst.amount_due - inst.amount_paid
    const pay = Math.min(need, remaining)
    const paidTotal = inst.amount_paid + pay
    const st = paidTotal >= inst.amount_due ? 'completed' : 'current'
    await centralDb.prepare(`UPDATE repayments SET amount_paid=?, status=?, paid_at=CURRENT_TIMESTAMP WHERE id=?`).bind(paidTotal, st, inst.id).run()
    remaining -= pay
  }
  await centralDb.prepare(`UPDATE invoices SET status=? WHERE contract_id=?`).bind(newOutstanding <= 0 ? 'paid' : 'partial', contract.id).run()
  return { amount_paid: newPaid, outstanding: newOutstanding, status }
}

// ----------------------------------------------------------------------------
// PAYMENTS - Secure Centralized Orchestration Routing Layer
// ----------------------------------------------------------------------------
type PaymentProvider = {
  id: string
  label: string
  hidden?: boolean
}

const PROVIDERS: Record<string, PaymentProvider> = {
  mpesa: { id: 'mpesa', label: 'M-Pesa' },
  sasapay: { id: 'sasapay', label: 'SasaPay' },
  kcb: { id: 'kcb', label: 'KCB', hidden: true }
}

function getProvider(name?: string): PaymentProvider {
  return PROVIDERS[String(name || 'mpesa').toLowerCase()] || PROVIDERS.mpesa
}

function genReceipt(provider: string, live: boolean): string {
  const prefix = provider === 'sasapay' ? 'SP' : provider === 'kcb' ? 'KCB' : 'MP'
  if (live) return prefix + 'L' + Date.now().toString().slice(-7)
  return prefix + Math.random().toString(36).slice(2, 9).toUpperCase()
}

// List the available payment providers exposed across the frontends
app.get('/api/payments/providers', requireAuth, (c) => {
  const providers = Object.values(PROVIDERS).filter((p) => !p.hidden).map((p) => {
    return { id: p.id, label: p.label, live: true, mode: 'live' }
  })
  return c.json({ providers })
})

// Centralized payment initiation proxy endpoint with HMAC Security Routing
app.post('/api/payments/initiate', requireAuth, async (c) => {
  const centralDb = c.env.CENTRAL_DB || c.env.DB
  const { contract_id, amount, phone, provider } = await c.req.json()
  const prov = getProvider(provider)
  
  const contract = await centralDb.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)
  
  if (contract.payment_type === 'cash' && contract.status === 'pending_payment') {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if (!p || p.quantity < contract.quantity) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && contract.status !== 'active') {
    return c.json({ error: 'This contract is not open for payment.' }, 400)
  }
  
  const amt = Number(amount)
  if (!amt || amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (contract.payment_type !== 'cash' && amt > contract.outstanding) {
    return c.json({ error: `Amount exceeds the outstanding balance of KES ${contract.outstanding}.` }, 400)
  }
  
  const payPhone = phone || c.get('user').phone
  const desc = contract.payment_type === 'cash' ? 'Feed Cash Sale' : 'Feed Murabaha'

  try {
    // 1. Point request pipeline directly to production secure endpoint setup
    const centralGatewayUrl = 'https://equipment.farmsky.africa/api/v1/payments/initiate'
    
    const requestPayload = {
      payment_method: prov.id === 'kcb' ? 'buni' : prov.id, // Maps to provider criteria definition
      amount: amt,
      phone: normalizePhone(payPhone),
      origin_reference: contract.contract_ref,
      description: desc,
      initiated_by_user: c.get('user').id
    }

    const rawBodyText = JSON.stringify(requestPayload)

    // 2. Cryptographic signature extraction handling via your local payments-shared module
    const { signRequest } = await import('./payments-shared')
    
    // 3. System markers mapping validation credentials
    const clientKey = 'feed' 
    const hmacSecret = c.env.FARMSKY_FEED_HMAC_SECRET 

    if (!hmacSecret) {
      console.error("Missing critical environment definition: FARMSKY_FEED_HMAC_SECRET configuration is absent.")
      return c.json({ error: 'Client application secret context initialization breakdown.' }, 500)
    }

    // Secure compilation matching your canonical format layout [client_key\ntimestamp\nnonce\nbody]
    const { timestamp, nonce, signature } = await signRequest(hmacSecret, clientKey, rawBodyText)

    const centralResponse = await fetch(centralGatewayUrl, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-Farmsky-Client': clientKey,
        'X-Farmsky-Timestamp': timestamp,
        'X-Farmsky-Nonce': nonce,
        'X-Farmsky-Signature': signature
      },
      body: rawBodyText
    })

    const result: any = await centralResponse.json()
    if (!centralResponse.ok || !result.success) {
      return c.json({ error: result.error || `${prov.label} central execution core rejected transaction request.` }, centralResponse.status || 502)
    }
  
    // 4. Record mapping rows inside payment_intents using Core's absolute transaction_ref
    await centralDb.prepare(
      `INSERT INTO payment_intents 
        (checkout_request_id, merchant_request_id, contract_id, customer_id, amount, phone, method, status, marketplace_source) 
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'feed')`
    ).bind(
      result.transaction_ref, 
      null, 
      contract_id, 
      contract.customer_id, 
      amt, 
      normalizePhone(payPhone), 
      prov.id
    ).run()
      
    await audit(c, c.get('user').id, 'payment_initiate', prov.id, `KES ${amt} securely signed & routed to core for ${contract.contract_ref}`)
    
    return c.json({ 
      ok: true, 
      provider: prov.id, 
      simulated: result.simulated, 
      checkout_request_id: result.transaction_ref, 
      customer_message: result.customer_message 
    })
  
  } catch (error: any) {
    console.error("Central engine secure dispatch execution dropped:", error)
    return c.json({ error: 'Could not establish secure link with payment orchestration gateway.' }, 500)
  }
})

// Confirmation query pooling logic targeting the central DB ledger state changes
app.post('/api/payments/confirm', requireAuth, async (c) => {
  const centralDb = c.env.CENTRAL_DB || c.env.DB
  const { checkout_request_id } = await c.req.json()
  
  const intent = await centralDb.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment record tracking reference not found.' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  if (intent.status === 'failed') return c.json({ ok: false, status: 'failed', result_desc: intent.result_desc || 'Payment failed' })
  
  // Webhooks are writing directly to our shared central tables. 
  // If the hook has not cleared yet, state retains a pending status.
  return c.json({ ok: false, status: 'pending' })
})

// Legacy individual M-Pesa routes updated to adhere to the centralized multi-tenant format
app.post('/api/mpesa/stkpush', requireAuth, async (c) => {
  return c.redirect('/api/payments/initiate', 307)
})

app.post('/api/mpesa/confirm', requireAuth, async (c) => {
  return c.redirect('/api/payments/confirm', 307)
})

app.get('/api/mpesa/status', requireAuth, (c) => {
  return c.json({ live: true, mode: 'live' })
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
    const completed = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE customer_id=? AND status='completed'`).bind(cid).first<any>()
    const nextDue = await db.prepare(`SELECT r.* FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.customer_id=? AND r.status!='completed' ORDER BY r.due_date LIMIT 1`).bind(cid).first<any>()
    return c.json({ role: 'customer', active_contracts: contracts?.n || 0, total_outstanding: contracts?.out || 0, completed_contracts: completed?.n || 0, next_payment: nextDue || null })
  }
  if (user.role === 'agent') {
    const cust = await db.prepare(`SELECT COUNT(*) n FROM customers WHERE agent_id=?`).bind(user.id).first<any>()
    const active = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE agent_id=? AND status='active'`).bind(user.id).first<any>()
    const pending = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE agent_id=? AND status='pending'`).bind(user.id).first<any>()
    const portfolio = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE agent_id=?`).bind(user.id).first<any>()
    const late = await db.prepare(`SELECT COUNT(*) n FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.agent_id=? AND r.status='late'`).bind(user.id).first<any>()
    const par = portfolio?.tot ? Math.round((portfolio.out / portfolio.tot) * 100) : 0
    return c.json({ role: 'agent', customers_onboarded: cust?.n || 0, active_contracts: active?.n || 0, pending_approvals: pending?.n || 0, portfolio_value: portfolio?.tot || 0, portfolio_at_risk: par, late_installments: late?.n || 0, commission: Math.round((portfolio?.tot || 0) * 0.025) })
  }
  const sales = await db.prepare(`SELECT COALESCE(SUM(amount),0) tot FROM transactions WHERE status='success'`).first<any>()
  const financed = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='credit'`).first<any>()
  const cashSales = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='cash'`).first<any>()
  const activeCust = await db.prepare(`SELECT COUNT(*) n FROM customers`).first<any>()
  const invValue = await db.prepare(`SELECT COALESCE(SUM(buying_price*quantity),0) tot FROM products`).first<any>()
  const totalRepay = await db.prepare(`SELECT COUNT(*) n FROM repayments`).first<any>()
  const completedRepay = await db.prepare(`SELECT COUNT(*) n FROM repayments WHERE status='completed'`).first<any>()
  const defaulted = await db.prepare(`SELECT COUNT(*) n FROM repayments WHERE status='defaulted'`).first<any>()
  const pending = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE status='pending'`).first<any>()
  const repayRate = totalRepay?.n ? Math.round((completedRepay.n / totalRepay.n) * 100) : 0
  const defaultRate = totalRepay?.n ? Math.round((defaulted.n / totalRepay.n) * 100) : 0
  const { results: topProducts } = await db.prepare(`SELECT p.name, COUNT(mc.id) sales FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id GROUP BY p.id ORDER BY sales DESC LIMIT 5`).all()
  return c.json({ role: 'admin', total_sales: sales?.tot || 0, murabaha_financed: financed?.tot || 0, cash_sales: cashSales?.tot || 0, repayment_rate: repayRate, default_rate: defaultRate, inventory_value: invValue?.tot || 0, active_customers: activeCust?.n || 0, pending_approvals: pending?.n || 0, top_products: topProducts })
})

// ----------------------------------------------------------------------------
// FINANCING & MARKUP SETTINGS  (processing fee + global markup)
// ----------------------------------------------------------------------------
// Read the full financing/markup settings. Readable by admins & super admins.
app.get('/api/settings/financing', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const processing_fee = await getSetting(c, 'processing_fee', { mode: 'none', percentage_rate: 0, tiers: [] })
  const finance_markup = await getSetting(c, 'finance_markup', { default_markup_pct: 20 })
  const user = c.get('user')
  return c.json({
    processing_fee,
    finance_markup,
    can_manage_processing_fees: hasPerm(user, 'manage_processing_fees'),
    can_manage_markup: hasPerm(user, 'manage_markup')
  })
})
// Update the Processing Fee configuration (percentage OR tiered range).
// Guarded by the "manage_processing_fees" granular permission.
app.put('/api/settings/processing-fee', requireAuth, requireRole('admin', 'super_admin'), requirePerm('manage_processing_fees'), async (c) => {
  const b = await c.req.json()
  const mode = ['none', 'percentage', 'tiered'].includes(b.mode) ? b.mode : 'none'
  const percentage_rate = Math.max(0, Number(b.percentage_rate) || 0)
  // Sanitise tiers: keep numeric min/fee, allow open-ended max.
  const tiers = Array.isArray(b.tiers) ? b.tiers.map((t: any) => ({
    min: Math.max(0, Number(t.min) || 0),
    max: (t.max === null || t.max === undefined || t.max === '') ? null : Math.max(0, Number(t.max) || 0),
    fee: Math.max(0, Number(t.fee) || 0)
  })) : []
  const cfg = { mode, percentage_rate, tiers }
  await setSetting(c, 'processing_fee', cfg, c.get('user').id)
  await audit(c, c.get('user').id, 'update', 'processing_fee', `mode=${mode}`)
  return c.json({ ok: true, processing_fee: cfg })
})
// Update the global default finance markup percentage.
// Guarded by the "manage_markup" granular permission.
app.put('/api/settings/markup', requireAuth, requireRole('admin', 'super_admin'), requirePerm('manage_markup'), async (c) => {
  const b = await c.req.json()
  const cfg = { default_markup_pct: Math.max(0, Number(b.default_markup_pct) || 0) }
  await setSetting(c, 'finance_markup', cfg, c.get('user').id)
  await audit(c, c.get('user').id, 'update', 'finance_markup', `default=${cfg.default_markup_pct}%`)
  return c.json({ ok: true, finance_markup: cfg })
})

// ----------------------------------------------------------------------------
// AGENTS
// ----------------------------------------------------------------------------
app.get('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.region, u.status,
     (SELECT COUNT(*) FROM customers WHERE agent_id=u.id) customers,
     (SELECT COUNT(*) FROM murabaha_contracts WHERE agent_id=u.id AND status='active') active
     FROM users u WHERE u.role='agent'`
  ).all()
  return c.json({ agents: results })
})
app.post('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p) return c.json({ error: 'Name and phone are required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  // Admin may set a password; otherwise one is auto-generated.
  const provided = b.password && String(b.password).length >= 4
  const pwd = provided ? String(b.password) : genPassword()
  // Granular governance: store the explicit permissions array + optional
  // custom organizational role label on the user record.
  const perms = Array.isArray(b.permissions) ? b.permissions : []
  const permsJson = JSON.stringify(perms)
  const accessDays = Array.isArray(b.access_days) && b.access_days.length ? JSON.stringify(b.access_days.map((n: any) => Number(n))) : null
  const r = await c.env.DB.prepare(
    `INSERT INTO users (full_name,phone,email,password,role,region,password_set,custom_role,permissions,supervisor_id,access_days,access_start,access_end)
     VALUES (?,?,?,?, 'agent', ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(b.full_name, p, b.email || null, pwd, b.region || null, provided ? 1 : 0,
    b.custom_role || null, permsJson, b.supervisor_id || null, accessDays, b.access_start || null, b.access_end || null).run()
  await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, permsJson).run()
  await audit(c, c.get('user').id, 'create', 'agent', b.full_name)
  return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: provided })
})
// Admin: instantly reset a user's password (agents, customers, support).
// Auto-generates a new password and returns it for the admin to share.
app.post('/api/users/:id/reset-password', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const target = await c.env.DB.prepare(`SELECT id, full_name, role FROM users WHERE id=?`).bind(id).first<any>()
  if (!target) return c.json({ error: 'User not found' }, 404)
  if (target.role === 'super_admin' && Number(id) !== c.get('user').id) {
    return c.json({ error: 'Cannot reset another Super Admin password' }, 400)
  }
  const body = await c.req.json().catch(() => ({}))
  const provided = body?.password && String(body.password).length >= 4
  const pwd = provided ? String(body.password) : genPassword()
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(pwd, id).run()
  // Force re-login by clearing existing sessions.
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'reset_password', target.role, target.full_name)
  return c.json({ ok: true, new_password: pwd, user: target.full_name })
})
app.put('/api/agents/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, region=? WHERE id=? AND role='agent'`).bind(b.full_name, b.phone, b.email, b.region, id).run()
  if (b.permissions) await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region, JSON.stringify(b.permissions), id).run()
  await audit(c, c.get('user').id, 'update', 'agent', b.full_name)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// USER ACCOUNTS (admin) - edit, activate/deactivate, delete
// ----------------------------------------------------------------------------
app.get('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.role, u.status, u.region, u.custom_role, u.permissions, u.supervisor_id,
            u.access_days, u.access_start, u.access_end,
            s.full_name AS supervisor_name, u.created_at
     FROM users u LEFT JOIN users s ON s.id = u.supervisor_id ORDER BY u.id`
  ).all()
  return c.json({ users: results })
})
// Super Admin / Admin: create a system operator, field agent, farmer or
// lender with an explicit permission grid + optional custom role label.
app.post('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p) return c.json({ error: 'Name and phone are required' }, 400)
  const role = ['admin', 'agent', 'customer', 'support', 'lender'].includes(b.role) ? b.role : 'agent'
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const provided = b.password && String(b.password).length >= 4
  const pwd = provided ? String(b.password) : genPassword()
  const perms = Array.isArray(b.permissions) ? b.permissions : []
  const permsJson = JSON.stringify(perms)
  const accessDays = Array.isArray(b.access_days) && b.access_days.length ? JSON.stringify(b.access_days.map((n: any) => Number(n))) : null
  const r = await c.env.DB.prepare(
    `INSERT INTO users (full_name,phone,email,password,role,status,region,password_set,custom_role,permissions,supervisor_id,access_days,access_start,access_end)
     VALUES (?,?,?,?,?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(b.full_name, p, b.email || null, pwd, role, b.region || null, provided ? 1 : 0,
    b.custom_role || null, permsJson, b.supervisor_id || null, accessDays, b.access_start || null, b.access_end || null).run()
  // Keep an agents row in sync when the role is agent (legacy expectations).
  if (role === 'agent') {
    await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, permsJson).run()
  }
  // Farmers also get a linked customer profile.
  if (role === 'customer') {
    await c.env.DB.prepare(`INSERT INTO customers (user_id, full_name, mobile, kyc_status) VALUES (?,?,?, 'pending')`).bind(r.meta.last_row_id, b.full_name, p).run()
  }
  await audit(c, c.get('user').id, 'create', role, b.full_name)
  return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: provided })
})
// Super Admin: move a user to be supervised by a certain user.
app.put('/api/users/:id/supervisor', requireAuth, requireRole('super_admin'), async (c) => {
  const id = Number(c.req.param('id'))
  const { supervisor_id } = await c.req.json()
  if (supervisor_id && Number(supervisor_id) === id) return c.json({ error: 'A user cannot supervise themselves' }, 400)
  await c.env.DB.prepare(`UPDATE users SET supervisor_id=? WHERE id=?`).bind(supervisor_id || null, id).run()
  await audit(c, c.get('user').id, 'assign_supervisor', 'user', `user ${id} -> supervisor ${supervisor_id || 'none'}`)
  return c.json({ ok: true })
})
app.put('/api/users/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  const hasPerms = Array.isArray(b.permissions)
  const permsJson = hasPerms ? JSON.stringify(b.permissions) : null
  // Time-Based Access Control fields (only applied when the key is present).
  const hasAccess = ('access_days' in b) || ('access_start' in b) || ('access_end' in b)
  const accessDays = Array.isArray(b.access_days) && b.access_days.length ? JSON.stringify(b.access_days.map((n: any) => Number(n))) : null
  if (b.password) {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, region=?, custom_role=?, permissions=COALESCE(?,permissions), password=? WHERE id=?`)
      .bind(b.full_name, b.phone, b.email, b.role, b.region, b.custom_role || null, permsJson, String(b.password), id).run()
  } else {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, region=?, custom_role=?, permissions=COALESCE(?,permissions) WHERE id=?`)
      .bind(b.full_name, b.phone, b.email, b.role, b.region, b.custom_role || null, permsJson, id).run()
  }
  if (hasAccess) {
    await c.env.DB.prepare(`UPDATE users SET access_days=?, access_start=?, access_end=? WHERE id=?`)
      .bind(accessDays, b.access_start || null, b.access_end || null, id).run()
  }
  if (hasPerms) await c.env.DB.prepare(`UPDATE agents SET permissions=? WHERE user_id=?`).bind(permsJson, id).run()
  await audit(c, c.get('user').id, 'update', 'user', b.full_name)
  return c.json({ ok: true })
})
app.put('/api/users/:id/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { status } = await c.req.json()
  if (Number(id) === c.get('user').id) return c.json({ error: 'You cannot change your own status' }, 400)
  await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, id).run()
  if (status === 'suspended') await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
  await audit(c, c.get('user').id, status === 'active' ? 'activate' : 'deactivate', 'user', String(id))
  return c.json({ ok: true })
})
app.delete('/api/users/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  if (Number(id) === c.get('user').id) return c.json({ error: 'You cannot delete your own account' }, 400)
  const u = await c.env.DB.prepare(`SELECT role FROM users WHERE id=?`).bind(id).first<any>()
  if (u?.role === 'super_admin') return c.json({ error: 'Cannot delete a Super Admin account' }, 400)
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM agents WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'delete', 'user', String(id))
  return c.json({ ok: true })
})

// Repayment performance
app.get('/api/repayments', requireAuth, requireRole('admin', 'super_admin', 'support'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT r.*, mc.contract_ref, cu.full_name customer FROM repayments r
     JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id ORDER BY r.due_date`
  ).all()
  return c.json({ repayments: results })
})
// Build a complete, readable default agreement when a product has no custom
// terms, so every order always shows a proper Cash Purchase / Finance document
// (not just a QR code) when the customer comes back to view their orders.
function buildDefaultTerms(ct: any): string {
  const money = (n: number) => 'KES ' + Number(n || 0).toLocaleString('en-KE')
  if (ct.payment_type === 'cash') {
    return [
      'TERMS OF CASH PURCHASE',
      '',
      `1. Parties. This agreement is between FarmSky Ventures ("the Seller") and ${ct.customer_name || 'the Customer'} ("the Buyer").`,
      `2. Goods. The Seller sells to the Buyer: ${ct.product_name} × ${ct.quantity}.`,
      `3. Price. The total purchase price is ${money(ct.murabaha_price)}, payable in full at checkout. This price is fixed and final.`,
      '4. Sharia Compliance (Murabaha). The price is a transparent cost-plus-markup sale. No interest (riba), penalties or compounding are charged at any time.',
      '5. Payment. Payment is made via the customer\'s chosen channel (M-Pesa, SasaPay or KCB). Ownership and risk pass to the Buyer once payment is confirmed.',
      '6. Delivery. Goods are delivered to the agreed location. The Buyer must inspect goods on receipt.',
      '7. Title. The Seller warrants clear title to the goods, free of any encumbrance, at the time of sale.',
      '8. Records. The contract reference and QR code on this document serve as proof of purchase for verification.',
      '',
      `Contract Reference: ${ct.contract_ref}`
    ].join('\n')
  }
  return [
    'MURABAHA FINANCE TERMS',
    '',
    `1. Parties. This agreement is between FarmSky Ventures ("the Financier/Seller") and ${ct.customer_name || 'the Customer'} ("the Buyer").`,
    `2. Goods. The Seller purchases and sells to the Buyer on deferred terms: ${ct.product_name} × ${ct.quantity}.`,
    `3. Murabaha Sale Price. Cost ${money(ct.supplier_cost)} plus a disclosed markup of ${ct.markup_pct}%, giving a FIXED total sale price of ${money(ct.murabaha_price)}.`,
    `4. Deposit. An initial deposit of ${money(ct.deposit_required)} is payable.`,
    `5. Instalments. The balance is repaid over ${ct.term_months} month(s) at approximately ${money(ct.monthly_payment)} per month.`,
    '6. Sharia Compliance. This is a Murabaha (cost-plus) sale, NOT a loan. The total price is fixed at the outset. No interest (riba), late penalties, or compounding are ever applied — including on late payment.',
    '7. Payment Channels. Instalments may be paid via M-Pesa, SasaPay or KCB.',
    '8. Ownership. The Seller owns the goods before sale; ownership transfers to the Buyer upon execution of this Murabaha contract.',
    '9. Default. In case of difficulty, the Buyer should contact FarmSky to agree a revised schedule. No additional charges accrue on the outstanding amount.',
    '10. Records. The contract reference and QR code on this document serve as proof of the agreement for verification.',
    '',
    `Contract Reference: ${ct.contract_ref}`
  ].join('\n')
}
// Documents
app.get('/api/documents/:type/:id', requireAuth, async (c) => {
  const type = c.req.param('type'), id = c.req.param('id')
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name product_name, p.cash_terms, p.finance_terms, cu.full_name customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  // Prefer the snapshot accepted at checkout; then the product's current terms
  // for the relevant payment type; finally a generated default agreement so the
  // document is always a readable contract, never an empty page with a QR code.
  const stored = (contract.accepted_terms || (contract.payment_type === 'cash' ? contract.cash_terms : contract.finance_terms) || '').trim()
  const terms = stored || buildDefaultTerms(contract)
  const generated = !stored
  return c.json({
    type, contract, terms, generated,
    doc_kind: contract.payment_type === 'cash' ? 'cash_purchase' : 'finance',
    txn_id: contract.contract_ref,
    qr: `https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(contract.contract_ref)}`
  })
})

// ----------------------------------------------------------------------------
// ADMIN DATA EXPORT  (filter + download CSV/Excel locally, or email a copy)
// ----------------------------------------------------------------------------
// Supported datasets and their base queries. Filters are applied safely.
const EXPORT_DATASETS: Record<string, { label: string; sql: string; cols: string[]; filterable: Record<string, string> }> = {
  users: {
    label: 'Users / Accounts',
    sql: `SELECT id, full_name, phone, email, role, status, region, created_at FROM users`,
    cols: ['id', 'full_name', 'phone', 'email', 'role', 'status', 'region', 'created_at'],
    filterable: { role: 'role', status: 'status', region: 'region' }
  },
  customers: {
    label: 'Customers / Farmers',
    sql: `SELECT cu.id, cu.full_name, cu.mobile, cu.county, cu.value_chain, cu.kyc_status, cu.risk_band, cu.credit_score, u.full_name agent FROM customers cu LEFT JOIN users u ON u.id=cu.agent_id`,
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
    sql: `SELECT id, sku, name, category, buying_price, cash_price, credit_price, quantity, unit, reorder_threshold FROM products`,
    cols: ['id', 'sku', 'name', 'category', 'buying_price', 'cash_price', 'credit_price', 'quantity', 'unit', 'reorder_threshold'],
    filterable: { category: 'category' }
  },
  contracts: {
    label: 'Murabaha Contracts',
    sql: `SELECT mc.id, mc.contract_ref, cu.full_name customer, p.name product, mc.payment_type, mc.murabaha_price, mc.amount_paid, mc.outstanding, mc.status, mc.created_at FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id JOIN products p ON p.id=mc.product_id`,
    cols: ['id', 'contract_ref', 'customer', 'product', 'payment_type', 'murabaha_price', 'amount_paid', 'outstanding', 'status', 'created_at'],
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
    sql: `SELECT a.id, u.full_name actor, a.action, a.entity, a.detail, a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id`,
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
  return { label: def.label, cols: def.cols, rows: results || [] }
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

// ----------------------------------------------------------------------------
// FRONTEND SHELL
// ----------------------------------------------------------------------------
app.get('/', (c) => c.html(SHELL))

const SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky — Sharia-Compliant Agri-Finance</title>
  <link rel="icon" type="image/png" href="/static/favicon.png">
  <script src="https://cdn.tailwindcss.com"></script>
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
