// =====================================================================
// Farmsky Public Merchant API  (Phase 3)
// ---------------------------------------------------------------------
// A unified, versioned public surface that third-party merchants use to
//   (a) manage catalog inventory   -> /v1/merchant/inventory
//   (b) start a hosted checkout     -> /v1/checkout/equipment | /v1/checkout/feeds
//
// Every request is authenticated with a merchant key + HMAC-SHA256
// signature (Phase 6 zero-trust). The same signing scheme as the internal
// payment gateway is reused (payment-gateway-shared.ts), so merchants sign:
//     canonical = merchant_key\ntimestamp\nnonce\nrawBody
// and send headers:
//     X-Merchant-Key, X-Merchant-Timestamp, X-Merchant-Nonce, X-Merchant-Signature
//
// This router is mounted by BOTH apps but is app-aware via APP_TYPE:
//   - Equipment (APP_TYPE=equipment) owns real payment settlement, so its
//     checkout endpoints create the central transaction directly.
//   - Feed (APP_TYPE=feed) forwards checkout to Equipment's central gateway
//     over an HMAC server-to-server call.
// =====================================================================

import { Hono } from 'hono'
import { verifySignature } from './payment-gateway-shared'
import type { Bindings } from './types'

const merchant = new Hono<{ Bindings: Bindings }>()

// In-memory nonce cache for replay protection (per-process). A persisted
// merchant_nonces table also guards across restarts (see verifyMerchant).
const seenNonces = new Map<string, number>()
function rememberNonce(nonce: string) {
  const now = Date.now()
  seenNonces.set(nonce, now)
  // prune > 10 min old
  for (const [k, t] of seenNonces) if (now - t > 10 * 60 * 1000) seenNonces.delete(k)
}

function appType(c: any): 'equipment' | 'feed' {
  const t = String(c.env?.APP_TYPE || 'equipment').toLowerCase()
  return t === 'feed' ? 'feed' : 'equipment'
}

function inventoryTypeForApp(c: any): 'equipment' | 'feed' {
  return appType(c)
}

// ---- Merchant authentication (key + HMAC + replay guard) --------------
async function loadMerchant(c: any, key: string) {
  return await c.env.DB.prepare(
    `SELECT * FROM merchant_keys WHERE merchant_key = ? AND is_active = 1 LIMIT 1`
  ).bind(key).first<any>()
}

async function verifyMerchant(c: any): Promise<{ ok: boolean; status?: number; error?: string; merchant?: any; rawBody?: string }> {
  const key = c.req.header('X-Merchant-Key') || ''
  const timestamp = c.req.header('X-Merchant-Timestamp') || ''
  const nonce = c.req.header('X-Merchant-Nonce') || ''
  const signature = c.req.header('X-Merchant-Signature') || ''
  if (!key) return { ok: false, status: 401, error: 'Missing X-Merchant-Key header' }
  if (!signature || !timestamp || !nonce) return { ok: false, status: 401, error: 'Missing signature material' }
  if (seenNonces.has(nonce)) return { ok: false, status: 401, error: 'Replay detected (nonce reused)' }

  const merchant = await loadMerchant(c, key)
  if (!merchant) return { ok: false, status: 401, error: 'Unknown or inactive merchant key' }

  const rawBody = await c.req.text()
  const v = await verifySignature(merchant.merchant_secret, key, timestamp, nonce, rawBody, signature)
  if (!v.ok) return { ok: false, status: 401, error: v.error || 'Signature verification failed' }
  rememberNonce(nonce)
  return { ok: true, merchant, rawBody }
}

function parseBody(rawBody: string): any {
  try { return rawBody ? JSON.parse(rawBody) : {} } catch { return {} }
}

// Scope guard: a merchant scoped to 'equipment' cannot touch 'feed' catalog.
function scopeAllows(merchant: any, invType: string): boolean {
  const s = String(merchant.app_scope || 'both')
  return s === 'both' || s === invType
}

// =====================================================================
// INVENTORY CRUD  —  /v1/merchant/inventory
// Operates on the shared `products` table, tagged with app_scope so the
// item shows in the correct storefront(s).
// =====================================================================

// POST /v1/merchant/inventory  — create an item
merchant.post('/v1/merchant/inventory', async (c) => {
  const auth = await verifyMerchant(c)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, (auth.status as any) || 401)
  const b = parseBody(auth.rawBody!)
  const invType = inventoryTypeForApp(c)
  if (!scopeAllows(auth.merchant, invType)) return c.json({ success: false, error: 'Merchant not permitted for this catalog' }, 403)

  const name = String(b.title || b.name || '').trim()
  const price = Number(b.amount ?? b.price ?? b.cash_price)
  if (!name || !Number.isFinite(price) || price <= 0) {
    return c.json({ success: false, error: 'title and a positive amount are required' }, 400)
  }
  const sku = String(b.sku || `MK-${Date.now()}-${Math.floor(Math.random() * 1e4)}`)
  const category = String(b.category || 'general')
  const qty = Number.isFinite(Number(b.quantity)) ? Number(b.quantity) : 0
  const markup = Number.isFinite(Number(b.credit_markup_pct)) ? Number(b.credit_markup_pct) : 20
  const creditPrice = price * (1 + markup / 100)

  const res = await c.env.DB.prepare(
    `INSERT INTO products (sku, name, category, buying_price, cash_markup_pct, credit_markup_pct,
       cash_price, credit_price, quantity, unit, image, app_scope)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(sku, name, category, price, 10, markup, price, creditPrice, qty,
         String(b.unit || 'unit'), String(b.image || ''), invType).run()

  return c.json({ success: true, item_id: res.meta?.last_row_id, sku, inventory_type: invType }, 201)
})

// PUT /v1/merchant/inventory/:item_id  — update an item
merchant.put('/v1/merchant/inventory/:item_id', async (c) => {
  const auth = await verifyMerchant(c)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, (auth.status as any) || 401)
  const b = parseBody(auth.rawBody!)
  const id = c.req.param('item_id')
  const invType = inventoryTypeForApp(c)

  const existing = await c.env.DB.prepare(`SELECT * FROM products WHERE id = ?`).bind(id).first<any>()
  if (!existing) return c.json({ success: false, error: 'Item not found' }, 404)
  if (!scopeAllows(auth.merchant, invType) || (existing.app_scope !== 'both' && existing.app_scope !== invType)) {
    return c.json({ success: false, error: 'Merchant not permitted for this item' }, 403)
  }

  const name = b.title ?? b.name ?? existing.name
  const price = Number(b.amount ?? b.price ?? b.cash_price ?? existing.cash_price)
  const category = b.category ?? existing.category
  const qty = (b.quantity != null) ? Number(b.quantity) : existing.quantity
  const markup = (b.credit_markup_pct != null) ? Number(b.credit_markup_pct) : existing.credit_markup_pct
  const creditPrice = price * (1 + Number(markup) / 100)

  await c.env.DB.prepare(
    `UPDATE products SET name=?, category=?, cash_price=?, credit_price=?, quantity=?, credit_markup_pct=?, image=? WHERE id=?`
  ).bind(name, category, price, creditPrice, qty, markup, b.image ?? existing.image, id).run()

  return c.json({ success: true, item_id: Number(id) })
})

// GET /v1/merchant/inventory  — list items (scoped)
merchant.get('/v1/merchant/inventory', async (c) => {
  const auth = await verifyMerchant(c)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, (auth.status as any) || 401)
  const invType = inventoryTypeForApp(c)
  const rows = await c.env.DB.prepare(
    `SELECT id, sku, name, category, cash_price, credit_price, quantity, unit, image, app_scope
       FROM products WHERE app_scope IN (?, 'both') ORDER BY id DESC LIMIT 500`
  ).bind(invType).all<any>()
  return c.json({ success: true, inventory_type: invType, items: rows.results || [] })
})

// DELETE /v1/merchant/inventory/:item_id  — remove an item
merchant.delete('/v1/merchant/inventory/:item_id', async (c) => {
  const auth = await verifyMerchant(c)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, (auth.status as any) || 401)
  const id = c.req.param('item_id')
  const invType = inventoryTypeForApp(c)
  const existing = await c.env.DB.prepare(`SELECT app_scope FROM products WHERE id = ?`).bind(id).first<any>()
  if (!existing) return c.json({ success: false, error: 'Item not found' }, 404)
  if (!scopeAllows(auth.merchant, invType) || (existing.app_scope !== 'both' && existing.app_scope !== invType)) {
    return c.json({ success: false, error: 'Merchant not permitted for this item' }, 403)
  }
  await c.env.DB.prepare(`DELETE FROM products WHERE id = ?`).bind(id).run()
  return c.json({ success: true, item_id: Number(id) })
})

// =====================================================================
// CHECKOUT  —  /v1/checkout/equipment  &  /v1/checkout/feeds
// Creates a merchant_checkouts session and returns a Farmsky hosted
// checkout URL the merchant redirects the buyer to.
// =====================================================================

function validateCheckout(b: any): string | null {
  if (!b.customer || typeof b.customer !== 'object') return 'customer object required'
  if (!String(b.customer.full_name || '').trim()) return 'customer.full_name required'
  if (!String(b.customer.phone || '').trim()) return 'customer.phone required'
  if (!String(b.customer.national_id || '').trim()) return 'customer.national_id required'
  if (!b.item || typeof b.item !== 'object') return 'item object required'
  if (!String(b.item.id || '').trim()) return 'item.id required'
  if (!String(b.item.title || '').trim()) return 'item.title required'
  if (!Number.isFinite(Number(b.item.amount)) || Number(b.item.amount) <= 0) return 'item.amount must be positive'
  const tt = String(b.transaction_type || '')
  if (!['DIRECT_PURCHASE', 'FINANCING_REQUEST'].includes(tt)) return "transaction_type must be DIRECT_PURCHASE or FINANCING_REQUEST"
  if (tt === 'FINANCING_REQUEST' && !(Number(b.financing_tenor_months) > 0)) return 'financing_tenor_months required for FINANCING_REQUEST'
  return null
}

async function createCheckout(c: any, invType: 'equipment' | 'feed') {
  const auth = await verifyMerchant(c)
  if (!auth.ok) return c.json({ success: false, error: auth.error }, (auth.status as any) || 401)
  // Data isolation: each app only hosts checkouts for its OWN inventory type.
  // A cross-catalog checkout must be sent to the sibling app's endpoint.
  if (invType !== appType(c)) {
    return c.json({ success: false, error: `This platform (${appType(c)}) does not host ${invType} checkouts. Use the ${invType} app.` }, 409)
  }
  if (!scopeAllows(auth.merchant, invType)) return c.json({ success: false, error: 'Merchant not permitted for this catalog' }, 403)
  const b = parseBody(auth.rawBody!)
  const err = validateCheckout(b)
  if (err) return c.json({ success: false, error: err }, 400)

  const checkoutRef = `chk_${invType}_${Date.now()}_${Math.floor(Math.random() * 1e6)}`
  const originPlatform = invType === 'equipment' ? 'equipment_app' : 'feed_app'

  await c.env.DB.prepare(
    `INSERT INTO merchant_checkouts
       (checkout_ref, merchant_key, inventory_type, transaction_type, item_id, item_title, amount,
        category, financing_tenor_months, customer_full_name, customer_phone, customer_national_id,
        success_callback_url, failure_callback_url, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CREATED')`
  ).bind(
    checkoutRef, auth.merchant.merchant_key, invType, b.transaction_type,
    String(b.item.id), String(b.item.title), Number(b.item.amount), String(b.item.category || 'general'),
    Number(b.financing_tenor_months || 0), String(b.customer.full_name), String(b.customer.phone),
    String(b.customer.national_id), String(b.success_callback_url || ''), String(b.failure_callback_url || '')
  ).run()

  // Hosted checkout URL the merchant redirects the buyer to.
  const base = String(c.env?.PUBLIC_BASE_URL || new URL(c.req.url).origin).replace(/\/+$/, '')
  const hostedUrl = `${base}/checkout/${checkoutRef}`

  return c.json({
    success: true,
    checkout_ref: checkoutRef,
    inventory_type: invType,
    origin_platform: originPlatform,
    transaction_type: b.transaction_type,
    amount: Number(b.item.amount),
    hosted_checkout_url: hostedUrl
  }, 201)
}

merchant.post('/v1/checkout/equipment', (c) => createCheckout(c, 'equipment'))
merchant.post('/v1/checkout/feeds', (c) => createCheckout(c, 'feed'))

// Public (no-HMAC) read of a checkout session, used by the hosted checkout page.
merchant.get('/v1/checkout/session/:ref', async (c) => {
  const ref = c.req.param('ref')
  const row = await c.env.DB.prepare(
    `SELECT checkout_ref, inventory_type, transaction_type, item_title, amount, category,
            financing_tenor_months, customer_full_name, status FROM merchant_checkouts WHERE checkout_ref = ?`
  ).bind(ref).first<any>()
  if (!row) return c.json({ success: false, error: 'Checkout not found' }, 404)
  return c.json({ success: true, checkout: row })
})

export default merchant
