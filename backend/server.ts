import 'dotenv/config'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Hono } from 'hono'
import app from './index'
import { openDatabase } from './db-postgres'
import { initializeDatabase } from './db-init'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = join(__dirname, '..')

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:5432/farmsky'
const migrateOnly = process.argv.includes('--migrate-only')

// Open a pool immediately (cheap, lazy connections) so `d1` can be wired into ENV
// before the (potentially slow) migration/seed pass runs. On Render cold starts the
// migration pass can take several seconds; we must NOT let it block the HTTP port
// from binding, otherwise inbound webhooks (e.g. SasaPay callbacks) hit a refused /
// timed-out connection => "Max retries exceeded" and the settlement is lost.
const { d1, raw } = await openDatabase(DATABASE_URL)

// Tracks whether migrations/seed have finished. Requests that need the DB before
// this flips true get a fast 503 (retryable) instead of hanging the connection.
let dbReady = false
let dbInitError: string | null = null

if (migrateOnly) {
  // In migrate-only mode we DO want to block and exit after migrating.
  await initializeDatabase(raw, PROJECT_ROOT)
  console.log(`PostgreSQL ready: ${DATABASE_URL.replace(/:[^:@/]+@/, ':***@')}`)
  await raw.end()
  process.exit(0)
}

const ENV = {
  DB: d1,
  MPESA_CONSUMER_KEY: process.env.MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET: process.env.MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE: process.env.MPESA_SHORTCODE,
  MPESA_PASSKEY: process.env.MPESA_PASSKEY,
  MPESA_ENV: process.env.MPESA_ENV,
  MPESA_CALLBACK_URL: process.env.MPESA_CALLBACK_URL,
  // SasaPay - accept either CLIENT_* or CONSUMER_* naming (auto-alias)
  SASAPAY_CLIENT_ID:     process.env.SASAPAY_CLIENT_ID     || process.env.SASAPAY_CONSUMER_KEY,
  SASAPAY_CLIENT_SECRET: process.env.SASAPAY_CLIENT_SECRET || process.env.SASAPAY_CONSUMER_SECRET,
  SASAPAY_CONSUMER_KEY:    process.env.SASAPAY_CONSUMER_KEY    || process.env.SASAPAY_CLIENT_ID,
  SASAPAY_CONSUMER_SECRET: process.env.SASAPAY_CONSUMER_SECRET || process.env.SASAPAY_CLIENT_SECRET,
  SASAPAY_MERCHANT_CODE: process.env.SASAPAY_MERCHANT_CODE,
  SASAPAY_ENV: process.env.SASAPAY_ENV,
  SASAPAY_CALLBACK_URL: process.env.SASAPAY_CALLBACK_URL,
  SASAPAY_B2C_CALLBACK_URL: process.env.SASAPAY_B2C_CALLBACK_URL || process.env.SASAPAY_CALLBACK_URL,
  BUNI_CLIENT_ID: process.env.BUNI_CLIENT_ID,
  BUNI_CLIENT_SECRET: process.env.BUNI_CLIENT_SECRET,
  BUNI_API_KEY: process.env.BUNI_API_KEY,
  BUNI_TILL_NUMBER: process.env.BUNI_TILL_NUMBER,
  BUNI_ENV: process.env.BUNI_ENV,
  BUNI_CALLBACK_URL: process.env.BUNI_CALLBACK_URL,
  SMS_PROVIDER: process.env.SMS_PROVIDER,
  SMS_API_URL: process.env.SMS_API_URL,
  SMS_API_TOKEN: process.env.SMS_API_TOKEN,
  SMS_SENDER_ID: process.env.SMS_SENDER_ID,
  SMS_BODY_TEMPLATE: process.env.SMS_BODY_TEMPLATE,
  SMS_PHONE_FIELD: process.env.SMS_PHONE_FIELD,
  SMS_MESSAGE_FIELD: process.env.SMS_MESSAGE_FIELD,
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  EMAIL_API_URL: process.env.EMAIL_API_URL,
  EMAIL_API_TOKEN: process.env.EMAIL_API_TOKEN,
  EMAIL_FROM: process.env.EMAIL_FROM,
  TRANSUNION_API_URL: process.env.TRANSUNION_API_URL,
  TRANSUNION_API_KEY: process.env.TRANSUNION_API_KEY,
  TRANSUNION_CLIENT_ID: process.env.TRANSUNION_CLIENT_ID,
  TRANSUNION_ENV: process.env.TRANSUNION_ENV,
  // Central Payment Gateway client (equipment.farmsky.africa) — env only.
  // Accept BOTH naming conventions so the app works regardless of which
  // variable names were entered in the Render dashboard:
  //   - FARMSKY_PAYMENTS_GATEWAY_URL / _CLIENT_KEY / _HMAC_SECRET  (canonical)
  //   - PAYMENT_GATEWAY_URL / PAYMENT_CLIENT_KEY                    (short aliases)
  FARMSKY_PAYMENTS_GATEWAY_URL: process.env.FARMSKY_PAYMENTS_GATEWAY_URL || process.env.PAYMENT_GATEWAY_URL,
  FARMSKY_PAYMENTS_CLIENT_KEY: process.env.FARMSKY_PAYMENTS_CLIENT_KEY || process.env.PAYMENT_CLIENT_KEY,
  FARMSKY_PAYMENTS_HMAC_SECRET: process.env.FARMSKY_PAYMENTS_HMAC_SECRET || process.env.PAYMENT_HMAC_SECRET,
  // Session signing secret
  SESSION_SECRET: process.env.SESSION_SECRET
}

const root = new Hono()

// ---------------------------------------------------------------------------
// Ultra-lightweight liveness endpoints. These are dependency-free and are
// declared BEFORE the static/catch-all handlers so they respond the instant the
// process is listening — even while migrations are still running. Point a free
// uptime pinger (UptimeRobot / cron-job.org, every 5-10 min) at /health to keep
// the Render service warm so SasaPay callbacks never hit a cold-start timeout.
// ---------------------------------------------------------------------------
root.get('/health', (c) => c.json({ ok: true, dbReady, ts: Date.now() }))
root.get('/healthz', (c) => c.text(dbReady ? 'ok' : 'starting', dbReady ? 200 : 200))
root.get('/api/ping', (c) => c.json({ ok: true, service: 'farmsky', dbReady, ts: Date.now() }))

root.use('/static/*', serveStatic({ root: './frontend' }))

// A Node-side executionCtx shim so `c.executionCtx.waitUntil(promise)` inside the
// app (used by runInBackground for webhook settlement) keeps the promise alive on
// the event loop instead of silently falling through. This makes background
// settlement after the instant callback ACK reliable on the Node runtime.
const nodeExecutionCtx = {
  waitUntil: (p: Promise<any>) => { Promise.resolve(p).catch(() => {}) },
  passThroughOnException: () => {}
}

// Payment webhook paths must ALWAYS be allowed through so they can ACK instantly,
// even during the brief startup window — SasaPay's connect timeout is short (~8s)
// and a lost/timed-out callback drops the settlement. The in-app handlers ACK
// immediately and settle in the background (runInBackground), so it is safe to
// admit them here; if the DB isn't ready yet the background task will surface via
// the admin recovery/pending tooling.
const ALWAYS_ADMIT = /^\/api\/(sasapay|mpesa|buni)\/(callback|ipn|confirm|result|timeout|b2c)/i

root.all('*', (c) => {
  const path = new URL(c.req.url).pathname
  // If a DB-dependent request arrives before migrations finish, fail fast with a
  // retryable 503 rather than hanging the socket. Webhook senders will see a clean
  // HTTP response instead of a connection timeout, and can retry.
  if (!dbReady && !ALWAYS_ADMIT.test(path)) {
    return c.json(
      { error: 'service_starting', message: 'Server is starting, please retry shortly.', dbReady: false, dbInitError },
      503,
      { 'Retry-After': '3' }
    )
  }
  return app.fetch(c.req.raw, ENV as any, nodeExecutionCtx as any)
})

const PORT = Number(process.env.PORT || 8080)
serve({ fetch: root.fetch, port: PORT }, (info) => {
  console.log(`Farmsky server running on http://0.0.0.0:${info.port} (binding port first; DB migrating in background)`)

  // Kick off migrations/seed AFTER the port is bound. This guarantees the socket
  // accepts connections immediately on cold start, eliminating the connection-level
  // timeout that caused SasaPay "Max retries exceeded" callback failures.
  initializeDatabase(raw, PROJECT_ROOT)
    .then(() => {
      dbReady = true
      console.log(`PostgreSQL ready: ${DATABASE_URL.replace(/:[^:@/]+@/, ':***@')}`)
    })
    .catch((err: any) => {
      dbInitError = err?.message || String(err)
      console.error('Database initialization failed:', dbInitError)
    })
  
  // Both gateways default to PRODUCTION unless *_ENV is explicitly a sandbox value.
  const sandboxValues = ['sandbox', 'development', 'dev', 'test', 'uat']
  const modeOf = (v?: string) => sandboxValues.includes(String(v || '').trim().toLowerCase()) ? 'sandbox' : 'production'

  // Status check for M-Pesa
  console.log(
    process.env.MPESA_CONSUMER_KEY
      ? 'M-Pesa: LIVE credentials detected (' + modeOf(process.env.MPESA_ENV) + ')'
      : 'M-Pesa: SIMULATION mode (no Daraja credentials set).'
  )

  // Status check for SasaPay
  const sasapayId = process.env.SASAPAY_CLIENT_ID || process.env.SASAPAY_CONSUMER_KEY
  const sasapaySecret = process.env.SASAPAY_CLIENT_SECRET || process.env.SASAPAY_CONSUMER_SECRET
  const sasapayMerchant = process.env.SASAPAY_MERCHANT_CODE
  console.log(
    (sasapayId && sasapaySecret && sasapayMerchant)
      ? 'SasaPay: LIVE credentials detected (' + modeOf(process.env.SASAPAY_ENV) + ')'
      : `SasaPay: SIMULATION mode (missing ${[!sasapayId && 'CLIENT_ID', !sasapaySecret && 'CLIENT_SECRET', !sasapayMerchant && 'MERCHANT_CODE'].filter(Boolean).join(', ') || 'credentials'}).`
  )
})
