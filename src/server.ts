// =====================================================================
// Node.js server entry point (for AWS EC2 / App Runner / any VPS).
// ---------------------------------------------------------------------
// Runs the SAME Hono app (src/index.tsx) outside Cloudflare by:
//   1. Loading environment variables (.env)
//   2. Opening a local SQLite database via the D1-compatible adapter
//   3. Auto-applying migrations + seed on first boot
//   4. Injecting DB + M-Pesa config into every request's `c.env`
//   5. Serving /static/* files and starting an HTTP listener
// =====================================================================

import 'dotenv/config'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import app from './index'
import { openDatabase } from './db-sqlite'
import { initializeDatabase, ensureDir } from './db-init'

// ----- Resolve project root (works whether run from src/ or dist/) -----
const __dirname = dirname(fileURLToPath(import.meta.url))
// dist/server.js -> project root is one level up; src/server.ts -> one level up
const PROJECT_ROOT = join(__dirname, '..')

// ----- Open + initialize the database -----
const DB_FILE = process.env.DATABASE_PATH || join(PROJECT_ROOT, 'data', 'farmsky.db')
ensureDir(DB_FILE)
const { d1, raw } = openDatabase(DB_FILE)
initializeDatabase(raw, PROJECT_ROOT)
console.log(`Database ready at: ${DB_FILE}`)

// ----- Build the env object injected into c.env on every request -----
const ENV = {
  DB: d1,
  MPESA_CONSUMER_KEY: process.env.MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET: process.env.MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE: process.env.MPESA_SHORTCODE,
  MPESA_PASSKEY: process.env.MPESA_PASSKEY,
  MPESA_ENV: process.env.MPESA_ENV,
  MPESA_CALLBACK_URL: process.env.MPESA_CALLBACK_URL,
  // SMS OTP provider (TalkSASA by default)
  SMS_PROVIDER: process.env.SMS_PROVIDER,
  SMS_API_URL: process.env.SMS_API_URL,
  SMS_API_TOKEN: process.env.SMS_API_TOKEN,
  SMS_SENDER_ID: process.env.SMS_SENDER_ID,
  SMS_BODY_TEMPLATE: process.env.SMS_BODY_TEMPLATE,
  SMS_PHONE_FIELD: process.env.SMS_PHONE_FIELD,
  SMS_MESSAGE_FIELD: process.env.SMS_MESSAGE_FIELD,
  // Email provider (export sharing) — Resend by default
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  EMAIL_API_URL: process.env.EMAIL_API_URL,
  EMAIL_API_TOKEN: process.env.EMAIL_API_TOKEN,
  EMAIL_FROM: process.env.EMAIL_FROM
}

// ----- Serve static assets from /public (separate Hono instance) -----
// We mount the main app behind a tiny outer app so we can both serve
// static files and inject `c.env` (the Cloudflare-style bindings) before
// the main app's routes run.
import { Hono } from 'hono'
const root = new Hono()
root.use('/static/*', serveStatic({ root: './public' }))
// Pass everything else to the main app, supplying the bindings as env.
root.all('*', (c) => app.fetch(c.req.raw, ENV as any))

// ----- Start the server -----
const PORT = Number(process.env.PORT || 8080)
serve({ fetch: root.fetch, port: PORT }, (info) => {
  console.log(`Farmsky server running on http://0.0.0.0:${info.port}`)
  console.log(
    process.env.MPESA_CONSUMER_KEY
      ? 'M-Pesa: LIVE credentials detected (Daraja ' + (process.env.MPESA_ENV || 'sandbox') + ')'
      : 'M-Pesa: SIMULATION mode (no Daraja credentials set). See .env.example.'
  )
})
