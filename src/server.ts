// =====================================================================
// Node.js server entry point (for AWS EC2 / App Runner / any VPS).
// ---------------------------------------------------------------------
// Runs the SAME Hono app (src/index.tsx) outside Cloudflare by:
//   1. Loading environment variables (.env)
//   2. Opening a PostgreSQL connection pool via the D1-compatible adapter
//   3. Auto-applying migrations + seed on first boot
//   4. Injecting DB + M-Pesa config into every request's `c.env`
//   5. Serving /static/* files and starting an HTTP listener
// =====================================================================

import 'dotenv/config'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Hono } from 'hono'
import app from './index'
import { openPostgres } from './db-postgres'
import { initializePostgres } from './db-init-pg'

// ----- Resolve project root (works whether run from src/ or dist/) -----
const __dirname = dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = join(__dirname, '..')

// ----- Build the PostgreSQL connection string -----
// Priority: DATABASE_URL (full conn string) > discrete PG* env vars > local default.
function resolveConnectionString(): string {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL
  const host = process.env.PGHOST || '127.0.0.1'
  const port = process.env.PGPORT || '5432'
  const user = process.env.PGUSER || 'farmsky'
  const pass = process.env.PGPASSWORD || 'farmsky'
  const db = process.env.PGDATABASE || 'farmsky'
  return `postgresql://${user}:${pass}@${host}:${port}/${db}`
}

async function main() {
  const connectionString = resolveConnectionString()
  const { d1, pool } = openPostgres(connectionString)

  // Apply migrations + seed (idempotent).
  await initializePostgres(pool, PROJECT_ROOT)
  const safeUrl = connectionString.replace(/:\/\/([^:]+):[^@]*@/, '://$1:****@')
  console.log(`Database ready (PostgreSQL): ${safeUrl}`)

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

  // ----- Serve static assets from /public (outer Hono instance) -----
  const root = new Hono()
  root.use('/static/*', serveStatic({ root: './public' }))
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
}

main().catch((err) => {
  console.error('Fatal startup error:', err)
  process.exit(1)
})
