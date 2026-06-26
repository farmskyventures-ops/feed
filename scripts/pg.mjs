#!/usr/bin/env node
// =====================================================================
// PostgreSQL CLI helper: migrate | seed | reset
//   node scripts/pg.mjs migrate   -> apply migrations-pg/*.sql in order
//   node scripts/pg.mjs seed      -> load seed-pg.sql
//   node scripts/pg.mjs reset     -> DROP all tables, migrate, seed
// Connection comes from DATABASE_URL or PG* env vars (see .env.example).
// =====================================================================
import 'dotenv/config'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import pg from 'pg'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

function connString() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL
  const host = process.env.PGHOST || '127.0.0.1'
  const port = process.env.PGPORT || '5432'
  const user = process.env.PGUSER || 'farmsky'
  const pass = process.env.PGPASSWORD || 'farmsky'
  const db = process.env.PGDATABASE || 'farmsky'
  return `postgresql://${user}:${pass}@${host}:${port}/${db}`
}

async function migrate(pool) {
  const dir = join(ROOT, 'migrations-pg')
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()
  for (const f of files) {
    try {
      await pool.query(readFileSync(join(dir, f), 'utf8'))
      console.log('applied', f)
    } catch (e) {
      if (!/already exists|duplicate column/i.test(e.message)) throw e
      console.log('skip (exists)', f)
    }
  }
}

async function seed(pool) {
  const file = join(ROOT, 'seed-pg.sql')
  if (!existsSync(file)) return console.log('no seed-pg.sql')
  await pool.query(readFileSync(file, 'utf8'))
  console.log('seed loaded')
}

async function reset(pool) {
  await pool.query(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
  console.log('schema dropped & recreated')
  await migrate(pool)
  await seed(pool)
}

const cmd = process.argv[2] || 'migrate'
const pool = new pg.Pool({ connectionString: connString() })
try {
  if (cmd === 'migrate') await migrate(pool)
  else if (cmd === 'seed') await seed(pool)
  else if (cmd === 'reset') await reset(pool)
  else { console.error('Unknown command:', cmd); process.exit(1) }
} catch (e) {
  console.error('Error:', e.message)
  process.exit(1)
} finally {
  await pool.end()
}
