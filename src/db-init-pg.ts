// =====================================================================
// PostgreSQL database bootstrap for the Node server.
// On start it applies all SQL migrations in migrations-pg/ (in order),
// then loads the demo seed if the database is empty.
// Safe to run repeatedly: DDL uses IF NOT EXISTS / ADD COLUMN IF NOT
// EXISTS, and the seed uses ON CONFLICT DO NOTHING.
// =====================================================================

import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type pg from 'pg'

async function applySqlFile(pool: pg.Pool, file: string) {
  const sql = readFileSync(file, 'utf8')
  // node-postgres can execute a multi-statement string in a single query.
  await pool.query(sql)
}

export async function initializePostgres(pool: pg.Pool, projectRoot: string) {
  // Has the schema already been created (does the users table exist)?
  let hasUsers = false
  try {
    const res = await pool.query(
      `SELECT to_regclass('public.users') AS t`
    )
    hasUsers = !!res.rows[0]?.t
  } catch {
    hasUsers = false
  }

  // Prefer Postgres-specific migrations; fall back to ./migrations if absent.
  let migrationsDir = join(projectRoot, 'migrations-pg')
  if (!existsSync(migrationsDir)) migrationsDir = join(projectRoot, 'migrations')

  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort()
    for (const f of files) {
      try {
        await applySqlFile(pool, join(migrationsDir, f))
      } catch (e: any) {
        // Ignore idempotent re-run noise.
        if (!/already exists|duplicate column|duplicate_object/i.test(String(e.message))) {
          console.error(`Migration ${f} error:`, e.message)
        }
      }
    }
  }

  // Seed only on a fresh database (no users yet).
  if (!hasUsers) {
    let seedFile = join(projectRoot, 'seed-pg.sql')
    if (!existsSync(seedFile)) seedFile = join(projectRoot, 'seed.sql')
    if (existsSync(seedFile)) {
      try {
        await applySqlFile(pool, seedFile)
        console.log('Seed data loaded.')
      } catch (e: any) {
        console.error('Seed error:', e.message)
      }
    }
  }
}
