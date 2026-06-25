// =====================================================================
// Database bootstrap for the Node server.
// On first start (empty DB) it applies all SQL migrations in order and
// loads the demo seed. Safe to run repeatedly: migrations use
// "IF NOT EXISTS" and the seed uses "INSERT OR IGNORE".
// =====================================================================

import { readFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type Database from 'better-sqlite3'

function applySqlFile(raw: Database.Database, file: string) {
  const sql = readFileSync(file, 'utf8')
  // better-sqlite3 .exec() runs multiple statements separated by ';'
  raw.exec(sql)
}

export function initializeDatabase(raw: Database.Database, projectRoot: string) {
  // Has the schema already been created?
  const hasUsers = raw
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    .get()

  const migrationsDir = join(projectRoot, 'migrations')
  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort()
    for (const f of files) {
      try {
        applySqlFile(raw, join(migrationsDir, f))
      } catch (e: any) {
        // Ignore "duplicate column"/"already exists" on re-run
        if (!/already exists|duplicate column/i.test(String(e.message))) {
          console.error(`Migration ${f} error:`, e.message)
        }
      }
    }
  }

  // Seed only on a fresh database (no users yet)
  if (!hasUsers) {
    const seedFile = join(projectRoot, 'seed.sql')
    if (existsSync(seedFile)) {
      try {
        applySqlFile(raw, seedFile)
        console.log('Seed data loaded.')
      } catch (e: any) {
        console.error('Seed error:', e.message)
      }
    }
  }
}

export function ensureDir(filePath: string) {
  const dir = dirname(filePath)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}
