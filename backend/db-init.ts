import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Pool } from 'pg'

const SERIAL_TABLES = [
  'users', 'agents', 'customers', 'suppliers', 'products', 'stock_movements',
  'murabaha_contracts', 'repayments', 'invoices', 'transactions', 'approvals',
  'transunion_checks', 'id_verifications', 'audit_logs', 'tickets', 'otp_codes',
  'payment_intents', 'change_requests', 'permission_catalog', 'role_templates'
]

function splitStatements(sql: string): string[] {
  const stripped = sql.replace(/^\s*--.*$/gm, '')
  return stripped
    .split(/;\s*(?:\n|$)/g)
    .map((statement) => statement.trim())
    .filter(Boolean)
}

function transformStatement(originalStatement: string): { sql: string; conflict: boolean } {
  let sql = originalStatement.trim()
  let conflict = false
  if (/^insert\s+or\s+ignore\s+into/i.test(sql)) {
    conflict = true
    sql = sql.replace(/^insert\s+or\s+ignore\s+into/i, 'INSERT INTO')
  }
  sql = sql.replace(/\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b/gi, 'BIGSERIAL PRIMARY KEY')
  sql = sql.replace(/\bAUTOINCREMENT\b/gi, '')
  sql = sql.replace(/\bDATETIME\b/gi, 'TIMESTAMP')
  sql = sql.replace(/\bREAL\b/gi, 'DOUBLE PRECISION')
  // Trim trailing commas accidentally left by transformations
  sql = sql.replace(/,\s*\)/g, '\n)')
  return { sql, conflict }
}

async function execStatement(pool: Pool, statement: string, allowConflict: boolean) {
  try {
    let sql = statement
    if (allowConflict && /^insert\s+into/i.test(sql) && !/on\s+conflict/i.test(sql)) {
      sql += ' ON CONFLICT DO NOTHING'
    }
    await pool.query(sql)
  } catch (error: any) {
    const code = error?.code || ''
    const message = String(error?.message || '')
    // Idempotency guards so re-running migrations on an existing DB is safe:
    // 42701 duplicate column, 42P07 duplicate table/index, 23505 unique violation
    // (handled by ON CONFLICT), 42809 wrong object type for DROP VIEW/TABLE on
    // an object of a different kind, 42P06 duplicate schema.
    if (['42701', '42P07', '23505', '42809', '42P06'].includes(code)) return
    if (/already exists|duplicate column|is not a|wrong (object )?type/i.test(message)) return
    throw error
  }
}

async function applySqlFile(pool: Pool, file: string) {
  const rawSql = readFileSync(file, 'utf8')
  for (const statement of splitStatements(rawSql)) {
    const { sql, conflict } = transformStatement(statement)
    await execStatement(pool, sql, conflict)
  }
}

async function tableExists(pool: Pool, tableName: string): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1
    ) AS present`,
    [tableName]
  )
  return Boolean(rows[0]?.present)
}

async function syncSequences(pool: Pool) {
  // Sequence sync must see EVERY row to compute the true MAX(id). Because the app
  // connects as a non-superuser with FORCE ROW LEVEL SECURITY, a plain
  // `SELECT MAX(id)` runs with no session context and RLS returns ZERO rows —
  // yielding MAX=NULL, resetting the sequence to 1, and causing duplicate-key
  // errors on the next insert. We therefore run each sync inside a dedicated
  // connection with admin session context so RLS is satisfied and all rows are
  // visible. (Admin context here is server-internal, never client-controlled.)
  for (const table of SERIAL_TABLES) {
    const client = await pool.connect()
    try {
      await client.query(`SELECT set_config('app.current_role', 'admin', false)`)
      await client.query(`SELECT set_config('app.user_can_finance', 'true', false)`)
      await client.query(
        `SELECT setval(pg_get_serial_sequence($1, 'id'), GREATEST(COALESCE((SELECT MAX(id) FROM ${table}), 1), 1), true)`,
        [table]
      )
    } catch (_) {
      /* table may not exist yet or have no id column — ignore */
    } finally {
      try { await client.query(`SELECT set_config('app.current_role', '', false)`) } catch (_) {}
      client.release()
    }
  }
}

export async function initializeDatabase(pool: Pool, projectRoot: string) {
  const hasUsers = await tableExists(pool, 'users')
  const migrationsDir = join(projectRoot, 'migrations')
  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir).filter((file) => file.endsWith('.sql')).sort()
    for (const file of files) {
      try {
        await applySqlFile(pool, join(migrationsDir, file))
      } catch (error: any) {
        console.error(`Migration ${file} error:`, error.message)
        throw error
      }
    }
  }
  if (!hasUsers) {
    const seedFile = join(projectRoot, 'seed.sql')
    if (existsSync(seedFile)) {
      await applySqlFile(pool, seedFile)
      console.log('Seed data loaded.')
    }
  }
  await syncSequences(pool)
}

export function ensureDir(): void {
  /* no-op: PostgreSQL storage is managed externally */
}
