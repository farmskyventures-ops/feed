import { Pool, type PoolConfig, types as pgTypes } from 'pg'

pgTypes.setTypeParser(20, (value) => Number(value))
pgTypes.setTypeParser(21, (value) => Number(value))
pgTypes.setTypeParser(23, (value) => Number(value))
pgTypes.setTypeParser(700, (value) => Number(value))
pgTypes.setTypeParser(701, (value) => Number(value))
pgTypes.setTypeParser(1700, (value) => Number(value))

export interface D1Like {
  prepare(sql: string): D1StatementLike
  setSessionConfig?(name: string, value: string): Promise<void>
}

export interface D1StatementLike {
  bind(...args: any[]): D1StatementLike
  first<T = any>(): Promise<T | null>
  all<T = any>(): Promise<{ results: T[]; success: boolean }>
  run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }>
}

const TABLES_WITH_NUMERIC_ID = new Set([
  'users', 'agents', 'customers', 'suppliers', 'products', 'stock_movements',
  'murabaha_contracts', 'repayments', 'invoices', 'transactions', 'approvals',
  'transunion_checks', 'id_verifications', 'audit_logs', 'tickets', 'otp_codes',
  'payment_intents', 'change_requests'
])

function convertPlaceholders(sql: string): string {
  let out = ''
  let inSingle = false
  let inDouble = false
  let index = 1
  for (let i = 0; i < sql.length; i++) {
    const char = sql[i]
    const next = sql[i + 1]
    if (char === "'" && !inDouble) {
      out += char
      if (inSingle && next === "'") {
        out += next
        i++
      } else {
        inSingle = !inSingle
      }
      continue
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble
      out += char
      continue
    }
    if (char === '?' && !inSingle && !inDouble) {
      out += `$${index++}`
      continue
    }
    out += char
  }
  return out
}

function tableNameFromInsert(sql: string): string | null {
  const match = sql.match(/^\s*insert\s+into\s+"?([a-zA-Z0-9_\.]+)"?/i)
  return match?.[1]?.split('.').pop()?.replace(/"/g, '') || null
}

function normalizeParam(value: any): any {
  if (value === undefined) return null
  if (typeof value === 'boolean') return value ? 1 : 0
  return value
}

class PostgresStatement implements D1StatementLike {
  private params: any[] = []

  constructor(private readonly pool: Pool, private readonly rawSql: string) {}

  bind(...args: any[]): D1StatementLike {
    this.params = args.map(normalizeParam)
    return this
  }

  private async query(sqlOverride?: string) {
    const sql = convertPlaceholders(sqlOverride || this.rawSql)
    return this.pool.query(sql, this.params)
  }

  async first<T = any>(): Promise<T | null> {
    const result = await this.query()
    return (result.rows[0] as T) ?? null
  }

  async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
    const result = await this.query()
    return { results: result.rows as T[], success: true }
  }

  async run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }> {
    let sql = this.rawSql.trim().replace(/;\s*$/, '')
    let lastRowId = 0
    if (/^insert\s+/i.test(sql) && !/\breturning\b/i.test(sql)) {
      const table = tableNameFromInsert(sql)
      if (table && TABLES_WITH_NUMERIC_ID.has(table)) sql += ' RETURNING id'
    }
    const result = await this.query(sql)
    if (result.rows?.[0]?.id != null) lastRowId = Number(result.rows[0].id)
    return {
      success: true,
      meta: {
        last_row_id: lastRowId,
        changes: result.rowCount || 0
      }
    }
  }
}

export class PostgresD1 implements D1Like {
  constructor(private readonly pool: Pool) {}

  prepare(sql: string): D1StatementLike {
    return new PostgresStatement(this.pool, sql)
  }

  /**
   * Sets a session-scoped configuration parameter (GUC) used by Row-Level
   * Security policies, e.g. app.current_marketplace_id / app.is_admin.
   * Uses set_config(name, value, is_local=false) so it applies to the whole
   * session. Tolerates non-Postgres/edge failures silently at the caller.
   */
  async setSessionConfig(name: string, value: string): Promise<void> {
    await this.pool.query('SELECT set_config($1, $2, false)', [name, value == null ? '' : String(value)])
  }
}

export async function openDatabase(connectionString: string): Promise<{ d1: PostgresD1; raw: Pool }> {
  // Issue 7 (security hardening): bound the connection pool and apply
  // conservative timeouts so a slow/hostile query cannot exhaust connections
  // or hang a worker indefinitely. A statement_timeout caps runaway queries.
  const requireSsl = process.env.PGSSLMODE === 'require' || process.env.DATABASE_SSL === 'require'
  const config: PoolConfig = {
    connectionString,
    ssl: requireSsl ? { rejectUnauthorized: false } : undefined,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30_000),
    connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT_MS || 10_000),
    statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS || 20_000),
    query_timeout: Number(process.env.PG_QUERY_TIMEOUT_MS || 20_000),
    application_name: 'farmsky'
  }
  const raw = new Pool(config)
  // Prevent an idle-client connection error from crashing the whole process.
  raw.on('error', (err) => {
    console.error('[db] idle client error (recovered):', err?.message || err)
  })
  await raw.query('SELECT 1')
  return { d1: new PostgresD1(raw), raw }
}
