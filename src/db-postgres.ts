// =====================================================================
// D1-compatible adapter over node-postgres (PostgreSQL)
// ---------------------------------------------------------------------
// Lets the SAME Hono app code that targets Cloudflare D1
//   c.env.DB.prepare(sql).bind(...args).first() / .all() / .run()
// run unchanged against a PostgreSQL database.
//
// It mimics the small slice of the D1 API the app uses, while bridging
// the SQL-dialect differences between SQLite/D1 and PostgreSQL:
//   - "?" positional placeholders  ->  "$1, $2, ..."
//   - INSERT ... (no RETURNING)    ->  appends "RETURNING id" so we can
//                                       surface meta.last_row_id
//   - run() reports rowCount as meta.changes
// =====================================================================

import pg from 'pg'

const { Pool } = pg

export interface D1Like {
  prepare(sql: string): D1StatementLike
  exec(sql: string): Promise<unknown>
}

export interface D1StatementLike {
  bind(...args: any[]): D1StatementLike
  first<T = any>(): Promise<T | null>
  all<T = any>(): Promise<{ results: T[]; success: boolean }>
  run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }>
}

// Convert SQLite-style "?" placeholders to PostgreSQL "$1, $2, ..." form.
// Skips "?" that appear inside single-quoted string literals.
function toPgPlaceholders(sql: string): string {
  let out = ''
  let i = 0
  let n = 0
  let inSingle = false
  while (i < sql.length) {
    const ch = sql[i]
    if (ch === "'") {
      // handle escaped '' inside a string literal
      if (inSingle && sql[i + 1] === "'") {
        out += "''"
        i += 2
        continue
      }
      inSingle = !inSingle
      out += ch
      i++
      continue
    }
    if (ch === '?' && !inSingle) {
      n++
      out += '$' + n
      i++
      continue
    }
    out += ch
    i++
  }
  return out
}

// Detect a bare INSERT that has no RETURNING clause, so we can append one
// and expose the generated id as meta.last_row_id (D1 parity).
function isInsertWithoutReturning(sql: string): boolean {
  const s = sql.trim().toLowerCase()
  return s.startsWith('insert') && !s.includes('returning')
}

class PgStatement implements D1StatementLike {
  private params: any[] = []
  constructor(private pool: pg.Pool, private sql: string) {}

  bind(...args: any[]): D1StatementLike {
    this.params = args
    return this
  }

  private pgSql(): string {
    return toPgPlaceholders(this.sql)
  }

  async first<T = any>(): Promise<T | null> {
    const res = await this.pool.query(this.pgSql(), this.params)
    return (res.rows[0] as T) ?? null
  }

  async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
    const res = await this.pool.query(this.pgSql(), this.params)
    return { results: res.rows as T[], success: true }
  }

  async run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }> {
    let sql = this.pgSql()
    let captureId = false
    if (isInsertWithoutReturning(this.sql)) {
      sql = sql.replace(/;\s*$/, '') + ' RETURNING id'
      captureId = true
    }
    let res
    try {
      res = await this.pool.query(sql, this.params)
    } catch (e: any) {
      // Some INSERTs (e.g. tables without an "id" column, or composite keys)
      // can't RETURNING id — retry without it.
      if (captureId && /column "id" does not exist|has no column named "id"/i.test(String(e.message))) {
        res = await this.pool.query(this.pgSql(), this.params)
        captureId = false
      } else {
        throw e
      }
    }
    const lastId = captureId && res.rows[0] ? Number(res.rows[0].id) : 0
    return {
      success: true,
      meta: { last_row_id: lastId, changes: res.rowCount ?? 0 }
    }
  }
}

export class PostgresD1 implements D1Like {
  constructor(private pool: pg.Pool) {}
  prepare(sql: string): D1StatementLike {
    return new PgStatement(this.pool, sql)
  }
  async exec(sql: string): Promise<unknown> {
    return this.pool.query(sql)
  }
}

export function openPostgres(connectionString: string): { d1: PostgresD1; pool: pg.Pool } {
  const pool = new Pool({
    connectionString,
    max: Number(process.env.PGPOOL_MAX || 10),
    ssl: /sslmode=require|\bssl=true/i.test(connectionString)
      ? { rejectUnauthorized: false }
      : undefined
  })
  return { d1: new PostgresD1(pool), pool }
}
