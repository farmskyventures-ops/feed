// =====================================================================
// D1-compatible adapter over better-sqlite3 (Node.js / server runtime)
// ---------------------------------------------------------------------
// This lets the SAME Hono app code that uses Cloudflare D1
//   c.env.DB.prepare(sql).bind(...args).first() / .all() / .run()
// run unchanged on a plain Node server (e.g. AWS EC2 / App Runner).
//
// It mimics the small slice of the D1 API the app actually uses:
//   - prepare(sql)            -> statement
//   - statement.bind(...args) -> statement (chainable)
//   - statement.first()       -> first row | null
//   - statement.all()         -> { results: rows[] }
//   - statement.run()         -> { success, meta: { last_row_id, changes } }
// =====================================================================

import Database from 'better-sqlite3'

export interface D1Like {
  prepare(sql: string): D1StatementLike
  exec(sql: string): unknown
}

export interface D1StatementLike {
  bind(...args: any[]): D1StatementLike
  first<T = any>(): Promise<T | null>
  all<T = any>(): Promise<{ results: T[]; success: boolean }>
  run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }>
}

class SqliteStatement implements D1StatementLike {
  private params: any[] = []
  constructor(private db: Database.Database, private sql: string) {}

  bind(...args: any[]): D1StatementLike {
    this.params = args
    return this
  }

  async first<T = any>(): Promise<T | null> {
    const stmt = this.db.prepare(this.sql)
    const row = stmt.get(...this.params)
    return (row as T) ?? null
  }

  async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
    const stmt = this.db.prepare(this.sql)
    const rows = stmt.all(...this.params) as T[]
    return { results: rows, success: true }
  }

  async run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }> {
    const stmt = this.db.prepare(this.sql)
    const info = stmt.run(...this.params)
    return {
      success: true,
      meta: {
        last_row_id: Number(info.lastInsertRowid),
        changes: info.changes
      }
    }
  }
}

export class SqliteD1 implements D1Like {
  constructor(private db: Database.Database) {}
  prepare(sql: string): D1StatementLike {
    return new SqliteStatement(this.db, sql)
  }
  exec(sql: string): unknown {
    return this.db.exec(sql)
  }
}

export function openDatabase(filePath: string): { d1: SqliteD1; raw: Database.Database } {
  const raw = new Database(filePath)
  raw.pragma('journal_mode = WAL')
  raw.pragma('foreign_keys = ON')
  return { d1: new SqliteD1(raw), raw }
}
