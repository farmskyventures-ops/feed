import type { MpesaEnv } from './mpesa'
import type { SmsEnv } from './sms'
import type { EmailEnv } from './email'

// DB is Cloudflare D1 in the Workers build, and a D1-compatible SQLite
// adapter (see db-sqlite.ts) in the Node server build. Typed loosely so
// the same app code compiles in both environments.
export type Bindings = MpesaEnv & SmsEnv & EmailEnv & {
  DB: any
}

export type SessionUser = {
  id: number
  full_name: string
  phone: string
  role: string
  region?: string
  custom_role?: string | null
  permissions?: string[]
}
