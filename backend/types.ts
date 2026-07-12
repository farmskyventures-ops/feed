import type { MpesaEnv } from './mpesa'
import type { SmsEnv } from './sms'
import type { EmailEnv } from './email'
import type { SasaPayEnv } from './sasapay'
import type { BuniEnv } from './buni'
import type { GatewayEnv } from './payment-gateway-client'

export type Bindings = MpesaEnv & SmsEnv & EmailEnv & SasaPayEnv & BuniEnv & GatewayEnv & {
  DB: any
  TRANSUNION_API_URL?: string
  TRANSUNION_API_KEY?: string
  TRANSUNION_CLIENT_ID?: string
  TRANSUNION_ENV?: string
  // Auth/session signing secret (fail-closed in production if unset)
  SESSION_SECRET?: string
}

export type SessionUser = {
  id: number
  full_name: string
  phone: string
  email?: string | null
  avatar_url?: string | null
  role: string
  region?: string
  label?: string
  permissions?: Record<string, boolean>
}
