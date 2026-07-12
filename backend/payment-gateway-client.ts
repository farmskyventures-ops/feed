// =====================================================================
// Farmsky Central Payment Gateway — CLIENT (for the FEED marketplace)
// ---------------------------------------------------------------------
// The FEED app is a *client* of the central gateway hosted at
// equipment.farmsky.africa. It NEVER talks to M-Pesa/SasaPay/Buni or the
// SMS/OTP/email providers directly in production — the central processor
// (equipment.farmsky.africa) owns the single merchant shortcode and all
// provider credentials.
//
// This module signs every outbound request with HMAC-SHA256 using the
// shared secret stored ONLY in the environment (never hardcoded). The
// same signing scheme is verified server-side by payment-gateway-shared.ts.
//
// Security properties:
//   * HMAC-SHA256 over `client_key\ntimestamp\nnonce\nbody`
//   * Per-request UUID nonce + ms timestamp (server rejects >5 min / replays)
//   * origin_app is derived server-side from the verified client_key — the
//     body's origin can never be spoofed.
//   * Idempotency-Key prevents double-charging on retry.
// =====================================================================

import { signRequest } from './payment-gateway-shared'

export type GatewayMethod = 'mpesa' | 'sasapay' | 'buni'

export interface GatewayEnv {
  FARMSKY_PAYMENTS_GATEWAY_URL?: string
  FARMSKY_PAYMENTS_CLIENT_KEY?: string
  FARMSKY_PAYMENTS_HMAC_SECRET?: string
}

export interface InitiatePaymentOptions {
  amount: number
  phone: string
  payment_method: GatewayMethod
  origin_reference?: string
  description?: string
  initiated_by_user?: number
  idempotency_key?: string
}

export interface GatewayResult {
  success: boolean
  transaction_ref?: string
  payment_method?: string
  origin_app?: string
  simulated?: boolean
  customer_message?: string
  status?: string
  error?: string
}

/** True only when all three gateway env vars are present (production wiring). */
export function gatewayConfigured(env: GatewayEnv): boolean {
  return Boolean(
    env.FARMSKY_PAYMENTS_GATEWAY_URL &&
    env.FARMSKY_PAYMENTS_CLIENT_KEY &&
    env.FARMSKY_PAYMENTS_HMAC_SECRET
  )
}

function baseUrl(env: GatewayEnv): string {
  return String(env.FARMSKY_PAYMENTS_GATEWAY_URL || '').replace(/\/+$/, '')
}

/**
 * Initiate a payment through the central gateway. Returns a normalized result.
 * Throws only on unexpected transport errors; provider/validation failures come
 * back as { success:false, error }.
 */
export async function initiatePayment(env: GatewayEnv, opts: InitiatePaymentOptions): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) {
    return { success: false, error: 'gateway_not_configured' }
  }
  const clientKey = String(env.FARMSKY_PAYMENTS_CLIENT_KEY)
  const secret = String(env.FARMSKY_PAYMENTS_HMAC_SECRET)
  const body = JSON.stringify({
    amount: opts.amount,
    phone: opts.phone,
    payment_method: opts.payment_method,
    origin_reference: opts.origin_reference,
    description: opts.description,
    initiated_by_user: opts.initiated_by_user
  })
  const { timestamp, nonce, signature } = await signRequest(secret, clientKey, body)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Farmsky-Client': clientKey,
    'X-Farmsky-Timestamp': timestamp,
    'X-Farmsky-Nonce': nonce,
    'X-Farmsky-Signature': signature
  }
  if (opts.idempotency_key) headers['Idempotency-Key'] = opts.idempotency_key

  const res = await fetch(`${baseUrl(env)}/initiate`, { method: 'POST', headers, body })
  const json = (await res.json().catch(() => ({}))) as GatewayResult
  if (!res.ok && json?.success == null) {
    return { success: false, error: json?.error || `gateway_http_${res.status}` }
  }
  return json
}

/**
 * Check the status of a previously-initiated transaction. For GET requests the
 * signed message is the transaction_ref itself (matches payment-gateway-shared verify).
 */
export async function getPaymentStatus(env: GatewayEnv, transactionRef: string): Promise<any> {
  if (!gatewayConfigured(env)) return { success: false, error: 'gateway_not_configured' }
  const clientKey = String(env.FARMSKY_PAYMENTS_CLIENT_KEY)
  const secret = String(env.FARMSKY_PAYMENTS_HMAC_SECRET)
  const { timestamp, nonce, signature } = await signRequest(secret, clientKey, transactionRef)
  const headers: Record<string, string> = {
    'X-Farmsky-Client': clientKey,
    'X-Farmsky-Timestamp': timestamp,
    'X-Farmsky-Nonce': nonce,
    'X-Farmsky-Signature': signature
  }
  const res = await fetch(`${baseUrl(env)}/status/${encodeURIComponent(transactionRef)}`, { headers })
  return await res.json().catch(() => ({ success: false, error: `gateway_http_${res.status}` }))
}
