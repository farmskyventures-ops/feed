// =====================================================================
// Farmsky Central Payment Gateway — CLIENT
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
  // SasaPay channel routing (mobile money / bank / wallet). Only meaningful when
  // payment_method === 'sasapay'; the host gateway maps these to the provider.
  channel?: string          // 'MOBILE_MONEY' | 'BANK' | 'SASAPAY_WALLET'
  channelCode?: string      // network/bank code selected by the customer
  accountNumber?: string    // optional; bank prompts are delivered to the phone
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

/**
 * The client_key identifies this app to the central gateway (must match a row
 * in the host's `app_clients` table). For the feed satellite this is always
 * 'feed'; we default to it so a missing/blank env var doesn't break payments.
 */
function clientKey(env: GatewayEnv): string {
  const k = String(env.FARMSKY_PAYMENTS_CLIENT_KEY || '').trim()
  return k || 'feed'
}

/**
 * True when we have enough to reach the gateway: a URL and the shared HMAC
 * secret. The client_key falls back to 'feed', so it is not required here.
 */
export function gatewayConfigured(env: GatewayEnv): boolean {
  return !!(
    env.FARMSKY_PAYMENTS_GATEWAY_URL &&
    env.FARMSKY_PAYMENTS_HMAC_SECRET
  )
}

/**
 * Normalize the configured gateway URL to the payments API base.
 *
 * The host mounts the gateway at `/api/v1/payments/*` and exposes
 * `/initiate` and `/status/:ref` beneath it. Operators sometimes set only the
 * host origin (e.g. `https://equipment.farmsky.africa`) in the Render
 * dashboard, which would make `${url}/initiate` resolve to the wrong path and
 * silently 404. To be resilient we:
 *   - strip any trailing slashes
 *   - strip a trailing `/initiate` or `/status` if it was mistakenly included
 *   - append `/api/v1/payments` when the path segment is missing
 * so BOTH of these inputs work:
 *   https://equipment.farmsky.africa
 *   https://equipment.farmsky.africa/api/v1/payments
 */
function baseUrl(env: GatewayEnv): string {
  let u = String(env.FARMSKY_PAYMENTS_GATEWAY_URL || '').trim().replace(/\/+$/, '')
  // Drop an accidental trailing endpoint so we can rebuild it cleanly.
  u = u.replace(/\/(initiate|status)\/?$/i, '')
  // Ensure the payments API path is present.
  if (!/\/api\/v1\/payments$/i.test(u)) {
    u = u.replace(/\/+$/, '') + '/api/v1/payments'
  }
  return u
}

/**
 * Initiate a payment through the central gateway.
 */
export async function initiatePayment(env: GatewayEnv, opts: InitiatePaymentOptions): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) {
    return { success: false, error: 'gateway_not_configured' }
  }

  try {
    const key = clientKey(env)
    const secret = String(env.FARMSKY_PAYMENTS_HMAC_SECRET)
    
    const body = JSON.stringify({
      amount: opts.amount,
      phone: opts.phone,
      payment_method: opts.payment_method,
      origin_reference: opts.origin_reference,
      description: opts.description,
      initiated_by_user: opts.initiated_by_user,
      // SasaPay channel routing (ignored by the host for M-Pesa/Buni)
      channel: opts.channel,
      channelCode: opts.channelCode,
      accountNumber: opts.accountNumber
    })

    const { timestamp, nonce, signature } = await signRequest(secret, key, body)
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Farmsky-Client': key,
      'X-Farmsky-Timestamp': timestamp,
      'X-Farmsky-Nonce': nonce,
      'X-Farmsky-Signature': signature
    }
    
    if (opts.idempotency_key) {
      headers['Idempotency-Key'] = opts.idempotency_key
    }

    const res = await fetch(`${baseUrl(env)}/initiate`, { 
        method: 'POST', 
        headers, 
        body 
    })

    const text = await res.text()
    let json: GatewayResult = {} as GatewayResult
    try { json = text ? JSON.parse(text) : ({} as GatewayResult) } catch { /* non-JSON error page */ }
    
    if (!res.ok) {
      // Surface the host's real error (e.g. 'Unknown or inactive client app',
      // 'Invalid signature', 'Replay detected') so misconfiguration is visible
      // instead of a silent failure.
      const detail = json.error || (text ? text.slice(0, 160) : `gateway_http_${res.status}`)
      return { success: false, status: String(res.status), error: detail }
    }
    
    return json
  } catch (err: any) {
    return { success: false, error: `gateway_connection_failed: ${err?.message || err}` }
  }
}

/**
 * Complete a SasaPay WALLET checkout by submitting the buyer's OTP
 * (VerificationCode) to the central gateway. Only meaningful when the gateway
 * returned needs_otp=true on /initiate. The gateway forwards the code to
 * SasaPay's process-payment endpoint and settlement then arrives via callback,
 * so this simply authorises the debit; the caller keeps polling /status.
 *
 * The gateway exposes this at POST /process with a JSON body carrying the
 * transaction_ref and verification_code, HMAC-signed like every other call.
 */
export async function processPayment(
  env: GatewayEnv,
  transactionRef: string,
  verificationCode: string
): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) return { success: false, error: 'gateway_not_configured' }
  try {
    const key = clientKey(env)
    const secret = String(env.FARMSKY_PAYMENTS_HMAC_SECRET)
    const body = JSON.stringify({ transaction_ref: transactionRef, verification_code: verificationCode })
    const { timestamp, nonce, signature } = await signRequest(secret, key, body)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Farmsky-Client': key,
      'X-Farmsky-Timestamp': timestamp,
      'X-Farmsky-Nonce': nonce,
      'X-Farmsky-Signature': signature
    }
    const res = await fetch(`${baseUrl(env)}/process`, { method: 'POST', headers, body })
    const text = await res.text()
    let json: GatewayResult = {} as GatewayResult
    try { json = text ? JSON.parse(text) : ({} as GatewayResult) } catch { /* non-JSON */ }
    if (!res.ok) {
      const detail = json.error || (text ? text.slice(0, 160) : `gateway_http_${res.status}`)
      return { success: false, status: String(res.status), error: detail }
    }
    return { success: true, ...json }
  } catch (err: any) {
    return { success: false, error: `gateway_connection_failed: ${err?.message || err}` }
  }
}

/**
 * Check status of a transaction.
 */
export async function getPaymentStatus(env: GatewayEnv, transactionRef: string): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) return { success: false, error: 'gateway_not_configured' }
  
  try {
    const key = clientKey(env)
    const secret = String(env.FARMSKY_PAYMENTS_HMAC_SECRET)
    
    const { timestamp, nonce, signature } = await signRequest(secret, key, transactionRef)
    
    const headers: Record<string, string> = {
      'X-Farmsky-Client': key,
      'X-Farmsky-Timestamp': timestamp,
      'X-Farmsky-Nonce': nonce,
      'X-Farmsky-Signature': signature
    }
    
    const res = await fetch(`${baseUrl(env)}/status/${encodeURIComponent(transactionRef)}`, { headers })
    return await res.json()
  } catch (err) {
    return { success: false, error: 'gateway_connection_failed' }
  }
}
