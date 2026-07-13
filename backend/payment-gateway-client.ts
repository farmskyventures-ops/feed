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

/** True only when all three gateway env vars are present. */
export function gatewayConfigured(env: GatewayEnv): boolean {
  return !!(
    env.FARMSKY_PAYMENTS_GATEWAY_URL &&
    env.FARMSKY_PAYMENTS_CLIENT_KEY &&
    env.FARMSKY_PAYMENTS_HMAC_SECRET
  )
}

function baseUrl(env: GatewayEnv): string {
  return String(env.FARMSKY_PAYMENTS_GATEWAY_URL || '').replace(/\/+$/, '')
}

/**
 * Initiate a payment through the central gateway.
 */
export async function initiatePayment(env: GatewayEnv, opts: InitiatePaymentOptions): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) {
    return { success: false, error: 'gateway_not_configured' }
  }

  try {
    const clientKey = String(env.FARMSKY_PAYMENTS_CLIENT_KEY)
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

    const { timestamp, nonce, signature } = await signRequest(secret, clientKey, body)
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Farmsky-Client': clientKey,
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

    const json = (await res.json().catch(() => ({}))) as GatewayResult
    
    if (!res.ok) {
      return { success: false, error: json.error || `gateway_http_${res.status}` }
    }
    
    return json
  } catch (err) {
    return { success: false, error: 'gateway_connection_failed' }
  }
}

/**
 * Check status of a transaction.
 */
export async function getPaymentStatus(env: GatewayEnv, transactionRef: string): Promise<GatewayResult> {
  if (!gatewayConfigured(env)) return { success: false, error: 'gateway_not_configured' }
  
  try {
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
    return await res.json()
  } catch (err) {
    return { success: false, error: 'gateway_connection_failed' }
  }
}
