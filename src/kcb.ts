// =====================================================================
// KCB (Kenya Commercial Bank) Buni — STK Push / Mobile-money collection
// ---------------------------------------------------------------------
// KCB exposes its payment rails through the "Buni" developer platform
// (https://buni.kcbgroup.com). The Mobile Money / STK Push API lets a
// merchant request a payment from a customer's phone (M-Pesa, KCB
// M-Benki, Airtel) against a KCB till/paybill.
//
// When live credentials are supplied via env/secrets, real API calls are
// made; otherwise a realistic SIMULATION is returned so the platform
// stays fully functional during demos and local development — exactly
// like the M-Pesa and SasaPay modules.
// =====================================================================

export type KcbEnv = {
  KCB_CONSUMER_KEY?: string
  KCB_CONSUMER_SECRET?: string
  KCB_TILL_NUMBER?: string        // KCB till / paybill the funds settle to
  KCB_ENV?: string                // 'production' | 'sandbox'
  KCB_CALLBACK_URL?: string
}

const SANDBOX_BASE = 'https://uat.buni.kcbgroup.com'
const PROD_BASE = 'https://api.buni.kcbgroup.com'

export function kcbConfigured(env: KcbEnv): boolean {
  return !!(env.KCB_CONSUMER_KEY && env.KCB_CONSUMER_SECRET && env.KCB_TILL_NUMBER)
}

function baseUrl(env: KcbEnv): string {
  return env.KCB_ENV === 'production' ? PROD_BASE : SANDBOX_BASE
}

function b64(s: string): string { return btoa(s) }

// Normalise a Kenyan phone number to 254XXXXXXXXX.
export function normalizePhone(phone: string): string {
  let p = String(phone || '').replace(/[^0-9]/g, '')
  if (p.startsWith('0')) p = '254' + p.slice(1)
  if (p.startsWith('7') && p.length === 9) p = '254' + p
  if (p.startsWith('1') && p.length === 9) p = '254' + p
  if (p.startsWith('2540')) p = '254' + p.slice(4)
  return p
}

async function getToken(env: KcbEnv): Promise<string> {
  const auth = b64(`${env.KCB_CONSUMER_KEY}:${env.KCB_CONSUMER_SECRET}`)
  const res = await fetch(`${baseUrl(env)}/token/?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  })
  if (!res.ok) throw new Error('Failed to obtain KCB token: ' + res.status)
  const data: any = await res.json()
  return data.access_token
}

export type PayResult = {
  simulated: boolean
  success: boolean
  checkout_request_id?: string
  merchant_request_id?: string
  customer_message?: string
  error?: string
}

// Initiate a KCB STK push for the given phone/amount.
export async function kcbPush(
  env: KcbEnv,
  opts: { phone: string; amount: number; account: string; description: string }
): Promise<PayResult> {
  if (!kcbConfigured(env)) {
    return {
      simulated: true,
      success: true,
      checkout_request_id: 'KCB_SIM_' + crypto.randomUUID().slice(0, 12),
      merchant_request_id: 'KCBM_' + crypto.randomUUID().slice(0, 8),
      customer_message: 'Simulated KCB prompt sent. (Configure KCB Buni keys for live payments.)'
    }
  }
  try {
    const token = await getToken(env)
    const phone = normalizePhone(opts.phone)
    const body = {
      phoneNumber: phone,
      amount: String(Math.max(1, Math.round(opts.amount))),
      invoiceNumber: opts.account.slice(0, 20),
      sharedShortCode: true,
      orgShortCode: env.KCB_TILL_NUMBER,
      orgPassKey: env.KCB_CONSUMER_SECRET,
      callbackUrl: env.KCB_CALLBACK_URL || 'https://example.com/api/payments/callback/kcb',
      transactionDescription: opts.description.slice(0, 50)
    }
    const res = await fetch(`${baseUrl(env)}/mm/api/request/1.0.0/stkpush`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    const data: any = await res.json()
    if (data.header?.statusCode === 0 || data.ResponseCode === '0' || data.responseCode === '0') {
      return {
        simulated: false,
        success: true,
        checkout_request_id: data.response?.CheckoutRequestID || data.CheckoutRequestID || data.transactionId,
        merchant_request_id: data.response?.MerchantRequestID || data.MerchantRequestID,
        customer_message: data.response?.CustomerMessage || data.header?.messages || 'KCB prompt sent. Enter your PIN on your phone.'
      }
    }
    return { simulated: false, success: false, error: data.header?.messages || data.message || 'KCB request failed' }
  } catch (e: any) {
    return { simulated: false, success: false, error: e.message || 'KCB request failed' }
  }
}

// Query the status of a previously-initiated payment.
export async function kcbQuery(env: KcbEnv, checkoutRequestId: string): Promise<{ ResultCode: any; ResultDesc?: string; receipt?: string }> {
  if (!kcbConfigured(env)) return { ResultCode: '0', ResultDesc: 'Simulated success' }
  try {
    const token = await getToken(env)
    const res = await fetch(`${baseUrl(env)}/mm/api/request/1.0.0/query`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgShortCode: env.KCB_TILL_NUMBER, CheckoutRequestID: checkoutRequestId })
    })
    const data: any = await res.json()
    const code = data.ResultCode ?? data.response?.ResultCode ?? (data.header?.statusCode === 0 ? '0' : undefined)
    return { ResultCode: code, ResultDesc: data.ResultDesc || data.header?.messages, receipt: data.MpesaReceiptNumber || data.response?.MpesaReceiptNumber }
  } catch (e: any) {
    return { ResultCode: undefined, ResultDesc: e.message }
  }
}
