// =====================================================================
// SasaPay (Wallet-as-a-Service) STK Push integration
// ---------------------------------------------------------------------
// SasaPay is a Kenyan CBK-licensed payment aggregator. It supports
// receiving money from M-Pesa, Airtel Money, SasaPay wallets and banks
// through a single STK push ("C2B" / Request Payment) API.
//
// Docs: https://sasapay.co.ke / https://developer.sasapay.app
//
// When live credentials are supplied via env/secrets, real API calls are
// made; otherwise a realistic SIMULATION is returned so the platform
// stays fully functional during demos and local development — exactly
// like the M-Pesa module.
// =====================================================================

export type SasaPayEnv = {
  SASAPAY_CLIENT_ID?: string
  SASAPAY_CLIENT_SECRET?: string
  SASAPAY_MERCHANT_CODE?: string
  SASAPAY_ENV?: string          // 'production' | 'sandbox'
  SASAPAY_CALLBACK_URL?: string
}

const SANDBOX_BASE = 'https://sandbox.sasapay.app/api/v1'
const PROD_BASE = 'https://api.sasapay.app/api/v1'

export function sasapayConfigured(env: SasaPayEnv): boolean {
  return !!(env.SASAPAY_CLIENT_ID && env.SASAPAY_CLIENT_SECRET && env.SASAPAY_MERCHANT_CODE)
}

function baseUrl(env: SasaPayEnv): string {
  return env.SASAPAY_ENV === 'production' ? PROD_BASE : SANDBOX_BASE
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

async function getToken(env: SasaPayEnv): Promise<string> {
  const auth = b64(`${env.SASAPAY_CLIENT_ID}:${env.SASAPAY_CLIENT_SECRET}`)
  const res = await fetch(`${baseUrl(env)}/auth/token/?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  })
  if (!res.ok) throw new Error('Failed to obtain SasaPay token: ' + res.status)
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

// Initiate a "Request Payment" (STK push) for the given phone/amount.
export async function sasapayPush(
  env: SasaPayEnv,
  opts: { phone: string; amount: number; account: string; description: string; channel?: string }
): Promise<PayResult> {
  if (!sasapayConfigured(env)) {
    return {
      simulated: true,
      success: true,
      checkout_request_id: 'SP_SIM_' + crypto.randomUUID().slice(0, 12),
      merchant_request_id: 'SPM_' + crypto.randomUUID().slice(0, 8),
      customer_message: 'Simulated SasaPay prompt sent. (Configure SasaPay keys for live payments.)'
    }
  }
  try {
    const token = await getToken(env)
    const phone = normalizePhone(opts.phone)
    const body = {
      MerchantCode: env.SASAPAY_MERCHANT_CODE,
      NetworkCode: opts.channel || '0',         // 0 = auto-detect (M-Pesa/Airtel/etc.)
      PhoneNumber: phone,
      TransactionDesc: opts.description.slice(0, 50),
      AccountReference: opts.account.slice(0, 20),
      Currency: 'KES',
      Amount: Math.max(1, Math.round(opts.amount)),
      CallBackURL: env.SASAPAY_CALLBACK_URL || 'https://example.com/api/payments/callback/sasapay'
    }
    const res = await fetch(`${baseUrl(env)}/payments/request-payment/`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    const data: any = await res.json()
    if (data.status === true || data.ResponseCode === '0') {
      return {
        simulated: false,
        success: true,
        checkout_request_id: data.CheckoutRequestID || data.MerchantRequestID || data.RequestId,
        merchant_request_id: data.MerchantRequestID,
        customer_message: data.detail || data.CustomerMessage || 'SasaPay prompt sent. Enter your PIN on your phone.'
      }
    }
    return { simulated: false, success: false, error: data.detail || data.message || 'SasaPay request failed' }
  } catch (e: any) {
    return { simulated: false, success: false, error: e.message || 'SasaPay request failed' }
  }
}

// Query the status of a previously-initiated payment.
export async function sasapayQuery(env: SasaPayEnv, checkoutRequestId: string): Promise<{ ResultCode: any; ResultDesc?: string; receipt?: string }> {
  if (!sasapayConfigured(env)) return { ResultCode: '0', ResultDesc: 'Simulated success' }
  try {
    const token = await getToken(env)
    const res = await fetch(`${baseUrl(env)}/payments/transaction-status/`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ MerchantCode: env.SASAPAY_MERCHANT_CODE, CheckoutRequestID: checkoutRequestId })
    })
    const data: any = await res.json()
    const code = data.ResultCode ?? (data.status === true ? '0' : data.ResponseCode)
    return { ResultCode: code, ResultDesc: data.detail || data.ResultDesc, receipt: data.MpesaReceiptNumber || data.TransactionCode }
  } catch (e: any) {
    return { ResultCode: undefined, ResultDesc: e.message }
  }
}
