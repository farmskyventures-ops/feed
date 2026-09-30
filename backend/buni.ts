// =====================================================================
// KCB Buni API integration  (MpesaExpressAPIService · FundsTransferAPIService · IPN)
// ---------------------------------------------------------------------
// Spec-compliant client for the KCB Buni API Gateway. Covers:
//   • OAuth2 client_credentials token generation (Basic auth)
//   • M-Pesa STK Push  (POST /mm/api/request/1.0.0/stkpush)
//   • Funds Transfer   (POST /fundstransfer/1.0.0/api/v1/transfer)
//   • IPN signature verification (SHA256withRSA, `signature` header)
//
// All network calls degrade GRACEFULLY to SIMULATION when credentials are
// not configured, so local dev / QA and non-KCB tenants keep working with
// zero behaviour change. The return shapes mirror ./mpesa (StkResult) so the
// central payment gateway can treat every rail uniformly.
//
// Docs (developer portal):
//   STK   https://sandbox.buni.kcbgroup.com/devportal/apis/6396efd5-de10-4b04-adec-128f54349614/documents
//   FT    https://sandbox.buni.kcbgroup.com/devportal/apis/372552ef-5ebd-4921-9a0d-2f3b1da8cb86/documents
//   IPN   https://sandbox.buni.kcbgroup.com/devportal/apis/01b3ebbd-1452-4baf-a068-2913ecd3af73/documents
// =====================================================================

import { normalizePhone } from './mpesa'

export type BuniEnv = {
  BUNI_CLIENT_ID?: string
  BUNI_CLIENT_SECRET?: string
  BUNI_API_KEY?: string          // legacy / optional apikey header (some gateway plans require it)
  BUNI_ENV?: string              // 'sandbox' | 'uat' | 'production' (default: production)
  BUNI_STK_CALLBACK_URL?: string // HTTPS endpoint M-Pesa posts STK results to
  BUNI_FT_CALLBACK_URL?: string  // HTTPS endpoint KCB posts funds-transfer results to
  BUNI_SHARED_SHORTCODE?: string // 'true' (default) → use KCB paybill 522533; else supply org values
  BUNI_ORG_SHORTCODE?: string    // only when sharedShortCode=false
  BUNI_ORG_PASSKEY?: string      // only when sharedShortCode=false
  BUNI_DEBIT_ACCOUNT?: string    // KCB account funds are transferred FROM (funds transfer)
  BUNI_COMPANY_CODE?: string     // parent bank code where the debit account sits (e.g. KE0010001)
  BUNI_IPN_PUBLIC_KEY?: string   // PEM public key from KCB for IPN signature verification
}

// UAT / sandbox share the same host per the spec; production uses api.*.
const SANDBOX_BASE = 'https://uat.buni.kcbgroup.com'
const PROD_BASE = 'https://api.buni.kcbgroup.com'

// STK-push terminal M-Pesa result codes (from the spec's callback table).
export const BUNI_STK_RESULT: Record<string, string> = {
  '0': 'The service request is processed successfully.',
  '1037': 'DS timeout — user cannot be reached',
  '2001': 'The initiator information is invalid. (Incorrect PIN)',
  '1032': 'Request cancelled by user',
}

// Appendix 1 — Funds-transfer transaction type codes.
export const BUNI_TRANSACTION_TYPES: Record<string, string> = {
  IF: 'Internal KCB Funds Transfer',
  RT: 'RTGS',
  PL: 'PESALINK',
  EF: 'EFT',
  MO: 'MOBILE MONEY',
}

// Appendix 2 — Bank participant identification codes (PIC).
export const BUNI_BANK_CODES: Record<string, string> = {
  '01': 'KCB', '02': 'Stanchart', '03': 'ABSA', '05': 'Bank of India',
  '06': 'Bank of Baroda', '07': 'NCBA', '10': 'Prime Bank', '11': 'Coop Bank',
  '12': 'NBK', '14': 'M-Oriental', '16': 'Citi Bank', '17': 'Habib Bank AG Zurich',
  '18': 'Middle East Bank', '19': 'Bank of Africa', '23': 'Consolidated', '25': 'Credit Bank',
  '26': 'Access Bank', '31': 'Stanbic Bank', '35': 'ABC Bank', '43': 'Eco Bank',
  '49': 'SPIRE Bank', '50': 'Paramount', '51': 'Kingdom Bank', '53': 'Gt Bank',
  '54': 'Victoria Bank', '55': 'Guardian Bank', '57': 'I&M Bank', '59': 'Development Bank',
  '60': 'SBM', '61': 'Housing finance', '63': 'DTB', '65': 'Mayfair Bank',
  '66': 'Sidian Bank', '68': 'Equity Bank', '70': 'Family Bank', '72': 'Gulf African Bank',
  '74': 'First Community Bank', '75': 'DIB Bank', '76': 'UBA', '78': 'KWFT',
  '79': 'Faulu Bank', '99': 'Post Bank', 'MPESA': 'MPESA',
}

function isSandbox(envValue?: string): boolean {
  const v = String(envValue || '').trim().toLowerCase()
  return v === 'sandbox' || v === 'development' || v === 'dev' || v === 'test' || v === 'uat'
}
function baseUrl(env: BuniEnv): string {
  return isSandbox(env.BUNI_ENV) ? SANDBOX_BASE : PROD_BASE
}
function sharedShortCode(env: BuniEnv): boolean {
  // Defaults to TRUE (use KCB's shared paybill 522533) unless explicitly disabled.
  return String(env.BUNI_SHARED_SHORTCODE ?? 'true').trim().toLowerCase() !== 'false'
}

export function buniConfigured(env: BuniEnv): boolean {
  return !!(env.BUNI_CLIENT_ID && env.BUNI_CLIENT_SECRET)
}
// Funds transfer additionally needs a debit account to move money from.
export function buniFtConfigured(env: BuniEnv): boolean {
  return buniConfigured(env) && !!env.BUNI_DEBIT_ACCOUNT
}

// Base64 that works on both Node and Workers.
function b64(s: string): string {
  // btoa is available on Workers; Buffer on Node.
  try { return btoa(s) } catch { /* fall through */ }
  // @ts-ignore - Node fallback
  return Buffer.from(s, 'utf-8').toString('base64')
}

// OAuth2 client_credentials → bearer token.
async function getToken(env: BuniEnv): Promise<string> {
  const auth = b64(`${env.BUNI_CLIENT_ID}:${env.BUNI_CLIENT_SECRET}`)
  const res = await fetch(`${baseUrl(env)}/token?grant_type=client_credentials`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  })
  if (!res.ok) throw new Error(`KCB Buni auth failed (${res.status})`)
  const data: any = await res.json()
  const token = data.access_token || data.accessToken
  if (!token) throw new Error('KCB Buni auth returned no access_token')
  return token
}

// A unique alphanumeric messageId (max 32 chars per the header spec).
function messageId(prefix = 'FSKY'): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`.slice(0, 32)
}

export type StkResult = {
  simulated: boolean
  success: boolean
  checkout_request_id?: string
  merchant_request_id?: string
  customer_message?: string
  error?: string
}

// ---------------------------------------------------------------------
// M-Pesa STK Push  (MpesaExpressAPIService)
// ---------------------------------------------------------------------
export async function buniStkPush(
  env: BuniEnv,
  opts: { phone: string; amount: number; account: string; description: string; callbackUrl?: string }
): Promise<StkResult> {
  if (!buniConfigured(env)) {
    return {
      simulated: true,
      success: true,
      checkout_request_id: 'BUNI_SIM_' + (globalThis.crypto?.randomUUID?.().slice(0, 12) || Date.now()),
      merchant_request_id: 'BUNI_SIM_' + Date.now().toString().slice(-8),
      customer_message: 'Simulated KCB Buni STK push sent. (Credentials not detected.)',
    }
  }
  try {
    const token = await getToken(env)
    const shared = sharedShortCode(env)
    const phone = normalizePhone(opts.phone)
    // Amount: decimals not permitted (spec) — send an integer string.
    const amount = String(Math.max(1, Math.round(opts.amount)))
    const body: Record<string, any> = {
      phoneNumber: phone,
      amount,
      invoiceNumber: String(opts.account).slice(0, 24),
      sharedShortCode: shared,
      orgShortCode: shared ? '' : (env.BUNI_ORG_SHORTCODE || ''),
      orgPassKey: shared ? '' : (env.BUNI_ORG_PASSKEY || ''),
      callbackUrl: (opts.callbackUrl || env.BUNI_STK_CALLBACK_URL || '').slice(0, 200),
      transactionDescription: String(opts.description).slice(0, 13),
    }
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      routeCode: '207',
      operation: 'STKPush',
      messageId: messageId('KCBOrg'),
      Authorization: `Bearer ${token}`,
    }
    if (env.BUNI_API_KEY) headers['apikey'] = env.BUNI_API_KEY
    const res = await fetch(`${baseUrl(env)}/mm/api/request/1.0.0/stkpush`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })
    const data: any = await res.json().catch(() => ({}))
    // Provider fault (invalid/missing credentials).
    if (data?.fault) {
      return { simulated: false, success: false, error: data.fault.description || data.fault.message || 'KCB Buni fault' }
    }
    const resp = data?.response || {}
    const header = data?.header || {}
    const statusCode = String(header.statusCode ?? resp.ResponseCode ?? '')
    if (statusCode === '0' && (resp.CheckoutRequestID || resp.MerchantRequestID)) {
      return {
        simulated: false,
        success: true,
        checkout_request_id: resp.CheckoutRequestID || resp.MerchantRequestID,
        merchant_request_id: resp.MerchantRequestID,
        customer_message: resp.CustomerMessage || 'STK push sent.',
      }
    }
    return {
      simulated: false,
      success: false,
      error: header.statusDescription || resp.ResponseDescription || 'KCB Buni STK push failed',
    }
  } catch (e: any) {
    return { simulated: false, success: false, error: e?.message || 'KCB Buni request failed' }
  }
}

// STK Push is callback-driven; there is no dedicated query endpoint in the spec.
// We return a PENDING-shaped response so the gateway keeps polling the callback
// ledger rather than treating an absent query as a failure. When simulating we
// report success so local QA completes deterministically.
export async function buniQuery(env: BuniEnv, checkoutRequestId: string): Promise<any> {
  if (!buniConfigured(env) || String(checkoutRequestId || '').includes('SIM')) {
    return { ResponseCode: '0', ResultCode: '0', ResultDesc: 'Simulated success' }
  }
  // No authoritative synchronous status endpoint — remain pending until the
  // asynchronous callback settles the transaction.
  return { ResultDesc: 'pending', pending: true }
}

// ---------------------------------------------------------------------
// Funds Transfer  (FundsTransferAPIService)
//   Moves money from the configured KCB debit account to a beneficiary
//   account (internal KCB, inter-bank RTGS/EFT/PesaLink, or M-Pesa wallet).
// ---------------------------------------------------------------------
export type FundsTransferResult = {
  simulated: boolean
  success: boolean
  status_code?: string
  status_message?: string
  status_description?: string
  merchant_id?: string
  retrieval_ref?: string
  error?: string
}

export async function buniFundsTransfer(
  env: BuniEnv,
  opts: {
    beneficiaryDetails: string
    creditAccountNumber: string
    debitAmount: number
    transactionReference: string
    transactionType: string     // IF | RT | PL | EF | MO (Appendix 1)
    beneficiaryBankCode: string  // Appendix 2 PIC; 'MPESA' for mobile wallet
    currency?: string
    paymentDetails?: string
    debitAccountNumber?: string
    companyCode?: string
  }
): Promise<FundsTransferResult> {
  if (!buniFtConfigured(env)) {
    return {
      simulated: true,
      success: true,
      status_code: '0',
      status_message: 'Success',
      status_description: 'Simulated funds transfer accepted for processing.',
      merchant_id: 'FT_SIM_' + (globalThis.crypto?.randomUUID?.() || Date.now()),
      retrieval_ref: 'SIM' + Date.now().toString().slice(-7),
    }
  }
  try {
    const token = await getToken(env)
    const body = {
      beneficiaryDetails: String(opts.beneficiaryDetails).slice(0, 35),
      companyCode: (opts.companyCode || env.BUNI_COMPANY_CODE || '').slice(0, 15),
      creditAccountNumber: String(opts.creditAccountNumber).slice(0, 12),
      currency: (opts.currency || 'KES').slice(0, 3),
      debitAccountNumber: String(opts.debitAccountNumber || env.BUNI_DEBIT_ACCOUNT || '').slice(0, 12),
      debitAmount: Math.max(1, Math.round(opts.debitAmount)),
      paymentDetails: String(opts.paymentDetails || 'Payment').slice(0, 35),
      transactionReference: String(opts.transactionReference).slice(0, 12),
      transactionType: String(opts.transactionType).slice(0, 2),
      beneficiaryBankCode: String(opts.beneficiaryBankCode).slice(0, 20),
    }
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    }
    if (env.BUNI_API_KEY) headers['apikey'] = env.BUNI_API_KEY
    const res = await fetch(`${baseUrl(env)}/fundstransfer/1.0.0/api/v1/transfer`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })
    const data: any = await res.json().catch(() => ({}))
    if (data?.fault) {
      return { simulated: false, success: false, error: data.fault.description || data.fault.message || 'KCB Buni fault' }
    }
    const code = String(data.statusCode ?? '')
    if (code === '0') {
      return {
        simulated: false,
        success: true,
        status_code: code,
        status_message: data.statusMessage,
        status_description: data.statusDescription,
        merchant_id: data.merchantID,
        retrieval_ref: data.retrievalRefNumber,
      }
    }
    return {
      simulated: false,
      success: false,
      status_code: code || '1',
      status_description: data.statusDescription || 'Funds transfer rejected',
      retrieval_ref: data.retrievalRefNumber,
      error: data.statusDescription || 'Funds transfer rejected',
    }
  } catch (e: any) {
    return { simulated: false, success: false, error: e?.message || 'KCB Buni funds transfer failed' }
  }
}

// ---------------------------------------------------------------------
// IPN signature verification  (SHA256withRSA, `signature` header)
//   KCB signs all IPN payloads with its private key; we verify with the
//   supplied PUBLIC KEY. When no public key is configured we return `null`
//   (indeterminate) so the caller can decide policy (e.g. accept in sim,
//   reject in production).
// ---------------------------------------------------------------------
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64body = pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '')
  const bin = atobUniversal(b64body)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer
}
function atobUniversal(s: string): string {
  try { return atob(s) } catch { /* node */ }
  // @ts-ignore
  return Buffer.from(s, 'base64').toString('binary')
}

// Returns: true (valid), false (invalid), or null (cannot verify — no key).
export async function buniVerifyIpnSignature(
  env: BuniEnv,
  rawBody: string,
  signatureB64: string | null | undefined
): Promise<boolean | null> {
  const pem = env.BUNI_IPN_PUBLIC_KEY
  if (!pem) return null
  if (!signatureB64) return false
  try {
    const subtle = (globalThis.crypto as any)?.subtle
    if (!subtle) return null
    const keyData = pemToArrayBuffer(pem)
    const key = await subtle.importKey(
      'spki',
      keyData,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    )
    const sigBin = atobUniversal(String(signatureB64).replace(/\s+/g, ''))
    const sig = new Uint8Array(sigBin.length)
    for (let i = 0; i < sigBin.length; i++) sig[i] = sigBin.charCodeAt(i)
    const enc = new TextEncoder().encode(rawBody)
    return await subtle.verify('RSASSA-PKCS1-v1_5', key, sig.buffer, enc)
  } catch {
    return false
  }
}
