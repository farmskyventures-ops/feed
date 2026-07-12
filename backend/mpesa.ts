// =====================================================================
// M-Pesa Daraja (Lipa na M-Pesa Online / STK Push) integration
// Supports Cloudflare (c.env), Render Env Vars, and Render Secret Files
// =====================================================================

import { env } from 'hono/adapter'
import fs from 'fs';
import path from 'path';

export type MpesaEnv = {
  MPESA_CONSUMER_KEY?: string
  MPESA_CONSUMER_SECRET?: string
  MPESA_SHORTCODE?: string
  MPESA_PASSKEY?: string
  MPESA_ENV?: string
  MPESA_CALLBACK_URL?: string
}

// Helper to read from either Render Secret Files or standard Environment Variables
function getSecret(name: string): string | undefined {
  // 1. Try to read from Render Secret Files mount (/etc/secrets/)
  const secretPath = path.join('/etc/secrets/', name);
  const fileExists = fs.existsSync(secretPath);
  
  if (fileExists) {
    try {
      const val = fs.readFileSync(secretPath, 'utf8').trim();
      console.log(`DEBUG: Successfully read secret ${name} from file system.`);
      return val;
    } catch (err) {
      console.error(`DEBUG: Error reading secret file: ${name}`, err);
    }
  } else {
    console.log(`DEBUG: Secret file not found for ${name} at ${secretPath}. Checking process.env...`);
  }

  // 2. Fallback to standard Environment Variable
  const envVal = process.env[name];
  if (envVal) {
    console.log(`DEBUG: Found ${name} in process.env.`);
  }
  
  return envVal;
}

// Updated Helper to resolve env variables from all possible sources
export function getMpesaEnv(c: any): MpesaEnv {
  const hEnv = env<MpesaEnv>(c)
  return {
    MPESA_CONSUMER_KEY: hEnv.MPESA_CONSUMER_KEY || getSecret('MPESA_CONSUMER_KEY'),
    MPESA_CONSUMER_SECRET: hEnv.MPESA_CONSUMER_SECRET || getSecret('MPESA_CONSUMER_SECRET'),
    MPESA_SHORTCODE: hEnv.MPESA_SHORTCODE || getSecret('MPESA_SHORTCODE'),
    MPESA_PASSKEY: hEnv.MPESA_PASSKEY || getSecret('MPESA_PASSKEY'),
    MPESA_ENV: hEnv.MPESA_ENV || getSecret('MPESA_ENV'),
    MPESA_CALLBACK_URL: hEnv.MPESA_CALLBACK_URL || getSecret('MPESA_CALLBACK_URL'),
  }
}

const SANDBOX_BASE = 'https://sandbox.safaricom.co.ke'
const PROD_BASE = 'https://api.safaricom.co.ke'

export function mpesaConfigured(env: MpesaEnv): boolean {
  return !!(env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_SHORTCODE && env.MPESA_PASSKEY)
}

// Production is the default. Only fall back to the sandbox host when the
// operator has EXPLICITLY opted in via MPESA_ENV=sandbox|development|test.
// On Render (where live credentials are configured) this means the platform
// talks to the live Daraja API without needing MPESA_ENV to be set at all.
function isSandbox(envValue?: string): boolean {
  const v = String(envValue || '').trim().toLowerCase()
  return v === 'sandbox' || v === 'development' || v === 'dev' || v === 'test'
}

function baseUrl(env: MpesaEnv): string {
  return isSandbox(env.MPESA_ENV) ? SANDBOX_BASE : PROD_BASE
}

function timestamp(): string {
  const now = new Date(Date.now() + 3 * 3600 * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}${p(now.getUTCHours())}${p(now.getUTCMinutes())}${p(now.getUTCSeconds())}`
}

function b64(s: string): string { return btoa(s) }

export function normalizePhone(phone: string): string {
  let p = String(phone || '').replace(/[^0-9]/g, '')
  if (p.startsWith('0')) p = '254' + p.slice(1)
  if (p.startsWith('7') && p.length === 9) p = '254' + p
  if (p.startsWith('2540')) p = '254' + p.slice(4)
  return p
}

async function getToken(env: MpesaEnv): Promise<string> {
  const auth = b64(`${env.MPESA_CONSUMER_KEY}:${env.MPESA_CONSUMER_SECRET}`)
  const res = await fetch(`${baseUrl(env)}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  })
  if (!res.ok) throw new Error('Failed to obtain M-Pesa token: ' + res.status)
  const data: any = await res.json()
  return data.access_token
}

export type StkResult = {
  simulated: boolean
  success: boolean
  checkout_request_id?: string
  merchant_request_id?: string
  customer_message?: string
  error?: string
}

export async function stkPush(env: MpesaEnv, opts: { phone: string; amount: number; account: string; description: string }): Promise<StkResult> {
  if (!mpesaConfigured(env)) {
    console.log("DEBUG: mpesaConfigured returned FALSE. Simulation mode active.");
    return {
      simulated: true,
      success: true,
      checkout_request_id: 'ws_CO_SIM_' + crypto.randomUUID().slice(0, 12),
      merchant_request_id: 'SIM_' + crypto.randomUUID().slice(0, 8),
      customer_message: 'Simulated STK push sent. (Credentials not detected.)'
    }
  }
  try {
    const token = await getToken(env)
    const ts = timestamp()
    const password = b64(`${env.MPESA_SHORTCODE}${env.MPESA_PASSKEY}${ts}`)
    const phone = normalizePhone(opts.phone)
    const body = {
      BusinessShortCode: env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: ts,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.max(1, Math.round(opts.amount)),
      PartyA: phone,
      PartyB: env.MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: env.MPESA_CALLBACK_URL || 'https://example.com/api/mpesa/callback',
      AccountReference: opts.account.slice(0, 12),
      TransactionDesc: opts.description.slice(0, 13)
    }
    const res = await fetch(`${baseUrl(env)}/mpesa/stkpush/v1/processrequest`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    const data: any = await res.json()
    if (data.ResponseCode === '0') {
      return {
        simulated: false,
        success: true,
        checkout_request_id: data.CheckoutRequestID,
        merchant_request_id: data.MerchantRequestID,
        customer_message: data.CustomerMessage || 'STK push sent.'
      }
    }
    return { simulated: false, success: false, error: data.errorMessage || data.ResponseDescription || 'STK push failed' }
  } catch (e: any) {
    return { simulated: false, success: false, error: e.message || 'M-Pesa request failed' }
  }
}

export async function stkQuery(env: MpesaEnv, checkoutRequestId: string): Promise<any> {
  if (!mpesaConfigured(env)) return { ResultCode: '0', ResultDesc: 'Simulated success' }
  const token = await getToken(env)
  const ts = timestamp()
  const password = b64(`${env.MPESA_SHORTCODE}${env.MPESA_PASSKEY}${ts}`)
  const res = await fetch(`${baseUrl(env)}/mpesa/stkpushquery/v1/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ BusinessShortCode: env.MPESA_SHORTCODE, Password: password, Timestamp: ts, CheckoutRequestID: checkoutRequestId })
  })
  return await res.json()
}
