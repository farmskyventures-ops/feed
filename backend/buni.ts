// =====================================================================
// KCB Buni API integration
// =====================================================================

export type BuniEnv = {
  BUNI_CLIENT_ID?: string
  BUNI_CLIENT_SECRET?: string
  BUNI_API_KEY?: string
  BUNI_ENV?: string 
}

const SANDBOX_BASE = 'https://uat.buni.kcbgroup.com'
const PROD_BASE = 'https://api.buni.kcbgroup.com'

// Production is the default; only use the UAT/sandbox host when explicitly
// opted in via BUNI_ENV=sandbox|development|test.
function isSandbox(envValue?: string): boolean {
  const v = String(envValue || '').trim().toLowerCase()
  return v === 'sandbox' || v === 'development' || v === 'dev' || v === 'test' || v === 'uat'
}
function baseUrl(env: BuniEnv): string {
  return isSandbox(env.BUNI_ENV) ? SANDBOX_BASE : PROD_BASE
}

export function buniConfigured(env: BuniEnv): boolean {
  return !!(env.BUNI_CLIENT_ID && env.BUNI_CLIENT_SECRET && env.BUNI_API_KEY)
}

async function getToken(env: BuniEnv): Promise<string> {
  const auth = btoa(`${env.BUNI_CLIENT_ID}:${env.BUNI_CLIENT_SECRET}`)
  const res = await fetch(`${baseUrl(env)}/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  })
  if (!res.ok) throw new Error(`KCB Buni Auth Failed`)
  const data: any = await res.json()
  return data.access_token
}

// --- ADDED FUNCTIONS TO FIX BUILD ERRORS ---

export async function buniStkPush(env: BuniEnv, opts: { phone: string, amount: number, account: string, description: string }) {
  if (!buniConfigured(env)) return { success: true, checkout_request_id: 'BUNI_SIM_' + Date.now() }
  
  const token = await getToken(env)
  // Update the path below to match the MpesaExpressAPIService endpoint shown in your portal
  const res = await fetch(`${baseUrl(env)}/mm/api/request`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'apikey': env.BUNI_API_KEY!
    },
    body: JSON.stringify({
      phoneNumber: opts.phone,
      amount: opts.amount,
      accountReference: opts.account,
      transactionDesc: opts.description
    })
  })
  const data = await res.json()
  return { success: res.ok, checkout_request_id: data.CheckoutRequestID || data.merchantRequestId }
}

export async function buniQuery(env: BuniEnv, checkoutRequestId: string) {
  const token = await getToken(env)
  // Update the path below to the appropriate KCB query endpoint
  const res = await fetch(`${baseUrl(env)}/mm/api/query?requestId=${checkoutRequestId}`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': env.BUNI_API_KEY! }
  })
  return await res.json()
}

// Existing function
export async function buniFundsTransfer(env: BuniEnv, payload: any) {
  const token = await getToken(env)
  const res = await fetch(`${baseUrl(env)}/api/v1/transfer`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'apikey': env.BUNI_API_KEY || ''
    },
    body: JSON.stringify(payload)
  })
  return await res.json()
}
