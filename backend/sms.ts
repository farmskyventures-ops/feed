// =====================================================================
// SMS provider for OTP delivery.
// ---------------------------------------------------------------------
// Primary provider: TALKSASA Bulk SMS (https://talksasa.com) using a
// Safaricom-registered Sender Name (NameID). It also supports any
// generic Bearer-token SMS gateway as a fallback.
// =====================================================================

export type SmsEnv = {
  SMS_PROVIDER?: string
  SMS_API_URL?: string
  SMS_API_TOKEN?: string
  SMS_SENDER_ID?: string
  SMS_BODY_TEMPLATE?: string
  SMS_PHONE_FIELD?: string
  SMS_MESSAGE_FIELD?: string
}

const TALKSASA_DEFAULT_URL = 'https://bulksms.talksasa.com/api/v3/sms/send'

function smsProvider(env: SmsEnv): string {
  return (env.SMS_PROVIDER || 'talksasa').toLowerCase()
}

function smsUrl(env: SmsEnv): string {
  if (env.SMS_API_URL) return env.SMS_API_URL
  if (smsProvider(env) === 'talksasa') return TALKSASA_DEFAULT_URL
  return ''
}

export function smsConfigured(env: SmsEnv): boolean {
  return !!(env.SMS_API_TOKEN && smsUrl(env))
}

export type SmsResult = { simulated: boolean; success: boolean; error?: string }

/**
 * Formats Kenyan inputs strictly into the standard +254XXXXXXXXX 
 * international format structure required by TalkSasa.
 */
function toE164(phone: string): string {
  const digits = String(phone || '').replace(/[^0-9]/g, '')
  
  if (!digits) return ''

  // Case 1: Standard local entry (e.g., 0712345678)
  if (digits.startsWith('0') && digits.length === 10) {
    return '+254' + digits.substring(1)
  }

  // Case 2: Local entry missing the zero prefix (e.g., 712345678)
  if (digits.length === 9 && (digits.startsWith('7') || digits.startsWith('1'))) {
    return '+254' + digits
  }

  // Case 3: Country code flat digit string without the plus sign (e.g., 254712345678)
  if (digits.startsWith('254') && (digits.length === 12 || digits.length === 11)) {
    return '+' + digits
  }

  return '+' + digits
}

export async function sendSms(
  env: SmsEnv,
  phone: string,
  message: string
): Promise<SmsResult> {
  if (!smsConfigured(env)) {
    return { simulated: true, success: true }
  }
  const provider = smsProvider(env)
  const url = smsUrl(env)
  try {
    let body: any
    if (provider === 'talksasa') {
      // TalkSASA v3 SMS strict production body schema
      body = {
        recipient: toE164(phone),
        sender_id: env.SMS_SENDER_ID || 'Farmsky', // Matches your exact whitelisted sender string
        type: 'plain',
        message
      }
    } else if (env.SMS_BODY_TEMPLATE) {
      const filled = env.SMS_BODY_TEMPLATE
        .replace(/\{phone\}/g, phone)
        .replace(/\{message\}/g, message.replace(/"/g, '\\"'))
        .replace(/\{sender\}/g, env.SMS_SENDER_ID || '')
      body = JSON.parse(filled)
    } else {
      const phoneField = env.SMS_PHONE_FIELD || 'to'
      const msgField = env.SMS_MESSAGE_FIELD || 'message'
      body = { [phoneField]: phone, [msgField]: message }
      if (env.SMS_SENDER_ID) body.sender = env.SMS_SENDER_ID
    }
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.SMS_API_TOKEN}`,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(body)
    })
    const txt = await res.text().catch(() => '')
    if (!res.ok) {
      return { simulated: false, success: false, error: `SMS gateway ${res.status}: ${txt.slice(0, 200)}` }
    }
    if (provider === 'talksasa') {
      try {
        const j = JSON.parse(txt)
        if (j && j.status && String(j.status).toLowerCase() !== 'success') {
          return { simulated: false, success: false, error: j.message || 'TalkSASA rejected the message' }
        }
      } catch { /* Treat non-JSON 2xx as gateway pass */ }
    }
    return { simulated: false, success: true }
  } catch (e: any) {
    return { simulated: false, success: false, error: e?.message || 'SMS send failed' }
  }
}

export function generateOtp(): string {
  return String(Math.floor(100000 + Math.random() * 900000))
}