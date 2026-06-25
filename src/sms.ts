// =====================================================================
// SMS provider for OTP delivery.
// ---------------------------------------------------------------------
// Primary provider: TALKSASA Bulk SMS (https://talksasa.com) using a
// Safaricom-registered Sender Name (NameID). It also supports any
// generic Bearer-token SMS gateway as a fallback.
//
// Configure entirely with environment variables (paste your API token +
// sender id at deploy time) — no code changes needed.
//
// If SMS is NOT configured, the app runs in DEMO mode: the OTP is
// returned to the screen so the flows remain fully testable.
//
// Env vars:
//   SMS_PROVIDER         "talksasa" (default) | "generic"
//   SMS_API_URL          send-SMS endpoint. For TalkSASA the default is
//                        https://bulksms.talksasa.com/api/v3/sms/send
//   SMS_API_TOKEN        API token / Bearer token from your provider
//   SMS_SENDER_ID        the Sender Name (NameID) registered with
//                        Safaricom (e.g. "FARMSKY"), max 11 chars
//   --- generic provider only (ignored for talksasa) ---
//   SMS_BODY_TEMPLATE    optional JSON template; placeholders {phone}
//                        {message} {sender}. Defaults to a common shape.
//   SMS_PHONE_FIELD      field name for the phone (default "to")
//   SMS_MESSAGE_FIELD    field name for the text  (default "message")
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

// SMS is "configured" (live) when we have a token AND a usable endpoint.
// For TalkSASA the endpoint defaults automatically, so just a token is
// enough; the generic provider also needs SMS_API_URL.
export function smsConfigured(env: SmsEnv): boolean {
  return !!(env.SMS_API_TOKEN && smsUrl(env))
}

export type SmsResult = { simulated: boolean; success: boolean; error?: string }

// E.164 with leading + for TalkSASA recipients (e.g. +2547XXXXXXXX)
function toE164(phone: string): string {
  const digits = String(phone || '').replace(/[^0-9]/g, '')
  return digits ? '+' + digits : ''
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
      // TalkSASA v3 SMS send shape
      body = {
        recipient: toE164(phone),
        sender_id: env.SMS_SENDER_ID || 'FARMSKY',
        type: 'plain',
        message
      }
    } else if (env.SMS_BODY_TEMPLATE) {
      // Fully custom JSON template with {phone}/{message}/{sender}
      const filled = env.SMS_BODY_TEMPLATE
        .replace(/\{phone\}/g, phone)
        .replace(/\{message\}/g, message.replace(/"/g, '\\"'))
        .replace(/\{sender\}/g, env.SMS_SENDER_ID || '')
      body = JSON.parse(filled)
    } else {
      // Sensible generic default shape; field names overridable via env.
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
    // TalkSASA returns { status: "success" | "error", message: ... }
    if (provider === 'talksasa') {
      try {
        const j = JSON.parse(txt)
        if (j && j.status && String(j.status).toLowerCase() !== 'success') {
          return { simulated: false, success: false, error: j.message || 'TalkSASA rejected the message' }
        }
      } catch { /* non-JSON 2xx — treat as success */ }
    }
    return { simulated: false, success: true }
  } catch (e: any) {
    return { simulated: false, success: false, error: e?.message || 'SMS send failed' }
  }
}

// 6-digit numeric OTP
export function generateOtp(): string {
  return String(Math.floor(100000 + Math.random() * 900000))
}
