// =====================================================================
// Email provider for the "share export to email" feature.
// ---------------------------------------------------------------------
// Primary provider: RESEND (https://resend.com). Also supports SendGrid
// and any generic Bearer-token JSON email API.
//
// Configure entirely with env vars; if not configured the UI offers a
// local download instead.
//
// Env vars:
//   EMAIL_PROVIDER       "resend" (default) | "sendgrid" | "generic"
//   EMAIL_API_URL        send endpoint. For Resend the default is
//                        https://api.resend.com/emails
//   EMAIL_API_TOKEN      API key / Bearer token (Resend: re_xxx...)
//   EMAIL_FROM           verified from address. Friendly name allowed:
//                        "Farmsky <no-reply@yourdomain.com>"
// =====================================================================

export type EmailEnv = {
  EMAIL_PROVIDER?: string
  EMAIL_API_URL?: string
  EMAIL_API_TOKEN?: string
  EMAIL_FROM?: string
}

const RESEND_DEFAULT_URL = 'https://api.resend.com/emails'

function emailProvider(env: EmailEnv): string {
  return (env.EMAIL_PROVIDER || 'resend').toLowerCase()
}

function emailUrl(env: EmailEnv): string {
  if (env.EMAIL_API_URL) return env.EMAIL_API_URL
  if (emailProvider(env) === 'resend') return RESEND_DEFAULT_URL
  return ''
}

export function emailConfigured(env: EmailEnv): boolean {
  return !!(env.EMAIL_API_TOKEN && env.EMAIL_FROM && emailUrl(env))
}

export type Attachment = { filename: string; contentBase64: string; contentType: string }
export type EmailResult = { configured: boolean; success: boolean; error?: string }

export async function sendEmail(
  env: EmailEnv,
  opts: { to: string; subject: string; text: string; attachments?: Attachment[] }
): Promise<EmailResult> {
  if (!emailConfigured(env)) return { configured: false, success: false }
  const provider = emailProvider(env)
  const url = emailUrl(env)
  try {
    let body: any
    if (provider === 'sendgrid') {
      body = {
        personalizations: [{ to: [{ email: opts.to }] }],
        from: { email: env.EMAIL_FROM },
        subject: opts.subject,
        content: [{ type: 'text/plain', value: opts.text }],
        attachments: (opts.attachments || []).map((a) => ({
          filename: a.filename, type: a.contentType, content: a.contentBase64, disposition: 'attachment'
        }))
      }
    } else {
      // Resend (and generic) shape.
      // Resend attachments take { filename, content } where content is a
      // Base64 string. We also pass contentType for generic gateways.
      body = {
        from: env.EMAIL_FROM,
        to: opts.to,
        subject: opts.subject,
        text: opts.text,
        attachments: (opts.attachments || []).map((a) => ({
          filename: a.filename,
          content: a.contentBase64,
          contentType: a.contentType
        }))
      }
    }
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.EMAIL_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      return { configured: true, success: false, error: `Email API ${res.status}: ${txt.slice(0, 200)}` }
    }
    return { configured: true, success: true }
  } catch (e: any) {
    return { configured: true, success: false, error: e?.message || 'Email send failed' }
  }
}
