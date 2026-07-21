// =====================================================================
// Cross-platform SSO handoff  (Phase 2)
// ---------------------------------------------------------------------
// Lets a user signed into one app open the sibling app ("Shop Equipment"
// from Feed, "Shop Feeds" from Equipment) WITHOUT logging in again.
//
// Flow:
//   1. Feed  GET /api/cross/handoff?target=equipment
//      -> Feed mints an HMAC-SHA256 token = base64({phone,ts,nonce}) + "." + sig
//         signed with the SHARED CROSS_APP_HMAC_SECRET, and returns the
//         sibling URL with the token: {CROSS_APP_URL}/sso?token=...
//   2. Browser navigates there. Equipment GET /sso?token=... verifies the
//      HMAC + freshness, looks up the user by NORMALIZED phone, and if the
//      account exists issues a local session cookie, then redirects to '/'.
//
// The token never carries a password; it is a short-lived (2 min) signed
// assertion "the bearer proved they are <phone> on the sibling app".
// =====================================================================

import { hmacSha256Hex } from './payment-gateway-shared'

const HANDOFF_TTL_MS = 2 * 60 * 1000

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function unb64url(s: string): string {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return atob(s)
}

/** Mint a signed handoff token for the given phone. */
export async function mintHandoffToken(secret: string, phone: string): Promise<string> {
  const payload = JSON.stringify({ phone, ts: Date.now(), nonce: crypto.randomUUID() })
  const body = b64url(payload)
  const sig = await hmacSha256Hex(secret, body)
  return `${body}.${sig}`
}

/** Verify a handoff token; returns the phone if valid & fresh. */
export async function verifyHandoffToken(secret: string, token: string): Promise<{ ok: boolean; phone?: string; error?: string }> {
  if (!secret) return { ok: false, error: 'Cross-app SSO not configured' }
  const [body, sig] = String(token || '').split('.')
  if (!body || !sig) return { ok: false, error: 'Malformed token' }
  const expected = await hmacSha256Hex(secret, body)
  if (expected.length !== sig.length) return { ok: false, error: 'Signature mismatch' }
  let diff = 0
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i)
  if (diff !== 0) return { ok: false, error: 'Signature mismatch' }
  let payload: any
  try { payload = JSON.parse(unb64url(body)) } catch { return { ok: false, error: 'Bad payload' } }
  if (!payload.phone || !payload.ts) return { ok: false, error: 'Incomplete token' }
  if (Math.abs(Date.now() - Number(payload.ts)) > HANDOFF_TTL_MS) return { ok: false, error: 'Token expired' }
  return { ok: true, phone: String(payload.phone) }
}
