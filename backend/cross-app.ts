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

// Short-lived by design. Tightened from 2 min to 60 s so an intercepted handoff
// URL has a much smaller replay window (anti-hijack guardrail). Legacy tokens
// that were minted before this change still verify against the 2-min window via
// LEGACY_HANDOFF_TTL_MS below, so tightening the mint TTL is non-breaking.
const HANDOFF_TTL_MS = 60 * 1000
const LEGACY_HANDOFF_TTL_MS = 2 * 60 * 1000

/** Stable fingerprint of the requesting client (IP + User-Agent), lower-cased
 *  and trimmed. Bound into the token at mint time and re-checked at verify time
 *  so a token stolen from one client cannot be replayed from another. */
export function handoffClientFingerprint(ip?: string | null, userAgent?: string | null): string {
  const cleanIp = String(ip || '').split(',')[0].trim().toLowerCase()
  const cleanUa = String(userAgent || '').trim().slice(0, 256)
  return `${cleanIp}|${cleanUa}`
}

async function fingerprintHash(secret: string, fp: string): Promise<string> {
  // HMAC the fingerprint so the raw IP/UA is never exposed in the token body.
  return (await hmacSha256Hex(secret, `fp:${fp}`)).slice(0, 32)
}

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function unb64url(s: string): string {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return atob(s)
}

/**
 * Mint a signed handoff token for the given phone (+ optional identity).
 *
 * SOURCE OF TRUTH: the Equipment Admin Portal is the authoritative place where
 * Super Admins are configured. When a Super Admin hands off to a sibling app
 * (e.g. Score / Equipment), we carry the ORIGINATING role + a `super_admin`
 * boolean in the HMAC-signed payload. Because the payload is signed with the
 * shared secret, only a holder of that secret can assert this — so the sibling
 * app can safely trust it and grant the SAME Super-Admin privileges WITHOUT a
 * second login / re-config.
 */
export async function mintHandoffToken(
  secret: string,
  phone: string,
  extra?: {
    email?: string | null
    name?: string | null
    role?: string | null
    super_admin?: boolean
    /** Optional client fingerprint (IP + User-Agent) to bind the token to the
     *  requesting browser — see handoffClientFingerprint(). When supplied, the
     *  sibling app must present a matching fingerprint at verify time. */
    fingerprint?: string | null
  },
): Promise<string> {
  const fpHash = extra?.fingerprint ? await fingerprintHash(secret, extra.fingerprint) : undefined
  const payload = JSON.stringify({
    phone,
    email: extra?.email || undefined,   // carried so email-keyed apps (Score) can resolve the user
    name: extra?.name || undefined,
    role: extra?.role || undefined,     // originating role, e.g. super_admin / admin
    super_admin: extra?.super_admin ? true : undefined, // authoritative Super-Admin assertion
    fp: fpHash,                          // anti-hijack: IP+UA binding (HMAC'd; optional)
    ts: Date.now(),
    nonce: crypto.randomUUID(),
  })
  const body = b64url(payload)
  const sig = await hmacSha256Hex(secret, body)
  return `${body}.${sig}`
}

/**
 * Verify a handoff token; returns the phone (+ email/name/role/super_admin) if
 * valid & fresh.
 *
 * @param expectedFingerprint  Optional client fingerprint (IP + User-Agent) of
 *   the browser presenting the token — see handoffClientFingerprint(). When the
 *   token was minted WITH a fingerprint, verification REQUIRES a match (replay
 *   from a different client is rejected). Tokens minted WITHOUT a fingerprint
 *   (legacy) skip this check, so the guard is fully backward-compatible.
 */
export async function verifyHandoffToken(
  secret: string,
  token: string,
  expectedFingerprint?: string | null,
): Promise<{ ok: boolean; phone?: string; email?: string; name?: string; role?: string; super_admin?: boolean; error?: string }> {
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
  // Fingerprinted tokens use the tight 60 s window; legacy (un-fingerprinted)
  // tokens keep the historical 2 min window so in-flight sessions never break.
  const ttl = payload.fp ? HANDOFF_TTL_MS : LEGACY_HANDOFF_TTL_MS
  if (Math.abs(Date.now() - Number(payload.ts)) > ttl) return { ok: false, error: 'Token expired' }
  // Anti-hijack: if the token carries a fingerprint, the presenting client must
  // match it. A missing expectedFingerprint on a bound token is a hard fail.
  if (payload.fp) {
    if (!expectedFingerprint) return { ok: false, error: 'Client verification required' }
    const presented = await fingerprintHash(secret, expectedFingerprint)
    if (presented.length !== String(payload.fp).length) return { ok: false, error: 'Client mismatch' }
    let fdiff = 0
    for (let i = 0; i < presented.length; i++) fdiff |= presented.charCodeAt(i) ^ String(payload.fp).charCodeAt(i)
    if (fdiff !== 0) return { ok: false, error: 'Client mismatch' }
  }
  return {
    ok: true,
    phone: String(payload.phone),
    email: payload.email ? String(payload.email) : undefined,
    name: payload.name ? String(payload.name) : undefined,
    role: payload.role ? String(payload.role) : undefined,
    super_admin: payload.super_admin === true,
  }
}
