// =====================================================================
// Shared payment-gateway helpers (HMAC signing / verifying)
//
// This file is intentionally tiny so the three marketplace apps
// (equipment / feed / input) can copy it verbatim and use the SAME
// signing scheme when calling the central gateway.
// =====================================================================

const encoder = new TextEncoder()

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  )
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message))
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Builds the canonical string that gets HMAC-signed.
 *
 * Format:   client_key\ntimestamp\nnonce\nbody
 *
 * - client_key : 'equipment' | 'feed' | 'input'
 * - timestamp  : Unix milliseconds (string)
 * - nonce      : random per-request UUID; rejected if re-used within window
 * - body       : raw JSON string of the request body (NOT re-stringified)
 */
export function canonicalString(client_key: string, timestamp: string, nonce: string, body: string): string {
  return `${client_key}\n${timestamp}\n${nonce}\n${body}`
}

export async function signRequest(secret: string, client_key: string, body: string): Promise<{ timestamp: string; nonce: string; signature: string }> {
  const timestamp = String(Date.now())
  const nonce = crypto.randomUUID()
  const signature = await hmacSha256Hex(secret, canonicalString(client_key, timestamp, nonce, body))
  return { timestamp, nonce, signature }
}

export async function verifySignature(
  secret: string,
  client_key: string,
  timestamp: string,
  nonce: string,
  body: string,
  providedSignature: string,
  maxSkewMs = 5 * 60 * 1000   // reject requests >5 min old (replay window)
): Promise<{ ok: boolean; error?: string }> {
  if (!secret || !client_key || !timestamp || !nonce || !providedSignature) {
    return { ok: false, error: 'Missing signature material' }
  }
  const ts = Number(timestamp)
  if (!Number.isFinite(ts)) return { ok: false, error: 'Invalid timestamp' }
  if (Math.abs(Date.now() - ts) > maxSkewMs) return { ok: false, error: 'Request timestamp outside allowed window' }

  const expected = await hmacSha256Hex(secret, canonicalString(client_key, timestamp, nonce, body))
  // Constant-time-ish comparison
  if (expected.length !== providedSignature.length) return { ok: false, error: 'Signature mismatch' }
  let diff = 0
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ providedSignature.charCodeAt(i)
  }
  if (diff !== 0) return { ok: false, error: 'Signature mismatch' }
  return { ok: true }
}

/**
 * Verify against SEVERAL candidate secrets, succeeding if ANY of them matches.
 *
 * Why: a client tenant (e.g. Score) and this gateway each resolve their HMAC
 * secret from an ORDERED list of environment variables. If the two deployments
 * disagree on which env var is populated (e.g. Score signs with
 * PAYMENT_HMAC_SECRET while the gateway registered the tenant from the shared
 * CROSS_APP_HMAC_SECRET), a single-secret check throws a spurious "Signature
 * mismatch" even though both are legitimately configured for the SAME channel.
 * Trying every legitimately-configured secret for this tenant closes that gap
 * WITHOUT weakening security (all candidates are operator-provisioned secrets
 * for exactly this client_key). Timestamp/replay window is still enforced once.
 *
 * Returns `matchedIndex` so the caller can log (WITHOUT the secret value) which
 * candidate matched — a fast, safe signal for diagnosing precedence drift.
 */
export async function verifySignatureMulti(
  secrets: Array<string | null | undefined>,
  client_key: string,
  timestamp: string,
  nonce: string,
  body: string,
  providedSignature: string,
  maxSkewMs = 5 * 60 * 1000
): Promise<{ ok: boolean; error?: string; matchedIndex?: number }> {
  const candidates = Array.from(new Set((secrets || []).map((s) => String(s || '').trim()).filter(Boolean)))
  if (!candidates.length || !client_key || !timestamp || !nonce || !providedSignature) {
    return { ok: false, error: 'Missing signature material' }
  }
  const ts = Number(timestamp)
  if (!Number.isFinite(ts)) return { ok: false, error: 'Invalid timestamp' }
  if (Math.abs(Date.now() - ts) > maxSkewMs) return { ok: false, error: 'Request timestamp outside allowed window' }

  for (let idx = 0; idx < candidates.length; idx++) {
    const expected = await hmacSha256Hex(candidates[idx], canonicalString(client_key, timestamp, nonce, body))
    if (expected.length !== providedSignature.length) continue
    let diff = 0
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ providedSignature.charCodeAt(i)
    if (diff === 0) return { ok: true, matchedIndex: idx }
  }
  return { ok: false, error: 'Signature mismatch' }
}

export { hmacSha256Hex }
