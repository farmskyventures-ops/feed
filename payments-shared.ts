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

export { hmacSha256Hex }
