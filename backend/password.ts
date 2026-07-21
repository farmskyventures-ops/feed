// =====================================================================
// Password hashing — PBKDF2-SHA256 via WebCrypto
// ---------------------------------------------------------------------
// Works identically on Node (>=18) and Cloudflare Workers (globalThis.crypto).
// Format stored in DB:  pbkdf2$<iterations>$<saltB64>$<hashB64>
//
// Legacy rows created before hashing was introduced hold the plaintext
// password. verifyPassword() transparently accepts a legacy plaintext match
// so existing/seeded accounts keep working, and the caller can opportunistically
// re-hash on next successful login (upgrade-on-login).
// =====================================================================

// =====================================================================
// Phase 4 — standardized, env-driven hashing parameters.
// These env vars MUST be set to the SAME values in both the Equipment
// and Feed apps so a password hashed by one verifies on the other:
//   AUTH_HASH_ITERATIONS  (default 210000)  PBKDF2 rounds / "salt rounds"
//   AUTH_HASH_KEYLEN      (default 32)       derived key length in bytes
//   AUTH_PEPPER           (default '')       server-side secret appended to
//                                            every password before hashing.
// Reading process.env keeps Node + Workers behaviour identical (Workers
// injects vars onto globalThis; process may be undefined there).
// =====================================================================
function envNum(name: string, dflt: number): number {
  try {
    const v = (typeof process !== 'undefined' && process.env) ? process.env[name] : (globalThis as any)?.[name]
    const n = Number(v)
    return Number.isFinite(n) && n > 0 ? n : dflt
  } catch { return dflt }
}
function envStr(name: string, dflt: string): string {
  try {
    const v = (typeof process !== 'undefined' && process.env) ? process.env[name] : (globalThis as any)?.[name]
    return (v == null || v === '') ? dflt : String(v)
  } catch { return dflt }
}

const ITERATIONS = envNum('AUTH_HASH_ITERATIONS', 210_000)  // OWASP 2023 guidance for PBKDF2-SHA256
const KEYLEN = envNum('AUTH_HASH_KEYLEN', 32)               // 256-bit derived key
const PEPPER = envStr('AUTH_PEPPER', '')                    // shared server-side secret (both apps)
const PREFIX = 'pbkdf2'

const enc = new TextEncoder()

/** Apply the shared server-side pepper before deriving/verifying. */
function withPepper(password: string): string {
  return PEPPER ? `${password}${PEPPER}` : password
}

function toB64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  // btoa is available on both Node 18+ and Workers
  return btoa(bin)
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    KEYLEN * 8
  )
  return new Uint8Array(bits)
}

/** True if a stored value is already in the hashed format (not plaintext). */
export function isHashed(stored: string | null | undefined): boolean {
  return typeof stored === 'string' && stored.startsWith(PREFIX + '$')
}

/** Produce a salted PBKDF2 hash string for storage. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const hash = await derive(withPepper(String(password)), salt, ITERATIONS)
  return `${PREFIX}$${ITERATIONS}$${toB64(salt)}$${toB64(hash)}`
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * Verify a plaintext password against a stored value.
 * Accepts both the hashed format and a legacy plaintext value (for seeded /
 * pre-migration accounts). Returns { ok, legacy } where legacy=true means the
 * stored value was plaintext and the caller SHOULD re-hash it.
 */
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<{ ok: boolean; legacy: boolean }> {
  if (stored == null) return { ok: false, legacy: false }
  const pw = String(password)
  if (isHashed(stored)) {
    const parts = stored.split('$')
    if (parts.length !== 4) return { ok: false, legacy: false }
    const iterations = Number(parts[1]) || ITERATIONS
    const salt = fromB64(parts[2])
    const expected = fromB64(parts[3])
    const actual = await derive(withPepper(pw), salt, iterations)
    return { ok: timingSafeEqual(actual, expected), legacy: false }
  }
  // Legacy plaintext comparison (constant-time-ish on the bytes).
  const a = enc.encode(pw)
  const b = enc.encode(String(stored))
  return { ok: timingSafeEqual(a, b), legacy: true }
}
