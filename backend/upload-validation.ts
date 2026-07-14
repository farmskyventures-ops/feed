// =====================================================================
// Server-side upload & input validation (defence-in-depth)
// =====================================================================
// The frontend performs first-line checks, but a hostile client can bypass
// the browser entirely and POST arbitrary JSON. Every route that accepts a
// user-supplied image or free-text field therefore re-validates here.
//
// Design goals:
//   1. Images must be UPLOADED files, delivered as a `data:image/...;base64,`
//      URL of an ALLOWED raster type — NEVER an external http(s) link (which
//      could point at a phishing / malware host or an unverified resource).
//   2. The base64 payload must decode and begin with the correct magic bytes
//      for its declared type, so a script/HTML file renamed as an image is
//      rejected before it is ever stored or re-served.
//   3. Free-text fields are length-capped and screened for classic injection
//      payloads (SQL meta-sequences, <script>, control chars). We ALWAYS use
//      parameterized queries, so this is belt-and-braces, not the sole guard.
// =====================================================================

// Allowed raster image MIME types for user uploads.
const ALLOWED_IMAGE_MIME = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif']
// Max decoded image size (5 MB). base64 inflates ~33%, so the string may be larger.
const MAX_IMAGE_BYTES = 5 * 1024 * 1024
const MAX_DATA_URL_CHARS = Math.ceil((MAX_IMAGE_BYTES * 4) / 3) + 128

export interface ImageValidationResult {
  ok: boolean
  error?: string
}

// Decode a small prefix of base64 to raw bytes for magic-byte sniffing. Works
// in both the Workers runtime (atob) and Node (Buffer).
function decodePrefix(b64: string, bytes: number): Uint8Array {
  const slice = b64.slice(0, Math.ceil((bytes * 4) / 3))
  try {
    if (typeof atob === 'function') {
      const bin = atob(slice)
      const out = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
      return out
    }
  } catch { /* fall through */ }
  try {
    // @ts-ignore - Buffer exists under Node
    return new Uint8Array(Buffer.from(slice, 'base64'))
  } catch {
    return new Uint8Array()
  }
}

function magicMatches(mime: string, bytes: Uint8Array): boolean {
  const hex = Array.from(bytes.slice(0, 12)).map((b) => b.toString(16).padStart(2, '0')).join('')
  const m = mime.toLowerCase()
  if (m === 'image/png') return hex.startsWith('89504e47')
  if (m === 'image/jpeg' || m === 'image/jpg') return hex.startsWith('ffd8ff')
  if (m === 'image/gif') return hex.startsWith('474946383') // GIF87a / GIF89a
  if (m === 'image/webp') {
    return bytes.length >= 12 &&
      String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) === 'RIFF' &&
      String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]) === 'WEBP'
  }
  return false
}

/**
 * Validate a user-supplied profile / KYC image. Accepts ONLY a base64 data URL
 * of an allowed raster type whose payload matches the declared magic bytes.
 * Explicitly rejects http(s):// and other external links.
 */
export function validateImageDataUrl(value: unknown, opts: { allowEmpty?: boolean } = {}): ImageValidationResult {
  if (value === null || value === undefined || value === '') {
    return opts.allowEmpty ? { ok: true } : { ok: false, error: 'An image is required.' }
  }
  if (typeof value !== 'string') return { ok: false, error: 'Invalid image value.' }
  const v = value.trim()

  // Reject any external / remote link outright — pictures must be uploaded.
  if (/^(https?:|ftp:|\/\/|data:(?!image\/))/i.test(v)) {
    return { ok: false, error: 'Links are not accepted — please upload an image file (PNG, JPEG, WEBP or GIF).' }
  }

  const m = v.match(/^data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)$/i)
  if (!m) return { ok: false, error: 'Please upload a valid image file (PNG, JPEG, WEBP or GIF).' }

  const mime = m[1].toLowerCase()
  if (!ALLOWED_IMAGE_MIME.includes(mime)) {
    return { ok: false, error: 'Only PNG, JPEG, WEBP or GIF images are allowed.' }
  }
  if (v.length > MAX_DATA_URL_CHARS) {
    return { ok: false, error: 'Image is too large (max 5 MB).' }
  }
  const b64 = m[2].replace(/\s+/g, '')
  if (!b64 || b64.length % 4 !== 0) return { ok: false, error: 'The image data is corrupt.' }

  const bytes = decodePrefix(b64, 12)
  if (bytes.length < 4 || !magicMatches(mime, bytes)) {
    return { ok: false, error: 'That file is not a valid image.' }
  }
  return { ok: true }
}

// Patterns that strongly indicate an injection / code payload rather than a
// legitimate name / address / note. Used as a screen for free-text fields.
const INJECTION_PATTERNS: RegExp[] = [
  /<\s*script\b/i,                                   // <script>
  /<\s*\/?\s*(iframe|object|embed|svg|img|body|link|meta)\b/i,
  /\bon\w+\s*=\s*["']?/i,                             // onerror= onclick= ...
  /javascript\s*:/i,
  /\bunion\b[\s\S]*\bselect\b/i,                     // UNION SELECT
  /\b(select|insert|update|delete|drop|alter|truncate|create)\b[\s\S]*\b(from|into|table|database)\b/i,
  /(--|#)\s*$/,                                       // trailing SQL comment
  /\/\*[\s\S]*\*\//,                                 // block comment
  /;\s*(drop|delete|update|insert|alter|truncate)\b/i,
  /\bor\b\s+\d+\s*=\s*\d+/i,                          // OR 1=1
  /\bxp_cmdshell\b/i,
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/          // control chars
]

export interface TextValidationResult {
  ok: boolean
  error?: string
}

/**
 * Screen a free-text field for length and injection payloads. Returns not-ok
 * with a friendly message when the value looks like code / an attack string.
 */
export function validateText(value: unknown, opts: { field?: string; max?: number; allowEmpty?: boolean } = {}): TextValidationResult {
  const field = opts.field || 'This field'
  const max = opts.max ?? 2000
  if (value === null || value === undefined || value === '') {
    return opts.allowEmpty === false ? { ok: false, error: `${field} is required.` } : { ok: true }
  }
  if (typeof value !== 'string') return { ok: true } // non-strings handled by their own coercion
  if (value.length > max) return { ok: false, error: `${field} is too long (max ${max} characters).` }
  for (const re of INJECTION_PATTERNS) {
    if (re.test(value)) return { ok: false, error: `${field} contains characters or content that are not allowed.` }
  }
  return { ok: true }
}

/**
 * Validate several text fields at once. Returns the first failure, or ok.
 */
export function validateTextFields(
  obj: Record<string, unknown>,
  fields: Array<{ key: string; label?: string; max?: number }>
): TextValidationResult {
  for (const f of fields) {
    if (obj[f.key] === undefined) continue
    const r = validateText(obj[f.key], { field: f.label || f.key, max: f.max })
    if (!r.ok) return r
  }
  return { ok: true }
}
