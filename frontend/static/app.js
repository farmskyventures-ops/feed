// ============================================================================
// Farmsky - Sharia-Compliant Agri-Finance Platform - SPA frontend
// ============================================================================
const api = axios.create({ baseURL: '/api', withCredentials: true })

// Payment requests go to THIS app's own backend (same-origin, carrying the
// logged-in session cookie). Feed's server then HMAC-signs the request and
// forwards it to the central gateway on the Equipment app SERVER-SIDE. The
// browser must never call the Equipment domain directly — it has no session
// there (that returned "Unauthorized") and cannot HMAC-sign. So the payment
// client is simply the same same-origin `api` instance.
const gatewayApi = api

let state = { user: null, route: 'dashboard', data: {} }
const $ = (id) => document.getElementById(id)
// Safely set innerHTML only if the target element still exists (prevents
// "Cannot set properties of null" crashes when a modal/view was closed while
// an async task — e.g. a payment poll — was still running).
const setHTML = (id, html) => { const el = $(id); if (el) { el.innerHTML = html; return true } return false }

// Global auth/network guard. A single expired-session (401) response should
// send the user back to the login screen ONCE and silently halt the many
// in-flight polling requests, instead of flooding the console with 401s.
let _authExpired = false
api.interceptors.response.use(
  (resp) => resp,
  (error) => {
    const status = error?.response?.status
    if (status === 401) {
      // Ignore 401s from the initial /me probe and the login attempt itself.
      const url = String(error.config?.url || '')
      const isProbe = url.endsWith('/me') || url.endsWith('/login')
      if (!isProbe && state.user && !_authExpired) {
        _authExpired = true
        state.user = null
        try { if (typeof stopLive === 'function') stopLive() } catch (_) {}
        try { closeModal() } catch (_) {}
        try { toast('Your session has expired. Please sign in again.', false) } catch (_) {}
        try { renderLogin() } catch (_) {}
        setTimeout(() => { _authExpired = false }, 1500)
      }
    }
    return Promise.reject(error)
  }
)
const fmt = (n) => 'KES ' + Number(n || 0).toLocaleString()
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]))
// Friendly labels for payment types
const payLabel = (t, model) => {
  if (t === 'financing') {
    return 'Murabaha Financing <span class="text-[10px] text-slate-400">(cost-plus)</span>'
  }
  return t === 'cash'
    ? 'Cash'
    : (String(t || '').charAt(0).toUpperCase() + String(t || '').slice(1))
}

let _products = [], _agents = [], _users = [], _customers = [], _walletUsers = []
let _permMeta = { permissions: [], roles: [] }
function getRoleTemplate(role) {
  return (_permMeta.roles || []).find((r) => r.role_key === role)
}
const roleLabel = (r) => getRoleTemplate(r)?.label || ({ super_admin: 'Super Admin', admin: 'Admin', operations_finance: 'Operations & Finance', agent: 'Agent', customer: 'Farmer', support: 'Support', lender: 'Lender', investor: 'Investor', mne: 'M & E', partner: 'Partner' }[r] || r)
const permsText = (perms) => Object.entries(perms || {}).filter(([, v]) => v).map(([k]) => k.replace(/_/g, ' ')).join(', ')
async function ensurePermissionMeta() {
  if (!_permMeta.permissions.length && state.user) {
    try { _permMeta = (await api.get('/permissions')).data } catch {}
  }
  return _permMeta
}
function templatePermissions(role) {
  return { ...(getRoleTemplate(role)?.permissions || {}) }
}
function selectedPermissions(prefix) {
  const out = {}
  document.querySelectorAll(`[data-perm-group="${prefix}"]`).forEach((el) => { out[el.value] = !!el.checked })
  return out
}
function permissionChecklist(prefix, selected = {}, readOnly = false) {
  const perms = (_permMeta.permissions || []).slice().sort((a, b) => `${a.category || ''}:${a.label}`.localeCompare(`${b.category || ''}:${b.label}`))
  if (!perms.length) return '<div class="text-xs text-slate-400">No permission check-boxes available yet.</div>'
  let currentCategory = ''
  return perms.map((p) => {
    const heading = p.category !== currentCategory ? `<div class="col-span-2 text-[11px] font-bold uppercase tracking-wide text-slate-400 pt-1">${esc(p.category || 'general')}</div>` : ''
    currentCategory = p.category
    return `${heading}<label class="col-span-2 sm:col-span-1 flex items-start gap-2 border border-slate-200 rounded-lg px-3 py-2 bg-white">
      <input type="checkbox" value="${esc(p.permission_key)}" data-perm-group="${prefix}" ${selected[p.permission_key] ? 'checked' : ''} ${readOnly ? 'disabled' : ''}>
      <span><span class="block text-sm font-medium text-slate-700">${esc(p.label)}</span><span class="block text-[11px] text-slate-400">${esc(p.description || p.permission_key)}</span></span>
    </label>`
  }).join('')
}
function refreshPermissionChecklist(prefix, roleSelectId, readOnly = false) {
  const box = $(prefix + '_box')
  if (!box || !$(roleSelectId)) return
  box.innerHTML = permissionChecklist(prefix, templatePermissions($(roleSelectId).value), readOnly)
}
// Password input with a show/hide eye toggle (Instruction 4).
// Renders an <input type=password> wrapped so an eye button can flip its type.
function passwordField(id, opts = {}) {
  const { placeholder = '', required = false, cls = 'w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg', value = '' } = opts
  return `<div class="relative">
    <input id="${id}" type="password" placeholder="${esc(placeholder)}" value="${esc(value)}" ${required ? 'required' : ''} class="${cls} pr-10">
    <button type="button" onclick="togglePw('${id}',this)" tabindex="-1"
      class="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-600" aria-label="Show password">
      <i class="fas fa-eye"></i>
    </button>
  </div>`
}
window.togglePw = (id, btn) => {
  const el = document.getElementById(id); if (!el) return
  const show = el.type === 'password'
  el.type = show ? 'text' : 'password'
  const icon = btn.querySelector('i')
  if (icon) { icon.classList.toggle('fa-eye', !show); icon.classList.toggle('fa-eye-slash', show) }
  btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password')
}
const _WEEK_DAYS = [['mon', 'Mon'], ['tue', 'Tue'], ['wed', 'Wed'], ['thu', 'Thu'], ['fri', 'Fri'], ['sat', 'Sat'], ['sun', 'Sun']]
// Renders a Time-Based Access Control (login window) editor block.
function scheduleEditor(prefix, sched = {}, readOnly = false) {
  const enabled = !!sched.schedule_enabled
  const days = Array.isArray(sched.access_days) ? sched.access_days : []
  const dis = readOnly ? 'disabled' : ''
  return `<div class="border rounded-xl p-3 bg-slate-50 text-sm">
    <label class="flex items-center gap-2 mb-2"><input type="checkbox" id="${prefix}_sched_on" ${enabled ? 'checked' : ''} ${dis}><span class="font-medium">Restrict login to a time window</span></label>
    <div class="field-label">Active days</div>
    <div class="flex flex-wrap gap-2 mb-3">
      ${_WEEK_DAYS.map(([k, lbl]) => `<label class="flex items-center gap-1 text-xs border rounded-lg px-2 py-1 bg-white"><input type="checkbox" value="${k}" data-sched-day="${prefix}" ${days.includes(k) ? 'checked' : ''} ${dis}>${lbl}</label>`).join('')}
    </div>
    <div class="responsive-grid cols-2">
      <div><label class="field-label">Active from</label><input type="time" id="${prefix}_sched_start" value="${esc(sched.access_start || '09:00')}" class="px-3 py-2 border rounded-lg w-full" ${dis}></div>
      <div><label class="field-label">Active until</label><input type="time" id="${prefix}_sched_end" value="${esc(sched.access_end || '16:00')}" class="px-3 py-2 border rounded-lg w-full" ${dis}></div>
    </div>
    <div class="help-text">Access is blocked outside these days/hours (server time). Leave unchecked for 24/7 access.</div>
  </div>`
}
function collectSchedule(prefix) {
  const days = Array.from(document.querySelectorAll(`[data-sched-day="${prefix}"]:checked`)).map(el => el.value)
  return {
    schedule_enabled: !!($(prefix + '_sched_on') && $(prefix + '_sched_on').checked),
    access_days: days,
    access_start: $(prefix + '_sched_start') ? $(prefix + '_sched_start').value : '',
    access_end: $(prefix + '_sched_end') ? $(prefix + '_sched_end').value : ''
  }
}
function canDo(perm) {
  if (!state.user) return false
  if (['super_admin', 'admin'].includes(state.user.role)) return true
  return !!state.user.permissions?.[perm]
}
function boolBadge(v, yes='Yes', no='No') { return v ? `<span class="text-emerald-600">${yes}</span>` : `<span class="text-slate-400">${no}</span>` }
function toggleSidebar(force) {
  const sidebar = $('appSidebar')
  const overlay = $('appOverlay')
  if (!sidebar || !overlay) return
  const open = typeof force === 'boolean' ? force : !sidebar.classList.contains('open')
  sidebar.classList.toggle('open', open)
  overlay.classList.toggle('show', open)
}
window.toggleSidebar = toggleSidebar
function confirmEdit(message) {
  return window.confirm(message || 'Save these changes?')
}
function confirmDelete(message) {
  return window.confirm(message || 'Delete this record? This cannot be undone.')
}
function confirmStatus(message) {
  return window.confirm(message || 'Apply this status change?')
}
function previewSelectedImage(input, previewId) {
  const file = input.files?.[0]
  if (!file || !$(previewId)) return
  const reader = new FileReader()
  reader.onload = () => { $(previewId).innerHTML = `<img src="${reader.result}" class="w-full h-full object-cover">` }
  reader.readAsDataURL(file)
}
window.previewSelectedImage = previewSelectedImage

function badge(status) {
  const map = {
    active: 'bg-emerald-100 text-emerald-700', completed: 'bg-blue-100 text-blue-700',
    pending: 'bg-amber-100 text-amber-700', rejected: 'bg-red-100 text-red-700',
    current: 'bg-slate-100 text-slate-600', late: 'bg-red-100 text-red-700',
    defaulted: 'bg-red-200 text-red-800', verified: 'bg-emerald-100 text-emerald-700',
    suspended: 'bg-red-100 text-red-700',
    in_stock: 'bg-emerald-100 text-emerald-700', low_stock: 'bg-amber-100 text-amber-700',
    out_of_stock: 'bg-red-100 text-red-700', paid: 'bg-emerald-100 text-emerald-700',
    partial: 'bg-amber-100 text-amber-700', unpaid: 'bg-slate-100 text-slate-600',
    low: 'bg-emerald-100 text-emerald-700', medium: 'bg-amber-100 text-amber-700', high: 'bg-red-100 text-red-700'
  }
  return `<span class="badge ${map[status] || 'bg-slate-100 text-slate-600'}">${esc(String(status).replace(/_/g, ' '))}</span>`
}
function toast(msg, ok = true) {
  const t = document.createElement('div')
  t.className = `fixed top-4 right-4 z-50 px-5 py-3 rounded-lg shadow-lg text-white ${ok ? 'bg-emerald-600' : 'bg-red-600'} fade-in`
  t.textContent = msg
  document.body.appendChild(t)
  setTimeout(() => t.remove(), 3200)
}
window.pickFileDataUrl = (input, targetId, nameId) => {
  const file = input.files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    $(targetId).value = reader.result
    if (nameId && $(nameId)) $(nameId).textContent = file.name
  }
  reader.readAsDataURL(file)
}
window.requestChangeModal = (entityType, entityId, requestedAction = 'update') => {
  showModal(`<h3 class="font-bold mb-1">Request Admin Action</h3>
    <p class="text-xs text-slate-500 mb-3">Operations & Finance users can submit a request instead of editing or deleting directly.</p>
    <div class="space-y-3 text-sm">
      <input id="cr_action" value="${esc(requestedAction)}" class="w-full px-3 py-2 border rounded-lg">
      <textarea id="cr_reason" placeholder="Reason / instructions for admin" class="w-full px-3 py-2 border rounded-lg min-h-28"></textarea>
    </div>
    <div class="flex gap-2 mt-4">
      <button onclick="submitChangeRequest('${entityType}', ${entityId})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Submit Request</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button>
    </div>`)
}
window.submitChangeRequest = async (entityType, entityId) => {
  try {
    await api.post('/change-requests', {
      entity_type: entityType,
      entity_id: entityId,
      requested_action: $('cr_action').value,
      reason: $('cr_reason').value
    })
    closeModal(); toast('Change request submitted to admin')
  } catch (err) { toast(err.response?.data?.error || 'Failed to submit request', false) }
}
// ---------------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------------
async function init() {
  try { const { data } = await api.get('/me'); state.user = data.user; renderApp() }
  catch { renderLogin() }
}
let _authTab = 'signin'
let _smsLive = false
async function renderLogin(tab) {
  _authTab = tab || 'signin'
  try { _smsLive = (await api.get('/auth/status')).data.sms_live } catch {}
  const heading = _authTab === 'signup' ? 'Create your account'
    : _authTab === 'reset' ? 'Reset your password'
    : 'Sign in to your account'
  $('app').innerHTML = `
  <div class="min-h-screen brand-bg flex items-center justify-center p-4">
    <div class="w-full max-w-md card p-8 fade-in">
      <div class="text-center mb-5">
        <img src="/static/farmsky-logo.png" alt="Farmsky" class="w-24 h-24 mx-auto mb-1 object-contain">
        <p class="text-sm text-slate-500">Financing Agriculture</p>
      </div>
      <h2 class="text-base font-semibold text-slate-700 text-center mb-4">${heading}</h2>
      <div id="authBody"></div>
      <div id="authFooter" class="mt-6 pt-4 border-t border-slate-100 text-center text-sm space-y-2"></div>
    </div>
  </div>`
  if (_authTab === 'signin') authSignIn()
  else if (_authTab === 'signup') authSignUp()
  else authReset()
  renderAuthFooter()
}
// Sign-up + Forgot password links live at the BOTTOM of the card.
function renderAuthFooter() {
  const f = $('authFooter')
  if (!f) return
  if (_authTab === 'signin') {
    f.innerHTML = `
      <p class="text-slate-500">New to Farmsky?
        <button onclick="renderLogin('signup')" class="font-semibold text-teal-600 hover:underline">Create an account</button>
      </p>
      <p><button onclick="renderLogin('reset')" class="text-slate-400 hover:text-teal-600 hover:underline">Forgot password?</button></p>`
  } else {
    f.innerHTML = `<p><button onclick="renderLogin('signin')" class="font-semibold text-teal-600 hover:underline"><i class="fas fa-arrow-left mr-1"></i>Back to sign in</button></p>`
  }
}
function smsBanner() {
  return _smsLive
    ? '<div class="bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs rounded-lg p-2 mb-3"><i class="fas fa-comment-sms mr-1"></i>A real SMS code will be sent to your phone.</div>'
    : '<div class="bg-amber-50 border border-amber-200 text-amber-700 text-xs rounded-lg p-2 mb-3"><i class="fas fa-flask mr-1"></i>Demo mode — the SMS code is shown on screen (configure SMS provider to go live).</div>'
}
function authSignIn() {
  $('authBody').innerHTML = `
    <form id="loginForm" class="space-y-4">
      <div>
        <label class="text-sm font-medium text-slate-600">Mobile Number</label>
        <input id="phone" type="text" placeholder="07XX XXX XXX" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required>
      </div>
      <div>
        <label class="text-sm font-medium text-slate-600">Password</label>
        ${passwordField('password', { placeholder: '••••', required: true })}
      </div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold">Sign In</button>
    </form>`
  $('loginForm').onsubmit = async (e) => {
    e.preventDefault()
    try {
      const { data } = await api.post('/login', { phone: $('phone').value, password: $('password').value })
      state.user = data.user; toast('Welcome, ' + data.user.full_name); renderApp()
    } catch (err) { toast(err.response?.data?.error || 'Login failed', false) }
  }
}
// ---------------------------------------------------------------------------
// KYC helpers — gallery + camera capture for ID front, ID back, selfie
// ---------------------------------------------------------------------------
function kycFileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result)
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}
window.kycOpenPicker = (inputId) => {
  const input = $(inputId)
  if (!input) return
  input.value = ''
  input.click()
}
window.kycHandlePick = async (input, hiddenId, previewId, statusId, nextSectionId = '') => {
  const file = input?.files?.[0]
  if (!file) return
  try {
    const dataUrl = await kycFileToDataUrl(file)
    const hidden = $(hiddenId)
    const preview = $(previewId)
    const status = $(statusId)
    if (hidden) hidden.value = dataUrl
    if (preview) {
      const isSelfie = previewId.toLowerCase().includes('selfie')
      preview.innerHTML = `<img src="${dataUrl}" class="${isSelfie ? 'w-28 h-28 rounded-full' : 'w-full h-40 rounded-xl'} object-cover border border-slate-200">`
    }
    if (status) status.innerHTML = `<span class="text-emerald-600"><i class="fas fa-circle-check mr-1"></i>Captured</span>`
    if (nextSectionId && $(nextSectionId)) {
      $(nextSectionId).classList.remove('hidden')
      $(nextSectionId).scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  } catch { toast('Could not read the selected image', false) }
}
function kycStepCard({ sectionId, title, subtitle, previewId, statusId, hiddenId, galleryId, cameraId, cameraFacing = 'environment', cameraLabel = 'Open camera', nextSectionId = '', hidden = false, value = '', previewHtml = '', statusText = 'Required' }) {
  const isSelfie = previewId.toLowerCase().includes('selfie')
  // The status badge uses a filled colored background so "Required" / "Captured"
  // is clearly visible against the card, rather than faint low-contrast text.
  const isCaptured = /captured/i.test(String(statusText))
  const badgeCls = isCaptured
    ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
    : 'bg-amber-100 text-amber-800 border border-amber-300'
  return `
    <section id="${sectionId}" class="${hidden ? 'hidden ' : ''}border border-slate-200 rounded-xl p-4 bg-slate-50">
      <div class="flex items-start justify-between gap-3 mb-3">
        <div>
          <div class="text-sm font-semibold text-slate-800">${title}</div>
          <div class="text-xs text-slate-500">${subtitle}</div>
        </div>
        <div id="${statusId}" class="text-[11px] font-semibold px-2 py-1 rounded-full ${badgeCls} whitespace-nowrap">${statusText}</div>
      </div>
      <div id="${previewId}" class="${isSelfie ? 'w-28 h-28 rounded-full' : 'w-full h-40 rounded-xl'} overflow-hidden bg-slate-200 flex items-center justify-center mx-auto border border-dashed border-slate-300">
        ${previewHtml || `<i class="fas ${isSelfie ? 'fa-user' : 'fa-id-card'} text-3xl text-slate-400"></i>`}
      </div>
      <input id="${hiddenId}" type="hidden" value="${esc(value || '')}">
      <input id="${galleryId}" type="file" accept="image/*" class="hidden" onchange="kycHandlePick(this,'${hiddenId}','${previewId}','${statusId}','${nextSectionId}')">
      <input id="${cameraId}" type="file" accept="image/*" capture="${cameraFacing}" class="hidden" onchange="kycHandlePick(this,'${hiddenId}','${previewId}','${statusId}','${nextSectionId}')">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-3">
        <button type="button" onclick="kycOpenPicker('${galleryId}')" class="btn bg-sky-600 hover:bg-sky-700 text-white border border-sky-700 px-3 py-2 rounded-lg text-sm font-semibold shadow-sm"><i class="fas fa-image mr-1"></i>Upload from gallery</button>
        <button type="button" onclick="kycOpenPicker('${cameraId}')" class="btn bg-teal-600 hover:bg-teal-700 text-white border border-teal-700 px-3 py-2 rounded-lg text-sm font-semibold shadow-sm"><i class="fas fa-camera mr-1"></i>${cameraLabel}</button>
      </div>
    </section>`
}

// ---- SIGN UP (SMS OTP) ----
function authSignUp() {
  $('authBody').innerHTML = `
    ${smsBanner()}
    <form id="suForm" class="space-y-3">
      <div><label class="text-sm font-medium text-slate-600">Full Name</label>
        <input id="su_name" type="text" placeholder="Jane Wanjiku" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required></div>
      <div><label class="text-sm font-medium text-slate-600">Mobile Number</label>
        <input id="su_phone" type="text" placeholder="07XX XXX XXX" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required></div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold"><i class="fas fa-paper-plane mr-1"></i>Send Verification Code</button>
    </form>`
  $('suForm').onsubmit = async (e) => {
    e.preventDefault()
    try {
      const { data } = await api.post('/signup/request-otp', { phone: $('su_phone').value, full_name: $('su_name').value })
      authSignUpVerify(data.phone, $('su_name').value, data.demo_otp)
    } catch (err) { toast(err.response?.data?.error || 'Could not send code', false) }
  }
}
function authSignUpVerify(phone, name, demoOtp) {
  $('authBody').innerHTML = `
    <p class="text-sm text-slate-600 mb-1">Enter the code sent to <b>${esc(phone)}</b></p>
    ${demoOtp ? `<div class="bg-teal-50 border border-teal-200 text-teal-800 text-sm rounded-lg p-2 mb-3">Demo code: <b class="tracking-widest">${esc(demoOtp)}</b></div>` : ''}
    <form id="suvForm" class="space-y-4">
      <div><label class="text-sm font-medium text-slate-600">Verification Code</label>
        <input id="su_code" type="text" inputmode="numeric" placeholder="6-digit code" value="${esc(demoOtp || '')}" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg tracking-widest" required></div>
      <div><label class="text-sm font-medium text-slate-600">Create Password</label>
        ${passwordField('su_pass', { placeholder: 'Choose a password', required: true })}</div>
      <div class="bg-sky-50 border border-sky-200 rounded-lg p-3 text-[12px] text-sky-800 leading-relaxed">
        <i class="fas fa-circle-info mr-1"></i>You're almost done! Your ID documents and farm details are <b>not</b> needed to sign up. You can add them later from your profile — they're only required when you apply for <b>financing</b>. Cash purchases work right away.
      </div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold">Create Account</button>
    </form>
    <button onclick="renderLogin('signup')" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Back</button>`
  $('suvForm').onsubmit = async (e) => {
    e.preventDefault()
    try {
      const { data } = await api.post('/signup/verify', { phone, full_name: name, code: $('su_code').value, password: $('su_pass').value })
      state.user = data.user; toast('Account created. Welcome, ' + data.user.full_name); renderApp()
    } catch (err) { toast(err.response?.data?.error || 'Verification failed', false) }
  }
}
// ---- PASSWORD RESET (SMS OTP) ----
function authReset() {
  $('authBody').innerHTML = `
    ${smsBanner()}
    <form id="rsForm" class="space-y-3">
      <div><label class="text-sm font-medium text-slate-600">Mobile Number</label>
        <input id="rs_phone" type="text" placeholder="07XX XXX XXX" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required></div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold"><i class="fas fa-paper-plane mr-1"></i>Send Reset Code</button>
    </form>`
  $('rsForm').onsubmit = async (e) => {
    e.preventDefault()
    try {
      const { data } = await api.post('/reset-password/request-otp', { phone: $('rs_phone').value })
      authResetVerify(data.phone, data.demo_otp)
    } catch (err) { toast(err.response?.data?.error || 'Could not send code', false) }
  }
}
function authResetVerify(phone, demoOtp) {
  $('authBody').innerHTML = `
    <p class="text-sm text-slate-600 mb-1">Enter the reset code sent to <b>${esc(phone)}</b></p>
    ${demoOtp ? `<div class="bg-teal-50 border border-teal-200 text-teal-800 text-sm rounded-lg p-2 mb-3">Demo code: <b class="tracking-widest">${esc(demoOtp)}</b></div>` : ''}
    <form id="rsvForm" class="space-y-3">
      <div><label class="text-sm font-medium text-slate-600">Reset Code</label>
        <input id="rs_code" type="text" inputmode="numeric" placeholder="6-digit code" value="${esc(demoOtp || '')}" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg tracking-widest" required></div>
      <div><label class="text-sm font-medium text-slate-600">New Password</label>
        ${passwordField('rs_pass', { placeholder: 'New password', required: true })}</div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold">Update Password</button>
    </form>
    <button onclick="renderLogin('reset')" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Back</button>`
  $('rsvForm').onsubmit = async (e) => {
    e.preventDefault()
    try {
      await api.post('/reset-password/verify', { phone, code: $('rs_code').value, password: $('rs_pass').value })
      toast('Password updated. Please sign in.'); renderLogin('signin')
    } catch (err) { toast(err.response?.data?.error || 'Reset failed', false) }
  }
}
window.renderLogin = renderLogin
window.fill = (p, pw) => { $('phone').value = p; $('password').value = pw }
async function logout() {
  // Always clear local session + return to login, even if the network request
  // fails (e.g. connection dropped) — never leave the user stuck logged-in.
  try { await api.post('/logout') } catch (_) {}
  try { if (typeof stopLive === 'function') stopLive() } catch (_) {}
  state.user = null
  renderLogin()
}
window.logout = logout

// ---------------------------------------------------------------------------
// APP SHELL + NAV
// ---------------------------------------------------------------------------
function navItems() {
  const r = state.user.role
  const account = { k: 'profile', i: 'fa-id-card', t: 'My Account' }
  const withAccount = (arr) => [...arr, account]
  const common = [{ k: 'dashboard', i: 'fa-gauge-high', t: 'Dashboard' }]
  const financeQueue = { k: 'finance_queue', i: 'fa-hand-holding-dollar', t: 'Finance Queue' }
  const wallets = { k: 'wallets', i: 'fa-wallet', t: 'Wallets & Payouts' }
  const myWallet = { k: 'wallet', i: 'fa-wallet', t: 'My Wallet' }
  if (r === 'super_admin' || r === 'admin') return withAccount([...common,
    { k: 'approvals', i: 'fa-clipboard-check', t: 'Approvals' },
    { k: 'inventory', i: 'fa-boxes-stacked', t: 'Inventory' },
    financeQueue,
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'contracts', i: 'fa-file-signature', t: 'Purchases' },
    { k: 'agents', i: 'fa-user-tie', t: 'Agents' },
    { k: 'users', i: 'fa-user-gear', t: 'User Accounts' },
    wallets,
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' },
    { k: 'settings', i: 'fa-sliders', t: 'Financing Settings' },
    { k: 'exports', i: 'fa-database', t: 'Data Export' }])
  if (r === 'operations_finance') return withAccount([...common,
    { k: 'approvals', i: 'fa-clipboard-check', t: 'Approvals' },
    financeQueue,
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'contracts', i: 'fa-file-signature', t: 'Purchases' },
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' }])
  if (r === 'agent') return withAccount([...common,
    { k: 'onboard', i: 'fa-user-plus', t: 'Add Farmer' },
    { k: 'customers', i: 'fa-users', t: 'My Farmers' },
    ...(canDo('can_manage_inventory') ? [{ k: 'inventory', i: 'fa-boxes-stacked', t: 'My Inventory' }] : []),
    { k: 'contracts', i: 'fa-file-signature', t: 'Credit Purchases' },
    myWallet])
  if (r === 'customer') return withAccount([...common,
    { k: 'shop', i: 'fa-store', t: 'Shop' },
    { k: 'contracts', i: 'fa-file-signature', t: 'My Purchases' }])
  if (r === 'support') return withAccount([...common,
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' }])
  // Lender / Investor / M&E / Partner: read-only dashboard + relevant views.
  if (['lender', 'investor', 'mne', 'partner'].includes(r)) return withAccount([...common,
    ...(canDo('view_credit_purchases') ? [{ k: 'contracts', i: 'fa-file-signature', t: 'Financed Portfolio' }] : []),
    ...(canDo('view_farmers') ? [{ k: 'customers', i: 'fa-users', t: 'Farmers' }] : [])])
  return withAccount(common)
}
function renderApp() {
  const items = navItems()
  $('app').innerHTML = `
  <div class="app-shell">
    <div id="appOverlay" class="app-overlay" onclick="toggleSidebar(false)"></div>
    <aside id="appSidebar" class="sidebar brand-bg text-white">
      <div class="p-4 border-b border-white/10 bg-white/95">
        <img src="/static/farmsky-logo.png" alt="Farmsky" class="h-16 mx-auto object-contain">
      </div>
      <nav class="flex-1 py-4 overflow-y-auto">
        ${items.map(it => `<div class="nav-link px-5 py-3 flex items-center gap-3 text-sm hover:bg-white/10 ${state.route === it.k ? 'active' : ''}" onclick="go('${it.k}')"><i class="fas ${it.i} w-5"></i>${it.t}</div>`).join('')}
      </nav>
      <div class="p-4 border-t border-white/10">
        <div class="text-sm font-medium">${esc(state.user.full_name)}</div>
        <div class="text-xs text-teal-200 mb-2">${esc(roleLabel(state.user.role))}${state.user.label ? ' · ' + esc(state.user.label) : ''}</div>
        <button onclick="logout()" class="btn w-full text-xs bg-white/10 hover:bg-white/20 py-2 rounded-lg"><i class="fas fa-right-from-bracket mr-1"></i>Logout</button>
      </div>
    </aside>
    <main class="main-area">
      <header class="topbar">
        <div class="flex items-center gap-3 min-w-0">
          <button class="menu-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
          <div class="min-w-0">
            <h2 id="pageTitle" class="text-xl font-bold text-slate-800 truncate"></h2>
            <div class="text-xs text-slate-500 md:hidden"><i class="fas fa-tractor text-teal-600 mr-1"></i>Cash & Murabaha Financing</div>
          </div>
        </div>
        <div class="text-sm text-slate-500 hidden md:block"><i class="fas fa-tractor text-teal-600 mr-1"></i>Cash & Murabaha Financing</div>
      </header>
      <div id="content-wrap"><div id="content"></div></div>
    </main>
  </div>
  <div id="modal"></div>`
  route()
}
window.go = (r) => { state.route = r; toggleSidebar(false); renderApp() }
function route() {
  const titles = { dashboard: 'Dashboard', approvals: 'Financing Approvals', inventory: 'Inventory', finance_queue: 'Finance Approval Queue', customers: 'Customers', contracts: 'Purchases & Contracts', agents: 'Agent Management', users: 'User Accounts & Access', repayments: 'Repayment Performance', onboard: 'Farmer Onboarding', shop: 'Feed Shop', exports: 'Data Export & Reports', settings: 'Financing & Markup Settings', profile: 'My Account', wallet: 'My Wallet', wallets: 'Wallets & Payouts' }
  $('pageTitle').textContent = titles[state.route] || 'Dashboard'
  const map = { dashboard: viewDashboard, approvals: viewApprovals, inventory: viewInventory, finance_queue: viewFinanceQueue, customers: viewCustomers, contracts: viewContracts, agents: viewAgents, users: viewUsers, repayments: viewRepayments, onboard: viewOnboard, shop: viewShop, exports: viewExports, settings: viewSettings, profile: viewProfile, wallet: viewMyWallet, wallets: viewWallets }
  ;(map[state.route] || viewDashboard)()
}

// ---------------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------------
function statCard(icon, label, value, color) {
  return `<div class="card p-5 fade-in">
    <div class="flex items-center justify-between">
      <div><p class="text-xs text-slate-500 uppercase tracking-wide">${label}</p><p class="text-2xl font-bold text-slate-800 mt-1">${value}</p></div>
      <div class="w-12 h-12 rounded-xl flex items-center justify-center ${color}"><i class="fas ${icon} text-lg"></i></div>
    </div></div>`
}
async function viewDashboard() {
  $('content').innerHTML = '<div class="text-slate-400">Loading...</div>'
  const { data } = await api.get('/dashboard')
  if (data.role === 'customer') {
    let next = data.next_payment ? `<div class="card p-5"><p class="text-xs text-slate-500 uppercase">Next Payment</p><p class="text-2xl font-bold mt-1">${fmt(data.next_payment.amount_due - data.next_payment.amount_paid)}</p><p class="text-sm text-slate-500">Due ${data.next_payment.due_date}</p></div>` : '<div class="card p-5"><p class="text-slate-500">No upcoming payments</p></div>'
    $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      ${statCard('fa-file-signature', 'Active Purchases', data.active_contracts, 'bg-teal-50 text-teal-600')}
      ${statCard('fa-money-bill-wave', 'Total Outstanding', fmt(data.total_outstanding), 'bg-amber-50 text-amber-600')}
      ${statCard('fa-circle-check', 'Completed', data.completed_contracts, 'bg-emerald-50 text-emerald-600')}
      ${next}
    </div>
    <div class="card p-6"><h3 class="font-bold mb-2"><i class="fas fa-store text-teal-600 mr-2"></i>Quick Actions</h3>
      <button onclick="go('shop')" class="btn brand-bg text-white px-5 py-2.5 rounded-lg text-sm mr-2"><i class="fas fa-cart-plus mr-1"></i>Buy Feed</button>
      <button onclick="go('contracts')" class="btn bg-slate-100 px-5 py-2.5 rounded-lg text-sm"><i class="fas fa-list mr-1"></i>My Purchases</button>
    </div>`
  } else if (data.role === 'agent') {
    $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      ${statCard('fa-users', 'Farmers Added', data.customers_onboarded, 'bg-teal-50 text-teal-600')}
      ${statCard('fa-file-signature', 'Active Contracts', data.active_contracts, 'bg-blue-50 text-blue-600')}
      ${statCard('fa-clock', 'Pending Approvals', data.pending_approvals, 'bg-amber-50 text-amber-600')}
      ${statCard('fa-credit-card', 'Credit Purchases', data.credit_purchases || 0, 'bg-violet-50 text-violet-600')}
      ${statCard('fa-coins', 'Commission', fmt(data.commission), 'bg-emerald-50 text-emerald-600')}
      ${statCard('fa-wallet', 'Portfolio Value', fmt(data.portfolio_value), 'bg-indigo-50 text-indigo-600')}
      ${statCard('fa-triangle-exclamation', 'Portfolio at Risk', data.portfolio_at_risk + '%', 'bg-red-50 text-red-600')}
      ${statCard('fa-calendar-xmark', 'Late Installments', data.late_installments, 'bg-orange-50 text-orange-600')}
    </div>
    <div class="card p-6"><button onclick="go('onboard')" class="btn brand-bg text-white px-5 py-2.5 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Add New Farmer</button></div>`
  } else {
    $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      ${statCard('fa-chart-line', 'Total Sales', fmt(data.total_sales), 'bg-teal-50 text-teal-600')}
      ${statCard('fa-hand-holding-dollar', 'Feed Financed', fmt(data.feed_financed), 'bg-blue-50 text-blue-600')}
      ${statCard('fa-money-bill', 'Cash Sales', fmt(data.cash_sales), 'bg-emerald-50 text-emerald-600')}
      ${statCard('fa-percent', 'Repayment Rate', data.repayment_rate + '%', 'bg-indigo-50 text-indigo-600')}
      ${statCard('fa-triangle-exclamation', 'Default Rate', data.default_rate + '%', 'bg-red-50 text-red-600')}
      ${statCard('fa-warehouse', 'Inventory Value', fmt(data.inventory_value), 'bg-amber-50 text-amber-600')}
      ${statCard('fa-users', 'Active Customers', data.active_customers, 'bg-cyan-50 text-cyan-600')}
      ${statCard('fa-clock', 'Pending Approvals', data.pending_approvals, 'bg-orange-50 text-orange-600')}
    </div>
    <div class="card p-6"><h3 class="font-bold mb-4"><i class="fas fa-ranking-star text-teal-600 mr-2"></i>Top Products</h3>
      ${data.top_products.map(p => `<div class="flex justify-between py-2 border-b border-slate-100 last:border-0"><span>${esc(p.name)}</span><span class="font-semibold">${p.sales} sales</span></div>`).join('') || '<p class="text-slate-400">No data</p>'}
    </div>`
  }
}

// ---------------------------------------------------------------------------
// SHOP (customer buy flow)
// ---------------------------------------------------------------------------
function prodImg(p, cls) {
  return p.image
    ? `<img src="${esc(p.image)}" alt="${esc(p.name)}" class="${cls} object-cover">`
    : `<div class="${cls} flex items-center justify-center bg-gradient-to-br from-teal-50 to-emerald-100 text-teal-400"><i class="fas fa-box-open text-3xl"></i></div>`
}
async function viewShop() {
  const { data } = await api.get('/products?shop=1')
  _products = data.products
  $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-3 gap-5">
    ${data.products.map(p => `
      <div class="card overflow-hidden fade-in flex flex-col">
        <div class="cursor-pointer" onclick="productDetail(${p.id})">${prodImg(p, 'w-full h-44')}</div>
        <div class="p-4 flex flex-col flex-1">
          <div class="flex justify-between items-start"><h3 class="font-bold text-slate-800">${esc(p.name)}</h3>${badge(p.stock_status)}</div>
          <p class="text-xs text-slate-500 mb-3">${esc(p.category)} · ${p.quantity} ${esc(p.unit)} in stock</p>
          <div class="space-y-1 text-sm mt-auto">
            <div class="flex justify-between"><span class="text-slate-500">Cash Price</span><span class="font-semibold text-emerald-600">${fmt(p.cash_price)}</span></div>
            <div class="flex justify-between"><span class="text-slate-500">Pay Later Price <span class="text-[10px] text-slate-400">(Murabaha Financing)</span></span><span class="font-semibold text-blue-600">${fmt(p.credit_price)}</span></div>
          </div>
          <div class="flex gap-2 mt-4">
            <button onclick="productDetail(${p.id})" class="btn flex-1 bg-slate-100 hover:bg-slate-200 py-2 rounded-lg text-sm"><i class="fas fa-circle-info mr-1"></i>Details</button>
            <button onclick="buyModal(${p.id})" ${p.quantity <= 0 ? 'disabled' : ''} class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm disabled:opacity-40"><i class="fas fa-cart-plus mr-1"></i>Buy</button>
          </div>
        </div>
      </div>`).join('')}
  </div>`
}
window.productDetail = (id) => {
  const p = _products.find(x => x.id === id)
  if (!p) return
  showModal(`
    ${prodImg(p, 'w-full h-56 rounded-xl mb-4')}
    <div class="flex justify-between items-start mb-1"><h3 class="text-xl font-bold">${esc(p.name)}</h3>${badge(p.stock_status)}</div>
    <p class="text-sm text-slate-500 mb-4"><i class="fas fa-tag mr-1"></i>${esc(p.category)} · SKU ${esc(p.sku)}</p>
    <div class="responsive-grid cols-2 text-sm">
      <div class="bg-emerald-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Cash Price</p><b class="text-emerald-700 text-lg">${fmt(p.cash_price)}</b></div>
      <div class="bg-blue-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Pay Later Price <span class="text-[10px] text-slate-400">(Murabaha Financing)</span></p><b class="text-blue-700 text-lg">${fmt(p.credit_price)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">In Stock</p><b>${p.quantity} ${esc(p.unit)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Pay Later Markup</p><b>${p.credit_markup_pct}%</b></div>
    </div>
    <button onclick="buyModal(${p.id})" ${p.quantity <= 0 ? 'disabled' : ''} class="btn w-full mt-5 brand-bg text-white py-2.5 rounded-lg text-sm disabled:opacity-40"><i class="fas fa-cart-plus mr-1"></i>Purchase This Product</button>
    <button onclick="closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Close</button>`)
}
window.buyModal = async (productId) => {
  if (!_products.length) { const { data } = await api.get('/products'); _products = data.products }
  const p = _products.find(x => x.id === productId)
  const minTerm = Math.max(1, Number(p.financing_term_min_months || 3))
  const maxTerm = Math.max(minTerm, Number(p.financing_term_max_months || 12))
  const termOptions = Array.from({ length: maxTerm - minTerm + 1 }, (_, i) => minTerm + i)
    .map(m => `<option value="${m}" ${m === Math.min(6, maxTerm) && m >= minTerm ? 'selected' : ''}>${m}</option>`).join('')
  const paymentOptions = [
    p.cash_enabled ? '<option value="cash">Cash purchase</option>' : '',
    p.financing_enabled ? `<option value="financing">${'Murabaha financing'}</option>` : ''
  ].join('')
  showModal(`
    <h3 class="text-lg font-bold mb-1">Purchase: ${esc(p.name)}</h3>
    <p class="text-xs text-slate-500 mb-4">Configure the order, review the deposit and repayment terms, then consent before purchase.</p>
    <div class="responsive-grid cols-2 text-sm">
      <div style="grid-column:1 / -1"><label class="font-medium">Description</label><div class="mt-1 text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2">${esc(p.description || 'No description added')}</div></div>
      <div><label class="font-medium">Quantity</label><input id="qty" type="number" value="1" min="1" max="${p.quantity}" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg"></div>
      <div><label class="font-medium">Payment Type</label>
        <select id="ptype" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg" onchange="toggleTerm()">${paymentOptions}</select>
      </div>
      <div id="termWrap" class="hidden"><label class="font-medium">Payment Term (months)</label>
        <select id="term" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg">${termOptions}</select>
      </div>
      <div><label class="font-medium">Delivery Location</label><input id="dloc" type="text" placeholder="Village / Ward" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg"></div>
    </div>
    <div class="responsive-grid cols-2 mt-3 text-xs">
      <div class="bg-slate-50 border border-slate-200 rounded-lg p-3"><div class="text-slate-500">Cash deposit requirement</div><div class="font-semibold mt-1">${Number(p.cash_deposit_pct ?? 100)}%</div></div>
      <div class="bg-slate-50 border border-slate-200 rounded-lg p-3"><div class="text-slate-500">Financing deposit requirement</div><div class="font-semibold mt-1">${Number(p.financing_deposit_pct ?? 10)}%</div></div>
      <div class="bg-slate-50 border border-slate-200 rounded-lg p-3"><div class="text-slate-500">Financing model</div><div class="font-semibold mt-1">${'Murabaha (Sharia cost-plus)'}</div></div>
      <div class="bg-slate-50 border border-slate-200 rounded-lg p-3"><div class="text-slate-500">Interest / finance rate</div><div class="font-semibold mt-1">${Number(p.financing_interest_pct || 0)}%</div></div>
    </div>
    <div id="quoteBox" class="mt-4"></div>
    <div class="flex gap-2 mt-5">
      <button onclick="getQuote(${p.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-calculator mr-1"></i>Preview Payment Terms</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button>
    </div>`)
  toggleTerm()
}
window.toggleTerm = () => {
  const wrap = $('termWrap')
  if (wrap) wrap.classList.toggle('hidden', $('ptype').value !== 'financing')
}
window.getQuote = async (productId) => {
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0 }
  const { data } = await api.post('/murabaha/quote', body)
  const financing = body.payment_type === 'financing'
  $('quoteBox').innerHTML = `
    <div class="bg-teal-50 border border-teal-200 rounded-xl p-4">
      <h4 class="font-bold text-teal-800 mb-2"><i class="fas fa-file-invoice-dollar mr-1"></i>Payment Summary</h4>
      <div class="space-y-1 text-sm">
        <div class="flex justify-between"><span>Purchase type</span><b>${payLabel(data.payment_type, data.financing_model)}</b></div>
        <div class="flex justify-between"><span>Supplier cost</span><b>${fmt(data.supplier_cost)}</b></div>
        <div class="flex justify-between"><span>Deposit required</span><b>${data.deposit_pct}% (${fmt(data.deposit_amount)})</b></div>
        <div class="flex justify-between"><span>Amount due now</span><b>${fmt(data.amount_due_now)}</b></div>
        <div class="flex justify-between"><span>Total payable</span><b>${fmt(data.total_payable)}</b></div>
        ${financing ? `
          <div class="flex justify-between"><span>Financed principal</span><b>${fmt(data.finance_principal)}</b></div>
          <div class="flex justify-between"><span>Term</span><b>${data.term_months} month(s)</b></div>
          <div class="flex justify-between"><span>Payment frequency</span><b>${esc(data.payment_frequency)}</b></div>
          <div class="flex justify-between"><span>Installments</span><b>${data.installment_count}</b></div>
          <div class="flex justify-between"><span>Installment amount</span><b>${fmt(data.installment_amount)}</b></div>
          <div class="flex justify-between"><span>Interest / finance rate</span><b>${data.interest_rate_pct || 0}%</b></div>` : `
          <div class="flex justify-between"><span>Balance after deposit</span><b>${fmt(data.outstanding_after_deposit)}</b></div>`}
      </div>
      <p class="text-xs text-teal-700 mt-2 italic">${esc(data.disclosure_note || '')}</p>
      ${data.terms_text ? `<div class="mt-3 text-xs text-slate-600 bg-white/70 rounded-lg p-3 border border-teal-100"><b>Terms summary:</b> ${esc(data.terms_text)}</div>` : ''}
      ${data.terms_document_url ? `<p class="mt-2 text-xs"><a href="${esc(data.terms_document_url)}" target="_blank" class="text-teal-700 underline">Open uploaded agreement</a></p>` : ''}
      <label class="flex items-center gap-2 mt-3 text-sm"><input type="checkbox" id="consent"> I consent to these configured cash / financing terms.</label>
      <button onclick="submitBuy(${productId})" class="btn w-full mt-3 brand-bg text-white py-2.5 rounded-lg text-sm">${financing ? 'Submit Financing Application' : 'Confirm Cash Purchase'}</button>
    </div>`
}
window.submitBuy = async (productId) => {
  if (!$('consent').checked) return toast('Consent is required (Sharia requirement)', false)
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0, delivery_location: $('dloc').value, consent: true }
  try {
    const { data } = await api.post('/murabaha/apply', body)
    if (data.requires_payment) {
      // Cash purchase -> pay now via M-Pesa STK push (full amount).
      payModal(data.id, data.amount_due_now, data.outstanding, 'cash')
      return
    }
    closeModal()
    toast('Application submitted: ' + data.contract_ref)
    state.route = 'contracts'; renderApp()
  } catch (err) {
    const d = err.response?.data
    if (err.response?.status === 412 && d?.error === 'kyc_required') {
      showModal(`<div class="text-center">
        <div class="w-14 h-14 mx-auto rounded-full bg-amber-100 text-amber-600 flex items-center justify-center text-2xl mb-3"><i class="fas fa-id-card"></i></div>
        <h3 class="text-lg font-bold mb-1">Complete User Registration</h3>
        <p class="text-sm text-slate-600 mb-4">${esc(d.message)}</p>
        <p class="text-xs text-slate-400 mb-4">This runs a TransUnion credit check and a liveness / ID verification.</p>
        <button onclick="completeRegistration(${d.customer_id}, true)" class="btn w-full brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-shield-halved mr-1"></i>Complete Registration Now</button>
        <button onclick="closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Later</button>
      </div>`)
    } else { toast(d?.error || 'Failed', false) }
  }
}

// ---------------------------------------------------------------------------
// CONTRACTS
// ---------------------------------------------------------------------------
async function viewContracts() {
  const { data } = await api.get('/murabaha')
  $('content').innerHTML = `<div class="card table-card">
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
        <th class="text-left px-4 py-3">Ref</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Product</th>
        <th class="text-left px-4 py-3">Type</th><th class="text-right px-4 py-3">Price</th><th class="text-right px-4 py-3">Outstanding</th>
        <th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
      <tbody>${data.contracts.map(c => `<tr class="border-t border-slate-100">
        <td class="px-4 py-3 font-mono text-xs">${esc(c.contract_ref)}</td>
        <td class="px-4 py-3">${esc(c.customer_name)}</td>
        <td class="px-4 py-3">${esc(c.product_name)} ×${c.quantity}</td>
        <td class="px-4 py-3">${payLabel(c.payment_type, c.financing_model)}</td>
        <td class="px-4 py-3 text-right">${fmt(c.murabaha_price)}</td>
        <td class="px-4 py-3 text-right">${fmt(c.outstanding)}</td>
        <td class="px-4 py-3">${badge(c.status)}</td>
        <td class="px-4 py-3"><button onclick="contractDetail(${c.id})" class="text-teal-600 hover:underline text-xs">View</button></td>
      </tr>`).join('') || '<tr><td colspan="8" class="text-center py-8 text-slate-400">No contracts</td></tr>'}</tbody>
    </table></div>`
}
window.contractDetail = async (id) => {
  const { data } = await api.get('/murabaha/' + id)
  const c = data.contract
  const canPay = state.user.role === 'customer' && c.status === 'active'
  const canDispatch = ['admin', 'super_admin', 'operations_finance'].includes(state.user.role) && ['active', 'completed', 'awaiting_cash_balance'].includes(c.status) && c.dispatch_status !== 'dispatched'
  const canRequest = !['admin', 'super_admin'].includes(state.user.role) && canDo('request_admin_action')

  // ---- Issue 2: Milestone Payment & Balance Calculator ----------------------
  const isCash = c.payment_type === 'cash'
  const depositPct = Number(c.deposit_pct || 0)
  const totalPayable = Number(c.murabaha_price || 0)
  const amountPaid = Number(c.amount_paid || 0)
  const outstanding = Number(c.outstanding || 0)
  // A milestone contract is one where only a deposit (< 100%) was required up front.
  const isMilestone = depositPct > 0 && depositPct < 100
  const hasBalance = outstanding > 0.5
  // Who may push a cash balance payment (button next to the contract).
  const canCollect = state.user.role === 'customer' || canDo('collect_payment') ||
    ['admin', 'super_admin', 'operations_finance', 'sales_agent'].includes(state.user.role)
  // Cash contract that has taken a deposit but still owes a balance.
  const cashBalanceDue = isCash && hasBalance && (c.status === 'awaiting_cash_balance' || c.ownership_recorded)

  // Compute the next financing installment + days to due (for reminders).
  let nextDue = null
  if (!isCash && Array.isArray(data.repayments)) {
    nextDue = data.repayments.find(r => r.status !== 'completed' && Number(r.amount_due) > Number(r.amount_paid || 0))
  }
  let dueBanner = ''
  if (nextDue && nextDue.due_date) {
    const days = Math.ceil((new Date(nextDue.due_date).getTime() - Date.now()) / 86400000)
    const dueAmt = Number(nextDue.amount_due) - Number(nextDue.amount_paid || 0)
    const tone = days < 0 ? 'red' : days <= 3 ? 'amber' : 'teal'
    const label = days < 0 ? `Overdue by ${Math.abs(days)} day(s)` : days === 0 ? 'Due today' : `Due in ${days} day(s)`
    dueBanner = `<div class="text-left mb-4 p-3 rounded-lg bg-${tone}-50 border border-${tone}-200">
        <div class="text-xs font-semibold text-${tone}-800"><i class="fas fa-bell mr-1"></i>Installment reminder — ${label}</div>
        <div class="text-xs text-${tone}-700 mt-0.5">Next payment of ${fmt(dueAmt)} is due on ${esc(nextDue.due_date)}.</div>
      </div>`
  }

  // Reactive balance calculator card (deposit > 0).
  let balanceCard = ''
  if (isMilestone || hasBalance) {
    const progress = totalPayable > 0 ? Math.min(100, Math.round((amountPaid / totalPayable) * 100)) : 0
    balanceCard = `<div class="text-left mb-4 p-3 rounded-lg bg-white border border-slate-200">
        <div class="text-[11px] font-semibold text-slate-600 uppercase tracking-wider mb-2 text-left">Balance Calculator</div>
        <div class="flex justify-between text-xs mb-1"><span class="text-slate-500">Total payable</span><b>${fmt(totalPayable)}</b></div>
        <div class="flex justify-between text-xs mb-1"><span class="text-slate-500">Deposit / paid so far${depositPct ? ` (${depositPct}% deposit)` : ''}</span><b class="text-emerald-700">${fmt(amountPaid)}</b></div>
        <div class="flex justify-between text-xs mb-2"><span class="text-slate-500">Remaining balance</span><b class="text-${hasBalance ? 'amber' : 'emerald'}-700">${fmt(outstanding)}</b></div>
        <div class="h-2 w-full bg-slate-100 rounded-full overflow-hidden"><div class="h-full bg-emerald-500" style="width:${progress}%"></div></div>
        <div class="text-[10px] text-slate-400 mt-1 text-left">${progress}% settled</div>
      </div>`
  }
  showModal(`
    <div class="flex justify-between items-start mb-3">
      <div><h3 class="text-lg font-bold">${esc(c.contract_ref)}</h3><p class="text-xs text-slate-500">${esc(c.customer_name)} · ${esc(c.product_name)}</p></div>
      ${badge(c.status)}
    </div>
    <div class="grid grid-cols-2 gap-3 text-sm mb-4">
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Purchase type</p><b>${payLabel(c.payment_type, c.financing_model)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Dispatch status</p><b>${esc((c.dispatch_status || 'pending').replace(/_/g, ' '))}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Supplier Cost</p><b>${fmt(c.supplier_cost)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Total payable</p><b>${fmt(c.murabaha_price)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Deposit</p><b>${Number(c.deposit_pct || 0)}% · ${fmt(c.deposit_amount || 0)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Interest / finance rate</p><b>${Number(c.interest_rate_pct || c.markup_pct || 0)}%</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Frequency</p><b>${esc(c.payment_frequency || 'monthly')}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Installment amount</p><b>${fmt(c.installment_amount || c.monthly_payment || 0)}</b></div>
      <div class="bg-teal-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Outstanding</p><b>${fmt(c.outstanding)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Terms</p><b>${c.term_months || 0} month(s)</b></div>
    </div>
    ${c.terms_text ? `<div class="text-xs text-slate-600 bg-slate-50 p-3 rounded-lg mb-4 border border-slate-200"><b>Configured terms:</b> ${esc(c.terms_text)}</div>` : ''}
    ${dueBanner}
    ${balanceCard}
    ${data.repayments.length ? `<h4 class="font-semibold text-sm mb-2">Repayment Schedule</h4>
    <table class="w-full text-xs mb-4"><thead class="text-slate-400"><tr><th class="text-left">#</th><th class="text-left">Due</th><th class="text-right">Amount</th><th class="text-right">Paid</th><th>Status</th></tr></thead>
    <tbody>${data.repayments.map(r => `<tr class="border-t border-slate-100"><td>${r.installment_no}</td><td>${r.due_date}</td><td class="text-right">${fmt(r.amount_due)}</td><td class="text-right">${fmt(r.amount_paid)}</td><td class="text-center">${badge(r.status)}</td></tr>`).join('')}</tbody></table>` : ''}
    <div class="flex flex-wrap gap-2">
      ${canPay ? `<button onclick="payModal(${c.id}, ${c.monthly_payment || c.installment_amount || c.outstanding}, ${c.outstanding})" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-mobile-alt mr-1"></i>Pay via M-Pesa</button>` : ''}
      ${cashBalanceDue && canCollect ? `<button onclick="payModal(${c.id}, ${outstanding}, ${outstanding}, 'cash')" class="btn flex-1 bg-amber-500 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-wallet mr-1"></i>Pay Balance (${fmt(outstanding)})</button>` : ''}
      ${!isCash && hasBalance && canCollect ? `<button onclick="payModal(${c.id}, ${nextDue ? (Number(nextDue.amount_due) - Number(nextDue.amount_paid||0)) : outstanding}, ${outstanding}, 'repay')" class="btn flex-1 bg-teal-600 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-coins mr-1"></i>Collect Installment</button>` : ''}
      ${canDispatch ? `<button onclick="dispatchContract(${c.id})" class="btn flex-1 bg-emerald-600 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-truck mr-1"></i>Dispatch Feedt</button>` : ''}
      ${canRequest ? `<button onclick="requestChangeModal('contract', ${c.id}, 'amend contract')" class="btn flex-1 bg-amber-500 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-paper-plane mr-1"></i>Request Admin Change</button>` : ''}
      <button onclick="viewDoc(${c.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-file-pdf mr-1"></i>Documents</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Close</button>
    </div>`)
}
window.dispatchContract = async (id) => {
  try {
    await api.post(`/murabaha/${id}/dispatch`, {})
    toast('Feed dispatched')
    closeModal(); viewContracts()
  } catch (err) { toast(err.response?.data?.error || 'Dispatch failed', false) }
}
window.payModal = async (id, amount, outstanding, kind) => {
  kind = kind || 'repay'
  const isCash = kind === 'cash'
  let mpMode = { mode: 'simulation', live: false }
  try { mpMode = (await api.get('/mpesa/status')).data } catch {}
  const modeBadge = (m) => m.live

  showModal(`<h3 class="text-lg font-bold mb-1"><i class="fas fa-mobile-alt text-teal-600 mr-2"></i>${isCash ? 'Cash Checkout' : 'Repayment'}</h3>
    <p class="text-xs text-slate-500 mb-3">${isCash ? 'Amount due' : 'Outstanding'}: ${fmt(outstanding)}</p>

    <!-- Customer-facing payment rails: M-Pesa and SasaPay. BOTH are routed
         through the Farmsky Central Payment Gateway (Feed.farmsky.africa),
         which owns all provider credentials — FEED never touches raw payment
         secrets. NOTE: KCB Buni is deliberately NOT exposed here; it is a
         backend/reconciliation-only rail and must stay hidden from customers. -->
    <label class="text-sm font-medium block mb-2">Choose payment method</label>
    <div class="grid grid-cols-2 gap-3 mb-3">
      <label class="border rounded-lg p-3 text-center cursor-pointer bg-white border-slate-200 has-[:checked]:ring-2 has-[:checked]:ring-emerald-500 has-[:checked]:border-emerald-400">
        <input type="radio" name="paymethod" value="mpesa" checked onchange="toggleSasaChannels()" class="hidden">
        <img src="/static/mpesa-logo.png" alt="M-Pesa" class="h-10 mx-auto mb-1 object-contain">
      </label>
      <label class="border rounded-lg p-3 text-center cursor-pointer bg-white border-slate-200 has-[:checked]:ring-2 has-[:checked]:ring-green-500 has-[:checked]:border-green-400">
        <input type="radio" name="paymethod" value="sasapay" onchange="toggleSasaChannels()" class="hidden">
        <img src="/static/sasapay-logo.png" alt="SasaPay" class="h-10 mx-auto mb-1 object-contain">
      </label>
    </div>

    <!-- SasaPay channel customizer: Mobile Money / Bank / Wallet. Mirrors the
         Feed app so customers can pay from a mobile network OR a bank
         account. The prompt is delivered to the phone; no bank account number
         is required. Hidden unless SasaPay is selected. -->
    <div id="sasapayChannelBlock" class="hidden mb-3 p-3 bg-slate-50 border border-slate-200 rounded-lg space-y-3">
      <div>
        <label class="text-xs font-semibold text-slate-600 uppercase tracking-wider block mb-1">Pay from</label>
        <select id="spChanType" onchange="onSasaChanTypeChange()" class="w-full px-2 py-1.5 border border-slate-300 bg-white rounded-md text-sm">
          <option value="mobile">Mobile Money (M-PESA / Airtel / T-Kash / Telkom)</option>
          <option value="bank">Bank Account</option>
          <option value="wallet">SasaPay Wallet (OTP)</option>
        </select>
      </div>
      <div id="spChanPickWrap">
        <label class="text-xs font-semibold text-slate-600 uppercase tracking-wider block mb-1" id="spChanPickLabel">Network</label>
        <select id="spChannelCode" class="w-full px-2 py-1.5 border border-slate-300 bg-white rounded-md text-sm"></select>
      </div>
      <div id="spBankAcctWrap" class="hidden">
        <p class="text-xs text-slate-500">Select your bank above, then approve the payment prompt sent to your phone. A bank account number is not required.</p>
      </div>
    </div>

    <label class="text-sm font-medium">Phone</label><input id="mpphone" value="${esc(state.user.phone)}" class="w-full mt-1 mb-3 px-3 py-2 border border-slate-300 rounded-lg">
    <label class="text-sm font-medium">Amount (KES)</label><input id="mpamt" type="number" value="${amount}" ${isCash ? 'readonly' : ''} class="w-full mt-1 mb-2 px-3 py-2 border border-slate-300 rounded-lg ${isCash ? 'bg-slate-50' : ''}">

    <!-- Issue 6: Dynamic legal agreement block — toggles between asset financing
         terms and cash sale terms, both left-aligned to the layout margin. -->
    <div id="payTermsBlock" class="text-left mb-4 mt-1 p-3 bg-slate-50 border border-slate-200 rounded-lg">
      <div class="text-[11px] font-semibold text-slate-600 uppercase tracking-wider mb-1 text-left">${isCash ? 'Cash Sale Agreement' : 'Asset Financing Agreement'}</div>
      <p class="text-[11px] leading-relaxed text-slate-500 text-left">${isCash
        ? 'This is an outright cash sale. By proceeding you confirm full/settlement payment of the amount due and accept transfer of ownership of the Feed upon settlement. All sales are governed by FarmSky cash sale terms and no financing profit or installment obligations apply.'
        : 'This is a Sharia-compliant asset financing (Murabaha) transaction. By proceeding you agree to the disclosed murabaha price, deposit and the installment repayment schedule until the outstanding balance is fully settled. Ownership transfers per the executed financing agreement and applicable FarmSky financing terms.'}</p>
    </div>
    <div id="payStatus"></div>
    <div class="flex gap-2"><button id="payBtn" onclick="doPay(${id}, '${kind}')" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm">Send Payment Prompt</button>
    <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}

// Cache of the full SasaPay channel catalogue (wallet + mobile + ALL banks).
let _sasaChannels = null
async function loadSasaChannels() {
  if (_sasaChannels) return _sasaChannels
  try { const { data } = await api.get('/sasapay/channels'); _sasaChannels = data } catch { _sasaChannels = { channels: [], banks: [], mobile: [], wallet: [] } }
  return _sasaChannels
}

// Global UI toggle helpers invoked by custom onchange bindings inside the modal
window.toggleSasaChannels = async () => {
  const method = document.querySelector('input[name="paymethod"]:checked')?.value;
  const block = document.getElementById('sasapayChannelBlock');
  if (!block) return
  if (method === 'sasapay') {
    block.classList.remove('hidden')
    await loadSasaChannels()
    onSasaChanTypeChange()
  } else {
    block.classList.add('hidden')
  }
}

// Populate the channel picker based on the selected type (mobile/bank/wallet).
window.onSasaChanTypeChange = () => {
  const type = $('spChanType')?.value || 'mobile'
  const sel = $('spChannelCode'); const lbl = $('spChanPickLabel')
  const bankWrap = $('spBankAcctWrap')
  if (!sel) return
  const cat = _sasaChannels || { mobile: [], bank: [], wallet: [] }
  let list = []
  if (type === 'mobile') { list = cat.mobile || []; lbl.textContent = 'Network' }
  else if (type === 'bank') { list = cat.banks || cat.bank || []; lbl.textContent = 'Select Bank' }
  else { list = cat.wallet || []; lbl.textContent = 'Wallet' }
  sel.innerHTML = list.map(ch => `<option value="${esc(ch.code)}">${esc(ch.name)}</option>`).join('') || '<option value="">— none —</option>'
  if (bankWrap) bankWrap.classList.toggle('hidden', type !== 'bank')
}

// Verify a bank/mobile account holder name before paying it.
window.doValidateCheckoutAccount = async () => {
  const code = $('spChannelCode')?.value; const acc = $('spAccNum')?.value
  const nm = $('spAcctName')
  if (!code || !acc) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = 'Enter an account number first.' } return }
  if (nm) { nm.className = 'text-xs text-slate-500 mt-1'; nm.textContent = 'Verifying…' }
  try {
    const { data } = await api.post('/sasapay/validate-account', { channel_code: code, account_number: acc })
    if (nm) { nm.className = 'text-xs text-emerald-700 mt-1'; nm.textContent = data.account_name ? ('✓ ' + data.account_name) : '✓ Account verified' }
  } catch (err) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = err.response?.data?.error || 'Could not verify account.' } }
}

// Issue 3: render an explicit, persistent state alert inside the payment modal.
// state = 'success' | 'failed' | 'info'. On success we auto-dismiss the modal
// after a brief delay so the operator clearly sees the confirmation first.
window.payStateAlert = (stateName, msg, receipt) => {
  const box = $('payStatus'); if (!box) return
  if (stateName === 'success') {
    box.innerHTML = `<div class="bg-emerald-50 border border-emerald-300 rounded-lg p-3 mb-3 flex items-center gap-2">
        <i class="fas fa-circle-check text-emerald-600 text-lg"></i>
        <div><div class="text-sm font-semibold text-emerald-800">Paid Successfully</div>
        ${receipt ? `<div class="text-xs text-emerald-700">Receipt: ${esc(receipt)}</div>` : ''}
        <div class="text-[11px] text-emerald-600 mt-0.5">Closing…</div></div></div>`
  } else if (stateName === 'failed') {
    box.innerHTML = `<div class="bg-red-50 border border-red-300 rounded-lg p-3 mb-3 flex items-center gap-2">
        <i class="fas fa-circle-xmark text-red-600 text-lg"></i>
        <div><div class="text-sm font-semibold text-red-800">Payment Failed</div>
        <div class="text-xs text-red-700">${esc(msg || 'The payment could not be completed.')}</div></div></div>`
  } else {
    box.innerHTML = `<div class="bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs text-slate-600 mb-3">${esc(msg || '')}</div>`
  }
}

window.doPay = async (id, kind) => {
  const isCash = kind === 'cash'
  const method = document.querySelector('input[name="paymethod"]:checked')?.value || 'mpesa'
  // BOTH customer-facing rails (M-Pesa + SasaPay) are delegated to the Farmsky
  // Central Payment Gateway via the single /mpesa/stkpush + /mpesa/confirm pair.
  // The chosen rail is passed as `payment_method`; the gateway performs the
  // provider handshake. (KCB Buni is never selectable on the frontend.)
  const endpoint = '/mpesa/stkpush'
  const confirmEndpoint = '/mpesa/confirm'
  const methodLabel = method === 'sasapay' ? 'SasaPay' : 'M-Pesa'

  const payload = {
    contract_id: id,
    amount: $('mpamt').value,
    phone: $('mpphone').value,
    payment_method: method
  }

  // Inject SasaPay channel routing (mobile / bank / wallet). Bank payments route
  // via the selected bank/network code and the customer's phone number (prompt
  // delivered to the phone) — no bank account number is required or sent.
  if (method === 'sasapay') {
    const type = $('spChanType')?.value || 'mobile'
    const code = $('spChannelCode')?.value || ''
    payload.channel_type = type
    payload.channel_code = code
    if (type === 'bank' && !code) {
      $('payStatus').innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-3">Please select your bank.</div>`
      return
    }
  }

  // Circular processing indicator on the button + disable to prevent double-click.
  const btn = $('payBtn')
  if (!btn || btn.disabled) return   // guard: already processing
  btn.disabled = true
  btn.classList.add('opacity-60', 'cursor-not-allowed', 'pointer-events-none')
  btn.setAttribute('aria-busy', 'true')
  btn.dataset.label = btn.innerHTML
  btn.innerHTML = `<span class="inline-flex items-center justify-center gap-2"><span class="inline-block w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin"></span>Processing…</span>`
  $('payStatus').innerHTML = `<div class="text-xs text-slate-500 mb-3 flex items-center gap-2"><span class="inline-block w-3.5 h-3.5 border-2 border-slate-300 border-t-teal-600 rounded-full animate-spin"></span>Sending ${methodLabel} payment request...</div>`

  try {
    // UPDATED: Fired payment initiation outward to central production gateway
    const { data } = await gatewayApi.post(endpoint, payload)

    setHTML('payStatus', `<div class="bg-teal-50 border border-teal-200 rounded-lg p-2 text-xs text-teal-700 mb-3"><i class="fas fa-mobile-alt mr-1"></i>${esc(data.customer_message || 'STK push sent. Confirm on your phone.')}</div><div class="text-xs text-slate-500 mb-3 flex items-center gap-2"><span class="inline-block w-3.5 h-3.5 border-2 border-slate-300 border-t-teal-600 rounded-full animate-spin"></span>Waiting for ${methodLabel} confirmation...</div>`)
    const reEnable = () => { const b = $('payBtn'); if (b) { b.disabled = false; b.classList.remove('opacity-60', 'cursor-not-allowed', 'pointer-events-none'); b.removeAttribute('aria-busy'); if (b.dataset.label) b.innerHTML = b.dataset.label } }
    let tries = 0
    const poll = async () => {
      // Stop immediately if the modal was closed or the session ended — this
      // avoids the null-innerHTML crash and the 401 request flood.
      if (!$('payStatus') || !state.user) return
      tries++
      try {
        // UPDATED: Request transaction verification through gateway logs
        const { data: cd } = await gatewayApi.post(confirmEndpoint, { checkout_request_id: data.checkout_request_id })
        if (cd.status === 'success') {
          payStateAlert('success', null, cd.mpesa_receipt)
          toast((isCash ? 'Cash purchase complete! Receipt: ' : 'Payment received! Receipt: ') + cd.mpesa_receipt)
          setTimeout(() => { closeModal(); state.route = 'contracts'; renderApp() }, 1800)
          return
        }
        else if (cd.status === 'failed') { payStateAlert('failed', cd.result_desc || 'Payment failed'); reEnable(); return }
      } catch (e) {
        // Auth failure or lost connectivity — stop polling (the interceptor
        // handles the redirect for 401; nothing more to do here).
        const st = e?.response?.status
        if (st === 401 || st === 403 || !e?.response) { reEnable(); return }
      }
      if (!$('payStatus') || !state.user) return
      if (tries < 40) setTimeout(poll, 3000)
      else { setHTML('payStatus', '<div class="bg-amber-50 border border-amber-200 rounded-lg p-2 text-xs text-amber-700 mb-3">Still waiting for confirmation. If you completed the payment, it will settle automatically once confirmed — check your Purchases shortly. An admin can also recover it from Wallets &rsaquo; Recover pending payments.</div>'); reEnable() }
    }
    setTimeout(poll, data.simulated ? 1200 : 4000)
  } catch (err) {
    setHTML('payStatus', `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-3">${esc(err.response?.data?.error || (!err.response ? 'Network error — please check your connection and try again.' : 'Payment failed'))}</div>`)
    const b = $('payBtn'); if (b) { b.disabled = false; b.classList.remove('opacity-60', 'cursor-not-allowed', 'pointer-events-none'); b.removeAttribute('aria-busy'); if (b.dataset.label) b.innerHTML = b.dataset.label }
  }
}

// Submit the SasaPay wallet OTP, then poll /sasapay/confirm to settle the contract.
window.doSasaOtp = async (checkoutId, id, kind) => {
  const isCash = kind === 'cash'
  const code = $('spOtp')?.value?.trim()
  if (!code) return toast('Enter the OTP code', false)
  setHTML('payStatus', `<div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>Verifying OTP…</div>`)
  try {
    // UPDATED: Send code validation out to central payment gateway 
    await gatewayApi.post('/sasapay/process', { checkout_request_id: checkoutId, verification_code: code })
    setHTML('payStatus', `<div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>OTP accepted. Confirming payment…</div>`)
    let tries = 0
    const poll = async () => {
      if (!$('payStatus') || !state.user) return
      tries++
      try {
        // UPDATED: Pull SasaPay wallet logs via central production gateway
        const { data: cd } = await gatewayApi.post('/sasapay/confirm', { checkout_request_id: checkoutId })
        if (cd.status === 'success') {
          payStateAlert('success', null, cd.mpesa_receipt)
          toast((isCash ? 'Cash purchase complete! Receipt: ' : 'Payment received! Receipt: ') + cd.mpesa_receipt)
          setTimeout(() => { closeModal(); state.route = 'contracts'; renderApp() }, 1800)
          return
        }
        else if (cd.status === 'failed') { payStateAlert('failed', cd.result_desc || 'Payment failed'); return }
      } catch (e) {
        const st = e?.response?.status
        if (st === 401 || st === 403 || !e?.response) return
      }
      if (!$('payStatus') || !state.user) return
      if (tries < 40) setTimeout(poll, 3000)
      else setHTML('payStatus', '<div class="bg-amber-50 border border-amber-200 rounded-lg p-2 text-xs text-amber-700 mb-3">Still confirming your wallet payment. It will settle automatically once SasaPay confirms — check your Purchases shortly.</div>')
    }
    setTimeout(poll, 1500)
  } catch (err) {
    setHTML('payStatus', `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-3">${esc(err.response?.data?.error || (!err.response ? 'Network error — please check your connection and try again.' : 'OTP verification failed'))}</div>`)
  }
}

window.viewDoc = async (id) => {
  // MAINTAINED: Kept local "api" instance intact because agreements live on local backend database
  const { data } = await api.get('/documents/contract/' + id)
  const c = data.contract
  showModal(`<div class="text-center">
    <h3 class="font-bold text-lg">Murabaha Agreement</h3>
    <p class="text-xs text-slate-500 mb-3">${esc(c.contract_ref)}</p>
    <img src="${data.qr}" class="mx-auto mb-3" alt="QR">
    <div class="text-left text-sm bg-slate-50 p-4 rounded-lg space-y-1">
      <p><b>Customer:</b> ${esc(c.customer_name)} (ID ${esc(c.national_id || '—')})</p>
      <p><b>Product:</b> ${esc(c.product_name)} ×${c.quantity}</p>
      <p><b>Supplier Cost:</b> ${fmt(c.supplier_cost)} · <b>Markup:</b> ${c.markup_pct}%</p>
      <p><b>Murabaha Price (fixed):</b> ${fmt(c.murabaha_price)}</p>
      <p class="text-xs italic text-slate-500 pt-2">Compliant with Murabaha principles. No interest, penalties, or compounding applied.</p>
    </div>
    <button onclick="window.print()" class="btn mt-4 bg-slate-800 text-white px-5 py-2 rounded-lg text-sm"><i class="fas fa-print mr-1"></i>Print / Save PDF</button>
    <button onclick="closeModal()" class="btn mt-4 ml-2 bg-slate-100 px-5 py-2 rounded-lg text-sm">Close</button>
  </div>`)
}
// ---------------------------------------------------------------------------
// APPROVALS (admin)
// ---------------------------------------------------------------------------
async function viewApprovals() {
  const { data } = await api.get('/murabaha')
  const pending = data.contracts.filter(c => c.status === 'pending')
  $('content').innerHTML = `<div class="card table-card"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Ref</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Product</th><th class="text-right px-4 py-3">Price</th><th class="text-left px-4 py-3">Term</th><th></th></tr></thead>
    <tbody>${pending.map(c => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3 font-mono text-xs">${esc(c.contract_ref)}</td><td class="px-4 py-3">${esc(c.customer_name)}</td>
      <td class="px-4 py-3">${esc(c.product_name)} ×${c.quantity}</td><td class="px-4 py-3 text-right">${fmt(c.murabaha_price)}</td>
      <td class="px-4 py-3">${c.term_months}mo</td>
      <td class="px-4 py-3 text-right whitespace-nowrap">
        <button onclick="contractDetail(${c.id})" class="text-slate-500 hover:underline text-xs mr-3">Review</button>
        <button onclick="decide(${c.id},'approve')" class="text-emerald-600 hover:underline text-xs mr-2"><i class="fas fa-check"></i> Approve</button>
        <button onclick="decide(${c.id},'reject')" class="text-red-600 hover:underline text-xs"><i class="fas fa-xmark"></i> Reject</button>
      </td></tr>`).join('') || '<tr><td colspan="6" class="text-center py-8 text-slate-400">No pending approvals</td></tr>'}</tbody>
  </table></div>`
}
window.decide = async (id, action) => {
  if (!confirmEdit(`Confirm ${action} for this financing contract?`)) return
  try { await api.post(`/murabaha/${id}/decision`, { action }); toast('Contract ' + action + 'd'); viewApprovals() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// INVENTORY (admin CRUD + image)
// ---------------------------------------------------------------------------
function productForm(prefix, p = {}) {
  const paymentMode = p.payment_option_mode || (p.cash_enabled && p.financing_enabled ? 'both' : p.cash_enabled ? 'cash' : 'financing') || 'both'
  // Split-data listing (Instruction 3): only finance-authorized users may set
  // markups / rates / financing terms / agreements. Base inventory users see them
  // disabled and the record is routed to the finance-approval queue.
  const canFin = canDo('can_manage_finance_settings')
  const finDis = canFin ? '' : 'disabled'
  const finNote = canFin ? '' : `
    <div style="grid-column:1 / -1" class="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-xs text-amber-800 mb-1">
      <i class="fas fa-lock mr-1"></i>Commercial markups, financing rates, PAYGO &amp; legal agreements are set by an authorized finance user.
      Complete the basic inventory details below — an admin or finance officer supplies the financial components before the product goes live.
    </div>`
  return `
    <div class="bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs text-slate-600 mb-4"><i class="fas fa-circle-info text-teal-600 mr-1"></i>Use the labeled fields below to collect or update inventory clearly: identify the Feed, capture stock levels, then define cash and financing terms.</div>
    <div class="flex items-center gap-3 mb-4">
      <div id="${prefix}_preview">${p.id ? prodImg(p, 'w-16 h-16 rounded-lg') : '<div class="w-16 h-16 rounded-lg bg-slate-100 flex items-center justify-center text-slate-400"><i class="fas fa-image"></i></div>'}</div>
      <div class="space-y-2">
        <label class="btn bg-slate-100 px-3 py-2 rounded-lg text-xs cursor-pointer"><i class="fas fa-upload mr-1"></i>Upload Feed image<input type="file" accept="image/*" class="hidden" onchange="pickImage(this,'${prefix}_img','${prefix}_preview')"></label>
        <div class="text-[11px] text-slate-400">Agreement files can be uploaded as an image or PDF and saved with the Feed record.</div>
      </div>
    </div>
    <input type="hidden" id="${prefix}_img" value="${esc(p.image || '')}">
    <div class="responsive-grid cols-2 text-sm">
      <div><label class="field-label">Feed SKU</label><input id="${prefix}_sku" value="${esc(p.sku || '')}" placeholder="SKU" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Feed name</label><input id="${prefix}_name" value="${esc(p.name || '')}" placeholder="Feed name" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Inventory category</label><input id="${prefix}_cat" value="${esc(p.category || 'Feed')}" placeholder="Category" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Stock unit</label><input id="${prefix}_unit" value="${esc(p.unit || 'unit')}" placeholder="Unit" class="px-3 py-2 border rounded-lg"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Feed description</label><textarea id="${prefix}_desc" placeholder="Feed details / description" class="px-3 py-2 border rounded-lg min-h-24">${esc(p.description || '')}</textarea></div>
      <div><label class="field-label">Buying cost</label><input id="${prefix}_buy" type="number" value="${Number(p.buying_price || 0)}" placeholder="Buying price" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Quantity in stock</label><input id="${prefix}_qty" type="number" value="${Number(p.quantity || 0)}" placeholder="Quantity" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Cash markup %</label><input id="${prefix}_cm" type="number" value="${Number(p.cash_markup_pct || 10)}" placeholder="Cash markup %" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Reorder threshold</label><input id="${prefix}_rt" type="number" value="${Number(p.reorder_threshold || 10)}" placeholder="Reorder threshold" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Payment availability</label><select id="${prefix}_mode" class="px-3 py-2 border rounded-lg">
        <option value="both" ${paymentMode === 'both' ? 'selected' : ''}>Cash + Financing</option>
        <option value="cash" ${paymentMode === 'cash' ? 'selected' : ''}>Cash only</option>
        <option value="financing" ${paymentMode === 'financing' ? 'selected' : ''}>Financing only</option>
      </select></div>
      <div><label class="field-label">Cash deposit %</label><input id="${prefix}_cash_dep" type="number" value="${Number(p.cash_deposit_pct ?? 100)}" placeholder="Cash deposit % (0/10/100)" class="px-3 py-2 border rounded-lg"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Cash terms summary</label><textarea id="${prefix}_cash_terms" placeholder="Cash terms summary" class="px-3 py-2 border rounded-lg min-h-24">${esc(p.cash_terms_text || '')}</textarea></div>
      <div style="grid-column:1 / -1" class="border rounded-xl p-3 bg-slate-50">
        <div class="font-medium text-slate-700 mb-2">Cash agreement</div>
        <input id="${prefix}_cash_doc" value="${esc(p.cash_terms_doc_url || '')}" placeholder="Cash agreement URL / uploaded file data" class="w-full px-3 py-2 border rounded-lg text-xs">
        <div class="flex items-center justify-between gap-2 mt-2">
          <label class="btn bg-white px-3 py-2 rounded-lg text-xs cursor-pointer border"><i class="fas fa-file-upload mr-1"></i>Upload<input type="file" accept="image/*,application/pdf" class="hidden" onchange="pickFileDataUrl(this,'${prefix}_cash_doc','${prefix}_cash_doc_name')"></label>
          <span id="${prefix}_cash_doc_name" class="text-[11px] text-slate-400 truncate">${p.cash_terms_doc_url ? 'existing document attached' : 'no file selected'}</span>
        </div>
      </div>
      <div style="grid-column:1 / -1" class="mt-2 mb-1 flex items-center gap-2 text-sm font-semibold text-slate-700 border-t pt-3">
        <i class="fas fa-hand-holding-dollar text-teal-600"></i>Financial components ${canFin ? '' : '<span class="badge bg-amber-100 text-amber-700 ml-1">finance-authorized only</span>'}
      </div>
      ${finNote}
      <div><label class="field-label">Financing markup %</label><input id="${prefix}_crm" ${finDis} type="number" value="${Number(p.credit_markup_pct || 20)}" placeholder="Financing markup %" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div><label class="field-label">TransUnion product code</label><input id="${prefix}_tu" ${finDis} value="${esc(p.transunion_product_code || '')}" placeholder="TransUnion product code" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div><label class="field-label">Financing model</label><select id="${prefix}_fin_model" ${finDis} class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}">
        <option value="murabaha" selected>Murabaha (Sharia cost-plus, no interest)</option>
      </select></div>
      <div><label class="field-label">Interest / finance rate %</label><input id="${prefix}_int" ${finDis} type="number" value="${Number(p.financing_interest_pct || 0)}" placeholder="Interest rate %" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div><label class="field-label">Repayment frequency</label><select id="${prefix}_freq" ${finDis} class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}">
        ${['daily','weekly','monthly'].map(v => `<option value="${v}" ${(p.financing_frequency || 'monthly') === v ? 'selected' : ''}>${v}</option>`).join('')}
      </select></div>
      <div><label class="field-label">Financing deposit %</label><input id="${prefix}_fin_dep" ${finDis} type="number" value="${Number(p.financing_deposit_pct ?? 10)}" placeholder="Financing deposit %" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div><label class="field-label">Minimum term (months)</label><input id="${prefix}_tmin" ${finDis} type="number" value="${Number(p.financing_term_min_months || 3)}" placeholder="Minimum term (months)" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div><label class="field-label">Maximum term (months)</label><input id="${prefix}_tmax" ${finDis} type="number" value="${Number(p.financing_term_max_months || 12)}" placeholder="Maximum term (months)" class="px-3 py-2 border rounded-lg ${finDis ? 'bg-slate-100 text-slate-400' : ''}"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Financing / PAYGO terms summary</label><textarea id="${prefix}_fin_terms" ${finDis} placeholder="Financing / PAYGO terms summary" class="px-3 py-2 border rounded-lg min-h-24 ${finDis ? 'bg-slate-100 text-slate-400' : ''}">${esc(p.financing_terms_text || '')}</textarea></div>
      <div style="grid-column:1 / -1" class="border rounded-xl p-3 bg-slate-50">
        <div class="font-medium text-slate-700 mb-2">Financing / PAYGO agreement</div>
        <input id="${prefix}_fin_doc" ${finDis} value="${esc(p.financing_terms_doc_url || '')}" placeholder="Financing agreement URL / uploaded file data" class="w-full px-3 py-2 border rounded-lg text-xs ${finDis ? 'bg-slate-100 text-slate-400' : ''}">
        <div class="flex items-center justify-between gap-2 mt-2">
          <label class="btn ${finDis ? 'bg-slate-200 text-slate-400 cursor-not-allowed' : 'bg-white cursor-pointer'} px-3 py-2 rounded-lg text-xs border"><i class="fas fa-file-upload mr-1"></i>Upload<input type="file" ${finDis} accept="image/*,application/pdf" class="hidden" onchange="pickFileDataUrl(this,'${prefix}_fin_doc','${prefix}_fin_doc_name')"></label>
          <span id="${prefix}_fin_doc_name" class="text-[11px] text-slate-400 truncate">${p.financing_terms_doc_url ? 'existing document attached' : 'no file selected'}</span>
        </div>
      </div>
    </div>`
}
function productPayload(prefix) {
  const mode = $(prefix + '_mode').value
  return {
    sku: $(prefix + '_sku').value,
    name: $(prefix + '_name').value,
    category: $(prefix + '_cat').value,
    description: $(prefix + '_desc').value,
    product_type: 'Feed',
    unit: $(prefix + '_unit').value,
    buying_price: Number($(prefix + '_buy').value || 0),
    quantity: Number($(prefix + '_qty').value || 0),
    cash_markup_pct: Number($(prefix + '_cm').value || 0),
    credit_markup_pct: Number($(prefix + '_crm').value || 0),
    reorder_threshold: Number($(prefix + '_rt').value || 10),
    image: $(prefix + '_img').value || null,
    payment_option_mode: mode,
    cash_enabled: mode !== 'financing',
    financing_enabled: mode !== 'cash',
    financing_model: $(prefix + '_fin_model').value,
    financing_interest_pct: Number($(prefix + '_int').value || 0),
    financing_frequency: $(prefix + '_freq').value,
    financing_term_min_months: Number($(prefix + '_tmin').value || 3),
    financing_term_max_months: Number($(prefix + '_tmax').value || 12),
    cash_deposit_pct: Number($(prefix + '_cash_dep').value || 100),
    financing_deposit_pct: Number($(prefix + '_fin_dep').value || 10),
    cash_terms_text: $(prefix + '_cash_terms').value || null,
    financing_terms_text: $(prefix + '_fin_terms').value || null,
    cash_terms_doc_url: $(prefix + '_cash_doc').value || null,
    financing_terms_doc_url: $(prefix + '_fin_doc').value || null,
    transunion_product_code: $(prefix + '_tu').value || null
  }
}
function financeStatusBadge(s) {
  const map = { published: 'bg-emerald-100 text-emerald-700', pending_finance: 'bg-amber-100 text-amber-700', draft: 'bg-slate-100 text-slate-600' }
  const label = { published: 'Live', pending_finance: 'Pending finance', draft: 'Draft' }[s] || s || 'Live'
  return `<span class="badge ${map[s] || 'bg-slate-100 text-slate-600'}">${esc(label)}</span>`
}
async function viewInventory() {
  // Instruction 5 Query 3 — "My Inventory Control Grid". Agents (base inventory
  // users) see only records they created (?mine=1); admins see the full catalog.
  const isAdmin = ['admin', 'super_admin'].includes(state.user.role)
  const { data } = await api.get('/products' + (isAdmin ? '' : '?mine=1'))
  _products = data.products
  const canInv = data.can_manage_inventory
  const canFin = data.can_manage_finance_settings
  const isDelete = isAdmin
  const addBtn = canInv
    ? `<button onclick="addProductModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-plus mr-1"></i>Add inventory</button>`
    : `<span class="text-xs text-slate-400">Read-only view · you are not authorized to add inventory</span>`
  $('content').innerHTML = `
  <div class="flex items-center justify-between mb-4">
    <div class="text-sm text-slate-500">${isAdmin ? 'Full Feed catalog' : 'Feed you have listed'} · ${data.products.length} item(s)</div>
    <div class="action-bar">${addBtn}</div>
  </div>
  <div class="card table-card"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Image</th><th class="text-left px-4 py-3">Feed</th><th class="text-left px-4 py-3">Status</th><th class="text-left px-4 py-3">Payment Options</th><th class="text-left px-4 py-3">Financing</th><th class="text-right px-4 py-3">Cash Dep.</th><th class="text-right px-4 py-3">Fin. Dep.</th><th class="text-right px-4 py-3">Qty</th><th></th></tr></thead>
    <tbody>${data.products.map(p => `<tr class="border-t border-slate-100">
      <td class="px-4 py-2">${prodImg(p, 'w-10 h-10 rounded-lg')}</td>
      <td class="px-4 py-3"><div class="font-medium">${esc(p.name)}</div><div class="text-xs text-slate-500">${esc(p.sku)} · ${esc(p.category || 'Feed')}</div></td>
      <td class="px-4 py-3">${financeStatusBadge(p.finance_status)}</td>
      <td class="px-4 py-3">${esc((p.payment_option_mode || 'both').replace('_', ' '))}</td>
      <td class="px-4 py-3">${esc(p.financing_model === 'paygo' ? 'PAYGO' : 'Interest financing')}<div class="text-xs text-slate-400">${Number(p.financing_interest_pct || 0)}% · ${esc(p.financing_frequency || 'monthly')}</div></td>
      <td class="px-4 py-3 text-right">${Number(p.cash_deposit_pct ?? 100)}%</td>
      <td class="px-4 py-3 text-right">${Number(p.financing_deposit_pct ?? 10)}%</td>
      <td class="px-4 py-3 text-right">${p.quantity} ${esc(p.unit)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        ${(canInv || canFin) ? `<button onclick="editProductModal(${p.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>` : ''}
        ${canInv ? `<button onclick="restockModal(${p.id},'${esc(p.name)}')" class="text-slate-500 hover:underline text-xs mr-2">Restock</button>` : ''}
        ${p.finance_status === 'pending_finance' && canFin ? `<button onclick="financeModal(${p.id})" class="text-amber-600 hover:underline text-xs mr-2"><i class="fas fa-hand-holding-dollar mr-1"></i>Set finance</button>` : ''}
        ${isDelete ? `<button onclick="deleteProduct(${p.id},'${esc(p.name)}')" class="text-red-600 hover:underline text-xs">Delete</button>` : ''}
      </td></tr>`).join('') || '<tr><td colspan="9" class="text-center py-8 text-slate-400">No inventory records</td></tr>'}</tbody>
  </table></div>`
}
window.pickImage = (input, targetId, previewId) => {
  const file = input.files[0]; if (!file) return
  const reader = new FileReader()
  reader.onload = (e) => {
    const img = new Image()
    img.onload = () => {
      const max = 600, scale = Math.min(1, max / Math.max(img.width, img.height))
      const canvas = document.createElement('canvas')
      canvas.width = img.width * scale; canvas.height = img.height * scale
      canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height)
      const dataUrl = canvas.toDataURL('image/jpeg', 0.8)
      $(targetId).value = dataUrl
      $(previewId).innerHTML = `<img src="${dataUrl}" class="w-16 h-16 rounded-lg object-cover">`
    }
    img.src = e.target.result
  }
  reader.readAsDataURL(file)
}
window.addProductModal = () => {
  showModal(`<h3 class="font-bold mb-3">Add Feed</h3>${productForm('np')}<div class="flex gap-2 mt-4"><button onclick="doAddProduct()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAddProduct = async () => {
  try {
    await api.post('/products', productPayload('np'))
    closeModal(); toast('Feed added'); viewInventory()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.editProductModal = (id) => {
  const p = _products.find(x => x.id === id)
  showModal(`<h3 class="font-bold mb-3">Edit Feed</h3>${productForm('ep', p)}<div class="flex gap-2 mt-4"><button onclick="doEditProduct(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditProduct = async (id) => {
  if (!confirmEdit('Save changes to this Feed record?')) return
  try {
    await api.put('/products/' + id, productPayload('ep'))
    closeModal(); toast('Feed updated'); viewInventory()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteProduct = async (id, name) => {
  if (!confirmDelete('Delete product "' + name + '"? This cannot be undone.')) return
  try { await api.delete('/products/' + id); toast('Product deleted'); viewInventory() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.restockModal = (id, name) => {
  showModal(`<h3 class="font-bold mb-3">Restock: ${name}</h3>
    <label class="text-sm">Quantity to add</label><input id="rq" type="number" value="10" class="w-full mt-1 mb-4 px-3 py-2 border border-slate-300 rounded-lg">
    <div class="flex gap-2"><button onclick="doRestock(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Add Stock</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doRestock = async (id) => {
  if (!confirmEdit(`Confirm inventory update and add ${$('rq').value || 0} unit(s) to stock?`)) return
  await api.put(`/products/${id}/stock`, { quantity: Number($('rq').value), movement_type: 'purchase' })
  closeModal(); toast('Stock updated'); viewInventory()
}

// ---------------------------------------------------------------------------
// FINANCE APPROVAL QUEUE (Instruction 3 & 4) — authorized finance users supply
// the markup / rate / PAYGO / agreement components for drafted products, then
// publish them to the storefront. Also surfaces the hidden-product audit feed.
// ---------------------------------------------------------------------------
async function viewFinanceQueue() {
  let queue = [], audit = { hidden_products: [], count: 0, reminder: '' }
  try {
    const [q, a] = await Promise.all([
      api.get('/products/finance-queue'),
      api.get('/products/finance-audit')
    ])
    queue = q.data.products || []
    audit = a.data
  } catch (err) { toast(err.response?.data?.error || 'Failed to load queue', false) }
  const reminder = audit.count
    ? `<div class="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-sm text-amber-800 mb-4"><i class="fas fa-bell mr-2"></i>${esc(audit.reminder)}</div>`
    : `<div class="bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-3 text-sm text-emerald-800 mb-4"><i class="fas fa-circle-check mr-2"></i>${esc(audit.reminder || 'All products have complete financial parameters.')}</div>`
  const rows = queue.map(p => `<tr class="border-t border-slate-100">
      <td class="px-4 py-2">${prodImg(p, 'w-10 h-10 rounded-lg')}</td>
      <td class="px-4 py-3"><div class="font-medium">${esc(p.name)}</div><div class="text-xs text-slate-500">${esc(p.sku)} · ${esc(p.category || 'Feed')}</div></td>
      <td class="px-4 py-3 text-xs text-slate-500">${esc(p.created_by_name || '—')}</td>
      <td class="px-4 py-3 text-right">${fmt(p.buying_price)}</td>
      <td class="px-4 py-3 text-right">${p.quantity} ${esc(p.unit || '')}</td>
      <td class="px-4 py-3 text-right"><button onclick="financeModal(${p.id})" class="btn brand-bg text-white px-3 py-1.5 rounded-lg text-xs"><i class="fas fa-hand-holding-dollar mr-1"></i>Supply finance</button></td>
    </tr>`).join('')
  const auditRows = (audit.hidden_products || []).map(a => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3"><div class="font-medium">${esc(a.name)}</div><div class="text-xs text-slate-500">${esc(a.sku)}</div></td>
      <td class="px-4 py-3">${financeStatusBadge(a.finance_status)}</td>
      <td class="px-4 py-3">${a.missing_markup ? '<span class="text-red-600 text-xs"><i class="fas fa-triangle-exclamation mr-1"></i>markup</span>' : '<span class="text-emerald-600 text-xs">markup ok</span>'}</td>
      <td class="px-4 py-3">${a.missing_agreement ? '<span class="text-red-600 text-xs"><i class="fas fa-triangle-exclamation mr-1"></i>agreement</span>' : '<span class="text-emerald-600 text-xs">agreement ok</span>'}</td>
      <td class="px-4 py-3 text-xs text-slate-500">${esc(a.created_by_name || '—')}</td>
    </tr>`).join('')
  $('content').innerHTML = `
  ${reminder}
  <div class="card table-card mb-6">
    <div class="px-4 py-3 border-b font-semibold text-slate-700"><i class="fas fa-list-check text-teal-600 mr-2"></i>Products awaiting financial setup</div>
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Image</th><th class="text-left px-4 py-3">Feed</th><th class="text-left px-4 py-3">Listed by</th><th class="text-right px-4 py-3">Buying cost</th><th class="text-right px-4 py-3">Qty</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" class="text-center py-8 text-slate-400">Nothing awaiting finance approval</td></tr>'}</tbody>
    </table>
  </div>
  <div class="card table-card">
    <div class="px-4 py-3 border-b font-semibold text-slate-700"><i class="fas fa-eye-slash text-amber-500 mr-2"></i>Hidden from storefront (audit)</div>
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Feed</th><th class="text-left px-4 py-3">Status</th><th class="text-left px-4 py-3">Markup</th><th class="text-left px-4 py-3">Agreement</th><th class="text-left px-4 py-3">Listed by</th></tr></thead>
      <tbody>${auditRows || '<tr><td colspan="5" class="text-center py-8 text-slate-400">No hidden products</td></tr>'}</tbody>
    </table>
  </div>`
}
window.financeModal = async (id) => {
  // Load the current product (from cache if present) so we can prefill.
  let p = (_products || []).find(x => x.id === id)
  if (!p) {
    try { const { data } = await api.get('/products/finance-queue'); p = (data.products || []).find(x => x.id === id) || {} } catch (_) { p = {} }
  }
  p = p || {}
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-hand-holding-dollar text-teal-600 mr-2"></i>Supply financial components</h3>
    <p class="text-xs text-slate-500 mb-4">${esc(p.name || 'Product')} · ${esc(p.sku || '')}</p>
    <div class="responsive-grid cols-2 text-sm">
      <div><label class="field-label">Financing markup %</label><input id="fz_crm" type="number" value="${Number(p.credit_markup_pct || 20)}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Financing model</label><select id="fz_model" class="px-3 py-2 border rounded-lg">
        <option value="murabaha" selected>Murabaha (Sharia cost-plus, no interest)</option>
      </select></div>
      <div><label class="field-label">Interest / finance rate %</label><input id="fz_int" type="number" value="${Number(p.financing_interest_pct || 0)}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Repayment frequency</label><select id="fz_freq" class="px-3 py-2 border rounded-lg">
        ${['daily','weekly','monthly'].map(v => `<option value="${v}" ${(p.financing_frequency || 'monthly') === v ? 'selected' : ''}>${v}</option>`).join('')}
      </select></div>
      <div><label class="field-label">Minimum term (months)</label><input id="fz_tmin" type="number" value="${Number(p.financing_term_min_months || 3)}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Maximum term (months)</label><input id="fz_tmax" type="number" value="${Number(p.financing_term_max_months || 12)}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Financing deposit %</label><input id="fz_dep" type="number" value="${Number(p.financing_deposit_pct ?? 10)}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Payment availability</label><select id="fz_mode" class="px-3 py-2 border rounded-lg">
        <option value="both">Cash + Financing</option><option value="financing">Financing only</option><option value="cash">Cash only</option>
      </select></div>
      <div style="grid-column:1 / -1"><label class="field-label">Financing / PAYGO terms summary</label><textarea id="fz_terms" class="px-3 py-2 border rounded-lg min-h-20">${esc(p.financing_terms_text || '')}</textarea></div>
      <div style="grid-column:1 / -1"><label class="field-label">Financing agreement URL / file</label><input id="fz_doc" value="${esc(p.financing_terms_doc_url || '')}" placeholder="Agreement URL or uploaded file data" class="px-3 py-2 border rounded-lg text-xs"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Finance notes (optional)</label><input id="fz_notes" value="${esc(p.finance_notes || '')}" class="px-3 py-2 border rounded-lg text-xs"></div>
    </div>
    <div class="flex gap-2 mt-4">
      <button onclick="submitFinance(${id}, true)" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm"><i class="fas fa-check mr-1"></i>Publish to storefront</button>
      <button onclick="submitFinance(${id}, false)" class="btn px-4 bg-slate-100 rounded-lg text-sm">Save draft</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button>
    </div>`)
}
window.submitFinance = async (id, publish) => {
  const payload = {
    credit_markup_pct: Number($('fz_crm').value || 0),
    financing_model: $('fz_model').value,
    financing_interest_pct: Number($('fz_int').value || 0),
    financing_frequency: $('fz_freq').value,
    financing_term_min_months: Number($('fz_tmin').value || 3),
    financing_term_max_months: Number($('fz_tmax').value || 12),
    financing_deposit_pct: Number($('fz_dep').value || 10),
    payment_option_mode: $('fz_mode').value,
    financing_enabled: true,
    financing_terms_text: $('fz_terms').value || null,
    financing_terms_doc_url: $('fz_doc').value || null,
    finance_notes: $('fz_notes').value || null,
    finance_status: publish ? 'published' : 'pending_finance'
  }
  try {
    await api.put(`/products/${id}/finance`, payload)
    closeModal(); toast(publish ? 'Product published' : 'Finance draft saved'); viewFinanceQueue()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// WALLET SYSTEM (Instruction 7) — agent statement + admin management/payouts.
// ---------------------------------------------------------------------------
function ledgerRow(l) {
  const sign = l.entry_type === 'credit' ? '+' : '−'
  const color = l.entry_type === 'credit' ? 'text-emerald-600' : 'text-red-600'
  return `<tr class="border-t border-slate-100">
    <td class="px-4 py-3 text-xs text-slate-500">${esc((l.created_at || '').replace('T', ' ').slice(0, 16))}</td>
    <td class="px-4 py-3"><span class="badge bg-slate-100 text-slate-600">${esc(l.category || '—')}</span></td>
    <td class="px-4 py-3 text-xs text-slate-500">${esc(l.description || l.reference || '—')}</td>
    <td class="px-4 py-3 text-right font-medium ${color}">${sign} ${fmt(l.amount)}</td>
    <td class="px-4 py-3 text-right text-xs text-slate-500">${fmt(l.balance_after)}</td>
  </tr>`
}
async function viewMyWallet() {
  let wallet = null, ledger = [], rules = [], analytics = null
  try {
    const [w, a] = await Promise.all([api.get('/wallet'), api.get('/wallet/analytics')])
    wallet = w.data.wallet; ledger = w.data.ledger || []; rules = w.data.earning_rules || []
    analytics = a.data
  } catch (err) { toast(err.response?.data?.error || 'Wallet unavailable', false) }
  const rulesHtml = rules.length ? rules.map(r => `<div class="flex items-center justify-between border-b border-slate-100 py-2 text-sm">
      <span><b>${esc(r.rule_type)}</b> · ${esc(r.calc_method)}</span>
      <span class="text-slate-600">${r.calc_method === 'percentage' ? Number(r.rate || 0) + '%' : fmt(r.fixed_amount)}</span>
    </div>`).join('') : '<div class="text-sm text-slate-400 py-2">No earning rules assigned yet.</div>'
  $('content').innerHTML = `
  <div class="responsive-grid cols-3 mb-6">
    <div class="card p-5">
      <div class="text-xs text-slate-500 mb-1">Wallet balance</div>
      <div class="text-2xl font-bold text-teal-700">${fmt(wallet?.balance)}</div>
      <div class="text-xs text-slate-400 mt-1">${esc(wallet?.currency || 'KES')} · ${esc(wallet?.status || 'active')}</div>
      <button onclick="withdrawModal(${Number(wallet?.balance || 0)})" class="btn brand-bg text-white px-3 py-1.5 rounded-lg text-xs mt-3"><i class="fas fa-money-bill-transfer mr-1"></i>Withdraw</button>
      <button onclick="payoutAccountsModal()" class="btn bg-white border px-3 py-1.5 rounded-lg text-xs mt-3 ml-1"><i class="fas fa-building-columns mr-1"></i>Payout accounts</button>
    </div>
    <div class="card p-5"><div class="text-xs text-slate-500 mb-1">Total earned</div><div class="text-2xl font-bold text-emerald-600">${fmt(analytics?.totals?.total_earned)}</div></div>
    <div class="card p-5"><div class="text-xs text-slate-500 mb-1">Total debited</div><div class="text-2xl font-bold text-slate-600">${fmt(analytics?.totals?.total_debited)}</div></div>
  </div>
  <div class="card p-5 mb-6"><div class="font-semibold text-slate-700 mb-2"><i class="fas fa-sliders text-teal-600 mr-2"></i>My earning criteria</div>${rulesHtml}</div>
  <div class="card table-card">
    <div class="px-4 py-3 border-b font-semibold text-slate-700"><i class="fas fa-receipt text-teal-600 mr-2"></i>Wallet statement (double-entry ledger)</div>
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Date</th><th class="text-left px-4 py-3">Category</th><th class="text-left px-4 py-3">Detail</th><th class="text-right px-4 py-3">Amount</th><th class="text-right px-4 py-3">Balance</th></tr></thead>
      <tbody>${ledger.map(ledgerRow).join('') || '<tr><td colspan="5" class="text-center py-8 text-slate-400">No transactions yet</td></tr>'}</tbody>
    </table>
  </div>`
}
async function viewWallets() {
  let wallets = [], analytics = null
  try {
    const [w, a] = await Promise.all([api.get('/wallets'), api.get('/wallet/analytics')])
    wallets = w.data.wallets || []
    analytics = a.data
  } catch (err) { toast(err.response?.data?.error || 'Failed to load wallets', false) }
  _walletUsers = wallets
  const catRows = (analytics?.by_category || []).map(c => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3">${esc(c.category)}</td>
      <td class="px-4 py-3">${esc(c.entry_type)}</td>
      <td class="px-4 py-3 text-right">${c.entries}</td>
      <td class="px-4 py-3 text-right">${fmt(c.total)}</td>
    </tr>`).join('')
  const rows = wallets.map(w => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3"><div class="font-medium">${esc(w.full_name)}</div><div class="text-xs text-slate-500">${esc(w.phone || '')} · ${esc(roleLabel(w.role))}</div></td>
      <td class="px-4 py-3 text-right font-medium text-teal-700">${fmt(w.balance)}</td>
      <td class="px-4 py-3 text-center">${w.rule_count || 0}</td>
      <td class="px-4 py-3">${badge(w.status || 'active')}</td>
      <td class="px-4 py-3 text-right whitespace-nowrap">
        <button onclick="earningRulesModal(${w.user_id},'${esc(w.full_name)}')" class="text-teal-600 hover:underline text-xs mr-2">Earning rules</button>
        <button onclick="payoutModal(${w.user_id},'${esc(w.full_name)}')" class="text-slate-600 hover:underline text-xs">Pay out</button>
      </td>
    </tr>`).join('')
  $('content').innerHTML = `
  <div class="responsive-grid cols-3 mb-6">
    <div class="card p-5"><div class="text-xs text-slate-500 mb-1">Total credited (global)</div><div class="text-2xl font-bold text-emerald-600">${fmt(analytics?.totals?.total_earned)}</div></div>
    <div class="card p-5"><div class="text-xs text-slate-500 mb-1">Total debited (global)</div><div class="text-2xl font-bold text-slate-600">${fmt(analytics?.totals?.total_debited)}</div></div>
    <div class="card p-5 flex items-center justify-center"><button onclick="assignWalletModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Assign wallet</button></div>
  </div>
  <div class="flex flex-wrap gap-2 mb-4">
    <button onclick="batchPayoutModal('all_agents')" class="btn bg-white border px-4 py-2 rounded-lg text-sm"><i class="fas fa-money-check-dollar mr-1 text-teal-600"></i>Batch payout to all agents</button>
    <button onclick="directPayModal()" class="btn bg-white border px-4 py-2 rounded-lg text-sm"><i class="fas fa-paper-plane mr-1 text-teal-600"></i>Direct payment</button>
    <button onclick="checkSasaBalance()" class="btn bg-white border px-4 py-2 rounded-lg text-sm"><i class="fas fa-scale-balanced mr-1 text-teal-600"></i>Confirm SasaPay balance</button>
    <button onclick="loadPendingPayments()" class="btn bg-white border px-4 py-2 rounded-lg text-sm"><i class="fas fa-rotate mr-1 text-amber-600"></i>Recover pending payments</button>
  </div>
  <div id="sasaBalanceBox"></div>
  <div id="pendingPaymentsBox"></div>
  <div class="card table-card mb-6">
    <div class="px-4 py-3 border-b font-semibold text-slate-700"><i class="fas fa-wallet text-teal-600 mr-2"></i>Wallets</div>
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Holder</th><th class="text-right px-4 py-3">Balance</th><th class="text-center px-4 py-3">Rules</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="text-center py-8 text-slate-400">No wallets assigned</td></tr>'}</tbody>
    </table>
  </div>
  <div class="card table-card">
    <div class="px-4 py-3 border-b font-semibold text-slate-700"><i class="fas fa-chart-pie text-teal-600 mr-2"></i>Earning analytics by category</div>
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Category</th><th class="text-left px-4 py-3">Type</th><th class="text-right px-4 py-3">Entries</th><th class="text-right px-4 py-3">Total</th></tr></thead>
      <tbody>${catRows || '<tr><td colspan="4" class="text-center py-8 text-slate-400">No ledger activity yet</td></tr>'}</tbody>
    </table>
  </div>`
}
window.assignWalletModal = async () => {
  let users = []
  try { const { data } = await api.get('/users'); users = data.users || [] } catch (_) {}
  const existing = new Set((_walletUsers || []).map(w => w.user_id))
  const opts = users.filter(u => !existing.has(u.id)).map(u => `<option value="${u.id}">${esc(u.full_name)} · ${esc(roleLabel(u.role))}</option>`).join('')
  showModal(`<h3 class="font-bold mb-3"><i class="fas fa-user-plus text-teal-600 mr-2"></i>Assign / authorize wallet</h3>
    <label class="field-label">User</label>
    <select id="aw_user" class="w-full px-3 py-2 border rounded-lg mb-4">${opts || '<option value="">All users already have wallets</option>'}</select>
    <div class="flex gap-2"><button onclick="doAssignWallet()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Assign wallet</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAssignWallet = async () => {
  const userId = Number($('aw_user').value)
  if (!userId) return toast('Select a user', false)
  try { await api.post('/wallets', { user_id: userId }); closeModal(); toast('Wallet assigned'); viewWallets() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.earningRulesModal = async (userId, name) => {
  let rules = []
  try { const { data } = await api.get('/earning-rules/' + userId); rules = data.earning_rules || [] } catch (_) {}
  const list = rules.map(r => `<div class="flex items-center justify-between border-b border-slate-100 py-2 text-sm">
      <span><b>${esc(r.rule_type)}</b> · ${esc(r.calc_method)} · ${r.calc_method === 'percentage' ? Number(r.rate || 0) + '%' : fmt(r.fixed_amount)} <span class="text-xs text-slate-400">(${esc(r.applies_to || '')})</span></span>
      <span class="${r.is_active ? 'text-emerald-600' : 'text-slate-400'} text-xs">${r.is_active ? 'active' : 'inactive'}</span>
    </div>`).join('') || '<div class="text-sm text-slate-400 py-2">No rules yet.</div>'
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-sliders text-teal-600 mr-2"></i>Earning criteria — ${esc(name)}</h3>
    <p class="text-xs text-slate-500 mb-3">Define how ${esc(name)} earns: e.g. 2% commission on completed orders, KES 5,000 retainer, transport, per-diem.</p>
    <div class="mb-4">${list}</div>
    <div class="border-t pt-3 responsive-grid cols-2 text-sm">
      <div><label class="field-label">Rule type</label><input id="er_type" placeholder="commission / retainer / transport / per_diem" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Calculation</label><select id="er_calc" class="px-3 py-2 border rounded-lg" onchange="toggleErCalc()">
        <option value="percentage">Percentage of order</option><option value="fixed">Fixed amount</option>
      </select></div>
      <div id="er_rate_wrap"><label class="field-label">Rate %</label><input id="er_rate" type="number" value="2" class="px-3 py-2 border rounded-lg"></div>
      <div id="er_fixed_wrap" style="display:none"><label class="field-label">Fixed amount (KES)</label><input id="er_fixed" type="number" value="5000" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Applies to</label><select id="er_applies" class="px-3 py-2 border rounded-lg">
        <option value="completed_order">Completed order (auto)</option><option value="manual">Manual / payout</option>
      </select></div>
      <div><label class="field-label">Description</label><input id="er_desc" placeholder="e.g. Sales commission" class="px-3 py-2 border rounded-lg"></div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doAddEarningRule(${userId})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Add rule</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Close</button></div>`)
}
window.toggleErCalc = () => {
  const pct = $('er_calc').value === 'percentage'
  $('er_rate_wrap').style.display = pct ? '' : 'none'
  $('er_fixed_wrap').style.display = pct ? 'none' : ''
}
window.doAddEarningRule = async (userId) => {
  const calc = $('er_calc').value
  const payload = {
    user_id: userId,
    rule_type: $('er_type').value.trim(),
    calc_method: calc,
    rate: calc === 'percentage' ? Number($('er_rate').value || 0) : null,
    fixed_amount: calc === 'fixed' ? Number($('er_fixed').value || 0) : null,
    applies_to: $('er_applies').value,
    description: $('er_desc').value || null
  }
  if (!payload.rule_type) return toast('Rule type is required', false)
  try { await api.post('/earning-rules', payload); toast('Rule added'); earningRulesModal(userId, '') }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
// ---------------------------------------------------------------------------
// WALLET WITHDRAWAL — cash out to a registered mobile / bank / SasaPay account.
// ---------------------------------------------------------------------------
window.withdrawModal = async (balance) => {
  await loadSasaChannels()
  let accounts = []
  try { const { data } = await api.get('/payout-accounts'); accounts = data.accounts || [] } catch (_) {}
  const savedOpts = accounts.map(a => `<option value="${a.id}">${esc(a.label || a.channel_name)} · ${esc(a.account_number)}${a.is_verified ? ' ✓' : ''}</option>`).join('')
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-money-bill-transfer text-teal-600 mr-2"></i>Withdraw funds</h3>
    <p class="text-xs text-slate-500 mb-3">Available balance: <b>${fmt(balance)}</b>. Funds are sent via SasaPay to your mobile, bank, or SasaPay wallet.</p>
    ${savedOpts ? `<label class="field-label">Use a saved account</label>
    <select id="wd_saved" onchange="onWithdrawSavedChange()" class="w-full px-3 py-2 border rounded-lg mb-3">
      <option value="">— New / one-off destination —</option>${savedOpts}
    </select>` : ''}
    <div id="wd_manual" class="space-y-3">
      <div><label class="field-label">Destination type</label>
        <select id="wd_type" onchange="onWithdrawTypeChange()" class="w-full px-3 py-2 border rounded-lg">
          <option value="mobile">Mobile Money</option><option value="bank">Bank Account</option><option value="wallet">SasaPay Wallet</option>
        </select></div>
      <div><label class="field-label" id="wd_chanlbl">Network</label>
        <select id="wd_channel" class="w-full px-3 py-2 border rounded-lg"></select></div>
      <div><label class="field-label">Account / phone number</label>
        <div class="flex gap-2">
          <input id="wd_account" type="text" placeholder="e.g. 0712345678" class="flex-1 px-3 py-2 border rounded-lg">
          <button type="button" onclick="doValidateWithdrawAccount()" class="btn px-3 bg-slate-100 rounded-lg text-xs whitespace-nowrap">Verify</button>
        </div>
        <div id="wd_acctname" class="text-xs text-emerald-700 mt-1"></div></div>
    </div>
    <label class="field-label mt-3">Amount (KES)</label><input id="wd_amt" type="number" class="w-full px-3 py-2 border rounded-lg mb-3">
    <label class="field-label">Reason (optional)</label><input id="wd_reason" placeholder="e.g. Cash out earnings" class="w-full px-3 py-2 border rounded-lg mb-3">
    <div id="wd_status"></div>
    <div class="flex gap-2 mt-2"><button id="wd_btn" onclick="doWithdraw()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Withdraw</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  onWithdrawTypeChange()
}
window.onWithdrawTypeChange = () => {
  const type = $('wd_type')?.value || 'mobile'
  const sel = $('wd_channel'); const lbl = $('wd_chanlbl')
  const cat = _sasaChannels || { mobile: [], banks: [], wallet: [] }
  let list = type === 'mobile' ? (cat.mobile || []) : type === 'bank' ? (cat.banks || cat.bank || []) : (cat.wallet || [])
  if (lbl) lbl.textContent = type === 'bank' ? 'Select Bank' : (type === 'wallet' ? 'Wallet' : 'Network')
  if (sel) sel.innerHTML = list.map(ch => `<option value="${esc(ch.code)}">${esc(ch.name)}</option>`).join('') || '<option value="">— none —</option>'
}
window.onWithdrawSavedChange = () => {
  const saved = $('wd_saved')?.value
  const manual = $('wd_manual')
  if (manual) manual.style.display = saved ? 'none' : ''
}
window.doValidateWithdrawAccount = async () => {
  const code = $('wd_channel')?.value; const acc = $('wd_account')?.value; const nm = $('wd_acctname')
  if (!code || !acc) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = 'Enter an account number first.' } return }
  if (nm) { nm.className = 'text-xs text-slate-500 mt-1'; nm.textContent = 'Verifying…' }
  try {
    const { data } = await api.post('/sasapay/validate-account', { channel_code: code, account_number: acc })
    if (nm) { nm.className = 'text-xs text-emerald-700 mt-1'; nm.textContent = data.account_name ? ('✓ ' + data.account_name) : '✓ Verified' }
  } catch (err) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = err.response?.data?.error || 'Could not verify.' } }
}
window.doWithdraw = async () => {
  const amount = Number($('wd_amt')?.value || 0)
  if (amount <= 0) return toast('Enter a valid amount', false)
  const payload = { amount, reason: $('wd_reason')?.value || null }
  const saved = $('wd_saved')?.value
  if (saved) payload.payout_account_id = Number(saved)
  else { payload.channel_code = $('wd_channel')?.value; payload.account_number = $('wd_account')?.value }
  const btn = $('wd_btn'); btn.disabled = true; btn.classList.add('opacity-50')
  $('wd_status').innerHTML = `<div class="text-xs text-slate-500 mb-2"><i class="fas fa-spinner fa-spin mr-1"></i>Processing withdrawal…</div>`
  try {
    const { data } = await api.post('/wallet/withdraw', payload)
    closeModal(); toast(data.customer_message || `Withdrawal ${data.status} (${data.reference})`); viewMyWallet()
  } catch (err) {
    $('wd_status').innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-2">${esc(err.response?.data?.error || 'Withdrawal failed')}</div>`
    btn.disabled = false; btn.classList.remove('opacity-50')
  }
}

// ---------------------------------------------------------------------------
// PAYOUT ACCOUNTS — register/manage validated mobile & bank destinations.
// ---------------------------------------------------------------------------
window.payoutAccountsModal = async () => {
  await loadSasaChannels()
  let accounts = []
  try { const { data } = await api.get('/payout-accounts'); accounts = data.accounts || [] } catch (_) {}
  const list = accounts.map(a => `<div class="flex items-center justify-between border-b border-slate-100 py-2 text-sm">
      <span><b>${esc(a.label || a.channel_name)}</b> · ${esc(a.account_number)} ${a.is_verified ? '<span class="text-emerald-600 text-xs">✓ verified</span>' : '<span class="text-amber-600 text-xs">unverified</span>'}${a.account_name ? ' · ' + esc(a.account_name) : ''}</span>
      <button onclick="delPayoutAccount(${a.id})" class="text-red-500 hover:underline text-xs">Remove</button>
    </div>`).join('') || '<div class="text-sm text-slate-400 py-2">No payout accounts yet.</div>'
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-building-columns text-teal-600 mr-2"></i>My payout accounts</h3>
    <p class="text-xs text-slate-500 mb-3">Register the mobile / bank destinations you can withdraw to. Each is validated with SasaPay.</p>
    <div class="mb-4">${list}</div>
    <div class="border-t pt-3 space-y-2">
      <div><label class="field-label">Type</label>
        <select id="pa_type" onchange="onPayoutAcctType()" class="w-full px-3 py-2 border rounded-lg">
          <option value="mobile">Mobile Money</option><option value="bank">Bank Account</option><option value="wallet">SasaPay Wallet</option>
        </select></div>
      <div><label class="field-label" id="pa_chanlbl">Network</label><select id="pa_channel" class="w-full px-3 py-2 border rounded-lg"></select></div>
      <div><label class="field-label">Account / phone number</label><input id="pa_account" class="w-full px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Label (optional)</label><input id="pa_label" placeholder="e.g. My M-PESA" class="w-full px-3 py-2 border rounded-lg"></div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doAddPayoutAccount()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Add & verify</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Close</button></div>`)
  onPayoutAcctType()
}
window.onPayoutAcctType = () => {
  const type = $('pa_type')?.value || 'mobile'
  const sel = $('pa_channel'); const lbl = $('pa_chanlbl')
  const cat = _sasaChannels || { mobile: [], banks: [], wallet: [] }
  let list = type === 'mobile' ? (cat.mobile || []) : type === 'bank' ? (cat.banks || cat.bank || []) : (cat.wallet || [])
  if (lbl) lbl.textContent = type === 'bank' ? 'Select Bank' : (type === 'wallet' ? 'Wallet' : 'Network')
  if (sel) sel.innerHTML = list.map(ch => `<option value="${esc(ch.code)}">${esc(ch.name)}</option>`).join('') || '<option value="">— none —</option>'
}
window.doAddPayoutAccount = async () => {
  const payload = { channel_code: $('pa_channel')?.value, account_number: $('pa_account')?.value, label: $('pa_label')?.value || null }
  if (!payload.channel_code || !payload.account_number) return toast('Channel and account number required', false)
  try { const { data } = await api.post('/payout-accounts', payload); toast(data.is_verified ? ('Added: ' + (data.account_name || 'verified')) : 'Added (unverified)'); payoutAccountsModal() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.delPayoutAccount = async (id) => {
  try { await api.delete('/payout-accounts/' + id); payoutAccountsModal() } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

window.payoutModal = (userId, name) => {
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-money-check-dollar text-teal-600 mr-2"></i>Pay out — ${esc(name)}</h3>
    <p class="text-xs text-slate-500 mb-3">Disburse fixed funds (retainer, transport, per-diem) directly to this wallet.</p>
    <div class="responsive-grid cols-2 text-sm">
      <div><label class="field-label">Category</label><select id="po_cat" class="px-3 py-2 border rounded-lg">
        <option value="retainer">Retainer</option><option value="transport">Transport</option><option value="per_diem">Per-diem</option><option value="bonus">Bonus</option>
      </select></div>
      <div><label class="field-label">Amount (KES)</label><input id="po_amt" type="number" value="5000" class="px-3 py-2 border rounded-lg"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Description</label><input id="po_desc" placeholder="e.g. March retainer" class="px-3 py-2 border rounded-lg"></div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doPayout(${userId})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Disburse</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doPayout = async (userId) => {
  const payload = { user_id: userId, category: $('po_cat').value, amount: Number($('po_amt').value || 0), description: $('po_desc').value || null }
  if (payload.amount <= 0) return toast('Amount must be greater than zero', false)
  try { const { data } = await api.post('/wallet/payouts', payload); closeModal(); toast(`Paid out ${fmt(data.total)} (${data.batch_ref})`); viewWallets() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.batchPayoutModal = (target) => {
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-users text-teal-600 mr-2"></i>Batch payout — all active agents</h3>
    <p class="text-xs text-slate-500 mb-3">Process a fixed disbursal to every active agent wallet at once.</p>
    <div class="responsive-grid cols-2 text-sm">
      <div><label class="field-label">Category</label><select id="bp_cat" class="px-3 py-2 border rounded-lg">
        <option value="retainer">Retainer</option><option value="transport">Transport</option><option value="per_diem">Per-diem</option>
      </select></div>
      <div><label class="field-label">Amount per agent (KES)</label><input id="bp_amt" type="number" value="5000" class="px-3 py-2 border rounded-lg"></div>
      <div style="grid-column:1 / -1"><label class="field-label">Description</label><input id="bp_desc" placeholder="e.g. Monthly retainer batch" class="px-3 py-2 border rounded-lg"></div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doBatchPayout('${target}')" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Disburse to all agents</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doBatchPayout = async (target) => {
  const payload = { target, category: $('bp_cat').value, amount: Number($('bp_amt').value || 0), description: $('bp_desc').value || null }
  if (payload.amount <= 0) return toast('Amount must be greater than zero', false)
  if (!confirmEdit('Disburse ' + fmt(payload.amount) + ' to every active agent?')) return
  try { const { data } = await api.post('/wallet/payouts', payload); closeModal(); toast(`Paid ${data.count} agent(s), total ${fmt(data.total)}`); viewWallets() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// ADMIN DIRECT PAYMENT — pay an individual directly to their in-app wallet or
// to a mobile/bank number via SasaPay B2C.
// ---------------------------------------------------------------------------
window.directPayModal = async () => {
  await loadSasaChannels()
  let users = []
  try { const { data } = await api.get('/users'); users = data.users || [] } catch (_) {}
  const userOpts = users.map(u => `<option value="${u.id}">${esc(u.full_name)} · ${esc(roleLabel(u.role))}</option>`).join('')
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-paper-plane text-teal-600 mr-2"></i>Direct payment to an individual</h3>
    <p class="text-xs text-slate-500 mb-3">Pay someone directly — credit their in-app wallet, or push funds to a mobile / bank number via SasaPay.</p>
    <label class="field-label">Destination</label>
    <select id="dp_dest" onchange="onDirectPayDest()" class="w-full px-3 py-2 border rounded-lg mb-3">
      <option value="wallet">In-app wallet (user)</option>
      <option value="external">Mobile / Bank (SasaPay)</option>
    </select>
    <div id="dp_wallet_wrap">
      <label class="field-label">User</label>
      <select id="dp_user" class="w-full px-3 py-2 border rounded-lg mb-3">${userOpts || '<option value="">No users</option>'}</select>
    </div>
    <div id="dp_ext_wrap" style="display:none" class="space-y-3 mb-3">
      <div><label class="field-label">Type</label>
        <select id="dp_type" onchange="onDirectPayType()" class="w-full px-3 py-2 border rounded-lg">
          <option value="mobile">Mobile Money</option><option value="bank">Bank Account</option><option value="wallet">SasaPay Wallet</option>
        </select></div>
      <div><label class="field-label" id="dp_chanlbl">Network</label><select id="dp_channel" class="w-full px-3 py-2 border rounded-lg"></select></div>
      <div><label class="field-label">Account / phone number</label>
        <div class="flex gap-2">
          <input id="dp_account" class="flex-1 px-3 py-2 border rounded-lg" placeholder="e.g. 0712345678">
          <button type="button" onclick="doValidateDirectAccount()" class="btn px-3 bg-slate-100 rounded-lg text-xs whitespace-nowrap">Verify</button>
        </div>
        <div id="dp_acctname" class="text-xs text-emerald-700 mt-1"></div></div>
    </div>
    <label class="field-label">Amount (KES)</label><input id="dp_amt" type="number" class="w-full px-3 py-2 border rounded-lg mb-3">
    <label class="field-label">Reason</label><input id="dp_reason" placeholder="e.g. Supplier payment" class="w-full px-3 py-2 border rounded-lg mb-3">
    <div id="dp_status"></div>
    <div class="flex gap-2 mt-2"><button id="dp_btn" onclick="doDirectPay()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Send payment</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  onDirectPayType()
}
window.onDirectPayDest = () => {
  const ext = $('dp_dest')?.value === 'external'
  $('dp_wallet_wrap').style.display = ext ? 'none' : ''
  $('dp_ext_wrap').style.display = ext ? '' : 'none'
}
window.onDirectPayType = () => {
  const type = $('dp_type')?.value || 'mobile'
  const sel = $('dp_channel'); const lbl = $('dp_chanlbl')
  const cat = _sasaChannels || { mobile: [], banks: [], wallet: [] }
  let list = type === 'mobile' ? (cat.mobile || []) : type === 'bank' ? (cat.banks || cat.bank || []) : (cat.wallet || [])
  if (lbl) lbl.textContent = type === 'bank' ? 'Select Bank' : (type === 'wallet' ? 'Wallet' : 'Network')
  if (sel) sel.innerHTML = list.map(ch => `<option value="${esc(ch.code)}">${esc(ch.name)}</option>`).join('') || '<option value="">— none —</option>'
}
window.doValidateDirectAccount = async () => {
  const code = $('dp_channel')?.value; const acc = $('dp_account')?.value; const nm = $('dp_acctname')
  if (!code || !acc) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = 'Enter an account number first.' } return }
  if (nm) { nm.className = 'text-xs text-slate-500 mt-1'; nm.textContent = 'Verifying…' }
  try {
    const { data } = await api.post('/sasapay/validate-account', { channel_code: code, account_number: acc })
    if (nm) { nm.className = 'text-xs text-emerald-700 mt-1'; nm.textContent = data.account_name ? ('✓ ' + data.account_name) : '✓ Verified' }
  } catch (err) { if (nm) { nm.className = 'text-xs text-red-600 mt-1'; nm.textContent = err.response?.data?.error || 'Could not verify.' } }
}
window.doDirectPay = async () => {
  const amount = Number($('dp_amt')?.value || 0)
  if (amount <= 0) return toast('Enter a valid amount', false)
  const destination = $('dp_dest')?.value || 'wallet'
  const payload = { destination, amount, reason: $('dp_reason')?.value || null }
  if (destination === 'wallet') { payload.user_id = Number($('dp_user')?.value); if (!payload.user_id) return toast('Select a user', false) }
  else { payload.channel_code = $('dp_channel')?.value; payload.account_number = $('dp_account')?.value; if (!payload.channel_code || !payload.account_number) return toast('Channel and account required', false) }
  const btn = $('dp_btn'); btn.disabled = true; btn.classList.add('opacity-50')
  $('dp_status').innerHTML = `<div class="text-xs text-slate-500 mb-2"><i class="fas fa-spinner fa-spin mr-1"></i>Processing payment…</div>`
  try {
    const { data } = await api.post('/wallet/direct-pay', payload)
    closeModal(); toast(data.customer_message || `Payment ${data.status} (${data.reference})`); viewWallets()
  } catch (err) {
    $('dp_status').innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-2">${esc(err.response?.data?.error || 'Payment failed')}</div>`
    btn.disabled = false; btn.classList.remove('opacity-50')
  }
}

// Confirm SasaPay merchant/organisation float balance.
window.checkSasaBalance = async () => {
  const box = $('sasaBalanceBox')
  if (box) box.innerHTML = `<div class="card p-4 mb-4 text-sm text-slate-500"><i class="fas fa-spinner fa-spin mr-1"></i>Querying SasaPay balance…</div>`
  try {
    const { data } = await api.get('/sasapay/balance')
    const accts = (data.accounts || []).map(a => `<div class="flex justify-between border-b border-slate-100 py-1"><span>${esc(a.label || a.account || a.AccountType || 'Account')}</span><span class="font-medium">${fmt(a.balance ?? a.Balance ?? a.available ?? 0)}</span></div>`).join('')
    if (box) box.innerHTML = `<div class="card p-4 mb-4">
      <div class="flex items-center justify-between mb-2"><span class="font-semibold text-slate-700"><i class="fas fa-scale-balanced text-teal-600 mr-2"></i>SasaPay balance${data.simulated ? ' <span class="text-[10px] text-amber-600">(simulation)</span>' : ''}</span><span class="text-lg font-bold text-teal-700">${fmt(data.org_balance)}</span></div>
      <div class="text-sm">${accts || '<div class="text-slate-400">No account breakdown returned.</div>'}</div>
    </div>`
  } catch (err) {
    if (box) box.innerHTML = `<div class="card p-4 mb-4 text-sm text-red-600">${esc(err.response?.data?.error || 'Balance query failed')}</div>`
  }
}

// ---------------------------------------------------------------------------
// PENDING PAYMENT RECOVERY (admin) — Issue 3
//   Lists payment intents stuck in 'pending' (money may have already reached
//   the SasaPay merchant wallet but the async callback never settled the
//   contract). Operators can (a) re-query the gateway to auto-settle if paid,
//   or (b) force-complete a genuinely paid transaction manually.
// ---------------------------------------------------------------------------
window.loadPendingPayments = async () => {
  const box = $('pendingPaymentsBox')
  if (!box) return
  box.innerHTML = `<div class="card p-4 mb-6 text-sm text-slate-500"><i class="fas fa-spinner fa-spin mr-1"></i>Loading pending payments…</div>`
  try {
    const { data } = await api.get('/admin/payments/pending')
    const intents = data.intents || []
    const rows = intents.map(p => {
      const cid = esc(p.checkout_request_id)
      const when = p.created_at ? esc(String(p.created_at).replace('T', ' ').slice(0, 16)) : '—'
      return `<tr class="border-t border-slate-100" id="pi-row-${cid}">
        <td class="px-4 py-3">
          <div class="font-medium">${esc(p.customer_name || '—')}</div>
          <div class="text-xs text-slate-500">${esc(p.contract_ref || '')} · ${esc(p.channel_name || p.channel_code || '')}</div>
          <div class="text-[10px] text-slate-400 break-all">${cid}</div>
        </td>
        <td class="px-4 py-3 text-right font-medium text-teal-700">${fmt(p.amount)}</td>
        <td class="px-4 py-3 text-xs text-slate-500">${when}</td>
        <td class="px-4 py-3">
          <span class="text-amber-600 bg-amber-50 px-2 py-1 rounded text-xs font-semibold">PENDING</span>
        </td>
        <td class="px-4 py-3 text-right whitespace-nowrap">
          <button onclick="recoverPayment('${cid}','query')" class="btn bg-teal-600 hover:bg-teal-700 text-white text-xs px-3 py-1.5 rounded mr-1"><i class="fas fa-rotate mr-1"></i>Query gateway</button>
          <button onclick="recoverPayment('${cid}','force')" class="btn bg-slate-800 hover:bg-slate-900 text-white text-xs px-3 py-1.5 rounded"><i class="fas fa-check-double mr-1"></i>Force complete</button>
        </td>
      </tr>`
    }).join('')
    box.innerHTML = `<div class="card table-card mb-6">
      <div class="px-4 py-3 border-b font-semibold text-slate-700 flex items-center justify-between">
        <span><i class="fas fa-triangle-exclamation text-amber-600 mr-2"></i>Pending payments (${intents.length})</span>
        <button onclick="loadPendingPayments()" class="text-xs text-teal-600 hover:underline"><i class="fas fa-arrows-rotate mr-1"></i>Refresh</button>
      </div>
      <table class="w-full text-sm">
        <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
          <th class="text-left px-4 py-3">Customer / Ref</th>
          <th class="text-right px-4 py-3">Amount</th>
          <th class="text-left px-4 py-3">Created</th>
          <th class="text-left px-4 py-3">Status</th>
          <th></th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="text-center py-8 text-emerald-600"><i class="fas fa-circle-check mr-1"></i>No pending payments — all settled.</td></tr>'}</tbody>
      </table>
    </div>`
  } catch (err) {
    box.innerHTML = `<div class="card p-4 mb-6 text-sm text-red-600">${esc(err.response?.data?.error || 'Failed to load pending payments (permission or network).')}</div>`
  }
}

window.recoverPayment = async (checkoutId, mode) => {
  const isForce = mode === 'force'
  const confirmMsg = isForce
    ? 'FORCE COMPLETE this payment? Only do this if you have confirmed the funds reached the SasaPay merchant wallet. This will settle the contract and update balances.'
    : 'Re-query SasaPay for this transaction and settle automatically if it reports as paid?'
  if (!confirm(confirmMsg)) return
  const row = $(`pi-row-${checkoutId}`)
  try {
    const { data } = await api.post('/admin/payments/recover', { checkout_request_id: checkoutId, mode })
    if (data.status === 'success') {
      toast(`Payment settled${data.forced ? ' (forced)' : ''}. Receipt: ${data.mpesa_receipt || '—'}`)
      if (row) row.remove()
      setTimeout(loadPendingPayments, 600)
    } else if (data.status === 'failed') {
      toast('Gateway reports this payment FAILED: ' + (data.result_desc || 'not completed'), false)
      setTimeout(loadPendingPayments, 600)
    } else {
      toast('Gateway still processing — funds not yet confirmed. Try again shortly or use Force complete if confirmed.', false)
    }
  } catch (err) {
    toast(err.response?.data?.error || 'Recovery failed (permission or network).', false)
  }
}

// ---------------------------------------------------------------------------
// CUSTOMERS + Complete Registration (TransUnion + Selfie Upload)
// ---------------------------------------------------------------------------
async function viewCustomers() {
  const { data } = await api.get('/customers')
  _customers = data.customers || []
  const isAdmin = ['admin', 'super_admin'].includes(state.user.role)
  const canEditFarmers = isAdmin || state.user.role === 'agent'
  const actionBar = canDo('add_farmer') || isAdmin
    ? `<div class="action-bar"><button onclick="viewOnboard()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Add Farmer</button></div>`
    : ''
  $('content').innerHTML = `${actionBar}<div class="card table-card"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Farmer</th><th class="text-left px-4 py-3">Mobile</th><th class="text-left px-4 py-3">County</th><th class="text-left px-4 py-3">Value Chain</th><th class="text-left px-4 py-3">KYC</th><th class="text-left px-4 py-3">Profile Status</th><th class="text-left px-4 py-3">Risk</th><th></th></tr></thead>
    <tbody>${_customers.map(c => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3"><div class="font-medium">${esc(c.full_name)}</div><div class="text-xs text-slate-400">ID ${esc(c.national_id || '—')}</div></td>
      <td class="px-4 py-3">${esc(c.mobile || '—')}</td>
      <td class="px-4 py-3">${esc(c.county || '—')}</td>
      <td class="px-4 py-3">${esc(c.value_chain || '—')}</td>
      <td class="px-4 py-3">${badge(c.kyc_status)}</td>
      <td class="px-4 py-3">${badge(c.status || 'active')}</td>
      <td class="px-4 py-3">${c.risk_band ? badge(c.risk_band) : '—'}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="custDetail(${c.id})" class="text-slate-500 hover:underline text-xs mr-2">View</button>
        ${canEditFarmers ? `<button onclick="editCustomerModal(${c.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>` : ''}
        ${c.kyc_status !== 'verified' ? `<button onclick="completeRegistration(${c.id})" class="text-blue-600 hover:underline text-xs mr-2"><i class="fas fa-id-card mr-1"></i>Complete Registration</button>` : ''}
        ${isAdmin ? `${(c.status || 'active') === 'active' ? `<button onclick="setCustomerStatus(${c.id},'suspended','${esc(c.full_name)}')" class="text-amber-600 hover:underline text-xs mr-2">Suspend</button>` : `<button onclick="setCustomerStatus(${c.id},'active','${esc(c.full_name)}')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}<button onclick="deleteCustomer(${c.id},'${esc(c.full_name)}')" class="text-red-600 hover:underline text-xs">Delete</button>` : ''}
      </td></tr>`).join('') || '<tr><td colspan="8" class="text-center py-8 text-slate-400">No customers</td></tr>'}</tbody>
  </table></div>`
}
window.custDetail = async (id) => {
  const { data } = await api.get('/customers/' + id)
  const c = data.customer, tu = data.transunion, idv = data.id_verification
  const isAdmin = ['admin', 'super_admin'].includes(state.user.role)
  const canEditFarmers = isAdmin || state.user.role === 'agent'
  showModal(`
    <h3 class="text-lg font-bold mb-1">${esc(c.full_name)}</h3>
    <p class="text-xs text-slate-500 mb-4">ID ${esc(c.national_id || '—')} · ${esc(c.mobile || '—')} · ${esc(c.county || '')}</p>
    <div class="responsive-grid cols-2 text-sm mb-4">
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Value Chain</p><b>${esc(c.value_chain_type || '—')} / ${esc(c.value_chain || '—')}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">KYC Status</p>${badge(c.kyc_status)}</div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Profile Status</p>${badge(c.status || 'active')}</div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Current Loan Amount</p><b>${esc(c.existing_loans || '—')}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">GPS</p><b>${c.latitude ? c.latitude + ', ' + c.longitude : '—'}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">SACCO Member</p><b>${esc((c.sacco_membership || 'no').toUpperCase())}</b></div>
    </div>
    <div class="border rounded-xl p-4 mb-4 ${tu ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200'}">
      <h4 class="font-semibold text-sm mb-2"><i class="fas fa-chart-line mr-1 text-teal-600"></i>TransUnion Credit Check</h4>
      ${tu ? `<div class="text-sm flex flex-wrap gap-4"><span>Score: <b>${tu.credit_score}</b></span><span>Band: ${badge(tu.risk_band)}</span><span>Defaults: <b>${tu.defaults_found}</b></span></div>` : '<p class="text-xs text-slate-400">Not yet run.</p>'}
    </div>
    <div class="border rounded-xl p-4 mb-4 ${idv ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200'}">
      <h4 class="font-semibold text-sm mb-2"><i class="fas fa-id-card mr-1 text-teal-600"></i>ID & Selfie Verification</h4>
      ${idv ? `<div class="text-sm flex flex-wrap gap-4"><span>Face match: <b>${idv.face_match ? '✓' : '✗'}</b></span><span>Liveness: <b>${idv.liveness ? '✓' : '✗'}</b></span><span>Status: ${badge(idv.status)}</span></div>` : '<p class="text-xs text-slate-400">Not yet run.</p>'}
    </div>
    ${c.id_front_url ? `<div class="responsive-grid cols-2 mb-3"><img src="${esc(c.id_front_url)}" class="w-full h-32 object-cover rounded-lg border"><img src="${esc(c.id_back_url || c.id_front_url)}" class="w-full h-32 object-cover rounded-lg border"></div>` : '<p class="text-xs text-amber-600 mb-3">National ID images not uploaded yet.</p>'}
    <div class="action-bar mt-4">
      ${c.kyc_status !== 'verified' ? `<button onclick="completeRegistration(${c.id})" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-shield-halved mr-1"></i>Complete Registration</button>` : ''}
      ${canEditFarmers ? `<button onclick="closeModal();editCustomerModal(${c.id})" class="btn bg-slate-100 px-4 py-2 rounded-lg text-sm">Edit Profile</button>` : ''}
      ${isAdmin ? `${(c.status || 'active') === 'active' ? `<button onclick="closeModal();setCustomerStatus(${c.id},'suspended','${esc(c.full_name)}')" class="btn bg-amber-100 text-amber-800 px-4 py-2 rounded-lg text-sm">Suspend Farmer</button>` : `<button onclick="closeModal();setCustomerStatus(${c.id},'active','${esc(c.full_name)}')" class="btn bg-emerald-100 text-emerald-800 px-4 py-2 rounded-lg text-sm">Activate Farmer</button>`}<button onclick="closeModal();deleteCustomer(${c.id},'${esc(c.full_name)}')" class="btn bg-red-100 text-red-700 px-4 py-2 rounded-lg text-sm">Delete Farmer</button>` : ''}
      <button onclick="closeModal()" class="btn bg-slate-100 px-4 py-2 rounded-lg text-sm">Close</button>
    </div>`)
}
window.editCustomerModal = (id) => {
  const c = _customers.find((x) => x.id === id)
  if (!c) return toast('Farmer record not loaded', false)
  showModal(`<h3 class="font-bold mb-1">Edit Farmer Profile</h3>
    <p class="text-xs text-slate-500 mb-3">Update the farmer profile, then confirm before saving the changes.</p>
    <div class="responsive-grid cols-2 text-sm">
      <div><label class="field-label">Full name</label><input id="cf_name" value="${esc(c.full_name || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">National ID</label><input id="cf_id" value="${esc(c.national_id || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Mobile number</label><input id="cf_mobile" value="${esc(c.mobile || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Alternative number</label><input id="cf_alt_mobile" value="${esc(c.alt_mobile || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">County</label><input id="cf_county" value="${esc(c.county || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Value chain</label><input id="cf_value_chain" value="${esc(c.value_chain || '')}" class="px-3 py-2 border rounded-lg"></div>
      <div><label class="field-label">Current loan amount</label><input id="cf_loans" value="${esc(c.existing_loans || '')}" class="px-3 py-2 border rounded-lg" placeholder="Loan amount"></div>
      <div><label class="field-label">SACCO membership</label><select id="cf_sacco" class="px-3 py-2 border rounded-lg"><option value="yes" ${(c.sacco_membership || '').toLowerCase() === 'yes' ? 'selected' : ''}>Yes</option><option value="no" ${(c.sacco_membership || '').toLowerCase() !== 'yes' ? 'selected' : ''}>No</option></select></div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doEditCustomer(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Farmer Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditCustomer = async (id) => {
  if (!confirmEdit('Save changes to this farmer profile?')) return
  try {
    await api.put('/customers/' + id, {
      full_name: $('cf_name').value,
      national_id: $('cf_id').value,
      mobile: $('cf_mobile').value,
      alt_mobile: $('cf_alt_mobile').value,
      county: $('cf_county').value,
      value_chain: $('cf_value_chain').value,
      existing_loans: $('cf_loans').value,
      sacco_membership: $('cf_sacco').value
    })
    closeModal(); toast('Farmer profile updated'); viewCustomers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.setCustomerStatus = async (id, status, name) => {
  if (!confirmStatus(`${status === 'active' ? 'Activate' : 'Suspend'} farmer profile for "${name}"?`)) return
  try { await api.put(`/customers/${id}/status`, { status }); toast('Farmer status updated'); viewCustomers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteCustomer = async (id, name) => {
  if (!confirmDelete(`Delete farmer profile for "${name}"? This also removes the linked farmer account.`)) return
  try { await api.delete('/customers/' + id); toast('Farmer deleted'); viewCustomers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.stopLive = () => {}
window.completeRegistration = async (id, returnToShop) => {
  let customer = {}
  try { const { data } = await api.get('/customers/' + id); customer = data.customer || {} } catch {}
  const hasFront = !!customer.id_front_url
  const hasBack = !!customer.id_back_url
  showModal(`<div>
    <h3 class="text-lg font-bold mb-1"><i class="fas fa-camera text-teal-600 mr-2"></i>ID / Selfie Verification</h3>
    <p class="text-xs text-slate-500 mb-4">Capture in this order: ID front → ID back → passport photo/selfie.</p>
    <div class="space-y-4">
      ${kycStepCard({ sectionId: 'cr_front_section', title: 'Step 1 — National ID front', subtitle: 'Upload from gallery or use the back camera.', previewId: 'cr_front_preview', statusId: 'cr_front_status', hiddenId: 'cr_id_front_url', galleryId: 'cr_front_gallery', cameraId: 'cr_front_camera', cameraFacing: 'environment', cameraLabel: 'Open back camera', nextSectionId: 'cr_back_section', value: customer.id_front_url || '', previewHtml: customer.id_front_url ? `<img src="${esc(customer.id_front_url)}" class="w-full h-40 rounded-xl object-cover border border-slate-200">` : '', statusText: customer.id_front_url ? '<span class="text-emerald-600"><i class="fas fa-circle-check mr-1"></i>Captured</span>' : 'Required' })}
      ${kycStepCard({ sectionId: 'cr_back_section', title: 'Step 2 — National ID back', subtitle: 'Unlocks after the front image is captured.', previewId: 'cr_back_preview', statusId: 'cr_back_status', hiddenId: 'cr_id_back_url', galleryId: 'cr_back_gallery', cameraId: 'cr_back_camera', cameraFacing: 'environment', cameraLabel: 'Open back camera', nextSectionId: 'cr_selfie_section', hidden: !hasFront, value: customer.id_back_url || '', previewHtml: customer.id_back_url ? `<img src="${esc(customer.id_back_url)}" class="w-full h-40 rounded-xl object-cover border border-slate-200">` : '', statusText: customer.id_back_url ? '<span class="text-emerald-600"><i class="fas fa-circle-check mr-1"></i>Captured</span>' : 'Required' })}
      ${kycStepCard({ sectionId: 'cr_selfie_section', title: 'Step 3 — Passport photo / live selfie', subtitle: 'Open the front camera for liveness verification.', previewId: 'cr_selfie_preview', statusId: 'cr_selfie_status', hiddenId: 'cr_selfie_url', galleryId: 'cr_selfie_gallery', cameraId: 'cr_selfie_camera', cameraFacing: 'user', cameraLabel: 'Open front camera', hidden: !(hasFront && hasBack) })}
    </div>
    <div id="regStatus" class="text-xs text-slate-500 mt-4">Capture all required images, then run verification.</div>
    <button id="captureBtn" onclick="runChecks(${id}, ${!!returnToShop})" class="btn w-full brand-bg text-white py-2.5 rounded-lg text-sm mt-4"><i class="fas fa-circle-check mr-1"></i>Verify Farmer</button>
    <button onclick="closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Cancel</button>
  </div>`)
}
window.runChecks = async (id, returnToShop) => {
  const btn = $('captureBtn'); if (btn) { btn.disabled = true; btn.classList.add('opacity-50') }
  const id_front_url = $('cr_id_front_url')?.value || ''
  const id_back_url = $('cr_id_back_url')?.value || ''
  const selfie_url = $('cr_selfie_url')?.value || ''
  if (!id_front_url) { $('regStatus').innerHTML = '<span class="text-amber-600">Capture the front of the ID first.</span>'; if (btn) { btn.disabled = false; btn.classList.remove('opacity-50') } return }
  if (!id_back_url) { $('regStatus').innerHTML = '<span class="text-amber-600">Capture the back of the ID next.</span>'; if (btn) { btn.disabled = false; btn.classList.remove('opacity-50') } return }
  if (!selfie_url) { $('regStatus').innerHTML = '<span class="text-amber-600">Take the passport photo / selfie for liveness verification.</span>'; if (btn) { btn.disabled = false; btn.classList.remove('opacity-50') } return }
  $('regStatus').innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Saving ID images and running verification…'
  try {
    await api.put('/customers/' + id, { id_front_url, id_back_url })
    const { data } = await api.post(`/customers/${id}/verify`, { selfie_url, liveness_mode: 'passport_photo' })
    $('regStatus').innerHTML = `<span class="text-emerald-600">Verified ✓ Credit score ${data.credit_score} · ${data.risk_band} risk</span>`
    setTimeout(() => {
      closeModal(); toast(`Registration complete · Score ${data.credit_score} · ${data.risk_band} risk`)
      if (returnToShop) { state.route = 'shop'; renderApp() }
      else if (state.route === 'customers') viewCustomers()
    }, 1100)
  } catch (err) {
    $('regStatus').innerHTML = `<span class="text-red-600">${esc(err.response?.data?.error || 'Verification failed')}</span>`
    if (btn) { btn.disabled = false; btn.classList.remove('opacity-50') }
  }
}

// ---------------------------------------------------------------------------
// ONBOARD (agent)
// ---------------------------------------------------------------------------
function viewOnboard() {
  $('content').innerHTML = `<div class="card p-6 max-w-3xl"><form id="onbForm" class="space-y-5">
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-user mr-2"></i>Personal Information</h3>
      <div class="responsive-grid cols-2 text-sm">
        <input name="full_name" placeholder="Full Name *" required class="px-3 py-2 border rounded-lg col-span-2">
        <input name="national_id" placeholder="National ID *" required class="px-3 py-2 border rounded-lg">
        <input name="date_of_birth" type="date" class="px-3 py-2 border rounded-lg">
        <select name="gender" class="px-3 py-2 border rounded-lg"><option value="">Gender</option><option>Female</option><option>Male</option></select>
        <input name="mobile" placeholder="Mobile *" required class="px-3 py-2 border rounded-lg">
        <input name="alt_mobile" placeholder="Alternative Number" class="px-3 py-2 border rounded-lg">
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-map-marker-alt mr-2"></i>Location</h3>
      <div class="responsive-grid cols-2 text-sm">
        <input name="county" placeholder="County" class="px-3 py-2 border rounded-lg">
        <input name="sub_county" placeholder="Sub-county" class="px-3 py-2 border rounded-lg">
        <input name="ward" placeholder="Ward" class="px-3 py-2 border rounded-lg">
        <input name="village" placeholder="Village" class="px-3 py-2 border rounded-lg">
        <input name="latitude" id="lat" placeholder="Latitude" class="px-3 py-2 border rounded-lg">
        <input name="longitude" id="lng" placeholder="Longitude" class="px-3 py-2 border rounded-lg">
      </div>
      <button type="button" onclick="captureGPS()" class="btn mt-2 text-xs bg-slate-100 px-3 py-1.5 rounded-lg"><i class="fas fa-location-crosshairs mr-1"></i>Auto-capture GPS</button></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-leaf mr-2"></i>Farming Profile</h3>
      <div class="responsive-grid cols-2 text-sm">
        <select name="value_chain_type" id="vct" onchange="updateChain()" class="px-3 py-2 border rounded-lg"><option value="">Value Chain Type</option><option value="crop">Crop</option><option value="livestock">Livestock</option></select>
        <select name="value_chain" id="vc" class="px-3 py-2 border rounded-lg"><option value="">Select type first</option></select>
        <input name="acreage" type="number" step="0.1" placeholder="Acreage" class="px-3 py-2 border rounded-lg">
        <input name="herd_size" type="number" placeholder="Herd Size" class="px-3 py-2 border rounded-lg">
        <input name="farm_experience" type="number" placeholder="Years experience" class="px-3 py-2 border rounded-lg">
        <input name="annual_production" placeholder="Annual production" class="px-3 py-2 border rounded-lg">
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-wallet mr-2"></i>Financial Profile</h3>
      <div class="responsive-grid cols-2 text-sm">
        <div><label class="field-label">Current loan amount</label><input name="existing_loans" placeholder="Loan amount" class="px-3 py-2 border rounded-lg"></div>
        <div><label class="field-label">SACCO membership</label><select name="sacco_membership" class="px-3 py-2 border rounded-lg"><option value="no">No</option><option value="yes">Yes</option></select></div>
      </div></div>
    <div class="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-700"><i class="fas fa-info-circle mr-1"></i>ID upload and manual selfie capture now happen during "Complete User Registration" — run it from the Customers page after onboarding.</div>
    <button class="btn brand-bg text-white px-6 py-2.5 rounded-lg text-sm"><i class="fas fa-paper-plane mr-1"></i>Submit Onboarding</button>
  </form></div>`
  $('onbForm').onsubmit = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target); const body = Object.fromEntries(fd.entries())
    try { await api.post('/customers', body); toast('Customer onboarded successfully'); state.route = 'customers'; renderApp() }
    catch (err) { toast(err.response?.data?.error || 'Failed', false) }
  }
}
window.captureGPS = () => {
  if (!navigator.geolocation) { $('lat').value = '-0.7167'; $('lng').value = '36.4333'; return toast('Geolocation unavailable, using demo coords') }
  navigator.geolocation.getCurrentPosition(
    p => { $('lat').value = p.coords.latitude.toFixed(4); $('lng').value = p.coords.longitude.toFixed(4); toast('GPS captured') },
    () => { $('lat').value = '-0.7167'; $('lng').value = '36.4333'; toast('Using demo coords (permission denied)') })
}
window.updateChain = () => {
  const crops = ['Maize', 'Beans', 'Wheat', 'Rice', 'Sorghum', 'Tomatoes', 'Onion', 'Avocado', 'Mango', 'Coffee', 'Tea', 'Other']
  const ls = ['Dairy', 'Beef', 'Goat', 'Sheep', 'Poultry', 'Fish', 'Pig', 'Camel']
  const list = $('vct').value === 'crop' ? crops : $('vct').value === 'livestock' ? ls : []
  $('vc').innerHTML = list.length ? list.map(x => `<option>${x}</option>`).join('') : '<option value="">Select type first</option>'
}

// ---------------------------------------------------------------------------
// AGENTS (admin CRUD)
// ---------------------------------------------------------------------------
async function viewAgents() {
  const { data } = await api.get('/agents')
  _agents = data.agents
  $('content').innerHTML = `<div class="flex justify-end mb-4"><button onclick="addAgentModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Create Agent</button></div>
  <div class="card table-card"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Region</th><th class="text-right px-4 py-3">Customers</th><th class="text-right px-4 py-3">Active</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.agents.map(a => `<tr class="border-t border-slate-100"><td class="px-4 py-3 font-medium">${esc(a.full_name)}</td><td class="px-4 py-3">${esc(a.phone)}</td><td class="px-4 py-3">${esc(a.region || '—')}</td><td class="px-4 py-3 text-right">${a.customers}</td><td class="px-4 py-3 text-right">${a.active}</td><td class="px-4 py-3">${badge(a.status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editAgentModal(${a.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        <button onclick="resetUserPassword(${a.id},'${esc(a.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
        ${a.status === 'active' ? `<button onclick="setUserStatus(${a.id},'suspended','agents','${esc(a.full_name)}')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${a.id},'active','agents','${esc(a.full_name)}')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
        <button onclick="deleteUser(${a.id},'${esc(a.full_name)}','agents')" class="text-red-600 hover:underline text-xs">Delete</button>
      </td></tr>`).join('') || '<tr><td colspan="7" class="text-center py-8 text-slate-400">No agents</td></tr>'}</tbody>
  </table></div>`
}
window.addAgentModal = () => {
  showModal(`<h3 class="font-bold mb-1">Onboard New Agent</h3>
    <p class="text-xs text-slate-500 mb-3">Create the agent's login. Set a password now, or leave blank to auto-generate one.</p>
    <div class="space-y-3 text-sm">
    <input id="ag_name" placeholder="Full Name" class="w-full px-3 py-2 border rounded-lg">
    <input id="ag_phone" placeholder="Phone (07XX XXX XXX)" class="w-full px-3 py-2 border rounded-lg">
    <input id="ag_email" placeholder="Email (optional)" class="w-full px-3 py-2 border rounded-lg">
    <input id="ag_region" placeholder="Region" class="w-full px-3 py-2 border rounded-lg">
    <input id="ag_pwd" placeholder="Password (optional — auto-generated if blank)" class="w-full px-3 py-2 border rounded-lg">
  </div><div class="flex gap-2 mt-4"><button onclick="doAddAgent()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Create Agent</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAddAgent = async () => {
  try {
    const body = { full_name: $('ag_name').value, phone: $('ag_phone').value, email: $('ag_email').value, region: $('ag_region').value }
    if ($('ag_pwd').value) body.password = $('ag_pwd').value
    const { data } = await api.post('/agents', body)
    closeModal()
    showCredential('Agent Created', body.full_name, body.phone || '', data.password, data.password_was_set_by_admin)
    viewAgents()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
// Reusable credential dialog (shows password to admin to share with the user)
window.showCredential = (title, name, phone, password, wasSet) => {
  showModal(`<div class="text-center">
    <div class="w-14 h-14 mx-auto rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center text-2xl mb-3"><i class="fas fa-key"></i></div>
    <h3 class="text-lg font-bold mb-1">${esc(title)}</h3>
    <p class="text-sm text-slate-600 mb-3">${esc(name)}${phone ? ' · ' + esc(phone) : ''}</p>
    <div class="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-3">
      <p class="text-xs text-slate-500 mb-1">${wasSet ? 'Password (as you set it)' : 'Auto-generated password'}</p>
      <p class="text-2xl font-bold tracking-widest text-slate-800">${esc(password)}</p>
    </div>
    <p class="text-xs text-slate-400 mb-4">Share this with the user securely. They can change it later via "Forgot password".</p>
    <button onclick="closeModal()" class="btn w-full brand-bg text-white py-2.5 rounded-lg text-sm">Done</button></div>`)
}
window.resetUserPassword = async (id, name) => {
  if (!confirm('Reset password for "' + name + '"? A new password will be generated and their current sessions ended.')) return
  try {
    const { data } = await api.post(`/users/${id}/reset-password`, {})
    showCredential('Password Reset', name, '', data.new_password, false)
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.editAgentModal = (id) => {
  const a = _agents.find(x => x.id === id)
  showModal(`<h3 class="font-bold mb-3">Edit Agent</h3><div class="space-y-3 text-sm">
    <input id="ea_name" value="${esc(a.full_name)}" class="w-full px-3 py-2 border rounded-lg">
    <input id="ea_phone" value="${esc(a.phone)}" class="w-full px-3 py-2 border rounded-lg">
    <input id="ea_email" value="${esc(a.email || '')}" placeholder="Email" class="w-full px-3 py-2 border rounded-lg">
    <input id="ea_region" value="${esc(a.region || '')}" placeholder="Region" class="w-full px-3 py-2 border rounded-lg">
  </div><div class="flex gap-2 mt-4"><button onclick="doEditAgent(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditAgent = async (id) => {
  if (!confirmEdit('Save changes to this agent profile?')) return
  try {
    await api.put('/agents/' + id, { full_name: $('ea_name').value, phone: $('ea_phone').value, email: $('ea_email').value, region: $('ea_region').value })
    closeModal(); toast('Agent updated'); viewAgents()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// USER ACCOUNTS (admin CRUD + super-admin access templates)
// ---------------------------------------------------------------------------
function userRoleOptions(selected) {
  const roles = (_permMeta.roles || []).length
    ? (_permMeta.roles || []).map((r) => ({ key: r.role_key, label: r.label }))
    : ['super_admin', 'admin', 'operations_finance', 'agent', 'lender', 'investor', 'mne', 'partner', 'customer', 'support'].map((r) => ({ key: r, label: roleLabel(r) }))
  return roles.map((r) => `<option value="${r.key}" ${selected === r.key ? 'selected' : ''}>${esc(r.label)}</option>`).join('')
}
async function viewUsers() {
  await ensurePermissionMeta()
  const { data } = await api.get('/users')
  _users = data.users
  const accessButton = state.user.role === 'super_admin'
    ? `<button onclick="openAccessManager()" class="btn bg-slate-100 px-4 py-2 rounded-lg text-sm"><i class="fas fa-shield-halved mr-1"></i>Manage Roles & Permissions</button>`
    : ''
  $('content').innerHTML = `
    <div class="action-bar">${accessButton}<button onclick="addUserModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Create User</button></div>
    <div class="card table-card"><table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Label</th><th class="text-left px-4 py-3">Role</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Permissions</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
      <tbody>${data.users.map(u => `<tr class="border-t border-slate-100">
        <td class="px-4 py-3 font-medium">${esc(u.full_name)}</td>
        <td class="px-4 py-3">${esc(u.label || '—')}</td>
        <td class="px-4 py-3">${esc(roleLabel(u.role))}</td>
        <td class="px-4 py-3">${esc(u.phone)}</td>
        <td class="px-4 py-3 text-xs text-slate-500">${esc(permsText(u.permissions || {})) || '—'}</td>
        <td class="px-4 py-3">${badge(u.status)}</td>
        <td class="px-4 py-3 whitespace-nowrap text-right">
          <button onclick="editUserModal(${u.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
          <button onclick="resetUserPassword(${u.id},'${esc(u.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
          ${u.status === 'active' ? `<button onclick="setUserStatus(${u.id},'suspended','users','${esc(u.full_name)}')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${u.id},'active','users','${esc(u.full_name)}')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
          <button onclick="deleteUser(${u.id},'${esc(u.full_name)}','users')" class="text-red-600 hover:underline text-xs">Delete</button>
        </td></tr>`).join('')}</tbody>
    </table></div>`
}
window.openAccessManager = async (editRoleKey = '') => {
  await ensurePermissionMeta()
  const role = (_permMeta.roles || []).find((r) => r.role_key === editRoleKey)
  showModal(`<h3 class="font-bold mb-1">Roles & Permission Check-boxes</h3>
    <p class="text-xs text-slate-500 mb-4">Super Admin can create permission check-boxes and role categories. These then appear directly in user setup.</p>
    <div class="border rounded-xl p-4 bg-slate-50 mb-4">
      <div class="font-semibold mb-2">Add Permission Check-box</div>
      <div class="responsive-grid cols-2 text-sm">
        <input id="perm_key" placeholder="permission_key" class="px-3 py-2 border rounded-lg">
        <input id="perm_label" placeholder="Display label" class="px-3 py-2 border rounded-lg">
        <input id="perm_category" placeholder="Category" class="px-3 py-2 border rounded-lg">
        <input id="perm_desc" placeholder="Short description" class="px-3 py-2 border rounded-lg">
      </div>
      <button onclick="savePermissionCatalog()" class="btn mt-3 brand-bg text-white px-4 py-2 rounded-lg text-sm">Save Permission</button>
      <div class="mt-3 space-y-2 max-h-40 overflow-y-auto">${(_permMeta.permissions || []).map((p) => `<div class="flex items-center justify-between gap-3 text-xs border border-slate-200 rounded-lg px-3 py-2 bg-white"><div><div class="font-medium text-slate-700">${esc(p.label)}</div><div class="text-slate-400">${esc(p.permission_key)} · ${esc(p.category || 'general')}</div></div><button onclick="deletePermissionCatalog('${esc(p.permission_key)}')" class="text-red-600 hover:underline">Delete</button></div>`).join('') || '<div class="text-xs text-slate-400">No permissions added yet.</div>'}</div>
    </div>
    <div class="border rounded-xl p-4 bg-slate-50">
      <div class="font-semibold mb-2">${role ? 'Edit Role Category' : 'Add Role Category'}</div>
      <div class="responsive-grid cols-2 text-sm">
        <input id="role_key" value="${esc(role?.role_key || '')}" ${role?.is_system ? 'disabled' : ''} placeholder="role_key" class="px-3 py-2 border rounded-lg">
        <input id="role_label" value="${esc(role?.label || '')}" placeholder="Display label" class="px-3 py-2 border rounded-lg">
        <input id="role_desc" value="${esc(role?.description || '')}" placeholder="Description" class="px-3 py-2 border rounded-lg col-span-2">
      </div>
      <div class="mt-3">
        <div class="field-label">Permission check-boxes shown for this role</div>
        <div id="rt_perm_box" class="responsive-grid cols-2">${permissionChecklist('rt_perm', role?.permissions || {}, false)}</div>
      </div>
      <div class="mt-4">
        <div class="field-label">Time-Based Access Control (login window)</div>
        ${scheduleEditor('rt', { schedule_enabled: role?.schedule_enabled, access_days: role?.access_days, access_start: role?.access_start, access_end: role?.access_end }, false)}
      </div>
      <div class="flex gap-2 mt-4 flex-wrap">
        <button onclick="saveRoleTemplate('${esc(role?.role_key || '')}')" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm">Save Role Category</button>
        ${role && !role.is_system ? `<button onclick="deleteRoleTemplate('${esc(role.role_key)}')" class="btn bg-red-100 text-red-700 px-4 py-2 rounded-lg text-sm">Delete Role Category</button>` : ''}
        <button onclick="openAccessManager()" class="btn bg-slate-100 px-4 py-2 rounded-lg text-sm">New Role</button>
      </div>
      <div class="mt-4 space-y-2 max-h-40 overflow-y-auto">${(_permMeta.roles || []).map((r) => `<div class="flex items-center justify-between gap-3 text-xs border border-slate-200 rounded-lg px-3 py-2 bg-white"><div><div class="font-medium text-slate-700">${esc(r.label)}</div><div class="text-slate-400">${esc(r.role_key)} · ${esc(permsText(r.permissions || {})) || 'no permissions selected'}</div></div><button onclick="openAccessManager('${esc(r.role_key)}')" class="text-teal-600 hover:underline">Edit</button></div>`).join('')}</div>
    </div>
    <div class="flex gap-2 mt-4"><button onclick="closeModal()" class="btn flex-1 bg-slate-100 py-2 rounded-lg text-sm">Close</button></div>`)
}
window.savePermissionCatalog = async () => {
  try {
    await api.post('/permissions', {
      permission_key: $('perm_key').value,
      label: $('perm_label').value,
      category: $('perm_category').value,
      description: $('perm_desc').value
    })
    _permMeta = { permissions: [], roles: [] }
    await ensurePermissionMeta()
    toast('Permission check-box saved')
    openAccessManager()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deletePermissionCatalog = async (key) => {
  if (!confirmDelete(`Delete permission check-box "${key}"?`)) return
  try {
    await api.delete('/permissions/' + encodeURIComponent(key))
    _permMeta = { permissions: [], roles: [] }
    await ensurePermissionMeta()
    toast('Permission deleted')
    openAccessManager()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.saveRoleTemplate = async () => {
  if (!confirmEdit('Save this role category and permission selection?')) return
  try {
    const sched = collectSchedule('rt')
    await api.post('/role-templates', {
      role_key: $('role_key').value,
      label: $('role_label').value,
      description: $('role_desc').value,
      permissions: selectedPermissions('rt_perm'),
      schedule_enabled: sched.schedule_enabled,
      access_days: sched.access_days,
      access_start: sched.access_start,
      access_end: sched.access_end
    })
    _permMeta = { permissions: [], roles: [] }
    await ensurePermissionMeta()
    closeModal(); toast('Role category saved'); viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteRoleTemplate = async (key) => {
  if (!confirmDelete(`Delete role category "${key}"?`)) return
  try {
    await api.delete('/role-templates/' + encodeURIComponent(key))
    _permMeta = { permissions: [], roles: [] }
    await ensurePermissionMeta()
    closeModal(); toast('Role category deleted'); viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.addUserModal = async () => {
  await ensurePermissionMeta()
  const defaultRole = getRoleTemplate('agent')?.role_key || 'agent'
  const allowCustomPerms = state.user.role === 'super_admin'
  showModal(`<h3 class="font-bold mb-1">Create User Account</h3>
    <p class="text-xs text-slate-500 mb-3">Choose the user category, label, and permission check-boxes that should apply.</p>
    <div class="space-y-3 text-sm">
      <input id="nu_name" placeholder="Full Name" class="w-full px-3 py-2 border rounded-lg">
      <input id="nu_phone" placeholder="Phone" class="w-full px-3 py-2 border rounded-lg">
      <input id="nu_email" placeholder="Email (optional)" class="w-full px-3 py-2 border rounded-lg">
      <select id="nu_role" class="w-full px-3 py-2 border rounded-lg">${userRoleOptions(defaultRole)}</select>
      <input id="nu_label" placeholder="Label (for example: Western Cluster Agent)" class="w-full px-3 py-2 border rounded-lg">
      <input id="nu_region" placeholder="Region" class="w-full px-3 py-2 border rounded-lg">
      <input id="nu_pwd" placeholder="Password (optional — auto-generated if blank)" class="w-full px-3 py-2 border rounded-lg">
      <div><div class="field-label">Permission check-boxes</div><div id="nu_perm_box" class="responsive-grid cols-2">${permissionChecklist('nu_perm', templatePermissions(defaultRole), !allowCustomPerms)}</div><div class="help-text">${allowCustomPerms ? 'Toggle the exact permissions to assign to this user.' : 'Only Super Admin can customize the check-box selection. Admin users see role-based defaults.'}</div></div>
      ${allowCustomPerms ? `<div><div class="field-label">Time-Based Access Control (login window)</div>${scheduleEditor('nu', {}, false)}<div class="help-text">Optional. Overrides the role login window for this user.</div></div>` : ''}
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doAddUser()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Create User</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  $('nu_role').onchange = () => refreshPermissionChecklist('nu_perm', 'nu_role', !allowCustomPerms)
}
window.doAddUser = async () => {
  try {
    const body = { full_name: $('nu_name').value, phone: $('nu_phone').value, email: $('nu_email').value, role: $('nu_role').value, label: $('nu_label').value, region: $('nu_region').value }
    if ($('nu_pwd').value) body.password = $('nu_pwd').value
    if (state.user.role === 'super_admin') { body.permissions = selectedPermissions('nu_perm'); Object.assign(body, collectSchedule('nu')) }
    const { data } = await api.post('/users', body)
    closeModal()
    showCredential('User Created', body.full_name, body.phone, data.password, data.password_was_set_by_admin)
    viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.editUserModal = async (id) => {
  await ensurePermissionMeta()
  const u = _users.find(x => x.id === id)
  const allowCustomPerms = state.user.role === 'super_admin'
  showModal(`<h3 class="font-bold mb-3">Edit User</h3><div class="space-y-3 text-sm">
    <input id="eu_name" value="${esc(u.full_name)}" placeholder="Full Name" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_phone" value="${esc(u.phone)}" placeholder="Phone" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_email" value="${esc(u.email || '')}" placeholder="Email" class="w-full px-3 py-2 border rounded-lg">
    <select id="eu_role" class="w-full px-3 py-2 border rounded-lg">${userRoleOptions(u.role)}</select>
    <input id="eu_label" value="${esc(u.label || '')}" placeholder="Label" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_region" value="${esc(u.region || '')}" placeholder="Region" class="w-full px-3 py-2 border rounded-lg">
    <div><div class="field-label">Permission check-boxes</div><div id="eu_perm_box" class="responsive-grid cols-2">${permissionChecklist('eu_perm', u.permissions || {}, !allowCustomPerms)}</div><div class="help-text">${allowCustomPerms ? 'Update the assigned permission check-boxes, then confirm to save.' : 'Only Super Admin can customize the permission check-boxes.'}</div></div>
    ${allowCustomPerms ? `<div><div class="field-label">Time-Based Access Control (login window)</div>${scheduleEditor('eu', { schedule_enabled: u.schedule_enabled, access_days: u.access_days, access_start: u.access_start, access_end: u.access_end }, false)}<div class="help-text">Optional. Overrides the role login window for this user.</div></div>` : ''}
    <input id="eu_pwd" placeholder="New password (leave blank to keep)" class="w-full px-3 py-2 border rounded-lg">
  </div><div class="flex gap-2 mt-4"><button onclick="doEditUser(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  $('eu_role').onchange = () => refreshPermissionChecklist('eu_perm', 'eu_role', !allowCustomPerms)
}
window.doEditUser = async (id) => {
  if (!confirmEdit('Save changes to this user account?')) return
  try {
    const body = { full_name: $('eu_name').value, phone: $('eu_phone').value, email: $('eu_email').value, role: $('eu_role').value, label: $('eu_label').value, region: $('eu_region').value }
    if ($('eu_pwd').value) body.password = $('eu_pwd').value
    if (state.user.role === 'super_admin') { body.permissions = selectedPermissions('eu_perm'); Object.assign(body, collectSchedule('eu')) }
    await api.put('/users/' + id, body)
    closeModal(); toast('User updated'); viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.setUserStatus = async (id, status, back, name = 'this user') => {
  if (!confirmStatus(`${status === 'active' ? 'Activate' : 'Suspend'} "${name}"?`)) return
  try { await api.put(`/users/${id}/status`, { status }); toast('Status updated'); back === 'agents' ? viewAgents() : viewUsers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteUser = async (id, name, back) => {
  if (!confirmDelete(`Delete "${name}"? This permanently removes the account.`)) return
  try { await api.delete('/users/' + id); toast('Account deleted'); back === 'agents' ? viewAgents() : viewUsers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// REPAYMENTS
// ---------------------------------------------------------------------------
async function viewRepayments() {
  const { data } = await api.get('/repayments')
  $('content').innerHTML = `<div class="card table-card"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Contract</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Inst.</th><th class="text-left px-4 py-3">Due Date</th><th class="text-right px-4 py-3">Amount</th><th class="text-right px-4 py-3">Paid</th><th class="text-left px-4 py-3">Status</th></tr></thead>
    <tbody>${data.repayments.map(r => `<tr class="border-t border-slate-100"><td class="px-4 py-3 font-mono text-xs">${esc(r.contract_ref)}</td><td class="px-4 py-3">${esc(r.customer)}</td><td class="px-4 py-3">#${r.installment_no}</td><td class="px-4 py-3">${r.due_date}</td><td class="px-4 py-3 text-right">${fmt(r.amount_due)}</td><td class="px-4 py-3 text-right">${fmt(r.amount_paid)}</td><td class="px-4 py-3">${badge(r.status)}</td></tr>`).join('') || '<tr><td colspan="7" class="text-center py-8 text-slate-400">No repayments</td></tr>'}</tbody>
  </table></div>`
}

// ---------------------------------------------------------------------------
// MY ACCOUNT / PROFILE (Instruction 3 + 4)
//   Farmers  : edit their data EXCEPT National ID & Phone (both locked).
//   Others   : profile picture only. Everyone can change their password.
// ---------------------------------------------------------------------------
let _profile = null
async function viewProfile() {
  let data
  try { data = (await api.get('/me/profile')).data }
  catch (err) { $('content').innerHTML = `<div class="card p-6 text-red-600 text-sm">${esc(err.response?.data?.error || 'Failed to load profile')}</div>`; return }
  _profile = data
  const u = data.user, c = data.customer, isFarmer = u.role === 'customer'
  const avatar = u.avatar_url
    ? `<img src="${esc(u.avatar_url)}" class="h-24 w-24 rounded-full object-cover border-2 border-teal-200">`
    : `<div class="h-24 w-24 rounded-full bg-teal-100 flex items-center justify-center text-2xl font-bold text-teal-700">${esc((u.full_name || '?').charAt(0).toUpperCase())}</div>`
  $('content').innerHTML = `
    <div class="space-y-6 max-w-3xl">
      <!-- Identity + avatar -->
      <div class="card p-6">
        <div class="flex items-center gap-5">
          <div id="avatarPreview">${avatar}</div>
          <div class="flex-1">
            <div class="font-bold text-lg text-slate-800">${esc(u.full_name)}</div>
            <div class="text-sm text-slate-500">${esc(roleLabel(u.role))}${u.label ? ' · ' + esc(u.label) : ''}</div>
            <div class="text-xs text-slate-400 mt-1"><i class="fas fa-phone mr-1"></i>${esc(u.phone)} <span class="ml-1 text-slate-300">(locked)</span></div>
          </div>
        </div>
        <div class="mt-4 field-group">
          <label class="field-label">Profile picture URL</label>
          <div class="flex gap-2">
            <input id="pf_avatar" value="${esc(u.avatar_url || '')}" class="flex-1 px-3 py-2 border rounded-lg text-sm" placeholder="https://... image URL">
            <button onclick="saveAvatar()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-image mr-1"></i>Update</button>
          </div>
          <p class="text-[11px] text-slate-500 mt-1">Everyone can update their profile picture.</p>
        </div>
      </div>

      ${isFarmer ? `
      <!-- Farmer data (National ID & Phone locked) -->
      <div class="card p-6">
        <h3 class="font-bold text-slate-800 mb-1"><i class="fas fa-leaf text-teal-600 mr-2"></i>My Farmer Profile</h3>
        <p class="text-xs text-slate-500 mb-4">You can update your details below. Your <b>National ID</b> and <b>Phone number</b> cannot be changed — contact an administrator if these need updating.</p>
        <div class="responsive-grid cols-2 text-sm">
          <div><label class="field-label">Full name</label><input id="pf_name" value="${esc(c?.full_name || u.full_name || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">National ID <span class="text-slate-400">(locked)</span></label><input value="${esc(c?.national_id || '')}" disabled class="px-3 py-2 border rounded-lg bg-slate-100 text-slate-500"></div>
          <div><label class="field-label">Phone number <span class="text-slate-400">(locked)</span></label><input value="${esc(c?.mobile || u.phone || '')}" disabled class="px-3 py-2 border rounded-lg bg-slate-100 text-slate-500"></div>
          <div><label class="field-label">Alternative number</label><input id="pf_alt_mobile" value="${esc(c?.alt_mobile || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">County</label><input id="pf_county" value="${esc(c?.county || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Sub-county</label><input id="pf_sub_county" value="${esc(c?.sub_county || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Ward</label><input id="pf_ward" value="${esc(c?.ward || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Village</label><input id="pf_village" value="${esc(c?.village || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Value chain</label><input id="pf_value_chain" value="${esc(c?.value_chain || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Acreage</label><input id="pf_acreage" value="${esc(c?.acreage || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">Current loan amount</label><input id="pf_loans" value="${esc(c?.existing_loans || '')}" class="px-3 py-2 border rounded-lg"></div>
          <div><label class="field-label">SACCO membership</label><select id="pf_sacco" class="px-3 py-2 border rounded-lg"><option value="yes" ${(c?.sacco_membership || '').toLowerCase() === 'yes' ? 'selected' : ''}>Yes</option><option value="no" ${(c?.sacco_membership || '').toLowerCase() !== 'yes' ? 'selected' : ''}>No</option></select></div>
        </div>
        <div class="flex gap-2 mt-4"><button onclick="saveFarmerProfile()" class="btn brand-bg text-white px-5 py-2 rounded-lg text-sm"><i class="fas fa-save mr-1"></i>Save My Details</button></div>
      </div>` : `
      <div class="card p-6">
        <p class="text-sm text-slate-500"><i class="fas fa-circle-info text-teal-600 mr-2"></i>As a <b>${esc(roleLabel(u.role))}</b>, you can update your profile picture and password here. Your account details are managed by an administrator.</p>
      </div>`}

      <!-- Change password (everyone) -->
      <div class="card p-6">
        <h3 class="font-bold text-slate-800 mb-1"><i class="fas fa-key text-teal-600 mr-2"></i>Change Password</h3>
        <p class="text-xs text-slate-500 mb-4">Choose a new password. You'll need your current password to confirm.</p>
        <div class="responsive-grid cols-2 text-sm">
          <div><label class="field-label">Current password</label>${passwordField('pf_cur_pw', { placeholder: 'Current password', cls: 'px-3 py-2 border rounded-lg w-full' })}</div>
          <div><label class="field-label">New password</label>${passwordField('pf_new_pw', { placeholder: 'New password', cls: 'px-3 py-2 border rounded-lg w-full' })}</div>
        </div>
        <div class="flex gap-2 mt-4"><button onclick="changeMyPassword()" class="btn brand-bg text-white px-5 py-2 rounded-lg text-sm"><i class="fas fa-lock mr-1"></i>Update Password</button></div>
      </div>
    </div>`
}
window.saveAvatar = async () => {
  try {
    const url = ($('pf_avatar') || {}).value || ''
    await api.put('/me/avatar', { avatar_url: url })
    if (state.user) state.user.avatar_url = url
    const box = $('avatarPreview')
    if (box) box.innerHTML = url ? `<img src="${esc(url)}" class="h-24 w-24 rounded-full object-cover border-2 border-teal-200">` : box.innerHTML
    toast('Profile picture updated')
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.saveFarmerProfile = async () => {
  const body = {
    full_name: ($('pf_name') || {}).value,
    alt_mobile: ($('pf_alt_mobile') || {}).value,
    county: ($('pf_county') || {}).value,
    sub_county: ($('pf_sub_county') || {}).value,
    ward: ($('pf_ward') || {}).value,
    village: ($('pf_village') || {}).value,
    value_chain: ($('pf_value_chain') || {}).value,
    acreage: ($('pf_acreage') || {}).value,
    existing_loans: ($('pf_loans') || {}).value,
    sacco_membership: ($('pf_sacco') || {}).value
  }
  try {
    const res = await api.put('/me/profile', body)
    if (res.data.user && state.user) { state.user.full_name = res.data.user.full_name; renderApp() }
    toast('Your details were updated')
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.changeMyPassword = async () => {
  const cur = ($('pf_cur_pw') || {}).value, nw = ($('pf_new_pw') || {}).value
  if (!nw || nw.length < 4) return toast('New password must be at least 4 characters', false)
  try {
    await api.put('/me/password', { current_password: cur, new_password: nw })
    if ($('pf_cur_pw')) $('pf_cur_pw').value = ''
    if ($('pf_new_pw')) $('pf_new_pw').value = ''
    toast('Password updated')
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// FINANCING & MARKUP SETTINGS
//   Processing Fee : applicable? -> percentage OR tiered -> choose products
//   Markup         : financing applicable? -> cash markup+terms OR %/tiered
//                    -> choose products (from inventory or add new)
// ---------------------------------------------------------------------------
let _feeCfg = { enabled: false, mode: 'percentage', percentage_rate: 0, tiers: [], product_ids: [] }
let _mkCfg = { financing_applicable: true, mode: 'percentage', percentage_rate: 20, tiers: [], cash_markup_pct: 10, cash_terms_text: '', product_ids: [] }
let _inventory = []
let _canManageFees = false, _canManageMarkup = false
async function viewSettings() {
  let data
  try { data = (await api.get('/settings/financing')).data }
  catch (err) { $('content').innerHTML = `<div class="card p-6 text-red-600 text-sm">${esc(err.response?.data?.error || 'Failed to load settings')}</div>`; return }
  _feeCfg = Object.assign({ enabled: false, mode: 'percentage', percentage_rate: 0, tiers: [], product_ids: [] }, data.processing_fee || {})
  if (!Array.isArray(_feeCfg.tiers)) _feeCfg.tiers = []
  if (!Array.isArray(_feeCfg.product_ids)) _feeCfg.product_ids = []
  _mkCfg = Object.assign({ financing_applicable: true, mode: 'percentage', percentage_rate: 20, tiers: [], cash_markup_pct: 10, cash_terms_text: '', product_ids: [] }, data.financing_markup || {})
  if (!Array.isArray(_mkCfg.tiers)) _mkCfg.tiers = []
  if (!Array.isArray(_mkCfg.product_ids)) _mkCfg.product_ids = []
  _inventory = Array.isArray(data.products) ? data.products : []
  _canManageFees = !!data.can_manage_processing_fees
  _canManageMarkup = !!data.can_manage_markup
  $('content').innerHTML = `
    <div class="space-y-6 max-w-3xl">
      <!-- ============ MARKUP ============ -->
      <div class="card p-6">
        <h3 class="font-bold text-slate-800 mb-1"><i class="fas fa-percent text-teal-600 mr-2"></i>Financing Markup</h3>
        <p class="text-xs text-slate-500 mb-4">Configure how the marketplace marks up sales. Start by choosing whether financing applies.</p>
        <div id="markupBuilder"></div>
        ${_canManageMarkup
          ? `<div class="flex gap-2 mt-5"><button onclick="saveMarkup()" class="btn brand-bg text-white px-5 py-2 rounded-lg text-sm"><i class="fas fa-save mr-1"></i>Save Markup</button></div>`
          : `<p class="text-xs text-amber-600 mt-4"><i class="fas fa-lock mr-1"></i>You lack the "Manage Markup Percentage" permission — read-only.</p>`}
      </div>

      <!-- ============ PROCESSING FEE ============ -->
      <div class="card p-6">
        <h3 class="font-bold text-slate-800 mb-1"><i class="fas fa-file-invoice-dollar text-teal-600 mr-2"></i>Processing Fee</h3>
        <p class="text-xs text-slate-500 mb-4">A fee charged on the amount financed (borrowed). Start by choosing whether fees are applicable.</p>
        <div id="feeBuilder"></div>
        ${_canManageFees
          ? `<div class="flex gap-2 mt-5"><button onclick="saveProcessingFee()" class="btn brand-bg text-white px-5 py-2 rounded-lg text-sm"><i class="fas fa-save mr-1"></i>Save Processing Fee</button></div>`
          : `<p class="text-xs text-amber-600 mt-4"><i class="fas fa-lock mr-1"></i>You lack the "Manage Processing Fees" permission — read-only.</p>`}
      </div>
    </div>`
  renderMarkupBuilder()
  renderFeeBuilder()
}

// ---- shared helpers -------------------------------------------------------
function yesNoToggle(name, value, onYes, onNo) {
  return `<div class="flex gap-2 mb-4" data-toggle="${name}">
    <button type="button" onclick="${onYes}" data-val="yes"
      class="btn px-4 py-2 rounded-lg text-sm border ${value ? 'brand-bg text-white border-transparent' : 'border-slate-300 text-slate-600'}">Yes</button>
    <button type="button" onclick="${onNo}" data-val="no"
      class="btn px-4 py-2 rounded-lg text-sm border ${!value ? 'brand-bg text-white border-transparent' : 'border-slate-300 text-slate-600'}">No</button>
  </div>`
}
function modeRadios(current, prefix, changeFn, disabled) {
  const ro = disabled ? 'disabled' : ''
  return `<div class="flex gap-4 mb-4">
    <label class="flex items-center gap-2 text-sm ${disabled ? 'opacity-60' : 'cursor-pointer'}">
      <input type="radio" name="${prefix}_mode" value="percentage" ${current === 'percentage' ? 'checked' : ''} ${ro} onchange="${changeFn}('percentage')"> Percentage (%)
    </label>
    <label class="flex items-center gap-2 text-sm ${disabled ? 'opacity-60' : 'cursor-pointer'}">
      <input type="radio" name="${prefix}_mode" value="tiered" ${current === 'tiered' ? 'checked' : ''} ${ro} onchange="${changeFn}('tiered')"> Tiered Range
    </label>
  </div>`
}
// Product selection chips + add-new inline form. cfg is _feeCfg or _mkCfg.
function productPicker(cfg, ns, canEdit) {
  const selected = new Set((cfg.product_ids || []).map(Number))
  // Issue 5: inventory list rows + their metadata must align to the far-left
  // edge of the layout grid (justify-start / text-left, no residual centering).
  const options = _inventory.map(p =>
    `<label class="flex items-center justify-start gap-2 text-sm py-1 text-left w-full ${canEdit ? 'cursor-pointer' : 'opacity-70'}">
      <input type="checkbox" value="${p.id}" ${selected.has(Number(p.id)) ? 'checked' : ''} ${canEdit ? '' : 'disabled'} onchange="togglePicked('${ns}',${p.id},this.checked)">
      <span class="text-left">${esc(p.name)} <span class="text-slate-400 text-xs">(${esc(p.sku || '')}${p.category ? ' · ' + esc(p.category) : ''})</span></span>
    </label>`).join('') || '<p class="text-xs text-slate-400 py-2 text-left">No products in inventory yet.</p>'
  return `
    <div class="mt-4 border-t border-slate-100 pt-4 text-left">
      <label class="field-label text-left">Apply to products</label>
      <p class="text-[11px] text-slate-500 mb-2 text-left">Tick the inventory products this applies to. Leave all unticked to apply to <b>every</b> product.</p>
      <div class="max-h-48 overflow-y-auto border border-slate-200 rounded-lg p-3 bg-slate-50 text-left flex flex-col items-start">${options}</div>
      ${canEdit ? `<button type="button" onclick="toggleQuickProduct('${ns}')" class="btn mt-3 bg-slate-800 text-white px-4 py-2 rounded-lg text-xs"><i class="fas fa-plus mr-1"></i>Add new product to inventory</button>` : ''}
      <div id="quickProduct_${ns}" class="hidden mt-3 border border-dashed border-slate-300 rounded-lg p-3 bg-white">
        <div class="grid grid-cols-2 gap-3">
          <div><label class="field-label">SKU</label><input id="qp_sku_${ns}" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="e.g. EQ-045"></div>
          <div><label class="field-label">Name</label><input id="qp_name_${ns}" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="Product name"></div>
          <div><label class="field-label">Category</label><input id="qp_cat_${ns}" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="Feed" value="Feed"></div>
          <div><label class="field-label">Buying Price (KES)</label><input id="qp_price_${ns}" type="number" min="0" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="0"></div>
        </div>
        <button type="button" onclick="createQuickProduct('${ns}')" class="btn mt-3 brand-bg text-white px-4 py-2 rounded-lg text-xs"><i class="fas fa-check mr-1"></i>Create &amp; select</button>
      </div>
    </div>`
}
window.togglePicked = (ns, id, checked) => {
  const cfg = ns === 'fee' ? _feeCfg : _mkCfg
  const set = new Set((cfg.product_ids || []).map(Number))
  if (checked) set.add(Number(id)); else set.delete(Number(id))
  cfg.product_ids = Array.from(set)
}
window.toggleQuickProduct = (ns) => { const el = $('quickProduct_' + ns); if (el) el.classList.toggle('hidden') }
window.createQuickProduct = async (ns) => {
  const sku = ($('qp_sku_' + ns) || {}).value, name = ($('qp_name_' + ns) || {}).value
  if (!sku || !name) return toast('SKU and name are required', false)
  const body = { sku: sku.trim(), name: name.trim(), category: ($('qp_cat_' + ns) || {}).value || 'Feed', buying_price: Number(($('qp_price_' + ns) || {}).value || 0) }
  try {
    const res = await api.post('/settings/quick-product', body)
    const prod = res.data.product
    _inventory.push(prod)
    const cfg = ns === 'fee' ? _feeCfg : _mkCfg
    cfg.product_ids = Array.from(new Set([...(cfg.product_ids || []).map(Number), Number(prod.id)]))
    toast('Product added to inventory')
    if (ns === 'fee') renderFeeBuilder(); else renderMarkupBuilder()
  } catch (err) { toast(err.response?.data?.error || 'Failed to add product', false) }
}

// ---- Processing Fee builder ----------------------------------------------
function renderFeeBuilder() {
  const el = $('feeBuilder'); if (!el) return
  const ro = !_canManageFees
  el.innerHTML = `
    <label class="field-label">Fees applicable?</label>
    ${yesNoToggle('feeApplicable', _feeCfg.enabled, "setFeeApplicable(true)", "setFeeApplicable(false)")}
    <div id="feeInner" class="${_feeCfg.enabled ? '' : 'hidden'}"></div>`
  if (_feeCfg.enabled) renderFeeInner()
}
window.setFeeApplicable = (v) => { if (!_canManageFees) return; _feeCfg.enabled = v; renderFeeBuilder() }
window.setFeeMode = (mode) => { if (!_canManageFees) return; _feeCfg.mode = mode; renderFeeInner() }
function renderFeeInner() {
  const el = $('feeInner'); if (!el) return
  const ro = _canManageFees ? '' : 'disabled'
  let inner = modeRadios(_feeCfg.mode, 'fee', 'setFeeMode', !_canManageFees)
  if (_feeCfg.mode === 'percentage') {
    inner += `<div class="field-group">
      <label class="field-label">Processing Fee Rate (%)</label>
      <input id="fee_pct" type="number" step="0.1" min="0" value="${_feeCfg.percentage_rate ?? 0}" ${ro} class="w-48 px-3 py-2 border rounded-lg ${ro ? 'bg-slate-100' : ''}" placeholder="e.g. 2.5">
      <p class="text-[11px] text-slate-500 mt-1">Charged as this percentage of the amount borrowed.</p>
    </div>`
  } else {
    inner += `<div class="overflow-x-auto"><table class="w-full text-sm border border-slate-200 rounded-lg">
        <thead class="bg-slate-50 text-slate-500 text-xs"><tr>
          <th class="text-left px-3 py-2">From (KES)</th><th class="text-left px-3 py-2">To (KES)</th>
          <th class="text-left px-3 py-2">Flat Fee (KES)</th><th class="px-3 py-2"></th></tr></thead>
        <tbody id="tierRows"></tbody></table></div>
      ${_canManageFees ? `<button onclick="addTier()" class="btn mt-3 bg-slate-800 text-white px-4 py-2 rounded-lg text-xs"><i class="fas fa-plus mr-1"></i>Add Range</button>` : ''}
      <p class="text-[11px] text-slate-500 mt-2">Example: <b>100,000</b> to <b>200,000</b> → Flat Fee <b>8,000</b>. Leave "To" blank for an open-ended top range.</p>`
  }
  inner += productPicker(_feeCfg, 'fee', _canManageFees)
  el.innerHTML = inner
  if (_feeCfg.mode === 'tiered') renderTierRows()
}
function renderTierRows() {
  const tb = $('tierRows'); if (!tb) return
  const ro = _canManageFees ? '' : 'disabled'
  if (!_feeCfg.tiers.length) { tb.innerHTML = `<tr><td colspan="4" class="text-center text-slate-400 py-4 text-xs">No ranges yet. Click "Add Range".</td></tr>`; return }
  tb.innerHTML = _feeCfg.tiers.map((t, i) => `<tr class="border-t border-slate-100">
    <td class="px-3 py-2"><input type="number" min="0" value="${t.min ?? ''}" ${ro} onchange="updateTier(${i},'min',this.value)" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2"><input type="number" min="0" value="${t.max ?? ''}" ${ro} onchange="updateTier(${i},'max',this.value)" placeholder="∞" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2"><input type="number" min="0" value="${t.fee ?? ''}" ${ro} onchange="updateTier(${i},'fee',this.value)" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2 text-right">${_canManageFees ? `<button onclick="removeTier(${i})" class="text-red-600 hover:underline text-xs"><i class="fas fa-trash"></i></button>` : ''}</td>
  </tr>`).join('')
}
window.addTier = () => { _feeCfg.tiers.push({ min: 0, max: null, fee: 0 }); renderTierRows() }
window.removeTier = (i) => { _feeCfg.tiers.splice(i, 1); renderTierRows() }
window.updateTier = (i, field, val) => { _feeCfg.tiers[i][field] = (field === 'max' && val === '') ? null : Number(val) }

// ---- Markup builder -------------------------------------------------------
function renderMarkupBuilder() {
  const el = $('markupBuilder'); if (!el) return
  el.innerHTML = `
    <label class="field-label">Is financing applicable?</label>
    ${yesNoToggle('mkFinancing', _mkCfg.financing_applicable, "setMkFinancing(true)", "setMkFinancing(false)")}
    <div id="mkInner"></div>`
  renderMkInner()
}
window.setMkFinancing = (v) => { if (!_canManageMarkup) return; _mkCfg.financing_applicable = v; renderMarkupBuilder() }
window.setMkMode = (mode) => { if (!_canManageMarkup) return; _mkCfg.mode = mode; renderMkInner() }
function renderMkInner() {
  const el = $('mkInner'); if (!el) return
  const ro = _canManageMarkup ? '' : 'disabled'
  let inner = ''
  if (!_mkCfg.financing_applicable) {
    // No financing -> cash markup + terms
    inner += `<div class="field-group">
        <label class="field-label">Cash Markup (%)</label>
        <input id="mk_cash_pct" type="number" step="0.1" min="0" value="${_mkCfg.cash_markup_pct ?? 10}" ${ro} class="w-48 px-3 py-2 border rounded-lg ${ro ? 'bg-slate-100' : ''}" placeholder="e.g. 10">
      </div>
      <div class="field-group mt-3">
        <label class="field-label">Cash Terms &amp; Conditions</label>
        <textarea id="mk_cash_terms" rows="3" ${ro} class="w-full px-3 py-2 border rounded-lg text-sm ${ro ? 'bg-slate-100' : ''}" placeholder="Describe cash purchase terms...">${esc(_mkCfg.cash_terms_text || '')}</textarea>
      </div>`
  } else {
    // Financing applicable -> percentage OR tiered
    inner += modeRadios(_mkCfg.mode, 'mk', 'setMkMode', !_canManageMarkup)
    if (_mkCfg.mode === 'percentage') {
      inner += `<div class="field-group">
        <label class="field-label">Finance Markup Rate (%)</label>
        <input id="mk_pct" type="number" step="0.1" min="0" value="${_mkCfg.percentage_rate ?? 20}" ${ro} class="w-48 px-3 py-2 border rounded-lg ${ro ? 'bg-slate-100' : ''}" placeholder="e.g. 20">
      </div>`
    } else {
      inner += `<div class="overflow-x-auto"><table class="w-full text-sm border border-slate-200 rounded-lg">
          <thead class="bg-slate-50 text-slate-500 text-xs"><tr>
            <th class="text-left px-3 py-2">From (KES)</th><th class="text-left px-3 py-2">To (KES)</th>
            <th class="text-left px-3 py-2">Markup (%)</th><th class="px-3 py-2"></th></tr></thead>
          <tbody id="mkTierRows"></tbody></table></div>
        ${_canManageMarkup ? `<button onclick="addMkTier()" class="btn mt-3 bg-slate-800 text-white px-4 py-2 rounded-lg text-xs"><i class="fas fa-plus mr-1"></i>Add Range</button>` : ''}`
    }
  }
  inner += productPicker(_mkCfg, 'mk', _canManageMarkup)
  el.innerHTML = inner
  if (_mkCfg.financing_applicable && _mkCfg.mode === 'tiered') renderMkTierRows()
}
function renderMkTierRows() {
  const tb = $('mkTierRows'); if (!tb) return
  const ro = _canManageMarkup ? '' : 'disabled'
  if (!_mkCfg.tiers.length) { tb.innerHTML = `<tr><td colspan="4" class="text-center text-slate-400 py-4 text-xs">No ranges yet. Click "Add Range".</td></tr>`; return }
  tb.innerHTML = _mkCfg.tiers.map((t, i) => `<tr class="border-t border-slate-100">
    <td class="px-3 py-2"><input type="number" min="0" value="${t.min ?? ''}" ${ro} onchange="updateMkTier(${i},'min',this.value)" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2"><input type="number" min="0" value="${t.max ?? ''}" ${ro} onchange="updateMkTier(${i},'max',this.value)" placeholder="∞" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2"><input type="number" step="0.1" min="0" value="${t.markup ?? ''}" ${ro} onchange="updateMkTier(${i},'markup',this.value)" class="w-28 px-2 py-1 border rounded ${ro ? 'bg-slate-100' : ''}"></td>
    <td class="px-3 py-2 text-right">${_canManageMarkup ? `<button onclick="removeMkTier(${i})" class="text-red-600 hover:underline text-xs"><i class="fas fa-trash"></i></button>` : ''}</td>
  </tr>`).join('')
}
window.addMkTier = () => { _mkCfg.tiers.push({ min: 0, max: null, markup: 0 }); renderMkTierRows() }
window.removeMkTier = (i) => { _mkCfg.tiers.splice(i, 1); renderMkTierRows() }
window.updateMkTier = (i, field, val) => { _mkCfg.tiers[i][field] = (field === 'max' && val === '') ? null : Number(val) }

// ---- Save handlers --------------------------------------------------------
window.saveMarkup = async () => {
  if (_mkCfg.financing_applicable) {
    if (_mkCfg.mode === 'percentage') _mkCfg.percentage_rate = Number(($('mk_pct') || {}).value || 0)
  } else {
    _mkCfg.cash_markup_pct = Number(($('mk_cash_pct') || {}).value || 0)
    _mkCfg.cash_terms_text = (($('mk_cash_terms') || {}).value || '')
  }
  try { await api.put('/settings/financing-markup', _mkCfg); toast('Markup saved') }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.saveProcessingFee = async () => {
  const body = { enabled: _feeCfg.enabled, mode: _feeCfg.mode, percentage_rate: 0, tiers: [], product_ids: _feeCfg.product_ids }
  if (_feeCfg.enabled && _feeCfg.mode === 'percentage') body.percentage_rate = Number(($('fee_pct') || {}).value || 0)
  if (_feeCfg.enabled && _feeCfg.mode === 'tiered') body.tiers = _feeCfg.tiers
  try { await api.put('/settings/processing-fee', body); toast('Processing fee saved') }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// DATA EXPORT & REPORTS (admin) - filter, download (CSV/Excel), email share
// ---------------------------------------------------------------------------
let _exportMeta = null
let _lastExport = null   // { label, cols, rows }
async function viewExports() {
  if (!_exportMeta) {
    try { _exportMeta = (await api.get('/export/datasets')).data } catch (e) { toast('Failed to load export options', false); return }
  }
  const opts = _exportMeta.datasets.map(d => `<option value="${d.key}">${esc(d.label)}</option>`).join('')
  $('content').innerHTML = `
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="card p-6 lg:col-span-1">
      <h3 class="font-bold text-slate-800 mb-1"><i class="fas fa-filter text-teal-600 mr-2"></i>Build Export</h3>
      <p class="text-xs text-slate-500 mb-4">Choose a dataset, apply filters, then download or email the result.</p>
      <label class="text-sm font-medium text-slate-600">Dataset</label>
      <select id="ex_dataset" onchange="exFilters()" class="w-full mt-1 mb-3 px-3 py-2 border border-slate-300 rounded-lg text-sm">${opts}</select>
      <div id="ex_filters"></div>
      <div class="grid grid-cols-2 gap-2 mt-1">
        <div><label class="text-xs text-slate-500">From date</label><input id="ex_from" type="date" class="w-full mt-1 px-2 py-2 border border-slate-300 rounded-lg text-sm"></div>
        <div><label class="text-xs text-slate-500">To date</label><input id="ex_to" type="date" class="w-full mt-1 px-2 py-2 border border-slate-300 rounded-lg text-sm"></div>
      </div>
      <button onclick="runExport()" class="btn w-full mt-4 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-magnifying-glass mr-1"></i>Preview Data</button>
    </div>
    <div class="card p-6 lg:col-span-2">
      <div class="flex items-center justify-between mb-3">
        <h3 class="font-bold text-slate-800"><i class="fas fa-table text-teal-600 mr-2"></i>Preview & Download</h3>
        <span id="ex_count" class="text-xs text-slate-500"></span>
      </div>
      <div class="flex flex-wrap gap-2 mb-4">
        <button onclick="downloadExport('csv')" class="btn bg-emerald-600 text-white px-3 py-2 rounded-lg text-sm"><i class="fas fa-file-csv mr-1"></i>Download CSV</button>
        <button onclick="downloadExport('xlsx')" class="btn bg-blue-600 text-white px-3 py-2 rounded-lg text-sm"><i class="fas fa-file-excel mr-1"></i>Download Excel</button>
        <button onclick="emailExportModal()" class="btn brand-bg text-white px-3 py-2 rounded-lg text-sm"><i class="fas fa-paper-plane mr-1"></i>Share via Email</button>
      </div>
      <div id="ex_preview" class="overflow-x-auto text-xs text-slate-500">Run a preview to see data here.</div>
    </div>
  </div>`
  exFilters()
}
window.exFilters = () => {
  const key = $('ex_dataset').value
  const d = _exportMeta.datasets.find(x => x.key === key)
  $('ex_filters').innerHTML = (d.filters || []).map(f =>
    `<div class="mb-2"><label class="text-xs text-slate-500 capitalize">${esc(f.replace(/_/g,' '))}</label>
     <input id="exf_${f}" placeholder="Any" class="w-full mt-1 px-2 py-2 border border-slate-300 rounded-lg text-sm"></div>`
  ).join('') || '<p class="text-xs text-slate-400 mb-2">No specific filters for this dataset.</p>'
}
function exParams() {
  const key = $('ex_dataset').value
  const d = _exportMeta.datasets.find(x => x.key === key)
  const filters = {}
  ;(d.filters || []).forEach(f => { const v = $('exf_' + f)?.value?.trim(); if (v) filters[f] = v })
  return { dataset: key, filters, date_from: $('ex_from').value || undefined, date_to: $('ex_to').value || undefined }
}
window.runExport = async () => {
  try {
    const { data } = await api.post('/export/data', exParams())
    _lastExport = { label: data.label, cols: data.cols, rows: data.rows }
    $('ex_count').textContent = data.rows.length + ' row(s)'
    const head = data.cols.map(c => `<th class="text-left px-2 py-1 bg-slate-50 sticky top-0">${esc(c)}</th>`).join('')
    const body = data.rows.slice(0, 200).map(r => `<tr class="border-t border-slate-100">${data.cols.map(c => `<td class="px-2 py-1">${esc(r[c] ?? '')}</td>`).join('')}</tr>`).join('')
    $('ex_preview').innerHTML = data.rows.length
      ? `<table class="w-full"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>${data.rows.length > 200 ? '<p class="mt-2 text-slate-400">Showing first 200 rows. Download for full data.</p>' : ''}`
      : '<p class="text-slate-400">No rows match these filters.</p>'
  } catch (err) { toast(err.response?.data?.error || 'Export failed', false) }
}
function exFilename(ext) {
  const key = $('ex_dataset')?.value || 'export'
  return `farmsky-${key}-${new Date().toISOString().slice(0,10)}.${ext}`
}
window.downloadExport = async (fmt) => {
  if (!_lastExport) { await runExport() }
  if (!_lastExport || !_lastExport.rows.length) return toast('Nothing to download — preview first', false)
  const { cols, rows } = _lastExport
  if (fmt === 'csv') {
    const esc2 = v => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s }
    const csv = cols.join(',') + '\n' + rows.map(r => cols.map(c => esc2(r[c])).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    triggerDownload(blob, exFilename('csv'))
  } else {
    // Real .xlsx via SheetJS
    const aoa = [cols, ...rows.map(r => cols.map(c => r[c]))]
    const ws = XLSX.utils.aoa_to_sheet(aoa)
    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, 'Export')
    XLSX.writeFile(wb, exFilename('xlsx'))
  }
  toast('Download started')
}
function triggerDownload(blob, name) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click()
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url) }, 1000)
}
window.emailExportModal = () => {
  const emailLive = _exportMeta?.email_configured
  showModal(`<h3 class="font-bold mb-1"><i class="fas fa-paper-plane text-teal-600 mr-2"></i>Share Export by Email</h3>
    ${emailLive
      ? '<p class="text-xs text-emerald-600 mb-3">Email provider configured — a CSV attachment will be sent.</p>'
      : '<p class="text-xs text-amber-600 mb-3">Email provider not configured at deploy. Set EMAIL_API_URL/TOKEN/FROM, or use the Download buttons. (Trying anyway will report this.)</p>'}
    <label class="text-sm font-medium">Recipient email</label>
    <input id="ex_email" type="email" placeholder="name@example.com" class="w-full mt-1 mb-4 px-3 py-2 border border-slate-300 rounded-lg">
    <div class="flex gap-2"><button onclick="sendExportEmail()" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm">Send</button>
    <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.sendExportEmail = async () => {
  const to = $('ex_email').value
  if (!to) return toast('Enter a recipient email', false)
  try {
    const { data } = await api.post('/export/email', { ...exParams(), to })
    closeModal(); toast(data.message || 'Email sent')
  } catch (err) {
    const d = err.response?.data
    toast(d?.message || d?.error || 'Email failed', false)
  }
}

// ---------------------------------------------------------------------------
// MODAL
// ---------------------------------------------------------------------------
function showModal(html) {
  $('modal').innerHTML = `<div class="fixed inset-0 modal-overlay flex items-center justify-center p-4 z-40" onclick="if(event.target===this)closeModal()">
    <div class="bg-white rounded-2xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto fade-in">${html}</div></div>`
}
window.closeModal = () => { stopLive(); $('modal').innerHTML = '' }

init()
