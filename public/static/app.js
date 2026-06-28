// ============================================================================
// Farmsky - Sharia-Compliant Agri-Finance Platform - SPA frontend
// ============================================================================
const api = axios.create({ baseURL: '/api', withCredentials: true })
let state = { user: null, route: 'dashboard', data: {} }
const $ = (id) => document.getElementById(id)
const fmt = (n) => 'KES ' + Number(n || 0).toLocaleString()
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]))
// Friendly label for the 'credit' payment type (data value stays 'credit')
const payLabel = (t) => t === 'credit'
  ? 'Pay Later <span class="text-[10px] text-slate-400">(Murabaha Financing)</span>'
  : (String(t || '').charAt(0).toUpperCase() + String(t || '').slice(1))

let _products = [], _agents = [], _users = []

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
        <input id="password" type="password" placeholder="••••" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required>
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
    <form id="suvForm" class="space-y-3">
      <div><label class="text-sm font-medium text-slate-600">Verification Code</label>
        <input id="su_code" type="text" inputmode="numeric" placeholder="6-digit code" value="${esc(demoOtp || '')}" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg tracking-widest" required></div>
      <div><label class="text-sm font-medium text-slate-600">Create Password</label>
        <input id="su_pass" type="password" placeholder="Choose a password" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required></div>
      <button class="btn w-full brand-bg text-white py-2.5 rounded-lg font-semibold">Verify & Create Account</button>
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
        <input id="rs_pass" type="password" placeholder="New password" class="w-full mt-1 px-4 py-2.5 border border-slate-300 rounded-lg" required></div>
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
async function logout() { await api.post('/logout'); state.user = null; renderLogin() }

// ---------------------------------------------------------------------------
// APP SHELL + NAV
// ---------------------------------------------------------------------------
function navItems() {
  const r = state.user.role
  const common = [{ k: 'dashboard', i: 'fa-gauge-high', t: 'Dashboard' }]
  if (r === 'super_admin' || r === 'admin') return [...common,
    { k: 'approvals', i: 'fa-clipboard-check', t: 'Approvals' },
    { k: 'inventory', i: 'fa-boxes-stacked', t: 'Inventory' },
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'contracts', i: 'fa-file-signature', t: 'Contracts' },
    { k: 'agents', i: 'fa-user-tie', t: 'Agents' },
    { k: 'users', i: 'fa-user-gear', t: 'User Accounts' },
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' },
    { k: 'exports', i: 'fa-database', t: 'Data Export' },
    { k: 'profile', i: 'fa-id-badge', t: 'My Profile' }]
  if (r === 'agent') return [...common,
    { k: 'onboard', i: 'fa-user-plus', t: 'Onboard Customer' },
    { k: 'customers', i: 'fa-users', t: 'My Customers' },
    { k: 'contracts', i: 'fa-file-signature', t: 'Applications' },
    { k: 'profile', i: 'fa-id-badge', t: 'My Profile' }]
  if (r === 'customer') return [...common,
    { k: 'shop', i: 'fa-store', t: 'Shop / Buy' },
    { k: 'contracts', i: 'fa-file-signature', t: 'My Orders' },
    { k: 'profile', i: 'fa-user-gear', t: 'My Profile' }]
  if (r === 'support') return [...common,
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' },
    { k: 'profile', i: 'fa-user-gear', t: 'My Profile' }]
  return common
}
// Agents/admins also get a self-service profile entry.
const _extraProfileRoles = ['agent', 'admin', 'super_admin']
function renderApp() {
  const items = navItems()
  const roleLabel = (state.user.custom_role && String(state.user.custom_role).trim())
    ? esc(state.user.custom_role) : esc(state.user.role.replace(/_/g, ' '))
  $('app').innerHTML = `
  <div class="relative min-h-screen lg:flex">
    <!-- Mobile backdrop -->
    <div id="sidebarBackdrop" class="fixed inset-0 bg-black/40 z-40 hidden lg:hidden" onclick="toggleSidebar(false)"></div>
    <aside id="sidebar" class="w-64 brand-bg text-white flex flex-col fixed h-full top-0 left-0 z-50">
      <div class="p-4 border-b border-white/10 bg-white/95 flex items-center justify-between">
        <img src="/static/farmsky-logo.png" alt="Farmsky" class="h-14 mx-auto object-contain">
        <button onclick="toggleSidebar(false)" class="lg:hidden text-slate-600 px-2"><i class="fas fa-xmark text-xl"></i></button>
      </div>
      <nav class="flex-1 py-4 overflow-y-auto">
        ${items.map(it => `<div class="nav-link px-5 py-3 flex items-center gap-3 text-sm hover:bg-white/10 ${state.route === it.k ? 'active' : ''}" onclick="go('${it.k}')"><i class="fas ${it.i} w-5"></i>${it.t}</div>`).join('')}
      </nav>
      <div class="p-4 border-t border-white/10">
        <div class="text-sm font-medium">${esc(state.user.full_name)}</div>
        <div class="text-xs text-teal-200 capitalize mb-2">${roleLabel}</div>
        <button onclick="logout()" class="btn w-full text-xs bg-white/10 hover:bg-white/20 py-2 rounded-lg"><i class="fas fa-right-from-bracket mr-1"></i>Logout</button>
      </div>
    </aside>
    <main id="mainArea" class="flex-1 lg:ml-64 min-w-0">
      <header class="app-header bg-white border-b border-slate-200 px-4 sm:px-8 py-4 flex justify-between items-center gap-3 sticky top-0 z-30">
        <div class="flex items-center gap-3 min-w-0">
          <button onclick="toggleSidebar(true)" class="lg:hidden text-slate-600 text-xl px-1"><i class="fas fa-bars"></i></button>
          <h2 id="pageTitle" class="text-lg sm:text-xl font-bold text-slate-800 truncate"></h2>
        </div>
        <div class="text-xs sm:text-sm text-slate-500 whitespace-nowrap"><i class="fas fa-shield-halved text-teal-600 mr-1"></i><span class="hidden sm:inline">Sharia-Compliant · No Interest</span><span class="sm:hidden">Halal</span></div>
      </header>
      <div id="content" class="p-4 sm:p-8"></div>
    </main>
  </div>
  <div id="modal"></div>`
  route()
}
window.toggleSidebar = (open) => {
  const sb = $('sidebar'), bd = $('sidebarBackdrop')
  if (!sb) return
  if (open) { sb.classList.add('open'); bd.classList.remove('hidden') }
  else { sb.classList.remove('open'); bd.classList.add('hidden') }
}
window.go = (r) => { state.route = r; toggleSidebar(false); renderApp() }
function route() {
  const titles = { dashboard: 'Dashboard', approvals: 'Murabaha Approvals', inventory: 'Inventory Management', customers: 'Customers', contracts: 'Contracts', agents: 'Agent Management', users: 'User Accounts', repayments: 'Repayment Performance', onboard: 'Customer Onboarding', shop: 'Shop', exports: 'Data Export & Reports', profile: 'My Profile & Settings' }
  $('pageTitle').textContent = titles[state.route] || 'Dashboard'
  const map = { dashboard: viewDashboard, approvals: viewApprovals, inventory: viewInventory, customers: viewCustomers, contracts: viewContracts, agents: viewAgents, users: viewUsers, repayments: viewRepayments, onboard: viewOnboard, shop: viewShop, exports: viewExports, profile: viewProfile }
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
      ${statCard('fa-file-signature', 'Active Contracts', data.active_contracts, 'bg-teal-50 text-teal-600')}
      ${statCard('fa-money-bill-wave', 'Total Outstanding', fmt(data.total_outstanding), 'bg-amber-50 text-amber-600')}
      ${statCard('fa-circle-check', 'Completed', data.completed_contracts, 'bg-emerald-50 text-emerald-600')}
      ${next}
    </div>
    <div class="card p-6"><h3 class="font-bold mb-2"><i class="fas fa-store text-teal-600 mr-2"></i>Quick Actions</h3>
      <button onclick="go('shop')" class="btn brand-bg text-white px-5 py-2.5 rounded-lg text-sm mr-2"><i class="fas fa-cart-plus mr-1"></i>Buy Products</button>
      <button onclick="go('contracts')" class="btn bg-slate-100 px-5 py-2.5 rounded-lg text-sm"><i class="fas fa-list mr-1"></i>My Contracts</button>
    </div>`
  } else if (data.role === 'agent') {
    $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      ${statCard('fa-users', 'Customers Onboarded', data.customers_onboarded, 'bg-teal-50 text-teal-600')}
      ${statCard('fa-file-signature', 'Active Contracts', data.active_contracts, 'bg-blue-50 text-blue-600')}
      ${statCard('fa-clock', 'Pending Approvals', data.pending_approvals, 'bg-amber-50 text-amber-600')}
      ${statCard('fa-coins', 'Commission', fmt(data.commission), 'bg-emerald-50 text-emerald-600')}
      ${statCard('fa-wallet', 'Portfolio Value', fmt(data.portfolio_value), 'bg-indigo-50 text-indigo-600')}
      ${statCard('fa-triangle-exclamation', 'Portfolio at Risk', data.portfolio_at_risk + '%', 'bg-red-50 text-red-600')}
      ${statCard('fa-calendar-xmark', 'Late Installments', data.late_installments, 'bg-orange-50 text-orange-600')}
    </div>
    <div class="card p-6"><button onclick="go('onboard')" class="btn brand-bg text-white px-5 py-2.5 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Onboard New Customer</button></div>`
  } else {
    $('content').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      ${statCard('fa-chart-line', 'Total Sales', fmt(data.total_sales), 'bg-teal-50 text-teal-600')}
      ${statCard('fa-hand-holding-dollar', 'Murabaha Financed', fmt(data.murabaha_financed), 'bg-blue-50 text-blue-600')}
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
  const { data } = await api.get('/products')
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
    <div class="grid grid-cols-2 gap-3 text-sm">
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
  const elig = p.payment_eligibility || 'both'
  // Build payment options based on the product's configured viability rule.
  let opts = ''
  if (elig === 'cash' || elig === 'both') opts += '<option value="cash">Cash</option>'
  if (elig === 'finance' || elig === 'both') opts += '<option value="credit">Pay Later — Murabaha Financing</option>'
  showModal(`
    <h3 class="text-lg font-bold mb-1">Purchase: ${esc(p.name)}</h3>
    <p class="text-xs text-slate-500 mb-4">Choose payment type — system will disclose full Murabaha cost before you consent.</p>
    <div class="space-y-3">
      <div class="field-group"><label class="field-label">Quantity</label><input id="qty" type="number" value="1" min="1" max="${p.quantity}" class="w-full px-3 py-2 border border-slate-300 rounded-lg"></div>
      <div class="field-group"><label class="field-label">Payment Type</label>
        <select id="ptype" class="w-full px-3 py-2 border border-slate-300 rounded-lg" onchange="toggleTerm()">${opts}</select></div>
      <div id="termWrap" class="hidden field-group"><label class="field-label">Payment Term (months)</label>
        <select id="term" class="w-full px-3 py-2 border border-slate-300 rounded-lg">
          <option>3</option><option selected>6</option><option>9</option><option>12</option>
        </select></div>
      <div class="field-group"><label class="field-label">Delivery Location</label><input id="dloc" type="text" placeholder="Village / Ward" class="w-full px-3 py-2 border border-slate-300 rounded-lg"></div>
    </div>
    <div id="quoteBox" class="mt-4"></div>
    <div class="flex gap-2 mt-5">
      <button onclick="getQuote(${p.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-calculator mr-1"></i>Disclose Cost</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button>
    </div>`)
  toggleTerm()
}
window.toggleTerm = () => { const t = $('termWrap'); if (t) t.classList.toggle('hidden', $('ptype').value !== 'credit') }
window.getQuote = async (productId) => {
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0 }
  const { data } = await api.post('/murabaha/quote', body)
  const credit = body.payment_type === 'credit'
  const terms = data.terms || ''
  const termsShort = terms.length > 220 ? esc(terms.slice(0, 220)) + '…' : esc(terms)
  $('quoteBox').innerHTML = `
    <div class="bg-teal-50 border border-teal-200 rounded-xl p-4">
      <h4 class="font-bold text-teal-800 mb-2"><i class="fas fa-file-invoice-dollar mr-1"></i>Cost Disclosure</h4>
      <div class="space-y-1 text-sm">
        <div class="flex justify-between"><span>Supplier Cost</span><b>${fmt(data.supplier_cost)}</b></div>
        <div class="flex justify-between"><span>Markup</span><b>${data.markup_pct}%</b></div>
        <div class="flex justify-between text-base text-teal-800"><span>${credit ? 'Financed Price' : 'Amount Payable'}</span><b>${fmt(data.murabaha_price)}</b></div>
        ${credit ? `<div class="flex justify-between"><span>Deposit Required (${data.deposit_pct}%)</span><b>${fmt(data.deposit_required)}</b></div>
        <div class="flex justify-between"><span>Term</span><b>${data.term_months} months</b></div>
        <div class="flex justify-between"><span>Monthly Payment</span><b>${fmt(data.monthly_payment)}</b></div>` : ''}
      </div>
      <p class="text-xs text-teal-700 mt-2 italic">${esc(data.sharia_note)}</p>
      ${terms ? `<div class="mt-3 border-t border-teal-200 pt-2">
        <p class="text-xs font-semibold text-teal-800 mb-1">Terms &amp; Conditions</p>
        <p class="text-xs text-slate-600 whitespace-pre-line">${termsShort}</p>
        ${terms.length > 220 ? `<button type="button" onclick="showTermsText(${JSON.stringify(terms).replace(/"/g,'&quot;')})" class="text-xs text-teal-600 hover:underline mt-1">Read more</button>` : ''}
      </div>` : ''}
      <label class="flex items-start gap-2 mt-3 text-sm"><input type="checkbox" id="consent" class="mt-1"> <span>I explicitly consent to this fixed Murabaha price.</span></label>
      <label class="flex items-start gap-2 mt-2 text-sm"><input type="checkbox" id="acceptTerms" class="mt-1"> <span>I have read and accept the Terms &amp; Conditions.</span></label>
      <button onclick="submitBuy(${productId})" class="btn w-full mt-3 brand-bg text-white py-2.5 rounded-lg text-sm">${credit ? 'Submit Pay Later Application' : 'Confirm Cash Purchase'}</button>
    </div>`
}
window.showTermsText = (text) => {
  showModal(`<h3 class="font-bold mb-2"><i class="fas fa-file-contract text-teal-600 mr-2"></i>Terms &amp; Conditions</h3>
    <div class="text-sm text-slate-700 whitespace-pre-line max-h-[60vh] overflow-y-auto border border-slate-200 rounded-lg p-3 bg-slate-50">${esc(text)}</div>
    <button onclick="closeModal()" class="btn w-full mt-3 bg-slate-100 py-2 rounded-lg text-sm">Close</button>`)
}
window.submitBuy = async (productId) => {
  if (!$('consent').checked) return toast('Consent is required (Sharia requirement)', false)
  if (!$('acceptTerms').checked) return toast('You must accept the Terms & Conditions', false)
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0, delivery_location: $('dloc').value, consent: true, terms_accepted: true }
  try {
    const { data } = await api.post('/murabaha/apply', body)
    if (data.requires_payment) {
      // Cash purchase -> pay now via M-Pesa STK push (full amount).
      payModal(data.id, data.murabaha_price, data.outstanding, 'cash')
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
  $('content').innerHTML = `<div class="card overflow-hidden">
    <table class="responsive-table w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
        <th class="text-left px-4 py-3">Ref</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Product</th>
        <th class="text-left px-4 py-3">Type</th><th class="text-right px-4 py-3">Price</th><th class="text-right px-4 py-3">Outstanding</th>
        <th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
      <tbody>${data.contracts.map(c => `<tr class="border-t border-slate-100">
        <td data-label="Ref" class="px-4 py-3 font-mono text-xs">${esc(c.contract_ref)}</td>
        <td data-label="Customer" class="px-4 py-3">${esc(c.customer_name)}</td>
        <td data-label="Product" class="px-4 py-3">${esc(c.product_name)} ×${c.quantity}</td>
        <td data-label="Type" class="px-4 py-3">${payLabel(c.payment_type)}</td>
        <td data-label="Price" class="px-4 py-3 text-right">${fmt(c.murabaha_price)}</td>
        <td data-label="Outstanding" class="px-4 py-3 text-right">${fmt(c.outstanding)}</td>
        <td data-label="Status" class="px-4 py-3">${badge(c.status)}</td>
        <td class="px-4 py-3"><button onclick="contractDetail(${c.id})" class="text-teal-600 hover:underline text-xs">View</button></td>
      </tr>`).join('') || '<tr><td colspan="8" class="text-center py-8 text-slate-400">No contracts</td></tr>'}</tbody>
    </table></div>`
}
window.contractDetail = async (id) => {
  const { data } = await api.get('/murabaha/' + id)
  const c = data.contract
  const canPay = state.user.role === 'customer' && c.status === 'active'
  showModal(`
    <div class="flex justify-between items-start mb-3">
      <div><h3 class="text-lg font-bold">${esc(c.contract_ref)}</h3><p class="text-xs text-slate-500">${esc(c.customer_name)} · ${esc(c.product_name)}</p></div>
      ${badge(c.status)}
    </div>
    <div class="grid grid-cols-2 gap-3 text-sm mb-4">
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Supplier Cost</p><b>${fmt(c.supplier_cost)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Markup</p><b>${c.markup_pct}%</b></div>
      <div class="bg-teal-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Murabaha Price (FIXED)</p><b>${fmt(c.murabaha_price)}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Outstanding</p><b>${fmt(c.outstanding)}</b></div>
    </div>
    ${data.repayments.length ? `<h4 class="font-semibold text-sm mb-2">Repayment Schedule</h4>
    <table class="w-full text-xs mb-4"><thead class="text-slate-400"><tr><th class="text-left">#</th><th class="text-left">Due</th><th class="text-right">Amount</th><th class="text-right">Paid</th><th>Status</th></tr></thead>
    <tbody>${data.repayments.map(r => `<tr class="border-t border-slate-100"><td>${r.installment_no}</td><td>${r.due_date}</td><td class="text-right">${fmt(r.amount_due)}</td><td class="text-right">${fmt(r.amount_paid)}</td><td class="text-center">${badge(r.status)}</td></tr>`).join('')}</tbody></table>` : ''}
    <div class="flex gap-2">
      ${canPay ? `<button onclick="payModal(${c.id}, ${c.monthly_payment}, ${c.outstanding})" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-money-bill-wave mr-1"></i>Make a Payment</button>` : ''}
      <button onclick="viewDoc(${c.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-file-pdf mr-1"></i>Documents</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Close</button>
    </div>`)
}
// Brand colours / icons for each payment provider used in the selector.
const PROVIDER_META = {
  mpesa:   { label: 'M-Pesa',  icon: 'fa-mobile-screen-button', color: '#43b02a' },
  sasapay: { label: 'SasaPay', icon: 'fa-wallet',               color: '#0a7d3e' },
  kcb:     { label: 'KCB',     icon: 'fa-building-columns',      color: '#00a651' }
}
window.payState = { provider: 'mpesa', providers: [] }
window.selectProvider = (pid) => {
  window.payState.provider = pid
  document.querySelectorAll('[data-prov]').forEach(el => {
    const active = el.getAttribute('data-prov') === pid
    el.classList.toggle('ring-2', active)
    el.classList.toggle('ring-teal-500', active)
    el.classList.toggle('border-teal-500', active)
    el.classList.toggle('bg-teal-50', active)
  })
  const sel = (window.payState.providers || []).find(p => p.id === pid) || { mode: 'simulation', live: false }
  const b = $('provBanner')
  if (b) b.innerHTML = sel.live
    ? `<div class="bg-emerald-50 border border-emerald-200 rounded-lg p-2 text-xs text-emerald-700"><i class="fas fa-circle-check mr-1"></i>Live ${esc(sel.label)} (${esc(sel.mode)}) — you will receive a real payment prompt.</div>`
    : `<div class="bg-amber-50 border border-amber-200 rounded-lg p-2 text-xs text-amber-700"><i class="fas fa-flask mr-1"></i>${esc(sel.label)} simulation mode — no real money moves. Add ${esc(sel.label)} keys to go live.</div>`
}
window.payModal = async (id, amount, outstanding, kind) => {
  kind = kind || 'repay'
  const isCash = kind === 'cash'
  // Load the available providers (M-Pesa / SasaPay / KCB) and their live/sim mode.
  let providers = [
    { id: 'mpesa', label: 'M-Pesa', live: false, mode: 'simulation' },
    { id: 'sasapay', label: 'SasaPay', live: false, mode: 'simulation' },
    { id: 'kcb', label: 'KCB', live: false, mode: 'simulation' }
  ]
  try { providers = (await api.get('/payments/providers')).data.providers || providers } catch {}
  window.payState = { provider: providers[0].id, providers }
  const cards = providers.map(p => {
    const m = PROVIDER_META[p.id] || { label: p.label, icon: 'fa-credit-card', color: '#0d9488' }
    return `<button type="button" data-prov="${p.id}" onclick="selectProvider('${p.id}')"
      class="btn flex-1 border border-slate-300 rounded-lg p-3 flex flex-col items-center gap-1 text-center transition">
      <i class="fas ${m.icon} text-xl" style="color:${m.color}"></i>
      <span class="text-xs font-semibold text-slate-700">${esc(m.label)}</span>
      <span class="text-[10px] ${p.live ? 'text-emerald-600' : 'text-amber-600'}">${p.live ? 'Live' : 'Demo'}</span>
    </button>`
  }).join('')
  showModal(`<h3 class="text-lg font-bold mb-1"><i class="fas fa-money-bill-wave text-teal-600 mr-2"></i>${isCash ? 'Cash Checkout — Make Payment' : 'Make a Payment'}</h3>
    <p class="text-xs text-slate-500 mb-3">${isCash ? 'Amount due' : 'Outstanding'}: ${fmt(outstanding)}</p>
    <label class="text-sm font-medium block mb-1">Choose payment method</label>
    <div class="flex gap-2 mb-3">${cards}</div>
    <div id="provBanner" class="mb-3"></div>
    <label class="text-sm font-medium">Phone Number</label><input id="mpphone" value="${esc(state.user.phone)}" class="w-full mt-1 mb-3 px-3 py-2 border border-slate-300 rounded-lg" placeholder="07XXXXXXXX">
    <label class="text-sm font-medium">Amount (KES)</label><input id="mpamt" type="number" value="${amount}" ${isCash ? 'readonly' : ''} class="w-full mt-1 mb-4 px-3 py-2 border border-slate-300 rounded-lg ${isCash ? 'bg-slate-50' : ''}">
    <div id="payStatus"></div>
    <div class="flex gap-2"><button id="payBtn" onclick="doPay(${id}, '${kind}')" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-paper-plane mr-1"></i>Send Payment Prompt</button>
    <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  selectProvider(window.payState.provider)
}
window.doPay = async (id, kind) => {
  const isCash = kind === 'cash'
  const provider = (window.payState && window.payState.provider) || 'mpesa'
  const provLabel = (PROVIDER_META[provider] || {}).label || provider
  const btn = $('payBtn'); btn.disabled = true; btn.classList.add('opacity-50')
  $('payStatus').innerHTML = `<div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>Sending ${esc(provLabel)} prompt...</div>`
  try {
    const { data } = await api.post('/payments/initiate', { contract_id: id, amount: $('mpamt').value, phone: $('mpphone').value, provider })
    $('payStatus').innerHTML = `<div class="bg-teal-50 border border-teal-200 rounded-lg p-2 text-xs text-teal-700 mb-3"><i class="fas fa-mobile-alt mr-1"></i>${esc(data.customer_message || 'Payment prompt sent. Confirm on your phone.')}</div><div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>Waiting for confirmation...</div>`
    let tries = 0
    const poll = async () => {
      tries++
      try {
        const { data: cd } = await api.post('/payments/confirm', { checkout_request_id: data.checkout_request_id })
        if (cd.status === 'success') { closeModal(); toast((isCash ? 'Cash purchase complete! Receipt: ' : 'Payment received! Receipt: ') + cd.mpesa_receipt); state.route = 'contracts'; renderApp(); return }
        else if (cd.status === 'failed') { $('payStatus').innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-3">${esc(cd.result_desc || 'Payment failed')}</div>`; btn.disabled = false; btn.classList.remove('opacity-50'); return }
      } catch (e) {}
      if (tries < 20) setTimeout(poll, 3000)
      else { $('payStatus').innerHTML = '<div class="text-xs text-amber-600 mb-3">Timed out waiting. Check Contracts later.</div>'; btn.disabled = false; btn.classList.remove('opacity-50') }
    }
    setTimeout(poll, data.simulated ? 1200 : 4000)
  } catch (err) {
    $('payStatus').innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-2 text-xs text-red-700 mb-3">${esc(err.response?.data?.error || 'Payment failed')}</div>`
    btn.disabled = false; btn.classList.remove('opacity-50')
  }
}
window.viewDoc = async (id) => {
  const { data } = await api.get('/documents/contract/' + id)
  const c = data.contract
  const isCash = c.payment_type === 'cash'
  const terms = (data.terms || '').trim()
  // The document is the readable agreement itself: cash-purchase terms for a
  // cash order, or finance terms for a financed (Murabaha) order. The QR code
  // is demoted to a small verification stamp in the header — it is NOT the
  // primary content any more.
  const docTitle = isCash ? 'Cash Purchase Agreement' : 'Murabaha Financing Agreement'
  const termsTitle = isCash ? 'Terms of Cash Purchase' : 'Finance Terms (Murabaha)'
  const today = new Date().toISOString().slice(0, 10)
  const termsHtml = terms
    ? `<div class="text-sm text-slate-700 whitespace-pre-line leading-relaxed">${esc(terms)}</div>`
    : `<p class="text-sm italic text-slate-400">No ${isCash ? 'cash purchase' : 'finance'} terms are recorded for this order.</p>`
  showModal(`<div id="docContent" class="text-left">
    <div class="flex justify-between items-start border-b border-slate-200 pb-3 mb-4">
      <div>
        <h3 class="font-bold text-lg text-slate-800">${docTitle}</h3>
        <p class="text-xs text-slate-500 font-mono">${esc(c.contract_ref)}</p>
        <p class="text-xs text-slate-400">Issued ${today} · ${isCash ? 'Cash Purchase' : 'Pay Later (Financing)'}</p>
      </div>
      <div class="text-center shrink-0 ml-3">
        <img src="${data.qr}" class="w-16 h-16" alt="Verification QR" title="Scan to verify ${esc(c.contract_ref)}">
        <p class="text-[9px] text-slate-400 mt-0.5">Verify</p>
      </div>
    </div>

    <div class="grid grid-cols-2 gap-2 text-sm bg-slate-50 p-4 rounded-lg mb-4">
      <p><span class="text-slate-500">Customer:</span> <b>${esc(c.customer_name)}</b></p>
      <p><span class="text-slate-500">National ID:</span> <b>${esc(c.national_id || '—')}</b></p>
      <p><span class="text-slate-500">Product:</span> <b>${esc(c.product_name)} ×${c.quantity}</b></p>
      <p><span class="text-slate-500">County:</span> <b>${esc(c.county || '—')}</b></p>
      <p><span class="text-slate-500">Supplier Cost:</span> <b>${fmt(c.supplier_cost)}</b></p>
      <p><span class="text-slate-500">Markup:</span> <b>${c.markup_pct}%</b></p>
      <p class="col-span-2 pt-1 border-t border-slate-200 mt-1"><span class="text-slate-500">${isCash ? 'Amount Payable' : 'Financed Price'} (fixed):</span> <b class="text-teal-700">${fmt(c.murabaha_price)}</b></p>
      ${!isCash && c.deposit_required ? `<p><span class="text-slate-500">Deposit Required:</span> <b>${fmt(c.deposit_required)}</b></p>` : ''}
      ${!isCash ? `<p><span class="text-slate-500">Outstanding:</span> <b>${fmt(c.outstanding)}</b></p>` : ''}
    </div>

    <div class="border border-slate-200 rounded-lg overflow-hidden mb-2">
      <div class="bg-teal-600 text-white px-4 py-2 text-sm font-semibold"><i class="fas fa-file-contract mr-2"></i>${termsTitle}</div>
      <div class="p-4 max-h-72 overflow-y-auto">${termsHtml}</div>
    </div>
    <p class="text-xs italic text-slate-500 mb-4">Sharia-compliant Murabaha agreement. The price is fixed at sale — no interest, penalties, or compounding are ever applied. This document constitutes your record of the agreed ${isCash ? 'cash purchase' : 'finance'} terms.</p>
  </div>
  <div class="flex gap-2">
    <button onclick="printDoc()" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-print mr-1"></i>Print / Save PDF</button>
    <button onclick="closeModal()" class="btn px-5 bg-slate-100 rounded-lg text-sm">Close</button>
  </div>`)
}
// Print just the document (terms agreement) cleanly.
window.printDoc = () => {
  const el = $('docContent')
  if (!el) { window.print(); return }
  const w = window.open('', '_blank')
  w.document.write(`<html><head><title>Agreement</title>
    <style>body{font-family:system-ui,Arial,sans-serif;color:#1e293b;padding:32px;line-height:1.5}
    h3{margin:0 0 4px}img{width:80px;height:80px}.muted{color:#64748b;font-size:12px}
    .box{border:1px solid #cbd5e1;border-radius:8px;padding:16px;margin-top:12px;white-space:pre-line;font-size:13px}
    .grid{font-size:13px;background:#f8fafc;padding:12px;border-radius:8px;margin:12px 0}</style></head>
    <body>${el.innerHTML}</body></html>`)
  w.document.close(); w.focus(); setTimeout(() => { w.print(); w.close() }, 300)
}

// ---------------------------------------------------------------------------
// APPROVALS (admin)
// ---------------------------------------------------------------------------
async function viewApprovals() {
  const { data } = await api.get('/murabaha')
  const pending = data.contracts.filter(c => c.status === 'pending')
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Ref</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Product</th><th class="text-right px-4 py-3">Price</th><th class="text-left px-4 py-3">Term</th><th></th></tr></thead>
    <tbody>${pending.map(c => `<tr class="border-t border-slate-100">
      <td data-label="Ref" class="px-4 py-3 font-mono text-xs">${esc(c.contract_ref)}</td><td data-label="Customer" class="px-4 py-3">${esc(c.customer_name)}</td>
      <td data-label="Product" class="px-4 py-3">${esc(c.product_name)} ×${c.quantity}</td><td data-label="Price" class="px-4 py-3 text-right">${fmt(c.murabaha_price)}</td>
      <td data-label="Term" class="px-4 py-3">${c.term_months}mo</td>
      <td class="px-4 py-3 text-right whitespace-nowrap">
        <button onclick="contractDetail(${c.id})" class="text-slate-500 hover:underline text-xs mr-3">Review</button>
        <button onclick="decide(${c.id},'approve')" class="text-emerald-600 hover:underline text-xs mr-2"><i class="fas fa-check"></i> Approve</button>
        <button onclick="decide(${c.id},'reject')" class="text-red-600 hover:underline text-xs"><i class="fas fa-xmark"></i> Reject</button>
      </td></tr>`).join('') || '<tr><td colspan="6" class="text-center py-8 text-slate-400">No pending approvals</td></tr>'}</tbody>
  </table></div>`
}
window.decide = async (id, action) => {
  try { await api.post(`/murabaha/${id}/decision`, { action }); toast('Contract ' + action + 'd'); viewApprovals() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// INVENTORY (admin CRUD + image)
// ---------------------------------------------------------------------------
async function viewInventory() {
  const { data } = await api.get('/products')
  _products = data.products
  $('content').innerHTML = `
  <div class="flex justify-end mb-4"><button onclick="addProductModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-plus mr-1"></i>Add Product</button></div>
  <div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Image</th><th class="text-left px-4 py-3">SKU</th><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Category</th><th class="text-right px-4 py-3">Buy</th><th class="text-right px-4 py-3">Cash</th><th class="text-right px-4 py-3">Pay Later</th><th class="text-right px-4 py-3">Qty</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.products.map(p => `<tr class="border-t border-slate-100">
      <td data-label="Image" class="px-4 py-2">${prodImg(p, 'w-10 h-10 rounded-lg')}</td>
      <td data-label="SKU" class="px-4 py-3 font-mono text-xs">${esc(p.sku)}</td><td data-label="Name" class="px-4 py-3">${esc(p.name)}</td><td data-label="Category" class="px-4 py-3">${esc(p.category)}</td>
      <td data-label="Buy" class="px-4 py-3 text-right">${fmt(p.buying_price)}</td><td data-label="Cash" class="px-4 py-3 text-right text-emerald-600">${fmt(p.cash_price)}</td><td data-label="Pay Later" class="px-4 py-3 text-right text-blue-600">${fmt(p.credit_price)}</td>
      <td data-label="Qty" class="px-4 py-3 text-right">${p.quantity} ${esc(p.unit)}</td><td data-label="Status" class="px-4 py-3">${badge(p.stock_status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editProductModal(${p.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        <button onclick="restockModal(${p.id},'${esc(p.name)}')" class="text-slate-500 hover:underline text-xs mr-2">Restock</button>
        <button onclick="deleteProduct(${p.id},'${esc(p.name)}')" class="text-red-600 hover:underline text-xs">Delete</button>
      </td></tr>`).join('')}</tbody>
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
// Shared markup/terms block used by Add & Edit. `x` is the id prefix.
function pricingRuleBlock(x, vals) {
  vals = vals || {}
  const elig = vals.payment_eligibility || 'both'
  return `
    <div class="field-group col-span-2"><label class="field-label">Payment Viability Rule</label>
      <select id="${x}_elig" onchange="togglePricing('${x}')" class="w-full px-3 py-2 border rounded-lg">
        <option value="cash" ${elig==='cash'?'selected':''}>Cash Only</option>
        <option value="finance" ${elig==='finance'?'selected':''}>Finance Only</option>
        <option value="both" ${elig==='both'?'selected':''}>Both (Cash & Finance)</option>
      </select></div>
    <div class="field-group ${x}-cash"><label class="field-label">Cash Markup %</label>
      <input id="${x}_cm" type="number" step="0.1" value="${vals.cash_markup_pct ?? 10}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group ${x}-cash"><label class="field-label">Cash Deposit Required %</label>
      <input id="${x}_cd" type="number" step="0.1" value="${vals.cash_deposit_pct ?? 100}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group ${x}-fin"><label class="field-label">Finance Markup %</label>
      <input id="${x}_fm" type="number" step="0.1" value="${vals.finance_markup_pct ?? vals.credit_markup_pct ?? 20}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group ${x}-fin"><label class="field-label">Finance Deposit Required %</label>
      <input id="${x}_fd" type="number" step="0.1" value="${vals.finance_deposit_pct ?? 20}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group col-span-2 ${x}-cash"><label class="field-label">Cash Sale Terms &amp; Conditions</label>
      <textarea id="${x}_ct" rows="3" placeholder="Paste or type the cash sale terms…" class="w-full px-3 py-2 border rounded-lg">${esc(vals.cash_terms || '')}</textarea>
      <label class="text-xs text-teal-600 cursor-pointer mt-1 inline-block"><i class="fas fa-upload mr-1"></i>Upload / scan document<input type="file" accept=".txt,.md,image/*,application/pdf" class="hidden" onchange="termsFromFile(this,'${x}_ct')"></label></div>
    <div class="field-group col-span-2 ${x}-fin"><label class="field-label">Financing Terms &amp; Conditions</label>
      <textarea id="${x}_ft" rows="3" placeholder="Paste or type the financing terms…" class="w-full px-3 py-2 border rounded-lg">${esc(vals.finance_terms || '')}</textarea>
      <label class="text-xs text-teal-600 cursor-pointer mt-1 inline-block"><i class="fas fa-upload mr-1"></i>Upload / scan document<input type="file" accept=".txt,.md,image/*,application/pdf" class="hidden" onchange="termsFromFile(this,'${x}_ft')"></label></div>`
}
window.togglePricing = (x) => {
  const elig = $(`${x}_elig`).value
  const showCash = elig === 'cash' || elig === 'both'
  const showFin = elig === 'finance' || elig === 'both'
  document.querySelectorAll('.' + x + '-cash').forEach(el => el.classList.toggle('hidden', !showCash))
  document.querySelectorAll('.' + x + '-fin').forEach(el => el.classList.toggle('hidden', !showFin))
}
// Terms can be copy-pasted, uploaded, or scanned. Text files load directly;
// images/PDFs store a reference note (the document is attached by filename).
window.termsFromFile = (input, targetId) => {
  const f = input.files[0]; if (!f) return
  if (f.type.startsWith('text/') || /\.(txt|md)$/i.test(f.name)) {
    const r = new FileReader(); r.onload = (e) => { $(targetId).value = e.target.result }; r.readAsText(f)
  } else {
    const cur = $(targetId).value
    $(targetId).value = (cur ? cur + '\n\n' : '') + '[Attached terms document: ' + f.name + ']'
    toast('Document attached to terms')
  }
}
function collectPricing(x) {
  const elig = $(`${x}_elig`).value
  return {
    payment_eligibility: elig,
    cash_markup_pct: Number($(`${x}_cm`).value || 0),
    finance_markup_pct: Number($(`${x}_fm`).value || 0),
    finance_deposit_pct: Number($(`${x}_fd`).value || 0),
    cash_terms: $(`${x}_ct`).value || null,
    finance_terms: $(`${x}_ft`).value || null
  }
}
window.addProductModal = () => {
  showModal(`<h3 class="font-bold mb-3">Add Product</h3>
    <div class="flex items-center gap-3 mb-3">
      <div id="np_preview" class="w-16 h-16 rounded-lg bg-slate-100 flex items-center justify-center text-slate-400"><i class="fas fa-image"></i></div>
      <label class="btn bg-slate-100 px-3 py-2 rounded-lg text-xs cursor-pointer"><i class="fas fa-upload mr-1"></i>Upload Image<input type="file" accept="image/*" class="hidden" onchange="pickImage(this,'np_img','np_preview')"></label>
    </div>
    <input type="hidden" id="np_img" value="">
    <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
      <div class="field-group col-span-2"><label class="field-label">SKU</label><input id="np_sku" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group col-span-2"><label class="field-label">Product Name</label><input id="np_name" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Category</label><input id="np_cat" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Unit (bag/unit)</label><input id="np_unit" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Buying Price (KES)</label><input id="np_buy" type="number" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Quantity</label><input id="np_qty" type="number" class="w-full px-3 py-2 border rounded-lg"></div>
      ${pricingRuleBlock('np', {})}
    </div>
    <div class="flex gap-2 mt-4"><button onclick="doAddProduct()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  togglePricing('np')
}
window.doAddProduct = async () => {
  try {
    await api.post('/products', { sku: $('np_sku').value, name: $('np_name').value, category: $('np_cat').value, unit: $('np_unit').value, buying_price: Number($('np_buy').value), quantity: Number($('np_qty').value), image: $('np_img').value || null, ...collectPricing('np') })
    closeModal(); toast('Product added'); viewInventory()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.editProductModal = (id) => {
  const p = _products.find(x => x.id === id)
  showModal(`<h3 class="font-bold mb-3">Edit Product</h3>
  <div class="flex items-center gap-3 mb-3">
    <div id="ep_preview">${prodImg(p, 'w-16 h-16 rounded-lg')}</div>
    <label class="btn bg-slate-100 px-3 py-2 rounded-lg text-xs cursor-pointer"><i class="fas fa-image mr-1"></i>Change Image<input type="file" accept="image/*" class="hidden" onchange="pickImage(this,'ep_img','ep_preview')"></label>
  </div>
  <input type="hidden" id="ep_img" value="${esc(p.image || '')}">
  <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
    <div class="field-group col-span-2"><label class="field-label">SKU</label><input id="ep_sku" value="${esc(p.sku)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group col-span-2"><label class="field-label">Product Name</label><input id="ep_name" value="${esc(p.name)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Category</label><input id="ep_cat" value="${esc(p.category)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Unit</label><input id="ep_unit" value="${esc(p.unit)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Buying Price (KES)</label><input id="ep_buy" type="number" value="${p.buying_price}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Quantity</label><input id="ep_qty" type="number" value="${p.quantity}" class="w-full px-3 py-2 border rounded-lg"></div>
    ${pricingRuleBlock('ep', p)}
    <div class="field-group col-span-2"><label class="field-label">Reorder Threshold</label><input id="ep_rt" type="number" value="${p.reorder_threshold}" class="w-full px-3 py-2 border rounded-lg"></div>
  </div><div class="flex gap-2 mt-4"><button onclick="doEditProduct(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
  togglePricing('ep')
}
window.doEditProduct = async (id) => {
  try {
    await api.put('/products/' + id, { sku: $('ep_sku').value, name: $('ep_name').value, category: $('ep_cat').value, unit: $('ep_unit').value, buying_price: Number($('ep_buy').value), quantity: Number($('ep_qty').value), reorder_threshold: Number($('ep_rt').value), image: $('ep_img').value || null, ...collectPricing('ep') })
    closeModal(); toast('Product updated'); viewInventory()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteProduct = async (id, name) => {
  if (!confirm('Delete product "' + name + '"? This cannot be undone.')) return
  try { await api.delete('/products/' + id); toast('Product deleted'); viewInventory() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.restockModal = (id, name) => {
  showModal(`<h3 class="font-bold mb-3">Restock: ${name}</h3>
    <label class="text-sm">Quantity to add</label><input id="rq" type="number" value="10" class="w-full mt-1 mb-4 px-3 py-2 border border-slate-300 rounded-lg">
    <div class="flex gap-2"><button onclick="doRestock(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Add Stock</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doRestock = async (id) => {
  await api.put(`/products/${id}/stock`, { quantity: Number($('rq').value), movement_type: 'purchase' })
  closeModal(); toast('Stock updated'); viewInventory()
}

// ---------------------------------------------------------------------------
// CUSTOMERS + Complete Registration (TransUnion + Liveness)
// ---------------------------------------------------------------------------
async function viewCustomers() {
  const { data } = await api.get('/customers')
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">ID</th><th class="text-left px-4 py-3">Mobile</th><th class="text-left px-4 py-3">County</th><th class="text-left px-4 py-3">Value Chain</th><th class="text-left px-4 py-3">KYC</th><th class="text-left px-4 py-3">Risk</th><th></th></tr></thead>
    <tbody>${data.customers.map(c => `<tr class="border-t border-slate-100">
      <td data-label="Name" class="px-4 py-3 font-medium">${esc(c.full_name)}</td><td data-label="ID" class="px-4 py-3">${esc(c.national_id || '—')}</td><td data-label="Mobile" class="px-4 py-3">${esc(c.mobile || '—')}</td>
      <td data-label="County" class="px-4 py-3">${esc(c.county || '—')}</td><td data-label="Value Chain" class="px-4 py-3">${esc(c.value_chain || '—')}</td><td data-label="KYC" class="px-4 py-3">${badge(c.kyc_status)}</td>
      <td data-label="Risk" class="px-4 py-3">${c.risk_band ? badge(c.risk_band) : '—'}</td>
      <td class="px-4 py-3 whitespace-nowrap">
        <button onclick="custDetail(${c.id})" class="text-slate-500 hover:underline text-xs mr-3">View</button>
        ${c.kyc_status !== 'verified' ? `<button onclick="completeRegistration(${c.id})" class="text-teal-600 hover:underline text-xs"><i class="fas fa-id-card mr-1"></i>Complete Registration</button>` : '<span class="text-emerald-600 text-xs"><i class="fas fa-circle-check mr-1"></i>Verified</span>'}
      </td></tr>`).join('') || '<tr><td colspan="8" class="text-center py-8 text-slate-400">No customers</td></tr>'}</tbody>
  </table></div>`
}
window.custDetail = async (id) => {
  const { data } = await api.get('/customers/' + id)
  const c = data.customer, tu = data.transunion, idv = data.id_verification
  showModal(`
    <h3 class="text-lg font-bold mb-1">${esc(c.full_name)}</h3>
    <p class="text-xs text-slate-500 mb-4">ID ${esc(c.national_id || '—')} · ${esc(c.mobile || '—')} · ${esc(c.county || '')}</p>
    <div class="grid grid-cols-2 gap-3 text-sm mb-4">
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Value Chain</p><b>${esc(c.value_chain_type || '—')} / ${esc(c.value_chain || '—')}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">KYC Status</p>${badge(c.kyc_status)}</div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">GPS</p><b>${c.latitude ? c.latitude + ', ' + c.longitude : '—'}</b></div>
      <div class="bg-slate-50 p-3 rounded-lg"><p class="text-xs text-slate-500">Risk Band</p>${c.risk_band ? badge(c.risk_band) : '—'}</div>
    </div>
    <div class="border rounded-xl p-4 mb-4 ${tu ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200'}">
      <h4 class="font-semibold text-sm mb-2"><i class="fas fa-chart-line mr-1 text-teal-600"></i>TransUnion Credit Check</h4>
      ${tu ? `<div class="text-sm flex gap-6"><span>Score: <b>${tu.credit_score}</b></span><span>Band: ${badge(tu.risk_band)}</span><span>Defaults: <b>${tu.defaults_found}</b></span></div>` : '<p class="text-xs text-slate-400">Not yet run.</p>'}
    </div>
    <div class="border rounded-xl p-4 mb-4 ${idv ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200'}">
      <h4 class="font-semibold text-sm mb-2"><i class="fas fa-id-card mr-1 text-teal-600"></i>Liveness & ID Verification</h4>
      ${idv ? `<div class="text-sm flex gap-6"><span>Face match: <b>${idv.face_match ? '✓' : '✗'}</b></span><span>Liveness: <b>${idv.liveness ? '✓' : '✗'}</b></span><span>Status: ${badge(idv.status)}</span></div>` : '<p class="text-xs text-slate-400">Not yet run.</p>'}
    </div>
    ${c.kyc_status !== 'verified' ? `<button onclick="completeRegistration(${c.id})" class="btn w-full brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-shield-halved mr-1"></i>Complete User Registration</button>` : ''}
    <button onclick="closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Close</button>`)
}
// ---------------------------------------------------------------------------
// SEQUENTIAL CAMERA KYC FUNNEL
// Step 1: ID Card Front  — rear camera (environment)
// Step 2: ID Card Back   — rear camera, unlocked only after step 1
// Step 3: Passport Selfie — front camera (user), locked portrait
// Then runs the verification engine (TransUnion + liveness).
// ---------------------------------------------------------------------------
let _liveStream = null
let _kyc = { id: null, returnToShop: false, step: 1, images: { id_front_url: null, id_back_url: null, passport_selfie_url: null } }

const KYC_STEPS = [
  { key: 'id_front_url', title: 'ID Card — Front', icon: 'fa-id-card', facing: 'environment', shape: 'rect',
    hint: 'Point the rear camera at the FRONT of your ID and capture the document.' },
  { key: 'id_back_url', title: 'ID Card — Back', icon: 'fa-id-card-clip', facing: 'environment', shape: 'rect',
    hint: 'Now capture the BACK of the same ID document with the rear camera.' },
  { key: 'passport_selfie_url', title: 'Passport Selfie', icon: 'fa-user', facing: 'user', shape: 'circle',
    hint: 'Switch to the front camera and take a live portrait selfie (liveness check).' }
]

window.completeRegistration = async (id, returnToShop) => {
  _kyc = { id, returnToShop: !!returnToShop, step: 1, images: { id_front_url: null, id_back_url: null, passport_selfie_url: null } }
  renderKycStep()
}
function kycStepHeader() {
  return `<div class="flex items-center justify-center gap-2 mb-4">
    ${KYC_STEPS.map((s, i) => {
      const n = i + 1
      const cls = _kyc.step > n ? 'step-done' : _kyc.step === n ? 'step-active' : 'step-todo'
      return `<div class="flex items-center gap-2">
        <div class="step-dot ${cls}">${_kyc.step > n ? '<i class="fas fa-check"></i>' : n}</div>
        ${i < KYC_STEPS.length - 1 ? '<div class="w-6 h-px bg-slate-300"></div>' : ''}
      </div>`
    }).join('')}
  </div>`
}
function renderKycStep() {
  const idx = _kyc.step - 1
  const s = KYC_STEPS[idx]
  const frameCls = s.shape === 'circle'
    ? 'cam-frame w-44 h-44 mx-auto rounded-full mb-3'
    : 'cam-frame w-full h-52 rounded-xl mb-3'
  showModal(`<div class="text-center">
    <h3 class="text-lg font-bold mb-1"><i class="fas ${s.icon} text-teal-600 mr-2"></i>Step ${_kyc.step} of 3 — ${esc(s.title)}</h3>
    ${kycStepHeader()}
    <p class="text-xs text-slate-500 mb-3">${esc(s.hint)}</p>
    <div class="${frameCls}">
      <video id="kycVideo" autoplay playsinline muted></video>
      <div id="kycShot" class="hidden absolute inset-0"></div>
      ${s.shape === 'circle' ? '<div class="absolute inset-0 border-4 border-teal-400 rounded-full animate-pulse pointer-events-none"></div>' : ''}
    </div>
    <div id="kycStatus" class="text-xs text-slate-500 mb-3">Initialising camera…</div>
    <input type="file" id="kycFile" accept="image/*" capture="${s.facing === 'user' ? 'user' : 'environment'}" class="hidden" onchange="kycFromFile(this)">
    <div class="flex gap-2">
      <button id="kycCaptureBtn" onclick="kycCapture()" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-circle-dot mr-1"></i>Capture</button>
    </div>
    <button onclick="kycStopCam();closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Cancel</button>
    <p class="text-[11px] text-slate-400 mt-2"><i class="fas fa-lock mr-1"></i>Steps unlock in order to ensure verification relevance.</p>
  </div>`)
  kycStartCam(s.facing)
}
async function kycStartCam(facing) {
  kycStopCam()
  const st = $('kycStatus')
  try {
    // Prefer the requested lens; lock orientation to the relevant camera.
    _liveStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: facing } }, audio: false })
    const v = $('kycVideo'); if (v) { v.srcObject = _liveStream; v.classList.remove('hidden') }
    if (st) st.innerHTML = facing === 'environment'
      ? 'Rear camera ready — frame the document and capture.'
      : 'Front camera ready — center your face and capture.'
  } catch (e) {
    // No camera / permission denied → offer the native file/camera picker so
    // the flow still works on every device. This also bypasses the file
    // directory by defaulting to the device camera via the capture attribute.
    if (st) st.innerHTML = '<span class="text-amber-600">Camera unavailable — tap "Use Device Camera" below.</span>'
    const btn = $('kycCaptureBtn')
    if (btn) { btn.innerHTML = '<i class="fas fa-camera mr-1"></i>Use Device Camera'; btn.setAttribute('onclick', "$('kycFile').click()") }
  }
}
function kycStopCam() { if (_liveStream) { _liveStream.getTracks().forEach(t => t.stop()); _liveStream = null } }
window.kycStopCam = kycStopCam
window.stopLive = kycStopCam   // keep closeModal()'s stopLive() working

function kycShrink(dataUrl, cb) {
  const img = new Image()
  img.onload = () => {
    const max = 900, scale = Math.min(1, max / Math.max(img.width, img.height))
    const cv = document.createElement('canvas')
    cv.width = img.width * scale; cv.height = img.height * scale
    cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height)
    cb(cv.toDataURL('image/jpeg', 0.8))
  }
  img.src = dataUrl
}
window.kycCapture = () => {
  const v = $('kycVideo')
  if (!_liveStream || !v || !v.videoWidth) { $('kycFile').click(); return }
  const cv = document.createElement('canvas')
  cv.width = v.videoWidth; cv.height = v.videoHeight
  cv.getContext('2d').drawImage(v, 0, 0)
  kycSaveShot(cv.toDataURL('image/jpeg', 0.8))
}
window.kycFromFile = (input) => {
  const f = input.files[0]; if (!f) return
  const r = new FileReader()
  r.onload = (e) => kycShrink(e.target.result, kycSaveShot)
  r.readAsDataURL(f)
}
function kycSaveShot(dataUrl) {
  const s = KYC_STEPS[_kyc.step - 1]
  _kyc.images[s.key] = dataUrl
  kycStopCam()
  if (_kyc.step < KYC_STEPS.length) {
    _kyc.step++
    renderKycStep()   // next step unlocks only now
  } else {
    kycFinish()
  }
}
async function kycFinish() {
  showModal(`<div class="text-center">
    <h3 class="text-lg font-bold mb-1"><i class="fas fa-shield-halved text-teal-600 mr-2"></i>Verifying</h3>
    ${kycStepHeader()}
    <div class="grid grid-cols-3 gap-2 my-3">
      ${KYC_STEPS.map(s => `<div><img src="${_kyc.images[s.key]}" class="w-full h-16 object-cover rounded-lg border border-slate-200"><p class="text-[10px] text-slate-400 mt-1">${esc(s.title)}</p></div>`).join('')}
    </div>
    <div id="kycStatus" class="text-xs text-slate-500 mb-2"><i class="fas fa-spinner fa-spin mr-1"></i>Uploading images & running TransUnion + liveness…</div>
  </div>`)
  try {
    await api.post(`/customers/${_kyc.id}/kyc-images`, _kyc.images)
    const { data } = await api.post(`/customers/${_kyc.id}/verify`)
    $('kycStatus').innerHTML = `<span class="text-emerald-600">Verified ✓ Credit score ${data.credit_score} · ${data.risk_band} risk</span>`
    setTimeout(() => {
      closeModal(); toast(`Registration complete · Score ${data.credit_score} · ${data.risk_band} risk`)
      if (_kyc.returnToShop) { state.route = 'shop'; renderApp() }
      else if (state.route === 'customers') viewCustomers()
      else if (state.route === 'profile') viewProfile()
    }, 1100)
  } catch (err) {
    if ($('kycStatus')) $('kycStatus').innerHTML = `<span class="text-red-600">${esc(err.response?.data?.error || 'Verification failed')}</span>`
  }
}

// ---------------------------------------------------------------------------
// ONBOARD (agent)
// ---------------------------------------------------------------------------
function viewOnboard() {
  $('content').innerHTML = `<div class="card p-4 sm:p-6 max-w-3xl"><form id="onbForm" class="space-y-5">
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-user mr-2"></i>Personal Information</h3>
      <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
        <div class="field-group col-span-2"><label class="field-label">Full Name *</label><input name="full_name" required class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">National ID *</label><input name="national_id" required class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Date of Birth</label><input name="date_of_birth" type="date" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Gender</label><select name="gender" class="w-full px-3 py-2 border rounded-lg"><option value="">Select…</option><option>Female</option><option>Male</option></select></div>
        <div class="field-group"><label class="field-label">Mobile *</label><input name="mobile" required class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Alternative Number</label><input name="alt_mobile" class="w-full px-3 py-2 border rounded-lg"></div>
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-map-marker-alt mr-2"></i>Location</h3>
      <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
        <div class="field-group"><label class="field-label">County</label><input name="county" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Sub-county</label><input name="sub_county" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Ward</label><input name="ward" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Village</label><input name="village" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Latitude</label><input name="latitude" id="lat" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Longitude</label><input name="longitude" id="lng" class="w-full px-3 py-2 border rounded-lg"></div>
      </div>
      <button type="button" onclick="captureGPS()" class="btn mt-1 text-xs bg-slate-100 px-3 py-1.5 rounded-lg"><i class="fas fa-location-crosshairs mr-1"></i>Auto-capture GPS</button></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-leaf mr-2"></i>Farming Profile</h3>
      <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
        <div class="field-group"><label class="field-label">Farmer Type</label>
          <select name="farming_profile" id="vct" onchange="onbToggleFarm()" class="w-full px-3 py-2 border rounded-lg"><option value="">Select…</option><option value="crop">Crop Farmer</option><option value="livestock">Livestock Farmer</option></select></div>
        <div class="field-group"><label class="field-label">Value Chain</label>
          <select name="value_chain" id="vc" class="w-full px-3 py-2 border rounded-lg"><option value="">Select type first</option></select></div>
        <div class="field-group"><label class="field-label">Acreage</label>
          <input name="acreage" type="number" step="0.1" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group hidden" id="cropField"><label class="field-label">Average Yield (tonnage)</label>
          <input name="output_tonnage" type="number" step="0.1" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group hidden" id="livestockField"><label class="field-label">Herd Size (animals)</label>
          <input name="herd_count" type="number" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Years of Experience</label>
          <input name="farm_experience" type="number" class="w-full px-3 py-2 border rounded-lg"></div>
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-wallet mr-2"></i>Financial Profile</h3>
      <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
        <div class="field-group"><label class="field-label">Current Loan Amount (KES)</label>
          <input name="current_loan_amount" type="number" step="0.01" min="0" value="0" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">SACCO Membership Status</label>
          <select name="sacco_member" class="w-full px-3 py-2 border rounded-lg"><option value="No">No</option><option value="Yes">Yes</option></select></div>
      </div></div>
    <div class="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-700"><i class="fas fa-info-circle mr-1"></i>ID front/back & passport selfie capture happen during "Complete User Registration" (sequential camera KYC + TransUnion + Liveness) — run it from the Customers page after onboarding.</div>
    <button class="btn brand-bg text-white px-6 py-2.5 rounded-lg text-sm w-full sm:w-auto"><i class="fas fa-paper-plane mr-1"></i>Submit Onboarding</button>
  </form></div>`
  $('onbForm').onsubmit = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target); const body = Object.fromEntries(fd.entries())
    try { await api.post('/customers', body); toast('Customer onboarded successfully'); state.route = 'customers'; renderApp() }
    catch (err) { toast(err.response?.data?.error || 'Failed', false) }
  }
}
// Conditional agricultural inputs: show only the metric relevant to the
// selected farmer type, and populate the value-chain dropdown accordingly.
window.onbToggleFarm = () => {
  const t = $('vct').value
  $('cropField').classList.toggle('hidden', t !== 'crop')
  $('livestockField').classList.toggle('hidden', t !== 'livestock')
  updateChain()
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
// SELF-SERVICE PROFILE / SETTINGS  (any authenticated user, own data only)
// Administrative attributes (permissions, credit approvals, custom user
// groupings, role) are deliberately omitted to prevent privilege escalation.
// ---------------------------------------------------------------------------
let _profile = null
async function viewProfile() {
  $('content').innerHTML = '<div class="text-slate-400">Loading…</div>'
  const { data } = await api.get('/profile')
  _profile = data
  const p = data.profile
  const cust = data.customer
  const ft = p.farming_profile || ''
  const sacco = (p.sacco_member === 1 || p.sacco_member === true) ? 'Yes' : 'No'
  const kyc = cust ? cust.kyc_status : null
  $('content').innerHTML = `
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 max-w-5xl">
    <div class="card p-4 sm:p-6 lg:col-span-2">
      <h3 class="font-bold text-teal-700 mb-4"><i class="fas fa-user mr-2"></i>Personal Information</h3>
      <form id="profForm" class="grid grid-cols-2 sm-collapse gap-3 text-sm">
        <div class="field-group col-span-2"><label class="field-label">Full Name</label><input name="full_name" value="${esc(p.full_name||'')}" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">Mobile Number</label><input value="${esc(p.phone||'')}" disabled class="w-full px-3 py-2 border rounded-lg bg-slate-50 text-slate-500"></div>
        <div class="field-group"><label class="field-label">Email</label><input name="email" value="${esc(p.email||'')}" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group col-span-2"><label class="field-label">Region</label><input name="region" value="${esc(p.region||'')}" class="w-full px-3 py-2 border rounded-lg"></div>

        <div class="col-span-2 mt-1"><h4 class="font-bold text-teal-700 mb-1"><i class="fas fa-leaf mr-2"></i>Farming Data</h4></div>
        <div class="field-group"><label class="field-label">Farmer Type</label>
          <select name="farming_profile" id="pf_type" onchange="profToggleFarm()" class="w-full px-3 py-2 border rounded-lg">
            <option value="">Select…</option>
            <option value="crop" ${ft==='crop'?'selected':''}>Crop Farmer</option>
            <option value="livestock" ${ft==='livestock'?'selected':''}>Livestock Farmer</option>
          </select></div>
        <div class="field-group ${ft==='crop'?'':'hidden'}" id="pf_crop"><label class="field-label">Average Yield (tonnage)</label>
          <input name="output_tonnage" type="number" step="0.1" value="${p.output_tonnage??''}" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group ${ft==='livestock'?'':'hidden'}" id="pf_livestock"><label class="field-label">Herd Size (animals)</label>
          <input name="herd_count" type="number" value="${p.herd_count??''}" class="w-full px-3 py-2 border rounded-lg"></div>

        <div class="col-span-2 mt-1"><h4 class="font-bold text-teal-700 mb-1"><i class="fas fa-wallet mr-2"></i>Financial Profile</h4></div>
        <div class="field-group"><label class="field-label">Current Loan Amount (KES)</label>
          <input name="current_loan_amount" type="number" step="0.01" min="0" value="${p.current_loan_amount??0}" class="w-full px-3 py-2 border rounded-lg"></div>
        <div class="field-group"><label class="field-label">SACCO Membership Status</label>
          <select name="sacco_member" class="w-full px-3 py-2 border rounded-lg"><option ${sacco==='No'?'selected':''}>No</option><option ${sacco==='Yes'?'selected':''}>Yes</option></select></div>

        <div class="col-span-2 mt-2"><button type="submit" class="btn brand-bg text-white px-6 py-2.5 rounded-lg text-sm w-full sm:w-auto"><i class="fas fa-floppy-disk mr-1"></i>Save Changes</button></div>
      </form>
    </div>
    <div class="space-y-6">
      <div class="card p-4 sm:p-6">
        <h3 class="font-bold text-teal-700 mb-3"><i class="fas fa-id-card mr-2"></i>Identity Documents</h3>
        <div class="grid grid-cols-3 gap-2 mb-3">
          ${[['ID Front','id_front_url'],['ID Back','id_back_url'],['Selfie','passport_selfie_url']].map(([lbl,k]) =>
            `<div><div class="w-full h-16 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center overflow-hidden">${p[k]?`<img src="${esc(p[k])}" class="w-full h-full object-cover">`:'<i class="fas fa-image text-slate-300"></i>'}</div><p class="text-[10px] text-slate-400 mt-1 text-center">${lbl}</p></div>`).join('')}
        </div>
        ${cust ? (kyc === 'verified'
          ? '<p class="text-xs text-emerald-600"><i class="fas fa-circle-check mr-1"></i>Verified</p>'
          : `<button onclick="completeRegistration(${cust.id})" class="btn w-full brand-bg text-white py-2 rounded-lg text-sm"><i class="fas fa-camera mr-1"></i>Complete KYC (Camera)</button>`)
          : '<p class="text-xs text-slate-400">No KYC profile linked.</p>'}
      </div>
      <div class="card p-4 sm:p-6">
        <h3 class="font-bold text-teal-700 mb-3"><i class="fas fa-key mr-2"></i>Change Password</h3>
        <form id="pwForm" class="space-y-2 text-sm">
          <div class="field-group"><label class="field-label">Current Password</label><input id="pw_cur" type="password" class="w-full px-3 py-2 border rounded-lg"></div>
          <div class="field-group"><label class="field-label">New Password</label><input id="pw_new" type="password" class="w-full px-3 py-2 border rounded-lg"></div>
          <button type="submit" class="btn w-full bg-slate-800 text-white py-2 rounded-lg text-sm">Update Password</button>
        </form>
      </div>
    </div>
  </div>`
  $('profForm').onsubmit = async (e) => {
    e.preventDefault()
    const body = Object.fromEntries(new FormData(e.target).entries())
    try { await api.put('/profile', body); toast('Profile updated'); if (body.full_name) { state.user.full_name = body.full_name } }
    catch (err) { toast(err.response?.data?.error || 'Failed', false) }
  }
  $('pwForm').onsubmit = async (e) => {
    e.preventDefault()
    try { await api.put('/profile/password', { current_password: $('pw_cur').value, new_password: $('pw_new').value }); toast('Password changed'); $('pw_cur').value=''; $('pw_new').value='' }
    catch (err) { toast(err.response?.data?.error || 'Failed', false) }
  }
}
window.profToggleFarm = () => {
  const t = $('pf_type').value
  $('pf_crop').classList.toggle('hidden', t !== 'crop')
  $('pf_livestock').classList.toggle('hidden', t !== 'livestock')
}

// ---------------------------------------------------------------------------
// AGENTS (admin CRUD)
// ---------------------------------------------------------------------------
async function viewAgents() {
  const { data } = await api.get('/agents')
  _agents = data.agents
  $('content').innerHTML = `<div class="flex justify-end mb-4"><button onclick="addAgentModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Create Agent</button></div>
  <div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Region</th><th class="text-right px-4 py-3">Customers</th><th class="text-right px-4 py-3">Active</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.agents.map(a => `<tr class="border-t border-slate-100"><td data-label="Name" class="px-4 py-3 font-medium">${esc(a.full_name)}</td><td data-label="Phone" class="px-4 py-3">${esc(a.phone)}</td><td data-label="Region" class="px-4 py-3">${esc(a.region || '—')}</td><td data-label="Customers" class="px-4 py-3 text-right">${a.customers}</td><td data-label="Active" class="px-4 py-3 text-right">${a.active}</td><td data-label="Status" class="px-4 py-3">${badge(a.status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editAgentModal(${a.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        <button onclick="resetUserPassword(${a.id},'${esc(a.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
        ${a.status === 'active' ? `<button onclick="setUserStatus(${a.id},'suspended','agents')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${a.id},'active','agents')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
        <button onclick="deleteUser(${a.id},'${esc(a.full_name)}','agents')" class="text-red-600 hover:underline text-xs">Delete</button>
      </td></tr>`).join('') || '<tr><td colspan="7" class="text-center py-8 text-slate-400">No agents</td></tr>'}</tbody>
  </table></div>`
}
// ---------------------------------------------------------------------------
// GRANULAR PERMISSION MATRIX (Super Admin authorization grid)
// ---------------------------------------------------------------------------
const PERM_MATRIX = [
  { section: 'User Registries', items: [
    ['add_users', 'Add Users'], ['add_farmers', 'Add Farmers'],
    ['add_agents', 'Add Agents'], ['add_lenders', 'Add Lenders'] ] },
  { section: 'Data Correction', items: [
    ['edit_records', 'Edit Records'], ['delete_records', 'Delete Records'] ] },
  { section: 'Ledger Inspections', items: [
    ['view_cash_sales', 'View Cash Sales'], ['view_financed_sales', 'View Financed Sales'] ] },
  { section: 'Credit & Logistics', items: [
    ['approve_loan', 'Approve a Loan'], ['dispatch_feeds', 'Dispatch Feeds'] ] },
  { section: 'Operational Tracking', items: [
    ['track_deliveries', 'Track Deliveries'], ['track_payments', 'Track Payments'], ['add_inventory', 'Add Inventory'] ] }
]
function permGridHtml(prefix, selected) {
  selected = selected || []
  return PERM_MATRIX.map(sec => `
    <div class="perm-section">
      <h5>${esc(sec.section)}</h5>
      <div class="perm-grid">
        ${sec.items.map(([k, lbl]) => `<label class="perm-item"><input type="checkbox" id="${prefix}_${k}" value="${k}" ${selected.includes(k) ? 'checked' : ''}> ${esc(lbl)}</label>`).join('')}
      </div>
    </div>`).join('')
}
function collectPerms(prefix) {
  const out = []
  PERM_MATRIX.forEach(sec => sec.items.forEach(([k]) => { const el = $(`${prefix}_${k}`); if (el && el.checked) out.push(k) }))
  return out
}

window.addAgentModal = () => {
  showModal(`<h3 class="font-bold mb-1">Onboard New Agent</h3>
    <p class="text-xs text-slate-500 mb-3">Create the agent's login. Set a password now, or leave blank to auto-generate one.</p>
    <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
      <div class="field-group col-span-2"><label class="field-label">Full Name</label><input id="ag_name" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Phone</label><input id="ag_phone" placeholder="07XX XXX XXX" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Email (optional)</label><input id="ag_email" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Region</label><input id="ag_region" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Password (blank = auto)</label><input id="ag_pwd" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group col-span-2"><label class="field-label">Custom User Type</label><input id="ag_custom" placeholder="e.g. Regional Lead, Field Representative" class="w-full px-3 py-2 border rounded-lg"></div>
    </div>
    <h4 class="font-bold text-sm text-teal-700 mt-3 mb-2">Permissions</h4>
    ${permGridHtml('ag', [])}
    <div class="flex gap-2 mt-4"><button onclick="doAddAgent()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Create Agent</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAddAgent = async () => {
  try {
    const body = { full_name: $('ag_name').value, phone: $('ag_phone').value, email: $('ag_email').value, region: $('ag_region').value, custom_role: $('ag_custom').value || null, permissions: collectPerms('ag') }
    if ($('ag_pwd').value) body.password = $('ag_pwd').value
    const { data } = await api.post('/agents', body)
    closeModal()
    showCredential('Agent Created', body.full_name, body.phone || '', data.password, data.password_was_set_by_admin)
    viewAgents()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
// Generic "Add User" with role selector + permission grid + custom type.
window.addUserModal = () => {
  showModal(`<h3 class="font-bold mb-1">Add System User</h3>
    <p class="text-xs text-slate-500 mb-3">Create an operator, field agent, farmer or lender with explicit access rights.</p>
    <div class="grid grid-cols-2 sm-collapse gap-3 text-sm">
      <div class="field-group col-span-2"><label class="field-label">Full Name</label><input id="nu_name" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Phone</label><input id="nu_phone" placeholder="07XX XXX XXX" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Email (optional)</label><input id="nu_email" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Base Role</label>
        <select id="nu_role" class="w-full px-3 py-2 border rounded-lg">
          <option value="agent">Agent</option><option value="admin">Admin</option>
          <option value="customer">Farmer / Customer</option><option value="lender">Lender</option><option value="support">Support</option>
        </select></div>
      <div class="field-group"><label class="field-label">Region</label><input id="nu_region" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group"><label class="field-label">Password (blank = auto)</label><input id="nu_pwd" class="w-full px-3 py-2 border rounded-lg"></div>
      <div class="field-group col-span-2"><label class="field-label">Custom User Type</label><input id="nu_custom" placeholder="e.g. Junior Auditor, Regional Lead" class="w-full px-3 py-2 border rounded-lg"></div>
    </div>
    <h4 class="font-bold text-sm text-teal-700 mt-3 mb-2">Permissions</h4>
    ${permGridHtml('nu', [])}
    <div class="flex gap-2 mt-4"><button onclick="doAddUser()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Create User</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAddUser = async () => {
  try {
    const body = { full_name: $('nu_name').value, phone: $('nu_phone').value, email: $('nu_email').value, role: $('nu_role').value, region: $('nu_region').value, custom_role: $('nu_custom').value || null, permissions: collectPerms('nu') }
    if ($('nu_pwd').value) body.password = $('nu_pwd').value
    const { data } = await api.post('/users', body)
    closeModal()
    showCredential('User Created', body.full_name, body.phone || '', data.password, data.password_was_set_by_admin)
    viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
// Super Admin: move a user under a supervisor.
window.supervisorModal = async (id, name) => {
  if (!_users.length) { const { data } = await api.get('/users'); _users = data.users }
  const candidates = _users.filter(u => u.id !== id)
  const cur = _users.find(u => u.id === id)
  showModal(`<h3 class="font-bold mb-1">Assign Supervisor</h3>
    <p class="text-xs text-slate-500 mb-3">Move <b>${esc(name)}</b> to be supervised by another user.</p>
    <div class="field-group"><label class="field-label">Supervisor</label>
      <select id="sup_sel" class="w-full px-3 py-2 border rounded-lg">
        <option value="">— None —</option>
        ${candidates.map(u => `<option value="${u.id}" ${cur && cur.supervisor_id === u.id ? 'selected' : ''}>${esc(u.full_name)} (${esc(u.custom_role || u.role)})</option>`).join('')}
      </select></div>
    <div class="flex gap-2 mt-4"><button onclick="doAssignSupervisor(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAssignSupervisor = async (id) => {
  try { await api.put(`/users/${id}/supervisor`, { supervisor_id: $('sup_sel').value || null }); closeModal(); toast('Supervisor updated'); viewUsers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
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
  try {
    await api.put('/agents/' + id, { full_name: $('ea_name').value, phone: $('ea_phone').value, email: $('ea_email').value, region: $('ea_region').value })
    closeModal(); toast('Agent updated'); viewAgents()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// USER ACCOUNTS (admin CRUD)
// ---------------------------------------------------------------------------
async function viewUsers() {
  const { data } = await api.get('/users')
  _users = data.users
  const supLabel = (u) => u.custom_role ? esc(u.custom_role) : esc(u.role.replace(/_/g, ' '))
  $('content').innerHTML = `
  <div class="flex justify-end mb-4"><button onclick="addUserModal()" class="btn brand-bg text-white px-4 py-2 rounded-lg text-sm"><i class="fas fa-user-plus mr-1"></i>Add User</button></div>
  <div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Role</th><th class="text-left px-4 py-3">Supervisor</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.users.map(u => `<tr class="border-t border-slate-100">
      <td data-label="Name" class="px-4 py-3 font-medium">${esc(u.full_name)}<div class="text-xs text-slate-400">${esc(u.email || '')}</div></td><td data-label="Phone" class="px-4 py-3">${esc(u.phone)}</td>
      <td data-label="Role" class="px-4 py-3 capitalize">${supLabel(u)}<div class="text-[10px] text-slate-400">${esc(u.role.replace(/_/g,' '))}</div></td>
      <td data-label="Supervisor" class="px-4 py-3">${esc(u.supervisor_name || '—')}</td><td data-label="Status" class="px-4 py-3">${badge(u.status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editUserModal(${u.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        ${state.user.role === 'super_admin' ? `<button onclick="supervisorModal(${u.id},'${esc(u.full_name)}')" class="text-indigo-600 hover:underline text-xs mr-2">Supervisor</button>` : ''}
        <button onclick="resetUserPassword(${u.id},'${esc(u.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
        ${u.status === 'active' ? `<button onclick="setUserStatus(${u.id},'suspended','users')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${u.id},'active','users')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
        <button onclick="deleteUser(${u.id},'${esc(u.full_name)}','users')" class="text-red-600 hover:underline text-xs">Delete</button>
      </td></tr>`).join('')}</tbody>
  </table></div>`
}
window.editUserModal = (id) => {
  const u = _users.find(x => x.id === id)
  const canPerm = state.user.role === 'super_admin' || state.user.role === 'admin'
  let perms = []
  try { perms = Array.isArray(u.permissions) ? u.permissions : (u.permissions ? JSON.parse(u.permissions) : []) } catch { perms = [] }
  showModal(`<h3 class="font-bold mb-3">Edit User</h3><div class="space-y-3 text-sm">
    <div class="field-group"><label class="field-label">Full Name</label><input id="eu_name" value="${esc(u.full_name)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Phone</label><input id="eu_phone" value="${esc(u.phone)}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Email</label><input id="eu_email" value="${esc(u.email || '')}" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Role</label><select id="eu_role" class="w-full px-3 py-2 border rounded-lg">
      ${['super_admin', 'admin', 'agent', 'customer', 'support'].map(r => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r.replace(/_/g, ' ')}</option>`).join('')}
    </select></div>
    <div class="field-group"><label class="field-label">Region</label><input id="eu_region" value="${esc(u.region || '')}" class="w-full px-3 py-2 border rounded-lg"></div>
    ${canPerm ? `<div class="field-group"><label class="field-label">Custom User Type (overrides role title)</label><input id="eu_custom" value="${esc(u.custom_role || '')}" placeholder="e.g. Regional Lead, Junior Auditor" class="w-full px-3 py-2 border rounded-lg"></div>
    <div class="field-group"><label class="field-label">Permissions</label>${permGridHtml('eu', perms)}</div>` : ''}
    <div class="field-group"><label class="field-label">New password (leave blank to keep)</label><input id="eu_pwd" type="password" class="w-full px-3 py-2 border rounded-lg"></div>
  </div><div class="flex gap-2 mt-4"><button onclick="doEditUser(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditUser = async (id) => {
  try {
    const canPerm = state.user.role === 'super_admin' || state.user.role === 'admin'
    const body = { full_name: $('eu_name').value, phone: $('eu_phone').value, email: $('eu_email').value, role: $('eu_role').value, region: $('eu_region').value }
    if (canPerm) { body.custom_role = $('eu_custom').value || null; body.permissions = collectPerms('eu') }
    if ($('eu_pwd').value) body.password = $('eu_pwd').value
    await api.put('/users/' + id, body)
    closeModal(); toast('User updated'); viewUsers()
  } catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.setUserStatus = async (id, status, back) => {
  try { await api.put(`/users/${id}/status`, { status }); toast('Status updated'); back === 'agents' ? viewAgents() : viewUsers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}
window.deleteUser = async (id, name, back) => {
  if (!confirm('Delete "' + name + '"? This permanently removes the account.')) return
  try { await api.delete('/users/' + id); toast('Account deleted'); back === 'agents' ? viewAgents() : viewUsers() }
  catch (err) { toast(err.response?.data?.error || 'Failed', false) }
}

// ---------------------------------------------------------------------------
// REPAYMENTS
// ---------------------------------------------------------------------------
async function viewRepayments() {
  const { data } = await api.get('/repayments')
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="responsive-table w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Contract</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Inst.</th><th class="text-left px-4 py-3">Due Date</th><th class="text-right px-4 py-3">Amount</th><th class="text-right px-4 py-3">Paid</th><th class="text-left px-4 py-3">Status</th></tr></thead>
    <tbody>${data.repayments.map(r => `<tr class="border-t border-slate-100"><td data-label="Contract" class="px-4 py-3 font-mono text-xs">${esc(r.contract_ref)}</td><td data-label="Customer" class="px-4 py-3">${esc(r.customer)}</td><td data-label="Inst." class="px-4 py-3">#${r.installment_no}</td><td data-label="Due Date" class="px-4 py-3">${r.due_date}</td><td data-label="Amount" class="px-4 py-3 text-right">${fmt(r.amount_due)}</td><td data-label="Paid" class="px-4 py-3 text-right">${fmt(r.amount_paid)}</td><td data-label="Status" class="px-4 py-3">${badge(r.status)}</td></tr>`).join('') || '<tr><td colspan="7" class="text-center py-8 text-slate-400">No repayments</td></tr>'}</tbody>
  </table></div>`
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
