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
    { k: 'exports', i: 'fa-database', t: 'Data Export' }]
  if (r === 'agent') return [...common,
    { k: 'onboard', i: 'fa-user-plus', t: 'Onboard Customer' },
    { k: 'customers', i: 'fa-users', t: 'My Customers' },
    { k: 'contracts', i: 'fa-file-signature', t: 'Applications' }]
  if (r === 'customer') return [...common,
    { k: 'shop', i: 'fa-store', t: 'Shop / Buy' },
    { k: 'contracts', i: 'fa-file-signature', t: 'My Contracts' }]
  if (r === 'support') return [...common,
    { k: 'customers', i: 'fa-users', t: 'Customers' },
    { k: 'repayments', i: 'fa-money-bill-wave', t: 'Repayments' }]
  return common
}
function renderApp() {
  const items = navItems()
  $('app').innerHTML = `
  <div class="flex min-h-screen">
    <aside class="w-64 brand-bg text-white flex flex-col fixed h-full">
      <div class="p-4 border-b border-white/10 bg-white/95">
        <img src="/static/farmsky-logo.png" alt="Farmsky" class="h-16 mx-auto object-contain">
      </div>
      <nav class="flex-1 py-4 overflow-y-auto">
        ${items.map(it => `<div class="nav-link px-5 py-3 flex items-center gap-3 text-sm hover:bg-white/10 ${state.route === it.k ? 'active' : ''}" onclick="go('${it.k}')"><i class="fas ${it.i} w-5"></i>${it.t}</div>`).join('')}
      </nav>
      <div class="p-4 border-t border-white/10">
        <div class="text-sm font-medium">${esc(state.user.full_name)}</div>
        <div class="text-xs text-teal-200 capitalize mb-2">${state.user.role.replace(/_/g, ' ')}</div>
        <button onclick="logout()" class="btn w-full text-xs bg-white/10 hover:bg-white/20 py-2 rounded-lg"><i class="fas fa-right-from-bracket mr-1"></i>Logout</button>
      </div>
    </aside>
    <main class="flex-1 ml-64">
      <header class="bg-white border-b border-slate-200 px-8 py-4 flex justify-between items-center sticky top-0 z-10">
        <h2 id="pageTitle" class="text-xl font-bold text-slate-800"></h2>
        <div class="text-sm text-slate-500"><i class="fas fa-shield-halved text-teal-600 mr-1"></i>Sharia-Compliant · No Interest</div>
      </header>
      <div id="content" class="p-8"></div>
    </main>
  </div>
  <div id="modal"></div>`
  route()
}
window.go = (r) => { state.route = r; renderApp() }
function route() {
  const titles = { dashboard: 'Dashboard', approvals: 'Murabaha Approvals', inventory: 'Inventory Management', customers: 'Customers', contracts: 'Contracts', agents: 'Agent Management', users: 'User Accounts', repayments: 'Repayment Performance', onboard: 'Customer Onboarding', shop: 'Shop', exports: 'Data Export & Reports' }
  $('pageTitle').textContent = titles[state.route] || 'Dashboard'
  const map = { dashboard: viewDashboard, approvals: viewApprovals, inventory: viewInventory, customers: viewCustomers, contracts: viewContracts, agents: viewAgents, users: viewUsers, repayments: viewRepayments, onboard: viewOnboard, shop: viewShop, exports: viewExports }
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
  showModal(`
    <h3 class="text-lg font-bold mb-1">Purchase: ${esc(p.name)}</h3>
    <p class="text-xs text-slate-500 mb-4">Choose payment type — system will disclose full Murabaha cost before you consent.</p>
    <div class="space-y-3">
      <div><label class="text-sm font-medium">Quantity</label><input id="qty" type="number" value="1" min="1" max="${p.quantity}" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg"></div>
      <div><label class="text-sm font-medium">Payment Type</label>
        <select id="ptype" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg" onchange="toggleTerm()">
          <option value="cash">Cash (lower margin)</option>
          <option value="credit">Pay Later — Murabaha Financing (fixed margin)</option>
        </select></div>
      <div id="termWrap" class="hidden"><label class="text-sm font-medium">Payment Term (months)</label>
        <select id="term" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg">
          <option>3</option><option selected>6</option><option>9</option><option>12</option>
        </select></div>
      <div><label class="text-sm font-medium">Delivery Location</label><input id="dloc" type="text" placeholder="Village / Ward" class="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg"></div>
    </div>
    <div id="quoteBox" class="mt-4"></div>
    <div class="flex gap-2 mt-5">
      <button onclick="getQuote(${p.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-calculator mr-1"></i>Disclose Cost</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button>
    </div>`)
}
window.toggleTerm = () => { $('termWrap').classList.toggle('hidden', $('ptype').value !== 'credit') }
window.getQuote = async (productId) => {
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0 }
  const { data } = await api.post('/murabaha/quote', body)
  const credit = body.payment_type === 'credit'
  $('quoteBox').innerHTML = `
    <div class="bg-teal-50 border border-teal-200 rounded-xl p-4">
      <h4 class="font-bold text-teal-800 mb-2"><i class="fas fa-file-invoice-dollar mr-1"></i>Cost Disclosure</h4>
      <div class="space-y-1 text-sm">
        <div class="flex justify-between"><span>Supplier Cost</span><b>${fmt(data.supplier_cost)}</b></div>
        <div class="flex justify-between"><span>Markup</span><b>${data.markup_pct}%</b></div>
        <div class="flex justify-between text-base text-teal-800"><span>Murabaha Price</span><b>${fmt(data.murabaha_price)}</b></div>
        ${credit ? `<div class="flex justify-between"><span>Term</span><b>${data.term_months} months</b></div>
        <div class="flex justify-between"><span>Monthly Payment</span><b>${fmt(data.monthly_payment)}</b></div>` : ''}
      </div>
      <p class="text-xs text-teal-700 mt-2 italic">${esc(data.sharia_note)}</p>
      <label class="flex items-center gap-2 mt-3 text-sm"><input type="checkbox" id="consent"> I explicitly consent to this fixed Murabaha price.</label>
      <button onclick="submitBuy(${productId})" class="btn w-full mt-3 brand-bg text-white py-2.5 rounded-lg text-sm">${credit ? 'Submit Pay Later Application' : 'Confirm Cash Purchase'}</button>
    </div>`
}
window.submitBuy = async (productId) => {
  if (!$('consent').checked) return toast('Consent is required (Sharia requirement)', false)
  const body = { product_id: productId, quantity: $('qty').value, payment_type: $('ptype').value, term_months: $('term') ? $('term').value : 0, delivery_location: $('dloc').value, consent: true }
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
    <table class="w-full text-sm">
      <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr>
        <th class="text-left px-4 py-3">Ref</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Product</th>
        <th class="text-left px-4 py-3">Type</th><th class="text-right px-4 py-3">Price</th><th class="text-right px-4 py-3">Outstanding</th>
        <th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
      <tbody>${data.contracts.map(c => `<tr class="border-t border-slate-100">
        <td class="px-4 py-3 font-mono text-xs">${esc(c.contract_ref)}</td>
        <td class="px-4 py-3">${esc(c.customer_name)}</td>
        <td class="px-4 py-3">${esc(c.product_name)} ×${c.quantity}</td>
        <td class="px-4 py-3">${payLabel(c.payment_type)}</td>
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
      ${canPay ? `<button onclick="payModal(${c.id}, ${c.monthly_payment}, ${c.outstanding})" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-mobile-alt mr-1"></i>Pay via M-Pesa</button>` : ''}
      <button onclick="viewDoc(${c.id})" class="btn flex-1 bg-slate-800 text-white py-2.5 rounded-lg text-sm"><i class="fas fa-file-pdf mr-1"></i>Documents</button>
      <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Close</button>
    </div>`)
}
window.payModal = async (id, amount, outstanding, kind) => {
  kind = kind || 'repay'
  const isCash = kind === 'cash'
  let mode = { mode: 'simulation', live: false }
  try { mode = (await api.get('/mpesa/status')).data } catch {}
  const banner = mode.live
    ? `<div class="bg-emerald-50 border border-emerald-200 rounded-lg p-2 text-xs text-emerald-700 mb-3"><i class="fas fa-circle-check mr-1"></i>Live M-Pesa Daraja (${esc(mode.mode)}) — you will receive a real STK prompt.</div>`
    : `<div class="bg-amber-50 border border-amber-200 rounded-lg p-2 text-xs text-amber-700 mb-3"><i class="fas fa-flask mr-1"></i>Simulation mode — no real money moves. Add Daraja keys to go live.</div>`
  showModal(`<h3 class="text-lg font-bold mb-1"><i class="fas fa-mobile-alt text-teal-600 mr-2"></i>${isCash ? 'Cash Checkout — Pay via M-Pesa' : 'Pay via M-Pesa'}</h3>
    <p class="text-xs text-slate-500 mb-3">${isCash ? 'Amount due' : 'Outstanding'}: ${fmt(outstanding)}</p>
    ${banner}
    <label class="text-sm font-medium">M-Pesa Phone</label><input id="mpphone" value="${esc(state.user.phone)}" class="w-full mt-1 mb-3 px-3 py-2 border border-slate-300 rounded-lg">
    <label class="text-sm font-medium">Amount (KES)</label><input id="mpamt" type="number" value="${amount}" ${isCash ? 'readonly' : ''} class="w-full mt-1 mb-4 px-3 py-2 border border-slate-300 rounded-lg ${isCash ? 'bg-slate-50' : ''}">
    <div id="payStatus"></div>
    <div class="flex gap-2"><button id="payBtn" onclick="doPay(${id}, '${kind}')" class="btn flex-1 brand-bg text-white py-2.5 rounded-lg text-sm">Send STK Push</button>
    <button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doPay = async (id, kind) => {
  const isCash = kind === 'cash'
  const btn = $('payBtn'); btn.disabled = true; btn.classList.add('opacity-50')
  $('payStatus').innerHTML = '<div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>Sending STK push...</div>'
  try {
    const { data } = await api.post('/mpesa/stkpush', { contract_id: id, amount: $('mpamt').value, phone: $('mpphone').value })
    $('payStatus').innerHTML = `<div class="bg-teal-50 border border-teal-200 rounded-lg p-2 text-xs text-teal-700 mb-3"><i class="fas fa-mobile-alt mr-1"></i>${esc(data.customer_message || 'STK push sent. Confirm on your phone.')}</div><div class="text-xs text-slate-500 mb-3"><i class="fas fa-spinner fa-spin mr-1"></i>Waiting for confirmation...</div>`
    let tries = 0
    const poll = async () => {
      tries++
      try {
        const { data: cd } = await api.post('/mpesa/confirm', { checkout_request_id: data.checkout_request_id })
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
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="w-full text-sm">
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
  <div class="card overflow-hidden"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Image</th><th class="text-left px-4 py-3">SKU</th><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Category</th><th class="text-right px-4 py-3">Buy</th><th class="text-right px-4 py-3">Cash</th><th class="text-right px-4 py-3">Pay Later</th><th class="text-right px-4 py-3">Qty</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.products.map(p => `<tr class="border-t border-slate-100">
      <td class="px-4 py-2">${prodImg(p, 'w-10 h-10 rounded-lg')}</td>
      <td class="px-4 py-3 font-mono text-xs">${esc(p.sku)}</td><td class="px-4 py-3">${esc(p.name)}</td><td class="px-4 py-3">${esc(p.category)}</td>
      <td class="px-4 py-3 text-right">${fmt(p.buying_price)}</td><td class="px-4 py-3 text-right text-emerald-600">${fmt(p.cash_price)}</td><td class="px-4 py-3 text-right text-blue-600">${fmt(p.credit_price)}</td>
      <td class="px-4 py-3 text-right">${p.quantity} ${esc(p.unit)}</td><td class="px-4 py-3">${badge(p.stock_status)}</td>
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
window.addProductModal = () => {
  showModal(`<h3 class="font-bold mb-3">Add Product</h3>
    <div class="flex items-center gap-3 mb-3">
      <div id="np_preview" class="w-16 h-16 rounded-lg bg-slate-100 flex items-center justify-center text-slate-400"><i class="fas fa-image"></i></div>
      <label class="btn bg-slate-100 px-3 py-2 rounded-lg text-xs cursor-pointer"><i class="fas fa-upload mr-1"></i>Upload Image<input type="file" accept="image/*" class="hidden" onchange="pickImage(this,'np_img','np_preview')"></label>
    </div>
    <input type="hidden" id="np_img" value="">
    <div class="grid grid-cols-2 gap-3 text-sm">
    <input id="np_sku" placeholder="SKU" class="px-3 py-2 border rounded-lg col-span-2">
    <input id="np_name" placeholder="Name" class="px-3 py-2 border rounded-lg col-span-2">
    <input id="np_cat" placeholder="Category" class="px-3 py-2 border rounded-lg">
    <input id="np_unit" placeholder="Unit (bag/unit)" class="px-3 py-2 border rounded-lg">
    <input id="np_buy" type="number" placeholder="Buying price" class="px-3 py-2 border rounded-lg">
    <input id="np_qty" type="number" placeholder="Quantity" class="px-3 py-2 border rounded-lg">
    <input id="np_cm" type="number" placeholder="Cash markup %" value="10" class="px-3 py-2 border rounded-lg">
    <input id="np_crm" type="number" placeholder="Pay Later markup %" value="20" class="px-3 py-2 border rounded-lg">
    </div><div class="flex gap-2 mt-4"><button onclick="doAddProduct()" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doAddProduct = async () => {
  try {
    await api.post('/products', { sku: $('np_sku').value, name: $('np_name').value, category: $('np_cat').value, unit: $('np_unit').value, buying_price: Number($('np_buy').value), quantity: Number($('np_qty').value), cash_markup_pct: Number($('np_cm').value), credit_markup_pct: Number($('np_crm').value), image: $('np_img').value || null })
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
  <div class="grid grid-cols-2 gap-3 text-sm">
    <input id="ep_sku" value="${esc(p.sku)}" placeholder="SKU" class="px-3 py-2 border rounded-lg col-span-2">
    <input id="ep_name" value="${esc(p.name)}" placeholder="Name" class="px-3 py-2 border rounded-lg col-span-2">
    <input id="ep_cat" value="${esc(p.category)}" placeholder="Category" class="px-3 py-2 border rounded-lg">
    <input id="ep_unit" value="${esc(p.unit)}" placeholder="Unit" class="px-3 py-2 border rounded-lg">
    <input id="ep_buy" type="number" value="${p.buying_price}" placeholder="Buying price" class="px-3 py-2 border rounded-lg">
    <input id="ep_qty" type="number" value="${p.quantity}" placeholder="Quantity" class="px-3 py-2 border rounded-lg">
    <input id="ep_cm" type="number" value="${p.cash_markup_pct}" placeholder="Cash markup %" class="px-3 py-2 border rounded-lg">
    <input id="ep_crm" type="number" value="${p.credit_markup_pct}" placeholder="Pay Later markup %" class="px-3 py-2 border rounded-lg">
    <input id="ep_rt" type="number" value="${p.reorder_threshold}" placeholder="Reorder threshold" class="px-3 py-2 border rounded-lg col-span-2">
  </div><div class="flex gap-2 mt-4"><button onclick="doEditProduct(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditProduct = async (id) => {
  try {
    await api.put('/products/' + id, { sku: $('ep_sku').value, name: $('ep_name').value, category: $('ep_cat').value, unit: $('ep_unit').value, buying_price: Number($('ep_buy').value), quantity: Number($('ep_qty').value), cash_markup_pct: Number($('ep_cm').value), credit_markup_pct: Number($('ep_crm').value), reorder_threshold: Number($('ep_rt').value), image: $('ep_img').value || null })
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
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">ID</th><th class="text-left px-4 py-3">Mobile</th><th class="text-left px-4 py-3">County</th><th class="text-left px-4 py-3">Value Chain</th><th class="text-left px-4 py-3">KYC</th><th class="text-left px-4 py-3">Risk</th><th></th></tr></thead>
    <tbody>${data.customers.map(c => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3 font-medium">${esc(c.full_name)}</td><td class="px-4 py-3">${esc(c.national_id || '—')}</td><td class="px-4 py-3">${esc(c.mobile || '—')}</td>
      <td class="px-4 py-3">${esc(c.county || '—')}</td><td class="px-4 py-3">${esc(c.value_chain || '—')}</td><td class="px-4 py-3">${badge(c.kyc_status)}</td>
      <td class="px-4 py-3">${c.risk_band ? badge(c.risk_band) : '—'}</td>
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
let _liveStream = null
window.completeRegistration = async (id, returnToShop) => {
  showModal(`<div class="text-center">
    <h3 class="text-lg font-bold mb-1"><i class="fas fa-camera text-teal-600 mr-2"></i>Liveness Verification</h3>
    <p class="text-xs text-slate-500 mb-4">Position the face in the frame and capture a live selfie.</p>
    <div class="relative w-40 h-40 mx-auto rounded-full bg-slate-900 overflow-hidden mb-4">
      <video id="liveVideo" autoplay playsinline muted class="w-full h-full object-cover"></video>
      <div class="absolute inset-0 border-4 border-teal-400 rounded-full animate-pulse pointer-events-none"></div>
    </div>
    <div id="regStatus" class="text-xs text-slate-500 mb-4">Initialising camera…</div>
    <button id="captureBtn" onclick="runChecks(${id}, ${!!returnToShop})" class="btn w-full brand-bg text-white py-2.5 rounded-lg text-sm"><i class="fas fa-circle-dot mr-1"></i>Capture & Verify</button>
    <button onclick="stopLive();closeModal()" class="btn w-full mt-2 bg-slate-100 py-2 rounded-lg text-sm">Cancel</button>
  </div>`)
  startLive()
}
async function startLive() {
  try {
    _liveStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' } })
    const v = $('liveVideo'); if (v) v.srcObject = _liveStream
    if ($('regStatus')) $('regStatus').textContent = 'Camera ready. Click capture when face is centered.'
  } catch (e) {
    if ($('regStatus')) $('regStatus').innerHTML = '<span class="text-amber-600">Camera unavailable — demo will simulate the liveness capture.</span>'
  }
}
function stopLive() { if (_liveStream) { _liveStream.getTracks().forEach(t => t.stop()); _liveStream = null } }
window.stopLive = stopLive
window.runChecks = async (id, returnToShop) => {
  const btn = $('captureBtn'); if (btn) { btn.disabled = true; btn.classList.add('opacity-50') }
  $('regStatus').innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Liveness detected ✓ · Running TransUnion credit check & ID match…'
  stopLive()
  try {
    const { data } = await api.post(`/customers/${id}/verify`)
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
      <div class="grid grid-cols-2 gap-3 text-sm">
        <input name="full_name" placeholder="Full Name *" required class="px-3 py-2 border rounded-lg col-span-2">
        <input name="national_id" placeholder="National ID *" required class="px-3 py-2 border rounded-lg">
        <input name="date_of_birth" type="date" class="px-3 py-2 border rounded-lg">
        <select name="gender" class="px-3 py-2 border rounded-lg"><option value="">Gender</option><option>Female</option><option>Male</option></select>
        <input name="mobile" placeholder="Mobile *" required class="px-3 py-2 border rounded-lg">
        <input name="alt_mobile" placeholder="Alternative Number" class="px-3 py-2 border rounded-lg">
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-map-marker-alt mr-2"></i>Location</h3>
      <div class="grid grid-cols-2 gap-3 text-sm">
        <input name="county" placeholder="County" class="px-3 py-2 border rounded-lg">
        <input name="sub_county" placeholder="Sub-county" class="px-3 py-2 border rounded-lg">
        <input name="ward" placeholder="Ward" class="px-3 py-2 border rounded-lg">
        <input name="village" placeholder="Village" class="px-3 py-2 border rounded-lg">
        <input name="latitude" id="lat" placeholder="Latitude" class="px-3 py-2 border rounded-lg">
        <input name="longitude" id="lng" placeholder="Longitude" class="px-3 py-2 border rounded-lg">
      </div>
      <button type="button" onclick="captureGPS()" class="btn mt-2 text-xs bg-slate-100 px-3 py-1.5 rounded-lg"><i class="fas fa-location-crosshairs mr-1"></i>Auto-capture GPS</button></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-leaf mr-2"></i>Farming Profile</h3>
      <div class="grid grid-cols-2 gap-3 text-sm">
        <select name="value_chain_type" id="vct" onchange="updateChain()" class="px-3 py-2 border rounded-lg"><option value="">Value Chain Type</option><option value="crop">Crop</option><option value="livestock">Livestock</option></select>
        <select name="value_chain" id="vc" class="px-3 py-2 border rounded-lg"><option value="">Select type first</option></select>
        <input name="acreage" type="number" step="0.1" placeholder="Acreage" class="px-3 py-2 border rounded-lg">
        <input name="herd_size" type="number" placeholder="Herd Size" class="px-3 py-2 border rounded-lg">
        <input name="farm_experience" type="number" placeholder="Years experience" class="px-3 py-2 border rounded-lg">
        <input name="annual_production" placeholder="Annual production" class="px-3 py-2 border rounded-lg">
      </div></div>
    <div><h3 class="font-bold text-teal-700 mb-2"><i class="fas fa-wallet mr-2"></i>Financial Profile</h3>
      <div class="grid grid-cols-2 gap-3 text-sm">
        <input name="mobile_money_usage" placeholder="Mobile money usage" class="px-3 py-2 border rounded-lg">
        <input name="existing_loans" placeholder="Existing loans" class="px-3 py-2 border rounded-lg">
        <input name="bank_account" placeholder="Bank account" class="px-3 py-2 border rounded-lg">
        <input name="sacco_membership" placeholder="SACCO membership" class="px-3 py-2 border rounded-lg">
      </div></div>
    <div class="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-700"><i class="fas fa-info-circle mr-1"></i>ID upload & live selfie capture happen during "Complete User Registration" (TransUnion + Liveness) — run it from the Customers page after onboarding.</div>
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
  <div class="card overflow-hidden"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Region</th><th class="text-right px-4 py-3">Customers</th><th class="text-right px-4 py-3">Active</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.agents.map(a => `<tr class="border-t border-slate-100"><td class="px-4 py-3 font-medium">${esc(a.full_name)}</td><td class="px-4 py-3">${esc(a.phone)}</td><td class="px-4 py-3">${esc(a.region || '—')}</td><td class="px-4 py-3 text-right">${a.customers}</td><td class="px-4 py-3 text-right">${a.active}</td><td class="px-4 py-3">${badge(a.status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editAgentModal(${a.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        <button onclick="resetUserPassword(${a.id},'${esc(a.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
        ${a.status === 'active' ? `<button onclick="setUserStatus(${a.id},'suspended','agents')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${a.id},'active','agents')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
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
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Name</th><th class="text-left px-4 py-3">Phone</th><th class="text-left px-4 py-3">Email</th><th class="text-left px-4 py-3">Role</th><th class="text-left px-4 py-3">Region</th><th class="text-left px-4 py-3">Status</th><th></th></tr></thead>
    <tbody>${data.users.map(u => `<tr class="border-t border-slate-100">
      <td class="px-4 py-3 font-medium">${esc(u.full_name)}</td><td class="px-4 py-3">${esc(u.phone)}</td><td class="px-4 py-3">${esc(u.email || '—')}</td>
      <td class="px-4 py-3 capitalize">${esc(u.role.replace(/_/g, ' '))}</td><td class="px-4 py-3">${esc(u.region || '—')}</td><td class="px-4 py-3">${badge(u.status)}</td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="editUserModal(${u.id})" class="text-teal-600 hover:underline text-xs mr-2">Edit</button>
        <button onclick="resetUserPassword(${u.id},'${esc(u.full_name)}')" class="text-blue-600 hover:underline text-xs mr-2">Reset Password</button>
        ${u.status === 'active' ? `<button onclick="setUserStatus(${u.id},'suspended','users')" class="text-amber-600 hover:underline text-xs mr-2">Deactivate</button>` : `<button onclick="setUserStatus(${u.id},'active','users')" class="text-emerald-600 hover:underline text-xs mr-2">Activate</button>`}
        <button onclick="deleteUser(${u.id},'${esc(u.full_name)}','users')" class="text-red-600 hover:underline text-xs">Delete</button>
      </td></tr>`).join('')}</tbody>
  </table></div>`
}
window.editUserModal = (id) => {
  const u = _users.find(x => x.id === id)
  showModal(`<h3 class="font-bold mb-3">Edit User</h3><div class="space-y-3 text-sm">
    <input id="eu_name" value="${esc(u.full_name)}" placeholder="Full Name" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_phone" value="${esc(u.phone)}" placeholder="Phone" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_email" value="${esc(u.email || '')}" placeholder="Email" class="w-full px-3 py-2 border rounded-lg">
    <select id="eu_role" class="w-full px-3 py-2 border rounded-lg">
      ${['super_admin', 'admin', 'agent', 'customer', 'support'].map(r => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r.replace(/_/g, ' ')}</option>`).join('')}
    </select>
    <input id="eu_region" value="${esc(u.region || '')}" placeholder="Region" class="w-full px-3 py-2 border rounded-lg">
    <input id="eu_pwd" placeholder="New password (leave blank to keep)" class="w-full px-3 py-2 border rounded-lg">
  </div><div class="flex gap-2 mt-4"><button onclick="doEditUser(${id})" class="btn flex-1 brand-bg text-white py-2 rounded-lg text-sm">Save Changes</button><button onclick="closeModal()" class="btn px-4 bg-slate-100 rounded-lg text-sm">Cancel</button></div>`)
}
window.doEditUser = async (id) => {
  try {
    const body = { full_name: $('eu_name').value, phone: $('eu_phone').value, email: $('eu_email').value, role: $('eu_role').value, region: $('eu_region').value }
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
  $('content').innerHTML = `<div class="card overflow-hidden"><table class="w-full text-sm">
    <thead class="bg-slate-50 text-slate-500 text-xs uppercase"><tr><th class="text-left px-4 py-3">Contract</th><th class="text-left px-4 py-3">Customer</th><th class="text-left px-4 py-3">Inst.</th><th class="text-left px-4 py-3">Due Date</th><th class="text-right px-4 py-3">Amount</th><th class="text-right px-4 py-3">Paid</th><th class="text-left px-4 py-3">Status</th></tr></thead>
    <tbody>${data.repayments.map(r => `<tr class="border-t border-slate-100"><td class="px-4 py-3 font-mono text-xs">${esc(r.contract_ref)}</td><td class="px-4 py-3">${esc(r.customer)}</td><td class="px-4 py-3">#${r.installment_no}</td><td class="px-4 py-3">${r.due_date}</td><td class="px-4 py-3 text-right">${fmt(r.amount_due)}</td><td class="px-4 py-3 text-right">${fmt(r.amount_paid)}</td><td class="px-4 py-3">${badge(r.status)}</td></tr>`).join('') || '<tr><td colspan="7" class="text-center py-8 text-slate-400">No repayments</td></tr>'}</tbody>
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
