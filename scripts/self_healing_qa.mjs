#!/usr/bin/env node
// =============================================================================
// Farmsky — System-wide Automated Testing, QA & Self-Healing Pipeline runner.
//
// Continuously (or on-demand / in CI) probes a running service, detects runtime
// errors, regressions and failing health checks, logs root-cause diagnostics,
// and triggers automated remediation for known failure modes.
//
// Usage:
//   node scripts/self_healing_qa.mjs --base http://127.0.0.1:8811 \
//        --phone +254702875711 --password 1224 [--watch 60] [--no-heal]
//
// Exit code 0 = healthy, 1 = degraded (anomalies found), 2 = unreachable.
// Wire into CI (fail the build) and/or a cron/uptime monitor (alert + auto-heal).
// The /api/admin/self-test endpoint performs in-process checks + known-failure
// remediation (sequence realignment); this runner adds external black-box probes
// (auth pipeline, offtake, payments) and the alert/rollback trigger surface.
// =============================================================================
const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, arr) => {
  if (x.startsWith('--')) a.push([x.slice(2), arr[i + 1] && !arr[i + 1].startsWith('--') ? arr[i + 1] : true])
  return a
}, []))
const BASE = args.base || process.env.BASE || 'http://127.0.0.1:8811'
const PHONE = args.phone || process.env.SA_PHONE || '+254702875711'
const PASSWORD = args.password || process.env.SA_PASS || '1224'
const HEAL = !args['no-heal']
const WATCH = args.watch ? Number(args.watch) : 0

const log = (lvl, ...a) => console.log(`[${new Date().toISOString()}] ${lvl}`, ...a)
async function j(method, path, token, body) {
  const r = await fetch(BASE + path, { method, headers: { 'content-type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined })
  let data; try { data = await r.json() } catch { data = null }
  return { status: r.status, data }
}

async function runOnce() {
  const anomalies = []
  try {
    const h = await j('GET', '/api/health')
    if (h.status !== 200) anomalies.push({ check: 'health', detail: `status ${h.status}`, severity: 'critical' })
  } catch (e) { log('FATAL', 'service unreachable:', e.message); return { reachable: false, anomalies: [{ check: 'reachability', severity: 'critical' }] } }

  const login = await j('POST', '/api/login', null, { phone: PHONE, password: PASSWORD })
  if (!login.data?.token) { anomalies.push({ check: 'admin_login', detail: 'cannot authenticate QA admin', severity: 'critical' }); return { reachable: true, anomalies } }
  const token = login.data.token
  const st = await j('POST', '/api/admin/self-test', token, { auto_heal: HEAL })
  for (const ch of (st.data?.checks || [])) {
    if (!ch.ok) anomalies.push({ check: ch.name, detail: ch.detail, remediation: ch.remediation, severity: 'high' })
  }
  if (st.data?.healed?.length) log('HEAL', 'auto-remediation applied to:', st.data.healed.join(', '))

  // Black-box regression probe of the reported failure mode: the sign-up pipeline.
  const suffix = String(Math.floor(Math.random() * 1e7))
  const sp = '+2547' + String(10000000 + Number(suffix)).slice(0, 8)
  const otp = await j('POST', '/api/signup/request-otp', null, { phone: sp, full_name: 'QA Probe' })
  if (otp.data?.demo_otp) {
    const ver = await j('POST', '/api/signup/verify', null, { phone: sp, full_name: 'QA Probe', code: otp.data.demo_otp, password: 'probe123', national_id: '7' + suffix.padStart(7, '0'), county: 'Nairobi' })
    if (!ver.data?.ok) anomalies.push({ check: 'signup_e2e', detail: ver.data?.error || `status ${ver.status}`, severity: 'critical', remediation: 'customers RLS INSERT — ensure runAsAdmin signup path + ownership_customers policy.' })
  }

  if (anomalies.length) {
    log('DEGRADED', `${anomalies.length} anomaly(ies) detected:`)
    for (const a of anomalies) log('  ANOMALY', JSON.stringify(a))
    const known = anomalies.filter(a => a.remediation)
    if (known.length) log('TRIGGER', `${known.length} known failure mode(s) — remediation hints emitted; CI should re-run migrations / redeploy last-good build.`)
  } else {
    log('OK', `all checks passed (${(st.data?.checks || []).length} in-process + sign-up e2e).`)
  }
  return { reachable: true, anomalies }
}

async function main() {
  do {
    const res = await runOnce()
    if (!WATCH) process.exit(res.reachable ? (res.anomalies.length ? 1 : 0) : 2)
    await new Promise(r => setTimeout(r, WATCH * 1000))
  } while (WATCH)
}
main().catch(e => { log('FATAL', e); process.exit(2) })
