import{createRequire}from'module';const require=createRequire(import.meta.url);

// src/server.ts
import "dotenv/config";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { fileURLToPath } from "node:url";
import { dirname as dirname2, join as join2 } from "node:path";

// src/index.tsx
import { Hono } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";

// src/mpesa.ts
var SANDBOX_BASE = "https://sandbox.safaricom.co.ke";
var PROD_BASE = "https://api.safaricom.co.ke";
function mpesaConfigured(env) {
  return !!(env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_SHORTCODE && env.MPESA_PASSKEY);
}
function baseUrl(env) {
  return env.MPESA_ENV === "production" ? PROD_BASE : SANDBOX_BASE;
}
function timestamp() {
  const now = new Date(Date.now() + 3 * 3600 * 1e3);
  const p = (n) => String(n).padStart(2, "0");
  return `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}${p(now.getUTCHours())}${p(now.getUTCMinutes())}${p(now.getUTCSeconds())}`;
}
function b64(s) {
  return btoa(s);
}
function normalizePhone(phone) {
  let p = String(phone || "").replace(/[^0-9]/g, "");
  if (p.startsWith("0")) p = "254" + p.slice(1);
  if (p.startsWith("7") && p.length === 9) p = "254" + p;
  if (p.startsWith("2540")) p = "254" + p.slice(4);
  return p;
}
async function getToken(env) {
  const auth = b64(`${env.MPESA_CONSUMER_KEY}:${env.MPESA_CONSUMER_SECRET}`);
  const res = await fetch(`${baseUrl(env)}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  });
  if (!res.ok) throw new Error("Failed to obtain M-Pesa token: " + res.status);
  const data = await res.json();
  return data.access_token;
}
async function stkPush(env, opts) {
  if (!mpesaConfigured(env)) {
    return {
      simulated: true,
      success: true,
      checkout_request_id: "ws_CO_SIM_" + crypto.randomUUID().slice(0, 12),
      merchant_request_id: "SIM_" + crypto.randomUUID().slice(0, 8),
      customer_message: "Simulated STK push sent. (Configure Daraja keys for live payments.)"
    };
  }
  try {
    const token = await getToken(env);
    const ts = timestamp();
    const password = b64(`${env.MPESA_SHORTCODE}${env.MPESA_PASSKEY}${ts}`);
    const phone = normalizePhone(opts.phone);
    const body = {
      BusinessShortCode: env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: ts,
      TransactionType: "CustomerPayBillOnline",
      Amount: Math.max(1, Math.round(opts.amount)),
      PartyA: phone,
      PartyB: env.MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: env.MPESA_CALLBACK_URL || "https://example.com/api/mpesa/callback",
      AccountReference: opts.account.slice(0, 12),
      TransactionDesc: opts.description.slice(0, 13)
    };
    const res = await fetch(`${baseUrl(env)}/mpesa/stkpush/v1/processrequest`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.ResponseCode === "0") {
      return {
        simulated: false,
        success: true,
        checkout_request_id: data.CheckoutRequestID,
        merchant_request_id: data.MerchantRequestID,
        customer_message: data.CustomerMessage || "STK push sent. Enter your M-Pesa PIN on your phone."
      };
    }
    return { simulated: false, success: false, error: data.errorMessage || data.ResponseDescription || "STK push failed" };
  } catch (e) {
    return { simulated: false, success: false, error: e.message || "M-Pesa request failed" };
  }
}
async function stkQuery(env, checkoutRequestId) {
  if (!mpesaConfigured(env)) return { ResultCode: "0", ResultDesc: "Simulated success" };
  const token = await getToken(env);
  const ts = timestamp();
  const password = b64(`${env.MPESA_SHORTCODE}${env.MPESA_PASSKEY}${ts}`);
  const res = await fetch(`${baseUrl(env)}/mpesa/stkpushquery/v1/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ BusinessShortCode: env.MPESA_SHORTCODE, Password: password, Timestamp: ts, CheckoutRequestID: checkoutRequestId })
  });
  return await res.json();
}

// src/sms.ts
var TALKSASA_DEFAULT_URL = "https://bulksms.talksasa.com/api/v3/sms/send";
function smsProvider(env) {
  return (env.SMS_PROVIDER || "talksasa").toLowerCase();
}
function smsUrl(env) {
  if (env.SMS_API_URL) return env.SMS_API_URL;
  if (smsProvider(env) === "talksasa") return TALKSASA_DEFAULT_URL;
  return "";
}
function smsConfigured(env) {
  return !!(env.SMS_API_TOKEN && smsUrl(env));
}
function toE164(phone) {
  const digits = String(phone || "").replace(/[^0-9]/g, "");
  return digits ? "+" + digits : "";
}
async function sendSms(env, phone, message) {
  if (!smsConfigured(env)) {
    return { simulated: true, success: true };
  }
  const provider = smsProvider(env);
  const url = smsUrl(env);
  try {
    let body;
    if (provider === "talksasa") {
      body = {
        recipient: toE164(phone),
        sender_id: env.SMS_SENDER_ID || "FARMSKY",
        type: "plain",
        message
      };
    } else if (env.SMS_BODY_TEMPLATE) {
      const filled = env.SMS_BODY_TEMPLATE.replace(/\{phone\}/g, phone).replace(/\{message\}/g, message.replace(/"/g, '\\"')).replace(/\{sender\}/g, env.SMS_SENDER_ID || "");
      body = JSON.parse(filled);
    } else {
      const phoneField = env.SMS_PHONE_FIELD || "to";
      const msgField = env.SMS_MESSAGE_FIELD || "message";
      body = { [phoneField]: phone, [msgField]: message };
      if (env.SMS_SENDER_ID) body.sender = env.SMS_SENDER_ID;
    }
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.SMS_API_TOKEN}`,
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify(body)
    });
    const txt = await res.text().catch(() => "");
    if (!res.ok) {
      return { simulated: false, success: false, error: `SMS gateway ${res.status}: ${txt.slice(0, 200)}` };
    }
    if (provider === "talksasa") {
      try {
        const j = JSON.parse(txt);
        if (j && j.status && String(j.status).toLowerCase() !== "success") {
          return { simulated: false, success: false, error: j.message || "TalkSASA rejected the message" };
        }
      } catch {
      }
    }
    return { simulated: false, success: true };
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SMS send failed" };
  }
}
function generateOtp() {
  return String(Math.floor(1e5 + Math.random() * 9e5));
}

// src/email.ts
var RESEND_DEFAULT_URL = "https://api.resend.com/emails";
function emailProvider(env) {
  return (env.EMAIL_PROVIDER || "resend").toLowerCase();
}
function emailUrl(env) {
  if (env.EMAIL_API_URL) return env.EMAIL_API_URL;
  if (emailProvider(env) === "resend") return RESEND_DEFAULT_URL;
  return "";
}
function emailConfigured(env) {
  return !!(env.EMAIL_API_TOKEN && env.EMAIL_FROM && emailUrl(env));
}
async function sendEmail(env, opts) {
  if (!emailConfigured(env)) return { configured: false, success: false };
  const provider = emailProvider(env);
  const url = emailUrl(env);
  try {
    let body;
    if (provider === "sendgrid") {
      body = {
        personalizations: [{ to: [{ email: opts.to }] }],
        from: { email: env.EMAIL_FROM },
        subject: opts.subject,
        content: [{ type: "text/plain", value: opts.text }],
        attachments: (opts.attachments || []).map((a) => ({
          filename: a.filename,
          type: a.contentType,
          content: a.contentBase64,
          disposition: "attachment"
        }))
      };
    } else {
      body = {
        from: env.EMAIL_FROM,
        to: opts.to,
        subject: opts.subject,
        text: opts.text,
        attachments: (opts.attachments || []).map((a) => ({
          filename: a.filename,
          content: a.contentBase64,
          contentType: a.contentType
        }))
      };
    }
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.EMAIL_API_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      return { configured: true, success: false, error: `Email API ${res.status}: ${txt.slice(0, 200)}` };
    }
    return { configured: true, success: true };
  } catch (e) {
    return { configured: true, success: false, error: e?.message || "Email send failed" };
  }
}

// src/index.tsx
var app = new Hono();
app.use("/api/*", cors());
function genToken() {
  return crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
}
function ref(prefix) {
  const n = Math.floor(Math.random() * 9e5 + 1e5);
  return `${prefix}-${Date.now().toString().slice(-6)}${n}`;
}
async function getSessionUser(c) {
  const token = getCookie(c, "session") || c.req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.role, u.region, u.status, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) return null;
  if (row.status !== "active") return null;
  return { id: row.id, full_name: row.full_name, phone: row.phone, role: row.role, region: row.region };
}
async function requireAuth(c, next) {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  c.set("user", user);
  await next();
}
function requireRole(...roles) {
  return async (c, next) => {
    const user = c.get("user");
    if (!roles.includes(user.role)) return c.json({ error: "Forbidden" }, 403);
    await next();
  };
}
async function audit(c, userId, action, entity, detail) {
  try {
    await c.env.DB.prepare(`INSERT INTO audit_logs (user_id, action, entity, detail) VALUES (?,?,?,?)`).bind(userId, action, entity, detail).run();
  } catch (_) {
  }
}
function genPassword() {
  return String(Math.floor(1e3 + Math.random() * 9e3));
}
async function createSession(c, user) {
  const token = genToken();
  const expires = Date.now() + 1e3 * 60 * 60 * 12;
  await c.env.DB.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)`).bind(token, user.id, expires).run();
  setCookie(c, "session", token, { path: "/", httpOnly: true, maxAge: 60 * 60 * 12, sameSite: "Lax" });
  return token;
}
async function issueOtp(c, phone, purpose) {
  const code = generateOtp();
  const expires = Date.now() + 1e3 * 60 * 5;
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE phone=? AND purpose=? AND consumed=0`).bind(phone, purpose).run();
  await c.env.DB.prepare(`INSERT INTO otp_codes (phone, code, purpose, expires_at) VALUES (?,?,?,?)`).bind(phone, code, purpose, expires).run();
  const msg = `Your Farmsky verification code is ${code}. It expires in 5 minutes.`;
  const sms = await sendSms(c.env, phone, msg);
  return { sms, demo_otp: sms.simulated ? code : void 0 };
}
async function verifyOtp(c, phone, code, purpose) {
  const row = await c.env.DB.prepare(
    `SELECT * FROM otp_codes WHERE phone=? AND purpose=? AND consumed=0 ORDER BY id DESC LIMIT 1`
  ).bind(phone, purpose).first();
  if (!row) return { ok: false, error: "No active code. Request a new one." };
  if (Number(row.expires_at) < Date.now()) return { ok: false, error: "Code expired. Request a new one." };
  if (Number(row.attempts) >= 5) return { ok: false, error: "Too many attempts. Request a new code." };
  if (String(row.code) !== String(code).trim()) {
    await c.env.DB.prepare(`UPDATE otp_codes SET attempts=attempts+1 WHERE id=?`).bind(row.id).run();
    return { ok: false, error: "Incorrect code." };
  }
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE id=?`).bind(row.id).run();
  return { ok: true };
}
app.post("/api/login", async (c) => {
  const { phone, password } = await c.req.json();
  const raw2 = String(phone || "").trim();
  const norm = normalizePhone(raw2);
  let user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ?`).bind(raw2, norm).first();
  if (!user || user.password !== String(password)) return c.json({ error: "Invalid phone number or password" }, 401);
  if (user.status !== "active") return c.json({ error: "Account suspended" }, 403);
  const token = await createSession(c, user);
  await audit(c, user.id, "login", "user", `${user.role} logged in`);
  return c.json({ token, user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role, region: user.region } });
});
app.post("/api/logout", async (c) => {
  const token = getCookie(c, "session");
  if (token) await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
  deleteCookie(c, "session", { path: "/" });
  return c.json({ ok: true });
});
app.get("/api/me", requireAuth, (c) => c.json({ user: c.get("user") }));
app.get("/api/auth/status", (c) => c.json({ sms_live: smsConfigured(c.env) }));
app.post("/api/signup/request-otp", async (c) => {
  const { phone, full_name } = await c.req.json();
  const p = normalizePhone(phone || "");
  if (!p || p.length < 9) return c.json({ error: "Enter a valid phone number" }, 400);
  if (!full_name || String(full_name).trim().length < 2) return c.json({ error: "Enter your full name" }, 400);
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (existing) return c.json({ error: "An account with this phone already exists. Please sign in." }, 409);
  const { sms, demo_otp } = await issueOtp(c, p, "signup");
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || "Failed to send OTP" }, 502);
  return c.json({ ok: true, phone: p, message: sms.simulated ? "Demo mode: use the code shown below." : `OTP sent to ${p}.`, demo_otp });
});
app.post("/api/signup/verify", async (c) => {
  const { phone, full_name, code, password, region } = await c.req.json();
  const p = normalizePhone(phone || "");
  if (!password || String(password).length < 4) return c.json({ error: "Password must be at least 4 characters" }, 400);
  const v = await verifyOtp(c, p, code, "signup");
  if (!v.ok) return c.json({ error: v.error }, 400);
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (existing) return c.json({ error: "Account already exists. Please sign in." }, 409);
  const r = await c.env.DB.prepare(
    `INSERT INTO users (full_name, phone, password, role, status, region, password_set) VALUES (?,?,?, 'customer', 'active', ?, 1)`
  ).bind(String(full_name).trim(), p, String(password), region || null).run();
  const userId = r.meta.last_row_id;
  await c.env.DB.prepare(
    `INSERT INTO customers (user_id, full_name, mobile, kyc_status) VALUES (?,?,?, 'pending')`
  ).bind(userId, String(full_name).trim(), p).run();
  const user = { id: userId, full_name: String(full_name).trim(), phone: p, role: "customer", region };
  await createSession(c, user);
  await audit(c, userId, "signup", "user", "customer self-registered via SMS OTP");
  return c.json({ ok: true, user });
});
app.post("/api/reset-password/request-otp", async (c) => {
  const { phone } = await c.req.json();
  const p = normalizePhone(phone || "");
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (!user) return c.json({ ok: true, phone: p, message: "If the number is registered, an OTP has been sent." });
  const { sms, demo_otp } = await issueOtp(c, p, "reset");
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || "Failed to send OTP" }, 502);
  return c.json({ ok: true, phone: p, message: sms.simulated ? "Demo mode: use the code shown below." : `OTP sent to ${p}.`, demo_otp });
});
app.post("/api/reset-password/verify", async (c) => {
  const { phone, code, password } = await c.req.json();
  const p = normalizePhone(phone || "");
  if (!password || String(password).length < 4) return c.json({ error: "Password must be at least 4 characters" }, 400);
  const v = await verifyOtp(c, p, code, "reset");
  if (!v.ok) return c.json({ error: v.error }, 400);
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (!user) return c.json({ error: "Account not found" }, 404);
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(String(password), user.id).run();
  await audit(c, user.id, "reset_password", "user", "password reset via SMS OTP");
  return c.json({ ok: true, message: "Password updated. You can now sign in." });
});
app.get("/api/products", requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT * FROM products ORDER BY name`).all();
  const withStatus = results.map((p) => ({
    ...p,
    stock_status: p.quantity <= 0 ? "out_of_stock" : p.quantity <= p.reorder_threshold ? "low_stock" : "in_stock"
  }));
  return c.json({ products: withStatus });
});
app.post("/api/products", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const cash = Number(b.buying_price) * (1 + Number(b.cash_markup_pct) / 100);
  const credit = Number(b.buying_price) * (1 + Number(b.credit_markup_pct) / 100);
  const r = await c.env.DB.prepare(
    `INSERT INTO products (sku,name,category,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,quantity,unit,reorder_threshold,image)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    b.sku,
    b.name,
    b.category,
    b.supplier_id || null,
    b.buying_price,
    b.cash_markup_pct,
    b.credit_markup_pct,
    Math.round(cash),
    Math.round(credit),
    b.quantity || 0,
    b.unit || "unit",
    b.reorder_threshold || 10,
    b.image || null
  ).run();
  await audit(c, c.get("user").id, "create", "product", b.name);
  return c.json({ id: r.meta.last_row_id });
});
app.put("/api/products/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const b = await c.req.json();
  const cash = Number(b.buying_price) * (1 + Number(b.cash_markup_pct) / 100);
  const credit = Number(b.buying_price) * (1 + Number(b.credit_markup_pct) / 100);
  await c.env.DB.prepare(
    `UPDATE products SET sku=?, name=?, category=?, buying_price=?, cash_markup_pct=?, credit_markup_pct=?, cash_price=?, credit_price=?, quantity=?, unit=?, reorder_threshold=?, image=COALESCE(?, image) WHERE id=?`
  ).bind(
    b.sku,
    b.name,
    b.category,
    b.buying_price,
    b.cash_markup_pct,
    b.credit_markup_pct,
    Math.round(cash),
    Math.round(credit),
    b.quantity,
    b.unit,
    b.reorder_threshold,
    b.image || null,
    id
  ).run();
  await audit(c, c.get("user").id, "update", "product", b.name);
  return c.json({ ok: true });
});
app.delete("/api/products/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const used = await c.env.DB.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE product_id=?`).bind(id).first();
  if (used?.n > 0) return c.json({ error: "Cannot delete: product is referenced by existing contracts" }, 400);
  await c.env.DB.prepare(`DELETE FROM products WHERE id=?`).bind(id).run();
  await audit(c, c.get("user").id, "delete", "product", String(id));
  return c.json({ ok: true });
});
app.put("/api/products/:id/stock", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const { quantity, movement_type } = await c.req.json();
  await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id = ?`).bind(Number(quantity), id).run();
  await c.env.DB.prepare(`INSERT INTO stock_movements (product_id, movement_type, quantity, reference) VALUES (?,?,?,?)`).bind(id, movement_type || "purchase", quantity, "manual adjustment").run();
  return c.json({ ok: true });
});
app.get("/api/customers", requireAuth, async (c) => {
  const user = c.get("user");
  let query = `SELECT * FROM customers`;
  let binds = [];
  if (user.role === "agent") {
    query += ` WHERE agent_id = ?`;
    binds = [user.id];
  }
  query += ` ORDER BY created_at DESC`;
  const { results } = await c.env.DB.prepare(query).bind(...binds).all();
  return c.json({ customers: results });
});
app.get("/api/customers/:id", requireAuth, async (c) => {
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(c.req.param("id")).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  const tu = await c.env.DB.prepare(`SELECT * FROM transunion_checks WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param("id")).first();
  const idv = await c.env.DB.prepare(`SELECT * FROM id_verifications WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param("id")).first();
  return c.json({ customer: cust, transunion: tu, id_verification: idv });
});
app.post("/api/customers", requireAuth, requireRole("agent", "admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const user = c.get("user");
  const r = await c.env.DB.prepare(
    `INSERT INTO customers (agent_id,full_name,national_id,date_of_birth,gender,mobile,alt_mobile,county,sub_county,ward,village,latitude,longitude,value_chain_type,value_chain,acreage,herd_size,farm_experience,mobile_money_usage,existing_loans,bank_account,sacco_membership,kyc_status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')`
  ).bind(
    user.role === "agent" ? user.id : b.agent_id || user.id,
    b.full_name,
    b.national_id,
    b.date_of_birth,
    b.gender,
    b.mobile,
    b.alt_mobile,
    b.county,
    b.sub_county,
    b.ward,
    b.village,
    b.latitude || null,
    b.longitude || null,
    b.value_chain_type,
    b.value_chain,
    b.acreage || null,
    b.herd_size || null,
    b.farm_experience || null,
    b.mobile_money_usage,
    b.existing_loans,
    b.bank_account,
    b.sacco_membership
  ).run();
  await audit(c, user.id, "onboard", "customer", b.full_name);
  return c.json({ id: r.meta.last_row_id });
});
app.post("/api/customers/:id/verify", requireAuth, async (c) => {
  const id = c.req.param("id");
  const user = c.get("user");
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  if (!["admin", "super_admin", "agent"].includes(user.role)) {
    if (!(user.role === "customer" && cust.user_id === user.id)) return c.json({ error: "Forbidden" }, 403);
  }
  const score = Math.floor(Math.random() * 350 + 450);
  const band = score >= 700 ? "low" : score >= 600 ? "medium" : "high";
  await c.env.DB.prepare(`INSERT INTO transunion_checks (customer_id,credit_score,risk_band,defaults_found,raw_response) VALUES (?,?,?,?,?)`).bind(id, score, band, band === "high" ? 1 : 0, JSON.stringify({ score, band })).run();
  await c.env.DB.prepare(`INSERT INTO id_verifications (customer_id,face_match,liveness,ocr_name,ocr_dob,ocr_id_number,status) VALUES (?,?,?,?,?,?, 'verified')`).bind(id, 1, 1, cust.full_name, cust.date_of_birth, cust.national_id).run();
  await c.env.DB.prepare(`UPDATE customers SET kyc_status='verified', risk_band=?, credit_score=? WHERE id=?`).bind(band, score, id).run();
  await audit(c, user.id, "verify", "customer", `KYC verified for ${cust.full_name}`);
  return c.json({ ok: true, credit_score: score, risk_band: band, face_match: true, liveness: true });
});
app.post("/api/murabaha/quote", requireAuth, async (c) => {
  const { product_id, quantity, payment_type, term_months } = await c.req.json();
  const p = await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first();
  if (!p) return c.json({ error: "Product not found" }, 404);
  const qty = Number(quantity) || 1;
  const supplier_cost = p.buying_price * qty;
  const markup_pct = payment_type === "cash" ? p.cash_markup_pct : p.credit_markup_pct;
  const unit_price = payment_type === "cash" ? p.cash_price : p.credit_price;
  const murabaha_price = unit_price * qty;
  const term = payment_type === "credit" ? Number(term_months) || 6 : 0;
  const monthly = term > 0 ? Math.round(murabaha_price / term) : 0;
  return c.json({
    product: p.name,
    quantity: qty,
    supplier_cost,
    markup_pct,
    murabaha_price,
    term_months: term,
    monthly_payment: monthly,
    sharia_note: "Price becomes FIXED once the contract is signed. No interest, penalties, or compounding."
  });
});
app.post("/api/murabaha/apply", requireAuth, async (c) => {
  const user = c.get("user");
  const { customer_id, product_id, quantity, payment_type, term_months, delivery_location, consent } = await c.req.json();
  if (!consent) return c.json({ error: "Customer consent is required (Sharia requirement)" }, 400);
  const p = await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first();
  if (!p) return c.json({ error: "Product not found" }, 404);
  const qty = Number(quantity) || 1;
  if (p.quantity < qty) return c.json({ error: "Insufficient stock" }, 400);
  let custId = customer_id;
  if (user.role === "customer") {
    const myCust = await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first();
    if (!myCust) return c.json({ error: "Customer profile not found" }, 404);
    custId = myCust.id;
  }
  const custRow = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first();
  if (payment_type === "credit" && custRow?.kyc_status !== "verified") {
    return c.json({
      error: "kyc_required",
      message: "Complete user registration (TransUnion credit check + liveness/ID verification) is required before Pay Later (Murabaha Financing) purchases.",
      customer_id: custId
    }, 412);
  }
  const supplier_cost = p.buying_price * qty;
  const markup_pct = payment_type === "cash" ? p.cash_markup_pct : p.credit_markup_pct;
  const unit_price = payment_type === "cash" ? p.cash_price : p.credit_price;
  const murabaha_price = unit_price * qty;
  const term = payment_type === "credit" ? Number(term_months) || 6 : 0;
  const monthly = term > 0 ? Math.round(murabaha_price / term) : 0;
  const contractRef = ref("MRB");
  const status = payment_type === "cash" ? "pending_payment" : "pending";
  const r = await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    contractRef,
    custId,
    custRow?.agent_id || null,
    product_id,
    qty,
    payment_type,
    supplier_cost,
    markup_pct,
    murabaha_price,
    term,
    monthly,
    delivery_location || "",
    status,
    0,
    1,
    0,
    murabaha_price
  ).run();
  const contractId = r.meta.last_row_id;
  await audit(c, user.id, "apply", "murabaha", `${payment_type} ${contractRef}`);
  return c.json({
    id: contractId,
    contract_ref: contractRef,
    status,
    murabaha_price,
    monthly_payment: monthly,
    requires_payment: payment_type === "cash",
    outstanding: murabaha_price,
    payment_type
  });
});
app.get("/api/murabaha", requireAuth, async (c) => {
  const user = c.get("user");
  let q = `SELECT mc.*, p.name as product_name, cu.full_name as customer_name
           FROM murabaha_contracts mc JOIN products p ON p.id = mc.product_id JOIN customers cu ON cu.id = mc.customer_id`;
  const binds = [];
  if (user.role === "agent") {
    q += ` WHERE mc.agent_id = ?`;
    binds.push(user.id);
  } else if (user.role === "customer") {
    const myCust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first();
    q += ` WHERE mc.customer_id = ?`;
    binds.push(myCust?.id || -1);
  }
  q += ` ORDER BY mc.created_at DESC`;
  const { results } = await c.env.DB.prepare(q).bind(...binds).all();
  return c.json({ contracts: results });
});
app.get("/api/murabaha/:id", requireAuth, async (c) => {
  const id = c.req.param("id");
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name as product_name, p.unit, cu.full_name as customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first();
  if (!contract) return c.json({ error: "Not found" }, 404);
  const { results: repayments } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? ORDER BY installment_no`).bind(id).all();
  const { results: txns } = await c.env.DB.prepare(`SELECT * FROM transactions WHERE contract_id=? ORDER BY id`).bind(id).all();
  return c.json({ contract, repayments, transactions: txns });
});
app.post("/api/murabaha/:id/decision", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const { action, notes } = await c.req.json();
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first();
  if (!contract) return c.json({ error: "Not found" }, 404);
  if (contract.status !== "pending") return c.json({ error: "Contract is not pending" }, 400);
  await c.env.DB.prepare(`INSERT INTO approvals (contract_id,reviewer_id,action,notes) VALUES (?,?,?,?)`).bind(id, c.get("user").id, action, notes || "").run();
  if (action === "approve") {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='active', ownership_recorded=1 WHERE id=?`).bind(id).run();
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run();
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, "credit_allocation", contract.quantity, contract.contract_ref).run();
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'unpaid')`).bind(ref("INV"), id, contract.customer_id, contract.murabaha_price).run();
    const term = contract.term_months, monthly = contract.monthly_payment, start = /* @__PURE__ */ new Date();
    for (let i = 1; i <= term; i++) {
      const due = new Date(start.getFullYear(), start.getMonth() + i, 1);
      const amount = i === term ? contract.murabaha_price - monthly * (term - 1) : monthly;
      await c.env.DB.prepare(`INSERT INTO repayments (contract_id,installment_no,due_date,amount_due,status) VALUES (?,?,?,?, 'current')`).bind(id, i, due.toISOString().slice(0, 10), amount).run();
    }
  } else if (action === "reject") {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='rejected' WHERE id=?`).bind(id).run();
  }
  await audit(c, c.get("user").id, action, "murabaha", contract.contract_ref);
  return c.json({ ok: true, action });
});
async function applyPayment(c, contract, amt, receipt, method, phone) {
  const isCashCheckout = contract.payment_type === "cash" && contract.status === "pending_payment";
  if (isCashCheckout) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run();
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, "sale", contract.quantity, contract.contract_ref).run();
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'paid')`).bind(ref("INV"), contract.id, contract.customer_id, contract.murabaha_price).run();
    await c.env.DB.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`).bind(ref("TXN"), contract.id, contract.customer_id, amt, method, "cash_sale", receipt, phone).run();
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=0, status='completed', ownership_recorded=1 WHERE id=?`).bind(amt, contract.id).run();
    return { amount_paid: amt, outstanding: 0, status: "completed" };
  }
  await c.env.DB.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`).bind(ref("TXN"), contract.id, contract.customer_id, amt, method, "repayment", receipt, phone).run();
  const newPaid = contract.amount_paid + amt;
  const newOutstanding = Math.max(0, contract.murabaha_price - newPaid);
  const status = newOutstanding <= 0 ? "completed" : "active";
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=?, status=? WHERE id=?`).bind(newPaid, newOutstanding, status, contract.id).run();
  let remaining = amt;
  const { results: due } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? AND status!='completed' ORDER BY installment_no`).bind(contract.id).all();
  for (const inst of due) {
    if (remaining <= 0) break;
    const need = inst.amount_due - inst.amount_paid;
    const pay = Math.min(need, remaining);
    const paidTotal = inst.amount_paid + pay;
    const st = paidTotal >= inst.amount_due ? "completed" : "current";
    await c.env.DB.prepare(`UPDATE repayments SET amount_paid=?, status=?, paid_at=CURRENT_TIMESTAMP WHERE id=?`).bind(paidTotal, st, inst.id).run();
    remaining -= pay;
  }
  await c.env.DB.prepare(`UPDATE invoices SET status=? WHERE contract_id=?`).bind(newOutstanding <= 0 ? "paid" : "partial", contract.id).run();
  return { amount_paid: newPaid, outstanding: newOutstanding, status };
}
app.post("/api/mpesa/stkpush", requireAuth, async (c) => {
  const { contract_id, amount, phone } = await c.req.json();
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first();
  if (!contract) return c.json({ error: "Contract not found" }, 404);
  if (contract.payment_type === "cash" && contract.status === "pending_payment") {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first();
    if (!p || p.quantity < contract.quantity) return c.json({ error: "This item is now out of stock." }, 409);
  } else if (contract.payment_type !== "cash" && contract.status !== "active") {
    return c.json({ error: "This contract is not open for payment." }, 400);
  }
  const amt = Number(amount);
  if (amt <= 0) return c.json({ error: "Invalid amount" }, 400);
  const desc = contract.payment_type === "cash" ? "Cash Sale" : "Murabaha";
  const result = await stkPush(c.env, { phone: phone || c.get("user").phone, amount: amt, account: contract.contract_ref, description: desc });
  if (!result.success) return c.json({ error: result.error || "STK push failed" }, 502);
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`).bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(phone || c.get("user").phone), "mpesa").run();
  await audit(c, c.get("user").id, "stk_push", "mpesa", `KES ${amt} to ${contract.contract_ref} (${result.simulated ? "sim" : "live"})`);
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message });
});
app.post("/api/mpesa/confirm", requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json();
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") return c.json({ ok: true, status: "success", mpesa_receipt: intent.mpesa_receipt });
  let success = false, receipt = "";
  if (!mpesaConfigured(c.env) || String(checkout_request_id).includes("SIM")) {
    success = true;
    receipt = "SLE" + Math.random().toString(36).slice(2, 9).toUpperCase();
  } else {
    const q = await stkQuery(c.env, checkout_request_id);
    if (q.ResultCode === "0" || q.ResultCode === 0) {
      success = true;
      receipt = "LIVE" + Date.now().toString().slice(-7);
    } else if (q.ResultCode) return c.json({ ok: false, status: "failed", result_desc: q.ResultDesc || "Payment not completed" });
    else return c.json({ ok: false, status: "pending" });
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
    const res = await applyPayment(c, contract, intent.amount, receipt, "mpesa", intent.phone);
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run();
    return c.json({ ok: true, status: "success", mpesa_receipt: receipt, ...res });
  }
  return c.json({ ok: false, status: "pending" });
});
app.post("/api/mpesa/callback", async (c) => {
  try {
    const body = await c.req.json();
    const cb = body?.Body?.stkCallback;
    if (!cb) return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
    const checkout = cb.CheckoutRequestID;
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first();
    if (intent && intent.status === "pending") {
      if (cb.ResultCode === 0) {
        const items = cb.CallbackMetadata?.Item || [];
        const receiptItem = items.find((i) => i.Name === "MpesaReceiptNumber");
        const receipt = receiptItem?.Value || "LIVE" + Date.now();
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), "mpesa", intent.phone);
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), cb.ResultDesc || "", checkout).run();
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(cb.ResultDesc || "Failed", checkout).run();
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch (e) {
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  }
});
app.get("/api/mpesa/status", requireAuth, (c) => {
  return c.json({ live: mpesaConfigured(c.env), mode: mpesaConfigured(c.env) ? c.env.MPESA_ENV || "sandbox" : "simulation" });
});
app.get("/api/dashboard", requireAuth, async (c) => {
  const user = c.get("user"), db = c.env.DB;
  if (user.role === "customer") {
    const myCust = await db.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first();
    const cid = myCust?.id || -1;
    const contracts = await db.prepare(`SELECT COUNT(*) n, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE customer_id=? AND status='active'`).bind(cid).first();
    const completed = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE customer_id=? AND status='completed'`).bind(cid).first();
    const nextDue = await db.prepare(`SELECT r.* FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.customer_id=? AND r.status!='completed' ORDER BY r.due_date LIMIT 1`).bind(cid).first();
    return c.json({ role: "customer", active_contracts: contracts?.n || 0, total_outstanding: contracts?.out || 0, completed_contracts: completed?.n || 0, next_payment: nextDue || null });
  }
  if (user.role === "agent") {
    const cust = await db.prepare(`SELECT COUNT(*) n FROM customers WHERE agent_id=?`).bind(user.id).first();
    const active = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE agent_id=? AND status='active'`).bind(user.id).first();
    const pending2 = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE agent_id=? AND status='pending'`).bind(user.id).first();
    const portfolio = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE agent_id=?`).bind(user.id).first();
    const late = await db.prepare(`SELECT COUNT(*) n FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.agent_id=? AND r.status='late'`).bind(user.id).first();
    const par = portfolio?.tot ? Math.round(portfolio.out / portfolio.tot * 100) : 0;
    return c.json({ role: "agent", customers_onboarded: cust?.n || 0, active_contracts: active?.n || 0, pending_approvals: pending2?.n || 0, portfolio_value: portfolio?.tot || 0, portfolio_at_risk: par, late_installments: late?.n || 0, commission: Math.round((portfolio?.tot || 0) * 0.025) });
  }
  const sales = await db.prepare(`SELECT COALESCE(SUM(amount),0) tot FROM transactions WHERE status='success'`).first();
  const financed = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='credit'`).first();
  const cashSales = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='cash'`).first();
  const activeCust = await db.prepare(`SELECT COUNT(*) n FROM customers`).first();
  const invValue = await db.prepare(`SELECT COALESCE(SUM(buying_price*quantity),0) tot FROM products`).first();
  const totalRepay = await db.prepare(`SELECT COUNT(*) n FROM repayments`).first();
  const completedRepay = await db.prepare(`SELECT COUNT(*) n FROM repayments WHERE status='completed'`).first();
  const defaulted = await db.prepare(`SELECT COUNT(*) n FROM repayments WHERE status='defaulted'`).first();
  const pending = await db.prepare(`SELECT COUNT(*) n FROM murabaha_contracts WHERE status='pending'`).first();
  const repayRate = totalRepay?.n ? Math.round(completedRepay.n / totalRepay.n * 100) : 0;
  const defaultRate = totalRepay?.n ? Math.round(defaulted.n / totalRepay.n * 100) : 0;
  const { results: topProducts } = await db.prepare(`SELECT p.name, COUNT(mc.id) sales FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id GROUP BY p.id ORDER BY sales DESC LIMIT 5`).all();
  return c.json({ role: "admin", total_sales: sales?.tot || 0, murabaha_financed: financed?.tot || 0, cash_sales: cashSales?.tot || 0, repayment_rate: repayRate, default_rate: defaultRate, inventory_value: invValue?.tot || 0, active_customers: activeCust?.n || 0, pending_approvals: pending?.n || 0, top_products: topProducts });
});
app.get("/api/agents", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.region, u.status,
     (SELECT COUNT(*) FROM customers WHERE agent_id=u.id) customers,
     (SELECT COUNT(*) FROM murabaha_contracts WHERE agent_id=u.id AND status='active') active
     FROM users u WHERE u.role='agent'`
  ).all();
  return c.json({ agents: results });
});
app.post("/api/agents", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const p = normalizePhone(b.phone || "");
  if (!b.full_name || !p) return c.json({ error: "Name and phone are required" }, 400);
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (dup) return c.json({ error: "A user with this phone already exists" }, 409);
  const provided = b.password && String(b.password).length >= 4;
  const pwd = provided ? String(b.password) : genPassword();
  const r = await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set) VALUES (?,?,?,?, 'agent', ?, ?)`).bind(b.full_name, p, b.email || null, pwd, b.region || null, provided ? 1 : 0).run();
  await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(b.permissions || {})).run();
  await audit(c, c.get("user").id, "create", "agent", b.full_name);
  return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: provided });
});
app.post("/api/users/:id/reset-password", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const target = await c.env.DB.prepare(`SELECT id, full_name, role FROM users WHERE id=?`).bind(id).first();
  if (!target) return c.json({ error: "User not found" }, 404);
  if (target.role === "super_admin" && Number(id) !== c.get("user").id) {
    return c.json({ error: "Cannot reset another Super Admin password" }, 400);
  }
  const body = await c.req.json().catch(() => ({}));
  const provided = body?.password && String(body.password).length >= 4;
  const pwd = provided ? String(body.password) : genPassword();
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(pwd, id).run();
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run();
  await audit(c, c.get("user").id, "reset_password", target.role, target.full_name);
  return c.json({ ok: true, new_password: pwd, user: target.full_name });
});
app.put("/api/agents/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const b = await c.req.json();
  await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, region=? WHERE id=? AND role='agent'`).bind(b.full_name, b.phone, b.email, b.region, id).run();
  if (b.permissions) await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region, JSON.stringify(b.permissions), id).run();
  await audit(c, c.get("user").id, "update", "agent", b.full_name);
  return c.json({ ok: true });
});
app.get("/api/users", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT id, full_name, phone, email, role, status, region, created_at FROM users ORDER BY id`).all();
  return c.json({ users: results });
});
app.put("/api/users/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const b = await c.req.json();
  if (b.password) {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, region=?, password=? WHERE id=?`).bind(b.full_name, b.phone, b.email, b.role, b.region, String(b.password), id).run();
  } else {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, region=? WHERE id=?`).bind(b.full_name, b.phone, b.email, b.role, b.region, id).run();
  }
  await audit(c, c.get("user").id, "update", "user", b.full_name);
  return c.json({ ok: true });
});
app.put("/api/users/:id/status", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const { status } = await c.req.json();
  if (Number(id) === c.get("user").id) return c.json({ error: "You cannot change your own status" }, 400);
  await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, id).run();
  if (status === "suspended") await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run();
  await audit(c, c.get("user").id, status === "active" ? "activate" : "deactivate", "user", String(id));
  return c.json({ ok: true });
});
app.delete("/api/users/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  if (Number(id) === c.get("user").id) return c.json({ error: "You cannot delete your own account" }, 400);
  const u = await c.env.DB.prepare(`SELECT role FROM users WHERE id=?`).bind(id).first();
  if (u?.role === "super_admin") return c.json({ error: "Cannot delete a Super Admin account" }, 400);
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run();
  await c.env.DB.prepare(`DELETE FROM agents WHERE user_id=?`).bind(id).run();
  await c.env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id).run();
  await audit(c, c.get("user").id, "delete", "user", String(id));
  return c.json({ ok: true });
});
app.get("/api/repayments", requireAuth, requireRole("admin", "super_admin", "support"), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT r.*, mc.contract_ref, cu.full_name customer FROM repayments r
     JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id ORDER BY r.due_date`
  ).all();
  return c.json({ repayments: results });
});
app.get("/api/documents/:type/:id", requireAuth, async (c) => {
  const type = c.req.param("type"), id = c.req.param("id");
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name product_name, cu.full_name customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first();
  if (!contract) return c.json({ error: "Not found" }, 404);
  return c.json({ type, contract, txn_id: contract.contract_ref, qr: `https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${contract.contract_ref}` });
});
var EXPORT_DATASETS = {
  users: {
    label: "Users / Accounts",
    sql: `SELECT id, full_name, phone, email, role, status, region, created_at FROM users`,
    cols: ["id", "full_name", "phone", "email", "role", "status", "region", "created_at"],
    filterable: { role: "role", status: "status", region: "region" }
  },
  customers: {
    label: "Customers / Farmers",
    sql: `SELECT cu.id, cu.full_name, cu.mobile, cu.county, cu.value_chain, cu.kyc_status, cu.risk_band, cu.credit_score, u.full_name agent FROM customers cu LEFT JOIN users u ON u.id=cu.agent_id`,
    cols: ["id", "full_name", "mobile", "county", "value_chain", "kyc_status", "risk_band", "credit_score", "agent"],
    filterable: { kyc_status: "cu.kyc_status", risk_band: "cu.risk_band", county: "cu.county" }
  },
  agents: {
    label: "Agents",
    sql: `SELECT id, full_name, phone, email, region, status, created_at FROM users WHERE role='agent'`,
    cols: ["id", "full_name", "phone", "email", "region", "status", "created_at"],
    filterable: { status: "status", region: "region" }
  },
  products: {
    label: "Inventory / Products",
    sql: `SELECT id, sku, name, category, buying_price, cash_price, credit_price, quantity, unit, reorder_threshold FROM products`,
    cols: ["id", "sku", "name", "category", "buying_price", "cash_price", "credit_price", "quantity", "unit", "reorder_threshold"],
    filterable: { category: "category" }
  },
  contracts: {
    label: "Murabaha Contracts",
    sql: `SELECT mc.id, mc.contract_ref, cu.full_name customer, p.name product, mc.payment_type, mc.murabaha_price, mc.amount_paid, mc.outstanding, mc.status, mc.created_at FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id JOIN products p ON p.id=mc.product_id`,
    cols: ["id", "contract_ref", "customer", "product", "payment_type", "murabaha_price", "amount_paid", "outstanding", "status", "created_at"],
    filterable: { status: "mc.status", payment_type: "mc.payment_type" }
  },
  repayments: {
    label: "Repayments",
    sql: `SELECT r.id, mc.contract_ref, cu.full_name customer, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id`,
    cols: ["id", "contract_ref", "customer", "installment_no", "due_date", "amount_due", "amount_paid", "status"],
    filterable: { status: "r.status" }
  },
  transactions: {
    label: "Transactions / Payments",
    sql: `SELECT t.id, t.txn_ref, cu.full_name customer, t.amount, t.method, t.type, t.mpesa_receipt, t.status, t.created_at FROM transactions t LEFT JOIN customers cu ON cu.id=t.customer_id`,
    cols: ["id", "txn_ref", "customer", "amount", "method", "type", "mpesa_receipt", "status", "created_at"],
    filterable: { status: "t.status", method: "t.method", type: "t.type" }
  },
  audit_logs: {
    label: "Audit Log",
    sql: `SELECT a.id, u.full_name actor, a.action, a.entity, a.detail, a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id`,
    cols: ["id", "actor", "action", "entity", "detail", "created_at"],
    filterable: { action: "a.action", entity: "a.entity" }
  }
};
async function buildExport(c, dataset, filters, dateFrom, dateTo) {
  const def = EXPORT_DATASETS[dataset];
  if (!def) throw new Error("Unknown dataset");
  const where = [];
  const binds = [];
  const hasWhere = /\bwhere\b/i.test(def.sql);
  for (const [key, col] of Object.entries(def.filterable)) {
    const v = filters?.[key];
    if (v != null && String(v).trim() !== "" && String(v) !== "all") {
      where.push(`${col} = ?`);
      binds.push(v);
    }
  }
  const dateCol = def.cols.includes("created_at") ? "created_at" : def.cols.includes("due_date") ? "due_date" : null;
  if (dateCol && dateFrom) {
    where.push(`${dateCol} >= ?`);
    binds.push(dateFrom);
  }
  if (dateCol && dateTo) {
    where.push(`${dateCol} <= ?`);
    binds.push(dateTo + " 23:59:59");
  }
  let sql = def.sql;
  if (where.length) sql += (hasWhere ? " AND " : " WHERE ") + where.join(" AND ");
  sql += ` ORDER BY 1 DESC`;
  const stmt = binds.length ? c.env.DB.prepare(sql).bind(...binds) : c.env.DB.prepare(sql);
  const { results } = await stmt.all();
  return { label: def.label, cols: def.cols, rows: results || [] };
}
function base64Utf8(s) {
  if (typeof Buffer !== "undefined") return Buffer.from(s, "utf8").toString("base64");
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function toCsv(cols, rows) {
  const esc = (v) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const head = cols.map(esc).join(",");
  const body = rows.map((r) => cols.map((cKey) => esc(r[cKey])).join(",")).join("\n");
  return head + "\n" + body;
}
app.get("/api/export/datasets", requireAuth, requireRole("admin", "super_admin"), (c) => {
  const list = Object.entries(EXPORT_DATASETS).map(([key, d]) => ({ key, label: d.label, filters: Object.keys(d.filterable), cols: d.cols }));
  return c.json({ datasets: list, email_configured: emailConfigured(c.env) });
});
app.post("/api/export/data", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { dataset, filters, date_from, date_to } = await c.req.json();
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to);
    await audit(c, c.get("user").id, "export", dataset, `${out.rows.length} rows`);
    return c.json({ ok: true, ...out });
  } catch (e) {
    return c.json({ error: e.message || "Export failed" }, 400);
  }
});
app.post("/api/export/email", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { dataset, filters, date_from, date_to, to, format } = await c.req.json();
  if (!to || !/.+@.+\..+/.test(String(to))) return c.json({ error: "Enter a valid recipient email" }, 400);
  if (!emailConfigured(c.env)) {
    return c.json({ error: "email_not_configured", message: "Email provider not configured. Use the Download button instead, or set EMAIL_API_URL/TOKEN/FROM at deploy." }, 412);
  }
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to);
    const csv = toCsv(out.cols, out.rows);
    const b642 = base64Utf8(csv);
    const fname = `farmsky-${dataset}-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.csv`;
    const r = await sendEmail(c.env, {
      to,
      subject: `Farmsky export \u2014 ${out.label} (${out.rows.length} rows)`,
      text: `Attached is the ${out.label} export you requested from Farmsky (${out.rows.length} rows).`,
      attachments: [{ filename: fname, contentBase64: b642, contentType: "text/csv" }]
    });
    if (!r.success) return c.json({ error: r.error || "Email send failed" }, 502);
    await audit(c, c.get("user").id, "export_email", dataset, `to ${to}`);
    return c.json({ ok: true, message: `Export emailed to ${to}` });
  } catch (e) {
    return c.json({ error: e.message || "Export failed" }, 400);
  }
});
app.get("/", (c) => c.html(SHELL));
var SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky \u2014 Sharia-Compliant Agri-Finance</title>
  <link rel="icon" type="image/png" href="/static/favicon.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <link href="/static/style.css" rel="stylesheet">
</head>
<body class="bg-slate-100 text-slate-800">
  <div id="app"></div>
  <script src="/static/app.js"></script>
</body>
</html>`;
var index_default = app;

// src/db-sqlite.ts
import Database from "better-sqlite3";
var SqliteStatement = class {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
  }
  params = [];
  bind(...args) {
    this.params = args;
    return this;
  }
  async first() {
    const stmt = this.db.prepare(this.sql);
    const row = stmt.get(...this.params);
    return row ?? null;
  }
  async all() {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt.all(...this.params);
    return { results: rows, success: true };
  }
  async run() {
    const stmt = this.db.prepare(this.sql);
    const info = stmt.run(...this.params);
    return {
      success: true,
      meta: {
        last_row_id: Number(info.lastInsertRowid),
        changes: info.changes
      }
    };
  }
};
var SqliteD1 = class {
  constructor(db) {
    this.db = db;
  }
  prepare(sql) {
    return new SqliteStatement(this.db, sql);
  }
  exec(sql) {
    return this.db.exec(sql);
  }
};
function openDatabase(filePath) {
  const raw2 = new Database(filePath);
  raw2.pragma("journal_mode = WAL");
  raw2.pragma("foreign_keys = ON");
  return { d1: new SqliteD1(raw2), raw: raw2 };
}

// src/db-init.ts
import { readFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
function applySqlFile(raw2, file) {
  const sql = readFileSync(file, "utf8");
  raw2.exec(sql);
}
function initializeDatabase(raw2, projectRoot) {
  const hasUsers = raw2.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
  const migrationsDir = join(projectRoot, "migrations");
  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort();
    for (const f of files) {
      try {
        applySqlFile(raw2, join(migrationsDir, f));
      } catch (e) {
        if (!/already exists|duplicate column/i.test(String(e.message))) {
          console.error(`Migration ${f} error:`, e.message);
        }
      }
    }
  }
  if (!hasUsers) {
    const seedFile = join(projectRoot, "seed.sql");
    if (existsSync(seedFile)) {
      try {
        applySqlFile(raw2, seedFile);
        console.log("Seed data loaded.");
      } catch (e) {
        console.error("Seed error:", e.message);
      }
    }
  }
}
function ensureDir(filePath) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

// src/server.ts
import { Hono as Hono2 } from "hono";
var __dirname = dirname2(fileURLToPath(import.meta.url));
var PROJECT_ROOT = join2(__dirname, "..");
var DB_FILE = process.env.DATABASE_PATH || join2(PROJECT_ROOT, "data", "farmsky.db");
ensureDir(DB_FILE);
var { d1, raw } = openDatabase(DB_FILE);
initializeDatabase(raw, PROJECT_ROOT);
console.log(`Database ready at: ${DB_FILE}`);
var ENV = {
  DB: d1,
  MPESA_CONSUMER_KEY: process.env.MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET: process.env.MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE: process.env.MPESA_SHORTCODE,
  MPESA_PASSKEY: process.env.MPESA_PASSKEY,
  MPESA_ENV: process.env.MPESA_ENV,
  MPESA_CALLBACK_URL: process.env.MPESA_CALLBACK_URL,
  // SMS OTP provider (TalkSASA by default)
  SMS_PROVIDER: process.env.SMS_PROVIDER,
  SMS_API_URL: process.env.SMS_API_URL,
  SMS_API_TOKEN: process.env.SMS_API_TOKEN,
  SMS_SENDER_ID: process.env.SMS_SENDER_ID,
  SMS_BODY_TEMPLATE: process.env.SMS_BODY_TEMPLATE,
  SMS_PHONE_FIELD: process.env.SMS_PHONE_FIELD,
  SMS_MESSAGE_FIELD: process.env.SMS_MESSAGE_FIELD,
  // Email provider (export sharing) — Resend by default
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  EMAIL_API_URL: process.env.EMAIL_API_URL,
  EMAIL_API_TOKEN: process.env.EMAIL_API_TOKEN,
  EMAIL_FROM: process.env.EMAIL_FROM
};
var root = new Hono2();
root.use("/static/*", serveStatic({ root: "./public" }));
root.all("*", (c) => index_default.fetch(c.req.raw, ENV));
var PORT = Number(process.env.PORT || 8080);
serve({ fetch: root.fetch, port: PORT }, (info) => {
  console.log(`Farmsky server running on http://0.0.0.0:${info.port}`);
  console.log(
    process.env.MPESA_CONSUMER_KEY ? "M-Pesa: LIVE credentials detected (Daraja " + (process.env.MPESA_ENV || "sandbox") + ")" : "M-Pesa: SIMULATION mode (no Daraja credentials set). See .env.example."
  );
});
