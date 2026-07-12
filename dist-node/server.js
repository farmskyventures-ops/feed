import{createRequire}from'module';const require=createRequire(import.meta.url);
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// backend/payments-shared.ts
var payments_shared_exports = {};
__export(payments_shared_exports, {
  canonicalString: () => canonicalString,
  hmacSha256Hex: () => hmacSha256Hex,
  signRequest: () => signRequest,
  verifySignature: () => verifySignature
});
async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function canonicalString(client_key, timestamp2, nonce, body) {
  return `${client_key}
${timestamp2}
${nonce}
${body}`;
}
async function signRequest(secret, client_key, body) {
  const timestamp2 = String(Date.now());
  const nonce = crypto.randomUUID();
  const signature = await hmacSha256Hex(secret, canonicalString(client_key, timestamp2, nonce, body));
  return { timestamp: timestamp2, nonce, signature };
}
async function verifySignature(secret, client_key, timestamp2, nonce, body, providedSignature, maxSkewMs = 5 * 60 * 1e3) {
  if (!secret || !client_key || !timestamp2 || !nonce || !providedSignature) {
    return { ok: false, error: "Missing signature material" };
  }
  const ts = Number(timestamp2);
  if (!Number.isFinite(ts)) return { ok: false, error: "Invalid timestamp" };
  if (Math.abs(Date.now() - ts) > maxSkewMs) return { ok: false, error: "Request timestamp outside allowed window" };
  const expected = await hmacSha256Hex(secret, canonicalString(client_key, timestamp2, nonce, body));
  if (expected.length !== providedSignature.length) return { ok: false, error: "Signature mismatch" };
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ providedSignature.charCodeAt(i);
  }
  if (diff !== 0) return { ok: false, error: "Signature mismatch" };
  return { ok: true };
}
var encoder;
var init_payments_shared = __esm({
  "backend/payments-shared.ts"() {
    "use strict";
    encoder = new TextEncoder();
  }
});

// backend/server.ts
import "dotenv/config";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { fileURLToPath } from "node:url";
import { dirname, join as join2 } from "node:path";
import { Hono as Hono3 } from "hono";

// backend/index.tsx
import { Hono as Hono2 } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";

// backend/mpesa.ts
import { env } from "hono/adapter";
var SANDBOX_BASE = "https://sandbox.safaricom.co.ke";
var PROD_BASE = "https://api.safaricom.co.ke";
function mpesaConfigured(env2) {
  return !!(env2.MPESA_CONSUMER_KEY && env2.MPESA_CONSUMER_SECRET && env2.MPESA_SHORTCODE && env2.MPESA_PASSKEY);
}
function isSandbox(envValue) {
  const v = String(envValue || "").trim().toLowerCase();
  return v === "sandbox" || v === "development" || v === "dev" || v === "test";
}
function baseUrl(env2) {
  return isSandbox(env2.MPESA_ENV) ? SANDBOX_BASE : PROD_BASE;
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
async function getToken(env2) {
  const auth = b64(`${env2.MPESA_CONSUMER_KEY}:${env2.MPESA_CONSUMER_SECRET}`);
  const res = await fetch(`${baseUrl(env2)}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  });
  if (!res.ok) throw new Error("Failed to obtain M-Pesa token: " + res.status);
  const data = await res.json();
  return data.access_token;
}
async function stkPush(env2, opts) {
  if (!mpesaConfigured(env2)) {
    console.log("DEBUG: mpesaConfigured returned FALSE. Simulation mode active.");
    return {
      simulated: true,
      success: true,
      checkout_request_id: "ws_CO_SIM_" + crypto.randomUUID().slice(0, 12),
      merchant_request_id: "SIM_" + crypto.randomUUID().slice(0, 8),
      customer_message: "Simulated STK push sent. (Credentials not detected.)"
    };
  }
  try {
    const token = await getToken(env2);
    const ts = timestamp();
    const password = b64(`${env2.MPESA_SHORTCODE}${env2.MPESA_PASSKEY}${ts}`);
    const phone = normalizePhone(opts.phone);
    const body = {
      BusinessShortCode: env2.MPESA_SHORTCODE,
      Password: password,
      Timestamp: ts,
      TransactionType: "CustomerPayBillOnline",
      Amount: Math.max(1, Math.round(opts.amount)),
      PartyA: phone,
      PartyB: env2.MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: env2.MPESA_CALLBACK_URL || "https://example.com/api/mpesa/callback",
      AccountReference: opts.account.slice(0, 12),
      TransactionDesc: opts.description.slice(0, 13)
    };
    const res = await fetch(`${baseUrl(env2)}/mpesa/stkpush/v1/processrequest`, {
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
        customer_message: data.CustomerMessage || "STK push sent."
      };
    }
    return { simulated: false, success: false, error: data.errorMessage || data.ResponseDescription || "STK push failed" };
  } catch (e) {
    return { simulated: false, success: false, error: e.message || "M-Pesa request failed" };
  }
}
async function stkQuery(env2, checkoutRequestId) {
  if (!mpesaConfigured(env2)) return { ResultCode: "0", ResultDesc: "Simulated success" };
  const token = await getToken(env2);
  const ts = timestamp();
  const password = b64(`${env2.MPESA_SHORTCODE}${env2.MPESA_PASSKEY}${ts}`);
  const res = await fetch(`${baseUrl(env2)}/mpesa/stkpushquery/v1/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ BusinessShortCode: env2.MPESA_SHORTCODE, Password: password, Timestamp: ts, CheckoutRequestID: checkoutRequestId })
  });
  return await res.json();
}

// backend/sasapay.ts
var SASAPAY_CHANNELS = [
  { code: "0", name: "SasaPay Wallet", type: "wallet" },
  { code: "63902", name: "M-PESA", type: "mobile" },
  { code: "63903", name: "Airtel Money", type: "mobile" },
  { code: "63907", name: "T-Kash", type: "mobile" },
  { code: "01", name: "KCB Bank", type: "bank" },
  { code: "02", name: "Standard Chartered Bank KE", type: "bank" },
  { code: "03", name: "Absa Bank", type: "bank" },
  { code: "07", name: "NCBA", type: "bank" },
  { code: "10", name: "Prime Bank", type: "bank" },
  { code: "11", name: "Cooperative Bank", type: "bank" },
  { code: "12", name: "National Bank", type: "bank" },
  { code: "14", name: "M-Oriental", type: "bank" },
  { code: "16", name: "Citibank", type: "bank" },
  { code: "18", name: "Middle East Bank", type: "bank" },
  { code: "19", name: "Bank of Africa", type: "bank" },
  { code: "23", name: "Consolidated Bank", type: "bank" },
  { code: "25", name: "Credit Bank", type: "bank" },
  { code: "31", name: "Stanbic Bank", type: "bank" },
  { code: "35", name: "ABC Bank", type: "bank" },
  { code: "36", name: "Choice Microfinance Bank", type: "bank" },
  { code: "43", name: "Eco Bank", type: "bank" },
  { code: "50", name: "Paramount Universal Bank", type: "bank" },
  { code: "51", name: "Kingdom Bank", type: "bank" },
  { code: "53", name: "Guaranty Bank", type: "bank" },
  { code: "54", name: "Victoria Commercial Bank", type: "bank" },
  { code: "55", name: "Guardian Bank", type: "bank" },
  { code: "57", name: "I&M Bank", type: "bank" },
  { code: "61", name: "HFC Bank", type: "bank" },
  { code: "63", name: "DTB", type: "bank" },
  { code: "65", name: "Mayfair Bank", type: "bank" },
  { code: "66", name: "Sidian Bank", type: "bank" },
  { code: "68", name: "Equity Bank", type: "bank" },
  { code: "70", name: "Family Bank", type: "bank" },
  { code: "72", name: "Gulf African Bank", type: "bank" },
  { code: "74", name: "First Community Bank", type: "bank" },
  { code: "75", name: "DIB Bank", type: "bank" },
  { code: "76", name: "UBA", type: "bank" },
  { code: "78", name: "KWFT Bank", type: "bank" },
  { code: "89", name: "Stima Sacco", type: "bank" },
  { code: "97", name: "Telkom Kenya", type: "mobile" }
];
function channelByCode(code) {
  return SASAPAY_CHANNELS.find((ch) => ch.code === String(code));
}
function accountTypeForChannel(code) {
  const ch = channelByCode(code);
  if (!ch) return 1;
  if (ch.type === "wallet") return 0;
  if (ch.type === "bank") return 4;
  return 1;
}
var SASAPAY_CALLBACK_IPS = [
  "47.129.43.141",
  "13.229.247.179",
  "13.215.155.141",
  "13.214.60.231",
  "54.169.74.198",
  "18.142.226.87",
  "47.129.243.116",
  "13.250.110.3",
  "155.12.30.40",
  "155.12.30.58",
  "41.90.137.105"
];
function isTrustedSasapayIp(ip) {
  if (!ip) return false;
  return String(ip).split(",").map((s) => s.trim()).some((t) => SASAPAY_CALLBACK_IPS.includes(t));
}
function sasapayIsSandbox(env2) {
  const v = String(env2.SASAPAY_ENV || "").trim().toLowerCase();
  return v === "sandbox" || v === "development" || v === "dev" || v === "test";
}
function sasapayMode(env2) {
  return sasapayIsSandbox(env2) ? "sandbox" : "production";
}
function baseUrl2(env2) {
  return sasapayIsSandbox(env2) ? "https://sandbox.sasapay.app" : "https://api.sasapay.app";
}
function clientId(env2) {
  return (env2.SASAPAY_CLIENT_ID || env2.SASAPAY_CONSUMER_KEY || "").trim() || void 0;
}
function clientSecret(env2) {
  return (env2.SASAPAY_CLIENT_SECRET || env2.SASAPAY_CONSUMER_SECRET || "").trim() || void 0;
}
function merchantCode(env2) {
  return (env2.SASAPAY_MERCHANT_CODE || "").trim() || void 0;
}
function sasapayConfigured(env2) {
  return !!(merchantCode(env2) && clientId(env2) && clientSecret(env2));
}
function normalizePhone2(phone) {
  let p = String(phone || "").replace(/[^0-9]/g, "");
  if (p.startsWith("0")) p = "254" + p.slice(1);
  if (p.startsWith("7") && p.length === 9) p = "254" + p;
  if (p.startsWith("1") && p.length === 9) p = "254" + p;
  if (p.startsWith("2540")) p = "254" + p.slice(4);
  return p;
}
async function readBody(res) {
  const text = await res.text().catch(() => "");
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { json, text };
}
var _tokenCache = /* @__PURE__ */ new Map();
async function getToken2(env2) {
  const id = clientId(env2);
  const secret = clientSecret(env2);
  if (!id || !secret) throw new Error("SasaPay client credentials are not configured");
  const cacheKey = `${baseUrl2(env2)}::${id}`;
  const cached = _tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 3e4) return cached.token;
  const auth = btoa(`${id}:${secret}`);
  const url = `${baseUrl2(env2)}/api/v1/auth/token/?grant_type=client_credentials`;
  const res = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: { Authorization: `Basic ${auth}`, Accept: "application/json" }
  });
  const { json, text } = await readBody(res);
  if (!res.ok || !json?.access_token) {
    const msg = json?.detail || json?.message || json?.error || (text ? text.slice(0, 200) : `HTTP ${res.status}`);
    throw new Error(`SasaPay auth failed [${res.status}] :: ${msg}`);
  }
  const ttl = Number(json.expires_in || 3600) * 1e3;
  _tokenCache.set(cacheKey, { token: String(json.access_token), expiresAt: Date.now() + ttl });
  return String(json.access_token);
}
async function sasapayStkPush(env2, opts) {
  if (!sasapayConfigured(env2)) {
    const code = opts.channelCode || opts.networkCode || "63902";
    return {
      simulated: true,
      success: true,
      checkout_request_id: "SP_SIM_" + crypto.randomUUID().slice(0, 12),
      merchant_request_id: "SPM_SIM_" + crypto.randomUUID().slice(0, 8),
      transaction_reference: "PR_SIM_" + Date.now().toString().slice(-8),
      payment_gateway: channelByCode(code)?.name || "SasaPay",
      needs_otp: code === "0",
      customer_message: `Simulated SasaPay ${channelByCode(code)?.name || "payment"} request sent.`
    };
  }
  let token;
  try {
    token = await getToken2(env2);
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay auth failed" };
  }
  const phone = normalizePhone2(opts.phone);
  const networkCode = String(opts.channelCode || opts.networkCode || "63902");
  const ch = channelByCode(networkCode);
  const callbackUrl = opts.callbackUrl || env2.SASAPAY_CALLBACK_URL || "";
  if (!callbackUrl) {
    return { simulated: false, success: false, error: "SasaPay: a payin CallBackURL is required (set SASAPAY_CALLBACK_URL)" };
  }
  const body = {
    MerchantCode: merchantCode(env2),
    NetworkCode: networkCode,
    PhoneNumber: phone,
    Currency: "KES",
    Amount: String(Math.max(1, Math.round(opts.amount))),
    AccountReference: String(opts.account || "").slice(0, 20),
    TransactionDesc: String(opts.description || "Farmsky payment").slice(0, 20),
    CallBackURL: callbackUrl
  };
  const url = `${baseUrl2(env2)}/api/v1/payments/request-payment/`;
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      redirect: "follow",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body)
    });
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay network error" };
  }
  const { json, text } = await readBody(res);
  if (res.ok && json?.status === true && (json.ResponseCode === "0" || json.ResponseCode === 0)) {
    return {
      simulated: false,
      success: true,
      checkout_request_id: String(json.CheckoutRequestID || json.MerchantRequestID || ""),
      merchant_request_id: String(json.MerchantRequestID || ""),
      transaction_reference: String(json.TransactionReference || ""),
      payment_gateway: json.PaymentGateway || ch?.name || "SasaPay",
      needs_otp: networkCode === "0",
      customer_message: json.CustomerMessage || json.ResponseDescription || json.detail || "Transaction processing initiated.",
      raw: json
    };
  }
  const msg = json?.detail || json?.ResponseDescription || json?.message || (text ? text.slice(0, 300) : `HTTP ${res.status}`);
  return { simulated: false, success: false, error: `SasaPay request-payment failed [${res.status}] :: ${msg}` };
}
async function sasapayProcessPayment(env2, checkoutRequestId, verificationCode) {
  if (!sasapayConfigured(env2) || String(checkoutRequestId).includes("SIM")) {
    return { simulated: true, success: true, customer_message: "Transaction is being processed" };
  }
  let token;
  try {
    token = await getToken2(env2);
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay auth failed" };
  }
  const url = `${baseUrl2(env2)}/api/v1/payments/process-payment/`;
  const body = { MerchantCode: merchantCode(env2), CheckoutRequestID: checkoutRequestId, VerificationCode: String(verificationCode) };
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      redirect: "follow",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body)
    });
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay network error" };
  }
  const { json, text } = await readBody(res);
  if (res.ok && json?.status === true) {
    return { simulated: false, success: true, customer_message: json.detail || "Transaction is being processed", raw: json };
  }
  const msg = json?.detail || json?.message || (text ? text.slice(0, 200) : `HTTP ${res.status}`);
  return { simulated: false, success: false, error: `SasaPay process-payment failed [${res.status}] :: ${msg}` };
}
async function sasapayB2C(env2, opts) {
  if (!sasapayConfigured(env2)) {
    return {
      simulated: true,
      success: true,
      b2c_request_id: "B2C_SIM_" + crypto.randomUUID().slice(0, 12),
      conversation_id: "CONV_SIM_" + crypto.randomUUID().slice(0, 8),
      originator_conversation_id: opts.reference,
      transaction_charges: "0.00",
      customer_message: `Simulated payout of KES ${opts.amount} to ${opts.receiverNumber} is being processed.`
    };
  }
  let token;
  try {
    token = await getToken2(env2);
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay auth failed" };
  }
  const callbackUrl = opts.callbackUrl || env2.SASAPAY_B2C_CALLBACK_URL || env2.SASAPAY_CALLBACK_URL || "";
  if (!callbackUrl) {
    return { simulated: false, success: false, error: "SasaPay: a payout CallBackURL is required (set SASAPAY_B2C_CALLBACK_URL)" };
  }
  const isMobile = channelByCode(opts.channel)?.type !== "bank" && opts.channel !== "0";
  const receiver = isMobile ? normalizePhone2(opts.receiverNumber) : String(opts.receiverNumber);
  const body = {
    MerchantCode: merchantCode(env2),
    MerchantTransactionReference: String(opts.reference).slice(0, 40),
    Amount: String(Math.max(1, Math.round(opts.amount))),
    Currency: "KES",
    ReceiverNumber: receiver,
    Channel: String(opts.channel),
    Reason: String(opts.reason || "Farmsky payout").slice(0, 100),
    CallBackURL: callbackUrl
  };
  const url = `${baseUrl2(env2)}/api/v1/payments/b2c/`;
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      redirect: "follow",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body)
    });
  } catch (e) {
    return { simulated: false, success: false, error: e?.message || "SasaPay network error" };
  }
  const { json, text } = await readBody(res);
  if (res.ok && json?.status === true && (json.ResponseCode === "0" || json.ResponseCode === 0)) {
    return {
      simulated: false,
      success: true,
      b2c_request_id: String(json.B2CRequestID || ""),
      conversation_id: String(json.ConversationID || ""),
      originator_conversation_id: String(json.OriginatorConversationID || opts.reference),
      transaction_charges: String(json.TransactionCharges ?? "0.00"),
      customer_message: json.detail || json.ResponseDescription || "Payout is being processed.",
      raw: json
    };
  }
  const msg = json?.detail || json?.ResponseDescription || json?.message || (text ? text.slice(0, 300) : `HTTP ${res.status}`);
  return { simulated: false, success: false, error: `SasaPay B2C failed [${res.status}] :: ${msg}` };
}
async function sasapayValidateAccount(env2, channelCode, accountNumber) {
  if (!sasapayConfigured(env2)) {
    return { success: true, simulated: true, account_name: "SIMULATED ACCOUNT HOLDER", channel_name: channelByCode(channelCode)?.name };
  }
  let token;
  try {
    token = await getToken2(env2);
  } catch (e) {
    return { success: false, error: e?.message || "SasaPay auth failed" };
  }
  const isMobile = channelByCode(channelCode)?.type === "mobile";
  const account = isMobile ? normalizePhone2(accountNumber) : String(accountNumber);
  const url = `${baseUrl2(env2)}/api/v1/accounts/account-validation/`;
  const body = {
    merchant_code: merchantCode(env2),
    channel_code: String(channelCode),
    account_number: account,
    account_type: accountTypeForChannel(channelCode)
  };
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      redirect: "follow",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body)
    });
  } catch (e) {
    return { success: false, error: e?.message || "SasaPay network error" };
  }
  const { json, text } = await readBody(res);
  if (res.ok && json?.status === true) {
    const d = json.account_details || {};
    return { success: true, account_name: d.account_name, channel_name: d.channel_name, raw: json };
  }
  const msg = json?.detail || json?.message || (text ? text.slice(0, 200) : `HTTP ${res.status}`);
  return { success: false, error: msg };
}
async function sasapayBalance(env2) {
  if (!sasapayConfigured(env2)) {
    return {
      success: true,
      simulated: true,
      currency: "KES",
      org_balance: 0,
      accounts: [
        { account_label: "Working Account", account_balance: 0 },
        { account_label: "Utility Account", account_balance: 0 },
        { account_label: "Bulk Payment", account_balance: 0 }
      ]
    };
  }
  let token;
  try {
    token = await getToken2(env2);
  } catch (e) {
    return { success: false, error: e?.message || "SasaPay auth failed" };
  }
  const url = `${baseUrl2(env2)}/api/v1/payments/check-balance/?MerchantCode=${encodeURIComponent(merchantCode(env2) || "")}`;
  let res;
  try {
    res = await fetch(url, { method: "GET", redirect: "follow", headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
  } catch (e) {
    return { success: false, error: e?.message || "SasaPay network error" };
  }
  const { json, text } = await readBody(res);
  if (res.ok && (json?.statusCode === "0" || json?.statusCode === 0)) {
    const d = json.data || {};
    return { success: true, currency: d.CurrencyCode || "KES", org_balance: Number(d.OrgAccountBalance || 0), accounts: d.Accounts || [], raw: json };
  }
  const msg = json?.message || json?.detail || (text ? text.slice(0, 200) : `HTTP ${res.status}`);
  return { success: false, error: msg };
}
async function sasapayQuery(env2, checkoutRequestId, callbackUrl) {
  if (!sasapayConfigured(env2) || String(checkoutRequestId).includes("SIM")) {
    return { paid: true, pending: false, failed: false, ResultCode: "0", ResultDesc: "Simulated success", status: true, TransactionCode: "SP" + Date.now().toString().slice(-7) };
  }
  try {
    const token = await getToken2(env2);
    const url = `${baseUrl2(env2)}/api/v1/transactions/status-query/`;
    const resolvedCallbackUrl = callbackUrl || env2.SASAPAY_CALLBACK_URL || "";
    console.log("Sending status query with Callback URL:", resolvedCallbackUrl);
    const body = {
      MerchantCode: merchantCode(env2),
      CheckoutRequestId: checkoutRequestId,
      CallbackUrl: resolvedCallbackUrl
    };
    const res = await fetch(url, {
      method: "POST",
      redirect: "follow",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body)
    });
    const { json, text } = await readBody(res);
    console.log("SasaPay status-query payload:", JSON.stringify(json) || text?.slice(0, 300));
    if (!json) {
      return { paid: false, pending: true, failed: false, ResultCode: null, ResultDesc: "Transaction still processing", status: false };
    }
    const data = json.data || json;
    const hasPaymentFields = "Paid" in data || "paid" in data || "AmountPaid" in data || "amount_paid" in data || "PaymentStatus" in data || "payment_status" in data || "TransactionStatus" in data || "TransactionCode" in data || "ResultCode" in data;
    const ackMessage = String(json.message || json.detail || "").toLowerCase();
    const isAsyncAck = !hasPaymentFields && (ackMessage.includes("check your callback") || ackMessage.includes("request has been received") || ackMessage.includes("being processed"));
    if (isAsyncAck) {
      return { ...json, paid: false, pending: true, failed: false, status: false, ResultCode: null, ResultDesc: json.message || "Awaiting SasaPay callback confirmation" };
    }
    const paidFlag = data.Paid === true || data.paid === true || String(data.PaymentStatus || data.payment_status || data.TransactionStatus || "").toLowerCase() === "paid" || String(data.PaymentStatus || data.payment_status || data.TransactionStatus || "").toLowerCase() === "completed";
    const receipt = data.TransactionCode || data.TransactionID || data.MpesaReceiptNumber || data.ReceiptNumber || data.CheckoutId || data.CheckoutRequestId || "";
    const amountPaid = Number(data.AmountPaid ?? data.amount_paid ?? data.TransactionAmount ?? 0);
    const rawStatusStr = String(data.PaymentStatus || data.TransactionStatus || data.payment_status || "").toLowerCase();
    const failedFlag = data.Paid === false && (rawStatusStr === "failed" || rawStatusStr === "cancelled" || rawStatusStr === "canceled") || rawStatusStr === "failed" || rawStatusStr === "cancelled" || rawStatusStr === "canceled" || String(data.ResultCode ?? "") === "1";
    const desc = data.ResultDesc || data.detail || data.message || json.detail || json.message || "";
    if (paidFlag) {
      return {
        ...json,
        paid: true,
        pending: false,
        failed: false,
        status: true,
        ResultCode: "0",
        TransactionCode: String(receipt || "SPL" + Date.now().toString().slice(-7)),
        amount_paid: amountPaid,
        ResultDesc: desc || "Payment completed"
      };
    }
    if (failedFlag) {
      return { ...json, paid: false, pending: false, failed: true, status: false, ResultCode: "1", ResultDesc: desc || "Payment not completed" };
    }
    return { ...json, paid: false, pending: true, failed: false, status: false, ResultCode: null, ResultDesc: desc || "Transaction still processing" };
  } catch (err) {
    console.error("SasaPay status-query exception:", err?.message || err);
    return { paid: false, pending: true, failed: false, ResultCode: null, ResultDesc: "Transaction still processing", status: false };
  }
}
async function verifySasapaySignature(env2, headerSignature, fields) {
  if (!headerSignature) return false;
  const secret = clientSecret(env2);
  if (!secret) return false;
  const message = [
    fields.sasapay_transaction_code ?? "",
    fields.merchant_code ?? "",
    fields.account_number ?? "",
    fields.payment_reference ?? "",
    fields.amount ?? ""
  ].join("-");
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-512" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
    const hex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return timingSafeEqual(hex.toLowerCase(), String(headerSignature).trim().toLowerCase());
  } catch {
    return false;
  }
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// backend/buni.ts
var SANDBOX_BASE2 = "https://uat.buni.kcbgroup.com";
var PROD_BASE2 = "https://api.buni.kcbgroup.com";
function isSandbox2(envValue) {
  const v = String(envValue || "").trim().toLowerCase();
  return v === "sandbox" || v === "development" || v === "dev" || v === "test" || v === "uat";
}
function baseUrl3(env2) {
  return isSandbox2(env2.BUNI_ENV) ? SANDBOX_BASE2 : PROD_BASE2;
}
function buniConfigured(env2) {
  return !!(env2.BUNI_CLIENT_ID && env2.BUNI_CLIENT_SECRET && env2.BUNI_API_KEY);
}
async function getToken3(env2) {
  const auth = btoa(`${env2.BUNI_CLIENT_ID}:${env2.BUNI_CLIENT_SECRET}`);
  const res = await fetch(`${baseUrl3(env2)}/token`, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });
  if (!res.ok) throw new Error(`KCB Buni Auth Failed`);
  const data = await res.json();
  return data.access_token;
}
async function buniStkPush(env2, opts) {
  if (!buniConfigured(env2)) return { success: true, checkout_request_id: "BUNI_SIM_" + Date.now() };
  const token = await getToken3(env2);
  const res = await fetch(`${baseUrl3(env2)}/mm/api/request`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      "apikey": env2.BUNI_API_KEY
    },
    body: JSON.stringify({
      phoneNumber: opts.phone,
      amount: opts.amount,
      accountReference: opts.account,
      transactionDesc: opts.description
    })
  });
  const data = await res.json();
  return { success: res.ok, checkout_request_id: data.CheckoutRequestID || data.merchantRequestId };
}
async function buniQuery(env2, checkoutRequestId) {
  const token = await getToken3(env2);
  const res = await fetch(`${baseUrl3(env2)}/mm/api/query?requestId=${checkoutRequestId}`, {
    headers: { "Authorization": `Bearer ${token}`, "apikey": env2.BUNI_API_KEY }
  });
  return await res.json();
}

// backend/payment-gateway.ts
import { Hono } from "hono";
init_payments_shared();
var gateway = new Hono();
function genRef() {
  return "FSK-" + crypto.randomUUID().replace(/-/g, "").slice(0, 18).toUpperCase();
}
async function loadClient(c, client_key) {
  return await c.env.DB.prepare(
    `SELECT id, client_key, display_name, origin_url, hmac_secret, callback_url, is_active
     FROM app_clients WHERE client_key = ?`
  ).bind(client_key).first();
}
async function loadMarketplace(c, marketplace_key) {
  try {
    return await c.env.DB.prepare(
      `SELECT id, marketplace_key, display_name, domain, is_main, is_active FROM marketplaces WHERE marketplace_key = ?`
    ).bind(marketplace_key).first();
  } catch (_) {
    return null;
  }
}
async function setTenantScope(c, marketplaceId, isAdmin = false) {
  const setLocal = c.env.DB?.setSessionConfig;
  if (typeof setLocal === "function") {
    try {
      await setLocal.call(c.env.DB, "app.current_marketplace_id", marketplaceId == null ? "" : String(marketplaceId));
    } catch (_) {
    }
    try {
      await setLocal.call(c.env.DB, "app.is_admin", isAdmin ? "true" : "false");
    } catch (_) {
    }
  }
}
async function auditSecurity(c, eventType, severity, opts = {}) {
  try {
    const ip = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || null;
    await c.env.DB.prepare(
      `INSERT INTO payment_audit_log (marketplace_id, origin_app, event_type, severity, transaction_ref, detail, ip_address)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(opts.marketplaceId ?? null, opts.originApp ?? null, eventType, severity, opts.transactionRef ?? null, (opts.detail || "").slice(0, 500), ip).run();
  } catch (_) {
  }
}
async function findTxByProviderRef(c, provider_request_id) {
  if (!provider_request_id) return null;
  return await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE provider_request_id = ? LIMIT 1`
  ).bind(provider_request_id).first();
}
async function logCallback(c, txRef, method, providerReqId, rawBody, valid, marketplaceId = null) {
  try {
    await c.env.DB.prepare(
      `INSERT INTO central_callbacks (transaction_ref, payment_method, provider_request_id, raw_payload, signature_valid, marketplace_id)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(txRef, method, providerReqId, rawBody.slice(0, 8e3), valid ? 1 : 0, marketplaceId).run();
  } catch (_) {
  }
}
async function notifyOriginApp(c, client, tx) {
  if (!client?.callback_url) return;
  try {
    const body = JSON.stringify({
      transaction_ref: tx.transaction_ref,
      origin_reference: tx.origin_reference,
      payment_method: tx.payment_method,
      status: tx.status,
      provider_receipt: tx.provider_receipt,
      amount: Number(tx.amount),
      currency: tx.currency,
      result_code: tx.result_code,
      result_desc: tx.result_desc,
      completed_at: tx.completed_at
    });
    const { signRequest: signRequest2 } = await Promise.resolve().then(() => (init_payments_shared(), payments_shared_exports));
    const { timestamp: timestamp2, nonce, signature } = await signRequest2(client.hmac_secret, client.client_key, body);
    await fetch(client.callback_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Farmsky-Client": client.client_key,
        "X-Farmsky-Timestamp": timestamp2,
        "X-Farmsky-Nonce": nonce,
        "X-Farmsky-Signature": signature
      },
      body
    });
  } catch (_) {
  }
}
gateway.post("/initiate", async (c) => {
  const rawBody = await c.req.text();
  const client_key = c.req.header("X-Farmsky-Client") || "";
  const timestamp2 = c.req.header("X-Farmsky-Timestamp") || "";
  const nonce = c.req.header("X-Farmsky-Nonce") || "";
  const signature = c.req.header("X-Farmsky-Signature") || "";
  const idempotencyKey = c.req.header("Idempotency-Key") || null;
  if (!client_key) return c.json({ success: false, error: "Missing X-Farmsky-Client header" }, 401);
  const client = await loadClient(c, client_key);
  if (!client || !client.is_active) {
    await auditSecurity(c, "UNKNOWN_CLIENT", "WARN", { originApp: client_key, detail: "initiate from unknown/inactive client" });
    return c.json({ success: false, error: "Unknown or inactive client app" }, 401);
  }
  const marketplace = await loadMarketplace(c, client_key);
  const marketplaceId = marketplace?.id ?? null;
  await setTenantScope(c, marketplaceId, false);
  const v = await verifySignature(client.hmac_secret, client_key, timestamp2, nonce, rawBody, signature);
  if (!v.ok) {
    await auditSecurity(c, "SIGNATURE_FAIL", "CRITICAL", { marketplaceId, originApp: client_key, detail: v.error || "invalid HMAC signature on /initiate" });
    return c.json({ success: false, error: v.error || "Invalid signature" }, 401);
  }
  if (nonce) {
    try {
      const existingNonce = await c.env.DB.prepare(
        `SELECT 1 FROM payment_nonces WHERE client_key = ? AND nonce = ? LIMIT 1`
      ).bind(client_key, nonce).first();
      if (existingNonce) {
        await auditSecurity(c, "REPLAY", "CRITICAL", { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` });
        return c.json({ success: false, error: "Replay detected" }, 401);
      }
      await c.env.DB.prepare(
        `INSERT INTO payment_nonces (client_key, nonce) VALUES (?, ?)`
      ).bind(client_key, nonce).run();
    } catch (e) {
      const code = e?.code || "";
      if (code === "23505" || /unique|duplicate/i.test(String(e?.message || ""))) {
        await auditSecurity(c, "REPLAY", "CRITICAL", { marketplaceId, originApp: client_key, detail: `replayed nonce ${nonce}` });
        return c.json({ success: false, error: "Replay detected" }, 401);
      }
    }
  }
  let body = {};
  try {
    body = rawBody ? JSON.parse(rawBody) : {};
  } catch {
    return c.json({ success: false, error: "Body must be JSON" }, 400);
  }
  const method = String(body.payment_method || "").toLowerCase();
  const amount = Number(body.amount);
  const phone = normalizePhone(String(body.phone || ""));
  const origin_reference = body.origin_reference ? String(body.origin_reference) : null;
  const description = body.description ? String(body.description).slice(0, 200) : `${client.display_name} payment`;
  const initiated_by_user = body.initiated_by_user ?? null;
  const channel = body.channel || "MOBILE_MONEY";
  const channelCode = body.channelCode || body.networkCode || void 0;
  const accountNumber = body.accountNumber || void 0;
  if (!["mpesa", "sasapay", "buni"].includes(method)) return c.json({ success: false, error: "payment_method must be mpesa | sasapay | buni" }, 400);
  if (!Number.isFinite(amount) || amount <= 0) return c.json({ success: false, error: "amount must be > 0" }, 400);
  if (!phone || phone.length < 11) return c.json({ success: false, error: "phone is invalid" }, 400);
  if (idempotencyKey) {
    const existing = await c.env.DB.prepare(
      `SELECT transaction_ref, payment_method, status FROM central_transactions WHERE origin_app = ? AND idempotency_key = ? LIMIT 1`
    ).bind(client_key, idempotencyKey).first();
    if (existing) {
      return c.json({
        success: true,
        idempotent_replay: true,
        transaction_ref: existing.transaction_ref,
        payment_method: existing.payment_method,
        status: existing.status
      });
    }
  }
  const transaction_ref = genRef();
  const desc = description.slice(0, 40);
  let providerResult;
  try {
    if (method === "mpesa") {
      providerResult = await stkPush(c.env, { phone, amount, account: transaction_ref, description: desc, networkCode: channelCode });
    } else if (method === "sasapay") {
      providerResult = await sasapayStkPush(c.env, {
        phone,
        amount,
        account: transaction_ref,
        description: desc,
        channel,
        channelCode,
        accountNumber
      });
    } else {
      providerResult = await buniStkPush(c.env, { phone, amount, account: transaction_ref, description: desc });
    }
  } catch (e) {
    return c.json({ success: false, error: e?.message || "Provider error" }, 502);
  }
  if (!providerResult?.success) {
    return c.json({ success: false, error: providerResult?.error || "Provider rejected the push" }, 502);
  }
  const ip = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || null;
  await c.env.DB.prepare(
    `INSERT INTO central_transactions
        (transaction_ref, idempotency_key, origin_app, marketplace_id, origin_reference, payment_method,
         provider_request_id, phone, amount, currency, description, status, initiated_by_user, ip_address)
      VALUES (?,?,?,?,?,?,?,?,?,?,?, 'PENDING', ?, ?)`
  ).bind(
    transaction_ref,
    idempotencyKey,
    client_key,
    marketplaceId,
    origin_reference,
    method,
    providerResult.checkout_request_id || null,
    phone,
    amount,
    "KES",
    desc,
    initiated_by_user,
    ip
  ).run();
  return c.json({
    success: true,
    transaction_ref,
    payment_method: method,
    origin_app: client_key,
    simulated: !!providerResult.simulated,
    customer_message: providerResult.customer_message || "Payment prompt sent.",
    status: "PENDING"
  });
});
gateway.get("/status/:ref", async (c) => {
  const transaction_ref = c.req.param("ref");
  const client_key = c.req.header("X-Farmsky-Client") || "";
  const timestamp2 = c.req.header("X-Farmsky-Timestamp") || "";
  const nonce = c.req.header("X-Farmsky-Nonce") || "";
  const signature = c.req.header("X-Farmsky-Signature") || "";
  const client = await loadClient(c, client_key);
  if (!client || !client.is_active) return c.json({ success: false, error: "Unknown client app" }, 401);
  const marketplace = await loadMarketplace(c, client_key);
  await setTenantScope(c, marketplace?.id ?? null, false);
  const v = await verifySignature(client.hmac_secret, client_key, timestamp2, nonce, transaction_ref, signature);
  if (!v.ok) {
    await auditSecurity(c, "SIGNATURE_FAIL", "WARN", { marketplaceId: marketplace?.id ?? null, originApp: client_key, detail: "invalid signature on /status poll" });
    return c.json({ success: false, error: v.error || "Invalid signature" }, 401);
  }
  let tx = await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE transaction_ref = ? AND origin_app = ? LIMIT 1`
  ).bind(transaction_ref, client_key).first();
  if (!tx) return c.json({ success: false, error: "Transaction not found" }, 404);
  if (tx.status === "PENDING" && tx.provider_request_id) {
    try {
      let pr;
      if (tx.payment_method === "mpesa") pr = await stkQuery(c.env, tx.provider_request_id);
      else if (tx.payment_method === "sasapay") pr = await sasapayQuery(c.env, tx.provider_request_id);
      else if (tx.payment_method === "buni") pr = await buniQuery(c.env, tx.provider_request_id);
      if (tx.payment_method === "sasapay" && pr?.status === true && !pr?.Paid) {
        const structuralCheck = await c.env.DB.prepare(
          `SELECT status, result_code, result_desc, provider_receipt, completed_at FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
        ).bind(transaction_ref).first();
        if (structuralCheck && structuralCheck.status !== "PENDING") {
          tx = { ...tx, ...structuralCheck };
        }
      } else {
        const code = pr?.ResultCode ?? pr?.status_code;
        if (code === 0 || code === "0" || pr?.status === true || pr?.Paid === true) {
          const receipt = pr?.TransactionCode || pr?.TransID || pr?.ThirdPartyTransID || null;
          await c.env.DB.prepare(
            `UPDATE central_transactions
                SET status='SUCCESS', result_code=?, result_desc=?, provider_receipt=COALESCE(?, provider_receipt), updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
              WHERE transaction_ref=?`
          ).bind(String(code ?? "0"), String(pr?.ResultDesc || pr?.ResultDescription || pr?.message || "Success"), receipt, transaction_ref).run();
          tx.status = "SUCCESS";
        } else if (code !== void 0 && code !== null && code !== 0 && code !== "0") {
          await c.env.DB.prepare(
            `UPDATE central_transactions
                SET status='FAILED', result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
              WHERE transaction_ref=?`
          ).bind(String(code), String(pr?.ResultDesc || pr?.message || "Failed"), transaction_ref).run();
          tx.status = "FAILED";
        }
      }
    } catch (_) {
    }
  }
  return c.json({
    success: true,
    transaction_ref: tx.transaction_ref,
    origin_app: tx.origin_app,
    origin_reference: tx.origin_reference,
    payment_method: tx.payment_method,
    status: tx.status,
    amount: Number(tx.amount),
    currency: tx.currency,
    provider_receipt: tx.provider_receipt,
    result_code: tx.result_code,
    result_desc: tx.result_desc,
    completed_at: tx.completed_at
  });
});
async function settleCallback(c, method, providerReqId, success, receipt, resultCode, resultDesc, rawBody) {
  await setTenantScope(c, null, true);
  if (!providerReqId) {
    await logCallback(c, null, method, null, rawBody, false);
    await auditSecurity(c, "CALLBACK_UNBOUND", "WARN", { originApp: method, detail: "callback missing provider_request_id" });
    return;
  }
  const tx = await findTxByProviderRef(c, providerReqId);
  if (!tx) {
    await logCallback(c, null, method, providerReqId, rawBody, false);
    await auditSecurity(c, "CALLBACK_NO_MATCH", "CRITICAL", { detail: `callback provider_request_id ${providerReqId} matches no transaction (possible spoof)` });
    return;
  }
  if (tx.status !== "PENDING") {
    await logCallback(c, tx.transaction_ref, method, providerReqId, rawBody, true, tx.marketplace_id ?? null);
    return;
  }
  await c.env.DB.prepare(
    `UPDATE central_transactions
        SET status=?, provider_receipt=COALESCE(?, provider_receipt),
            result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
      WHERE transaction_ref=?`
  ).bind(success ? "SUCCESS" : "FAILED", receipt, resultCode, resultDesc, tx.transaction_ref).run();
  await logCallback(c, tx.transaction_ref, method, providerReqId, rawBody, true, tx.marketplace_id ?? null);
  const client = await loadClient(c, tx.origin_app);
  const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(tx.transaction_ref).first();
  if (client && refreshed) await notifyOriginApp(c, client, refreshed);
}
gateway.post("/callbacks/mpesa", async (c) => {
  const raw2 = await c.req.text();
  try {
    const body = JSON.parse(raw2);
    const cb = body?.Body?.stkCallback;
    const providerReqId = cb?.CheckoutRequestID || null;
    const success = cb?.ResultCode === 0;
    const items = cb?.CallbackMetadata?.Item || [];
    const receipt = items.find((i) => i?.Name === "MpesaReceiptNumber")?.Value || null;
    await settleCallback(c, "mpesa", providerReqId, success, receipt ? String(receipt) : null, String(cb?.ResultCode ?? ""), cb?.ResultDesc || null, raw2);
  } catch (_) {
    await logCallback(c, null, "mpesa", null, raw2, false);
  }
  return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
});
gateway.post("/callbacks/sasapay", async (c) => {
  const raw2 = await c.req.text();
  const forwardHeader = c.req.header("X-Forwarded-For") || c.req.header("CF-Connecting-IP") || "";
  const requestIp = forwardHeader.split(",")[0].trim();
  const SASAPAY_TRUSTED_IPS = /* @__PURE__ */ new Set([
    "47.129.43.141",
    "13.229.247.179",
    "13.215.155.141",
    "13.214.60.231",
    "54.169.74.198",
    "18.142.226.87",
    "47.129.243.116",
    "13.250.110.3",
    "155.12.30.40",
    "155.12.30.58",
    "41.90.137.105"
  ]);
  if (!SASAPAY_TRUSTED_IPS.has(requestIp)) {
    await auditSecurity(c, "CALLBACK_IP_BLOCKED", "CRITICAL", { originApp: "sasapay", detail: `Blocked untrusted IP: ${requestIp}` });
    return c.json({ error: "Untrusted origin gateway transaction dropped." }, 401);
  }
  try {
    const body = JSON.parse(raw2);
    const providerReqId = body?.CheckoutRequestID || body?.MerchantRequestID || null;
    const code = body?.ResultCode ?? body?.status_code;
    const success = code === 0 || code === "0" || body?.status === true;
    const receipt = body?.TransactionCode || body?.ThirdPartyTransID || null;
    await settleCallback(c, "sasapay", providerReqId, success, receipt ? String(receipt) : null, String(code ?? ""), body?.ResultDesc || body?.message || null, raw2);
  } catch (_) {
    await logCallback(c, null, "sasapay", null, raw2, false);
  }
  return c.json({ status: "Success", message: "Callback received" });
});
gateway.post("/callbacks/buni", async (c) => {
  const raw2 = await c.req.text();
  try {
    const body = JSON.parse(raw2);
    const providerReqId = body?.CheckoutRequestID || body?.TransactionID || null;
    const code = body?.ResponseCode ?? body?.ResultCode;
    const success = code === "00" || code === 0 || code === "0" || body?.status === true;
    const receipt = body?.TransactionID || body?.ReceiptNumber || null;
    await settleCallback(c, "buni", providerReqId, success, receipt ? String(receipt) : null, String(code ?? ""), body?.ResponseDescription || body?.ResultDesc || null, raw2);
  } catch (_) {
    await logCallback(c, null, "buni", null, raw2, false);
  }
  return c.json({ ResponseCode: "00", ResponseMessage: "Success" });
});
gateway.get("/admin/summary", async (c) => {
  await setTenantScope(c, null, true);
  const { results: byApp } = await c.env.DB.prepare(
    `SELECT origin_app, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY origin_app`
  ).all();
  const { results: byMethod } = await c.env.DB.prepare(
    `SELECT payment_method, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY payment_method`
  ).all();
  const { results: matrix } = await c.env.DB.prepare(
    `SELECT origin_app, payment_method, COUNT(*) as count, COALESCE(SUM(amount), 0) as total
        FROM central_transactions WHERE status='SUCCESS' GROUP BY origin_app, payment_method`
  ).all();
  return c.json({ by_app: byApp, by_method: byMethod, matrix });
});
gateway.get("/admin/revenue-matrix", async (c) => {
  await setTenantScope(c, null, true);
  const { results: matrix } = await c.env.DB.prepare(
    `SELECT COALESCE(m.marketplace_key, ct.origin_app) AS marketplace_key,
            ct.payment_method,
            COUNT(*) AS success_count,
            COALESCE(SUM(ct.amount), 0) AS gross_revenue,
            MIN(ct.completed_at) AS first_settlement,
            MAX(ct.completed_at) AS last_settlement
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.status='SUCCESS'
      GROUP BY COALESCE(m.marketplace_key, ct.origin_app), ct.payment_method
      ORDER BY marketplace_key, ct.payment_method`
  ).all();
  const { results: rollup } = await c.env.DB.prepare(
    `SELECT COALESCE(m.marketplace_key, ct.origin_app) AS marketplace_key,
            COUNT(*) AS total_success,
            COALESCE(SUM(ct.amount), 0) AS total_revenue
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.status='SUCCESS'
      GROUP BY COALESCE(m.marketplace_key, ct.origin_app)
      ORDER BY total_revenue DESC`
  ).all();
  return c.json({ matrix, rollup, note: "Single shortcode revenue attributed per marketplace tenant." });
});
gateway.get("/admin/suspicious-activity", async (c) => {
  await setTenantScope(c, null, true);
  const events = await c.env.DB.prepare(
    `SELECT event_type, severity, COUNT(*) AS occurrences, MAX(created_at) AS last_seen
       FROM payment_audit_log
      GROUP BY event_type, severity
      ORDER BY occurrences DESC`
  ).all().catch(() => ({ results: [] }));
  const integrity = await c.env.DB.prepare(
    `SELECT ct.transaction_ref, ct.origin_app, ct.marketplace_id, m.marketplace_key
       FROM central_transactions ct
       LEFT JOIN marketplaces m ON m.id = ct.marketplace_id
      WHERE ct.marketplace_id IS NULL OR m.marketplace_key IS DISTINCT FROM ct.origin_app
      LIMIT 100`
  ).all().catch(() => ({ results: [] }));
  const invalidCallbacks = await c.env.DB.prepare(
    `SELECT payment_method, COUNT(*) AS invalid_callbacks, MAX(received_at) AS last_seen
       FROM central_callbacks WHERE signature_valid = 0
      GROUP BY payment_method`
  ).all().catch(() => ({ results: [] }));
  return c.json({
    security_events: events.results || [],
    integrity_breaks: integrity.results || [],
    invalid_callbacks: invalidCallbacks.results || []
  });
});
gateway.post("/admin/recover-sasapay", async (c) => {
  await setTenantScope(c, null, true);
  const body = await c.req.json().catch(() => ({}));
  const { checkout_request_id } = body;
  if (!checkout_request_id) {
    return c.json({ success: false, error: "Missing checkout_request_id parameter in body" }, 400);
  }
  const tx = await findTxByProviderRef(c, checkout_request_id);
  if (!tx) {
    return c.json({ success: false, error: `No transaction log maps to Checkout ID: ${checkout_request_id}` }, 404);
  }
  try {
    const queryResult = await sasapayQuery(c.env, checkout_request_id);
    const structuralCheck = await c.env.DB.prepare(
      `SELECT status, provider_receipt, result_code, result_desc FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
    ).bind(tx.transaction_ref).first();
    if (structuralCheck && structuralCheck.status === "SUCCESS") {
      return c.json({
        success: true,
        message: "Transaction successfully processed and resolved to SUCCESS via Webhook channel.",
        transaction_ref: tx.transaction_ref,
        provider_receipt: structuralCheck.provider_receipt
      });
    }
    const code = queryResult?.ResultCode ?? queryResult?.status_code;
    const isPaid = code === 0 || code === "0" || queryResult?.status === true || queryResult?.Paid === true;
    if (isPaid && queryResult?.Paid === true) {
      const receipt = queryResult?.TransactionCode || queryResult?.TransID || queryResult?.ThirdPartyTransID || "MANUAL_RECOVERY";
      const desc = queryResult?.ResultDescription || queryResult?.ResultDesc || "Transaction recovered successfully.";
      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='SUCCESS', provider_receipt=COALESCE(?, provider_receipt),
                result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(String(receipt), String(code ?? "0"), desc, tx.transaction_ref).run();
      const client = await loadClient(c, tx.origin_app);
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(tx.transaction_ref).first();
      if (client && refreshed) await notifyOriginApp(c, client, refreshed);
      return c.json({
        success: true,
        message: "Transaction verified and successfully moved to SUCCESS.",
        transaction_ref: tx.transaction_ref,
        provider_receipt: receipt
      });
    }
    return c.json({
      success: false,
      message: "SasaPay indicates transaction is still uncompleted, asynchronous, or failed.",
      provider_raw_response: queryResult
    }, 200);
  } catch (error) {
    return c.json({ success: false, error: error?.message || "Handshake recovery processing aborted" }, 500);
  }
});
gateway.post("/admin/recover-status", async (c) => {
  await setTenantScope(c, null, true);
  const body = await c.req.json().catch(() => ({}));
  const { transaction_ref } = body;
  if (!transaction_ref) {
    return c.json({ success: false, error: "Missing transaction_ref parameter in body" }, 400);
  }
  const tx = await c.env.DB.prepare(
    `SELECT * FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
  ).bind(transaction_ref).first();
  if (!tx) {
    return c.json({ success: false, error: `Transaction ${transaction_ref} not found in gateway database` }, 404);
  }
  if (!tx.provider_request_id) {
    return c.json({ success: false, error: "Transaction lacks a provider request tracking token" }, 422);
  }
  try {
    let queryResult;
    const method = tx.payment_method;
    if (method === "mpesa") {
      queryResult = await stkQuery(c.env, tx.provider_request_id);
    } else if (method === "sasapay") {
      queryResult = await sasapayQuery(c.env, tx.provider_request_id);
    } else if (method === "buni") {
      queryResult = await buniQuery(c.env, tx.provider_request_id);
    } else {
      return c.json({ success: false, error: `Unsupported recovery rails type: ${method}` }, 400);
    }
    if (method === "sasapay" && queryResult?.status === true && !queryResult?.Paid) {
      const liveCheck = await c.env.DB.prepare(
        `SELECT status, provider_receipt FROM central_transactions WHERE transaction_ref = ? LIMIT 1`
      ).bind(transaction_ref).first();
      if (liveCheck && liveCheck.status === "SUCCESS") {
        return c.json({
          success: true,
          resolved_status: "SUCCESS",
          message: `Transaction state updated successfully over verified channel.`,
          transaction_ref,
          provider_receipt: liveCheck.provider_receipt
        });
      }
    }
    let code;
    let isPaid = false;
    let receipt = null;
    let desc = "Recovered via status check script.";
    if (method === "mpesa") {
      code = queryResult?.ResultCode;
      isPaid = code === 0 || code === "0";
      const items = queryResult?.CallbackMetadata?.Item || [];
      receipt = items.find((i) => i?.Name === "MpesaReceiptNumber")?.Value || null;
      desc = queryResult?.ResultDesc || desc;
    } else if (method === "sasapay") {
      code = queryResult?.ResultCode ?? queryResult?.status_code;
      isPaid = code === 0 || code === "0" || queryResult?.Paid === true;
      receipt = queryResult?.TransactionCode || queryResult?.TransID || queryResult?.ThirdPartyTransID || null;
      desc = queryResult?.ResultDescription || queryResult?.ResultDesc || queryResult?.message || desc;
    } else if (method === "buni") {
      code = queryResult?.ResponseCode ?? queryResult?.ResultCode;
      isPaid = code === "00" || code === 0 || code === "0" || queryResult?.status === true;
      receipt = queryResult?.TransactionID || queryResult?.ReceiptNumber || null;
      desc = queryResult?.ResponseDescription || queryResult?.ResultDesc || desc;
    }
    if (isPaid) {
      const finalReceipt = receipt ? String(receipt) : `REC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='SUCCESS', provider_receipt=COALESCE(?, provider_receipt),
                result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(finalReceipt, String(code ?? "0"), desc, transaction_ref).run();
      const client = await loadClient(c, tx.origin_app);
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(transaction_ref).first();
      if (client && refreshed) await notifyOriginApp(c, client, refreshed);
      return c.json({
        success: true,
        resolved_status: "SUCCESS",
        message: `Transaction state successfully verified and synced for payment method: ${method}`,
        transaction_ref,
        provider_receipt: finalReceipt
      });
    } else if (code !== void 0 && code !== null && method !== "sasapay") {
      await c.env.DB.prepare(
        `UPDATE central_transactions
            SET status='FAILED', result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP, completed_at=CURRENT_TIMESTAMP
          WHERE transaction_ref=?`
      ).bind(String(code), desc, transaction_ref).run();
      const client = await loadClient(c, tx.origin_app);
      const refreshed = await c.env.DB.prepare(`SELECT * FROM central_transactions WHERE transaction_ref=?`).bind(transaction_ref).first();
      if (client && refreshed) await notifyOriginApp(c, client, refreshed);
      return c.json({
        success: true,
        resolved_status: "FAILED",
        message: "Provider confirmed that the transaction failed or was canceled by the user.",
        transaction_ref
      });
    }
    return c.json({
      success: false,
      message: "Provider status inquiry returned inconclusive status. Transaction remains unmodified.",
      provider_raw_response: queryResult
    }, 200);
  } catch (err) {
    return c.json({ success: false, error: err?.message || "Upstream provider connectivity failure on status recovery execution." }, 502);
  }
});
var payment_gateway_default = gateway;

// backend/sms.ts
var TALKSASA_DEFAULT_URL = "https://bulksms.talksasa.com/api/v3/sms/send";
function smsProvider(env2) {
  return (env2.SMS_PROVIDER || "talksasa").toLowerCase();
}
function smsUrl(env2) {
  if (env2.SMS_API_URL) return env2.SMS_API_URL;
  if (smsProvider(env2) === "talksasa") return TALKSASA_DEFAULT_URL;
  return "";
}
function smsConfigured(env2) {
  return !!(env2.SMS_API_TOKEN && smsUrl(env2));
}
function toE164(phone) {
  const digits = String(phone || "").replace(/[^0-9]/g, "");
  if (!digits) return "";
  if (digits.startsWith("0") && digits.length === 10) {
    return "+254" + digits.substring(1);
  }
  if (digits.length === 9 && (digits.startsWith("7") || digits.startsWith("1"))) {
    return "+254" + digits;
  }
  if (digits.startsWith("254") && (digits.length === 12 || digits.length === 11)) {
    return "+" + digits;
  }
  return "+" + digits;
}
async function sendSms(env2, phone, message) {
  if (!smsConfigured(env2)) {
    return { simulated: true, success: true };
  }
  const provider = smsProvider(env2);
  const url = smsUrl(env2);
  try {
    let body;
    if (provider === "talksasa") {
      body = {
        recipient: toE164(phone),
        sender_id: env2.SMS_SENDER_ID || "Farmsky",
        // Matches your exact whitelisted sender string
        type: "plain",
        message
      };
    } else if (env2.SMS_BODY_TEMPLATE) {
      const filled = env2.SMS_BODY_TEMPLATE.replace(/\{phone\}/g, phone).replace(/\{message\}/g, message.replace(/"/g, '\\"')).replace(/\{sender\}/g, env2.SMS_SENDER_ID || "");
      body = JSON.parse(filled);
    } else {
      const phoneField = env2.SMS_PHONE_FIELD || "to";
      const msgField = env2.SMS_MESSAGE_FIELD || "message";
      body = { [phoneField]: phone, [msgField]: message };
      if (env2.SMS_SENDER_ID) body.sender = env2.SMS_SENDER_ID;
    }
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env2.SMS_API_TOKEN}`,
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

// backend/email.ts
var RESEND_DEFAULT_URL = "https://api.resend.com/emails";
function emailProvider(env2) {
  return (env2.EMAIL_PROVIDER || "resend").toLowerCase();
}
function emailUrl(env2) {
  if (env2.EMAIL_API_URL) return env2.EMAIL_API_URL;
  if (emailProvider(env2) === "resend") return RESEND_DEFAULT_URL;
  return "";
}
function emailConfigured(env2) {
  return !!(env2.EMAIL_API_TOKEN && env2.EMAIL_FROM && emailUrl(env2));
}
async function sendEmail(env2, opts) {
  if (!emailConfigured(env2)) return { configured: false, success: false };
  const provider = emailProvider(env2);
  const url = emailUrl(env2);
  try {
    let body;
    if (provider === "sendgrid") {
      body = {
        personalizations: [{ to: [{ email: opts.to }] }],
        from: { email: env2.EMAIL_FROM },
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
        from: env2.EMAIL_FROM,
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
        Authorization: `Bearer ${env2.EMAIL_API_TOKEN}`,
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

// backend/password.ts
var ITERATIONS = 21e4;
var KEYLEN = 32;
var PREFIX = "pbkdf2";
var enc = new TextEncoder();
function toB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function fromB64(b642) {
  const bin = atob(b642);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function derive(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    KEYLEN * 8
  );
  return new Uint8Array(bits);
}
function isHashed(stored) {
  return typeof stored === "string" && stored.startsWith(PREFIX + "$");
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(String(password), salt, ITERATIONS);
  return `${PREFIX}$${ITERATIONS}$${toB64(salt)}$${toB64(hash)}`;
}
function timingSafeEqual2(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function verifyPassword(password, stored) {
  if (stored == null) return { ok: false, legacy: false };
  const pw = String(password);
  if (isHashed(stored)) {
    const parts = stored.split("$");
    if (parts.length !== 4) return { ok: false, legacy: false };
    const iterations = Number(parts[1]) || ITERATIONS;
    const salt = fromB64(parts[2]);
    const expected = fromB64(parts[3]);
    const actual = await derive(pw, salt, iterations);
    return { ok: timingSafeEqual2(actual, expected), legacy: false };
  }
  const a = enc.encode(pw);
  const b = enc.encode(String(stored));
  return { ok: timingSafeEqual2(a, b), legacy: true };
}

// backend/payment-gateway-client.ts
init_payments_shared();
function gatewayConfigured(env2) {
  return Boolean(
    env2.FARMSKY_PAYMENTS_GATEWAY_URL && env2.FARMSKY_PAYMENTS_CLIENT_KEY && env2.FARMSKY_PAYMENTS_HMAC_SECRET
  );
}
function baseUrl4(env2) {
  return String(env2.FARMSKY_PAYMENTS_GATEWAY_URL || "").replace(/\/+$/, "");
}
async function initiatePayment(env2, opts) {
  if (!gatewayConfigured(env2)) {
    return { success: false, error: "gateway_not_configured" };
  }
  const clientKey = String(env2.FARMSKY_PAYMENTS_CLIENT_KEY);
  const secret = String(env2.FARMSKY_PAYMENTS_HMAC_SECRET);
  const body = JSON.stringify({
    amount: opts.amount,
    phone: opts.phone,
    payment_method: opts.payment_method,
    origin_reference: opts.origin_reference,
    description: opts.description,
    initiated_by_user: opts.initiated_by_user
  });
  const { timestamp: timestamp2, nonce, signature } = await signRequest(secret, clientKey, body);
  const headers = {
    "Content-Type": "application/json",
    "X-Farmsky-Client": clientKey,
    "X-Farmsky-Timestamp": timestamp2,
    "X-Farmsky-Nonce": nonce,
    "X-Farmsky-Signature": signature
  };
  if (opts.idempotency_key) headers["Idempotency-Key"] = opts.idempotency_key;
  const res = await fetch(`${baseUrl4(env2)}/initiate`, { method: "POST", headers, body });
  const json = await res.json().catch(() => ({}));
  if (!res.ok && json?.success == null) {
    return { success: false, error: json?.error || `gateway_http_${res.status}` };
  }
  return json;
}
async function getPaymentStatus(env2, transactionRef) {
  if (!gatewayConfigured(env2)) return { success: false, error: "gateway_not_configured" };
  const clientKey = String(env2.FARMSKY_PAYMENTS_CLIENT_KEY);
  const secret = String(env2.FARMSKY_PAYMENTS_HMAC_SECRET);
  const { timestamp: timestamp2, nonce, signature } = await signRequest(secret, clientKey, transactionRef);
  const headers = {
    "X-Farmsky-Client": clientKey,
    "X-Farmsky-Timestamp": timestamp2,
    "X-Farmsky-Nonce": nonce,
    "X-Farmsky-Signature": signature
  };
  const res = await fetch(`${baseUrl4(env2)}/status/${encodeURIComponent(transactionRef)}`, { headers });
  return await res.json().catch(() => ({ success: false, error: `gateway_http_${res.status}` }));
}

// backend/index.tsx
var app = new Hono2();
app.use("/api/*", cors({
  origin: (origin) => origin || "*",
  // reflect the caller's own origin
  credentials: true,
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization", "X-SasaPay-Signature"],
  maxAge: 600
}));
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "SAMEORIGIN");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header("X-XSS-Protection", "0");
  c.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  c.header("Cross-Origin-Opener-Policy", "same-origin");
});
var _rlBuckets = /* @__PURE__ */ new Map();
function rateLimit(bucket, max, windowMs) {
  return async (c, next) => {
    const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for")?.split(",")[0].trim() || c.req.header("x-real-ip") || "unknown";
    const key = `${bucket}:${ip}`;
    const now = Date.now();
    const rec = _rlBuckets.get(key);
    if (!rec || rec.resetAt < now) {
      _rlBuckets.set(key, { count: 1, resetAt: now + windowMs });
    } else {
      rec.count++;
      if (rec.count > max) {
        const retry = Math.ceil((rec.resetAt - now) / 1e3);
        c.header("Retry-After", String(retry));
        return c.json({ error: "Too many requests. Please slow down and try again shortly." }, 429);
      }
    }
    if (_rlBuckets.size > 5e3) {
      for (const [k, v] of _rlBuckets) {
        if (v.resetAt < now) _rlBuckets.delete(k);
      }
    }
    await next();
  };
}
app.use("/api/login", rateLimit("login", 10, 6e4));
app.use("/api/signup/request-otp", rateLimit("otp", 8, 6e4));
app.use("/api/reset-password/request-otp", rateLimit("otp", 8, 6e4));
app.use("/api/sasapay/stkpush", rateLimit("pay", 20, 6e4));
app.use("/api/mpesa/stkpush", rateLimit("pay", 20, 6e4));
app.use("/api/buni/stkpush", rateLimit("pay", 20, 6e4));
function genToken() {
  return crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
}
function ref(prefix) {
  const n = Math.floor(Math.random() * 9e5 + 1e5);
  return `${prefix}-${Date.now().toString().slice(-6)}${n}`;
}
function safeJson(value, fallback) {
  try {
    return value ? JSON.parse(String(value)) : fallback;
  } catch {
    return fallback;
  }
}
function builtinDefaults(role) {
  if (["super_admin", "admin"].includes(role)) {
    return { view: true, edit: true, delete: true, deactivate: true, approve: true, dispatch: true, add_farmer: true, view_farmers: true, view_credit_purchases: true, manage_users: true, request_admin_action: true, can_manage_inventory: true, can_manage_finance_settings: true, view_wallet: true, manage_wallets: true };
  }
  if (role === "operations_finance") {
    return { view: true, approve: true, dispatch: true, view_farmers: true, view_credit_purchases: true, request_admin_action: true, can_manage_finance_settings: true };
  }
  if (role === "agent") {
    return { view: true, add_farmer: true, view_farmers: true, view_credit_purchases: true, can_manage_inventory: true, view_wallet: true };
  }
  if (role === "support") {
    return { view: true, view_farmers: true, view_credit_purchases: true };
  }
  if (role === "lender") {
    return { view: true, view_credit_purchases: true };
  }
  if (role === "mne") {
    return { view: true, view_farmers: true, view_credit_purchases: true };
  }
  if (["investor", "partner"].includes(role)) {
    return { view: true };
  }
  return { view: true };
}
async function loadRoleTemplate(c, role) {
  try {
    const row = await c.env.DB.prepare(`SELECT permissions FROM role_templates WHERE role_key=?`).bind(role).first();
    if (row?.permissions) {
      const parsed = safeJson(row.permissions, {});
      if (parsed && Object.keys(parsed).length) return parsed;
    }
  } catch (_) {
  }
  return builtinDefaults(role);
}
function defaultPermissions(role) {
  return builtinDefaults(role);
}
function parsePermissions(raw2, role, fallback) {
  const base = fallback ?? defaultPermissions(role);
  return { ...base, ...safeJson(raw2, {}) };
}
async function permissionsForRole(c, role, override) {
  const base = await loadRoleTemplate(c, role);
  return { ...base, ...override || {} };
}
function hasPermission(user, perm) {
  if (["super_admin", "admin"].includes(user.role)) return true;
  return Boolean(user.permissions?.[perm]);
}
function hasVisibility(user, perm) {
  if (["super_admin", "admin"].includes(user.role)) return true;
  const v = user.permissions?.[perm];
  return v === void 0 ? true : Boolean(v);
}
var FINANCIAL_FIELDS = ["existing_loans", "credit_score", "risk_band", "annual_production"];
var PROFILE_FIELDS = ["value_chain", "value_chain_type", "county", "sub_county", "ward", "village", "acreage", "herd_size", "farm_experience", "sacco_membership", "date_of_birth", "gender", "latitude", "longitude"];
var DOCUMENT_FIELDS = ["id_front_url", "id_back_url", "selfie_url", "passport_photo_url"];
function redactCustomer(user, cust) {
  if (!cust) return cust;
  const out = { ...cust };
  if (!hasVisibility(user, "view_financial_data")) {
    for (const f of FINANCIAL_FIELDS) if (f in out) out[f] = null;
  }
  if (!hasVisibility(user, "view_farmer_profile_data")) {
    for (const f of PROFILE_FIELDS) if (f in out) out[f] = null;
  }
  if (!hasVisibility(user, "view_document_attachments")) {
    for (const f of DOCUMENT_FIELDS) if (f in out) out[f] = null;
  }
  return out;
}
function numberVal(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}
function boolInt(value, fallback = true) {
  if (value === void 0 || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}
function roundMoney(value) {
  return Math.round((Number(value) || 0) * 100) / 100;
}
async function getSetting(c, key, fallback) {
  try {
    const row = await c.env.DB.prepare(`SELECT setting_value FROM app_settings WHERE setting_key=?`).bind(key).first();
    if (row?.setting_value) return safeJson(row.setting_value, fallback);
  } catch (_) {
  }
  return fallback;
}
async function setSetting(c, key, value) {
  const json = JSON.stringify(value);
  const existing = await c.env.DB.prepare(`SELECT setting_key FROM app_settings WHERE setting_key=?`).bind(key).first();
  if (existing) {
    await c.env.DB.prepare(`UPDATE app_settings SET setting_value=?, updated_at=CURRENT_TIMESTAMP WHERE setting_key=?`).bind(json, key).run();
  } else {
    await c.env.DB.prepare(`INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?)`).bind(key, json).run();
  }
}
var DEFAULT_PROCESSING_FEE = { enabled: false, mode: "percentage", percentage_rate: 0, tiers: [], product_ids: [] };
function normalizeProductIds(raw2) {
  if (!Array.isArray(raw2)) return [];
  const ids = raw2.map((v) => Number(v)).filter((n) => Number.isFinite(n) && n > 0);
  return Array.from(new Set(ids));
}
function normalizeProcessingFee(raw2) {
  const cfg = { ...DEFAULT_PROCESSING_FEE, ...raw2 && typeof raw2 === "object" ? raw2 : {} };
  cfg.enabled = Boolean(cfg.enabled);
  cfg.mode = cfg.mode === "tiered" ? "tiered" : "percentage";
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 0);
  cfg.tiers = Array.isArray(cfg.tiers) ? cfg.tiers.map((t) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), fee: numberVal(t.fee, 0) })).filter((t) => t.max >= t.min) : [];
  cfg.product_ids = normalizeProductIds(cfg.product_ids);
  return cfg;
}
var DEFAULT_FINANCING_MARKUP = {
  financing_applicable: true,
  mode: "percentage",
  // 'percentage' | 'tiered'
  percentage_rate: 20,
  tiers: [],
  default_cash_markup_pct: 10,
  default_credit_markup_pct: 20,
  cash_markup_pct: 10,
  cash_terms_text: "",
  product_ids: []
};
function normalizeFinancingMarkup(raw2) {
  const cfg = { ...DEFAULT_FINANCING_MARKUP, ...raw2 && typeof raw2 === "object" ? raw2 : {} };
  cfg.financing_applicable = raw2 && Object.prototype.hasOwnProperty.call(raw2, "financing_applicable") ? Boolean(cfg.financing_applicable) : true;
  cfg.mode = cfg.mode === "tiered" ? "tiered" : "percentage";
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 20);
  cfg.tiers = Array.isArray(cfg.tiers) ? cfg.tiers.map((t) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), markup: numberVal(t.markup, 0) })).filter((t) => t.max >= t.min) : [];
  cfg.cash_markup_pct = numberVal(cfg.cash_markup_pct, 10);
  cfg.cash_terms_text = String(cfg.cash_terms_text || "");
  cfg.default_credit_markup_pct = cfg.mode === "percentage" ? cfg.percentage_rate : numberVal(cfg.default_credit_markup_pct, 20);
  cfg.default_cash_markup_pct = cfg.cash_markup_pct;
  cfg.product_ids = normalizeProductIds(cfg.product_ids);
  return cfg;
}
function computeProcessingFee(cfg, borrowedAmount, productId) {
  const c = normalizeProcessingFee(cfg);
  if (!c.enabled) return 0;
  if (Array.isArray(c.product_ids) && c.product_ids.length > 0) {
    const pid = Number(productId);
    if (!Number.isFinite(pid) || !c.product_ids.includes(pid)) return 0;
  }
  const amount = Number(borrowedAmount) || 0;
  if (c.mode === "percentage") return roundMoney(amount * (c.percentage_rate / 100));
  const tier = c.tiers.find((t) => amount >= t.min && amount <= t.max);
  return tier ? roundMoney(tier.fee) : 0;
}
var DAY_KEYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
function parseHM(value) {
  const m = String(value || "").match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return null;
  return Number(m[1]) * 60 + Number(m[2]);
}
function checkAccessWindow(schedule, now = /* @__PURE__ */ new Date()) {
  if (!schedule || !schedule.enabled) return { allowed: true };
  const days = Array.isArray(schedule.days) ? schedule.days.map((d) => String(d).toLowerCase()) : [];
  const today = DAY_KEYS[now.getDay()];
  if (days.length && !days.includes(today)) {
    return { allowed: false, reason: "Access is not permitted on this day for your role." };
  }
  const start = parseHM(schedule.start);
  const end = parseHM(schedule.end);
  if (start !== null && end !== null) {
    const cur = now.getHours() * 60 + now.getMinutes();
    if (cur < start || cur > end) {
      return { allowed: false, reason: `Access is only permitted between ${schedule.start} and ${schedule.end}.` };
    }
  }
  return { allowed: true };
}
async function resolveAccessWindow(c, user) {
  if (Number(user.schedule_enabled) === 1) {
    return { enabled: true, days: safeJson(user.access_days, []), start: user.access_start || "", end: user.access_end || "" };
  }
  try {
    const row = await c.env.DB.prepare(`SELECT schedule_enabled, access_days, access_start, access_end FROM role_templates WHERE role_key=?`).bind(user.role).first();
    if (row && Number(row.schedule_enabled) === 1) {
      return { enabled: true, days: safeJson(row.access_days, []), start: row.access_start || "", end: row.access_end || "" };
    }
  } catch (_) {
  }
  return { enabled: false, days: [], start: "", end: "" };
}
function normalizeProductPayload(b) {
  const buying = numberVal(b.buying_price);
  const cashMarkup = numberVal(b.cash_markup_pct, 10);
  const creditMarkup = numberVal(b.credit_markup_pct, 20);
  const cashPrice = numberVal(b.cash_price, roundMoney(buying * (1 + cashMarkup / 100)));
  const creditPrice = numberVal(b.credit_price, roundMoney(buying * (1 + creditMarkup / 100)));
  const paymentMode = b.payment_option_mode || (boolInt(b.cash_enabled, true) && boolInt(b.financing_enabled, true) ? "both" : boolInt(b.cash_enabled, true) ? "cash" : "financing");
  return {
    sku: String(b.sku || "").trim(),
    name: String(b.name || "").trim(),
    category: String(b.category || "Equipment").trim(),
    description: b.description || null,
    product_type: b.product_type || "equipment",
    supplier_id: b.supplier_id || null,
    buying_price: buying,
    cash_markup_pct: cashMarkup,
    credit_markup_pct: creditMarkup,
    cash_price: cashPrice,
    credit_price: creditPrice,
    quantity: numberVal(b.quantity, 0),
    unit: b.unit || "unit",
    reorder_threshold: numberVal(b.reorder_threshold, 10),
    image: b.image || null,
    cash_enabled: boolInt(b.cash_enabled, paymentMode !== "financing"),
    financing_enabled: boolInt(b.financing_enabled, paymentMode !== "cash"),
    payment_option_mode: paymentMode,
    financing_model: b.financing_model || "loan_interest",
    financing_interest_pct: numberVal(b.financing_interest_pct, 0),
    financing_frequency: b.financing_frequency || "monthly",
    financing_term_min_months: numberVal(b.financing_term_min_months, 3),
    financing_term_max_months: numberVal(b.financing_term_max_months, 12),
    cash_deposit_pct: numberVal(b.cash_deposit_pct, 100),
    financing_deposit_pct: numberVal(b.financing_deposit_pct, 10),
    cash_terms_text: b.cash_terms_text || null,
    financing_terms_text: b.financing_terms_text || null,
    cash_terms_doc_url: b.cash_terms_doc_url || null,
    financing_terms_doc_url: b.financing_terms_doc_url || null,
    transunion_product_code: b.transunion_product_code || null
  };
}
function financingQuote(p, quantity, paymentType, termMonths, processingFeeCfg) {
  const qty = Math.max(1, numberVal(quantity, 1));
  const supplier_cost = roundMoney(numberVal(p.buying_price) * qty);
  if (paymentType === "cash") {
    const total = roundMoney(numberVal(p.cash_price) * qty);
    const deposit_pct2 = numberVal(p.cash_deposit_pct, 100);
    const amount_due_now = roundMoney(total * deposit_pct2 / 100);
    return {
      quantity: qty,
      supplier_cost,
      payment_type: "cash",
      financing_model: "cash",
      markup_pct: numberVal(p.cash_markup_pct, 0),
      amount_due_now,
      deposit_pct: deposit_pct2,
      deposit_amount: amount_due_now,
      finance_principal: total,
      term_months: 0,
      payment_frequency: "one_off",
      installment_count: 0,
      installment_amount: 0,
      total_price: total,
      total_payable: total,
      outstanding_after_deposit: roundMoney(total - amount_due_now),
      disclosure_note: deposit_pct2 >= 100 ? "Full cash payment is required at checkout." : deposit_pct2 > 0 ? `A ${deposit_pct2}% deposit is required to confirm the cash order.` : "No deposit is required at checkout for this cash order.",
      terms_text: p.cash_terms_text || null,
      terms_document_url: p.cash_terms_doc_url || null
    };
  }
  const term = Math.max(numberVal(p.financing_term_min_months, 3), Math.min(numberVal(termMonths, numberVal(p.financing_term_min_months, 3)), numberVal(p.financing_term_max_months, 12)));
  const principalBase = roundMoney(numberVal(p.credit_price || p.cash_price) * qty);
  const deposit_pct = numberVal(p.financing_deposit_pct, 10);
  const deposit_amount = roundMoney(principalBase * deposit_pct / 100);
  const finance_principal = roundMoney(principalBase - deposit_amount);
  const interestRate = 0;
  const model = "murabaha";
  const frequency = p.financing_frequency && ["monthly", "weekly"].includes(p.financing_frequency) ? p.financing_frequency : "monthly";
  const installment_count = frequency === "weekly" ? term * 4 : term;
  const financing_charge = 0;
  const processing_fee = computeProcessingFee(processingFeeCfg, finance_principal, p.id);
  const financed_total = roundMoney(finance_principal + financing_charge + processing_fee);
  const installment_amount = installment_count > 0 ? roundMoney(financed_total / installment_count) : financed_total;
  const total_payable = roundMoney(deposit_amount + financed_total);
  return {
    quantity: qty,
    supplier_cost,
    payment_type: "financing",
    financing_model: model,
    markup_pct: numberVal(p.credit_markup_pct, 0),
    amount_due_now: deposit_amount,
    deposit_pct,
    deposit_amount,
    finance_principal,
    processing_fee,
    interest_rate_pct: interestRate,
    term_months: term,
    payment_frequency: frequency,
    installment_count,
    installment_amount,
    monthly_payment: frequency === "monthly" ? installment_amount : roundMoney(financed_total / Math.max(term, 1)),
    total_price: principalBase,
    total_payable,
    outstanding_after_deposit: financed_total,
    disclosure_note: "Sharia-compliant Murabaha: a fixed cost-plus markup is agreed up front and repaid in equal installments over the selected term. No interest (riba) is charged." + (processing_fee > 0 ? ` A processing fee of ${processing_fee.toLocaleString()} applies to the financed amount.` : ""),
    terms_text: p.financing_terms_text || null,
    terms_document_url: p.financing_terms_doc_url || null
  };
}
async function getSessionUser(c) {
  const token = getCookie(c, "session") || c.req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return null;
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.avatar_url, u.role, u.region, u.label, u.permissions, u.status,
            u.schedule_enabled, u.access_days, u.access_start, u.access_end, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first();
  if (!row) return null;
  if (Number(row.expires_at) < Date.now()) return null;
  if (row.status !== "active") return null;
  const window = await resolveAccessWindow(c, row);
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end });
  if (!access.allowed) return null;
  const fallback = await loadRoleTemplate(c, row.role);
  return {
    id: row.id,
    full_name: row.full_name,
    phone: row.phone,
    email: row.email || null,
    avatar_url: row.avatar_url || null,
    role: row.role,
    region: row.region,
    label: row.label || null,
    permissions: parsePermissions(row.permissions, row.role, fallback)
  };
}
async function setUserContext(c, user) {
  const setLocal = c.env.DB?.setSessionConfig;
  if (typeof setLocal !== "function") return;
  try {
    await setLocal.call(c.env.DB, "app.current_user_id", user ? String(user.id) : "");
    await setLocal.call(c.env.DB, "app.current_role", user ? String(user.role) : "");
    const canFinance = user ? ["admin", "super_admin"].includes(user.role) || Boolean(user.permissions?.can_manage_finance_settings) : false;
    await setLocal.call(c.env.DB, "app.user_can_finance", canFinance ? "true" : "false");
  } catch (_) {
  }
}
async function withAdminContext(c, fn) {
  const setLocal = c.env.DB?.setSessionConfig;
  const depth = c.get("__adminCtxDepth") || 0;
  if (depth === 0 && typeof setLocal === "function") {
    try {
      await setLocal.call(c.env.DB, "app.current_role", "admin");
      await setLocal.call(c.env.DB, "app.user_can_finance", "true");
    } catch (_) {
    }
  }
  c.set("__adminCtxDepth", depth + 1);
  try {
    return await fn();
  } finally {
    c.set("__adminCtxDepth", depth);
    if (depth === 0) await setUserContext(c, c.get("user") || null);
  }
}
async function requireAuth(c, next) {
  const user = await getSessionUser(c);
  if (!user) return c.json({ error: "Unauthorized" }, 401);
  c.set("user", user);
  await setUserContext(c, user);
  await next();
}
function requireRole(...roles) {
  return async (c, next) => {
    const user = c.get("user");
    if (!roles.includes(user.role)) return c.json({ error: "Forbidden" }, 403);
    await next();
  };
}
function requirePermission(...perms) {
  return async (c, next) => {
    const user = c.get("user");
    if (!perms.some((perm) => hasPermission(user, perm))) return c.json({ error: "Forbidden" }, 403);
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
  const isHttps = (c.req.header("x-forwarded-proto") || "").includes("https") || new URL(c.req.url).protocol === "https:";
  setCookie(c, "session", token, { path: "/", httpOnly: true, maxAge: 60 * 60 * 12, sameSite: "Lax", secure: isHttps });
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
  const check = user ? await verifyPassword(String(password), user.password) : { ok: false, legacy: false };
  if (!user || !check.ok) return c.json({ error: "Invalid phone number or password" }, 401);
  if (user.status !== "active") return c.json({ error: "Account suspended" }, 403);
  if (check.legacy) {
    try {
      await c.env.DB.prepare(`UPDATE users SET password=? WHERE id=?`).bind(await hashPassword(String(password)), user.id).run();
    } catch (_) {
    }
  }
  const window = await resolveAccessWindow(c, user);
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end });
  if (!access.allowed) return c.json({ error: access.reason || "Access is restricted at this time." }, 403);
  const token = await createSession(c, user);
  await audit(c, user.id, "login", "user", `${user.role} logged in`);
  const loginFallback = await loadRoleTemplate(c, user.role);
  return c.json({ token, user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role, region: user.region, label: user.label || null, permissions: parsePermissions(user.permissions, user.role, loginFallback) } });
});
app.post("/api/logout", async (c) => {
  const token = getCookie(c, "session");
  if (token) await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
  deleteCookie(c, "session", { path: "/" });
  return c.json({ ok: true });
});
app.get("/api/me", requireAuth, (c) => c.json({ user: c.get("user") }));
app.get("/api/me/profile", requireAuth, async (c) => {
  const user = c.get("user");
  let customer = null;
  if (user.role === "customer") {
    customer = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first();
  }
  return c.json({ user, customer });
});
app.put("/api/me/avatar", requireAuth, async (c) => {
  const user = c.get("user");
  const { avatar_url } = await c.req.json();
  await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(avatar_url || null, user.id).run();
  await audit(c, user.id, "update", "profile", "avatar");
  return c.json({ ok: true, avatar_url: avatar_url || null });
});
app.put("/api/me/password", requireAuth, async (c) => {
  const user = c.get("user");
  const { current_password, new_password } = await c.req.json();
  if (!new_password || String(new_password).length < 4) return c.json({ error: "New password must be at least 4 characters" }, 400);
  const row = await c.env.DB.prepare(`SELECT password FROM users WHERE id=?`).bind(user.id).first();
  const chk = row ? await verifyPassword(String(current_password), row.password) : { ok: false };
  if (!row || !chk.ok) return c.json({ error: "Current password is incorrect" }, 400);
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(await hashPassword(String(new_password)), user.id).run();
  await audit(c, user.id, "update", "profile", "password change");
  return c.json({ ok: true });
});
app.put("/api/me/profile", requireAuth, async (c) => {
  const user = c.get("user");
  const b = await c.req.json();
  if (b.avatar_url !== void 0) {
    await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(b.avatar_url || null, user.id).run();
  }
  if (user.role !== "customer") {
    await audit(c, user.id, "update", "profile", "avatar (non-farmer self-update)");
    const updated2 = await getSessionUser(c);
    return c.json({ ok: true, user: updated2, note: "Only your profile picture and password can be changed here." });
  }
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first();
  if (!cust) return c.json({ error: "Farmer profile not found" }, 404);
  const saccoProvided = b.sacco_membership !== void 0;
  const saccoMember = ["yes", "true", "1", "on"].includes(String(b.sacco_membership || "").toLowerCase());
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership)
     WHERE id=?`
  ).bind(
    b.full_name ?? null,
    b.date_of_birth ?? null,
    b.gender ?? null,
    b.alt_mobile ?? null,
    b.county ?? null,
    b.sub_county ?? null,
    b.ward ?? null,
    b.village ?? null,
    b.latitude ?? null,
    b.longitude ?? null,
    b.value_chain_type ?? null,
    b.value_chain ?? null,
    b.acreage ?? null,
    b.herd_size ?? null,
    b.farm_experience ?? null,
    b.annual_production ?? null,
    b.existing_loans ?? null,
    saccoProvided ? saccoMember ? "yes" : "no" : null,
    cust.id
  ).run();
  if (b.full_name) {
    await c.env.DB.prepare(`UPDATE users SET full_name=? WHERE id=?`).bind(String(b.full_name).trim(), user.id).run();
  }
  await audit(c, user.id, "update", "profile", "farmer self-update (ID & phone locked)");
  const updated = await getSessionUser(c);
  return c.json({ ok: true, user: updated });
});
app.get("/api/auth/status", (c) => c.json({ sms_live: smsConfigured(c.env) }));
app.get("/api/integrations/transunion/status", requireAuth, (c) => {
  const live = Boolean(c.env.TRANSUNION_API_URL && c.env.TRANSUNION_API_KEY);
  return c.json({ live, environment: c.env.TRANSUNION_ENV || "stub", ready_for_mapping: live });
});
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
  const { phone, full_name, code, password, region, national_id, id_front_url, id_back_url } = await c.req.json();
  const p = normalizePhone(phone || "");
  if (!password || String(password).length < 4) return c.json({ error: "Password must be at least 4 characters" }, 400);
  if (!id_front_url || !id_back_url) return c.json({ error: "Upload front and back of the national ID to continue" }, 400);
  const v = await verifyOtp(c, p, code, "signup");
  if (!v.ok) return c.json({ error: v.error }, 400);
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (existing) return c.json({ error: "Account already exists. Please sign in." }, 409);
  const role = "customer";
  const farmerPerms = await permissionsForRole(c, role);
  const r = await c.env.DB.prepare(
    `INSERT INTO users (full_name, phone, password, role, status, region, password_set, label, permissions) VALUES (?,?,?, ?, 'active', ?, 1, ?, ?)`
  ).bind(String(full_name).trim(), p, await hashPassword(String(password)), role, region || null, "Farmer", JSON.stringify(farmerPerms)).run();
  const userId = r.meta.last_row_id;
  await c.env.DB.prepare(
    `INSERT INTO customers (user_id, full_name, national_id, mobile, id_front_url, id_back_url, kyc_status) VALUES (?,?,?,?,?,?, 'pending')`
  ).bind(userId, String(full_name).trim(), national_id || null, p, id_front_url, id_back_url).run();
  const user = { id: userId, full_name: String(full_name).trim(), phone: p, role, region, label: "Farmer", permissions: farmerPerms };
  await createSession(c, user);
  await audit(c, userId, "signup", "user", "customer self-registered via SMS OTP with ID documents");
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
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(await hashPassword(String(password)), user.id).run();
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(user.id).run();
  await audit(c, user.id, "reset_password", "user", "password reset via SMS OTP");
  return c.json({ ok: true, message: "Password updated. You can now sign in." });
});
app.get("/api/products", requireAuth, async (c) => {
  const user = c.get("user");
  const mine = c.req.query("mine") === "1";
  const shop = c.req.query("shop") === "1";
  const rows = await withAdminContext(c, async () => {
    let query = `SELECT * FROM products`;
    const binds = [];
    const where = [];
    if (shop) where.push(`finance_status = 'published'`);
    if (mine && !["admin", "super_admin"].includes(user.role)) {
      where.push(`created_by = ?`);
      binds.push(user.id);
    }
    if (where.length) query += ` WHERE ` + where.join(" AND ");
    query += ` ORDER BY name`;
    const { results } = await c.env.DB.prepare(query).bind(...binds).all();
    return results;
  });
  const withStatus = rows.map((p) => ({
    ...p,
    stock_status: p.quantity <= 0 ? "out_of_stock" : p.quantity <= p.reorder_threshold ? "low_stock" : "in_stock"
  }));
  return c.json({ products: withStatus, can_manage_inventory: hasPermission(user, "can_manage_inventory"), can_manage_finance_settings: hasPermission(user, "can_manage_finance_settings") });
});
app.post("/api/products", requireAuth, requirePermission("can_manage_inventory"), async (c) => {
  const user = c.get("user");
  const canFinance = hasPermission(user, "can_manage_finance_settings");
  const p = normalizeProductPayload(await c.req.json());
  if (!p.sku || !p.name) return c.json({ error: "SKU and name are required" }, 400);
  let financeStatus = "published";
  if (!canFinance) {
    p.credit_markup_pct = 0;
    p.credit_price = p.cash_price;
    p.financing_enabled = false;
    p.financing_interest_pct = 0;
    p.financing_terms_text = null;
    p.financing_terms_doc_url = null;
    p.payment_option_mode = "cash";
    financeStatus = "pending_finance";
  }
  const financeSetBy = canFinance ? user.id : null;
  const r = await c.env.DB.prepare(
    `INSERT INTO products (sku,name,category,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url,transunion_product_code,created_by,finance_status,finance_set_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    p.sku,
    p.name,
    p.category,
    p.description,
    p.product_type,
    p.supplier_id,
    p.buying_price,
    p.cash_markup_pct,
    p.credit_markup_pct,
    p.cash_price,
    p.credit_price,
    p.quantity,
    p.unit,
    p.reorder_threshold,
    p.image,
    p.cash_enabled,
    p.financing_enabled,
    p.payment_option_mode,
    p.financing_model,
    p.financing_interest_pct,
    p.financing_frequency,
    p.financing_term_min_months,
    p.financing_term_max_months,
    p.cash_deposit_pct,
    p.financing_deposit_pct,
    p.cash_terms_text,
    p.financing_terms_text,
    p.cash_terms_doc_url,
    p.financing_terms_doc_url,
    p.transunion_product_code,
    user.id,
    financeStatus,
    financeSetBy
  ).run();
  await audit(c, user.id, "create", "product", `${p.name} (${financeStatus})`);
  return c.json({ id: r.meta.last_row_id, finance_status: financeStatus });
});
app.put("/api/products/:id", requireAuth, requirePermission("can_manage_inventory", "can_manage_finance_settings"), async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const canInv = hasPermission(user, "can_manage_inventory");
  const canFinance = hasPermission(user, "can_manage_finance_settings");
  const existing = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(id).first());
  if (!existing) return c.json({ error: "Not found" }, 404);
  const p = normalizeProductPayload(await c.req.json());
  const coreCols = canInv ? {
    sku: p.sku,
    name: p.name,
    category: p.category,
    description: p.description,
    product_type: p.product_type,
    buying_price: p.buying_price,
    cash_markup_pct: p.cash_markup_pct,
    cash_price: p.cash_price,
    quantity: p.quantity,
    unit: p.unit,
    reorder_threshold: p.reorder_threshold,
    image: p.image || existing.image,
    cash_enabled: p.cash_enabled,
    cash_deposit_pct: p.cash_deposit_pct,
    cash_terms_text: p.cash_terms_text,
    cash_terms_doc_url: p.cash_terms_doc_url
  } : {
    sku: existing.sku,
    name: existing.name,
    category: existing.category,
    description: existing.description,
    product_type: existing.product_type,
    buying_price: existing.buying_price,
    cash_markup_pct: existing.cash_markup_pct,
    cash_price: existing.cash_price,
    quantity: existing.quantity,
    unit: existing.unit,
    reorder_threshold: existing.reorder_threshold,
    image: existing.image,
    cash_enabled: existing.cash_enabled,
    cash_deposit_pct: existing.cash_deposit_pct,
    cash_terms_text: existing.cash_terms_text,
    cash_terms_doc_url: existing.cash_terms_doc_url
  };
  const finCols = canFinance ? {
    credit_markup_pct: p.credit_markup_pct,
    credit_price: p.credit_price,
    financing_enabled: p.financing_enabled,
    financing_model: p.financing_model,
    financing_interest_pct: p.financing_interest_pct,
    financing_frequency: p.financing_frequency,
    financing_term_min_months: p.financing_term_min_months,
    financing_term_max_months: p.financing_term_max_months,
    financing_deposit_pct: p.financing_deposit_pct,
    financing_terms_text: p.financing_terms_text,
    financing_terms_doc_url: p.financing_terms_doc_url,
    transunion_product_code: p.transunion_product_code,
    payment_option_mode: p.payment_option_mode,
    finance_status: "published",
    finance_set_by: user.id
  } : {
    credit_markup_pct: existing.credit_markup_pct,
    credit_price: existing.credit_price,
    financing_enabled: existing.financing_enabled,
    financing_model: existing.financing_model,
    financing_interest_pct: existing.financing_interest_pct,
    financing_frequency: existing.financing_frequency,
    financing_term_min_months: existing.financing_term_min_months,
    financing_term_max_months: existing.financing_term_max_months,
    financing_deposit_pct: existing.financing_deposit_pct,
    financing_terms_text: existing.financing_terms_text,
    financing_terms_doc_url: existing.financing_terms_doc_url,
    transunion_product_code: existing.transunion_product_code,
    payment_option_mode: existing.payment_option_mode,
    finance_status: existing.finance_status,
    finance_set_by: existing.finance_set_by
  };
  await c.env.DB.prepare(
    `UPDATE products SET sku=?, name=?, category=?, description=?, product_type=?, buying_price=?, cash_markup_pct=?, credit_markup_pct=?, cash_price=?, credit_price=?, quantity=?, unit=?, reorder_threshold=?, image=COALESCE(?, image), cash_enabled=?, financing_enabled=?, payment_option_mode=?, financing_model=?, financing_interest_pct=?, financing_frequency=?, financing_term_min_months=?, financing_term_max_months=?, cash_deposit_pct=?, financing_deposit_pct=?, cash_terms_text=?, financing_terms_text=?, cash_terms_doc_url=?, financing_terms_doc_url=?, transunion_product_code=?, finance_status=?, finance_set_by=?, finance_set_at=CASE WHEN ?='published' THEN CURRENT_TIMESTAMP ELSE finance_set_at END WHERE id=?`
  ).bind(
    coreCols.sku,
    coreCols.name,
    coreCols.category,
    coreCols.description,
    coreCols.product_type,
    coreCols.buying_price,
    coreCols.cash_markup_pct,
    finCols.credit_markup_pct,
    coreCols.cash_price,
    finCols.credit_price,
    coreCols.quantity,
    coreCols.unit,
    coreCols.reorder_threshold,
    coreCols.image || null,
    coreCols.cash_enabled,
    finCols.financing_enabled,
    finCols.payment_option_mode,
    finCols.financing_model,
    finCols.financing_interest_pct,
    finCols.financing_frequency,
    finCols.financing_term_min_months,
    finCols.financing_term_max_months,
    coreCols.cash_deposit_pct,
    finCols.financing_deposit_pct,
    coreCols.cash_terms_text,
    finCols.financing_terms_text,
    coreCols.cash_terms_doc_url,
    finCols.financing_terms_doc_url,
    finCols.transunion_product_code,
    finCols.finance_status,
    finCols.finance_set_by,
    finCols.finance_status,
    id
  ).run();
  await audit(c, user.id, "update", "product", `${coreCols.name}${canFinance ? "" : " (core only)"}`);
  return c.json({ ok: true });
});
app.delete("/api/products/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE product_id=?`).bind(id).first();
  if (used?.n > 0) return c.json({ error: "Cannot delete: product is referenced by existing purchases" }, 400);
  await c.env.DB.prepare(`DELETE FROM products WHERE id=?`).bind(id).run();
  await audit(c, c.get("user").id, "delete", "product", String(id));
  return c.json({ ok: true });
});
app.put("/api/products/:id/stock", requireAuth, requirePermission("can_manage_inventory"), async (c) => {
  const id = c.req.param("id");
  const { quantity, movement_type } = await c.req.json();
  await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id = ?`).bind(Number(quantity), id).run();
  await c.env.DB.prepare(`INSERT INTO stock_movements (product_id, movement_type, quantity, reference) VALUES (?,?,?,?)`).bind(id, movement_type || "purchase", quantity, "manual adjustment").run();
  return c.json({ ok: true });
});
app.get("/api/products/finance-queue", requireAuth, requirePermission("can_manage_finance_settings"), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.*, u.full_name AS created_by_name
         FROM products p LEFT JOIN users u ON u.id = p.created_by
        WHERE p.finance_status = 'pending_finance'
        ORDER BY p.created_at DESC`
    ).all();
    return results;
  });
  return c.json({ products: rows });
});
app.put("/api/products/:id/finance", requireAuth, requirePermission("can_manage_finance_settings"), async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const b = await c.req.json();
  const publish = b.finance_status !== "pending_finance";
  await c.env.DB.prepare(
    `UPDATE products SET
        credit_markup_pct = COALESCE(?, credit_markup_pct),
        credit_price = COALESCE(?, credit_price),
        financing_enabled = COALESCE(?, financing_enabled),
        financing_model = COALESCE(?, financing_model),
        financing_interest_pct = COALESCE(?, financing_interest_pct),
        financing_frequency = COALESCE(?, financing_frequency),
        financing_term_min_months = COALESCE(?, financing_term_min_months),
        financing_term_max_months = COALESCE(?, financing_term_max_months),
        financing_deposit_pct = COALESCE(?, financing_deposit_pct),
        financing_terms_text = COALESCE(?, financing_terms_text),
        financing_terms_doc_url = COALESCE(?, financing_terms_doc_url),
        payment_option_mode = COALESCE(?, payment_option_mode),
        finance_notes = COALESCE(?, finance_notes),
        finance_status = ?, finance_set_by = ?, finance_set_at = CURRENT_TIMESTAMP
      WHERE id = ?`
  ).bind(
    b.credit_markup_pct ?? null,
    b.credit_price ?? null,
    b.financing_enabled === void 0 ? null : boolInt(b.financing_enabled, true) ? 1 : 0,
    b.financing_model ?? null,
    b.financing_interest_pct ?? null,
    b.financing_frequency ?? null,
    b.financing_term_min_months ?? null,
    b.financing_term_max_months ?? null,
    b.financing_deposit_pct ?? null,
    b.financing_terms_text ?? null,
    b.financing_terms_doc_url ?? null,
    b.payment_option_mode ?? (publish ? "both" : null),
    b.finance_notes ?? null,
    publish ? "published" : "pending_finance",
    user.id,
    id
  ).run();
  await audit(c, user.id, "finance_authorize", "product", `product ${id} ${publish ? "published" : "saved"}`);
  return c.json({ ok: true, finance_status: publish ? "published" : "pending_finance" });
});
app.get("/api/products/finance-audit", requireAuth, requirePermission("can_manage_finance_settings"), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.id, p.sku, p.name, p.finance_status, p.created_at, p.created_by,
              u.full_name AS created_by_name,
              (CASE WHEN p.credit_markup_pct IS NULL OR p.credit_markup_pct = 0 THEN 1 ELSE 0 END) AS missing_markup,
              (CASE WHEN p.financing_terms_text IS NULL OR p.financing_terms_text = '' THEN 1 ELSE 0 END) AS missing_agreement
         FROM products p LEFT JOIN users u ON u.id = p.created_by
        WHERE p.finance_status <> 'published'
        ORDER BY p.created_at ASC`
    ).all();
    return results;
  });
  const list = rows;
  const reminder = list.length ? `${list.length} product(s) are hidden from the storefront pending financial parameters. Authorized finance personnel should review the queue.` : "All products have complete financial parameters and are visible on the storefront.";
  return c.json({ hidden_products: list, count: list.length, reminder, notify_roles: ["admin", "super_admin", "operations_finance"] });
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
  return c.json({ customers: results.map((r) => redactCustomer(user, r)) });
});
app.get("/api/customers/:id", requireAuth, async (c) => {
  const user = c.get("user");
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(c.req.param("id")).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  const tu = await c.env.DB.prepare(`SELECT * FROM transunion_checks WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param("id")).first();
  const idv = await c.env.DB.prepare(`SELECT * FROM id_verifications WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param("id")).first();
  const showFinancial = hasVisibility(user, "view_financial_data");
  return c.json({ customer: redactCustomer(user, cust), transunion: showFinancial ? tu : null, id_verification: idv });
});
app.post("/api/customers", requireAuth, requireRole("agent", "admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const user = c.get("user");
  const saccoMember = ["yes", "true", "1", "on"].includes(String(b.sacco_membership || "").toLowerCase());
  const assignedAgent = user.role === "agent" ? user.id : b.agent_id || user.id;
  const r = await c.env.DB.prepare(
    `INSERT INTO customers (agent_id,onboarded_by,full_name,national_id,date_of_birth,gender,mobile,alt_mobile,county,sub_county,ward,village,latitude,longitude,value_chain_type,value_chain,acreage,herd_size,farm_experience,annual_production,existing_loans,sacco_membership,id_front_url,id_back_url,kyc_status,status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', 'active')`
  ).bind(
    assignedAgent,
    assignedAgent,
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
    b.annual_production || null,
    b.existing_loans || null,
    saccoMember ? "yes" : "no",
    b.id_front_url || null,
    b.id_back_url || null
  ).run();
  await audit(c, user.id, "onboard", "customer", b.full_name);
  return c.json({ id: r.meta.last_row_id });
});
app.put("/api/customers/:id", requireAuth, async (c) => {
  const user = c.get("user");
  const id = c.req.param("id");
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  const isAdmin = ["admin", "super_admin"].includes(user.role);
  const isOwningAgent = user.role === "agent" && cust.agent_id === user.id;
  if (!isAdmin && !isOwningAgent) return c.json({ error: "Forbidden" }, 403);
  const b = await c.req.json();
  const saccoProvided = b.sacco_membership !== void 0;
  const saccoMember = ["yes", "true", "1", "on"].includes(String(b.sacco_membership || "").toLowerCase());
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      national_id=COALESCE(?, national_id),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      mobile=COALESCE(?, mobile),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership),
      id_front_url=COALESCE(?, id_front_url),
      id_back_url=COALESCE(?, id_back_url)
     WHERE id=?`
  ).bind(
    b.full_name ?? null,
    b.national_id ?? null,
    b.date_of_birth ?? null,
    b.gender ?? null,
    b.mobile ?? null,
    b.alt_mobile ?? null,
    b.county ?? null,
    b.sub_county ?? null,
    b.ward ?? null,
    b.village ?? null,
    b.latitude ?? null,
    b.longitude ?? null,
    b.value_chain_type ?? null,
    b.value_chain ?? null,
    b.acreage ?? null,
    b.herd_size ?? null,
    b.farm_experience ?? null,
    b.annual_production ?? null,
    b.existing_loans ?? null,
    saccoProvided ? saccoMember ? "yes" : "no" : null,
    b.id_front_url ?? null,
    b.id_back_url ?? null,
    id
  ).run();
  await audit(c, user.id, "update", "customer", String(id));
  return c.json({ ok: true });
});
app.put("/api/customers/:id/status", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const { status } = await c.req.json();
  if (!["active", "suspended"].includes(String(status))) return c.json({ error: "Status must be active or suspended" }, 400);
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  await c.env.DB.prepare(`UPDATE customers SET status=? WHERE id=?`).bind(status, id).run();
  if (cust.user_id) {
    await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, cust.user_id).run();
    if (status === "suspended") await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(cust.user_id).run();
  }
  await audit(c, c.get("user").id, status === "active" ? "activate" : "deactivate", "customer", String(id));
  return c.json({ ok: true });
});
app.delete("/api/customers/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  const open = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status IN ('active','pending','pending_payment')`).bind(id).first();
  if (Number(open?.n || 0) > 0) return c.json({ error: "Farmer has open contracts. Settle or cancel them first." }, 400);
  await c.env.DB.prepare(`DELETE FROM transunion_checks WHERE customer_id=?`).bind(id).run();
  await c.env.DB.prepare(`DELETE FROM id_verifications WHERE customer_id=?`).bind(id).run();
  await c.env.DB.prepare(`DELETE FROM customers WHERE id=?`).bind(id).run();
  if (cust.user_id) {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(cust.user_id).run();
    await c.env.DB.prepare(`DELETE FROM users WHERE id=? AND role='customer'`).bind(cust.user_id).run();
  }
  await audit(c, c.get("user").id, "delete", "customer", String(id));
  return c.json({ ok: true });
});
app.post("/api/customers/:id/verify", requireAuth, async (c) => {
  const id = c.req.param("id");
  const user = c.get("user");
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first();
  if (!cust) return c.json({ error: "Not found" }, 404);
  if (!["admin", "super_admin", "agent", "operations_finance"].includes(user.role)) {
    if (!(user.role === "customer" && cust.user_id === user.id)) return c.json({ error: "Forbidden" }, 403);
  }
  if (!cust.id_front_url || !cust.id_back_url) return c.json({ error: "Front and back national ID uploads are required before verification" }, 400);
  const transunionLive = Boolean(c.env.TRANSUNION_API_URL && c.env.TRANSUNION_API_KEY);
  const score = Math.floor(Math.random() * 350 + 450);
  const band = score >= 700 ? "low" : score >= 600 ? "medium" : "high";
  const providerRef = `TU-${Date.now()}`;
  await c.env.DB.prepare(`INSERT INTO transunion_checks (customer_id,credit_score,risk_band,defaults_found,raw_response,provider_reference,integration_status) VALUES (?,?,?,?,?,?,?)`).bind(id, score, band, band === "high" ? 1 : 0, JSON.stringify({ score, band, integration_ready: transunionLive }), providerRef, transunionLive ? "ready_for_live_mapping" : "stubbed").run();
  await c.env.DB.prepare(`INSERT INTO id_verifications (customer_id,face_match,liveness,ocr_name,ocr_dob,ocr_id_number,status) VALUES (?,?,?,?,?,?, 'verified')`).bind(id, 1, 1, cust.full_name, cust.date_of_birth, cust.national_id).run();
  await c.env.DB.prepare(`UPDATE customers SET kyc_status='verified', risk_band=?, credit_score=? WHERE id=?`).bind(band, score, id).run();
  await audit(c, user.id, "verify", "customer", `KYC verified for ${cust.full_name}`);
  return c.json({ ok: true, credit_score: score, risk_band: band, face_match: true, liveness: true, transunion_integration_ready: transunionLive, provider_reference: providerRef });
});
app.post("/api/murabaha/quote", requireAuth, async (c) => {
  const { product_id, quantity, payment_type, term_months } = await c.req.json();
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first());
  if (!p) return c.json({ error: "Product not found" }, 404);
  if (payment_type === "cash" && !p.cash_enabled) return c.json({ error: "Cash purchase is not enabled for this equipment" }, 400);
  if (payment_type !== "cash" && !p.financing_enabled) return c.json({ error: "Financing is not enabled for this equipment" }, 400);
  const feeCfg = await getSetting(c, "processing_fee", DEFAULT_PROCESSING_FEE);
  const q = financingQuote(p, quantity, payment_type === "cash" ? "cash" : "financing", term_months, feeCfg);
  return c.json({ product: p.name, ...q });
});
app.post("/api/murabaha/apply", requireAuth, async (c) => {
  const user = c.get("user");
  const { customer_id, product_id, quantity, payment_type, term_months, delivery_location, consent } = await c.req.json();
  if (!consent) return c.json({ error: "Customer consent to the configured terms is required" }, 400);
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first());
  if (!p) return c.json({ error: "Product not found" }, 404);
  if (p.finance_status && p.finance_status !== "published") return c.json({ error: "This product is not yet available for purchase" }, 400);
  const qty = Math.max(1, Number(quantity) || 1);
  if (p.quantity < qty) return c.json({ error: "Insufficient stock" }, 400);
  let custId = customer_id;
  if (user.role === "customer") {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first());
    if (!myCust) return c.json({ error: "Customer profile not found" }, 404);
    custId = myCust.id;
  }
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first());
  const normalizedPaymentType = payment_type === "cash" ? "cash" : "financing";
  if (normalizedPaymentType === "financing" && custRow?.kyc_status !== "verified") {
    return c.json({
      error: "kyc_required",
      message: "Complete registration (TransUnion credit check, ID upload, and liveness verification) before equipment financing purchases.",
      customer_id: custId
    }, 412);
  }
  const feeCfg = await getSetting(c, "processing_fee", DEFAULT_PROCESSING_FEE);
  const q = financingQuote(p, qty, normalizedPaymentType, term_months, feeCfg);
  const contractRef = ref(normalizedPaymentType === "cash" ? "CSH" : q.financing_model === "paygo" ? "PGO" : "FIN");
  const status = normalizedPaymentType === "cash" ? q.amount_due_now > 0 ? "pending_payment" : "awaiting_cash_balance" : "pending";
  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    contractRef,
    custId,
    custRow?.agent_id || null,
    custRow?.onboarded_by || custRow?.agent_id || user.id,
    product_id,
    qty,
    normalizedPaymentType,
    q.supplier_cost,
    q.markup_pct,
    q.total_payable,
    q.term_months,
    q.monthly_payment || q.installment_amount || 0,
    delivery_location || "",
    status,
    0,
    1,
    0,
    q.total_payable,
    q.financing_model,
    q.interest_rate_pct || 0,
    q.deposit_pct,
    q.deposit_amount,
    q.finance_principal,
    q.payment_frequency,
    q.installment_amount || 0,
    "pending",
    q.terms_document_url || null,
    q.terms_text || null
  ).run());
  const contractId = r.meta.last_row_id;
  await audit(c, user.id, "apply", "financing", `${normalizedPaymentType} ${contractRef}`);
  return c.json({
    id: contractId,
    contract_ref: contractRef,
    status,
    payment_type: normalizedPaymentType,
    financing_model: q.financing_model,
    amount_due_now: q.amount_due_now,
    total_payable: q.total_payable,
    outstanding: q.total_payable,
    installment_amount: q.installment_amount,
    monthly_payment: q.monthly_payment || q.installment_amount,
    requires_payment: normalizedPaymentType === "cash" && q.amount_due_now > 0,
    payment_frequency: q.payment_frequency
  });
});
app.get("/api/murabaha", requireAuth, async (c) => {
  const user = c.get("user");
  let q = `SELECT mc.*, p.name as product_name, cu.full_name as customer_name
           FROM murabaha_contracts mc JOIN products p ON p.id = mc.product_id JOIN customers cu ON cu.id = mc.customer_id`;
  const binds = [];
  const where = [];
  if (user.role === "agent") {
    where.push(`mc.agent_id = ?`);
    binds.push(user.id);
  } else if (user.role === "customer") {
    const myCust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first();
    where.push(`mc.customer_id = ?`);
    binds.push(myCust?.id || -1);
  } else {
    const canCash = hasVisibility(user, "view_cash_sales");
    const canFin = hasVisibility(user, "view_financed_sales");
    if (!canCash && !canFin) {
      where.push(`1 = 0`);
    } else if (canCash && !canFin) {
      where.push(`mc.payment_type = 'cash'`);
    } else if (!canCash && canFin) {
      where.push(`mc.payment_type = 'financing'`);
    }
  }
  if (where.length) q += ` WHERE ` + where.join(" AND ");
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
app.post("/api/murabaha/:id/decision", requireAuth, requireRole("admin", "super_admin", "operations_finance"), async (c) => {
  const id = c.req.param("id");
  const { action, notes } = await c.req.json();
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first();
  if (!contract) return c.json({ error: "Not found" }, 404);
  if (contract.status !== "pending") return c.json({ error: "Application is not pending" }, 400);
  await c.env.DB.prepare(`INSERT INTO approvals (contract_id,reviewer_id,action,notes) VALUES (?,?,?,?)`).bind(id, c.get("user").id, action, notes || "").run();
  if (action === "approve") {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='active', ownership_recorded=1 WHERE id=?`).bind(id).run();
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run();
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, contract.financing_model === "paygo" ? "paygo_allocation" : "credit_allocation", contract.quantity, contract.contract_ref).run();
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'unpaid')`).bind(ref("INV"), id, contract.customer_id, contract.murabaha_price).run();
    const term = Number(contract.term_months) || 0;
    const installment = Number(contract.installment_amount || contract.monthly_payment || 0);
    const frequency = contract.payment_frequency || "monthly";
    const count = frequency === "daily" ? term * 30 : frequency === "weekly" ? term * 4 : term;
    const start = /* @__PURE__ */ new Date();
    for (let i = 1; i <= count; i++) {
      const due = new Date(start);
      if (frequency === "weekly") due.setDate(due.getDate() + i * 7);
      else if (frequency === "daily") due.setDate(due.getDate() + i);
      else due.setMonth(due.getMonth() + i);
      const amount = i === count ? roundMoney(Number(contract.outstanding) - installment * (count - 1)) : installment;
      await c.env.DB.prepare(`INSERT INTO repayments (contract_id,installment_no,due_date,amount_due,status) VALUES (?,?,?,?, 'current')`).bind(id, i, due.toISOString().slice(0, 10), amount > 0 ? amount : installment).run();
    }
  } else if (action === "reject") {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='rejected' WHERE id=?`).bind(id).run();
  }
  await audit(c, c.get("user").id, action, "financing", contract.contract_ref);
  return c.json({ ok: true, action });
});
app.post("/api/murabaha/:id/dispatch", requireAuth, requireRole("admin", "super_admin", "operations_finance"), async (c) => {
  const id = c.req.param("id");
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first();
  if (!contract) return c.json({ error: "Not found" }, 404);
  if (!["active", "completed", "awaiting_cash_balance"].includes(contract.status)) return c.json({ error: "Only approved or paid purchases can be dispatched" }, 400);
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET dispatch_status='dispatched', dispatched_at=CURRENT_TIMESTAMP, dispatched_by=? WHERE id=?`).bind(c.get("user").id, id).run();
  await audit(c, c.get("user").id, "dispatch", "contract", contract.contract_ref);
  return c.json({ ok: true });
});
app.get("/api/murabaha/reminders/due", requireAuth, async (c) => {
  const withinDays = Math.max(0, Math.min(60, Number(c.req.query("days") || 3)));
  const rows = await c.env.DB.prepare(
    `SELECT r.id AS repayment_id, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status,
            mc.id AS contract_id, mc.contract_ref, mc.payment_type, mc.outstanding,
            cu.full_name AS customer_name, cu.mobile AS customer_phone
       FROM repayments r
       JOIN murabaha_contracts mc ON mc.id = r.contract_id
       LEFT JOIN customers cu ON cu.id = mc.customer_id
      WHERE mc.payment_type != 'cash'
        AND mc.status = 'active'
        AND r.status != 'completed'
      ORDER BY r.due_date ASC
      LIMIT 500`
  ).all();
  const today = /* @__PURE__ */ new Date();
  today.setHours(0, 0, 0, 0);
  const reminders = (rows?.results || []).map((r) => {
    const due = new Date(r.due_date);
    due.setHours(0, 0, 0, 0);
    const days = Math.round((due.getTime() - today.getTime()) / 864e5);
    const balance = Number(r.amount_due) - Number(r.amount_paid || 0);
    return { ...r, balance_due: balance, days_to_due: days, overdue: days < 0 };
  }).filter((r) => r.balance_due > 0.5 && r.days_to_due <= withinDays);
  return c.json({ ok: true, within_days: withinDays, count: reminders.length, reminders });
});
async function applyPayment(c, contract, amt, receipt, method, phone) {
  const isCash = contract.payment_type === "cash";
  const currentPaid = numberVal(contract.amount_paid, 0);
  const totalDue = numberVal(contract.murabaha_price, 0);
  const newPaid = roundMoney(currentPaid + amt);
  const newOutstanding = roundMoney(Math.max(0, totalDue - newPaid));
  const firstCashCollection = isCash && !contract.ownership_recorded;
  if (firstCashCollection) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run();
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, "sale", contract.quantity, contract.contract_ref).run();
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, ?)`).bind(ref("INV"), contract.id, contract.customer_id, totalDue, newOutstanding <= 0 ? "paid" : "partial").run();
  }
  await c.env.DB.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`).bind(ref("TXN"), contract.id, contract.customer_id, amt, method, isCash ? "cash_sale" : contract.financing_model === "paygo" ? "paygo_repayment" : "repayment", receipt, phone).run();
  const status = isCash ? newOutstanding <= 0 ? "completed" : "awaiting_cash_balance" : newOutstanding <= 0 ? "completed" : "active";
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=?, status=?, ownership_recorded=1 WHERE id=?`).bind(newPaid, newOutstanding, status, contract.id).run();
  let remaining = amt;
  const { results: due } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? AND status!='completed' ORDER BY installment_no`).bind(contract.id).all();
  for (const inst of due) {
    if (remaining <= 0) break;
    const need = numberVal(inst.amount_due) - numberVal(inst.amount_paid);
    const pay = Math.min(need, remaining);
    const paidTotal = roundMoney(numberVal(inst.amount_paid) + pay);
    const st = paidTotal >= numberVal(inst.amount_due) ? "completed" : "current";
    await c.env.DB.prepare(`UPDATE repayments SET amount_paid=?, status=?, paid_at=CURRENT_TIMESTAMP WHERE id=?`).bind(paidTotal, st, inst.id).run();
    remaining = roundMoney(remaining - pay);
  }
  await c.env.DB.prepare(`UPDATE invoices SET status=? WHERE contract_id=?`).bind(newOutstanding <= 0 ? "paid" : "partial", contract.id).run();
  if (status === "completed" && contract.status !== "completed") {
    try {
      await distributeCommission(c, { ...contract, status });
    } catch (e) {
      console.error("distributeCommission error:", e?.message || e);
    }
  }
  return { amount_paid: newPaid, outstanding: newOutstanding, status };
}
function runInBackground(c, work) {
  const p = (async () => {
    try {
      await work();
    } catch (err) {
      console.error("Background settlement error:", err?.message || err);
    }
  })();
  try {
    c.executionCtx?.waitUntil?.(p);
  } catch (_) {
  }
}
app.post("/api/mpesa/stkpush", requireAuth, async (c) => {
  const { contract_id, amount, phone, payment_method } = await c.req.json();
  const user = c.get("user");
  const rail = payment_method === "sasapay" ? "sasapay" : "mpesa";
  const contract = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first());
  if (!contract) return c.json({ error: "Contract not found" }, 404);
  if (user.role === "customer") {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first());
    if (!myCust || Number(contract.customer_id) !== Number(myCust.id)) return c.json({ error: "Forbidden" }, 403);
  }
  if (contract.payment_type === "cash" && ["pending_payment", "awaiting_cash_balance", "completed"].includes(contract.status)) {
    const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first());
    if (!contract.ownership_recorded && (!p || p.quantity < contract.quantity)) return c.json({ error: "This item is now out of stock." }, 409);
  } else if (contract.payment_type !== "cash" && !["active", "completed"].includes(contract.status)) {
    return c.json({ error: "This purchase is not open for payment." }, 400);
  }
  const amt = Number(amount);
  if (amt <= 0) return c.json({ error: "Invalid amount" }, 400);
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: "Amount exceeds outstanding balance" }, 400);
  const desc = contract.payment_type === "cash" ? "Feed Cash Purchase" : contract.financing_model === "paygo" ? "PAYGO Feed Payment" : "Feed Murabaha Payment";
  const payerPhone = phone || c.get("user").phone;
  if (gatewayConfigured(c.env)) {
    const g = await initiatePayment(c.env, {
      amount: amt,
      phone: payerPhone,
      payment_method: rail,
      origin_reference: contract.contract_ref,
      description: desc,
      initiated_by_user: c.get("user").id,
      idempotency_key: `feed-${contract.contract_ref}-${amt}`
    });
    if (!g.success) return c.json({ error: g.error || "Payment gateway rejected the request" }, 502);
    await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`).bind(g.transaction_ref, g.transaction_ref, contract_id, contract.customer_id, amt, normalizePhone(payerPhone), `gateway_${rail}`).run();
    await audit(c, c.get("user").id, "stk_push", "gateway", `KES ${amt} to ${contract.contract_ref} via central gateway ${rail} (${g.simulated ? "sim" : "live"})`);
    return c.json({ ok: true, simulated: !!g.simulated, checkout_request_id: g.transaction_ref, customer_message: g.customer_message || "Payment request sent. Approve the prompt on your phone." });
  }
  const result = await stkPush(c.env, { phone: payerPhone, amount: amt, account: contract.contract_ref, description: desc });
  if (!result.success) return c.json({ error: result.error || "STK push failed" }, 502);
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`).bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(payerPhone), "mpesa").run();
  await audit(c, c.get("user").id, "stk_push", "mpesa", `KES ${amt} to ${contract.contract_ref} (${result.simulated ? "sim" : "live"})`);
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message });
});
app.post("/api/mpesa/confirm", requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json();
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") return c.json({ ok: true, status: "success", mpesa_receipt: intent.mpesa_receipt });
  let success = false, receipt = "";
  if (String(intent.method).startsWith("gateway_") && gatewayConfigured(c.env)) {
    const s = await getPaymentStatus(c.env, checkout_request_id);
    const st = String(s?.status || "").toUpperCase();
    if (s?.simulated || st === "SUCCESS" || st === "COMPLETED") {
      success = true;
      receipt = s?.provider_receipt || "GW" + Date.now().toString().slice(-8);
    } else if (st === "FAILED" || st === "CANCELLED") {
      await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(s?.error || "Payment not completed", checkout_request_id).run();
      return c.json({ ok: false, status: "failed", result_desc: s?.error || "Payment not completed" });
    } else {
      return c.json({ ok: false, status: "pending" });
    }
  } else if (!mpesaConfigured(c.env) || String(checkout_request_id).includes("SIM")) {
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
    const res = await withAdminContext(c, async () => {
      const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
      return await applyPayment(c, contract, intent.amount, receipt, String(intent.method).startsWith("gateway_") ? "gateway" : "mpesa", intent.phone);
    });
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run();
    return c.json({ ok: true, status: "success", mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status });
  }
  return c.json({ ok: false, status: "pending" });
});
async function logPaymentSecurityEvent(c, eventType, severity, detail, txRef) {
  try {
    const ip = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || c.req.header("X-Real-IP") || "";
    await c.env.DB.prepare(
      `INSERT INTO payment_audit_log (origin_app, event_type, severity, transaction_ref, detail, ip_address) VALUES (?,?,?,?,?,?)`
    ).bind("feed", eventType, severity, txRef || null, detail, ip).run();
  } catch (_) {
  }
}
app.post("/api/payments/incoming", rateLimit("ipn", 120, 6e4), async (c) => {
  const raw2 = await c.req.text();
  const clientKey = c.req.header("X-Farmsky-Client") || "";
  const ts = c.req.header("X-Farmsky-Timestamp") || "";
  const nonce = c.req.header("X-Farmsky-Nonce") || "";
  const sig = c.req.header("X-Farmsky-Signature") || "";
  const secret = c.env.FARMSKY_PAYMENTS_HMAC_SECRET || "";
  const expectedClient = String(c.env.FARMSKY_PAYMENTS_CLIENT_KEY || "feed");
  if (!secret) {
    await logPaymentSecurityEvent(c, "CONFIG_MISSING", "CRITICAL", "FARMSKY_PAYMENTS_HMAC_SECRET not set; inbound IPN rejected");
    return c.json({ error: "gateway_not_configured" }, 503);
  }
  if (!clientKey || clientKey !== expectedClient) {
    await logPaymentSecurityEvent(c, "CROSS_TENANT_ACCESS", "CRITICAL", `client_key mismatch: got "${clientKey}"`);
    return c.json({ error: "unauthorized_client" }, 401);
  }
  const { verifySignature: verifySignature2 } = await Promise.resolve().then(() => (init_payments_shared(), payments_shared_exports));
  const v = await verifySignature2(secret, expectedClient, ts, nonce, raw2, sig);
  if (!v.ok) {
    await logPaymentSecurityEvent(c, "SIGNATURE_FAIL", "CRITICAL", `reason=${v.error || "invalid"}`);
    return c.json({ error: "invalid_signature" }, 401);
  }
  if (nonce) {
    try {
      await c.env.DB.prepare(`INSERT INTO payment_nonces (client_key, nonce) VALUES (?,?)`).bind(expectedClient, nonce).run();
    } catch (e) {
      await logPaymentSecurityEvent(c, "REPLAY", "CRITICAL", `duplicate nonce ${nonce}`);
      return c.json({ error: "replay_detected" }, 409);
    }
  }
  let body = {};
  try {
    body = JSON.parse(raw2);
  } catch {
    return c.json({ error: "bad_body" }, 400);
  }
  const txRef = body?.transaction_ref;
  const status = String(body?.status || "").toUpperCase();
  if (!txRef) return c.json({ ok: true });
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(txRef).first();
  if (intent && intent.status === "pending" && (status === "SUCCESS" || status === "COMPLETED")) {
    runInBackground(c, async () => {
      await withAdminContext(c, async () => {
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
        if (contract) await applyPayment(c, contract, intent.amount, String(body?.provider_receipt || txRef), "gateway", intent.phone);
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(String(body?.provider_receipt || txRef), txRef).run();
      });
    });
  }
  return c.json({ ok: true });
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
  const mpesaMode = ["sandbox", "development", "dev", "test"].includes(String(c.env.MPESA_ENV || "").trim().toLowerCase()) ? "sandbox" : "production";
  return c.json({ live: mpesaConfigured(c.env), mode: mpesaConfigured(c.env) ? mpesaMode : "simulation" });
});
app.get("/api/sasapay/channels", (c) => {
  return c.json({
    channels: SASAPAY_CHANNELS,
    banks: SASAPAY_CHANNELS.filter((x) => x.type === "bank"),
    mobile: SASAPAY_CHANNELS.filter((x) => x.type === "mobile"),
    wallet: SASAPAY_CHANNELS.filter((x) => x.type === "wallet"),
    live: sasapayConfigured(c.env),
    mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : "simulation"
  });
});
app.post("/api/sasapay/stkpush", requireAuth, async (c) => {
  const b = await c.req.json();
  const { contract_id, amount, phone, account_number } = b;
  let channelCode = String(b.channel_code || "").trim();
  if (!channelCode) channelCode = b.channel === "BANK" ? "" : "63902";
  const chan = channelByCode(channelCode);
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first();
  if (!contract) return c.json({ error: "Contract not found" }, 404);
  if (contract.payment_type === "cash" && ["pending_payment", "awaiting_cash_balance", "completed"].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first();
    if (!contract.ownership_recorded && (!p || p.quantity < contract.quantity)) return c.json({ error: "This item is now out of stock." }, 409);
  } else if (contract.payment_type !== "cash" && !["active", "completed"].includes(contract.status)) {
    return c.json({ error: "This purchase is not open for payment." }, 400);
  }
  const amt = Number(amount);
  if (amt <= 0) return c.json({ error: "Invalid amount" }, 400);
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: "Amount exceeds outstanding balance" }, 400);
  const isBank = chan?.type === "bank";
  if (!chan && channelCode) return c.json({ error: "Unknown payment channel selected." }, 400);
  const desc = contract.payment_type === "cash" ? "Cash Equipment Purchase" : "Equipment Financing Payment";
  const payerPhone = phone || c.get("user").phone;
  const result = await sasapayStkPush(c.env, {
    phone: payerPhone,
    amount: amt,
    account: contract.contract_ref,
    description: desc,
    networkCode: channelCode || "63902",
    channelCode: channelCode || "63902"
  });
  if (!result.success) return c.json({ error: result.error || "SasaPay transaction initialization failed" }, 502);
  await c.env.DB.prepare(
    `INSERT INTO payment_intents
       (checkout_request_id, merchant_request_id, contract_id, customer_id, amount, phone,
        method, status, provider, direction, channel_code, channel_name, account_number,
        transaction_reference, needs_otp)
     VALUES (?,?,?,?,?,?, 'sasapay', 'pending', 'sasapay', 'payin', ?,?,?,?,?)`
  ).bind(
    result.checkout_request_id,
    result.merchant_request_id,
    contract_id,
    contract.customer_id,
    amt,
    normalizePhone2(payerPhone),
    channelCode || "63902",
    chan?.name || null,
    account_number || null,
    result.transaction_reference || null,
    result.needs_otp ? 1 : 0
  ).run();
  await audit(c, c.get("user").id, "stk_push", "sasapay", `KES ${amt} via ${chan?.name || channelCode} to ${contract.contract_ref} (${result.simulated ? "sim" : "live"})`);
  return c.json({
    ok: true,
    simulated: result.simulated,
    checkout_request_id: result.checkout_request_id,
    needs_otp: !!result.needs_otp,
    channel: chan?.name || channelCode,
    customer_message: result.customer_message || (result.needs_otp ? "Enter the OTP sent to your SasaPay wallet to authorise the payment." : isBank ? "Bank payment initiated. Approve the prompt sent to your phone / banking app." : "STK Push sent. Enter your PIN on your phone.")
  });
});
app.post("/api/sasapay/process", requireAuth, async (c) => {
  const { checkout_request_id, verification_code } = await c.req.json();
  if (!checkout_request_id || !verification_code) return c.json({ error: "checkout_request_id and verification_code are required" }, 400);
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") return c.json({ ok: true, status: "success" });
  const r = await sasapayProcessPayment(c.env, checkout_request_id, String(verification_code));
  if (!r.success) return c.json({ ok: false, error: r.error || "OTP verification failed" }, 400);
  return c.json({ ok: true, status: "processing", customer_message: r.customer_message || "OTP accepted. Confirming payment\u2026" });
});
app.post("/api/sasapay/confirm", requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json();
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") return c.json({ ok: true, status: "success", mpesa_receipt: intent.mpesa_receipt });
  if (intent.status === "failed") return c.json({ ok: false, status: "failed", result_desc: intent.result_desc || "Payment not completed" });
  let success = false, receipt = "";
  if (!sasapayConfigured(c.env) || String(checkout_request_id).includes("SIM")) {
    success = true;
    receipt = "SP" + Math.random().toString(36).slice(2, 9).toUpperCase();
  } else {
    const q = await sasapayQuery(c.env, checkout_request_id, c.env.SASAPAY_CALLBACK_URL);
    console.log("--- SasaPay Response Debug:", JSON.stringify(q));
    if (q?.paid === true) {
      success = true;
      receipt = q.TransactionCode || q.TransactionID || "SPL" + Date.now().toString().slice(-7);
    } else if (q?.failed === true) {
      const rawDesc = String(q.ResultDesc || q.message || "Payment not completed");
      const safeDesc = /</.test(rawDesc) ? "Payment not completed" : rawDesc;
      await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(safeDesc.slice(0, 300), checkout_request_id).run();
      return c.json({ ok: false, status: "failed", result_desc: safeDesc });
    } else {
      const latest = await c.env.DB.prepare(`SELECT status, mpesa_receipt, result_desc FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
      if (latest?.status === "success") return c.json({ ok: true, status: "success", mpesa_receipt: latest.mpesa_receipt });
      if (latest?.status === "failed") return c.json({ ok: false, status: "failed", result_desc: latest.result_desc || "Payment not completed" });
      return c.json({ ok: false, status: "pending" });
    }
  }
  if (success) {
    const fresh = await c.env.DB.prepare(`SELECT status, mpesa_receipt FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
    if (fresh?.status === "success") {
      return c.json({ ok: true, status: "success", mpesa_receipt: fresh.mpesa_receipt });
    }
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
    const res = await applyPayment(c, contract, intent.amount, receipt, "sasapay", intent.phone);
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(receipt, receipt, checkout_request_id).run();
    return c.json({ ok: true, status: "success", mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status });
  }
  return c.json({ ok: false, status: "pending" });
});
app.post("/api/sasapay/callback", async (c) => {
  const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || c.req.header("x-real-ip");
  const sig = c.req.header("x-sasapay-signature") || c.req.header("X-SasaPay-Signature");
  const body = await c.req.json().catch(() => ({}));
  console.log("SasaPay C2B callback received:", JSON.stringify({ ip: ip || null, hasSig: !!sig, body }));
  runInBackground(c, async () => {
    if (sasapayConfigured(c.env)) {
      const ipOk = isTrustedSasapayIp(ip);
      const sigOk = await verifySasapaySignature(c.env, sig, {
        sasapay_transaction_code: body.TransactionCode || body.TransactionID || "",
        merchant_code: body.MerchantCode || "",
        account_number: body.AccountReference || body.BillRefNumber || "",
        payment_reference: body.CheckoutRequestID || body.MerchantRequestID || "",
        amount: body.Amount || body.TransAmount || ""
      });
      if (!ipOk && !sigOk) {
        console.warn("SasaPay callback UNVERIFIED (processing anyway):", `ip=${ip || "?"} sig=${sig ? "present-but-bad" : "missing"}`);
        await audit(c, null, "callback_unverified", "sasapay", `unverified ip=${ip || "?"} sig=${sig ? "bad" : "missing"} ref=${body.CheckoutRequestID || body.MerchantRequestID || body.BillRefNumber || "?"}`);
      }
    }
    const checkout = body?.CheckoutRequestID || body?.MerchantRequestID;
    const billRef = body?.BillRefNumber || body?.AccountReference;
    if (!checkout && !billRef) return;
    let intent = checkout ? await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first() : null;
    if (!intent && billRef) {
      intent = await c.env.DB.prepare(
        `SELECT pi.* FROM payment_intents pi JOIN murabaha_contracts mc ON mc.id = pi.contract_id
          WHERE mc.contract_ref = ? AND pi.status = 'pending' ORDER BY pi.created_at DESC LIMIT 1`
      ).bind(String(billRef)).first();
    }
    if (!intent) {
      const msisdn = body?.CustomerMobile || body?.MSISDN || body?.PhoneNumber || body?.Msisdn;
      const amt = Number(body?.TransAmount ?? body?.Amount ?? body?.amount ?? 0);
      if (msisdn && amt > 0) {
        const norm = normalizePhone2(String(msisdn));
        intent = await c.env.DB.prepare(
          `SELECT * FROM payment_intents
            WHERE phone = ? AND amount = ? AND status = 'pending' AND direction = 'payin'
            ORDER BY created_at DESC LIMIT 1`
        ).bind(norm, amt).first();
        if (intent) console.log("SasaPay callback matched by phone+amount fallback:", `${norm} KES ${amt} -> ${intent.checkout_request_id}`);
      }
    }
    if (!intent) {
      console.warn("SasaPay callback: NO matching intent", JSON.stringify({ checkout, billRef }));
      await audit(c, null, "callback_no_match", "sasapay", `checkout=${checkout || "?"} billRef=${billRef || "?"}`);
      return;
    }
    if (intent.status === "pending") {
      const code = body.ResultCode ?? body.status_code;
      const paid = code === 0 || code === "0" || body.Paid === true || body.paid === true || body.status === true;
      if (paid) {
        const receipt = body.TransactionCode || body.TransID || body.TransactionID || body.ThirdPartyTransID || body.MpesaReceiptNumber || "SPL" + Date.now();
        const paidAmt = Number(body.TransAmount ?? body.Amount ?? body.amount ?? 0);
        if (paidAmt && Math.abs(paidAmt - Number(intent.amount)) > 0.5) {
          console.warn("SasaPay callback amount mismatch:", `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`);
          await audit(c, null, "callback_amount_mismatch", "sasapay", `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`);
        }
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), "sasapay", intent.phone);
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(String(receipt), String(receipt), body.ResultDesc || "Transaction processed successfully.", intent.checkout_request_id).run();
        await audit(c, null, "callback_settled", "sasapay", `settled ${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`);
        console.log("SasaPay callback SETTLED:", `${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`);
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(body.ResultDesc || body.message || "Failed", intent.checkout_request_id).run();
        console.log("SasaPay callback marked FAILED:", `${intent.checkout_request_id} \u2014 ${body.ResultDesc || body.message || "Failed"}`);
      }
    } else {
      console.log("SasaPay callback: intent already", intent.status, `(${intent.checkout_request_id}) \u2014 ignoring (idempotent)`);
    }
  });
  return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
});
app.post("/api/sasapay/ipn", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  console.log("SasaPay IPN received:", JSON.stringify(body));
  runInBackground(c, async () => {
    const checkout = body?.CheckoutRequestID || body?.MerchantRequestID;
    const billRef = body?.BillRefNumber || body?.AccountReference || body?.InvoiceNumber;
    if (!checkout && !billRef) return;
    let intent = checkout ? await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first() : null;
    if (!intent && billRef) {
      intent = await c.env.DB.prepare(
        `SELECT pi.* FROM payment_intents pi JOIN murabaha_contracts mc ON mc.id = pi.contract_id
          WHERE mc.contract_ref = ? AND pi.status = 'pending' ORDER BY pi.created_at DESC LIMIT 1`
      ).bind(String(billRef)).first();
    }
    if (!intent) {
      console.warn("SasaPay IPN: NO matching intent", JSON.stringify({ checkout, billRef }));
      await audit(c, null, "ipn_no_match", "sasapay", `checkout=${checkout || "?"} billRef=${billRef || "?"}`);
      return;
    }
    if (intent.status === "pending") {
      const receipt = body.TransID || body.TransactionCode || body.TransactionID || body.ThirdPartyTransID || "SPL" + Date.now();
      const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
      if (contract) await applyPayment(c, contract, intent.amount, String(receipt), "sasapay", intent.phone);
      await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(String(receipt), String(receipt), intent.checkout_request_id).run();
      await audit(c, null, "ipn_settled", "sasapay", `settled ${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`);
      console.log("SasaPay IPN SETTLED:", `${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`);
    } else {
      console.log("SasaPay IPN: intent already", intent.status, `(${intent.checkout_request_id}) \u2014 ignoring (idempotent)`);
    }
  });
  return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
});
app.post("/api/sasapay/validate-account", requireAuth, async (c) => {
  const { channel_code, account_number } = await c.req.json();
  if (!channel_code || !account_number) return c.json({ error: "channel_code and account_number are required" }, 400);
  const chan = channelByCode(String(channel_code));
  if (!chan) return c.json({ error: "Unknown channel" }, 400);
  const acct = chan.type === "mobile" || chan.type === "wallet" ? normalizePhone2(String(account_number)) : String(account_number);
  const v = await sasapayValidateAccount(c.env, String(channel_code), acct);
  if (!v.success) return c.json({ ok: false, error: v.error || "Validation failed" }, 400);
  return c.json({ ok: true, simulated: v.simulated, account_name: v.account_name, channel_name: v.channel_name || chan.name, normalized_account: acct });
});
app.get("/api/sasapay/balance", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const bal = await sasapayBalance(c.env);
  if (!bal.success) return c.json({ ok: false, error: bal.error || "Balance query failed" }, 502);
  return c.json({ ok: true, simulated: bal.simulated, currency: bal.currency, org_balance: bal.org_balance, accounts: bal.accounts || [] });
});
app.get("/api/sasapay/status", requireAuth, (c) => {
  return c.json({ live: sasapayConfigured(c.env), mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : "simulation" });
});
app.get("/api/sasapay/callback", (c) => c.json({ ok: true, service: "sasapay-callback", method: "expects POST" }));
app.get("/api/sasapay/ipn", (c) => c.json({ ok: true, service: "sasapay-ipn", method: "expects POST" }));
app.get("/api/sasapay/callback-health", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const events = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE entity='sasapay' AND (action LIKE 'callback%' OR action LIKE 'ipn%')
      ORDER BY created_at DESC LIMIT 20`
  ).all();
  const last = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE action IN ('callback_settled','callback_unverified','callback_no_match','callback_amount_mismatch','ipn_settled','ipn_no_match')
      ORDER BY created_at DESC LIMIT 1`
  ).first();
  const pending = await c.env.DB.prepare(
    `SELECT checkout_request_id, amount, phone, channel_name, created_at
       FROM payment_intents
      WHERE provider='sasapay' AND direction='payin' AND status='pending'
      ORDER BY created_at DESC LIMIT 20`
  ).all();
  return c.json({
    live: sasapayConfigured(c.env),
    callback_url: c.env.SASAPAY_CALLBACK_URL || null,
    last_webhook_event: last || null,
    recent_webhook_events: events?.results || [],
    pending_payins: pending?.results || [],
    pending_count: (pending?.results || []).length
  });
});
app.get("/api/admin/payments/pending", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const minAgeMin = Math.max(0, Number(c.req.query("min_age_min") || 0));
  const rows = await c.env.DB.prepare(
    `SELECT pi.*, mc.contract_ref, mc.outstanding, mc.status AS contract_status,
            cu.full_name AS customer_name
       FROM payment_intents pi
       LEFT JOIN murabaha_contracts mc ON mc.id = pi.contract_id
       LEFT JOIN customers cu ON cu.id = pi.customer_id
      WHERE pi.status = 'pending'
      ORDER BY pi.created_at DESC
      LIMIT 200`
  ).all();
  const now = Date.now();
  const list = (rows?.results || []).filter((r) => {
    if (!minAgeMin) return true;
    const t = Date.parse(r.created_at || "") || now;
    return now - t >= minAgeMin * 60 * 1e3;
  });
  return c.json({ ok: true, count: list.length, intents: list });
});
app.post("/api/admin/payments/recover", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const checkout = String(body.checkout_request_id || "").trim();
  const mode = String(body.mode || "query").toLowerCase();
  if (!checkout) return c.json({ error: "checkout_request_id is required" }, 400);
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") {
    return c.json({ ok: true, status: "success", already: true, mpesa_receipt: intent.mpesa_receipt });
  }
  let success = false, receipt = "", gatewayDesc = "";
  let forced = false;
  if (mode === "force") {
    success = true;
    forced = true;
    receipt = String(body.receipt || intent.transaction_code || "MANUAL" + Date.now().toString().slice(-8));
    gatewayDesc = "Manual admin override";
  } else {
    if (!sasapayConfigured(c.env) || String(checkout).includes("SIM")) {
      success = true;
      receipt = "SP" + Math.random().toString(36).slice(2, 9).toUpperCase();
    } else {
      const q = await sasapayQuery(c.env, checkout);
      console.log("--- SasaPay Response Debug:", JSON.stringify(q));
      gatewayDesc = String(q?.ResultDesc || q?.message || "");
      if (q?.paid === true || q?.status === true) {
        success = true;
        receipt = q.TransactionCode || q.TransactionID || "SPL" + Date.now().toString().slice(-7);
      } else if (q?.pending === true) {
        return c.json({ ok: false, status: "pending", result_desc: gatewayDesc || "Gateway still processing" });
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind((gatewayDesc || "Payment not completed").slice(0, 300), checkout).run();
        await audit(c, c.get("user").id, "payment_recover", "sasapay", `marked FAILED ${checkout} (${gatewayDesc})`);
        return c.json({ ok: false, status: "failed", result_desc: gatewayDesc || "Payment not completed" });
      }
    }
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
    let res = null;
    if (contract) res = await applyPayment(c, contract, intent.amount, receipt, "sasapay", intent.phone);
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(receipt, receipt, (gatewayDesc || (forced ? "Manual admin override" : "Recovered")).slice(0, 300), checkout).run();
    await audit(
      c,
      c.get("user").id,
      "payment_recover",
      "sasapay",
      `${forced ? "FORCED" : "query-settled"} ${checkout} -> SUCCESS (KES ${intent.amount}, receipt ${receipt})`
    );
    return c.json({ ok: true, status: "success", forced, mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status });
  }
  return c.json({ ok: false, status: "pending" });
});
app.post("/api/buni/stkpush", requireAuth, async (c) => {
  const { contract_id, amount, phone } = await c.req.json();
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first();
  if (!contract) return c.json({ error: "Contract not found" }, 404);
  if (contract.payment_type === "cash" && ["pending_payment", "awaiting_cash_balance", "completed"].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first();
    if (!contract.ownership_recorded && (!p || p.quantity < contract.quantity)) return c.json({ error: "This item is now out of stock." }, 409);
  } else if (contract.payment_type !== "cash" && !["active", "completed"].includes(contract.status)) {
    return c.json({ error: "This purchase is not open for payment." }, 400);
  }
  const amt = Number(amount);
  if (amt <= 0) return c.json({ error: "Invalid amount" }, 400);
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: "Amount exceeds outstanding balance" }, 400);
  const desc = contract.payment_type === "cash" ? "Cash Equipment Purchase" : "Equipment Financing Payment";
  const result = await buniStkPush(c.env, { phone: phone || c.get("user").phone, amount: amt, account: contract.contract_ref, description: desc });
  if (!result.success) return c.json({ error: result.error || "KCB Buni STK push failed" }, 502);
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`).bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(phone || c.get("user").phone), "buni").run();
  await audit(c, c.get("user").id, "stk_push", "buni", `KES ${amt} to ${contract.contract_ref} (${result.simulated ? "sim" : "live"})`);
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message });
});
app.post("/api/buni/confirm", requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json();
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first();
  if (!intent) return c.json({ error: "Payment intent not found" }, 404);
  if (intent.status === "success") return c.json({ ok: true, status: "success", mpesa_receipt: intent.mpesa_receipt });
  let success = false, receipt = "";
  if (!buniConfigured(c.env) || String(checkout_request_id).includes("SIM")) {
    success = true;
    receipt = "BUNI" + Math.random().toString(36).slice(2, 9).toUpperCase();
  } else {
    const q = await buniQuery(c.env, checkout_request_id);
    const code = q.ResultCode ?? q.status_code;
    if (code === "0" || code === 0 || q.status === true) {
      success = true;
      receipt = "BUNI" + Date.now().toString().slice(-7);
    } else if (code) return c.json({ ok: false, status: "failed", result_desc: q.ResultDesc || q.message || "Payment not completed" });
    else return c.json({ ok: false, status: "pending" });
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
    const res = await applyPayment(c, contract, intent.amount, receipt, "buni", intent.phone);
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run();
    return c.json({ ok: true, status: "success", mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status });
  }
  return c.json({ ok: false, status: "pending" });
});
app.post("/api/buni/callback", async (c) => {
  try {
    const body = await c.req.json();
    const checkout = body?.CheckoutRequestID || body?.TransactionID;
    if (!checkout) return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first();
    if (intent && intent.status === "pending") {
      const code = body.ResultCode ?? body.status_code;
      if (code === 0 || code === "0" || body.status === true) {
        const receipt = body.TransactionID || body.ReceiptNumber || "BUNI" + Date.now();
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first();
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), "buni", intent.phone);
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), body.ResultDesc || "", checkout).run();
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(body.ResultDesc || body.message || "Failed", checkout).run();
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch {
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  }
});
app.get("/api/buni/status", requireAuth, (c) => {
  return c.json({ live: buniConfigured(c.env), mode: buniConfigured(c.env) ? c.env.BUNI_ENV || "sandbox" : "simulation", hidden: true });
});
app.route("/api/v1/payments", payment_gateway_default);
app.get("/api/v1/payments-admin/summary", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const res = await fetch(new URL("/api/v1/payments/admin/summary", c.req.url).toString());
  return c.json(await res.json());
});
app.get("/api/dashboard", requireAuth, async (c) => {
  const user = c.get("user"), db = c.env.DB;
  if (user.role === "customer") {
    const myCust = await db.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first();
    const cid = myCust?.id || -1;
    const contracts = await db.prepare(`SELECT COUNT(*) n, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE customer_id=? AND status='active'`).bind(cid).first();
    const completed = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status='completed'`).bind(cid).first();
    const nextDue = await db.prepare(`SELECT r.* FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.customer_id=? AND r.status!='completed' ORDER BY r.due_date LIMIT 1`).bind(cid).first();
    return c.json({ role: "customer", active_contracts: contracts?.n || 0, total_outstanding: contracts?.out || 0, completed_contracts: completed?.n || 0, next_payment: nextDue || null });
  }
  if (user.role === "agent") {
    const cust = await db.prepare(`SELECT COUNT(*)::int n FROM customers WHERE agent_id=?`).bind(user.id).first();
    const active = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='active'`).bind(user.id).first();
    const pending2 = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='pending'`).bind(user.id).first();
    const portfolio = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE agent_id=?`).bind(user.id).first();
    const late = await db.prepare(`SELECT COUNT(*)::int n FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.agent_id=? AND r.status='late'`).bind(user.id).first();
    const creditOnly = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND payment_type='financing'`).bind(user.id).first();
    const par = portfolio?.tot ? Math.round(portfolio.out / portfolio.tot * 100) : 0;
    return c.json({ role: "agent", customers_onboarded: cust?.n || 0, active_contracts: active?.n || 0, pending_approvals: pending2?.n || 0, portfolio_value: portfolio?.tot || 0, portfolio_at_risk: par, late_installments: late?.n || 0, commission: Math.round((portfolio?.tot || 0) * 0.025), credit_purchases: creditOnly?.n || 0 });
  }
  const sales = await db.prepare(`SELECT COALESCE(SUM(amount),0) tot FROM transactions WHERE status='success'`).first();
  const financed = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='financing'`).first();
  const cashSales = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='cash'`).first();
  const activeCust = await db.prepare(`SELECT COUNT(*)::int n FROM customers`).first();
  const invValue = await db.prepare(`SELECT COALESCE(SUM(buying_price*quantity),0) tot FROM products`).first();
  const totalRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments`).first();
  const completedRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='completed'`).first();
  const defaulted = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='defaulted'`).first();
  const pending = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE status='pending'`).first();
  const repayRate = totalRepay?.n ? Math.round(completedRepay.n / totalRepay.n * 100) : 0;
  const defaultRate = totalRepay?.n ? Math.round(defaulted.n / totalRepay.n * 100) : 0;
  const { results: topProducts } = await db.prepare(`SELECT p.name, COUNT(mc.id) sales FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id GROUP BY p.id ORDER BY sales DESC LIMIT 5`).all();
  return c.json({ role: user.role === "operations_finance" ? "operations_finance" : "admin", total_sales: sales?.tot || 0, equipment_financed: financed?.tot || 0, cash_sales: cashSales?.tot || 0, repayment_rate: repayRate, default_rate: defaultRate, inventory_value: invValue?.tot || 0, active_customers: activeCust?.n || 0, pending_approvals: pending?.n || 0, top_products: topProducts });
});
app.get("/api/agents", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.region, u.label, u.permissions, u.status,
     (SELECT COUNT(*) FROM customers WHERE agent_id=u.id) customers,
     (SELECT COUNT(*) FROM murabaha_contracts WHERE agent_id=u.id AND status='active') active
     FROM users u WHERE u.role='agent'`
  ).all();
  const agentFallback = await loadRoleTemplate(c, "agent");
  return c.json({ agents: results.map((a) => ({ ...a, permissions: parsePermissions(a.permissions, "agent", agentFallback) })) });
});
app.post("/api/agents", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const p = normalizePhone(b.phone || "");
  if (!b.full_name || !p) return c.json({ error: "Name and phone are required" }, 400);
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (dup) return c.json({ error: "A user with this phone already exists" }, 409);
  const provided = b.password && String(b.password).length >= 4;
  const pwd = provided ? String(b.password) : genPassword();
  const perms = await permissionsForRole(c, "agent", b.permissions || {});
  const r = await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set,label,permissions) VALUES (?,?,?,?, 'agent', ?, ?, ?, ?)`).bind(b.full_name, p, b.email || null, await hashPassword(pwd), b.region || null, provided, b.label || "Agent", JSON.stringify(perms)).run();
  await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run();
  await audit(c, c.get("user").id, "create", "agent", b.full_name);
  return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: provided });
});
app.post("/api/users/:id/reset-password", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const target = await c.env.DB.prepare(`SELECT id, full_name, role FROM users WHERE id=?`).bind(id).first();
  if (!target) return c.json({ error: "User not found" }, 404);
  if (target.role === "super_admin" && Number(id) !== c.get("user").id) return c.json({ error: "Cannot reset another Super Admin password" }, 400);
  const body = await c.req.json().catch(() => ({}));
  const provided = body?.password && String(body.password).length >= 4;
  const pwd = provided ? String(body.password) : genPassword();
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(await hashPassword(pwd), id).run();
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run();
  await audit(c, c.get("user").id, "reset_password", target.role, target.full_name);
  return c.json({ ok: true, new_password: pwd, user: target.full_name });
});
app.put("/api/agents/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const b = await c.req.json();
  const perms = await permissionsForRole(c, "agent", b.permissions || {});
  await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, region=?, label=?, permissions=? WHERE id=? AND role='agent'`).bind(b.full_name, b.phone, b.email, b.region, b.label || "Agent", JSON.stringify(perms), id).run();
  await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region, JSON.stringify(perms), id).run();
  await audit(c, c.get("user").id, "update", "agent", b.full_name);
  return c.json({ ok: true });
});
app.get("/api/users", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT id, full_name, phone, email, role, label, permissions, status, region, schedule_enabled, access_days, access_start, access_end, created_at FROM users ORDER BY id`).all();
  const usersWithPerms = [];
  for (const u of results) {
    const fallback = await loadRoleTemplate(c, u.role);
    usersWithPerms.push({ ...u, permissions: parsePermissions(u.permissions, u.role, fallback), access_days: safeJson(u.access_days, []) });
  }
  return c.json({ users: usersWithPerms });
});
app.post("/api/users", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const b = await c.req.json();
  const p = normalizePhone(b.phone || "");
  if (!b.full_name || !p || !b.role) return c.json({ error: "Name, phone and role are required" }, 400);
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first();
  if (dup) return c.json({ error: "A user with this phone already exists" }, 409);
  const provided = b.password && String(b.password).length >= 4;
  const pwd = provided ? String(b.password) : genPassword();
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {});
  const templateRow = await c.env.DB.prepare(`SELECT label FROM role_templates WHERE role_key=?`).bind(String(b.role)).first();
  const label = b.label || templateRow?.label || (String(b.role) === "operations_finance" ? "Operations & Finance" : String(b.role).replace(/_/g, " "));
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0;
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null;
  const r = await c.env.DB.prepare(`INSERT INTO users (full_name, phone, email, password, role, label, permissions, status, region, password_set, schedule_enabled, access_days, access_start, access_end) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(b.full_name, p, b.email || null, await hashPassword(pwd), b.role, label, JSON.stringify(perms), b.status || "active", b.region || null, provided, schedEnabled, schedDays, b.access_start || null, b.access_end || null).run();
  if (b.role === "agent") await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run();
  await audit(c, c.get("user").id, "create", "user", `${b.full_name} (${b.role})`);
  return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: provided });
});
app.put("/api/users/:id", requireAuth, requireRole("admin", "super_admin"), async (c) => {
  const id = c.req.param("id");
  const b = await c.req.json();
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {});
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0;
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null;
  if (b.password) {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=?, password=? WHERE id=?`).bind(b.full_name, b.phone, b.email, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, await hashPassword(String(b.password)), id).run();
  } else {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE id=?`).bind(b.full_name, b.phone, b.email, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, id).run();
  }
  if (b.role === "agent") {
    const exists = await c.env.DB.prepare(`SELECT user_id FROM agents WHERE user_id=?`).bind(id).first();
    if (exists) await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region || null, JSON.stringify(perms), id).run();
    else await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(id, b.region || null, JSON.stringify(perms)).run();
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
app.get("/api/permissions", requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT permission_key, label, description, category FROM permission_catalog ORDER BY category, label`).all();
  const { results: roles } = await c.env.DB.prepare(`SELECT role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end FROM role_templates ORDER BY label`).all();
  return c.json({
    permissions: results,
    roles: roles.map((r) => ({ ...r, permissions: safeJson(r.permissions, {}), access_days: safeJson(r.access_days, []) }))
  });
});
app.post("/api/permissions", requireAuth, requireRole("super_admin"), async (c) => {
  const b = await c.req.json();
  const key = String(b.permission_key || "").trim().toLowerCase().replace(/[^a-z0-9_]+/g, "_");
  if (!key || !b.label) return c.json({ error: "Permission key and label are required" }, 400);
  await c.env.DB.prepare(`INSERT INTO permission_catalog (permission_key, label, description, category) VALUES (?,?,?,?)`).bind(key, b.label, b.description || null, b.category || "general").run();
  await audit(c, c.get("user").id, "create", "permission", key);
  return c.json({ ok: true, permission_key: key });
});
app.delete("/api/permissions/:key", requireAuth, requireRole("super_admin"), async (c) => {
  const key = c.req.param("key");
  await c.env.DB.prepare(`DELETE FROM permission_catalog WHERE permission_key=?`).bind(key).run();
  await audit(c, c.get("user").id, "delete", "permission", key);
  return c.json({ ok: true });
});
app.post("/api/role-templates", requireAuth, requireRole("super_admin"), async (c) => {
  const b = await c.req.json();
  const key = String(b.role_key || "").trim().toLowerCase().replace(/[^a-z0-9_]+/g, "_");
  if (!key || !b.label) return c.json({ error: "Role key and label are required" }, 400);
  const perms = b.permissions && typeof b.permissions === "object" ? b.permissions : {};
  const scheduleEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0;
  const accessDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null;
  const accessStart = b.access_start || null;
  const accessEnd = b.access_end || null;
  const existing = await c.env.DB.prepare(`SELECT id, is_system FROM role_templates WHERE role_key=?`).bind(key).first();
  if (existing) {
    await c.env.DB.prepare(`UPDATE role_templates SET label=?, description=?, permissions=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE role_key=?`).bind(b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd, key).run();
  } else {
    await c.env.DB.prepare(`INSERT INTO role_templates (role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end) VALUES (?,?,?,?, 0, ?,?,?,?)`).bind(key, b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd).run();
  }
  await audit(c, c.get("user").id, existing ? "update" : "create", "role_template", key);
  return c.json({ ok: true, role_key: key });
});
app.delete("/api/role-templates/:key", requireAuth, requireRole("super_admin"), async (c) => {
  const key = c.req.param("key");
  const row = await c.env.DB.prepare(`SELECT is_system FROM role_templates WHERE role_key=?`).bind(key).first();
  if (!row) return c.json({ error: "Not found" }, 404);
  if (row.is_system) return c.json({ error: "Built-in roles cannot be deleted" }, 400);
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM users WHERE role=?`).bind(key).first();
  if (Number(used?.n || 0) > 0) return c.json({ error: "Cannot delete: users are assigned to this role." }, 400);
  await c.env.DB.prepare(`DELETE FROM role_templates WHERE role_key=?`).bind(key).run();
  await audit(c, c.get("user").id, "delete", "role_template", key);
  return c.json({ ok: true });
});
app.get("/api/settings/financing", requireAuth, async (c) => {
  const user = c.get("user");
  const processing_fee = normalizeProcessingFee(await getSetting(c, "processing_fee", DEFAULT_PROCESSING_FEE));
  const financing_markup = normalizeFinancingMarkup(await getSetting(c, "financing_markup", DEFAULT_FINANCING_MARKUP));
  const { results } = await c.env.DB.prepare(`SELECT id, sku, name, category, quantity FROM products ORDER BY name`).all();
  return c.json({
    processing_fee,
    financing_markup,
    // legacy alias kept so older frontends do not break
    finance_markup: financing_markup,
    products: results,
    can_manage_processing_fees: hasPermission(user, "manage_processing_fees"),
    can_manage_markup: hasPermission(user, "manage_markup_pct")
  });
});
app.put("/api/settings/processing-fee", requireAuth, requirePermission("manage_processing_fees"), async (c) => {
  const b = await c.req.json();
  const cfg = normalizeProcessingFee(b);
  await setSetting(c, "processing_fee", cfg);
  await audit(c, c.get("user").id, "update", "settings", `processing_fee:${cfg.enabled ? cfg.mode : "disabled"} products:${cfg.product_ids.length || "all"}`);
  return c.json({ ok: true, processing_fee: cfg });
});
async function saveFinancingMarkup(c) {
  const b = await c.req.json();
  const cfg = normalizeFinancingMarkup(b);
  await setSetting(c, "financing_markup", cfg);
  await audit(c, c.get("user").id, "update", "settings", `financing_markup:${cfg.financing_applicable ? cfg.mode : "cash_only"} products:${cfg.product_ids.length || "all"}`);
  return c.json({ ok: true, financing_markup: cfg, finance_markup: cfg });
}
app.put("/api/settings/financing-markup", requireAuth, requirePermission("manage_markup_pct"), saveFinancingMarkup);
app.put("/api/settings/markup", requireAuth, requirePermission("manage_markup_pct"), saveFinancingMarkup);
app.post("/api/settings/quick-product", requireAuth, async (c) => {
  const user = c.get("user");
  const allowed = user.role === "admin" || user.role === "super_admin" || hasPermission(user, "manage_processing_fees") || hasPermission(user, "manage_markup_pct");
  if (!allowed) return c.json({ error: "Forbidden" }, 403);
  const p = normalizeProductPayload(await c.req.json());
  if (!p.sku || !p.name) return c.json({ error: "SKU and name are required" }, 400);
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO products (sku,name,category,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url,transunion_product_code)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      p.sku,
      p.name,
      p.category,
      p.description,
      p.product_type,
      p.supplier_id,
      p.buying_price,
      p.cash_markup_pct,
      p.credit_markup_pct,
      p.cash_price,
      p.credit_price,
      p.quantity,
      p.unit,
      p.reorder_threshold,
      p.image,
      p.cash_enabled,
      p.financing_enabled,
      p.payment_option_mode,
      p.financing_model,
      p.financing_interest_pct,
      p.financing_frequency,
      p.financing_term_min_months,
      p.financing_term_max_months,
      p.cash_deposit_pct,
      p.financing_deposit_pct,
      p.cash_terms_text,
      p.financing_terms_text,
      p.cash_terms_doc_url,
      p.financing_terms_doc_url,
      p.transunion_product_code
    ).run();
    await audit(c, user.id, "create", "product", `${p.name} (via settings builder)`);
    return c.json({ id: r.meta.last_row_id, product: { id: r.meta.last_row_id, sku: p.sku, name: p.name, category: p.category, quantity: p.quantity } });
  } catch (err) {
    if (/unique|duplicate/i.test(String(err?.message || ""))) return c.json({ error: "A product with this SKU already exists" }, 400);
    return c.json({ error: "Failed to create product" }, 500);
  }
});
app.post("/api/change-requests", requireAuth, async (c) => {
  const user = c.get("user");
  if (!hasPermission(user, "request_admin_action")) return c.json({ error: "Forbidden" }, 403);
  const { entity_type, entity_id, requested_action, reason } = await c.req.json();
  await c.env.DB.prepare(`INSERT INTO change_requests (requester_id, entity_type, entity_id, requested_action, reason) VALUES (?,?,?,?,?)`).bind(user.id, entity_type, entity_id || null, requested_action, reason || "").run();
  await audit(c, user.id, "request_admin_action", entity_type || "entity", `${requested_action || "request"} ${entity_id || ""}`);
  return c.json({ ok: true });
});
app.get("/api/repayments", requireAuth, requireRole("admin", "super_admin", "support", "operations_finance"), async (c) => {
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
    sql: `SELECT id, full_name, phone, email, role, label, status, region, created_at FROM users`,
    cols: ["id", "full_name", "phone", "email", "role", "label", "status", "region", "created_at"],
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
    sql: `SELECT id, sku, name, category, product_type, payment_option_mode, financing_model, financing_interest_pct, cash_deposit_pct, financing_deposit_pct, buying_price, cash_price, credit_price, quantity, unit, reorder_threshold FROM products`,
    cols: ["id", "sku", "name", "category", "product_type", "payment_option_mode", "financing_model", "financing_interest_pct", "cash_deposit_pct", "financing_deposit_pct", "buying_price", "cash_price", "credit_price", "quantity", "unit", "reorder_threshold"],
    filterable: { category: "category" }
  },
  contracts: {
    label: "Murabaha Contracts",
    sql: `SELECT mc.id, mc.contract_ref, cu.full_name customer, p.name product, mc.payment_type, mc.financing_model, mc.deposit_pct, mc.deposit_amount, mc.payment_frequency, mc.installment_amount, mc.murabaha_price, mc.amount_paid, mc.outstanding, mc.status, mc.dispatch_status, mc.created_at FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id JOIN products p ON p.id=mc.product_id`,
    cols: ["id", "contract_ref", "customer", "product", "payment_type", "financing_model", "deposit_pct", "deposit_amount", "payment_frequency", "installment_amount", "murabaha_price", "amount_paid", "outstanding", "status", "dispatch_status", "created_at"],
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
async function ensureWallet(c, userId, assignedBy = null) {
  return await withAdminContext(c, async () => {
    const existing = await c.env.DB.prepare(`SELECT id FROM wallets WHERE user_id=?`).bind(userId).first();
    if (existing) return Number(existing.id);
    const r = await c.env.DB.prepare(`INSERT INTO wallets (user_id, assigned_by) VALUES (?,?)`).bind(userId, assignedBy).run();
    return Number(r.meta.last_row_id);
  });
}
async function postLedger(c, opts) {
  return await c.env.DB.prepare(
    `INSERT INTO wallet_ledger (wallet_id, user_id, entry_type, amount, balance_after, category, reference, description, created_by)
     VALUES (?,?,?,?, 0, ?,?,?,?)`
  ).bind(opts.walletId, opts.userId, opts.type, roundMoney(opts.amount), opts.category, opts.reference ?? null, opts.description ?? null, opts.createdBy ?? null).run();
}
app.get("/api/wallet", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  const walletId = await ensureWallet(c, user.id);
  const wallet = await c.env.DB.prepare(`SELECT * FROM wallets WHERE id=?`).bind(walletId).first();
  const { results: ledger } = await c.env.DB.prepare(`SELECT * FROM wallet_ledger WHERE wallet_id=? ORDER BY id DESC LIMIT 200`).bind(walletId).all();
  const { results: rules } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 ORDER BY id`).bind(user.id).all();
  return c.json({ wallet, ledger, earning_rules: rules });
});
app.get("/api/wallets", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT w.*, u.full_name, u.phone, u.role,
              (SELECT COUNT(*) FROM earning_rules er WHERE er.user_id=w.user_id AND er.is_active=1) AS rule_count
         FROM wallets w JOIN users u ON u.id = w.user_id ORDER BY u.full_name`
    ).all();
    return results;
  });
  return c.json({ wallets: rows });
});
app.post("/api/wallets", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const admin = c.get("user");
  const b = await c.req.json();
  const userId = Number(b.user_id);
  if (!userId) return c.json({ error: "user_id is required" }, 400);
  const walletId = await ensureWallet(c, userId, admin.id);
  await audit(c, admin.id, "assign", "wallet", `wallet for user ${userId}`);
  return c.json({ ok: true, wallet_id: walletId });
});
app.get("/api/earning-rules/:userId", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const userId = c.req.param("userId");
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? ORDER BY id`).bind(userId).all();
    return results;
  });
  return c.json({ earning_rules: rows });
});
app.post("/api/earning-rules", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const admin = c.get("user");
  const b = await c.req.json();
  const userId = Number(b.user_id);
  const ruleType = String(b.rule_type || "").trim();
  if (!userId || !ruleType) return c.json({ error: "user_id and rule_type are required" }, 400);
  const calcMethod = b.calc_method === "percentage" ? "percentage" : "fixed";
  await ensureWallet(c, userId, admin.id);
  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO earning_rules (user_id, rule_type, calc_method, rate, fixed_amount, applies_to, description, is_active, created_by)
     VALUES (?,?,?,?,?,?,?,1,?)`
  ).bind(userId, ruleType, calcMethod, calcMethod === "percentage" ? numberVal(b.rate, 0) : null, calcMethod === "fixed" ? numberVal(b.fixed_amount, 0) : null, b.applies_to || (ruleType === "commission" ? "completed_order" : "manual"), b.description || null, admin.id).run());
  await audit(c, admin.id, "create", "earning_rule", `${ruleType} for user ${userId}`);
  return c.json({ ok: true, id: r.meta.last_row_id });
});
app.put("/api/earning-rules/:id", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const admin = c.get("user");
  const id = c.req.param("id");
  const b = await c.req.json();
  await withAdminContext(c, async () => await c.env.DB.prepare(
    `UPDATE earning_rules SET rule_type=COALESCE(?,rule_type), calc_method=COALESCE(?,calc_method), rate=?, fixed_amount=?, applies_to=COALESCE(?,applies_to), description=COALESCE(?,description), is_active=COALESCE(?,is_active), updated_at=CURRENT_TIMESTAMP WHERE id=?`
  ).bind(b.rule_type ?? null, b.calc_method ?? null, b.rate ?? null, b.fixed_amount ?? null, b.applies_to ?? null, b.description ?? null, b.is_active === void 0 ? null : boolInt(b.is_active, true) ? 1 : 0, id).run());
  await audit(c, admin.id, "update", "earning_rule", String(id));
  return c.json({ ok: true });
});
async function distributeCommission(c, contract) {
  if (!contract) return;
  const agentId = contract.created_by || contract.agent_id;
  if (!agentId) return;
  const orderValue = numberVal(contract.murabaha_price ?? contract.total_payable, 0);
  await withAdminContext(c, async () => {
    const { results: rules } = await c.env.DB.prepare(
      `SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 AND applies_to='completed_order'`
    ).bind(agentId).all();
    if (!rules?.length) return;
    const walletId = await ensureWallet(c, agentId);
    for (const rule of rules) {
      const dup = await c.env.DB.prepare(
        `SELECT 1 FROM wallet_ledger WHERE wallet_id=? AND category=? AND reference=? LIMIT 1`
      ).bind(walletId, rule.rule_type, contract.contract_ref).first();
      if (dup) continue;
      const amount = rule.calc_method === "percentage" ? roundMoney(orderValue * numberVal(rule.rate, 0) / 100) : roundMoney(numberVal(rule.fixed_amount, 0));
      if (amount <= 0) continue;
      await postLedger(c, { userId: agentId, walletId, type: "credit", amount, category: rule.rule_type, reference: contract.contract_ref, description: `${rule.rule_type} on ${contract.contract_ref}`, createdBy: null });
    }
  });
}
app.post("/api/wallet/payouts", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const admin = c.get("user");
  const b = await c.req.json();
  const category = String(b.category || "retainer");
  const amount = roundMoney(numberVal(b.amount, 0));
  if (amount <= 0) return c.json({ error: "amount must be > 0" }, 400);
  const batchRef = ref("PAY");
  const result = await withAdminContext(c, async () => {
    let recipients = [];
    if (Array.isArray(b.user_ids) && b.user_ids.length) {
      recipients = b.user_ids.map((x) => Number(x)).filter(Boolean);
    } else if (b.user_id) {
      recipients = [Number(b.user_id)];
    } else if (b.target === "all_agents") {
      const { results } = await c.env.DB.prepare(`SELECT id FROM users WHERE role='agent' AND status='active'`).all();
      recipients = results.map((r) => Number(r.id));
    }
    if (!recipients.length) return { error: "No recipients resolved" };
    let total = 0, count = 0;
    for (const uid of recipients) {
      const walletId = await ensureWallet(c, uid, admin.id);
      await postLedger(c, { userId: uid, walletId, type: "credit", amount, category, reference: batchRef, description: b.description || `${category} disbursal`, createdBy: admin.id });
      total += amount;
      count++;
    }
    await c.env.DB.prepare(
      `INSERT INTO payout_batches (batch_ref, category, description, total_amount, recipient_count, issued_by, payment_method) VALUES (?,?,?,?,?,?, 'wallet_credit')`
    ).bind(batchRef, category, b.description || null, roundMoney(total), count, admin.id).run();
    return { total: roundMoney(total), count };
  });
  if (result.error) return c.json(result, 400);
  await audit(c, admin.id, "payout", "wallet", `${batchRef} ${category} x${result.count}`);
  return c.json({ ok: true, batch_ref: batchRef, ...result });
});
app.get("/api/wallet/analytics", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  const isAdmin = hasPermission(user, "manage_wallets") && ["admin", "super_admin"].includes(user.role);
  const byCategory = await c.env.DB.prepare(
    `SELECT category, entry_type, COUNT(*) AS entries, COALESCE(SUM(amount),0) AS total
       FROM wallet_ledger GROUP BY category, entry_type ORDER BY category`
  ).all();
  const totals = await c.env.DB.prepare(
    `SELECT COALESCE(SUM(CASE WHEN entry_type='credit' THEN amount ELSE 0 END),0) AS total_earned,
            COALESCE(SUM(CASE WHEN entry_type='debit'  THEN amount ELSE 0 END),0) AS total_debited
       FROM wallet_ledger`
  ).first();
  return c.json({ scope: isAdmin ? "global" : "self", totals, by_category: byCategory.results });
});
app.get("/api/payout-accounts", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  const { results } = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE user_id=? ORDER BY is_default DESC, id DESC`).bind(user.id).all();
  return c.json({ accounts: results });
});
app.post("/api/payout-accounts", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  const b = await c.req.json();
  const channelCode = String(b.channel_code || "").trim();
  const chan = channelByCode(channelCode);
  if (!chan) return c.json({ error: "Unknown channel" }, 400);
  const raw2 = String(b.account_number || "").trim();
  if (!raw2) return c.json({ error: "account_number is required" }, 400);
  const account = chan.type === "mobile" || chan.type === "wallet" ? normalizePhone2(raw2) : raw2;
  const acctType = accountTypeForChannel(channelCode);
  const v = await sasapayValidateAccount(c.env, channelCode, account);
  const verified = v.success ? 1 : 0;
  const accountName = v.account_name || b.account_name || null;
  if (b.is_default) {
    await c.env.DB.prepare(`UPDATE payout_accounts SET is_default=0 WHERE user_id=?`).bind(user.id).run();
  }
  const r = await c.env.DB.prepare(
    `INSERT INTO payout_accounts (user_id, label, channel_code, channel_name, account_type, account_number, account_name, is_verified, is_default, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(user.id, b.label || chan.name, channelCode, chan.name, acctType, account, accountName, verified, b.is_default ? 1 : 0, user.id).run();
  await audit(c, user.id, "create", "payout_account", `${chan.name} ${account} (${verified ? "verified" : "unverified"})`);
  return c.json({ ok: true, id: r.meta.last_row_id, is_verified: !!verified, account_name: accountName, simulated: v.simulated });
});
app.delete("/api/payout-accounts/:id", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  await c.env.DB.prepare(`DELETE FROM payout_accounts WHERE id=? AND user_id=?`).bind(c.req.param("id"), user.id).run();
  return c.json({ ok: true });
});
app.post("/api/wallet/withdraw", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const user = c.get("user");
  const b = await c.req.json();
  const amount = roundMoney(numberVal(b.amount, 0));
  if (amount <= 0) return c.json({ error: "amount must be > 0" }, 400);
  let channelCode = String(b.channel_code || "").trim();
  let receiver = String(b.account_number || "").trim();
  let recipientName = b.account_name || null;
  if (b.payout_account_id) {
    const acct = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE id=? AND user_id=?`).bind(b.payout_account_id, user.id).first();
    if (!acct) return c.json({ error: "Payout account not found" }, 404);
    channelCode = String(acct.channel_code);
    receiver = String(acct.account_number);
    recipientName = acct.account_name || null;
  }
  const chan = channelByCode(channelCode);
  if (!chan) return c.json({ error: "A valid withdrawal channel is required" }, 400);
  if (!receiver) return c.json({ error: "A destination account is required" }, 400);
  if (chan.type === "mobile" || chan.type === "wallet") receiver = normalizePhone2(receiver);
  const reference = ref("WD");
  const walletId = await ensureWallet(c, user.id);
  try {
    await postLedger(c, { userId: user.id, walletId, type: "debit", amount, category: "withdrawal", reference, description: b.reason || `Withdrawal to ${chan.name}`, createdBy: user.id });
  } catch (e) {
    const msg = String(e?.message || "");
    if (/insufficient/i.test(msg)) return c.json({ error: "Insufficient wallet balance" }, 400);
    return c.json({ error: "Withdrawal could not be posted" }, 400);
  }
  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'withdrawal', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 1, ?)`
  ).bind(reference, walletId, user.id, amount, channelCode, chan.name, receiver, recipientName, b.reason || "Wallet withdrawal", user.id).run();
  const payout = await sasapayB2C(c.env, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || "Wallet withdrawal", reference });
  if (!payout.success) {
    await postLedger(c, { userId: user.id, walletId, type: "credit", amount, category: "adjustment", reference, description: `Reversal \u2014 failed withdrawal ${reference}`, createdBy: user.id });
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || "B2C failed", reference).run();
    return c.json({ error: payout.error || "Disbursal failed; wallet has been refunded." }, 502);
  }
  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? "success" : "processing", reference).run();
  await audit(c, user.id, "withdraw", "wallet", `KES ${amount} to ${chan.name} ${receiver} (${payout.simulated ? "sim" : "live"})`);
  return c.json({ ok: true, simulated: payout.simulated, reference, status: payout.simulated ? "success" : "processing", customer_message: payout.customer_message || (payout.simulated ? "Withdrawal completed (simulation)." : "Withdrawal is being processed.") });
});
app.get("/api/wallet/withdrawals", requireAuth, requirePermission("view_wallet", "manage_wallets"), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals ORDER BY id DESC LIMIT 100`).all();
  return c.json({ withdrawals: results });
});
app.post("/api/wallet/direct-pay", requireAuth, requirePermission("manage_wallets"), async (c) => {
  const admin = c.get("user");
  const b = await c.req.json();
  const amount = roundMoney(numberVal(b.amount, 0));
  if (amount <= 0) return c.json({ error: "amount must be > 0" }, 400);
  const destination = b.destination === "external" ? "external" : "wallet";
  const reference = ref("DP");
  if (destination === "wallet") {
    const recipientId = Number(b.user_id);
    if (!recipientId) return c.json({ error: "user_id is required for a wallet payment" }, 400);
    const result = await withAdminContext(c, async () => {
      const walletId = await ensureWallet(c, recipientId, admin.id);
      await postLedger(c, { userId: recipientId, walletId, type: "credit", amount, category: b.category || "direct_pay", reference, description: b.reason || "Direct payment", createdBy: admin.id });
      await c.env.DB.prepare(
        `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, reason, status, ledger_debited, created_by)
         VALUES (?, 'direct_pay', ?,?,?,?, 'KES', '0', 'SasaPay Wallet (internal)', ?, ?, 'success', 0, ?)`
      ).bind(reference, walletId, admin.id, recipientId, amount, String(recipientId), b.reason || "Direct wallet payment", admin.id).run();
      return { walletId };
    });
    await audit(c, admin.id, "direct_pay", "wallet", `KES ${amount} to user ${recipientId} wallet`);
    return c.json({ ok: true, destination: "wallet", reference, status: "success", ...result });
  }
  const channelCode = String(b.channel_code || "").trim();
  const chan = channelByCode(channelCode);
  if (!chan) return c.json({ error: "A valid payout channel is required" }, 400);
  let receiver = String(b.account_number || "").trim();
  if (!receiver) return c.json({ error: "A destination account is required" }, 400);
  if (chan.type === "mobile" || chan.type === "wallet") receiver = normalizePhone2(receiver);
  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'direct_pay', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 0, ?)`
  ).bind(reference, admin.id, b.user_id ? Number(b.user_id) : null, amount, channelCode, chan.name, receiver, b.account_name || null, b.reason || "Direct payment", admin.id).run();
  const payout = await sasapayB2C(c.env, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || "Direct payment", reference });
  if (!payout.success) {
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || "B2C failed", reference).run();
    return c.json({ error: payout.error || "Disbursal failed" }, 502);
  }
  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? "success" : "processing", reference).run();
  await audit(c, admin.id, "direct_pay", "sasapay", `KES ${amount} to ${chan.name} ${receiver} (${payout.simulated ? "sim" : "live"})`);
  return c.json({ ok: true, destination: "external", simulated: payout.simulated, reference, status: payout.simulated ? "success" : "processing", customer_message: payout.customer_message || "Payment is being processed." });
});
app.post("/api/sasapay/b2c-callback", async (c) => {
  try {
    const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || c.req.header("x-real-ip");
    const sig = c.req.header("x-sasapay-signature") || c.req.header("X-SasaPay-Signature");
    const body = await c.req.json().catch(() => ({}));
    if (sasapayConfigured(c.env)) {
      const ipOk = isTrustedSasapayIp(ip);
      const sigOk = await verifySasapaySignature(c.env, sig, {
        sasapay_transaction_code: body.TransactionCode || body.SasaPayTransactionCode || "",
        merchant_code: body.MerchantCode || "",
        account_number: body.ReceiverNumber || "",
        payment_reference: body.MerchantTransactionReference || body.OriginatorConversationID || "",
        amount: body.Amount || ""
      });
      if (!ipOk && !sigOk) {
        await audit(c, null, "callback_rejected", "sasapay_b2c", `untrusted ip=${ip || "?"} sig=${sig ? "bad" : "missing"}`);
        return c.json({ ResultCode: 1, ResultDesc: "Rejected" }, 403);
      }
    }
    const reference = body.MerchantTransactionReference || body.OriginatorConversationID;
    const b2cId = body.B2CRequestID || body.ConversationID;
    const row = reference ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE reference=?`).bind(reference).first() : b2cId ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE b2c_request_id=? OR conversation_id=?`).bind(b2cId, b2cId).first() : null;
    if (row && (row.status === "processing" || row.status === "pending")) {
      const code = body.ResultCode ?? body.status_code ?? body.TransactionCode;
      const success = code === 0 || code === "0" || body.status === true || String(body.ResultDesc || "").toLowerCase().includes("success");
      if (success) {
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='success', transaction_code=?, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(body.TransactionCode || body.SasaPayTransactionCode || "", String(code ?? "0"), body.ResultDesc || "Success", row.reference).run();
      } else {
        if (row.ledger_debited && row.wallet_id && row.user_id) {
          try {
            await withAdminContext(c, async () => {
              await postLedger(c, { userId: row.user_id, walletId: row.wallet_id, type: "credit", amount: numberVal(row.amount, 0), category: "adjustment", reference: row.reference, description: `Reversal \u2014 failed payout ${row.reference}`, createdBy: null });
            });
          } catch (_) {
          }
        }
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(String(code ?? "1"), body.ResultDesc || "Payout failed", row.reference).run();
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch {
    return c.json({ ResultCode: 0, ResultDesc: "Accepted" });
  }
});
app.get("/api/security/rls-check", requireAuth, requireRole("super_admin"), async (c) => {
  const setLocal = c.env.DB?.setSessionConfig;
  if (typeof setLocal !== "function") return c.json({ supported: false, note: "RLS is a PostgreSQL feature; not active on this runtime." });
  await setLocal.call(c.env.DB, "app.current_user_id", "");
  await setLocal.call(c.env.DB, "app.current_role", "");
  const probe = async (t) => {
    try {
      const r = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM ${t}`).first();
      return Number(r?.n ?? -1);
    } catch {
      return -1;
    }
  };
  const result = {
    customers: await probe("customers"),
    products: await probe("products"),
    murabaha_contracts: await probe("murabaha_contracts"),
    wallet_ledger: await probe("wallet_ledger")
  };
  await setUserContext(c, c.get("user"));
  const leaking = Object.entries(result).filter(([, n]) => n > 0).map(([t]) => t);
  return c.json({
    supported: true,
    without_context_counts: result,
    isolation_ok: leaking.length === 0,
    message: leaking.length === 0 ? "RLS active: no rows are visible without a user context \u2014 data-leak vectors are closed." : `WARNING: tables leaking without context: ${leaking.join(", ")}. Ensure backend/sql/03_ownership_rls_setup.sql has been applied.`
  });
});
app.get("/", (c) => c.html(SHELL));
var SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky \u2014 Sharia-Compliant Agri-Finance</title>
  <link rel="icon" type="image/png" href="/static/favicon.png">
  <!-- Production Tailwind build (compiled via Tailwind CLI, no runtime CDN JIT). -->
  <link href="/static/tailwind.css" rel="stylesheet">
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

// backend/db-postgres.ts
import { Pool, types as pgTypes } from "pg";
pgTypes.setTypeParser(20, (value) => Number(value));
pgTypes.setTypeParser(21, (value) => Number(value));
pgTypes.setTypeParser(23, (value) => Number(value));
pgTypes.setTypeParser(700, (value) => Number(value));
pgTypes.setTypeParser(701, (value) => Number(value));
pgTypes.setTypeParser(1700, (value) => Number(value));
var TABLES_WITH_NUMERIC_ID = /* @__PURE__ */ new Set([
  "users",
  "agents",
  "customers",
  "suppliers",
  "products",
  "stock_movements",
  "murabaha_contracts",
  "repayments",
  "invoices",
  "transactions",
  "approvals",
  "transunion_checks",
  "id_verifications",
  "audit_logs",
  "tickets",
  "otp_codes",
  "payment_intents",
  "change_requests"
]);
function convertPlaceholders(sql) {
  let out = "";
  let inSingle = false;
  let inDouble = false;
  let index = 1;
  for (let i = 0; i < sql.length; i++) {
    const char = sql[i];
    const next = sql[i + 1];
    if (char === "'" && !inDouble) {
      out += char;
      if (inSingle && next === "'") {
        out += next;
        i++;
      } else {
        inSingle = !inSingle;
      }
      continue;
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      out += char;
      continue;
    }
    if (char === "?" && !inSingle && !inDouble) {
      out += `$${index++}`;
      continue;
    }
    out += char;
  }
  return out;
}
function tableNameFromInsert(sql) {
  const match = sql.match(/^\s*insert\s+into\s+"?([a-zA-Z0-9_\.]+)"?/i);
  return match?.[1]?.split(".").pop()?.replace(/"/g, "") || null;
}
function normalizeParam(value) {
  if (value === void 0) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  return value;
}
var PostgresStatement = class {
  constructor(pool, rawSql) {
    this.pool = pool;
    this.rawSql = rawSql;
  }
  params = [];
  bind(...args) {
    this.params = args.map(normalizeParam);
    return this;
  }
  async query(sqlOverride) {
    const sql = convertPlaceholders(sqlOverride || this.rawSql);
    return this.pool.query(sql, this.params);
  }
  async first() {
    const result = await this.query();
    return result.rows[0] ?? null;
  }
  async all() {
    const result = await this.query();
    return { results: result.rows, success: true };
  }
  async run() {
    let sql = this.rawSql.trim().replace(/;\s*$/, "");
    let lastRowId = 0;
    if (/^insert\s+/i.test(sql) && !/\breturning\b/i.test(sql)) {
      const table = tableNameFromInsert(sql);
      if (table && TABLES_WITH_NUMERIC_ID.has(table)) sql += " RETURNING id";
    }
    const result = await this.query(sql);
    if (result.rows?.[0]?.id != null) lastRowId = Number(result.rows[0].id);
    return {
      success: true,
      meta: {
        last_row_id: lastRowId,
        changes: result.rowCount || 0
      }
    };
  }
};
var PostgresD1 = class {
  constructor(pool) {
    this.pool = pool;
  }
  prepare(sql) {
    return new PostgresStatement(this.pool, sql);
  }
  /**
   * Sets a session-scoped configuration parameter (GUC) used by Row-Level
   * Security policies, e.g. app.current_marketplace_id / app.is_admin.
   * Uses set_config(name, value, is_local=false) so it applies to the whole
   * session. Tolerates non-Postgres/edge failures silently at the caller.
   */
  async setSessionConfig(name, value) {
    await this.pool.query("SELECT set_config($1, $2, false)", [name, value == null ? "" : String(value)]);
  }
};
async function openDatabase(connectionString) {
  const requireSsl = process.env.PGSSLMODE === "require" || process.env.DATABASE_SSL === "require";
  const config = {
    connectionString,
    ssl: requireSsl ? { rejectUnauthorized: false } : void 0,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 3e4),
    connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT_MS || 1e4),
    statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS || 2e4),
    query_timeout: Number(process.env.PG_QUERY_TIMEOUT_MS || 2e4),
    application_name: "farmsky"
  };
  const raw2 = new Pool(config);
  raw2.on("error", (err) => {
    console.error("[db] idle client error (recovered):", err?.message || err);
  });
  await raw2.query("SELECT 1");
  return { d1: new PostgresD1(raw2), raw: raw2 };
}

// backend/db-init.ts
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
var SERIAL_TABLES = [
  "users",
  "agents",
  "customers",
  "suppliers",
  "products",
  "stock_movements",
  "murabaha_contracts",
  "repayments",
  "invoices",
  "transactions",
  "approvals",
  "transunion_checks",
  "id_verifications",
  "audit_logs",
  "tickets",
  "otp_codes",
  "payment_intents",
  "change_requests",
  "permission_catalog",
  "role_templates"
];
function splitStatements(sql) {
  const stripped = sql.replace(/^\s*--.*$/gm, "");
  return stripped.split(/;\s*(?:\n|$)/g).map((statement) => statement.trim()).filter(Boolean);
}
function transformStatement(originalStatement) {
  let sql = originalStatement.trim();
  let conflict = false;
  if (/^insert\s+or\s+ignore\s+into/i.test(sql)) {
    conflict = true;
    sql = sql.replace(/^insert\s+or\s+ignore\s+into/i, "INSERT INTO");
  }
  sql = sql.replace(/\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b/gi, "BIGSERIAL PRIMARY KEY");
  sql = sql.replace(/\bAUTOINCREMENT\b/gi, "");
  sql = sql.replace(/\bDATETIME\b/gi, "TIMESTAMP");
  sql = sql.replace(/\bREAL\b/gi, "DOUBLE PRECISION");
  sql = sql.replace(/,\s*\)/g, "\n)");
  return { sql, conflict };
}
async function execStatement(pool, statement, allowConflict) {
  try {
    let sql = statement;
    if (allowConflict && /^insert\s+into/i.test(sql) && !/on\s+conflict/i.test(sql)) {
      sql += " ON CONFLICT DO NOTHING";
    }
    await pool.query(sql);
  } catch (error) {
    const code = error?.code || "";
    const message = String(error?.message || "");
    if (["42701", "42P07", "23505", "42809", "42P06"].includes(code)) return;
    if (/already exists|duplicate column|is not a|wrong (object )?type/i.test(message)) return;
    throw error;
  }
}
async function applySqlFile(pool, file) {
  const rawSql = readFileSync(file, "utf8");
  for (const statement of splitStatements(rawSql)) {
    const { sql, conflict } = transformStatement(statement);
    await execStatement(pool, sql, conflict);
  }
}
async function tableExists(pool, tableName) {
  const { rows } = await pool.query(
    `SELECT EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1
    ) AS present`,
    [tableName]
  );
  return Boolean(rows[0]?.present);
}
async function syncSequences(pool) {
  for (const table of SERIAL_TABLES) {
    const client = await pool.connect();
    try {
      await client.query(`SELECT set_config('app.current_role', 'admin', false)`);
      await client.query(`SELECT set_config('app.user_can_finance', 'true', false)`);
      await client.query(
        `SELECT setval(pg_get_serial_sequence($1, 'id'), GREATEST(COALESCE((SELECT MAX(id) FROM ${table}), 1), 1), true)`,
        [table]
      );
    } catch (_) {
    } finally {
      try {
        await client.query(`SELECT set_config('app.current_role', '', false)`);
      } catch (_) {
      }
      client.release();
    }
  }
}
async function initializeDatabase(pool, projectRoot) {
  const hasUsers = await tableExists(pool, "users");
  const migrationsDir = join(projectRoot, "migrations");
  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir).filter((file) => file.endsWith(".sql")).sort();
    for (const file of files) {
      try {
        await applySqlFile(pool, join(migrationsDir, file));
      } catch (error) {
        console.error(`Migration ${file} error:`, error.message);
        throw error;
      }
    }
  }
  if (!hasUsers) {
    const seedFile = join(projectRoot, "seed.sql");
    if (existsSync(seedFile)) {
      await applySqlFile(pool, seedFile);
      console.log("Seed data loaded.");
    }
  }
  await syncSequences(pool);
}

// backend/server.ts
var __dirname = dirname(fileURLToPath(import.meta.url));
var PROJECT_ROOT = join2(__dirname, "..");
var DATABASE_URL = process.env.DATABASE_URL || "postgresql://postgres:postgres@127.0.0.1:5432/farmsky";
var migrateOnly = process.argv.includes("--migrate-only");
var { d1, raw } = await openDatabase(DATABASE_URL);
var dbReady = false;
var dbInitError = null;
if (migrateOnly) {
  await initializeDatabase(raw, PROJECT_ROOT);
  console.log(`PostgreSQL ready: ${DATABASE_URL.replace(/:[^:@/]+@/, ":***@")}`);
  await raw.end();
  process.exit(0);
}
var ENV = {
  DB: d1,
  MPESA_CONSUMER_KEY: process.env.MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET: process.env.MPESA_CONSUMER_SECRET,
  MPESA_SHORTCODE: process.env.MPESA_SHORTCODE,
  MPESA_PASSKEY: process.env.MPESA_PASSKEY,
  MPESA_ENV: process.env.MPESA_ENV,
  MPESA_CALLBACK_URL: process.env.MPESA_CALLBACK_URL,
  // SasaPay - accept either CLIENT_* or CONSUMER_* naming (auto-alias)
  SASAPAY_CLIENT_ID: process.env.SASAPAY_CLIENT_ID || process.env.SASAPAY_CONSUMER_KEY,
  SASAPAY_CLIENT_SECRET: process.env.SASAPAY_CLIENT_SECRET || process.env.SASAPAY_CONSUMER_SECRET,
  SASAPAY_CONSUMER_KEY: process.env.SASAPAY_CONSUMER_KEY || process.env.SASAPAY_CLIENT_ID,
  SASAPAY_CONSUMER_SECRET: process.env.SASAPAY_CONSUMER_SECRET || process.env.SASAPAY_CLIENT_SECRET,
  SASAPAY_MERCHANT_CODE: process.env.SASAPAY_MERCHANT_CODE,
  SASAPAY_ENV: process.env.SASAPAY_ENV,
  SASAPAY_CALLBACK_URL: process.env.SASAPAY_CALLBACK_URL,
  SASAPAY_B2C_CALLBACK_URL: process.env.SASAPAY_B2C_CALLBACK_URL || process.env.SASAPAY_CALLBACK_URL,
  BUNI_CLIENT_ID: process.env.BUNI_CLIENT_ID,
  BUNI_CLIENT_SECRET: process.env.BUNI_CLIENT_SECRET,
  BUNI_API_KEY: process.env.BUNI_API_KEY,
  BUNI_TILL_NUMBER: process.env.BUNI_TILL_NUMBER,
  BUNI_ENV: process.env.BUNI_ENV,
  BUNI_CALLBACK_URL: process.env.BUNI_CALLBACK_URL,
  SMS_PROVIDER: process.env.SMS_PROVIDER,
  SMS_API_URL: process.env.SMS_API_URL,
  SMS_API_TOKEN: process.env.SMS_API_TOKEN,
  SMS_SENDER_ID: process.env.SMS_SENDER_ID,
  SMS_BODY_TEMPLATE: process.env.SMS_BODY_TEMPLATE,
  SMS_PHONE_FIELD: process.env.SMS_PHONE_FIELD,
  SMS_MESSAGE_FIELD: process.env.SMS_MESSAGE_FIELD,
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER,
  EMAIL_API_URL: process.env.EMAIL_API_URL,
  EMAIL_API_TOKEN: process.env.EMAIL_API_TOKEN,
  EMAIL_FROM: process.env.EMAIL_FROM,
  TRANSUNION_API_URL: process.env.TRANSUNION_API_URL,
  TRANSUNION_API_KEY: process.env.TRANSUNION_API_KEY,
  TRANSUNION_CLIENT_ID: process.env.TRANSUNION_CLIENT_ID,
  TRANSUNION_ENV: process.env.TRANSUNION_ENV,
  // Central Payment Gateway client (equipment.farmsky.africa) — env only
  FARMSKY_PAYMENTS_GATEWAY_URL: process.env.FARMSKY_PAYMENTS_GATEWAY_URL,
  FARMSKY_PAYMENTS_CLIENT_KEY: process.env.FARMSKY_PAYMENTS_CLIENT_KEY,
  FARMSKY_PAYMENTS_HMAC_SECRET: process.env.FARMSKY_PAYMENTS_HMAC_SECRET,
  // Session signing secret
  SESSION_SECRET: process.env.SESSION_SECRET
};
var root = new Hono3();
root.get("/health", (c) => c.json({ ok: true, dbReady, ts: Date.now() }));
root.get("/healthz", (c) => c.text(dbReady ? "ok" : "starting", dbReady ? 200 : 200));
root.get("/api/ping", (c) => c.json({ ok: true, service: "farmsky", dbReady, ts: Date.now() }));
root.use("/static/*", serveStatic({ root: "./frontend" }));
var nodeExecutionCtx = {
  waitUntil: (p) => {
    Promise.resolve(p).catch(() => {
    });
  },
  passThroughOnException: () => {
  }
};
var ALWAYS_ADMIT = /^\/api\/(sasapay|mpesa|buni)\/(callback|ipn|confirm|result|timeout|b2c)/i;
root.all("*", (c) => {
  const path = new URL(c.req.url).pathname;
  if (!dbReady && !ALWAYS_ADMIT.test(path)) {
    return c.json(
      { error: "service_starting", message: "Server is starting, please retry shortly.", dbReady: false, dbInitError },
      503,
      { "Retry-After": "3" }
    );
  }
  return index_default.fetch(c.req.raw, ENV, nodeExecutionCtx);
});
var PORT = Number(process.env.PORT || 8080);
serve({ fetch: root.fetch, port: PORT }, (info) => {
  console.log(`Farmsky server running on http://0.0.0.0:${info.port} (binding port first; DB migrating in background)`);
  initializeDatabase(raw, PROJECT_ROOT).then(() => {
    dbReady = true;
    console.log(`PostgreSQL ready: ${DATABASE_URL.replace(/:[^:@/]+@/, ":***@")}`);
  }).catch((err) => {
    dbInitError = err?.message || String(err);
    console.error("Database initialization failed:", dbInitError);
  });
  const sandboxValues = ["sandbox", "development", "dev", "test", "uat"];
  const modeOf = (v) => sandboxValues.includes(String(v || "").trim().toLowerCase()) ? "sandbox" : "production";
  console.log(
    process.env.MPESA_CONSUMER_KEY ? "M-Pesa: LIVE credentials detected (" + modeOf(process.env.MPESA_ENV) + ")" : "M-Pesa: SIMULATION mode (no Daraja credentials set)."
  );
  const sasapayId = process.env.SASAPAY_CLIENT_ID || process.env.SASAPAY_CONSUMER_KEY;
  const sasapaySecret = process.env.SASAPAY_CLIENT_SECRET || process.env.SASAPAY_CONSUMER_SECRET;
  const sasapayMerchant = process.env.SASAPAY_MERCHANT_CODE;
  console.log(
    sasapayId && sasapaySecret && sasapayMerchant ? "SasaPay: LIVE credentials detected (" + modeOf(process.env.SASAPAY_ENV) + ")" : `SasaPay: SIMULATION mode (missing ${[!sasapayId && "CLIENT_ID", !sasapaySecret && "CLIENT_SECRET", !sasapayMerchant && "MERCHANT_CODE"].filter(Boolean).join(", ") || "credentials"}).`
  );
});
