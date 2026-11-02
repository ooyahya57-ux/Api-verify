import crypto from "node:crypto";

export function json(res, status, data) {
  res.status(status).setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}

export function env(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

export async function supabase(path, options = {}) {
  const base = env("SUPABASE_URL").replace(/\/$/, "");
  const secret = env("SUPABASE_SERVICE_ROLE_KEY");
  const response = await fetch(`${base}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: secret,
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!response.ok) throw new Error("Database request failed");
  return data;
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}
function sign(value) {
  return crypto.createHmac("sha256", env("SESSION_SECRET")).update(value).digest("base64url");
}
export function createSession() {
  const payload = b64url(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 }));
  return `${payload}.${sign(payload)}`;
}
export function validSession(req) {
  const cookies = Object.fromEntries((req.headers.cookie || "").split(";").map(x => {
    const i = x.indexOf("=");
    return i < 0 ? ["", ""] : [x.slice(0, i).trim(), x.slice(i + 1).trim()];
  }));
  const token = cookies.ctx_admin || "";
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return Number(data.exp) > Date.now();
  } catch { return false; }
}
export function requireAdmin(req, res) {
  if (!validSession(req)) {
    json(res, 401, { ok: false, msg: "Please sign in" });
    return false;
  }
  return true;
}
export function cookieHeader(value, maxAge = 28800) {
  return `ctx_admin=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
