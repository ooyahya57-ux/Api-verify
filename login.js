import crypto from "node:crypto";
import { json, env, createSession, cookieHeader } from "../_lib.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return json(res, 405, { ok: false, msg: "Method not allowed" });
  try {
    const password = String(req.body?.password || "");
    const expected = env("ADMIN_PASSWORD");
    const a = Buffer.from(password);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return json(res, 401, { ok: false, msg: "Wrong password" });
    }
    res.setHeader("Set-Cookie", cookieHeader(createSession()));
    return json(res, 200, { ok: true });
  } catch {
    return json(res, 500, { ok: false, msg: "Server configuration error" });
  }
}
