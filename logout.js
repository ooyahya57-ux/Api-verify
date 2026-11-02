import { json } from "../_lib.js";
export default function handler(req, res) {
  res.setHeader("Set-Cookie", "ctx_admin=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  return json(res, 200, { ok: true });
}
