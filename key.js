import { json, supabase, requireAdmin } from "./_lib.js";

export default async function handler(req, res) {
  if (!requireAdmin(req, res)) return;
  const key = String(req.query?.key || "");
  if (!key) return json(res, 400, { ok: false, msg: "Missing key" });
  try {
    if (req.method === "PATCH") {
      const active = req.body?.is_active;
      if (typeof active !== "boolean") return json(res, 400, { ok: false, msg: "is_active must be boolean" });
      await supabase(`license_keys?license_key=eq.${encodeURIComponent(key)}`, {
        method: "PATCH", headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ is_active: active })
      });
      return json(res, 200, { ok: true });
    }
    if (req.method === "DELETE") {
      await supabase(`license_keys?license_key=eq.${encodeURIComponent(key)}`, {
        method: "DELETE", headers: { Prefer: "return=minimal" }
      });
      return json(res, 200, { ok: true });
    }
    return json(res, 405, { ok: false, msg: "Method not allowed" });
  } catch {
    return json(res, 500, { ok: false, msg: "Key operation failed" });
  }
}
