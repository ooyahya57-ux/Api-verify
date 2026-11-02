import crypto from "node:crypto";
import { json, supabase, requireAdmin } from "../_lib.js";

export default async function handler(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    if (req.method === "GET") {
      const rows = await supabase("license_keys?select=license_key,is_active,max_devices,expires_at,created_at,license_devices(device_id,created_at)&order=created_at.desc");
      return json(res, 200, { ok: true, keys: rows || [] });
    }
    if (req.method === "POST") {
      const count = Math.max(1, Math.min(100, Number(req.body?.count || 1)));
      const maxDevices = Math.max(1, Math.min(20, Number(req.body?.max_devices || 1)));
      const days = Math.max(0, Math.min(3650, Number(req.body?.days || 0)));
      const expires = days ? new Date(Date.now() + days * 86400000).toISOString() : null;
      const keys = Array.from({ length: count }, () =>
        "CTX-" + crypto.randomBytes(9).toString("hex").toUpperCase()
      );
      const rows = keys.map(license_key => ({
        license_key, max_devices: maxDevices, expires_at: expires, is_active: true
      }));
      await supabase("license_keys", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(rows)
      });
      return json(res, 201, { ok: true, keys });
    }
    return json(res, 405, { ok: false, msg: "Method not allowed" });
  } catch {
    return json(res, 500, { ok: false, msg: "Could not process keys" });
  }
}
