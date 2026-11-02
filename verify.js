import { json, supabase } from "./_lib.js";

export default async function handler(req, res) {
  if (req.method === "GET") {
    return json(res, 200, {
      service: "CTX Key Verification API",
      status: "online",
      endpoint: "POST /api/verify"
    });
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return json(res, 405, { ok: false, msg: "Method not allowed" });
  }
  try {
    const { key, device } = req.body || {};
    if (typeof key !== "string" || typeof device !== "string" ||
        !key.trim() || !device.trim() || key.length > 128 || device.length > 256) {
      return json(res, 400, { ok: false, msg: "key and device are required" });
    }
    const result = await supabase("rpc/verify_license", {
      method: "POST",
      body: JSON.stringify({ p_key: key.trim(), p_device: device.trim() })
    });
    return json(res, 200, result || { ok: false, msg: "Verification failed" });
  } catch {
    return json(res, 500, { ok: false, msg: "Verification service error" });
  }
}
