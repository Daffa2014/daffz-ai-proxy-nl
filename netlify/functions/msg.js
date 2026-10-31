// DaffzHub Message proxy (Netlify function). Supabase URL and service key live ONLY in
// Netlify environment variables (SUPABASE_URL, SUPABASE_SERVICE_KEY), never in this file or in GitHub.
const hitsSend = new Map(); // best-effort limits per IP (reset when the function restarts)
const hitsGet = new Map();

function count(map, ip, windowMs) {
  const now = Date.now();
  const list = (map.get(ip) || []).filter((t) => now - t < windowMs);
  list.push(now);
  map.set(ip, list);
  if (map.size > 5000) map.clear();
  return list.length;
}

function clean(s, max) {
  return String(s == null ? "" : s)
    .replace(/[\u0000-\u001f\u007f<>]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

exports.handler = async (event) => {
  const send = (code, obj) => ({ statusCode: code, headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });
  if (event.httpMethod !== "POST") return send(405, { error: "POST only" });
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!base || !key) return send(500, { error: "Server is not configured" });

  const h = event.headers || {};
  const ip = String(h["x-nf-client-connection-ip"] || h["x-forwarded-for"] || "unknown").split(",")[0].trim();

  let b;
  try { b = JSON.parse(event.body || "{}"); } catch (e) { return send(400, { error: "Bad JSON" }); }
  if (!b || typeof b.room !== "string" || !/^[sgm]:?[A-Za-z0-9_\-]{0,70}$/.test(b.room)) return send(400, { error: "Bad room" });
  const room = b.room;
  const isGlobal = room.charAt(0) === "g";

  const sb = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" };
  const url = base.replace(/\/+$/, "") + "/rest/v1/dh_messages";

  try {
    if (b.action === "send") {
      const gap = isGlobal ? 10000 : 3000;
      const recent = (hitsSend.get(ip) || []).filter((t) => Date.now() - t < gap);
      if (recent.length) return send(429, { error: "Too fast, wait a moment" });
      count(hitsSend, ip, 60000);
      const name = clean(b.name, 30);
      const body = clean(b.body, 200);
      if (!name || !body) return send(400, { error: "Empty message" });
      const r = await fetch(url, { method: "POST", headers: Object.assign({ Prefer: "return=minimal" }, sb), body: JSON.stringify({ room, name, body }) });
      if (!r.ok) return send(502, { error: "Could not save" });
      // now and then delete messages older than 1 day so the table stays small
      if (Math.random() < 0.05) {
        const cutoff = new Date(Date.now() - 86400000).toISOString();
        fetch(url + "?created_at=lt." + encodeURIComponent(cutoff), { method: "DELETE", headers: sb }).catch(() => {});
      }
      return send(200, { ok: true });
    }

    if (b.action === "get") {
      if (count(hitsGet, ip, 60000) > 40) return send(429, { error: "Too many requests" });
      const after = Number.isInteger(b.after) && b.after >= 0 ? b.after : null;
      let q = url + "?select=id,name,body,created_at&room=eq." + encodeURIComponent(room);
      if (after === null) q += "&order=id.desc&limit=30";
      else q += "&id=gt." + after + "&order=id.asc&limit=50";
      const r = await fetch(q, { headers: sb });
      if (!r.ok) return send(502, { error: "Could not read" });
      let rows = await r.json();
      if (after === null) rows = rows.reverse();
      return send(200, { messages: rows });
    }

    return send(400, { error: "Bad action" });
  } catch (e) {
    return send(502, { error: "Upstream error" });
  }
};
