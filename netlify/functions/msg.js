// DaffzHub Message proxy v3 (Netlify function). Supabase URL and service key live ONLY in
// Netlify environment variables (SUPABASE_URL, SUPABASE_SERVICE_KEY), never in this file or in GitHub.
// Rooms: s:<JobId> (server), m:<PlaceId> (map), g (global), p:<id>_<id> (private)
const hitsSend = new Map(); // best-effort limits per IP (reset when the function restarts)
const hitsGet = new Map();
const hitsPres = new Map();

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

const ROOM_RE = /^(g|[smp]:[A-Za-z0-9_\-]{1,70})$/;

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
  if (!b || typeof b !== "object") return send(400, { error: "Bad request" });

  const sb = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" };
  const url = base.replace(/\/+$/, "") + "/rest/v1/dh_messages";
  const purl = base.replace(/\/+$/, "") + "/rest/v1/dh_presence";

  // read the newest messages of one room (after = last id the client already has)
  async function readRoom(room, after) {
    let q = url + "?select=id,name,body,uid,created_at&room=eq." + encodeURIComponent(room);
    if (after === null) q += "&order=id.desc&limit=30";
    else q += "&id=gt." + after + "&order=id.asc&limit=50";
    const r = await fetch(q, { headers: sb });
    if (!r.ok) throw new Error("read");
    let rows = await r.json();
    if (after === null) rows = rows.reverse();
    return rows;
  }
  const afterOf = (v) => (Number.isInteger(v) && v >= 0 ? v : null);

  try {
    if (b.action === "send") {
      if (typeof b.room !== "string" || !ROOM_RE.test(b.room)) return send(400, { error: "Bad room" });
      const room = b.room;
      const gap = room === "g" ? 10000 : 3000;
      const recent = (hitsSend.get(ip) || []).filter((t) => Date.now() - t < gap);
      if (recent.length) return send(429, { error: "Too fast, wait a moment" });
      count(hitsSend, ip, 60000);
      const name = clean(b.name, 30);
      const body = clean(b.body, 200);
      if (!name || !body) return send(400, { error: "Empty message" });
      const uid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      const r = await fetch(url, { method: "POST", headers: Object.assign({ Prefer: "return=minimal" }, sb), body: JSON.stringify({ room, name, body, uid }) });
      if (!r.ok) return send(502, { error: "Could not save" });
      // now and then delete messages older than 1 day so the table stays small
      if (Math.random() < 0.05) {
        const cutoff = new Date(Date.now() - 86400000).toISOString();
        fetch(url + "?created_at=lt." + encodeURIComponent(cutoff), { method: "DELETE", headers: sb }).catch(() => {});
      }
      return send(200, { ok: true });
    }

    // pull: several rooms in ONE request  { rooms: {server:"s:..", map:"m:..."}, after: {server: 12} }
    if (b.action === "pull") {
      if (count(hitsGet, ip, 60000) > 40) return send(429, { error: "Too many requests" });
      if (!b.rooms || typeof b.rooms !== "object") return send(400, { error: "Bad rooms" });
      const names = Object.keys(b.rooms).slice(0, 4);
      const jobs = [];
      for (const n of names) {
        const room = b.rooms[n];
        if (!/^[a-z]{1,10}$/.test(n) || typeof room !== "string" || !ROOM_RE.test(room)) return send(400, { error: "Bad room" });
        const after = b.after && typeof b.after === "object" ? afterOf(b.after[n]) : null;
        jobs.push(readRoom(room, after).then((rows) => [n, rows]));
      }
      const out = {};
      for (const [n, rows] of await Promise.all(jobs)) out[n] = rows;
      return send(200, { rooms: out });
    }

    // presence: "I am here" + who else is here (only DaffzHub users that also ask are told)
    if (b.action === "presence") {
      if (count(hitsPres, ip, 60000) > 8) return send(429, { error: "Too many requests" });
      if (typeof b.room !== "string" || !/^s:[A-Za-z0-9_\-]{1,70}$/.test(b.room)) return send(400, { error: "Bad room" });
      const uid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      const name = clean(b.name, 30);
      if (!uid || !name) return send(400, { error: "Bad user" });
      const up = await fetch(purl + "?on_conflict=room,uid", {
        method: "POST",
        headers: Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" }),
        body: JSON.stringify({ room: b.room, uid, name, seen_at: new Date().toISOString() }),
      });
      if (!up.ok) return send(502, { error: "Could not save" });
      const since = new Date(Date.now() - 45000).toISOString();
      const r = await fetch(purl + "?select=uid,name&limit=100&room=eq." + encodeURIComponent(b.room) + "&seen_at=gte." + encodeURIComponent(since), { headers: sb });
      if (!r.ok) return send(502, { error: "Could not read" });
      if (Math.random() < 0.05) {
        const old = new Date(Date.now() - 600000).toISOString();
        fetch(purl + "?seen_at=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      return send(200, { users: await r.json() });
    }

    return send(400, { error: "Bad action" });
  } catch (e) {
    return send(502, { error: "Upstream error" });
  }
};
