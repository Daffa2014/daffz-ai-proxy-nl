// DaffzHub Message proxy v6 (Netlify function). Supabase URL and service key live ONLY in
// Netlify environment variables (SUPABASE_URL, SUPABASE_SERVICE_KEY), never in this file or in GitHub.
// Staff badges: OWNER_KEY (one secret) and ADMIN_KEYS (secrets separated by commas) are also Netlify environment variables.
// Rooms: s:<JobId> (server), m:<PlaceId> (map), g (global), p:<id>_<id> (private)
const hitsSend = new Map(); // best-effort limits per IP (reset when the function restarts)
const hitsGet = new Map();
const hitsPres = new Map();
const hitsTr = new Map();
const hitsStats = new Map();
let statsCache = { t: 0, data: null };

// who is this key? Only the server knows the secrets. Wrong or missing key = no badge.
function roleOf(k) {
  if (typeof k !== "string" || k.length < 8 || k.length > 100) return null;
  if (process.env.OWNER_KEY && k === process.env.OWNER_KEY) return "owner";
  const list = String(process.env.ADMIN_KEYS || "").split(",").map((x) => x.trim()).filter((x) => x.length >= 8);
  return list.indexOf(k) >= 0 ? "admin" : null;
}

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
  const uurl = base.replace(/\/+$/, "") + "/rest/v1/dh_users";

  // read the newest messages of one room (after = last id the client already has)
  async function readRoom(room, after) {
    let q = url + "?select=id,name,body,uid,role,created_at&room=eq." + encodeURIComponent(room);
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
      const r = await fetch(url, { method: "POST", headers: Object.assign({ Prefer: "return=minimal" }, sb), body: JSON.stringify({ room, name, body, uid, role: roleOf(b.key) }) });
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
        body: JSON.stringify({ room: b.room, uid, name, role: roleOf(b.key), seen_at: new Date().toISOString() }),
      });
      if (!up.ok) return send(502, { error: "Could not save" });
      const since = new Date(Date.now() - 45000).toISOString();
      const r = await fetch(purl + "?select=uid,name,role&limit=100&room=eq." + encodeURIComponent(b.room) + "&seen_at=gte." + encodeURIComponent(since), { headers: sb });
      if (!r.ok) return send(502, { error: "Could not read" });
      if (Math.random() < 0.05) {
        const old = new Date(Date.now() - 600000).toISOString();
        fetch(purl + "?seen_at=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      const users = await r.json();
      // everyone online in DaffzHub (all servers) - only for clients that ask with all:true (they are online and visible too)
      if (b.all === true) {
        const ra = await fetch(purl + "?select=uid,name,role&order=seen_at.desc&limit=80&seen_at=gte." + encodeURIComponent(since), { headers: sb });
        if (ra.ok) {
          const rows = await ra.json();
          const seen = new Set();
          const all = [];
          for (const u of rows) {
            if (u && typeof u.uid === "number" && !seen.has(u.uid)) { seen.add(u.uid); all.push({ uid: u.uid, name: u.name, role: u.role || null }); }
          }
          return send(200, { users, all: all.slice(0, 50), online: all.length });
        }
      }
      return send(200, { users });
    }

    // translate: one short text -> target language (free public translate service, no key needed)
    if (b.action === "translate") {
      if (count(hitsTr, ip, 60000) > 40) return send(429, { error: "Too many requests" });
      const text = clean(b.text, 300);
      const to = typeof b.to === "string" ? b.to : "";
      if (!text || !/^[a-zA-Z]{2,3}(-[a-zA-Z]{2,4})?$/.test(to)) return send(400, { error: "Bad text or language" });
      try {
        const r = await fetch("https://translate.googleapis.com/translate_a/single?client=gtx&dt=t&sl=auto&tl=" + encodeURIComponent(to) + "&q=" + encodeURIComponent(text));
        if (r.ok) {
          const d = await r.json();
          if (Array.isArray(d) && Array.isArray(d[0])) {
            const out = d[0].map((p) => (Array.isArray(p) && typeof p[0] === "string" ? p[0] : "")).join("").slice(0, 600);
            if (out) return send(200, { text: out, src: typeof d[2] === "string" ? d[2] : "" });
          }
        }
      } catch (e) { /* try the backup below */ }
      try {
        const r2 = await fetch("https://api.mymemory.translated.net/get?q=" + encodeURIComponent(text) + "&langpair=" + encodeURIComponent("Autodetect|" + to));
        if (r2.ok) {
          const d2 = await r2.json();
          const t = d2 && d2.responseData && d2.responseData.translatedText;
          if (typeof t === "string" && t) return send(200, { text: t.slice(0, 600), src: "" });
        }
      } catch (e) { /* give up */ }
      return send(502, { error: "Translate service unavailable" });
    }

    // stats: anonymous hub counter. The hub sends a random id (no Roblox id, no name). Returns how many hubs are alive.
    if (b.action === "stats") {
      if (count(hitsStats, ip, 60000) > 6) return send(429, { error: "Too many requests" });
      if (typeof b.id !== "string" || !/^[A-Za-z0-9]{16,40}$/.test(b.id)) return send(400, { error: "Bad id" });
      const now = Date.now();
      const up = await fetch(uurl + "?on_conflict=id", {
        method: "POST",
        headers: Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" }),
        body: JSON.stringify({ id: b.id, last_seen: new Date(now).toISOString() }),
      });
      if (!up.ok) return send(502, { error: "Could not save" });
      if (statsCache.data && now - statsCache.t < 20000) return send(200, statsCache.data);
      const countSince = async (ms) => {
        const q = ms > 0 ? "&last_seen=gte." + encodeURIComponent(new Date(now - ms).toISOString()) : "";
        const r = await fetch(uurl + "?select=id" + q, { method: "HEAD", headers: Object.assign({}, sb, { Prefer: "count=exact" }) });
        const n = parseInt(String(r.headers.get("content-range") || "").split("/")[1], 10);
        return Number.isFinite(n) ? n : 0;
      };
      const [online, day, week, month, total] = await Promise.all([countSince(120000), countSince(86400000), countSince(7 * 86400000), countSince(30 * 86400000), countSince(0)]);
      statsCache = { t: now, data: { online, day, week, month, total } };
      if (Math.random() < 0.02) {
        const old = new Date(now - 90 * 86400000).toISOString();
        fetch(uurl + "?last_seen=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      return send(200, statsCache.data);
    }

    return send(400, { error: "Bad action" });
  } catch (e) {
    return send(502, { error: "Upstream error" });
  }
};
