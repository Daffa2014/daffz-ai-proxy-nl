// DaffzHub Message proxy v8 (Netlify function). Supabase URL and service key live ONLY in
// Netlify environment variables (SUPABASE_URL, SUPABASE_SERVICE_KEY), never in this file or in GitHub.
// Staff badges: OWNER_KEY (one secret) and ADMIN_KEYS (secrets separated by commas) are also Netlify environment variables.
// Rooms: s:<JobId> (server), m:<PlaceId> (map), g (global), p:<id>_<id> (private), c:<secret code> (group)
// Groups: max 5 members, max 3 groups per person. Joining gives a signed token (valid 7 days) that the hub sends with every group request.
const crypto = require("crypto");
const hitsSend = new Map(); // best-effort limits per IP (reset when the function restarts)
const hitsGet = new Map();
const hitsPres = new Map();
const hitsTr = new Map();
const hitsStats = new Map();
const hitsGrp = new Map();
const hitsFb = new Map();
let statsCache = { t: 0, data: null };

// who is this key? Only the server knows the secrets. Wrong or missing key = no badge.
function roleOf(k) {
  if (typeof k !== "string" || k.length < 8 || k.length > 100) return null;
  if (process.env.OWNER_KEY && k === process.env.OWNER_KEY) return "owner";
  const list = String(process.env.ADMIN_KEYS || "").split(",").map((x) => x.trim()).filter((x) => x.length >= 8);
  return list.indexOf(k) >= 0 ? "admin" : null;
}

// group token = <expiry seconds>.<signature>. The secret is derived from the Supabase service key, so no new setting is needed.
function tokenSig(room, uid, exp) {
  return crypto.createHmac("sha256", "dh-group|" + String(process.env.SUPABASE_SERVICE_KEY || "")).update(room + "|" + uid + "|" + exp).digest("hex").slice(0, 32);
}
function makeToken(room, uid) {
  const exp = Math.floor((Date.now() + TOKEN_MS) / 1000);
  return { token: exp + "." + tokenSig(room, uid, exp), exp };
}
function checkToken(room, uid, token) {
  if (typeof token !== "string" || !Number.isInteger(uid) || uid <= 0) return false;
  const m = /^(\d{8,12})\.([0-9a-f]{32})$/.exec(token);
  if (!m) return false;
  const exp = parseInt(m[1], 10);
  if (exp * 1000 < Date.now()) return false;
  const want = Buffer.from(tokenSig(room, uid, exp));
  const got = Buffer.from(m[2]);
  return want.length === got.length && crypto.timingSafeEqual(want, got);
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

const ROOM_RE = /^(g|[smp]:[A-Za-z0-9_\-]{1,70}|c:[A-Za-z0-9]{10,16})$/;
const GROUP_RE = /^c:[A-Za-z0-9]{10,16}$/;
const GROUP_MAX_MEMBERS = 5;
const GROUP_MAX_PER_USER = 3;
const GROUP_ACTIVE_MS = 30 * 86400000; // somebody who did not show up for 30 days frees the place
const TOKEN_MS = 7 * 86400000;

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
  const gurl = base.replace(/\/+$/, "") + "/rest/v1/dh_group_members";
  const furl = base.replace(/\/+$/, "") + "/rest/v1/dh_feedback";

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
      if (GROUP_RE.test(room) && !checkToken(room, uid, b.token)) return send(403, { error: "Not a member of this group" });
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
      const names = Object.keys(b.rooms).slice(0, 8);
      const jobs = [];
      const denied = [];
      const puid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      for (const n of names) {
        const room = b.rooms[n];
        if (!/^[a-z]{1,10}$/.test(n) || typeof room !== "string" || !ROOM_RE.test(room)) return send(400, { error: "Bad room" });
        // group rooms: only people with a valid token can read. The others are skipped (the hub renews its token and tries again).
        if (GROUP_RE.test(room) && !checkToken(room, puid, b.tokens && typeof b.tokens === "object" ? b.tokens[n] : null)) { denied.push(n); continue; }
        const after = b.after && typeof b.after === "object" ? afterOf(b.after[n]) : null;
        jobs.push(readRoom(room, after).then((rows) => [n, rows]));
      }
      const out = {};
      for (const [n, rows] of await Promise.all(jobs)) out[n] = rows;
      return send(200, { rooms: out, denied });
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

    // groups: join (also used to renew the token), leave, member count
    if (b.action === "gjoin" || b.action === "gleave" || b.action === "gmembers") {
      if (count(hitsGrp, ip, 60000) > 20) return send(429, { error: "Too many requests" });
      if (typeof b.room !== "string" || !GROUP_RE.test(b.room)) return send(400, { error: "Bad group code" });
      const uid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      if (!uid) return send(400, { error: "Bad user" });
      const room = b.room;
      const since = new Date(Date.now() - GROUP_ACTIVE_MS).toISOString();
      const activeOf = async (q) => {
        const r = await fetch(gurl + "?select=room,uid&limit=20&last_seen=gte." + encodeURIComponent(since) + "&" + q, { headers: sb });
        if (!r.ok) throw new Error("members");
        return r.json();
      };
      if (b.action === "gleave") {
        if (!checkToken(room, uid, b.token)) return send(403, { error: "Not a member of this group" });
        await fetch(gurl + "?room=eq." + encodeURIComponent(room) + "&uid=eq." + uid, { method: "DELETE", headers: sb });
        return send(200, { ok: true });
      }
      if (b.action === "gmembers") {
        if (!checkToken(room, uid, b.token)) return send(403, { error: "Not a member of this group" });
        const list = await activeOf("room=eq." + encodeURIComponent(room));
        return send(200, { members: list.length, max: GROUP_MAX_MEMBERS });
      }
      // gjoin
      const list = await activeOf("room=eq." + encodeURIComponent(room));
      const isMember = list.some((m) => m.uid === uid);
      if (!isMember) {
        if (list.length >= GROUP_MAX_MEMBERS) return send(409, { error: "This group is full (" + GROUP_MAX_MEMBERS + " members)" });
        const mine = await activeOf("uid=eq." + uid);
        if (mine.length >= GROUP_MAX_PER_USER) return send(409, { error: "You are already in " + GROUP_MAX_PER_USER + " groups" });
      }
      const up = await fetch(gurl + "?on_conflict=room,uid", {
        method: "POST",
        headers: Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" }),
        body: JSON.stringify({ room, uid, last_seen: new Date().toISOString() }),
      });
      if (!up.ok) return send(502, { error: "Could not save" });
      if (Math.random() < 0.02) {
        const old = new Date(Date.now() - 45 * 86400000).toISOString();
        fetch(gurl + "?last_seen=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      const t = makeToken(room, uid);
      return send(200, { token: t.token, exp: t.exp, members: isMember ? list.length : list.length + 1, max: GROUP_MAX_MEMBERS });
    }

    // translate: one short text -> target language (free public translate service, no key needed)
    if (b.action === "translate") {
      if (count(hitsTr, ip, 60000) > 40) return send(429, { error: "Too many requests" });
      const text = clean(b.text, 300);
      const to = typeof b.to === "string" ? b.to : "";
      const LANG_RE = /^[a-zA-Z]{2,3}(-[a-zA-Z]{2,4})?$/;
      if (!text || !LANG_RE.test(to)) return send(400, { error: "Bad text or language" });
      // optional source language: "auto" (or missing) = detect it
      const from = typeof b.from === "string" && LANG_RE.test(b.from) ? b.from : "auto";
      try {
        const r = await fetch("https://translate.googleapis.com/translate_a/single?client=gtx&dt=t&sl=" + encodeURIComponent(from) + "&tl=" + encodeURIComponent(to) + "&q=" + encodeURIComponent(text));
        if (r.ok) {
          const d = await r.json();
          if (Array.isArray(d) && Array.isArray(d[0])) {
            const out = d[0].map((p) => (Array.isArray(p) && typeof p[0] === "string" ? p[0] : "")).join("").slice(0, 600);
            if (out) return send(200, { text: out, src: typeof d[2] === "string" ? d[2] : from === "auto" ? "" : from });
          }
        }
      } catch (e) { /* try the backup below */ }
      try {
        const r2 = await fetch("https://api.mymemory.translated.net/get?q=" + encodeURIComponent(text) + "&langpair=" + encodeURIComponent((from === "auto" ? "Autodetect" : from) + "|" + to));
        if (r2.ok) {
          const d2 = await r2.json();
          const t = d2 && d2.responseData && d2.responseData.translatedText;
          if (typeof t === "string" && t) return send(200, { text: t.slice(0, 600), src: from === "auto" ? "" : from });
        }
      } catch (e) { /* give up */ }
      return send(502, { error: "Translate service unavailable" });
    }

    // feedback: a note from a user to the developer (bug, idea or other). Saved in dh_feedback, read it in the Supabase table editor.
    if (b.action === "feedback") {
      if (count(hitsFb, ip, 600000) > 3) return send(429, { error: "Too many feedback messages. Try again in a few minutes." });
      const kind = b.kind === "bug" || b.kind === "idea" ? b.kind : "other";
      const text = clean(b.text, 600);
      if (text.length < 5) return send(400, { error: "Write a bit more (at least 5 characters)" });
      const row = {
        kind,
        body: text,
        ver: clean(b.ver, 80),
        place: Number.isInteger(b.place) && b.place > 0 ? b.place : null,
        exec: clean(b.exec, 40),
        device: clean(b.device, 20),
        name: clean(b.name, 40) || null,
        uid: Number.isInteger(b.uid) && b.uid > 0 && clean(b.name, 40) ? b.uid : null,
      };
      const r = await fetch(furl, { method: "POST", headers: Object.assign({}, sb, { Prefer: "return=minimal" }), body: JSON.stringify(row) });
      if (!r.ok) return send(502, { error: "Could not save" });
      return send(200, { ok: true });
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
