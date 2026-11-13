// DaffzHub Message proxy v11 (Netlify function). v11 adds the Staff Panel (admins, kick, block, warn, announcements, appeals, switches, log). v10 adds apush / apull (avatars shared between DaffzHub users of the same server). Supabase URL and service key live ONLY in
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
const hitsAvPush = new Map();
const hitsAvPull = new Map();
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
const AV_MAX_JSON = 20000;      // biggest avatar look (as text); the table also checks this
const AV_ACTIVE_MS = 6 * 3600000; // a shared look older than this is ignored
const SERVER_RE = /^s:[A-Za-z0-9_\-]{1,70}$/;

// the look is plain data (numbers, short words, lists). Anything else is thrown away so nothing odd is stored.
function cleanLook(v, depth) {
  depth = depth || 0;
  if (depth > 5) return undefined;
  if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
  if (typeof v === "boolean") return v;
  if (typeof v === "string") return /^[A-Za-z0-9_ .\-]{0,40}$/.test(v) ? v : undefined;
  if (Array.isArray(v)) {
    const out = [];
    for (const x of v.slice(0, 80)) { const c = cleanLook(x, depth + 1); if (c !== undefined) out.push(c); }
    return out;
  }
  if (v && typeof v === "object") {
    const out = {};
    let n = 0;
    for (const k of Object.keys(v)) {
      if (n++ >= 80) break;
      if (!/^[A-Za-z0-9_]{1,30}$/.test(k)) continue;
      const c = cleanLook(v[k], depth + 1);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
}

// ---- v11 staff panel helpers (outside the handler) ----
const hitsStaff = new Map();
const STAFF_FLAGS = ["msg_server", "msg_map", "msg_global", "msg_private", "msg_group", "online", "control"];
const KICK_LIMIT = 3;              // admin: kicks per 24 hours
const WARN_LIMIT = 3;              // warnings that trigger an automatic 1 day block
const INVITE_MS = 10 * 60000;
const ANNOUNCE_ADMIN_GAP = 60000;  // admin: one announcement per minute
const cacheFlags = { t: 0, data: {} };
const cacheBan = new Map();
const cacheStaff = new Map();
const ownerSeen = new Set();
const sha256 = (s) => crypto.createHash("sha256").update("dh-staff|" + String(s)).digest("hex");
const newKey = () => crypto.randomBytes(24).toString("base64url");
const isUid = (v) => Number.isInteger(v) && v > 0;

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
  const aurl = base.replace(/\/+$/, "") + "/rest/v1/dh_avatars";

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
    // ================= v11: staff panel =================
    const turl = (t) => base.replace(/\/+$/, "") + "/rest/v1/" + t;
    const enc = encodeURIComponent;
    const iso = (ms) => new Date(ms).toISOString();
    const sbm = Object.assign({}, sb, { Prefer: "return=minimal" });
    const sbr = Object.assign({}, sb, { Prefer: "return=representation" });
    const sbu = Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" });
    const getRows = async (path) => {
      const r = await fetch(turl(path), { headers: sb });
      if (!r.ok) throw new Error("read " + path);
      return r.json();
    };

    // owner key or a legacy admin key (env) first, then an admin made in the panel (key is stored only as a hash, bound to the user id)
    async function roleOfReq(r) {
      const k = r && r.key;
      if (typeof k !== "string" || k.length < 8 || k.length > 100) return null;
      const r0 = roleOf(k);
      if (r0) return r0;
      const uid = isUid(r.uid) ? r.uid : null;
      if (!uid) return null;
      const want = sha256(k);
      const c = cacheStaff.get(uid);
      let hash;
      if (c && Date.now() - c.t < 30000) hash = c.hash;
      else {
        const rows = await getRows("dh_staff?select=key_hash&status=eq.active&uid=eq." + uid + "&limit=1");
        hash = rows[0] && rows[0].key_hash ? rows[0].key_hash : null;
        cacheStaff.set(uid, { t: Date.now(), hash });
        if (cacheStaff.size > 2000) cacheStaff.clear();
      }
      if (!hash || hash.length !== want.length) return null;
      return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(want)) ? "admin" : null;
    }
    async function flagsOff() {
      if (Date.now() - cacheFlags.t < 10000) return cacheFlags.data;
      const rows = await getRows("dh_flags?select=key&off=eq.true");
      const set = {};
      for (const x of rows) set[x.key] = true;
      cacheFlags.t = Date.now();
      cacheFlags.data = set;
      return set;
    }
    async function activeBan(uid) {
      if (!isUid(uid)) return null;
      const c = cacheBan.get(uid);
      if (c && Date.now() - c.t < 20000) return c.ban;
      const rows = await getRows("dh_bans?select=id,reason,until,appeal_status,appeal_reply,created_at&uid=eq." + uid + "&active=eq.true&or=(until.is.null,until.gt." + enc(iso(Date.now())) + ")&order=id.desc&limit=1");
      const ban = rows[0] || null;
      cacheBan.set(uid, { t: Date.now(), ban });
      if (cacheBan.size > 3000) cacheBan.clear();
      return ban;
    }
    async function slog(role, uid, name, action, tuid, tname, detail) {
      await fetch(turl("dh_stafflog"), { method: "POST", headers: sbm, body: JSON.stringify({
        actor_uid: isUid(uid) ? uid : null, actor_name: clean(name, 40) || null, actor_role: role, action,
        target_uid: isUid(tuid) ? tuid : null, target_name: clean(tname, 40) || null, detail: clean(detail, 300) || null }) }).catch(() => {});
    }
    async function targetStatus(tuid) {
      const rows = await getRows("dh_staff?select=status&status=in.(owner,active)&uid=eq." + tuid + "&limit=1");
      return rows[0] ? rows[0].status : null;
    }
    async function robloxFind(q) {
      q = clean(q, 40).replace(/^@/, "");
      if (!q) return null;
      try {
        if (/^\d{1,12}$/.test(q)) {
          const r = await fetch("https://users.roblox.com/v1/users/" + q);
          if (!r.ok) return null;
          const d = await r.json();
          return d && isUid(d.id) ? { uid: d.id, name: clean(d.displayName || d.name, 40), user: clean(d.name, 40) } : null;
        }
        const r = await fetch("https://users.roblox.com/v1/usernames/users", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ usernames: [q], excludeBannedUsers: false }) });
        if (!r.ok) return null;
        const d = await r.json();
        const u = d && Array.isArray(d.data) ? d.data[0] : null;
        return u && isUid(u.id) ? { uid: u.id, name: clean(u.displayName || u.name, 40), user: clean(u.name, 40) } : null;
      } catch (e) { return null; }
    }
    // how many kicks has this admin used in the last 24 hours (and when does the oldest one free up)
    async function kickQuota(uid) {
      const rows = await getRows("dh_stafflog?select=at&action=eq.kick&actor_uid=eq." + uid + "&at=gte." + enc(iso(Date.now() - 86400000)) + "&order=at.asc&limit=20");
      const left = Math.max(0, KICK_LIMIT - rows.length);
      return { left, next: left === 0 && rows[0] ? Date.parse(rows[0].at) + 86400000 : null };
    }
    const roomKey = (room) => {
      if (typeof room !== "string") return null;
      if (room === "g") return "msg_global";
      const p = room.slice(0, 2);
      return p === "s:" ? "msg_server" : p === "m:" ? "msg_map" : p === "p:" ? "msg_private" : p === "c:" ? "msg_group" : null;
    };

    // every request passes here: blocked people and switched-off features are turned away before anything else happens
    const gateAct = b.action;
    if (gateAct !== "staff" && gateAct !== "stats" && gateAct !== "translate" && gateAct !== "feedback") {
      const grole = typeof b.key === "string" ? await roleOfReq(b) : null;
      if (grole !== "owner") {
        if (isUid(b.uid) && (await activeBan(b.uid))) return send(403, { error: "You are blocked from DaffzHub", banned: true });
        const off = await flagsOff();
        if (gateAct === "send" && off[roomKey(b.room)]) return send(503, { error: "This chat mode is turned off by staff", off: roomKey(b.room) });
        if (gateAct === "pull" && b.rooms && typeof b.rooms === "object") {
          const gone = [];
          for (const n of Object.keys(b.rooms)) {
            if (off[roomKey(b.rooms[n])]) { gone.push(n); delete b.rooms[n]; }
          }
          if (gone.length && !Object.keys(b.rooms).length) return send(200, { rooms: {}, denied: [], off: gone });
        }
        if ((gateAct === "apush" || gateAct === "apull") && off.online) return send(503, { error: "Online is turned off by staff", off: "online" });
        if ((gateAct === "gjoin" || gateAct === "gmembers" || gateAct === "gleave") && off.msg_group) return send(503, { error: "Groups are turned off by staff", off: "msg_group" });
      }
    }
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
      const r = await fetch(url, { method: "POST", headers: Object.assign({ Prefer: "return=minimal" }, sb), body: JSON.stringify({ room, name, body, uid, role: await roleOfReq(b) }) });
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
        body: JSON.stringify({ room: b.room, uid, name, role: await roleOfReq(b), seen_at: new Date().toISOString() }),
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
        const qs = gurl + "?limit=20&last_seen=gte." + encodeURIComponent(since) + "&" + q;
        let r = await fetch(qs + "&select=room,uid,gname", { headers: sb });
        if (!r.ok) r = await fetch(qs + "&select=room,uid", { headers: sb }); // the gname column may not exist yet
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
      // the group name: the first person who gives one sets it for everybody, and nobody can change it later
      const known = (list.find((m) => typeof m.gname === "string" && m.gname) || {}).gname || null;
      const typed = clean(b.name, 20) || null;
      const gname = known || typed;
      const row = { room, uid, last_seen: new Date().toISOString() };
      if (!known && typed) row.gname = typed;
      const save = (r) => fetch(gurl + "?on_conflict=room,uid", {
        method: "POST",
        headers: Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" }),
        body: JSON.stringify(r),
      });
      let up = await save(row);
      if (!up.ok && row.gname) { delete row.gname; up = await save(row); } // no gname column yet: still let the person in
      if (!up.ok) return send(502, { error: "Could not save" });
      if (Math.random() < 0.02) {
        const old = new Date(Date.now() - 45 * 86400000).toISOString();
        fetch(gurl + "?last_seen=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      const t = makeToken(room, uid);
      return send(200, { token: t.token, exp: t.exp, members: isMember ? list.length : list.length + 1, max: GROUP_MAX_MEMBERS, gname: gname || null });
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

    // apush: share MY look with the other DaffzHub users of this server ({look: null} = stop sharing / back to normal)
    if (b.action === "apush") {
      if (count(hitsAvPush, ip, 60000) > 12) return send(429, { error: "Too many requests" });
      if (typeof b.room !== "string" || !SERVER_RE.test(b.room)) return send(400, { error: "Bad room" });
      const uid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      const name = clean(b.name, 30);
      if (!uid || !name) return send(400, { error: "Bad user" });
      if (b.look === null) {
        const d = await fetch(aurl + "?room=eq." + encodeURIComponent(b.room) + "&uid=eq." + uid, { method: "DELETE", headers: sb });
        if (!d.ok) return send(502, { error: "Could not save" });
        return send(200, { ok: true, cleared: true });
      }
      if (!b.look || typeof b.look !== "object" || Array.isArray(b.look)) return send(400, { error: "Bad look" });
      const look = cleanLook(b.look);
      const text = JSON.stringify(look);
      if (!look || text.length < 2 || text.length > AV_MAX_JSON) return send(400, { error: "Look too big" });
      const up = await fetch(aurl + "?on_conflict=room,uid", {
        method: "POST",
        headers: Object.assign({}, sb, { Prefer: "resolution=merge-duplicates,return=minimal" }),
        body: JSON.stringify({ room: b.room, uid, name, look, updated_at: new Date().toISOString() }),
      });
      if (!up.ok) return send(502, { error: "Could not save" });
      if (Math.random() < 0.05) {
        const old = new Date(Date.now() - 86400000).toISOString();
        fetch(aurl + "?updated_at=lt." + encodeURIComponent(old), { method: "DELETE", headers: sb }).catch(() => {});
      }
      return send(200, { ok: true });
    }

    // apull: the shared looks of the DaffzHub users who are in this server right now.
    // Only somebody who is online in this server himself gets the list (same two-way rule as the user list).
    // have = {"<uid>": "<updated_at>"} of what the hub already has, so unchanged looks are not sent again.
    if (b.action === "apull") {
      if (count(hitsAvPull, ip, 60000) > 30) return send(429, { error: "Too many requests" });
      if (typeof b.room !== "string" || !SERVER_RE.test(b.room)) return send(400, { error: "Bad room" });
      const uid = Number.isInteger(b.uid) && b.uid > 0 ? b.uid : null;
      if (!uid) return send(400, { error: "Bad user" });
      const since = new Date(Date.now() - 45000).toISOString();
      const rp = await fetch(purl + "?select=uid,name,role&limit=100&room=eq." + encodeURIComponent(b.room) + "&seen_at=gte." + encodeURIComponent(since), { headers: sb });
      if (!rp.ok) return send(502, { error: "Could not read" });
      const here = await rp.json();
      if (!here.some((u) => u && u.uid === uid)) return send(200, { list: [], uids: [], here: false });
      const fresh = new Date(Date.now() - AV_ACTIVE_MS).toISOString();
      const ra = await fetch(aurl + "?select=uid,name,look,updated_at&limit=60&order=updated_at.desc&room=eq." + encodeURIComponent(b.room) + "&updated_at=gte." + encodeURIComponent(fresh), { headers: sb });
      if (!ra.ok) return send(502, { error: "Could not read" });
      const rows = await ra.json();
      const online = new Map();
      for (const u of here) if (u && typeof u.uid === "number") online.set(u.uid, u);
      const have = b.have && typeof b.have === "object" ? b.have : {};
      const list = [];
      const uids = [];
      for (const r of rows) {
        if (!r || typeof r.uid !== "number" || r.uid === uid || !online.has(r.uid)) continue;
        uids.push(r.uid);
        const u = online.get(r.uid);
        const row = { uid: r.uid, name: r.name, role: u.role || null, t: r.updated_at };
        if (have[String(r.uid)] !== r.updated_at) row.look = r.look;
        list.push(row);
      }
      // people who are here (DaffzHub users) but share nothing are listed too, for the participants list
      const people = [];
      for (const u of here) if (u && typeof u.uid === "number" && u.uid !== uid) people.push({ uid: u.uid, name: u.name, role: u.role || null });
      return send(200, { list, uids, people, here: true });
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


    // staff: one action with an "op". Open to everybody: poll, accept, decline, appeal. The rest needs a staff key.
    if (b.action === "staff") {
      if (count(hitsStaff, ip, 60000) > 60) return send(429, { error: "Too many requests" });
      const op = typeof b.op === "string" ? b.op : "";
      const uid = isUid(b.uid) ? b.uid : null;
      const myName = clean(b.name, 30);
      const role = await roleOfReq(b);
      const isOwner = role === "owner";
      const target = isUid(b.target) ? b.target : null;
      const tname = clean(b.tname, 40);
      const futureOk = (v) => { const t = Date.parse(v); return Number.isFinite(t) && t > Date.now() + 30000 && t < Date.now() + 3650 * 86400000 ? t : null; };

      if (op === "poll") {
        if (!uid) return send(400, { error: "Bad user" });
        if (isOwner && !ownerSeen.has(uid)) {
          ownerSeen.add(uid);
          await fetch(turl("dh_staff") + "?on_conflict=uid", { method: "POST", headers: sbu, body: JSON.stringify({ uid, name: myName || null, status: "owner", key_hash: null, expires_at: null }) }).catch(() => {});
        }
        const out = { role, flags: await flagsOff(), ban: isOwner ? null : await activeBan(uid), cmds: [], last: null };
        const room = typeof b.room === "string" && SERVER_RE.test(b.room) ? b.room : null;
        const map = typeof b.map === "string" && /^m:[A-Za-z0-9_\-]{1,70}$/.test(b.map) ? b.map : null;
        const after = Number.isInteger(b.after) && b.after >= 0 ? b.after : null;
        const parts = ["uid.eq." + uid, "scope.eq.all"];
        if (room) parts.push("and(scope.eq.room,room.eq." + room + ")");
        if (map) parts.push("and(scope.eq.room,room.eq." + map + ")");
        let q = "dh_cmds?select=id,kind,payload,by_name&expires_at=gt." + enc(iso(Date.now())) + "&order=id.asc&limit=20&or=(" + parts.join(",") + ")";
        q += after !== null ? "&id=gt." + after : "&created_at=gt." + enc(iso(Date.now() - 90000));
        const cmds = await getRows(q);
        out.cmds = cmds.map((c) => ({ id: c.id, kind: c.kind, payload: c.payload, by: c.by_name }));
        if (cmds.length) out.last = cmds[cmds.length - 1].id;
        const inv = await getRows("dh_staff?select=invited_by,expires_at&status=eq.invited&uid=eq." + uid + "&expires_at=gt." + enc(iso(Date.now())) + "&limit=1");
        if (inv[0]) out.invite = { from: inv[0].invited_by, exp: inv[0].expires_at };
        if (role === "admin") { const kq = await kickQuota(uid); out.kickLeft = kq.left; out.kickNext = kq.next; }
        return send(200, out);
      }

      if (op === "accept" || op === "decline") {
        if (!uid) return send(400, { error: "Bad user" });
        const inv = await getRows("dh_staff?select=uid&status=eq.invited&uid=eq." + uid + "&expires_at=gt." + enc(iso(Date.now())) + "&limit=1");
        if (!inv[0]) return send(410, { error: "The invitation is gone or expired" });
        if (op === "decline") {
          await fetch(turl("dh_staff") + "?status=eq.invited&uid=eq." + uid, { method: "DELETE", headers: sb });
          return send(200, { ok: true });
        }
        const key = newKey();
        const up = await fetch(turl("dh_staff") + "?status=eq.invited&uid=eq." + uid, { method: "PATCH", headers: sbm,
          body: JSON.stringify({ status: "active", key_hash: sha256(key), accepted_at: iso(Date.now()), expires_at: null, name: myName || null }) });
        if (!up.ok) return send(502, { error: "Could not save" });
        cacheStaff.delete(uid);
        await slog("admin", uid, myName, "accept", uid, myName, "accepted the admin invitation");
        return send(200, { key });
      }

      if (op === "appeal") {
        if (!uid) return send(400, { error: "Bad user" });
        const text = clean(b.text, 300);
        if (text.length < 5) return send(400, { error: "Write a bit more (at least 5 characters)" });
        const rows = await getRows("dh_bans?select=id,appeal_status&uid=eq." + uid + "&active=eq.true&or=(until.is.null,until.gt." + enc(iso(Date.now())) + ")&order=id.desc&limit=1");
        if (!rows[0]) return send(404, { error: "You are not blocked" });
        if (rows[0].appeal_status !== "none") return send(409, { error: "You already sent an appeal for this block" });
        const up = await fetch(turl("dh_bans") + "?id=eq." + rows[0].id, { method: "PATCH", headers: sbm, body: JSON.stringify({ appeal: text, appeal_at: iso(Date.now()), appeal_status: "pending" }) });
        if (!up.ok) return send(502, { error: "Could not save" });
        cacheBan.delete(uid);
        await slog("user", uid, myName, "appeal", uid, myName, text);
        return send(200, { ok: true });
      }

      // ---- everything below needs owner or admin ----
      if (!role) return send(403, { error: "Not allowed" });
      if (!uid) return send(400, { error: "Bad user" });
      const actor = { role, uid, name: myName || "staff" };
      const deny = (msg) => send(403, { error: msg });
      // who may be touched: nobody touches the owner or himself; an admin cannot touch another admin
      async function touchable(tuid) {
        if (tuid === uid) return "You cannot do this to yourself";
        const st = await targetStatus(tuid);
        if (st === "owner") return "The owner cannot be touched";
        if (st === "active" && !isOwner) return "Admins cannot do this to another admin";
        return null;
      }

      if (op === "lookup") {
        let f = target ? { uid: target, name: tname || String(target), user: "" } : await robloxFind(b.q);
        if (!f) return send(404, { error: "User not found" });
        const [ban, warns, st] = await Promise.all([
          activeBan(f.uid),
          getRows("dh_warns?select=id&cleared=eq.false&uid=eq." + f.uid),
          targetStatus(f.uid),
        ]);
        return send(200, { uid: f.uid, name: f.name, user: f.user, ban, warns: warns.length, staff: st });
      }

      if (op === "ban") {
        if (!target) return send(400, { error: "Bad target" });
        const why = await touchable(target);
        if (why) return deny(why);
        let until = null;
        if (b.until) { until = futureOk(b.until); if (!until) return send(400, { error: "The end time must be in the future" }); }
        const reason = clean(b.reason, 120) || "No reason given";
        await fetch(turl("dh_bans") + "?uid=eq." + target + "&active=eq.true", { method: "PATCH", headers: sbm, body: JSON.stringify({ active: false, ended_at: iso(Date.now()), ended_by: actor.name }) });
        const ins = await fetch(turl("dh_bans"), { method: "POST", headers: sbm, body: JSON.stringify({ uid: target, name: tname || null, reason, by_uid: uid, by_name: actor.name, by_role: role, until: until ? iso(until) : null }) });
        if (!ins.ok) return send(502, { error: "Could not save" });
        cacheBan.delete(target);
        await slog(role, uid, actor.name, "ban", target, tname, (until ? "until " + iso(until) : "permanent") + " | " + reason);
        return send(200, { ok: true });
      }
      if (op === "unban") {
        if (!target) return send(400, { error: "Bad target" });
        await fetch(turl("dh_bans") + "?uid=eq." + target + "&active=eq.true", { method: "PATCH", headers: sbm, body: JSON.stringify({ active: false, ended_at: iso(Date.now()), ended_by: actor.name }) });
        cacheBan.delete(target);
        await slog(role, uid, actor.name, "unban", target, tname, "");
        return send(200, { ok: true });
      }
      if (op === "bans") {
        const rows = await getRows("dh_bans?select=id,uid,name,reason,until,by_name,by_role,created_at,appeal_status&active=eq.true&or=(until.is.null,until.gt." + enc(iso(Date.now())) + ")&order=id.desc&limit=50");
        return send(200, { bans: rows });
      }

      if (op === "warn") {
        if (!target) return send(400, { error: "Bad target" });
        const why = await touchable(target);
        if (why) return deny(why);
        const reason = clean(b.reason, 120) || "No reason given";
        const ins = await fetch(turl("dh_warns"), { method: "POST", headers: sbm, body: JSON.stringify({ uid: target, name: tname || null, reason, by_uid: uid, by_name: actor.name, by_role: role }) });
        if (!ins.ok) return send(502, { error: "Could not save" });
        const open = await getRows("dh_warns?select=id&cleared=eq.false&uid=eq." + target);
        await fetch(turl("dh_cmds"), { method: "POST", headers: sbm, body: JSON.stringify({ kind: "warn", uid: target, scope: "user", payload: { reason, count: open.length, limit: WARN_LIMIT }, by_name: actor.name, expires_at: iso(Date.now() + 120000) }) });
        await slog(role, uid, actor.name, "warn", target, tname, reason + " (" + open.length + "/" + WARN_LIMIT + ")");
        let auto = false;
        if (open.length >= WARN_LIMIT) {
          auto = true;
          await fetch(turl("dh_warns") + "?cleared=eq.false&uid=eq." + target, { method: "PATCH", headers: sbm, body: JSON.stringify({ cleared: true }) });
          await fetch(turl("dh_bans") + "?uid=eq." + target + "&active=eq.true", { method: "PATCH", headers: sbm, body: JSON.stringify({ active: false, ended_at: iso(Date.now()), ended_by: "auto" }) });
          await fetch(turl("dh_bans"), { method: "POST", headers: sbm, body: JSON.stringify({ uid: target, name: tname || null, reason: WARN_LIMIT + " warnings", by_name: "auto", by_role: "auto", until: iso(Date.now() + 86400000) }) });
          cacheBan.delete(target);
          await slog("auto", null, "auto", "ban", target, tname, "1 day, " + WARN_LIMIT + " warnings");
        }
        return send(200, { ok: true, count: auto ? WARN_LIMIT : open.length, limit: WARN_LIMIT, auto });
      }
      if (op === "warns") {
        if (!target) return send(400, { error: "Bad target" });
        const rows = await getRows("dh_warns?select=id,reason,by_name,created_at&cleared=eq.false&uid=eq." + target + "&order=id.desc&limit=20");
        return send(200, { warns: rows });
      }
      if (op === "clearwarns") {
        if (!isOwner) return deny("Only the owner can clear warnings");
        if (!target) return send(400, { error: "Bad target" });
        await fetch(turl("dh_warns") + "?cleared=eq.false&uid=eq." + target, { method: "PATCH", headers: sbm, body: JSON.stringify({ cleared: true }) });
        await slog(role, uid, actor.name, "clearwarns", target, tname, "");
        return send(200, { ok: true });
      }

      if (op === "kick") {
        if (!target) return send(400, { error: "Bad target" });
        const why = await touchable(target);
        if (why) return deny(why);
        let left = null;
        if (!isOwner) {
          const kq = await kickQuota(uid);
          if (kq.left <= 0) return send(429, { error: "No kicks left", kickLeft: 0, kickNext: kq.next });
          left = kq.left - 1;
        }
        const msg = clean(b.msg, 150);
        const ins = await fetch(turl("dh_cmds"), { method: "POST", headers: sbm, body: JSON.stringify({ kind: "kick", uid: target, scope: "user", payload: { msg }, by_name: actor.name, expires_at: iso(Date.now() + 60000) }) });
        if (!ins.ok) return send(502, { error: "Could not save" });
        await slog(role, uid, actor.name, "kick", target, tname, msg);
        return send(200, { ok: true, kickLeft: left });
      }

      if (op === "announce") {
        const text = clean(b.text, 200);
        if (text.length < 3) return send(400, { error: "Write a bit more (at least 3 characters)" });
        const scope = b.scope === "all" || b.scope === "map" ? b.scope : "server";
        if (scope === "all" && !isOwner) return deny("Only the owner can announce to everybody");
        if (scope === "map" && !isOwner) return deny("Only the owner can announce to a whole map");
        const room = scope === "map" ? b.room : scope === "server" ? b.room : null;
        if (scope === "server" && !(typeof room === "string" && SERVER_RE.test(room))) return send(400, { error: "Bad server" });
        if (scope === "map" && !(typeof room === "string" && /^m:[A-Za-z0-9_\-]{1,70}$/.test(room))) return send(400, { error: "Bad map" });
        if (!isOwner) {
          const last = await getRows("dh_stafflog?select=at&action=eq.announce&actor_uid=eq." + uid + "&at=gte." + enc(iso(Date.now() - ANNOUNCE_ADMIN_GAP)) + "&limit=1");
          if (last[0]) return send(429, { error: "Wait a minute between announcements" });
        }
        const ins = await fetch(turl("dh_cmds"), { method: "POST", headers: sbm, body: JSON.stringify({ kind: "announce", uid: null, scope: scope === "all" ? "all" : "room", room: scope === "all" ? null : room, payload: { text }, by_name: actor.name, expires_at: iso(Date.now() + 600000) }) });
        if (!ins.ok) return send(502, { error: "Could not save" });
        await slog(role, uid, actor.name, "announce", null, scope, text);
        return send(200, { ok: true });
      }

      // ---- owner only ----
      if (!isOwner) return deny("Only the owner can do this");

      if (op === "flag") {
        const k = typeof b.flag === "string" ? b.flag : "";
        if (STAFF_FLAGS.indexOf(k) < 0) return send(400, { error: "Bad switch" });
        const off = b.off === true;
        const up = await fetch(turl("dh_flags") + "?on_conflict=key", { method: "POST", headers: sbu, body: JSON.stringify({ key: k, off, by_name: actor.name, updated_at: iso(Date.now()) }) });
        if (!up.ok) return send(502, { error: "Could not save" });
        cacheFlags.t = 0;
        await slog(role, uid, actor.name, "flag", null, k, off ? "OFF" : "ON");
        return send(200, { ok: true, flags: await flagsOff() });
      }
      if (op === "invite") {
        const f = target ? { uid: target, name: tname || String(target) } : await robloxFind(b.q);
        if (!f) return send(404, { error: "User not found" });
        if (f.uid === uid) return send(400, { error: "That is you" });
        const st = await targetStatus(f.uid);
        if (st === "owner") return send(400, { error: "That is the owner" });
        if (st === "active") return send(409, { error: f.name + " is already an admin" });
        const up = await fetch(turl("dh_staff") + "?on_conflict=uid", { method: "POST", headers: sbu, body: JSON.stringify({ uid: f.uid, name: f.name, status: "invited", key_hash: null, invited_by: actor.name, invited_at: iso(Date.now()), expires_at: iso(Date.now() + INVITE_MS), accepted_at: null }) });
        if (!up.ok) return send(502, { error: "Could not save" });
        await slog(role, uid, actor.name, "invite", f.uid, f.name, "admin invitation (10 min)");
        return send(200, { ok: true, uid: f.uid, name: f.name, exp: iso(Date.now() + INVITE_MS) });
      }
      if (op === "uninvite" || op === "unadmin") {
        if (!target) return send(400, { error: "Bad target" });
        const st = op === "unadmin" ? "active" : "invited";
        await fetch(turl("dh_staff") + "?status=eq." + st + "&uid=eq." + target, { method: "DELETE", headers: sb });
        cacheStaff.delete(target);
        await slog(role, uid, actor.name, op, target, tname, "");
        return send(200, { ok: true });
      }
      if (op === "admins") {
        const rows = await getRows("dh_staff?select=uid,name,status,expires_at,accepted_at&status=in.(invited,active)&order=invited_at.desc&limit=60");
        return send(200, { admins: rows });
      }
      if (op === "appeals") {
        const rows = await getRows("dh_bans?select=id,uid,name,reason,appeal,appeal_at&appeal_status=eq.pending&active=eq.true&order=appeal_at.asc&limit=30");
        return send(200, { appeals: rows });
      }
      if (op === "review") {
        const id = Number.isInteger(b.id) && b.id > 0 ? b.id : null;
        if (!id) return send(400, { error: "Bad appeal" });
        const rows = await getRows("dh_bans?select=id,uid,name&appeal_status=eq.pending&id=eq." + id + "&limit=1");
        if (!rows[0]) return send(404, { error: "Appeal not found" });
        const accept = b.accept === true;
        const reply = clean(b.reply, 150);
        const patch = { appeal_status: accept ? "accepted" : "rejected", appeal_reply: reply || null };
        if (accept) { patch.active = false; patch.ended_at = iso(Date.now()); patch.ended_by = actor.name; }
        const up = await fetch(turl("dh_bans") + "?id=eq." + id, { method: "PATCH", headers: sbm, body: JSON.stringify(patch) });
        if (!up.ok) return send(502, { error: "Could not save" });
        cacheBan.delete(rows[0].uid);
        await slog(role, uid, actor.name, accept ? "appeal_accept" : "appeal_reject", rows[0].uid, rows[0].name, reply);
        return send(200, { ok: true });
      }
      if (op === "log") {
        let q = "dh_stafflog?select=at,actor_name,actor_role,action,target_name,detail&order=id.desc&limit=100";
        if (target) q += "&or=(actor_uid.eq." + target + ",target_uid.eq." + target + ")";
        return send(200, { log: await getRows(q) });
      }
      return send(400, { error: "Bad op" });
    }

    return send(400, { error: "Bad action" });
  } catch (e) {
    return send(502, { error: "Upstream error" });
  }
};
