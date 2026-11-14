// DaffzHub Monitor (Netlify function, one file: page + API). Put it at netlify/functions/monitor.js
// Open: https://<your-site>.netlify.app/.netlify/functions/monitor
// New Netlify environment variables: ADMIN_PASSWORD (the web password) and OWNER_UID (any of your Roblox user ids).
// It also uses the ones msg.js already has: OWNER_KEY, SUPABASE_URL, SUPABASE_SERVICE_KEY. Never put secrets in this file or in GitHub.
const crypto = require("crypto");

const E = process.env;
const SESSION_MS = 8 * 3600 * 1000;
const STAFF_OPS = new Set(["lookup", "ban", "unban", "warn", "kick", "announce", "invite", "uninvite", "unadmin", "admins", "untamper", "clearwarns", "log", "bans", "appeals", "review", "flag"]);
const FIELDS = ["q", "target", "tname", "reason", "until", "msg", "text", "scope", "room", "flag", "off", "id", "accept", "reply"];
const fails = new Map(); // ip -> {n, t}  (best effort: a server that restarts forgets it)

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const SECRET = () => "dh-monitor|" + (E.SUPABASE_SERVICE_KEY || "") + "|" + (E.ADMIN_PASSWORD || "");
const sign = (exp) => exp + "." + crypto.createHmac("sha256", SECRET()).update(String(exp)).digest("hex");
function valid(token) {
  const m = /^(\d{10,14})\.([0-9a-f]{64})$/.exec(String(token || ""));
  if (!m || Number(m[1]) < Date.now()) return false;
  const want = Buffer.from(sign(m[1]));
  const got = Buffer.from(String(token));
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}
function cookieOf(req, name) {
  const c = String(req.headers.cookie || "").split(";").map((x) => x.trim());
  for (const x of c) if (x.startsWith(name + "=")) return x.slice(name.length + 1);
  return "";
}
const ipOf = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
const iso = (ms) => new Date(ms).toISOString();
const enc = encodeURIComponent;

function sbHeaders(extra) {
  return Object.assign({ apikey: E.SUPABASE_SERVICE_KEY, Authorization: "Bearer " + E.SUPABASE_SERVICE_KEY, "Content-Type": "application/json" }, extra || {});
}
const sbUrl = (path) => String(E.SUPABASE_URL || "").replace(/\/+$/, "") + "/rest/v1/" + path;
async function sbGet(path) {
  const r = await fetch(sbUrl(path), { headers: sbHeaders() });
  if (!r.ok) throw new Error("db " + r.status);
  return r.json();
}
async function sbCount(path) {
  const r = await fetch(sbUrl(path), { method: "HEAD", headers: sbHeaders({ Prefer: "count=exact" }) });
  const n = parseInt(String(r.headers.get("content-range") || "").split("/")[1], 10);
  return Number.isFinite(n) ? n : 0;
}
async function staff(op, extra) {
  const body = { action: "staff", op, uid: Number(E.OWNER_UID), name: E.OWNER_NAME || "Web", key: E.OWNER_KEY };
  for (const k of FIELDS) if (extra && extra[k] !== undefined) body[k] = extra[k];
  const r = await require("./msg.js").handler({ httpMethod: "POST", headers: { "x-nf-client-connection-ip": "monitor-web" }, body: JSON.stringify(body) });
  let data = {};
  try { data = JSON.parse(r.body); } catch (e) { data = {}; }
  return { code: r.statusCode, data };
}
async function timed(fn) {
  const t = Date.now();
  try { const ok = await fn(); return { ms: Date.now() - t, ok: ok !== false }; } catch (e) { return { ms: Date.now() - t, ok: false }; }
}

async function overview() {
  const now = Date.now();
  const since = (ms) => "&last_seen=gte." + enc(iso(now - ms));
  const [online, day, week, month, total, bans, tamper, fresh] = await Promise.all([
    sbCount("dh_users?select=id" + since(120000)),
    sbCount("dh_users?select=id" + since(86400000)),
    sbCount("dh_users?select=id" + since(7 * 86400000)),
    sbCount("dh_users?select=id" + since(30 * 86400000)),
    sbCount("dh_users?select=id"),
    sbCount("dh_bans?select=id&active=eq.true&or=(until.is.null,until.gt." + enc(iso(now)) + ")"),
    sbCount("dh_kickwatch?select=uid&flagged=eq.true&flagged_at=gt." + enc(iso(now - 3 * 86400000))),
    sbCount("dh_feedback?select=id&done=eq.false"),
  ]);
  return { online, day, week, month, total, bans, tamper, fresh };
}
async function servers() {
  const rows = await sbGet("dh_presence?select=room,uid,name&seen_at=gte." + enc(iso(Date.now() - 180000)) + "&limit=1000");
  const by = {};
  for (const r of rows) {
    if (typeof r.room !== "string" || r.room.slice(0, 2) !== "s:") continue;
    const s = by[r.room] || (by[r.room] = { room: r.room, count: 0, names: [] });
    s.count++;
    if (s.names.length < 3) s.names.push(r.name);
  }
  return Object.values(by).sort((a, b) => b.count - a.count).slice(0, 30);
}
async function status() {
  const out = [];
  const msg = await timed(async () => { const r = await staff("poll", {}); return r.code === 200 && r.data.role === "owner"; });
  out.push({ name: "Fungsi msg (Netlify)", detail: msg.ok ? "Message, Online, Staff Panel. Kamu dikenali sebagai Owner." : "Tidak merespons, atau kunci Owner tidak cocok.", ms: msg.ms, ok: msg.ok });
  const db = await timed(async () => { await sbCount("dh_flags?select=key"); return true; });
  out.push({ name: "Database (Supabase)", detail: "Tabel dh_* terjangkau", ms: db.ms, ok: db.ok });
  const gh = await timed(async () => { const r = await fetch("https://raw.githubusercontent.com/Daffa2014/Daffzhub-/main/version.txt"); return r.ok; });
  out.push({ name: "version.txt (GitHub)", detail: "Dipakai pengecekan update di hub", ms: gh.ms, ok: gh.ok });
  const hub = await timed(async () => { const r = await fetch("https://raw.githubusercontent.com/Daffa2014/Daffzhub-/main/DaffzHub", { method: "HEAD" }); return r.ok; });
  out.push({ name: "File DaffzHub (GitHub)", detail: "File yang dimuat loader", ms: hub.ms, ok: hub.ok });
  return out;
}

function reply(res, code, obj, cookie) {
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (cookie) headers["Set-Cookie"] = cookie;
  res.out = { statusCode: code, headers, body: JSON.stringify(obj) };
  return res.out;
}
const cookieStr = (v, maxAge) => "dhm=" + v + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + maxAge;

async function api(req, res) {
  try {
    if (req.method !== "POST") return reply(res, 405, { error: "POST only" });
    if (req.headers["x-dhm"] !== "1") return reply(res, 400, { error: "Bad request" });
    if (!E.ADMIN_PASSWORD || !E.OWNER_KEY || !E.OWNER_UID || !E.SUPABASE_URL || !E.SUPABASE_SERVICE_KEY) {
      return reply(res, 500, { error: "Belum siap: variabel ADMIN_PASSWORD / OWNER_UID di Netlify belum diisi" });
    }
    let b = req.body;
    if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { b = {}; } }
    if (!b || typeof b !== "object") b = {};
    const op = typeof b.op === "string" ? b.op : "";

    if (op === "login") {
      const ip = ipOf(req);
      const f = fails.get(ip);
      if (f && f.n >= 5 && Date.now() - f.t < 15 * 60000) return reply(res, 429, { error: "Too many wrong passwords. Try again in 15 minutes." });
      await new Promise((r) => setTimeout(r, 600));
      if (typeof b.password !== "string" || !same(b.password, E.ADMIN_PASSWORD)) {
        fails.set(ip, { n: (f && Date.now() - f.t < 15 * 60000 ? f.n : 0) + 1, t: Date.now() });
        if (fails.size > 500) fails.clear();
        return reply(res, 401, { error: "Wrong password" });
      }
      fails.delete(ip);
      return reply(res, 200, { ok: true }, cookieStr(sign(Date.now() + SESSION_MS), SESSION_MS / 1000));
    }
    if (op === "logout") return reply(res, 200, { ok: true }, cookieStr("", 0));
    if (!valid(cookieOf(req, "dhm"))) return reply(res, 401, { error: "Not logged in", login: true });
    if (op === "me") return reply(res, 200, { ok: true, owner: E.OWNER_NAME || "Owner" });

    if (op === "overview") return reply(res, 200, await overview());
    if (op === "servers") return reply(res, 200, { servers: await servers() });
    if (op === "status") return reply(res, 200, { services: await status() });
    if (op === "feedback") {
      const kind = b.kind === "bug" || b.kind === "idea" || b.kind === "other" ? "&kind=eq." + b.kind : "";
      const rows = await sbGet("dh_feedback?select=id,created_at,kind,body,ver,place,exec,device,name,done&done=eq.false" + kind + "&order=id.desc&limit=100");
      return reply(res, 200, { feedback: rows });
    }
    if (op === "feedback_done") {
      if (!Number.isInteger(b.id) || b.id < 1) return reply(res, 400, { error: "Bad id" });
      const r = await fetch(sbUrl("dh_feedback?id=eq." + b.id), { method: "PATCH", headers: sbHeaders({ Prefer: "return=minimal" }), body: JSON.stringify({ done: true }) });
      return reply(res, r.ok ? 200 : 502, r.ok ? { ok: true } : { error: "Could not save" });
    }
    if (STAFF_OPS.has(op)) {
      const r = await staff(op, b);
      return reply(res, r.code, r.data);
    }
    return reply(res, 400, { error: "Bad op" });
  } catch (e) {
    return reply(res, 502, { error: "Upstream error" });
  }
}

const PAGE = "<!doctype html>\n<html lang=\"id\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"robots\" content=\"noindex,nofollow\">\n<title>DaffzHub Monitor</title>\n<style>\n:root{--bg:#0e1013;--card:#161a20;--card2:#1c2128;--line:#262c35;--tx:#e8ecf1;--mu:#8b96a5;--ac:#4f8cff;--ok:#3ecf8e;--warn:#f5b84a;--bad:#ff5d6c}\n*{box-sizing:border-box}\nhtml,body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}\n.wrap{max-width:1180px;margin:0 auto;padding:16px}\nh1{font-size:20px;margin:0}h2{font-size:16px;margin:0 0 12px}\n.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}\n.grid{display:grid;gap:14px;margin-top:14px}\n.g4{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}\n.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}\n.top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:space-between}\n.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:99px;background:var(--card2);border:1px solid var(--line);font-size:13px}\n.dot{width:8px;height:8px;border-radius:50%;background:var(--mu)}\n.ok .dot,.dot.ok{background:var(--ok)}.bad .dot,.dot.bad{background:var(--bad)}.warn .dot{background:var(--warn)}\n.num{font-size:28px;font-weight:700}.mu{color:var(--mu);font-size:13px}\ninput,select,textarea,button{font:inherit;color:var(--tx)}\ninput,select,textarea{background:var(--card2);border:1px solid var(--line);border-radius:8px;padding:9px 10px;min-width:0;width:100%}\n.inl{width:auto;flex:1 1 160px}\nbutton{background:var(--card2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;cursor:pointer}\nbutton:hover{border-color:var(--ac)}button:disabled{opacity:.5;cursor:default}\nbutton.pri{background:var(--ac);border-color:var(--ac);color:#fff}\nbutton.dng{background:#3a1c21;border-color:#6b2a33;color:#ffb3bb}\n.list>div{padding:10px 0;border-top:1px solid var(--line);display:flex;gap:10px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}\n.list>div:first-child{border-top:0}\n.grow{flex:1 1 220px;min-width:0;overflow-wrap:anywhere}\n.tag{font-size:12px;padding:2px 8px;border-radius:99px;background:var(--card2);border:1px solid var(--line);color:var(--mu)}\n.tag.bad{color:#ffb3bb;border-color:#6b2a33}.tag.ok{color:#9ae6c2;border-color:#1f5a40}.tag.warn{color:#f7d08a;border-color:#6a5220}\n#login{max-width:340px;margin:18vh auto 0}\n#msg{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);background:var(--card2);border:1px solid var(--line);padding:10px 16px;border-radius:10px;max-width:92vw;display:none;z-index:5}\n#msg.bad{border-color:var(--bad)}#msg.ok{border-color:var(--ok)}\ndialog{background:var(--card);color:var(--tx);border:1px solid var(--line);border-radius:12px;max-width:420px;width:92vw}\ndialog::backdrop{background:rgba(0,0,0,.6)}\n.hide{display:none!important}\n</style>\n</head>\n<body>\n<div id=\"login\" class=\"card hide\">\n  <h1>DaffzHub Monitor</h1>\n  <p class=\"mu\">Masukkan password admin.</p>\n  <form id=\"lf\"><input id=\"pw\" type=\"password\" autocomplete=\"current-password\" placeholder=\"Password\" required>\n  <div style=\"height:10px\"></div><button class=\"pri\" style=\"width:100%\">Masuk</button></form>\n  <p id=\"lerr\" class=\"mu\" style=\"color:var(--bad)\"></p>\n</div>\n\n<div id=\"app\" class=\"wrap hide\">\n  <div class=\"top\">\n    <h1>DaffzHub Monitor</h1>\n    <div class=\"row\"><span id=\"pillAll\" class=\"pill\"><span class=\"dot\"></span><span id=\"pillTx\">memeriksa…</span></span>\n      <button id=\"refresh\">Muat ulang</button><button id=\"logout\">Keluar</button></div>\n  </div>\n\n  <div id=\"stats\" class=\"grid g4\"></div>\n\n  <div class=\"grid g2\">\n    <div class=\"card\"><h2>Status layanan</h2><div id=\"svc\" class=\"list\"></div></div>\n    <div class=\"card\"><h2>Server aktif <span id=\"srvN\" class=\"mu\"></span></h2><div id=\"srv\" class=\"list\"></div></div>\n  </div>\n\n  <div class=\"grid g2\">\n    <div class=\"card\">\n      <h2>Kelola pemain</h2>\n      <form id=\"sf\" class=\"row\"><input id=\"q\" class=\"inl\" placeholder=\"Username atau ID Roblox\" required><button class=\"pri\">Cari</button></form>\n      <div id=\"pl\" style=\"margin-top:12px\"></div>\n      <h2 style=\"margin-top:18px\">Pemain diblokir <span id=\"banN\" class=\"mu\"></span></h2>\n      <div id=\"bans\" class=\"list\"></div>\n    </div>\n    <div class=\"card\">\n      <h2>Pengumuman</h2>\n      <form id=\"af\">\n        <textarea id=\"atx\" rows=\"3\" maxlength=\"200\" placeholder=\"Isi pengumuman (3-200 huruf)\" required></textarea>\n        <div class=\"row\" style=\"margin-top:8px\">\n          <select id=\"asc\" class=\"inl\"><option value=\"all\">Semua pengguna</option><option value=\"server\">Satu server aktif</option></select>\n          <select id=\"asv\" class=\"inl hide\"></select>\n        </div>\n        <div style=\"margin-top:8px\"><button class=\"pri\">Kirim pengumuman</button></div>\n      </form>\n    </div>\n  </div>\n\n  <div class=\"grid g2\">\n    <div class=\"card\">\n      <h2>Admin</h2>\n      <form id=\"inf\" class=\"row\"><input id=\"inq\" class=\"inl\" placeholder=\"Username untuk diundang\" required><button class=\"pri\">Undang</button></form>\n      <div id=\"adm\" class=\"list\" style=\"margin-top:10px\"></div>\n    </div>\n    <div class=\"card\"><h2>Aktivitas staff</h2><div id=\"log\" class=\"list\"></div></div>\n  </div>\n\n  <div class=\"card\" style=\"margin-top:14px\">\n    <div class=\"top\"><h2>Feedback belum selesai <span id=\"fbN\" class=\"mu\"></span></h2>\n      <select id=\"fbk\" style=\"width:auto\"><option value=\"\">Semua</option><option value=\"bug\">Bug</option><option value=\"idea\">Ide</option><option value=\"other\">Lainnya</option></select></div>\n    <div id=\"fb\" class=\"list\"></div>\n  </div>\n  <p class=\"mu\">Data diambil langsung dari server DaffzHub. Halaman ini tidak menyimpan apa pun sendiri.</p>\n</div>\n\n<dialog id=\"dlg\"><h2 id=\"dt\"></h2><div id=\"db\"></div><div class=\"row\" style=\"margin-top:14px;justify-content:flex-end\">\n  <button id=\"dno\">Batal</button><button id=\"dyes\" class=\"pri\">Ya, lanjut</button></div></dialog>\n<div id=\"msg\"></div>\n\n<script>\n\"use strict\";\nconst $ = (id) => document.getElementById(id);\nfunction h(tag, props, ...kids) {\n  const e = document.createElement(tag);\n  for (const k in props || {}) { if (k === \"class\") e.className = props[k]; else if (k === \"on\") for (const ev in props.on) e.addEventListener(ev, props.on[ev]); else e.setAttribute(k, props[k]); }\n  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));\n  return e;\n}\nconst clear = (e) => { while (e.firstChild) e.removeChild(e.firstChild); return e; };\nlet toastT;\nfunction toast(t, kind) { const m = $(\"msg\"); m.textContent = t; m.className = kind || \"\"; m.style.display = \"block\"; clearTimeout(toastT); toastT = setTimeout(() => (m.style.display = \"none\"), 4000); }\nasync function api(op, data) {\n  let r;\n  try { r = await fetch(location.pathname, { method: \"POST\", headers: { \"Content-Type\": \"application/json\", \"X-DHM\": \"1\" }, body: JSON.stringify(Object.assign({ op }, data || {})) }); }\n  catch (e) { throw new Error(\"Tidak bisa menghubungi server\"); }\n  let j = {}; try { j = await r.json(); } catch (e) {}\n  if (r.status === 401 && j.login) { showLogin(); throw new Error(\"Sesi habis, masuk lagi\"); }\n  if (!r.ok) throw new Error(j.error || \"Gagal (\" + r.status + \")\");\n  return j;\n}\nfunction ago(t) { const s = Math.max(0, (Date.now() - Date.parse(t)) / 1000); if (s < 60) return \"baru saja\"; if (s < 3600) return Math.floor(s / 60) + \" mnt lalu\"; if (s < 86400) return Math.floor(s / 3600) + \" jam lalu\"; return Math.floor(s / 86400) + \" hari lalu\"; }\nfunction until(t) { return t ? \"sampai \" + new Date(t).toLocaleString() : \"permanen\"; }\nfunction ask(title, body, danger) {\n  return new Promise((res) => {\n    const d = $(\"dlg\"); $(\"dt\").textContent = title; clear($(\"db\")).append(body);\n    $(\"dyes\").className = danger ? \"dng\" : \"pri\";\n    const done = (v) => { d.close(); $(\"dyes\").onclick = $(\"dno\").onclick = null; res(v); };\n    $(\"dyes\").onclick = () => done(true); $(\"dno\").onclick = () => done(false); d.oncancel = () => res(false);\n    d.showModal();\n  });\n}\nasync function run(fn, okText) { try { const r = await fn(); if (okText) toast(okText, \"ok\"); return r; } catch (e) { toast(e.message, \"bad\"); return null; } }\n\nfunction showLogin() { $(\"app\").classList.add(\"hide\"); $(\"login\").classList.remove(\"hide\"); $(\"pw\").focus(); }\nfunction showApp() { $(\"login\").classList.add(\"hide\"); $(\"app\").classList.remove(\"hide\"); loadAll(); }\n$(\"lf\").addEventListener(\"submit\", async (e) => {\n  e.preventDefault(); $(\"lerr\").textContent = \"\";\n  try { await api(\"login\", { password: $(\"pw\").value }); $(\"pw\").value = \"\"; showApp(); } catch (er) { $(\"lerr\").textContent = er.message; }\n});\n$(\"logout\").onclick = async () => { try { await api(\"logout\"); } catch (e) {} showLogin(); };\n$(\"refresh\").onclick = () => loadAll();\n\nlet servers = [], ctx = null;\nasync function loadAll() {\n  loadOverview(); loadServers(); loadStatus(); loadBans(); loadAdmins(); loadLog(); loadFeedback();\n}\nasync function loadOverview() {\n  const o = await run(() => api(\"overview\")); if (!o) return;\n  const items = [[\"Online sekarang\", o.online], [\"24 jam\", o.day], [\"7 hari\", o.week], [\"30 hari\", o.month], [\"Total pengguna\", o.total], [\"Diblokir\", o.bans], [\"Salinan dimodifikasi\", o.tamper], [\"Feedback baru\", o.fresh]];\n  const box = clear($(\"stats\"));\n  for (const [l, v] of items) box.append(h(\"div\", { class: \"card\" }, h(\"div\", { class: \"mu\" }, l), h(\"div\", { class: \"num\" }, String(v))));\n}\nasync function loadServers() {\n  const r = await run(() => api(\"servers\")); if (!r) return;\n  servers = r.servers; $(\"srvN\").textContent = \"(\" + servers.length + \")\";\n  const box = clear($(\"srv\"));\n  if (!servers.length) box.append(h(\"div\", { class: \"mu\" }, \"Tidak ada server aktif dalam 3 menit terakhir.\"));\n  for (const s of servers) box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" }, h(\"b\", {}, s.count + \" pemain\"), \" \", h(\"span\", { class: \"mu\" }, s.names.join(\", \") + (s.count > s.names.length ? \", …\" : \"\")), h(\"div\", { class: \"mu\" }, s.room.slice(2, 10) + \"…\"))));\n  const sel = clear($(\"asv\"));\n  for (const s of servers) sel.append(h(\"option\", { value: s.room }, s.count + \" pemain - \" + s.room.slice(2, 10)));\n}\nasync function loadStatus() {\n  $(\"pillTx\").textContent = \"memeriksa…\"; $(\"pillAll\").className = \"pill\";\n  const r = await run(() => api(\"status\")); if (!r) return;\n  const box = clear($(\"svc\")); let allOk = true;\n  for (const s of r.services) { if (!s.ok) allOk = false; box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" }, h(\"span\", { class: \"dot \" + (s.ok ? \"ok\" : \"bad\"), style: \"display:inline-block;margin-right:8px\" }), h(\"b\", {}, s.name), h(\"div\", { class: \"mu\" }, s.detail)), h(\"span\", { class: \"mu\" }, s.ms + \" ms\"))); }\n  $(\"pillAll\").className = \"pill \" + (allOk ? \"ok\" : \"bad\"); $(\"pillTx\").textContent = allOk ? \"Semua normal\" : \"Ada masalah\";\n}\n$(\"asc\").onchange = () => $(\"asv\").classList.toggle(\"hide\", $(\"asc\").value !== \"server\");\n$(\"af\").addEventListener(\"submit\", async (e) => {\n  e.preventDefault();\n  const scope = $(\"asc\").value, text = $(\"atx\").value.trim();\n  if (scope === \"server\" && !$(\"asv\").value) return toast(\"Belum ada server aktif untuk dipilih\", \"bad\");\n  const where = scope === \"all\" ? \"semua pengguna\" : \"server \" + $(\"asv\").selectedOptions[0].textContent;\n  if (!(await ask(\"Kirim pengumuman?\", h(\"div\", {}, h(\"div\", { class: \"mu\" }, \"Ke: \" + where), h(\"p\", {}, text))))) return;\n  const r = await run(() => api(\"announce\", { text, scope, room: scope === \"server\" ? $(\"asv\").value : undefined }), \"Pengumuman terkirim\");\n  if (r) $(\"atx\").value = \"\";\n});\n\n// ---- players ----\n$(\"sf\").addEventListener(\"submit\", async (e) => {\n  e.preventDefault();\n  const r = await run(() => api(\"lookup\", { q: $(\"q\").value.trim() })); if (!r) return;\n  ctx = r; renderPlayer();\n});\nfunction renderPlayer() {\n  const p = ctx, box = clear($(\"pl\"));\n  if (!p) return;\n  const tags = [];\n  if (p.staff === \"owner\") tags.push(h(\"span\", { class: \"tag ok\" }, \"Owner\"));\n  else if (p.staff === \"active\") tags.push(h(\"span\", { class: \"tag ok\" }, \"Admin\"));\n  if (p.ban) tags.push(h(\"span\", { class: \"tag bad\" }, \"Diblokir \" + until(p.ban.until)));\n  if (p.warns) tags.push(h(\"span\", { class: \"tag warn\" }, p.warns + \" peringatan\"));\n  if (p.tampered) tags.push(h(\"span\", { class: \"tag bad\" }, \"Salinan dimodifikasi\"));\n  const act = (label, cls, fn) => h(\"button\", { class: cls || \"\", on: { click: fn } }, label);\n  const protectedUser = p.staff === \"owner\";\n  box.append(h(\"div\", { class: \"card\", style: \"background:var(--card2)\" },\n    h(\"b\", {}, p.name), \" \", h(\"span\", { class: \"mu\" }, (p.user ? \"@\" + p.user + \" · \" : \"\") + \"ID \" + p.uid),\n    h(\"div\", { class: \"row\", style: \"margin:8px 0\" }, tags),\n    protectedUser ? h(\"div\", { class: \"mu\" }, \"Owner tidak bisa dikenai tindakan.\") :\n    h(\"div\", { class: \"row\" },\n      act(\"Warn\", \"\", () => doReason(\"warn\", \"Beri peringatan\", false)),\n      act(\"Kick\", \"\", () => doReason(\"kick\", \"Kick dari server\", false)),\n      p.ban ? act(\"Unblock\", \"\", () => doUnban()) : act(\"Block\", \"dng\", () => doReason(\"ban\", \"Blokir pemain\", true)),\n      p.tampered ? act(\"Hapus tanda modifikasi\", \"\", () => doUntamper()) : null)));\n}\nfunction reasonForm(withUntil) {\n  const r = h(\"input\", { placeholder: \"Alasan (opsional)\", maxlength: \"120\" });\n  const u = h(\"select\", {}, h(\"option\", { value: \"\" }, \"Permanen\"), h(\"option\", { value: \"3600000\" }, \"1 jam\"), h(\"option\", { value: \"86400000\" }, \"1 hari\"), h(\"option\", { value: \"604800000\" }, \"7 hari\"), h(\"option\", { value: \"2592000000\" }, \"30 hari\"));\n  return { r, u, el: h(\"div\", {}, h(\"div\", { class: \"mu\" }, \"Pemain: \" + ctx.name), r, withUntil ? h(\"div\", { style: \"margin-top:8px\" }, u) : null) };\n}\nasync function doReason(op, title, withUntil) {\n  const f = reasonForm(withUntil);\n  if (!(await ask(title + \"?\", f.el, op === \"ban\"))) return;\n  const d = { target: ctx.uid, tname: ctx.name };\n  if (op === \"kick\") d.msg = f.r.value.trim(); else d.reason = f.r.value.trim();\n  if (op === \"ban\" && f.u.value) d.until = new Date(Date.now() + Number(f.u.value)).toISOString();\n  const res = await run(() => api(op, d), \"Berhasil: \" + op); if (!res) return;\n  if (op === \"warn\" && res.auto) toast(\"Batas peringatan tercapai: otomatis diblokir 1 hari\", \"ok\");\n  const r2 = await run(() => api(\"lookup\", { target: ctx.uid, tname: ctx.name })); if (r2) { ctx = r2; renderPlayer(); }\n  loadBans(); loadLog();\n}\nasync function doUnban() {\n  if (!(await ask(\"Buka blokir?\", h(\"div\", {}, ctx.name)))) return;\n  if (!(await run(() => api(\"unban\", { target: ctx.uid, tname: ctx.name }), \"Blokir dibuka\"))) return;\n  const r2 = await run(() => api(\"lookup\", { target: ctx.uid, tname: ctx.name })); if (r2) { ctx = r2; renderPlayer(); }\n  loadBans(); loadLog();\n}\nasync function doUntamper() {\n  if (!(await ask(\"Hapus tanda 'salinan dimodifikasi'?\", h(\"div\", {}, ctx.name)))) return;\n  if (!(await run(() => api(\"untamper\", { target: ctx.uid, tname: ctx.name }), \"Tanda dihapus\"))) return;\n  ctx.tampered = false; renderPlayer(); loadOverview(); loadLog();\n}\nasync function loadBans() {\n  const r = await run(() => api(\"bans\")); if (!r) return;\n  $(\"banN\").textContent = \"(\" + r.bans.length + \")\";\n  const box = clear($(\"bans\"));\n  if (!r.bans.length) box.append(h(\"div\", { class: \"mu\" }, \"Tidak ada.\"));\n  for (const b of r.bans) box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" }, h(\"b\", {}, b.name || b.uid), \" \", h(\"span\", { class: \"mu\" }, until(b.until) + \" · oleh \" + (b.by_name || \"?\")), h(\"div\", { class: \"mu\" }, b.reason || \"\")),\n    h(\"button\", { on: { click: async () => { if (!(await ask(\"Buka blokir?\", h(\"div\", {}, b.name || b.uid)))) return; await run(() => api(\"unban\", { target: b.uid, tname: b.name || \"\" }), \"Blokir dibuka\"); loadBans(); loadOverview(); loadLog(); } } }, \"Unblock\")));\n}\n\n// ---- admins ----\n$(\"inf\").addEventListener(\"submit\", async (e) => {\n  e.preventDefault();\n  const q = $(\"inq\").value.trim();\n  if (!(await ask(\"Undang jadi admin?\", h(\"div\", {}, h(\"div\", {}, q), h(\"div\", { class: \"mu\" }, \"Undangan berlaku 10 menit. Pemain harus menerimanya di Staff Panel.\")))) ) return;\n  const r = await run(() => api(\"invite\", { q }), \"Undangan terkirim\"); if (r) { $(\"inq\").value = \"\"; loadAdmins(); loadLog(); }\n});\nasync function loadAdmins() {\n  const r = await run(() => api(\"admins\")); if (!r) return;\n  const box = clear($(\"adm\"));\n  if (!r.admins.length) box.append(h(\"div\", { class: \"mu\" }, \"Belum ada admin.\"));\n  for (const a of r.admins) {\n    const inv = a.status === \"invited\";\n    box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" }, h(\"b\", {}, a.name || a.uid), \" \", h(\"span\", { class: \"tag \" + (inv ? \"warn\" : \"ok\") }, inv ? \"diundang\" : \"admin\")),\n      h(\"button\", { class: \"dng\", on: { click: async () => { if (!(await ask(inv ? \"Batalkan undangan?\" : \"Cabut admin?\", h(\"div\", {}, a.name || a.uid), true))) return; await run(() => api(inv ? \"uninvite\" : \"unadmin\", { target: a.uid, tname: a.name || \"\" }), \"Selesai\"); loadAdmins(); loadLog(); } } }, inv ? \"Batalkan\" : \"Cabut\")));\n  }\n}\nasync function loadLog() {\n  const r = await run(() => api(\"log\")); if (!r) return;\n  const box = clear($(\"log\"));\n  if (!r.log.length) box.append(h(\"div\", { class: \"mu\" }, \"Belum ada aktivitas.\"));\n  for (const l of r.log.slice(0, 40)) box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" }, h(\"b\", {}, l.actor_name || \"?\"), \" \" + l.action + (l.target_name ? \" → \" + l.target_name : \"\"), h(\"div\", { class: \"mu\" }, l.detail || \"\")), h(\"span\", { class: \"mu\" }, ago(l.at))));\n}\n\n// ---- feedback ----\n$(\"fbk\").onchange = () => loadFeedback();\nasync function loadFeedback() {\n  const r = await run(() => api(\"feedback\", { kind: $(\"fbk\").value })); if (!r) return;\n  $(\"fbN\").textContent = \"(\" + r.feedback.length + \")\";\n  const box = clear($(\"fb\"));\n  if (!r.feedback.length) box.append(h(\"div\", { class: \"mu\" }, \"Tidak ada feedback baru.\"));\n  for (const f of r.feedback) box.append(h(\"div\", {}, h(\"div\", { class: \"grow\" },\n    h(\"span\", { class: \"tag\" }, f.kind || \"?\"), \" \", h(\"b\", {}, f.name || \"anonim\"), \" \", h(\"span\", { class: \"mu\" }, ago(f.created_at) + (f.ver ? \" · v\" + f.ver : \"\") + (f.exec ? \" · \" + f.exec : \"\") + (f.device ? \" · \" + f.device : \"\")),\n    h(\"div\", {}, f.body || \"\")),\n    h(\"button\", { on: { click: async () => { if (await run(() => api(\"feedback_done\", { id: f.id }), \"Ditandai selesai\")) { loadFeedback(); loadOverview(); } } } }, \"Tandai selesai\")));\n}\n\n(async () => { try { await api(\"me\"); showApp(); } catch (e) { showLogin(); } })();\nsetInterval(() => { if (!$(\"app\").classList.contains(\"hide\") && !document.hidden) { loadOverview(); loadServers(); } }, 60000);\n</script>\n</body>\n</html>\n";

exports.handler = async (event) => {
  const h = {};
  for (const k in event.headers || {}) h[k.toLowerCase()] = event.headers[k];
  if (event.httpMethod === "GET") {
    return { statusCode: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow" }, body: PAGE };
  }
  const res = {};
  let b = {};
  try { b = JSON.parse(event.body || "{}"); } catch (e) { b = {}; }
  h["x-forwarded-for"] = h["x-nf-client-connection-ip"] || h["x-forwarded-for"];
  await api({ method: event.httpMethod, headers: h, body: b }, res);
  return res.out || { statusCode: 500, headers: { "Content-Type": "application/json" }, body: "{}" };
};
