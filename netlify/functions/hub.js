// DaffzHub loader gate. The hub itself lives in a PRIVATE GitHub repo.
// Needs these environment variables on Netlify (never in this file or in GitHub):
//   HUB_SECRET  the secret word that is inside the loader (?k=...)
//   GH_TOKEN    fine-grained GitHub token, only for the private repo, Contents: Read-only
// Optional: HUB_REPO (default Daffa2014/dh-core), HUB_FILE (default DaffzHub)
const crypto = require("crypto");

const DECOY = "What are you doing here";
const hits = {};

function send(status, body, extra) {
  return { statusCode: status, headers: Object.assign({ "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }, extra || {}), body };
}
function decoy() { return send(200, DECOY); }

function same(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

exports.handler = async (event) => {
  const secret = process.env.HUB_SECRET;
  const token = process.env.GH_TOKEN;
  if (!secret || !token) return decoy();
  if (event.httpMethod && event.httpMethod !== "GET") return decoy();

  const h = event.headers || {};
  const ip = String(h["x-nf-client-connection-ip"] || h["x-forwarded-for"] || "x").split(",")[0].trim();
  const now = Date.now();
  const list = (hits[ip] || []).filter((t) => now - t < 60000);
  list.push(now);
  hits[ip] = list;
  if (list.length > 10) return decoy();             // at most 10 tries per minute per IP
  const keys = Object.keys(hits);
  if (keys.length > 2000) for (const k of keys.slice(0, 1000)) delete hits[k];

  const k = (event.queryStringParameters || {}).k;
  if (typeof k !== "string" || !same(k, secret)) return decoy();

  const repo = process.env.HUB_REPO || "Daffa2014/dh-core";
  const file = process.env.HUB_FILE || "DaffzHub";
  try {
    const r = await fetch("https://api.github.com/repos/" + repo + "/contents/" + encodeURIComponent(file), {
      headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github.raw", "User-Agent": "dh-gate", "X-GitHub-Api-Version": "2022-11-28" }
    });
    if (!r.ok) return decoy();
    const text = await r.text();
    if (text.length < 1000) return decoy();
    return send(200, text);
  } catch (e) {
    return decoy();
  }
};
