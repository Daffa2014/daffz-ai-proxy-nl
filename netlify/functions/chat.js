// DaffzHub AI proxy (Netlify function). The Gemini key lives ONLY in the
// GEMINI_API_KEY environment variable on Netlify, never in this file or in GitHub.
const MODELS = ["gemini-flash-lite-latest", "gemini-flash-latest"];
const hits = new Map(); // best-effort rate limit per IP (resets when the function restarts)

function limited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 60000);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return list.length > 12; // max 12 requests per minute per IP
}

exports.handler = async (event) => {
  const send = (code, obj) => ({ statusCode: code, headers: { "Content-Type": "application/json" }, body: typeof obj === "string" ? obj : JSON.stringify(obj) });
  if (event.httpMethod !== "POST") return send(405, { error: { message: "POST only" } });
  const key = process.env.GEMINI_API_KEY;
  if (!key) return send(500, { error: { message: "Server is not configured" } });

  const h = event.headers || {};
  const ip = String(h["x-nf-client-connection-ip"] || h["x-forwarded-for"] || "unknown").split(",")[0].trim();
  if (limited(ip)) return send(429, { error: { message: "Too many requests" } });

  let b;
  try { b = JSON.parse(event.body || "{}"); } catch (e) { return send(400, { error: { message: "Bad JSON" } }); }
  if (!b || !Array.isArray(b.contents)) return send(400, { error: { message: "Missing contents" } });

  // keep only plain text, last 16 messages, limited length
  let total = 0;
  const contents = [];
  for (const m of b.contents.slice(-16)) {
    const role = m && m.role === "model" ? "model" : "user";
    const text = m && m.parts && m.parts[0] && typeof m.parts[0].text === "string" ? m.parts[0].text.slice(0, 2000) : "";
    if (!text) continue;
    total += text.length;
    contents.push({ role, parts: [{ text }] });
  }
  if (!contents.length || total > 8000) return send(400, { error: { message: "Message too long" } });

  const sys = b.systemInstruction && b.systemInstruction.parts && b.systemInstruction.parts[0] && b.systemInstruction.parts[0].text;
  const model = MODELS.includes(b.model) ? b.model : MODELS[0];
  const out = { contents, generationConfig: { temperature: 0.8, maxOutputTokens: 1024 } };
  if (typeof sys === "string") out.systemInstruction = { parts: [{ text: sys.slice(0, 3000) }] };

  try {
    const r = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent",
      { method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": key }, body: JSON.stringify(out) }
    );
    return send(r.status, await r.text());
  } catch (e) {
    return send(502, { error: { message: "Upstream error" } });
  }
};
  
