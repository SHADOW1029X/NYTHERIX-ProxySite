// =============================================================================
//  NYTHERIX — Admin Backend Worker (pure JSON API)
//
//  D1 Binding:  DB  →  nytherix_db
//  Table:       settings (id INTEGER, target_url TEXT, enabled INTEGER)
//  Seed row:    INSERT OR IGNORE INTO settings VALUES (1, '', 0);
//
//  This worker has NO login/session system of its own — authentication for
//  the admin dashboard is handled entirely by the separate dashboard-
//  management worker (login.html / PHOTONdashboard.html, /auth/me,
//  /auth/logout). This worker just reads/writes the `settings` row.
//
//  Endpoints:
//    GET  /api/settings   → { target_url, enabled }
//    POST /api/settings   body: { target_url, enabled } → updated settings
// =============================================================================

// Set this to the exact origin of your static admin dashboard site.
const ALLOWED_ORIGIN = "https://dashboards.23amtics322.workers.dev";

function corsHeaders(request) {
  const origin = request.headers.get("Origin");
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
  if (origin === ALLOWED_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN;
    headers["Access-Control-Allow-Credentials"] = "true";
  }
  return headers;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders }
  });
}

async function getSettings(env) {
  const row = await env.DB.prepare(
    "SELECT target_url, enabled FROM settings WHERE id=1"
  ).first();
  if (!row) {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO settings (id, target_url, enabled) VALUES (1, '', 0)"
    ).run();
    return { target_url: "", enabled: 0 };
  }
  return { target_url: row.target_url || "", enabled: row.enabled ? 1 : 0 };
}

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;
    const cors   = corsHeaders(request);

    // ── CORS PREFLIGHT ────────────────────────────────────────────────────
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // ── GET /api/settings ────────────────────────────────────────────────
    if (path === "/api/settings" && method === "GET") {
      const settings = await getSettings(env);
      return json(settings, 200, cors);
    }

    // ── POST /api/settings ───────────────────────────────────────────────
    if (path === "/api/settings" && method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body." }, 400, cors);
      }

      let tgt = String(body.target_url ?? "").trim();
      const enabled = body.enabled ? 1 : 0;

      // Auto-prefix scheme
      if (tgt && !tgt.startsWith("http://") && !tgt.startsWith("https://")) {
        tgt = "https://" + tgt;
      }

      // Validate
      if (tgt) {
        try {
          new URL(tgt);
        } catch {
          return json({ error: "Invalid URL — please enter a valid destination." }, 400, cors);
        }
      }

      await env.DB.prepare(`
        INSERT INTO settings (id, target_url, enabled) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET target_url=excluded.target_url, enabled=excluded.enabled
      `).bind(tgt, enabled).run();

      return json({ target_url: tgt, enabled }, 200, cors);
    }

    return json({ error: "Not Found" }, 404, cors);
  }
};