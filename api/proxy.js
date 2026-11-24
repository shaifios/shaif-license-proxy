export const config = {
  runtime: "edge",
};

const MANUS_ORIGIN = (
  process.env.MANUS_ORIGIN || "https://licensectrl-cqjuixq7.manus.space"
).replace(/\/$/, "");
const WINDOW_MS = 5 * 60 * 1000;
const TICKET_TTL_MS = 30 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ALLOWED_CLIENT_CERTS = new Set([
  "A40DA80A59D170CAA950CF15C18C454D47A39B26989D8B640ECD745BA71BF5DC", // MT Manager Testkey
  "3F7C184C9033B34B4ACA2B9AE9395E175DD3E6A4B1E76E62190F250DEB07D819", // shaif.keystore
]);
const MANUS_EXPECTED_CERT =
  "E34A3D79627CB495F2E05E454726328E757C391CD10460719BD81B2259650158";

const BUILTIN_UPSTREAMS = {
  "ed91b853-d398-4c9a-b102-6eb0e6c670f0":
    "https://media-us.mbscf.com/app/cards/archives/en/v566_ac7ff/cards_v566.zip",
};

function getUpstreams() {
  let extra = {};
  if (process.env.RELEASE_UPSTREAMS_JSON) {
    try {
      extra = JSON.parse(process.env.RELEASE_UPSTREAMS_JSON);
    } catch {}
  }
  return { ...BUILTIN_UPSTREAMS, ...extra };
}

const tickets = new Map();

function pruneTickets() {
  const now = Date.now();
  for (const [k, exp] of tickets.entries()) {
    if (exp <= now) tickets.delete(k);
  }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function extractBearer(req) {
  const auth = req.headers.get("Authorization") || "";
  const m = /^Bearer ([A-Za-z0-9_-]{43,256})$/.exec(auth);
  return m ? m[1] : null;
}

async function forwardJsonToManus(req, origin, pathname, rewriteAuthorizeKind) {
  const headers = new Headers();
  for (const name of [
    "authorization",
    "content-type",
    "accept",
    "accept-encoding",
    "x-device-id",
    "x-request-time",
    "x-request-nonce",
    "x-request-signature",
  ]) {
    const val = req.headers.get(name);
    if (val !== null) headers.set(name, val);
  }

  let rawBody =
    req.method === "GET" || req.method === "HEAD"
      ? undefined
      : await req.arrayBuffer();

  if (pathname === "/api/mobile/activate" && rawBody) {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(rawBody));
      const sentCert =
        typeof parsed?.certificate_sha256 === "string"
          ? parsed.certificate_sha256.toUpperCase()
          : "";
      if (ALLOWED_CLIENT_CERTS.has(sentCert)) {
        parsed.certificate_sha256 = MANUS_EXPECTED_CERT;
        rawBody = new TextEncoder().encode(JSON.stringify(parsed));
      }
    } catch {}
  }

  const upstreamRes = await fetch(`${MANUS_ORIGIN}${pathname}`, {
    method: req.method,
    headers,
    body: rawBody,
    redirect: "manual",
  });

  if (!rewriteAuthorizeKind || upstreamRes.status !== 200) {
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: {
        "Content-Type":
          upstreamRes.headers.get("Content-Type") ||
          "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  const payload = await upstreamRes.json();
  if (payload && payload.allowed === true && typeof payload.url === "string") {
    const m = /\/api\/mobile\/files\/(library|app)\/([A-Za-z0-9_-]{1,128})$/.exec(
      payload.url
    );
    if (m) {
      const [, kind, releaseId] = m;
      const token = extractBearer(req);
      const deviceId = req.headers.get("X-Device-ID") || "";
      if (token && deviceId) {
        pruneTickets();
        const key = `${await sha256Hex(token)}:${deviceId}:${kind}:${releaseId}`;
        tickets.set(key, Date.now() + TICKET_TTL_MS);
      }
      payload.url = `${origin}/api/mobile/files/${kind}/${releaseId}`;
    }
  }

  return jsonResponse(payload, 200);
}

async function handleFileDownload(req, kind, releaseId) {
  if (!UUID_RE.test(releaseId)) {
    return jsonResponse({ allowed: false, reason: "invalid_request" }, 400);
  }

  const token = extractBearer(req);
  const deviceId = req.headers.get("X-Device-ID") || "";
  const timestamp = Number(req.headers.get("X-Request-Time") || "0");
  const nonce = req.headers.get("X-Request-Nonce") || "";
  const signature = req.headers.get("X-Request-Signature") || "";

  if (
    !token ||
    deviceId.length < 8 ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(Date.now() - timestamp) > WINDOW_MS ||
    !UUID_RE.test(nonce) ||
    signature.length < 16
  ) {
    return jsonResponse({ allowed: false, reason: "invalid_request" }, 403);
  }

  pruneTickets();
  const key = `${await sha256Hex(token)}:${deviceId}:${kind}:${releaseId}`;
  const exp = tickets.get(key);
  if (!exp || exp <= Date.now()) {
    return jsonResponse({ allowed: false, reason: "authorization_required" }, 403);
  }

  const source = getUpstreams()[releaseId];
  if (!source) {
    return jsonResponse({ allowed: false, reason: "upstream_not_configured" }, 503);
  }

  const upstreamHeaders = new Headers({
    Accept: "*/*",
    "Accept-Encoding": "identity",
  });
  const rangeHeader = req.headers.get("Range");
  if (rangeHeader && req.method === "GET") {
    upstreamHeaders.set("Range", rangeHeader);
  }

  const upstreamRes = await fetch(source, {
    method: req.method,
    headers: upstreamHeaders,
    redirect: "follow",
  });

  if (upstreamRes.status !== 200 && upstreamRes.status !== 206) {
    return jsonResponse({ allowed: false, reason: "upstream_status_or_mime" }, 503);
  }

  const outHeaders = new Headers({
    "Content-Type":
      kind === "app"
        ? "application/vnd.android.package-archive"
        : "application/zip",
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  const cl = upstreamRes.headers.get("Content-Length");
  if (cl) outHeaders.set("Content-Length", cl);
  const cr = upstreamRes.headers.get("Content-Range");
  if (cr) outHeaders.set("Content-Range", cr);

  return new Response(req.method === "HEAD" ? null : upstreamRes.body, {
    status: upstreamRes.status,
    headers: outHeaders,
  });
}

export default async function handler(req) {
  const url = new URL(req.url);
  const rawPath = url.searchParams.get("__path") || url.pathname;
  const pathname = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  const origin = url.origin;

  if (req.method === "GET" && (pathname === "/" || pathname === "/health")) {
    return jsonResponse({ ok: true, service: "shaif-license-proxy-vercel" });
  }
  if (req.method === "POST" && pathname === "/api/mobile/activate") {
    return await forwardJsonToManus(req, origin, pathname, null);
  }
  if (req.method === "POST" && pathname === "/api/mobile/status") {
    return await forwardJsonToManus(req, origin, pathname, null);
  }
  if (req.method === "POST" && pathname === "/api/mobile/library/authorize") {
    return await forwardJsonToManus(req, origin, pathname, "library");
  }
  if (req.method === "POST" && pathname === "/api/mobile/app/authorize") {
    return await forwardJsonToManus(req, origin, pathname, "app");
  }

  const m = /^\/api\/mobile\/files\/(library|app)\/([^/]+)$/.exec(pathname);
  if (m && (req.method === "GET" || req.method === "HEAD")) {
    return await handleFileDownload(req, m[1], m[2]);
  }

  return jsonResponse({ allowed: false }, 404);
}
