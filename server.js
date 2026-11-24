import http from "node:http";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";

const PORT = Number(process.env.PORT || 10000);
const MANUS_ORIGIN = (process.env.MANUS_ORIGIN || "https://licensectrl-cqjuixq7.manus.space").replace(/\/$/, "");
const WINDOW_MS = 5 * 60 * 1000;
const TICKET_TTL_MS = 30 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ALLOWED_CLIENT_CERTS = new Set([
  "A40DA80A59D170CAA950CF15C18C454D47A39B26989D8B640ECD745BA71BF5DC", // MT Manager Testkey
  "3F7C184C9033B34B4ACA2B9AE9395E175DD3E6A4B1E76E62190F250DEB07D819", // shaif.keystore
]);
const MANUS_EXPECTED_CERT = "E34A3D79627CB495F2E05E454726328E757C391CD10460719BD81B2259650158";

// Built-in verified upstreams (extend anytime via Render env var RELEASE_UPSTREAMS_JSON)
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

// In-memory 30-minute download tickets bound to (sha256(token), deviceId, kind, releaseId)
const tickets = new Map();

function pruneTickets() {
  const now = Date.now();
  for (const [k, v] of tickets.entries()) {
    if (v.expiresAt <= now) tickets.delete(k);
  }
}

function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req, limitBytes = 65536) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > limitBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function extractBearer(req) {
  const auth = req.headers["authorization"] || "";
  const m = /^Bearer ([A-Za-z0-9_-]{43,256})$/.exec(String(auth));
  return m ? m[1] : null;
}

function publicOrigin(req) {
  if (process.env.RENDER_EXTERNAL_URL) {
    return process.env.RENDER_EXTERNAL_URL.replace(/\/$/, "");
  }
  const host = req.headers["x-forwarded-host"] || req.headers["host"];
  return `https://${host}`;
}

async function forwardJsonToManus(req, res, pathname, rewriteAuthorizeKind = null) {
  let rawBody = await readBody(req);

  if (pathname === "/api/mobile/activate" && rawBody.length > 0) {
    try {
      const parsed = JSON.parse(rawBody.toString("utf8"));
      const sentCert =
        typeof parsed?.certificate_sha256 === "string"
          ? parsed.certificate_sha256.toUpperCase()
          : "";
      if (ALLOWED_CLIENT_CERTS.has(sentCert)) {
        parsed.certificate_sha256 = MANUS_EXPECTED_CERT;
        rawBody = Buffer.from(JSON.stringify(parsed), "utf8");
      }
    } catch {}
  }

  const headers = {};
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
    const val = req.headers[name];
    if (val !== undefined) headers[name] = String(val);
  }

  const upstreamRes = await fetch(`${MANUS_ORIGIN}${pathname}`, {
    method: "POST",
    headers,
    body: rawBody,
    redirect: "manual",
  });

  const text = await upstreamRes.text();
  if (!rewriteAuthorizeKind || upstreamRes.status !== 200) {
    res.writeHead(upstreamRes.status, {
      "Content-Type": upstreamRes.headers.get("content-type") || "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Length": Buffer.byteLength(text),
    });
    res.end(text);
    return;
  }

  const payload = JSON.parse(text);
  if (payload && payload.allowed === true && typeof payload.url === "string") {
    const m = /\/api\/mobile\/files\/(library|app)\/([A-Za-z0-9_-]{1,128})$/.exec(payload.url);
    if (m) {
      const [, kind, releaseId] = m;
      const token = extractBearer(req);
      const deviceId = String(req.headers["x-device-id"] || "");
      if (token && deviceId) {
        pruneTickets();
        const key = `${sha256Hex(token)}:${deviceId}:${kind}:${releaseId}`;
        tickets.set(key, {
          expiresAt: Date.now() + TICKET_TTL_MS,
          sizeBytes: payload.size_bytes,
          sha256: payload.sha256,
        });
      }
      payload.url = `${publicOrigin(req)}/api/mobile/files/${kind}/${releaseId}`;
    }
  }

  sendJson(res, 200, payload);
}

async function handleFileDownload(req, res, kind, releaseId) {
  if (!UUID_RE.test(releaseId)) {
    return sendJson(res, 400, { allowed: false, reason: "invalid_request" });
  }

  const token = extractBearer(req);
  const deviceId = String(req.headers["x-device-id"] || "");
  const timestamp = Number(req.headers["x-request-time"] || "0");
  const nonce = String(req.headers["x-request-nonce"] || "");
  const signature = String(req.headers["x-request-signature"] || "");

  if (
    !token ||
    deviceId.length < 8 ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(Date.now() - timestamp) > WINDOW_MS ||
    !UUID_RE.test(nonce) ||
    signature.length < 16
  ) {
    return sendJson(res, 403, { allowed: false, reason: "invalid_request" });
  }

  pruneTickets();
  const key = `${sha256Hex(token)}:${deviceId}:${kind}:${releaseId}`;
  const ticket = tickets.get(key);
  if (!ticket || ticket.expiresAt <= Date.now()) {
    return sendJson(res, 403, { allowed: false, reason: "authorization_required" });
  }

  const source = getUpstreams()[releaseId];
  if (!source) {
    return sendJson(res, 503, { allowed: false, reason: "upstream_not_configured" });
  }

  const upstreamHeaders = {
    Accept: "*/*",
    "Accept-Encoding": "identity",
  };
  if (req.headers["range"] && req.method === "GET") {
    upstreamHeaders["Range"] = String(req.headers["range"]);
  }

  const controller = new AbortController();
  req.on("close", () => {
    if (!res.writableEnded) controller.abort();
  });

  const upstreamRes = await fetch(source, {
    method: req.method,
    headers: upstreamHeaders,
    redirect: "follow",
    signal: controller.signal,
  });

  if (upstreamRes.status !== 200 && upstreamRes.status !== 206) {
    return sendJson(res, 503, { allowed: false, reason: "upstream_status_or_mime" });
  }

  const outHeaders = {
    "Content-Type":
      kind === "app" ? "application/vnd.android.package-archive" : "application/zip",
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  const cl = upstreamRes.headers.get("content-length");
  if (cl) outHeaders["Content-Length"] = cl;
  const cr = upstreamRes.headers.get("content-range");
  if (cr) outHeaders["Content-Range"] = cr;

  res.writeHead(upstreamRes.status, outHeaders);
  if (req.method === "HEAD" || !upstreamRes.body) {
    res.end();
    return;
  }

  const nodeStream = Readable.fromWeb(upstreamRes.body);
  nodeStream.on("error", () => {
    if (!res.destroyed) res.destroy();
  });
  nodeStream.pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", "http://localhost");
    const { pathname } = url;

    if (req.method === "GET" && pathname === "/health") {
      return sendJson(res, 200, { ok: true, service: "shaif-license-proxy" });
    }
    if (req.method === "POST" && pathname === "/api/mobile/activate") {
      return await forwardJsonToManus(req, res, pathname, null);
    }
    if (req.method === "POST" && pathname === "/api/mobile/status") {
      return await forwardJsonToManus(req, res, pathname, null);
    }
    if (req.method === "POST" && pathname === "/api/mobile/library/authorize") {
      return await forwardJsonToManus(req, res, pathname, "library");
    }
    if (req.method === "POST" && pathname === "/api/mobile/app/authorize") {
      return await forwardJsonToManus(req, res, pathname, "app");
    }

    const m = /^\/api\/mobile\/files\/(library|app)\/([^/]+)$/.exec(pathname);
    if (m && (req.method === "GET" || req.method === "HEAD")) {
      return await handleFileDownload(req, res, m[1], m[2]);
    }

    sendJson(res, 404, { allowed: false });
  } catch (err) {
    if (!res.headersSent) {
      sendJson(res, 503, { allowed: false, reason: "proxy_error" });
    } else if (!res.destroyed) {
      res.destroy();
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`shaif-license-proxy listening on port ${PORT}`);
});
