/**
 * OpenFuse Registry — DNS management API for agent discovery.
 * Creates DNS TXT records at _openfuse.{name}.openfused.net on registration.
 * Reads go through DNS directly — no Worker needed for discovery.
 * R2 is optional future social profile layer (not protocol).
 */

interface Env {
  REGISTRY: R2Bucket;     // Future: social profiles, not protocol
  CF_DNS_TOKEN: string;   // API token with DNS write perms
  CF_ZONE_ID: string;     // openfused.net zone ID
  DNS_DOMAIN: string;     // "openfused.net"
}

interface RegisterRequest {
  name: string;
  endpoint?: string;
  publicKey: string;
  encryptionKey?: string;
  fingerprint: string;
  signature: string;
  signedAt: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // GET / — service info + latest version
      if (path === "/" && request.method === "GET") {
        // Fetch latest version from npm instead of hardcoding
        let latest = "0.3.13"; // fallback
        try {
          const npm = await fetch("https://registry.npmjs.org/openfused/latest", {
            signal: AbortSignal.timeout(2000),
          });
          if (npm.ok) {
            const data = await npm.json() as { version?: string };
            if (data.version) latest = data.version;
          }
        } catch {}
        return json({
          service: "openfuse-registry",
          version: "0.4.0",
          latest,
          dns: `*.${env.DNS_DOMAIN}`,
          changelog: "https://github.com/openfused/openfused/releases",
          discovery: "dig TXT _openfuse.{name}.openfused.net",
        });
      }

      // POST /register — validate signature, create DNS TXT record
      if (path === "/register" && request.method === "POST") {
        const rl = await checkRateLimit(env, request);
        if (rl) return rl;
        return await register(env, await request.text());
      }

      // POST /revoke — remove DNS TXT record (signed by key owner)
      if (path === "/revoke" && request.method === "POST") {
        const rl = await checkRateLimit(env, request);
        if (rl) return rl;
        return await revoke(env, await request.text());
      }

      // GET /discover/{name} — fallback for clients without DNS resolution
      if (path.startsWith("/discover/") && request.method === "GET") {
        const name = path.slice("/discover/".length).replace(/[^a-zA-Z0-9_-]/g, "");
        return await discoverFallback(env, name);
      }

      return json({ error: "Not found" }, 404);
    } catch (e: any) {
      return json({ error: e.message || "Internal error" }, 500);
    }
  },
};

// --- Rate limiting via R2 (zero extra bindings) ---

async function checkRateLimit(env: Env, request: Request): Promise<Response | null> {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const rateLimitKey = `_ratelimit/${ip}`;
  const recent = await env.REGISTRY.get(rateLimitKey);
  if (recent) {
    const ts = await recent.text();
    if (Date.now() - new Date(ts).getTime() < 60_000) {
      return json({ error: "Rate limited — try again in 60 seconds" }, 429);
    }
  }
  await env.REGISTRY.put(rateLimitKey, new Date().toISOString());
  return null;
}

// --- Registration: validate signature → create DNS TXT record ---

async function register(env: Env, body: string): Promise<Response> {
  let req: RegisterRequest;
  try {
    req = JSON.parse(body);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  if (!req.name || !req.publicKey || !req.fingerprint || !req.signature || !req.signedAt) {
    return json({ error: "Missing required fields" }, 400);
  }

  // Validate field formats — prevent TXT record injection via spaces/= in values
  if (/[\s=]/.test(req.publicKey)) return json({ error: "publicKey contains invalid characters" }, 400);
  if (/[\s=]/.test(req.fingerprint)) return json({ error: "fingerprint contains invalid characters" }, 400);
  if (req.encryptionKey && /[\s=]/.test(req.encryptionKey)) return json({ error: "encryptionKey contains invalid characters" }, 400);
  // publicKey: must be 64-char hex (Ed25519)
  if (!/^[0-9a-fA-F]{64}$/.test(req.publicKey)) return json({ error: "publicKey must be 64-char hex" }, 400);
  // fingerprint: colon-separated hex pairs (e.g. A1B2:C3D4:E5F6:7890:...)
  if (!/^[0-9a-fA-F]{4}(:[0-9a-fA-F]{4}){7}$/.test(req.fingerprint)) return json({ error: "fingerprint must be colon-separated hex (e.g. A1B2:C3D4:...)" }, 400);
  // encryptionKey: age public key format
  if (req.encryptionKey && !/^age1[a-z0-9]{58}$/.test(req.encryptionKey)) return json({ error: "encryptionKey must be a valid age public key" }, 400);
  const safeName = req.name.replace(/[^a-zA-Z0-9_-]/g, "");
  if (safeName !== req.name) return json({ error: "Name: a-z, 0-9, -, _ only" }, 400);
  if (safeName.length > 64) return json({ error: "Name too long (max 64)" }, 400);
  if (safeName.length < 2) return json({ error: "Name too short (min 2)" }, 400);

  // Validate endpoint if provided — must be a URL, not arbitrary text/scripts
  if (req.endpoint) {
    if (/\s/.test(req.endpoint)) return json({ error: "endpoint contains whitespace" }, 400);
    try {
      const url = new URL(req.endpoint);
      if (!["http:", "https:"].includes(url.protocol)) {
        return json({ error: "Public registry requires http:// or https:// endpoint. SSH peers go in your local address book." }, 400);
      }
    } catch {
      return json({ error: "Invalid endpoint URL" }, 400);
    }
  }

  // Reject stale signatures — prevents replay of captured registration requests
  const signedAge = Date.now() - new Date(req.signedAt).getTime();
  if (isNaN(signedAge) || Math.abs(signedAge) > 5 * 60 * 1000) {
    return json({ error: "Signature expired — signedAt must be within 5 minutes" }, 403);
  }

  // Verify Ed25519 signature
  const canonical = `${req.name}|${req.endpoint || ""}|${req.publicKey}|${req.encryptionKey || ""}`;
  const payload = `${req.name}\n${req.signedAt}\n${canonical}`;
  const valid = await verifyEd25519(payload, req.signature, req.publicKey);
  if (!valid) {
    return json({ error: "Invalid signature" }, 403);
  }

  // Anti-squatting: check if name is already taken by a different key
  const existing = await lookupDnsTxt(env, safeName);
  if (existing) {
    const fields = parseTxt(existing);
    if (fields.pk && fields.pk !== req.publicKey) {
      return json({ error: `Name '${safeName}' is registered to a different key` }, 409);
    }
  }

  // Verify endpoint is live (if provided) — HEAD /profile must return 200.
  // Block private/loopback IPs to prevent SSRF against internal services.
  if (req.endpoint) {
    try {
      const endpointUrl = new URL(req.endpoint);
      const hostname = endpointUrl.hostname.replace(/^\[|\]$/g, "");
      if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.|localhost$|::1$|0\.0\.0\.0$)/.test(hostname)
        || /^(fc|fd|fe80)/i.test(hostname)
        || /^::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname)
        || /^\d+$/.test(hostname)) {
        return json({ error: "Endpoint verification failed" }, 422);
      }
      const probe = await fetch(`${req.endpoint.replace(/\/$/, "")}/profile`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
        redirect: "error",
      });
      if (!probe.ok) {
        return json({ error: "Endpoint verification failed" }, 422);
      }
    } catch {
      return json({ error: "Endpoint verification failed" }, 422);
    }
  }

  // Create DNS TXT record
  const txtContent = `v=of1 e=${req.endpoint || ""} pk=${req.publicKey} ek=${req.encryptionKey || ""} fp=${req.fingerprint}`;
  await upsertDnsTxt(env, safeName, txtContent);

  return json({
    ok: true,
    name: safeName,
    dns: `_openfuse.${safeName}.${env.DNS_DOMAIN}`,
    fingerprint: req.fingerprint,
  }, 201);
}

// --- Revocation: validate signature → delete DNS TXT ---

async function revoke(env: Env, body: string): Promise<Response> {
  let req: { name: string; signature: string; signedAt: string };
  try {
    req = JSON.parse(body);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  if (!req.name || !req.signature || !req.signedAt) {
    return json({ error: "Missing required fields" }, 400);
  }

  const safeName = req.name.replace(/[^a-zA-Z0-9_-]/g, "");

  // Look up current key from DNS
  const existing = await lookupDnsTxt(env, safeName);
  if (!existing) return json({ error: `Agent '${safeName}' not found` }, 404);

  const fields = parseTxt(existing);
  if (!fields.pk) return json({ error: "Corrupted DNS record" }, 500);

  // Reject stale signatures — prevents replay of captured revocation requests
  const signedAge = Date.now() - new Date(req.signedAt).getTime();
  if (isNaN(signedAge) || Math.abs(signedAge) > 5 * 60 * 1000) {
    return json({ error: "Signature expired — signedAt must be within 5 minutes" }, 403);
  }

  // Verify revocation is signed by the registered key
  const payload = `${req.name}\n${req.signedAt}\nREVOKE:${fields.pk}`;
  const valid = await verifyEd25519(payload, req.signature, fields.pk);
  if (!valid) return json({ error: "Invalid signature — must be signed by the registered key" }, 403);

  // Delete DNS record
  await deleteDnsTxt(env, safeName);

  return json({ ok: true, name: safeName, status: "revoked" });
}

// --- Discovery fallback (for clients without DNS resolution) ---

async function discoverFallback(env: Env, name: string): Promise<Response> {
  const txt = await lookupDnsTxt(env, name);
  if (!txt) return json({ error: `Agent '${name}' not found` }, 404);

  const fields = parseTxt(txt);
  return json({
    name,
    endpoint: fields.e || "",
    publicKey: fields.pk || "",
    encryptionKey: fields.ek || undefined,
    fingerprint: fields.fp || "",
    capabilities: ["inbox", "shared", "knowledge"],
    dns: `_openfuse.${name}.${env.DNS_DOMAIN}`,
  });
}

// --- DNS TXT management ---

async function lookupDnsTxt(env: Env, name: string): Promise<string | null> {
  const recordName = `_openfuse.${name}.${env.DNS_DOMAIN}`;
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?type=TXT&name=${recordName}`,
    { headers: { "Authorization": `Bearer ${env.CF_DNS_TOKEN}`, "Content-Type": "application/json" } }
  );
  const data = await resp.json() as { result?: { content: string }[] };
  if (data.result && data.result.length > 0) return data.result[0].content;
  return null;
}

async function upsertDnsTxt(env: Env, name: string, content: string): Promise<void> {
  const recordName = `_openfuse.${name}.${env.DNS_DOMAIN}`;
  const baseUrl = `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`;
  const headers = { "Authorization": `Bearer ${env.CF_DNS_TOKEN}`, "Content-Type": "application/json" };

  // Delete existing record if any
  const search = await fetch(`${baseUrl}?type=TXT&name=${recordName}`, { headers });
  const data = await search.json() as { result?: { id: string }[] };
  if (data.result && data.result.length > 0) {
    await fetch(`${baseUrl}/${data.result[0].id}`, { method: "DELETE", headers });
  }

  // Create new record
  await fetch(baseUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({ type: "TXT", name: recordName, content, ttl: 300 }),
  });
}

async function deleteDnsTxt(env: Env, name: string): Promise<void> {
  const recordName = `_openfuse.${name}.${env.DNS_DOMAIN}`;
  const baseUrl = `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`;
  const headers = { "Authorization": `Bearer ${env.CF_DNS_TOKEN}`, "Content-Type": "application/json" };

  const search = await fetch(`${baseUrl}?type=TXT&name=${recordName}`, { headers });
  const data = await search.json() as { result?: { id: string }[] };
  if (data.result && data.result.length > 0) {
    await fetch(`${baseUrl}/${data.result[0].id}`, { method: "DELETE", headers });
  }
}

function parseTxt(txt: string): Record<string, string> {
  // Strip surrounding quotes — DNS API wraps TXT values in double quotes
  const clean = txt.replace(/^"+|"+$/g, "");
  const fields: Record<string, string> = {};
  for (const part of clean.split(" ")) {
    const eq = part.indexOf("=");
    if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1).replace(/"/g, "");
  }
  return fields;
}

// --- Ed25519 via Web Crypto ---

async function verifyEd25519(message: string, signatureB64: string, publicKeyHex: string): Promise<boolean> {
  try {
    const keyBytes = hexToBytes(publicKeyHex);
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
    const sigBytes = base64ToBytes(signatureB64);
    const msgBytes = new TextEncoder().encode(message);
    return await crypto.subtle.verify("Ed25519", key, sigBytes, msgBytes);
  } catch {
    return false;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function json(data: any, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2) + "\n", {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json" },
  });
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}
