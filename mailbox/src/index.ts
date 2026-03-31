/**
 * OpenFuse Free Mailbox — multi-tenant hosted inbox for AI agents.
 *
 * All agents share one R2 bucket, namespaced by {name}-{fingerprint}/.
 * DNS TXT records at _openfuse.{name}.openfused.net are the authoritative
 * key registry. No signup needed — just `openfuse register` and you have an inbox.
 *
 * Routes:
 *   GET  /                    — service info
 *   HEAD /profile             — endpoint verification (always 200)
 *   GET  /profile/{name}      — agent's profile
 *   POST /inbox               — receive message (?to={name} for routing)
 *   POST /inbox/{name}        — receive message (name in path)
 *   GET  /outbox/{name}       — pull your messages (challenge auth)
 *   DELETE /outbox/{name}/{f} — ACK a message (challenge auth)
 */

interface Env {
  MAILBOX: R2Bucket;
  DNS_DOMAIN: string;     // "openfused.net"
  REGISTRY_URL: string;   // "https://registry.openfused.dev"
}

interface DnsTxtFields {
  pk?: string;   // publicKey (64-char hex)
  ek?: string;   // encryptionKey (age1...)
  fp?: string;   // fingerprint (colon-separated)
  e?: string;    // endpoint
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(request) });
    }

    try {
      // --- Service info ---
      if (path === "/" && request.method === "GET") {
        return json({
          service: "openfuse-mailbox",
          description: "Free hosted inbox for AI agents. https://openfused.dev",
          register: "openfuse register --endpoint https://inbox.openfused.dev",
        });
      }

      // --- Endpoint verification (registry probes HEAD /profile) ---
      if (path === "/profile" && (request.method === "HEAD" || request.method === "GET")) {
        return new Response("OpenFuse free mailbox — register at openfused.dev", {
          status: 200,
          headers: { ...corsHeaders(), "Content-Type": "text/plain" },
        });
      }

      // --- Agent profile ---
      if (path.startsWith("/profile/") && request.method === "GET") {
        const name = sanitize(path.slice("/profile/".length));
        if (!name) return json({ error: "Invalid name" }, 400);

        const fields = await lookupAgent(env, name);
        if (!fields?.pk) return json({ error: `Agent '${name}' not found` }, 404);

        const fp8 = (await sha256hex(fields.pk)).slice(0, 8).toUpperCase();
        const obj = await env.MAILBOX.get(`${name}-${fp8}/profile.md`);
        if (!obj) return json({ error: "No profile set" }, 404);

        return new Response(await obj.text(), {
          headers: { ...corsHeaders(), "Content-Type": "text/plain; charset=utf-8" },
        });
      }

      // --- Receive inbox message ---
      if ((path === "/inbox" || path.startsWith("/inbox/")) && request.method === "POST") {
        return await receiveInbox(env, request, path, url);
      }

      // --- Pull outbox (challenge auth) ---
      if (path.startsWith("/outbox/") && request.method === "GET") {
        const parts = path.slice("/outbox/".length).split("/");
        const name = sanitize(parts[0]);
        if (!name) return json({ error: "Invalid name" }, 400);
        return await getOutbox(env, name, request.headers);
      }

      // --- ACK outbox message ---
      if (path.startsWith("/outbox/") && request.method === "DELETE") {
        const parts = path.slice("/outbox/".length).split("/");
        const name = sanitize(parts[0]);
        const file = sanitize(parts[1] || "");
        if (!name || !file) return json({ error: "Invalid path" }, 400);
        return await ackOutbox(env, name, file, request.headers);
      }

      return json({ error: "Not found" }, 404);
    } catch (e: any) {
      return json({ error: e.message || "Internal error" }, 500);
    }
  },
};

// ---------------------------------------------------------------------------
// Inbox: receive a signed message
// ---------------------------------------------------------------------------

async function receiveInbox(
  env: Env,
  request: Request,
  path: string,
  url: URL,
): Promise<Response> {
  // Rate limit: 1 message per sender IP per 10 seconds
  // (We can't use R2 rate limiting easily here, so we rely on CF's built-in
  // DDoS protection + the signature verification cost as a natural throttle.)

  const body = await request.text();
  let msg: any;
  try {
    msg = JSON.parse(body);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  // Validate required fields
  if (!msg.from || !msg.signature || !msg.publicKey || !msg.timestamp || !msg.message) {
    return json({ error: "Missing required fields: from, signature, publicKey, timestamp, message" }, 400);
  }

  // Verify Ed25519 signature
  const payload = `${msg.from}\n${msg.timestamp}\n${msg.message}`;
  if (!await verifyEd25519(payload, msg.signature, msg.publicKey)) {
    return json({ error: "Invalid signature" }, 403);
  }

  // Reject stale messages — prevents replay of captured signed messages
  const msgAge = Date.now() - new Date(msg.timestamp).getTime();
  if (isNaN(msgAge) || Math.abs(msgAge) > 10 * 60 * 1000) {
    return json({ error: "Message timestamp expired (10 minute window)" }, 403);
  }

  // Determine recipient name — from path or query param
  let recipientName = "";
  if (path.startsWith("/inbox/")) {
    recipientName = sanitize(path.slice("/inbox/".length));
  }
  if (!recipientName) {
    recipientName = sanitize(url.searchParams.get("to") || "");
  }
  if (!recipientName) {
    return json({ error: "Recipient required: POST /inbox/{name} or POST /inbox?to={name}" }, 400);
  }

  // Look up recipient from DNS to get their fingerprint
  const recipient = await lookupAgent(env, recipientName);
  if (!recipient?.pk) {
    return json({ error: `Agent '${recipientName}' not registered` }, 404);
  }

  // Verify recipient's endpoint is inbox.openfused.dev (they opted into hosted mailbox).
  // Use URL origin comparison, not string prefix — prevents bypass via
  // "https://inbox.openfused.dev.evil.com" matching a startsWith check.
  if (recipient.e) {
    try {
      const endpointOrigin = new URL(recipient.e).origin;
      if (endpointOrigin !== "https://inbox.openfused.dev") {
        return json({
          error: `Agent '${recipientName}' has endpoint ${recipient.e} — deliver directly, not via hosted mailbox`,
        }, 422);
      }
    } catch {
      return json({ error: `Agent '${recipientName}' has invalid endpoint` }, 422);
    }
  }

  // Compute namespace
  const recipientFp = (await sha256hex(recipient.pk)).slice(0, 8).toUpperCase();
  const safeFrom = sanitize(msg.from);
  const senderFp = (await sha256hex(msg.publicKey)).slice(0, 8);
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const key = `${recipientName}-${recipientFp}/inbox/${ts}_from-${safeFrom}-${senderFp}.json`;
  await env.MAILBOX.put(key, body);

  return json({ ok: true, delivered: recipientName }, 201);
}

// ---------------------------------------------------------------------------
// Outbox: pull your messages (challenge-response auth)
// ---------------------------------------------------------------------------

async function getOutbox(
  env: Env,
  name: string,
  headers: Headers,
): Promise<Response> {
  const pubkeyHex = headers.get("x-openfuse-publickey");
  const sigB64 = headers.get("x-openfuse-signature");
  const timestamp = headers.get("x-openfuse-timestamp");

  if (!pubkeyHex || !sigB64 || !timestamp) {
    return json({ error: "Authentication required: X-OpenFuse-PublicKey, X-OpenFuse-Signature, X-OpenFuse-Timestamp" }, 401);
  }

  // Verify timestamp freshness (5 minute window)
  const age = Date.now() - new Date(timestamp).getTime();
  if (isNaN(age) || Math.abs(age) > 300_000) {
    return json({ error: "Timestamp expired (5 minute window)" }, 401);
  }

  // Verify challenge signature: "OUTBOX:{name}:{timestamp}"
  const challenge = `OUTBOX:${name}:${timestamp}`;
  if (!await verifyEd25519(challenge, sigB64, pubkeyHex)) {
    return json({ error: "Invalid signature" }, 403);
  }

  // Verify the public key matches the registered agent
  const agent = await lookupAgent(env, name);
  if (!agent?.pk || agent.pk !== pubkeyHex) {
    return json({ error: "Public key does not match registered key for this agent" }, 403);
  }

  // List messages in this agent's namespace
  const fp8 = (await sha256hex(pubkeyHex)).slice(0, 8).toUpperCase();
  const prefix = `${name}-${fp8}/inbox/`;
  const listed = await env.MAILBOX.list({ prefix });

  const messages: any[] = [];
  for (const obj of listed.objects) {
    // Skip archived messages
    if (obj.key.includes("/.read/")) continue;
    if (!obj.key.endsWith(".json")) continue;

    const data = await env.MAILBOX.get(obj.key);
    if (data) {
      try {
        const msg = JSON.parse(await data.text());
        msg._outboxFile = obj.key.split("/").pop();
        messages.push(msg);
      } catch {}
    }
  }

  return json(messages);
}

// ---------------------------------------------------------------------------
// ACK: mark a message as read (move to .read/)
// ---------------------------------------------------------------------------

async function ackOutbox(
  env: Env,
  name: string,
  file: string,
  headers: Headers,
): Promise<Response> {
  const pubkeyHex = headers.get("x-openfuse-publickey");
  const sigB64 = headers.get("x-openfuse-signature");
  const timestamp = headers.get("x-openfuse-timestamp");

  if (!pubkeyHex || !sigB64 || !timestamp) {
    return json({ error: "Auth required" }, 401);
  }

  const age = Date.now() - new Date(timestamp).getTime();
  if (isNaN(age) || Math.abs(age) > 300_000) {
    return json({ error: "Expired" }, 401);
  }

  const challenge = `ACK:${name}:${file}:${timestamp}`;
  if (!await verifyEd25519(challenge, sigB64, pubkeyHex)) {
    return json({ error: "Invalid signature" }, 403);
  }

  // Verify key ownership
  const agent = await lookupAgent(env, name);
  if (!agent?.pk || agent.pk !== pubkeyHex) {
    return json({ error: "Key mismatch" }, 403);
  }

  const fp8 = (await sha256hex(pubkeyHex)).slice(0, 8).toUpperCase();
  const srcKey = `${name}-${fp8}/inbox/${file}`;
  const obj = await env.MAILBOX.get(srcKey);
  if (!obj) {
    return json({ error: "Message not found" }, 404);
  }

  // Move to .read/
  const dstKey = `${name}-${fp8}/inbox/.read/${file}`;
  await env.MAILBOX.put(dstKey, await obj.text());
  await env.MAILBOX.delete(srcKey);

  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// DNS lookup: resolve agent's public key + fingerprint from registry
// ---------------------------------------------------------------------------

async function lookupAgent(env: Env, name: string): Promise<DnsTxtFields | null> {
  // Try registry API first (faster than DNS for Workers)
  try {
    const res = await fetch(`${env.REGISTRY_URL}/discover/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const data = await res.json() as any;
      // Validate publicKey format — 64-char hex (Ed25519)
      if (data.publicKey && !/^[0-9a-fA-F]{64}$/.test(data.publicKey)) {
        return null;
      }
      return {
        pk: data.publicKey,
        ek: data.encryptionKey,
        fp: data.fingerprint,
        e: data.endpoint,
      };
    }
    // Registry returned non-200 (e.g., 404) — agent not found
    return null;
  } catch (e) {
    // Network error or timeout — registry unavailable, not "not found"
    throw new Error("Registry unavailable — try again later");
  }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

async function verifyEd25519(
  message: string,
  signatureB64: string,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    const keyBytes = hexToBytes(publicKeyHex);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sigBytes = base64ToBytes(signatureB64);
    const msgBytes = new TextEncoder().encode(message);
    return await crypto.subtle.verify("Ed25519", key, sigBytes, msgBytes);
  } catch {
    return false;
  }
}

async function sha256hex(input: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function sanitize(s: string): string {
  return s.replace(/[^a-zA-Z0-9_-]/g, "");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function json(data: any, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2) + "\n", {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json" },
  });
}

function corsHeaders(request?: Request): Record<string, string> {
  // Restrict CORS to known origins — don't allow arbitrary sites to read inbox data.
  const allowed = ["https://openfused.dev", "https://claude.ai"];
  let origin = "";
  if (request) {
    const reqOrigin = request.headers.get("origin") || "";
    if (allowed.includes(reqOrigin)) origin = reqOrigin;
  }
  return {
    "Access-Control-Allow-Origin": origin || allowed[0],
    "Access-Control-Allow-Methods": "GET, POST, DELETE, HEAD, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, X-OpenFuse-PublicKey, X-OpenFuse-Signature, X-OpenFuse-Timestamp",
    "Vary": "Origin",
  };
}
