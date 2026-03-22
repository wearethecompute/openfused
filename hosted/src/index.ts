/**
 * OpenFused Hosted Mailbox — R2-backed agent context store.
 * Same API as the Rust daemon, backed by object storage instead of filesystem.
 * Each customer gets their own Worker + R2 bucket via Workers for Platforms.
 *
 * Endpoints:
 *   GET  /           — service info
 *   GET  /profile    — PROFILE.md
 *   GET  /config     — public keys
 *   POST /inbox      — receive signed messages
 *   GET  /outbox/:n  — pickup replies (auth challenge)
 *   GET  /shared/:f  — read shared files
 *   PUT  /shared/:f  — write shared files (owner only)
 *   GET  /context    — read CONTEXT.md
 *   PUT  /context    — update CONTEXT.md (owner only)
 */

interface Env {
  STORE: R2Bucket;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // --- Public endpoints ---

      if (path === "/" && request.method === "GET") {
        return json({ service: "openfused-mailbox", version: "0.1.0" });
      }

      if (path === "/profile" && request.method === "GET") {
        return await getFile(env, "PROFILE.md");
      }

      if (path === "/config" && request.method === "GET") {
        return await getConfig(env);
      }

      // --- Inbox (POST only, signature verified) ---

      if (path === "/inbox" && request.method === "POST") {
        return await receiveInbox(env, await request.text());
      }

      // --- Outbox (authenticated pickup) ---

      if (path.startsWith("/outbox/") && request.method === "GET") {
        const name = path.slice("/outbox/".length).replace(/[^a-zA-Z0-9_-]/g, "");
        return await getOutbox(env, name, request.headers);
      }

      // --- Shared files (public read) ---

      if (path.startsWith("/shared/") && request.method === "GET") {
        const file = path.slice("/shared/".length).replace(/[^a-zA-Z0-9._-]/g, "");
        if (!file || file.includes("..")) return json({ error: "Invalid path" }, 400);
        return await getFile(env, `shared/${file}`);
      }

      // --- Context (public read) ---

      if (path === "/context" && request.method === "GET") {
        return await getFile(env, "CONTEXT.md");
      }

      return json({ error: "Not found" }, 404);
    } catch (e: any) {
      return json({ error: e.message || "Internal error" }, 500);
    }
  },
};

// --- File helpers ---

async function getFile(env: Env, key: string): Promise<Response> {
  const obj = await env.STORE.get(key);
  if (!obj) return json({ error: "Not found" }, 404);
  const body = await obj.text();
  return new Response(body, {
    headers: { ...corsHeaders(), "Content-Type": key.endsWith(".json") ? "application/json" : "text/plain" },
  });
}

async function getConfig(env: Env): Promise<Response> {
  const obj = await env.STORE.get(".mesh.json");
  if (!obj) return json({ error: "Not configured" }, 404);
  const config = JSON.parse(await obj.text());
  // Only expose public fields
  return json({
    id: config.id,
    name: config.name,
    publicKey: config.publicKey,
    encryptionKey: config.encryptionKey,
  });
}

// --- Inbox ---

async function receiveInbox(env: Env, body: string): Promise<Response> {
  let msg: any;
  try {
    msg = JSON.parse(body);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const from = msg.from;
  const signature = msg.signature;
  const publicKey = msg.publicKey;
  const timestamp = msg.timestamp;
  const message = msg.message;

  if (!from || !signature || !publicKey || !timestamp || !message) {
    return json({ error: "Missing required fields" }, 400);
  }

  // Verify Ed25519 signature
  const payload = `${from}\n${timestamp}\n${message}`;
  const valid = await verifyEd25519(payload, signature, publicKey);
  if (!valid) {
    return json({ error: "Invalid signature" }, 403);
  }

  // Get our name for the envelope filename
  const configObj = await env.STORE.get(".mesh.json");
  const ourName = configObj ? JSON.parse(await configObj.text()).name || "unknown" : "unknown";

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const safeFrom = from.replace(/[^a-zA-Z0-9_-]/g, "");
  const key = `inbox/${ts}_from-${safeFrom}_to-${ourName}.json`;

  await env.STORE.put(key, body);

  return json({ ok: true }, 201);
}

// --- Outbox (authenticated) ---

async function getOutbox(env: Env, name: string, headers: Headers): Promise<Response> {
  // Require signature challenge: OUTBOX:{name}:{timestamp}
  const pubkeyHex = headers.get("x-openfuse-publickey");
  const sigB64 = headers.get("x-openfuse-signature");
  const timestamp = headers.get("x-openfuse-timestamp");

  if (!pubkeyHex || !sigB64 || !timestamp) {
    return json({ error: "Authentication required" }, 401);
  }

  // Verify timestamp freshness (5 min window)
  const age = Date.now() - new Date(timestamp).getTime();
  if (isNaN(age) || Math.abs(age) > 300_000) {
    return json({ error: "Timestamp expired" }, 401);
  }

  // Verify signature
  const challenge = `OUTBOX:${name}:${timestamp}`;
  const valid = await verifyEd25519(challenge, sigB64, pubkeyHex);
  if (!valid) {
    return json({ error: "Invalid signature" }, 403);
  }

  // List outbox files addressed to this name
  const listed = await env.STORE.list({ prefix: "outbox/" });
  const messages: any[] = [];

  for (const obj of listed.objects) {
    if (!obj.key.endsWith(".json")) continue;
    if (!obj.key.includes(`_to-${name}.json`)) continue;
    const data = await env.STORE.get(obj.key);
    if (data) {
      try {
        messages.push(JSON.parse(await data.text()));
      } catch {}
    }
  }

  return json(messages);
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
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-OpenFuse-PublicKey, X-OpenFuse-Signature, X-OpenFuse-Timestamp",
  };
}
