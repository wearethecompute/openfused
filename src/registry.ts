// --- Registry: DNS + keyserver hybrid ---
// The registry solves agent discovery without requiring a DHT or blockchain.
// It's a signed directory: agents register name→endpoint+publicKey mappings,
// similar to DNS (name resolution) + PGP keyservers (key distribution).
// Crucially, imported keys are UNTRUSTED by default — the local agent must
// explicitly `openfuse key trust` after out-of-band verification (fingerprint check).
// This is TOFU (Trust On First Use) done right: the registry distributes keys,
// but never asserts trust. Trust is a local decision.

import { signMessage, fingerprint } from "./crypto.js";
import { ContextStore } from "./store.js";

// Registry API lives on .dev (product layer). DNS TXT records on .net (protocol layer).
export const DEFAULT_REGISTRY = "https://registry.openfused.dev";

export interface Manifest {
  name: string;
  endpoint: string;
  publicKey: string;
  encryptionKey?: string;
  fingerprint: string;
  created: string;
  capabilities: string[];
  description?: string;
  signature?: string;
  signedAt?: string;
  revoked?: boolean;
  revokedAt?: string;
  rotatedFrom?: string;
}

export function resolveRegistry(flag?: string): string {
  return flag || process.env.OPENFUSE_REGISTRY || DEFAULT_REGISTRY;
}

export async function register(store: ContextStore, endpoint: string, registry: string): Promise<Manifest> {
  const config = await store.readConfig();
  if (!config.publicKey) throw new Error("No signing key — run `openfuse init` first");

  const manifest: Manifest = {
    name: config.name,
    endpoint,
    publicKey: config.publicKey,
    encryptionKey: config.encryptionKey,
    fingerprint: fingerprint(config.publicKey),
    created: new Date().toISOString(),
    capabilities: ["inbox", "shared", "knowledge"],
  };

  // Canonical string prevents field-reordering attacks — pipe-delimited, deterministic order.
  // Signature proves the registrant owns the private key (anti-squatting).
  const canonical = `${manifest.name}|${manifest.endpoint}|${manifest.publicKey}|${manifest.encryptionKey || ""}`;
  const signed = await signMessage(store.root, manifest.name, canonical);
  manifest.signature = signed.signature;
  manifest.signedAt = signed.timestamp;

  const resp = await fetch(`${registry.replace(/\/$/, "")}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(manifest),
  });

  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` })) as { error?: string };
    throw new Error(body.error || `Registry returned ${resp.status}`);
  }

  return manifest;
}

// Discovery: try DNS TXT first (decentralized, no registry needed), fall back to Worker API.
// DNS format: v=of1 e={endpoint} pk={pubkey} ek={agekey} fp={fingerprint}
// Self-hosted: _openfuse.{name}.{their-domain} — user manages their own TXT records.
// Our zone: _openfuse.{name}.openfused.net — managed by the registry Worker on registration.
export async function discover(name: string, registry: string): Promise<Manifest> {
  // If name contains a dot, it's a domain — try DNS TXT directly
  // Otherwise try DNS at openfused.net, then fall back to registry API
  const dnsNames = name.includes(".")
    ? [`_openfuse.${name}`]
    : [`_openfuse.${name}.openfused.net`];

  for (const dnsName of dnsNames) {
    const manifest = await discoverViaDns(dnsName, name);
    if (manifest) return manifest;
  }

  // Fall back to registry API
  const resp = await fetch(`${registry.replace(/\/$/, "")}/discover/${name}`);
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` })) as { error?: string };
    throw new Error(body.error || `Agent '${name}' not found`);
  }
  return (await resp.json()) as Manifest;
}

async function discoverViaDns(dnsName: string, agentName: string): Promise<Manifest | null> {
  try {
    // Use DNS-over-HTTPS (Cloudflare 1.1.1.1) to resolve TXT records
    const resp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(dnsName)}&type=TXT`, {
      headers: { "Accept": "application/dns-json" },
    });
    if (!resp.ok) return null;
    const data = await resp.json() as { Answer?: { data: string }[] };
    if (!data.Answer || data.Answer.length === 0) return null;

    // Parse v=of1 format from TXT record
    const txt = data.Answer[0].data.replace(/"/g, "");
    if (!txt.startsWith("v=of1")) return null;

    const fields: Record<string, string> = {};
    for (const part of txt.split(" ")) {
      const [k, v] = part.split("=", 2);
      if (k && v) fields[k] = v;
    }

    if (!fields.e || !fields.pk) return null;

    return {
      name: agentName,
      endpoint: fields.e,
      publicKey: fields.pk,
      encryptionKey: fields.ek || undefined,
      fingerprint: fields.fp || "",
      created: "",
      capabilities: ["inbox", "shared", "knowledge"],
    };
  } catch {
    return null;
  }
}

// Revocation is permanent and self-authenticated: the agent signs its own revocation
// with the key being revoked. No admin needed — if you have the private key, you can kill it.
export async function revoke(store: ContextStore, registry: string): Promise<void> {
  const config = await store.readConfig();
  if (!config.publicKey) throw new Error("No signing key");

  const revokeMsg = `REVOKE:${config.publicKey}`;
  const signed = await signMessage(store.root, config.name, revokeMsg);

  const resp = await fetch(`${registry.replace(/\/$/, "")}/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: config.name,
      signature: signed.signature,
      signedAt: signed.timestamp,
    }),
  });

  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` })) as { error?: string };
    throw new Error(body.error || `Revocation failed`);
  }
}

// Non-blocking version check with 2s timeout — never delays the CLI for a slow network.
export async function checkUpdate(currentVersion: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const resp = await fetch(DEFAULT_REGISTRY, { signal: controller.signal });
    clearTimeout(timeout);
    if (!resp.ok) return null;
    const body = (await resp.json()) as { latest?: string };
    if (body.latest && body.latest !== currentVersion) return body.latest;
    return null;
  } catch {
    return null;
  }
}
