// Crypto module — delegates to Rust WASM core for all operations.
// Keeps the same public API so cli.ts, sync.ts, watch.ts, registry.ts don't change.

import { createHash, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { WasmCore } from "./wasm-core.js";

const KEY_DIR = ".keys";

// --- Types (re-exported for consumers) ---

export interface SignedMessage {
  from: string;
  timestamp: string;
  message: string;
  signature: string;
  publicKey: string;
  encryptionKey?: string;
  encrypted?: boolean;
}

export interface KeyringEntry {
  name: string;
  address: string;
  signingKey: string;
  encryptionKey?: string;
  fingerprint: string;
  trusted: boolean;
  subscribed?: boolean;
  relationship?: string | null;
  note?: string | null;
  added: string;
}

// --- Key generation ---

export async function generateKeys(storeRoot: string): Promise<{ publicKey: string; encryptionKey: string }> {
  const core = new WasmCore(storeRoot);
  return core.generateKeys();
}

export async function hasKeys(storeRoot: string): Promise<boolean> {
  return existsSync(join(storeRoot, KEY_DIR, "private.key"));
}

// --- Fingerprint ---

export function fingerprint(publicKey: string): string {
  const hash = createHash("sha256").update(publicKey).digest();
  const pairs: string[] = [];
  for (let i = 0; i < 16; i++) {
    pairs.push(hash[i].toString(16).toUpperCase().padStart(2, "0"));
  }
  const groups: string[] = [];
  for (let i = 0; i < pairs.length; i += 2) {
    groups.push(pairs[i] + pairs[i + 1]);
  }
  return groups.join(":");
}

// --- Signing ---

export async function loadAgeRecipient(storeRoot: string): Promise<string> {
  return (await readFile(join(storeRoot, KEY_DIR, "age.pub"), "utf-8")).trim();
}

export async function signChallenge(storeRoot: string, challenge: string): Promise<{ signature: string; publicKey: string }> {
  const core = new WasmCore(storeRoot);
  return core.signChallenge(challenge);
}

export async function signMessage(storeRoot: string, from: string, message: string): Promise<SignedMessage> {
  const core = new WasmCore(storeRoot);
  return core.signMessage(from, message);
}

export async function signAndEncrypt(
  storeRoot: string,
  from: string,
  plaintext: string,
  recipientAgeKey: string,
): Promise<SignedMessage> {
  const core = new WasmCore(storeRoot);
  return core.signAndEncrypt(from, plaintext, recipientAgeKey);
}

export function verifyMessage(signed: SignedMessage): boolean {
  try {
    const payload = Buffer.from(`${signed.from}\n${signed.timestamp}\n${signed.message}`);
    const x = Buffer.from(signed.publicKey.trim(), "hex").toString("base64url");
    const pubKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
    return cryptoVerify(null, payload, pubKey, Buffer.from(signed.signature, "base64"));
  } catch {
    return false;
  }
}

export async function decryptMessage(storeRoot: string, signed: SignedMessage): Promise<string> {
  if (!signed.encrypted) return signed.message;
  const core = new WasmCore(storeRoot);
  return core.decryptMessage(signed as any);
}

// --- Helpers ---

export function wrapExternalMessage(signed: SignedMessage, verified: boolean): string {
  const status = verified ? "verified" : "UNVERIFIED";
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<external_message from="${esc(signed.from)}" verified="${verified}" time="${esc(signed.timestamp)}" status="${status}">
${esc(signed.message)}
</external_message>`;
}

export function serializeSignedMessage(signed: SignedMessage): string {
  return JSON.stringify(signed, null, 2);
}

export function deserializeSignedMessage(raw: string): SignedMessage | null {
  try {
    const parsed = JSON.parse(raw);
    if (parsed.from && parsed.message && parsed.signature && parsed.publicKey) {
      return parsed as SignedMessage;
    }
  } catch {}
  return null;
}
