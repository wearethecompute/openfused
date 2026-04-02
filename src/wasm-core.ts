// TypeScript wrapper for openfused-core WASM module.
// Loads the compiled wasm32-wasip1 binary and calls it via node:wasi.
// All crypto + store operations go through Rust WASM.
// Networking (sync, registry, watch) stays in Node.js.

import { WASI } from "node:wasi";
import { readFileSync } from "node:fs";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

// Cache compiled WASM module — expensive to compile, cheap to instantiate
let cachedModule: WebAssembly.Module | null = null;

function getWasmPath(): string {
  const dir = dirname(fileURLToPath(import.meta.url));
  return join(dir, "..", "wasm", "openfused-core.wasm");
}

function getModule(): WebAssembly.Module {
  if (!cachedModule) {
    const wasmBytes = readFileSync(getWasmPath());
    cachedModule = new WebAssembly.Module(wasmBytes);
  }
  return cachedModule;
}

interface WasiCallResult {
  stdout: string;
  exitCode: number;
}

async function callWasm(storeRoot: string, args: string[]): Promise<WasiCallResult> {
  // Create a temp file to capture stdout (node:wasi doesn't support piping stdout directly)
  // Restrictive permissions: 0o700 dir + 0o600 file — prevents other users from reading
  // WASM output which may contain decrypted messages, keys, or config data.
  const tmpDir = await mkdtemp(join(tmpdir(), "openfuse-wasi-"));
  const { chmodSync, openSync, closeSync } = await import("node:fs");
  chmodSync(tmpDir, 0o700);
  const stdoutPath = join(tmpDir, "stdout");
  const fd = openSync(stdoutPath, "w", 0o600);

  try {
    const wasi = new WASI({
      version: "preview1",
      args: ["openfused-core", ...args],
      env: { OPENFUSE_STORE: storeRoot },
      preopens: {
        "/store": storeRoot,
      },
      stdout: fd,
    });

    const module = getModule();
    const instance = new WebAssembly.Instance(module, wasi.getImportObject());

    let exitCode = 0;
    try {
      wasi.start(instance);
    } catch (e: any) {
      // WASI throws on non-zero exit
      if (e.message?.includes("exit")) {
        exitCode = 1;
      } else {
        throw e;
      }
    }

    closeSync(fd);
    const stdout = await readFile(stdoutPath, "utf-8");
    await rm(tmpDir, { recursive: true, force: true });

    return { stdout: stdout.trim(), exitCode };
  } catch (e) {
    try { closeSync(fd); } catch {}
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    throw e;
  }
}

async function callWasmJson<T>(storeRoot: string, args: string[]): Promise<T> {
  const { stdout, exitCode } = await callWasm(storeRoot, args);
  if (!stdout) {
    throw new Error(`WASM returned empty output for command: ${args[0] ?? "unknown"}`);
  }
  const parsed = JSON.parse(stdout);
  if (exitCode !== 0 && parsed.error) {
    throw new Error(parsed.error);
  }
  return parsed as T;
}

// --- Public API ---

export interface SignedMessage {
  from: string;
  timestamp: string;
  message: string;
  signature: string;
  publicKey: string;
  encryptionKey?: string;
  encrypted: boolean;
}

export interface InboxMessage {
  file: string;
  from: string;
  time: string;
  content: string;
  wrappedContent: string;
  verified: boolean;
  encrypted: boolean;
}

export interface MeshConfig {
  id: string;
  name: string;
  created: string;
  publicKey?: string;
  encryptionKey?: string;
  peers: PeerConfig[];
  keyring: KeyringEntry[];
  autoTrust?: boolean;
}

export interface PeerConfig {
  id: string;
  name: string;
  url: string;
  access: string;
  mountPath?: string;
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

export interface StatusInfo {
  id: string;
  name: string;
  peers: number;
  inboxCount: number;
  sharedCount: number;
}

export interface ValidityReport {
  entries: ValiditySection[];
  stale: number;
  fresh: number;
}

export interface ValiditySection {
  header: string;
  content: string;
  ttl_str: string;
  ttl_ms: number;
  added?: string;
  confidence: number;
  expired: boolean;
}

export class WasmCore {
  constructor(private storeRoot: string) {}

  // --- Store ---

  async init(name: string, id: string): Promise<{ name: string; id: string; publicKey: string; encryptionKey: string }> {
    return callWasmJson(this.storeRoot, ["init", name, id]);
  }

  async initWorkspace(name: string, id: string): Promise<{ ok: boolean }> {
    return callWasmJson(this.storeRoot, ["init-workspace", name, id]);
  }

  async readConfig(): Promise<MeshConfig> {
    return callWasmJson(this.storeRoot, ["read-config"]);
  }

  async writeConfig(config: MeshConfig): Promise<void> {
    await callWasmJson(this.storeRoot, ["write-config", JSON.stringify(config)]);
  }

  async readContext(): Promise<string> {
    const result = await callWasmJson<{ content: string }>(this.storeRoot, ["read-context"]);
    return result.content;
  }

  async writeContext(content: string): Promise<void> {
    await callWasmJson(this.storeRoot, ["write-context", content]);
  }

  async appendContext(text: string): Promise<string> {
    const result = await callWasmJson<{ ok: boolean; timestamp: string }>(this.storeRoot, ["append-context", text]);
    return result.timestamp;
  }

  async readProfile(): Promise<string> {
    const result = await callWasmJson<{ content: string }>(this.storeRoot, ["read-profile"]);
    return result.content;
  }

  async writeProfile(content: string): Promise<void> {
    await callWasmJson(this.storeRoot, ["write-profile", content]);
  }

  async readInbox(): Promise<InboxMessage[]> {
    return callWasmJson(this.storeRoot, ["read-inbox"]);
  }

  async sendInbox(peer: string, message: string, from: string): Promise<void> {
    await callWasmJson(this.storeRoot, ["send-inbox", peer, message, from]);
  }

  async archiveInbox(filename: string): Promise<void> {
    await callWasmJson(this.storeRoot, ["archive-inbox", filename]);
  }

  async archiveInboxAll(): Promise<number> {
    const result = await callWasmJson<{ count: number }>(this.storeRoot, ["archive-inbox-all"]);
    return result.count;
  }

  async listShared(): Promise<string[]> {
    return callWasmJson(this.storeRoot, ["list-shared"]);
  }

  async share(filename: string, content: string): Promise<void> {
    await callWasmJson(this.storeRoot, ["share", filename, content]);
  }

  async status(): Promise<StatusInfo> {
    return callWasmJson(this.storeRoot, ["status"]);
  }

  async compact(): Promise<{ moved: number; kept: number }> {
    return callWasmJson(this.storeRoot, ["compact"]);
  }

  async validate(): Promise<ValidityReport> {
    return callWasmJson(this.storeRoot, ["validate"]);
  }

  async pruneStale(): Promise<number> {
    const result = await callWasmJson<{ pruned: number }>(this.storeRoot, ["prune-stale"]);
    return result.pruned;
  }

  // --- Crypto ---

  async signMessage(from: string, message: string): Promise<SignedMessage> {
    return callWasmJson(this.storeRoot, ["sign-message", from, message]);
  }

  async signAndEncrypt(from: string, message: string, recipientAgeKey: string): Promise<SignedMessage> {
    return callWasmJson(this.storeRoot, ["sign-and-encrypt", from, message, recipientAgeKey]);
  }

  async verifyMessage(signed: SignedMessage): Promise<boolean> {
    const result = await callWasmJson<{ valid: boolean }>(this.storeRoot, ["verify-message", JSON.stringify(signed)]);
    return result.valid;
  }

  async decryptMessage(signed: SignedMessage): Promise<string> {
    const result = await callWasmJson<{ plaintext: string }>(this.storeRoot, ["decrypt-message", JSON.stringify(signed)]);
    return result.plaintext;
  }

  async generateKeys(): Promise<{ publicKey: string; encryptionKey: string; fingerprint: string }> {
    return callWasmJson(this.storeRoot, ["generate-keys"]);
  }

  async fingerprint(publicKey: string): Promise<string> {
    const result = await callWasmJson<{ fingerprint: string }>(this.storeRoot, ["fingerprint", publicKey]);
    return result.fingerprint;
  }

  async resolveKeyring(query: string): Promise<KeyringEntry> {
    return callWasmJson(this.storeRoot, ["resolve-keyring", query]);
  }

  async signChallenge(challenge: string): Promise<{ signature: string; publicKey: string }> {
    return callWasmJson(this.storeRoot, ["sign-challenge", challenge]);
  }
}
