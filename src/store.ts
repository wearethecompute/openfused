// --- Store module ---
// Delegates to Rust WASM core for all store operations.
// Same public API — cli.ts, sync.ts, mcp.ts, watch.ts don't change.

import { resolve } from "node:path";
import { existsSync } from "node:fs";
import { WasmCore, type MeshConfig as WasmMeshConfig, type KeyringEntry as WasmKeyringEntry } from "./wasm-core.js";
import { fingerprint, type SignedMessage, type KeyringEntry } from "./crypto.js";

export type { KeyringEntry } from "./crypto.js";

export interface MeshConfig {
  id: string;
  name: string;
  created: string;
  publicKey?: string;
  encryptionKey?: string;
  peers: PeerConfig[];
  keyring: KeyringEntry[];
  trustedKeys?: string[]; // legacy v0.1
  autoTrust?: boolean;
}

export interface PeerConfig {
  id: string;
  name: string;
  url: string;
  access: "read" | "readwrite";
  mountPath?: string;
}

/** Validate agent/peer names: alphanumeric + hyphens + underscores + dots, 1-64 chars.
 *  Rejects path traversal (../, /, \) and rsync glob chars (*, ?, [). */
export function validateName(name: string, label = "Name"): string {
  if (!name || name.length < 1 || name.length > 64) {
    throw new Error(`${label} must be 1-64 characters`);
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(name)) {
    throw new Error(`${label} must start with alphanumeric and contain only a-z, 0-9, -, _, .`);
  }
  if (name.includes("..") || name.includes("/") || name.includes("\\")) {
    throw new Error(`${label} contains invalid path characters`);
  }
  return name;
}

/** Resolve a keyring entry by name, name:fingerprint, or bare fingerprint prefix.
 *  Throws if ambiguous (multiple matches) or not found. */
export function resolveKeyring(keyring: KeyringEntry[], query: string): KeyringEntry {
  let name: string;
  let fpPrefix: string | undefined;

  if (query.includes(":")) {
    const colonIdx = query.lastIndexOf(":");
    const maybeFp = query.slice(colonIdx + 1);
    if (/^[0-9a-fA-F]{4,16}$/.test(maybeFp)) {
      name = query.slice(0, colonIdx);
      fpPrefix = maybeFp.toUpperCase();
    } else {
      name = query;
    }
  } else {
    name = query;
  }

  let matches = keyring.filter(
    (k) => k.name === name || k.address.startsWith(`${name}@`)
  );

  if (matches.length === 0 && /^[0-9a-fA-F]{4,16}$/.test(query)) {
    const upper = query.toUpperCase();
    matches = keyring.filter(
      (k) => k.fingerprint.replace(/:/g, "").startsWith(upper)
    );
  }

  if (fpPrefix && matches.length > 1) {
    matches = matches.filter(
      (k) => k.fingerprint.replace(/:/g, "").startsWith(fpPrefix!)
    );
  }

  if (matches.length === 0) {
    throw new Error(`Key not found: "${query}". Run: openfuse key list`);
  }
  if (matches.length > 1) {
    const options = matches.map(
      (k) => `  ${k.name}:${k.fingerprint.replace(/:/g, "").slice(0, 8)}  ${k.address}`
    ).join("\n");
    throw new Error(
      `Multiple keys match "${query}". Disambiguate with fingerprint:\n${options}`
    );
  }
  return matches[0];
}

export class ContextStore {
  readonly root: string;
  private core: WasmCore;

  constructor(root: string) {
    this.root = resolve(root);
    this.core = new WasmCore(this.root);
  }

  get configPath() {
    return `${this.root}/.mesh.json`;
  }

  async exists(): Promise<boolean> {
    return existsSync(this.configPath);
  }

  async init(name: string, id: string): Promise<void> {
    // Create dir before WASM init — WASI preopens require the directory to exist
    const { mkdir } = await import("node:fs/promises");
    await mkdir(this.root, { recursive: true });
    await this.core.init(name, id);
  }

  async initWorkspace(name: string, id: string): Promise<void> {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(this.root, { recursive: true });
    await this.core.initWorkspace(name, id);
  }

  async readConfig(): Promise<MeshConfig> {
    const config = await this.core.readConfig() as MeshConfig;
    // Rust skips empty arrays with skip_serializing_if — ensure keyring/peers always exist
    if (!config.keyring) config.keyring = [];
    if (!config.peers) config.peers = [];
    return config;
  }

  async writeConfig(config: MeshConfig): Promise<void> {
    await this.core.writeConfig(config as any);
  }

  async readContext(): Promise<string> {
    return this.core.readContext();
  }

  async writeContext(content: string): Promise<void> {
    await this.core.writeContext(content);
  }

  async compactContext(): Promise<{ moved: number; kept: number }> {
    return this.core.compact();
  }

  async readProfile(): Promise<string> {
    return this.core.readProfile();
  }

  async writeProfile(content: string): Promise<void> {
    await this.core.writeProfile(content);
  }

  async sendInbox(peerId: string, message: string): Promise<string> {
    const config = await this.readConfig();
    await this.core.sendInbox(peerId, message, config.name);
    return peerId;
  }

  async readInbox(): Promise<Array<{
    file: string;
    content: string;
    wrappedContent: string;
    from: string;
    time: string;
    verified: boolean;
    encrypted: boolean;
  }>> {
    return this.core.readInbox();
  }

  async listShared(): Promise<string[]> {
    return this.core.listShared();
  }

  async share(filename: string, content: string): Promise<void> {
    await this.core.share(filename, content);
  }

  async status(): Promise<{
    id: string;
    name: string;
    peers: number;
    inboxCount: number;
    sharedCount: number;
  }> {
    return this.core.status();
  }
}
