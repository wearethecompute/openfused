import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { existsSync } from "node:fs";
import {
  generateKeys, hasKeys, signMessage, signAndEncrypt, verifyMessage, decryptMessage,
  deserializeSignedMessage, serializeSignedMessage, wrapExternalMessage,
  fingerprint, type SignedMessage, type KeyringEntry,
} from "./crypto.js";

export interface MeshConfig {
  id: string;
  name: string;
  created: string;
  publicKey?: string;
  encryptionKey?: string;
  peers: PeerConfig[];
  keyring: KeyringEntry[];
  trustedKeys?: string[]; // legacy, migrated to keyring
}

export interface PeerConfig {
  id: string;
  name: string;
  url: string;
  access: "read" | "readwrite";
  mountPath?: string;
}

const STORE_DIRS = ["history", "knowledge", "inbox", "outbox", "shared", ".peers"];

export class ContextStore {
  readonly root: string;

  constructor(root: string) {
    this.root = resolve(root);
  }

  get configPath() {
    return join(this.root, ".mesh.json");
  }

  async exists(): Promise<boolean> {
    return existsSync(this.configPath);
  }

  async init(name: string, id: string): Promise<void> {
    await mkdir(this.root, { recursive: true });
    for (const dir of STORE_DIRS) {
      await mkdir(join(this.root, dir), { recursive: true });
    }

    // Copy templates
    const templatesDir = new URL("../templates/", import.meta.url).pathname;
    for (const file of ["CONTEXT.md", "PROFILE.md"]) {
      const templatePath = join(templatesDir, file);
      const destPath = join(this.root, file);
      if (!existsSync(destPath)) {
        const content = await readFile(templatePath, "utf-8");
        await writeFile(destPath, content);
      }
    }

    const keys = await generateKeys(this.root);

    const config: MeshConfig = {
      id,
      name,
      created: new Date().toISOString(),
      publicKey: keys.publicKey,
      encryptionKey: keys.encryptionKey,
      peers: [],
      keyring: [],
    };
    await this.writeConfig(config);
  }

  async readConfig(): Promise<MeshConfig> {
    const raw = await readFile(this.configPath, "utf-8");
    const config = JSON.parse(raw) as MeshConfig;

    // Migrate legacy trustedKeys → keyring
    if (config.trustedKeys && config.trustedKeys.length > 0) {
      if (!config.keyring) config.keyring = [];
      for (const key of config.trustedKeys) {
        const k = key.trim();
        if (!k || config.keyring.some((e) => e.signingKey === k)) continue;
        config.keyring.push({
          name: `migrated-${k.slice(0, 8)}`,
          address: "",
          signingKey: k,
          fingerprint: fingerprint(k),
          trusted: true,
          added: new Date().toISOString(),
        });
      }
      delete config.trustedKeys;
      await this.writeConfig(config);
    }

    if (!config.keyring) config.keyring = [];
    return config;
  }

  async writeConfig(config: MeshConfig): Promise<void> {
    await writeFile(this.configPath, JSON.stringify(config, null, 2) + "\n");
  }

  async readContext(): Promise<string> {
    return readFile(join(this.root, "CONTEXT.md"), "utf-8");
  }

  async writeContext(content: string): Promise<void> {
    await writeFile(join(this.root, "CONTEXT.md"), content);
  }

  async readProfile(): Promise<string> {
    return readFile(join(this.root, "PROFILE.md"), "utf-8");
  }

  async writeProfile(content: string): Promise<void> {
    await writeFile(join(this.root, "PROFILE.md"), content);
  }

  // --- Inbox ---

  async sendInbox(peerId: string, message: string): Promise<void> {
    const config = await this.readConfig();

    // Look up peer's encryption key in keyring
    const entry = config.keyring.find(
      (e) => e.name === peerId || e.address.startsWith(`${peerId}@`)
    );

    let signed: SignedMessage;
    if (entry?.encryptionKey) {
      signed = await signAndEncrypt(this.root, config.id, message, entry.encryptionKey);
    } else {
      signed = await signMessage(this.root, config.id, message);
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `${timestamp}_${peerId}.json`;
    await writeFile(join(this.root, "outbox", filename), serializeSignedMessage(signed));
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
    const inboxDir = join(this.root, "inbox");
    if (!existsSync(inboxDir)) return [];

    const config = await this.readConfig();
    const files = await readdir(inboxDir);
    const messages = [];

    for (const file of files.filter((f) => f.endsWith(".json") || f.endsWith(".md"))) {
      const raw = await readFile(join(inboxDir, file), "utf-8");

      const signed = deserializeSignedMessage(raw);
      if (signed) {
        const sigValid = verifyMessage(signed);
        const trusted = config.keyring.some(
          (k) => k.trusted && k.signingKey.trim() === signed.publicKey.trim()
        );
        const verified = sigValid && trusted;

        let content: string;
        if (signed.encrypted) {
          try {
            content = await decryptMessage(this.root, signed);
          } catch {
            content = "[encrypted — cannot decrypt]";
          }
        } else {
          content = signed.message;
        }

        messages.push({
          file,
          content,
          wrappedContent: wrapExternalMessage(signed, verified),
          from: signed.from,
          time: signed.timestamp,
          verified,
          encrypted: !!signed.encrypted,
        });
      } else {
        const parts = file.replace(/\.(md|json)$/, "").split("_");
        const from = parts.slice(1).join("_");
        messages.push({
          file,
          content: raw,
          wrappedContent: wrapExternalMessage(
            { from, timestamp: parts[0], message: raw, signature: "", publicKey: "" },
            false,
          ),
          from,
          time: parts[0],
          verified: false,
          encrypted: false,
        });
      }
    }

    return messages.sort((a, b) => a.time.localeCompare(b.time));
  }

  // --- Shared files ---

  async listShared(): Promise<string[]> {
    const sharedDir = join(this.root, "shared");
    if (!existsSync(sharedDir)) return [];
    return readdir(sharedDir);
  }

  async share(filename: string, content: string): Promise<void> {
    // Sanitize: extract basename, reject traversal
    const base = filename.split("/").pop()!.split("\\").pop()!;
    if (!base || base === "." || base === ".." || base.includes("..")) {
      throw new Error(`Invalid filename: ${filename}`);
    }
    const sharedDir = join(this.root, "shared");
    await mkdir(sharedDir, { recursive: true });
    await writeFile(join(sharedDir, base), content);
  }

  // --- Status ---

  async status(): Promise<{
    id: string;
    name: string;
    peers: number;
    inboxCount: number;
    sharedCount: number;
  }> {
    const config = await this.readConfig();
    const inbox = await this.readInbox();
    const shared = await this.listShared();
    return {
      id: config.id,
      name: config.name,
      peers: config.peers.length,
      inboxCount: inbox.length,
      sharedCount: shared.length,
    };
  }
}
