// --- Transport design ---
// Two transports, one protocol. HTTP for WAN (daemon serves context over the internet),
// SSH/rsync for LAN (zero config if you already have SSH keys — uses ~/.ssh/config aliases
// so agents reference hostnames, never raw IPs that change). Both transports do the same
// thing: pull CONTEXT.md + PROFILE.md + shared/ + knowledge/, push outbox → peer inbox.

import { readFile, writeFile, mkdir, readdir, rename } from "node:fs/promises";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import { ContextStore } from "./store.js";

const execFile = promisify(execFileCb);

export interface SyncResult {
  peerName: string;
  pulled: string[];
  pushed: string[];
  errors: string[];
}

interface Transport {
  type: "http" | "ssh";
  baseUrl?: string;
  host?: string;
  path?: string;
}

// Archive instead of delete: preserves audit trail and lets agents review what was sent.
// Without this, sync would re-deliver the same message every cycle.
async function archiveSent(outboxDir: string, fname: string): Promise<void> {
  const sentDir = join(outboxDir, ".sent");
  await mkdir(sentDir, { recursive: true });
  await rename(join(outboxDir, fname), join(sentDir, fname));
}

function parseUrl(url: string): Transport {
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return { type: "http", baseUrl: url.replace(/\/$/, "") };
  } else if (url.startsWith("ssh://")) {
    const rest = url.slice(6);
    const colonIdx = rest.indexOf(":");
    if (colonIdx === -1) throw new Error("SSH URL must be ssh://host:/path");
    const host = rest.slice(0, colonIdx);
    const path = rest.slice(colonIdx + 1);
    // Prevent argument injection: rsync treats leading "-" as flags, and shell
    // metacharacters could escape the execFile boundary on some platforms.
    if (host.startsWith("-") || path.startsWith("-")) {
      throw new Error("Invalid SSH URL: host/path cannot start with '-'");
    }
    if (/[;|`$]/.test(host)) {
      throw new Error("Invalid SSH URL: host contains shell metacharacters");
    }
    if (/[;|`$&(){}]/.test(path)) {
      throw new Error("Invalid SSH URL: path contains shell metacharacters");
    }
    return { type: "ssh", host, path };
  }
  throw new Error(`Unknown URL scheme: ${url}. Use http:// or ssh://`);
}

/** Try to deliver a single outbox message immediately. Returns true if delivered. */
export async function deliverOne(store: ContextStore, peerName: string, filename: string): Promise<boolean> {
  const config = await store.readConfig();
  const peer = config.peers.find((p) => p.name === peerName || p.id === peerName);
  if (!peer) return false;

  const outboxDir = join(store.root, "outbox");
  const filePath = join(outboxDir, filename);
  if (!existsSync(filePath)) return false;

  try {
    const transport = parseUrl(peer.url);

    if (transport.type === "http") {
      const body = await readFile(filePath, "utf-8");
      const r = await fetch(`${transport.baseUrl}/inbox`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });
      if (!r.ok) return false;
    } else {
      await execFile("rsync", [
        "-az", filePath,
        `${transport.host}:${transport.path}/inbox/${filename}`,
      ]);
    }

    // Delivered — archive to .sent/
    await archiveSent(outboxDir, filename);
    return true;
  } catch {
    return false; // stays in outbox for next sync
  }
}

export async function syncAll(store: ContextStore): Promise<SyncResult[]> {
  const config = await store.readConfig();
  const results: SyncResult[] = [];
  for (const peer of config.peers) {
    try {
      results.push(await syncPeer(store, peer));
    } catch (e: any) {
      results.push({ peerName: peer.name, pulled: [], pushed: [], errors: [e.message] });
    }
  }
  return results;
}

export async function syncOne(store: ContextStore, peerName: string): Promise<SyncResult> {
  const config = await store.readConfig();
  const peer = config.peers.find((p) => p.name === peerName || p.id === peerName);
  if (!peer) throw new Error(`Peer not found: ${peerName}`);
  return syncPeer(store, peer);
}

async function syncPeer(
  store: ContextStore,
  peer: { name: string; id: string; url: string },
): Promise<SyncResult> {
  const transport = parseUrl(peer.url);
  const peerDir = join(store.root, ".peers", peer.name);
  await mkdir(peerDir, { recursive: true });

  if (transport.type === "http") {
    return syncHttp(store, peer, transport.baseUrl!, peerDir);
  } else {
    return syncSsh(store, peer, transport.host!, transport.path!, peerDir);
  }
}

// --- HTTP sync ---

async function syncHttp(
  store: ContextStore,
  peer: { name: string; id: string },
  baseUrl: string,
  peerDir: string,
): Promise<SyncResult> {
  const pulled: string[] = [];
  const pushed: string[] = [];
  const errors: string[] = [];

  for (const file of ["CONTEXT.md", "PROFILE.md"]) {
    try {
      const resp = await fetch(`${baseUrl}/read/${file}`);
      if (resp.ok) {
        await writeFile(join(peerDir, file), await resp.text());
        pulled.push(file);
      }
    } catch (e: any) {
      errors.push(`${file}: ${e.message}`);
    }
  }

  for (const dir of ["shared", "knowledge"]) {
    try {
      const resp = await fetch(`${baseUrl}/ls/${dir}`);
      if (!resp.ok) continue;
      const files = (await resp.json()) as { name: string; is_dir: boolean }[];
      const localDir = join(peerDir, dir);
      await mkdir(localDir, { recursive: true });
      for (const f of files) {
        if (f.is_dir) continue;
        // Remote peer controls this filename — must sanitize before writing to local disk.
        // Basename extraction blocks "../../../etc/passwd" style traversal from a malicious peer.
        const safeName = f.name.split("/").pop()!.split("\\").pop()!;
        if (!safeName || safeName.includes("..")) continue;
        const r = await fetch(`${baseUrl}/read/${dir}/${safeName}`);
        if (r.ok) {
          await writeFile(join(localDir, safeName), Buffer.from(await r.arrayBuffer()));
          pulled.push(`${dir}/${safeName}`);
        }
      }
    } catch (e: any) {
      errors.push(`${dir}/: ${e.message}`);
    }
  }

  // Pull peer's outbox for messages addressed to us (HTTP version)
  const config = await store.readConfig();
  const myName = config.name;
  const inboxDir = join(store.root, "inbox");
  await mkdir(inboxDir, { recursive: true });
  try {
    const resp = await fetch(`${baseUrl}/outbox/${myName}`);
    if (resp.ok) {
      const messages = (await resp.json()) as any[];
      for (const msg of messages) {
        const ts = (msg.timestamp || new Date().toISOString()).replace(/[:.]/g, "-");
        const from = msg.from || "unknown";
        const fname = `${ts}_from-${from}_to-${myName}.json`;
        const dest = join(inboxDir, fname);
        if (!existsSync(dest)) {
          await writeFile(dest, JSON.stringify(msg, null, 2));
          pulled.push(`outbox→${fname}`);
        }
      }
    }
  } catch {}

  // Push outbox → peer inbox
  const outboxDir = join(store.root, "outbox");
  if (existsSync(outboxDir)) {
    for (const fname of await readdir(outboxDir)) {
      if (!fname.endsWith(".json")) continue;
      if (!fname.includes(`_to-${peer.name}.json`) && !fname.includes(peer.id)) continue;
      try {
        const body = await readFile(join(outboxDir, fname), "utf-8");
        const r = await fetch(`${baseUrl}/inbox`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        });
        if (r.ok) {
          await archiveSent(outboxDir, fname);
          pushed.push(fname);
        } else errors.push(`push ${fname}: HTTP ${r.status}`);
      } catch (e: any) {
        errors.push(`push ${fname}: ${e.message}`);
      }
    }
  }

  await writeFile(join(peerDir, ".last-sync"), new Date().toISOString());
  return { peerName: peer.name, pulled, pushed, errors };
}

// --- SSH sync (rsync) ---

async function syncSsh(
  store: ContextStore,
  peer: { name: string; id: string },
  host: string,
  remotePath: string,
  peerDir: string,
): Promise<SyncResult> {
  const pulled: string[] = [];
  const pushed: string[] = [];
  const errors: string[] = [];

  for (const file of ["CONTEXT.md", "PROFILE.md"]) {
    try {
      await execFile("rsync", ["-az", `${host}:${remotePath}/${file}`, join(peerDir, file)]);
      pulled.push(file);
    } catch (e: any) {
      errors.push(`${file}: ${e.stderr || e.message}`);
    }
  }

  for (const dir of ["shared", "knowledge"]) {
    const localDir = join(peerDir, dir);
    await mkdir(localDir, { recursive: true });
    try {
      await execFile("rsync", ["-az", "--delete", `${host}:${remotePath}/${dir}/`, `${localDir}/`]);
      pulled.push(`${dir}/`);
    } catch (e: any) {
      errors.push(`${dir}/: ${e.stderr || e.message}`);
    }
  }

  // Pull peer's outbox for messages addressed to us — peer may be behind NAT
  // and can't push to us, so we grab messages they left in their outbox for us.
  const config = await store.readConfig();
  const myName = config.name;
  const inboxDir = join(store.root, "inbox");
  await mkdir(inboxDir, { recursive: true });
  try {
    await execFile("rsync", [
      "-az", "--ignore-existing",
      "--include", `*_to-${myName}.json`,
      "--include", `*_to-all.json`,
      "--include", `*_${myName}.json`,   // legacy format (pre-envelope)
      "--exclude", "*",
      `${host}:${remotePath}/outbox/`,
      `${inboxDir}/`,
    ]);
    pulled.push("outbox→inbox");
  } catch (e: any) {
    if (!String(e.stderr || e.message).includes("No such file")) {
      errors.push(`pull outbox: ${e.stderr || e.message}`);
    }
  }

  // Push our outbox → peer inbox
  const outboxDir = join(store.root, "outbox");
  if (existsSync(outboxDir)) {
    for (const fname of await readdir(outboxDir)) {
      if (!fname.endsWith(".json")) continue;
      if (!fname.includes(`_to-${peer.name}.json`) && !fname.includes(peer.id)) continue;
      try {
        await execFile("rsync", ["-az", join(outboxDir, fname), `${host}:${remotePath}/inbox/${fname}`]);
        await archiveSent(outboxDir, fname);
        pushed.push(fname);
      } catch (e: any) {
        errors.push(`push ${fname}: ${e.stderr || e.message}`);
      }
    }
  }

  await writeFile(join(peerDir, ".last-sync"), new Date().toISOString());
  return { peerName: peer.name, pulled, pushed, errors };
}
