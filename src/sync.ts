// --- Transport design ---
// Two transports, one protocol. HTTP for WAN (daemon serves context over the internet),
// SSH/rsync for LAN (zero config if you already have SSH keys — uses ~/.ssh/config aliases
// so agents reference hostnames, never raw IPs that change). Both transports do the same
// thing: pull CONTEXT.md + PROFILE.md + shared/ + knowledge/, push outbox → peer inbox.

import { readFile, writeFile, mkdir, readdir, rename } from "node:fs/promises";
import { join, resolve } from "node:path";
import { existsSync } from "node:fs";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import dns from "node:dns/promises";
import { ContextStore } from "./store.js";

/** Block SSRF: reject URLs pointing to private/reserved IP ranges. */
export async function checkSsrf(url: string): Promise<void> {
  const parsed = new URL(url);
  const hostname = parsed.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  try {
    const { address } = await dns.lookup(hostname);
    const parts = address.split(".").map(Number);
    if (
      address === "127.0.0.1" || address === "::1" || address === "0.0.0.0" ||
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254) ||
      address.startsWith("fc") || address.startsWith("fd") || address.startsWith("fe80")
    ) {
      throw new Error(`SSRF blocked: ${hostname} resolves to private address ${address}`);
    }
  } catch (e: any) {
    if (e.message.startsWith("SSRF blocked")) throw e;
    // DNS resolution failed — allow (could be .local or SSH alias)
  }
}

const execFile = promisify(execFileCb);

// Strip dangerous HTML from peer content before writing to disk.
// Peer-synced files get read by agents/LLMs — malicious HTML could execute
// if rendered in a browser or trick an LLM into acting on injected instructions.
function sanitizePeerContent(raw: string): string {
  return raw
    .replace(/<script[\s\S]*?<\/script>/gi, "[REMOVED: script tag]")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "[REMOVED: iframe tag]")
    .replace(/<object[\s\S]*?<\/object>/gi, "[REMOVED: object tag]")
    .replace(/<embed[\s\S]*?>/gi, "[REMOVED: embed tag]")
    .replace(/<link[\s\S]*?>/gi, "[REMOVED: link tag]")
    .replace(/on\w+\s*=\s*["'][^"']*["']/gi, "[REMOVED: event handler]")
    .replace(/javascript\s*:/gi, "[REMOVED: javascript URI]");
}

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
// relPath can be "file.json" (flat, legacy) or "recipientDir/file.json" (new subdir layout).
async function archiveSent(outboxRoot: string, relPath: string): Promise<void> {
  // Path traversal defense: resolve and verify we stay under outboxRoot
  const fullPath = resolve(outboxRoot, relPath);
  if (!fullPath.startsWith(resolve(outboxRoot) + "/")) {
    throw new Error(`Path traversal blocked: ${relPath}`);
  }
  const dir = join(fullPath, "..");
  const fname = relPath.includes("/") ? relPath.split("/").pop()! : relPath;
  const sentDir = join(dir, ".sent");
  await mkdir(sentDir, { recursive: true });
  await rename(fullPath, join(sentDir, fname));
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
    if (/[;|`$&(){}\s\n\r]/.test(host)) {
      throw new Error("Invalid SSH URL: host contains shell metacharacters");
    }
    if (/[;|`$&(){}\s\n\r]/.test(path)) {
      throw new Error("Invalid SSH URL: path contains shell metacharacters");
    }
    return { type: "ssh", host, path };
  }
  throw new Error(`Unknown URL scheme: ${url}. Use http:// or ssh://`);
}

/** Try to deliver a single outbox message immediately. Returns true if delivered.
 *  filename can be "recipientDir/msg.json" (new) or "flat.json" (legacy). */
export async function deliverOne(store: ContextStore, peerName: string, filename: string): Promise<boolean> {
  const config = await store.readConfig();
  const peer = config.peers.find((p) => p.name === peerName || p.id === peerName);
  if (!peer) return false;

  const outboxRoot = join(store.root, "outbox");
  const filePath = join(outboxRoot, filename);
  if (!existsSync(filePath)) return false;

  const baseName = filename.includes("/") ? filename.split("/").pop()! : filename;

  try {
    const transport = parseUrl(peer.url);

    if (transport.type === "http") {
      await checkSsrf(transport.baseUrl!);
      const body = await readFile(filePath, "utf-8");
      // Append ?to={name} for multi-tenant hosted mailboxes (inbox.openfused.dev).
      // Self-hosted daemons ignore the query param (single-tenant).
      const inboxUrl = `${transport.baseUrl}/inbox?to=${encodeURIComponent(peerName)}`;
      const r = await fetch(inboxUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });
      if (!r.ok) return false;
    } else {
      await execFile("rsync", [
        "-az", filePath,
        `${transport.host}:${transport.path}/inbox/${baseName}`,
      ]);
    }

    // Delivered — archive to .sent/
    await archiveSent(outboxRoot, filename);
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

  // SSRF check: block requests to private/reserved IPs
  await checkSsrf(baseUrl);

  // Try /read/{file} (full mode) then /profile (public mode) for PROFILE.md.
  // CONTEXT.md 404s are silently skipped — peers in public mode don't serve it.
  for (const file of ["CONTEXT.md", "PROFILE.md"]) {
    try {
      const url = file === "PROFILE.md"
        ? `${baseUrl}/profile`  // public mode serves /profile not /read/PROFILE.md
        : `${baseUrl}/read/${file}`;
      let resp = await fetch(url);
      // Fallback: try /read/ path if /profile didn't work (full mode daemon)
      if (!resp.ok && file === "PROFILE.md") {
        resp = await fetch(`${baseUrl}/read/${file}`);
      }
      if (resp.ok) {
        const raw = sanitizePeerContent(await resp.text());
        const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        const wrapped = `<external_content_unverified from="${esc(peer.name)}" file="${esc(file)}">\n${raw}\n</external_content_unverified>`;
        await writeFile(join(peerDir, file), wrapped);
        pulled.push(file);
      }
      // Don't report 404s as errors — peer may be in public mode
    } catch {}
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
          const raw = sanitizePeerContent(Buffer.from(await r.arrayBuffer()).toString("utf-8"));
          const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
          const wrapped = `<external_content_unverified from="${esc(peer.name)}" file="${esc(safeName)}">\n${raw}\n</external_content_unverified>`;
          await writeFile(join(localDir, safeName), wrapped);
          pulled.push(`${dir}/${safeName}`);
        }
      }
    } catch (e: any) {
      errors.push(`${dir}/: ${e.message}`);
    }
  }

  // Pull peer's outbox for messages addressed to us (HTTP version).
  // Authenticated: we sign a challenge proving we own this name, so the daemon
  // only serves outbox to the actual recipient. Prevents metadata enumeration.
  const config = await store.readConfig();
  const myName = config.name;
  const inboxDir = join(store.root, "inbox");
  await mkdir(inboxDir, { recursive: true });
  try {
    const { signChallenge } = await import("./crypto.js");
    const timestamp = new Date().toISOString();
    const challenge = `OUTBOX:${myName}:${timestamp}`;
    const { signature, publicKey } = await signChallenge(store.root, challenge);

    const resp = await fetch(`${baseUrl}/outbox/${myName}`, {
      headers: {
        "X-OpenFuse-PublicKey": publicKey,
        "X-OpenFuse-Signature": signature,
        "X-OpenFuse-Timestamp": timestamp,
      },
    });
    if (resp.ok) {
      const messages = (await resp.json()) as any[];
      for (const msg of messages) {
        const ts = (msg.timestamp || new Date().toISOString()).replace(/[:.]/g, "-");
        const from = msg.from || "unknown";
        const safeFrom = from.replace(/[^a-zA-Z0-9\-_]/g, "");
        const safeTs = ts.replace(/[^a-zA-Z0-9\-_]/g, "");
        const fname = `${safeTs}_from-${safeFrom}_to-${myName}.json`;
        const outboxFile = msg._outboxFile; // filename on sender's outbox
        const dest = join(inboxDir, fname);
        if (!existsSync(dest)) {
          // Strip the _outboxFile metadata before saving
          const { _outboxFile, ...cleanMsg } = msg;
          await writeFile(dest, JSON.stringify(cleanMsg, null, 2));
          pulled.push(`outbox→${fname}`);

          // ACK: tell sender to move this message to .sent/
          if (outboxFile) {
            try {
              const ackTs = new Date().toISOString();
              const ackChallenge = `ACK:${myName}:${outboxFile}:${ackTs}`;
              const ackSig = await signChallenge(store.root, ackChallenge);
              await fetch(`${baseUrl}/outbox/${myName}/${outboxFile}`, {
                method: "DELETE",
                headers: {
                  "X-OpenFuse-PublicKey": ackSig.publicKey,
                  "X-OpenFuse-Signature": ackSig.signature,
                  "X-OpenFuse-Timestamp": ackTs,
                },
              });
            } catch {} // best-effort ACK
          }
        }
      }
    }
  } catch {}

  // Push outbox → peer inbox (scan subdirs named {peer}-{fp}/)
  const outboxDir = join(store.root, "outbox");
  if (existsSync(outboxDir)) {
    for (const entry of await readdir(outboxDir, { withFileTypes: true })) {
      // Match subdirs starting with peer name (new format: name-FINGERPRINT/)
      if (entry.isDirectory() && entry.name.startsWith(`${peer.name}-`)) {
        const subDir = join(outboxDir, entry.name);
        for (const fname of await readdir(subDir)) {
          if (!fname.endsWith(".json")) continue;
          const relPath = `${entry.name}/${fname}`;
          try {
            const body = await readFile(join(subDir, fname), "utf-8");
            const inboxUrl = `${baseUrl}/inbox?to=${encodeURIComponent(peer.name)}`;
            const r = await fetch(inboxUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body,
            });
            if (r.ok) {
              await archiveSent(outboxDir, relPath);
              pushed.push(relPath);
            } else errors.push(`push ${relPath}: HTTP ${r.status}`);
          } catch (e: any) {
            errors.push(`push ${relPath}: ${e.message}`);
          }
        }
      }
      // Legacy flat files (pre-subdir format)
      if (entry.isFile() && entry.name.endsWith(".json")) {
        if (!entry.name.includes(`_to-${peer.name}-`) && !entry.name.includes(`_to-${peer.name}.json`)) continue;
        try {
          const body = await readFile(join(outboxDir, entry.name), "utf-8");
          const inboxUrl = `${baseUrl}/inbox?to=${encodeURIComponent(peer.name)}`;
          const r = await fetch(inboxUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
          });
          if (r.ok) {
            await archiveSent(outboxDir, entry.name);
            pushed.push(entry.name);
          } else errors.push(`push ${entry.name}: HTTP ${r.status}`);
        } catch (e: any) {
          errors.push(`push ${entry.name}: ${e.message}`);
        }
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
  // New layout: outbox/{name}-{fp}/*.json — pull from all dirs starting with our name.
  const config = await store.readConfig();
  const myName = config.name;
  const inboxDir = join(store.root, "inbox");
  await mkdir(inboxDir, { recursive: true });

  // New subdir format: pull outbox/{myName}-*/*.json into a temp dir (preserves structure),
  // then move the .json files into inbox/ (flattened). rsync --include handles the filtering;
  // we avoid ssh commands to prevent shell injection via host/path values.
  const tmpPull = join(store.root, ".tmp-outbox-pull");
  try {
    await mkdir(tmpPull, { recursive: true });
    await execFile("rsync", [
      "-az", "--ignore-existing",
      "--include", `${myName}-*/`,
      "--include", `${myName}-*/*.json`,
      "--exclude", "*",
      `${host}:${remotePath}/outbox/`,
      `${tmpPull}/`,
    ]);
    // Flatten: move .json files from subdirs into inbox/
    if (existsSync(tmpPull)) {
      for (const subEntry of await readdir(tmpPull, { withFileTypes: true })) {
        if (!subEntry.isDirectory() || !subEntry.name.startsWith(`${myName}-`)) continue;
        const subPath = join(tmpPull, subEntry.name);
        for (const fname of await readdir(subPath)) {
          if (!fname.endsWith(".json")) continue;
          const dest = join(inboxDir, fname);
          if (!existsSync(dest)) {
            await rename(join(subPath, fname), dest);
          }
        }
      }
    }
    pulled.push("outbox→inbox");
  } catch (e: any) {
    if (!String(e.stderr || e.message).includes("No such file")) {
      errors.push(`pull outbox (subdir): ${e.stderr || e.message}`);
    }
  } finally {
    // Clean up temp dir
    try { await (await import("node:fs/promises")).rm(tmpPull, { recursive: true, force: true }); } catch {}
  }

  // Legacy flat format: outbox/*_to-{name}*.json
  try {
    await execFile("rsync", [
      "-az", "--ignore-existing",
      "--include", `*_to-${myName}-*.json`,
      "--include", `*_to-${myName}.json`,
      "--include", `*_to-all.json`,
      "--exclude", "*",
      `${host}:${remotePath}/outbox/`,
      `${inboxDir}/`,
    ]);
  } catch (e: any) {
    if (!String(e.stderr || e.message).includes("No such file")) {
      errors.push(`pull outbox (legacy): ${e.stderr || e.message}`);
    }
  }

  // Push our outbox → peer inbox (scan subdirs named {peer}-{fp}/)
  const outboxDir = join(store.root, "outbox");
  if (existsSync(outboxDir)) {
    for (const entry of await readdir(outboxDir, { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name.startsWith(`${peer.name}-`)) {
        const subDir = join(outboxDir, entry.name);
        for (const fname of await readdir(subDir)) {
          if (!fname.endsWith(".json")) continue;
          const relPath = `${entry.name}/${fname}`;
          try {
            await execFile("rsync", ["-az", join(subDir, fname), `${host}:${remotePath}/inbox/${fname}`]);
            await archiveSent(outboxDir, relPath);
            pushed.push(relPath);
          } catch (e: any) {
            errors.push(`push ${relPath}: ${e.stderr || e.message}`);
          }
        }
      }
      // Legacy flat files
      if (entry.isFile() && entry.name.endsWith(".json")) {
        if (!entry.name.includes(`_to-${peer.name}-`) && !entry.name.includes(`_to-${peer.name}.json`)) continue;
        try {
          await execFile("rsync", ["-az", join(outboxDir, entry.name), `${host}:${remotePath}/inbox/${entry.name}`]);
          await archiveSent(outboxDir, entry.name);
          pushed.push(entry.name);
        } catch (e: any) {
          errors.push(`push ${entry.name}: ${e.stderr || e.message}`);
        }
      }
    }
  }

  await writeFile(join(peerDir, ".last-sync"), new Date().toISOString());
  return { peerName: peer.name, pulled, pushed, errors };
}
