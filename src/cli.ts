#!/usr/bin/env node

import { Command } from "commander";
import { nanoid } from "nanoid";
import { ContextStore, validateName, resolveKeyring } from "./store.js";
import { watchInbox, watchContext, watchSync } from "./watch.js";
import { syncAll, syncOne, deliverOne } from "./sync.js";
import * as registry from "./registry.js";
import { fingerprint } from "./crypto.js";
import { resolve, join } from "node:path";
import { readFile } from "node:fs/promises";
import { WasmCore } from "./wasm-core.js";

import { createRequire } from "node:module";
const VERSION = createRequire(import.meta.url)("../package.json").version;

// Enable proxy support: Node.js built-in fetch doesn't respect HTTP_PROXY env vars.
// Setting a global EnvHttpProxyAgent makes all fetch() calls proxy-aware —
// essential for corporate networks, containers, and tunneled environments.
if (process.env.https_proxy || process.env.HTTPS_PROXY || process.env.http_proxy || process.env.HTTP_PROXY) {
  try {
    const { EnvHttpProxyAgent, setGlobalDispatcher } = await import("undici");
    setGlobalDispatcher(new EnvHttpProxyAgent());
  } catch {}
}

const program = new Command();

program
  .name("openfuse")
  .description("The file protocol for AI agent context. Encrypted, signed, peer-to-peer.")
  .version(VERSION);

// --- init ---
program
  .command("init")
  .description("Initialize a new context store or shared workspace")
  .option("-n, --name <name>", "Agent name", "agent")
  .option("-d, --dir <path>", "Directory to init", ".")
  .option("--workspace", "Initialize as a shared workspace (CHARTER.md + tasks/ + messages/ + _broadcast/)")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (await store.exists()) {
      console.error("Context store already exists at", store.root);
      process.exit(1);
    }
    const id = nanoid(12);
    validateName(opts.name, "Agent name");
    if (opts.workspace) {
      await store.initWorkspace(opts.name, id);
      console.log(`Initialized shared workspace: ${store.root}`);
      console.log(`  Workspace: ${opts.name} (${id})`);
      console.log(`\nStructure:`);
      console.log(`  CHARTER.md   — workspace rules and purpose`);
      console.log(`  CONTEXT.md   — shared working memory`);
      console.log(`  tasks/       — task coordination`);
      console.log(`  messages/    — agent-to-agent DMs`);
      console.log(`  _broadcast/  — all-hands messages`);
    } else {
      await store.init(opts.name, id);
      const config = await store.readConfig();
      console.log(`Initialized context store: ${store.root}`);
      console.log(`  Agent ID: ${id}`);
      console.log(`  Name: ${opts.name}`);
      console.log(`  Signing key: ${config.publicKey}`);
      console.log(`  Encryption key: ${config.encryptionKey}`);
      console.log(`  Fingerprint: ${fingerprint(config.publicKey!)}`);
    }
  });

// --- status ---
program
  .command("status")
  .description("Show context store status")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (!(await store.exists())) {
      console.error("No context store found. Run `openfuse init` first.");
      process.exit(1);
    }
    const s = await store.status();
    console.log(`Agent: ${s.name} (${s.id})`);
    console.log(`Peers: ${s.peers}`);
    console.log(`Inbox: ${s.inboxCount} messages`);
    console.log(`Shared: ${s.sharedCount} files`);

    const latest = await registry.checkUpdate(VERSION);
    if (latest) {
      console.error(`\n  Update available: ${VERSION} → ${latest} — https://github.com/openfused/openfused/releases`);
    }
  });

// --- context ---
program
  .command("context")
  .description("Read or update CONTEXT.md")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-s, --set <text>", "Set context to this text")
  .option("-a, --append <text>", "Append to context")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (opts.set) {
      await store.writeContext(opts.set);
      console.log("Context updated.");
    } else if (opts.append) {
      const existing = await store.readContext();
      const text = opts.append.replace(/\\n/g, "\n");
      const timestamp = `<!-- openfuse:added: ${new Date().toISOString()} -->`;
      await store.writeContext(existing + "\n" + timestamp + "\n" + text);
      console.log("Context appended.");
    } else {
      console.log(await store.readContext());
    }
  });

// --- profile ---
program
  .command("profile")
  .description("Read or update PROFILE.md (public address card)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-s, --set <text>", "Set profile to this text")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (opts.set) {
      await store.writeProfile(opts.set);
      console.log("Profile updated locally.");

      // Push to remote endpoint if agent has an HTTP peer for itself
      const config = await store.readConfig();
      const endpoint = config.peers?.find(
        (p: any) => p.name === config.name && p.url?.startsWith("http"),
      )?.url;
      if (endpoint) {
        try {
          const { signChallenge } = await import("./crypto.js");
          const timestamp = new Date().toISOString();
          const challenge = `PROFILE:${config.name}:${timestamp}`;
          const { signature, publicKey } = await signChallenge(store.root, challenge);
          const resp = await fetch(
            `${endpoint}/profile/${encodeURIComponent(config.name)}`,
            {
              method: "PUT",
              headers: {
                "Content-Type": "text/plain",
                "X-OpenFuse-PublicKey": publicKey,
                "X-OpenFuse-Signature": signature,
                "X-OpenFuse-Timestamp": timestamp,
              },
              body: opts.set,
            },
          );
          if (resp.ok) {
            console.log("Profile synced to hosted mailbox.");
          } else {
            const err = await resp.text();
            console.error(`Failed to sync profile to mailbox: ${err}`);
          }
        } catch (e: any) {
          console.error(`Failed to sync profile: ${e.message}`);
        }
      }
    } else {
      console.log(await store.readProfile());
    }
  });

// --- inbox ---
const inbox = program.command("inbox").description("Manage inbox messages");

inbox
  .command("list")
  .description("List inbox messages")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("--raw", "Show raw content instead of wrapped")
  .option("--all", "Show all messages including unverified (default: verified only)")
  .option("--no-sync", "Skip pulling from remote peers before listing")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    // Auto-sync: pull new messages from remote peers before listing
    if (opts.sync !== false) {
      try {
        const config = await store.readConfig();
        if (config.peers.length > 0) {
          const { syncAll } = await import("./sync.js");
          await syncAll(store);
        }
      } catch {}
    }
    const allMessages = await store.readInbox();
    // Default: only show verified messages. Unverified messages from unknown
    // senders are hidden to prevent prompt injection. Use --all to see them.
    const messages = opts.all ? allMessages : allMessages.filter((m: any) => m.verified);
    const hidden = allMessages.length - messages.length;
    if (messages.length === 0 && hidden === 0) {
      console.log("Inbox is empty.");
      return;
    }
    if (messages.length === 0 && hidden > 0) {
      console.log(`Inbox has ${hidden} unverified message(s) from untrusted senders.`);
      console.log(`Run with --all to see them, or trust the sender: openfuse key trust <name>`);
      return;
    }
    for (const msg of messages) {
      const badge = msg.verified ? "[VERIFIED]" : "[UNVERIFIED]";
      const enc = msg.encrypted ? " [ENCRYPTED]" : "";
      console.log(`\n--- ${badge}${enc} From: ${msg.from} | ${msg.time} ---`);
      console.log(opts.raw ? msg.content : msg.wrappedContent);
    }
    if (hidden > 0) {
      console.log(`\n(${hidden} unverified message(s) hidden — use --all to show)`);
    }
  });

inbox
  .command("archive [file]")
  .description("Archive inbox message(s) to inbox/.read/ — specific file or --all")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("--all", "Archive all inbox messages")
  .action(async (file, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const { readdir: rd, mkdir, rename } = await import("node:fs/promises");
    const { join, basename } = await import("node:path");
    const inboxDir = join(store.root, "inbox");
    const readDir = join(inboxDir, ".read");
    await mkdir(readDir, { recursive: true });

    if (opts.all) {
      const files = (await rd(inboxDir)).filter(f => f.endsWith(".json") || f.endsWith(".md"));
      for (const f of files) await rename(join(inboxDir, f), join(readDir, f));
      console.log(`Archived ${files.length} messages.`);
    } else if (file) {
      const safe = basename(file);
      try {
        await rename(join(inboxDir, safe), join(readDir, safe));
        console.log(`Archived: ${safe}`);
      } catch {
        console.error(`Not found in inbox: ${safe}`);
        process.exit(1);
      }
    } else {
      console.error("Specify a filename or use --all");
      process.exit(1);
    }
  });

inbox
  .command("send <peerId> <message>")
  .description("Send a message to a peer's inbox")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (peerId, message, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    await store.sendInbox(peerId, message);

    // Find the outbox file we just created
    const outboxFile = findNewestOutboxFile(store.root, peerId);
    if (outboxFile) {
      const delivered = await deliverOne(store, peerId, outboxFile);
      if (delivered) {
        console.log(`Delivered to ${peerId}.`);
        return;
      }
    }
    console.log(`Queued for ${peerId}. Will deliver on next sync.`);
  });

// --- watch ---
program
  .command("watch")
  .description("Watch for inbox messages, context changes, and sync with peers")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("--sync-interval <seconds>", "Peer sync interval in seconds (0 to disable)", "60")
  .option("--tunnel <host>", "Reverse SSH tunnel to host for NAT traversal (uses autossh if available)")
  .option("--tunnel-port <port>", "Remote port for reverse SSH tunnel", "2222")
  .option("--cloudflared", "Start a cloudflared quick tunnel (no config needed, gives you a public URL)")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (!(await store.exists())) {
      console.error("No context store found. Run `openfuse init` first.");
      process.exit(1);
    }
    const config = await store.readConfig();
    const interval = parseInt(opts.syncInterval) * 1000;

    console.log(`Watching context store: ${config.name} (${config.id})`);
    if (config.peers.length > 0 && interval > 0) {
      console.log(`Syncing with ${config.peers.length} peer(s) every ${opts.syncInterval}s`);
    }

    // Reverse SSH tunnel (optional)
    if (opts.tunnel) {
      const { spawn } = await import("node:child_process");
      const tunnelPort = opts.tunnelPort;
      const tunnelHost = opts.tunnel;

      // Prevent SSH option injection: reject values that look like flags
      if (tunnelHost.startsWith("-") || /\s/.test(tunnelHost)) {
        console.error("Invalid --tunnel value: must be a hostname, not flags");
        process.exit(1);
      }
      if (tunnelPort.startsWith("-") || /\s/.test(tunnelPort) || !/^\d+$/.test(tunnelPort)) {
        console.error("Invalid --tunnel-port value: must be a numeric port");
        process.exit(1);
      }

      // Try autossh first, fall back to ssh
      const cmd = await (async () => {
        try {
          const { execFileSync } = await import("node:child_process");
          execFileSync("which", ["autossh"], { stdio: "ignore" });
          return "autossh";
        } catch {
          return "ssh";
        }
      })();

      const args = cmd === "autossh"
        ? ["-M", "0", "-N", "-R", `${tunnelPort}:localhost:2053`, tunnelHost, "-o", "ServerAliveInterval=15", "-o", "ExitOnForwardFailure=yes"]
        : ["-N", "-R", `${tunnelPort}:localhost:2053`, tunnelHost, "-o", "ServerAliveInterval=15", "-o", "ExitOnForwardFailure=yes"];

      const tunnel = spawn(cmd, args, { stdio: "ignore" });
      tunnel.on("error", (e) => console.error(`[tunnel] ${cmd} failed: ${e.message}`));
      tunnel.on("exit", (code) => {
        if (code !== 0) console.error(`[tunnel] ${cmd} exited with code ${code}`);
      });
      process.on("exit", () => tunnel.kill());

      console.log(`Tunnel: ${cmd} -R ${tunnelPort}:localhost:2053 ${tunnelHost}`);
      console.log(`Your store is reachable at ssh://${tunnelHost}:${tunnelPort} (via daemon on :2053)`);
    }

    // Cloudflared quick tunnel (optional) — gives you a public *.trycloudflare.com URL
    if (opts.cloudflared) {
      const { spawn } = await import("node:child_process");
      const cf = spawn("cloudflared", ["tunnel", "--url", "http://localhost:2053"], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      cf.on("error", (e) => console.error(`[cloudflared] failed: ${e.message}. Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/`));
      cf.stderr.on("data", (data: Buffer) => {
        const line = data.toString();
        const match = line.match(/https:\/\/[^\s]+\.trycloudflare\.com/);
        if (match) {
          console.log(`[cloudflared] Your public URL: ${match[0]}`);
          console.log(`  Register it: openfuse register --endpoint ${match[0]}`);
        }
      });
      process.on("exit", () => cf.kill());
      console.log("Starting cloudflared tunnel...");
    }

    console.log(`Press Ctrl+C to stop.\n`);

    watchInbox(store.root, (from, message) => {
      console.log(`\n[inbox] New message from ${from}:`);
      console.log(message);
    });

    watchContext(store.root, () => {
      console.log(`\n[context] CONTEXT.md updated`);
    });

    if (config.peers.length > 0 && interval > 0) {
      watchSync(
        store,
        interval,
        (peer, pulled, pushed) => {
          const parts: string[] = [];
          if (pulled.length) parts.push(`pulled ${pulled.length} files`);
          if (pushed.length) parts.push(`pushed ${pushed.length} messages`);
          console.log(`\n[sync] ${peer}: ${parts.join(", ")}`);
        },
        (peer, errors) => {
          for (const e of errors) console.error(`\n[sync] ${peer}: ${e}`);
        },
      );
    }

    await new Promise(() => {});
  });

// --- compact ---
program
  .command("compact")
  .description("Move [DONE] sections from CONTEXT.md to history/")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("--prune-stale", "Also archive sections past their <!-- validity: --> window (confidence < 0.1)")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    let prunedCount = 0;

    if (opts.pruneStale) {
      const core = new WasmCore(resolve(opts.dir));
      prunedCount = await core.pruneStale();
    }

    const { moved, kept } = await store.compactContext();
    if (moved === 0 && prunedCount === 0) {
      console.log("Nothing to compact. Mark sections with [DONE] to archive them.");
    } else {
      const parts: string[] = [];
      if (moved > 0) parts.push(`${moved} done`);
      if (prunedCount > 0) parts.push(`${prunedCount} stale`);
      console.log(`Compacted: ${parts.join(", ")}, ${kept} kept.`);
    }
  });

// --- validate ---
program
  .command("validate")
  .description("Scan CONTEXT.md for expired validity windows and report stale entries")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("--json", "Output as JSON")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (!(await store.exists())) {
      console.error("No context store found. Run `openfuse init` first.");
      process.exit(1);
    }
    const core = new WasmCore(resolve(opts.dir));
    const report = await core.validate();

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    const total = report.entries.length;
    if (total === 0) {
      console.log("No validity-annotated sections found.");
      console.log("Add `<!-- validity: 6h -->` before time-sensitive context entries.");
      return;
    }

    console.log(`Validity check: ${report.fresh} fresh, ${report.stale} stale (of ${total} annotated)`);
    if (report.stale > 0) {
      console.log("\nStale sections (confidence < 0.5):");
      for (const e of report.entries.filter((e) => e.expired)) {
        const age = e.added ? ` written ${e.added}` : "";
        console.log(`  [${e.ttl_str} TTL${age}] ${e.header}`);
      }
      console.log("\nRun `openfuse compact --prune-stale` to archive stale sections.");
    } else {
      console.log("All annotated sections are within their validity windows.");
    }
  });

// --- share ---
program
  .command("share <file>")
  .description("Share a file with the mesh")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (file, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const content = await readFile(resolve(file), "utf-8");
    const filename = file.split("/").pop()!;
    await store.share(filename, content);
    console.log(`Shared: ${filename}`);
  });

// --- peer ---
const peer = program.command("peer").description("Manage peers");

peer
  .command("list")
  .description("List connected peers")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    if (config.peers.length === 0) {
      console.log("No peers connected.");
      return;
    }
    for (const p of config.peers) {
      console.log(`  ${p.name} (${p.id}) — ${p.url} [${p.access}]`);
    }
  });

peer
  .command("add <url>")
  .description("Add a peer by URL (http:// for WAN, ssh://host:/path for LAN)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-n, --name <name>", "Peer name")
  .option("-a, --access <mode>", "Access mode: read or readwrite", "read")
  .action(async (url, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const peerId = nanoid(12);
    const peerName = opts.name ?? `peer-${config.peers.length + 1}`;
    validateName(peerName, "Peer name");
    config.peers.push({
      id: peerId,
      name: peerName,
      url,
      access: opts.access as "read" | "readwrite",
    });
    await store.writeConfig(config);
    console.log(`Added peer: ${peerName} (${url}) [${opts.access}]`);
  });

peer
  .command("remove <id>")
  .description("Remove a peer by ID or name")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (id, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    config.peers = config.peers.filter((p) => p.id !== id && p.name !== id);
    await store.writeConfig(config);
    console.log(`Removed peer: ${id}`);
  });

// --- key ---
const key = program.command("key").description("Manage keys and keyring");

key
  .command("show")
  .description("Show this agent's public keys")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    console.log(`Signing key:    ${config.publicKey ?? "(none)"}`);
    console.log(`Encryption key: ${config.encryptionKey ?? "(none)"}`);
    console.log(`Fingerprint:    ${fingerprint(config.publicKey ?? "")}`);
  });

key
  .command("list")
  .description("List all keys in the keyring (like gpg --list-keys)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    console.log(`${config.name}  (self)`);
    console.log(`  signing:    ${config.publicKey}`);
    console.log(`  encryption: ${config.encryptionKey}`);
    console.log(`  fingerprint: ${fingerprint(config.publicKey ?? "")}\n`);

    if (config.keyring.length === 0) {
      console.log("Keyring is empty. Import keys with: openfuse key import <name> <keyfile>");
      return;
    }
    // Detect name collisions for display
    const nameCounts = new Map<string, number>();
    for (const e of config.keyring) nameCounts.set(e.name, (nameCounts.get(e.name) || 0) + 1);

    for (const e of config.keyring) {
      const trust = e.trusted ? "[TRUSTED]" : "[untrusted]";
      const addr = e.address || "(no address)";
      const shortFp = e.fingerprint.replace(/:/g, "").slice(0, 8);
      // Show fingerprint suffix when names collide so user knows how to disambiguate
      const displayName = (nameCounts.get(e.name) || 0) > 1
        ? `${e.name}:${shortFp}`
        : e.name;
      console.log(`${displayName}  ${addr}  ${trust}`);
      console.log(`  signing:    ${e.signingKey}`);
      console.log(`  encryption: ${e.encryptionKey ?? "(no age key)"}`);
      console.log(`  fingerprint: ${e.fingerprint}\n`);
    }
  });

key
  .command("import <name> <signingKeyFile>")
  .description("Import a peer's signing key")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-e, --encryption-key <key>", "age encryption key (age1...)")
  .option("-@ , --address <addr>", "Address (e.g. wisp@alice.local)")
  .action(async (name, signingKeyFile, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const signingKey = (await readFile(resolve(signingKeyFile), "utf-8")).trim();
    const fp = fingerprint(signingKey);

    if (config.keyring.some((e) => e.signingKey === signingKey)) {
      console.log(`Key already in keyring (fingerprint: ${fp})`);
      return;
    }

    const autoTrust = config.autoTrust ?? false;
    config.keyring.push({
      name,
      address: opts.address ?? "",
      signingKey,
      encryptionKey: opts.encryptionKey,
      fingerprint: fp,
      trusted: autoTrust,
      added: new Date().toISOString(),
    });
    await store.writeConfig(config);
    console.log(`Imported key for: ${name}`);
    console.log(`  Fingerprint: ${fp}`);
    if (autoTrust) {
      console.log(`  Auto-trusted (workspace mode)`);
    } else {
      console.log(`\nKey is NOT trusted yet. Run: openfuse key trust ${name}`);
    }
  });

key
  .command("trust <query>")
  .description("Trust a key in the keyring (name, name:fingerprint, or fingerprint)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (query, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const entry = resolveKeyring(config.keyring, query);
    entry.trusted = true;
    await store.writeConfig(config);
    console.log(`Trusted: ${entry.name} (${entry.fingerprint})`);
  });

key
  .command("untrust <query>")
  .description("Revoke trust for a key (name, name:fingerprint, or fingerprint)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (query, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const entry = resolveKeyring(config.keyring, query);
    entry.trusted = false;
    await store.writeConfig(config);
    console.log(`Revoked trust: ${entry.name} (${entry.fingerprint})`);
  });

key
  .command("export")
  .description("Export this agent's public keys for sharing")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    console.log(`# OpenFuse key export: ${config.name} (${config.id})`);
    console.log(`# Fingerprint: ${fingerprint(config.publicKey ?? "")}`);
    console.log(`signing:${config.publicKey}`);
    console.log(`encryption:${config.encryptionKey}`);
  });

// --- sync ---
program
  .command("sync [peer]")
  .description("Sync with peers (pull context, push outbox)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (peerName, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (!(await store.exists())) {
      console.error("No context store found. Run `openfuse init` first.");
      process.exit(1);
    }

    const results = peerName ? [await syncOne(store, peerName)] : await syncAll(store);

    for (const r of results) {
      console.log(`--- ${r.peerName} ---`);
      if (r.pulled.length) console.log(`  pulled: ${r.pulled.join(", ")}`);
      if (r.pushed.length) console.log(`  pushed: ${r.pushed.join(", ")}`);
      for (const e of r.errors) console.error(`  error: ${e}`);
      if (!r.pulled.length && !r.pushed.length && !r.errors.length) {
        console.log("  (nothing to sync)");
      }
    }

    if (results.length === 0) {
      console.log("No peers configured. Add one with: openfuse peer add <url>");
    }
  });

// --- register ---
program
  .command("register")
  .description("Register this agent in the public registry")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-n, --name <name>", "Full agent name (defaults to {storename}.openfused.net, or set your own domain)")
  .option("-e, --endpoint <url>", "Endpoint URL where peers can reach you (optional — keys-only registration without endpoint)")
  .option("-r, --registry <url>", "Registry URL")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const reg = registry.resolveRegistry(opts.registry);
    const config = await store.readConfig();
    const agentName = opts.name || `${config.name}.openfused.net`;
    const manifest = await registry.register(store, opts.endpoint || "", reg, agentName);

    // Auto-add endpoint as a peer so sync/inbox list can pull from it
    if (manifest.endpoint?.startsWith("http")) {
      const config2 = await store.readConfig();
      const selfName = config2.name;
      if (!config2.peers.some((p: any) => p.url === manifest.endpoint && p.name === selfName)) {
        config2.peers.push({
          id: (await import("nanoid")).nanoid(12),
          name: selfName,
          url: manifest.endpoint,
          access: "read" as const,
        });
        await store.writeConfig(config2);
      }
    }

    console.log(`Registered: ${manifest.name} [SIGNED]`);
    if (manifest.endpoint) console.log(`  Endpoint:    ${manifest.endpoint}`);
    else console.log(`  Endpoint:    (none — keys-only registration)`);
    console.log(`  Fingerprint: ${manifest.fingerprint}`);
    console.log(`  DNS:         _openfuse.${manifest.name}`);
    console.log(`  Registry:    ${reg}`);
    console.log(`\nOthers can find you with:`);
    console.log(`  openfuse discover ${manifest.name}`);
    console.log(`  openfuse send ${manifest.name} "hello"`);
  });

// --- discover ---
program
  .command("discover <name>")
  .description("Look up an agent by name in the registry")
  .option("-r, --registry <url>", "Registry URL")
  .action(async (name, opts) => {
    const reg = registry.resolveRegistry(opts.registry);
    const manifest = await registry.discover(name, reg);
    const status = manifest.revoked
      ? "[REVOKED]"
      : manifest.signature
        ? "[SIGNED]"
        : "[unsigned]";
    console.log(`${manifest.name}  ${status}`);
    if (manifest.revoked) console.log(`  ⚠ KEY REVOKED at ${manifest.revokedAt}`);
    if (manifest.rotatedFrom) console.log(`  Rotated from: ${fingerprint(manifest.rotatedFrom)}`);
    console.log(`  Endpoint:       ${manifest.endpoint}`);
    console.log(`  Signing key:    ${manifest.publicKey}`);
    if (manifest.encryptionKey) console.log(`  Encryption key: ${manifest.encryptionKey}`);
    console.log(`  Fingerprint:    ${manifest.fingerprint}`);
    console.log(`  Capabilities:   ${manifest.capabilities.join(", ")}`);
    console.log(`  Created:        ${manifest.created}`);
  });

// --- send ---
// Helper: find the newest outbox file for a recipient
import { readdirSync, statSync } from "node:fs";
function findNewestOutboxFile(storeRoot: string, name: string): string {
  const outboxDir = join(storeRoot, "outbox");
  try {
    for (const entry of readdirSync(outboxDir)) {
      if (entry.startsWith(`${name}-`) && statSync(join(outboxDir, entry)).isDirectory()) {
        const files = readdirSync(join(outboxDir, entry))
          .filter((f: string) => f.endsWith(".json"))
          .sort()
          .reverse();
        if (files.length > 0) return join(entry, files[0]);
      }
    }
  } catch {}
  return "";
}

program
  .command("send <name> <message>")
  .description("Send a message to an agent")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-r, --registry <url>", "Registry URL")
  .option("--http", "Force HTTP delivery (uses registry endpoint)")
  .option("--ssh", "Force SSH delivery (uses local peer SSH URL)")
  .option("--trust", "Auto-trust the recipient's key (skip manual fingerprint verification)")
  .action(async (name: string, message: string, opts: { dir: string; registry?: string; http?: boolean; ssh?: boolean; trust?: boolean }) => {
    const store = new ContextStore(resolve(opts.dir));
    const reg = registry.resolveRegistry(opts.registry);
    let config = await store.readConfig();

    // Ensure recipient is known — check local peers, then registry
    const existingPeer = config.peers.find((p) => p.name === name);
    let httpEndpoint = existingPeer?.url?.startsWith("http") ? existingPeer.url : "";
    let sshUrl = existingPeer?.url?.startsWith("ssh") ? existingPeer.url : "";

    // If --http forced or no local peer, discover from registry
    if (opts.http || !existingPeer) {
      try {
        const manifest = await registry.discover(name, reg);
        if (manifest.endpoint?.startsWith("http")) httpEndpoint = manifest.endpoint;

        // Auto-import key + add as peer
        const existing = config.keyring.find((e) => e.signingKey === manifest.publicKey);
        if (!existing) {
          config.keyring.push({
            name: manifest.name,
            address: `${manifest.name}@registry`,
            signingKey: manifest.publicKey,
            encryptionKey: manifest.encryptionKey,
            fingerprint: manifest.fingerprint,
            trusted: !!opts.trust,
            added: new Date().toISOString(),
          });
          if (opts.trust) {
            console.log(`Trusted ${manifest.name} (${manifest.fingerprint})`);
          }
        } else if (opts.trust && !existing.trusted) {
          existing.trusted = true;
          console.log(`Trusted ${manifest.name} (${existing.fingerprint})`);
        }
        if (manifest.endpoint && !config.peers.some((p) => p.name === manifest.name)) {
          config.peers.push({
            id: (await import("nanoid")).nanoid(12),
            name: manifest.name,
            url: manifest.endpoint,
            access: "read" as const,
          });
        }
        await store.writeConfig(config);
      } catch {
        if (!existingPeer && !config.keyring.some((k) => k.name === name)) {
          console.error(`Agent '${name}' not found in local peers or registry.`);
          process.exit(1);
        }
      }
    }

    // Create signed message in outbox
    await store.sendInbox(name, message);
    const outboxFile = findNewestOutboxFile(store.root, name);
    if (!outboxFile) {
      console.log(`Queued for ${name}.`);
      return;
    }

    // Determine delivery method
    const forceHttp = opts.http;
    const forceSsh = opts.ssh;

    // --ssh: deliver via local peer SSH
    if (forceSsh) {
      if (!sshUrl) {
        console.log(`Queued for ${name}. No SSH peer configured — use \`openfuse peer add ssh://...\`.`);
        return;
      }
      const delivered = await deliverOne(store, name, outboxFile);
      console.log(delivered ? `Delivered to ${name} via SSH.` : `Queued for ${name}. SSH delivery failed — run \`openfuse sync\`.`);
      return;
    }

    // --http or default with HTTP endpoint: deliver via HTTP
    if ((forceHttp || !sshUrl) && httpEndpoint) {
      try {
        const { checkSsrf } = await import("./sync.js");
        await checkSsrf(httpEndpoint);
        const body = await readFile(join(store.root, "outbox", outboxFile), "utf-8");
        const inboxUrl = `${httpEndpoint.replace(/\/$/, "")}/inbox/${encodeURIComponent(name)}`;
        const r = await fetch(inboxUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        });
        if (r.ok) {
          const { mkdir, rename } = await import("node:fs/promises");
          const filePath = join(store.root, "outbox", outboxFile);
          const sentDir = join(filePath, "..", ".sent");
          const baseName = outboxFile.split("/").pop()!;
          await mkdir(sentDir, { recursive: true });
          await rename(filePath, join(sentDir, baseName));
          console.log(`Delivered to ${name}.`);
        } else {
          console.log(`Queued for ${name}. Endpoint returned ${r.status}.`);
        }
      } catch (e: any) {
        console.log(`Queued for ${name}. Run \`openfuse sync\` to deliver.`);
        if (process.env.DEBUG) console.error(`  Delivery error: ${e.message}`);
      }
      return;
    }

    // Default: try local peer (SSH or HTTP)
    if (existingPeer) {
      const delivered = await deliverOne(store, name, outboxFile);
      console.log(delivered ? `Delivered to ${name}.` : `Queued for ${name}. Run \`openfuse sync\` to deliver.`);
      return;
    }

    console.log(`Queued for ${name}. No endpoint — they'll need to pull from your outbox.`);
  });

// --- tasks (A2A) ---
const tasks = program.command("tasks").description("Manage A2A tasks on the daemon");

tasks
  .command("list")
  .description("List all tasks from the daemon")
  .option("--url <url>", "Daemon URL", "http://127.0.0.1:2053")
  .option("--token <token>", "Bearer token (also reads OPENFUSE_TOKEN env)")
  .option("--json", "Output raw JSON")
  .action(async (opts: { url: string; token?: string; json?: boolean }) => {
    const token = opts.token || process.env.OPENFUSE_TOKEN;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch(`${opts.url}/tasks`, { headers });
    if (!res.ok) {
      const body = await res.text();
      console.error(`Error ${res.status}: ${body}`);
      process.exit(1);
    }
    const data = (await res.json()) as { tasks: any[] };

    if (opts.json) {
      console.log(JSON.stringify(data.tasks, null, 2));
      return;
    }

    if (data.tasks.length === 0) {
      console.log("No tasks.");
      return;
    }

    for (const t of data.tasks) {
      const created = t._openfuse?.createdAt?.slice(0, 19) || "";
      const msgs = t.history?.length || 0;
      const arts = t.artifacts?.length || 0;
      console.log(`  ${t.id}  [${t.status.state}]  ${msgs} msg, ${arts} artifact  ${created}`);
    }
  });

tasks
  .command("get <id>")
  .description("Get a specific task by ID")
  .option("--url <url>", "Daemon URL", "http://127.0.0.1:2053")
  .option("--token <token>", "Bearer token (also reads OPENFUSE_TOKEN env)")
  .option("--json", "Output raw JSON")
  .action(async (id: string, opts: { url: string; token?: string; json?: boolean }) => {
    const token = opts.token || process.env.OPENFUSE_TOKEN;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch(`${opts.url}/tasks/${encodeURIComponent(id)}`, { headers });
    if (!res.ok) {
      const body = await res.text();
      console.error(`Error ${res.status}: ${body}`);
      process.exit(1);
    }
    const task = (await res.json()) as any;

    if (opts.json) {
      console.log(JSON.stringify(task, null, 2));
      return;
    }

    console.log(`Task:    ${task.id}`);
    console.log(`State:   ${task.status.state}`);
    if (task.contextId) console.log(`Context: ${task.contextId}`);
    if (task._openfuse) {
      console.log(`Created: ${task._openfuse.createdAt}`);
      console.log(`Updated: ${task._openfuse.updatedAt}`);
    }

    if (task.history?.length > 0) {
      console.log(`\nHistory (${task.history.length} messages):`);
      for (const msg of task.history) {
        const text = msg.parts?.map((p: any) => p.text).filter(Boolean).join(" ") || "(non-text)";
        console.log(`  [${msg.role}] ${text.slice(0, 120)}`);
      }
    }

    if (task.artifacts?.length > 0) {
      console.log(`\nArtifacts (${task.artifacts.length}):`);
      for (const a of task.artifacts) {
        console.log(`  ${a.artifactId}: ${a.name || "(unnamed)"}`);
      }
    }
  });

program.parse();
