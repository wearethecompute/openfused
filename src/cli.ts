#!/usr/bin/env node

import { Command } from "commander";
import { nanoid } from "nanoid";
import { ContextStore } from "./store.js";
import { watchInbox, watchContext, watchSync } from "./watch.js";
import { syncAll, syncOne, deliverOne } from "./sync.js";
import * as registry from "./registry.js";
import { fingerprint } from "./crypto.js";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

const VERSION = "0.3.5";

const program = new Command();

program
  .name("openfuse")
  .description("Decentralized context mesh for AI agents. The protocol is files.")
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
      console.error(`\n  Update available: ${VERSION} → ${latest} — https://github.com/wearethecompute/openfused/releases`);
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
      console.log("Profile updated.");
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
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const messages = await store.readInbox();
    if (messages.length === 0) {
      console.log("Inbox is empty.");
      return;
    }
    for (const msg of messages) {
      const badge = msg.verified ? "[VERIFIED]" : "[UNVERIFIED]";
      const enc = msg.encrypted ? " [ENCRYPTED]" : "";
      console.log(`\n--- ${badge}${enc} From: ${msg.from} | ${msg.time} ---`);
      console.log(opts.raw ? msg.content : msg.wrappedContent);
    }
  });

inbox
  .command("archive <file>")
  .description("Archive a specific inbox message to inbox/.read/")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (file, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const { mkdir, rename } = await import("node:fs/promises");
    const { join, basename } = await import("node:path");
    const safe = basename(file);
    const inboxDir = join(store.root, "inbox");
    const readDir = join(inboxDir, ".read");
    await mkdir(readDir, { recursive: true });
    try {
      await rename(join(inboxDir, safe), join(readDir, safe));
      console.log(`Archived: ${safe}`);
    } catch {
      console.error(`Not found in inbox: ${safe}`);
      process.exit(1);
    }
  });

inbox
  .command("send <peerId> <message>")
  .description("Send a message to a peer's inbox")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (peerId, message, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const filename = await store.sendInbox(peerId, message);

    // Try immediate delivery — if peer is reachable, deliver now
    const delivered = await deliverOne(store, peerId, filename);
    if (delivered) {
      console.log(`Delivered to ${peerId}.`);
    } else {
      console.log(`Queued for ${peerId}. Will deliver on next sync.`);
    }
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
        ? ["-M", "0", "-N", "-R", `${tunnelPort}:localhost:9781`, tunnelHost, "-o", "ServerAliveInterval=15", "-o", "ExitOnForwardFailure=yes"]
        : ["-N", "-R", `${tunnelPort}:localhost:9781`, tunnelHost, "-o", "ServerAliveInterval=15", "-o", "ExitOnForwardFailure=yes"];

      const tunnel = spawn(cmd, args, { stdio: "ignore" });
      tunnel.on("error", (e) => console.error(`[tunnel] ${cmd} failed: ${e.message}`));
      tunnel.on("exit", (code) => {
        if (code !== 0) console.error(`[tunnel] ${cmd} exited with code ${code}`);
      });
      process.on("exit", () => tunnel.kill());

      console.log(`Tunnel: ${cmd} -R ${tunnelPort}:localhost:9781 ${tunnelHost}`);
      console.log(`Your store is reachable at ssh://${tunnelHost}:${tunnelPort} (via daemon on :9781)`);
    }

    // Cloudflared quick tunnel (optional) — gives you a public *.trycloudflare.com URL
    if (opts.cloudflared) {
      const { spawn } = await import("node:child_process");
      const cf = spawn("cloudflared", ["tunnel", "--url", "http://localhost:9781"], {
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
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const { moved, kept } = await store.compactContext();
    if (moved === 0) {
      console.log("Nothing to compact. Mark sections with [DONE] to archive them.");
    } else {
      console.log(`Compacted: ${moved} done, ${kept} kept.`);
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
    config.peers.push({
      id: peerId,
      name: opts.name ?? `peer-${config.peers.length + 1}`,
      url,
      access: opts.access as "read" | "readwrite",
    });
    await store.writeConfig(config);
    console.log(`Added peer: ${opts.name ?? peerId} (${url}) [${opts.access}]`);
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
    for (const e of config.keyring) {
      const trust = e.trusted ? "[TRUSTED]" : "[untrusted]";
      const addr = e.address || "(no address)";
      console.log(`${e.name}  ${addr}  ${trust}`);
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

    config.keyring.push({
      name,
      address: opts.address ?? "",
      signingKey,
      encryptionKey: opts.encryptionKey,
      fingerprint: fp,
      trusted: false,
      added: new Date().toISOString(),
    });
    await store.writeConfig(config);
    console.log(`Imported key for: ${name}`);
    console.log(`  Fingerprint: ${fp}`);
    console.log(`\nKey is NOT trusted yet. Run: openfuse key trust ${name}`);
  });

key
  .command("trust <name>")
  .description("Trust a key in the keyring")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (name, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const entry = config.keyring.find((e) => e.name === name || e.fingerprint === name);
    if (!entry) {
      console.error(`Key not found: ${name}`);
      process.exit(1);
    }
    entry.trusted = true;
    await store.writeConfig(config);
    console.log(`Trusted: ${entry.name} (${entry.fingerprint})`);
  });

key
  .command("untrust <name>")
  .description("Revoke trust for a key")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (name, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const entry = config.keyring.find((e) => e.name === name || e.fingerprint === name);
    if (!entry) {
      console.error(`Key not found: ${name}`);
      process.exit(1);
    }
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
  .requiredOption("-e, --endpoint <url>", "Endpoint URL where peers can reach you")
  .option("-r, --registry <url>", "Registry URL")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const reg = registry.resolveRegistry(opts.registry);
    const manifest = await registry.register(store, opts.endpoint, reg);
    console.log(`Registered: ${manifest.name} [SIGNED]`);
    console.log(`  Endpoint:    ${manifest.endpoint}`);
    console.log(`  Fingerprint: ${manifest.fingerprint}`);
    console.log(`  Registry:    ${reg}`);
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
program
  .command("send <name> <message>")
  .description("Send a message to an agent (resolves via registry)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-r, --registry <url>", "Registry URL")
  .action(async (name, message, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const reg = registry.resolveRegistry(opts.registry);

    try {
      const manifest = await registry.discover(name, reg);
      const config = await store.readConfig();

      // Auto-import key (untrusted)
      if (!config.keyring.some((e) => e.signingKey === manifest.publicKey)) {
        config.keyring.push({
          name: manifest.name,
          address: `${manifest.name}@registry`,
          signingKey: manifest.publicKey,
          encryptionKey: manifest.encryptionKey,
          fingerprint: manifest.fingerprint,
          trusted: false,
          added: new Date().toISOString(),
        });
        await store.writeConfig(config);
        console.log(`Imported key for ${manifest.name} from registry [untrusted]`);
        console.log(`  Run \`openfuse key trust ${manifest.name}\` to trust`);
      }

      await store.sendInbox(name, message);
      console.log(`Message queued in outbox for ${name}. Run \`openfuse sync\` to deliver.`);
    } catch {
      // Not in registry — send as a peer message
      await store.sendInbox(name, message);
      console.log(`Message sent to ${name}'s outbox.`);
    }
  });

program.parse();
