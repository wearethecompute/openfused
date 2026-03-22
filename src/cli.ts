#!/usr/bin/env node

import { Command } from "commander";
import { nanoid } from "nanoid";
import { ContextStore, validateName } from "./store.js";
import { watchInbox, watchContext, watchSync } from "./watch.js";
import { syncAll, syncOne, deliverOne } from "./sync.js";
import * as registry from "./registry.js";
import { fingerprint } from "./crypto.js";
import { resolve, join } from "node:path";
import { readFile } from "node:fs/promises";
import { parseValiditySections, buildValidityReport } from "./validity.js";

const VERSION = "0.3.13";

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
      // Soft-expiry pruning: rewrite CONTEXT.md with stale sections stripped
      const content = await store.readContext();
      const sections = parseValiditySections(content);
      const staleSections = sections.filter((s) => s.expired);

      if (staleSections.length > 0) {
        // Remove stale annotated sections from file
        let updated = content;
        for (const s of staleSections) {
          // Strip the section text from the file (simple text removal)
          updated = updated.replace(s.sectionText, "[STALE — archived by openfuse compact --prune-stale]");
        }
        await store.writeContext(updated);
        prunedCount = staleSections.length;
      }
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
    const content = await store.readContext();
    const sections = parseValiditySections(content);
    const report = buildValidityReport(sections);

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    if (report.total === 0) {
      console.log("No validity-annotated sections found.");
      console.log("Add `<!-- validity: 6h -->` before time-sensitive context entries.");
      return;
    }

    console.log(`Validity check: ${report.fresh} fresh, ${report.stale} stale (of ${report.total} annotated)`);
    if (report.stale > 0) {
      console.log("\nStale sections (confidence < 0.1):");
      for (const e of report.entries.filter((e) => e.expired)) {
        const age = e.addedAt ? ` written ${e.addedAt}` : "";
        console.log(`  [${e.ttlLabel} TTL${age}] ${e.preview}`);
      }
      console.log("\nRun `openfuse compact --prune-stale` to archive stale sections.");
    } else {
      console.log("All annotated sections are within their validity windows. ✓");
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
  .option("-n, --name <name>", "Full agent name (defaults to {storename}.openfused.net, or set your own domain)")
  .requiredOption("-e, --endpoint <url>", "Endpoint URL where peers can reach you")
  .option("-r, --registry <url>", "Registry URL")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const reg = registry.resolveRegistry(opts.registry);
    const config = await store.readConfig();
    const agentName = opts.name || `${config.name}.openfused.net`;
    const manifest = await registry.register(store, opts.endpoint, reg, agentName);
    console.log(`Registered: ${manifest.name} [SIGNED]`);
    console.log(`  Endpoint:    ${manifest.endpoint}`);
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

      // Auto-import key (untrusted) + add as peer so future `openfuse sync` can
      // deliver replies and pull context. Key is deliberately NOT trusted — the user
      // must explicitly `openfuse key trust <name>` after out-of-band verification.
      // NOTE: manifest data comes from the registry and is attacker-controlled.
      // The endpoint URL is stored as-is; a malicious entry could point at an internal
      // service. Sync will pull from it — consider validating URL scheme/host.
      let config = await store.readConfig();
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

      const filename = await store.sendInbox(name, message);

      // Try direct HTTP delivery if endpoint is http(s)
      if (manifest.endpoint.startsWith("http")) {
        try {
          // SSRF check: registry endpoints are attacker-controlled
          const { checkSsrf } = await import("./sync.js");
          await checkSsrf(manifest.endpoint);
          const body = await readFile(join(store.root, "outbox", filename), "utf-8");
          const r = await fetch(`${manifest.endpoint.replace(/\/$/, "")}/inbox`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
          });
          if (r.ok) {
            // Archive to .sent/
            const { mkdir, rename } = await import("node:fs/promises");
            const sentDir = join(store.root, "outbox", ".sent");
            await mkdir(sentDir, { recursive: true });
            await rename(join(store.root, "outbox", filename), join(sentDir, filename));
            console.log(`Delivered to ${name}.`);
          } else {
            console.log(`Queued for ${name}. Endpoint returned ${r.status}. Will deliver on next sync.`);
          }
        } catch {
          console.log(`Queued for ${name}. Will deliver on next sync.`);
        }
      } else {
        console.log(`Queued for ${name}. Run \`openfuse sync\` to deliver.`);
      }
    } catch {
      // Not in registry — send as a peer message
      const filename = await store.sendInbox(name, message);
      const delivered = await deliverOne(store, name, filename);
      if (delivered) {
        console.log(`Delivered to ${name}.`);
      } else {
        console.log(`Queued for ${name}. Run \`openfuse sync\` to deliver.`);
      }
    }
  });

program.parse();
