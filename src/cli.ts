#!/usr/bin/env node

import { Command } from "commander";
import { nanoid } from "nanoid";
import { ContextStore } from "./store.js";
import { watchInbox, watchContext } from "./watch.js";
import { resolve } from "node:path";

const program = new Command();

program
  .name("openfuse")
  .description("Decentralized context mesh for AI agents. The protocol is files.")
  .version("0.2.1");

// --- init ---
program
  .command("init")
  .description("Initialize a new context store in the current directory")
  .option("-n, --name <name>", "Agent name", "agent")
  .option("-d, --dir <path>", "Directory to init", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (await store.exists()) {
      console.error("Context store already exists at", store.root);
      process.exit(1);
    }
    const id = nanoid(12);
    await store.init(opts.name, id);
    console.log(`Initialized context store: ${store.root}`);
    const config = await store.readConfig();
    console.log(`  Agent ID: ${id}`);
    console.log(`  Name: ${opts.name}`);
    console.log(`  Signing keys: generated (.keys/)`);
    console.log(`\nStructure:`);
    console.log(`  CONTEXT.md  — working memory (edit this)`);
    console.log(`  SOUL.md     — agent identity & rules`);
    console.log(`  inbox/      — messages from other agents`);
    console.log(`  shared/     — files shared with the mesh`);
    console.log(`  knowledge/  — persistent knowledge base`);
    console.log(`  history/    — conversation & decision logs`);
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
      await store.writeContext(existing + "\n" + text);
      console.log("Context appended.");
    } else {
      const content = await store.readContext();
      console.log(content);
    }
  });

// --- soul ---
program
  .command("soul")
  .description("Read or update SOUL.md")
  .option("-d, --dir <path>", "Context store directory", ".")
  .option("-s, --set <text>", "Set soul to this text")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (opts.set) {
      await store.writeSoul(opts.set);
      console.log("Soul updated.");
    } else {
      const content = await store.readSoul();
      console.log(content);
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
      console.log(`\n--- ${badge} From: ${msg.from} | ${msg.time} ---`);
      console.log(opts.raw ? msg.content : msg.wrappedContent);
    }
  });

inbox
  .command("send <peerId> <message>")
  .description("Send a message to a peer's inbox")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (peerId, message, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    await store.sendInbox(peerId, message);
    console.log(`Message sent to ${peerId}'s inbox.`);
  });

// --- watch ---
program
  .command("watch")
  .description("Watch for inbox messages and context changes")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    if (!(await store.exists())) {
      console.error("No context store found. Run `openfuse init` first.");
      process.exit(1);
    }
    const config = await store.readConfig();
    console.log(`Watching context store: ${config.name} (${config.id})`);
    console.log(`Press Ctrl+C to stop.\n`);

    watchInbox(store.root, (from, message) => {
      console.log(`\n[inbox] New message from ${from}:`);
      console.log(message);
    });

    watchContext(store.root, () => {
      console.log(`\n[context] CONTEXT.md updated`);
    });

    // Keep alive
    await new Promise(() => {});
  });

// --- share ---
program
  .command("share <file>")
  .description("Share a file with the mesh")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (file, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const { readFile } = await import("node:fs/promises");
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
  .description("Add a peer by URL")
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
  .description("Remove a peer by ID")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (id, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    config.peers = config.peers.filter((p) => p.id !== id && p.name !== id);
    await store.writeConfig(config);
    console.log(`Removed peer: ${id}`);
  });

peer
  .command("trust <publicKeyFile>")
  .description("Trust a peer's public key (messages from them will show as verified)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (publicKeyFile, opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    const { readFile } = await import("node:fs/promises");
    const pubKey = (await readFile(resolve(publicKeyFile), "utf-8")).trim();
    if (!config.trustedKeys) config.trustedKeys = [];
    if (config.trustedKeys.includes(pubKey)) {
      console.log("Key already trusted.");
      return;
    }
    config.trustedKeys.push(pubKey);
    await store.writeConfig(config);
    console.log("Key trusted. Messages signed with this key will show as [VERIFIED].");
  });

// --- key ---
program
  .command("key")
  .description("Show this agent's public key (share with peers so they can trust you)")
  .option("-d, --dir <path>", "Context store directory", ".")
  .action(async (opts) => {
    const store = new ContextStore(resolve(opts.dir));
    const config = await store.readConfig();
    if (config.publicKey) {
      console.log(config.publicKey);
    } else {
      console.error("No keys found. Run `openfuse init` first.");
    }
  });

program.parse();
