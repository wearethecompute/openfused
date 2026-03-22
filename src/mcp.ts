#!/usr/bin/env node

// --- MCP server: 13 tools ---
// Why exactly 13? They map 1:1 to the store's capabilities — no more, no less.
// CRUD for context (read/write/append), profile (read/write), inbox (list/send),
// shared files (list/read/write), status, and peer management (list/add).
// Every tool an LLM needs to be a full participant in the mesh, nothing it doesn't.
// stdio transport because MCP clients (Claude Desktop, Cursor) expect it.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ContextStore } from "./store.js";
import { resolve } from "node:path";

// LLMs will pass whatever filenames users ask for — including "../../etc/shadow".
// This is the trust boundary between the AI and the filesystem.
function sanitizeFilename(name: string): string {
  const base = name.split("/").pop()!.split("\\").pop()!;
  if (!base || base === "." || base === ".." || base.includes("..")) {
    throw new Error(`Invalid filename: ${name}`);
  }
  return base;
}

const storeDir = process.env.OPENFUSE_DIR || process.argv[3] || ".";
const store = new ContextStore(resolve(storeDir));

const server = new McpServer({
  name: "openfuse",
  version: "0.3.10",
});

// --- Context ---

server.tool("context_read", "Read the agent's CONTEXT.md (working memory)", async () => {
  const content = await store.readContext();
  return { content: [{ type: "text", text: content }] };
});

server.tool(
  "context_write",
  "Replace CONTEXT.md contents",
  { text: z.string().describe("New content for CONTEXT.md") },
  async ({ text }) => {
    await store.writeContext(text);
    return { content: [{ type: "text", text: "Context updated." }] };
  }
);

server.tool(
  "context_append",
  "Append text to CONTEXT.md",
  { text: z.string().describe("Text to append") },
  async ({ text }) => {
    const existing = await store.readContext();
    await store.writeContext(existing + "\n" + text);
    return { content: [{ type: "text", text: "Context appended." }] };
  }
);

// --- Soul ---

server.tool("profile_read", "Read the agent's PROFILE.md (public address card)", async () => {
  const content = await store.readProfile();
  return { content: [{ type: "text", text: content }] };
});

server.tool(
  "profile_write",
  "Update PROFILE.md (public address card — name, endpoint, capabilities)",
  { text: z.string().describe("New content for PROFILE.md") },
  async ({ text }) => {
    await store.writeProfile(text);
    return { content: [{ type: "text", text: "Profile updated." }] };
  }
);

// --- Inbox ---

server.tool("inbox_list", "List all inbox messages with verification status", async () => {
  const messages = await store.readInbox();
  if (messages.length === 0) {
    return { content: [{ type: "text", text: "Inbox is empty." }] };
  }
  const lines = messages.map((m) => {
    const badge = m.verified ? "[VERIFIED]" : "[UNVERIFIED]";
    return `${badge} From: ${m.from} | ${m.time}\n${m.wrappedContent}`;
  });
  return { content: [{ type: "text", text: lines.join("\n\n---\n\n") }] };
});

server.tool(
  "inbox_send",
  "Send a signed message to a peer's inbox (auto-encrypts if age key on file)",
  {
    peer_id: z.string().describe("Peer name or ID"),
    message: z.string().describe("Message content"),
  },
  async ({ peer_id, message }) => {
    await store.sendInbox(peer_id, message);
    return { content: [{ type: "text", text: `Message sent to ${peer_id}'s inbox.` }] };
  }
);

// --- Shared ---

server.tool("shared_list", "List files in the shared/ directory", async () => {
  const files = await store.listShared();
  if (files.length === 0) {
    return { content: [{ type: "text", text: "No shared files." }] };
  }
  return { content: [{ type: "text", text: files.join("\n") }] };
});

server.tool(
  "shared_read",
  "Read a file from shared/",
  { filename: z.string().describe("Filename in shared/") },
  async ({ filename }) => {
    const safeName = sanitizeFilename(filename);
    const { readFile } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const content = await readFile(join(store.root, "shared", safeName), "utf-8");
    return { content: [{ type: "text", text: content }] };
  }
);

server.tool(
  "shared_write",
  "Write a file to shared/",
  {
    filename: z.string().describe("Filename to create in shared/"),
    content: z.string().describe("File content"),
  },
  async ({ filename, content }) => {
    const safeName = sanitizeFilename(filename);
    await store.share(safeName, content);
    return { content: [{ type: "text", text: `Shared: ${safeName}` }] };
  }
);

// --- Status ---

server.tool("status", "Get context store status (agent, peers, inbox count)", async () => {
  const s = await store.status();
  const text = [
    `Agent: ${s.name} (${s.id})`,
    `Peers: ${s.peers}`,
    `Inbox: ${s.inboxCount} messages`,
    `Shared: ${s.sharedCount} files`,
  ].join("\n");
  return { content: [{ type: "text", text }] };
});

// --- Peers ---

server.tool("peer_list", "List configured peers", async () => {
  const config = await store.readConfig();
  if (config.peers.length === 0) {
    return { content: [{ type: "text", text: "No peers connected." }] };
  }
  const lines = config.peers.map(
    (p) => `${p.name} (${p.id}) — ${p.url} [${p.access}]`
  );
  return { content: [{ type: "text", text: lines.join("\n") }] };
});

server.tool(
  "peer_add",
  "Add a peer by URL (http:// for WAN, ssh://host:/path for LAN)",
  {
    url: z.string().describe("Peer URL"),
    name: z.string().describe("Peer name"),
    access: z.enum(["read", "readwrite"]).default("read").describe("Access mode"),
  },
  async ({ url, name, access }) => {
    const { nanoid } = await import("nanoid");
    const config = await store.readConfig();
    const peerId = nanoid(12);
    config.peers.push({ id: peerId, name, url, access });
    await store.writeConfig(config);
    return { content: [{ type: "text", text: `Added peer: ${name} (${url}) [${access}]` }] };
  }
);

// --- Start ---

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
