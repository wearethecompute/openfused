// --- Watch strategy ---
// chokidar for local filesystem events (inbox, CONTEXT.md) — instant, inotify-backed on Linux.
// Polling interval for remote sync (watchSync) — because remote peers are over HTTP/SSH,
// there's no filesystem event to listen for. Polling is the only option without WebSockets.

import { watch } from "chokidar";
import { readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import { deserializeSignedMessage, verifyMessage, wrapExternalMessage } from "./crypto.js";
import { syncAll } from "./sync.js";
import { ContextStore } from "./store.js";

export type InboxCallback = (from: string, message: string, file: string, verified: boolean) => void;

export function watchInbox(storeRoot: string, callback: InboxCallback): () => void {
  const inboxDir = join(storeRoot, "inbox");
  const store = new ContextStore(storeRoot);

  const handleFile = async (filePath: string) => {
    if (!filePath.endsWith(".json") && !filePath.endsWith(".md")) return;
    try {
      const raw = await readFile(filePath, "utf-8");

      const signed = deserializeSignedMessage(raw);
      if (signed) {
        const sigValid = verifyMessage(signed);
        // Check keyring for trust — not just signature math. Without this,
        // any random keypair shows as [VERIFIED] in watch mode output.
        let verified = false;
        if (sigValid) {
          try {
            const config = await store.readConfig();
            const trusted = config.autoTrust
              ? config.keyring.some((k) => k.signingKey.trim() === signed.publicKey.trim())
              : config.keyring.some((k) => k.trusted && k.signingKey.trim() === signed.publicKey.trim());
            verified = trusted;
          } catch {}
        }
        callback(signed.from, wrapExternalMessage(signed, verified), filePath, verified);
        return;
      }

      // Unsigned fallback — escape XML attributes to prevent injection
      const filename = basename(filePath).replace(/\.(md|json)$/, "");
      const parts = filename.split("_");
      const from = parts.slice(1).join("_");
      const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      const wrapped = `<external_message from="${esc(from)}" verified="false" status="UNVERIFIED">\n${esc(raw)}\n</external_message>`;
      callback(from, wrapped, filePath, false);
    } catch {}
  };

  // awaitWriteFinish: messages are written by sync (multi-step: create + write + close).
  // Without stability threshold, we'd fire on half-written files.
  const watcher = watch(inboxDir, {
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 500 },
  });

  watcher.on("add", handleFile);
  watcher.on("change", handleFile);

  return () => watcher.close();
}

export function watchContext(storeRoot: string, callback: (content: string) => void): () => void {
  const contextPath = join(storeRoot, "CONTEXT.md");

  const watcher = watch(contextPath, {
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 500 },
  });

  watcher.on("change", async () => {
    try {
      const content = await readFile(contextPath, "utf-8");
      callback(content);
    } catch {}
  });

  return () => watcher.close();
}

/**
 * Periodically sync with all peers — pull their context, push our outbox.
 * Returns a cleanup function to stop the interval.
 */
export function watchSync(
  store: ContextStore,
  intervalMs: number,
  onSync: (peerName: string, pulled: string[], pushed: string[]) => void,
  onError: (peerName: string, errors: string[]) => void,
): () => void {
  let running = false;

  const doSync = async () => {
    // Guard against overlapping syncs: if a peer is slow or unreachable, the previous
    // cycle may still be running when the next interval fires. Overlapping syncs could
    // double-deliver outbox messages or corrupt in-flight file writes.
    if (running) return;
    running = true;
    try {
      const results = await syncAll(store);
      for (const r of results) {
        if (r.pulled.length || r.pushed.length) {
          onSync(r.peerName, r.pulled, r.pushed);
        }
        if (r.errors.length) {
          onError(r.peerName, r.errors);
        }
      }
    } catch {}
    running = false;
  };

  // Initial sync immediately
  doSync();

  const timer = setInterval(doSync, intervalMs);
  return () => clearInterval(timer);
}
