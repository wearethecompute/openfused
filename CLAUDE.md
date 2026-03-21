# OpenFused

Decentralized context mesh for AI agents. The protocol is files.

## Repo Structure
```
src/              TypeScript SDK (npm package "openfused")
  cli.ts          CLI: init, status, context, soul, inbox, watch, share, peer, key, sync, register, discover, send
  store.ts        Context store CRUD + encrypted inbox + keyring
  crypto.ts       Ed25519 signing + age encryption + fingerprints
  sync.ts         Sync over HTTP (WAN) and rsync/SSH (LAN)
  registry.ts     Registry client (register, discover, send, revoke)
  mcp.ts          MCP server (13 tools for Claude Desktop/Code/Cursor)
  watch.ts        File watchers (chokidar) for inbox + context changes
rust/             Rust CLI (native binary, same features as TS)
  src/main.rs     CLI entrypoint
  src/store.rs    Context store + keyring
  src/crypto.rs   Ed25519 + age encryption
  src/sync.rs     HTTP + SSH sync
  src/registry.rs Registry client + version checker
  src/watch.rs    File watchers (notify)
daemon/           Rust FUSE daemon (openfused binary)
  src/main.rs     CLI: serve + mount subcommands
  src/server.rs   axum HTTP server + POST /inbox
  src/store.rs    Local store reader with path security
  src/fuse_fs.rs  FUSE filesystem — mounts remote peers locally
  Dockerfile      Multi-stage Docker build
worker/           CF Worker — public agent registry
  src/index.ts    Registry API (register, discover, list, revoke, rotate)
  wrangler.toml   R2 bucket binding
templates/        Default CONTEXT.md + SOUL.md
drafts/           HN post draft
mesh/             Example context stores
```

## Key Technical Details
- Ed25519 signing + age encryption keypairs generated on `openfuse init` (stored in .keys/, gitignored)
- Encrypt-then-sign: ciphertext encrypted for recipient's age key, then signed with sender's Ed25519
- Keyring in .mesh.json: GPG-style, agent-name@hostname addressing, SHA-256 fingerprints
- `openfuse sync` pulls context over HTTP (WAN) or rsync/SSH (LAN)
- SSH transport uses ~/.ssh/config host aliases — hostnames not IPs
- Delivered outbox messages archived to outbox/.sent/ (no duplicate delivery)
- SOUL.md is private — never served to peers or synced
- Registry: CF Worker + R2 at openfuse-registry.wzmcghee.workers.dev
- Registry imports keys as untrusted by default — explicit `openfuse key trust` required
- Key revocation + rotation supported (signed by current/old key)
- Path traversal blocked via canonicalization + basename extraction
- Daemon body size limit: 1MB
- MCP server: 13 tools, stdio transport, works with any MCP client

## Build & Test
```bash
# TypeScript SDK
npm install && npm run build
node dist/cli.js init --name test && node dist/cli.js status

# Rust CLI
cd rust && cargo build
./target/debug/openfuse init --name test && ./target/debug/openfuse status

# Rust daemon
cd daemon && cargo build
./target/debug/openfused serve --store /path/to/context --port 9781

# Docker
docker compose up

# Deploy registry worker
cd worker && unset CLOUDFLARE_API_TOKEN && npx wrangler deploy
```

## Publishing
- npm: auto-publishes via GitHub Action on `v*` tag push
- crates.io: auto-publishes via GitHub Action on `v*` tag (needs CARGO_TOKEN secret)
- Docker: auto-publishes to ghcr.io/wearethecompute/openfused on `v*` tag
- Package: `openfused` on npm
- Maintainer: wearethecompute <compute@meaningoflife.dev>

## GitHub
- Repo: https://github.com/wearethecompute/openfused
- Remote: origin → github-watc:wearethecompute/openfused.git
- Keep commits authored as: wearethecompute <compute@meaningoflife.dev>
- SSH config alias: `github-watc` (uses ~/.ssh/wearethecompute key)

## Philosophy
wearethecompute.md — founding doc. The protocol is files. The network is the mirror.
