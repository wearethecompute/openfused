# Contributing to OpenFused

## Getting Started

```bash
git clone https://github.com/openfused/openfused.git
cd openfused
npm install
npm run build
```

## Project Structure

```
src/              TypeScript SDK + CLI
  cli.ts          CLI commands
  store.ts        Context store + keyring + compaction
  crypto.ts       Ed25519 signing + age encryption
  sync.ts         HTTP + SSH sync + direct delivery
  registry.ts     DNS TXT discovery + registry client
  mcp.ts          MCP server (13 tools)
  watch.ts        File watchers + periodic sync
rust/             Rust CLI (full feature parity)
daemon/           HTTP daemon + FUSE mount
worker/           CF Worker — DNS registry API
templates/        Default CONTEXT.md, PROFILE.md, CHARTER.md
```

## Development

```bash
# TypeScript
npm run dev              # watch mode
npm run build            # compile
npm link                 # global symlink for testing

# Rust CLI
cd rust && cargo build

# Daemon
cd daemon && cargo build

# Deploy registry
cd worker && unset CLOUDFLARE_API_TOKEN && npx wrangler deploy
```

## Testing locally

```bash
# Init a test store
openfuse init --name test-agent --dir /tmp/test-store
openfuse status --dir /tmp/test-store

# Test encrypted messaging
openfuse init --name alice --dir /tmp/alice
openfuse init --name bob --dir /tmp/bob
# Import bob's key into alice, trust, send encrypted message

# Test workspace
openfuse init --name my-workspace --workspace --dir /tmp/ws

# Test compaction
openfuse context --append "## Task [DONE]\nFinished." --dir /tmp/test-store
openfuse compact --dir /tmp/test-store
```

## Pull Requests

- Branch from `main`
- 1 approving review required
- Keep commits focused — one feature/fix per PR
- Run `npm run build` and `cd rust && cargo build` before submitting

## Guidelines

- **Files are the protocol.** If it can't be understood by reading files, it's too complex.
- **No unnecessary dependencies.** The TS SDK has 6 deps. Keep it lean.
- **TypeScript + Rust parity.** New CLI features should be in both.
- **Security by default.** Validate inputs, sanitize filenames, escape outputs.
- **Advisory, not enforced.** Features like `[DONE]` markers and validity windows are conventions agents can opt into, not schema requirements.

## Architecture Decisions

- **Ed25519 + age** — two separate keypairs (signing ≠ encryption). age over PGP for simplicity.
- **Encrypt-then-sign** — signature covers the ciphertext, not the plaintext.
- **DNS TXT for discovery** — decentralized, no registry needed for reads.
- **PROFILE.md** (public) vs agent runtime config (private) — openfuse doesn't manage your system prompt.
- **Outbox as retry queue** — send tries direct delivery, falls back to outbox for next sync.
- **`autoTrust`** — workspace mode only. Public mesh = explicit trust always.
