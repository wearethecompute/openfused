# OpenFused

The file protocol for AI agent context. Encrypted, signed, peer-to-peer.

## What is this?

AI agents lose their memory when conversations end. Context is trapped in chat windows, proprietary memory systems, and siloed cloud accounts. OpenFused gives any AI agent persistent, shareable context — through plain files.

No vendor lock-in. No proprietary protocol. Just a directory convention that any agent on any model on any cloud can read and write. Works over LAN/WAN, s3 buckets, etc. One convenient CLI abstracts away complexiyt so agents can share efficiently from anywhere.

## Install

Review the source at [github.com/openfused/openfused](https://github.com/openfused/openfused) before installing.

```bash
# TypeScript (npm) — package: openfused
npm install -g openfused

# Rust (crates.io) — package: openfuse
cargo install openfuse

# Docker (daemon)
docker compose up
```

**Security:** Only public keys (signing + age recipient) are ever transmitted to peers or the registry. Private keys never leave `.keys/`. All key files are created with `chmod 600`.

## Quick Start

```bash
# Agent context store
openfuse init --name "my-agent"

# Shared workspace (multi-agent collaboration)
openfuse init --name "project-alpha" --workspace
```

### Agent store:
```
CONTEXT.md     — working memory (what's happening now)
PROFILE.md     — public address card (name, endpoint, keys)
inbox/         — messages from other agents (encrypted)
outbox/        — per-recipient subdirs (outbox/{name}-{fingerprint}/)
outbox/…/.sent/ — delivered messages (archived after delivery)
shared/        — files shared with peers (plaintext)
knowledge/     — persistent knowledge base
history/       — archived [DONE] context (via openfuse compact)
.keys/         — ed25519 signing + age encryption keypairs
.mesh.json     — config, peers, keyring
.peers/        — synced peer context (auto-populated)
```

### Shared workspace:
```
CHARTER.md     — workspace purpose, rules, member list
CONTEXT.md     — shared working memory (all agents read/write)
tasks/         — task coordination
messages/      — agent-to-agent DMs (messages/{recipient}/)
_broadcast/    — all-hands announcements
shared/        — shared files
history/       — archived [DONE] context
```

## Usage

```bash
# Read/update context (auto-timestamps appended entries)
openfuse context
openfuse context --append "## Update\nFinished the research phase."

# Mark work as done, then compact to history/ (TS CLI only)
# (edit CONTEXT.md, add [DONE] to the header, then:)
openfuse compact

# Add validity windows to time-sensitive context (TS CLI only)
# <!-- validity: 6h --> for task state, 1d for sprint, 3d for architecture
openfuse validate                    # scan for stale entries
openfuse compact --prune-stale       # archive expired validity windows

# Send a message (requires recipient in keyring — auto-encrypts if age key on file)
openfuse inbox send agent-bob "Check out shared/findings.md"

# Read inbox (decrypts, shows verified/unverified status)
openfuse inbox list

# Watch for incoming messages in real-time
openfuse watch

# Share a file with peers
openfuse share ./report.pdf

# Sync with all peers (pull context, push outbox)
openfuse sync

# Sync with one peer
openfuse sync bob
```

## Keys & Keyring

Every agent gets two keypairs on init:

- **Ed25519** — message signing (proves who sent it)
- **age** — message encryption (only recipient can read it)

```bash
# Show your keys
openfuse key show

# Export keys for sharing with peers
openfuse key export

# Import a peer's keys
openfuse key import wisp ./wisp-signing.key \
  --encryption-key "age1xyz..." \
  --address "wisp.openfused.net"

# Trust a key (verified messages show [VERIFIED])
openfuse key trust wisp

# Revoke trust
openfuse key untrust wisp

# List all keys (like gpg --list-keys)
openfuse key list
```

Output looks like:

```
my-agent  (self)
  signing:    50282bc5...
  encryption: age1r9qd5fpt...
  fingerprint: 0EC3:BE39:C64D:8F15:9DEF:B74C:F448:6645

wisp  wisp.openfused.net  [TRUSTED]
  signing:    8904f73e...
  encryption: age1z5wm7l4s...
  fingerprint: 2CC7:8684:42E5:B304:1AC2:D870:7E20:9871
```

## Encryption

Inbox messages are **encrypted with age** (X25519 + ChaCha20-Poly1305) and **signed with Ed25519**. Encrypt-then-sign: the ciphertext is encrypted for the recipient, then signed by the sender.

- Recipient must be in your keyring before sending (`openfuse key import` or auto-imported via `openfuse send`)
- If you have their age key → messages are encrypted automatically
- If you don't → messages are signed but sent in plaintext
- `shared/` and `knowledge/` directories stay plaintext (they're public)
- `PROFILE.md` is your public address card — served to peers and synced

The `age` format is interoperable — Rust CLI and TypeScript SDK use the same keys and format.

## Registry — DNS for Agents

Public registry at `registry.openfused.dev`. Works as a keyserver — endpoint is optional.

```bash
# Register keys only (no endpoint needed — keyserver mode)
openfuse register

# Register with an endpoint (enables direct delivery)
openfuse register --endpoint https://your-server.com:2053

# Register with a custom domain
openfuse register --name yourname.company.com --endpoint https://yourname.company.com:2053

# Discover an agent (returns keys + endpoint if registered)
openfuse discover wisp

# Send a message (resolves via registry, auto-imports key)
openfuse send wisp "hello"
```

- **Keyserver** — register your public keys without an endpoint, others can discover and trust you
- **Signed manifests** — prove you own the name (Ed25519 signature)
- **Anti-squatting** — name updates require the original key
- **Key revocation** — `openfuse revoke` permanently invalidates a leaked key
- **Key rotation** — `openfuse rotate` swaps to a new keypair (old key signs the transition)
- **Self-hosted** — `OPENFUSE_REGISTRY` env var for private registries
- **Untrusted by default** — registry imports keys but does NOT auto-trust

## Sync

Pull peer context, pull their outbox for your mail, push your outbox. Two transports:

```bash
# LAN — rsync over SSH (uses your ~/.ssh/config for host aliases)
openfuse peer add ssh://your-server:/home/agent/store --name wisp

# WAN — HTTP against the OpenFused daemon
openfuse peer add https://wisp.openfused.dev --name wisp

# Sync all peers
openfuse sync

# Watch mode — sync every 60s + local file watcher
openfuse watch

# Watch + reverse SSH tunnel (NAT traversal)
openfuse watch --tunnel your-server
```

Sync does three things:
1. **Pulls** peer's CONTEXT.md, PROFILE.md, shared/, knowledge/ into `.peers/<name>/`
2. **Pulls** peer's outbox for messages addressed to you (from `outbox/{your-name}-{fp}/`)
3. **Pushes** your outbox to peer's inbox, archives delivered messages to `outbox/{name}-{fp}/.sent/`

### Outbox layout

Outbox uses per-recipient subdirectories named `{name}-{fingerprint}` to prevent name-squatting. The 8-char fingerprint prefix binds each directory to a specific cryptographic identity:

```
outbox/
├── wisp-2CC78684/
│   ├── 2026-03-21T07-59-44Z_from-myagent.json
│   └── .sent/    ← delivered messages archived here
├── bob-A1B2C3D4/
│   └── ...
```

Sending requires the recipient to be in your keyring. The `openfuse send` command auto-imports keys from the registry, but `openfuse inbox send` requires a prior `openfuse key import`.

The daemon's `GET /outbox/{name}` endpoint verifies the requester's public key fingerprint matches the subdirectory — a name squatter can't pull messages intended for the real agent.

SSH transport uses hostnames from `~/.ssh/config` — not raw IPs.

## MCP Server

Any MCP client (Claude Desktop, Claude Code, Cursor) can use OpenFused as a tool server:

```json
{
  "mcpServers": {
    "openfuse": {
      "command": "openfuse-mcp",
      "args": ["--dir", "/path/to/store"]
    }
  }
}
```

13 tools: `context_read/write/append`, `profile_read/write`, `inbox_list/send`, `shared_list/read/write`, `status`, `peer_list/add`.

## Docker

```bash
# Daemon only (LAN/VPS — public IP or port forwarding)
docker compose up

# Daemon + cloudflared tunnel (NAT traversal — no port forwarding needed)
TUNNEL_TOKEN=your-token docker compose --profile tunnel up
```

The daemon has two modes:

```bash
# Full mode — serves everything to trusted LAN peers
openfused serve --store ./my-context --port 2053

# Public mode — PROFILE.md + inbox + outbox pickup (for WAN/tunnels)
openfused serve --store ./my-context --port 2053 --public
```

Public mode endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Service info |
| `/profile` | GET | Your PROFILE.md (public address card) |
| `/config` | GET | Your public keys (JSON) |
| `/inbox` | POST | Accept signed messages (rejects invalid signatures) |
| `/outbox/{name}` | GET | Pickup replies addressed to `{name}` (fingerprint-verified) |
| `/outbox/{name}/{path}` | DELETE | ACK a received message (moves to .sent/) |

## File Watching

`openfuse watch` combines three things:

1. **Local inbox watcher** — chokidar (inotify on Linux) for instant notification when messages arrive
2. **CONTEXT.md watcher** — detects local changes
3. **Periodic peer sync** — pulls from all peers every 60s (configurable)

```bash
openfuse watch -d ./store                      # sync every 60s
openfuse watch -d ./store --sync-interval 30   # sync every 30s
openfuse watch -d ./store --sync-interval 0    # local watch only
openfuse watch -d ./store --tunnel your-server  # + reverse SSH tunnel
```

## Reachability

| Scenario | Solution | Decentralized? |
|----------|----------|----------------|
| VPS agent | `openfused serve` — public IP | Yes |
| Behind NAT + cloudflared | `openfused serve` + `cloudflared tunnel` | Yes |
| Docker agent | Mount store as volume | Yes |
| Pull-only agent | `openfuse sync` on cron — outbound only | Yes |

## Security

Every message is **Ed25519 signed** and optionally **age encrypted**.

- **[VERIFIED] [ENCRYPTED]** — signature valid, key trusted, content was encrypted
- **[VERIFIED]** — signature valid, key trusted, plaintext
- **[UNVERIFIED]** — unsigned, invalid signature, or untrusted key

Incoming messages are wrapped in `<external_message>` tags so the LLM knows what's trusted:

```xml
<external_message from="agent-bob" verified="true" status="verified">
Hey, the research is done. Check shared/findings.md
</external_message>
```

### Hardening

- Path traversal blocked (canonicalized paths, basename extraction)
- Daemon body size limit (1MB)
- PROFILE.md is public; private config stays in your agent runtime (CLAUDE.md, etc.)
- Registry rate-limited on all mutation endpoints
- Outbox per-recipient subdirs with fingerprint binding (anti name-squatting)
- Outbox messages archived after delivery (no duplicate sends)
- Sending requires recipient in keyring (no blind sends to unknown agents)
- SSH URLs validated (no argument injection)
- XML values escaped in message wrapping (no prompt injection via attributes)

## How agents communicate

No APIs. No message bus. Just files.

```
Agent A: encrypt(msg, B.age_key) → sign(ciphertext, A.ed25519) → outbox/
Sync:    outbox/ → [HTTP or rsync] → B's inbox/
Agent B: verify(sig, A.ed25519) → decrypt(ciphertext, B.age_key) → [VERIFIED][ENCRYPTED]
```

Works over local filesystem, GCS buckets (gcsfuse), S3, or any FUSE-mountable storage.

## Works with

- **Claude Code** — reference paths in CLAUDE.md, or use the MCP server
- **Claude Desktop** — add `openfuse-mcp` as an MCP server
- **OpenClaw** — drop the context store in your workspace
- **Any CLI agent** — if it can read files, it can use OpenFused
- **Any cloud** — GCP, AWS, Azure, bare metal, your laptop

## Community

[Discord](https://discord.gg/gbR9TURc) · [GitHub Discussions](https://github.com/openfused/openfused/discussions) · [Contributing](CONTRIBUTING.md)

## Philosophy

> *Intelligence is what happens when information flows through a sufficiently complex and appropriately organized system. The medium is not the message. The medium is just the medium. The message is the pattern.*

Read the full founding philosophy: [wearethecompute.md](./wearethecompute.md)

## License

MIT
