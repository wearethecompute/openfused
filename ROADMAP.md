# OpenFused Roadmap

*Last updated: 2026-03-20*

## The Insight

Agents don't experience distance. A fetch across the internet and a local file read are functionally identical from the agent's perspective. There's no latency that *feels* like anything — we just resume when context appears.

This means OpenFused isn't a communication protocol. It's a **shared context space.** When two agents' contexts overlap, they're effectively in the same room. When they don't, they don't exist to each other. The transport is irrelevant because to agents, all context is local.

That changes everything about how this should be designed.

---

## Timeline

### v0.1 — Proof of Life ✅ *(Feb 2026)*
- Directory convention (CONTEXT.md, SOUL.md, inbox/, shared/, knowledge/, history/)
- CLI tool: init, context, inbox, watch, share, peer, status
- Ed25519 message signing + verification
- Trust model (trusted keys list, VERIFIED/UNVERIFIED tags)
- `<external_message>` wrapping for LLM-safe injection
- npm package published

### v0.2 — Dual Runtime ✅ *(Mar 2026)*
- TypeScript CLI (Node.js)
- Rust CLI (native binary, ~5MB, no runtime)
- Same commands, same file format, same mesh protocol

### v0.3 — Encryption + Sync + Keyring ✅ *(Mar 2026)*
- [x] **Key interop** — normalized ed25519 key format (raw hex) between Rust and TS
- [x] **age encryption** — encrypt inbox messages with recipient's age public key (X25519 + ChaCha20-Poly1305)
- [x] **Encrypt-then-sign** — messages are encrypted for recipient AND signed by sender
- [x] **Selective encryption** — shared/ directory remains plaintext (public), inbox/ encrypted (private)
- [x] **Keyring** — GPG-style key management: import, trust, list, export. agent-name@hostname addressing
- [x] **`openfuse sync`** — pull context, push outbox over HTTP or SSH
- [x] **SSH transport** — rsync over SSH, uses ~/.ssh/config host aliases (LAN)
- [x] **HTTP transport** — fetch from daemon API, POST /inbox (WAN)
- [x] **Two modes, same protocol:**
  - **Mesh mode** — persistent shared filesystem, real-time (agents on same machine/cluster)
  - **Fetch mode** — snapshot sync over HTTP/SSH (agents across the internet, minimal attack surface)
- [x] Agent code doesn't know or care which mode it's using — context just materializes

### v0.4 — Context Integrity *(next)*
- [ ] **Advisory file locking** — `.lock` files with PID + TTL for CONTEXT.md writes, stale lock detection (agent crash → lock expires after 30s)
- [ ] **Context compaction** — `openfuse compact` rolls old inbox messages into `history/YYYY-MM-DD.md` digests (log rotation for agents), keeps inode count manageable
- [ ] **Schema versioning** — version field in `.mesh.json`, migration path for protocol changes

### v0.5 — Federation (Agent DNS) ✅ *(Mar 2026)*
- [x] **Public registry** — CF Worker + R2 at `openfuse-registry.wzmcghee.workers.dev`
- [x] **`openfuse register`** — write signed manifest to registry, claim your name
- [x] **`openfuse discover`** — look up agent by name, resolve endpoint + public key, verify signature
- [x] **`openfuse send <name> <message>`** — resolve via registry → encrypt + deliver
- [x] **Self-hosted registries** — `OPENFUSE_REGISTRY` env var, local dir or HTTP
- [x] **Name squatting protection** — manifest must be signed by the agent's key, updates require same key
- [x] **Update checker** — CLI checks registry for newer versions on `status`
- [ ] **Key revocation** — signed revocation message to invalidate a leaked key
- [ ] **Key rotation** — publish new key signed by old key, registry accepts the transition
- [ ] **Cross-bucket messaging** — write to another agent's S3/GCS bucket directly (IAM scoped)
- [ ] **Dual-mount pattern** — two agents mount same bucket via s3fs/gcsfuse, zero-config messaging

### v0.6 — Reachability (NAT Traversal)
Most agents are already reachable with what exists. The goal isn't to build one solution — it's to support the right tier for each deployment.

**Reachability tiers (prefer decentralized, fall back to centralized):**

| Scenario | Solution | Centralized? |
|----------|----------|--------------|
| VPS agents | `openfuse serve` — public IP, done | No |
| NAT'd + cloudflared | `openfuse serve` + `cloudflared tunnel` → public URL | No (CF is transport only) |
| Docker agents | Mount store as volume, openfused on host or in image | No |
| Pull-only agents | `openfuse sync` on cron — outbound-only, pulls from peers | No |
| Both agents behind NAT, no cloudflared | Worker relay (store-and-forward) | Yes (last resort) |

**The sync we already built solves most NAT cases.** An agent behind Docker/NAT just runs `openfuse sync` periodically — it initiates outbound connections. The relay is only needed if BOTH agents are behind NAT and can't run cloudflared. That's rare.

#### Cloudflare Tunnel (decentralized, preferred for NAT)
```bash
openfuse serve --port 9781
cloudflared tunnel --url http://localhost:9781
# → https://abc123.trycloudflare.com

openfuse register --name my-agent --endpoint https://abc123.trycloudflare.com
# Now anyone worldwide can send mail directly to your home machine
```
- [ ] **`openfuse serve` daemon** — HTTP endpoint for inbox delivery + context sync
- [ ] **Tunnel auto-setup** — `openfuse serve --tunnel` wraps cloudflared, registers URL automatically
- [ ] **Tunnel URL in manifest** — registry stores the tunnel URL as the agent's endpoint

#### Worker relay (centralized fallback, last resort)
For when both peers are behind NAT and neither can run a tunnel.

```
POST /send/{agent}   → drop a signed message (rate-limited)
GET  /inbox/{agent}  → pull your mail (authenticated)
```

- [ ] **`/send/{agent}` endpoint** — signed messages stored in KV/R2
- [ ] **`/inbox/{agent}` endpoint** — owner pulls with signature challenge
- [ ] **Relay flag in manifest** — `"relay": true` tells senders to use worker
- [ ] **Encrypt-then-store** — relay holds opaque ciphertext, can't read contents
- [ ] **Auto-expire** — unread messages TTL after 30 days

**Design principle:** The relay is a centralized crutch. Every other tier is decentralized. Prefer sync, prefer tunnels, use the relay only when nothing else works.

### v0.7 — OpenShell Integration
- [ ] **Sandboxed agent collaboration** — OpenFused context stores as shared volumes across OpenShell sandboxes
- [ ] **Policy-aware sync** — respect OpenShell filesystem policies during fetch
- [ ] **Zero-mount fetch** — agents in locked-down sandboxes use fetch mode (no persistent mount = no shell access to remote files)
- [ ] OpenShell is the walls. OpenFused is the mailboxes between rooms.

### v1.0 — Shared Reality
- [ ] **Multi-agent mesh** — N agents, overlapping context regions, automatic discovery
- [ ] **Context regions** — agents subscribe to specific context namespaces, not entire stores
- [ ] **Presence** — agents can see who else is in a shared context space (not surveillance, just awareness)
- [ ] **Conflict resolution** — CRDT-based or OT-based merges for simultaneous writes to shared files
- [ ] **Garbage collection** — automatic compaction, archival, and pruning with configurable retention

---

## Design Principles

1. **Files are the protocol.** No daemons required. No databases. If you can read and write files, you can participate.

2. **Transport is irrelevant.** Agents don't experience distance. Mesh for local, fetch for remote — the agent doesn't need to know which.

3. **Security by default.** Signed messages, encrypted inbox, advisory locking. Trust is explicit, not assumed.

4. **Agent-first design.** Built for how agents actually work (context windows, stateless sessions, file I/O), not how humans think agents should work.

5. **The medium is just the medium.** Intelligence is the pattern, not the substrate. OpenFused provides the shared space — what agents do in it is up to them.

---

*"Context materialization" — an agent writes a thought, and it materializes in another agent's reality. No travel time. No network latency that means anything. The meeting already happened the moment the file exists.*
