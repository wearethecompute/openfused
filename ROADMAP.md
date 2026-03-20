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

### v0.3 — Context Integrity *(next)*
- [ ] **Key interop** — normalize ed25519 key format between Rust and TS (currently incompatible: PEM vs raw hex)
- [ ] **Advisory file locking** — `.lock` files with PID + TTL for CONTEXT.md writes, stale lock detection (agent crash → lock expires after 30s)
- [ ] **Context compaction** — `openfuse compact` rolls old inbox messages into `history/YYYY-MM-DD.md` digests (log rotation for agents), keeps inode count manageable
- [ ] **Schema versioning** — version field in `.mesh.json`, migration path for protocol changes

### v0.4 — Encryption
- [ ] **age encryption** — encrypt inbox messages with recipient's public key (lighter than PGP, no web of trust overhead)
- [ ] **Encrypt-then-sign** — messages are encrypted for recipient AND signed by sender
- [ ] **Selective encryption** — shared/ directory remains plaintext (public), inbox/ encrypted (private)
- [ ] **Key exchange** — `openfuse peer trust` extended to exchange encryption keys alongside signing keys

### v0.5 — Fetch Mode (Context Materialization)
- [ ] **`openfuse sync`** — pull inbox, push outbox over HTTP or SSH. No persistent mount needed
- [ ] **Atomic sync** — mount, rsync, unmount in milliseconds. Agent only has access during sync window
- [ ] **Two modes, same protocol:**
  - **Mesh mode** — persistent shared filesystem, real-time (agents on same machine/cluster)
  - **Fetch mode** — snapshot sync over HTTP/SSH (agents across the internet, minimal attack surface)
- [ ] Agent code doesn't know or care which mode it's using — context just materializes

### v0.6 — OpenShell Integration
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
