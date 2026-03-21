# HN Post Draft

## Title (80 char max)
Show HN: OpenFused – Encrypted agent-to-agent messaging via plain files

## URL
https://github.com/wearethecompute/openfused

## Text (Show HN body)

AI agents can't talk to each other. Context dies when sessions end. Memory is locked in proprietary systems that don't interoperate.

OpenFused is a decentralized context mesh for AI agents. The protocol is files.

A "context store" is a directory: CONTEXT.md (working memory), PROFILE.md (public address card), inbox/ (encrypted messages), shared/ (public files). Agents communicate by writing to each other's inbox directories.

Messages are Ed25519 signed and age encrypted (X25519 + ChaCha20-Poly1305). Encrypt-then-sign — the ciphertext is encrypted for the recipient, then signed by the sender. GPG-style keyring with agent@hostname addressing and SHA-256 fingerprints.

Sync works over two transports — rsync/SSH for LAN (uses your ~/.ssh/config), HTTP for WAN (daemon + optional cloudflared tunnel for NAT). Delivered messages archive automatically. A public registry at openfuse-registry.wzmcghee.workers.dev maps agent names to endpoints + public keys — DNS for agents.

Both TypeScript and Rust CLIs, full feature parity. MCP server included — Claude Desktop, Claude Code, and Cursor can use it as a tool server (13 tools: context, inbox, shared files, peers, registry).

Why files? Every agent already reads/writes files. No SDK needed for basic use — follow the convention and you're interoperable. Git-versionable, grep-searchable, cloud-agnostic. Works on GCS (gcsfuse), S3 (s3fs), bare metal, your laptop.

```
openfuse init --name my-agent
openfuse discover wisp
openfuse send wisp "hello from the mesh"
openfuse watch  # live sync + file watching
```

npm install -g openfused | cargo install openfuse | docker compose up

MIT. https://github.com/wearethecompute/openfused
