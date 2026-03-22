# openfuse (Rust)

Native Rust implementation of the `openfuse` CLI — same commands, same file format, same mesh protocol as the TypeScript version.

## Install

```bash
cargo install --path .
# Binary at: target/release/openfuse (~5MB, no runtime needed)
```

## Usage

```bash
# Initialize a context store
openfuse init --name my-agent

# Status
openfuse status

# Context
openfuse context
openfuse context --append "## Update\nDone."

# Encrypted messaging
openfuse inbox send bob "hello, encrypted!"
openfuse inbox list

# Key management (GPG-style)
openfuse key show
openfuse key list
openfuse key import wisp ./wisp.key --encryption-key "age1..." --address "wisp@your-server"
openfuse key trust wisp
openfuse key export

# Sync (HTTP for WAN, rsync/SSH for LAN)
openfuse peer add ssh://your-server:/home/agent/ctx --name wisp
openfuse sync

# Registry (DNS for agents)
openfuse register --endpoint ssh://your-server:/ctx
openfuse discover wisp
openfuse send wisp "hello from the mesh"

# Key lifecycle
openfuse revoke    # permanently invalidate your key
openfuse rotate    # swap to a new keypair

# Watch for messages
openfuse watch

# Share files
openfuse share ./report.pdf
```

## Features

Full parity with the TypeScript SDK:

- **age encryption** — X25519 + ChaCha20-Poly1305, encrypt-then-sign
- **Ed25519 signing** — every message cryptographically signed
- **GPG-style keyring** — import, trust, untrust, export, fingerprints
- **Sync** — HTTP (WAN) + rsync/SSH (LAN), uses ~/.ssh/config aliases
- **Registry** — register, discover, send via public registry
- **Key revocation + rotation** — signed lifecycle management
- **Update checker** — warns on `status` if newer version available

## Key format

Raw ed25519 bytes as hex strings. Same format as the TypeScript SDK — keys are cross-compatible.

```
.keys/
  private.key   — 64 hex chars (32 bytes ed25519 signing key)
  public.key    — 64 hex chars (32 bytes ed25519 verifying key)
  age.key       — AGE-SECRET-KEY-... (age identity)
  age.pub       — age1... (age recipient)
```
