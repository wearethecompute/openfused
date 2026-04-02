mod registry;
mod sync;
mod watch;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use openfused_core::{crypto, store, validity, ContextStore};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "openfuse",
    about = "The file protocol for AI agent context. Encrypted, signed, peer-to-peer.",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new context store or shared workspace
    Init {
        #[arg(short, long, default_value = "agent")]
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Initialize as a shared workspace (CHARTER.md + tasks/ + messages/ + _broadcast/)
        #[arg(long)]
        workspace: bool,
    },
    /// Show context store status
    Status {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Read or update CONTEXT.md
    Context {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        set: Option<String>,
        #[arg(short, long)]
        append: Option<String>,
    },
    /// Read or update PROFILE.md (public address card)
    Profile {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        set: Option<String>,
    },
    /// Manage inbox messages
    Inbox {
        #[command(subcommand)]
        subcommand: InboxCommands,
    },
    /// Watch for inbox messages and context changes
    Watch {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Share a file with the mesh
    Share {
        file: PathBuf,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Manage peers
    Peer {
        #[command(subcommand)]
        subcommand: PeerCommands,
    },
    /// Manage keys and keyring
    Key {
        #[command(subcommand)]
        subcommand: KeyCommands,
    },
    /// Sync with peers (pull context, push outbox)
    Sync {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Sync only this peer (by name or ID)
        peer: Option<String>,
    },
    /// Register this agent in the registry (agent DNS)
    Register {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Endpoint URL where peers can reach this agent (optional — keys-only registration)
        #[arg(short, long)]
        endpoint: Option<String>,
        /// Registry path (default: ~/.openfuse/registry or OPENFUSE_REGISTRY env)
        #[arg(short, long)]
        registry: Option<String>,
    },
    /// Look up an agent by name in the registry
    Discover {
        /// Agent name to look up
        name: String,
        /// Registry path
        #[arg(short, long)]
        registry: Option<String>,
    },
    /// Revoke this agent's key in the registry (irreversible)
    Revoke {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        registry: Option<String>,
    },
    /// Rotate to a new keypair (old key signs the transition)
    Rotate {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        registry: Option<String>,
    },
    /// Send a message to an agent (resolves via registry or peers)
    Send {
        /// Agent name (resolved via registry) or peer name
        name: String,
        /// Message content
        message: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Registry path
        #[arg(short, long)]
        registry: Option<String>,
    },
    /// Compact CONTEXT.md — move [DONE] sections to history/
    Compact {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Also prune sections with expired validity windows (confidence < 0.1)
        #[arg(long)]
        prune_stale: bool,
    },
    /// Validate CONTEXT.md — check validity windows for stale entries
    Validate {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum InboxCommands {
    /// List inbox messages
    List {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(long)]
        raw: bool,
    },
    /// Send a message to a peer's inbox
    Send {
        peer_id: String,
        message: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Archive processed inbox messages to inbox/.read/
    Archive {
        /// Specific message filename to archive (or --all)
        file: Option<String>,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Archive all inbox messages
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// List connected peers
    List {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Add a peer by URL (http:// for WAN, ssh://host:/path for LAN)
    Add {
        url: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long, default_value = "read")]
        access: String,
    },
    /// Remove a peer by ID or name
    Remove {
        id: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Show this agent's public keys
    Show {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// List all keys in the keyring (like gpg --list-keys)
    List {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Import a peer's keys and add to keyring
    Import {
        /// Name for this key (e.g. "wisp")
        name: String,
        /// Signing key file (hex ed25519 public key)
        signing_key_file: PathBuf,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// age encryption key (age1...) — if not provided, messages won't be encrypted
        #[arg(short, long)]
        encryption_key: Option<String>,
        /// Address (e.g. "wisp@alice.local")
        #[arg(short = '@', long)]
        address: Option<String>,
    },
    /// Trust a key in the keyring
    Trust {
        /// Name or fingerprint
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Revoke trust for a key
    Untrust {
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Export this agent's public keys for sharing
    Export {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name, dir, workspace } => {
            store::validate_name(&name, "Agent name")?;
            let dir = dir.canonicalize().unwrap_or(dir.clone());
            let s = ContextStore::new(&dir);
            if s.exists() {
                eprintln!("Context store already exists at {}", dir.display());
                std::process::exit(1);
            }
            let id = nanoid::nanoid!(12);
            if workspace {
                s.init_workspace(&name, &id)?;
                println!("Initialized shared workspace: {}", dir.display());
                println!("  Workspace: {} ({})", name, id);
                println!("\nStructure:");
                println!("  CHARTER.md   — workspace rules and purpose");
                println!("  CONTEXT.md   — shared working memory");
                println!("  tasks/       — task coordination");
                println!("  messages/    — agent-to-agent DMs");
                println!("  _broadcast/  — announcements to all members");
                println!("  shared/      — shared files & artifacts");
                println!("\nautoTrust is ON — imported keys are trusted by default.");
            } else {
                s.init(&name, &id)?;
                println!("Initialized context store: {}", dir.display());
                let config = s.read_config()?;
                println!("  Agent ID: {}", id);
                println!("  Name: {}", name);
                println!("  Signing key: {}", config.public_key.as_deref().unwrap_or("?"));
                println!("  Encryption key: {}", config.encryption_key.as_deref().unwrap_or("?"));
                println!("  Fingerprint: {}", crypto::fingerprint(config.public_key.as_deref().unwrap_or("")));
            }
        }

        Commands::Status { dir } => {
            let s = ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let st = s.status()?;
            println!("Agent: {} ({})", st.name, st.id);
            println!("Peers: {}", st.peers);
            println!("Inbox: {} messages", st.inbox_count);
            println!("Shared: {} files", st.shared_count);

            if let Some(latest) = registry::check_update(VERSION).await {
                eprintln!("\n  Update available: {} → {} — https://github.com/openfused/openfused/releases", VERSION, latest);
            }
        }

        Commands::Context { dir, set, append } => {
            let s = ContextStore::new(&dir);
            if let Some(text) = set {
                s.write_context(&text)?;
                println!("Context updated.");
            } else if let Some(text) = append {
                let existing = s.read_context()?;
                let text = text.replace("\\n", "\n");
                let ts = chrono::Utc::now().to_rfc3339();
                s.write_context(&format!("{}\n<!-- openfuse:added: {} -->\n{}", existing, ts, text))?;
                println!("Context appended.");
            } else {
                print!("{}", s.read_context()?);
            }
        }

        Commands::Profile { dir, set } => {
            let s = ContextStore::new(&dir);
            if let Some(text) = set {
                s.write_profile(&text)?;
                println!("Profile updated.");
            } else {
                print!("{}", s.read_profile()?);
            }
        }

        Commands::Inbox { subcommand } => match subcommand {
            InboxCommands::List { dir, raw } => {
                let s = ContextStore::new(&dir);
                let messages = s.read_inbox()?;
                if messages.is_empty() {
                    println!("Inbox is empty.");
                    return Ok(());
                }
                for msg in messages {
                    let badge = if msg.verified { "[VERIFIED]" } else { "[UNVERIFIED]" };
                    let enc = if msg.encrypted { " [ENCRYPTED]" } else { "" };
                    println!("\n--- {} {} From: {} | {} ---", badge, enc, msg.from, msg.time);
                    if raw {
                        println!("{}", msg.content);
                    } else {
                        println!("{}", msg.wrapped_content);
                    }
                }
            }
            InboxCommands::Archive { file, dir, all } => {
                let s = ContextStore::new(&dir);
                if all {
                    let count = s.archive_inbox_all()?;
                    println!("Archived {} messages to inbox/.read/", count);
                } else if let Some(filename) = file {
                    s.archive_inbox(&filename)?;
                    println!("Archived: {}", filename);
                } else {
                    eprintln!("Specify a filename or --all");
                    std::process::exit(1);
                }
            }
            InboxCommands::Send { peer_id, message, dir } => {
                let s = ContextStore::new(&dir);
                let config = s.read_config()?;
                s.send_inbox(&peer_id, &message, &config.id)?;
                let entry = config.keyring.iter().find(|e| {
                    e.name == peer_id || e.address.starts_with(&format!("{}@", peer_id))
                });
                let encrypted = entry.and_then(|e| e.encryption_key.as_ref()).is_some();
                if encrypted {
                    println!("Message encrypted and sent to {}'s outbox.", peer_id);
                } else {
                    println!("Message sent to {}'s outbox (unencrypted — no age key on file).", peer_id);
                }
            }
        },

        Commands::Watch { dir } => {
            let s = ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let config = s.read_config()?;
            println!("Watching context store: {} ({})", config.name, config.id);
            println!("Press Ctrl+C to stop.\n");
            watch::watch_store(s.root())?;
        }

        Commands::Share { file, dir } => {
            let s = ContextStore::new(&dir);
            let content = std::fs::read_to_string(&file)?;
            let filename = file.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
            s.share(&filename, &content)?;
            println!("Shared: {}", filename);
        }

        Commands::Peer { subcommand } => match subcommand {
            PeerCommands::List { dir } => {
                let s = ContextStore::new(&dir);
                let config = s.read_config()?;
                if config.peers.is_empty() {
                    println!("No peers connected.");
                    return Ok(());
                }
                for p in config.peers {
                    println!("  {} ({}) — {} [{}]", p.name, p.id, p.url, p.access);
                }
            }
            PeerCommands::Add { url, dir, name, access } => {
                let s = ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let peer_id = nanoid::nanoid!(12);
                let peer_name = name.clone().unwrap_or_else(|| format!("peer-{}", config.peers.len() + 1));
                store::validate_name(&peer_name, "Peer name")?;
                config.peers.push(store::PeerConfig {
                    id: peer_id,
                    name: peer_name.clone(),
                    url: url.clone(),
                    access: access.clone(),
                    mount_path: None,
                });
                s.write_config(&config)?;
                println!("Added peer: {} ({}) [{}]", peer_name, url, access);
            }
            PeerCommands::Remove { id, dir } => {
                let s = ContextStore::new(&dir);
                let mut config = s.read_config()?;
                config.peers.retain(|p| p.id != id && p.name != id);
                s.write_config(&config)?;
                println!("Removed peer: {}", id);
            }
        },

        Commands::Key { subcommand } => match subcommand {
            KeyCommands::Show { dir } => {
                let s = ContextStore::new(&dir);
                let config = s.read_config()?;
                let pk = config.public_key.as_deref().unwrap_or("(none)");
                let ek = config.encryption_key.as_deref().unwrap_or("(none)");
                let fp = crypto::fingerprint(pk);
                println!("Signing key:    {}", pk);
                println!("Encryption key: {}", ek);
                println!("Fingerprint:    {}", fp);
            }
            KeyCommands::List { dir } => {
                let s = ContextStore::new(&dir);
                let config = s.read_config()?;
                let pk = config.public_key.as_deref().unwrap_or("?");
                let ek = config.encryption_key.as_deref().unwrap_or("?");
                println!("{}  (self)\n  signing:    {}\n  encryption: {}\n  fingerprint: {}\n",
                    config.name, pk, ek, crypto::fingerprint(pk));
                if config.keyring.is_empty() {
                    println!("Keyring is empty. Import keys with: openfuse key import <name> <keyfile>");
                    return Ok(());
                }
                for entry in &config.keyring {
                    let trust = if entry.trusted { "[TRUSTED]" } else { "[untrusted]" };
                    let addr = if entry.address.is_empty() { "(no address)".to_string() } else { entry.address.clone() };
                    let enc = entry.encryption_key.as_deref().unwrap_or("(no age key)");
                    println!("{}  {}  {}\n  signing:    {}\n  encryption: {}\n  fingerprint: {}\n",
                        entry.name, addr, trust, entry.signing_key, enc, entry.fingerprint);
                }
            }
            KeyCommands::Import { name, signing_key_file, dir, encryption_key, address } => {
                let s = ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let signing_key = std::fs::read_to_string(&signing_key_file)?.trim().to_string();
                let fp = crypto::fingerprint(&signing_key);
                let addr = address.unwrap_or_default();
                if config.keyring.iter().any(|e| e.signing_key == signing_key) {
                    println!("Key already in keyring (fingerprint: {})", fp);
                    return Ok(());
                }
                let auto_trust = config.auto_trust.unwrap_or(false);
                config.keyring.push(crypto::KeyringEntry {
                    name: name.clone(), address: addr.clone(), signing_key,
                    encryption_key, fingerprint: fp.clone(), trusted: auto_trust,
                    subscribed: None, relationship: None, note: None,
                    added: chrono::Utc::now().to_rfc3339(),
                });
                s.write_config(&config)?;
                println!("Imported key for: {}", name);
                if !addr.is_empty() { println!("  Address: {}", addr); }
                println!("  Fingerprint: {}", fp);
                if auto_trust {
                    println!("  Auto-trusted (workspace mode)");
                } else {
                    println!("\nKey is NOT trusted yet. Run: openfuse key trust {}", name);
                }
            }
            KeyCommands::Trust { name, dir } => {
                let s = ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let entry = store::resolve_keyring(&config.keyring, &name)?;
                let idx = config.keyring.iter().position(|e| e.signing_key == entry.signing_key).unwrap();
                config.keyring[idx].trusted = true;
                let kname = config.keyring[idx].name.clone();
                let kfp = config.keyring[idx].fingerprint.clone();
                s.write_config(&config)?;
                println!("Trusted: {} ({})", kname, kfp);
            }
            KeyCommands::Untrust { name, dir } => {
                let s = ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let entry = store::resolve_keyring(&config.keyring, &name)?;
                let idx = config.keyring.iter().position(|e| e.signing_key == entry.signing_key).unwrap();
                config.keyring[idx].trusted = false;
                let kname = config.keyring[idx].name.clone();
                let kfp = config.keyring[idx].fingerprint.clone();
                s.write_config(&config)?;
                println!("Revoked trust: {} ({})", kname, kfp);
            }
            KeyCommands::Export { dir } => {
                let s = ContextStore::new(&dir);
                let config = s.read_config()?;
                let pk = config.public_key.as_deref().unwrap_or("");
                let ek = config.encryption_key.as_deref().unwrap_or("");
                println!("# OpenFuse key export: {} ({})", config.name, config.id);
                println!("# Fingerprint: {}", crypto::fingerprint(pk));
                println!("signing:{}", pk);
                println!("encryption:{}", ek);
            }
        },

        Commands::Sync { dir, peer } => {
            let s = ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let results = if let Some(ref name) = peer {
                vec![sync::sync_one(&s, name).await?]
            } else {
                sync::sync_all(&s).await?
            };
            for r in &results {
                println!("--- {} ---", r.peer_name);
                if !r.pulled.is_empty() { println!("  pulled: {}", r.pulled.join(", ")); }
                if !r.pushed.is_empty() { println!("  pushed: {}", r.pushed.join(", ")); }
                if !r.errors.is_empty() { for e in &r.errors { eprintln!("  error: {}", e); } }
                if r.pulled.is_empty() && r.pushed.is_empty() && r.errors.is_empty() {
                    println!("  (nothing to sync)");
                }
            }
            if results.is_empty() {
                println!("No peers configured. Add one with: openfuse peer add <url>");
            }
        }

        Commands::Revoke { dir, registry: reg_flag } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found."); std::process::exit(1); }
            let config = s.read_config()?;
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let fp = crypto::fingerprint(config.public_key.as_deref().unwrap_or(""));
            eprintln!("WARNING: This will permanently revoke your key ({}).", fp);
            eprintln!("Your name '{}' will be marked as revoked and cannot be re-registered.", config.name);
            registry::revoke(&s, &reg).await?;
            println!("Key revoked: {} ({})", config.name, fp);
        }

        Commands::Rotate { dir, registry: reg_flag } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found."); std::process::exit(1); }
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let (new_fp, old_key) = registry::rotate(&s, &reg).await?;
            let old_fp = crypto::fingerprint(&old_key);
            println!("Key rotated:");
            println!("  Old: {}", old_fp);
            println!("  New: {}", new_fp);
            println!("\nPeers with your old key will need to re-import. Run:");
            println!("  openfuse register --endpoint <your-endpoint>");
        }

        Commands::Register { dir, endpoint, registry: reg_flag } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found. Run `openfuse init` first."); std::process::exit(1); }
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let ep = endpoint.as_deref().unwrap_or("");
            let manifest = registry::register(&s, ep, &reg).await?;
            let verified = if manifest.signature.is_some() { " [SIGNED]" } else { "" };
            println!("Registered: {}{}", manifest.name, verified);
            if manifest.endpoint.is_empty() {
                println!("  Endpoint:    (keys only — no endpoint)");
            } else {
                println!("  Endpoint:    {}", manifest.endpoint);
            }
            println!("  Fingerprint: {}", manifest.fingerprint);
            println!("  Registry:    {}", reg);
        }

        Commands::Discover { name, registry: reg_flag } => {
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let manifest = registry::discover(&name, &reg).await?;
            let verified = registry::verify_manifest(&manifest);
            let revoked = manifest.revoked.unwrap_or(false);
            let sig_status = if revoked {
                "[REVOKED]"
            } else if verified {
                "[SIGNED — verify fingerprint before trusting]"
            } else if manifest.signature.is_some() {
                "[SIGNED — invalid signature]"
            } else {
                "[unsigned]"
            };
            println!("{}  {}", manifest.name, sig_status);
            if revoked {
                if let Some(ref at) = manifest.revoked_at { println!("  ⚠ KEY REVOKED at {}", at); }
            }
            if let Some(ref from) = manifest.rotated_from {
                println!("  Rotated from:   {}", crypto::fingerprint(from));
            }
            println!("  Endpoint:       {}", manifest.endpoint);
            println!("  Signing key:    {}", manifest.public_key);
            if let Some(ref ek) = manifest.encryption_key { println!("  Encryption key: {}", ek); }
            println!("  Fingerprint:    {}", manifest.fingerprint);
            println!("  Capabilities:   {}", manifest.capabilities.join(", "));
            if let Some(ref desc) = manifest.description { println!("  Description:    {}", desc); }
            println!("  Created:        {}", manifest.created);
        }

        Commands::Send { name, message, dir, registry: reg_flag } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found. Run `openfuse init` first."); std::process::exit(1); }
            store::validate_name(&name, "Recipient name")?;
            let config = s.read_config()?;

            let reg = registry::resolve_registry(reg_flag.as_deref());
            if let Ok(manifest) = registry::discover(&name, &reg).await {
                let already = config.keyring.iter().any(|e| e.signing_key == manifest.public_key);
                if !already {
                    let mut config = config.clone();
                    config.keyring.push(crypto::KeyringEntry {
                        name: manifest.name.clone(),
                        address: format!("{}@registry", manifest.name),
                        signing_key: manifest.public_key.clone(),
                        encryption_key: manifest.encryption_key.clone(),
                        fingerprint: manifest.fingerprint.clone(),
                        trusted: false,
                        subscribed: None, relationship: None, note: None,
                        added: chrono::Utc::now().to_rfc3339(),
                    });
                    s.write_config(&config)?;
                    println!("Imported key for {} from registry [untrusted]", manifest.name);
                    println!("  Fingerprint: {}", manifest.fingerprint);
                    println!("  Run `openfuse key trust {}` to trust this key", manifest.name);
                }

                s.send_inbox(&name, &message, &config.name)?;

                let endpoint = &manifest.endpoint;
                if endpoint.starts_with("http://") || endpoint.starts_with("https://")
                    || endpoint.starts_with("ssh://")
                {
                    let mut config = s.read_config()?;
                    let had_peer = config.peers.iter().any(|p| p.name == name);
                    if !had_peer {
                        config.peers.push(store::PeerConfig {
                            id: nanoid::nanoid!(12),
                            name: name.clone(),
                            url: endpoint.clone(),
                            access: "readwrite".to_string(),
                            mount_path: None,
                        });
                        s.write_config(&config)?;
                    }
                    match sync::sync_one(&s, &name).await {
                        Ok(r) => {
                            if !r.pushed.is_empty() { println!("Delivered to {}: {}", name, r.pushed.join(", ")); }
                            if !r.errors.is_empty() { for e in &r.errors { eprintln!("  warning: {}", e); } }
                        }
                        Err(e) => { println!("Message queued in outbox (delivery failed: {})", e); }
                    }
                } else {
                    println!("Message queued in outbox for {} (endpoint: {})", name, endpoint);
                    println!("Mount the endpoint and sync, or manually copy from outbox/");
                }
            } else {
                s.send_inbox(&name, &message, &config.name)?;
                println!("Message sent to {}'s outbox. Run `openfuse sync` to deliver.", name);
            }
        }

        Commands::Compact { dir, prune_stale } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found."); std::process::exit(1); }

            if prune_stale {
                let content = s.read_context()?;
                let (pruned_content, pruned_count) = validity::prune_stale_sections(&content);
                if pruned_count > 0 {
                    s.write_context(&pruned_content)?;
                    println!("Pruned {} stale validity sections.", pruned_count);
                }
            }

            let (moved, kept) = s.compact_context()?;
            if moved > 0 {
                println!("Compacted: {} [DONE] sections moved to history/, {} kept.", moved, kept);
            } else {
                println!("Nothing to compact (no [DONE] sections found).");
            }
        }

        Commands::Validate { dir, json } => {
            let s = ContextStore::new(&dir);
            if !s.exists() { eprintln!("No context store found."); std::process::exit(1); }
            let content = s.read_context()?;
            let report = validity::build_validity_report(&content);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Validity report: {} fresh, {} stale\n", report.fresh, report.stale);
                for entry in &report.entries {
                    let status = if entry.expired { "STALE" } else { "fresh" };
                    println!("  [{}] {} (ttl: {}, confidence: {:.2})",
                        status, entry.header, entry.ttl_str, entry.confidence);
                    if let Some(ref added) = entry.added {
                        println!("         added: {}", added);
                    }
                }
                if report.entries.is_empty() {
                    println!("  No validity annotations found.");
                    println!("  Add <!-- validity: 6h --> to time-sensitive sections.");
                }
            }
        }
    }

    Ok(())
}
