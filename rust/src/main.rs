mod crypto;
mod registry;
mod store;
mod sync;
mod watch;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const VERSION: &str = "0.3.0";

#[derive(Parser)]
#[command(
    name = "openfuse",
    about = "Decentralized context mesh for AI agents. The protocol is files.",
    version = "0.3.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new context store
    Init {
        #[arg(short, long, default_value = "agent")]
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
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
    /// Read or update SOUL.md
    Soul {
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
        /// Endpoint URL where peers can reach this agent
        #[arg(short, long)]
        endpoint: String,
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
        Commands::Init { name, dir } => {
            let dir = dir.canonicalize().unwrap_or(dir.clone());
            let s = store::ContextStore::new(&dir);
            if s.exists() {
                eprintln!("Context store already exists at {}", dir.display());
                std::process::exit(1);
            }
            let id = nanoid::nanoid!(12);
            s.init(&name, &id)?;
            println!("Initialized context store: {}", dir.display());
            let config = s.read_config()?;
            println!("  Agent ID: {}", id);
            println!("  Name: {}", name);
            println!("  Signing key: {}", config.public_key.as_deref().unwrap_or("?"));
            println!(
                "  Encryption key: {}",
                config.encryption_key.as_deref().unwrap_or("?")
            );
            println!(
                "  Fingerprint: {}",
                crypto::fingerprint(config.public_key.as_deref().unwrap_or(""))
            );
        }

        Commands::Status { dir } => {
            let s = store::ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let st = s.status()?;
            println!("Agent: {} ({})", st.name, st.id);
            println!("Peers: {}", st.peers);
            println!("Inbox: {} messages", st.inbox_count);
            println!("Shared: {} files", st.shared_count);

            // Check for updates (non-blocking, best-effort)
            if let Some(latest) = registry::check_update(VERSION).await {
                eprintln!("\n  Update available: {} → {} — https://github.com/wearethecompute/openfused/releases", VERSION, latest);
            }
        }

        Commands::Context { dir, set, append } => {
            let s = store::ContextStore::new(&dir);
            if let Some(text) = set {
                s.write_context(&text)?;
                println!("Context updated.");
            } else if let Some(text) = append {
                let existing = s.read_context()?;
                let text = text.replace("\\n", "\n");
                s.write_context(&format!("{}\n{}", existing, text))?;
                println!("Context appended.");
            } else {
                print!("{}", s.read_context()?);
            }
        }

        Commands::Soul { dir, set } => {
            let s = store::ContextStore::new(&dir);
            if let Some(text) = set {
                s.write_soul(&text)?;
                println!("Soul updated.");
            } else {
                print!("{}", s.read_soul()?);
            }
        }

        Commands::Inbox { subcommand } => match subcommand {
            InboxCommands::List { dir, raw } => {
                let s = store::ContextStore::new(&dir);
                let messages = s.read_inbox()?;
                if messages.is_empty() {
                    println!("Inbox is empty.");
                    return Ok(());
                }
                for msg in messages {
                    let badge = if msg.verified {
                        "[VERIFIED]"
                    } else {
                        "[UNVERIFIED]"
                    };
                    let enc = if msg.encrypted { " [ENCRYPTED]" } else { "" };
                    println!("\n--- {} {} From: {} | {} ---", badge, enc, msg.from, msg.time);
                    if raw {
                        println!("{}", msg.content);
                    } else {
                        println!("{}", msg.wrapped_content);
                    }
                }
            }
            InboxCommands::Send {
                peer_id,
                message,
                dir,
            } => {
                let s = store::ContextStore::new(&dir);
                let config = s.read_config()?;
                s.send_inbox(&peer_id, &message, &config.id)?;

                // Check if message was encrypted
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
            let s = store::ContextStore::new(&dir);
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
            let s = store::ContextStore::new(&dir);
            let content = std::fs::read_to_string(&file)?;
            let filename = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();
            s.share(&filename, &content)?;
            println!("Shared: {}", filename);
        }

        Commands::Peer { subcommand } => match subcommand {
            PeerCommands::List { dir } => {
                let s = store::ContextStore::new(&dir);
                let config = s.read_config()?;
                if config.peers.is_empty() {
                    println!("No peers connected.");
                    return Ok(());
                }
                for p in config.peers {
                    println!("  {} ({}) — {} [{}]", p.name, p.id, p.url, p.access);
                }
            }
            PeerCommands::Add {
                url,
                dir,
                name,
                access,
            } => {
                let s = store::ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let peer_id = nanoid::nanoid!(12);
                let peer_name =
                    name.clone().unwrap_or_else(|| format!("peer-{}", config.peers.len() + 1));
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
                let s = store::ContextStore::new(&dir);
                let mut config = s.read_config()?;
                config.peers.retain(|p| p.id != id && p.name != id);
                s.write_config(&config)?;
                println!("Removed peer: {}", id);
            }
        },

        Commands::Key { subcommand } => match subcommand {
            KeyCommands::Show { dir } => {
                let s = store::ContextStore::new(&dir);
                let config = s.read_config()?;
                let pk = config.public_key.as_deref().unwrap_or("(none)");
                let ek = config.encryption_key.as_deref().unwrap_or("(none)");
                let fp = crypto::fingerprint(pk);
                println!("Signing key:    {}", pk);
                println!("Encryption key: {}", ek);
                println!("Fingerprint:    {}", fp);
            }
            KeyCommands::List { dir } => {
                let s = store::ContextStore::new(&dir);
                let config = s.read_config()?;

                // Show our own key first
                let pk = config.public_key.as_deref().unwrap_or("?");
                let ek = config.encryption_key.as_deref().unwrap_or("?");
                println!(
                    "{}  (self)\n  signing:    {}\n  encryption: {}\n  fingerprint: {}\n",
                    config.name,
                    pk,
                    ek,
                    crypto::fingerprint(pk)
                );

                if config.keyring.is_empty() {
                    println!("Keyring is empty. Import keys with: openfuse key import <name> <keyfile>");
                    return Ok(());
                }

                for entry in &config.keyring {
                    let trust = if entry.trusted {
                        "[TRUSTED]"
                    } else {
                        "[untrusted]"
                    };
                    let addr = if entry.address.is_empty() {
                        "(no address)".to_string()
                    } else {
                        entry.address.clone()
                    };
                    let enc = entry
                        .encryption_key
                        .as_deref()
                        .unwrap_or("(no age key)");
                    println!(
                        "{}  {}  {}\n  signing:    {}\n  encryption: {}\n  fingerprint: {}\n",
                        entry.name, addr, trust, entry.signing_key, enc, entry.fingerprint
                    );
                }
            }
            KeyCommands::Import {
                name,
                signing_key_file,
                dir,
                encryption_key,
                address,
            } => {
                let s = store::ContextStore::new(&dir);
                let mut config = s.read_config()?;

                let signing_key = std::fs::read_to_string(&signing_key_file)?.trim().to_string();
                let fp = crypto::fingerprint(&signing_key);
                let addr = address.unwrap_or_default();

                // Check for duplicate
                if config.keyring.iter().any(|e| e.signing_key == signing_key) {
                    println!("Key already in keyring (fingerprint: {})", fp);
                    return Ok(());
                }

                config.keyring.push(crypto::KeyringEntry {
                    name: name.clone(),
                    address: addr.clone(),
                    signing_key,
                    encryption_key,
                    fingerprint: fp.clone(),
                    trusted: false,
                    added: chrono::Utc::now().to_rfc3339(),
                });
                s.write_config(&config)?;

                println!("Imported key for: {}", name);
                if !addr.is_empty() {
                    println!("  Address: {}", addr);
                }
                println!("  Fingerprint: {}", fp);
                println!("\nKey is NOT trusted yet. Run: openfuse key trust {}", name);
            }
            KeyCommands::Trust { name, dir } => {
                let s = store::ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let idx = config
                    .keyring
                    .iter()
                    .position(|e| e.name == name || e.fingerprint == name);
                match idx {
                    Some(i) => {
                        config.keyring[i].trusted = true;
                        let kname = config.keyring[i].name.clone();
                        let kfp = config.keyring[i].fingerprint.clone();
                        s.write_config(&config)?;
                        println!("Trusted: {} ({})", kname, kfp);
                    }
                    None => {
                        eprintln!("Key not found: {}", name);
                        std::process::exit(1);
                    }
                }
            }
            KeyCommands::Untrust { name, dir } => {
                let s = store::ContextStore::new(&dir);
                let mut config = s.read_config()?;
                let idx = config
                    .keyring
                    .iter()
                    .position(|e| e.name == name || e.fingerprint == name);
                match idx {
                    Some(i) => {
                        config.keyring[i].trusted = false;
                        let kname = config.keyring[i].name.clone();
                        let kfp = config.keyring[i].fingerprint.clone();
                        s.write_config(&config)?;
                        println!("Revoked trust: {} ({})", kname, kfp);
                    }
                    None => {
                        eprintln!("Key not found: {}", name);
                        std::process::exit(1);
                    }
                }
            }
            KeyCommands::Export { dir } => {
                let s = store::ContextStore::new(&dir);
                let config = s.read_config()?;
                let pk = config.public_key.as_deref().unwrap_or("");
                let ek = config.encryption_key.as_deref().unwrap_or("");
                // Output in a format that's easy to share
                println!("# OpenFuse key export: {} ({})", config.name, config.id);
                println!("# Fingerprint: {}", crypto::fingerprint(pk));
                println!("signing:{}", pk);
                println!("encryption:{}", ek);
            }
        },

        Commands::Sync { dir, peer } => {
            let s = store::ContextStore::new(&dir);
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
                if !r.pulled.is_empty() {
                    println!("  pulled: {}", r.pulled.join(", "));
                }
                if !r.pushed.is_empty() {
                    println!("  pushed: {}", r.pushed.join(", "));
                }
                if !r.errors.is_empty() {
                    for e in &r.errors {
                        eprintln!("  error: {}", e);
                    }
                }
                if r.pulled.is_empty() && r.pushed.is_empty() && r.errors.is_empty() {
                    println!("  (nothing to sync)");
                }
            }

            if results.is_empty() {
                println!("No peers configured. Add one with: openfuse peer add <url>");
            }
        }

        Commands::Register {
            dir,
            endpoint,
            registry: reg_flag,
        } => {
            let s = store::ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let manifest = registry::register(&s, &endpoint, &reg).await?;
            let verified = if manifest.signature.is_some() { " [SIGNED]" } else { "" };
            println!("Registered: {}{}", manifest.name, verified);
            println!("  Endpoint:    {}", manifest.endpoint);
            println!("  Fingerprint: {}", manifest.fingerprint);
            println!("  Registry:    {}", reg);
        }

        Commands::Discover {
            name,
            registry: reg_flag,
        } => {
            let reg = registry::resolve_registry(reg_flag.as_deref());
            let manifest = registry::discover(&name, &reg).await?;
            let verified = registry::verify_manifest(&manifest);
            let sig_status = if verified {
                "[SIGNED ✓]"
            } else if manifest.signature.is_some() {
                "[SIGNED ✗ invalid]"
            } else {
                "[unsigned]"
            };
            println!("{}  {}", manifest.name, sig_status);
            println!("  Endpoint:       {}", manifest.endpoint);
            println!("  Signing key:    {}", manifest.public_key);
            if let Some(ref ek) = manifest.encryption_key {
                println!("  Encryption key: {}", ek);
            }
            println!("  Fingerprint:    {}", manifest.fingerprint);
            println!("  Capabilities:   {}", manifest.capabilities.join(", "));
            if let Some(ref desc) = manifest.description {
                println!("  Description:    {}", desc);
            }
            println!("  Created:        {}", manifest.created);
        }

        Commands::Send {
            name,
            message,
            dir,
            registry: reg_flag,
        } => {
            let s = store::ContextStore::new(&dir);
            if !s.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let config = s.read_config()?;

            // Try to resolve via registry first
            let reg = registry::resolve_registry(reg_flag.as_deref());
            if let Ok(manifest) = registry::discover(&name, &reg).await {
                // Auto-import key into keyring if not already there
                let already = config.keyring.iter().any(|e| e.signing_key == manifest.public_key);
                if !already {
                    let mut config = config.clone();
                    config.keyring.push(crypto::KeyringEntry {
                        name: manifest.name.clone(),
                        address: format!("{}@registry", manifest.name),
                        signing_key: manifest.public_key.clone(),
                        encryption_key: manifest.encryption_key.clone(),
                        fingerprint: manifest.fingerprint.clone(),
                        trusted: true, // Auto-trust from signed manifest
                        added: chrono::Utc::now().to_rfc3339(),
                    });
                    s.write_config(&config)?;
                    println!("Imported key for {} from registry", manifest.name);
                }

                // Send the message (auto-encrypts if age key available)
                s.send_inbox(&name, &message, &config.id)?;

                // Try to deliver via sync if endpoint is http:// or ssh://
                let endpoint = &manifest.endpoint;
                if endpoint.starts_with("http://") || endpoint.starts_with("https://")
                    || endpoint.starts_with("ssh://")
                {
                    // Add as temporary peer and sync
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
                            if !r.pushed.is_empty() {
                                println!("Delivered to {}: {}", name, r.pushed.join(", "));
                            }
                            if !r.errors.is_empty() {
                                for e in &r.errors {
                                    eprintln!("  warning: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("Message queued in outbox (delivery failed: {})", e);
                        }
                    }
                } else {
                    println!("Message queued in outbox for {} (endpoint: {})", name, endpoint);
                    println!("Mount the endpoint and sync, or manually copy from outbox/");
                }
            } else {
                // Not in registry — try as a peer name
                s.send_inbox(&name, &message, &config.id)?;
                println!("Message sent to {}'s outbox. Run `openfuse sync` to deliver.", name);
            }
        }
    }

    Ok(())
}
