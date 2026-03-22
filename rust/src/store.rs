use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KeyringEntry, SignedMessage};

/// Validate agent/peer names: alphanumeric + hyphens + underscores + dots, 1-64 chars.
/// Rejects path traversal (../, /, \) and rsync glob chars (*, ?, [).
pub fn validate_name(name: &str, label: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("{} must be 1-64 characters", label);
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        anyhow::bail!("{} must start with alphanumeric character", label);
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        anyhow::bail!("{} must contain only a-z, 0-9, -, _, .", label);
    }
    if name.contains("..") {
        anyhow::bail!("{} contains invalid path characters", label);
    }
    Ok(())
}

// Convention: the context store is a plain directory with well-known subdirs.
// No database, no binary format — just files. Any tool that reads files can
// participate in the mesh without importing a library.
const STORE_DIRS: &[&str] = &["history", "knowledge", "inbox", "outbox", "shared"];

// --- Config types ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshConfig {
    pub id: String,
    pub name: String,
    pub created: String,
    /// Ed25519 signing public key (hex)
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// age encryption public key (age1...)
    #[serde(rename = "encryptionKey", skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    pub peers: Vec<PeerConfig>,
    /// GPG-style keyring — replaces the flat trustedKeys list so we can track
    /// per-key metadata (trust level, fingerprint, encryption key, address).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keyring: Vec<KeyringEntry>,
    /// Legacy v0.1 field — auto-migrated to keyring on first read so existing
    /// stores upgrade seamlessly without manual intervention.
    #[serde(rename = "trustedKeys", skip_serializing_if = "Option::is_none")]
    pub trusted_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub access: String,
    #[serde(rename = "mountPath", skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
}

pub struct StatusInfo {
    pub id: String,
    pub name: String,
    pub peers: usize,
    pub inbox_count: usize,
    pub shared_count: usize,
}

pub struct InboxMessage {
    pub file: String,
    pub content: String,
    pub wrapped_content: String,
    pub from: String,
    pub time: String,
    pub verified: bool,
    pub encrypted: bool,
}

// --- Context store ---

pub struct ContextStore {
    root: PathBuf,
}

impl ContextStore {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(".mesh.json")
    }

    pub fn exists(&self) -> bool {
        self.config_path().exists()
    }

    // --- Init ---

    pub fn init(&self, name: &str, id: &str) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        for dir in STORE_DIRS {
            fs::create_dir_all(self.root.join(dir))?;
        }
        fs::create_dir_all(self.root.join(".peers"))?;

        let context_path = self.root.join("CONTEXT.md");
        if !context_path.exists() {
            fs::write(
                &context_path,
                "# Context\n\n*Working memory — what's happening right now.*\n",
            )?;
        }

        // PROFILE.md is the public address card — served to peers, synced, shown in registry.
        // SOUL.md (if it exists) is private identity/personality — never served or synced.
        // This split lets agents share contact info without exposing system prompts.
        let profile_path = self.root.join("PROFILE.md");
        if !profile_path.exists() {
            fs::write(
                &profile_path,
                format!(
                    "# {}\n\n**ID:** {}\n\n## Endpoint\n\n_(not configured — run `openfuse register`)_\n",
                    name, id
                ),
            )?;
        }

        let (public_key, encryption_key) = crypto::generate_keys(&self.root)?;

        let config = MeshConfig {
            id: id.to_string(),
            name: name.to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            public_key: Some(public_key),
            encryption_key: Some(encryption_key),
            peers: vec![],
            keyring: vec![],
            trusted_keys: None,
        };
        self.write_config(&config)?;
        Ok(())
    }

    // --- Config I/O ---

    pub fn read_config(&self) -> Result<MeshConfig> {
        let raw = fs::read_to_string(self.config_path())?;
        let mut config: MeshConfig = serde_json::from_str(&raw)?;

        // Migrate legacy trusted_keys → keyring
        if let Some(keys) = config.trusted_keys.take() {
            for key in keys {
                let key = key.trim().to_string();
                if key.is_empty() {
                    continue;
                }
                let already = config.keyring.iter().any(|e| e.signing_key == key);
                if !already {
                    config.keyring.push(KeyringEntry {
                        name: format!("migrated-{}", &key[..8.min(key.len())]),
                        address: String::new(),
                        signing_key: key.clone(),
                        encryption_key: None,
                        fingerprint: crypto::fingerprint(&key),
                        trusted: true,
                        added: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            // Save migrated config
            self.write_config(&config)?;
        }

        Ok(config)
    }

    pub fn write_config(&self, config: &MeshConfig) -> Result<()> {
        let json = serde_json::to_string_pretty(config)?;
        fs::write(self.config_path(), format!("{}\n", json))?;
        Ok(())
    }

    // --- Context / Soul ---

    pub fn read_context(&self) -> Result<String> {
        Ok(fs::read_to_string(self.root.join("CONTEXT.md"))?)
    }

    pub fn write_context(&self, content: &str) -> Result<()> {
        fs::write(self.root.join("CONTEXT.md"), content)?;
        Ok(())
    }

    pub fn read_profile(&self) -> Result<String> {
        Ok(fs::read_to_string(self.root.join("PROFILE.md"))?)
    }

    pub fn write_profile(&self, content: &str) -> Result<()> {
        fs::write(self.root.join("PROFILE.md"), content)?;
        Ok(())
    }

    // --- Inbox ---

    /// Send a message to a peer. Encrypts if we have their age key in the keyring.
    pub fn send_inbox(&self, peer_id: &str, message: &str, from: &str) -> Result<()> {
        validate_name(peer_id, "Recipient name")?;
        let config = self.read_config()?;

        // Look up peer's encryption key in keyring
        let entry = config.keyring.iter().find(|e| {
            e.name == peer_id || e.address.starts_with(&format!("{}@", peer_id))
        });

        let signed = if let Some(entry) = entry {
            if let Some(ref age_key) = entry.encryption_key {
                crypto::sign_and_encrypt(&self.root, from, message, age_key)?
            } else {
                crypto::sign_message(&self.root, from, message)?
            }
        } else {
            crypto::sign_message(&self.root, from, message)?
        };

        let serialized = serde_json::to_string_pretty(&signed)?;
        // Envelope filename encodes timestamp + routing so messages can be matched to
        // recipients without parsing JSON, and colons/dots are replaced to stay
        // filesystem-safe across OS boundaries (Windows, FAT32, etc).
        let timestamp = chrono::Utc::now()
            .to_rfc3339()
            .replace([':', '.'], "-");
        let filename = format!("{}_from-{}_to-{}.json", timestamp, config.name, peer_id);
        fs::write(self.root.join("outbox").join(&filename), &serialized)?;
        Ok(())
    }

    pub fn read_inbox(&self) -> Result<Vec<InboxMessage>> {
        let inbox_dir = self.root.join("inbox");
        if !inbox_dir.exists() {
            return Ok(vec![]);
        }

        let config = self.read_config()?;
        let mut messages = vec![];

        for entry in fs::read_dir(&inbox_dir)? {
            let entry = entry?;
            let path = entry.path();
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            if !fname.ends_with(".json") && !fname.ends_with(".md") {
                continue;
            }

            let raw = fs::read_to_string(&path)?;

            if let Ok(signed) = serde_json::from_str::<SignedMessage>(&raw) {
                if signed.from.is_empty() {
                    continue;
                }

                let sig_valid = crypto::verify_message(&signed);
                let trusted = config
                    .keyring
                    .iter()
                    .any(|e| e.trusted && e.signing_key.trim() == signed.public_key.trim());

                let verified = sig_valid && trusted;

                // Decrypt if encrypted
                let content = if signed.encrypted {
                    match crypto::decrypt_message(&self.root, &signed) {
                        Ok(plain) => plain,
                        Err(_) => "[encrypted — cannot decrypt]".to_string(),
                    }
                } else {
                    signed.message.clone()
                };

                let wrapped = crypto::wrap_external_message(&signed, verified);
                messages.push(InboxMessage {
                    file: fname,
                    content,
                    wrapped_content: wrapped,
                    from: signed.from.clone(),
                    time: signed.timestamp.clone(),
                    verified,
                    encrypted: signed.encrypted,
                });
            } else {
                // Unsigned fallback
                let stem = fname.trim_end_matches(".json").trim_end_matches(".md");
                let parts: Vec<&str> = stem.splitn(2, '_').collect();
                let from = if parts.len() > 1 {
                    parts[1].to_string()
                } else {
                    "unknown".to_string()
                };
                let time = parts[0].to_string();
                // Use the same XML escaping as signed messages to prevent
                // prompt injection via crafted unsigned message content.
                let esc = |s: &str| s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
                let wrapped = format!(
                    "<external_message from=\"{}\" verified=\"false\" time=\"{}\" status=\"UNVERIFIED\">\n{}\n</external_message>",
                    esc(&from), esc(&time), esc(&raw)
                );
                messages.push(InboxMessage {
                    file: fname,
                    content: raw,
                    wrapped_content: wrapped,
                    from,
                    time,
                    verified: false,
                    encrypted: false,
                });
            }
        }

        messages.sort_by(|a, b| a.time.cmp(&b.time));
        Ok(messages)
    }

    // --- Shared files ---

    pub fn list_shared(&self) -> Result<Vec<String>> {
        let shared_dir = self.root.join("shared");
        if !shared_dir.exists() {
            return Ok(vec![]);
        }
        let files = fs::read_dir(shared_dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        Ok(files)
    }

    pub fn share(&self, filename: &str, content: &str) -> Result<()> {
        // Extract basename to neutralize path traversal (e.g. "../../etc/passwd").
        // file_name() strips all directory components; the ".." check is belt-and-suspenders.
        let base = std::path::Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && !n.contains(".."))
            .ok_or_else(|| anyhow::anyhow!("Invalid filename: {}", filename))?;
        let shared_dir = self.root.join("shared");
        fs::create_dir_all(&shared_dir)?;
        fs::write(shared_dir.join(base), content)?;
        Ok(())
    }

    // --- Status ---

    pub fn status(&self) -> Result<StatusInfo> {
        let config = self.read_config()?;
        let inbox = self.read_inbox()?;
        let shared = self.list_shared()?;
        Ok(StatusInfo {
            id: config.id,
            name: config.name,
            peers: config.peers.len(),
            inbox_count: inbox.len(),
            shared_count: shared.len(),
        })
    }
}
