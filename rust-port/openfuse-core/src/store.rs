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

/// Resolve a keyring entry by name, name:fingerprint, or bare fingerprint prefix.
/// Returns an error if ambiguous (multiple matches) or not found.
pub fn resolve_keyring<'a>(keyring: &'a [KeyringEntry], query: &str) -> Result<&'a KeyringEntry> {
    let (name, fp_prefix) = if let Some(colon_idx) = query.rfind(':') {
        let maybe_fp = &query[colon_idx + 1..];
        if maybe_fp.chars().all(|c| c.is_ascii_hexdigit()) && maybe_fp.len() >= 4 && maybe_fp.len() <= 16 {
            (&query[..colon_idx], Some(maybe_fp.to_uppercase()))
        } else {
            (query, None)
        }
    } else {
        (query, None)
    };

    // Match by name or address prefix
    let mut matches: Vec<&KeyringEntry> = keyring
        .iter()
        .filter(|k| k.name == name || k.address.starts_with(&format!("{}@", name)))
        .collect();

    // If no name match, try bare fingerprint prefix
    if matches.is_empty() && query.chars().all(|c| c.is_ascii_hexdigit()) && query.len() >= 4 {
        let upper = query.to_uppercase();
        matches = keyring
            .iter()
            .filter(|k| k.fingerprint.replace(':', "").starts_with(&upper))
            .collect();
    }

    // Filter by fingerprint prefix if provided
    if let Some(ref fp) = fp_prefix {
        if matches.len() > 1 {
            matches.retain(|k| k.fingerprint.replace(':', "").starts_with(fp.as_str()));
        }
    }

    match matches.len() {
        0 => anyhow::bail!("Key not found: \"{}\". Run: openfuse key list", query),
        1 => Ok(matches[0]),
        _ => {
            let options: Vec<String> = matches
                .iter()
                .map(|k| {
                    let short_fp = k.fingerprint.replace(':', "");
                    format!("  {}:{}  {}", k.name, &short_fp[..8.min(short_fp.len())], k.address)
                })
                .collect();
            anyhow::bail!(
                "Multiple keys match \"{}\". Disambiguate with fingerprint:\n{}",
                query,
                options.join("\n")
            )
        }
    }
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
    /// Workspace mode: auto-trust all imported keys (safe because you control who joins)
    #[serde(rename = "autoTrust", default, skip_serializing_if = "Option::is_none")]
    pub auto_trust: Option<bool>,
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
            fs::write(&context_path, include_str!("../templates/CONTEXT.md"))?;
        }

        let profile_path = self.root.join("PROFILE.md");
        if !profile_path.exists() {
            fs::write(&profile_path, include_str!("../templates/PROFILE.md"))?;
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
            auto_trust: None,
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
        let config = self.read_config()?;

        // Resolve recipient from keyring — supports name, name:fingerprint, or bare fingerprint.
        let entry = resolve_keyring(&config.keyring, peer_id)?;

        let signed = if let Some(ref age_key) = entry.encryption_key {
            crypto::sign_and_encrypt(&self.root, from, message, age_key)?
        } else {
            crypto::sign_message(&self.root, from, message)?
        };

        let serialized = serde_json::to_string_pretty(&signed)?;

        // Outbox structure: outbox/{recipient}-{fp8}/{ts}_from-{sender}.json
        // The fingerprint subdir prevents name squatting — the daemon verifies
        // the recipient's key matches the fingerprint before serving messages.
        let short_fp = entry.fingerprint.replace(':', "");
        let recipient_dir = format!("{}-{}", peer_id, &short_fp[..8]);
        let outbox_subdir = self.root.join("outbox").join(&recipient_dir);
        fs::create_dir_all(&outbox_subdir)?;

        let timestamp = chrono::Utc::now()
            .to_rfc3339()
            .replace([':', '.'], "-");
        let filename = format!("{}_from-{}.json", timestamp, config.name);
        fs::write(outbox_subdir.join(&filename), &serialized)?;
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
                // Identity binding: key must be trusted AND name must match the keyring entry.
                // Prevents a trusted agent from impersonating someone else via forged "from" field.
                let auto_trust = config.auto_trust.unwrap_or(false);
                let key_matches_name = |e: &KeyringEntry| {
                    e.signing_key.trim() == signed.public_key.trim()
                        && (e.name == signed.from || e.address.starts_with(&format!("{}@", signed.from)))
                };
                let trusted = if auto_trust {
                    config.keyring.iter().any(key_matches_name)
                } else {
                    config.keyring.iter().any(|e| e.trusted && key_matches_name(e))
                };

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

                // Wrap the decrypted content (not the ciphertext) for LLM display
                let display_signed = if signed.encrypted {
                    let mut s = signed.clone();
                    s.message = content.clone();
                    s
                } else {
                    signed.clone()
                };
                let wrapped = crypto::wrap_external_message(&display_signed, verified);
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

    // --- Compact ---

    /// Move [DONE] sections from CONTEXT.md to history/{date}.md.
    /// Returns (moved_count, kept_count).
    pub fn compact_context(&self) -> Result<(usize, usize)> {
        let context = self.read_context()?;
        let mut kept = Vec::new();
        let mut done = Vec::new();
        let mut current_section = String::new();
        let mut in_section = false;

        for line in context.lines() {
            if line.starts_with("## ") || line.starts_with("### ") {
                if in_section {
                    if current_section.contains("[DONE]") {
                        done.push(current_section.clone());
                    } else {
                        kept.push(current_section.clone());
                    }
                }
                current_section = format!("{}\n", line);
                in_section = true;
            } else if in_section {
                current_section.push_str(line);
                current_section.push('\n');
            } else {
                // Content before any section header (title, etc)
                kept.push(format!("{}\n", line));
            }
        }
        // Flush last section
        if in_section {
            if current_section.contains("[DONE]") {
                done.push(current_section);
            } else {
                kept.push(current_section);
            }
        }

        if done.is_empty() {
            return Ok((0, kept.len()));
        }

        // Write kept sections back to CONTEXT.md
        let kept_text = kept.join("");
        self.write_context(kept_text.trim_end())?;

        // Append done sections to history/{date}.md
        let history_dir = self.root.join("history");
        fs::create_dir_all(&history_dir)?;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let history_file = history_dir.join(format!("{}.md", date));

        let mut archive = if history_file.exists() {
            fs::read_to_string(&history_file)?
        } else {
            format!("# Archived — {}\n\n", date)
        };
        for section in &done {
            archive.push_str(section);
            archive.push('\n');
        }
        fs::write(&history_file, &archive)?;

        Ok((done.len(), kept.len()))
    }

    // --- Inbox archive ---

    /// Archive a single inbox message to inbox/.read/
    pub fn archive_inbox(&self, filename: &str) -> Result<()> {
        let base = std::path::Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && !n.contains(".."))
            .ok_or_else(|| anyhow::anyhow!("Invalid filename: {}", filename))?;
        let inbox_dir = self.root.join("inbox");
        let archive_dir = inbox_dir.join(".read");
        fs::create_dir_all(&archive_dir)?;
        let src = inbox_dir.join(base);
        if !src.exists() {
            anyhow::bail!("Message not found: {}", base);
        }
        // Path traversal defense: verify resolved path stays under inbox/
        let resolved = src.canonicalize()?;
        let inbox_canon = inbox_dir.canonicalize()?;
        if !resolved.starts_with(&inbox_canon) {
            anyhow::bail!("Path traversal blocked: {}", filename);
        }
        let dst = archive_dir.join(base);
        fs::rename(&src, &dst)?;
        Ok(())
    }

    /// Archive all inbox messages to inbox/.read/
    pub fn archive_inbox_all(&self) -> Result<usize> {
        let inbox_dir = self.root.join("inbox");
        let archive_dir = inbox_dir.join(".read");
        fs::create_dir_all(&archive_dir)?;
        let mut count = 0;
        if inbox_dir.exists() {
            for entry in fs::read_dir(&inbox_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if fname.ends_with(".json") || fname.ends_with(".md") {
                        fs::rename(&path, archive_dir.join(fname))?;
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    // --- Workspace ---

    /// Initialize as a shared workspace (multi-agent collaboration).
    pub fn init_workspace(&self, name: &str, id: &str) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        for dir in &["tasks", "messages", "_broadcast", "shared", "history"] {
            fs::create_dir_all(self.root.join(dir))?;
        }

        let charter_path = self.root.join("CHARTER.md");
        if !charter_path.exists() {
            fs::write(&charter_path, include_str!("../templates/CHARTER.md"))?;
        }

        let context_path = self.root.join("CONTEXT.md");
        if !context_path.exists() {
            fs::write(&context_path, include_str!("../templates/CONTEXT.md"))?;
        }

        let config = MeshConfig {
            id: id.to_string(),
            name: name.to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            public_key: None,
            encryption_key: None,
            peers: vec![],
            keyring: vec![],
            trusted_keys: None,
            auto_trust: Some(true),
        };
        self.write_config(&config)?;
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
