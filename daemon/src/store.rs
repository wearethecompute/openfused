use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyringEntry {
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(default, rename = "encryptionKey")]
    pub encryption_key: Option<String>,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default)]
    pub added: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeshConfig {
    pub id: String,
    pub name: String,
    pub created: String,
    #[serde(default)]
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    #[serde(default, rename = "encryptionKey")]
    pub encryption_key: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub keyring: Vec<KeyringEntry>,
    #[serde(default)]
    pub trusted_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub access: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub struct ContextStore {
    pub root: PathBuf,
}

impl ContextStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn config(&self) -> Option<MeshConfig> {
        let path = self.root.join(".mesh.json");
        let data = fs::read_to_string(&path).await.ok()?;
        serde_json::from_str(&data).ok()
    }

    pub async fn list_dir(&self, subdir: &str) -> Vec<FileEntry> {
        let dir = self.root.join(subdir);
        let mut entries = Vec::new();

        if let Ok(mut reader) = fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = reader.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    entries.push(FileEntry {
                        name: entry.file_name().to_string_lossy().to_string(),
                        is_dir: meta.is_dir(),
                        size: meta.len(),
                    });
                }
            }
        }

        entries
    }

    pub async fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        // Two-layer defense: prefix allowlist blocks access to .keys/, inbox/, .mesh.json, etc.
        // Canonicalization below catches symlink/.. tricks that bypass the prefix check.
        let allowed_prefixes = ["shared/", "knowledge/", "CONTEXT.md", "PROFILE.md"];
        if !allowed_prefixes.iter().any(|p| path.starts_with(p)) {
            tracing::warn!("Blocked read of restricted path: {}", path);
            return None;
        }

        // Resolve symlinks and ".." then verify we're still inside the store root.
        // Without this, "shared/../../.keys/private.key" passes the prefix check.
        let full_path = self.root.join(path);
        let canonical = match full_path.canonicalize() {
            Ok(p) => p,
            Err(_) => return None,
        };
        let root_canonical = match self.root.canonicalize() {
            Ok(p) => p,
            Err(_) => return None,
        };
        if !canonical.starts_with(&root_canonical) {
            tracing::warn!("Blocked path traversal: {} resolved to {}", path, canonical.display());
            return None;
        }

        fs::read(&canonical).await.ok()
    }

    pub async fn list_root(&self) -> Vec<FileEntry> {
        let mut entries = Vec::new();

        for name in &["CONTEXT.md", "PROFILE.md", "shared", "knowledge"] {
            let path = self.root.join(name);
            if let Ok(meta) = fs::metadata(&path).await {
                entries.push(FileEntry {
                    name: name.to_string(),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                });
            }
        }

        entries
    }

    /// Write a message to the inbox directory.
    /// Filename comes from the `from` field of an untrusted HTTP request, so we
    /// aggressively strip it to a safe charset. This is stricter than basename
    /// extraction because the inbox is append-only and world-writable — an attacker
    /// controls the filename directly via POST /inbox.
    pub async fn write_inbox(&self, filename: &str, content: &str) -> Result<(), std::io::Error> {
        let inbox_dir = self.root.join("inbox");
        fs::create_dir_all(&inbox_dir).await?;

        // Whitelist charset + length cap. Leading dots rejected to prevent hidden files.
        let safe_name: String = filename
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .take(128)
            .collect();
        if safe_name.is_empty() || safe_name.starts_with('.') {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid filename"));
        }

        fs::write(inbox_dir.join(safe_name), content).await
    }
}
