use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::store::ContextStore;

/// Default public registry URL
pub const DEFAULT_REGISTRY: &str = "https://openfuse-registry.wzmcghee.workers.dev";

/// Agent manifest — the "DNS record" for an agent in the registry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub name: String,
    /// Where to reach this agent (http://, ssh://, gs://, s3://)
    pub endpoint: String,
    /// Ed25519 signing public key (hex)
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// age encryption public key (age1...)
    #[serde(rename = "encryptionKey", skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// SHA-256 fingerprint of signing key
    pub fingerprint: String,
    pub created: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Ed25519 signature over the canonical manifest (proves ownership)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Timestamp used during signing (needed to verify)
    #[serde(rename = "signedAt", skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// Resolve registry target from flag, env var, or default.
/// Returns either a URL (http(s)://) or a local path.
pub fn resolve_registry(flag: Option<&str>) -> String {
    if let Some(p) = flag {
        p.to_string()
    } else if let Ok(p) = std::env::var("OPENFUSE_REGISTRY") {
        p
    } else {
        DEFAULT_REGISTRY.to_string()
    }
}

fn is_http(registry: &str) -> bool {
    registry.starts_with("http://") || registry.starts_with("https://")
}

/// Build and sign a manifest from the current store config.
pub fn build_manifest(store: &ContextStore, endpoint: &str) -> Result<Manifest> {
    let config = store.read_config()?;
    let name = &config.name;
    let public_key = config
        .public_key
        .as_deref()
        .context("No signing key — run `openfuse init` first")?;
    let encryption_key = config.encryption_key.clone();
    let fingerprint = crypto::fingerprint(public_key);

    let mut manifest = Manifest {
        name: name.clone(),
        endpoint: endpoint.to_string(),
        public_key: public_key.to_string(),
        encryption_key,
        fingerprint,
        created: chrono::Utc::now().to_rfc3339(),
        capabilities: vec![
            "inbox".to_string(),
            "shared".to_string(),
            "knowledge".to_string(),
        ],
        description: None,
        signature: None,
        signed_at: None,
    };

    // Sign the manifest
    let canonical = canonical_manifest(&manifest);
    let signed = crypto::sign_message(store.root(), &manifest.name, &canonical)?;
    manifest.signature = Some(signed.signature);
    manifest.signed_at = Some(signed.timestamp);

    Ok(manifest)
}

/// Register this agent. Handles both local dir and HTTP registries.
pub async fn register(store: &ContextStore, endpoint: &str, registry: &str) -> Result<Manifest> {
    let manifest = build_manifest(store, endpoint)?;

    if is_http(registry) {
        register_http(&manifest, registry).await?;
    } else {
        register_local(&manifest, Path::new(registry))?;
    }

    Ok(manifest)
}

fn register_local(manifest: &Manifest, registry: &Path) -> Result<()> {
    let agent_dir = registry.join(&manifest.name);
    fs::create_dir_all(&agent_dir)?;
    let json = serde_json::to_string_pretty(manifest)?;
    fs::write(agent_dir.join("manifest.json"), format!("{}\n", json))?;
    Ok(())
}

async fn register_http(manifest: &Manifest, registry: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/register", registry.trim_end_matches('/'));
    let body = serde_json::to_string(manifest)?;

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("Failed to connect to registry")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if status.is_success() {
        Ok(())
    } else {
        // Try to extract error message from JSON
        let err_msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or(text);
        anyhow::bail!("Registry returned {}: {}", status, err_msg)
    }
}

/// Discover an agent by name. Handles both local dir and HTTP registries.
pub async fn discover(name: &str, registry: &str) -> Result<Manifest> {
    if is_http(registry) {
        discover_http(name, registry).await
    } else {
        discover_local(name, Path::new(registry))
    }
}

fn discover_local(name: &str, registry: &Path) -> Result<Manifest> {
    let manifest_path = registry.join(name).join("manifest.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("Agent '{}' not found in registry at {}", name, registry.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

async fn discover_http(name: &str, registry: &str) -> Result<Manifest> {
    let client = reqwest::Client::new();
    let url = format!("{}/discover/{}", registry.trim_end_matches('/'), name);
    let resp = client.get(&url).send().await.context("Failed to connect to registry")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if status.is_success() {
        Ok(serde_json::from_str(&text)?)
    } else {
        let err_msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or(format!("HTTP {}", status));
        anyhow::bail!("{}", err_msg)
    }
}

/// List all agents in the registry.
pub async fn list_agents(registry: &str) -> Result<Vec<Manifest>> {
    if is_http(registry) {
        list_http(registry).await
    } else {
        list_local(Path::new(registry))
    }
}

fn list_local(registry: &Path) -> Result<Vec<Manifest>> {
    let mut agents = vec![];
    if !registry.exists() {
        return Ok(agents);
    }
    for entry in fs::read_dir(registry)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let manifest_path = entry.path().join("manifest.json");
        if manifest_path.exists() {
            if let Ok(raw) = fs::read_to_string(&manifest_path) {
                if let Ok(m) = serde_json::from_str::<Manifest>(&raw) {
                    agents.push(m);
                }
            }
        }
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

async fn list_http(registry: &str) -> Result<Vec<Manifest>> {
    let client = reqwest::Client::new();
    let url = format!("{}/list", registry.trim_end_matches('/'));
    let resp = client.get(&url).send().await?;
    let body: serde_json::Value = resp.json().await?;
    // The /list endpoint returns { agents: [...], count: N }
    // But agents are summaries, not full manifests. Return what we have.
    let mut agents = vec![];
    if let Some(arr) = body["agents"].as_array() {
        for a in arr {
            if let (Some(name), Some(endpoint), Some(fp)) = (
                a["name"].as_str(),
                a["endpoint"].as_str(),
                a["fingerprint"].as_str(),
            ) {
                agents.push(Manifest {
                    name: name.to_string(),
                    endpoint: endpoint.to_string(),
                    public_key: String::new(),
                    encryption_key: None,
                    fingerprint: fp.to_string(),
                    created: String::new(),
                    capabilities: vec![],
                    description: None,
                    signature: None,
                    signed_at: None,
                });
            }
        }
    }
    Ok(agents)
}

/// Verify a manifest's signature (proves the registrant owns the key).
pub fn verify_manifest(manifest: &Manifest) -> bool {
    let Some(ref sig) = manifest.signature else {
        return false;
    };
    let Some(ref signed_at) = manifest.signed_at else {
        return false;
    };
    let canonical = canonical_manifest(manifest);
    let signed = crypto::SignedMessage {
        from: manifest.name.clone(),
        timestamp: signed_at.clone(),
        message: canonical,
        signature: sig.clone(),
        public_key: manifest.public_key.clone(),
        encrypted: false,
    };
    crypto::verify_message(&signed)
}

/// Check if a newer version is available. Non-blocking, best-effort.
pub async fn check_update(current: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?;
    let resp = client.get(DEFAULT_REGISTRY).send().await.ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;
    let latest = body["latest"].as_str()?;
    if latest != current {
        Some(latest.to_string())
    } else {
        None
    }
}

/// Canonical string representation of a manifest for signing.
fn canonical_manifest(m: &Manifest) -> String {
    format!(
        "{}|{}|{}|{}",
        m.name,
        m.endpoint,
        m.public_key,
        m.encryption_key.as_deref().unwrap_or("")
    )
}
