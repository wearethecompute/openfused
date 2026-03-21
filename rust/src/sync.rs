use anyhow::{Context as _, Result};
use std::fs;
use std::path::Path;

use crate::store::{ContextStore, PeerConfig};

pub struct SyncResult {
    pub peer_name: String,
    pub pulled: Vec<String>,
    pub pushed: Vec<String>,
    pub errors: Vec<String>,
}

// Two transports: HTTP for WAN (daemon serves context over the internet) and
// SSH/rsync for LAN (leverages ~/.ssh/config for auth, no daemon needed).
// SSH is preferred for trusted home-lab peers; HTTP for public registry peers.
enum Transport {
    Http { base_url: String },
    Ssh { host: String, path: String },
}

fn parse_url(url: &str) -> Result<Transport> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(Transport::Http {
            base_url: url.trim_end_matches('/').to_string(),
        })
    } else if url.starts_with("ssh://") {
        // ssh://hostname:/path or ssh://user@hostname:/path
        // hostname can be an SSH config alias — we pass it straight to rsync/ssh
        let rest = &url[6..];
        let (host, path) = rest
            .split_once(':')
            .context("SSH URL must be ssh://host:/path")?;
        // Prevent argument injection: rsync treats leading '-' as flags, and shell
        // metacharacters in the host could execute arbitrary commands. A malicious
        // peer URL like "ssh://--server:/" would become `rsync -az --server:/ ...`.
        if host.starts_with('-') || path.starts_with('-') {
            anyhow::bail!("Invalid SSH URL: host/path cannot start with '-'");
        }
        if host.contains(';') || host.contains('|') || host.contains('`') || host.contains('$') {
            anyhow::bail!("Invalid SSH URL: host contains shell metacharacters");
        }
        Ok(Transport::Ssh {
            host: host.to_string(),
            path: path.to_string(),
        })
    } else {
        anyhow::bail!("Unknown URL scheme: {url}. Use http:// or ssh://")
    }
}

pub async fn sync_all(store: &ContextStore) -> Result<Vec<SyncResult>> {
    let config = store.read_config()?;
    let mut results = vec![];

    for peer in &config.peers {
        match sync_peer(store, peer).await {
            Ok(result) => results.push(result),
            Err(e) => results.push(SyncResult {
                peer_name: peer.name.clone(),
                pulled: vec![],
                pushed: vec![],
                errors: vec![format!("sync failed: {}", e)],
            }),
        }
    }

    Ok(results)
}

pub async fn sync_one(store: &ContextStore, peer_name: &str) -> Result<SyncResult> {
    let config = store.read_config()?;
    let peer = config
        .peers
        .iter()
        .find(|p| p.name == peer_name || p.id == peer_name)
        .context(format!("Peer not found: {}", peer_name))?
        .clone();
    sync_peer(store, &peer).await
}

async fn sync_peer(store: &ContextStore, peer: &PeerConfig) -> Result<SyncResult> {
    let transport = parse_url(&peer.url)?;
    let peer_dir = store.root().join(".peers").join(&peer.name);
    fs::create_dir_all(&peer_dir)?;

    match transport {
        Transport::Http { base_url } => sync_http(store, peer, &base_url, &peer_dir).await,
        Transport::Ssh { host, path } => sync_ssh(store, peer, &host, &path, &peer_dir).await,
    }
}

// --- HTTP sync (WAN) ---

async fn sync_http(
    store: &ContextStore,
    peer: &PeerConfig,
    base_url: &str,
    peer_dir: &Path,
) -> Result<SyncResult> {
    let client = reqwest::Client::new();
    let mut pulled = vec![];
    let mut pushed = vec![];
    let mut errors = vec![];

    // Pull root files
    for file in &["CONTEXT.md", "PROFILE.md"] {
        match client
            .get(format!("{}/read/{}", base_url, file))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.bytes().await?;
                fs::write(peer_dir.join(file), &body)?;
                pulled.push(file.to_string());
            }
            Ok(resp) => errors.push(format!("{}: HTTP {}", file, resp.status())),
            Err(e) => errors.push(format!("{}: {}", file, e)),
        }
    }

    // Pull directories (shared/, knowledge/)
    for dir in &["shared", "knowledge"] {
        match pull_http_dir(&client, base_url, dir, peer_dir).await {
            Ok(files) => pulled.extend(files),
            Err(e) => errors.push(format!("{}/: {}", dir, e)),
        }
    }

    // Push outbox → peer inbox
    match push_http_outbox(store, &client, base_url, peer).await {
        Ok(files) => pushed.extend(files),
        Err(e) => errors.push(format!("push: {}", e)),
    }

    fs::write(
        peer_dir.join(".last-sync"),
        chrono::Utc::now().to_rfc3339(),
    )?;

    Ok(SyncResult {
        peer_name: peer.name.clone(),
        pulled,
        pushed,
        errors,
    })
}

#[derive(serde::Deserialize)]
struct FileEntry {
    name: String,
    is_dir: bool,
    #[allow(dead_code)]
    size: u64,
}

async fn pull_http_dir(
    client: &reqwest::Client,
    base_url: &str,
    dir: &str,
    peer_dir: &Path,
) -> Result<Vec<String>> {
    let mut pulled = vec![];
    let resp = client
        .get(format!("{}/ls/{}", base_url, dir))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(pulled);
    }

    let files: Vec<FileEntry> = resp.json().await?;
    let local_dir = peer_dir.join(dir);
    fs::create_dir_all(&local_dir)?;

    for f in files {
        if f.is_dir {
            continue;
        }
        // Remote peers control the filename in the /ls response — a malicious peer
        // could return "../../../etc/cron.d/backdoor". Extract basename to contain writes.
        let safe_name = match std::path::Path::new(&f.name)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && !n.contains(".."))
        {
            Some(n) => n.to_string(),
            None => continue, // skip malicious filenames
        };
        let resp = client
            .get(format!("{}/read/{}/{}", base_url, dir, safe_name))
            .send()
            .await?;
        if resp.status().is_success() {
            let body = resp.bytes().await?;
            fs::write(local_dir.join(&safe_name), &body)?;
            pulled.push(format!("{}/{}", dir, safe_name));
        }
    }

    Ok(pulled)
}

async fn push_http_outbox(
    store: &ContextStore,
    client: &reqwest::Client,
    base_url: &str,
    peer: &PeerConfig,
) -> Result<Vec<String>> {
    let mut pushed = vec![];
    let outbox_dir = store.root().join("outbox");
    if !outbox_dir.exists() {
        return Ok(pushed);
    }

    for entry in fs::read_dir(&outbox_dir)? {
        let entry = entry?;
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".json") {
            continue;
        }
        // Only push messages addressed to this peer
        if !fname.contains(&format!("_to-{}", peer.name)) && !fname.contains(&peer.id) {
            continue;
        }

        let body = fs::read(entry.path())?;
        match client
            .post(format!("{}/inbox", base_url))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                // Move to .sent/ to prevent re-delivery
                archive_sent(&outbox_dir, &fname)?;
                pushed.push(fname);
            }
            Ok(r) => anyhow::bail!("{}: HTTP {}", fname, r.status()),
            Err(e) => anyhow::bail!("{}: {}", fname, e),
        }
    }

    Ok(pushed)
}

// --- SSH sync (LAN) ---
// Uses rsync over SSH. Host can be an SSH config alias (e.g. "alice.local")
// so we get hostname resolution, user, and key from ~/.ssh/config for free.

async fn sync_ssh(
    store: &ContextStore,
    peer: &PeerConfig,
    host: &str,
    remote_path: &str,
    peer_dir: &Path,
) -> Result<SyncResult> {
    let mut pulled = vec![];
    let mut pushed = vec![];
    let mut errors = vec![];

    // Pull root files
    for file in &["CONTEXT.md", "PROFILE.md"] {
        let src = format!("{}:{}/{}", host, remote_path, file);
        let dst = peer_dir.join(file);
        match rsync(&src, &dst.to_string_lossy()).await {
            Ok(_) => pulled.push(file.to_string()),
            Err(e) => errors.push(format!("{}: {}", file, e)),
        }
    }

    // Pull directories
    for dir in &["shared", "knowledge"] {
        let local = peer_dir.join(dir);
        fs::create_dir_all(&local)?;
        let src = format!("{}:{}/{}/", host, remote_path, dir);
        let dst = format!("{}/", local.to_string_lossy());
        match rsync_dir(&src, &dst).await {
            Ok(_) => pulled.push(format!("{}/", dir)),
            Err(e) => errors.push(format!("{}/: {}", dir, e)),
        }
    }

    // Pull peer's outbox for messages addressed to us — peer may be behind NAT
    // and can't push to us, so we grab messages they left for us.
    let config = store.read_config()?;
    let my_name = &config.name;
    let inbox_dir = store.root().join("inbox");
    fs::create_dir_all(&inbox_dir)?;
    {
        let src = format!("{}:{}/outbox/", host, remote_path);
        let dst = format!("{}/", inbox_dir.to_string_lossy());
        let output = tokio::process::Command::new("rsync")
            .args([
                "-az", "--ignore-existing",
                "--include", &format!("*_to-{}.json", my_name),
                "--include", "*_to-all.json",
                "--exclude", "*",
                &src, &dst,
            ])
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => { pulled.push("outbox→inbox".to_string()); }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("No such file") {
                    errors.push(format!("pull outbox: {}", stderr.trim()));
                }
            }
            Err(e) => errors.push(format!("pull outbox: {}", e)),
        }
    }

    // Push our outbox → remote inbox
    let outbox_dir = store.root().join("outbox");
    if outbox_dir.exists() {
        for entry in fs::read_dir(&outbox_dir)? {
            let entry = entry?;
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".json") {
                continue;
            }
            if !fname.contains(&format!("_to-{}", peer.name)) && !fname.contains(&peer.id) {
                continue;
            }

            let src = entry.path().to_string_lossy().to_string();
            let dst = format!("{}:{}/inbox/{}", host, remote_path, fname);
            match rsync(&src, &dst).await {
                Ok(_) => {
                    archive_sent(&outbox_dir, &fname)?;
                    pushed.push(fname);
                }
                Err(e) => errors.push(format!("push {}: {}", entry.file_name().to_string_lossy(), e)),
            }
        }
    }

    fs::write(
        peer_dir.join(".last-sync"),
        chrono::Utc::now().to_rfc3339(),
    )?;

    Ok(SyncResult {
        peer_name: peer.name.clone(),
        pulled,
        pushed,
        errors,
    })
}

/// Archive delivered messages to outbox/.sent/ instead of deleting them.
/// Prevents duplicate delivery on next sync while preserving an audit trail.
/// Without this, every sync would re-push all outbox messages to the peer.
fn archive_sent(outbox_dir: &Path, fname: &str) -> Result<()> {
    let sent_dir = outbox_dir.join(".sent");
    fs::create_dir_all(&sent_dir)?;
    let src = outbox_dir.join(fname);
    let dst = sent_dir.join(fname);
    fs::rename(&src, &dst)?;
    Ok(())
}

async fn rsync(src: &str, dst: &str) -> Result<()> {
    let output = tokio::process::Command::new("rsync")
        .args(["-az", src, dst])
        .output()
        .await?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

async fn rsync_dir(src: &str, dst: &str) -> Result<()> {
    let output = tokio::process::Command::new("rsync")
        .args(["-az", "--delete", src, dst])
        .output()
        .await?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}
