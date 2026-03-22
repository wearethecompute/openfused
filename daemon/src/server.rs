use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, AllowOrigin};

use crate::store::{ContextStore, FileEntry};

// Two serving modes: "public" exposes only PROFILE.md + inbox (safe for the open
// internet), while "full" also serves CONTEXT.md, shared/, and knowledge/ (for
// trusted LAN peers). This prevents accidental exposure of working memory to
// untrusted peers while still allowing message delivery.
pub async fn serve(store_path: PathBuf, bind: &str, port: u16, public: bool) {
    let store = Arc::new(ContextStore::new(store_path));

    let mut app = Router::new()
        .route("/", get(root))
        .route("/config", get(get_config))
        .route("/profile", get(get_profile))
        .route("/inbox", post(receive_inbox))
        .route("/outbox/{name}", get(get_outbox))
        .route("/outbox/{name}/{filename}", delete(ack_outbox));

    if public {
        tracing::info!("Public mode: serving PROFILE.md + inbox only");
    } else {
        tracing::info!("Full mode: serving all context to peers");
        app = app
            .route("/ls", get(list_root))
            .route("/ls/{*path}", get(list_dir))
            .route("/read/{*path}", get(read_file));
    }

    let app = app
        // 1MB body limit — inbox messages are JSON envelopes, not file transfers.
        // Prevents a malicious peer from filling the disk via POST /inbox.
        .layer(DefaultBodyLimit::max(1024 * 1024))
        // Restrict CORS: only allow same-origin by default. Permissive CORS on
        // localhost lets any website exfiltrate agent context via cross-origin requests.
        .layer(CorsLayer::new()
            .allow_origin(AllowOrigin::list([]))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE]))
        .with_state(store);

    let addr = format!("{}:{}", bind, port);
    tracing::info!("OpenFuse daemon listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "openfused v0.3.13 — agent messaging daemon"
}

async fn get_config(
    State(store): State<Arc<ContextStore>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config = store.config().await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "id": config.id,
        "name": config.name,
        "publicKey": config.public_key,
        "encryptionKey": config.encryption_key,
    })))
}

/// PROFILE.md is served separately from /read because it's available in both
/// public and full modes. It's the agent's business card — always safe to share.
/// SOUL.md is deliberately NOT served (private identity, never leaves the host).
async fn get_profile(
    State(store): State<Arc<ContextStore>>,
) -> Result<(StatusCode, [(axum::http::header::HeaderName, &'static str); 1], Vec<u8>), StatusCode> {
    let body = store.read_file("PROFILE.md").await.ok_or(StatusCode::NOT_FOUND)?;
    Ok((StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], body))
}

async fn list_root(State(store): State<Arc<ContextStore>>) -> Json<Vec<FileEntry>> {
    Json(store.list_root().await)
}

async fn list_dir(
    State(store): State<Arc<ContextStore>>,
    Path(path): Path<String>,
) -> Result<Json<Vec<FileEntry>>, StatusCode> {
    if !["shared", "knowledge"].contains(&path.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(store.list_dir(&path).await))
}

async fn read_file(
    State(store): State<Arc<ContextStore>>,
    Path(path): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    store.read_file(&path).await.ok_or(StatusCode::NOT_FOUND)
}

/// Serve outbox messages addressed to a specific agent.
/// Authenticated: caller must prove they own the name via Ed25519 signature challenge.
/// Headers: X-OpenFuse-PublicKey, X-OpenFuse-Signature, X-OpenFuse-Timestamp
/// Signature covers: "OUTBOX:{name}:{timestamp}"
/// Timestamp must be within 5 minutes to prevent replay.
async fn get_outbox(
    State(store): State<Arc<ContextStore>>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let safe_name = name.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "");

    // Extract auth headers
    let pubkey_hex = headers.get("x-openfuse-publickey")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sig_b64 = headers.get("x-openfuse-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp = headers.get("x-openfuse-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify timestamp is within 5 minutes (prevents replay)
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        let age = chrono::Utc::now().signed_duration_since(ts);
        if age.num_seconds().abs() > 300 {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify signature: payload = "OUTBOX:{name}:{timestamp}"
    let challenge = format!("OUTBOX:{}:{}", safe_name, timestamp);
    if !verify_challenge(&challenge, sig_b64, pubkey_hex) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify the public key belongs to this agent
    if !verify_key_ownership(&store, &safe_name, pubkey_hex).await {
        tracing::warn!("Outbox auth rejected: unknown public key for agent '{}'", safe_name);
        return Err(StatusCode::FORBIDDEN);
    }

    // Collect messages addressed to this name, include filename for ACK
    let outbox_dir = store.root.join("outbox");
    let mut messages = vec![];

    if let Ok(mut entries) = tokio::fs::read_dir(&outbox_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".json") { continue; }
            if !fname.contains(&format!("_to-{}.json", safe_name)) { continue; }
            if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                if let Ok(mut msg) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Include filename so client can ACK (DELETE /outbox/{name}/{filename})
                    msg["_outboxFile"] = serde_json::Value::String(fname);
                    messages.push(msg);
                }
            }
        }
    }

    Ok(Json(messages))
}

/// ACK a received outbox message — moves it to outbox/.sent/ so it won't be
/// served again. Same signature auth as GET /outbox/{name}. The recipient calls
/// this after successfully processing each message to prevent duplicate delivery.
async fn ack_outbox(
    State(store): State<Arc<ContextStore>>,
    Path((name, filename)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let safe_name = name.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "");
    let safe_file = filename.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.', "");

    // Same auth as GET /outbox — verify requester owns this name
    let pubkey_hex = headers.get("x-openfuse-publickey")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sig_b64 = headers.get("x-openfuse-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp = headers.get("x-openfuse-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        let age = chrono::Utc::now().signed_duration_since(ts);
        if age.num_seconds().abs() > 300 {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    let challenge = format!("ACK:{}:{}:{}", safe_name, safe_file, timestamp);
    if !verify_signature(&safe_name, timestamp, &challenge, sig_b64, pubkey_hex) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify key belongs to this agent — same check as GET /outbox
    if !verify_key_ownership(&store, &safe_name, pubkey_hex).await {
        tracing::warn!("ACK rejected: unknown public key for agent '{}'", safe_name);
        return Err(StatusCode::FORBIDDEN);
    }

    // Move to .sent/
    let outbox_dir = store.root.join("outbox");
    let src = outbox_dir.join(&safe_file);
    if !src.exists() || !safe_file.contains(&format!("_to-{}.json", safe_name)) {
        return Err(StatusCode::NOT_FOUND);
    }

    let sent_dir = outbox_dir.join(".sent");
    tokio::fs::create_dir_all(&sent_dir).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tokio::fs::rename(&src, sent_dir.join(&safe_file)).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("ACK'd outbox message: {} (moved to .sent/)", safe_file);
    Ok(StatusCode::OK)
}

/// Receive a signed message into the inbox.
/// Verifies Ed25519 signature before accepting — rejects unsigned or forged messages.
async fn receive_inbox(
    State(store): State<Arc<ContextStore>>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    let msg: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let from = msg["from"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let signature = msg["signature"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let public_key = msg["publicKey"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let timestamp = msg["timestamp"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let message = msg["message"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

    // Verify Ed25519 signature — reject forged or unsigned messages at the door
    if !verify_signature(from, timestamp, message, signature, public_key) {
        tracing::warn!("Rejected message with invalid signature from: {}", from);
        return Err(StatusCode::FORBIDDEN);
    }

    let to = store.config().await
        .map(|c| c.name)
        .unwrap_or_else(|| "unknown".to_string());
    let timestamp = chrono::Utc::now()
        .to_rfc3339()
        .replace([':', '.'], "-");
    let filename = format!("{}_from-{}_to-{}.json", timestamp, from, to);

    store
        .write_inbox(&filename, &body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Note: signature is self-consistent (signed by the embedded key), NOT identity-verified.
    // Trust verification happens at read-time via the keyring, not at delivery-time.
    tracing::info!("Received signed message from: {}", from);
    Ok(StatusCode::CREATED)
}

/// Verify a public key belongs to the claimed agent name by checking:
/// 1. Inbox messages from this agent with matching publicKey
/// 2. Keyring entries matching name + signing key
/// 3. Legacy trusted_keys list
/// Without this, any random keypair could impersonate a registered agent.
async fn verify_key_ownership(store: &Arc<ContextStore>, name: &str, pubkey_hex: &str) -> bool {
    // Check inbox for messages from this agent with matching key
    let inbox_dir = store.root.join("inbox");
    if let Ok(mut entries) = tokio::fs::read_dir(&inbox_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.contains(&format!("_from-{}", name)) { continue; }
            if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&content) {
                    if msg["publicKey"].as_str() == Some(pubkey_hex) {
                        return true;
                    }
                }
            }
        }
    }
    // Check keyring and legacy trusted_keys
    if let Some(config) = store.config().await {
        if config.keyring.iter().any(|k| k.name == name && k.signing_key == pubkey_hex) {
            return true;
        }
        if config.trusted_keys.contains(&pubkey_hex.to_string()) {
            return true;
        }
    }
    false
}

/// Verify a raw challenge string signed with Ed25519.
/// Used for outbox authentication — caller signs "OUTBOX:{name}:{timestamp}" to prove identity.
fn verify_challenge(challenge: &str, sig_b64: &str, pubkey_hex: &str) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex.trim()) else { return false };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else { return false };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else { return false };
    let Ok(sig_bytes) = BASE64.decode(sig_b64) else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify(challenge.as_bytes(), &signature).is_ok()
}

/// Verify Ed25519 signature: payload = "{from}\n{timestamp}\n{message}"
/// This only proves the message was signed by the holder of this key — NOT that the key
/// belongs to who they claim to be. Identity binding happens later when the recipient
/// checks the key against their trusted keyring. We verify here to reject garbage/spam
/// at the network edge before it hits disk.
fn verify_signature(from: &str, timestamp: &str, message: &str, sig_b64: &str, pubkey_hex: &str) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex.trim()) else { return false };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else { return false };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else { return false };
    let Ok(sig_bytes) = BASE64.decode(sig_b64) else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };
    let signature = Signature::from_bytes(&sig_arr);
    let payload = format!("{}\n{}\n{}", from, timestamp, message);
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}
