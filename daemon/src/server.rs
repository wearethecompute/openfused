use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

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
        .route("/inbox", post(receive_inbox));

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
        .layer(CorsLayer::permissive())
        .with_state(store);

    let addr = format!("{}:{}", bind, port);
    tracing::info!("OpenFuse daemon listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "openfused v0.3.2 — context mesh daemon"
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
) -> Result<Vec<u8>, StatusCode> {
    store.read_file("PROFILE.md").await.ok_or(StatusCode::NOT_FOUND)
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

    tracing::info!("Received verified message from: {}", from);
    Ok(StatusCode::CREATED)
}

/// Verify Ed25519 signature: payload = "{from}\n{timestamp}\n{message}"
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
