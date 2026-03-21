use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::store::{ContextStore, FileEntry};

pub async fn serve(store_path: PathBuf, bind: &str, port: u16, public: bool) {
    let store = Arc::new(ContextStore::new(store_path));

    let mut app = Router::new()
        .route("/", get(root))
        .route("/config", get(get_config))
        .route("/profile", get(get_profile))
        .route("/inbox", post(receive_inbox));

    // Full context serving — only for trusted peers (LAN/SSH)
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
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB max request body
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

/// Serve PROFILE.md — the agent's public business card
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

/// Receive a signed message into the inbox
async fn receive_inbox(
    State(store): State<Arc<ContextStore>>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    let msg: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if msg.get("from").is_none() || msg.get("signature").is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let from = msg["from"].as_str().unwrap_or("unknown");
    let timestamp = chrono::Utc::now()
        .to_rfc3339()
        .replace([':', '.'], "-");
    let filename = format!("{}_{}.json", timestamp, from);

    store
        .write_inbox(&filename, &body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Received inbox message from: {}", from);
    Ok(StatusCode::CREATED)
}
