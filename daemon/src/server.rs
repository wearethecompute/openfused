use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{delete, get, post},
    Router,
};
use subtle::ConstantTimeEq;
use tokio_stream::wrappers::ReceiverStream;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::store::ContextStore;
use crate::types::*;

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<ContextStore>,
    pub token: Option<String>,
}

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

pub async fn serve(
    store_path: PathBuf,
    bind: &str,
    port: u16,
    public: bool,
    token: Option<String>,
    gc_days: u32,
) {
    let store = Arc::new(ContextStore::new(store_path));

    let state = AppState {
        store: store.clone(),
        token: token.clone(),
    };

    // A2A routes — protected by bearer token auth (if configured)
    let a2a_routes = Router::new()
        .route("/message/send", post(send_message))
        .route("/message/stream", post(stream_message))
        .route("/tasks", get(list_tasks))
        .route("/tasks/{id}", get(get_task))
        .route("/tasks/{id}/cancel", post(cancel_task))
        .route("/tasks/{id}/subscribe", post(subscribe_task))
        .route("/tasks/{id}/status", post(update_task_status_handler))
        .route("/tasks/{id}/artifacts", post(create_artifact_handler));

    // Apply bearer auth middleware if token is configured
    let a2a_routes = if token.is_some() {
        a2a_routes.layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
    } else {
        a2a_routes
    };

    // Build main router
    let mut app = Router::new()
        // Public routes (no auth — discovery must work without credentials)
        .route("/", get(root))
        .route("/.well-known/agent-card.json", get(get_agent_card))
        .route("/config", get(get_config))
        .route("/profile", get(get_profile))
        // A2A routes (auth'd if token set)
        .merge(a2a_routes)
        // Native OpenFused routes (own Ed25519 sig auth)
        .route("/inbox", post(receive_inbox))
        .route("/inbox/{name}", post(receive_inbox))  // alias for multi-tenant compat
        .route("/outbox/{name}", get(get_outbox))
        .route("/outbox/{name}/{*filepath}", delete(ack_outbox));

    if public {
        tracing::info!("Public mode: serving PROFILE.md + inbox only (safe for internet)");
    } else {
        tracing::warn!(
            "Full mode: serving CONTEXT.md, shared/, knowledge/ to anyone who connects"
        );
        tracing::warn!("Only use on trusted LAN/VPN. For internet use, add --public");
        app = app
            .route("/ls", get(list_root))
            .route("/ls/{*path}", get(list_dir))
            .route("/read/{*path}", get(read_file));
    }

    let app = app
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list([
                    "https://openfused.dev".parse().unwrap(),
                    "https://claude.ai".parse().unwrap(),
                ]))
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                    "X-OpenFuse-PublicKey".parse().unwrap(),
                    "X-OpenFuse-Signature".parse().unwrap(),
                    "X-OpenFuse-Timestamp".parse().unwrap(),
                ]),
        )
        .with_state(state.clone());

    // Auth status logging
    if token.is_some() {
        tracing::info!("A2A routes protected by bearer token (--token / OPENFUSE_TOKEN)");
    } else {
        tracing::warn!("A2A routes (/message/*, /tasks/*) are UNAUTHENTICATED");
        tracing::warn!("Do not expose to untrusted networks without --token or OPENFUSE_TOKEN");
    }

    // Task garbage collection background task
    if gc_days > 0 {
        let gc_store = store.clone();
        let max_age = chrono::Duration::days(gc_days as i64);
        tokio::spawn(async move {
            // Initial delay: 60s after startup
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            loop {
                let removed = gc_store.gc_tasks(max_age).await;
                if removed > 0 {
                    tracing::info!("GC: removed {} expired tasks", removed);
                }
                // Run every 6 hours
                tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
            }
        });
        tracing::info!("Task GC: cleaning tasks older than {} days (every 6h)", gc_days);
    }

    let addr = format!("{}:{}", bind, port);
    tracing::info!("OpenFuse daemon listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------
// Bearer auth middleware
// ---------------------------------------------------------------------------

async fn bearer_auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(ref expected_token) = state.token else {
        return next.run(request).await;
    };

    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let provided_token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");

    // Constant-time comparison to prevent timing attacks
    let expected_bytes = expected_token.as_bytes();
    let provided_bytes = provided_token.as_bytes();
    let is_valid = expected_bytes.len() == provided_bytes.len()
        && expected_bytes.ct_eq(provided_bytes).into();

    if !is_valid {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
            Json(ProblemDetail {
                r#type: "about:blank".to_string(),
                title: "Unauthorized".to_string(),
                status: 401,
                detail: Some("Missing or invalid bearer token".to_string()),
            }),
        )
            .into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------------
// Core routes
// ---------------------------------------------------------------------------

async fn root() -> &'static str {
    "OpenFused — file-native shared memory and signed messaging for AI agents. https://openfused.dev"
}

async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let store = &state.store;
    let config = store.config().await.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({
        "id": config.id,
        "name": config.name,
        "publicKey": config.public_key,
        "encryptionKey": config.encryption_key,
    })))
}

async fn get_profile(
    State(state): State<AppState>,
) -> Result<
    (
        StatusCode,
        [(axum::http::header::HeaderName, &'static str); 1],
        Vec<u8>,
    ),
    StatusCode,
> {
    let store = &state.store;
    let body = store
        .read_file("PROFILE.md")
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        body,
    ))
}

// ---------------------------------------------------------------------------
// A2A: Agent Card discovery
// ---------------------------------------------------------------------------

async fn get_agent_card(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AgentCard>, StatusCode> {
    let store = &state.store;
    let config = store.config().await.ok_or(StatusCode::NOT_FOUND)?;
    let profile = store.read_profile_text().await.unwrap_or_default();
    let base_url = external_base_url(&headers)
        .unwrap_or_else(|| "http://127.0.0.1:2053".to_string());
    let description = summarize_profile(&profile).unwrap_or_else(|| {
        "OpenFused agent with file-native shared context and signed messaging.".to_string()
    });

    let card = AgentCard {
        name: config.name,
        description,
        version: env!("CARGO_PKG_VERSION").to_string(),
        default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        capabilities: AgentCapabilities {
            streaming: true,
            push_notifications: false,
        },
        skills: vec![
            AgentSkill {
                id: "openfused-context".to_string(),
                name: "Shared Context".to_string(),
                description: "Reads and writes durable agent context backed by the OpenFused store."
                    .to_string(),
                tags: vec![
                    "context".to_string(),
                    "memory".to_string(),
                    "files".to_string(),
                ],
            },
            AgentSkill {
                id: "openfused-messaging".to_string(),
                name: "Signed Messaging".to_string(),
                description:
                    "Exchanges signed agent messages and artifacts through the OpenFused protocol."
                        .to_string(),
                tags: vec![
                    "messaging".to_string(),
                    "agent".to_string(),
                    "artifacts".to_string(),
                ],
            },
        ],
        supported_interfaces: vec![AgentInterface {
            url: base_url,
            protocol: "a2a/basic".to_string(),
            version: Some("0.3".to_string()),
        }],
        provider: Some(AgentProvider {
            organization: "OpenFused".to_string(),
            url: Some("https://openfused.dev".to_string()),
        }),
        icon_url: None,
        security_schemes: HashMap::new(),
    };

    Ok(Json(card))
}

// ---------------------------------------------------------------------------
// A2A: Message send (create or continue a task)
// ---------------------------------------------------------------------------

async fn send_message(
    State(state): State<AppState>,
    Json(request): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<SendMessageResponse>), (StatusCode, Json<ProblemDetail>)> {
    let store = &state.store;
    // Validate parts
    if request.message.parts.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ProblemDetail::bad_request("Message must have at least one part")),
        ));
    }
    if !request.message.parts.iter().all(|p| p.is_supported()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ProblemDetail::bad_request(
                "All parts must have at least one content field (text, data, or file)",
            )),
        ));
    }

    // If task_id is present, this is a follow-up to an existing task.
    if let Some(ref task_id) = request.message.task_id {
        let task = store.append_history(task_id, request.message.clone()).await.map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ProblemDetail::not_found(e.to_string())),
            )
        })?;
        return Ok((StatusCode::OK, Json(SendMessageResponse::Task(task))));
    }

    // New task.
    let now = chrono::Utc::now().to_rfc3339();
    let task_id = generate_task_id();
    let context_id = request
        .message
        .context_id
        .clone()
        .unwrap_or_else(|| generate_context_id());

    // Normalize parts (add kind field if missing).
    let normalized_message = A2AMessage {
        parts: request
            .message
            .parts
            .into_iter()
            .map(|p| p.normalized())
            .collect(),
        context_id: Some(context_id.clone()),
        task_id: Some(task_id.clone()),
        ..request.message
    };

    let task = TaskRecord {
        id: task_id.clone(),
        context_id: Some(context_id),
        status: TaskStatus {
            state: task_state::SUBMITTED.to_string(),
            message: None,
            timestamp: Some(now.clone()),
        },
        artifacts: vec![],
        history: vec![normalized_message],
        metadata: request.metadata.map(|m| {
            m.into_iter()
                .collect::<serde_json::Map<String, serde_json::Value>>()
        }),
        openfuse: Some(OpenfuseTaskMeta {
            created_at: now.clone(),
            updated_at: now,
        }),
    };

    let input =
        serde_json::to_value(&request.configuration).unwrap_or(serde_json::Value::Null);
    store.create_task(&task, &input).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ProblemDetail::internal(e.to_string())),
        )
    })?;

    Ok((StatusCode::CREATED, Json(SendMessageResponse::Task(task))))
}

// ---------------------------------------------------------------------------
// A2A: Task retrieval
// ---------------------------------------------------------------------------

async fn list_tasks(
    State(state): State<AppState>,
) -> Json<ListTasksResponse> {
    let store = &state.store;
    let tasks = store.list_tasks().await;
    Json(ListTasksResponse { tasks })
}

async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TaskRecord>, (StatusCode, Json<ProblemDetail>)> {
    let store = &state.store;
    let task = store.read_task(&id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ProblemDetail::not_found(format!("Task not found: {}", id))),
        )
    })?;
    Ok(Json(task))
}

// ---------------------------------------------------------------------------
// A2A: Task cancellation
// ---------------------------------------------------------------------------

async fn cancel_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TaskRecord>, (StatusCode, Json<ProblemDetail>)> {
    let store = &state.store;
    let cancel_status = TaskStatus {
        state: task_state::CANCELED.to_string(),
        message: None,
        timestamp: Some(chrono::Utc::now().to_rfc3339()),
    };

    let task = store
        .update_task_status(&id, cancel_status)
        .await
        .map_err(|e| {
            let detail = e.to_string();
            if detail.contains("not found") || detail.contains("NotFound") {
                (StatusCode::NOT_FOUND, Json(ProblemDetail::not_found(detail)))
            } else if detail.contains("terminal") {
                (StatusCode::CONFLICT, Json(ProblemDetail::conflict(detail)))
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ProblemDetail::internal(detail)),
                )
            }
        })?;

    Ok(Json(task))
}

// ---------------------------------------------------------------------------
// OpenFuse extensions: task status update + artifact creation
// ---------------------------------------------------------------------------

/// POST /tasks/{id}/status — lets any agent update a task's status via HTTP.
async fn update_task_status_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateTaskStatusRequest>,
) -> Result<Json<TaskRecord>, (StatusCode, Json<ProblemDetail>)> {
    let store = &state.store;
    // Validate state is a known A2A task state.
    if !task_state::is_valid(&request.status.state) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ProblemDetail::bad_request(format!(
                "Invalid task state: '{}'. Valid states: submitted, working, input-required, completed, failed, canceled, rejected, auth-required",
                request.status.state
            ))),
        ));
    }

    let task = store
        .update_task_status(&id, request.status)
        .await
        .map_err(|e| {
            let detail = e.to_string();
            if detail.contains("not found") || detail.contains("NotFound") {
                (StatusCode::NOT_FOUND, Json(ProblemDetail::not_found(detail)))
            } else if detail.contains("terminal") {
                (StatusCode::CONFLICT, Json(ProblemDetail::conflict(detail)))
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ProblemDetail::internal(detail)),
                )
            }
        })?;

    Ok(Json(task))
}

/// POST /tasks/{id}/artifacts — lets any agent attach an artifact to a task.
async fn create_artifact_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<CreateArtifactRequest>,
) -> Result<(StatusCode, Json<TaskRecord>), (StatusCode, Json<ProblemDetail>)> {
    let store = &state.store;
    let task = store
        .write_artifact(&id, request.artifact)
        .await
        .map_err(|e| {
            let detail = e.to_string();
            if detail.contains("not found") || detail.contains("NotFound") {
                (StatusCode::NOT_FOUND, Json(ProblemDetail::not_found(detail)))
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ProblemDetail::internal(detail)),
                )
            }
        })?;

    Ok((StatusCode::CREATED, Json(task)))
}

// ---------------------------------------------------------------------------
// A2A: SSE Streaming
// ---------------------------------------------------------------------------

/// POST /message:stream — create a task and stream events via SSE.
async fn stream_message(
    State(state): State<AppState>,
    Json(request): Json<SendMessageRequest>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>>, (StatusCode, Json<ProblemDetail>)>
{
    let store = &state.store;
    // Validate
    if request.message.parts.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ProblemDetail::bad_request("Message must have at least one part")),
        ));
    }

    // Create task (same logic as send_message).
    let now = chrono::Utc::now().to_rfc3339();
    let task_id = generate_task_id();
    let context_id = request
        .message
        .context_id
        .clone()
        .unwrap_or_else(generate_context_id);

    let normalized_message = A2AMessage {
        parts: request.message.parts.into_iter().map(|p| p.normalized()).collect(),
        context_id: Some(context_id.clone()),
        task_id: Some(task_id.clone()),
        ..request.message
    };

    let task = TaskRecord {
        id: task_id.clone(),
        context_id: Some(context_id),
        status: TaskStatus {
            state: task_state::SUBMITTED.to_string(),
            message: None,
            timestamp: Some(now.clone()),
        },
        artifacts: vec![],
        history: vec![normalized_message],
        metadata: request.metadata.map(|m| {
            m.into_iter().collect::<serde_json::Map<String, serde_json::Value>>()
        }),
        openfuse: Some(OpenfuseTaskMeta {
            created_at: now.clone(),
            updated_at: now,
        }),
    };

    let input = serde_json::to_value(&request.configuration).unwrap_or(serde_json::Value::Null);
    store.create_task(&task, &input).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ProblemDetail::internal(e.to_string())))
    })?;

    // Set up SSE stream from events.ndjson. Use the task record's ID (server-generated,
    // safe) rather than any user-supplied value for the path.
    let events_path = store
        .root
        .join("tasks")
        .join(&task.id)
        .join("events.ndjson");
    let task_snapshot = task.clone();

    Ok(build_sse_stream(store.clone(), events_path, task_snapshot))
}

/// POST /tasks/{id}/subscribe — subscribe to an existing task's events via SSE.
async fn subscribe_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>>, (StatusCode, Json<ProblemDetail>)>
{
    let store = &state.store;
    // read_task sanitizes the ID internally; use the returned task.id for the path
    // to prevent path traversal via URL-encoded characters in the raw `id`.
    let task = store.read_task(&id).await.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ProblemDetail::not_found(format!("Task not found: {}", id))))
    })?;

    let events_path = store.root.join("tasks").join(&task.id).join("events.ndjson");
    let task_snapshot = task;

    Ok(build_sse_stream(store.clone(), events_path, task_snapshot))
}

/// Build an SSE stream from a task snapshot + events.ndjson file tail.
fn build_sse_stream(
    store: Arc<ContextStore>,
    events_path: PathBuf,
    task_snapshot: TaskRecord,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let task_id = task_snapshot.id.clone();
    let is_already_terminal = task_state::is_terminal(&task_snapshot.status.state);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<SseEvent, std::convert::Infallible>>(64);

    tokio::spawn(async move {
        // First event: full task snapshot.
        let snapshot_json = serde_json::to_string(&task_snapshot).unwrap_or_default();
        let event = SseEvent::default().event("task").data(snapshot_json);
        if tx.send(Ok(event)).await.is_err() {
            return;
        }

        // If already terminal, close immediately.
        if is_already_terminal {
            return;
        }

        // Tail events.ndjson for new events.
        let Ok(mut file_rx) = crate::tail::tail_ndjson(events_path).await else {
            return;
        };

        // SECURITY: Timeout after 30 minutes to prevent resource leaks from
        // tasks that never reach terminal state. Clients can reconnect via
        // POST /tasks/{id}/subscribe.
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(30 * 60));
        tokio::pin!(timeout);

        loop {
            let line = tokio::select! {
                _ = &mut timeout => {
                    let ev = SseEvent::default()
                        .event("timeout")
                        .data(r#"{"reason":"SSE stream timeout after 30 minutes"}"#);
                    let _ = tx.send(Ok(ev)).await;
                    return;
                }
                recv = file_rx.recv() => match recv {
                    Some(l) => l,
                    None => return,
                },
            };

            let event_type = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line)
            {
                parsed["kind"].as_str().unwrap_or("event").to_string()
            } else {
                "event".to_string()
            };

            let sse_event = SseEvent::default().event(&event_type).data(line);
            if tx.send(Ok(sse_event)).await.is_err() {
                return; // Client disconnected
            }

            // Check if task reached terminal state — read fresh from disk.
            if let Some(task) = store.read_task(&task_id).await {
                if task_state::is_terminal(&task.status.state) {
                    let final_json = serde_json::to_string(&task).unwrap_or_default();
                    let ev = SseEvent::default().event("task").data(final_json);
                    let _ = tx.send(Ok(ev)).await;
                    return;
                }
            } else {
                // Task was deleted (GC or manual). Close the stream.
                let ev = SseEvent::default()
                    .event("error")
                    .data(r#"{"reason":"task deleted"}"#);
                let _ = tx.send(Ok(ev)).await;
                return;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------------------------------------------------------------------------
// Full-mode file serving (trusted LAN only)
// ---------------------------------------------------------------------------

async fn list_root(State(state): State<AppState>) -> Json<Vec<FileEntry>> {
    let store = &state.store;
    Json(store.list_root().await)
}

async fn list_dir(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<Vec<FileEntry>>, StatusCode> {
    let store = &state.store;
    if !["shared", "knowledge"].contains(&path.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(store.list_dir(&path).await))
}

async fn read_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let store = &state.store;
    store.read_file(&path).await.ok_or(StatusCode::NOT_FOUND)
}

// ---------------------------------------------------------------------------
// Native OpenFused: inbox + outbox
// ---------------------------------------------------------------------------

/// Receive a signed message into the inbox.
async fn receive_inbox(
    State(state): State<AppState>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    let store = &state.store;
    let msg: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let from = msg["from"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let signature = msg["signature"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let public_key = msg["publicKey"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let timestamp = msg["timestamp"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let message = msg["message"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

    if !verify_signature(from, timestamp, message, signature, public_key) {
        tracing::warn!("Rejected message with invalid signature from: {}", from);
        return Err(StatusCode::FORBIDDEN);
    }

    // Reject stale messages — prevents replay of captured signed messages (10 min window)
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        let age = chrono::Utc::now().signed_duration_since(ts);
        if age.num_seconds().abs() > 600 {
            tracing::warn!("Rejected stale message from: {} (age={}s)", from, age.num_seconds());
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let to = store
        .config()
        .await
        .map(|c| c.name)
        .unwrap_or_else(|| "unknown".to_string());
    let sender_fp = &hex::encode(sha2::Sha256::digest(public_key.as_bytes()))[..8];
    let ts = chrono::Utc::now()
        .to_rfc3339()
        .replace([':', '.'], "-");
    let filename = format!("{}_from-{}-{}_to-{}.json", ts, from, sender_fp, to);

    store
        .write_inbox(&filename, &body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Received signed message from: {}", from);
    Ok(StatusCode::CREATED)
}

/// Serve outbox messages addressed to a specific agent.
async fn get_outbox(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let store = &state.store;
    let safe_name = name.replace(
        |c: char| !c.is_alphanumeric() && c != '-' && c != '_',
        "",
    );

    let pubkey_hex = headers
        .get("x-openfuse-publickey")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sig_b64 = headers
        .get("x-openfuse-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp = headers
        .get("x-openfuse-timestamp")
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

    let challenge = format!("OUTBOX:{}:{}", safe_name, timestamp);
    if !verify_challenge(&challenge, sig_b64, pubkey_hex) {
        return Err(StatusCode::FORBIDDEN);
    }

    if !verify_key_ownership(&store, &safe_name, pubkey_hex).await {
        tracing::warn!(
            "Outbox auth rejected: unknown public key for agent '{}'",
            safe_name
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let requester_fp = {
        let hash = Sha256::digest(pubkey_hex.as_bytes());
        hex::encode(&hash[..4]).to_uppercase()
    };

    let outbox_dir = store.root.join("outbox");
    let mut messages = vec![];

    if let Ok(mut entries) = tokio::fs::read_dir(&outbox_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let entry_name = entry.file_name().to_string_lossy().to_string();

            // Subdir format: outbox/{name}-{FINGERPRINT}/*.json
            if entry
                .file_type()
                .await
                .map(|t| t.is_dir())
                .unwrap_or(false)
            {
                let prefix = format!("{}-", safe_name);
                if !entry_name.starts_with(&prefix) {
                    continue;
                }
                let dir_fp = &entry_name[prefix.len()..];
                if !dir_fp.eq_ignore_ascii_case(&requester_fp) {
                    continue;
                }

                let sub_dir = entry.path();
                if let Ok(mut sub_entries) = tokio::fs::read_dir(&sub_dir).await {
                    while let Ok(Some(sub_entry)) = sub_entries.next_entry().await {
                        let fname = sub_entry.file_name().to_string_lossy().to_string();
                        if !fname.ends_with(".json") {
                            continue;
                        }
                        if let Ok(content) =
                            tokio::fs::read_to_string(sub_entry.path()).await
                        {
                            if let Ok(mut msg) =
                                serde_json::from_str::<serde_json::Value>(&content)
                            {
                                msg["_outboxFile"] = serde_json::Value::String(format!(
                                    "{}/{}",
                                    entry_name, fname
                                ));
                                messages.push(msg);
                            }
                        }
                    }
                }
                continue;
            }

            // Legacy flat format
            let fname = entry_name;
            if !fname.ends_with(".json") {
                continue;
            }
            if fname.contains(&format!("_to-{}-", safe_name)) {
                let suffix = fname.trim_end_matches(".json");
                let fp_part = suffix.rsplit('-').next().unwrap_or("");
                if !fp_part.eq_ignore_ascii_case(&requester_fp) {
                    continue;
                }
            } else if !fname.contains(&format!("_to-{}.json", safe_name)) {
                continue;
            }

            if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                if let Ok(mut msg) = serde_json::from_str::<serde_json::Value>(&content) {
                    msg["_outboxFile"] = serde_json::Value::String(fname.clone());
                    messages.push(msg);
                }
            }
        }
    }

    Ok(Json(messages))
}

/// ACK a received outbox message.
async fn ack_outbox(
    State(state): State<AppState>,
    Path((name, filepath)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let store = &state.store;
    let safe_name = name.replace(
        |c: char| !c.is_alphanumeric() && c != '-' && c != '_',
        "",
    );

    let sanitized_path: String = filepath
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .map(|s| {
            s.replace(
                |c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.',
                "",
            )
        })
        .collect::<Vec<_>>()
        .join("/");
    if sanitized_path.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if sanitized_path.split('/').count() > 2 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pubkey_hex = headers
        .get("x-openfuse-publickey")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let sig_b64 = headers
        .get("x-openfuse-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let timestamp = headers
        .get("x-openfuse-timestamp")
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

    let challenge = format!("ACK:{}:{}:{}", safe_name, sanitized_path, timestamp);
    if !verify_challenge(&challenge, sig_b64, pubkey_hex) {
        return Err(StatusCode::FORBIDDEN);
    }

    if !verify_key_ownership(&store, &safe_name, pubkey_hex).await {
        tracing::warn!(
            "ACK rejected: unknown public key for agent '{}'",
            safe_name
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Verify fingerprint in subdir path
    if sanitized_path.contains('/') {
        let subdir = sanitized_path.split('/').next().unwrap_or("");
        let expected_prefix = format!("{}-", safe_name);
        if subdir.starts_with(&expected_prefix) {
            let dir_fp = &subdir[expected_prefix.len()..];
            let requester_fp = {
                let hash = Sha256::digest(pubkey_hex.as_bytes());
                hex::encode(&hash[..4]).to_uppercase()
            };
            if !dir_fp.eq_ignore_ascii_case(&requester_fp) {
                tracing::warn!(
                    "ACK fingerprint mismatch: dir={}, requester={}",
                    dir_fp,
                    requester_fp
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    let outbox_dir = store.root.join("outbox");
    let src = outbox_dir.join(&sanitized_path);
    if !src.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    let parent = src.parent().unwrap_or(&outbox_dir);
    let sent_dir = parent.join(".sent");
    let base_name = src.file_name().unwrap_or_default();
    tokio::fs::create_dir_all(&sent_dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tokio::fs::rename(&src, sent_dir.join(base_name))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        "ACK'd outbox message: {} (moved to .sent/)",
        sanitized_path
    );
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

async fn verify_key_ownership(store: &Arc<ContextStore>, name: &str, pubkey_hex: &str) -> bool {
    if let Some(config) = store.config().await {
        if config
            .keyring
            .iter()
            .any(|k| k.name == name && k.signing_key == pubkey_hex)
        {
            return true;
        }
        // Note: trusted_keys (legacy v0.1 format) is NOT checked here because it
        // has no name binding — would allow any name to authenticate with a trusted key.
        // The Rust core migrates trusted_keys to keyring entries on first config read.
    }
    false
}

fn verify_challenge(challenge: &str, sig_b64: &str, pubkey_hex: &str) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex.trim()) else {
        return false;
    };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify(challenge.as_bytes(), &signature).is_ok()
}

fn verify_signature(
    from: &str,
    timestamp: &str,
    message: &str,
    sig_b64: &str,
    pubkey_hex: &str,
) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex.trim()) else {
        return false;
    };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    let payload = format!("{}\n{}\n{}", from, timestamp, message);
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn summarize_profile(profile: &str) -> Option<String> {
    for line in profile.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

fn external_base_url(headers: &axum::http::HeaderMap) -> Option<String> {
    let host = headers.get(axum::http::header::HOST)?.to_str().ok()?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    Some(format!("{}://{}", proto, host))
}

fn generate_task_id() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "task_{}_{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        hex::encode(bytes)
    )
}

fn generate_context_id() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("ctx_{}", hex::encode(bytes))
}
