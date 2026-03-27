//! Shared A2A + OpenFused types used by both server.rs and store.rs.
//!
//! These types align with the A2A protocol spec (v0.3) while preserving
//! OpenFused-specific metadata under `_openfuse` keys.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// A2A Parts & Messages
// ---------------------------------------------------------------------------

/// A single content part within a Message or Artifact.
///
/// A2A uses a oneof pattern: exactly one of text/data/file should be present.
/// We're lenient on input (accept any combination) but always emit clean output.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct A2APart {
    /// Content type discriminator. Optional on input (inferred from which
    /// field is present), always emitted on output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Structured JSON data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,

    /// File content — inline object with mimeType, data (base64), name, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,

    /// MIME type of the content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Original filename, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    /// Arbitrary part-level metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

impl A2APart {
    /// Returns true if this part has at least one content field set.
    pub fn is_supported(&self) -> bool {
        self.text.is_some() || self.data.is_some() || self.file.is_some()
    }

    /// Infer and normalize the `kind` field from content presence.
    pub fn normalized(mut self) -> Self {
        if self.kind.is_none() {
            if self.text.is_some() {
                self.kind = Some("text".to_string());
            } else if self.file.is_some() {
                self.kind = Some("file".to_string());
            } else if self.data.is_some() {
                self.kind = Some("data".to_string());
            }
        }
        self
    }
}

/// A message in the A2A protocol — either from a user or an agent.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct A2AMessage {
    pub message_id: String,

    /// Conversation thread ID. Omitted on first message; server generates one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    /// Task this message belongs to. Omitted on first message; server generates one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,

    /// "user" or "agent".
    pub role: String,

    pub parts: Vec<A2APart>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_task_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Task lifecycle
// ---------------------------------------------------------------------------

/// Task state constants (A2A spec uses these string values).
pub mod task_state {
    pub const SUBMITTED: &str = "submitted";
    pub const WORKING: &str = "working";
    pub const INPUT_REQUIRED: &str = "input-required";
    pub const COMPLETED: &str = "completed";
    pub const FAILED: &str = "failed";
    pub const CANCELED: &str = "canceled";
    pub const REJECTED: &str = "rejected";
    pub const AUTH_REQUIRED: &str = "auth-required";

    /// Returns true if the state is terminal (no further transitions allowed).
    pub fn is_terminal(state: &str) -> bool {
        matches!(state, COMPLETED | FAILED | CANCELED | REJECTED)
    }

    /// Returns true if the state is a valid A2A task state.
    pub fn is_valid(state: &str) -> bool {
        matches!(
            state,
            SUBMITTED | WORKING | INPUT_REQUIRED | COMPLETED | FAILED | CANCELED | REJECTED | AUTH_REQUIRED
        )
    }
}

/// Current status of a task.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    /// One of the task_state constants.
    pub state: String,

    /// Optional status message from the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2AMessage>,

    /// ISO 8601 timestamp of this status change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// An output artifact produced by a task.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifact {
    pub artifact_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Artifact content as parts (text, file, data).
    #[serde(default)]
    pub parts: Vec<A2APart>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// A task record — the canonical on-disk representation stored in task.json.
///
/// A2A fields are at the top level. OpenFused-specific metadata (created_at,
/// updated_at, store path) lives under `_openfuse`.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskRecord {
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,

    pub status: TaskStatus,

    #[serde(default)]
    pub artifacts: Vec<TaskArtifact>,

    /// Conversation history — messages in order.
    #[serde(default)]
    pub history: Vec<A2AMessage>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,

    /// OpenFused-internal metadata (timestamps, store info). Not part of A2A spec.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_openfuse")]
    pub openfuse: Option<OpenfuseTaskMeta>,
}

/// OpenFused-specific metadata stored alongside A2A task data.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpenfuseTaskMeta {
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// SSE event types (for events.ndjson lines)
// ---------------------------------------------------------------------------

/// A single event line written to events.ndjson. One of these per line.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,

    /// Event kind: "status", "artifact", "message".
    pub kind: String,

    /// For status events: the new status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskStatus>,

    /// For artifact events: the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<TaskArtifact>,

    /// For message events: the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2AMessage>,
}

// ---------------------------------------------------------------------------
// Agent Card (A2A discovery)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub version: String,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub capabilities: AgentCapabilities,
    pub skills: Vec<AgentSkill>,
    pub supported_interfaces: Vec<AgentInterface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub security_schemes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub streaming: bool,
    pub push_notifications: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProvider {
    pub organization: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    pub message: A2AMessage,
    #[serde(default)]
    pub configuration: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Response to message:send — either a Task or a direct Message.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SendMessageResponse {
    Task(TaskRecord),
    #[allow(dead_code)]
    Message(A2AMessage),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTasksResponse {
    pub tasks: Vec<TaskRecord>,
}

/// Request to update a task's status (OpenFuse extension endpoint).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTaskStatusRequest {
    pub status: TaskStatus,
}

/// Request to add an artifact to a task (OpenFuse extension endpoint).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateArtifactRequest {
    #[serde(flatten)]
    pub artifact: TaskArtifact,
}

// ---------------------------------------------------------------------------
// Error response (RFC 7807 Problem Detail)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ProblemDetail {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ProblemDetail {
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            r#type: "about:blank".to_string(),
            title: "Bad Request".to_string(),
            status: 400,
            detail: Some(detail.into()),
        }
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self {
            r#type: "about:blank".to_string(),
            title: "Not Found".to_string(),
            status: 404,
            detail: Some(detail.into()),
        }
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self {
            r#type: "about:blank".to_string(),
            title: "Conflict".to_string(),
            status: 409,
            detail: Some(detail.into()),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            r#type: "about:blank".to_string(),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: Some(detail.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Store config types (kept here to avoid circular deps)
// ---------------------------------------------------------------------------

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
    #[serde(default, rename = "publicKey")]
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
