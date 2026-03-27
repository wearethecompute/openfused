use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::types::*;

pub struct ContextStore {
    pub root: PathBuf,
}

impl ContextStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    // -----------------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------------

    pub async fn config(&self) -> Option<MeshConfig> {
        let path = self.root.join(".mesh.json");
        let data = fs::read_to_string(&path).await.ok()?;
        serde_json::from_str(&data).ok()
    }

    // -----------------------------------------------------------------------
    // File listing / reading
    // -----------------------------------------------------------------------

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
        let full_path = self.root.join(path);
        let canonical = full_path.canonicalize().ok()?;
        let root_canonical = self.root.canonicalize().ok()?;
        if !canonical.starts_with(&root_canonical) {
            tracing::warn!(
                "Blocked path traversal: {} resolved to {}",
                path,
                canonical.display()
            );
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

    pub async fn read_profile_text(&self) -> Option<String> {
        fs::read_to_string(self.root.join("PROFILE.md")).await.ok()
    }

    // -----------------------------------------------------------------------
    // Task CRUD
    // -----------------------------------------------------------------------

    /// Create a new task directory with task.json, input.json, events.ndjson, artifacts/.
    pub async fn create_task(
        &self,
        task: &TaskRecord,
        input: &serde_json::Value,
    ) -> Result<(), std::io::Error> {
        let safe_id = sanitize_path_segment(&task.id);
        validate_path_segment(&safe_id)?;
        let task_dir = self.root.join("tasks").join(&safe_id);
        let artifacts_dir = task_dir.join("artifacts");
        fs::create_dir_all(&artifacts_dir).await?;

        let task_json = serde_json::to_vec_pretty(task)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let input_json = serde_json::to_vec_pretty(input)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        fs::write(task_dir.join("task.json"), task_json).await?;
        fs::write(task_dir.join("input.json"), input_json).await?;
        fs::write(task_dir.join("events.ndjson"), Vec::<u8>::new()).await?;

        // Append initial status event
        let event = TaskEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind: "status".to_string(),
            status: Some(task.status.clone()),
            artifact: None,
            message: None,
        };
        self.append_event(&task.id, &event).await?;

        Ok(())
    }

    /// Read a task by ID.
    pub async fn read_task(&self, id: &str) -> Option<TaskRecord> {
        let safe_id = sanitize_path_segment(id);
        let path = self.root.join("tasks").join(&safe_id).join("task.json");
        let data = fs::read_to_string(path).await.ok()?;
        serde_json::from_str(&data).ok()
    }

    /// List all tasks, sorted by most recently updated first.
    pub async fn list_tasks(&self) -> Vec<TaskRecord> {
        let tasks_dir = self.root.join("tasks");
        let mut tasks = Vec::new();

        let Ok(mut reader) = fs::read_dir(&tasks_dir).await else {
            return tasks;
        };

        while let Ok(Some(entry)) = reader.next_entry().await {
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }

            let path = entry.path().join("task.json");
            let Ok(data) = fs::read_to_string(path).await else {
                continue;
            };
            let Ok(task) = serde_json::from_str::<TaskRecord>(&data) else {
                continue;
            };
            tasks.push(task);
        }

        // Sort by updated_at descending (from _openfuse metadata).
        tasks.sort_by(|a, b| {
            let a_time = a.openfuse.as_ref().map(|m| m.updated_at.as_str()).unwrap_or("");
            let b_time = b.openfuse.as_ref().map(|m| m.updated_at.as_str()).unwrap_or("");
            b_time.cmp(a_time)
        });
        tasks
    }

    /// Update a task's status. Writes to task.json and appends to events.ndjson.
    pub async fn update_task_status(
        &self,
        id: &str,
        new_status: TaskStatus,
    ) -> Result<TaskRecord, std::io::Error> {
        let safe_id = sanitize_path_segment(id);
        let task_path = self.root.join("tasks").join(&safe_id).join("task.json");

        let data = fs::read_to_string(&task_path)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Task not found"))?;
        let mut task: TaskRecord = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Don't allow transitions from terminal states.
        if task_state::is_terminal(&task.status.state) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Task is in terminal state: {}", task.status.state),
            ));
        }

        let now = chrono::Utc::now().to_rfc3339();
        task.status = new_status.clone();
        if let Some(ref mut meta) = task.openfuse {
            meta.updated_at = now.clone();
        }

        let task_json = serde_json::to_vec_pretty(&task)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&task_path, task_json).await?;

        // Append status event.
        let event = TaskEvent {
            timestamp: now,
            kind: "status".to_string(),
            status: Some(new_status),
            artifact: None,
            message: None,
        };
        self.append_event(&safe_id, &event).await?;

        Ok(task)
    }

    /// Append an event line to events.ndjson.
    pub async fn append_event(
        &self,
        id: &str,
        event: &TaskEvent,
    ) -> Result<(), std::io::Error> {
        let safe_id = sanitize_path_segment(id);
        let path = self.root.join("tasks").join(&safe_id).join("events.ndjson");

        let mut line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }

    /// Write an artifact to tasks/<id>/artifacts/ and update task.json.
    pub async fn write_artifact(
        &self,
        id: &str,
        artifact: TaskArtifact,
    ) -> Result<TaskRecord, std::io::Error> {
        let safe_id = sanitize_path_segment(id);
        let task_path = self.root.join("tasks").join(&safe_id).join("task.json");
        let artifacts_dir = self.root.join("tasks").join(&safe_id).join("artifacts");
        fs::create_dir_all(&artifacts_dir).await?;

        // If the artifact has a text part, write it to a file too.
        if let Some(name) = &artifact.name {
            let safe_name = sanitize_path_segment(name);
            for part in &artifact.parts {
                if let Some(text) = &part.text {
                    fs::write(artifacts_dir.join(&safe_name), text.as_bytes()).await?;
                    break;
                }
            }
        }

        // Update task.json with the new artifact.
        let data = fs::read_to_string(&task_path)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Task not found"))?;
        let mut task: TaskRecord = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let now = chrono::Utc::now().to_rfc3339();
        if let Some(ref mut meta) = task.openfuse {
            meta.updated_at = now.clone();
        }

        task.artifacts.push(artifact.clone());

        let task_json = serde_json::to_vec_pretty(&task)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&task_path, task_json).await?;

        // Append artifact event.
        let event = TaskEvent {
            timestamp: now,
            kind: "artifact".to_string(),
            status: None,
            artifact: Some(artifact),
            message: None,
        };
        self.append_event(&safe_id, &event).await?;

        Ok(task)
    }

    /// Append a message to a task's history.
    pub async fn append_history(
        &self,
        id: &str,
        message: A2AMessage,
    ) -> Result<TaskRecord, std::io::Error> {
        let safe_id = sanitize_path_segment(id);
        let task_path = self.root.join("tasks").join(&safe_id).join("task.json");

        let data = fs::read_to_string(&task_path)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "Task not found"))?;
        let mut task: TaskRecord = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let now = chrono::Utc::now().to_rfc3339();
        if let Some(ref mut meta) = task.openfuse {
            meta.updated_at = now.clone();
        }

        // Append message event.
        let event = TaskEvent {
            timestamp: now,
            kind: "message".to_string(),
            status: None,
            artifact: None,
            message: Some(message.clone()),
        };
        self.append_event(&safe_id, &event).await?;

        task.history.push(message);

        let task_json = serde_json::to_vec_pretty(&task)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&task_path, task_json).await?;

        Ok(task)
    }

    // -----------------------------------------------------------------------
    // Inbox
    // -----------------------------------------------------------------------

    /// Write a message to the inbox directory.
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid filename",
            ));
        }

        fs::write(inbox_dir.join(safe_name), content).await
    }
}

/// Sanitize a path segment — strip anything that could traverse directories.
/// Returns None if the result is empty or starts with a dot (hidden file/dir).
/// Iteratively strips ".." to prevent reconstitution attacks.
fn sanitize_path_segment(s: &str) -> String {
    let mut result: String = s
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    // Iteratively strip ".." to prevent "..." → "." after single-pass replace.
    while result.contains("..") {
        result = result.replace("..", "");
    }
    // Strip leading dots to prevent hidden files/dirs.
    result = result.trim_start_matches('.').to_string();
    result
}

/// Validate a sanitized path segment is safe for use as a directory/file name.
fn validate_path_segment(s: &str) -> Result<(), std::io::Error> {
    if s.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Path segment is empty after sanitization",
        ));
    }
    if s.starts_with('.') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Path segment cannot start with a dot",
        ));
    }
    Ok(())
}
