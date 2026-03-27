//! File tail utility — watches an NDJSON file and streams new lines.
//!
//! Used by SSE endpoints to stream task events. The file watcher is a
//! notification layer (doorbell), not a data layer. If the watcher misses
//! an event, the periodic fallback re-read catches it.

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;

/// Tail an NDJSON file, sending each new line through the returned channel.
///
/// - Starts reading from the current end of file (only new lines).
/// - Uses `notify` to detect writes; falls back to polling every 5s.
/// - The watcher is dropped (cleaned up) when the receiver is dropped.
pub async fn tail_ndjson(path: PathBuf) -> Result<mpsc::Receiver<String>, std::io::Error> {
    let (tx, rx) = mpsc::channel::<String>(64);

    // Open the file and seek to end.
    let file = tokio::fs::File::open(&path).await?;
    let initial_len = file.metadata().await?.len();

    tokio::spawn(async move {
        // Channel for filesystem notifications.
        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);

        // Set up file watcher. Falls back to 5s polling if inotify is unavailable
        // (e.g., inotify watch limit exhausted).
        let watch_path = path.clone();
        let _watcher = setup_watcher(watch_path, notify_tx.clone());
        if _watcher.is_none() {
            tracing::warn!(
                "File watcher setup failed for {}; falling back to 5s polling. \
                 Check inotify limits if this persists.",
                path.display()
            );
        }

        // Periodic fallback: send a tick every 5s in case the watcher misses events.
        let fallback_tx = notify_tx.clone();
        let _ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if fallback_tx.send(()).await.is_err() {
                    break;
                }
            }
        });

        let mut offset = initial_len;

        loop {
            // Wait for a notification (file change or periodic tick).
            if notify_rx.recv().await.is_none() {
                break; // Watcher dropped
            }

            // Drain any queued notifications to batch reads.
            while notify_rx.try_recv().is_ok() {}

            // Read new lines from the file.
            match read_new_lines(&path, &mut offset).await {
                Ok(lines) => {
                    for line in lines {
                        if tx.send(line).await.is_err() {
                            return; // Receiver dropped (client disconnected)
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Error reading {}: {}", path.display(), e);
                }
            }
        }
    });

    Ok(rx)
}

/// Read new lines from a file starting at the given offset.
/// Updates offset to the new position after reading.
async fn read_new_lines(
    path: &PathBuf,
    offset: &mut u64,
) -> Result<Vec<String>, std::io::Error> {
    let file = tokio::fs::File::open(path).await?;
    let file_len = file.metadata().await?.len();

    if file_len <= *offset {
        return Ok(vec![]);
    }

    let mut file = file;
    file.seek(std::io::SeekFrom::Start(*offset)).await?;

    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }
        *offset += bytes_read as u64;
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            lines.push(trimmed);
        }
    }

    Ok(lines)
}

/// Set up a filesystem watcher that sends () on the channel when the file changes.
fn setup_watcher(
    path: PathBuf,
    tx: mpsc::Sender<()>,
) -> Option<RecommendedWatcher> {
    let watch_dir = path.parent()?.to_path_buf();
    let watch_filename = path.file_name()?.to_os_string();

    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, _>| {
        if let Ok(event) = res {
            // Only care about data modifications to our specific file.
            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let matches = event.paths.iter().any(|p| {
                    p.file_name()
                        .map(|f| f == watch_filename)
                        .unwrap_or(false)
                });
                if matches {
                    let _ = tx.blocking_send(());
                }
            }
        }
    })
    .ok()?;

    watcher.watch(&watch_dir, RecursiveMode::NonRecursive).ok()?;
    Some(watcher)
}
