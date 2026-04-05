use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;
use anyhow::Result;
use notify::{Watcher, RecursiveMode, recommended_watcher, EventKind};

use openfused_core::crypto;

pub fn watch_store(store_root: &Path) -> Result<()> {
    let inbox_dir = store_root.join("inbox");
    let context_path = store_root.join("CONTEXT.md");

    let (tx, rx) = channel();

    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;

    watcher.watch(&inbox_dir, RecursiveMode::NonRecursive)?;
    watcher.watch(&context_path, RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(event)) => {
                let paths = event.paths;
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in &paths {
                            let fname = path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("");

                            if path.parent().map(|p| p.ends_with("inbox")).unwrap_or(false) {
                                if fname.ends_with(".json") || fname.ends_with(".md") {
                                    if let Ok(raw) = std::fs::read_to_string(path) {
                                        if let Ok(signed) = serde_json::from_str::<crypto::SignedMessage>(&raw) {
                                            let verified = crypto::verify_message(&signed);
                                            let trust = crypto::MessageTrust { verified, ..Default::default() };
                                            let wrapped = crypto::wrap_external_message(&signed, &trust);
                                            println!("\n[inbox] New message from {}:", signed.from);
                                            println!("{}", wrapped);
                                        } else {
                                            println!("\n[inbox] New message: {}", fname);
                                            println!("{}", raw);
                                        }
                                    }
                                }
                            } else if fname == "CONTEXT.md" {
                                println!("\n[context] CONTEXT.md updated");
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Err(e)) => eprintln!("[watch] error: {:?}", e),
            Err(_) => {}
        }
    }
}
