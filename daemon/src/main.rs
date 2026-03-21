mod fuse_fs;
mod server;
mod store;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "openfused", about = "FUSE daemon for decentralized AI agent context mesh")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon: serve local context store over HTTP + mount remote peers via FUSE
    Serve {
        /// Path to the context store
        #[arg(short, long, default_value = ".")]
        store: PathBuf,

        /// Port for the HTTP file server (peers connect to this)
        #[arg(short, long, default_value_t = 9781)]
        port: u16,

        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,

        /// Public mode: only serve PROFILE.md + inbox (for WAN/tunnels)
        #[arg(long)]
        public: bool,
    },

    /// Mount a remote peer's context store locally via FUSE
    Mount {
        /// Remote peer URL (e.g. http://agent-bob:9781)
        url: String,

        /// Local mount point
        mountpoint: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { store, port, bind, public } => {
            let store_path = store.canonicalize().unwrap_or(store);
            tracing::info!("Serving context store: {:?} on {}:{}", store_path, bind, port);
            server::serve(store_path, &bind, port, public).await;
        }
        Commands::Mount { url, mountpoint } => {
            tracing::info!("Mounting {} at {:?}", url, mountpoint);
            fuse_fs::mount_remote(&url, &mountpoint).await;
        }
    }
}
