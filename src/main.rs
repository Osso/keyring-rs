mod access;
mod crypto;
mod dbus;
mod error;
mod storage;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

fn state_dir() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/state")
        });
    base.join("keyring-rs")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting keyring-daemon");

    // Ensure state directory exists
    let data_path = state_dir();
    std::fs::create_dir_all(&data_path)?;

    // Initialize storage
    let db_path = data_path.join("secrets.db");
    tracing::info!("Using database: {}", db_path.display());

    let mut storage = storage::Storage::open(&db_path)?;

    // Create default collection if it doesn't exist
    if storage.get_collection("default")?.is_none() {
        tracing::info!("Creating default collection");
        storage.create_collection("default", "Default Keyring")?;
    }

    // For now, auto-unlock with empty password (TODO: proper unlock flow)
    // In production, this should prompt for password
    storage.unlock("")?;

    let storage = Arc::new(RwLock::new(storage));

    // Initialize access control (prompt enabled by default)
    let access = Arc::new(access::AccessControl::new(true));

    // Start D-Bus service
    let connection = dbus::start_service(storage.clone(), access.clone()).await?;

    tracing::info!("Daemon ready, waiting for requests...");

    // Wait for SIGINT/SIGTERM
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    drop(connection);
    Ok(())
}
