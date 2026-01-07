// Unlock socket for greetd integration
//
// Receives unlock requests from greetd at login time.
// Only accepts connections from root (UID 0).

use keyring_protocol::{UnlockRequest, UnlockResponse, UNLOCK_SOCKET_PATH};
use peercred_ipc::{CallerInfo, Connection, Server};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::Result;
use crate::storage::Storage;

/// Unlock server that listens for requests from greetd
pub struct UnlockServer {
    storage: Arc<RwLock<Storage>>,
}

impl UnlockServer {
    pub fn new(storage: Arc<RwLock<Storage>>) -> Self {
        Self { storage }
    }

    /// Start the unlock server
    ///
    /// Creates socket at /run/keyring-rs/unlock.sock with mode 0o600 (root only)
    pub async fn run(&self) -> Result<()> {
        // Ensure parent directory exists
        let socket_path = Path::new(UNLOCK_SOCKET_PATH);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bind with restrictive permissions (root only)
        let server = Server::bind_with_mode(UNLOCK_SOCKET_PATH, 0o600)
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))?;

        tracing::info!("Unlock socket listening on {}", UNLOCK_SOCKET_PATH);

        loop {
            match server.accept().await {
                Ok((conn, caller)) => {
                    if let Err(e) = self.handle_connection(conn, caller).await {
                        tracing::warn!("Unlock connection error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        mut conn: Connection,
        caller: CallerInfo,
    ) -> Result<()> {
        // Only accept connections from root
        if caller.uid != 0 {
            tracing::warn!(
                "Rejecting unlock request from non-root user: uid={} pid={} exe={}",
                caller.uid,
                caller.pid,
                caller.exe.display()
            );
            conn.write(&UnlockResponse::Error {
                message: "only root can unlock".into(),
            })
            .await
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))?;
            return Ok(());
        }

        tracing::info!(
            "Unlock request from pid={} exe={}",
            caller.pid,
            caller.exe.display()
        );

        // Read the unlock request
        let request: UnlockRequest = conn
            .read()
            .await
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))?;

        tracing::info!("Unlock request for user: {}", request.user);

        // Try to unlock
        let response = {
            let mut storage = self.storage.write().await;

            if !storage.is_locked() {
                UnlockResponse::AlreadyUnlocked
            } else {
                match storage.unlock(&request.password) {
                    Ok(()) => {
                        tracing::info!("Keyring unlocked successfully");
                        UnlockResponse::Success
                    }
                    Err(e) => {
                        tracing::warn!("Unlock failed: {}", e);
                        // TODO: distinguish wrong password from other errors
                        UnlockResponse::WrongPassword
                    }
                }
            }
        };

        conn.write(&response)
            .await
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))?;

        Ok(())
    }
}

// Tests for protocol types are in keyring-protocol crate
