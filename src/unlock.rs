// Unlock socket for greetd integration
//
// Receives unlock requests from greetd at login time.
// Only accepts connections from root (UID 0).

use keyring_protocol::{UNLOCK_SOCKET_PATH, UnlockRequest, UnlockResponse};
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
        self.ensure_socket_parent()?;
        let server = self.bind_server()?;

        tracing::info!("Unlock socket listening on {}", UNLOCK_SOCKET_PATH);

        loop {
            let (conn, caller) = match server.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::error!("Accept error: {}", error);
                    continue;
                }
            };

            if let Err(error) = self.handle_connection(conn, caller).await {
                tracing::warn!("Unlock connection error: {}", error);
            }
        }
    }

    fn ensure_socket_parent(&self) -> Result<()> {
        let socket_path = Path::new(UNLOCK_SOCKET_PATH);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn bind_server(&self) -> Result<Server> {
        Server::bind_with_mode(UNLOCK_SOCKET_PATH, 0o600)
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))
    }

    async fn handle_connection(&self, mut conn: Connection, caller: CallerInfo) -> Result<()> {
        if !self.authorize_caller(&mut conn, &caller).await? {
            return Ok(());
        }

        let request = self.read_request(&mut conn, &caller).await?;
        let response = self.unlock_response(&request.password).await;
        self.write_response(&mut conn, &response).await
    }

    async fn authorize_caller(&self, conn: &mut Connection, caller: &CallerInfo) -> Result<bool> {
        if caller.uid == 0 {
            return Ok(true);
        }

        tracing::warn!(
            "Rejecting unlock request from non-root user: uid={} pid={} exe={}",
            caller.uid,
            caller.pid,
            caller.exe.display()
        );
        let response = UnlockResponse::Error {
            message: "only root can unlock".into(),
        };
        self.write_response(conn, &response).await?;
        Ok(false)
    }

    async fn read_request(
        &self,
        conn: &mut Connection,
        caller: &CallerInfo,
    ) -> Result<UnlockRequest> {
        tracing::info!(
            "Unlock request from pid={} exe={}",
            caller.pid,
            caller.exe.display()
        );
        let request: UnlockRequest = conn
            .read()
            .await
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))?;
        tracing::info!("Unlock request for user: {}", request.user);
        Ok(request)
    }

    async fn unlock_response(&self, password: &str) -> UnlockResponse {
        let mut storage = self.storage.write().await;

        if !storage.is_locked() {
            return UnlockResponse::AlreadyUnlocked;
        }

        match storage.unlock(password) {
            Ok(()) => {
                tracing::info!("Keyring unlocked successfully");
                UnlockResponse::Success
            }
            Err(error) => {
                tracing::warn!("Unlock failed: {}", error);
                UnlockResponse::WrongPassword
            }
        }
    }

    async fn write_response(&self, conn: &mut Connection, response: &UnlockResponse) -> Result<()> {
        conn.write(&response)
            .await
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))
    }
}

// Tests for protocol types are in keyring-protocol crate
