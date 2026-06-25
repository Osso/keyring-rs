// Unlock socket for greetd integration
//
// Receives unlock requests from greetd at login time.
// Only accepts connections from root (UID 0).

use keyring_protocol::{UNLOCK_SOCKET_PATH, UnlockRequest, UnlockResponse};
use peercred_ipc::{CallerInfo, Connection, Server};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::Result;
use crate::storage::Storage;

/// Unlock server that listens for requests from greetd
pub struct UnlockServer {
    storage: Arc<RwLock<Storage>>,
    socket_path: PathBuf,
}

impl UnlockServer {
    pub fn new(storage: Arc<RwLock<Storage>>) -> Self {
        Self {
            storage,
            socket_path: PathBuf::from(UNLOCK_SOCKET_PATH),
        }
    }

    #[cfg(test)]
    fn new_with_socket_path(storage: Arc<RwLock<Storage>>, socket_path: PathBuf) -> Self {
        Self {
            storage,
            socket_path,
        }
    }

    /// Start the unlock server
    ///
    /// Creates socket at /run/keyring-rs/unlock.sock with mode 0o600 (root only)
    pub async fn run(&self) -> Result<()> {
        self.ensure_socket_parent()?;
        let server = self.bind_server()?;

        tracing::info!("Unlock socket listening on {}", self.socket_path.display());

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
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn bind_server(&self) -> Result<Server> {
        Server::bind_with_mode(&self.socket_path, 0o600)
            .map_err(|e| crate::error::KeyringError::Io(e.to_string()))
    }

    async fn handle_connection(&self, mut conn: Connection, caller: CallerInfo) -> Result<()> {
        let request = self.read_request(&mut conn, &caller).await?;

        if !self.authorize_caller(&mut conn, &caller).await? {
            return Ok(());
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use peercred_ipc::Client;
    use tempfile::tempdir;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, sleep};

    fn temp_storage() -> Storage {
        let dir = tempdir().unwrap();
        Storage::open(dir.path().join("test.db")).unwrap()
    }

    #[tokio::test]
    async fn unlock_response_returns_wrong_password_for_invalid_secret() {
        let mut storage = temp_storage();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.lock();
        let server = UnlockServer::new(Arc::new(RwLock::new(storage)));

        let response = server.unlock_response("wrong-password").await;
        assert_eq!(response, UnlockResponse::WrongPassword);
    }

    #[tokio::test]
    async fn unlock_response_returns_already_unlocked_when_storage_open() {
        let mut storage = temp_storage();
        storage.unlock("test-password").unwrap();
        let server = UnlockServer::new(Arc::new(RwLock::new(storage)));

        let response = server.unlock_response("test-password").await;
        assert_eq!(response, UnlockResponse::AlreadyUnlocked);
    }

    #[tokio::test]
    async fn unlock_response_returns_success_for_valid_password() {
        let mut storage = temp_storage();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.lock();
        let storage = Arc::new(RwLock::new(storage));
        let server = UnlockServer::new(storage.clone());

        let response = server.unlock_response("test-password").await;
        assert_eq!(response, UnlockResponse::Success);
        assert!(!storage.read().await.is_locked());
    }

    #[tokio::test]
    async fn non_root_caller_is_rejected_over_unlock_socket() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("unlock.sock");
        let storage = Arc::new(RwLock::new(temp_storage()));
        let server = UnlockServer::new_with_socket_path(storage, socket_path.clone());
        let server_task = tokio::spawn(async move { server.run().await });

        let response = call_unlock_with_retry(
            socket_path.clone(),
            UnlockRequest {
                user: "alice".to_string(),
                password: "irrelevant".to_string(),
            },
        )
        .await;

        assert_eq!(
            response,
            UnlockResponse::Error {
                message: "only root can unlock".to_string()
            }
        );

        stop_server(server_task).await;
    }

    #[tokio::test]
    #[should_panic(expected = "unlock call did not succeed before timeout")]
    async fn call_unlock_with_retry_times_out_when_socket_never_appears() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("missing.sock");

        call_unlock_with_retry(
            socket_path,
            UnlockRequest {
                user: "alice".to_string(),
                password: "irrelevant".to_string(),
            },
        )
        .await;
    }

    async fn call_unlock_with_retry(
        socket_path: PathBuf,
        request: UnlockRequest,
    ) -> UnlockResponse {
        const MAX_ATTEMPTS: usize = 40;
        const RETRY_DELAY: Duration = Duration::from_millis(25);

        for _ in 0..MAX_ATTEMPTS {
            let path = socket_path.clone();
            let req = request.clone();
            let result = tokio::task::spawn_blocking(move || Client::call(path, &req))
                .await
                .unwrap();

            match result {
                Ok(response) => return response,
                Err(error) => {
                    let message = error.to_string();
                    if message.contains("No such file") || message.contains("Connection refused") {
                        sleep(RETRY_DELAY).await;
                        continue;
                    }
                    panic!("unlock call failed unexpectedly: {}", message);
                }
            }
        }

        panic!("unlock call did not succeed before timeout");
    }

    async fn stop_server(handle: JoinHandle<Result<()>>) {
        handle.abort();
        let _ = handle.await;
    }
}
