// Per-application access control
//
// Tracks which processes have been granted access to the keyring.
// Access is remembered for the lifetime of the process (by PID).
// Uses authd for confirmation dialogs.

use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH};
use peercred_ipc::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: PathBuf,
}

impl ProcessInfo {
    pub fn from_pid(pid: u32) -> Option<Self> {
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
        Some(Self { pid, exe })
    }

    pub fn is_alive(&self) -> bool {
        std::fs::metadata(format!("/proc/{}", self.pid)).is_ok()
    }

    pub fn display_name(&self) -> String {
        self.exe
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("PID {}", self.pid))
    }
}

pub struct AccessControl {
    /// PIDs that have been granted access
    authorized: RwLock<HashMap<u32, ProcessInfo>>,
    /// Whether to prompt for access (false = auto-allow all)
    prompt_enabled: bool,
}

impl AccessControl {
    pub fn new(prompt_enabled: bool) -> Self {
        Self {
            authorized: RwLock::new(HashMap::new()),
            prompt_enabled,
        }
    }

    /// Check if a process is authorized, prompting if necessary
    pub async fn check_access(&self, pid: u32) -> Result<bool, AccessError> {
        if !self.prompt_enabled {
            return Ok(true);
        }

        // Check if already authorized
        {
            let authorized = self.authorized.read().await;
            if let Some(info) = authorized.get(&pid) {
                if info.is_alive() {
                    return Ok(true);
                }
            }
        }

        // Get process info
        let info = ProcessInfo::from_pid(pid).ok_or(AccessError::ProcessNotFound(pid))?;

        // Prompt user via authd
        let granted = self.prompt_via_authd(&info).await?;

        if granted {
            let mut authorized = self.authorized.write().await;
            authorized.insert(pid, info);
        }

        Ok(granted)
    }

    /// Prompt the user via authd with confirm_only mode
    async fn prompt_via_authd(&self, info: &ProcessInfo) -> Result<bool, AccessError> {
        let exe = info.exe.clone();
        let display_name = info.display_name();

        // Use std thread since peercred-ipc Client is sync
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = prompt_authd_sync(&exe, &display_name);
            let _ = tx.send(result);
        });

        rx.recv()
            .map_err(|e| AccessError::DialogFailed(format!("Channel error: {}", e)))?
    }

    /// Remove dead processes from the authorized list
    pub async fn prune_dead(&self) {
        let mut authorized = self.authorized.write().await;
        authorized.retain(|_, info| info.is_alive());
    }
}

/// Synchronous authd prompt (runs in blocking thread)
fn prompt_authd_sync(caller_exe: &PathBuf, display_name: &str) -> Result<bool, AccessError> {
    // Build AuthRequest with confirm_only=true
    let request = AuthRequest {
        target: caller_exe.clone(),
        args: vec![format!("access keyring ({})", display_name)],
        env: HashMap::new(),
        password: String::new(),
        confirm_only: true,
    };

    // Use peercred-ipc Client for proper protocol handling
    let response: AuthResponse = Client::call(SOCKET_PATH, &request)
        .map_err(|e| AccessError::DialogFailed(format!("authd call failed: {}", e)))?;

    match response {
        AuthResponse::Success { .. } => Ok(true),
        AuthResponse::Denied { reason } => {
            tracing::info!("Access denied: {}", reason);
            Ok(false)
        }
        AuthResponse::AuthFailed => Ok(false),
        AuthResponse::UnknownTarget => {
            // No policy - need to configure authd to allow keyring access
            tracing::warn!("No authd policy for keyring access - allowing by default");
            Ok(true)
        }
        AuthResponse::Error { message } => Err(AccessError::DialogFailed(message)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("Process not found: {0}")]
    ProcessNotFound(u32),
    #[error("Dialog failed: {0}")]
    DialogFailed(String),
}
