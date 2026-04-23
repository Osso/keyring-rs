// Per-application access control
//
// Tracks which processes have been granted access to the keyring.
// Access is remembered for the lifetime of the process (by PID).
// Uses authd for confirmation dialogs.

use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH};
use peercred_ipc::Client;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
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
    /// Prompt backend (authd in production; injected hook in tests)
    prompt_authd_callback: Arc<PromptAuthdCallback>,
}

impl AccessControl {
    pub fn new(prompt_enabled: bool) -> Self {
        Self {
            authorized: RwLock::new(HashMap::new()),
            prompt_enabled,
            prompt_authd_callback: Arc::new(prompt_authd_sync),
        }
    }

    #[cfg(test)]
    fn new_with_prompt(
        prompt_enabled: bool,
        prompt_authd_callback: impl Fn(&Path, &str) -> Result<bool, AccessError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            authorized: RwLock::new(HashMap::new()),
            prompt_enabled,
            prompt_authd_callback: Arc::new(prompt_authd_callback),
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
        let prompt_authd_callback = self.prompt_authd_callback.clone();

        // Use std thread since peercred-ipc Client is sync
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = prompt_authd_callback(exe.as_path(), &display_name);
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
fn prompt_authd_sync(caller_exe: &Path, display_name: &str) -> Result<bool, AccessError> {
    // Build AuthRequest with confirm_only=true
    let request = AuthRequest {
        target: caller_exe.to_path_buf(),
        args: vec![format!("access keyring ({})", display_name)],
        env: HashMap::new(),
        password: String::new(),
        confirm_only: true,
    };

    // Use peercred-ipc Client for proper protocol handling
    let response: AuthResponse = Client::call(SOCKET_PATH, &request)
        .map_err(|e| AccessError::DialogFailed(format!("authd call failed: {}", e)))?;

    interpret_auth_response(response)
}

fn interpret_auth_response(response: AuthResponse) -> Result<bool, AccessError> {
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

type PromptAuthdCallback = dyn Fn(&Path, &str) -> Result<bool, AccessError> + Send + Sync;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn check_access_uses_cached_live_authorization_without_prompt() {
        let access = AccessControl::new_with_prompt(true, |_, _| {
            panic!("prompt should not be called for live cache")
        });
        let current_pid = std::process::id();
        let current_exe = std::env::current_exe().unwrap();
        access.authorized.write().await.insert(
            current_pid,
            ProcessInfo {
                pid: current_pid,
                exe: current_exe,
            },
        );

        let result = access.check_access(current_pid).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn check_access_reprompts_when_cached_pid_is_dead() {
        let prompt_calls = Arc::new(AtomicUsize::new(0));
        let prompt_calls_clone = prompt_calls.clone();
        let access = AccessControl::new_with_prompt(true, move |_, _| {
            prompt_calls_clone.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        });
        let current_pid = std::process::id();
        let current_exe = std::env::current_exe().unwrap();
        access.authorized.write().await.insert(
            current_pid,
            ProcessInfo {
                pid: 0,
                exe: current_exe,
            },
        );

        let result = access.check_access(current_pid).await.unwrap();

        assert!(result);
        assert_eq!(prompt_calls.load(Ordering::SeqCst), 1);
        let authorized = access.authorized.read().await;
        assert_eq!(authorized.get(&current_pid).unwrap().pid, current_pid);
    }

    #[tokio::test]
    async fn prompt_via_authd_returns_hook_result_and_uses_display_name() {
        let observed_display = Arc::new(std::sync::Mutex::new(String::new()));
        let observed_display_clone = observed_display.clone();
        let access = AccessControl::new_with_prompt(true, move |_, display_name| {
            *observed_display_clone.lock().unwrap() = display_name.to_string();
            Ok(false)
        });

        let info = ProcessInfo {
            pid: 42,
            exe: PathBuf::from("/tmp/sample-app"),
        };
        let result = access.prompt_via_authd(&info).await.unwrap();

        assert!(!result);
        assert_eq!(*observed_display.lock().unwrap(), "sample-app".to_string());
    }

    #[test]
    fn interpret_auth_response_denied_returns_false() {
        let result = interpret_auth_response(AuthResponse::Denied {
            reason: "policy denied".to_string(),
        })
        .unwrap();
        assert!(!result);
    }

    #[test]
    fn interpret_auth_response_unknown_target_allows_access() {
        let result = interpret_auth_response(AuthResponse::UnknownTarget).unwrap();
        assert!(result);
    }

    #[test]
    fn interpret_auth_response_error_returns_dialog_failed() {
        let error = interpret_auth_response(AuthResponse::Error {
            message: "backend exploded".to_string(),
        })
        .unwrap_err();

        assert!(matches!(
            error,
            AccessError::DialogFailed(message) if message == "backend exploded"
        ));
    }
}
