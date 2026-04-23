mod access;
mod crypto;
mod dbus;
mod error;
mod storage;
mod unlock;

use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

const SYSTEMD_LISTEN_FDS_START: RawFd = 3;

fn state_dir() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/state")
        });
    base.join("keyring-rs")
}

fn first_systemd_activation_fd(
    current_pid: u32,
    listen_pid_env: Option<&str>,
    listen_fds_env: Option<&str>,
) -> Option<RawFd> {
    let listen_pid = listen_pid_env?.parse::<u32>().ok()?;
    if listen_pid != current_pid {
        return None;
    }

    let listen_fds = listen_fds_env?.parse::<i32>().ok()?;
    if listen_fds < 1 {
        return None;
    }

    Some(SYSTEMD_LISTEN_FDS_START)
}

fn activation_listener_from_env() -> std::io::Result<Option<UnixListener>> {
    let activation_fd = first_systemd_activation_fd(
        std::process::id(),
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
    );
    let Some(fd) = activation_fd else {
        return Ok(None);
    };

    // SAFETY: systemd passes valid inherited file descriptors starting at fd 3.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;
    Ok(Some(listener))
}

fn start_socket_activation_listener() -> std::io::Result<Option<JoinHandle<()>>> {
    let Some(listener) = activation_listener_from_env()? else {
        return Ok(None);
    };

    let handle = tokio::spawn(run_socket_activation_listener(listener));
    Ok(Some(handle))
}

async fn run_socket_activation_listener(listener: UnixListener) {
    log_activation_socket(&listener);

    loop {
        if let Err(error) = accept_activation_connection(&listener).await {
            tracing::error!("Systemd activation socket accept error: {}", error);
            break;
        }
    }
}

fn log_activation_socket(listener: &UnixListener) {
    let Ok(addr) = listener.local_addr() else {
        return;
    };
    let path = addr
        .as_pathname()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unnamed>".to_string());
    tracing::info!("Systemd socket activation listening on {}", path);
}

async fn accept_activation_connection(listener: &UnixListener) -> std::io::Result<()> {
    let (stream, _) = listener.accept().await?;
    drop(stream);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting keyring-daemon");

    let socket_activation_handle = start_socket_activation_listener()?;

    // Ensure state directory exists
    let data_path = state_dir();
    std::fs::create_dir_all(&data_path)?;

    // Initialize storage
    let db_path = data_path.join("secrets.db");
    tracing::info!("Using database: {}", db_path.display());

    let storage = storage::Storage::open(&db_path)?;

    // Create default collection if it doesn't exist
    if storage.get_collection("default")?.is_none() {
        tracing::info!("Creating default collection");
        storage.create_collection("default", "Default Keyring")?;
    }

    let storage = Arc::new(RwLock::new(storage));

    // Initialize access control (prompt enabled by default)
    let access = Arc::new(access::AccessControl::new(true));

    // Start unlock server (for greetd integration)
    let unlock_storage = storage.clone();
    let unlock_handle = tokio::spawn(async move {
        let server = unlock::UnlockServer::new(unlock_storage);
        if let Err(e) = server.run().await {
            tracing::error!("Unlock server error: {}", e);
        }
    });

    // Start D-Bus service
    let connection = dbus::start_service(storage.clone(), access.clone()).await?;

    tracing::info!("Daemon ready, waiting for requests...");

    // Wait for SIGINT/SIGTERM
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    unlock_handle.abort();
    if let Some(handle) = socket_activation_handle {
        handle.abort();
    }
    drop(connection);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_activation_fd_when_pid_matches_and_fds_present() {
        assert_eq!(
            first_systemd_activation_fd(4242, Some("4242"), Some("1")),
            Some(SYSTEMD_LISTEN_FDS_START)
        );
    }

    #[test]
    fn systemd_activation_fd_none_when_pid_differs() {
        assert_eq!(
            first_systemd_activation_fd(4242, Some("9999"), Some("1")),
            None
        );
    }

    #[test]
    fn systemd_activation_fd_none_when_no_fds() {
        assert_eq!(
            first_systemd_activation_fd(4242, Some("4242"), Some("0")),
            None
        );
    }

    #[test]
    fn systemd_activation_fd_none_on_invalid_env() {
        assert_eq!(
            first_systemd_activation_fd(4242, Some("oops"), Some("1")),
            None
        );
        assert_eq!(
            first_systemd_activation_fd(4242, Some("4242"), Some("oops")),
            None
        );
    }
}
