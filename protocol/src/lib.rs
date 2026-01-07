//! Protocol types for keyring-rs unlock IPC
//!
//! Used by:
//! - keyring-rs daemon (server)
//! - greetd (client) to unlock keyring at login
//!
//! # Example (client)
//!
//! ```ignore
//! use keyring_protocol::{UnlockRequest, UnlockResponse, UNLOCK_SOCKET_PATH};
//! use peercred_ipc::Client;
//!
//! let response: UnlockResponse = Client::call(
//!     UNLOCK_SOCKET_PATH,
//!     &UnlockRequest {
//!         user: "alice".into(),
//!         password: "secret".into(),
//!     },
//! )?;
//!
//! match response {
//!     UnlockResponse::Success => println!("Keyring unlocked"),
//!     UnlockResponse::AlreadyUnlocked => println!("Already unlocked"),
//!     UnlockResponse::WrongPassword => eprintln!("Wrong password"),
//!     UnlockResponse::Error { message } => eprintln!("Error: {}", message),
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Socket path for unlock requests (root-only)
pub const UNLOCK_SOCKET_PATH: &str = "/run/keyring-rs/unlock.sock";

/// Request sent by greetd after successful PAM authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockRequest {
    /// Username being logged in
    pub user: String,
    /// Login password (same as keyring password)
    pub password: String,
}

/// Response to unlock request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnlockResponse {
    /// Keyring was successfully unlocked
    Success,
    /// Password did not match
    WrongPassword,
    /// Keyring was already unlocked
    AlreadyUnlocked,
    /// Other error occurred
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = UnlockRequest {
            user: "alice".into(),
            password: "secret123".into(),
        };
        let bytes = rmp_serde::to_vec(&req).unwrap();
        let decoded: UnlockRequest = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.user, "alice");
        assert_eq!(decoded.password, "secret123");
    }

    #[test]
    fn response_roundtrip() {
        let cases = vec![
            UnlockResponse::Success,
            UnlockResponse::WrongPassword,
            UnlockResponse::AlreadyUnlocked,
            UnlockResponse::Error {
                message: "test error".into(),
            },
        ];

        for resp in cases {
            let bytes = rmp_serde::to_vec(&resp).unwrap();
            let decoded: UnlockResponse = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(decoded, resp);
        }
    }

    #[test]
    fn socket_path_is_correct() {
        assert_eq!(UNLOCK_SOCKET_PATH, "/run/keyring-rs/unlock.sock");
    }
}
