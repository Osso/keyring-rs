use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};

use crate::error::{KeyringError, Result};

const NONCE_SIZE: usize = 12;

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
        Self { cipher }
    }

    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let key = derive_key(password, salt)?;
        Ok(Self::new(&key))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE])> {
        let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KeyringError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyringError::Decryption(e.to_string()))
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| KeyringError::Encryption(format!("Key derivation failed: {}", e)))?;

    Ok(key)
}

pub fn generate_salt() -> [u8; 16] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let salt = generate_salt();
        let crypto = Crypto::from_password("test-password", &salt).unwrap();

        let plaintext = b"secret data";
        let (ciphertext, nonce) = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn wrong_password_fails() {
        let salt = generate_salt();
        let crypto1 = Crypto::from_password("password1", &salt).unwrap();
        let crypto2 = Crypto::from_password("password2", &salt).unwrap();

        let (ciphertext, nonce) = crypto1.encrypt(b"secret").unwrap();
        let result = crypto2.decrypt(&ciphertext, &nonce);

        assert!(result.is_err());
    }
}
