// D-Bus Secret Service implementation
// https://specifications.freedesktop.org/secret-service/latest/

use aes::Aes128;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
#[cfg(not(coverage))]
use authd_protocol::{
    AuthRequest, AuthResponse, SOCKET_PATH as AUTHD_SOCKET_PATH, collect_wayland_env,
};
use cbc::{Decryptor as Aes128CbcDec, Encryptor as Aes128CbcEnc};
use hkdf::Hkdf;
use num_bigint::BigUint;
#[cfg(not(coverage))]
use peercred_ipc::Client as IpcClient;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::collections::HashMap;
#[cfg(not(coverage))]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, interface};

use crate::access::AccessControl;
use crate::storage::Storage;

// Secret struct as per D-Bus spec: (session, parameters, value, content_type)
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
type SessionMap = HashMap<String, SessionState>;
const ROOT_PROMPT_PATH: &str = "/";
const PROMPT_PATH_PREFIX: &str = "/org/freedesktop/secrets/prompt";
const SESSION_PATH_PREFIX: &str = "/org/freedesktop/secrets/session";
const ALGORITHM_PLAIN: &str = "plain";
const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
const DH_AES_KEY_SIZE: usize = 16;
const DH_IV_SIZE: usize = 16;
const DH_SHARED_SECRET_SIZE: usize = 128;
const DH_GENERATOR: u8 = 2;
const DH_GROUP_PRIME_BYTES: [u8; DH_SHARED_SECRET_SIZE] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

#[derive(Clone)]
enum SessionEncryption {
    Plain,
    Dh { key: [u8; DH_AES_KEY_SIZE] },
}

#[derive(Clone)]
struct SessionState {
    encryption: SessionEncryption,
}

pub struct SecretService {
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
    access: Arc<AccessControl>,
    connection: Connection,
}

impl SecretService {
    fn new(
        storage: Arc<RwLock<Storage>>,
        sessions: Arc<RwLock<SessionMap>>,
        access: Arc<AccessControl>,
        connection: Connection,
    ) -> Self {
        Self {
            storage,
            sessions,
            access,
            connection,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    /// Open a session for secret transport
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let (encryption, output) = negotiate_session_open(algorithm, input)?;

        register_session_object(&self.connection, self.sessions.clone(), encryption, output).await
    }

    /// Search for items matching attributes
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let item_ids: Vec<u64> = storage
            .search_items(&attributes)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let paths: Vec<OwnedObjectPath> = item_ids
            .iter()
            .map(|id| {
                OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/default/{}",
                    id
                ))
                .unwrap()
            })
            .collect();

        if storage.is_locked() {
            Ok((vec![], paths))
        } else {
            Ok((paths, vec![]))
        }
    }

    /// Get secrets for multiple items
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, Secret>> {
        // Check caller access
        if let Some(sender) = header.sender() {
            check_sender_access(&self.connection, &self.access, sender.as_str()).await?;
        }

        let session_encryption =
            resolve_session_encryption(&self.sessions, session.as_str()).await?;
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let mut result: HashMap<OwnedObjectPath, Secret> = HashMap::new();

        for item_path in items {
            let Some(item_id) = item_id_from_object_path(&item_path) else {
                continue;
            };

            if let Some(secret) =
                secret_for_item_id(&storage, item_id, &session, &session_encryption)?
            {
                result.insert(item_path, secret);
            }
        }

        Ok(result)
    }

    /// Unlock collections or items
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        if !storage.is_locked() {
            return Ok((
                objects,
                OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap(),
            ));
        }
        drop(storage);

        let prompt_path =
            register_unlock_prompt(&self.connection, self.storage.clone(), objects.clone())
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok((vec![], prompt_path))
    }

    /// Lock collections or items
    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        storage.lock();

        let prompt_path = OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap();
        Ok((objects, prompt_path))
    }

    /// Read an alias (e.g., "default" collection)
    async fn read_alias(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let stored_alias = storage
            .get_alias(name)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        if let Some(collection_name) = stored_alias {
            return collection_object_path(&collection_name);
        }

        if name == "default" {
            if storage
                .get_collection("default")
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
                .is_some()
            {
                collection_object_path("default")
            } else {
                Ok(OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap())
            }
        } else {
            Ok(OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap())
        }
    }

    /// Set an alias
    async fn set_alias(&self, name: &str, collection: OwnedObjectPath) -> zbus::fdo::Result<()> {
        let collection_name = collection_name_from_path(collection.as_str())
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid collection path".to_string()))?;

        let storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        if let Some(collection_name) = collection_name.as_deref() {
            if storage
                .get_collection(collection_name)
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
                .is_none()
            {
                return Err(zbus::fdo::Error::Failed(format!(
                    "Collection not found: {}",
                    collection_name
                )));
            }
        }

        storage
            .set_alias(name, collection_name.as_deref())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    /// Collections property
    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        let collections = load_collections(&self.storage).await;
        collection_paths(&collections)
    }
}

// Collection interface
pub struct SecretCollection {
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
    name: String,
    connection: Connection,
}

impl SecretCollection {
    fn new(
        storage: Arc<RwLock<Storage>>,
        sessions: Arc<RwLock<SessionMap>>,
        name: String,
        connection: Connection,
    ) -> Self {
        Self {
            storage,
            sessions,
            name,
            connection,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl SecretCollection {
    /// Search for items in this collection
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let item_ids: Vec<u64> = storage
            .search_items(&attributes)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(item_ids
            .iter()
            .map(|id| {
                OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}/{}",
                    self.name, id
                ))
                .unwrap()
            })
            .collect())
    }

    /// Create a new item in this collection
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let decoded_secret = decode_secret_for_storage(&self.sessions, &secret).await?;
        let (label, attributes) = extract_item_properties(&properties);
        let id = create_or_replace_collection_item(
            &self.storage,
            &self.name,
            &label,
            attributes,
            replace,
            &decoded_secret,
        )
        .await?;
        let item_path = register_collection_item_path(self, id).await?;

        // No prompt needed and best-effort signal.
        Self::item_created(&ctxt, item_path.clone()).await.ok();
        Ok((item_path, root_prompt_path()))
    }

    /// Delete this collection
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        let deleted_item_ids = {
            let storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
            storage
                .delete_collection(&self.name)
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
                .ok_or_else(|| {
                    zbus::fdo::Error::Failed(format!("Collection not found: {}", self.name))
                })?
        };

        for item_id in deleted_item_ids {
            if let Err(error) = unregister_item_object(&self.connection, &self.name, item_id).await
            {
                tracing::warn!(
                    "Failed to unregister deleted item object {} in {}: {}",
                    item_id,
                    self.name,
                    error
                );
            }
        }

        if let Err(error) = unregister_collection_object(&self.connection, &self.name).await {
            tracing::warn!(
                "Failed to unregister deleted collection object {}: {}",
                self.name,
                error
            );
        }

        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    #[zbus(signal)]
    async fn item_created(ctxt: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(ctxt: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(ctxt: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    /// Items property - list all items in collection
    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        // Search with empty attributes returns all items
        let empty: HashMap<String, String> = HashMap::new();
        let item_ids: Vec<u64> = storage.search_items(&empty).unwrap_or_default();

        item_ids
            .iter()
            .map(|id| {
                OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}/{}",
                    self.name, id
                ))
                .unwrap()
            })
            .collect()
    }

    /// Label property
    #[zbus(property)]
    async fn label(&self) -> String {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_collection(&self.name)
            .ok()
            .flatten()
            .map(|c| c.label)
            .unwrap_or_default()
    }

    /// Locked property
    #[zbus(property)]
    async fn locked(&self) -> bool {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage.is_locked()
    }

    /// Created property (unix timestamp)
    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.collection_timestamps().await.0
    }

    /// Modified property (unix timestamp)
    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.collection_timestamps().await.1
    }
}

impl SecretCollection {
    async fn collection_timestamps(&self) -> (u64, u64) {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let Some(collection) = storage.get_collection(&self.name).ok().flatten() else {
            return (0, 0);
        };
        (collection.created, collection.modified)
    }
}

// Item interface
pub struct SecretItem {
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
    collection: String,
    id: u64,
}

impl SecretItem {
    fn new(
        storage: Arc<RwLock<Storage>>,
        sessions: Arc<RwLock<SessionMap>>,
        collection: String,
        id: u64,
    ) -> Self {
        Self {
            storage,
            sessions,
            collection,
            id,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl SecretItem {
    /// Get the secret
    async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        let session_encryption =
            resolve_session_encryption(&self.sessions, session.as_str()).await?;
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;

        let item = storage
            .get_item(self.id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
            .ok_or_else(|| zbus::fdo::Error::Failed("Item not found".into()))?;

        encode_secret_for_transport(session, &session_encryption, &item.secret, "text/plain")
    }

    /// Set the secret
    async fn set_secret(&self, secret: Secret) -> zbus::fdo::Result<()> {
        let decoded_secret = decode_secret_for_storage(&self.sessions, &secret).await?;
        let storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        replace_item_secret(
            &storage,
            self.id,
            &self.collection,
            decoded_secret.as_slice(),
        )
    }

    /// Delete this item
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        let storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        storage
            .delete_item(self.id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    /// Locked property
    #[zbus(property)]
    async fn locked(&self) -> bool {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage.is_locked()
    }

    /// Attributes property
    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        map_item_or_default(
            &self.storage,
            self.id,
            |item| item.attributes,
            HashMap::new(),
        )
        .await
    }

    /// Label property
    #[zbus(property)]
    async fn label(&self) -> String {
        map_item_or_default(&self.storage, self.id, |item| item.label, String::new()).await
    }

    /// Created property
    #[zbus(property)]
    async fn created(&self) -> u64 {
        map_item_or_default(&self.storage, self.id, |item| item.created, 0).await
    }

    /// Modified property
    #[zbus(property)]
    async fn modified(&self) -> u64 {
        map_item_or_default(&self.storage, self.id, |item| item.modified, 0).await
    }
}

pub struct SecretPrompt {
    storage: Arc<RwLock<Storage>>,
    connection: Connection,
    path: OwnedObjectPath,
    objects: Vec<OwnedObjectPath>,
    completed: AtomicBool,
}

impl SecretPrompt {
    fn new(
        storage: Arc<RwLock<Storage>>,
        connection: Connection,
        path: OwnedObjectPath,
        objects: Vec<OwnedObjectPath>,
    ) -> Self {
        Self {
            storage,
            connection,
            path,
            objects,
            completed: AtomicBool::new(false),
        }
    }

    fn take_completion_slot(&self) -> bool {
        self.completed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    async fn finish_prompt(
        &self,
        ctxt: &SignalEmitter<'_>,
        dismissed: bool,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<()> {
        let result: OwnedValue = OwnedValue::try_from(Value::new(objects))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Self::completed(ctxt, dismissed, result)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let _ = self
            .connection
            .object_server()
            .remove::<SecretPrompt, _>(self.path.as_str())
            .await;
        Ok(())
    }

    async fn completion_from_unlock(&self, window_id: &str) -> (bool, Vec<OwnedObjectPath>) {
        let Some(password) = request_prompt_password(window_id) else {
            return (true, vec![]);
        };

        let mut storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        match storage.unlock(&password) {
            Ok(()) => (false, self.objects.clone()),
            Err(error) => {
                tracing::warn!("Prompt unlock failed: {}", error);
                (false, vec![])
            }
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl SecretPrompt {
    async fn prompt(
        &self,
        window_id: &str,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        if !self.take_completion_slot() {
            return Ok(());
        }

        let (dismissed, objects) = self.completion_from_unlock(window_id).await;
        self.finish_prompt(&ctxt, dismissed, objects).await
    }

    async fn dismiss(
        &self,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        if !self.take_completion_slot() {
            return Ok(());
        }
        self.finish_prompt(&ctxt, true, vec![]).await
    }

    #[zbus(signal)]
    async fn completed(
        ctxt: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

pub struct SecretSession {
    sessions: Arc<RwLock<SessionMap>>,
    connection: Connection,
    path: OwnedObjectPath,
}

impl SecretSession {
    fn new(
        sessions: Arc<RwLock<SessionMap>>,
        connection: Connection,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            sessions,
            connection,
            path,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SecretSession {
    async fn close(&self) -> zbus::fdo::Result<()> {
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(self.path.as_str());
        }

        let _ = self
            .connection
            .object_server()
            .remove::<SecretSession, _>(self.path.as_str())
            .await;
        Ok(())
    }
}

#[path = "dbus_helpers.rs"]
mod helpers;
pub use helpers::start_service;
use helpers::*;

#[cfg(test)]
#[path = "dbus_tests.rs"]
mod tests;
