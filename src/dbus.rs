// D-Bus Secret Service implementation
// https://specifications.freedesktop.org/secret-service/latest/

use aes::Aes128;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use authd_protocol::{
    AuthRequest, AuthResponse, SOCKET_PATH as AUTHD_SOCKET_PATH, collect_wayland_env,
};
use cbc::{Decryptor as Aes128CbcDec, Encryptor as Aes128CbcEnc};
use hkdf::Hkdf;
use num_bigint::BigUint;
use peercred_ipc::Client as IpcClient;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::collections::HashMap;
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

        // Get existing item to preserve attributes
        let existing = storage
            .get_item(self.id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
            .ok_or_else(|| zbus::fdo::Error::Failed("Item not found".into()))?;

        // Delete and recreate with new secret
        storage
            .delete_item(self.id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        storage
            .create_item(
                &self.collection,
                &existing.label,
                &decoded_secret,
                existing.attributes,
            )
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(())
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

pub async fn start_service(
    storage: Arc<RwLock<Storage>>,
    access: Arc<AccessControl>,
) -> zbus::Result<Connection> {
    let connection = Connection::session().await?;
    let sessions = Arc::new(RwLock::new(HashMap::new()));

    // Register main service
    let service = SecretService::new(
        storage.clone(),
        sessions.clone(),
        access.clone(),
        connection.clone(),
    );
    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    register_default_collection_objects(&connection, storage.clone(), sessions.clone()).await?;

    register_existing_item_objects(&connection, storage, sessions).await?;

    connection.request_name("org.freedesktop.secrets").await?;

    tracing::info!("D-Bus service started on org.freedesktop.secrets");

    Ok(connection)
}

fn item_object_path(collection: &str, id: u64) -> zbus::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{}/{}",
        collection, id
    ))
    .map_err(|e| zbus::Error::Failure(e.to_string()))
}

fn collection_object_path(collection: &str) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{}",
        collection
    ))
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
}

fn collection_name_from_path(path: &str) -> Option<Option<String>> {
    if path == ROOT_PROMPT_PATH {
        return Some(None);
    }

    let collection_name = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    if collection_name.is_empty() || collection_name.contains('/') {
        return None;
    }

    Some(Some(collection_name.to_string()))
}

async fn register_default_collection_objects(
    connection: &Connection,
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
) -> zbus::Result<()> {
    let collection = SecretCollection::new(
        storage.clone(),
        sessions.clone(),
        "default".to_string(),
        connection.clone(),
    );
    connection
        .object_server()
        .at("/org/freedesktop/secrets/collection/default", collection)
        .await?;

    let alias_collection =
        SecretCollection::new(storage, sessions, "default".to_string(), connection.clone());
    connection
        .object_server()
        .at("/org/freedesktop/secrets/aliases/default", alias_collection)
        .await?;
    Ok(())
}

fn extract_item_properties(
    properties: &HashMap<String, OwnedValue>,
) -> (String, HashMap<String, String>) {
    let label = properties
        .get("org.freedesktop.Secret.Item.Label")
        .and_then(|v| TryInto::<String>::try_into(v.clone()).ok())
        .unwrap_or_else(|| "Unnamed".to_string());
    let attributes = properties
        .get("org.freedesktop.Secret.Item.Attributes")
        .and_then(|v| TryInto::<HashMap<String, String>>::try_into(v.clone()).ok())
        .unwrap_or_default();
    (label, attributes)
}

async fn create_or_replace_collection_item(
    storage: &Arc<RwLock<Storage>>,
    collection_name: &str,
    label: &str,
    attributes: HashMap<String, String>,
    replace: bool,
    decoded_secret: &[u8],
) -> zbus::fdo::Result<u64> {
    let storage: RwLockWriteGuard<'_, Storage> = storage.write().await;
    if replace && !attributes.is_empty() {
        delete_matching_items(&storage, &attributes)?;
    }

    storage
        .create_item(collection_name, label, decoded_secret, attributes)
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
}

fn delete_matching_items(
    storage: &Storage,
    attributes: &HashMap<String, String>,
) -> zbus::fdo::Result<()> {
    let existing: Vec<u64> = storage
        .search_items(attributes)
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    for id in existing {
        let _ = storage.delete_item(id);
    }
    Ok(())
}

async fn register_collection_item_path(
    collection: &SecretCollection,
    id: u64,
) -> zbus::fdo::Result<OwnedObjectPath> {
    register_item_object(
        &collection.connection,
        collection.storage.clone(),
        collection.sessions.clone(),
        &collection.name,
        id,
    )
    .await
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
}

fn root_prompt_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap()
}

async fn load_collections(storage: &Arc<RwLock<Storage>>) -> Vec<crate::storage::Collection> {
    let storage: RwLockReadGuard<'_, Storage> = storage.read().await;
    storage.list_collections().unwrap_or_default()
}

fn collection_paths(collections: &[crate::storage::Collection]) -> Vec<OwnedObjectPath> {
    collections
        .iter()
        .filter_map(|collection| collection_object_path(&collection.name).ok())
        .collect()
}

fn item_id_from_object_path(path: &OwnedObjectPath) -> Option<u64> {
    path.as_str().rsplit('/').next()?.parse::<u64>().ok()
}

fn secret_for_item_id(
    storage: &Storage,
    item_id: u64,
    session_path: &OwnedObjectPath,
    session_encryption: &SessionEncryption,
) -> zbus::fdo::Result<Option<Secret>> {
    let item = match storage.get_item(item_id) {
        Ok(Some(item)) => item,
        _ => return Ok(None),
    };

    let secret = encode_secret_for_transport(
        session_path.clone(),
        session_encryption,
        &item.secret,
        "text/plain",
    )?;
    Ok(Some(secret))
}

async fn register_item_object(
    connection: &Connection,
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
    collection: &str,
    id: u64,
) -> zbus::Result<OwnedObjectPath> {
    let path = item_object_path(collection, id)?;
    let item = SecretItem::new(storage, sessions, collection.to_string(), id);
    connection.object_server().at(path.as_str(), item).await?;
    Ok(path)
}

async fn unregister_item_object(
    connection: &Connection,
    collection: &str,
    id: u64,
) -> zbus::Result<()> {
    let path = item_object_path(collection, id)?;
    match connection
        .object_server()
        .remove::<SecretItem, _>(path.as_str())
        .await
    {
        Ok(_) => Ok(()),
        Err(zbus::Error::InterfaceNotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn unregister_collection_object(
    connection: &Connection,
    collection: &str,
) -> zbus::Result<()> {
    let path = collection_object_path(collection).map_err(zbus::Error::from)?;
    match connection
        .object_server()
        .remove::<SecretCollection, _>(path.as_str())
        .await
    {
        Ok(_) => Ok(()),
        Err(zbus::Error::InterfaceNotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn register_existing_item_objects(
    connection: &Connection,
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<SessionMap>>,
) -> zbus::Result<()> {
    let item_locations = {
        let storage_guard: RwLockReadGuard<'_, Storage> = storage.read().await;
        storage_guard
            .list_item_locations()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?
    };

    for (collection, id) in item_locations {
        register_item_object(
            connection,
            storage.clone(),
            sessions.clone(),
            &collection,
            id,
        )
        .await?;
    }

    Ok(())
}

async fn register_unlock_prompt(
    connection: &Connection,
    storage: Arc<RwLock<Storage>>,
    objects: Vec<OwnedObjectPath>,
) -> zbus::Result<OwnedObjectPath> {
    for _ in 0..8 {
        let path = prompt_object_path();
        let prompt = SecretPrompt::new(
            storage.clone(),
            connection.clone(),
            path.clone(),
            objects.clone(),
        );
        match connection.object_server().at(path.as_str(), prompt).await {
            Ok(_) => return Ok(path),
            Err(zbus::Error::InterfaceExists(_, _)) => continue,
            Err(error) => return Err(error),
        }
    }

    Err(zbus::Error::Failure(
        "Unable to allocate unique prompt path".to_string(),
    ))
}

fn prompt_object_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!(
        "{}/prompt{}",
        PROMPT_PATH_PREFIX,
        rand::random::<u64>()
    ))
    .expect("prompt path format is valid")
}

fn session_object_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{}/{}", SESSION_PATH_PREFIX, rand::random::<u64>()))
        .expect("session path format is valid")
}

fn negotiate_session_open(
    algorithm: &str,
    input: Value<'_>,
) -> zbus::fdo::Result<(SessionEncryption, OwnedValue)> {
    match algorithm {
        ALGORITHM_PLAIN => open_plain_session(input),
        ALGORITHM_DH => open_dh_session(input),
        _ => Err(zbus::fdo::Error::NotSupported(format!(
            "Unsupported algorithm: {}",
            algorithm
        ))),
    }
}

fn open_plain_session(input: Value<'_>) -> zbus::fdo::Result<(SessionEncryption, OwnedValue)> {
    validate_plain_session_input(&input)?;
    Ok((
        SessionEncryption::Plain,
        OwnedValue::try_from(Value::new(String::new())).unwrap(),
    ))
}

fn open_dh_session(input: Value<'_>) -> zbus::fdo::Result<(SessionEncryption, OwnedValue)> {
    let (encryption, service_public_key) = negotiate_dh_session_encryption(input)?;
    let output = OwnedValue::try_from(Value::new(service_public_key))
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    Ok((encryption, output))
}

async fn register_session_object(
    connection: &Connection,
    sessions: Arc<RwLock<SessionMap>>,
    encryption: SessionEncryption,
    output: OwnedValue,
) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
    for _ in 0..8 {
        let session_path = session_object_path();
        let session =
            SecretSession::new(sessions.clone(), connection.clone(), session_path.clone());

        match connection
            .object_server()
            .at(session_path.as_str(), session)
            .await
        {
            Ok(_) => {
                let mut sessions = sessions.write().await;
                sessions.insert(
                    session_path.as_str().to_string(),
                    SessionState {
                        encryption: encryption.clone(),
                    },
                );
                return Ok((output, session_path));
            }
            Err(zbus::Error::InterfaceExists(_, _)) => continue,
            Err(e) => return Err(zbus::fdo::Error::Failed(e.to_string())),
        }
    }

    Err(zbus::fdo::Error::Failed(
        "Unable to allocate unique session path".to_string(),
    ))
}

fn validate_plain_session_input(input: &Value<'_>) -> zbus::fdo::Result<()> {
    if let Ok(value) = String::try_from(input.clone()) {
        if value.is_empty() {
            return Ok(());
        }
    }

    if let Ok(value) = Vec::<u8>::try_from(input.clone()) {
        if value.is_empty() {
            return Ok(());
        }
    }

    Err(zbus::fdo::Error::InvalidArgs(
        "plain algorithm expects an empty string or empty byte array input".to_string(),
    ))
}

fn negotiate_dh_session_encryption(
    input: Value<'_>,
) -> zbus::fdo::Result<(SessionEncryption, Vec<u8>)> {
    let client_public_key = parse_dh_public_key(input)?;
    let (private_key, service_public_key) = generate_dh_keypair();
    let key = derive_dh_aes_key(&client_public_key, &private_key)?;
    Ok((SessionEncryption::Dh { key }, service_public_key))
}

fn parse_dh_public_key(input: Value<'_>) -> zbus::fdo::Result<BigUint> {
    let public_key_bytes: Vec<u8> = Vec::<u8>::try_from(input).map_err(|_| {
        zbus::fdo::Error::InvalidArgs(
            "DH algorithm expects input variant with byte array".to_string(),
        )
    })?;
    if public_key_bytes.is_empty() {
        return Err(zbus::fdo::Error::InvalidArgs(
            "DH public key cannot be empty".to_string(),
        ));
    }

    Ok(BigUint::from_bytes_be(&public_key_bytes))
}

fn generate_dh_keypair() -> (BigUint, Vec<u8>) {
    let prime = BigUint::from_bytes_be(&DH_GROUP_PRIME_BYTES);
    let generator = BigUint::from(DH_GENERATOR);

    let mut private_key_bytes = [0u8; DH_SHARED_SECRET_SIZE];
    OsRng.fill_bytes(&mut private_key_bytes);
    let private_key = BigUint::from_bytes_be(&private_key_bytes);
    let public_key = generator.modpow(&private_key, &prime).to_bytes_be();

    (private_key, public_key)
}

fn derive_dh_aes_key(
    client_public: &BigUint,
    private_key: &BigUint,
) -> zbus::fdo::Result<[u8; 16]> {
    let prime = BigUint::from_bytes_be(&DH_GROUP_PRIME_BYTES);
    let one = BigUint::from(1u8);
    let p_minus_one = &prime - &one;
    if client_public <= &one || client_public >= &p_minus_one {
        return Err(zbus::fdo::Error::InvalidArgs(
            "DH public key out of range".to_string(),
        ));
    }

    let shared_secret = client_public.modpow(private_key, &prime);
    let shared_secret_bytes = shared_secret.to_bytes_be();
    if shared_secret_bytes.len() > DH_SHARED_SECRET_SIZE {
        return Err(zbus::fdo::Error::Failed(
            "DH shared secret exceeded expected size".to_string(),
        ));
    }

    let mut ikm = vec![0u8; DH_SHARED_SECRET_SIZE - shared_secret_bytes.len()];
    ikm.extend(shared_secret_bytes);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; DH_AES_KEY_SIZE];
    hkdf.expand(&[], &mut key)
        .map_err(|_| zbus::fdo::Error::Failed("Failed to derive DH session key".to_string()))?;
    Ok(key)
}

async fn resolve_session_encryption(
    sessions: &Arc<RwLock<SessionMap>>,
    session_path: &str,
) -> zbus::fdo::Result<SessionEncryption> {
    if session_path == ROOT_PROMPT_PATH {
        return Ok(SessionEncryption::Plain);
    }

    let sessions = sessions.read().await;
    sessions
        .get(session_path)
        .map(|state| state.encryption.clone())
        .ok_or_else(|| zbus::fdo::Error::Failed(format!("Session not found: {}", session_path)))
}

async fn decode_secret_for_storage(
    sessions: &Arc<RwLock<SessionMap>>,
    secret: &Secret,
) -> zbus::fdo::Result<Vec<u8>> {
    let session = resolve_session_encryption(sessions, secret.0.as_str()).await?;
    decode_secret_bytes(&session, &secret.1, &secret.2)
}

fn decode_secret_bytes(
    session: &SessionEncryption,
    parameters: &[u8],
    value: &[u8],
) -> zbus::fdo::Result<Vec<u8>> {
    match session {
        SessionEncryption::Plain => {
            if !parameters.is_empty() {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "plain session expects empty secret parameters".to_string(),
                ));
            }
            Ok(value.to_vec())
        }
        SessionEncryption::Dh { key } => decrypt_dh_secret(value, parameters, key),
    }
}

fn encode_secret_for_transport(
    session_path: OwnedObjectPath,
    session: &SessionEncryption,
    secret: &[u8],
    content_type: &str,
) -> zbus::fdo::Result<Secret> {
    let (parameters, value) = match session {
        SessionEncryption::Plain => (vec![], secret.to_vec()),
        SessionEncryption::Dh { key } => encrypt_dh_secret(secret, key)?,
    };

    Ok((session_path, parameters, value, content_type.to_string()))
}

fn encrypt_dh_secret(
    secret: &[u8],
    key: &[u8; DH_AES_KEY_SIZE],
) -> zbus::fdo::Result<(Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; DH_IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    let ciphertext = Aes128CbcEnc::<Aes128>::new(key.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(secret);
    Ok((iv.to_vec(), ciphertext))
}

fn decrypt_dh_secret(
    ciphertext: &[u8],
    parameters: &[u8],
    key: &[u8; DH_AES_KEY_SIZE],
) -> zbus::fdo::Result<Vec<u8>> {
    let iv: [u8; DH_IV_SIZE] = parameters.try_into().map_err(|_| {
        zbus::fdo::Error::InvalidArgs(format!("DH secret parameter must be {} bytes", DH_IV_SIZE))
    })?;

    let plaintext = Aes128CbcDec::<Aes128>::new(key.into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| zbus::fdo::Error::Failed("Failed to decrypt secret payload".to_string()))?;
    Ok(plaintext)
}

fn request_prompt_password(window_id: &str) -> Option<String> {
    if !confirm_prompt_via_authd(window_id) {
        return None;
    }

    extract_prompt_password(window_id)
}

fn extract_prompt_password(window_id: &str) -> Option<String> {
    // Temporary transport until authd can return entered passwords to callers.
    if let Some(password) = window_id.strip_prefix("password:") {
        if !password.is_empty() {
            return Some(password.to_string());
        }
    }

    std::env::var("KEYRING_PROMPT_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
}

fn confirm_prompt_via_authd(window_id: &str) -> bool {
    confirm_prompt_via_authd_sync(window_id)
}

fn confirm_prompt_via_authd_sync(window_id: &str) -> bool {
    let target =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/keyring-daemon"));
    let mut env = collect_wayland_env();
    env.insert(
        "KEYRING_PROMPT_WINDOW_ID".to_string(),
        window_id.to_string(),
    );

    let request = AuthRequest {
        target,
        args: vec!["unlock keyring".to_string()],
        env,
        password: String::new(),
        confirm_only: true,
    };

    match IpcClient::call(AUTHD_SOCKET_PATH, &request) {
        Ok(AuthResponse::Success { .. } | AuthResponse::UnknownTarget) => true,
        Ok(AuthResponse::Denied { reason }) => {
            tracing::info!("authd denied keyring prompt: {}", reason);
            false
        }
        Ok(AuthResponse::AuthFailed) => false,
        Ok(AuthResponse::Error { message }) => {
            tracing::warn!("authd prompt error: {}", message);
            false
        }
        Err(error) => {
            tracing::warn!(
                "authd socket unavailable, proceeding without prompt gate: {}",
                error
            );
            true
        }
    }
}

async fn caller_pid(connection: &Connection, sender: &str) -> Option<u32> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetConnectionUnixProcessID",
            &(sender,),
        )
        .await
        .ok()?;

    reply.body().deserialize::<u32>().ok()
}

async fn check_sender_access(
    connection: &Connection,
    access: &AccessControl,
    sender: &str,
) -> zbus::fdo::Result<()> {
    let pid = caller_pid(connection, sender)
        .await
        .ok_or_else(|| zbus::fdo::Error::Failed("Could not get caller PID".into()))?;

    let allowed = access
        .check_access(pid)
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    if !allowed {
        return Err(zbus::fdo::Error::AccessDenied(
            "Access denied by user".into(),
        ));
    }

    Ok(())
}

async fn map_item_or_default<T, F>(
    storage: &Arc<RwLock<Storage>>,
    id: u64,
    field: F,
    default: T,
) -> T
where
    F: FnOnce(crate::storage::DecryptedItem) -> T,
{
    let storage: RwLockReadGuard<'_, Storage> = storage.read().await;
    storage
        .get_item(id)
        .ok()
        .flatten()
        .map(field)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn extract_prompt_password_from_window_id_token() {
        assert_eq!(
            extract_prompt_password("password:test-password"),
            Some("test-password".to_string())
        );
        assert_eq!(extract_prompt_password("0"), None);
    }

    #[test]
    fn collection_name_from_path_parses_valid_paths() {
        assert_eq!(
            collection_name_from_path("/org/freedesktop/secrets/collection/default"),
            Some(Some("default".to_string()))
        );
        assert_eq!(collection_name_from_path("/"), Some(None));
        assert_eq!(
            collection_name_from_path("/org/freedesktop/secrets/collection/"),
            None
        );
        assert_eq!(
            collection_name_from_path("/org/freedesktop/secrets/collection/a/b"),
            None
        );
    }

    #[test]
    fn collection_paths_skip_invalid_collection_names() {
        let collections = vec![
            crate::storage::Collection {
                name: "default".to_string(),
                label: "Default".to_string(),
                created: 1,
                modified: 1,
            },
            crate::storage::Collection {
                name: "bad name".to_string(),
                label: "Broken".to_string(),
                created: 2,
                modified: 2,
            },
        ];

        let paths = collection_paths(&collections);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0].as_str(),
            "/org/freedesktop/secrets/collection/default"
        );
    }

    #[test]
    fn item_id_from_object_path_parses_terminal_id() {
        let valid =
            OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default/42").unwrap();
        let invalid =
            OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap();

        assert_eq!(item_id_from_object_path(&valid), Some(42));
        assert_eq!(item_id_from_object_path(&invalid), None);
    }

    #[test]
    fn dh_key_derivation_is_symmetric() {
        let (private_a, public_a) = generate_dh_keypair();
        let (private_b, public_b) = generate_dh_keypair();

        let key_ab = derive_dh_aes_key(&BigUint::from_bytes_be(&public_b), &private_a).unwrap();
        let key_ba = derive_dh_aes_key(&BigUint::from_bytes_be(&public_a), &private_b).unwrap();

        assert_eq!(key_ab, key_ba);
    }

    #[test]
    fn dh_encrypt_decrypt_roundtrip() {
        let key = [7u8; DH_AES_KEY_SIZE];
        let secret = b"transport-secret";
        let (iv, ciphertext) = encrypt_dh_secret(secret, &key).unwrap();
        assert_eq!(iv.len(), DH_IV_SIZE);
        assert_ne!(ciphertext, secret);

        let decrypted = decrypt_dh_secret(&ciphertext, &iv, &key).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn plain_secret_rejects_non_empty_parameters() {
        let error = decode_secret_bytes(&SessionEncryption::Plain, &[1, 2, 3], b"secret")
            .expect_err("plain secret with parameters should fail");
        assert!(matches!(error, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn open_session_dh_get_secret_returns_encrypted_payload() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        let item_id = storage
            .create_item("default", "Default Item", b"dh-secret", HashMap::new())
            .unwrap();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage, access).await.unwrap();

        let (client_private, client_public) = generate_dh_keypair();
        let client = Connection::session().await.unwrap();

        let open_response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "OpenSession",
                &(ALGORITHM_DH, Value::new(client_public)),
            )
            .await
            .unwrap();
        let (service_public, session_path): (OwnedValue, OwnedObjectPath) =
            open_response.body().deserialize().unwrap();
        let service_public_bytes: Vec<u8> = service_public.try_into().unwrap();
        let client_key = derive_dh_aes_key(
            &BigUint::from_bytes_be(&service_public_bytes),
            &client_private,
        )
        .unwrap();

        let item_path = item_object_path("default", item_id).unwrap();
        let secret_response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                item_path.as_str(),
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(session_path.clone(),),
            )
            .await
            .unwrap();

        let (returned_session, parameters, value, content_type): Secret =
            secret_response.body().deserialize().unwrap();
        assert_eq!(returned_session.as_str(), session_path.as_str());
        assert_eq!(content_type, "text/plain");
        assert_eq!(parameters.len(), DH_IV_SIZE);
        assert_ne!(value, b"dh-secret");

        let decrypted = decrypt_dh_secret(&value, &parameters, &client_key).unwrap();
        assert_eq!(decrypted, b"dh-secret");
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn unlock_returns_live_prompt_path_when_locked() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.lock();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage.clone(), access).await.unwrap();

        let client = Connection::session().await.unwrap();
        let objects =
            vec![OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap()];
        let response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "Unlock",
                &(objects,),
            )
            .await
            .unwrap();
        let (unlocked, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            response.body().deserialize().unwrap();

        assert!(unlocked.is_empty());
        assert_ne!(prompt_path.as_str(), ROOT_PROMPT_PATH);
        assert!(prompt_path.as_str().starts_with(PROMPT_PATH_PREFIX));
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn prompt_unlocks_collection_with_password_token() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.lock();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage.clone(), access).await.unwrap();

        let client = Connection::session().await.unwrap();
        let objects =
            vec![OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap()];
        let unlock_response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "Unlock",
                &(objects,),
            )
            .await
            .unwrap();
        let (_unlocked, prompt_path): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            unlock_response.body().deserialize().unwrap();

        client
            .call_method(
                Some("org.freedesktop.secrets"),
                prompt_path.as_str(),
                Some("org.freedesktop.Secret.Prompt"),
                "Prompt",
                &("password:test-password",),
            )
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        let storage = storage.read().await;
        assert!(!storage.is_locked());
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn set_alias_persists_and_read_alias_returns_collection_path() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.create_collection("work", "Work").unwrap();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage.clone(), access).await.unwrap();

        let client = Connection::session().await.unwrap();
        let work_path =
            OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work").unwrap();
        client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "SetAlias",
                &("test", work_path.clone()),
            )
            .await
            .unwrap();

        let response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "ReadAlias",
                &("test",),
            )
            .await
            .unwrap();
        let alias_path: OwnedObjectPath = response.body().deserialize().unwrap();
        assert_eq!(alias_path.as_str(), work_path.as_str());

        let storage = storage.read().await;
        assert_eq!(storage.get_alias("test").unwrap(), Some("work".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn delete_collection_removes_items_and_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        let item_id = storage
            .create_item(
                "default",
                "Default Item",
                b"default-secret",
                HashMap::from([("service".to_string(), "default.example".to_string())]),
            )
            .unwrap();
        storage.set_alias("test", Some("default")).unwrap();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage.clone(), access).await.unwrap();

        let client = Connection::session().await.unwrap();
        let delete_response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets/collection/default",
                Some("org.freedesktop.Secret.Collection"),
                "Delete",
                &(),
            )
            .await
            .unwrap();
        let prompt_path: OwnedObjectPath = delete_response.body().deserialize().unwrap();
        assert_eq!(prompt_path.as_str(), ROOT_PROMPT_PATH);

        let alias_response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets",
                Some("org.freedesktop.Secret.Service"),
                "ReadAlias",
                &("test",),
            )
            .await
            .unwrap();
        let alias_path: OwnedObjectPath = alias_response.body().deserialize().unwrap();
        assert_eq!(alias_path.as_str(), ROOT_PROMPT_PATH);

        let storage = storage.read().await;
        assert!(storage.get_collection("default").unwrap().is_none());
        assert!(storage.get_item(item_id).unwrap().is_none());
        assert_eq!(storage.get_alias("test").unwrap(), None);

        let second_delete = client
            .call_method(
                Some("org.freedesktop.secrets"),
                "/org/freedesktop/secrets/collection/default",
                Some("org.freedesktop.Secret.Collection"),
                "Delete",
                &(),
            )
            .await;
        assert!(second_delete.is_err());
    }

    #[tokio::test]
    #[ignore = "requires secret-tool under isolated dbus-run-session"]
    async fn secret_tool_store_lookup_smoke() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service_connection = start_service(storage.clone(), access).await.unwrap();

        let secret = "smoke-secret";
        let mut store = Command::new("secret-tool")
            .args([
                "store",
                "--label",
                "Smoke",
                "service",
                "dbus-smoke",
                "user",
                "alice",
            ])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        store
            .stdin
            .as_mut()
            .unwrap()
            .write_all(secret.as_bytes())
            .unwrap();
        let store_output = store.wait_with_output().unwrap();
        assert!(
            store_output.status.success(),
            "secret-tool store failed: {}",
            String::from_utf8_lossy(&store_output.stderr)
        );

        let lookup_output = Command::new("secret-tool")
            .args(["lookup", "service", "dbus-smoke", "user", "alice"])
            .output()
            .unwrap();
        assert!(
            lookup_output.status.success(),
            "secret-tool lookup failed: stderr={}",
            String::from_utf8_lossy(&lookup_output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&lookup_output.stdout).trim(),
            secret
        );

        let item_path = {
            let storage = storage.read().await;
            let locations = storage.list_item_locations().unwrap();
            let (collection, id) = locations
                .into_iter()
                .find(|(collection, _)| collection == "default")
                .unwrap();
            item_object_path(&collection, id).unwrap()
        };

        let client = Connection::session().await.unwrap();
        let response = client
            .call_method(
                Some("org.freedesktop.secrets"),
                item_path.as_str(),
                Some("org.freedesktop.Secret.Item"),
                "GetSecret",
                &(OwnedObjectPath::try_from("/").unwrap(),),
            )
            .await
            .unwrap();
        let (_session, _params, secret_bytes, _content_type): Secret =
            response.body().deserialize().unwrap();
        assert_eq!(secret_bytes, secret.as_bytes());
    }
}
