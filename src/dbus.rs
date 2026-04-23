// D-Bus Secret Service implementation
// https://specifications.freedesktop.org/secret-service/latest/

use authd_protocol::{
    AuthRequest, AuthResponse, SOCKET_PATH as AUTHD_SOCKET_PATH, collect_wayland_env,
};
use peercred_ipc::Client as IpcClient;
use std::collections::{HashMap, HashSet};
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
const ROOT_PROMPT_PATH: &str = "/";
const PROMPT_PATH_PREFIX: &str = "/org/freedesktop/secrets/prompt";

pub struct SecretService {
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<HashSet<String>>>,
    access: Arc<AccessControl>,
    connection: Connection,
}

impl SecretService {
    pub fn new(
        storage: Arc<RwLock<Storage>>,
        access: Arc<AccessControl>,
        connection: Connection,
    ) -> Self {
        Self {
            storage,
            sessions: Arc::new(RwLock::new(HashSet::new())),
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
        _input: Value<'_>,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "plain" {
            return Err(zbus::fdo::Error::NotSupported(
                "Only 'plain' algorithm supported".into(),
            ));
        }

        let session_id = format!("session{}", rand::random::<u32>());
        let session_path = format!("/org/freedesktop/secrets/session/{}", session_id);

        let mut sessions: RwLockWriteGuard<'_, HashSet<String>> = self.sessions.write().await;
        sessions.insert(session_id.clone());

        Ok((
            OwnedValue::try_from(Value::new("")).unwrap(),
            OwnedObjectPath::try_from(session_path).unwrap(),
        ))
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

        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let mut result: HashMap<OwnedObjectPath, Secret> = HashMap::new();

        for item_path in items {
            // Parse item ID from path: /org/freedesktop/secrets/collection/default/{id}
            let path_str = item_path.as_str();
            if let Some(id_str) = path_str.rsplit('/').next() {
                if let Ok(id) = id_str.parse::<u64>() {
                    if let Ok(Some(item)) = storage.get_item(id) {
                        let secret: Secret = (
                            session.clone(),
                            vec![],                   // parameters (empty for plain)
                            item.secret,              // the actual secret
                            "text/plain".to_string(), // content type
                        );
                        result.insert(item_path, secret);
                    }
                }
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
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        let collections: Vec<crate::storage::Collection> = match storage.list_collections() {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        collections
            .iter()
            .map(|c| {
                OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{}", c.name))
                    .unwrap()
            })
            .collect()
    }
}

// Collection interface
pub struct SecretCollection {
    storage: Arc<RwLock<Storage>>,
    name: String,
    connection: Connection,
}

impl SecretCollection {
    pub fn new(storage: Arc<RwLock<Storage>>, name: String, connection: Connection) -> Self {
        Self {
            storage,
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
        let id = {
            let storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;

            // Extract label from properties
            let label: String = properties
                .get("org.freedesktop.Secret.Item.Label")
                .and_then(|v| TryInto::<String>::try_into(v.clone()).ok())
                .unwrap_or_else(|| "Unnamed".to_string());

            // Extract attributes from properties
            let attributes: HashMap<String, String> = properties
                .get("org.freedesktop.Secret.Item.Attributes")
                .and_then(|v| TryInto::<HashMap<String, String>>::try_into(v.clone()).ok())
                .unwrap_or_default();

            // If replace is true, search for existing item with same attributes
            if replace && !attributes.is_empty() {
                let existing: Vec<u64> = storage
                    .search_items(&attributes)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

                for id in existing {
                    let _ = storage.delete_item(id);
                }
            }

            // Create the item - secret.2 is the actual secret bytes
            storage
                .create_item(&self.name, &label, &secret.2, attributes)
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
        };

        let item_path =
            register_item_object(&self.connection, self.storage.clone(), &self.name, id)
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        // No prompt needed
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();

        // Signal that item was created
        Self::item_created(&ctxt, item_path.clone()).await.ok();

        Ok((item_path, prompt_path))
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
    collection: String,
    id: u64,
}

impl SecretItem {
    pub fn new(storage: Arc<RwLock<Storage>>, collection: String, id: u64) -> Self {
        Self {
            storage,
            collection,
            id,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl SecretItem {
    /// Get the secret
    async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;

        let item = storage
            .get_item(self.id)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
            .ok_or_else(|| zbus::fdo::Error::Failed("Item not found".into()))?;

        Ok((session, vec![], item.secret, "text/plain".to_string()))
    }

    /// Set the secret
    async fn set_secret(&self, secret: Secret) -> zbus::fdo::Result<()> {
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
                &secret.2,
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
    pub fn new(
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

pub async fn start_service(
    storage: Arc<RwLock<Storage>>,
    access: Arc<AccessControl>,
) -> zbus::Result<Connection> {
    let connection = Connection::session().await?;

    // Register main service
    let service = SecretService::new(storage.clone(), access.clone(), connection.clone());
    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    // Register default collection
    let collection =
        SecretCollection::new(storage.clone(), "default".to_string(), connection.clone());
    connection
        .object_server()
        .at("/org/freedesktop/secrets/collection/default", collection)
        .await?;

    // Register alias for default collection
    let alias_collection =
        SecretCollection::new(storage.clone(), "default".to_string(), connection.clone());
    connection
        .object_server()
        .at("/org/freedesktop/secrets/aliases/default", alias_collection)
        .await?;

    register_existing_item_objects(&connection, storage).await?;

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

async fn register_item_object(
    connection: &Connection,
    storage: Arc<RwLock<Storage>>,
    collection: &str,
    id: u64,
) -> zbus::Result<OwnedObjectPath> {
    let path = item_object_path(collection, id)?;
    let item = SecretItem::new(storage, collection.to_string(), id);
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
) -> zbus::Result<()> {
    let item_locations = {
        let storage_guard: RwLockReadGuard<'_, Storage> = storage.read().await;
        storage_guard
            .list_item_locations()
            .map_err(|e| zbus::Error::Failure(e.to_string()))?
    };

    for (collection, id) in item_locations {
        register_item_object(connection, storage.clone(), &collection, id).await?;
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
