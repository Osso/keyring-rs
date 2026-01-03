// D-Bus Secret Service implementation
// https://specifications.freedesktop.org/secret-service/latest/

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{interface, Connection};
use zbus::object_server::SignalEmitter;

use crate::storage::Storage;

// Secret struct as per D-Bus spec: (session, parameters, value, content_type)
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

pub struct SecretService {
    storage: Arc<RwLock<Storage>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

struct Session {
    #[allow(dead_code)]
    id: String,
}

impl SecretService {
    pub fn new(storage: Arc<RwLock<Storage>>) -> Self {
        Self {
            storage,
            sessions: Arc::new(RwLock::new(HashMap::new())),
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

        let mut sessions: RwLockWriteGuard<'_, HashMap<String, Session>> =
            self.sessions.write().await;
        sessions.insert(session_id.clone(), Session { id: session_id });

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
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, Secret>> {
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
                            vec![],                           // parameters (empty for plain)
                            item.secret,                      // the actual secret
                            "text/plain".to_string(),         // content type
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
        // For now, everything is auto-unlocked
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((objects, prompt_path))
    }

    /// Lock collections or items
    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut storage: RwLockWriteGuard<'_, Storage> = self.storage.write().await;
        storage.lock();

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((objects, prompt_path))
    }

    /// Read an alias (e.g., "default" collection)
    async fn read_alias(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if name == "default" {
            Ok(OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap())
        } else {
            Ok(OwnedObjectPath::try_from("/").unwrap())
        }
    }

    /// Set an alias
    async fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) -> zbus::fdo::Result<()> {
        // TODO: implement alias management
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
                OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}",
                    c.name
                ))
                .unwrap()
            })
            .collect()
    }
}

// Collection interface
pub struct SecretCollection {
    storage: Arc<RwLock<Storage>>,
    name: String,
}

impl SecretCollection {
    pub fn new(storage: Arc<RwLock<Storage>>, name: String) -> Self {
        Self { storage, name }
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
        let id = storage
            .create_item(&self.name, &label, &secret.2, attributes)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let item_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.name, id
        ))
        .unwrap();

        // No prompt needed
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();

        // Signal that item was created
        Self::item_created(&ctxt, item_path.clone()).await.ok();

        Ok((item_path, prompt_path))
    }

    /// Delete this collection
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        // TODO: implement collection deletion
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
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_collection(&self.name)
            .ok()
            .flatten()
            .map(|c| c.created)
            .unwrap_or(0)
    }

    /// Modified property (unix timestamp)
    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_collection(&self.name)
            .ok()
            .flatten()
            .map(|c| c.modified)
            .unwrap_or(0)
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
        Self { storage, collection, id }
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

        Ok((
            session,
            vec![],
            item.secret,
            "text/plain".to_string(),
        ))
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
            .create_item(&self.collection, &existing.label, &secret.2, existing.attributes)
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
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_item(self.id)
            .ok()
            .flatten()
            .map(|i| i.attributes)
            .unwrap_or_default()
    }

    /// Label property
    #[zbus(property)]
    async fn label(&self) -> String {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_item(self.id)
            .ok()
            .flatten()
            .map(|i| i.label)
            .unwrap_or_default()
    }

    /// Created property
    #[zbus(property)]
    async fn created(&self) -> u64 {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_item(self.id)
            .ok()
            .flatten()
            .map(|i| i.created)
            .unwrap_or(0)
    }

    /// Modified property
    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let storage: RwLockReadGuard<'_, Storage> = self.storage.read().await;
        storage
            .get_item(self.id)
            .ok()
            .flatten()
            .map(|i| i.modified)
            .unwrap_or(0)
    }
}

pub async fn start_service(storage: Arc<RwLock<Storage>>) -> zbus::Result<Connection> {
    let connection = Connection::session().await?;

    // Register main service
    let service = SecretService::new(storage.clone());
    connection
        .object_server()
        .at("/org/freedesktop/secrets", service)
        .await?;

    // Register default collection
    let collection = SecretCollection::new(storage.clone(), "default".to_string());
    connection
        .object_server()
        .at("/org/freedesktop/secrets/collection/default", collection)
        .await?;

    // Register alias for default collection
    let alias_collection = SecretCollection::new(storage.clone(), "default".to_string());
    connection
        .object_server()
        .at("/org/freedesktop/secrets/aliases/default", alias_collection)
        .await?;

    connection.request_name("org.freedesktop.secrets").await?;

    tracing::info!("D-Bus service started on org.freedesktop.secrets");

    Ok(connection)
}
