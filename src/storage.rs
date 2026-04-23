use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{Crypto, generate_salt};
use crate::error::{KeyringError, Result};

const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
const ITEMS: TableDefinition<u64, &[u8]> = TableDefinition::new("items");
const ATTRIBUTES: TableDefinition<(u64, &str), &str> = TableDefinition::new("attributes");
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const ALIAS_METADATA_KEY_PREFIX: &str = "alias:";
const PASSWORD_SENTINEL_CIPHERTEXT_KEY: &str = "password_sentinel_ciphertext";
const PASSWORD_SENTINEL_NONCE_KEY: &str = "password_sentinel_nonce";
const PASSWORD_SENTINEL_NONCE_SIZE: usize = 12;
const PASSWORD_SENTINEL_PLAINTEXT: &[u8] = b"keyring-rs-password-sentinel-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub name: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: u64,
    pub collection: String,
    pub label: String,
    pub secret: Vec<u8>, // encrypted
    pub nonce: [u8; 12],
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: u64,
    pub collection: String,
    pub label: String,
    pub secret: Vec<u8>, // plaintext
    pub attributes: HashMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

pub struct Storage {
    db: Database,
    crypto: Option<Crypto>,
    salt: [u8; 16],
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(COLLECTIONS)?;
            let _ = write_txn.open_table(ITEMS)?;
            let _ = write_txn.open_table(ATTRIBUTES)?;
            let _ = write_txn.open_table(METADATA)?;
        }
        write_txn.commit()?;

        // Load or generate salt
        let salt = Self::load_or_create_salt(&db)?;

        Ok(Self {
            db,
            crypto: None,
            salt,
        })
    }

    fn load_or_create_salt(db: &Database) -> Result<[u8; 16]> {
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(METADATA)?;

        if let Some(salt_data) = table.get("salt")? {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(salt_data.value());
            return Ok(salt);
        }
        drop(table);
        drop(read_txn);

        // Generate new salt
        let salt = generate_salt();
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(METADATA)?;
            table.insert("salt", salt.as_slice())?;
        }
        write_txn.commit()?;

        Ok(salt)
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let crypto = Crypto::from_password(password, &self.salt)?;
        if let Some((ciphertext, nonce)) = self.load_password_sentinel()? {
            let decrypted = crypto
                .decrypt(&ciphertext, &nonce)
                .map_err(|_| KeyringError::InvalidPassword)?;
            if decrypted != PASSWORD_SENTINEL_PLAINTEXT {
                return Err(KeyringError::InvalidPassword);
            }
        }
        self.crypto = Some(crypto);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.crypto = None;
    }

    pub fn is_locked(&self) -> bool {
        self.crypto.is_none()
    }

    fn crypto(&self) -> Result<&Crypto> {
        self.crypto.as_ref().ok_or(KeyringError::Locked)
    }

    // Collection operations

    pub fn create_collection(&self, name: &str, label: &str) -> Result<Collection> {
        let now = now_timestamp();
        let collection = Collection {
            name: name.to_string(),
            label: label.to_string(),
            created: now,
            modified: now,
        };

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(COLLECTIONS)?;
            let data = serde_json::to_vec(&collection)?;
            table.insert(name, data.as_slice())?;

            if let Some(crypto) = self.crypto.as_ref() {
                let mut metadata = write_txn.open_table(METADATA)?;
                let has_ciphertext = {
                    let value = metadata.get(PASSWORD_SENTINEL_CIPHERTEXT_KEY)?;
                    value.is_some()
                };
                let has_nonce = {
                    let value = metadata.get(PASSWORD_SENTINEL_NONCE_KEY)?;
                    value.is_some()
                };

                match (has_ciphertext, has_nonce) {
                    (false, false) => {
                        let (ciphertext, nonce) = crypto.encrypt(PASSWORD_SENTINEL_PLAINTEXT)?;
                        metadata.insert(PASSWORD_SENTINEL_CIPHERTEXT_KEY, ciphertext.as_slice())?;
                        metadata.insert(PASSWORD_SENTINEL_NONCE_KEY, nonce.as_slice())?;
                    }
                    (true, true) => {}
                    _ => {
                        return Err(KeyringError::Decryption(
                            "Incomplete password sentinel metadata".to_string(),
                        ));
                    }
                }
            }
        }
        write_txn.commit()?;

        Ok(collection)
    }

    pub fn get_collection(&self, name: &str) -> Result<Option<Collection>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(COLLECTIONS)?;

        match table.get(name)? {
            Some(data) => {
                let collection: Collection = serde_json::from_slice(data.value())?;
                Ok(Some(collection))
            }
            None => Ok(None),
        }
    }

    pub fn list_collections(&self) -> Result<Vec<Collection>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(COLLECTIONS)?;

        let mut collections = Vec::new();
        for entry in table.iter()? {
            let (_, data_guard) = entry?;
            let collection: Collection = serde_json::from_slice(data_guard.value())?;
            collections.push(collection);
        }

        Ok(collections)
    }

    pub fn get_alias(&self, alias: &str) -> Result<Option<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(METADATA)?;
        let alias_key = alias_metadata_key(alias);

        let value = table.get(alias_key.as_str())?;
        match value {
            Some(encoded) => Ok(Some(serde_json::from_slice(encoded.value())?)),
            None => Ok(None),
        }
    }

    pub fn set_alias(&self, alias: &str, collection: Option<&str>) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        let alias_key = alias_metadata_key(alias);

        {
            let mut table = write_txn.open_table(METADATA)?;
            match collection {
                Some(collection) => {
                    let encoded = serde_json::to_vec(collection)?;
                    table.insert(alias_key.as_str(), encoded.as_slice())?;
                }
                None => {
                    table.remove(alias_key.as_str())?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn list_item_locations(&self) -> Result<Vec<(String, u64)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ITEMS)?;

        let mut item_locations = Vec::new();
        for entry in table.iter()? {
            let (_, data_guard) = entry?;
            let item: Item = serde_json::from_slice(data_guard.value())?;
            item_locations.push((item.collection, item.id));
        }

        Ok(item_locations)
    }

    // Item operations

    pub fn create_item(
        &self,
        collection: &str,
        label: &str,
        secret: &[u8],
        attributes: HashMap<String, String>,
    ) -> Result<u64> {
        let crypto = self.crypto()?;

        let (encrypted, nonce) = crypto.encrypt(secret)?;
        let now = now_timestamp();
        let id = now; // Use timestamp as simple ID

        let item = Item {
            id,
            collection: collection.to_string(),
            label: label.to_string(),
            secret: encrypted,
            nonce,
            created: now,
            modified: now,
        };

        let write_txn = self.db.begin_write()?;
        {
            let mut items_table = write_txn.open_table(ITEMS)?;
            let data = serde_json::to_vec(&item)?;
            items_table.insert(id, data.as_slice())?;

            let mut attrs_table = write_txn.open_table(ATTRIBUTES)?;
            for (key, value) in &attributes {
                attrs_table.insert((id, key.as_str()), value.as_str())?;
            }
        }
        write_txn.commit()?;

        Ok(id)
    }

    pub fn get_item(&self, id: u64) -> Result<Option<DecryptedItem>> {
        let crypto = self.crypto()?;

        let read_txn = self.db.begin_read()?;
        let items_table = read_txn.open_table(ITEMS)?;

        let item: Item = match items_table.get(id)? {
            Some(data) => serde_json::from_slice(data.value())?,
            None => return Ok(None),
        };

        let secret = crypto.decrypt(&item.secret, &item.nonce)?;

        // Load attributes
        let attrs_table = read_txn.open_table(ATTRIBUTES)?;
        let mut attributes = HashMap::new();

        for entry in attrs_table.iter()? {
            let (key_guard, value_guard) = entry?;
            let (item_id, key) = key_guard.value();
            if item_id == id {
                attributes.insert(key.to_string(), value_guard.value().to_string());
            }
        }

        Ok(Some(DecryptedItem {
            id: item.id,
            collection: item.collection,
            label: item.label,
            secret,
            attributes,
            created: item.created,
            modified: item.modified,
        }))
    }

    pub fn search_items(&self, query: &HashMap<String, String>) -> Result<Vec<u64>> {
        let read_txn = self.db.begin_read()?;
        let attrs_table = read_txn.open_table(ATTRIBUTES)?;

        // Build a map of item_id -> matching attribute count
        let mut matches: HashMap<u64, usize> = HashMap::new();

        for entry in attrs_table.iter()? {
            let (key_guard, value_guard) = entry?;
            let (item_id, key) = key_guard.value();
            if let Some(expected) = query.get(key) {
                if value_guard.value() == expected {
                    *matches.entry(item_id).or_default() += 1;
                }
            }
        }

        // Return items that match ALL query attributes
        let required = query.len();
        let results: Vec<u64> = matches
            .into_iter()
            .filter(|(_, count)| *count == required)
            .map(|(id, _)| id)
            .collect();

        Ok(results)
    }

    pub fn delete_item(&self, id: u64) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut items_table = write_txn.open_table(ITEMS)?;
            let existed = items_table.remove(id)?.is_some();

            // Remove attributes
            let mut attrs_table = write_txn.open_table(ATTRIBUTES)?;
            let to_remove: Vec<(u64, String)> = attrs_table
                .iter()?
                .filter_map(|e| e.ok())
                .filter_map(|(key_guard, _)| {
                    let (item_id, key) = key_guard.value();
                    if item_id == id {
                        Some((item_id, key.to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            for (item_id, key) in to_remove {
                attrs_table.remove((item_id, key.as_str()))?;
            }

            existed
        };
        write_txn.commit()?;

        Ok(removed)
    }

    pub fn delete_collection(&self, name: &str) -> Result<Option<Vec<u64>>> {
        let write_txn = self.db.begin_write()?;
        if !Self::remove_collection_entry(&write_txn, name)? {
            return Ok(None);
        }

        let deleted_item_ids = Self::remove_items_in_collection(&write_txn, name)?;
        Self::remove_attributes_for_items(&write_txn, &deleted_item_ids)?;
        Self::remove_aliases_for_collection(&write_txn, name)?;

        write_txn.commit()?;
        Ok(Some(deleted_item_ids))
    }

    fn remove_collection_entry(write_txn: &WriteTransaction, name: &str) -> Result<bool> {
        let mut collections_table = write_txn.open_table(COLLECTIONS)?;
        Ok(collections_table.remove(name)?.is_some())
    }

    fn remove_items_in_collection(write_txn: &WriteTransaction, name: &str) -> Result<Vec<u64>> {
        let mut items_table = write_txn.open_table(ITEMS)?;
        let mut deleted_item_ids = Vec::new();

        for entry in items_table.iter()? {
            let (id_guard, item_data) = entry?;
            let item: Item = serde_json::from_slice(item_data.value())?;
            if item.collection == name {
                deleted_item_ids.push(id_guard.value());
            }
        }

        for item_id in &deleted_item_ids {
            items_table.remove(*item_id)?;
        }

        Ok(deleted_item_ids)
    }

    fn remove_attributes_for_items(write_txn: &WriteTransaction, item_ids: &[u64]) -> Result<()> {
        if item_ids.is_empty() {
            return Ok(());
        }

        let item_ids: HashSet<u64> = item_ids.iter().copied().collect();
        let mut attrs_table = write_txn.open_table(ATTRIBUTES)?;
        let mut keys_to_remove = Vec::new();

        for entry in attrs_table.iter()? {
            let (key_guard, _) = entry?;
            let (item_id, key) = key_guard.value();
            if item_ids.contains(&item_id) {
                keys_to_remove.extend([(item_id, key.to_string())]);
            }
        }

        for (item_id, key) in keys_to_remove {
            attrs_table.remove((item_id, key.as_str()))?;
        }

        Ok(())
    }

    fn remove_aliases_for_collection(write_txn: &WriteTransaction, name: &str) -> Result<()> {
        let mut metadata_table = write_txn.open_table(METADATA)?;
        let mut alias_keys_to_remove = Vec::new();

        for entry in metadata_table.iter()? {
            let (key_guard, value_guard) = entry?;
            let key = key_guard.value();
            if !key.starts_with(ALIAS_METADATA_KEY_PREFIX) {
                continue;
            }

            let aliased_collection: String = serde_json::from_slice(value_guard.value())?;
            if aliased_collection == name {
                alias_keys_to_remove.push(key.to_string());
            }
        }

        for alias_key in alias_keys_to_remove {
            metadata_table.remove(alias_key.as_str())?;
        }

        Ok(())
    }

    fn load_password_sentinel(
        &self,
    ) -> Result<Option<(Vec<u8>, [u8; PASSWORD_SENTINEL_NONCE_SIZE])>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(METADATA)?;

        let ciphertext = table.get(PASSWORD_SENTINEL_CIPHERTEXT_KEY)?;
        let nonce = table.get(PASSWORD_SENTINEL_NONCE_KEY)?;

        match (ciphertext, nonce) {
            (Some(ciphertext), Some(nonce)) => {
                if nonce.value().len() != PASSWORD_SENTINEL_NONCE_SIZE {
                    return Err(KeyringError::Decryption(
                        "Invalid password sentinel nonce length".to_string(),
                    ));
                }
                let mut nonce_bytes = [0u8; PASSWORD_SENTINEL_NONCE_SIZE];
                nonce_bytes.copy_from_slice(nonce.value());
                Ok(Some((ciphertext.value().to_vec(), nonce_bytes)))
            }
            (None, None) => Ok(None),
            _ => Err(KeyringError::Decryption(
                "Incomplete password sentinel metadata".to_string(),
            )),
        }
    }
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn alias_metadata_key(alias: &str) -> String {
    format!("{}{}", ALIAS_METADATA_KEY_PREFIX, alias)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyringError;
    use std::collections::HashMap;

    #[test]
    fn create_and_get_collection() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage
            .create_collection("test", "Test Collection")
            .unwrap();
        let collection = storage.get_collection("test").unwrap().unwrap();

        assert_eq!(collection.name, "test");
        assert_eq!(collection.label, "Test Collection");
    }

    #[test]
    fn create_and_get_item() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage.create_collection("default", "Default").unwrap();
        storage.unlock("test-password").unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("username".to_string(), "alice".to_string());
        attrs.insert("service".to_string(), "example.com".to_string());

        let id = storage
            .create_item("default", "Example Login", b"secret123", attrs)
            .unwrap();

        let item = storage.get_item(id).unwrap().unwrap();
        assert_eq!(item.label, "Example Login");
        assert_eq!(item.secret, b"secret123");
        assert_eq!(item.attributes.get("username").unwrap(), "alice");
    }

    #[test]
    fn search_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage.create_collection("default", "Default").unwrap();
        storage.unlock("test-password").unwrap();

        let mut attrs1 = HashMap::new();
        attrs1.insert("service".to_string(), "github.com".to_string());
        storage
            .create_item("default", "GitHub", b"gh-secret", attrs1)
            .unwrap();

        let mut attrs2 = HashMap::new();
        attrs2.insert("service".to_string(), "gitlab.com".to_string());
        storage
            .create_item("default", "GitLab", b"gl-secret", attrs2)
            .unwrap();

        let mut query = HashMap::new();
        query.insert("service".to_string(), "github.com".to_string());

        let results = storage.search_items(&query).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn list_item_locations_returns_collection_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.create_collection("work", "Work").unwrap();

        let default_id = storage
            .create_item("default", "Default Item", b"default-secret", HashMap::new())
            .unwrap();
        let work_id = storage
            .create_item("work", "Work Item", b"work-secret", HashMap::new())
            .unwrap();

        let mut locations = storage.list_item_locations().unwrap();
        locations.sort_by_key(|(_, id)| *id);

        assert_eq!(locations.len(), 2);
        assert!(locations.contains(&("default".to_string(), default_id)));
        assert!(locations.contains(&("work".to_string(), work_id)));
    }

    #[test]
    fn unlock_password_sentinel_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();

        // Uninitialized sentinel path: no sentinel metadata yet.
        storage.unlock("test-password").unwrap();
        storage.lock();

        // Create sentinel when creating a collection while unlocked.
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.lock();

        // Right password path.
        storage.unlock("test-password").unwrap();
        storage.lock();

        // Wrong password path.
        let err = storage.unlock("wrong-password").unwrap_err();
        assert!(matches!(err, KeyringError::InvalidPassword));
    }

    #[test]
    fn alias_roundtrip_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = Storage::open(&db_path).unwrap();

        storage.set_alias("default", Some("default")).unwrap();
        assert_eq!(
            storage.get_alias("default").unwrap(),
            Some("default".to_string())
        );

        storage.set_alias("default", Some("work")).unwrap();
        assert_eq!(
            storage.get_alias("default").unwrap(),
            Some("work".to_string())
        );

        storage.set_alias("default", None).unwrap();
        assert_eq!(storage.get_alias("default").unwrap(), None);

        storage.set_alias("favorite", Some("default")).unwrap();
        drop(storage);

        let reopened = Storage::open(&db_path).unwrap();
        assert_eq!(
            reopened.get_alias("favorite").unwrap(),
            Some("default".to_string())
        );
    }

    #[test]
    fn delete_collection_removes_items_attributes_and_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage.create_collection("work", "Work").unwrap();

        storage.set_alias("favorite", Some("work")).unwrap();
        storage.set_alias("primary", Some("default")).unwrap();

        let mut work_attrs = HashMap::new();
        work_attrs.insert("service".to_string(), "work.example".to_string());
        let work_item_id = storage
            .create_item("work", "Work Item", b"work-secret", work_attrs)
            .unwrap();

        let mut default_attrs = HashMap::new();
        default_attrs.insert("service".to_string(), "default.example".to_string());
        let default_item_id = storage
            .create_item("default", "Default Item", b"default-secret", default_attrs)
            .unwrap();

        let deleted_item_ids = storage.delete_collection("work").unwrap().unwrap();
        assert_eq!(deleted_item_ids, vec![work_item_id]);
        assert!(storage.get_collection("work").unwrap().is_none());
        assert!(storage.get_item(work_item_id).unwrap().is_none());
        assert!(storage.get_item(default_item_id).unwrap().is_some());
        assert_eq!(storage.get_alias("favorite").unwrap(), None);
        assert_eq!(
            storage.get_alias("primary").unwrap(),
            Some("default".to_string())
        );

        let missing = storage.delete_collection("missing").unwrap();
        assert_eq!(missing, None);
    }
}
