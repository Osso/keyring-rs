use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{generate_salt, Crypto};
use crate::error::{KeyringError, Result};

const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
const ITEMS: TableDefinition<u64, &[u8]> = TableDefinition::new("items");
const ATTRIBUTES: TableDefinition<(u64, &str), &str> = TableDefinition::new("attributes");
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

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
    pub secret: Vec<u8>,     // encrypted
    pub nonce: [u8; 12],
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: u64,
    pub collection: String,
    pub label: String,
    pub secret: Vec<u8>,     // plaintext
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
        // TODO: Verify password by decrypting a test value
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
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn create_and_get_collection() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path().join("test.db")).unwrap();

        storage.create_collection("test", "Test Collection").unwrap();
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
        storage.create_item("default", "GitHub", b"gh-secret", attrs1).unwrap();

        let mut attrs2 = HashMap::new();
        attrs2.insert("service".to_string(), "gitlab.com".to_string());
        storage.create_item("default", "GitLab", b"gl-secret", attrs2).unwrap();

        let mut query = HashMap::new();
        query.insert("service".to_string(), "github.com".to_string());

        let results = storage.search_items(&query).unwrap();
        assert_eq!(results.len(), 1);
    }
}
