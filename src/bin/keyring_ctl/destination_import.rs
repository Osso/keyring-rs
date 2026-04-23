use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::source_reader::SourceSnapshot;
use crate::storage::Storage;

const DESTINATION_DB_PATH_ENV: &str = "KEYRING_DB_PATH";
const DESTINATION_PASSWORD_ENV: &str = "KEYRING_PASSWORD";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub collections_created: usize,
    pub collections_existing: usize,
    pub items_created: usize,
}

#[derive(Debug, Error)]
pub enum DestinationImportError {
    #[error("Missing destination password in ${env}")]
    MissingPassword { env: &'static str },
    #[error("Destination password cannot be empty")]
    EmptyPassword,
    #[error("Filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Storage error: {0}")]
    Storage(#[from] crate::error::KeyringError),
}

pub fn import_snapshot_into_default_storage(
    snapshot: &SourceSnapshot,
) -> Result<ImportSummary, DestinationImportError> {
    let password = std::env::var(DESTINATION_PASSWORD_ENV).map_err(|_| {
        DestinationImportError::MissingPassword {
            env: DESTINATION_PASSWORD_ENV,
        }
    })?;
    let destination_path = destination_db_path();
    import_snapshot_into_storage(snapshot, destination_path, &password)
}

pub fn import_snapshot_into_storage(
    snapshot: &SourceSnapshot,
    destination_path: impl AsRef<Path>,
    password: &str,
) -> Result<ImportSummary, DestinationImportError> {
    if password.is_empty() {
        return Err(DestinationImportError::EmptyPassword);
    }

    let destination_path = destination_path.as_ref();
    ensure_destination_parent(destination_path)?;

    let mut storage = Storage::open(destination_path)?;
    storage.unlock(password)?;

    let mut summary = ImportSummary {
        collections_created: 0,
        collections_existing: 0,
        items_created: 0,
    };

    for collection in &snapshot.collections {
        if storage.get_collection(&collection.name)?.is_none() {
            storage.create_collection(&collection.name, &collection.label)?;
            summary.collections_created += 1;
        } else {
            summary.collections_existing += 1;
        }

        for item in &collection.items {
            storage.create_item(
                &collection.name,
                &item.label,
                item.secret.as_slice(),
                item.attributes.clone(),
            )?;
            summary.items_created += 1;
        }
    }

    Ok(summary)
}

fn destination_db_path() -> PathBuf {
    if let Ok(path) = std::env::var(DESTINATION_DB_PATH_ENV) {
        return PathBuf::from(path);
    }
    state_dir().join("secrets.db")
}

fn ensure_destination_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn state_dir() -> PathBuf {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".local/state")
        });
    base.join("keyring-rs")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::tempdir;
    use zbus::zvariant::OwnedObjectPath;

    use super::*;
    use crate::source_reader::{SourceCollection, SourceItem};

    #[test]
    fn import_snapshot_preserves_collection_and_item_fields() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        let snapshot = source_snapshot(
            "default",
            "Default Keyring",
            "Email Account",
            HashMap::from([("service".to_string(), "mail".to_string())]),
            b"super-secret".to_vec(),
        );

        let summary = import_snapshot_into_storage(&snapshot, &db_path, "test-password").unwrap();
        assert_eq!(summary.collections_created, 1);
        assert_eq!(summary.collections_existing, 0);
        assert_eq!(summary.items_created, 1);

        let mut storage = Storage::open(&db_path).unwrap();
        storage.unlock("test-password").unwrap();
        let collection = storage.get_collection("default").unwrap().unwrap();
        assert_eq!(collection.label, "Default Keyring");

        let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);
        let item_ids = storage.search_items(&attrs).unwrap();
        assert_eq!(item_ids.len(), 1);
        let item = storage.get_item(item_ids[0]).unwrap().unwrap();
        assert_eq!(item.label, "Email Account");
        assert_eq!(item.attributes, attrs);
        assert_eq!(item.secret, b"super-secret");
    }

    #[test]
    fn import_snapshot_counts_existing_collection() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        {
            let mut storage = Storage::open(&db_path).unwrap();
            storage.unlock("test-password").unwrap();
            storage
                .create_collection("default", "Already Exists")
                .unwrap();
        }

        let snapshot = source_snapshot(
            "default",
            "Ignored Label",
            "Item",
            HashMap::from([("k".to_string(), "v".to_string())]),
            b"secret".to_vec(),
        );

        let summary = import_snapshot_into_storage(&snapshot, &db_path, "test-password").unwrap();
        assert_eq!(summary.collections_created, 0);
        assert_eq!(summary.collections_existing, 1);
        assert_eq!(summary.items_created, 1);
    }

    #[test]
    fn import_snapshot_rejects_empty_password() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        let snapshot = source_snapshot(
            "default",
            "Default",
            "Item",
            HashMap::new(),
            b"secret".to_vec(),
        );

        let error = import_snapshot_into_storage(&snapshot, &db_path, "").unwrap_err();
        assert!(matches!(error, DestinationImportError::EmptyPassword));
    }

    fn source_snapshot(
        collection_name: &str,
        collection_label: &str,
        item_label: &str,
        attributes: HashMap<String, String>,
        secret: Vec<u8>,
    ) -> SourceSnapshot {
        SourceSnapshot {
            collections: vec![SourceCollection {
                name: collection_name.to_string(),
                label: collection_label.to_string(),
                path: OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}",
                    collection_name
                ))
                .unwrap(),
                items: vec![SourceItem {
                    path: OwnedObjectPath::try_from(format!(
                        "/org/freedesktop/secrets/collection/{}/1",
                        collection_name
                    ))
                    .unwrap(),
                    label: item_label.to_string(),
                    attributes,
                    secret,
                    content_type: "text/plain".to_string(),
                }],
            }],
            skipped_locked_collections: vec![],
            skipped_filtered_collections: vec![],
        }
    }
}
