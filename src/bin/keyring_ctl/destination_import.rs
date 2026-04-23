use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use thiserror::Error;

use crate::source_reader::{SourceCollection, SourceItem, SourceSnapshot};
use crate::storage::Storage;

const DESTINATION_DB_PATH_ENV: &str = "KEYRING_DB_PATH";
const DESTINATION_PASSWORD_ENV: &str = "KEYRING_PASSWORD";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CollisionPolicy {
    Skip,
    Replace,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub collections_created: usize,
    pub collections_existing: usize,
    pub items_created: usize,
    pub items_skipped: usize,
    pub items_replaced: usize,
    pub items_renamed: usize,
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
    collision_policy: CollisionPolicy,
) -> Result<ImportSummary, DestinationImportError> {
    let password = std::env::var(DESTINATION_PASSWORD_ENV).map_err(|_| {
        DestinationImportError::MissingPassword {
            env: DESTINATION_PASSWORD_ENV,
        }
    })?;
    let destination_path = destination_db_path();
    import_snapshot_into_storage(snapshot, destination_path, &password, collision_policy)
}

pub fn import_snapshot_into_storage(
    snapshot: &SourceSnapshot,
    destination_path: impl AsRef<Path>,
    password: &str,
    collision_policy: CollisionPolicy,
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
        items_skipped: 0,
        items_replaced: 0,
        items_renamed: 0,
    };

    for collection in sorted_collections(snapshot) {
        import_collection(&storage, collection, collision_policy, &mut summary)?;
    }

    Ok(summary)
}

fn import_collection(
    storage: &Storage,
    collection: &SourceCollection,
    collision_policy: CollisionPolicy,
    summary: &mut ImportSummary,
) -> Result<(), DestinationImportError> {
    if storage.get_collection(&collection.name)?.is_none() {
        storage.create_collection(&collection.name, &collection.label)?;
        summary.collections_created += 1;
    } else {
        summary.collections_existing += 1;
    }

    for item in sorted_items(collection) {
        import_item(storage, &collection.name, item, collision_policy, summary)?;
    }

    Ok(())
}

fn import_item(
    storage: &Storage,
    collection_name: &str,
    item: &SourceItem,
    collision_policy: CollisionPolicy,
    summary: &mut ImportSummary,
) -> Result<(), DestinationImportError> {
    let collisions = colliding_item_ids(storage, collection_name, &item.label, &item.attributes)?;

    if collisions.is_empty() {
        create_destination_item(storage, collection_name, &item.label, item)?;
        summary.items_created += 1;
        return Ok(());
    }

    match collision_policy {
        CollisionPolicy::Skip => {
            summary.items_skipped += 1;
            Ok(())
        }
        CollisionPolicy::Replace => {
            for item_id in collisions {
                let _ = storage.delete_item(item_id)?;
            }
            create_destination_item(storage, collection_name, &item.label, item)?;
            summary.items_created += 1;
            summary.items_replaced += 1;
            Ok(())
        }
        CollisionPolicy::Rename => {
            let renamed_label = renamed_label_for_collision(storage, collection_name, &item.label)?;
            create_destination_item(storage, collection_name, &renamed_label, item)?;
            summary.items_created += 1;
            summary.items_renamed += 1;
            Ok(())
        }
    }
}

fn create_destination_item(
    storage: &Storage,
    collection_name: &str,
    label: &str,
    item: &SourceItem,
) -> Result<u64, crate::error::KeyringError> {
    storage.create_item(
        collection_name,
        label,
        item.secret.as_slice(),
        item.attributes.clone(),
    )
}

fn colliding_item_ids(
    storage: &Storage,
    collection_name: &str,
    label: &str,
    attributes: &HashMap<String, String>,
) -> Result<Vec<u64>, crate::error::KeyringError> {
    let mut collisions = Vec::new();
    for (existing_collection, item_id) in storage.list_item_locations()? {
        if existing_collection != collection_name {
            continue;
        }

        let Some(existing) = storage.get_item(item_id)? else {
            continue;
        };
        if existing.label == label && existing.attributes == *attributes {
            collisions.push(item_id);
        }
    }

    collisions.sort_unstable();
    Ok(collisions)
}

fn renamed_label_for_collision(
    storage: &Storage,
    collection_name: &str,
    original_label: &str,
) -> Result<String, crate::error::KeyringError> {
    let labels = labels_in_collection(storage, collection_name)?;
    if !labels.contains(original_label) {
        return Ok(original_label.to_string());
    }

    let mut suffix = 1usize;
    loop {
        let candidate = format!("{} (imported {})", original_label, suffix);
        if !labels.contains(&candidate) {
            return Ok(candidate);
        }
        suffix += 1;
    }
}

fn labels_in_collection(
    storage: &Storage,
    collection_name: &str,
) -> Result<HashSet<String>, crate::error::KeyringError> {
    let mut labels = HashSet::new();
    for (existing_collection, item_id) in storage.list_item_locations()? {
        if existing_collection != collection_name {
            continue;
        }
        if let Some(item) = storage.get_item(item_id)? {
            labels.insert(item.label);
        }
    }
    Ok(labels)
}

fn sorted_collections(snapshot: &SourceSnapshot) -> Vec<&SourceCollection> {
    let mut collections = snapshot.collections.iter().collect::<Vec<_>>();
    collections.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.path.as_str().cmp(right.path.as_str()))
    });
    collections
}

fn sorted_items(collection: &SourceCollection) -> Vec<&SourceItem> {
    let mut items = collection.items.iter().collect::<Vec<_>>();
    items.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    items
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

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Skip,
        )
        .unwrap();
        assert_eq!(summary.collections_created, 1);
        assert_eq!(summary.collections_existing, 0);
        assert_eq!(summary.items_created, 1);
        assert_eq!(summary.items_skipped, 0);

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

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Skip,
        )
        .unwrap();
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

        let error = import_snapshot_into_storage(&snapshot, &db_path, "", CollisionPolicy::Skip)
            .unwrap_err();
        assert!(matches!(error, DestinationImportError::EmptyPassword));
    }

    #[test]
    fn collision_policy_skip_preserves_existing_item() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);

        seed_item(
            &db_path,
            "test-password",
            "default",
            "Account",
            attrs.clone(),
            b"old",
        );
        let snapshot = source_snapshot(
            "default",
            "Default",
            "Account",
            attrs.clone(),
            b"new".to_vec(),
        );

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Skip,
        )
        .unwrap();
        assert_eq!(summary.items_created, 0);
        assert_eq!(summary.items_skipped, 1);
        assert_eq!(summary.items_replaced, 0);
        assert_eq!(summary.items_renamed, 0);

        let items = collection_items(&db_path, "test-password", "default");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "Account");
        assert_eq!(items[0].secret, b"old");
    }

    #[test]
    fn collision_policy_replace_overwrites_existing_item() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);

        seed_item(
            &db_path,
            "test-password",
            "default",
            "Account",
            attrs.clone(),
            b"old",
        );
        let snapshot = source_snapshot(
            "default",
            "Default",
            "Account",
            attrs.clone(),
            b"new".to_vec(),
        );

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Replace,
        )
        .unwrap();
        assert_eq!(summary.items_created, 1);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_replaced, 1);
        assert_eq!(summary.items_renamed, 0);

        let items = collection_items(&db_path, "test-password", "default");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "Account");
        assert_eq!(items[0].secret, b"new");
    }

    #[test]
    fn collision_policy_rename_uses_deterministic_suffix() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");
        let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);

        seed_item(
            &db_path,
            "test-password",
            "default",
            "Account",
            attrs.clone(),
            b"old",
        );
        seed_item(
            &db_path,
            "test-password",
            "default",
            "Account (imported 1)",
            attrs.clone(),
            b"older",
        );

        let snapshot = source_snapshot("default", "Default", "Account", attrs, b"new".to_vec());

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Rename,
        )
        .unwrap();
        assert_eq!(summary.items_created, 1);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_replaced, 0);
        assert_eq!(summary.items_renamed, 1);

        let mut labels: Vec<String> = collection_items(&db_path, "test-password", "default")
            .into_iter()
            .map(|item| item.label)
            .collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                "Account".to_string(),
                "Account (imported 1)".to_string(),
                "Account (imported 2)".to_string()
            ]
        );
    }

    fn seed_item(
        db_path: &Path,
        password: &str,
        collection_name: &str,
        label: &str,
        attributes: HashMap<String, String>,
        secret: &[u8],
    ) {
        let mut storage = Storage::open(db_path).unwrap();
        storage.unlock(password).unwrap();
        if storage.get_collection(collection_name).unwrap().is_none() {
            storage
                .create_collection(collection_name, "Default")
                .unwrap();
        }
        storage
            .create_item(collection_name, label, secret, attributes)
            .unwrap();
    }

    fn collection_items(
        db_path: &Path,
        password: &str,
        collection_name: &str,
    ) -> Vec<crate::storage::DecryptedItem> {
        let mut storage = Storage::open(db_path).unwrap();
        storage.unlock(password).unwrap();

        let mut items = Vec::new();
        for (existing_collection, item_id) in storage.list_item_locations().unwrap() {
            if existing_collection != collection_name {
                continue;
            }
            if let Some(item) = storage.get_item(item_id).unwrap() {
                items.push(item);
            }
        }

        items.sort_by(|left, right| left.label.cmp(&right.label));
        items
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
