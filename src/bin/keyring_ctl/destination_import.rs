use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use thiserror::Error;

use crate::source_reader::{SourceCollection, SourceItem, SourceSnapshot};
use crate::storage::Storage;

const DESTINATION_DB_PATH_ENV: &str = "KEYRING_DB_PATH";
const DESTINATION_PASSWORD_ENV: &str = "KEYRING_PASSWORD";
const SUPPORTED_CONTENT_TYPE: &str = "text/plain";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CollisionPolicy {
    Skip,
    Replace,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemFailure {
    pub collection: String,
    pub label: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    pub collections_created: usize,
    pub collections_existing: usize,
    pub items_scanned: usize,
    pub items_imported: usize,
    pub items_skipped: usize,
    pub items_failed: usize,
    pub items_replaced: usize,
    pub items_renamed: usize,
    pub failed_items: Vec<ItemFailure>,
}

impl ImportSummary {
    pub fn for_dry_run(snapshot: &SourceSnapshot) -> Self {
        Self {
            collections_created: 0,
            collections_existing: 0,
            items_scanned: snapshot.collections.iter().map(|c| c.items.len()).sum(),
            items_imported: 0,
            items_skipped: 0,
            items_failed: 0,
            items_replaced: 0,
            items_renamed: 0,
            failed_items: Vec::new(),
        }
    }

    fn new() -> Self {
        Self {
            collections_created: 0,
            collections_existing: 0,
            items_scanned: 0,
            items_imported: 0,
            items_skipped: 0,
            items_failed: 0,
            items_replaced: 0,
            items_renamed: 0,
            failed_items: Vec::new(),
        }
    }

    fn record_item_failure(&mut self, collection_name: &str, item: &SourceItem, reason: String) {
        self.items_failed += 1;
        self.failed_items.push(ItemFailure {
            collection: collection_name.to_string(),
            label: item.label.clone(),
            path: item.path.as_str().to_string(),
            reason,
        });
    }
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

    let mut summary = ImportSummary::new();
    for collection in sorted_collections(snapshot) {
        import_collection(&storage, collection, collision_policy, &mut summary);
    }

    Ok(summary)
}

#[derive(Debug)]
enum ItemImportResult {
    Imported,
    Skipped,
    Replaced,
    Renamed,
    Failed(String),
}

fn import_collection(
    storage: &Storage,
    collection: &SourceCollection,
    collision_policy: CollisionPolicy,
    summary: &mut ImportSummary,
) {
    let items = sorted_items(collection);
    if let Err(error) = ensure_collection_exists(storage, collection, summary) {
        let reason = format!(
            "Destination collection unavailable (`{}`): {}",
            collection.name, error
        );
        for item in items {
            summary.items_scanned += 1;
            summary.record_item_failure(&collection.name, item, reason.clone());
        }
        return;
    }

    for item in items {
        summary.items_scanned += 1;
        match import_item(storage, &collection.name, item, collision_policy) {
            ItemImportResult::Imported => summary.items_imported += 1,
            ItemImportResult::Skipped => summary.items_skipped += 1,
            ItemImportResult::Replaced => {
                summary.items_imported += 1;
                summary.items_replaced += 1;
            }
            ItemImportResult::Renamed => {
                summary.items_imported += 1;
                summary.items_renamed += 1;
            }
            ItemImportResult::Failed(reason) => {
                summary.record_item_failure(&collection.name, item, reason)
            }
        }
    }
}

fn ensure_collection_exists(
    storage: &Storage,
    collection: &SourceCollection,
    summary: &mut ImportSummary,
) -> Result<(), crate::error::KeyringError> {
    if storage.get_collection(&collection.name)?.is_none() {
        storage.create_collection(&collection.name, &collection.label)?;
        summary.collections_created += 1;
    } else {
        summary.collections_existing += 1;
    }

    Ok(())
}

fn import_item(
    storage: &Storage,
    collection_name: &str,
    item: &SourceItem,
    collision_policy: CollisionPolicy,
) -> ItemImportResult {
    if item.content_type != SUPPORTED_CONTENT_TYPE {
        return ItemImportResult::Failed(format!(
            "Unsupported content type `{}` (expected `{}`)",
            item.content_type, SUPPORTED_CONTENT_TYPE
        ));
    }

    let collisions =
        match colliding_item_ids(storage, collection_name, &item.label, &item.attributes) {
            Ok(collisions) => collisions,
            Err(error) => {
                return ItemImportResult::Failed(format!("Unable to detect collisions: {}", error));
            }
        };

    if collisions.is_empty() {
        return import_new_item(storage, collection_name, &item.label, item);
    }

    match collision_policy {
        CollisionPolicy::Skip => ItemImportResult::Skipped,
        CollisionPolicy::Replace => {
            replace_colliding_items(storage, collection_name, item, collisions)
        }
        CollisionPolicy::Rename => import_with_renamed_label(storage, collection_name, item),
    }
}

fn import_new_item(
    storage: &Storage,
    collection_name: &str,
    label: &str,
    item: &SourceItem,
) -> ItemImportResult {
    match create_destination_item(storage, collection_name, label, item) {
        Ok(_id) => ItemImportResult::Imported,
        Err(error) => ItemImportResult::Failed(format!("Failed to create item: {}", error)),
    }
}

fn replace_colliding_items(
    storage: &Storage,
    collection_name: &str,
    item: &SourceItem,
    collisions: Vec<u64>,
) -> ItemImportResult {
    for collision_id in collisions {
        if let Err(error) = storage.delete_item(collision_id) {
            return ItemImportResult::Failed(format!(
                "Failed to delete colliding item {}: {}",
                collision_id, error
            ));
        }
    }

    match create_destination_item(storage, collection_name, &item.label, item) {
        Ok(_id) => ItemImportResult::Replaced,
        Err(error) => {
            ItemImportResult::Failed(format!("Failed to create replacement item: {}", error))
        }
    }
}

fn import_with_renamed_label(
    storage: &Storage,
    collection_name: &str,
    item: &SourceItem,
) -> ItemImportResult {
    let renamed_label = match renamed_label_for_collision(storage, collection_name, &item.label) {
        Ok(label) => label,
        Err(error) => {
            return ItemImportResult::Failed(format!("Failed to compute renamed label: {}", error));
        }
    };

    match create_destination_item(storage, collection_name, &renamed_label, item) {
        Ok(_id) => ItemImportResult::Renamed,
        Err(error) => ItemImportResult::Failed(format!("Failed to create renamed item: {}", error)),
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
    fn dry_run_summary_reports_scanned_item_count() {
        let snapshot = source_snapshot(
            "default",
            "Default",
            "Item",
            HashMap::new(),
            b"secret".to_vec(),
        );
        let summary = ImportSummary::for_dry_run(&snapshot);

        assert_eq!(summary.items_scanned, 1);
        assert_eq!(summary.items_imported, 0);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_failed, 0);
        assert!(summary.failed_items.is_empty());
    }

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
        assert_eq!(summary.items_scanned, 1);
        assert_eq!(summary.items_imported, 1);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_failed, 0);

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
        assert_eq!(summary.items_scanned, 1);
        assert_eq!(summary.items_imported, 0);
        assert_eq!(summary.items_skipped, 1);
        assert_eq!(summary.items_replaced, 0);
        assert_eq!(summary.items_renamed, 0);
        assert_eq!(summary.items_failed, 0);

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
        assert_eq!(summary.items_imported, 1);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_replaced, 1);
        assert_eq!(summary.items_renamed, 0);
        assert_eq!(summary.items_failed, 0);

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
        assert_eq!(summary.items_imported, 1);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_replaced, 0);
        assert_eq!(summary.items_renamed, 1);
        assert_eq!(summary.items_failed, 0);

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

    #[test]
    fn unsupported_content_type_is_reported_as_failed_item() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("import.db");

        let snapshot = SourceSnapshot {
            collections: vec![SourceCollection {
                name: "default".to_string(),
                label: "Default".to_string(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default")
                    .unwrap(),
                items: vec![SourceItem {
                    path: OwnedObjectPath::try_from(
                        "/org/freedesktop/secrets/collection/default/1",
                    )
                    .unwrap(),
                    label: "Binary Secret".to_string(),
                    attributes: HashMap::new(),
                    secret: b"data".to_vec(),
                    content_type: "application/octet-stream".to_string(),
                }],
            }],
            skipped_locked_collections: vec![],
            skipped_filtered_collections: vec![],
        };

        let summary = import_snapshot_into_storage(
            &snapshot,
            &db_path,
            "test-password",
            CollisionPolicy::Skip,
        )
        .unwrap();

        assert_eq!(summary.items_scanned, 1);
        assert_eq!(summary.items_imported, 0);
        assert_eq!(summary.items_skipped, 0);
        assert_eq!(summary.items_failed, 1);
        assert_eq!(summary.failed_items.len(), 1);
        assert_eq!(summary.failed_items[0].collection, "default");
        assert_eq!(summary.failed_items[0].label, "Binary Secret");
        assert!(
            summary.failed_items[0]
                .reason
                .contains("Unsupported content type")
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
