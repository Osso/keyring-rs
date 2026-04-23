use std::collections::{HashMap, HashSet};

use thiserror::Error;
use zbus::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const SECRET_SERVICE_BUS: &str = "org.freedesktop.secrets";
const SECRET_SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SECRET_SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const SECRET_COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const SECRET_ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const COLLECTION_PATH_PREFIX: &str = "/org/freedesktop/secrets/collection/";
const OPEN_SESSION_PLAIN_ALGORITHM: &str = "plain";
const LOCKED_COLLECTION_RETRY_GUIDANCE: &str = "Unlock these collections in gnome-keyring (for example in Seahorse or via a secret-tool lookup), then retry `keyring-ctl import-gnome`.";

type SecretTuple = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshot {
    pub collections: Vec<SourceCollection>,
    pub skipped_locked_collections: Vec<String>,
    pub skipped_filtered_collections: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCollection {
    pub name: String,
    pub label: String,
    pub path: OwnedObjectPath,
    pub items: Vec<SourceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceItem {
    pub path: OwnedObjectPath,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
    pub content_type: String,
}

#[derive(Debug, Error)]
pub enum SourceReaderError {
    #[error("D-Bus failure: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("Missing property `{property}` on {object_path}")]
    MissingProperty {
        object_path: String,
        property: &'static str,
    },
    #[error("Invalid property `{property}` on {object_path}: {reason}")]
    InvalidProperty {
        object_path: String,
        property: &'static str,
        reason: String,
    },
    #[error("OpenSession returned invalid session path: {0}")]
    InvalidSessionPath(String),
    #[error("Item `{item_path}` returned encrypted parameters for plain session")]
    PlainSessionEncryptedSecret { item_path: String },
    #[error("Item `{item_path}` returned secret for a different session: {session_path}")]
    SecretSessionMismatch {
        item_path: String,
        session_path: String,
    },
    #[error("Locked source collection(s): {collections}. {retry_guidance}")]
    LockedSourceCollections {
        collections: String,
        retry_guidance: &'static str,
    },
}

pub async fn read_secret_service_source(
    collection_filters: &[String],
) -> Result<SourceSnapshot, SourceReaderError> {
    let connection = Connection::session().await?;
    let reader = SecretServiceSourceReader::new(connection);
    reader.read_unlocked_snapshot(collection_filters).await
}

struct SecretServiceSourceReader {
    connection: Connection,
}

impl SecretServiceSourceReader {
    fn new(connection: Connection) -> Self {
        Self { connection }
    }

    async fn read_unlocked_snapshot(
        &self,
        collection_filters: &[String],
    ) -> Result<SourceSnapshot, SourceReaderError> {
        let filter = normalize_collection_filter(collection_filters);
        let collection_paths = self.service_collections().await?;
        let session_path = self.open_plain_session().await?;
        let read_result = self
            .read_with_open_session(collection_paths, &session_path, &filter)
            .await;
        let _ = self.close_session(&session_path).await;
        read_result
    }

    async fn read_with_open_session(
        &self,
        collection_paths: Vec<OwnedObjectPath>,
        session_path: &OwnedObjectPath,
        filter: &HashSet<String>,
    ) -> Result<SourceSnapshot, SourceReaderError> {
        let mut snapshot = SourceSnapshot {
            collections: Vec::new(),
            skipped_locked_collections: Vec::new(),
            skipped_filtered_collections: Vec::new(),
        };
        let mut locked_collections = Vec::new();

        for collection_path in collection_paths {
            let name = collection_name_for_path(collection_path.as_str());
            if !collection_selected(&name, filter) {
                snapshot.skipped_filtered_collections.push(name);
                continue;
            }

            let props = self
                .interface_properties(collection_path.as_str(), SECRET_COLLECTION_INTERFACE)
                .await?;
            if bool_property(&props, "Locked", collection_path.as_str())? {
                locked_collections.push(name);
                continue;
            }

            let label = string_property(&props, "Label", collection_path.as_str())?;
            let item_paths = object_paths_property(&props, "Items", collection_path.as_str())?;
            let items = self.read_collection_items(item_paths, session_path).await?;
            snapshot.collections.push(SourceCollection {
                name,
                label,
                path: collection_path,
                items,
            });
        }

        if !locked_collections.is_empty() {
            return Err(locked_collections_error(locked_collections));
        }

        Ok(snapshot)
    }

    async fn read_collection_items(
        &self,
        item_paths: Vec<OwnedObjectPath>,
        session_path: &OwnedObjectPath,
    ) -> Result<Vec<SourceItem>, SourceReaderError> {
        let mut items = Vec::new();
        for item_path in item_paths {
            let item_props = self
                .interface_properties(item_path.as_str(), SECRET_ITEM_INTERFACE)
                .await?;
            if bool_property(&item_props, "Locked", item_path.as_str())? {
                continue;
            }

            let label = string_property(&item_props, "Label", item_path.as_str())?;
            let attributes = attributes_property(&item_props, "Attributes", item_path.as_str())?;
            let (secret, content_type) = self.read_item_secret(&item_path, session_path).await?;
            items.push(SourceItem {
                path: item_path,
                label,
                attributes,
                secret,
                content_type,
            });
        }
        Ok(items)
    }

    async fn service_collections(&self) -> Result<Vec<OwnedObjectPath>, SourceReaderError> {
        let props = self
            .interface_properties(SECRET_SERVICE_PATH, SECRET_SERVICE_INTERFACE)
            .await?;
        object_paths_property(&props, "Collections", SECRET_SERVICE_PATH)
    }

    async fn interface_properties(
        &self,
        object_path: &str,
        interface: &str,
    ) -> Result<HashMap<String, OwnedValue>, SourceReaderError> {
        let response = self
            .connection
            .call_method(
                Some(SECRET_SERVICE_BUS),
                object_path,
                Some(PROPERTIES_INTERFACE),
                "GetAll",
                &(interface,),
            )
            .await?;
        Ok(response.body().deserialize()?)
    }

    async fn open_plain_session(&self) -> Result<OwnedObjectPath, SourceReaderError> {
        let response = self
            .connection
            .call_method(
                Some(SECRET_SERVICE_BUS),
                SECRET_SERVICE_PATH,
                Some(SECRET_SERVICE_INTERFACE),
                "OpenSession",
                &(OPEN_SESSION_PLAIN_ALGORITHM, Value::new("")),
            )
            .await?;
        let (_output, session_path): (OwnedValue, OwnedObjectPath) =
            response.body().deserialize()?;
        if !session_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/session/")
        {
            return Err(SourceReaderError::InvalidSessionPath(
                session_path.as_str().to_string(),
            ));
        }
        Ok(session_path)
    }

    async fn close_session(&self, session_path: &OwnedObjectPath) -> Result<(), SourceReaderError> {
        self.connection
            .call_method(
                Some(SECRET_SERVICE_BUS),
                session_path.as_str(),
                Some("org.freedesktop.Secret.Session"),
                "Close",
                &(),
            )
            .await?;
        Ok(())
    }

    async fn read_item_secret(
        &self,
        item_path: &OwnedObjectPath,
        session_path: &OwnedObjectPath,
    ) -> Result<(Vec<u8>, String), SourceReaderError> {
        let response = self
            .connection
            .call_method(
                Some(SECRET_SERVICE_BUS),
                item_path.as_str(),
                Some(SECRET_ITEM_INTERFACE),
                "GetSecret",
                &(session_path.clone(),),
            )
            .await?;

        let (returned_session, parameters, value, content_type): SecretTuple =
            response.body().deserialize()?;
        if returned_session.as_str() != session_path.as_str() {
            return Err(SourceReaderError::SecretSessionMismatch {
                item_path: item_path.as_str().to_string(),
                session_path: returned_session.as_str().to_string(),
            });
        }
        if !parameters.is_empty() {
            return Err(SourceReaderError::PlainSessionEncryptedSecret {
                item_path: item_path.as_str().to_string(),
            });
        }

        Ok((value, content_type))
    }
}

fn normalize_collection_filter(values: &[String]) -> HashSet<String> {
    values.iter().cloned().collect()
}

fn collection_selected(name: &str, filter: &HashSet<String>) -> bool {
    filter.is_empty() || filter.contains(name)
}

fn collection_name_for_path(path: &str) -> String {
    path.strip_prefix(COLLECTION_PATH_PREFIX)
        .and_then(|tail| {
            if tail.is_empty() || tail.contains('/') {
                None
            } else {
                Some(tail.to_string())
            }
        })
        .unwrap_or_else(|| path.to_string())
}

fn locked_collections_error(collections: Vec<String>) -> SourceReaderError {
    let mut collections = collections;
    collections.sort();
    collections.dedup();
    SourceReaderError::LockedSourceCollections {
        collections: collections.join(", "),
        retry_guidance: LOCKED_COLLECTION_RETRY_GUIDANCE,
    }
}

fn string_property(
    properties: &HashMap<String, OwnedValue>,
    key: &'static str,
    object_path: &str,
) -> Result<String, SourceReaderError> {
    let value = properties
        .get(key)
        .ok_or_else(|| SourceReaderError::MissingProperty {
            object_path: object_path.to_string(),
            property: key,
        })?;
    String::try_from(value.clone()).map_err(|error| SourceReaderError::InvalidProperty {
        object_path: object_path.to_string(),
        property: key,
        reason: error.to_string(),
    })
}

fn bool_property(
    properties: &HashMap<String, OwnedValue>,
    key: &'static str,
    object_path: &str,
) -> Result<bool, SourceReaderError> {
    let value = properties
        .get(key)
        .ok_or_else(|| SourceReaderError::MissingProperty {
            object_path: object_path.to_string(),
            property: key,
        })?;
    bool::try_from(value.clone()).map_err(|error| SourceReaderError::InvalidProperty {
        object_path: object_path.to_string(),
        property: key,
        reason: error.to_string(),
    })
}

fn object_paths_property(
    properties: &HashMap<String, OwnedValue>,
    key: &'static str,
    object_path: &str,
) -> Result<Vec<OwnedObjectPath>, SourceReaderError> {
    let value = properties
        .get(key)
        .ok_or_else(|| SourceReaderError::MissingProperty {
            object_path: object_path.to_string(),
            property: key,
        })?;
    Vec::<OwnedObjectPath>::try_from(value.clone()).map_err(|error| {
        SourceReaderError::InvalidProperty {
            object_path: object_path.to_string(),
            property: key,
            reason: error.to_string(),
        }
    })
}

fn attributes_property(
    properties: &HashMap<String, OwnedValue>,
    key: &'static str,
    object_path: &str,
) -> Result<HashMap<String, String>, SourceReaderError> {
    let value = properties
        .get(key)
        .ok_or_else(|| SourceReaderError::MissingProperty {
            object_path: object_path.to_string(),
            property: key,
        })?;
    HashMap::<String, String>::try_from(value.clone()).map_err(|error| {
        SourceReaderError::InvalidProperty {
            object_path: object_path.to_string(),
            property: key,
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AccessControl;
    use crate::dbus;
    use crate::storage::Storage;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use zbus::{Connection, interface};

    #[test]
    fn collection_name_for_path_extracts_collection_segment() {
        assert_eq!(
            collection_name_for_path("/org/freedesktop/secrets/collection/default"),
            "default"
        );
        assert_eq!(
            collection_name_for_path("/org/freedesktop/secrets/collection/login"),
            "login"
        );
    }

    #[test]
    fn collection_name_for_path_returns_original_for_item_path() {
        let item_path = "/org/freedesktop/secrets/collection/default/42";
        assert_eq!(collection_name_for_path(item_path), item_path.to_string());
    }

    #[test]
    fn collection_filter_selection_handles_empty_and_explicit_filters() {
        let empty = HashSet::new();
        assert!(collection_selected("default", &empty));

        let filter = normalize_collection_filter(&["default".to_string()]);
        assert!(collection_selected("default", &filter));
        assert!(!collection_selected("login", &filter));
    }

    #[test]
    fn locked_collection_error_is_sorted_and_has_retry_guidance() {
        let error = locked_collections_error(vec![
            "login".to_string(),
            "default".to_string(),
            "login".to_string(),
        ]);
        let message = error.to_string();

        assert!(message.contains("default, login"));
        assert!(message.contains("retry `keyring-ctl import-gnome`"));
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn read_unlocked_snapshot_reads_live_secret_service_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
        storage.unlock("test-password").unwrap();
        storage.create_collection("default", "Default").unwrap();
        storage
            .create_item(
                "default",
                "Source Item",
                b"source-secret",
                HashMap::from([
                    ("service".to_string(), "source.example".to_string()),
                    ("user".to_string(), "alice".to_string()),
                ]),
            )
            .unwrap();

        let storage = Arc::new(RwLock::new(storage));
        let access = Arc::new(AccessControl::new(false));
        let _service = dbus::start_service(storage, access).await.unwrap();

        let snapshot = read_secret_service_source(&[]).await.unwrap();
        assert_eq!(snapshot.collections.len(), 1);
        assert_eq!(snapshot.collections[0].name, "default");
        assert_eq!(snapshot.collections[0].items.len(), 1);
        assert_eq!(snapshot.collections[0].items[0].label, "Source Item");
        assert_eq!(
            snapshot.collections[0].items[0].attributes.get("service"),
            Some(&"source.example".to_string())
        );
        assert_eq!(snapshot.collections[0].items[0].secret, b"source-secret");
        assert_eq!(snapshot.collections[0].items[0].content_type, "text/plain");
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn read_unlocked_snapshot_reports_invalid_session_path() {
        let _service = start_fake_service(FakeMode::InvalidSessionPath).await;
        let error = read_secret_service_source(&[]).await.unwrap_err();
        assert!(
            matches!(
                error,
                SourceReaderError::InvalidSessionPath(ref path) if path == "/"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn read_unlocked_snapshot_reports_secret_session_mismatch() {
        let _service = start_fake_service(FakeMode::SessionMismatch).await;
        let error = read_secret_service_source(&[]).await.unwrap_err();
        assert!(
            matches!(error, SourceReaderError::SecretSessionMismatch { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn read_unlocked_snapshot_reports_plain_session_encrypted_secret() {
        let _service = start_fake_service(FakeMode::EncryptedSecret).await;
        let error = read_secret_service_source(&[]).await.unwrap_err();
        assert!(
            matches!(error, SourceReaderError::PlainSessionEncryptedSecret { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn read_unlocked_snapshot_reports_property_decode_failures() {
        let _service = start_fake_service(FakeMode::MissingCollectionLabel).await;
        let error = read_secret_service_source(&[]).await.unwrap_err();
        assert!(
            matches!(
                error,
                SourceReaderError::InvalidProperty { property, .. }
                    | SourceReaderError::MissingProperty { property, .. }
                    if property == "Label"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FakeMode {
        InvalidSessionPath,
        SessionMismatch,
        EncryptedSecret,
        MissingCollectionLabel,
    }

    struct FakeService {
        mode: FakeMode,
    }

    #[interface(name = "org.freedesktop.Secret.Service")]
    impl FakeService {
        fn open_session(
            &self,
            _algorithm: &str,
            _input: OwnedValue,
        ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
            let session = match self.mode {
                FakeMode::InvalidSessionPath => OwnedObjectPath::try_from("/").unwrap(),
                _ => OwnedObjectPath::try_from(SESSION_PATH).unwrap(),
            };
            Ok((owned(Value::new(String::new())), session))
        }

        #[zbus(property)]
        fn collections(&self) -> Vec<OwnedObjectPath> {
            vec![OwnedObjectPath::try_from(COLLECTION_PATH).unwrap()]
        }
    }

    struct FakeCollection;

    #[interface(name = "org.freedesktop.Secret.Collection")]
    impl FakeCollection {
        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }

        #[zbus(property)]
        fn label(&self) -> String {
            "Default Collection".to_string()
        }

        #[zbus(property)]
        fn items(&self) -> Vec<OwnedObjectPath> {
            vec![OwnedObjectPath::try_from(ITEM_PATH).unwrap()]
        }
    }

    struct FakeCollectionMissingLabel;

    #[interface(name = "org.freedesktop.Secret.Collection")]
    impl FakeCollectionMissingLabel {
        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }

        #[zbus(property)]
        fn items(&self) -> Vec<OwnedObjectPath> {
            vec![OwnedObjectPath::try_from(ITEM_PATH).unwrap()]
        }
    }

    struct FakeItem {
        mode: FakeMode,
    }

    #[interface(name = "org.freedesktop.Secret.Item")]
    impl FakeItem {
        fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<SecretTuple> {
            let (returned_session, parameters) = match self.mode {
                FakeMode::SessionMismatch => (
                    OwnedObjectPath::try_from(OTHER_SESSION_PATH).unwrap(),
                    Vec::new(),
                ),
                FakeMode::EncryptedSecret => (session.clone(), vec![1, 2, 3]),
                _ => (session.clone(), Vec::new()),
            };

            Ok((
                returned_session,
                parameters,
                b"fake-secret".to_vec(),
                "text/plain".to_string(),
            ))
        }

        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }

        #[zbus(property)]
        fn label(&self) -> String {
            "Fake Item".to_string()
        }

        #[zbus(property)]
        fn attributes(&self) -> HashMap<String, String> {
            HashMap::from([("service".to_string(), "fake.example".to_string())])
        }
    }

    struct FakeSession;

    #[interface(name = "org.freedesktop.Secret.Session")]
    impl FakeSession {
        fn close(&self) -> zbus::fdo::Result<()> {
            Ok(())
        }
    }

    const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/default";
    const ITEM_PATH: &str = "/org/freedesktop/secrets/collection/default/1";
    const SESSION_PATH: &str = "/org/freedesktop/secrets/session/source";
    const OTHER_SESSION_PATH: &str = "/org/freedesktop/secrets/session/other";

    async fn start_fake_service(mode: FakeMode) -> Connection {
        let connection = Connection::session().await.unwrap();
        register_fake_root(&connection, mode).await;
        register_fake_collection(&connection, mode).await;
        register_fake_item_and_session(&connection, mode).await;

        connection.request_name(SECRET_SERVICE_BUS).await.unwrap();
        connection
    }

    async fn register_fake_root(connection: &Connection, mode: FakeMode) {
        connection
            .object_server()
            .at(SECRET_SERVICE_PATH, FakeService { mode })
            .await
            .unwrap();
    }

    async fn register_fake_collection(connection: &Connection, mode: FakeMode) {
        if mode == FakeMode::MissingCollectionLabel {
            connection
                .object_server()
                .at(COLLECTION_PATH, FakeCollectionMissingLabel)
                .await
                .unwrap();
            return;
        }

        connection
            .object_server()
            .at(COLLECTION_PATH, FakeCollection)
            .await
            .unwrap();
    }

    async fn register_fake_item_and_session(connection: &Connection, mode: FakeMode) {
        connection
            .object_server()
            .at(ITEM_PATH, FakeItem { mode })
            .await
            .unwrap();
        connection
            .object_server()
            .at(SESSION_PATH, FakeSession)
            .await
            .unwrap();
    }

    fn owned(value: Value<'_>) -> OwnedValue {
        OwnedValue::try_from(value).unwrap()
    }
}
