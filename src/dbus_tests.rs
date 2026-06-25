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
    let invalid = OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap();

    assert_eq!(item_id_from_object_path(&valid), Some(42));
    assert_eq!(item_id_from_object_path(&invalid), None);
}

#[tokio::test]
#[ignore = "requires dbus-run-session"]
async fn direct_service_methods_cover_locked_search_lock_and_alias_branches() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);
    storage
        .create_item("default", "Email", b"secret", attrs.clone())
        .unwrap();
    storage.lock();

    let storage = Arc::new(RwLock::new(storage));
    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let connection = Connection::session().await.unwrap();
    let service = SecretService::new(
        storage.clone(),
        sessions.clone(),
        Arc::new(AccessControl::new(false)),
        connection.clone(),
    );
    let default_path =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap();

    let (unlocked, locked) = service.search_items(attrs.clone()).await.unwrap();
    assert!(unlocked.is_empty());
    assert_eq!(locked.len(), 1);

    let (unlocked, prompt_path) = service.unlock(vec![default_path.clone()]).await.unwrap();
    assert!(unlocked.is_empty());
    assert_ne!(prompt_path.as_str(), ROOT_PROMPT_PATH);

    storage.write().await.unlock("test-password").unwrap();
    let (unlocked, prompt_path) = service.unlock(vec![default_path.clone()]).await.unwrap();
    assert_eq!(unlocked, vec![default_path.clone()]);
    assert_eq!(prompt_path.as_str(), ROOT_PROMPT_PATH);

    let (locked_objects, prompt_path) = service.lock(vec![default_path.clone()]).await.unwrap();
    assert_eq!(locked_objects, vec![default_path.clone()]);
    assert_eq!(prompt_path.as_str(), ROOT_PROMPT_PATH);

    storage.write().await.unlock("test-password").unwrap();
    assert_eq!(
        service.read_alias("default").await.unwrap().as_str(),
        default_path.as_str()
    );
    assert_eq!(
        service.read_alias("missing").await.unwrap().as_str(),
        ROOT_PROMPT_PATH
    );
    service
        .set_alias("favorite", default_path.clone())
        .await
        .unwrap();
    assert_eq!(
        service.read_alias("favorite").await.unwrap().as_str(),
        default_path.as_str()
    );
    let missing_collection =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/missing").unwrap();
    assert!(service.set_alias("bad", missing_collection).await.is_err());

    let collection = SecretCollection::new(storage, sessions, "default".to_string(), connection);
    let paths = collection.search_items(attrs).await.unwrap();
    assert_eq!(paths.len(), 1);
    assert!(paths[0].as_str().contains("/collection/default/"));
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
fn dh_decrypt_rejects_wrong_iv_length() {
    let key = [7u8; DH_AES_KEY_SIZE];
    let error = decrypt_dh_secret(b"ciphertext", &[1, 2, 3], &key).expect_err("short iv must fail");

    assert!(matches!(error, zbus::fdo::Error::InvalidArgs(_)));
}

#[test]
fn parse_dh_public_key_rejects_invalid_inputs() {
    let wrong_type = parse_dh_public_key(Value::from("not-bytes"))
        .expect_err("string value must not parse as DH bytes");
    assert!(matches!(wrong_type, zbus::fdo::Error::InvalidArgs(_)));

    let empty_bytes =
        parse_dh_public_key(Value::from(Vec::<u8>::new())).expect_err("empty public key must fail");
    assert!(matches!(empty_bytes, zbus::fdo::Error::InvalidArgs(_)));
}

#[test]
fn derive_dh_aes_key_rejects_out_of_range_public_keys() {
    let private_key = BigUint::from(2u8);
    let prime = BigUint::from_bytes_be(&DH_GROUP_PRIME_BYTES);
    let p_minus_one = &prime - BigUint::from(1u8);

    let too_small = derive_dh_aes_key(&BigUint::from(1u8), &private_key)
        .expect_err("public key <= 1 must fail");
    assert!(matches!(too_small, zbus::fdo::Error::InvalidArgs(_)));

    let too_large = derive_dh_aes_key(&p_minus_one, &private_key).expect_err("p - 1 must fail");
    assert!(matches!(too_large, zbus::fdo::Error::InvalidArgs(_)));
}

#[test]
fn extract_prompt_password_rejects_empty_password_token() {
    assert_eq!(extract_prompt_password("password:"), None);
}

#[tokio::test]
async fn map_item_or_default_returns_item_field_or_default() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let item_id = storage
        .create_item(
            "default",
            "Email",
            b"secret",
            HashMap::from([("service".to_string(), "mail".to_string())]),
        )
        .unwrap();
    let storage = Arc::new(RwLock::new(storage));

    let label = map_item_or_default(&storage, item_id, |item| item.label, String::new()).await;
    let missing =
        map_item_or_default(&storage, item_id + 1, |item| item.label, "fallback".into()).await;

    assert_eq!(label, "Email");
    assert_eq!(missing, "fallback");
}

#[tokio::test]
async fn create_or_replace_collection_item_replaces_matching_items() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);
    storage
        .create_item("default", "Old", b"old", attrs.clone())
        .unwrap();
    let storage = Arc::new(RwLock::new(storage));

    let new_id =
        create_or_replace_collection_item(&storage, "default", "New", attrs.clone(), true, b"new")
            .await
            .unwrap();
    let storage = storage.read().await;
    let matches = storage.search_items(&attrs).unwrap();

    assert_eq!(matches, vec![new_id]);
    assert_eq!(storage.get_item(new_id).unwrap().unwrap().secret, b"new");
}

#[test]
fn replace_item_secret_preserves_metadata_with_new_secret() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let attrs = HashMap::from([("service".to_string(), "mail".to_string())]);
    let item_id = storage
        .create_item("default", "Email", b"old", attrs.clone())
        .unwrap();

    replace_item_secret(&storage, item_id, "default", b"new").unwrap();

    let matches = storage.search_items(&attrs).unwrap();
    assert_eq!(matches.len(), 1);
    let item = storage.get_item(matches[0]).unwrap().unwrap();
    assert_eq!(item.label, "Email");
    assert_eq!(item.attributes, attrs);
    assert_eq!(item.secret, b"new");
}

#[test]
fn secret_for_item_id_returns_none_for_missing_item_and_secret_for_existing() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let item_id = storage
        .create_item("default", "Email", b"secret", HashMap::new())
        .unwrap();
    let session = OwnedObjectPath::try_from("/").unwrap();

    let missing =
        secret_for_item_id(&storage, item_id + 1, &session, &SessionEncryption::Plain).unwrap();
    let secret =
        secret_for_item_id(&storage, item_id, &session, &SessionEncryption::Plain).unwrap();

    assert!(missing.is_none());
    assert_eq!(secret.unwrap().2, b"secret");
}

#[test]
fn negotiate_session_open_accepts_plain_inputs_and_rejects_unknown_algorithm() {
    let (encryption, output) = negotiate_session_open(ALGORITHM_PLAIN, Value::from(""))
        .expect("empty string is valid plain input");
    assert!(matches!(encryption, SessionEncryption::Plain));
    assert_eq!(String::try_from(output).unwrap(), "");

    let (encryption, output) =
        negotiate_session_open(ALGORITHM_PLAIN, Value::from(Vec::<u8>::new()))
            .expect("empty byte array is valid plain input");
    assert!(matches!(encryption, SessionEncryption::Plain));
    assert_eq!(String::try_from(output).unwrap(), "");

    let unsupported = match negotiate_session_open("unsupported", Value::from("")) {
        Ok(_) => panic!("unknown algorithm must fail"),
        Err(error) => error,
    };
    assert!(matches!(unsupported, zbus::fdo::Error::NotSupported(_)));
}

#[tokio::test]
async fn secret_item_set_secret_and_delete_update_storage() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    let item_id = storage
        .create_item("default", "Email", b"old", HashMap::new())
        .unwrap();
    let storage = Arc::new(RwLock::new(storage));
    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let item = SecretItem::new(storage.clone(), sessions, "default".to_string(), item_id);

    item.set_secret((
        OwnedObjectPath::try_from("/").unwrap(),
        Vec::new(),
        b"new".to_vec(),
        "text/plain".to_string(),
    ))
    .await
    .unwrap();
    let updated_id = {
        let storage = storage.read().await;
        let updated = storage
            .search_items(&HashMap::new())
            .unwrap()
            .into_iter()
            .find_map(|id| storage.get_item(id).unwrap())
            .unwrap();
        assert_eq!(updated.secret, b"new");
        updated.id
    };

    let updated_item = SecretItem::new(
        storage.clone(),
        Arc::new(RwLock::new(HashMap::new())),
        "default".to_string(),
        updated_id,
    );
    updated_item.delete().await.unwrap();
    let storage = storage.read().await;
    assert!(storage.list_item_locations().unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires dbus-run-session"]
async fn prompt_completion_reports_dismissed_without_password_and_empty_on_bad_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = Storage::open(dir.path().join("test.db")).unwrap();
    storage.unlock("test-password").unwrap();
    storage.create_collection("default", "Default").unwrap();
    storage.lock();
    let storage = Arc::new(RwLock::new(storage));
    let connection = Connection::session().await.unwrap();
    let objects =
        vec![OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default").unwrap()];
    let prompt = SecretPrompt::new(storage, connection, root_prompt_path(), objects);

    let (dismissed, unlocked) = prompt.completion_from_unlock("").await;
    assert!(dismissed);
    assert!(unlocked.is_empty());

    let (dismissed, unlocked) = prompt.completion_from_unlock("password:wrong").await;
    assert!(!dismissed);
    assert!(unlocked.is_empty());
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
    let work_path = OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work").unwrap();
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
