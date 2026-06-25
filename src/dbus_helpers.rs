use super::*;

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

pub(super) fn item_object_path(collection: &str, id: u64) -> zbus::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{}/{}",
        collection, id
    ))
    .map_err(|e| zbus::Error::Failure(e.to_string()))
}

pub(super) fn collection_object_path(collection: &str) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(format!(
        "/org/freedesktop/secrets/collection/{}",
        collection
    ))
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
}

pub(super) fn collection_name_from_path(path: &str) -> Option<Option<String>> {
    if path == ROOT_PROMPT_PATH {
        return Some(None);
    }

    let collection_name = path.strip_prefix("/org/freedesktop/secrets/collection/")?;
    if collection_name.is_empty() || collection_name.contains('/') {
        return None;
    }

    Some(Some(collection_name.to_string()))
}

pub(super) async fn register_default_collection_objects(
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

pub(super) fn extract_item_properties(
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

pub(super) fn replace_item_secret(
    storage: &Storage,
    item_id: u64,
    collection_name: &str,
    decoded_secret: &[u8],
) -> zbus::fdo::Result<()> {
    let existing = load_item_for_secret_update(storage, item_id)?;
    recreate_item_with_secret(storage, item_id, collection_name, existing, decoded_secret)
}

pub(super) fn load_item_for_secret_update(
    storage: &Storage,
    item_id: u64,
) -> zbus::fdo::Result<crate::storage::DecryptedItem> {
    storage
        .get_item(item_id)
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
        .ok_or_else(|| zbus::fdo::Error::Failed("Item not found".into()))
}

pub(super) fn recreate_item_with_secret(
    storage: &Storage,
    item_id: u64,
    collection_name: &str,
    existing: crate::storage::DecryptedItem,
    decoded_secret: &[u8],
) -> zbus::fdo::Result<()> {
    storage
        .delete_item(item_id)
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    storage
        .create_item(
            collection_name,
            &existing.label,
            decoded_secret,
            existing.attributes,
        )
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

    Ok(())
}

pub(super) async fn create_or_replace_collection_item(
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

pub(super) fn delete_matching_items(
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

pub(super) async fn register_collection_item_path(
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

pub(super) fn root_prompt_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(ROOT_PROMPT_PATH).unwrap()
}

pub(super) async fn load_collections(
    storage: &Arc<RwLock<Storage>>,
) -> Vec<crate::storage::Collection> {
    let storage: RwLockReadGuard<'_, Storage> = storage.read().await;
    storage.list_collections().unwrap_or_default()
}

pub(super) fn collection_paths(collections: &[crate::storage::Collection]) -> Vec<OwnedObjectPath> {
    collections
        .iter()
        .filter_map(|collection| collection_object_path(&collection.name).ok())
        .collect()
}

pub(super) fn item_id_from_object_path(path: &OwnedObjectPath) -> Option<u64> {
    path.as_str().rsplit('/').next()?.parse::<u64>().ok()
}

pub(super) fn secret_for_item_id(
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

pub(super) async fn register_item_object(
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

pub(super) async fn unregister_item_object(
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

pub(super) async fn unregister_collection_object(
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

pub(super) async fn register_existing_item_objects(
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

pub(super) async fn register_unlock_prompt(
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

pub(super) fn prompt_object_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!(
        "{}/prompt{}",
        PROMPT_PATH_PREFIX,
        rand::random::<u64>()
    ))
    .expect("prompt path format is valid")
}

pub(super) fn session_object_path() -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{}/{}", SESSION_PATH_PREFIX, rand::random::<u64>()))
        .expect("session path format is valid")
}

pub(super) fn negotiate_session_open(
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

pub(super) fn open_plain_session(
    input: Value<'_>,
) -> zbus::fdo::Result<(SessionEncryption, OwnedValue)> {
    validate_plain_session_input(&input)?;
    Ok((
        SessionEncryption::Plain,
        OwnedValue::try_from(Value::new(String::new())).unwrap(),
    ))
}

pub(super) fn open_dh_session(
    input: Value<'_>,
) -> zbus::fdo::Result<(SessionEncryption, OwnedValue)> {
    let (encryption, service_public_key) = negotiate_dh_session_encryption(input)?;
    let output = OwnedValue::try_from(Value::new(service_public_key))
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    Ok((encryption, output))
}

pub(super) async fn register_session_object(
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

pub(super) fn validate_plain_session_input(input: &Value<'_>) -> zbus::fdo::Result<()> {
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

pub(super) fn negotiate_dh_session_encryption(
    input: Value<'_>,
) -> zbus::fdo::Result<(SessionEncryption, Vec<u8>)> {
    let client_public_key = parse_dh_public_key(input)?;
    let (private_key, service_public_key) = generate_dh_keypair();
    let key = derive_dh_aes_key(&client_public_key, &private_key)?;
    Ok((SessionEncryption::Dh { key }, service_public_key))
}

pub(super) fn parse_dh_public_key(input: Value<'_>) -> zbus::fdo::Result<BigUint> {
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

pub(super) fn generate_dh_keypair() -> (BigUint, Vec<u8>) {
    let prime = BigUint::from_bytes_be(&DH_GROUP_PRIME_BYTES);
    let generator = BigUint::from(DH_GENERATOR);

    let mut private_key_bytes = [0u8; DH_SHARED_SECRET_SIZE];
    OsRng.fill_bytes(&mut private_key_bytes);
    let private_key = BigUint::from_bytes_be(&private_key_bytes);
    let public_key = generator.modpow(&private_key, &prime).to_bytes_be();

    (private_key, public_key)
}

pub(super) fn derive_dh_aes_key(
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

pub(super) async fn resolve_session_encryption(
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

pub(super) async fn decode_secret_for_storage(
    sessions: &Arc<RwLock<SessionMap>>,
    secret: &Secret,
) -> zbus::fdo::Result<Vec<u8>> {
    let session = resolve_session_encryption(sessions, secret.0.as_str()).await?;
    decode_secret_bytes(&session, &secret.1, &secret.2)
}

pub(super) fn decode_secret_bytes(
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

pub(super) fn encode_secret_for_transport(
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

pub(super) fn encrypt_dh_secret(
    secret: &[u8],
    key: &[u8; DH_AES_KEY_SIZE],
) -> zbus::fdo::Result<(Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; DH_IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    let ciphertext = Aes128CbcEnc::<Aes128>::new(key.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(secret);
    Ok((iv.to_vec(), ciphertext))
}

pub(super) fn decrypt_dh_secret(
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

pub(super) fn request_prompt_password(window_id: &str) -> Option<String> {
    if !confirm_prompt_via_authd(window_id) {
        return None;
    }

    extract_prompt_password(window_id)
}

pub(super) fn extract_prompt_password(window_id: &str) -> Option<String> {
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

#[cfg(not(coverage))]
pub(super) fn confirm_prompt_via_authd(window_id: &str) -> bool {
    confirm_prompt_via_authd_sync(window_id)
}

#[cfg(coverage)]
pub(super) fn confirm_prompt_via_authd(_window_id: &str) -> bool {
    true
}

#[cfg(not(coverage))]
pub(super) fn confirm_prompt_via_authd_sync(window_id: &str) -> bool {
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
        prompt_title: Some("Unlock keyring".to_string()),
        prompt_message: Some("A session is requesting keyring unlock".to_string()),
        prompt_detail: Some(format!("Window id: {window_id}")),
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

pub(super) async fn caller_pid(connection: &Connection, sender: &str) -> Option<u32> {
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

pub(super) async fn check_sender_access(
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

pub(super) async fn map_item_or_default<T, F>(
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
