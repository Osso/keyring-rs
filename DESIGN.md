# keyring-daemon Design Document

## Overview

Minimal Rust replacement for gnome-keyring-daemon, implementing the freedesktop.org Secret Service D-Bus API.

## Goals

- Drop-in replacement for gnome-keyring-daemon's secret storage
- Compatible with existing tools (secret-tool, libsecret clients)
- Simple, auditable codebase
- Modern encryption (age/ChaCha20-Poly1305)

## Non-Goals (v0.1)

- SSH agent functionality
- GPG agent functionality
- PAM integration
- PKCS#11 module
- Import existing gnome-keyring files

## Architecture

```
┌─────────────────┐     D-Bus (session bus)      ┌──────────────────┐
│  secret-tool    │◄────────────────────────────►│                  │
│  Chrome         │   org.freedesktop.secrets    │  keyring-daemon  │
│  libsecret apps │                              │                  │
└─────────────────┘                              └────────┬─────────┘
                                                          │
                                                          ▼
                                                 ┌──────────────────┐
                                                 │  ~/.local/share/ │
                                                 │  keyring-rs/     │
                                                 │  secrets.db      │
                                                 └──────────────────┘
```

## D-Bus Interface

### Service Name
`org.freedesktop.secrets`

### Object Paths
- `/org/freedesktop/secrets` - Service object
- `/org/freedesktop/secrets/collection/{name}` - Collection objects
- `/org/freedesktop/secrets/collection/{name}/{id}` - Item objects
- `/org/freedesktop/secrets/session/{id}` - Session objects
- `/org/freedesktop/secrets/aliases/default` - Alias to default collection

### Interfaces

#### org.freedesktop.Secret.Service
- `OpenSession(algorithm, input) → (output, session_path)`
- `CreateCollection(properties, alias) → (collection_path, prompt_path)`
- `SearchItems(attributes) → (unlocked[], locked[])`
- `Unlock(objects[]) → (unlocked[], prompt_path)`
- `Lock(objects[]) → (locked[], prompt_path)`
- `GetSecrets(items[], session) → secrets{}`
- `ReadAlias(name) → collection_path`
- `SetAlias(name, collection)`

#### org.freedesktop.Secret.Collection
- `SearchItems(attributes) → items[]`
- `CreateItem(properties, secret, replace) → (item_path, prompt_path)`
- `Delete() → prompt_path`
- Properties: `Items`, `Label`, `Locked`, `Created`, `Modified`

#### org.freedesktop.Secret.Item
- `GetSecret(session) → secret`
- `SetSecret(secret)`
- `Delete() → prompt_path`
- Properties: `Locked`, `Attributes`, `Label`, `Created`, `Modified`

#### org.freedesktop.Secret.Session
- `Close()`

#### org.freedesktop.Secret.Prompt
- `Prompt(window_id)`
- `Dismiss()`
- Signal: `Completed(dismissed, result)`

## Session Encryption

The Secret Service spec supports encrypted transport:
- `plain` - no encryption (secrets sent in cleartext over D-Bus)
- `dh-ietf1024-sha256-aes128-cbc-pkcs7` - DH key exchange + AES

For v0.1: Support `plain` only (D-Bus is local and permission-controlled).

## Storage Format

Pure Rust using redb (embedded key-value store) + ChaCha20-Poly1305 encryption.

### Database Structure (redb tables)

```rust
// Table definitions
const COLLECTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("collections");
const ITEMS: TableDefinition<u64, &[u8]> = TableDefinition::new("items");
const ATTRIBUTES: TableDefinition<(u64, &str), &str> = TableDefinition::new("attributes");
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
```

### Data Structures

```rust
struct Collection {
    name: String,
    label: String,
    created: u64,
    modified: u64,
    item_ids: Vec<u64>,
}

struct Item {
    id: u64,
    collection: String,
    label: String,
    secret: Vec<u8>,      // encrypted with ChaCha20-Poly1305
    nonce: [u8; 12],      // unique per-item
    created: u64,
    modified: u64,
}

struct Attribute {
    item_id: u64,
    name: String,
    value: String,
}
```

## Encryption

- Master key derived from password via Argon2id (memory-hard)
- Secrets encrypted with ChaCha20-Poly1305 (AEAD)
- Each secret has unique 12-byte nonce
- Salt stored in metadata table

## Unlock Flow

1. Client calls `Unlock([collection_path])`
2. Daemon returns prompt path
3. Client calls `Prompt(window_id)` on prompt
4. Daemon spawns password dialog (via xdg-desktop-portal or custom)
5. User enters password
6. Daemon derives key, unlocks collection
7. Prompt emits `Completed(false, [collection_path])`

## Dependencies (pure Rust)

- `zbus` - D-Bus implementation
- `redb` - Embedded key-value database
- `chacha20poly1305` - AEAD encryption
- `argon2` - Password hashing (memory-hard KDF)
- `tokio` - Async runtime
- `serde` - Serialization for storage

## File Locations

- `~/.local/share/keyring-rs/secrets.db` - Encrypted database
- `~/.config/keyring-rs/config.toml` - Configuration (optional)
- `/run/user/$UID/keyring-rs/` - Runtime socket/control files

## Open Questions

1. Password prompt mechanism - portal vs custom dialog vs env var?
2. Auto-lock on idle?
3. Multiple collections or single "default" only?
4. Should we support the DH session encryption?
