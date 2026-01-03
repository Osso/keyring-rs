use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("Storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("Commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Collection not found: {0}")]
    CollectionNotFound(String),

    #[error("Item not found: {0}")]
    ItemNotFound(u64),

    #[error("Collection is locked")]
    Locked,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("D-Bus error: {0}")]
    DBus(#[from] zbus::Error),
}

pub type Result<T> = std::result::Result<T, KeyringError>;
