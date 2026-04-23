#[cfg(test)]
#[path = "../access.rs"]
mod access;
#[path = "../crypto.rs"]
mod crypto;
#[cfg(test)]
#[path = "../dbus.rs"]
mod dbus;
#[path = "keyring_ctl/destination_import.rs"]
mod destination_import;
#[path = "../error.rs"]
mod error;
#[path = "keyring_ctl/source_reader.rs"]
mod source_reader;
#[path = "../storage.rs"]
mod storage;

use clap::{Args, Parser, Subcommand};
use destination_import::{
    CollisionPolicy, DestinationImportError, ImportSummary, import_snapshot_into_default_storage,
};
use source_reader::{SourceSnapshot, read_secret_service_source};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "keyring-ctl",
    version,
    about = "Maintenance and migration commands for keyring-rs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Import secrets from an active Secret Service implementation (for example gnome-keyring).
    ImportGnome(ImportGnomeArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
struct ImportGnomeArgs {
    /// Show what would be imported without writing destination storage.
    #[arg(long)]
    dry_run: bool,

    /// Restrict import to one or more source collections (repeatable).
    #[arg(long = "collection", value_name = "NAME")]
    collections: Vec<String>,

    /// Policy when an item with the same label+attributes already exists.
    #[arg(long = "on-collision", value_enum, default_value_t = CollisionPolicy::Skip)]
    on_collision: CollisionPolicy,
}

#[derive(Debug, Error)]
enum ImportGnomeError {
    #[error("{0}")]
    Source(#[from] source_reader::SourceReaderError),
    #[error("{0}")]
    Destination(#[from] DestinationImportError),
}

async fn run_import_gnome(args: &ImportGnomeArgs) -> Result<(), ImportGnomeError> {
    let snapshot = read_secret_service_source(&args.collections).await?;
    let import_summary = if args.dry_run {
        ImportSummary::for_dry_run(&snapshot)
    } else {
        import_snapshot_into_default_storage(&snapshot, args.on_collision)?
    };

    print_source_snapshot(&snapshot, args, &import_summary);
    Ok(())
}

fn print_source_snapshot(
    snapshot: &SourceSnapshot,
    args: &ImportGnomeArgs,
    import_summary: &ImportSummary,
) {
    let total_items: usize = snapshot.collections.iter().map(|c| c.items.len()).sum();
    let mode = if args.dry_run { "dry-run" } else { "apply" };
    println!(
        "Source read complete ({mode}): {} unlocked collection(s), {} item(s)",
        snapshot.collections.len(),
        total_items
    );

    print_collection_summary(snapshot);
    print_snapshot_filters(snapshot);
    print_migration_audit(import_summary);
}

fn print_collection_summary(snapshot: &SourceSnapshot) {
    for collection in &snapshot.collections {
        println!(
            "- {} ({}) [{}] {} item(s)",
            collection.name,
            collection.label,
            collection.path.as_str(),
            collection.items.len()
        );
    }
}

fn print_snapshot_filters(snapshot: &SourceSnapshot) {
    if !snapshot.skipped_locked_collections.is_empty() {
        println!(
            "Skipped locked collections: {}",
            snapshot.skipped_locked_collections.join(", ")
        );
    }

    if !snapshot.skipped_filtered_collections.is_empty() {
        println!(
            "Skipped by --collection filter: {}",
            snapshot.skipped_filtered_collections.join(", ")
        );
    }
}

fn print_migration_audit(import_summary: &ImportSummary) {
    println!(
        "Imported: {} new collection(s), {} existing collection(s)",
        import_summary.collections_created, import_summary.collections_existing
    );
    println!(
        "Migration audit: scanned={}, imported={}, skipped={}, failed={}",
        import_summary.items_scanned,
        import_summary.items_imported,
        import_summary.items_skipped,
        import_summary.items_failed
    );
    println!(
        "Collision outcomes: replaced={}, renamed={}",
        import_summary.items_replaced, import_summary.items_renamed
    );
    if !import_summary.failed_items.is_empty() {
        println!("Failure details:");
        for failure in &import_summary.failed_items {
            println!(
                "- [{}/{}] {}: {}",
                failure.collection, failure.label, failure.path, failure.reason
            );
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::ImportGnome(args) => run_import_gnome(&args).await,
    };

    if let Err(error) = result {
        eprintln!("import-gnome failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;
    use tokio::time::sleep;

    fn parse_import(args: &[&str]) -> ImportGnomeArgs {
        let cli = Cli::try_parse_from(args).expect("import-gnome args should parse");
        match cli.command {
            Commands::ImportGnome(import) => import,
        }
    }

    #[test]
    fn import_gnome_defaults() {
        let args = parse_import(&["keyring-ctl", "import-gnome"]);
        assert!(!args.dry_run);
        assert!(args.collections.is_empty());
        assert_eq!(args.on_collision, CollisionPolicy::Skip);
    }

    #[test]
    fn import_gnome_accepts_dry_run_flag() {
        let args = parse_import(&["keyring-ctl", "import-gnome", "--dry-run"]);
        assert!(args.dry_run);
        assert!(args.collections.is_empty());
    }

    #[test]
    fn import_gnome_accepts_multiple_collection_filters() {
        let args = parse_import(&[
            "keyring-ctl",
            "import-gnome",
            "--collection",
            "default",
            "--collection",
            "login",
        ]);
        assert_eq!(args.collections, vec!["default", "login"]);
    }

    #[test]
    fn import_gnome_accepts_collision_policy_flag() {
        let args = parse_import(&["keyring-ctl", "import-gnome", "--on-collision", "rename"]);
        assert_eq!(args.on_collision, CollisionPolicy::Rename);
    }

    #[test]
    fn print_source_snapshot_shows_collection_counts() {
        let snapshot = SourceSnapshot {
            collections: vec![source_reader::SourceCollection {
                name: "default".to_string(),
                label: "Default".to_string(),
                path: zbus::zvariant::OwnedObjectPath::try_from(
                    "/org/freedesktop/secrets/collection/default",
                )
                .unwrap(),
                items: vec![source_reader::SourceItem {
                    path: zbus::zvariant::OwnedObjectPath::try_from(
                        "/org/freedesktop/secrets/collection/default/1",
                    )
                    .unwrap(),
                    label: "Item".to_string(),
                    attributes: std::collections::HashMap::new(),
                    secret: b"secret".to_vec(),
                    content_type: "text/plain".to_string(),
                }],
            }],
            skipped_locked_collections: vec!["login".to_string()],
            skipped_filtered_collections: vec![],
        };
        let args = ImportGnomeArgs {
            dry_run: true,
            collections: vec![],
            on_collision: CollisionPolicy::Skip,
        };

        let summary = ImportSummary::for_dry_run(&snapshot);
        print_source_snapshot(&snapshot, &args, &summary);
    }

    #[tokio::test]
    #[ignore = "requires dbus-run-session"]
    async fn import_round_trip_lookup_from_seeded_source_service() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source.db");
        let destination_db_path = dir.path().join("destination.db");

        let attrs = HashMap::from([
            ("service".to_string(), "import-smoke".to_string()),
            ("user".to_string(), "alice".to_string()),
        ]);

        let mut source_storage = storage::Storage::open(&source_db_path).unwrap();
        source_storage.unlock("source-password").unwrap();
        source_storage
            .create_collection("default", "Source Default")
            .unwrap();
        source_storage
            .create_item(
                "default",
                "Imported Item",
                b"imported-secret",
                attrs.clone(),
            )
            .unwrap();

        let source_storage = Arc::new(RwLock::new(source_storage));
        let source_access = Arc::new(access::AccessControl::new(false));
        let source_connection = dbus::start_service(source_storage, source_access)
            .await
            .unwrap();

        let snapshot = wait_for_source_snapshot(1, 1).await;
        assert_eq!(snapshot.collections.len(), 1);
        assert_eq!(snapshot.collections[0].items.len(), 1);

        drop(source_connection);
        sleep(Duration::from_millis(50)).await;

        let summary = destination_import::import_snapshot_into_storage(
            &snapshot,
            &destination_db_path,
            "destination-password",
            CollisionPolicy::Skip,
        )
        .unwrap();
        assert_eq!(summary.items_scanned, 1);
        assert_eq!(summary.items_imported, 1);
        assert_eq!(summary.items_failed, 0);

        let mut destination_storage = storage::Storage::open(&destination_db_path).unwrap();
        destination_storage.unlock("destination-password").unwrap();

        let imported_ids = destination_storage.search_items(&attrs).unwrap();
        assert_eq!(imported_ids.len(), 1);
        let imported_item = destination_storage
            .get_item(imported_ids[0])
            .unwrap()
            .unwrap();
        assert_eq!(imported_item.label, "Imported Item");
        assert_eq!(imported_item.secret, b"imported-secret");
        assert_eq!(imported_item.attributes, attrs);
    }

    async fn wait_for_source_snapshot(
        expected_collections: usize,
        expected_items: usize,
    ) -> SourceSnapshot {
        const MAX_ATTEMPTS: usize = 50;
        const POLL_DELAY: Duration = Duration::from_millis(50);
        let mut last_observation = String::from("none");

        for _ in 0..MAX_ATTEMPTS {
            match read_secret_service_source(&Vec::new()).await {
                Ok(snapshot) => {
                    let item_count: usize =
                        snapshot.collections.iter().map(|c| c.items.len()).sum();
                    last_observation = format!(
                        "snapshot collections={} items={}",
                        snapshot.collections.len(),
                        item_count
                    );
                    if snapshot.collections.len() >= expected_collections
                        && item_count >= expected_items
                    {
                        return snapshot;
                    }
                }
                Err(error) => {
                    last_observation = format!("error: {error}");
                }
            }
            sleep(POLL_DELAY).await;
        }

        panic!(
            "source service did not expose expected collections and items in time (last observation: {last_observation})"
        );
    }
}
