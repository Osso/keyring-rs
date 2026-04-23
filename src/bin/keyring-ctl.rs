#[path = "../crypto.rs"]
mod crypto;
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
        None
    } else {
        Some(import_snapshot_into_default_storage(
            &snapshot,
            args.on_collision,
        )?)
    };

    print_source_snapshot(&snapshot, args, import_summary.as_ref());
    Ok(())
}

fn print_source_snapshot(
    snapshot: &SourceSnapshot,
    args: &ImportGnomeArgs,
    import_summary: Option<&ImportSummary>,
) {
    let total_items: usize = snapshot.collections.iter().map(|c| c.items.len()).sum();
    let mode = if args.dry_run { "dry-run" } else { "apply" };
    println!(
        "Source read complete ({mode}): {} unlocked collection(s), {} item(s)",
        snapshot.collections.len(),
        total_items
    );

    for collection in &snapshot.collections {
        println!(
            "- {} ({}) [{}] {} item(s)",
            collection.name,
            collection.label,
            collection.path.as_str(),
            collection.items.len()
        );
    }

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

    if let Some(summary) = import_summary {
        println!(
            "Imported: {} new collection(s), {} existing collection(s), {} item(s)",
            summary.collections_created, summary.collections_existing, summary.items_created
        );
        println!(
            "Collisions: {} skipped, {} replaced, {} renamed",
            summary.items_skipped, summary.items_replaced, summary.items_renamed
        );
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

        print_source_snapshot(&snapshot, &args, None);
    }
}
