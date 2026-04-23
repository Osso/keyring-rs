use clap::{Args, Parser, Subcommand};

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
}

fn run_import_gnome(args: &ImportGnomeArgs) {
    let mode = if args.dry_run { "dry-run" } else { "apply" };
    let target = if args.collections.is_empty() {
        "all collections".to_string()
    } else {
        format!("collections: {}", args.collections.join(", "))
    };

    println!("import-gnome command wired ({mode}; {target}); implementation pending");
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::ImportGnome(args) => run_import_gnome(&args),
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
}
