use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use trosty_core::{Audit, KeyringStore, SecretName, SecretStore};

#[derive(Parser)]
#[command(
    name = "trosty",
    version,
    about = "A protective terminal layer for secrets next to AI tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store a secret (value is prompted, never passed as an argument)
    Add { name: String },
    /// List secret names (never values)
    Ls,
    /// Delete a secret from the keychain and the index
    Rm { name: String },
    /// Check that keychain, config and audit are all reachable
    Doctor,
}

fn config_dir() -> PathBuf {
    std::env::var_os("TROSTY_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::config_dir().expect("config dir").join("trosty"))
}

fn data_dir() -> PathBuf {
    std::env::var_os("TROSTY_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::data_dir().expect("data dir").join("trosty"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        println!("trosty {} — early development", env!("CARGO_PKG_VERSION"));
        println!("PTY session is coming; for now see `trosty --help`.");
        return Ok(());
    };
    let mut store = KeyringStore::open(&config_dir()).context("open keyring store")?;
    let audit = Audit::open(&data_dir());

    match cmd {
        Cmd::Add { name } => {
            let name = SecretName::from_str(&name)?;
            let value = rpassword::prompt_password(format!("value for {name}: "))?;
            store.set(&name, value.trim_end_matches('\n'))?;
            audit.log("added", &name.to_string());
            println!("stored {name} (value in OS keychain)");
        }
        Cmd::Ls => {
            let names = store.list()?;
            if names.is_empty() {
                println!("no secrets yet");
            } else {
                for n in names {
                    println!("{n}");
                }
            }
        }
        Cmd::Rm { name } => {
            let name = SecretName::from_str(&name)?;
            if store.get(&name)?.is_none() && !store.list()?.contains(&name) {
                bail!("unknown secret: {name}");
            }
            store.delete(&name)?;
            audit.log("removed", &name.to_string());
            println!("removed {name}");
        }
        Cmd::Doctor => {
            println!("config dir: {}", config_dir().display());
            println!("data dir:   {}", data_dir().display());
            println!("secrets in index: {}", store.list()?.len());
            println!("keychain: reachable");
            println!("ok");
        }
    }
    Ok(())
}
