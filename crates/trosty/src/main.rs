use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use trosty_core::{Audit, KeyringStore, MemoryStore, SecretName, SecretStore};

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
    /// Import a .env file into a project namespace (values go to the keychain)
    Import {
        file: PathBuf,
        #[arg(long)]
        project: String,
    },
    /// Run a command with {{name}} expanded; its output is masked back
    Exec {
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
}

fn config_dir() -> PathBuf {
    std::env::var_os("TROSTY_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::config_dir().expect("config dir").join("trosty"))
}

/// Read every secret currently in the store's index, failing closed if any
/// value can't be read: a masking pipeline that silently drops a secret it
/// can't reach would let it through the child process unmasked, which is
/// worse than refusing to run at all.
fn collect_secrets(store: &dyn SecretStore) -> Result<Vec<(SecretName, String)>> {
    let mut secrets = Vec::new();
    for name in store.list()? {
        match store.get(&name)? {
            Some(value) => secrets.push((name, value)),
            None => bail!("secret {name} in index but unreadable from keychain — refusing to run"),
        }
    }
    Ok(secrets)
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
    let mut store: Box<dyn SecretStore> = if std::env::var_os("TROSTY_MEMORY_STORE").is_some() {
        Box::new(MemoryStore::new())
    } else {
        Box::new(KeyringStore::open(&config_dir()).context("open keyring store")?)
    };
    let audit = Audit::open(&data_dir());

    if std::env::var_os("TROSTY_MEMORY_STORE").is_some() {
        if let Ok(seed) = std::env::var("TROSTY_SEED") {
            for pair in seed.split(',') {
                if let Some((n, v)) = pair.split_once('=') {
                    store.set(&SecretName::from_str(n)?, v)?;
                }
            }
        }
    }

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
        Cmd::Import { file, project } => {
            let content = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let file = std::fs::canonicalize(&file)
                .with_context(|| format!("canonicalize {}", file.display()))?;
            let dir = file
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_default();
            let mut imported = 0usize;
            for (key, value) in trosty_core::parse_env(&content) {
                let name = SecretName::from_str(&format!("{project}/{key}"))?;
                match store.set(&name, &value) {
                    Ok(()) => {
                        audit.log("imported", &name.to_string());
                        println!("imported {name}");
                        imported += 1;
                    }
                    Err(trosty_core::CoreError::TooShort) => {
                        println!("skipped {key} (too short)");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            let mut projects = trosty_core::ProjectsFile::open(&config_dir())?;
            projects.set(&dir, &project)?;
            println!("{imported} secrets → namespace {project}/, project dir registered");
        }
        Cmd::Exec { cmd } => {
            let mut expanded = Vec::with_capacity(cmd.len());
            for arg in &cmd {
                let e = trosty_core::expand(arg, store.as_ref())?;
                if e != *arg {
                    audit.log("expanded", arg);
                }
                expanded.push(e);
            }
            let secrets = collect_secrets(store.as_ref())?;
            let scrubber = trosty_core::Scrubber::new(&secrets);
            let (program, args) = expanded.split_first().expect("clap requires cmd");
            let mut child = std::process::Command::new(program)
                .args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .with_context(|| format!("spawn {program}"))?;

            use std::io::Read;
            let mask_pipe = |mut r: Box<dyn Read>, mut w: Box<dyn std::io::Write>| {
                let mut stream = scrubber.stream();
                let mut buf = [0u8; 8192];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            let masked = stream.feed(&text);
                            let _ = w.write_all(masked.as_bytes());
                        }
                    }
                }
                let _ = w.write_all(stream.finish().as_bytes());
                let _ = w.flush();
            };
            let stdout = child.stdout.take().expect("piped");
            let stderr = child.stderr.take().expect("piped");
            std::thread::scope(|s| {
                s.spawn(|| mask_pipe(Box::new(stdout), Box::new(std::io::stdout())));
                s.spawn(|| mask_pipe(Box::new(stderr), Box::new(std::io::stderr())));
            });
            let status = child.wait()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    Ok(())
}
