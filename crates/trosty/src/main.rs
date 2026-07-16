use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use trosty_core::{Audit, KeyringStore, MemoryStore, SecretName, SecretStore};

mod hook;
mod session;

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
    /// Run as a Claude Code hook (reads event JSON on stdin), or manage the
    /// hook install in ~/.claude/settings.json.
    Hook {
        #[command(subcommand)]
        action: Option<HookAction>,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Write the three trosty hooks into ~/.claude/settings.json (idempotent)
    Install,
    /// Remove trosty's hooks from ~/.claude/settings.json
    Uninstall,
}

fn config_dir() -> PathBuf {
    std::env::var_os("TROSTY_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs::config_dir().expect("config dir").join("trosty"))
}

fn claude_settings_path() -> PathBuf {
    std::env::var_os("TROSTY_CLAUDE_SETTINGS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .expect("home dir")
                .join(".claude")
                .join("settings.json")
        })
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

/// Parse `TROSTY_SEED_FILE` contents (newline-separated `name=value` pairs,
/// same syntax as `TROSTY_SEED`'s comma-separated pairs) into `store`. Used
/// both at initial open and again on every hot-reload, so the file is the
/// live source of truth for the memory-store test double.
fn load_seed_file(store: &mut MemoryStore, path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read seed file {}", path.display()))?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((n, v)) = line.split_once('=') {
            store.set(&SecretName::from_str(n)?, v)?;
        }
    }
    Ok(())
}

/// Build the secret store, and the path (if any) whose mtime the session
/// should watch for hot-reload: an in-memory store (optionally pre-seeded
/// via `TROSTY_SEED` and/or `TROSTY_SEED_FILE`, tests only) when
/// `TROSTY_MEMORY_STORE` is set, otherwise the real OS keychain watching its
/// `secrets.toml` index. `TROSTY_SEED`/`TROSTY_SEED_FILE` are only honored
/// alongside `TROSTY_MEMORY_STORE` — never let a stray env var seed the real
/// keychain. Calling this again (as the `reload` closure does) re-reads
/// whichever source is live, which is exactly what a hot-reload needs.
fn open_store() -> Result<(Box<dyn SecretStore>, Option<PathBuf>)> {
    if std::env::var_os("TROSTY_MEMORY_STORE").is_some() {
        let mut store = MemoryStore::new();
        if let Ok(seed) = std::env::var("TROSTY_SEED") {
            for pair in seed.split(',') {
                if let Some((n, v)) = pair.split_once('=') {
                    store.set(&SecretName::from_str(n)?, v)?;
                }
            }
        }
        let watch = if let Ok(seed_file) = std::env::var("TROSTY_SEED_FILE") {
            let path = PathBuf::from(seed_file);
            load_seed_file(&mut store, &path)?;
            Some(path)
        } else {
            None
        };
        Ok((Box::new(store), watch))
    } else {
        let watch = config_dir().join("secrets.toml");
        Ok((
            Box::new(KeyringStore::open(&config_dir()).context("open keyring store")?),
            Some(watch),
        ))
    }
}

/// Extract valid `{{name}}` placeholder names from a string.
fn placeholder_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        match after.find("}}") {
            Some(close) => {
                if let Ok(name) = SecretName::from_str(&after[..close]) {
                    names.push(name.to_string());
                }
                rest = &after[close + 2..];
            }
            None => break,
        }
    }
    names
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let (store, watch) = open_store()?;
        let secrets = collect_secrets(store.as_ref())?; // fail-closed before any child spawns
        let projects = trosty_core::ProjectsFile::open(&config_dir())?;
        let audit = Audit::open(&data_dir());
        // Re-opens the store the same way and re-collects — for the memory
        // store this re-reads TROSTY_SEED_FILE; for the keychain it re-reads
        // secrets.toml and re-fetches from the OS keychain.
        let reload = || -> Result<Vec<(SecretName, String)>> {
            let (store, _watch) = open_store()?;
            collect_secrets(store.as_ref())
        };
        let code = session::run(&secrets, &projects, &audit, watch, reload)?;
        std::process::exit(code);
    };
    let (mut store, _watch) = open_store()?;
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
            let events = hook::installed_events(&claude_settings_path());
            println!(
                "claude hooks: {}/3 installed ({})",
                events.len(),
                if events.is_empty() {
                    "-".to_string()
                } else {
                    events.join(", ")
                }
            );
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
                    // Audit names only — the raw arg may embed literal
                    // secret values, which must never reach the log.
                    for name in placeholder_names(arg) {
                        audit.log("expanded", &name);
                    }
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
                            let masked = stream.feed_bytes(&buf[..n]);
                            let _ = w.write_all(&masked);
                        }
                    }
                }
                let _ = w.write_all(&stream.finish_bytes());
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
        Cmd::Hook { action } => match action {
            None => {
                use std::io::Read;
                let mut input = String::new();
                std::io::stdin().read_to_string(&mut input)?;
                let out = hook::dispatch(&input, store.as_ref(), &audit);
                println!("{out}");
            }
            Some(HookAction::Install) => hook::install(&claude_settings_path())?,
            Some(HookAction::Uninstall) => hook::uninstall(&claude_settings_path())?,
        },
    }
    Ok(())
}
