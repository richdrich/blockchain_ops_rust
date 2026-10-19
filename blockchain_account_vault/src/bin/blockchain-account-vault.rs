//! `blockchain-account-vault`: create an account key file, seal a directory of key files under a
//! password, open one to standard output, or print the paper backups.
//!
//! ```text
//! blockchain-account-vault create <FILE.json> [--prefix <CHARS>] [--same-password-as <FILE.enc>] [--plain] [--threads <N>]
//! blockchain-account-vault seal <DIR> [--recursive] [--same-password-as <FILE.enc>]
//! blockchain-account-vault open <FILE> [--field <NAME>]
//! blockchain-account-vault print <DIR> --out <FILE.pdf> [--recursive]
//! ```
//!
//! The password is read from the terminal without echo. With no terminal on
//! standard input it is read as one line from standard input instead, so a
//! script can supply it.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use blockchain_account_vault::account::{
    expected_tries, find_vanity_account, generate_account, normalise_prefix,
};
use blockchain_account_vault::pdf::render_backup_pdf;
use blockchain_account_vault::vault::{
    KeyFile, Vault, backup_page, discover, json_field, write_new_plain,
};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "blockchain-account-vault",
    version,
    about = "Password-sealed key files and their paper backups"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new Algorand account key file, sealed unless --plain, and print its address
    Create(CreateArgs),
    /// Encrypt every unsealed key file (*.json, *.key) in a directory and delete the plaintext
    Seal(SealArgs),
    /// Write one key file's plaintext to standard output, decrypting it if it is sealed
    Open(OpenArgs),
    /// Render a backup sheet (QR code + mnemonic) for every key file in a directory
    Print(PrintArgs),
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// The key file to create, named by its plaintext form (e.g. accounts/ROLE.json); its directory must exist
    file: PathBuf,

    /// Search for an address starting with these characters (A-Z, 2-7; each one makes the search 32 times longer)
    #[arg(long, value_name = "CHARS")]
    prefix: Option<String>,

    /// A sealed file the password must also open, so the new file is under the same password as it
    #[arg(
        long = "same-password-as",
        value_name = "FILE.enc",
        conflicts_with = "plain"
    )]
    same_password_as: Option<PathBuf>,

    /// Write the key file in the clear instead of sealing it
    #[arg(long)]
    plain: bool,

    /// Threads for the prefix search (default: one per core)
    #[arg(long, value_name = "N", requires = "prefix")]
    threads: Option<usize>,
}

#[derive(Args, Debug)]
struct SealArgs {
    /// Directory holding the key files
    dir: PathBuf,

    /// Also seal the key files in the directories beneath it
    #[arg(long)]
    recursive: bool,

    /// A sealed file the password must also open, so these files end up under the same password as it
    #[arg(long = "same-password-as", value_name = "FILE.enc")]
    same_password_as: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct OpenArgs {
    /// The key file, named in either form (x.key or x.key.enc)
    file: PathBuf,

    /// Print one string field of a JSON key file (e.g. passphrase, address) instead of the whole file
    #[arg(long, value_name = "NAME")]
    field: Option<String>,
}

#[derive(Args, Debug)]
struct PrintArgs {
    /// Directory holding the key files
    dir: PathBuf,

    /// Output PDF file to write (one page per key file)
    #[arg(long = "out", value_name = "FILE")]
    out: PathBuf,

    /// Also print the key files in the directories beneath it
    #[arg(long)]
    recursive: bool,
}

/// Read one password. Prompts go to the terminal or standard error, never to
/// standard output, which `open` reserves for the key.
fn read_password(prompt: &str) -> Result<String> {
    let password = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).context("failed to read the password")?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read the password from standard input")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if password.is_empty() {
        bail!("the password must not be empty");
    }
    Ok(password)
}

/// Read the password a seal will use. At a terminal it is asked for twice.
fn read_new_password() -> Result<String> {
    let password = read_password("Password: ")?;
    if std::io::stdin().is_terminal() {
        let again = read_password("Confirm password: ")?;
        if again != password {
            bail!("the passwords do not match");
        }
    }
    Ok(password)
}

fn open_prompt() -> Result<String> {
    read_password("Password for sealed key files: ")
}

fn create(args: CreateArgs) -> Result<()> {
    let file = KeyFile::at(args.file);
    let plain_path = file.plain_path();
    if plain_path.extension().and_then(|e| e.to_str()) != Some("json") {
        bail!("an account key file is named <NAME>.json, not {plain_path:?}");
    }
    if file.exists() {
        bail!("{plain_path:?} exists already (in plain or sealed form)");
    }
    let dir = match plain_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !dir.is_dir() {
        bail!("{dir:?} is not a directory");
    }
    let prefix = args.prefix.as_deref().map(normalise_prefix).transpose()?;

    // ask for the password before a search that may run for minutes, not after it.
    let vault = if args.plain {
        None
    } else {
        let vault = Vault::with_password(read_new_password()?);
        // one directory, one password: it must open whatever is sealed here already.
        if let Some(reference) = &args.same_password_as {
            vault.check_opens(reference)?;
        }
        for sealed in discover(&dir, false)?.iter().filter(|f| f.is_sealed()) {
            vault.check_opens(&sealed.sealed_path())?;
        }
        Some(vault)
    };

    let account = match &prefix {
        None => generate_account(),
        Some(prefix) => {
            let threads = args.threads.unwrap_or_else(|| {
                std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
            });
            eprintln!(
                "searching for an address starting {prefix}: about {} tries on {threads} thread(s)",
                expected_tries(prefix.len())
            );
            let started = Instant::now();
            let found = find_vanity_account(prefix, threads)?;
            eprintln!(
                "found after {} tries in {:.1}s",
                found.tries,
                started.elapsed().as_secs_f64()
            );
            found.account
        }
    };

    let bytes = account.to_key_file_json()?;
    let written = match &vault {
        Some(vault) => vault.seal_new(&file, &bytes)?,
        None => write_new_plain(&file, &bytes)?,
    };
    eprintln!("created {}", written.display());
    println!("{}", account.address);
    Ok(())
}

fn seal(args: SealArgs) -> Result<()> {
    let files = discover(&args.dir, args.recursive)?;
    let unsealed: Vec<&KeyFile> = files.iter().filter(|file| !file.is_sealed()).collect();
    if unsealed.is_empty() {
        println!("no unsealed key files in {:?}", args.dir);
        return Ok(());
    }

    let vault = Vault::with_password(read_new_password()?);
    // one tree, one password: it must open whatever is sealed here already.
    if let Some(reference) = &args.same_password_as {
        vault.check_opens(reference)?;
    }
    for file in files.iter().filter(|file| file.is_sealed()) {
        vault.check_opens(&file.sealed_path())?;
    }

    let mut sealed = 0usize;
    for file in unsealed {
        if vault.seal(file)? {
            println!("sealed {}", file.sealed_path().display());
            sealed += 1;
        }
    }
    println!("{sealed} key file(s) sealed; the plaintext is deleted");
    Ok(())
}

fn open(args: OpenArgs) -> Result<()> {
    let file = KeyFile::at(args.file);
    let opened = Vault::new().open(&file, open_prompt)?;
    let mut out = std::io::stdout().lock();
    match args.field {
        Some(field) => writeln!(out, "{}", json_field(&opened.bytes, &field)?)?,
        None => out.write_all(&opened.bytes)?,
    }
    out.flush()?;
    Ok(())
}

fn print(args: PrintArgs) -> Result<()> {
    let files = discover(&args.dir, args.recursive)?;
    if files.is_empty() {
        bail!("no key files (*.json, *.key) in {:?}", args.dir);
    }
    let mut vault = Vault::new();
    let mut pages = Vec::with_capacity(files.len());
    for file in &files {
        let name = file.name_under(&args.dir);
        let opened = vault.open(file, open_prompt)?;
        // a sealed file's page is encrypted under the same password; a plain one is printed plain.
        let password = if opened.was_sealed {
            vault.password()
        } else {
            None
        };
        pages.push(backup_page(&name, &opened.bytes, password)?);
    }
    let pdf = render_backup_pdf(&pages)?;
    std::fs::write(&args.out, pdf).with_context(|| format!("failed to write {:?}", args.out))?;
    println!("{} page(s) written to {}", pages.len(), args.out.display());
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Create(args) => create(args),
        Command::Seal(args) => seal(args),
        Command::Open(args) => open(args),
        Command::Print(args) => print(args),
    }
}
