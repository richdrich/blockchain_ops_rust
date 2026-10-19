//! Tests for the `blockchain-account-vault` binary, driven end to end. The password is supplied on standard
//! input, which is how a script drives the tool.

use std::path::Path;

use assert_cmd::Command;
use blockchain_account_vault::envelope::{FAST_KDF_ENV, is_encrypted_envelope};

use crate::support::{ADDRESS, PASSPHRASE, PASSWORD, SEED_FILE, account_json, write};

fn tool() -> Command {
    let mut command = Command::cargo_bin("blockchain-account-vault").unwrap();
    command.env(FAST_KDF_ENV, "1");
    command
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A cluster-shaped directory: two role accounts at the top, a node's two keys beneath.
fn populate(dir: &Path) {
    write(&dir.join("APP_ADMIN.json"), &account_json());
    write(&dir.join("RELAY_USER_1.json"), &account_json());
    write(&dir.join("allowlist.yaml"), "nodes: []\n");
    write(&dir.join("node-0/account.key"), &account_json());
    write(&dir.join("node-0/consensus.key"), SEED_FILE);
}

fn seal(dir: &Path, extra: &[&str], password: &str) -> std::process::Output {
    tool()
        .arg("seal")
        .arg(dir)
        .args(extra)
        .write_stdin(format!("{password}\n"))
        .output()
        .unwrap()
}

#[test]
fn seal_encrypts_every_key_file_and_leaves_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());

    let output = seal(dir.path(), &["--recursive"], PASSWORD);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("4 key file(s) sealed"),
        "{}",
        stdout(&output)
    );

    for name in [
        "APP_ADMIN.json",
        "RELAY_USER_1.json",
        "node-0/account.key",
        "node-0/consensus.key",
    ] {
        assert!(!dir.path().join(name).exists(), "{name} must be gone");
        let sealed = std::fs::read(dir.path().join(format!("{name}.enc"))).unwrap();
        assert!(
            is_encrypted_envelope(&sealed),
            "{name}.enc must be an envelope"
        );
    }
    // a file that is not a key file is left alone.
    assert!(dir.path().join("allowlist.yaml").exists());

    // sealing again finds nothing to do, and asks for no password.
    let again = tool()
        .arg("seal")
        .arg(dir.path())
        .arg("--recursive")
        .output()
        .unwrap();
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(stdout(&again).contains("no unsealed key files"));
}

#[test]
fn seal_without_recursive_leaves_the_directories_beneath_alone() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    let output = seal(dir.path(), &[], PASSWORD);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(dir.path().join("APP_ADMIN.json.enc").exists());
    assert!(dir.path().join("node-0/consensus.key").exists());
}

#[test]
fn seal_refuses_a_password_that_does_not_open_what_is_already_sealed() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("APP_ADMIN.json"), &account_json());
    assert!(seal(dir.path(), &[], PASSWORD).status.success());

    // a node's keys arrive later, and must go under the same password.
    write(&dir.path().join("node-0/consensus.key"), SEED_FILE);
    let wrong = seal(dir.path(), &["--recursive"], "another password");
    assert!(!wrong.status.success());
    assert!(
        stderr(&wrong).contains("does not open"),
        "{}",
        stderr(&wrong)
    );
    assert!(
        dir.path().join("node-0/consensus.key").exists(),
        "nothing may be sealed on a refusal"
    );

    let right = seal(dir.path(), &["--recursive"], PASSWORD);
    assert!(right.status.success(), "{}", stderr(&right));
    assert!(dir.path().join("node-0/consensus.key.enc").exists());
}

#[test]
fn seal_can_be_held_to_the_password_of_a_file_elsewhere() {
    let accounts = tempfile::tempdir().unwrap();
    write(&accounts.path().join("APP_ADMIN.json"), &account_json());
    assert!(seal(accounts.path(), &[], PASSWORD).status.success());
    let reference = accounts.path().join("APP_ADMIN.json.enc");

    let cluster = tempfile::tempdir().unwrap();
    write(&cluster.path().join("node-0/consensus.key"), SEED_FILE);
    let same = [
        "--recursive",
        "--same-password-as",
        reference.to_str().unwrap(),
    ];

    let wrong = seal(cluster.path(), &same, "another password");
    assert!(!wrong.status.success());
    assert!(cluster.path().join("node-0/consensus.key").exists());

    let right = seal(cluster.path(), &same, PASSWORD);
    assert!(right.status.success(), "{}", stderr(&right));
}

#[test]
fn seal_refuses_an_empty_password() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    let output = seal(dir.path(), &[], "");
    assert!(!output.status.success());
    assert!(dir.path().join("APP_ADMIN.json").exists());
}

#[test]
fn open_writes_a_sealed_file_to_standard_output_and_nothing_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    assert!(
        seal(dir.path(), &["--recursive"], PASSWORD)
            .status
            .success()
    );
    let before: Vec<_> = walk(dir.path());

    // named in either form.
    for name in ["node-0/consensus.key", "node-0/consensus.key.enc"] {
        let output = tool()
            .arg("open")
            .arg(dir.path().join(name))
            .write_stdin(format!("{PASSWORD}\n"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(output.stdout, SEED_FILE.as_bytes());
    }
    assert_eq!(
        walk(dir.path()),
        before,
        "open must not create or change a file"
    );
}

#[test]
fn open_prints_one_field_of_an_account() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    assert!(seal(dir.path(), &[], PASSWORD).status.success());
    for (field, want) in [("passphrase", PASSPHRASE), ("address", ADDRESS)] {
        let output = tool()
            .arg("open")
            .arg(dir.path().join("RELAY_USER_1.json"))
            .args(["--field", field])
            .write_stdin(format!("{PASSWORD}\n"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(stdout(&output), format!("{want}\n"));
    }
}

#[test]
fn open_reads_a_plain_file_without_a_password() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    let output = tool()
        .arg("open")
        .arg(dir.path().join("node-0/consensus.key"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, SEED_FILE.as_bytes());
}

#[test]
fn open_with_a_wrong_password_prints_no_key() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    assert!(
        seal(dir.path(), &["--recursive"], PASSWORD)
            .status
            .success()
    );
    let output = tool()
        .arg("open")
        .arg(dir.path().join("node-0/consensus.key"))
        .write_stdin("another password\n")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "nothing may reach standard output"
    );
    assert!(
        stderr(&output).contains("does not open"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn print_renders_a_page_for_every_key_file_sealed_or_not() {
    let dir = tempfile::tempdir().unwrap();
    populate(dir.path());
    // seal the top level only, so the run covers both sealed and plain files.
    assert!(seal(dir.path(), &[], PASSWORD).status.success());
    let out = dir.path().join("backup.pdf");

    let output = tool()
        .arg("print")
        .arg(dir.path())
        .arg("--recursive")
        .arg("--out")
        .arg(&out)
        .write_stdin(format!("{PASSWORD}\n"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("4 page(s)"), "{}", stdout(&output));
    assert!(std::fs::read(&out).unwrap().starts_with(b"%PDF"));
}

#[test]
fn print_fails_on_a_directory_with_no_key_files() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("allowlist.yaml"), "nodes: []\n");
    let output = tool()
        .arg("print")
        .arg(dir.path())
        .arg("--out")
        .arg(dir.path().join("backup.pdf"))
        .output()
        .unwrap();
    assert!(!output.status.success());
}

fn create(file: &Path, extra: &[&str], password: Option<&str>) -> std::process::Output {
    let mut command = tool();
    command.arg("create").arg(file).args(extra);
    if let Some(password) = password {
        command.write_stdin(format!("{password}\n"));
    }
    command.output().unwrap()
}

fn open_field(file: &Path, field: &str, password: Option<&str>) -> String {
    let mut command = tool();
    command.arg("open").arg(file).arg("--field").arg(field);
    if let Some(password) = password {
        command.write_stdin(format!("{password}\n"));
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    stdout(&output).trim().to_string()
}

#[test]
fn create_writes_a_sealed_account_and_prints_only_its_address() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("REGISTRAR_SERVICE.json");

    let output = create(&file, &[], Some(PASSWORD));
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!file.exists(), "no plaintext may reach disk");
    let sealed = dir.path().join("REGISTRAR_SERVICE.json.enc");
    assert!(is_encrypted_envelope(&std::fs::read(&sealed).unwrap()));

    let address = stdout(&output).trim().to_string();
    assert_eq!(address.len(), 58);
    assert_eq!(open_field(&file, "address", Some(PASSWORD)), address);
    let passphrase = open_field(&file, "passphrase", Some(PASSWORD));
    assert_eq!(passphrase.split_whitespace().count(), 25);
    for shown in [stdout(&output), stderr(&output)] {
        assert!(
            !shown.contains(&passphrase),
            "the passphrase must not be printed"
        );
    }
}

#[test]
fn create_plain_writes_an_account_in_the_clear() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("FREE_USER_FUNDER.json");

    let output = create(&file, &["--plain"], None);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(open_field(&file, "address", None), stdout(&output).trim());
}

#[test]
fn create_refuses_an_existing_key_file_in_either_form() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("APP_ADMIN.json"), &account_json());
    let output = create(&dir.path().join("APP_ADMIN.json"), &["--plain"], None);
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("APP_ADMIN.json")).unwrap(),
        account_json()
    );

    assert!(seal(dir.path(), &[], PASSWORD).status.success());
    let output = create(&dir.path().join("APP_ADMIN.json"), &[], Some(PASSWORD));
    assert!(!output.status.success());
    assert!(!dir.path().join("APP_ADMIN.json").exists());
}

#[test]
fn create_needs_the_password_the_directory_is_sealed_under() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("APP_ADMIN.json"), &account_json());
    assert!(seal(dir.path(), &[], PASSWORD).status.success());

    let file = dir.path().join("NEW_ROLE.json");
    let output = create(&file, &[], Some("a different password"));
    assert!(!output.status.success());
    assert!(!file.exists() && !dir.path().join("NEW_ROLE.json.enc").exists());

    let output = create(&file, &[], Some(PASSWORD));
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn create_with_a_prefix_finds_a_matching_address() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("VANITY.json");
    let output = create(
        &file,
        &["--plain", "--prefix", "b7", "--threads", "2"],
        None,
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let address = stdout(&output).trim().to_string();
    assert!(address.starts_with("B7"), "{address}");
    assert_eq!(open_field(&file, "address", None), address);
}

#[test]
fn create_rejects_a_prefix_no_address_can_have() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("VANITY.json");
    let output = create(&file, &["--plain", "--prefix", "B1NG"], None);
    assert!(!output.status.success());
    assert!(!file.exists());
}

#[test]
fn create_needs_a_json_name_in_an_existing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let output = create(&dir.path().join("ROLE.key"), &["--plain"], None);
    assert!(!output.status.success());
    let output = create(&dir.path().join("missing/ROLE.json"), &["--plain"], None);
    assert!(!output.status.success());
}

/// Every file beneath `dir` with its contents, sorted.
fn walk(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                files.push((path, bytes));
            }
        }
    }
    files.sort();
    files
}
