# account_vault

Key files sealed under a password, with printable paper backups.

A project that signs for Algorand accounts ends up with key files on disk. This crate keeps them encrypted between uses, opens one when it is needed without writing it back to disk, and prints a backup sheet for each.

It is the mechanism `bingle_admin` uses for the Bingle role accounts, lifted out so that other tooling (the Sidewinder deploy scripts, for one) shares the same file format, the same password and the same paper backup. A file sealed by either tool opens with the other.

## Key files

A **key file** is any `*.json` or `*.key` file:

- An **account** is `{"address": "…", "passphrase": "<25 words>"}` JSON, whatever its extension.
- Anything else is an **opaque secret**, such as a bare consensus-key seed.

Its **sealed** form is the same name with `.enc` appended: `APP_ADMIN.json` becomes `APP_ADMIN.json.enc`, and `node-0/consensus.key` becomes `node-0/consensus.key.enc`.

## The tool

```
cargo install account_vault
```

Seal every key file in a directory, and in the directories beneath it. The plaintext is deleted once each sealed file has been checked:

```
account-vault seal ./mainnet_accounts --recursive
```

The password is asked for twice. It must also open every file already sealed there, so one directory tree cannot end up under two passwords. To hold a separate directory to the password of an existing file:

```
account-vault seal ./cluster --recursive --same-password-as ./mainnet_accounts/APP_ADMIN.json.enc
```

Open one key file to standard output. Nothing is written to disk:

```
account-vault open ./cluster/node-0/consensus.key
```

Print one field of an account, for a command that takes the 25 words as an argument:

```
account-vault open ./mainnet_accounts/RELAY_USER_1.json --field passphrase
```

Render a backup sheet for every key file, one page each:

```
account-vault print ./mainnet_accounts --recursive --out backup.pdf
```

The password is read from the terminal without echo. When standard input is not a terminal it is read as one line from standard input, so a script can supply it.

## What a backup page carries

Each page has the file's name, a QR code and a mnemonic, and the number of bytes they encode.

- For an account, they encode its 32-byte private key. Unsealed, the mnemonic is the account's own 25 words.
- For an opaque secret, they encode the file's bytes as they are. A secret of more than 96 bytes does not fit a page and is refused.
- For a sealed file, the secret is encrypted under the same password before it is encoded, so the paper is no more use to a finder than the file.

Restoring from a page is not a command yet. The library has both halves: `mnemonic::mnemonic_to_bytes` turns the words back into bytes (it needs the byte count printed on the page), and `envelope::decrypt_secret` opens an encrypted one.

## The encryption

Argon2id (64 MiB, 3 passes) stretches the password into a 256-bit key, and AES-256-GCM encrypts and authenticates the file under it. Every encryption has a fresh random salt and nonce. The sealed file is a JSON envelope that carries the salt, the nonce and the cost parameters, so a file sealed today still opens if the defaults change.

`BINGLE_INSECURE_FAST_KDF` in the environment lowers the cost to the minimum for new encryptions. It exists so test suites can seal many files quickly. Never set it for real keys.

## The library

| Module | What it does |
|---|---|
| `envelope` | Encrypt and decrypt: the JSON envelope for files, and a compact binary blob for paper |
| `account_dir` | Read named accounts (`NAME.json` or `NAME.json.enc`) from a directory, asking for the password once |
| `vault` | Find key files, seal them, open one, build its backup page |
| `mnemonic` | Algorand-style word encoding for any byte length |
| `pdf` | Render backup pages |
