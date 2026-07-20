//! Library crate for `pqp` — a quantum-resistant GPG emulation tool.
//!
//! Provides modules for post-quantum cryptography (ML-KEM, ML-DSA),
//! symmetric encryption (XChaCha20-Poly1305), key management, file
//! format serialization, and ASCII-armor encoding.
//!
//! # Usage
//!
//! `pqp` is a CLI tool with the following commands:
//!
//! | Command | Description |
//! |---|---|
//! | [`gen-key`](cli::Commands::GenKey) | Generate a PQ key pair (Kyber + Dilithium) |
//! | [`list-keys`](cli::Commands::ListKeys) | List keys in the keyring |
//! | [`encrypt`](cli::Commands::Encrypt) | Encrypt a file for a recipient |
//! | [`decrypt`](cli::Commands::Decrypt) | Decrypt a file |
//! | [`sign`](cli::Commands::Sign) | Sign a file with a private key |
//! | [`verify`](cli::Commands::Verify) | Verify a signature |
//! | [`export`](cli::Commands::Export) | Export a public key (armored) |
//! | [`import`](cli::Commands::Import) | Import a public key (armored) |
//! | [`remove-key`](cli::Commands::RemoveKey) | Remove a public (and optionally private) key |
//!
//! # Global flags
//!
//! * `--dry-run` / `-n` — print a dry-run message to stderr and exit without action
//!
//! # Commands in detail
//!
//! ### `gen-key`
//! `pqp gen-key -u <user> [--no-passphrase] [--kem <variant>] [--dsa <variant>] [--encoding <enc>]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-u`, `--user` | User ID for the key |
//! | `--no-passphrase` | Store the secret key without passphrase encryption |
//! | `--kem` | KEM variant: `ML-KEM-512`, `ML-KEM-768` (default), `ML-KEM-1024` |
//! | `--dsa` | DSA variant: `ML-DSA-44`, `ML-DSA-65` (default), `ML-DSA-87` |
//! | `--encoding` | Armor encoding: `BASE64` (default), `ASCII85` |
//!
//! ### `list-keys`
//! `pqp list-keys [--format <format>]`
//!
//! | Flag | Description |
//! |---|---|
//! | `--format` | Output format: `table` (default), `no-headers`, `json` |
//!
//! ### `encrypt`
//! `pqp encrypt -r <recipient> -o <outfile> [--compress <algo>] [--sign] [--signer <user>] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-r`, `--recipient` | Recipient key ID or user ID |
//! | `-o`, `--output` | Output file path |
//! | `--compress` | Compression: `none`, `zstd` (default), `gzip`, `bzip2`, `lzma` |
//! | `-s`, `--sign` | Sign the ciphertext with sender key |
//! | `-u`, `--signer` | Signer key ID or user ID (requires `--sign`) |
//! | `infile` | Input file path (omit or `-` for stdin) |
//!
//! ### `decrypt`
//! `pqp decrypt -o <outfile> [--no-passphrase] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-o`, `--output` | Output file path |
//! | `--no-passphrase` | Use empty passphrase (no prompt) |
//! | `infile` | Input file path (omit or `-` for stdin) |
//!
//! ### `sign`
//! `pqp sign -u <user> -o <outfile> [--no-passphrase] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-u`, `--user` | Signing key ID or user ID |
//! | `-o`, `--output` | Output signature file path |
//! | `--no-passphrase` | Use empty passphrase (no prompt) |
//! | `infile` | Input file path (omit or `-` for stdin) |
//!
//! ### `verify`
//! `pqp verify <signature> [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `signature` | Signature file path |
//! | `infile` | Original file path (omit or `-` for stdin) |
//!
//! ### `export`
//! `pqp export <key-id-or-user-id> [-o <outfile>]`
//!
//! | Flag | Description |
//! |---|---|
//! | `key_id` | Key ID or user ID to export |
//! | `-o`, `--output` | Output file path |
//!
//! ### `import`
//! `pqp import [--url <url>] [--dont-ask-confirmation] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `--url` | URL to fetch the armored key from |
//! | `--dont-ask-confirmation` | Skip confirmation prompt before importing |
//! | `infile` | Armored key file path (omit or `-` for stdin) |
//!
//! ### `remove-key`
//! `pqp remove-key <key-id-or-user-id> [--dont-ask] [--remove-private-key]`
//!
//! | Flag | Description |
//! |---|---|
//! | `key_id` | Key ID or user ID to remove |
//! | `--dont-ask` | Skip confirmation prompt before removing |
//! | `--remove-private-key` | Also remove the private key if it exists |
//!
//! # Key storage
//!
//! Keys are stored in `~/.pqp/keys/<key-id>/`. Secret keys are encrypted
//! with Argon2id + XChaCha20-Poly1305. All commands accept `-` or omit
//! the input positional argument to read from stdin.
//!
//! Identifiers (key ID or user ID) are resolved by checking directory names
//! first, then matching `user_id` in `pqp.conf` metadata.
//!
//! # Quick start
//!
//! ```bash
//! # Generate a key pair
//! pqp gen-key -u "alice@example.com"
//!
//! # Encrypt a file for a recipient
//! pqp encrypt -r <key-id> -o secret.txt.pqp.enc secret.txt
//!
//! # Decrypt a file
//! pqp decrypt -o secret.txt secret.txt.pqp.enc
//!
//! # Sign and verify
//! pqp sign -u <key-id> -o file.txt.pqp.sig file.txt
//! pqp verify file.txt.pqp.sig file.txt
//! ```

pub mod armor;
pub mod cli;
pub mod crypto;
pub mod format;
pub mod keyring;
