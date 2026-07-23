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
//! # Global configuration file
//!
//! `pqp` reads `~/.config/pqp/pqp.toml` (XDG config) if present, falling
//! back to `~/.pqp/pqp.toml` for backward compatibility. Each command
//! section mirrors CLI options. Precedence (lowest to highest): code
//! defaults < config file < CLI flags.
//! See `pqp.toml.sample` in the source tree for detailed pros/cons of
//! every value.
//!
//! **Available options:**
//!
//! | Section | Key | Values | Default | Trade-offs |
//! |---|---|---|---|---|
//! | `[gen-key]` | `kem` | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | `ML-KEM-768` | 512 fastest, 1024 max security but 2× size |
//! | `[gen-key]` | `dsa` | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | `ML-DSA-65` | 44 compact, 87 max security but 2× sig size |
//! | `[gen-key]` | `encoding` | `BASE64`, `ASCII85` | `BASE64` | ASCII85 ~25% smaller, less universal |
//! | `[list-keys]` | `format` | `table`, `no-headers`, `json` | `table` | table human, no-headers scripts, json programs |
//! | `[encrypt]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | zstd best speed/ratio, lzma best ratio/slowest |
//! | `[export]` | `format` | `armor`, `pqp` | `armor` | armor universal, pqp self-describing |
//! | `[export]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | only for PQP format |
//!
//! Example `~/.config/pqp/pqp.toml`:
//! ```toml
//! [gen-key]
//! kem = "ML-KEM-768"
//! dsa = "ML-DSA-65"
//!
//! [encrypt]
//! compress = "zstd"
//! ```
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
//! | `--format` | Output format: `armor` (default, PEM-style), `pqp` (`AlgorithmList::EncodedPayload`) |
//! | `--compress` | Compression for PQP format: `none`, `zstd` (default), `gzip`, `bzip2`, `lzma` |
//!
//! The PQP format (`--format pqp`) encodes the key as
//! `ML-KEM-768+ML-DSA-65+[ZSTD]+BASE64::<payload>`, embedding KEM and DSA variant
//! names in the algorithm string for self-describing interchange. Compression is
//! applied before encoding and auto-detected on import.
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
//! Keys are stored in `~/.local/share/pqp/keys/<key-id>/` (XDG data dir),
//! falling back to `~/.pqp/keys/<key-id>/` for backward compatibility.
//! Secret keys are encrypted with Argon2id + XChaCha20-Poly1305.
//! All commands accept `-` or omit the input positional argument to read
//! from stdin.
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
pub mod config;
pub mod crypto;
pub mod format;
pub mod keyring;
