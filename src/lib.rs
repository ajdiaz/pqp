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
//! ## Key fingerprint
//!
//! Every generated key has a `fingerprint`: `hex(SHA3-256(kem_pk || sign_pk))`,
//! a 64-character hex string that uniquely identifies the key material. It is
//! stored in `pqp.conf`, included as a `Fingerprint` header in armor exports,
//! embedded in PQP format metadata, and displayed in `list-keys` output.
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
//! | [`purge-keys`](cli::Commands::PurgeKeys) | Remove all keys from the keyring |
//!
//! # Global configuration file
//!
//! `pqp` reads `~/.config/pqp/pqp.toml` (XDG config) if present, falling
//! back to `~/.pqp/pqp.toml` for backward compatibility. The `PQP_HOME`
//! environment variable overrides both, using the legacy structure inside
//! the specified directory (`$PQP_HOME/.pqp/pqp.toml`).
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
//! | `[gen-key]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `none` | stored as per-key default, commands use own default unless set |
//! | `[gen-key]` | `expiration-date` | `5y`, `30d`, `2030-12-31`, etc | `5y` | relative or absolute; also `1y`, `12m`, `90d` |
//! | `[gen-key]` | `metadata` | arbitrary `key=value` pairs | (none) | stored in pqp.conf and armor headers; not interpreted |
//! | `[gen-key]` | `argon2-mem` | KiB (`19456`, `65536`, etc) | `19456` | higher = more brute-force resistance, more RAM |
//! | `[gen-key]` | `argon2-time` | iterations (`2`, `3`, etc) | `2` | higher = slower, more work per guess |
//! | `[gen-key]` | `argon2-par` | threads (`1`, `4`, etc) | `1` | higher = faster on multi-core |
//! | `[encrypt]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
//! | `[sign]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
//! | `[list-keys]` | `format` | `table`, `no-headers`, `json` | `table` | table human, no-headers scripts, json programs |
//! | `[encrypt]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | zstd best speed/ratio, lzma best ratio/slowest |
//! | `[export]` | `format` | `armor`, `pqp` | `pqp` | pqp self-describing, armor universal pasteable |
//! | `[export]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | only for PQP format |
//! | `[keyring]` | `path` | any directory path | (none) | overrides default keyring location |
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
//! * `--keyring-path <path>` — use an alternative keyring directory instead of the default
//!   (also configurable via `KEYRING_PATH` env var or `[keyring].path` in config)
//!
//! # Commands in detail
//!
//! ### `gen-key`
//! `pqp gen-key -u <user> [--no-passphrase] [--kem <variant>] [--dsa <variant>] [--encoding <enc>] [--compress <algo>] [--expiration-date <date>] [--metadata <key=value>]...`
//!
//! | Flag | Description |
//! |---|---|
//! | `-u`, `--user` | User ID for the key |
//! | `--no-passphrase` | Store the secret key without passphrase encryption |
//! | `--kem` | KEM variant: `ML-KEM-512`, `ML-KEM-768` (default), `ML-KEM-1024` |
//! | `--dsa` | DSA variant: `ML-DSA-44`, `ML-DSA-65` (default), `ML-DSA-87` |
//! | `--encoding` | Armor encoding: `BASE64` (default), `ASCII85` |
//! | `--compress` | Default compression preference: `none` (default), `zstd`, `gzip`, `bzip2`, `lzma` |
//! | `--expiration-date` | Key expiration: `<N>y` (default: `5y`), `<N>m`, `<N>d`, or `YYYY-MM-DD` |
//! | `--metadata` | Key metadata as `key=value` pairs (repeatable) |
//! | `--argon2-mem` | Argon2id memory cost in KiB (default: `19456` ~19 MiB) |
//! | `--argon2-time` | Argon2id time cost / iterations (default: `2`) |
//! | `--argon2-par` | Argon2id parallelism / threads (default: `1`) |
//!
//! ### `list-keys`
//! `pqp list-keys [--format <format>]`
//!
//! | Flag | Description |
//! |---|---|
//! | `--format` | Output format: `table` (default), `no-headers`, `json` |
//!
//! ### `encrypt`
//! `pqp encrypt -r <recipient> -o <outfile> [--compress <algo>] [--sign] [--signer <user>] [--allow-expired] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-r`, `--recipient` | Recipient key ID or user ID |
//! | `-o`, `--output` | Output file path |
//! | `--compress` | Compression: `none`, `zstd` (default), `gzip`, `bzip2`, `lzma` |
//! | `-s`, `--sign` | Sign the ciphertext with sender key |
//! | `-u`, `--signer` | Signer key ID or user ID (requires `--sign`) |
//! | `--allow-expired` | Allow using an expired recipient or signer key |
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
//! `pqp sign -u <user> -o <outfile> [--no-passphrase] [--allow-expired] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `-u`, `--user` | Signing key ID or user ID |
//! | `-o`, `--output` | Output signature file path |
//! | `--no-passphrase` | Use empty passphrase (no prompt) |
//! | `--allow-expired` | Allow using an expired signing key |
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
//! | `--format` | Output format: `pqp` (default, `AlgorithmList::EncodedPayload`), `armor` (PEM-style) |
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
//! ### `purge-keys`
//! `pqp purge-keys [--no-ask-confirmation] [--remove-private-keys]`
//!
//! | Flag | Description |
//! |---|---|
//! | `--no-ask-confirmation` | Skip the confirmation prompt before removing keys |
//! | `--remove-private-keys` | Also remove private keys if they exist |
//!
//! # Key storage
//!
//! Keys are stored in `~/.local/share/pqp/keys/<key-id>/` (XDG data dir),
//! falling back to `~/.pqp/keys/<key-id>/` for backward compatibility.
//! The `PQP_HOME` environment variable overrides both, using the legacy
//! structure inside the specified directory (`$PQP_HOME/.pqp/keys/`).
//!
//! Identifiers (key ID or user ID) are resolved by checking directory names
//! first, then matching `user_id` in `pqp.conf` metadata.
//!
//! # Security hardening
//!
//! `pqp` applies the following security measures to protect key material and
//! resist attacks:
//!
//! | Measure | Description |
//! |---|---|
//! | File permissions | Secret key files (`pqp-secret.der`) and metadata (`pqp.conf`) are created with `0o600` (owner read/write only). Key directories use `0o700`. Public keys use `0o644`. |
//! | Decompression bomb protection | All decompression is limited to 100 MiB output, preventing OOM from malicious compressed files. |
//! | KDF domain separation | The SHA3-256 KDF on KEM shared secrets includes a context label (`pqp-kem-encrypt-v1`) per NIST SP 800-56C. |
//! | HTTP timeout | `import --url` enforces a 30-second timeout to prevent slow-loris DoS. |
//! | Path traversal defense | Key ID resolution validates all directory names against `^[0-9a-f]{16}$` before use in filesystem operations. |
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
pub mod expiry;
pub mod format;
pub mod keyring;
pub mod util;
