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
//! | [`edit-key`](cli::Commands::EditKey) | Edit an existing key's metadata and/or passphrase |
//! | [`remove-key`](cli::Commands::RemoveKey) | Remove a public (and optionally private) key |
//! | [`purge-keys`](cli::Commands::PurgeKeys) | Remove all keys from the keyring |
//!
//! # Global configuration file
//!
//! `pqp` reads `~/.config/pqp/pqp.toml` (XDG config) if present, falling
//! back to `~/.pqp/pqp.toml` for backward compatibility. The `PQP_HOME`
//! environment variable overrides both, using the legacy structure inside
//! the specified directory (`$PQP_HOME/.pqp/pqp.toml`).
//! Config file precedence (lowest to highest): code defaults < config file
//! (default path, or `PQP_CONFIG` env var, or `--config` flag) < CLI flags.
//! A `[config]` section in the config file is ignored (reserved).
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
//! | `[gen-key]` | `argon2-mem` | KiB (`65536`, `19456`, etc) | `65536` | higher = more brute-force resistance, more RAM |
//! | `[gen-key]` | `argon2-time` | iterations (`3`, `2`, etc) | `3` | higher = slower, more work per guess |
//! | `[gen-key]` | `argon2-par` | threads (`1`, `4`, etc) | `1` | higher = faster on multi-core |
//! | `[encrypt]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
//! | `[sign]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
//! | `[list-keys]` | `format` | `table`, `no-headers`, `json` | `table` | table human, no-headers scripts, json programs |
//! | `[encrypt]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | zstd best speed/ratio, lzma best ratio/slowest |
//! | `[export]` | `format` | `armor`, `pqp` | `pqp` | pqp self-describing, armor universal pasteable |
//! | `[export]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | only for PQP format |
//! | `[edit-key]` | `user` | any string | (none) | new user ID for the key |
//! | `[edit-key]` | `expiration-date` | `5y`, `30d`, `2030-12-31`, etc | (none) | relative or absolute |
//! | `[edit-key]` | `encoding` | `BASE64`, `ASCII85` | (none) | new encoding for armored output |
//! | `[edit-key]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | (none) | new default compression algorithm |
//! | `[keyring]` | `path` | any directory path | (none) | overrides default keyring location |
//! | `[password-tool]` | `command` | any program path (e.g. `pinentry`) | (none) | external tool for passphrase prompts; overridden by `--password-tool` flag |
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
//! | Flag | Description |
//! |---|---|
//! | `--dry-run` / `-n` | Print a dry-run message to stderr and exit without action |
//! | `--keyring-path <path>` | Use an alternative keyring directory (also via `KEYRING_PATH` env or `[keyring].path` config) |
//! | `--config <path>` | Path to an alternative configuration file (also via `PQP_CONFIG` env var) |
//! | `--password-tool <tool>` | External tool for passphrase prompts (e.g. pinentry); askpass-style tools receive the prompt as their final argument and print the passphrase on stdout |
//!
//! # Environment variables
//!
//! | Variable | Description |
//! |---|---|
//! | `PQP_HOME` | Override XDG and legacy paths, using the legacy structure inside the specified directory |
//! | `PQP_CONFIG` | Path to an alternative configuration file (takes precedence over default path, overridden by `--config` flag) |
//! | `KEYRING_PATH` | Path to an alternative keyring directory |
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
//! | `--argon2-mem` | Argon2id memory cost in KiB (default: `65536` ~64 MiB) |
//! | `--argon2-time` | Argon2id time cost / iterations (default: `3`) |
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
//! | `-s`, `--sign` | Sign the ciphertext with sender key (DSA variant recorded in the AlgorithmList; decrypt strips and verifies it) |
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
//! `pqp import [--url <url>] [--dont-ask-confirmation] [--force] [infile]`
//!
//! | Flag | Description |
//! |---|---|
//! | `--url` | URL to fetch the armored key from |
//! | `--dont-ask-confirmation` | Skip confirmation prompt before importing |
//! | `-f`, `--force` | Force override an existing key with the same fingerprint |
//! | `infile` | Armored key file path (omit or `-` for stdin) |
//!
//! When a key with the same fingerprint (SHA3-256 of public key material) already
//! exists in the keyring, the import is rejected unless `--force` is used. This
//! prevents accidentally overwriting keys. Keys that have a private key (pub+sec) are
//! never overridden automatically.
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
//! ### `edit-key`
//! `pqp edit-key [--user <user>] [--expiration-date <date>] [--encoding <enc>] [--compress <algo>] [--passphrase] [--no-passphrase] [--metadata <key=value>]... <key-id>`
//!
//! | Flag | Description |
//! |---|---|
//! | `--user` / `-u` | New user ID for the key |
//! | `--expiration-date` | New expiration date (relative or absolute) |
//! | `--encoding` | New encoding: `BASE64` or `ASCII85` |
//! | `--compress` | New compression algorithm: none, zstd, gzip, bzip2, lzma |
//! | `--passphrase` | Change the key's passphrase (prompts for old and new) |
//! | `--no-passphrase` | Set empty passphrase (prompts for old passphrase) |
//! | `--metadata` | Add metadata as `key=value` pairs (repeatable, appended) |
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
//! # Cryptography
//!
//! `pqp` relies on the following pure-Rust crates for all cryptographic
//! operations. Security guarantees depend on the correctness of these
//! implementations and their underlying algorithms.
//!
//! | Algorithm | Crate | Standard | Post-Quantum |
//! |---|---|---|---|
//! | ML-KEM (Kyber) | [`ml-kem`](https://crates.io/crates/ml-kem) v0.3 (RustCrypto) | NIST FIPS 203 | **Yes** — Module Lattice KEM, security based on Module Learning With Errors (MLWE). Believed resistant to Shor's and Grover's quantum algorithms. See [CRYSTALS-Kyber paper](https://eprint.iacr.org/2017/634), [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203), [pq-crystals.org](https://pq-crystals.org/kyber/). |
//! | ML-DSA (Dilithium) | [`ml-dsa`](https://crates.io/crates/ml-dsa) v0.1 (RustCrypto) | NIST FIPS 204 | **Yes** — Module Lattice Digital Signature, security based on MLWE and MSIS problems. See [CRYSTALS-Dilithium paper](https://eprint.iacr.org/2017/633), [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204), [pq-crystals.org](https://pq-crystals.org/dilithium/). |
//! | XChaCha20-Poly1305 | [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) v0.11 (RustCrypto) | IETF RFC 8439 (XChaCha20 extension) | **Indirectly** — symmetric cipher with 256-bit key provides 128-bit post-quantum security against Grover's search. Binds authentication tag to associated data. |
//! | Argon2id | [`argon2`](https://crates.io/crates/argon2) v0.5 (RustCrypto) | PHC winner (2015), RFC 9106 | **Yes** — memory-hard KDF resistant to GPU/ASIC brute-force acceleration. See [Argon2 specification](https://github.com/P-H-C/phc-winner-argon2), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106). |
//! | SHA3-256 | [`sha3`](https://crates.io/crates/sha3) v0.10 (RustCrypto) | NIST FIPS 202 | **Indirectly** — 256-bit output provides 128-bit post-quantum collision resistance against Grover's algorithm. Used for key fingerprinting and KDF. See [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). |
//!
//! All crates are pure-Rust, audited, and maintained by the RustCrypto
//! project. The [`pqcrypto` umbrella crate](https://crates.io/crates/pqcrypto)
//! was explicitly avoided due to RUSTSEC-2026-0164 (unmaintained).
//!
//! **Key derivation chain:**
//! 1. Passphrase → Argon2id → symmetric key (stored parameters per key)
//! 2. KEM shared secret → SHA3-256 KDF with domain separation
//!    (`pqp-kem-encrypt-v1`) → XChaCha20 key per NIST SP 800-56C
//! 3. Passphrase-encrypted secret keys on disk: Argon2id-derived key wraps
//!    the Kyber + Dilithium private key material using XChaCha20-Poly1305
//!
//! **NIST security levels:**
//! - ML-KEM-512 / ML-DSA-44: NIST Level 1/2 (≈ AES-128 equivalent)
//! - ML-KEM-768 / ML-DSA-65: NIST Level 3 (≈ AES-192 equivalent) — **default, recommended**
//! - ML-KEM-1024 / ML-DSA-87: NIST Level 5 (≈ AES-256 equivalent)
//!
//! NIST levels are defined by the computational cost of breaking the
//! algorithm relative to the cost of breaking AES at the corresponding
//! key size. Level 3 provides a comfortable margin against known quantum
//! cryptanalytic advances and is the recommended default for most users.
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
pub mod password;
pub mod util;
