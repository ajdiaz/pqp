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
//!
//! Keys are stored in `~/.pqp/keys/<key-id>/`. Secret keys are encrypted
//! with Argon2id + XChaCha20-Poly1305. All commands accept `-` or omit
//! the input positional argument to read from stdin.
//!
//! All commands accept `--dry-run` / `-n` as a global flag to print a
//! message to stderr and exit without performing any action.
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
