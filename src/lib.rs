//! Library crate for `pqp` — a quantum-resistant GPG emulation tool.
//!
//! Provides modules for post-quantum cryptography (ML-KEM, ML-DSA),
//! symmetric encryption (XChaCha20-Poly1305), key management, file
//! format serialization, and ASCII-armor encoding.

pub mod armor;
pub mod cli;
pub mod crypto;
pub mod format;
pub mod keyring;
