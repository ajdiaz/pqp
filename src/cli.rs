//! CLI interface definitions using `clap`.
//!
//! Defines the [`Cli`] entry point and [`Commands`] enum with all
//! subcommands. This module is purely structural — command dispatch
//! and business logic live in `src/main.rs`.

use clap::{Parser, Subcommand};

/// Top-level CLI structure for the `pqp` binary.
#[derive(Parser)]
#[command(name = "pqp", about = "Quantum-Resistant GPG Emulation")]
pub struct Cli {
    /// Print a dry-run message and exit without doing anything.
    #[arg(
        short = 'n',
        long = "dry-run",
        global = true,
        help = "Do nothing, print dry-run message"
    )]
    pub dry_run: bool,

    /// Path to an alternative keyring directory.
    #[arg(
        long = "keyring-path",
        global = true,
        help = "Path to an alternative keyring directory"
    )]
    pub keyring_path: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

/// All subcommands supported by `pqp`.
#[derive(Subcommand)]
pub enum Commands {
    /// Generate a PQ key pair (Kyber + Dilithium).
    #[command(name = "gen-key")]
    GenKey {
        #[arg(short = 'u', long = "user", help = "User ID for the key")]
        user: String,
        #[arg(long = "no-passphrase", help = "Generate key without a passphrase")]
        no_passphrase: bool,
        #[arg(
            long = "kem",
            default_value = "ML-KEM-768",
            help = "KEM algorithm variant: ML-KEM-512, ML-KEM-768, ML-KEM-1024"
        )]
        kem: String,
        #[arg(
            long = "dsa",
            default_value = "ML-DSA-65",
            help = "Digital signature algorithm variant: ML-DSA-44, ML-DSA-65, ML-DSA-87"
        )]
        dsa: String,
        #[arg(
            long = "encoding",
            default_value = "BASE64",
            help = "Encoding for armored output: BASE64, ASCII85"
        )]
        encoding: String,
        #[arg(
            long = "compress",
            default_value = "none",
            help = "Default compression algorithm: none, zstd, gzip, bzip2, lzma"
        )]
        compress: String,
        #[arg(
            long = "expiration-date",
            default_value = "5y",
            help = "Key expiration: <N>y, <N>m, <N>d, or YYYY-MM-DD"
        )]
        expiration_date: String,
        #[arg(long = "metadata", help = "Key metadata as key=value (repeatable)")]
        metadata: Vec<String>,
        #[arg(
            long = "argon2-mem",
            default_value = "19456",
            help = "Argon2id memory cost in KiB (default 19456 ~= 19 MiB)"
        )]
        argon2_mem: u32,
        #[arg(
            long = "argon2-time",
            default_value = "2",
            help = "Argon2id time cost (iterations, default 2)"
        )]
        argon2_time: u32,
        #[arg(
            long = "argon2-par",
            default_value = "1",
            help = "Argon2id parallelism (threads, default 1)"
        )]
        argon2_par: u32,
    },
    /// List keys in the keyring.
    #[command(name = "list-keys")]
    ListKeys {
        #[arg(
            long = "format",
            default_value = "table",
            help = "Output format: table, no-headers, json"
        )]
        format: String,
    },
    /// Encrypt a file for a recipient.
    #[command(name = "encrypt")]
    Encrypt {
        #[arg(short = 'r', long = "recipient", help = "Recipient key ID or user ID")]
        recipient: String,
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(help = "Input file path (omit or - for stdin)")]
        input: Option<String>,
        #[arg(
            short = 's',
            long = "sign",
            help = "Sign the ciphertext with sender key"
        )]
        sign: bool,
        #[arg(
            short = 'u',
            long = "signer",
            help = "Signer key ID or user ID (requires --sign)"
        )]
        signer: Option<String>,
        #[arg(
            long = "compress",
            default_value = "zstd",
            help = "Compression algorithm: none, zstd, gzip, bzip2, lzma"
        )]
        compress: String,
        #[arg(long = "allow-expired", help = "Allow using an expired key")]
        allow_expired: bool,
    },
    /// Decrypt a file.
    #[command(name = "decrypt")]
    Decrypt {
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(help = "Input file path (omit or - for stdin)")]
        input: Option<String>,
        #[arg(long = "no-passphrase", help = "Use empty passphrase (no prompt)")]
        no_passphrase: bool,
    },
    /// Sign a file with a private key.
    #[command(name = "sign")]
    Sign {
        #[arg(short = 'u', long = "user", help = "Signing key ID or user ID")]
        user: String,
        #[arg(short = 'o', long = "output", help = "Output signature file path")]
        output: Option<String>,
        #[arg(help = "Input file path (omit or - for stdin)")]
        input: Option<String>,
        #[arg(long = "no-passphrase", help = "Use empty passphrase (no prompt)")]
        no_passphrase: bool,
        #[arg(long = "allow-expired", help = "Allow using an expired key")]
        allow_expired: bool,
    },
    /// Verify a signature.
    #[command(name = "verify")]
    Verify {
        #[arg(help = "Signature file path")]
        signature: String,
        #[arg(help = "Original file path (omit or - for stdin)")]
        input: Option<String>,
    },
    /// Export a public key (armored or PQP format).
    #[command(name = "export")]
    Export {
        #[arg(help = "Key ID or user ID to export")]
        key_id: String,
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(
            long = "format",
            default_value = "armor",
            help = "Output format: armor (-----BEGIN/END-----) or pqp (AlgorithmList::Payload)"
        )]
        format_: String,
        #[arg(
            long = "compress",
            default_value = "zstd",
            help = "Compression for PQP format: none, zstd, gzip, bzip2, lzma (zstd default, ignored for armor)"
        )]
        compress: String,
    },
    /// Remove a public key (and optionally private key) from the keyring.
    #[command(name = "remove-key")]
    RemoveKey {
        #[arg(help = "Key ID or user ID to remove")]
        key_id: String,
        #[arg(long = "dont-ask", help = "Skip confirmation prompt before removing")]
        dont_ask: bool,
        #[arg(
            long = "remove-private-key",
            help = "Also remove the private key if it exists"
        )]
        remove_private_key: bool,
    },
    /// Import a public key (armored).
    #[command(name = "import")]
    Import {
        #[arg(help = "Armored key file path (omit or - for stdin)")]
        input: Option<String>,
        #[arg(long = "url", help = "URL to fetch the armored key from")]
        url: Option<String>,
        #[arg(
            long = "dont-ask-confirmation",
            help = "Skip confirmation prompt before importing"
        )]
        dont_ask_confirmation: bool,
    },
}
