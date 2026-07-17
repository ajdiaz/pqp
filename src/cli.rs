use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pqp", about = "Quantum-Resistant GPG Emulation")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(name = "gen-key", about = "Generate a PQ key pair (Kyber + Dilithium)")]
    GenKey {
        #[arg(short = 'u', long = "user", help = "User ID for the key")]
        user: String,
        #[arg(long = "no-passphrase", help = "Generate key without a passphrase")]
        no_passphrase: bool,
    },
    #[command(name = "list-keys", about = "List keys in keyring")]
    ListKeys {
        #[arg(
            long = "format",
            default_value = "table",
            help = "Output format: table, no-headers, json"
        )]
        format: String,
    },
    #[command(name = "encrypt", about = "Encrypt a file for a recipient")]
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
    },
    #[command(name = "decrypt", about = "Decrypt a file")]
    Decrypt {
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(help = "Input file path (omit or - for stdin)")]
        input: Option<String>,
    },
    #[command(name = "sign", about = "Sign a file")]
    Sign {
        #[arg(short = 'u', long = "user", help = "Signing key ID or user ID")]
        user: String,
        #[arg(short = 'o', long = "output", help = "Output signature file path")]
        output: Option<String>,
        #[arg(help = "Input file path (omit or - for stdin)")]
        input: Option<String>,
    },
    #[command(name = "verify", about = "Verify a signature")]
    Verify {
        #[arg(help = "Signature file path")]
        signature: String,
        #[arg(help = "Original file path (omit or - for stdin)")]
        input: Option<String>,
    },
    #[command(name = "export", about = "Export a public key (armored)")]
    Export {
        #[arg(help = "Key ID or user ID to export")]
        key_id: String,
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
    },
    #[command(name = "import", about = "Import a public key (armored)")]
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
