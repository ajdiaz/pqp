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
    },
    #[command(name = "list-keys", about = "List public keys in keyring")]
    ListKeys,
    #[command(name = "encrypt", about = "Encrypt a file for a recipient")]
    Encrypt {
        #[arg(short = 'r', long = "recipient", help = "Recipient key ID")]
        recipient: String,
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(help = "Input file path")]
        input: String,
        #[arg(
            short = 's',
            long = "sign",
            help = "Sign the ciphertext with sender key"
        )]
        sign: bool,
        #[arg(short = 'u', long = "signer", help = "Signer key ID (requires --sign)")]
        signer: Option<String>,
    },
    #[command(name = "decrypt", about = "Decrypt a file")]
    Decrypt {
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
        #[arg(help = "Input file path")]
        input: String,
    },
    #[command(name = "sign", about = "Sign a file")]
    Sign {
        #[arg(short = 'u', long = "user", help = "Signing key ID")]
        user: String,
        #[arg(short = 'o', long = "output", help = "Output signature file path")]
        output: Option<String>,
        #[arg(help = "Input file path")]
        input: String,
    },
    #[command(name = "verify", about = "Verify a signature")]
    Verify {
        #[arg(help = "Signature file path")]
        signature: String,
        #[arg(help = "Original file path")]
        input: String,
    },
    #[command(name = "export", about = "Export a public key (armored)")]
    Export {
        #[arg(help = "Key ID to export")]
        key_id: String,
        #[arg(short = 'o', long = "output", help = "Output file path")]
        output: Option<String>,
    },
    #[command(name = "import", about = "Import a public key (armored)")]
    Import {
        #[arg(help = "Armored key file path")]
        input: String,
    },
}
