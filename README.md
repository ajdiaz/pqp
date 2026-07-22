# 🛡️ pqp — Quantum-Resistant GPG Emulation

A modern CLI tool that brings **post-quantum cryptography** to your terminal. Emulates GPG's key management, encryption, signing, and file format — but replaces RSA/ECC with **ML-KEM (Kyber)** and **ML-DSA (Dilithium)**, the FIPS 203/204 standards for the quantum era.

```bash
# 🔐 Encrypt a file for a recipient
pqp encrypt -r alice@example.com -o secret.pqp.enc doc.pdf

# 📜 Sign and verify  
pqp sign -u bob@example.com -o doc.pdf.pqp.sig doc.pdf
pqp verify doc.pdf.pqp.sig doc.pdf

# 🔑 Generate a key pair
pqp gen-key -u "alice@example.com"
```

---

## 🧬 Cryptographic Stack

| Layer | Algorithm | Standard |
|---|---|---|
| Key Encapsulation | ML-KEM (CRYSTALS-Kyber) | FIPS 203 |
| Digital Signatures | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 |
| Symmetric Encryption | XChaCha20-Poly1305 | — |
| Key Derivation | Argon2id | RFC 9106 |
| Compression | Zstandard, GZIP, BZIP2, LZMA, DEFLATE | — |
| Encoding | BASE64, ASCII85 | — |

All cryptography uses pure Rust crates from [RustCrypto](https://github.com/RustCrypto).

---

## 🚀 Quick Start

### Generate a key pair

```bash
pqp gen-key -u "alice@example.com"
# Enter passphrase for new key:
# Confirm passphrase:
# Generated key pair: key-id=a1b2c3d4e5f6a7b8
```

Custom variants and no-passphrase mode:

```bash
pqp gen-key -u "bot@example.com" --no-passphrase --kem ML-KEM-1024 --dsa ML-DSA-87
```

### Encrypt a file

```bash
pqp encrypt -r a1b2c3d4e5f6a7b8 -o report.pdf.pqp.enc report.pdf
# Encrypted: report.pdf.pqp.enc
```

Compress before encrypting:

```bash
pqp encrypt -r alice -o bigfile.pqp.enc --compress gzip bigfile.tar
```

Sign the ciphertext with your key:

```bash
pqp encrypt -r bob -o msg.pqp.enc -s msg.txt
```

### Decrypt a file

```bash
pqp decrypt -o report.pdf report.pdf.pqp.enc
# Enter passphrase for secret key:
# Decrypted: report.pdf
```

### Sign and verify

```bash
pqp sign -u a1b2c3d4e5f6a7b8 -o contract.pdf.pqp.sig contract.pdf
# Signed: contract.pdf.pqp.sig

pqp verify contract.pdf.pqp.sig contract.pdf
# Verified: signed by key-id=a1b2c3d4e5f6a7b8
```

### List, export, import, remove keys

```bash
pqp list-keys --format json
pqp export a1b2c3d4e5f6a7b8 -o alice.pqp.asc
pqp export --format pqp a1b2c3d4e5f6a7b8           # Self-describing PQP format (ZSTD by default)
pqp export --format pqp --compress none a1b2c3...   # PQP without compression
pqp import alice.pqp.asc                             # Auto-detects format
pqp import key.pqp.pub                               # PQP format auto-detected
pqp import --url https://keys.example.com/bob.pqp.asc
pqp remove-key a1b2c3d4e5f6a7b8 --remove-private-key
```

---

## 📋 Commands

| Command | Description |
|---|---|
| `gen-key` | Generate a PQ key pair (Kyber + Dilithium) |
| `list-keys` | List keys in the keyring |
| `encrypt` | Encrypt a file for a recipient |
| `decrypt` | Decrypt a file |
| `sign` | Sign a file with a private key |
| `verify` | Verify a signature |
| `export` | Export a public key (armored) |
| `import` | Import a public key (armored) |
| `remove-key` | Remove a public (and optionally private) key |

### 🌐 Global flags

| Flag | Description |
|---|---|
| `--dry-run`, `-n` | Print dry-run message and exit without action |

### ⚙️ Global configuration file

`pqp` reads `~/.pqp/pqp.toml` if it exists. Set default options per command with TOML sections; CLI flags always win.

```toml
[gen-key]
kem = "ML-KEM-1024"
dsa = "ML-DSA-87"

[encrypt]
compress = "gzip"

[export]
format = "pqp"
compress = "none"
```

A sample with all options and comments is at `pqp.toml.sample`.

### ⚙️ Per-command options

**gen-key:** `-u <user>` · `--no-passphrase` · `--kem <variant>` · `--dsa <variant>` · `--encoding <enc>`

**list-keys:** `--format <table|no-headers|json>`

**encrypt:** `-r <recipient>` · `-o <outfile>` · `--compress <algo>` · `--sign` · `--signer <user>`

**decrypt:** `-o <outfile>` · `--no-passphrase`

**sign:** `-u <user>` · `-o <outfile>` · `--no-passphrase`

**verify:** `<signature>` · `[infile]`

**export:** `<key-id>` · `-o <outfile>` · `--format <armor|pqp>` · `--compress <algo>`

**import:** `[infile]` · `--url <url>` · `--dont-ask-confirmation`

**remove-key:** `<key-id>` · `--dont-ask` · `--remove-private-key`

---

## 📁 File Format

All encrypted, signed, and key files use the format:

```
AlgorithmList::EncodedPayload
```

### Examples

| Content | AlgorithmList | Extension |
|---|---|---|
| Encrypted | `ML-KEM+XChaCha20-Poly1305+ZSTD+BASE64` | `.pqp.enc` |
| Signature | `ML-DSA+SHA3-256+BASE64` | `.pqp.sig` |
| Public Key (armor) | `-----BEGIN PQP PUBLIC KEY-----` | `.pqp.asc` |
| Public Key (PQP) | `ML-KEM-768+ML-DSA-65+ZSTD+BASE64` | `.pqp.pub` |

### 🔐 Encrypted file layout

```
┌──────────────────────────────┐
│  AlgorithmList (canonical)  │
├──────────────────────────────┤
│  :: separator                │
├──────────────────────────────┤
│  KEM ciphertext              │
│  Symmetric nonce (24 bytes)  │
│  Symmetric ciphertext + tag  │
│  Optional Dilithium signature│
└──────────────────────────────┘
```

---

## 🔧 Build & Quality

```bash
cargo build --release
cargo test -- --test-threads=1
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

---

## 📜 License

MIT OR Apache-2.0
