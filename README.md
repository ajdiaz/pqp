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
#   user-id: alice@example.com
#   created: 2026-07-28T12:00:00Z
#   kem: ML-KEM-768
#   dsa: ML-DSA-65
#   encoding: BASE64
#   compress: none
#   expires: 2031-07-27T12:00:00Z
#   fingerprint: 3a7bd3e25f46a09e8e4f5e2c7b1d8a3c9f0e2d4b6a8c1e3f5a7b9d0c2e4f6a8b
```

Custom variants, no-passphrase, and expiration:

```bash
pqp gen-key -u "bot@example.com" --no-passphrase --kem ML-KEM-1024 --dsa ML-DSA-87
pqp gen-key -u "short-term@example.com" --expiration-date 30d
pqp gen-key -u "long-term@example.com" --expiration-date 2035-12-31
pqp gen-key -u "labeled@example.com" --metadata department=engineering --metadata role=service-bot
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

Allow using an expired recipient key (warns, then proceeds):

```bash
pqp encrypt -r alice -o outdated.pqp.enc --allow-expired doc.txt
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

pqp sign -u expired-key -o legacy.pqp.sig --allow-expired doc.txt
# Warning: signing key expired, proceeding...

pqp verify contract.pdf.pqp.sig contract.pdf
# Verified: signed by key-id=a1b2c3d4e5f6a7b8
```

### List, export, import, remove keys

```bash
pqp list-keys
# Key ID           User ID             Created               Type   KEM       Sign       Compress  Expires    Status   Fingerprint
# --------------------------------------------------------------------------------------------------------------------------
# a1b2c3d4e5f6a7b8 alice@example.com   2026-07-28T12:00:00Z  pub+sec ML-KEM-768 ML-DSA-65 none     2031-07-27 valid      3a7bd3e25f46a09e...
pqp list-keys --format json
pqp export a1b2c3d4e5f6a7b8                        # PQP format (default, ZSTD+Base64)
pqp export --format armor a1b2c3...                 # ASCII-armored PEM-style
pqp export --format pqp --compress none a1b2c3...   # PQP without compression
pqp import alice.pqp.asc                             # Auto-detects format
pqp import key.pqp.pub                               # PQP format auto-detected
pqp import --url https://keys.example.com/bob.pqp.asc
pqp import --force key.pqp.pub                        # Override key with same fingerprint
pqp remove-key a1b2c3d4e5f6a7b8 --remove-private-key
pqp remove-key a1b2c3d4e5f6a7b8 --remove-private-key
pqp purge-keys                                                 # Remove all public keys (asks confirmation)
pqp purge-keys --no-ask-confirmation                           # Remove all public keys (no prompt)
pqp purge-keys --remove-private-keys --no-ask-confirmation     # Remove all keys including private
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
| `export` | Export a public key (PQP format by default) |
| `import` | Import a public key (armored or PQP) |
| `remove-key` | Remove a public (and optionally private) key |
| `purge-keys` | Remove all keys from the keyring |

### 🌐 Global flags

| Flag | Description |
|---|---|---|
| `--dry-run`, `-n` | Print dry-run message and exit without action |
| `--keyring-path <path>` | Use alternative keyring directory (or set `KEYRING_PATH` env var) |

### ⚙️ Global configuration file

`pqp` follows the XDG Base Directory specification:

| File | XDG Path | Legacy Path (fallback) |
|---|---|---|
| Config | `~/.config/pqp/pqp.toml` | `~/.pqp/pqp.toml` |
| Keys | `~/.local/share/pqp/keys/` | `~/.pqp/keys/` |

Set `PQP_HOME` environment variable to override both XDG and legacy paths.
When set, pqp uses the legacy structure inside that directory
(`$PQP_HOME/.pqp/pqp.toml` for config, `$PQP_HOME/.pqp/keys/` for keys).

Set default options per command with TOML sections in the config file; CLI flags always win over config file values.

**Available options:**

| Section | Key | Values | Default | Trade-offs |
|---|---|---|---|---|
| `[gen-key]` | `kem` | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | `ML-KEM-768` | 512 = fastest/smallest, 1024 = max security but 2× size |
| `[gen-key]` | `dsa` | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | `ML-DSA-65` | 44 = compact & fast, 87 = max security but 2× signature size |
| `[gen-key]` | `encoding` | `BASE64`, `ASCII85` | `BASE64` | ASCII85 ~25% smaller but less universal |
| `[gen-key]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `none` | stored as per-key default, commands use own default unless set |
| `[gen-key]` | `expiration-date` | `5y`, `30d`, `2030-12-31`, etc | `5y` | relative or absolute; also `1y`, `12m`, `90d` |
| `[gen-key]` | `metadata` | arbitrary `key=value` pairs | (none) | stored in pqp.conf and armor headers; not interpreted |
| `[gen-key]` | `argon2-mem` | KiB (e.g. `19456`, `65536`) | `19456` (~19 MiB) | higher = more GPU/ASIC resistance, more RAM |
| `[gen-key]` | `argon2-time` | iterations (e.g. `2`, `3`) | `2` | higher = slower derivation, linearly more work |
| `[gen-key]` | `argon2-par` | threads (e.g. `1`, `4`) | `1` | higher = faster on multi-core, less memory-hard |
| `[encrypt]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
| `[sign]` | `allow-expired` | `true`, `false` | `false` | if true, warn but proceed with expired keys |
| `[list-keys]` | `format` | `table`, `no-headers`, `json` | `table` | `table` human-friendly, `no-headers` for scripts, `json` for programs |
| `[encrypt]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | zstd = best speed/ratio, lzma = best ratio/slowest, none = raw |
| `[export]` | `format` | `armor`, `pqp` | `pqp` | pqp = self-describing & compact, armor = universal pasteable |
| `[export]` | `compress` | `none`, `zstd`, `gzip`, `bzip2`, `lzma` | `zstd` | Only for PQP format; same trade-offs as encrypt |
| `[keyring]` | `path` | any directory path | (none) | overrides default keyring location (XDG / PQP_HOME) |

Example with non-default choices:

```toml
[gen-key]
kem = "ML-KEM-1024"    # Maximum quantum security
dsa = "ML-DSA-87"      # Maximum signature strength
encoding = "ASCII85"   # Compact export

[list-keys]
format = "json"        # Machine-readable output

[encrypt]
compress = "lzma"      # Best compression, slowest

[export]
format = "pqp"         # Self-describing format
compress = "none"      # No compression on export
```

A fully commented sample with detailed pros/cons for every value is at [`pqp.toml.sample`](pqp.toml.sample).

### 🔒 Security hardening

| Measure | Description |
|---|---|
| File permissions | Secret keys and metadata at rest use `0o600` (owner-only). Key directories use `0o700`. Public keys use `0o644`. |
| Decompression limit | Output from any compressed payload is capped at 100 MiB to prevent decompression bombs. |
| HTTP timeout | `import --url` enforces a 30-second timeout to prevent slow-loris attacks. |
| Path validation | Key IDs are strictly validated as `^[0-9a-f]{16}$` before any filesystem operation. |
| Key separation | KEM shared secrets undergo SHA3-256 KDF with domain separation (`pqp-kem-encrypt-v1`) per NIST SP 800-56C. |
| Secrets zeroization | All passphrases and secret key material are zeroized in memory after use. |
| Constant-time compare | Signature hash comparison uses `subtle::ConstantTimeEq`. |
| Argon2id configurable | KDF parameters (memory, time, parallelism) are stored per-key and configurable via CLI or config file. |

---

### ⚙️ Per-command options

**gen-key:** `-u <user>` · `--no-passphrase` · `--kem <variant>` · `--dsa <variant>` · `--encoding <enc>` · `--compress <algo>` · `--expiration-date <date>` · `--metadata <key=value>` · `--argon2-mem <kib>` · `--argon2-time <count>` · `--argon2-par <count>`

**list-keys:** `--format <table|no-headers|json>`

**encrypt:** `-r <recipient>` · `-o <outfile>` · `--compress <algo>` · `--sign` · `--signer <user>` · `--allow-expired`

**decrypt:** `-o <outfile>` · `--no-passphrase`

**sign:** `-u <user>` · `-o <outfile>` · `--no-passphrase` · `--allow-expired`

**verify:** `<signature>` · `[infile]`

**export:** `<key-id>` · `-o <outfile>` · `--format <pqp|armor>` · `--compress <algo>`

**import:** `[infile]` · `--url <url>` · `--dont-ask-confirmation`

**remove-key:** `<key-id>` · `--dont-ask` · `--remove-private-key`

**purge-keys:** `--no-ask-confirmation` · `--remove-private-keys`

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

| Public Key (PQP) | `ML-KEM-768+ML-DSA-65+ZSTD+BASE64::<payload>` | `.pqp.pub` |
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

MIT — see [COPYING](COPYING) for details.
