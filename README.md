# pqp - Quantum-Resistant GPG Emulation

A CLI tool that emulates GPG's key management, encryption, signing, and file
format, using post-quantum asymmetric algorithms instead of RSA/ECC.

## Algorithms

| Layer | Algorithm |
|---|---|
| Key Encapsulation (KEM) | ML-KEM (CRYSTALS-Kyber) FIPS 203 |
| Digital Signatures | ML-DSA (CRYSTALS-Dilithium) FIPS 204 |
| Symmetric Encryption | XChaCha20-Poly1305 |
| Key Derivation | Argon2id |

## Commands

```
pqp gen-key    Generate a PQ key pair
pqp list-keys  List public keys in keyring
pqp encrypt    Encrypt a file for a recipient
pqp decrypt    Decrypt a file
pqp sign       Sign a file with a private key
pqp verify     Verify a signature
pqp export     Export a public key (armored)
pqp import     Import a public key (armored)
```

## File Format

All encrypted/signed files use the format:
`AlgorithmList::EncodedPayload`

Example: `ML-KEM+XChaCha20-Poly1305+BASE64::<payload>`

## Build

```bash
cargo build --release
cargo test -- --test-threads=1
cargo clippy --all-targets -- -D warnings
```

## License

MIT OR Apache-2.0
