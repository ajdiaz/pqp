# pqp zsh completion
# Source: source completions/pqp.zsh
# Or install: cp completions/pqp.zsh /usr/share/zsh/site-functions/_pqp

#compdef pqp

_pqp() {
    local -a args
    local -a subcommands

    subcommands=(
        'gen-key:Generate a PQ key pair (Kyber + Dilithium)'
        'list-keys:List keys in the keyring'
        'encrypt:Encrypt a file for a recipient'
        'decrypt:Decrypt a file'
        'sign:Sign a file with a private key'
        'verify:Verify a signature'
        'export:Export a public key (armored or PQP format)'
        'remove-key:Remove a public key from the keyring' \
'purge-keys:Remove all keys from the keyring'
        'edit-key:Edit an existing key'\''s metadata and/or passphrase'
        'import:Import a public key'
    )

    args=(
        '(-n --dry-run)'{-n,--dry-run}'[Do nothing, print dry-run message]'
        '--keyring-path[Use an alternative keyring directory]:keyring path:_files -/'
        '--config[Path to an alternative configuration file]:config file:_files'
        '--password-tool[External tool for passphrase prompts]'
        '*: :->subcmd'
    )

    _arguments -C "$args[@]" && return

    case "$state" in
        subcmd)
            _describe -t commands 'pqp commands' subcommands
            ;;
    esac

    case "$words[1]" in
        gen-key)
            _pqp_gen_key
            ;;
        list-keys)
            _pqp_list_keys
            ;;
        encrypt)
            _pqp_encrypt
            ;;
        decrypt)
            _pqp_decrypt
            ;;
        sign)
            _pqp_sign
            ;;
        verify)
            _pqp_verify
            ;;
        export)
            _pqp_export
            ;;
        edit-key)
            _pqp_edit_key
            ;;
        remove-key)
            _pqp_remove_key
            ;;
        purge-keys)
            _pqp_purge_keys
            ;;
        import)
            _pqp_import
            ;;
    esac
}

_pqp_gen_key() {
    _arguments \
        '(-u --user)'{-u,--user}'[User ID for the key]:user ID:->user' \
        '--no-passphrase[Generate key without a passphrase]' \
        '--kem[KEM algorithm variant]:variant:(ML-KEM-512 ML-KEM-768 ML-KEM-1024)' \
        '--dsa[Digital signature algorithm variant]:variant:(ML-DSA-44 ML-DSA-65 ML-DSA-87)' \
        '--encoding[Encoding for armored output]:encoding:(BASE64 ASCII85)' \
        '--compress[Default compression algorithm preference]:compress:(none zstd gzip bzip2 lzma)' \
        '--expiration-date[Key expiration date]:expiration:' \
        '--metadata[Key metadata as key=value (repeatable)]:metadata:' \
        '--argon2-mem[Argon2id memory cost in KiB]:mem size:' \
        '--argon2-time[Argon2id time cost (iterations)]:iterations:' \
        '--argon2-par[Argon2id parallelism (threads)]:threads:'
}

_pqp_list_keys() {
    _arguments \
        '--format[Output format]:format:(table no-headers json)'
}

_pqp_encrypt() {
    _arguments \
        '(-r --recipient)'{-r,--recipient}'[Recipient key ID or user ID]:recipient:' \
        '(-o --output)'{-o,--output}'[Output file path]:output file:_files' \
        '(-s --sign)'{-s,--sign}'[Sign the ciphertext with sender key]' \
        '(-u --signer)'{-u,--signer}'[Signer key ID or user ID]:signer:' \
        '--compress[Compression algorithm]:compress:(none zstd gzip bzip2 lzma)' \
        '--allow-expired[Allow using an expired key]' \
        '*:input file:_files'
}

_pqp_decrypt() {
    _arguments \
        '(-o --output)'{-o,--output}'[Output file path]:output file:_files' \
        '--no-passphrase[Use empty passphrase (no prompt)]' \
        '*:input file:_files'
}

_pqp_sign() {
    _arguments \
        '(-u --user)'{-u,--user}'[Signing key ID or user ID]:user:' \
        '(-o --output)'{-o,--output}'[Output signature file path]:output file:_files' \
        '--no-passphrase[Use empty passphrase (no prompt)]' \
        '--allow-expired[Allow using an expired key]' \
        '*:input file:_files'
}

_pqp_verify() {
    _arguments \
        ':signature file:_files' \
        '*:input file:_files'
}

_pqp_export() {
    _arguments \
        '(-o --output)'{-o,--output}'[Output file path]:output file:_files' \
        '--format[Output format]:format:(armor pqp)' \
        '--compress[Compression for PQP format]:compress:(none zstd gzip bzip2 lzma)' \
        ':key ID or user ID:'
}

_pqp_edit_key() {
    _arguments \
        '(-u --user)'{-u,--user}'[New user ID for the key]:user ID:' \
        '--expiration-date[New expiration date]:expiration:' \
        '--encoding[New encoding for armored output]:encoding:(BASE64 ASCII85)' \
        '--compress[New default compression algorithm]:compress:(none zstd gzip bzip2 lzma)' \
        '--passphrase[Change the key passphrase]' \
        '--no-passphrase[Set empty passphrase]' \
        '--metadata[Add key metadata as key=value (repeatable)]:metadata:' \
        ':key ID or user ID:'
}

_pqp_remove_key() {
    _arguments \
        '--dont-ask[Skip confirmation prompt before removing]' \
        '--remove-private-key[Also remove the private key if it exists]' \
        ':key ID or user ID:'
}

_pqp_purge_keys() {
    _arguments \
        '--no-ask-confirmation[Skip confirmation prompt before removing keys]' \
        '--remove-private-keys[Also remove private keys if they exist]'
}

_pqp_import() {
    _arguments \
        '--url[URL to fetch the armored key from]:url:' \
        '--dont-ask-confirmation[Skip confirmation prompt before importing]' \
        '--force[Force override of an existing key with the same fingerprint]' \
        '*:input file:_files'
}

_pqp "$@"
