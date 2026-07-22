# pqp fish completion
# Source: source completions/pqp.fish
# Or install: cp completions/pqp.fish ~/.config/fish/completions/pqp.fish

function __pqp_complete_keys
    # Attempt to list key IDs from the keyring; silently ignore errors
    pqp list-keys --format no-headers 2>/dev/null | awk '{print $1}'
end

# Global dry-run flag for all commands
complete -c pqp -s n -l dry-run -d "Do nothing, print dry-run message"

# --- gen-key ---
complete -c pqp -f -n "__fish_use_subcommand" -a gen-key -d "Generate a PQ key pair (Kyber + Dilithium)"
complete -c pqp -f -n "__fish_seen_subcommand_from gen-key" -s u -l user -d "User ID for the key" -r
complete -c pqp -f -n "__fish_seen_subcommand_from gen-key" -l no-passphrase -d "Generate key without a passphrase"
complete -c pqp -f -n "__fish_seen_subcommand_from gen-key" -l kem -d "KEM algorithm variant" -r -xa "ML-KEM-512 ML-KEM-768 ML-KEM-1024"
complete -c pqp -f -n "__fish_seen_subcommand_from gen-key" -l dsa -d "Digital signature algorithm variant" -r -xa "ML-DSA-44 ML-DSA-65 ML-DSA-87"
complete -c pqp -f -n "__fish_seen_subcommand_from gen-key" -l encoding -d "Encoding for armored output" -r -xa "BASE64 ASCII85"

# --- list-keys ---
complete -c pqp -f -n "__fish_use_subcommand" -a list-keys -d "List keys in the keyring"
complete -c pqp -f -n "__fish_seen_subcommand_from list-keys" -l format -d "Output format" -r -xa "table no-headers json"

# --- encrypt ---
complete -c pqp -f -n "__fish_use_subcommand" -a encrypt -d "Encrypt a file for a recipient"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -s r -l recipient -d "Recipient key ID or user ID" -r -a "(__pqp_complete_keys)"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -s o -l output -d "Output file path" -r
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -s s -l sign -d "Sign the ciphertext with sender key"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -s u -l signer -d "Signer key ID or user ID (requires --sign)" -r -a "(__pqp_complete_keys)"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -l compress -d "Compression algorithm" -r -xa "none zstd gzip bzip2 lzma"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from encrypt" -a "(__fish_complete_path)" -d "Input file"

# --- decrypt ---
complete -c pqp -f -n "__fish_use_subcommand" -a decrypt -d "Decrypt a file"
complete -c pqp -f -n "__fish_seen_subcommand_from decrypt" -s o -l output -d "Output file path" -r
complete -c pqp -f -n "__fish_seen_subcommand_from decrypt" -l no-passphrase -d "Use empty passphrase (no prompt)"
complete -c pqp -f -n "__fish_seen_subcommand_from decrypt" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from decrypt" -a "(__fish_complete_path)" -d "Input file"

# --- sign ---
complete -c pqp -f -n "__fish_use_subcommand" -a sign -d "Sign a file with a private key"
complete -c pqp -f -n "__fish_seen_subcommand_from sign" -s u -l user -d "Signing key ID or user ID" -r -a "(__pqp_complete_keys)"
complete -c pqp -f -n "__fish_seen_subcommand_from sign" -s o -l output -d "Output signature file path" -r
complete -c pqp -f -n "__fish_seen_subcommand_from sign" -l no-passphrase -d "Use empty passphrase (no prompt)"
complete -c pqp -f -n "__fish_seen_subcommand_from sign" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from sign" -a "(__fish_complete_path)" -d "Input file"

# --- verify ---
complete -c pqp -f -n "__fish_use_subcommand" -a verify -d "Verify a signature"
complete -c pqp -f -n "__fish_seen_subcommand_from verify" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from verify" -a "(__fish_complete_path)" -d "Signature file"
complete -c pqp -f -n "__fish_seen_subcommand_from verify" -a "(__fish_complete_path)" -d "Original file"

# --- export ---
complete -c pqp -f -n "__fish_use_subcommand" -a export -d "Export a public key (armored or PQP format)"
complete -c pqp -f -n "__fish_seen_subcommand_from export" -s o -l output -d "Output file path" -r
complete -c pqp -f -n "__fish_seen_subcommand_from export" -l format -d "Output format" -r -xa "armor pqp"
complete -c pqp -f -n "__fish_seen_subcommand_from export" -l compress -d "Compression for PQP format" -r -xa "none zstd gzip bzip2 lzma"
complete -c pqp -f -n "__fish_seen_subcommand_from export" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from export" -a "(__pqp_complete_keys)" -d "Key ID or user ID"

# --- remove-key ---
complete -c pqp -f -n "__fish_use_subcommand" -a remove-key -d "Remove a public key from the keyring"
complete -c pqp -f -n "__fish_seen_subcommand_from remove-key" -l dont-ask -d "Skip confirmation prompt"
complete -c pqp -f -n "__fish_seen_subcommand_from remove-key" -l remove-private-key -d "Also remove the private key"
complete -c pqp -f -n "__fish_seen_subcommand_from remove-key" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from remove-key" -a "(__pqp_complete_keys)" -d "Key ID or user ID"

# --- import ---
complete -c pqp -f -n "__fish_use_subcommand" -a import -d "Import a public key"
complete -c pqp -f -n "__fish_seen_subcommand_from import" -l url -d "URL to fetch the armored key from" -r
complete -c pqp -f -n "__fish_seen_subcommand_from import" -l dont-ask-confirmation -d "Skip confirmation prompt"
complete -c pqp -f -n "__fish_seen_subcommand_from import" -l help -d "Print help"
complete -c pqp -f -n "__fish_seen_subcommand_from import" -a "(__fish_complete_path)" -d "Armored key file"
