# pqp bash completion
# Source this file: source completions/pqp.bash
# Or install: cp completions/pqp.bash /etc/bash_completion.d/pqp

_pqp() {
    local cur prev words cword
    _init_completion || return

    # Global flags available before any subcommand
    local global_opts='-n --dry-run --help -h'

    # Subcommands
    local commands='gen-key list-keys encrypt decrypt sign verify export remove-key import'

    # Subcommand dispatch
    if [[ $cword -eq 1 ]]; then
        case "$prev" in
            pqp)
                COMPREPLY=($(compgen -W "$commands $global_opts" -- "$cur"))
                return
                ;;
        esac
    fi

    # Past subcommand — complete flags for that subcommand
    local subcmd
    if [[ $cword -ge 1 ]]; then
        subcmd="${words[1]}"
    fi

    case "$subcmd" in
        gen-key)
            case "$prev" in
                -u|--user)
                    # user ID — free text, no completion
                    return
                    ;;
                --kem)
                    COMPREPLY=($(compgen -W 'ML-KEM-512 ML-KEM-768 ML-KEM-1024' -- "$cur"))
                    return
                    ;;
                --dsa)
                    COMPREPLY=($(compgen -W 'ML-DSA-44 ML-DSA-65 ML-DSA-87' -- "$cur"))
                    return
                    ;;
                --encoding)
                    COMPREPLY=($(compgen -W 'BASE64 ASCII85' -- "$cur"))
                    return
                    ;;
                --compress)
                    COMPREPLY=($(compgen -W 'none zstd gzip bzip2 lzma' -- "$cur"))
                    return
                    ;;
                --expiration-date)
                    # free-form: N y/m/d or YYYY-MM-DD
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--user -u --kem --dsa --encoding --compress --expiration-date --no-passphrase --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        list-keys)
            case "$prev" in
                --format)
                    COMPREPLY=($(compgen -W 'table no-headers json' -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--format --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        encrypt)
            case "$prev" in
                -r|--recipient)
                    # key ID or user ID — defer to dynamic listing if possible
                    return
                    ;;
                -o|--output)
                    # file path
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                -u|--signer)
                    return
                    ;;
                --compress)
                    COMPREPLY=($(compgen -W 'none zstd gzip bzip2 lzma' -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--recipient -r --output -o --sign -s --signer -u --compress --allow-expired --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        decrypt)
            case "$prev" in
                -o|--output)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--output -o --no-passphrase --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        sign)
            case "$prev" in
                -u|--user)
                    return
                    ;;
                -o|--output)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--user -u --output -o --no-passphrase --allow-expired --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        verify)
            case "$prev" in
                *)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
            esac
            ;;
        export)
            case "$prev" in
                -o|--output)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                --format)
                    COMPREPLY=($(compgen -W 'armor pqp' -- "$cur"))
                    return
                    ;;
                --compress)
                    COMPREPLY=($(compgen -W 'none zstd gzip bzip2 lzma' -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--output -o --format --compress --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        remove-key)
            case "$prev" in
                *)
                    COMPREPLY=($(compgen -W '--dont-ask --remove-private-key --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        import)
            case "$prev" in
                --url)
                    # URL — no completion
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W '--url --dont-ask-confirmation --help -h' -- "$cur"))
                    return
                    ;;
            esac
            ;;
        *)
            COMPREPLY=($(compgen -W "$commands $global_opts" -- "$cur"))
            return
            ;;
    esac
} &&
complete -F _pqp pqp
