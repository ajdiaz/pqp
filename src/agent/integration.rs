//! Seam between the CLI and the passphrase agent.
//!
//! These helpers let the rest of `pqp` transparently consult a running agent
//! before prompting the user. All of them treat the agent as optional: when no
//! agent is reachable (or the socket path is unknown) they fall back to the
//! normal interactive prompt, so `pqp` keeps working exactly as before when no
//! agent is running.
//!
//! The main entry points are [`load_secret_key_via_agent`] (for commands that
//! operate on a single known key, such as `sign` and `encrypt --sign`) and
//! [`load_key_for_decrypt`] (for `decrypt`, which must try every key in the
//! keyring but should only prompt once per run).

use super::client;
use crate::{keyring, password};
use anyhow::Result;
use std::path::Path;
use zeroize::Zeroize;

/// Return `true` if an agent is reachable at `socket`.
///
/// `None` (no socket path configured or resolvable) always yields `false`.
pub fn is_agent_running(socket: Option<&Path>) -> bool {
    socket.map(client::is_running).unwrap_or(false)
}

/// Fetch the passphrase cached for `key_id`, if any.
///
/// Connection errors and absent entries both yield `None`, so this is safe to
/// call unconditionally.
pub fn get_cached_passphrase(socket: Option<&Path>, key_id: &str) -> Option<String> {
    let socket = socket?;
    client::get(socket, key_id).ok().flatten()
}

/// Store `passphrase` for `key_id` in the agent. Best effort: failures (for
/// example, no agent running) are ignored.
pub fn cache_passphrase(socket: Option<&Path>, key_id: &str, passphrase: &str) {
    if let Some(socket) = socket {
        let _ = client::put(socket, key_id, passphrase);
    }
}

/// Forget any passphrase cached for `key_id`. Best effort.
pub fn forget_cached_passphrase(socket: Option<&Path>, key_id: &str) {
    if let Some(socket) = socket {
        let _ = client::del(socket, key_id);
    }
}

/// Load and decrypt a secret key, resolving its passphrase through the agent
/// first and falling back to an interactive `prompt`.
///
/// Returns the same `(kem_sk, sign_sk, kem_algorithm, sign_algorithm)` tuple
/// as [`keyring::load_secret_key`].
///
/// Behaviour:
/// 1. When `no_passphrase` is set, the key is loaded with an empty passphrase
///    and the agent is not consulted.
/// 2. A passphrase cached in the agent is tried first; if it is stale (the
///    load fails) the agent entry is dropped and the prompt is used instead.
/// 3. On a successful interactive load the passphrase is cached in the agent
///    (when one is running) so the next operation does not prompt.
///
/// The passphrase buffer is zeroized before returning.
pub fn load_secret_key_via_agent(
    socket: Option<&Path>,
    key_id: &str,
    prompt: &str,
    no_passphrase: bool,
) -> Result<(Vec<u8>, Vec<u8>, String, String)> {
    if no_passphrase {
        return keyring::load_secret_key(key_id, "");
    }

    if let Some(passphrase) = get_cached_passphrase(socket, key_id) {
        match keyring::load_secret_key(key_id, &passphrase) {
            Ok(loaded) => return Ok(loaded),
            Err(_) => forget_cached_passphrase(socket, key_id),
        }
    }

    let passphrase = password::read_passphrase(prompt)?;
    let loaded = keyring::load_secret_key(key_id, &passphrase);
    if loaded.is_ok() {
        cache_passphrase(socket, key_id, &passphrase);
    }
    let mut bytes = passphrase.into_bytes();
    bytes.zeroize();
    loaded
}

/// Attempt to load the secret material for `key_id` during decryption.
///
/// Decryption must try every key in the keyring, but should prompt the user at
/// most once per run. `prompt_passphrase` is a lazily-populated cache of the
/// passphrase entered for this run: the first candidate key that needs it
/// triggers the prompt, and subsequent keys reuse it.
///
/// For each key the agent is consulted first; a cached passphrase that fails to
/// load is dropped and falls through to the prompt. Returns `Ok(None)` when the
/// key could not be loaded (wrong passphrase, or simply not the recipient),
/// and an error only when the interactive prompt itself fails.
pub fn load_key_for_decrypt(
    socket: Option<&Path>,
    key_id: &str,
    no_passphrase: bool,
    prompt_passphrase: &mut Option<String>,
) -> Result<Option<(Vec<u8>, String)>> {
    if !no_passphrase {
        if let Some(passphrase) = get_cached_passphrase(socket, key_id) {
            match keyring::load_secret_key(key_id, &passphrase) {
                Ok((kem_sk, _, kem_algorithm, _)) => return Ok(Some((kem_sk, kem_algorithm))),
                Err(_) => forget_cached_passphrase(socket, key_id),
            }
        }
    }

    if prompt_passphrase.is_none() {
        let passphrase = if no_passphrase {
            String::new()
        } else {
            password::read_passphrase("Enter passphrase for secret key: ")?
        };
        *prompt_passphrase = Some(passphrase);
    }

    let candidate = prompt_passphrase.as_deref().unwrap_or("");
    match keyring::load_secret_key(key_id, candidate) {
        Ok((kem_sk, _, kem_algorithm, _)) => {
            if !no_passphrase {
                cache_passphrase(socket, key_id, candidate);
            }
            Ok(Some((kem_sk, kem_algorithm)))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::server;
    use crate::crypto::{DsaVariant, KemVariant};
    use std::path::PathBuf;
    use std::sync::mpsc;

    fn start_agent(
        ttl: std::time::Duration,
    ) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let socket_for_thread = socket.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = ready_tx.send(());
            let _ = server::run(&socket_for_thread, ttl);
        });
        ready_rx.recv().ok();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if client::is_running(&socket) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        (dir, socket, handle)
    }

    #[test]
    fn test_cache_and_get_passphrase() {
        let (_dir, socket, handle) = start_agent(std::time::Duration::from_secs(60));
        let key = "0123456789abcdef";
        assert!(get_cached_passphrase(Some(&socket), key).is_none());
        cache_passphrase(Some(&socket), key, "s3cr3t");
        assert_eq!(
            get_cached_passphrase(Some(&socket), key).as_deref(),
            Some("s3cr3t")
        );
        forget_cached_passphrase(Some(&socket), key);
        assert!(get_cached_passphrase(Some(&socket), key).is_none());
        client::stop(&socket).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn test_cache_helpers_no_agent_are_noops() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(!is_agent_running(Some(&socket)));
        assert!(get_cached_passphrase(Some(&socket), "0123456789abcdef").is_none());
        // These must not panic or error.
        cache_passphrase(Some(&socket), "0123456789abcdef", "x");
        forget_cached_passphrase(Some(&socket), "0123456789abcdef");
        assert!(!is_agent_running(None));
        assert!(get_cached_passphrase(None, "0123456789abcdef").is_none());
    }

    #[test]
    fn test_load_secret_key_via_agent_uses_cache() {
        // Use an isolated keyring via the thread-local override.
        let keyring_dir = tempfile::tempdir().unwrap();
        crate::keyring::set_keyring_override(Some(keyring_dir.path().to_path_buf()));

        let meta = crate::keyring::generate_key(
            "agent-test@example.com",
            "agent-pass",
            KemVariant::MlKem768,
            DsaVariant::MlDsa65,
            crate::armor::Encoding::Base64,
            "none",
            "5y",
            Vec::new(),
            crate::crypto::sym::DEFAULT_ARGON2_MEM,
            crate::crypto::sym::DEFAULT_ARGON2_TIME,
            crate::crypto::sym::DEFAULT_ARGON2_PAR,
        )
        .unwrap();

        let (_dir, socket, handle) = start_agent(std::time::Duration::from_secs(60));

        // First load: agent misses, so the prompt is invoked via an
        // askpass-style password tool configured for this thread.
        let tool = write_mock_askpass("agent-pass");
        crate::password::set_password_tool(Some(tool));
        let (kem_sk, sign_sk, kem_alg, dsa_alg) =
            load_secret_key_via_agent(Some(&socket), &meta.key_id, "prompt: ", false).unwrap();
        assert!(!kem_sk.is_empty());
        assert!(!sign_sk.is_empty());
        assert_eq!(kem_alg, "ML-KEM-768");
        assert_eq!(dsa_alg, "ML-DSA-65");

        // The successful load must have populated the agent cache.
        assert_eq!(
            get_cached_passphrase(Some(&socket), &meta.key_id).as_deref(),
            Some("agent-pass")
        );

        // Second load without any password tool must succeed purely from cache.
        crate::password::set_password_tool(None);
        let (_, _, _, _) =
            load_secret_key_via_agent(Some(&socket), &meta.key_id, "prompt: ", false).unwrap();

        client::stop(&socket).unwrap();
        handle.join().unwrap();
        crate::keyring::set_keyring_override(None);
    }

    #[test]
    fn test_load_secret_key_via_agent_no_passphrase() {
        let keyring_dir = tempfile::tempdir().unwrap();
        crate::keyring::set_keyring_override(Some(keyring_dir.path().to_path_buf()));

        let meta = crate::keyring::generate_key(
            "nopass@example.com",
            "",
            KemVariant::MlKem768,
            DsaVariant::MlDsa65,
            crate::armor::Encoding::Base64,
            "none",
            "5y",
            Vec::new(),
            crate::crypto::sym::DEFAULT_ARGON2_MEM,
            crate::crypto::sym::DEFAULT_ARGON2_TIME,
            crate::crypto::sym::DEFAULT_ARGON2_PAR,
        )
        .unwrap();

        let (_dir, socket, handle) = start_agent(std::time::Duration::from_secs(60));
        let (_, _, _, _) =
            load_secret_key_via_agent(Some(&socket), &meta.key_id, "prompt: ", true).unwrap();
        // Nothing should have been cached for an empty passphrase.
        assert!(get_cached_passphrase(Some(&socket), &meta.key_id).is_none());

        client::stop(&socket).unwrap();
        handle.join().unwrap();
        crate::keyring::set_keyring_override(None);
    }

    #[test]
    fn test_load_key_for_decrypt_uses_agent_then_prompt() {
        let keyring_dir = tempfile::tempdir().unwrap();
        crate::keyring::set_keyring_override(Some(keyring_dir.path().to_path_buf()));

        let meta = crate::keyring::generate_key(
            "decrypt-agent@example.com",
            "decrypt-pass",
            KemVariant::MlKem768,
            DsaVariant::MlDsa65,
            crate::armor::Encoding::Base64,
            "none",
            "5y",
            Vec::new(),
            crate::crypto::sym::DEFAULT_ARGON2_MEM,
            crate::crypto::sym::DEFAULT_ARGON2_TIME,
            crate::crypto::sym::DEFAULT_ARGON2_PAR,
        )
        .unwrap();

        let (_dir, socket, handle) = start_agent(std::time::Duration::from_secs(60));
        let tool = write_mock_askpass("decrypt-pass");
        crate::password::set_password_tool(Some(tool));

        let mut prompted = None;
        let loaded =
            load_key_for_decrypt(Some(&socket), &meta.key_id, false, &mut prompted).unwrap();
        assert!(loaded.is_some());
        assert_eq!(
            get_cached_passphrase(Some(&socket), &meta.key_id).as_deref(),
            Some("decrypt-pass")
        );

        // Second call: the agent provides the passphrase, so `prompted` stays
        // untouched even with the tool removed.
        crate::password::set_password_tool(None);
        let mut prompted = None;
        let loaded =
            load_key_for_decrypt(Some(&socket), &meta.key_id, false, &mut prompted).unwrap();
        assert!(loaded.is_some());
        assert!(prompted.is_none());

        client::stop(&socket).unwrap();
        handle.join().unwrap();
        crate::keyring::set_keyring_override(None);
    }

    /// Write an executable askpass-style mock script that prints `passphrase`
    /// to stdout. Mirrors the helper used by the integration tests.
    fn write_mock_askpass(passphrase: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mock-askpass.sh");
        let script = format!("#!/bin/sh\nprintf '%s' '{}'\n", passphrase);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Leak the temp dir so the script survives the test (kept alive by OS).
        let leaked = dir.keep();
        leaked.join("mock-askpass.sh").to_string_lossy().to_string()
    }
}
