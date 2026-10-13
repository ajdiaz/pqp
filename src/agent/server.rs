//! Agent daemon: binds a Unix socket and serves the passphrase cache.
//!
//! The daemon is single-address (one Unix socket) and serves one thread per
//! connection. All connections share a single [`Cache`] behind a mutex.
//! A client sends one line and reads one line, but the server also accepts
//! several pipelined requests on the same connection before it is closed.
//!
//! Shutdown is triggered by the `EXIT` request: the handler flips an atomic
//! flag and connects back to the socket once, which wakes the blocking
//! `accept()` loop so it can drop the cache (zeroizing every passphrase) and
//! unlink the socket.

use super::protocol::{Request, Response};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Maximum length of a single protocol line (guards against memory abuse).
const MAX_LINE: u64 = 1024 * 1024;

/// One cached passphrase together with its absolute expiry instant.
struct Entry {
    passphrase: Zeroizing<Vec<u8>>,
    expires_at: Instant,
}

/// In-memory passphrase cache. Dropping an [`Entry`] zeroizes its passphrase.
struct Cache {
    entries: HashMap<String, Entry>,
    ttl: Duration,
}

impl Cache {
    /// Create an empty cache whose entries live for `ttl`.
    fn new(ttl: Duration) -> Self {
        Cache {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Fetch a passphrase, refreshing its expiry on use. Returns `None` when
    /// the key is absent or its entry has expired (in which case the expired
    /// entry is removed and zeroized).
    fn get(&mut self, key_id: &str) -> Option<Vec<u8>> {
        let now = Instant::now();
        match self.entries.get(key_id) {
            None => None,
            Some(entry) if entry.expires_at <= now => {
                self.entries.remove(key_id);
                None
            }
            Some(_) => {
                let ttl = self.ttl;
                let entry = self.entries.get_mut(key_id)?;
                entry.expires_at = now + ttl;
                Some(entry.passphrase.to_vec())
            }
        }
    }

    /// Store `passphrase` for `key_id`, replacing (and zeroizing) any previous
    /// entry.
    fn put(&mut self, key_id: &str, passphrase: Vec<u8>) {
        self.entries.insert(
            key_id.to_string(),
            Entry {
                passphrase: Zeroizing::new(passphrase),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Forget a single key's passphrase.
    fn del(&mut self, key_id: &str) {
        self.entries.remove(key_id);
    }

    /// Forget every cached passphrase.
    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Validate a key id: exactly 16 lowercase hex characters.
fn is_valid_key_id(key_id: &str) -> bool {
    key_id.len() == 16
        && key_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Run the agent daemon until it receives `EXIT` or the socket errors.
///
/// Binds `socket_path` (creating its parent directory with `0o700`
/// permissions and the socket itself with `0o600`), then serves requests,
/// keeping passphrases in memory for at most `ttl` since their last use.
///
/// If a socket file already exists but no agent is reachable at it, the stale
/// file is removed and reused; if another agent *is* reachable, an error is
/// returned so the caller does not silently shadow it.
///
/// The function returns once the agent has shut down gracefully, after
/// zeroizing every cached passphrase and unlinking the socket.
pub fn run(socket_path: &Path, ttl: Duration) -> Result<()> {
    prepare_socket_path(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding agent socket {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .context("setting agent socket permissions")?;

    let cache = Arc::new(Mutex::new(Cache::new(ttl)));
    let shutdown = Arc::new(AtomicBool::new(false));
    let path = Arc::new(socket_path.to_path_buf());

    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let cache = Arc::clone(&cache);
                let shutdown = Arc::clone(&shutdown);
                let path = Arc::clone(&path);
                thread::spawn(move || {
                    let _ = handle_connection(stream, cache, shutdown, path);
                });
            }
            Err(_) => continue,
        }
    }

    // Graceful shutdown: dropping the cache zeroizes every cached passphrase.
    drop(cache);
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Ensure the socket's parent directory exists and remove a stale socket file
/// left behind by a previous (crashed) agent.
fn prepare_socket_path(socket_path: &Path) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).context("creating agent socket directory")?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    if socket_path.exists() {
        if UnixStream::connect(socket_path).is_ok() {
            anyhow::bail!(
                "another pqp agent is already listening on {}",
                socket_path.display()
            );
        }
        std::fs::remove_file(socket_path).context("removing stale agent socket")?;
    }
    Ok(())
}

/// Serve a single client connection until it closes or sends `EXIT`.
fn handle_connection(
    stream: UnixStream,
    cache: Arc<Mutex<Cache>>,
    shutdown: Arc<AtomicBool>,
    socket_path: Arc<PathBuf>,
) -> Result<()> {
    let read_half = stream.try_clone().context("cloning agent stream")?;
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let read = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        if line.len() as u64 > MAX_LINE {
            let _ = write_response(&mut writer, &Response::Err("request line too long".into()));
            break;
        }
        let request = line.trim_end_matches(['\n', '\r']);
        if request.is_empty() {
            continue;
        }

        match Request::parse(request) {
            Ok(Request::Exit) => {
                let _ = write_response(&mut writer, &Response::Ok(None));
                shutdown.store(true, Ordering::SeqCst);
                // Wake the blocking accept() so the listener loop can exit.
                let _ = UnixStream::connect(&*socket_path);
                return Ok(());
            }
            Ok(request) => {
                let response = dispatch(request, &cache);
                if write_response(&mut writer, &response).is_err() {
                    break;
                }
            }
            Err(message) => {
                if write_response(&mut writer, &Response::Err(message)).is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Execute a request against the cache and produce a response.
fn dispatch(request: Request, cache: &Arc<Mutex<Cache>>) -> Response {
    match request {
        Request::Ping => Response::Ok(Some("pqp-agent/1".into())),
        Request::Clear => {
            if let Ok(mut guard) = cache.lock() {
                guard.clear();
            }
            Response::Ok(None)
        }
        Request::Get { key_id } => {
            if !is_valid_key_id(&key_id) {
                return Response::Err("invalid key id".into());
            }
            match cache.lock().ok().and_then(|mut c| c.get(&key_id)) {
                Some(passphrase) => Response::Data(passphrase),
                None => Response::Err("not found".into()),
            }
        }
        Request::Put { key_id, passphrase } => {
            if !is_valid_key_id(&key_id) {
                return Response::Err("invalid key id".into());
            }
            if passphrase.is_empty() {
                return Response::Err("refusing to cache an empty passphrase".into());
            }
            if let Ok(mut guard) = cache.lock() {
                guard.put(&key_id, passphrase);
            }
            Response::Ok(None)
        }
        Request::Del { key_id } => {
            if !is_valid_key_id(&key_id) {
                return Response::Err("invalid key id".into());
            }
            if let Ok(mut guard) = cache.lock() {
                guard.del(&key_id);
            }
            Response::Ok(None)
        }
        // `EXIT` is handled before dispatch; this arm should never run.
        Request::Exit => Response::Ok(None),
    }
}

/// Write a response line (with trailing newline) and flush.
fn write_response(writer: &mut impl Write, response: &Response) -> Result<()> {
    let mut line = response.encode().into_bytes();
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_key_id() {
        assert!(is_valid_key_id("0123456789abcdef"));
        assert!(is_valid_key_id("ffffffffffffffff"));
        assert!(!is_valid_key_id("0123456789ABCDEF"));
        assert!(!is_valid_key_id("0123456789abcde"));
        assert!(!is_valid_key_id("0123456789abcdefg"));
        assert!(!is_valid_key_id("../0123456789ab"));
        assert!(!is_valid_key_id(""));
    }

    #[test]
    fn test_cache_put_get_del() {
        let mut cache = Cache::new(Duration::from_secs(60));
        assert!(cache.get("0123456789abcdef").is_none());
        cache.put("0123456789abcdef", b"secret".to_vec());
        assert_eq!(cache.get("0123456789abcdef"), Some(b"secret".to_vec()));
        cache.del("0123456789abcdef");
        assert!(cache.get("0123456789abcdef").is_none());
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = Cache::new(Duration::from_millis(20));
        cache.put("0123456789abcdef", b"secret".to_vec());
        assert!(cache.get("0123456789abcdef").is_some());
        std::thread::sleep(Duration::from_millis(40));
        assert!(cache.get("0123456789abcdef").is_none());
    }

    #[test]
    fn test_cache_refreshes_expiry_on_use() {
        let mut cache = Cache::new(Duration::from_millis(50));
        cache.put("0123456789abcdef", b"secret".to_vec());
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(25));
            assert!(cache.get("0123456789abcdef").is_some());
        }
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = Cache::new(Duration::from_secs(60));
        cache.put("0123456789abcdef", b"secret".to_vec());
        cache.clear();
        assert!(cache.get("0123456789abcdef").is_none());
    }

    #[test]
    fn test_dispatch_rejects_invalid_key_id() {
        let cache = Arc::new(Mutex::new(Cache::new(Duration::from_secs(60))));
        let response = dispatch(
            Request::Get {
                key_id: "not-a-key".into(),
            },
            &cache,
        );
        assert!(matches!(response, Response::Err(_)));
    }

    #[test]
    fn test_dispatch_rejects_empty_passphrase() {
        let cache = Arc::new(Mutex::new(Cache::new(Duration::from_secs(60))));
        let response = dispatch(
            Request::Put {
                key_id: "0123456789abcdef".into(),
                passphrase: Vec::new(),
            },
            &cache,
        );
        assert!(matches!(response, Response::Err(_)));
    }

    #[test]
    fn test_dispatch_ping() {
        let cache = Arc::new(Mutex::new(Cache::new(Duration::from_secs(60))));
        assert_eq!(
            dispatch(Request::Ping, &cache),
            Response::Ok(Some("pqp-agent/1".into()))
        );
    }
}
