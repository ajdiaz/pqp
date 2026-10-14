//! Client side of the `pqp` passphrase agent protocol.
//!
//! These helpers connect to a running agent over its Unix socket and speak
//! the line-oriented protocol defined in [`super::protocol`]. Each call opens
//! a short-lived connection, performs one request/response exchange, and
//! closes it.
//!
//! Callers that only want "best effort" behaviour (e.g. the CLI, which should
//! still work when no agent is running) can use the higher-level wrappers in
//! [`super::integration`], which swallow connection errors.

use super::protocol::{Request, Response};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Connect to the agent listening on `socket`.
fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket)
        .with_context(|| format!("connecting to agent socket {}", socket.display()))
}

/// Send a single request and read a single response line.
fn roundtrip(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream = connect(socket)?;
    let mut line = request.encode();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .context("sending agent request")?;
    stream.flush().context("flushing agent request")?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .context("reading agent response")?;
    Response::parse(response.trim_end_matches(['\n', '\r'])).map_err(|e| anyhow::anyhow!(e))
}

/// Return `true` if an agent is reachable at `socket` and answers `PING`.
pub fn is_running(socket: &Path) -> bool {
    matches!(roundtrip(socket, &Request::Ping), Ok(Response::Ok(_)))
}

/// Ask the agent to shut down gracefully.
///
/// Returns an error if no agent is reachable or it refuses to stop.
pub fn stop(socket: &Path) -> Result<()> {
    match roundtrip(socket, &Request::Exit)? {
        Response::Ok(_) => Ok(()),
        Response::Err(message) => anyhow::bail!("agent refused to stop: {}", message),
        Response::Data(_) => anyhow::bail!("unexpected agent response to EXIT"),
    }
}

/// Forget every passphrase cached by the agent.
///
/// Returns an error if no agent is reachable.
pub fn clear(socket: &Path) -> Result<()> {
    match roundtrip(socket, &Request::Clear)? {
        Response::Ok(_) => Ok(()),
        Response::Err(message) => anyhow::bail!("agent refused to clear: {}", message),
        Response::Data(_) => anyhow::bail!("unexpected agent response to CLEAR"),
    }
}

/// Fetch the passphrase cached for `key_id`.
///
/// Returns `Ok(None)` when the agent has no (valid) entry for the key, and an
/// error only when the connection itself fails or the reply is malformed.
pub fn get(socket: &Path, key_id: &str) -> Result<Option<String>> {
    let response = roundtrip(
        socket,
        &Request::Get {
            key_id: key_id.to_string(),
        },
    )?;
    match response {
        Response::Data(bytes) => Ok(Some(
            String::from_utf8(bytes).context("agent returned a non-UTF-8 passphrase")?,
        )),
        Response::Ok(_) | Response::Err(_) => Ok(None),
    }
}

/// Cache `passphrase` for `key_id`.
///
/// Returns an error if no agent is reachable or it rejects the request.
pub fn put(socket: &Path, key_id: &str, passphrase: &str) -> Result<()> {
    let response = roundtrip(
        socket,
        &Request::Put {
            key_id: key_id.to_string(),
            passphrase: passphrase.as_bytes().to_vec(),
        },
    )?;
    match response {
        Response::Ok(_) => Ok(()),
        Response::Err(message) => anyhow::bail!("agent rejected passphrase: {}", message),
        Response::Data(_) => anyhow::bail!("unexpected agent response to PUT"),
    }
}

/// Forget the passphrase cached for `key_id`.
///
/// Returns an error if no agent is reachable.
pub fn del(socket: &Path, key_id: &str) -> Result<()> {
    match roundtrip(
        socket,
        &Request::Del {
            key_id: key_id.to_string(),
        },
    )? {
        Response::Ok(_) => Ok(()),
        Response::Err(message) => anyhow::bail!("agent refused to forget passphrase: {}", message),
        Response::Data(_) => anyhow::bail!("unexpected agent response to DEL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::server;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// Start a test agent on a temporary socket and return the socket path and
    /// a join handle. The socket path is unique per test (temp dir).
    fn start_agent(ttl: Duration) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let socket_for_thread = socket.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = ready_tx.send(());
            let _ = server::run(&socket_for_thread, ttl);
        });
        // The thread signals readiness before binding, so poll for the socket
        // to actually accept connections.
        ready_rx.recv().ok();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if is_running(&socket) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        (dir, socket, handle)
    }

    #[test]
    fn test_client_server_roundtrip() {
        let (_dir, socket, handle) = start_agent(Duration::from_secs(60));
        assert!(is_running(&socket));
        let key = "0123456789abcdef";
        assert!(get(&socket, key).unwrap().is_none());
        put(&socket, key, "hunter2").unwrap();
        assert_eq!(get(&socket, key).unwrap().as_deref(), Some("hunter2"));
        del(&socket, key).unwrap();
        assert!(get(&socket, key).unwrap().is_none());
        clear(&socket).unwrap();
        stop(&socket).unwrap();
        handle.join().unwrap();
        assert!(!socket.exists());
    }

    #[test]
    fn test_client_server_expiry() {
        let (_dir, socket, handle) = start_agent(Duration::from_millis(30));
        let key = "0123456789abcdef";
        put(&socket, key, "hunter2").unwrap();
        assert_eq!(get(&socket, key).unwrap().as_deref(), Some("hunter2"));
        std::thread::sleep(Duration::from_millis(80));
        assert!(get(&socket, key).unwrap().is_none());
        stop(&socket).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn test_is_running_false_without_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(!is_running(&socket));
    }

    #[test]
    fn test_get_without_agent_errors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(get(&socket, "0123456789abcdef").is_err());
    }

    #[test]
    fn test_stop_without_agent_errors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(stop(&socket).is_err());
    }
}
