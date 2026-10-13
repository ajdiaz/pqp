//! Passphrase-caching agent, a `gpg-agent` / `ssh-agent` analogue for `pqp`.
//!
//! The agent keeps decrypted passphrases in memory so that repeated
//! private-key operations (`decrypt`, `sign`, `encrypt --sign`, `edit-key`)
//! do not ask the user for the passphrase every time. Entries expire after a
//! configurable time-to-live (default [`DEFAULT_EXPIRE_TIME`]), and the cache
//! is refreshed every time a passphrase is used, mirroring `gpg-agent`'s
//! `default-cache-ttl` behaviour.
//!
//! # Architecture
//!
//! ```text
//!   pqp decrypt ──┐
//!   pqp sign    ──┼── Unix socket ──► pqp agent (daemon)
//!   pqp encrypt ──┘                     │
//!                                       └─ in-memory passphrase cache
//! ```
//!
//! * [`server`] implements the daemon: it binds a Unix domain socket, serves
//!   requests from a thread pool (one thread per connection), and owns the
//!   passphrase cache.
//! * [`client`] implements the wire protocol used to talk to a running agent
//!   (`ping`, `get`, `put`, `del`, `clear`, `stop`).
//! * [`protocol`] defines the line-oriented request/response framing shared
//!   by both sides.
//! * [`integration`] contains the helpers the CLI uses to transparently
//!   consult the agent while loading secret keys.
//!
//! # Security
//!
//! * Passphrases live only in process memory and are always held in
//!   [`zeroize::Zeroizing`] buffers, so they are wiped when an entry expires,
//!   is evicted, or the agent shuts down.
//! * The socket is created with `0o600` permissions inside a `0o700`
//!   directory, so only the owning user can reach it — the same trust model
//!   as `ssh-agent` and `gpg-agent`.
//! * Nothing is ever written to disk; the cache is purely volatile.

pub mod client;
pub mod integration;
pub mod protocol;
pub mod server;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;

pub use integration::{
    cache_passphrase, forget_cached_passphrase, get_cached_passphrase, load_key_for_decrypt,
    load_secret_key_via_agent,
};

/// Default cache time-to-live when neither the CLI flag nor the config file
/// specify one (10 minutes, matching `gpg-agent`'s historical default).
pub const DEFAULT_EXPIRE_TIME: &str = "10m";

/// Resolve the default agent Unix socket path.
///
/// Precedence:
/// 1. `PQP_HOME` set → `$PQP_HOME/.pqp/agent.sock` (isolated instances)
/// 2. `XDG_RUNTIME_DIR` set and absolute → `$XDG_RUNTIME_DIR/pqp-agent.sock`
/// 3. Fallback → `<XDG data dir>/pqp/agent.sock`
///
/// The CLI `--unix-socket-path` flag and the `[agent] unix-socket-path`
/// config key take precedence over this default.
pub fn default_socket_path() -> Result<PathBuf> {
    if let Ok(pqp_home) = std::env::var("PQP_HOME") {
        return Ok(PathBuf::from(pqp_home).join(".pqp").join("agent.sock"));
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(runtime);
        if path.is_absolute() {
            return Ok(path.join("pqp-agent.sock"));
        }
    }
    let data = crate::util::data_dir().context("cannot determine XDG data directory")?;
    Ok(data.join("pqp").join("agent.sock"))
}

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Accepted forms:
/// * a bare integer, interpreted as seconds (`600`)
/// * one or more `<number><unit>` components, where unit is one of
///   `s` (seconds), `m` (minutes), `h` (hours) or `d` (days). Components may
///   be combined, e.g. `1h30m` or `2d12h`.
///
/// A zero duration (e.g. `0`, `0m`) is rejected: a cache that never holds
/// anything is almost certainly a mistake.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty duration");
    }

    if let Ok(seconds) = trimmed.parse::<u64>() {
        return seconds_to_duration(seconds);
    }

    let mut total: u64 = 0;
    let mut number = String::new();
    let mut saw_unit = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        let value: u64 = number.parse().with_context(|| {
            format!(
                "invalid duration `{}`: missing number before `{}`",
                input, ch
            )
        })?;
        number.clear();
        let multiplier = match ch.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            other => anyhow::bail!("unknown duration unit `{}` in `{}`", other, input),
        };
        total = total
            .checked_add(
                value
                    .checked_mul(multiplier)
                    .ok_or_else(|| anyhow::anyhow!("duration `{}` overflows", input))?,
            )
            .ok_or_else(|| anyhow::anyhow!("duration `{}` overflows", input))?;
        saw_unit = true;
    }

    if !number.is_empty() || !saw_unit {
        anyhow::bail!(
            "invalid duration `{}`: expected a unit suffix (s, m, h, d)",
            input
        );
    }
    seconds_to_duration(total)
}

/// Convert a non-zero number of seconds into a [`Duration`].
fn seconds_to_duration(seconds: u64) -> Result<Duration> {
    if seconds == 0 {
        anyhow::bail!("duration must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

/// Render a [`Duration`] compactly using the largest whole unit that divides
/// it exactly (e.g. `600s` → `10m`, `86400s` → `1d`).
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 86400 && secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_plain_seconds() {
        assert_eq!(parse_duration("600").unwrap(), Duration::from_secs(600));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("8h").unwrap(), Duration::from_secs(28800));
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_compound() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(
            parse_duration("2d12h").unwrap(),
            Duration::from_secs(216000)
        );
    }

    #[test]
    fn test_parse_duration_uppercase_units() {
        assert_eq!(parse_duration("5M").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  30s ").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_rejects_zero() {
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("0m").is_err());
    }

    #[test]
    fn test_parse_duration_rejects_empty() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
    }

    #[test]
    fn test_parse_duration_rejects_unknown_unit() {
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("1w").is_err());
    }

    #[test]
    fn test_parse_duration_rejects_missing_number() {
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("h30m").is_err());
    }

    #[test]
    fn test_parse_duration_rejects_trailing_number() {
        assert!(parse_duration("1h30").is_err());
    }

    #[test]
    fn test_format_duration_units() {
        assert_eq!(format_duration(Duration::from_secs(600)), "10m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(5400)), "90m");
    }

    #[test]
    fn test_default_socket_path_uses_pqp_home() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::var_os("PQP_HOME");
        std::env::set_var("PQP_HOME", dir.path());
        let path = default_socket_path().unwrap();
        assert_eq!(path, dir.path().join(".pqp").join("agent.sock"));
        match original {
            Some(v) => std::env::set_var("PQP_HOME", v),
            None => std::env::remove_var("PQP_HOME"),
        }
    }
}
