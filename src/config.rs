//! Global configuration file `~/.pqp/pqp.toml`.
//!
//! Provides defaults for CLI options. Precedence (lowest to highest):
//! 1. Code-level hardcoded defaults
//! 2. Config file values in `~/.pqp/pqp.toml`
//! 3. CLI flags passed by the user
//!
//! The config file mirrors CLI command structure using TOML sections:
//! ```toml
//! [gen-key]
//! kem = "ML-KEM-1024"
//! dsa = "ML-DSA-87"
//! encoding = "ASCII85"
//!
//! [list-keys]
//! format = "json"
//!
//! [encrypt]
//! compress = "gzip"
//!
//! [export]
//! format = "pqp"
//! compress = "none"
//! ```

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use toml::Value;

/// Path to the configuration file.
fn config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".pqp").join("pqp.toml"))
}

/// Load the config file, returning an empty map if it doesn't exist.
///
/// Returns a command→option→value mapping. Example:
/// `{"gen-key": {"kem": "ML-KEM-1024", ...}, "encrypt": {"compress": "gzip"}}`
pub fn load() -> Result<HashMap<String, HashMap<String, Value>>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = std::fs::read_to_string(&path).context(format!("reading {}", path.display()))?;
    let raw: Value = toml::from_str(&content).context(format!("parsing {}", path.display()))?;
    let mut result: HashMap<String, HashMap<String, Value>> = HashMap::new();
    if let Value::Table(table) = raw {
        for (cmd, opts) in table {
            if let Value::Table(opt_table) = opts {
                let entries: HashMap<String, Value> = opt_table.into_iter().collect();
                result.insert(cmd, entries);
            }
        }
    }
    Ok(result)
}

/// Apply a config override for a string-typed CLI option.
///
/// Returns the config value if `cli` matches `hard_default` and a config
/// entry exists, otherwise returns `cli` unchanged.
pub fn apply_str(
    cli: &str,
    config_section: Option<&HashMap<String, Value>>,
    key: &str,
    hard_default: &str,
) -> String {
    if cli != hard_default {
        return cli.to_string();
    }
    if let Some(section) = config_section {
        if let Some(Value::String(val)) = section.get(key) {
            return val.clone();
        }
    }
    hard_default.to_string()
}

/// Apply a config override for a boolean-typed CLI option.
pub fn apply_bool(
    cli: bool,
    config_section: Option<&HashMap<String, Value>>,
    key: &str,
    hard_default: bool,
) -> bool {
    if cli != hard_default {
        return cli;
    }
    if let Some(section) = config_section {
        if let Some(Value::Boolean(val)) = section.get(key) {
            return *val;
        }
    }
    hard_default
}

/// Return the config section for a given command name, if present.
pub fn section<'a>(
    config: &'a HashMap<String, HashMap<String, Value>>,
    cmd: &str,
) -> Option<&'a HashMap<String, Value>> {
    config.get(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section(entries: Vec<(&str, &str)>) -> HashMap<String, HashMap<String, Value>> {
        let mut map = HashMap::new();
        let mut opts = HashMap::new();
        for (k, v) in entries {
            opts.insert(k.to_string(), Value::String(v.to_string()));
        }
        map.insert("test-cmd".to_string(), opts);
        map
    }

    #[test]
    fn test_load_returns_empty_when_no_file() {
        let original = std::env::var_os("HOME");
        std::env::set_var("HOME", "/tmp/pqp-test-nonexistent-home-XXXX");
        let cfg = load().unwrap();
        assert!(cfg.is_empty());
        if let Some(h) = original {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn test_apply_str_uses_cli_when_not_default() {
        let section = make_section(vec![("kem", "ML-KEM-1024")]);
        let result = apply_str(
            "ML-KEM-512",
            Some(&section["test-cmd"]),
            "kem",
            "ML-KEM-768",
        );
        assert_eq!(result, "ML-KEM-512");
    }

    #[test]
    fn test_apply_str_uses_config_when_cli_is_default() {
        let section = make_section(vec![("kem", "ML-KEM-1024")]);
        let result = apply_str(
            "ML-KEM-768",
            Some(&section["test-cmd"]),
            "kem",
            "ML-KEM-768",
        );
        assert_eq!(result, "ML-KEM-1024");
    }

    #[test]
    fn test_apply_str_uses_default_when_no_config() {
        let result = apply_str("ML-KEM-768", None, "kem", "ML-KEM-768");
        assert_eq!(result, "ML-KEM-768");
    }

    #[test]
    fn test_apply_str_uses_default_when_key_missing() {
        let section = make_section(vec![]);
        let result = apply_str(
            "ML-KEM-768",
            Some(&section["test-cmd"]),
            "kem",
            "ML-KEM-768",
        );
        assert_eq!(result, "ML-KEM-768");
    }

    #[test]
    fn test_apply_bool_uses_cli_when_not_default() {
        let section = make_section(vec![]);
        let result = apply_bool(true, Some(&section["test-cmd"]), "sign", false);
        assert!(result);
    }

    #[test]
    fn test_apply_bool_uses_config_when_cli_is_default() {
        let mut opts = HashMap::new();
        opts.insert("sign".to_string(), Value::Boolean(true));
        let mut map = HashMap::new();
        map.insert("test-cmd".to_string(), opts);
        let result = apply_bool(false, Some(&map["test-cmd"]), "sign", false);
        assert!(result);
    }

    #[test]
    fn test_apply_bool_uses_default_when_no_config() {
        let result = apply_bool(false, None, "sign", false);
        assert!(!result);
    }

    #[test]
    fn test_section_returns_none_for_unknown_cmd() {
        let cfg = HashMap::new();
        assert!(section(&cfg, "unknown-cmd").is_none());
    }

    #[test]
    fn test_section_returns_some_for_known_cmd() {
        let cfg = make_section(vec![("kem", "ML-KEM-768")]);
        let s = section(&cfg, "test-cmd");
        assert!(s.is_some());
    }

    #[test]
    fn test_load_parses_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join(".pqp");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("pqp.toml"),
            r#"[gen-key]
kem = "ML-KEM-1024"

[encrypt]
compress = "gzip""#,
        )
        .unwrap();
        let original = std::env::var_os("HOME");
        std::env::set_var("HOME", dir.path());
        let cfg = load().unwrap();
        assert!(!cfg.is_empty());
        assert_eq!(
            cfg.get("gen-key")
                .and_then(|m| m.get("kem"))
                .and_then(|v| v.as_str()),
            Some("ML-KEM-1024")
        );
        assert_eq!(
            cfg.get("encrypt")
                .and_then(|m| m.get("compress"))
                .and_then(|v| v.as_str()),
            Some("gzip")
        );
        if let Some(h) = original {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }
}
