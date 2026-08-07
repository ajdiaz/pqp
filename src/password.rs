//! Passphrase prompting with optional external tools.
//!
//! By default, passphrases are read interactively via `rpassword`
//! (echo disabled, TTY required). When an external password tool is
//! configured (via the `--password-tool` CLI flag or the `[password-tool]`
//! config section), prompts are delegated to that program instead:
//!
//! - **pinentry** (any binary whose name contains `pinentry`) is driven
//!   through the standard Assuan `GETPIN` protocol.
//! - Any other program is treated as an *askpass*-style helper: it is
//!   invoked with the prompt text as its final argument and the passphrase
//!   is read from its stdout.
//!
//! Tool selection is stored in a thread-local override via
//! [`set_password_tool`], mirroring the keyring override pattern.

use anyhow::{Context, Result};
use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

thread_local! {
    static PASSWORD_TOOL: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Set (or clear, with `None`) the external password tool for this thread.
///
/// This is the mechanism used by the CLI to propagate the `--password-tool`
/// flag and the `[password-tool]` config section before dispatching commands.
pub fn set_password_tool(tool: Option<String>) {
    PASSWORD_TOOL.with(|cell| *cell.borrow_mut() = tool);
}

/// Return the configured external password tool, if any.
pub fn password_tool() -> Option<String> {
    PASSWORD_TOOL.with(|cell| cell.borrow().clone())
}

/// Read a passphrase for the given prompt.
///
/// If an external password tool is configured (via [`set_password_tool`]),
/// the prompt is delegated to it (see module docs for the protocol used).
/// Otherwise the passphrase is read interactively via `rpassword`, which
/// requires a TTY and fails on non-interactive sessions.
pub fn read_passphrase(prompt: &str) -> Result<String> {
    match password_tool() {
        Some(tool) => read_from_tool(&tool, prompt),
        None => read_interactive(prompt),
    }
}

/// Interactively read a passphrase with echo disabled.
fn read_interactive(prompt: &str) -> Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(_e) => Err(anyhow::anyhow!(
            "cannot read passphrase without a TTY (try --no-passphrase or --password-tool)"
        )),
    }
}

/// Delegate a passphrase prompt to an external tool.
///
/// Tools whose name contains `pinentry` are driven through the Assuan
/// `GETPIN` protocol; all other tools are treated as askpass helpers that
/// receive the prompt as an argument and print the passphrase on stdout.
fn read_from_tool(tool: &str, prompt: &str) -> Result<String> {
    let program = tool.split_whitespace().next().unwrap_or(tool);
    if program.contains("pinentry") {
        read_from_pinentry(tool, prompt)
    } else {
        read_from_askpass(tool, prompt)
    }
}

/// Run an askpass-style helper: `<tool> <prompt>` and read the passphrase
/// from stdout.
fn read_from_askpass(tool: &str, prompt: &str) -> Result<String> {
    let mut parts = tool.split_whitespace();
    let program = parts.next().context("password tool command is empty")?;
    let args: Vec<&str> = parts.collect();
    let output = Command::new(program)
        .args(args)
        .arg(prompt)
        .output()
        .context(format!("running password tool `{}`", tool))?;
    if !output.status.success() {
        anyhow::bail!("password tool `{}` exited with {}", tool, output.status);
    }
    let pass =
        String::from_utf8(output.stdout).context("password tool returned non-UTF-8 output")?;
    let pass = pass.trim_end_matches(['\n', '\r']).to_string();
    if pass.is_empty() {
        anyhow::bail!("password tool `{}` returned an empty passphrase", tool);
    }
    Ok(pass)
}

/// Drive a pinentry-compatible tool through the Assuan `GETPIN` protocol.
///
/// Sends `SETDESC`, `SETPROMPT`, and `GETPIN`, then reads the `D <pin>`
/// reply. Any `ERR` line or a non-zero exit status is reported as an error.
fn read_from_pinentry(tool: &str, prompt: &str) -> Result<String> {
    let mut parts = tool.split_whitespace();
    let program = parts.next().context("password tool command is empty")?;
    let args: Vec<&str> = parts.collect();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context(format!("spawning password tool `{}`", tool))?;
    let mut stdin = child
        .stdin
        .take()
        .context("cannot open password tool stdin")?;
    let stdout = child
        .stdout
        .take()
        .context("cannot open password tool stdout")?;

    writeln!(stdin, "SETDESC {}", prompt).context("sending SETDESC to password tool")?;
    writeln!(stdin, "SETPROMPT Enter passphrase:").context("sending SETPROMPT to password tool")?;
    writeln!(stdin, "GETPIN").context("sending GETPIN to password tool")?;
    drop(stdin);

    let reader = BufReader::new(stdout);
    let mut pin: Option<String> = None;
    for line in reader.lines() {
        let line = line.context("reading password tool output")?;
        if let Some(rest) = line.strip_prefix("D ") {
            pin = Some(rest.to_string());
        } else if line.starts_with("ERR ") {
            anyhow::bail!("password tool error: {}", line);
        }
    }

    let status = child.wait().context("waiting for password tool")?;
    if !status.success() {
        anyhow::bail!("password tool exited with {}", status);
    }
    pin.ok_or_else(|| anyhow::anyhow!("password tool did not return a passphrase"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to run a closure with a temporary password tool override,
    /// restoring the previous value afterwards.
    fn with_tool(tool: Option<&str>, f: impl FnOnce()) {
        let prev = password_tool();
        set_password_tool(tool.map(String::from));
        f();
        set_password_tool(prev);
    }

    #[test]
    fn test_interactive_fails_without_tty() {
        set_password_tool(None);
        assert!(read_passphrase("prompt: ").is_err());
    }

    #[test]
    fn test_askpass_reads_stdout() {
        with_tool(Some("echo"), || {
            let pass = read_passphrase("prompt: ").unwrap();
            // echo "prompt: " prints the prompt back; trailing newline trimmed
            assert_eq!(pass, "prompt: ");
        });
    }

    #[test]
    fn test_askpass_empty_output_is_error() {
        with_tool(Some("true"), || {
            assert!(read_passphrase("prompt: ").is_err());
        });
    }

    #[test]
    fn test_askpass_nonzero_exit_is_error() {
        with_tool(Some("false"), || {
            assert!(read_passphrase("prompt: ").is_err());
        });
    }

    #[test]
    fn test_askpass_missing_tool_is_error() {
        with_tool(Some("definitely-not-a-real-tool-xyz"), || {
            assert!(read_passphrase("prompt: ").is_err());
        });
    }

    #[test]
    fn test_pinentry_protocol() {
        let script = mock_pinentry_script();
        with_tool(Some(&script), || {
            let pass = read_passphrase("test prompt").unwrap();
            assert_eq!(pass, "test-pin");
        });
    }

    #[test]
    fn test_pinentry_error() {
        let script = mock_pinentry_error_script();
        with_tool(Some(&script), || {
            assert!(read_passphrase("test prompt").is_err());
        });
    }

    #[test]
    fn test_password_tool_roundtrip_override() {
        set_password_tool(Some("foo".to_string()));
        assert_eq!(password_tool(), Some("foo".to_string()));
        set_password_tool(None);
        assert_eq!(password_tool(), None);
    }

    #[cfg(unix)]
    fn mock_pinentry_script() -> String {
        let dir = std::env::temp_dir().join(format!("pqp-pinentry-mock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mock-pinentry.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile IFS= read -r line; do\n  case \"$line\" in\n    SETDESC*) echo OK ;;\n    SETPROMPT*) echo OK ;;\n    GETPIN) echo \"D test-pin\"; echo OK; exit 0 ;;\n    *) echo \"ERR unknown command\"; exit 1 ;;\n  esac\ndone\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().to_string()
    }

    #[cfg(unix)]
    fn mock_pinentry_error_script() -> String {
        let dir = std::env::temp_dir().join(format!("pqp-pinentry-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mock-pinentry-err.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\nwhile IFS= read -r line; do\n  case \"$line\" in\n    GETPIN) echo \"ERR 83886179 User canceled\"; exit 1 ;;\n    *) echo OK ;;\n  esac\ndone\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().to_string()
    }
}
