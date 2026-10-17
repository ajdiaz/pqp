//! Validation tests for the static assets under `contrib/`.
//!
//! These keep the shipped systemd unit honest: they assert the file is
//! well-formed and still contains the directives that make it usable as a
//! `systemd --user` service for `pqp agent`. They read the checked-in files
//! from `CARGO_MANIFEST_DIR`, so they never touch the real system.

use std::path::PathBuf;

/// Read a file below the repository's `contrib/` directory.
///
/// `relative` is the path inside `contrib/`, e.g. `systemd/pqp-agent.service`.
/// Panics (failing the test) if the file cannot be read.
fn contrib(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("contrib")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()))
}

/// Return the value of the first line starting with `directive`.
///
/// Panics (failing the test) when the directive is absent.
fn directive<'a>(unit: &'a str, directive: &str) -> &'a str {
    unit.lines()
        .find(|line| line.starts_with(directive))
        .unwrap_or_else(|| panic!("missing {directive} in unit"))
}

#[test]
fn systemd_unit_is_well_formed() {
    let unit = contrib("systemd/pqp-agent.service");

    assert!(unit.contains("[Unit]"), "missing [Unit] section");
    assert!(unit.contains("[Service]"), "missing [Service] section");
    assert!(unit.contains("[Install]"), "missing [Install] section");

    // The service must launch the passphrase agent, not another subcommand.
    let exec_start = directive(&unit, "ExecStart=");
    assert!(
        exec_start.contains("agent"),
        "ExecStart must run the agent: {exec_start}"
    );

    // It should stop the agent gracefully (cache wipe + socket removal).
    let exec_stop = directive(&unit, "ExecStop=");
    assert!(
        exec_stop.contains("agent") && exec_stop.contains("--stop"),
        "ExecStop must stop the agent: {exec_stop}"
    );

    // Enabled at login for the user manager.
    assert!(
        unit.contains("WantedBy=default.target"),
        "unit must be wanted by default.target"
    );
}

#[test]
fn systemd_unit_hardens_the_daemon() {
    let unit = contrib("systemd/pqp-agent.service");
    assert!(unit.contains("Type=exec"), "unit should use Type=exec");

    for required in [
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=AF_UNIX",
    ] {
        assert!(unit.contains(required), "missing hardening: {required}");
    }

    // `ProtectSystem=strict` and `ProtectHome=read-only` make the runtime
    // directory read-only, so it must be re-opened for the agent to create its
    // Unix socket there.
    assert!(
        unit.contains("ReadWritePaths=%t"),
        "unit must let the agent write its socket to the runtime directory"
    );
}

#[test]
fn contrib_readme_documents_installation() {
    let readme = contrib("systemd/README.md");
    assert!(
        readme.contains("systemctl --user enable --now pqp-agent.service"),
        "README should document enabling the service"
    );
    assert!(
        readme.contains("make install-systemd"),
        "README should mention the make helper target"
    );
}
