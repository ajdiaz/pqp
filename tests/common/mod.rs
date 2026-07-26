use std::path::{Path, PathBuf};

/// RAII guard for a temporary isolated keyring directory.
///
/// Creates a `tempfile::TempDir`, sets it as the keyring override (thread-local)
/// for library calls, and provides [`path()`](Self::path) for CLI subprocess tests
/// to pass via `KEYRING_PATH` env var.
///
/// On [`Drop`], clears the thread-local override and removes the temp directory
/// (even on panic, via `TempDir`'s Drop).
pub struct TestKeyring {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestKeyring {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("failed to create temp keyring dir");
        let path = dir.path().to_path_buf();
        pqp::keyring::set_keyring_override(Some(path.clone()));
        TestKeyring { _dir: dir, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestKeyring {
    fn drop(&mut self) {
        pqp::keyring::set_keyring_override(None);
    }
}
