//! Generated OpenSSH client wiring for `network.allow_ssh`.
//!
//! `ssh` has no environment variable for `ProxyCommand`, so the setting has to
//! reach it as a file. This module materialises a session-scoped config that
//! routes every SSH target through `nono ssh-tunnel`, plus an `ssh` wrapper
//! that gets prepended to the child's `PATH` so a bare `ssh` picks the config
//! up too.
//!
//! Both are **ergonomics, not enforcement**. Invoking `/usr/bin/ssh` by
//! absolute path skips them and fails closed with `EACCES`, because the
//! seccomp-notify destination pin is what contains the process.

use nono::{NonoError, Result};
use std::path::{Path, PathBuf};

/// Session-scoped generated SSH config and `ssh` wrapper.
///
/// Dropping removes the whole directory, mirroring how the TLS-intercept
/// trust bundle is torn down.
pub(crate) struct SshClientFiles {
    root: PathBuf,
    config_path: PathBuf,
    bin_dir: PathBuf,
    wrapper_path: Option<PathBuf>,
}

impl SshClientFiles {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Directory to prepend to the child's `PATH`, when a wrapper was created.
    pub(crate) fn bin_dir(&self) -> Option<&Path> {
        self.wrapper_path.as_ref().map(|_| self.bin_dir.as_path())
    }

    pub(crate) fn wrapper_path(&self) -> Option<&Path> {
        self.wrapper_path.as_deref()
    }

    /// `GIT_SSH_COMMAND` value pointing git's SSH at the generated config.
    pub(crate) fn git_ssh_command(&self) -> String {
        format!("ssh -F {}", shell_quote(&self.config_path.to_string_lossy()))
    }
}

impl Drop for SshClientFiles {
    fn drop(&mut self) {
        // The bin dir is 0o500; without the write bit its entries cannot be
        // unlinked, so restore it before removing the tree.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.bin_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Write the generated config and wrapper under a fresh 0o700 session dir.
pub(crate) fn prepare_ssh_client_files(nono_exe: &Path) -> Result<SshClientFiles> {
    let base = crate::session::ensure_sessions_dir()?;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let root = base.join(format!("ssh-{pid}-{nanos:09}"));
    create_private_dir(&root)?;

    let config_path = root.join("config");
    let bin_dir = root.join("bin");
    create_private_dir(&bin_dir)?;

    // `Host *` is deliberate: a non-allowed host then fails with the proxy's
    // "403 ... is not in the allowlist", which names the host, instead of a
    // bare EACCES from a direct connect.
    let config = format!(
        "Host *\n  ProxyCommand {} ssh-tunnel %h %p\n",
        shell_quote(&nono_exe.to_string_lossy())
    );
    write_new(&config_path, config.as_bytes(), 0o400)?;

    let wrapper_path = match resolve_real_ssh() {
        Some(real_ssh) => {
            let script = format!(
                "#!/bin/sh\nexec {} -F {} \"$@\"\n",
                shell_quote(&real_ssh.to_string_lossy()),
                shell_quote(&config_path.to_string_lossy())
            );
            let path = bin_dir.join("ssh");
            write_new(&path, script.as_bytes(), 0o500)?;
            set_dir_mode(&bin_dir, 0o500)?;
            Some(path)
        }
        None => None,
    };

    Ok(SshClientFiles {
        root,
        config_path,
        bin_dir,
        wrapper_path,
    })
}

/// First `ssh` on the host `PATH`. Resolved here, before the wrapper dir is
/// prepended, so the wrapper cannot exec itself.
fn resolve_real_ssh() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("ssh"))
        .find(|candidate| candidate.is_file())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to create SSH client config dir '{}': {e}",
            dir.display()
        ))
    })?;
    set_dir_mode(dir, 0o700)
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set permissions on SSH client config dir '{}': {e}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to create SSH client file '{}': {e}",
                path.display()
            ))
        })?;
    file.write_all(contents).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to write SSH client file '{}': {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn write_new(path: &Path, contents: &[u8], _mode: u32) -> Result<()> {
    std::fs::write(path, contents).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to write SSH client file '{}': {e}",
            path.display()
        ))
    })
}

/// POSIX single-quote escaping, so a path with spaces survives both the
/// `ProxyCommand` shell and the wrapper script.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_escapes_embedded_quotes() {
        assert_eq!(shell_quote("/usr/bin/ssh"), "'/usr/bin/ssh'");
        assert_eq!(shell_quote("/a b/ssh"), "'/a b/ssh'");
        assert_eq!(shell_quote("/it's/ssh"), r"'/it'\''s/ssh'");
    }

    type IsolatedState = (
        tempfile::TempDir,
        crate::test_env::EnvVarGuard,
        std::sync::MutexGuard<'static, ()>,
    );

    /// Keeps the generated tree out of the developer's real state dir, which
    /// a concurrently running nono session also owns. The lock is the crate
    /// convention for tests that mutate the process environment.
    fn isolated_state() -> IsolatedState {
        let lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tmpdir");
        let guard = crate::test_env::EnvVarGuard::set_all(&[(
            "XDG_STATE_HOME",
            dir.path().to_str().expect("utf8"),
        )]);
        (dir, guard, lock)
    }

    #[test]
    fn generated_config_points_at_the_tunnel_and_is_read_only() {
        let (_dir, _env, _lock) = isolated_state();
        let exe = PathBuf::from("/opt/nono bin/nono");
        let files = prepare_ssh_client_files(&exe).expect("prepare ssh client files");
        let config = std::fs::read_to_string(files.config_path()).expect("read config");
        assert!(config.starts_with("Host *\n"));
        assert!(config.contains("ProxyCommand '/opt/nono bin/nono' ssh-tunnel %h %p"));
        assert_eq!(
            files.git_ssh_command(),
            format!("ssh -F '{}'", files.config_path().display())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(files.config_path())
                .expect("stat config")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o400);
        }
    }

    #[test]
    fn dropping_removes_the_session_directory() {
        let (_dir, _env, _lock) = isolated_state();
        let files = prepare_ssh_client_files(Path::new("/usr/bin/nono")).expect("prepare");
        let root = files.config_path().parent().expect("root").to_path_buf();
        assert!(root.exists());
        drop(files);
        assert!(!root.exists());
    }
}
