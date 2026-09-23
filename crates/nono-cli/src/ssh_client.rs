//! Generated OpenSSH client wiring for `network.allow_ssh`.
//!
//! `ssh` has no environment variable for `ProxyCommand`, so the setting has to
//! reach it as a file. This module materialises a session-scoped config that
//! routes every SSH target through `nono ssh-relay`, plus wrappers for every
//! tool that speaks SSH, prepended to the child's `PATH` so a bare `ssh`,
//! `scp` or `sftp` picks the config up too.
//!
//! `-F` is what makes the wrapper load-bearing rather than cosmetic: it makes
//! OpenSSH skip `/etc/ssh/ssh_config` entirely. On NixOS that file `Include`s
//! paths in the Nix store, which inside the sandbox's user namespace report as
//! `nobody:nogroup`, and OpenSSH rejects a config it considers wrongly owned.
//! `ssh` survived that only because it was the one tool being wrapped.
//!
//! Both are **ergonomics, not enforcement**. Invoking `/usr/bin/ssh` by
//! absolute path skips them and fails closed with `EACCES`, because the
//! seccomp-notify destination pin is what contains the process, and the
//! endpoint is reachable only through the mediation in the parent.
//!
//! The per-session host key generated here is the inbound half of the two
//! known-hosts stores: the client is given a `known_hosts` naming only that
//! key, so no process in the sandbox can make a trust decision about a real
//! remote host, and a key captured from one session is useless in the next.

use nono::{NonoError, Result};
use std::path::{Path, PathBuf};

/// Names of the tools wrapped on the child's `PATH`.
///
/// Each takes `-F` with the same meaning. `rsync` is deliberately absent: it
/// has no config flag of its own and finds its remote shell through `PATH` or
/// `RSYNC_RSH`, both of which the wrapper already covers.
const WRAPPED_TOOLS: [&str; 3] = ["ssh", "scp", "sftp"];

/// Session-scoped generated SSH config and the `ssh`/`scp`/`sftp` wrappers.
///
/// Dropping removes the whole directory, mirroring how the TLS-intercept
/// trust bundle is torn down.
pub(crate) struct SshClientFiles {
    root: PathBuf,
    config_path: PathBuf,
    bin_dir: PathBuf,
    wrapper_paths: Vec<PathBuf>,
    known_hosts_path: PathBuf,
    socket_path: PathBuf,
    host_key: russh::keys::PrivateKey,
}

impl SshClientFiles {
    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Generated `known_hosts` naming nono's per-session host key. The client
    /// verifies the mediation against it, so it must be readable inside the
    /// sandbox or every session fails host-key verification.
    pub(crate) fn known_hosts_path(&self) -> &Path {
        &self.known_hosts_path
    }

    /// Directory to prepend to the child's `PATH`, when wrappers were created.
    pub(crate) fn bin_dir(&self) -> Option<&Path> {
        if self.wrapper_paths.is_empty() {
            None
        } else {
            Some(self.bin_dir.as_path())
        }
    }

    /// Every generated wrapper, for the read and execute grants.
    pub(crate) fn wrapper_paths(&self) -> &[PathBuf] {
        &self.wrapper_paths
    }

    /// `GIT_SSH_COMMAND` value pointing git's SSH at the generated config.
    pub(crate) fn git_ssh_command(&self) -> String {
        self.ssh_command()
    }

    /// `RSYNC_RSH` value, so rsync routes through the mediation even when it
    /// resolves its remote shell without consulting `PATH`.
    pub(crate) fn rsync_rsh(&self) -> String {
        self.ssh_command()
    }

    fn ssh_command(&self) -> String {
        format!(
            "ssh -F {}",
            shell_quote(&self.config_path.to_string_lossy())
        )
    }

    /// Unix socket the relay connects to, bound by the bastion.
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The per-session host key, handed to the bastion's server config.
    pub(crate) fn host_key(&self) -> russh::keys::PrivateKey {
        self.host_key.clone()
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
    // Nothing else sweeps this tree, and a leftover directory makes every
    // later launch fail in `write_new`. Armed until `SshClientFiles` takes
    // over cleanup.
    let cleanup = DirGuard {
        dir: Some(root.clone()),
    };

    let config_path = root.join("config");
    let bin_dir = root.join("bin");
    create_private_dir(&bin_dir)?;

    // The generated known_hosts names nono's own per-session key for `*`.
    // `*` is safe precisely because the relay delivers whatever endpoint the
    // parent authorizes: the name the client thinks it is talking to is not a
    // trust input on this leg.
    let host_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .map_err(|err| {
                NonoError::SshBastion(format!(
                    "network.allow_ssh could not generate a session host key: {err}"
                ))
            })?;
    let public_key = host_key.public_key().to_openssh().map_err(|err| {
        NonoError::SshBastion(format!(
            "network.allow_ssh could not encode the session host key: {err}"
        ))
    })?;
    let known_hosts_path = root.join("known_hosts");
    write_new(
        &known_hosts_path,
        format!("* {public_key}\n").as_bytes(),
        0o400,
    )?;

    let socket_path = root.join("bastion.sock");

    // `Host *` is deliberate: a non-allowed host then fails with the
    // mediation's "is not an allowed SSH endpoint", which names the host,
    // instead of a bare EACCES from a direct connect.
    let config = format!(
        "Host *\n  \
         ProxyCommand {nono} ssh-relay %h %p %r\n  \
         StrictHostKeyChecking yes\n  \
         UserKnownHostsFile {known_hosts}\n  \
         IdentityAgent none\n  \
         PubkeyAuthentication no\n  \
         PasswordAuthentication no\n",
        nono = shell_quote(&nono_exe.to_string_lossy()),
        known_hosts = shell_quote(&known_hosts_path.to_string_lossy()),
    );
    write_new(&config_path, config.as_bytes(), 0o400)?;

    // One wrapper per tool that understands `-F`. A tool missing from the
    // host gets no wrapper rather than a broken one, and `ssh` missing means
    // no wrappers are useful at all: the others all exec it.
    let mut wrapper_paths = Vec::new();
    if resolve_on_path("ssh").is_some() {
        for tool in WRAPPED_TOOLS {
            let Some(real) = resolve_on_path(tool) else {
                continue;
            };
            let script = format!(
                "#!/bin/sh\nexec {} -F {} \"$@\"\n",
                shell_quote(&real.to_string_lossy()),
                shell_quote(&config_path.to_string_lossy())
            );
            let path = bin_dir.join(tool);
            write_new(&path, script.as_bytes(), 0o500)?;
            wrapper_paths.push(path);
        }
        set_dir_mode(&bin_dir, 0o500)?;
    }

    cleanup.disarm();
    Ok(SshClientFiles {
        root,
        config_path,
        bin_dir,
        wrapper_paths,
        known_hosts_path,
        socket_path,
        host_key,
    })
}

/// Removes a partially built session dir when construction fails part-way.
struct DirGuard {
    dir: Option<PathBuf>,
}

impl DirGuard {
    fn disarm(mut self) {
        self.dir = None;
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bin_dir = dir.join("bin");
            let _ = std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// First `name` on the host `PATH`. Resolved here, before the wrapper dir is
/// prepended, so a wrapper cannot exec itself.
fn resolve_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
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
    fn generated_config_points_at_the_relay_and_is_read_only() {
        let (_dir, _env, _lock) = isolated_state();
        let exe = PathBuf::from("/opt/nono bin/nono");
        let files = prepare_ssh_client_files(&exe).expect("prepare ssh client files");
        let config = std::fs::read_to_string(files.config_path()).expect("read config");
        assert!(config.starts_with("Host *\n"));
        assert!(config.contains("ProxyCommand '/opt/nono bin/nono' ssh-relay %h %p %r"));
        assert!(
            !config.contains("ssh-tunnel"),
            "the raw tunnel route is gone: {config}"
        );
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

    /// `ssh` alone being wrapped is what made `scp`, `sftp` and `rsync` fail
    /// on any host whose system `ssh_config` the sandbox cannot read. Each
    /// wrapper has to carry `-F`, which is what makes OpenSSH skip that file.
    #[test]
    fn every_ssh_speaking_tool_is_wrapped_onto_the_generated_config() {
        let (_dir, _env, _lock) = isolated_state();
        let exe = PathBuf::from("/opt/nono/bin/nono");
        let files = prepare_ssh_client_files(&exe).expect("prepare ssh client files");

        let bin_dir = files
            .bin_dir()
            .expect("a wrapper dir on a host carrying ssh");
        for tool in WRAPPED_TOOLS {
            let wrapper = bin_dir.join(tool);
            let script = std::fs::read_to_string(&wrapper)
                .unwrap_or_else(|e| panic!("read the {tool} wrapper: {e}"));
            assert!(
                script.contains(&format!("-F '{}'", files.config_path().display())),
                "the {tool} wrapper must name the generated config: {script}"
            );
            assert!(
                files.wrapper_paths().contains(&wrapper),
                "the {tool} wrapper must be granted to the sandbox"
            );
        }

        // rsync takes no config flag; the env var is its only route.
        assert_eq!(files.rsync_rsh(), files.git_ssh_command());
    }

    /// The client must verify nono, and only nono: a key captured from one
    /// session must be useless in the next.
    #[test]
    fn each_session_pins_a_fresh_host_key_the_client_must_verify() {
        let (_dir, _env, _lock) = isolated_state();
        let exe = PathBuf::from("/opt/nono/bin/nono");

        let first = prepare_ssh_client_files(&exe).expect("prepare first session");
        let config = std::fs::read_to_string(first.config_path()).expect("read config");
        assert!(config.contains("StrictHostKeyChecking yes"));
        assert!(config.contains("UserKnownHostsFile "));

        let known_hosts_line = |files: &SshClientFiles| {
            let path = std::fs::read_to_string(files.config_path())
                .expect("read config")
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("UserKnownHostsFile ")
                        .map(|p| p.trim_matches('\'').to_string())
                })
                .expect("config names a known_hosts file");
            std::fs::read_to_string(path).expect("read known_hosts")
        };

        let first_line = known_hosts_line(&first);
        assert!(first_line.starts_with("* ssh-ed25519 "));

        let second = prepare_ssh_client_files(&exe).expect("prepare second session");
        assert_ne!(
            first_line,
            known_hosts_line(&second),
            "a second session must present a different host key"
        );
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
