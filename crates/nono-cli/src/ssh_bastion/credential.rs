//! The credential the bastion authenticates with, resolved in the parent.
//!
//! Everything here runs before the sandbox is built, so "no usable credential"
//! is a startup error next to the other `allow_ssh` validations rather than a
//! publickey refusal half a session later. Neither the agent socket nor the key
//! file is granted to the sandbox: the signature is produced out here.

use nono::{NonoError, Result};
use russh::keys::{PrivateKey, ssh_key};
use std::path::{Path, PathBuf};

/// Where the bastion gets a signature.
#[derive(Debug, Clone)]
pub(crate) enum SshCredential {
    /// The host's agent, reached on this socket path. The agent holds the key.
    Agent(PathBuf),
    /// A key file nono read and parsed itself.
    Key(Box<PrivateKey>),
}

impl SshCredential {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Agent(path) => format!("ssh-agent at {}", path.display()),
            Self::Key(key) => format!("key of type {}", key.algorithm()),
        }
    }
}

/// Environment variable naming the host's agent socket.
pub(crate) const AGENT_SOCK_ENV: &str = "SSH_AUTH_SOCK";

/// Resolve the credential an SSH allowance will authenticate with.
///
/// `--ssh-key` wins when given, because naming a key is an explicit choice;
/// otherwise the host's agent is used, which keeps the private key out of
/// nono's address space as well as out of the sandbox.
///
/// # Errors
///
/// Fails when the named key cannot be read, is encrypted, or is of a type the
/// mediation cannot use directly, and when no key was named and no agent is
/// reachable.
pub(crate) fn resolve(key_file: Option<&Path>) -> Result<SshCredential> {
    match key_file {
        Some(path) => load_key(path),
        None => resolve_agent(),
    }
}

fn resolve_agent() -> Result<SshCredential> {
    let raw = std::env::var_os(AGENT_SOCK_ENV).filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Err(NonoError::SshBastion(format!(
            "network.allow_ssh needs a credential to authenticate with, and there is none: \
             {AGENT_SOCK_ENV} is not set in nono's own environment.\n\n\
             Start an ssh-agent and add the key, or name one with --ssh-key FILE. \
             nono authenticates on the sandbox's behalf, so the key never enters the sandbox."
        )));
    };
    let path = PathBuf::from(raw);
    if !path.exists() {
        return Err(NonoError::SshBastion(format!(
            "network.allow_ssh cannot use the ssh-agent: {AGENT_SOCK_ENV} names '{}', \
             which does not exist",
            path.display()
        )));
    }
    Ok(SshCredential::Agent(path))
}

/// Read and parse a private key file in the parent.
///
/// An encrypted key is refused rather than prompted for: nono is often launched
/// non-interactively, and a passphrase prompt racing sandbox startup is worse
/// than a clear refusal.
fn load_key(path: &Path) -> Result<SshCredential> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        NonoError::SshBastion(format!(
            "--ssh-key '{}' could not be read: {err}",
            path.display()
        ))
    })?;

    let key = match russh::keys::decode_secret_key(&text, None) {
        Ok(key) => key,
        Err(russh::keys::Error::KeyIsEncrypted) => {
            return Err(NonoError::SshBastion(format!(
                "--ssh-key '{}' is encrypted, and nono will not prompt for a passphrase \
                 while a sandbox is starting.\n\n\
                 Add it to your agent instead:  ssh-add {}",
                path.display(),
                path.display()
            )));
        }
        Err(err) => {
            return Err(NonoError::SshBastion(format!(
                "--ssh-key '{}' could not be parsed: {err}",
                path.display()
            )));
        }
    };

    reject_unusable_algorithm(path, &key)?;
    Ok(SshCredential::Key(Box::new(key)))
}

/// Refuse key types the outbound leg cannot drive from a file.
///
/// A hardware-backed key needs the token, which only the agent can talk to.
/// Catching it here turns a mid-session authentication failure into a startup
/// error that names the remedy.
fn reject_unusable_algorithm(path: &Path, key: &PrivateKey) -> Result<()> {
    let algorithm = key.algorithm();
    let hardware_backed = matches!(
        algorithm,
        ssh_key::Algorithm::SkEcdsaSha2NistP256 | ssh_key::Algorithm::SkEd25519
    );
    if hardware_backed {
        return Err(NonoError::SshBastion(format!(
            "--ssh-key '{}' is a hardware-backed key ({}), which nono cannot use from a file \
             because signing needs the security key itself.\n\n\
             Add it to your agent instead:  ssh-add -K",
            path.display(),
            algorithm.as_str()
        )));
    }
    // A certificate is a separate artifact from the private key file, so it
    // never reaches here: `decode_secret_key` refuses it as a parse failure.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_key(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("create key file");
        file.write_all(contents.as_bytes()).expect("write key file");
        path
    }

    #[test]
    fn a_plain_ed25519_key_is_usable() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .expect("generate key");
        let pem = key.to_openssh(ssh_key::LineEnding::LF).expect("encode key");
        let path = write_key(dir.path(), "id_ed25519", &pem);

        match resolve(Some(&path)).expect("plain key resolves") {
            SshCredential::Key(_) => {}
            other => panic!("expected a key credential, got {other:?}"),
        }
    }

    #[test]
    fn an_encrypted_key_names_the_agent_as_the_remedy() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .expect("generate key");
        let encrypted = key
            .encrypt(&mut rand::rng(), b"passphrase")
            .expect("encrypt key");
        let pem = encrypted
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode key");
        let path = write_key(dir.path(), "id_encrypted", &pem);

        let err = resolve(Some(&path))
            .expect_err("an encrypted key must not be usable")
            .to_string();
        assert!(
            err.contains("ssh-add"),
            "the refusal must name the agent as the remedy: {err}"
        );
    }

    #[test]
    fn an_unreadable_key_names_the_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let missing = dir.path().join("absent");
        let err = resolve(Some(&missing))
            .expect_err("a missing key must fail")
            .to_string();
        assert!(
            err.contains("absent"),
            "the refusal must name the key path: {err}"
        );
    }

    #[test]
    fn garbage_is_refused_as_a_parse_failure() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = write_key(dir.path(), "id_garbage", "not a key at all\n");
        let err = resolve(Some(&path))
            .expect_err("garbage must fail")
            .to_string();
        assert!(
            err.contains("could not be parsed"),
            "expected a parse failure, got: {err}"
        );
    }
}
