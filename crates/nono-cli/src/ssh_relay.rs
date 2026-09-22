//! `nono ssh-relay <host> <port>` — the in-sandbox half of the SSH mediation.
//!
//! OpenSSH runs it as a `ProxyCommand`, so it runs *inside* the sandbox. That
//! is exactly why it holds no policy and no credential: it connects to the
//! bastion's unix socket, names the endpoint the client asked for, and copies
//! bytes. Compromising it grants nothing the sandbox does not already have,
//! because the endpoint it names is re-checked in the parent.

use crate::cli::SshRelayArgs;
use crate::ssh_bastion::{ACCEPTED_REPLY, DENIED_REPLY, TARGET_PREAMBLE};
use nono::{NonoError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::UnixStream;

/// Environment variable naming the bastion socket, set by nono for the child.
pub const BASTION_SOCKET_ENV: &str = "NONO_SSH_BASTION";

pub(crate) fn run_ssh_relay(args: SshRelayArgs) -> Result<()> {
    let socket = std::env::var(BASTION_SOCKET_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            NonoError::SshBastion(format!(
                "nono ssh-relay: {BASTION_SOCKET_ENV} is not set — this command only runs \
                 inside a nono sandbox with an SSH allowance in effect"
            ))
        })?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            NonoError::SshBastion(format!("nono ssh-relay: could not start runtime: {err}"))
        })?;

    runtime.block_on(relay(&socket, &args.host, args.port))
}

async fn relay(socket: &str, host: &str, port: u16) -> Result<()> {
    let mut stream = UnixStream::connect(socket).await.map_err(|err| {
        NonoError::SshBastion(format!(
            "nono ssh-relay: could not reach the SSH mediation at {socket}: {err}"
        ))
    })?;

    stream
        .write_all(format!("{TARGET_PREAMBLE} {host} {port}\n").as_bytes())
        .await
        .map_err(NonoError::Io)?;
    stream.flush().await.map_err(NonoError::Io)?;

    // The verdict arrives before any SSH byte, so a refusal reaches the user as
    // a sentence naming the host rather than as `ssh` complaining about a bad
    // protocol version.
    let verdict = read_line(&mut stream).await?;
    if let Some(reason) = verdict.strip_prefix(DENIED_REPLY) {
        return Err(NonoError::SshBastion(format!(
            "nono: {}",
            reason.trim_start()
        )));
    }
    if verdict.trim_end() != ACCEPTED_REPLY {
        return Err(NonoError::SshBastion(format!(
            "nono ssh-relay: unexpected reply from the SSH mediation: '{}'",
            verdict.trim_end()
        )));
    }

    let (mut tunnel_read, mut tunnel_write) = stream.into_split();
    let mut stdout = tokio::io::stdout();

    // The server closing is what ends the session. A closed stdin only means
    // the client has nothing more to send, so half-close and keep draining.
    let upstream = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = copy(&mut stdin, &mut tunnel_write).await;
        let _ = tunnel_write.shutdown().await;
    });

    let result = async {
        copy(&mut tunnel_read, &mut stdout).await?;
        stdout.flush().await
    }
    .await;

    upstream.abort();
    result.map(|_| ()).map_err(NonoError::Io)
}

/// Read one newline-terminated line without over-reading.
///
/// The SSH identification banner follows immediately on the same stream, so a
/// buffered reader here would swallow the first bytes of the session.
async fn read_line(stream: &mut UnixStream) -> Result<String> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while line.len() < 4096 {
        stream.read_exact(&mut byte).await.map_err(|err| {
            NonoError::SshBastion(format!(
                "nono ssh-relay: the SSH mediation closed without a verdict: {err}"
            ))
        })?;
        if byte[0] == b'\n' {
            return String::from_utf8(line).map_err(|_| {
                NonoError::SshBastion(
                    "nono ssh-relay: the SSH mediation sent a non-UTF-8 verdict".to_string(),
                )
            });
        }
        line.push(byte[0]);
    }
    Err(NonoError::SshBastion(
        "nono ssh-relay: the SSH mediation sent an oversized verdict".to_string(),
    ))
}
