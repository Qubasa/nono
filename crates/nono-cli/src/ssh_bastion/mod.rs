//! The SSH bastion: nono between a sandboxed SSH client and the remote host.
//!
//! An `allow_ssh` allowance used to be a byte-transparent tunnel to a port. A
//! tunnel cannot tell `git fetch` from an interactive shell or a port forward,
//! because the difference is inside the encrypted stream. So nono terminates
//! the client's session here, opens its own session to the endpoint, and
//! relays it one channel request at a time.
//!
//! Three things move out of the sandbox as a result: the credential (nono
//! signs, using the host's agent or a key it read itself), the host-key
//! decision (checked against the user's `known_hosts` out here, never on first
//! use), and the authorization of what the session may do.
//!
//! What that buys is bounded, and the bound is worth stating: the mediation
//! stops nono from *handing* the sandbox a credential. It does not by itself
//! stop a sandboxed process from reaching one it can already see. With
//! `linux.af_unix_mediation` off - the default in proxy-only mode, issue
//! #1901 - a process inside can still connect to the host's `SSH_AUTH_SOCK`
//! on its own and get signatures for any host. Set
//! `linux.af_unix_mediation: "pathname"` for the agent to actually be out of
//! reach; `warn_on_redundant_agent_grant` covers only the narrower case where
//! the caller granted the socket explicitly.
//!
//! The sandbox reaches the bastion over a unix socket in the `0700` session
//! directory. Filesystem permissions carry the weight a token would otherwise
//! have to, and an `AF_UNIX` connection to a granted path is a separate
//! decision from the seccomp destination pin, so the mediation needs no entry
//! in it.

pub(crate) mod client;
pub(crate) mod command;
pub(crate) mod credential;
pub(crate) mod policy;
pub(crate) mod server;

use crate::network_policy::{ResolvedSshAllowance, SshEndpoint};
use nono::{NonoError, Result};
use policy::{EndpointRule, RefusedRequest};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub(crate) use credential::{AGENT_SOCK_ENV, SshCredential};

/// First line the relay sends: which endpoint the client asked for.
///
/// It arrives from inside the sandbox as `%h %p`, so it is a request and not a
/// fact. The parent matches it against the resolved allowances before dialling
/// anything, which is where the port-exact guarantee is actually kept.
pub(crate) const TARGET_PREAMBLE: &str = "NONO-SSH-TARGET";
/// Reply meaning the endpoint was allowed and SSH bytes follow.
pub(crate) const ACCEPTED_REPLY: &str = "NONO-SSH-OK";
/// Reply meaning the endpoint was refused; the rest of the line says why.
pub(crate) const DENIED_REPLY: &str = "NONO-SSH-DENIED";
/// Upper bound on the preamble line, so a client that never sends a newline
/// cannot make the parent buffer without limit.
const PREAMBLE_LIMIT: usize = 512;
/// How long the sandbox-facing leg tolerates silence before giving up.
///
/// It is also the deadline russh applies to reading the client's SSH
/// identification banner, which is why it is set rather than left at `None`:
/// a peer that connects and never speaks would otherwise hold a session, an
/// fd and an authenticated outbound leg forever. Matches
/// `client::OUTBOUND_INACTIVITY`, so neither leg outlives the other.
const INBOUND_INACTIVITY: Duration = Duration::from_secs(3600);
/// How long the relay has to name the endpoint it wants.
const TARGET_LINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Sessions served at once.
///
/// Every connection costs an outbound TCP connect, a key exchange and a
/// userauth against the remote host before the client inside the sandbox has
/// said anything, so the accept loop has to be the thing that says no. With a
/// confirm-on-use agent key each one is also a prompt on the user's desktop.
const MAX_CONCURRENT_SESSIONS: usize = 32;
/// Pause before accepting again after `accept` failed.
///
/// A sticky error (EMFILE, ENOMEM) would otherwise spin a worker thread flat
/// out, and the same runtime serves the HTTP proxy.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(200);

/// Escape what came off the wire before it reaches a log line or a terminal.
///
/// Commands, subsystem names, `TERM` and the requested host are all chosen by
/// the sandboxed process. A raw carriage return or ANSI escape in one of them
/// would let it forge audit records and rewrite the operator's screen.
pub(crate) fn escape_for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

/// One authorized endpoint plus what it may do there.
#[derive(Debug, Clone)]
pub(crate) struct SessionTarget {
    pub(crate) endpoint: SshEndpoint,
    pub(crate) user: String,
    pub(crate) rule: EndpointRule,
}

impl SessionTarget {
    pub(crate) fn describe(&self) -> String {
        format!(
            "{}@{}:{}",
            self.user, self.endpoint.host, self.endpoint.port
        )
    }
}

/// The allowances in force, resolved once in the parent.
#[derive(Debug, Clone)]
pub(crate) struct Allowances(Arc<Vec<ResolvedSshAllowance>>);

impl Allowances {
    pub(crate) fn new(allowances: Vec<ResolvedSshAllowance>) -> Self {
        Self(Arc::new(allowances))
    }

    /// Match a requested `host:port` against the allowances, port-exactly.
    ///
    /// The remote user is the allowance's, never the client's: the sandbox
    /// chooses which allowed endpoint to reach, not which identity to reach it
    /// as, which is what makes `ssh root@allowed-host` run as the allowance
    /// says rather than as root.
    fn authorize(&self, host: &str, port: u16, default_user: &str) -> Option<SessionTarget> {
        let requested = crate::network_policy::ssh_endpoint_authority(host, port);
        self.0
            .iter()
            .find(|allowance| {
                crate::network_policy::ssh_endpoint_authority(
                    &allowance.endpoint.host,
                    allowance.endpoint.port,
                ) == requested
            })
            .map(|allowance| SessionTarget {
                endpoint: allowance.endpoint.clone(),
                user: allowance
                    .endpoint
                    .user
                    .clone()
                    .unwrap_or_else(|| default_user.to_string()),
                rule: if allowance.commands.is_empty() {
                    EndpointRule::Session
                } else {
                    EndpointRule::Commands(allowance.commands.clone())
                },
            })
    }

    fn describe_all(&self) -> String {
        self.0
            .iter()
            .map(|allowance| {
                crate::network_policy::ssh_endpoint_authority(
                    &allowance.endpoint.host,
                    allowance.endpoint.port,
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A running bastion. Dropping it removes the socket.
pub(crate) struct BastionHandle {
    socket_path: PathBuf,
}

impl BastionHandle {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for BastionHandle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Everything one bastion needs, assembled before the sandbox is built.
pub(crate) struct BastionConfig {
    pub(crate) socket_path: PathBuf,
    pub(crate) host_key: russh::keys::PrivateKey,
    pub(crate) known_hosts: PathBuf,
    pub(crate) allowances: Allowances,
    pub(crate) credential: SshCredential,
    pub(crate) default_user: String,
}

/// Bind the socket and serve mediated sessions on `runtime` until the process
/// ends.
///
/// # Errors
///
/// Fails when the socket cannot be bound. A failure here fails the launch:
/// there is no configuration in which the endpoint is reachable without the
/// mediation, so a bastion that did not start means SSH does not work, and
/// saying so beats an unexplained connection refused.
pub(crate) fn start(
    runtime: &tokio::runtime::Runtime,
    config: BastionConfig,
) -> Result<BastionHandle> {
    let socket_path = config.socket_path.clone();
    let _ = std::fs::remove_file(&socket_path);

    let listener = runtime
        .block_on(async { UnixListener::bind(&socket_path) })
        .map_err(|err| {
            NonoError::Io(std::io::Error::new(
                err.kind(),
                format!(
                    "network.allow_ssh could not start the SSH mediation on '{}': {err}",
                    socket_path.display()
                ),
            ))
        })?;

    let server_config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(INBOUND_INACTIVITY),
        auth_rejection_time: std::time::Duration::from_secs(0),
        keys: vec![config.host_key],
        ..russh::server::Config::default()
    });

    let credential_description = config.credential.describe();
    let endpoints = config.allowances.describe_all();

    let shared = Arc::new(SharedConfig {
        known_hosts: config.known_hosts,
        allowances: config.allowances,
        credential: config.credential,
        default_user: config.default_user,
        server: server_config,
        sessions: Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS)),
    });

    runtime.spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(err) => {
                    tracing::warn!("ssh bastion could not accept a connection: {err}");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    continue;
                }
            };
            let Ok(permit) = shared.sessions.clone().try_acquire_owned() else {
                tracing::warn!(
                    "ssh bastion refused a connection: {MAX_CONCURRENT_SESSIONS} sessions are \
                     already open"
                );
                continue;
            };
            let shared = shared.clone();
            // Each session is its own task: a panic while parsing hostile
            // remote bytes ends that session and nothing else.
            tokio::spawn(async move {
                if let Err(err) = handle_connection(shared, stream).await {
                    tracing::warn!("ssh bastion session ended: {err}");
                }
                drop(permit);
            });
        }
    });

    tracing::info!(
        "SSH mediation for {endpoints} listening on {} ({credential_description})",
        socket_path.display()
    );

    Ok(BastionHandle { socket_path })
}

struct SharedConfig {
    known_hosts: PathBuf,
    allowances: Allowances,
    credential: SshCredential,
    default_user: String,
    server: Arc<russh::server::Config>,
    sessions: Arc<Semaphore>,
}

async fn handle_connection(shared: Arc<SharedConfig>, mut stream: UnixStream) -> Result<()> {
    let (host, port) = read_target(&mut stream).await?;

    let Some(target) = shared
        .allowances
        .authorize(&host, port, &shared.default_user)
    else {
        let message = format!(
            "{}:{port} is not an allowed SSH endpoint. Allowed: {}",
            escape_for_display(&host),
            shared.allowances.describe_all()
        );
        audit::refused_endpoint(&host, port);
        let _ = stream
            .write_all(format!("{DENIED_REPLY} {message}\n").as_bytes())
            .await;
        let _ = stream.flush().await;
        return Ok(());
    };

    let outbound = match client::connect(
        &target.endpoint,
        &target.user,
        &shared.credential,
        &shared.known_hosts,
    )
    .await
    {
        Ok(outbound) => outbound,
        Err(err) => {
            let _ = stream
                .write_all(format!("{DENIED_REPLY} {err}\n").as_bytes())
                .await;
            let _ = stream.flush().await;
            return Ok(());
        }
    };

    stream
        .write_all(format!("{ACCEPTED_REPLY}\n").as_bytes())
        .await
        .map_err(NonoError::Io)?;
    stream.flush().await.map_err(NonoError::Io)?;

    server::serve(shared.server.clone(), stream, target, outbound).await
}

/// Read the relay's target line without consuming a byte of what follows.
///
/// Byte at a time on purpose: the SSH identification banner is already on its
/// way behind this line, and a buffered read would swallow part of it.
async fn read_target(stream: &mut UnixStream) -> Result<(String, u16)> {
    let line = tokio::time::timeout(TARGET_LINE_TIMEOUT, read_target_line(stream))
        .await
        .map_err(|_| {
            NonoError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "ssh bastion waited {}s for a target line and got none",
                    TARGET_LINE_TIMEOUT.as_secs()
                ),
            ))
        })??;
    parse_target(&line)
}

async fn read_target_line(stream: &mut UnixStream) -> Result<String> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.map_err(|err| {
            NonoError::Io(std::io::Error::new(
                err.kind(),
                format!("ssh bastion could not read the target line: {err}"),
            ))
        })?;
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= PREAMBLE_LIMIT {
            return Err(NonoError::SshBastion(
                "ssh bastion target line exceeded its limit".to_string(),
            ));
        }
        line.push(byte[0]);
    }

    String::from_utf8(line).map_err(|_| {
        NonoError::SshBastion("ssh bastion target line was not valid UTF-8".to_string())
    })
}

fn parse_target(line: &str) -> Result<(String, u16)> {
    let malformed = || {
        NonoError::SshBastion(format!(
            "ssh bastion received a malformed target line: '{line}'"
        ))
    };
    let mut fields = line.trim_end_matches('\r').split(' ');
    if fields.next() != Some(TARGET_PREAMBLE) {
        return Err(malformed());
    }
    let host = fields.next().ok_or_else(malformed)?;
    let port = fields.next().ok_or_else(malformed)?;
    if fields.next().is_some() || host.is_empty() {
        return Err(malformed());
    }
    let port: u16 = port.parse().map_err(|_| malformed())?;
    Ok((host.to_string(), port))
}

/// Audit lines for every authorization decision.
///
/// They go through the same `tracing` targets the rest of the network layer
/// uses, so "the policy refused this" and "the connection broke" are separate
/// records rather than one indistinguishable failure.
pub(crate) mod audit {
    use super::{RefusedRequest, SessionTarget, escape_for_display};

    /// One allowed request, as the audit log records it.
    ///
    /// `routine` mirrors `RefusedRequest::routine`: a window change on every
    /// drag of a terminal corner is not worth an info line, an exec is.
    pub(crate) struct Allowed {
        pub(crate) request: &'static str,
        pub(crate) detail: Option<String>,
        pub(crate) routine: bool,
    }

    pub(crate) fn allowed(target: &SessionTarget, allowed: Allowed) {
        // The detail is escaped here rather than at the callsite so that no
        // future caller can forget: every one of them is wire data.
        let line = match &allowed.detail {
            Some(detail) => format!(
                "ssh bastion allowed {} on {}: {}",
                allowed.request,
                target.describe(),
                escape_for_display(detail)
            ),
            None => format!(
                "ssh bastion allowed {} on {}",
                allowed.request,
                target.describe()
            ),
        };
        if allowed.routine {
            tracing::debug!("{line}");
        } else {
            tracing::info!("{line}");
        }
    }

    pub(crate) fn refused(target: &SessionTarget, refusal: &RefusedRequest) {
        // Both levels record the same decision. Only a refusal a client did
        // not have to make is worth waking the reader for.
        if refusal.routine {
            tracing::debug!(
                "ssh bastion refused {} on {}: {}",
                refusal.request,
                target.describe(),
                refusal.reason
            );
        } else {
            tracing::warn!(
                "ssh bastion refused {} on {}: {}",
                refusal.request,
                target.describe(),
                refusal.reason
            );
        }
    }

    /// Record a channel the remote host tried to open back toward nono.
    pub(crate) fn refused_remote(host: &str, port: u16, refusal: &RefusedRequest) {
        tracing::warn!(
            "ssh bastion refused {} from {}:{port}: {}",
            refusal.request,
            escape_for_display(host),
            refusal.reason
        );
    }

    pub(crate) fn refused_endpoint(host: &str, port: u16) {
        tracing::warn!(
            "ssh bastion refused the endpoint {}:{port}: no allowance covers it",
            escape_for_display(host)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_policy::ResolvedSshAllowance;

    fn allowance(
        user: Option<&str>,
        host: &str,
        port: u16,
        commands: &[&str],
    ) -> ResolvedSshAllowance {
        ResolvedSshAllowance {
            endpoint: SshEndpoint {
                user: user.map(str::to_string),
                host: host.to_string(),
                port,
            },
            commands: commands.iter().map(|c| (*c).to_string()).collect(),
        }
    }

    #[test]
    fn the_allowance_decides_the_remote_user_not_the_client() {
        let allowances = Allowances::new(vec![allowance(
            Some("deploy"),
            "build.example.com",
            22,
            &[],
        )]);
        let target = allowances
            .authorize("build.example.com", 22, "local")
            .expect("the allowed endpoint must authorize");
        assert_eq!(target.user, "deploy");
    }

    #[test]
    fn an_allowance_without_a_user_falls_back_to_nonos_own() {
        let allowances = Allowances::new(vec![allowance(None, "build.example.com", 22, &[])]);
        let target = allowances
            .authorize("build.example.com", 22, "local")
            .expect("the allowed endpoint must authorize");
        assert_eq!(target.user, "local");
    }

    #[test]
    fn a_port_the_allowance_does_not_name_is_refused() {
        let allowances = Allowances::new(vec![allowance(None, "build.example.com", 2222, &[])]);
        assert!(
            allowances
                .authorize("build.example.com", 22, "local")
                .is_none()
        );
        assert!(
            allowances
                .authorize("build.example.com", 2222, "local")
                .is_some()
        );
    }

    #[test]
    fn a_second_host_is_refused() {
        let allowances = Allowances::new(vec![allowance(None, "build.example.com", 22, &[])]);
        assert!(
            allowances
                .authorize("other.example.com", 22, "local")
                .is_none()
        );
    }

    #[test]
    fn a_command_list_makes_the_endpoint_a_task_endpoint() {
        let allowances = Allowances::new(vec![allowance(
            None,
            "build.example.com",
            22,
            &["git-upload-pack /srv/repo.git"],
        )]);
        let target = allowances
            .authorize("build.example.com", 22, "local")
            .expect("the allowed endpoint must authorize");
        assert_eq!(
            target.rule,
            EndpointRule::Commands(vec!["git-upload-pack /srv/repo.git".to_string()])
        );
    }

    #[test]
    fn the_target_line_round_trips() {
        let (host, port) =
            parse_target(&format!("{TARGET_PREAMBLE} build.example.com 2222")).expect("parses");
        assert_eq!((host.as_str(), port), ("build.example.com", 2222));
    }

    #[test]
    fn a_malformed_target_line_is_refused() {
        for line in [
            "GARBAGE host 22",
            &format!("{TARGET_PREAMBLE} host"),
            &format!("{TARGET_PREAMBLE} host 22 extra"),
            &format!("{TARGET_PREAMBLE}  22"),
            &format!("{TARGET_PREAMBLE} host 99999"),
        ] {
            assert!(
                parse_target(line).is_err(),
                "line must be refused: {line:?}"
            );
        }
    }
}
