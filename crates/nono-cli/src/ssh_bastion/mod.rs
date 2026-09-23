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

use crate::network_policy::{ResolvedSshAllowance, SshEndpoint, ssh_endpoint_authority};
use nono::{NonoError, Result};
use policy::{EndpointRule, RefusedRequest};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub(crate) use credential::{AGENT_SOCK_ENV, SshCredential};

/// First line the relay sends: which endpoint and remote user the client asked
/// for.
///
/// It arrives from inside the sandbox as `%h %p %r`, so it is a request and not
/// a fact. The parent matches it against the resolved allowances before
/// dialling anything, which is where the port-exact and user-exact guarantees
/// are actually kept.
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

/// One authorized endpoint plus the remote user and what it may do there.
#[derive(Debug, Clone)]
pub(crate) struct SessionTarget {
    pub(crate) endpoint: SshEndpoint,
    pub(crate) user: String,
    pub(crate) rule: EndpointRule,
}

impl SessionTarget {
    pub(crate) fn describe(&self) -> String {
        format!("{}@{}", self.user, self.authority())
    }

    fn authority(&self) -> String {
        ssh_endpoint_authority(&self.endpoint.host, self.endpoint.port)
    }
}

/// What the relay asked for: an endpoint and the remote user to reach it as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetRequest {
    host: String,
    port: u16,
    user: String,
}

/// Why a [`TargetRequest`] matched no allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetRefusal {
    /// No allowance names the endpoint at all.
    Endpoint,
    /// The endpoint is allowed, but not as the requested user. Carries the
    /// identities that are allowed there.
    User(Vec<String>),
}

impl TargetRefusal {
    /// The line the client sees, naming what is allowed instead.
    fn message(&self, request: &TargetRequest, allowances: &Allowances) -> String {
        match self {
            Self::Endpoint => format!(
                "{}:{} is not an allowed SSH endpoint. Allowed: {}",
                escape_for_display(&request.host),
                request.port,
                allowances.describe_all()
            ),
            Self::User(allowed) => format!(
                "'{}' is not an allowed remote user on {}. Allowed there: {}",
                escape_for_display(&request.user),
                escape_for_display(&ssh_endpoint_authority(&request.host, request.port)),
                allowed.join(", ")
            ),
        }
    }

    fn audit_reason(&self) -> &'static str {
        match self {
            Self::Endpoint => "no allowance covers the endpoint",
            Self::User(_) => "no allowance names that remote user on the endpoint",
        }
    }
}

/// The allowances in force, resolved once in the parent with every remote user
/// filled in.
#[derive(Debug, Clone)]
pub(crate) struct Allowances(Arc<Vec<SessionTarget>>);

impl Allowances {
    /// Resolve each allowance to the concrete identity it authorizes.
    ///
    /// An allowance that names no user stands for `default_user`, exactly as
    /// a bare `ssh host` would.
    ///
    /// # Errors
    ///
    /// Refuses two allowances that resolve to the same user on the same
    /// endpoint, such as `build.example.com` and `alice@build.example.com`
    /// when nono runs as `alice`. Which one's command policy applied would
    /// otherwise depend on their order.
    pub(crate) fn new(allowances: Vec<ResolvedSshAllowance>, default_user: &str) -> Result<Self> {
        let mut targets: Vec<SessionTarget> = Vec::with_capacity(allowances.len());
        for allowance in allowances {
            let target = SessionTarget {
                user: allowance
                    .endpoint
                    .user
                    .clone()
                    .unwrap_or_else(|| default_user.to_string()),
                rule: if allowance.commands.is_empty() {
                    EndpointRule::Session
                } else {
                    EndpointRule::Commands(allowance.commands)
                },
                endpoint: allowance.endpoint,
            };
            let identity = target.describe();
            if targets.iter().any(|known| known.describe() == identity) {
                return Err(NonoError::ConfigParse(format!(
                    "SSH endpoint {identity} is allowed twice: an entry without a user@ prefix \
                     stands for the user nono runs as, so it names the same remote identity as \
                     an entry that spells that user out. Keep one entry per user and endpoint"
                )));
            }
            targets.push(target);
        }
        Ok(Self(Arc::new(targets)))
    }

    /// Match a requested `user@host:port` against the allowances, port-exactly
    /// and user-exactly.
    ///
    /// The remote user is part of what is authorized and is never rewritten:
    /// under an allowance for `deploy@allowed-host`, a sandboxed
    /// `ssh root@allowed-host` is refused rather than sent on as `deploy`.
    fn authorize(
        &self,
        request: &TargetRequest,
    ) -> std::result::Result<SessionTarget, TargetRefusal> {
        let authority = ssh_endpoint_authority(&request.host, request.port);
        let mut allowed_here = Vec::new();
        for target in self.0.iter() {
            if target.authority() != authority {
                continue;
            }
            if target.user == request.user {
                return Ok(target.clone());
            }
            allowed_here.push(target.describe());
        }
        if allowed_here.is_empty() {
            Err(TargetRefusal::Endpoint)
        } else {
            Err(TargetRefusal::User(allowed_here))
        }
    }

    fn describe_all(&self) -> String {
        self.0
            .iter()
            .map(SessionTarget::describe)
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
    server: Arc<russh::server::Config>,
    sessions: Arc<Semaphore>,
}

async fn handle_connection(shared: Arc<SharedConfig>, mut stream: UnixStream) -> Result<()> {
    let request = read_target(&mut stream).await?;

    let target = match shared.allowances.authorize(&request) {
        Ok(target) => target,
        Err(refusal) => {
            let message = refusal.message(&request, &shared.allowances);
            audit::refused_target(
                &request.host,
                request.port,
                &request.user,
                refusal.audit_reason(),
            );
            let _ = stream
                .write_all(format!("{DENIED_REPLY} {message}\n").as_bytes())
                .await;
            let _ = stream.flush().await;
            return Ok(());
        }
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
async fn read_target(stream: &mut UnixStream) -> Result<TargetRequest> {
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

fn parse_target(line: &str) -> Result<TargetRequest> {
    let malformed = || {
        NonoError::SshBastion(format!(
            "ssh bastion received a malformed target line: '{}'",
            escape_for_display(line)
        ))
    };
    let mut fields = line.trim_end_matches('\r').split(' ');
    if fields.next() != Some(TARGET_PREAMBLE) {
        return Err(malformed());
    }
    let host = fields.next().ok_or_else(malformed)?;
    let port = fields.next().ok_or_else(malformed)?;
    let user = fields.next().ok_or_else(malformed)?;
    if fields.next().is_some() || host.is_empty() || user.is_empty() {
        return Err(malformed());
    }
    let port: u16 = port.parse().map_err(|_| malformed())?;
    Ok(TargetRequest {
        host: host.to_string(),
        port,
        user: user.to_string(),
    })
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

    pub(crate) fn refused_target(host: &str, port: u16, user: &str, reason: &str) {
        tracing::warn!(
            "ssh bastion refused {}@{}:{port}: {reason}",
            escape_for_display(user),
            escape_for_display(host)
        );
    }

    /// Record a client authenticating as a user other than the one the
    /// session was authorized for.
    pub(crate) fn refused_user(target: &SessionTarget, requested: &str) {
        tracing::warn!(
            "ssh bastion refused userauth as '{}' on {}: the session was authorized for '{}'",
            escape_for_display(requested),
            target.describe(),
            target.user
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn allow(entries: Vec<ResolvedSshAllowance>) -> Allowances {
        Allowances::new(entries, "local").expect("distinct identities resolve")
    }

    fn request(user: &str, host: &str, port: u16) -> TargetRequest {
        TargetRequest {
            host: host.to_string(),
            port,
            user: user.to_string(),
        }
    }

    #[test]
    fn the_allowed_user_is_authorized_as_itself() {
        let allowances = allow(vec![allowance(
            Some("deploy"),
            "build.example.com",
            22,
            &[],
        )]);
        let target = allowances
            .authorize(&request("deploy", "build.example.com", 22))
            .expect("the allowed identity must authorize");
        assert_eq!(target.user, "deploy");
    }

    #[test]
    fn another_user_on_an_allowed_endpoint_is_refused_not_rewritten() {
        let allowances = allow(vec![allowance(
            Some("deploy"),
            "build.example.com",
            22,
            &[],
        )]);
        let refusal = allowances
            .authorize(&request("root", "build.example.com", 22))
            .expect_err("root was never allowed");
        assert_eq!(
            refusal,
            TargetRefusal::User(vec!["deploy@build.example.com:22".to_string()])
        );
        let message = refusal.message(&request("root", "build.example.com", 22), &allowances);
        assert!(message.contains("'root'"), "{message}");
        assert!(message.contains("deploy@build.example.com:22"), "{message}");
    }

    #[test]
    fn each_user_on_one_endpoint_keeps_its_own_rule() {
        let allowances = allow(vec![
            allowance(Some("deploy"), "build.example.com", 22, &[]),
            allowance(
                Some("git"),
                "build.example.com",
                22,
                &["git-upload-pack /srv/repo.git"],
            ),
        ]);
        let deploy = allowances
            .authorize(&request("deploy", "build.example.com", 22))
            .expect("deploy is allowed");
        assert_eq!(deploy.rule, EndpointRule::Session);
        let git = allowances
            .authorize(&request("git", "build.example.com", 22))
            .expect("git is allowed");
        assert_eq!(
            git.rule,
            EndpointRule::Commands(vec!["git-upload-pack /srv/repo.git".to_string()])
        );
        assert!(
            allowances
                .authorize(&request("root", "build.example.com", 22))
                .is_err()
        );
    }

    #[test]
    fn an_allowance_without_a_user_allows_only_nonos_own() {
        let allowances = allow(vec![allowance(None, "build.example.com", 22, &[])]);
        let target = allowances
            .authorize(&request("local", "build.example.com", 22))
            .expect("nono's own user must authorize");
        assert_eq!(target.user, "local");
        assert!(
            allowances
                .authorize(&request("root", "build.example.com", 22))
                .is_err()
        );
    }

    #[test]
    fn a_bare_entry_and_one_naming_nonos_own_user_collide() {
        let err = Allowances::new(
            vec![
                allowance(None, "build.example.com", 22, &[]),
                allowance(
                    Some("local"),
                    "build.example.com",
                    22,
                    &["git-upload-pack /srv/repo.git"],
                ),
            ],
            "local",
        )
        .expect_err("two entries for one identity must be refused")
        .to_string();
        assert!(err.contains("local@build.example.com:22"), "{err}");
    }

    #[test]
    fn a_port_the_allowance_does_not_name_is_refused() {
        let allowances = allow(vec![allowance(None, "build.example.com", 2222, &[])]);
        assert_eq!(
            allowances
                .authorize(&request("local", "build.example.com", 22))
                .expect_err("port 22 was never allowed"),
            TargetRefusal::Endpoint
        );
        assert!(
            allowances
                .authorize(&request("local", "build.example.com", 2222))
                .is_ok()
        );
    }

    #[test]
    fn a_second_host_is_refused() {
        let allowances = allow(vec![allowance(None, "build.example.com", 22, &[])]);
        assert_eq!(
            allowances
                .authorize(&request("local", "other.example.com", 22))
                .expect_err("the host was never allowed"),
            TargetRefusal::Endpoint
        );
    }

    #[test]
    fn the_target_line_round_trips() {
        let parsed = parse_target(&format!("{TARGET_PREAMBLE} build.example.com 2222 deploy"))
            .expect("parses");
        assert_eq!(parsed, request("deploy", "build.example.com", 2222));
    }

    #[test]
    fn a_malformed_target_line_is_refused() {
        for line in [
            "GARBAGE host 22 user",
            &format!("{TARGET_PREAMBLE} host 22"),
            &format!("{TARGET_PREAMBLE} host 22 user extra"),
            &format!("{TARGET_PREAMBLE}  22 user"),
            &format!("{TARGET_PREAMBLE} host 22 "),
            &format!("{TARGET_PREAMBLE} host 99999 user"),
        ] {
            assert!(
                parse_target(line).is_err(),
                "line must be refused: {line:?}"
            );
        }
    }
}
