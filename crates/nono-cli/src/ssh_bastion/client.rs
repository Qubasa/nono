//! The outbound leg: nono's own SSH session to the allowed endpoint.
//!
//! Two things happen out here that the sandbox is deliberately not trusted
//! with. The remote host key is checked against the user's `known_hosts`, with
//! no trust-on-first-use and no write-back, so no in-sandbox process can decide
//! that a new key is fine. And the signature is produced by the host's agent or
//! by a key nono read itself, so the credential never crosses the boundary.

use crate::network_policy::SshEndpoint;
use nono::{NonoError, Result};
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, ssh_key};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::audit;
use super::credential::SshCredential;
use super::policy::{ChannelDecision, RemoteChannelKind, authorize_remote_channel};

/// How long the outbound session tolerates silence before giving up.
const OUTBOUND_INACTIVITY: Duration = Duration::from_secs(3600);

/// Verdict recorded by [`OutboundHandler::check_server_key`].
///
/// `check_server_key` can only answer yes or no, and a bare no surfaces as a
/// generic handshake failure. The reason is parked here so the caller can say
/// which of "unknown" and "changed" happened, and name the endpoint.
#[derive(Debug, Clone, Default)]
struct HostKeyVerdict(Arc<Mutex<Option<String>>>);

impl HostKeyVerdict {
    fn record(&self, reason: String) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(reason);
        }
    }

    fn take(&self) -> Option<String> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

pub(crate) struct OutboundHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    verdict: HostKeyVerdict,
}

impl OutboundHandler {
    /// Refuse a channel the remote host opened toward nono.
    ///
    /// Dropping the handle is what rejects it. russh's defaults accept most of
    /// these, so every one of them is named here rather than left to them.
    fn refuse_remote(&self, kind: RemoteChannelKind) {
        if let ChannelDecision::Refuse(refusal) = authorize_remote_channel(kind) {
            audit::refused_remote(&self.host, self.port, &refusal);
        }
    }
}

impl client::Handler for OutboundHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            russh::keys::PublicKeyOrCertificate::Certificate(_) => {
                self.verdict.record(format!(
                    "{}:{} presented a host certificate, which nono does not verify on the \
                     sandbox's behalf",
                    self.host, self.port
                ));
                return Ok(false);
            }
        };

        match russh::keys::check_known_hosts_path(&self.host, self.port, &key, &self.known_hosts) {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.verdict.record(format!(
                    "{}:{} is not in {}, and nono does not trust a host key on first use for a \
                     sandboxed session.\n\n\
                     Connect to it once outside the sandbox to record the key, then retry.",
                    self.host,
                    self.port,
                    self.known_hosts.display()
                ));
                Ok(false)
            }
            Err(russh::keys::Error::KeyChanged { line }) => {
                self.verdict.record(format!(
                    "{}:{} presented a host key that differs from the one recorded at {}:{}. \
                     The stored key was left unchanged.",
                    self.host,
                    self.port,
                    self.known_hosts.display(),
                    line
                ));
                Ok(false)
            }
            Err(err) => {
                self.verdict.record(format!(
                    "{}:{} host key could not be checked against {}: {err}",
                    self.host,
                    self.port,
                    self.known_hosts.display()
                ));
                Ok(false)
            }
        }
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::Session);
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::X11);
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::DirectTcpip);
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::DirectStreamlocal);
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::ForwardedTcpip);
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::ForwardedStreamlocal);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: russh::Channel<client::Msg>,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_remote(RemoteChannelKind::AgentForward);
        Ok(())
    }
}

/// An authenticated outbound session.
pub(crate) struct Outbound {
    pub(crate) handle: client::Handle<OutboundHandler>,
}

/// Dial the endpoint, verify its host key, and authenticate as the allowance's
/// user.
///
/// The user is the allowance's, never the client's: the sandbox chooses which
/// allowed endpoint to reach, not which identity to reach it as.
pub(crate) async fn connect(
    endpoint: &SshEndpoint,
    user: &str,
    credential: &SshCredential,
    known_hosts: &Path,
) -> Result<Outbound> {
    let verdict = HostKeyVerdict::default();
    let handler = OutboundHandler {
        host: endpoint.host.clone(),
        port: endpoint.port,
        known_hosts: known_hosts.to_path_buf(),
        verdict: verdict.clone(),
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(OUTBOUND_INACTIVITY),
        ..client::Config::default()
    });

    let mut handle = client::connect(config, (endpoint.host.as_str(), endpoint.port), handler)
        .await
        .map_err(|err| match verdict.take() {
            Some(reason) => NonoError::SshBastion(reason),
            None => NonoError::SshBastion(format!(
                "network.allow_ssh could not reach {}:{}: {err}",
                endpoint.host, endpoint.port
            )),
        })?;

    authenticate(&mut handle, endpoint, user, credential).await?;
    Ok(Outbound { handle })
}

/// Why an outbound authentication did not happen, phrased for the user who
/// wrote the allowance.
fn refused(endpoint: &SshEndpoint, user: &str, detail: &str) -> NonoError {
    NonoError::SshBastion(format!(
        "network.allow_ssh could not authenticate to {}@{}:{}: {detail}",
        user, endpoint.host, endpoint.port
    ))
}

async fn authenticate(
    handle: &mut client::Handle<OutboundHandler>,
    endpoint: &SshEndpoint,
    user: &str,
    credential: &SshCredential,
) -> Result<()> {
    match credential {
        SshCredential::Key(key) => {
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|err| {
                    refused(
                        endpoint,
                        user,
                        &format!("the server rejected the key exchange: {err}"),
                    )
                })?
                .flatten();
            let key = PrivateKeyWithHashAlg::new(key.clone(), hash_alg);
            let result = handle
                .authenticate_publickey(user, key)
                .await
                .map_err(|err| refused(endpoint, user, &format!("the attempt failed: {err}")))?;
            if !result.success() {
                return Err(refused(
                    endpoint,
                    user,
                    "the server rejected the key named by --ssh-key",
                ));
            }
            Ok(())
        }
        SshCredential::Agent(socket) => {
            authenticate_with_agent(handle, endpoint, user, socket).await
        }
    }
}

/// Try each agent identity in turn, as OpenSSH does.
///
/// The agent is reached from the parent, so a sandboxed process cannot ask it
/// for a signature at all, let alone one for a host no allowance covers.
async fn authenticate_with_agent(
    handle: &mut client::Handle<OutboundHandler>,
    endpoint: &SshEndpoint,
    user: &str,
    socket: &Path,
) -> Result<()> {
    let mut agent = russh::keys::agent::client::AgentClient::connect_uds(socket)
        .await
        .map_err(|err| {
            refused(
                endpoint,
                user,
                &format!("the ssh-agent at {} refused: {err}", socket.display()),
            )
        })?;

    let identities = agent.request_identities().await.map_err(|err| {
        refused(
            endpoint,
            user,
            &format!("the ssh-agent would not list its identities: {err}"),
        )
    })?;

    if identities.is_empty() {
        return Err(refused(
            endpoint,
            user,
            &format!("the ssh-agent at {} holds no identities", socket.display()),
        ));
    }

    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .map_err(|err| {
            refused(
                endpoint,
                user,
                &format!("the server rejected the key exchange: {err}"),
            )
        })?
        .flatten();

    // Each identity in turn, as OpenSSH does. A certificate is offered as a
    // certificate rather than as the key inside it, because a server that
    // trusts the CA may not know the key at all.
    let mut unsignable = Vec::new();
    for identity in identities {
        let fingerprint = identity.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        let attempt = match identity {
            russh::keys::agent::AgentIdentity::PublicKey { key, .. } => {
                handle
                    .authenticate_publickey_with(user, key, hash_alg, &mut agent)
                    .await
            }
            russh::keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                handle
                    .authenticate_certificate_with(user, certificate, hash_alg, &mut agent)
                    .await
            }
        };
        // An `Err` here is the agent declining to sign, not the server
        // declining the key: a FIDO key whose token is absent, a touch that
        // timed out, a locked smartcard. OpenSSH moves to the next identity,
        // and so does nono.
        let result = match attempt {
            Ok(result) => result,
            Err(err) => {
                unsignable.push(format!("{fingerprint} ({err})"));
                continue;
            }
        };
        if result.success() {
            tracing::debug!(
                "ssh bastion authenticated to {}@{}:{} with agent identity {fingerprint}",
                user,
                endpoint.host,
                endpoint.port
            );
            return Ok(());
        }
    }

    if unsignable.is_empty() {
        return Err(refused(
            endpoint,
            user,
            "the server rejected every identity the ssh-agent holds",
        ));
    }
    Err(refused(
        endpoint,
        user,
        &format!(
            "no identity the ssh-agent holds was accepted, and it would not sign with {}",
            unsignable.join(", ")
        ),
    ))
}
