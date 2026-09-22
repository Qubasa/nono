//! The sandbox-facing leg: nono's own SSH server, on a unix socket.
//!
//! The client inside the sandbox terminates here, not at the remote host. Every
//! channel and every channel request is authorized by [`super::policy`] before
//! it is relayed, which is the whole reason the session is terminated rather
//! than tunnelled: the difference between `git fetch` and a port forward is
//! inside the encrypted stream, so only a party that decrypts it can tell.
//!
//! Authentication on this leg is the `none` method. The boundary is the `0700`
//! session directory the socket lives in: a process of another uid cannot
//! `connect(2)` to it at all, and a process of the same uid could read the
//! credential directly. Asking for a password here would be theatre.

use nono::{NonoError, Result};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty, Sig};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::client::Outbound;
use super::policy::{
    ChannelDecision, ChannelKind, ChannelRequest, EndpointRule, GlobalRequest, RefusedRequest,
};
use super::{SessionTarget, audit};

/// The outbound half of one relayed channel.
///
/// Split rather than shared: `wait` needs `&mut`, and the pump task owns it
/// for the life of the channel while every request handler writes through the
/// clonable write half.
type RemoteWrite = Arc<ChannelWriteHalf<russh::client::Msg>>;

/// One mediated session: the outbound half plus the channels bound to it.
pub(crate) struct BastionSession {
    target: SessionTarget,
    outbound: Arc<Outbound>,
    /// Client channel id to the outbound channel it is relayed onto. Written
    /// by `channel_open_session`, read by every request that follows.
    channels: Arc<Mutex<HashMap<ChannelId, RemoteWrite>>>,
}

impl BastionSession {
    pub(crate) fn new(target: SessionTarget, outbound: Outbound) -> Self {
        Self {
            target,
            outbound: Arc::new(outbound),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn rule(&self) -> &EndpointRule {
        &self.target.rule
    }

    async fn outbound_channel(&self, id: ChannelId) -> Option<RemoteWrite> {
        self.channels.lock().await.get(&id).cloned()
    }

    /// Answer a refused request the way a server answers a failed request, so
    /// a refused `-L` fails that request and leaves a running shell alone.
    fn refuse(&self, id: ChannelId, session: &mut Session, refusal: &RefusedRequest) {
        audit::refused(&self.target, refusal);
        let _ = session.channel_failure(id);
    }
}

impl server::Handler for BastionSession {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> std::result::Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let ChannelDecision::Refuse(refusal) =
            super::policy::authorize_channel(self.rule(), ChannelKind::Session)
        {
            audit::refused(&self.target, &refusal);
            return Ok(());
        }

        let remote = match self.outbound.handle.channel_open_session().await {
            Ok(remote) => remote,
            Err(err) => {
                tracing::warn!(
                    "ssh bastion could not open a session channel on {}: {err}",
                    self.target.describe()
                );
                return Ok(());
            }
        };
        let (remote_read, remote_write) = remote.split();

        let id = channel.id();
        self.channels
            .lock()
            .await
            .insert(id, Arc::new(remote_write));
        reply.accept().await;

        spawn_remote_pump(id, remote_read, session.handle(), self.target.clone());
        audit::allowed(&self.target, "session", None);
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_channel(ChannelKind::X11);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_channel(ChannelKind::DirectTcpip);
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_channel(ChannelKind::ForwardedTcpip);
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.refuse_channel(ChannelKind::DirectStreamlocal);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(remote) = self.outbound_channel(channel).await {
            let _ = remote.data_bytes(data.to_vec()).await;
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(remote) = self.outbound_channel(channel).await {
            let _ = remote.extended_data_bytes(code, data.to_vec()).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(remote) = self.outbound_channel(channel).await {
            let _ = remote.eof().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(remote) = self.channels.lock().await.remove(&channel) {
            let _ = remote.close().await;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Exec(data)) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => {
                let command = String::from_utf8_lossy(data).into_owned();
                match self.outbound_channel(channel).await {
                    Some(remote) if remote.exec(false, data.to_vec()).await.is_ok() => {
                        audit::allowed(&self.target, "exec", Some(&command));
                        let _ = session.channel_success(channel);
                    }
                    _ => {
                        let _ = session.channel_failure(channel);
                    }
                }
            }
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Shell) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => match self.outbound_channel(channel).await {
                Some(remote) if remote.request_shell(false).await.is_ok() => {
                    audit::allowed(&self.target, "shell", None);
                    let _ = session.channel_success(channel);
                }
                _ => {
                    let _ = session.channel_failure(channel);
                }
            },
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Subsystem(name)) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => match self.outbound_channel(channel).await {
                Some(remote) if remote.request_subsystem(false, name).await.is_ok() => {
                    audit::allowed(&self.target, "subsystem", Some(name));
                    let _ = session.channel_success(channel);
                }
                _ => {
                    let _ = session.channel_failure(channel);
                }
            },
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Pty) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => {
                let modes = modes.to_vec();
                match self.outbound_channel(channel).await {
                    Some(remote)
                        if remote
                            .request_pty(
                                false, term, col_width, row_height, pix_width, pix_height, &modes,
                            )
                            .await
                            .is_ok() =>
                    {
                        audit::allowed(&self.target, "pty-req", Some(term));
                        let _ = session.channel_success(channel);
                    }
                    _ => {
                        let _ = session.channel_failure(channel);
                    }
                }
            }
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::WindowChange) {
            ChannelDecision::Refuse(refusal) => self.refuse(channel, session, &refusal),
            ChannelDecision::Allow => match self.outbound_channel(channel).await {
                Some(remote)
                    if remote
                        .window_change(col_width, row_height, pix_width, pix_height)
                        .await
                        .is_ok() =>
                {
                    let _ = session.channel_success(channel);
                }
                _ => {
                    let _ = session.channel_failure(channel);
                }
            },
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Signal) {
            ChannelDecision::Refuse(refusal) => self.refuse(channel, session, &refusal),
            ChannelDecision::Allow => {
                if let Some(remote) = self.outbound_channel(channel).await {
                    let _ = remote.signal(signal).await;
                }
            }
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::Env) {
            ChannelDecision::Refuse(refusal) => self.refuse(channel, session, &refusal),
            ChannelDecision::Allow => {
                let _ = session.channel_success(channel);
            }
        }
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::X11) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => {
                let _ = session.channel_success(channel);
            }
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        match super::policy::authorize_request(self.rule(), ChannelRequest::AgentForward) {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
                Ok(false)
            }
            ChannelDecision::Allow => Ok(true),
        }
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.refuse_global(GlobalRequest::TcpipForward))
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.refuse_global(GlobalRequest::CancelTcpipForward))
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.refuse_global(GlobalRequest::StreamlocalForward))
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.refuse_global(GlobalRequest::CancelStreamlocalForward))
    }
}

impl BastionSession {
    /// Record a refused channel open. Dropping the reply handle without
    /// accepting is what actually rejects it, so there is nothing to send.
    fn refuse_channel(&self, kind: ChannelKind) {
        if let ChannelDecision::Refuse(refusal) =
            super::policy::authorize_channel(self.rule(), kind)
        {
            audit::refused(&self.target, &refusal);
        }
    }

    fn refuse_global(&self, request: GlobalRequest) -> bool {
        match super::policy::authorize_global(request) {
            ChannelDecision::Refuse(refusal) => {
                audit::refused(&self.target, &refusal);
                false
            }
            ChannelDecision::Allow => true,
        }
    }
}

/// Put the refusal on the client's stderr.
///
/// A bare channel failure reaches OpenSSH as a one-line "administratively
/// prohibited" with no attribution, which reads as the remote host misbehaving.
/// The text says which nono rule fired.
fn send_refusal_text(session: &mut Session, channel: ChannelId, refusal: &RefusedRequest) {
    let message = format!("nono: {} refused: {}\r\n", refusal.request, refusal.reason);
    let _ = session.extended_data(channel, 1, message.into_bytes());
}

/// Carry everything the remote sends back to the client.
///
/// Its own task, so a session that stalls or panics ends that session only;
/// `handle` is the client-facing side and every send is best-effort, because
/// the client closing first is normal rather than an error.
fn spawn_remote_pump(
    id: ChannelId,
    mut remote: ChannelReadHalf,
    handle: server::Handle,
    target: SessionTarget,
) {
    tokio::spawn(async move {
        loop {
            let Some(msg) = remote.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { data } => {
                    let _ = handle.data(id, data.to_vec()).await;
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    let _ = handle.extended_data(id, ext, data.to_vec()).await;
                }
                ChannelMsg::Eof => {
                    let _ = handle.eof(id).await;
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    let _ = handle.exit_status_request(id, exit_status).await;
                }
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                } => {
                    let _ = handle
                        .exit_signal_request(id, signal_name, core_dumped, error_message, lang_tag)
                        .await;
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = handle.close(id).await;
        tracing::debug!(
            "ssh bastion session channel closed on {}",
            target.describe()
        );
    });
}

/// Serve one already-authorized connection from the sandbox.
pub(crate) async fn serve(
    config: Arc<server::Config>,
    stream: tokio::net::UnixStream,
    target: SessionTarget,
    outbound: Outbound,
) -> Result<()> {
    let handler = BastionSession::new(target, outbound);
    let running = server::run_stream(config, stream, handler)
        .await
        .map_err(|err| NonoError::SshBastion(format!("ssh bastion session failed: {err}")))?;
    running
        .await
        .map_err(|err| NonoError::SshBastion(format!("ssh bastion session ended: {err}")))
}
