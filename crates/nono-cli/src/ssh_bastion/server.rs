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
//!
//! Nothing in a handler waits on the remote. russh polls these handlers on the
//! session loop, and the loop is also what drains the messages the return
//! direction sends back, so a handler that waits for remote window stops the
//! very thing that would deliver the window update. Each relayed channel gets
//! a pump task in each direction instead, and the handlers only queue.

use nono::{NonoError, Result};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty, Sig};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::client::Outbound;
use super::policy::{
    ChannelDecision, ChannelKind, ChannelRequest, EndpointRule, GlobalRequest, RefusedRequest,
};
use super::{SessionTarget, audit};

/// Queued client bytes past which the session stops replenishing the client's
/// channel window.
///
/// The inbound queues have to be unbounded to keep the session loop moving, so
/// this is what bounds them: a remote that stops reading stops the sandbox from
/// sending, which is what flow control is for.
const BACKLOG_HIGH_WATER: usize = 4 * 1024 * 1024;
/// Window advertised while the backlog is over the high-water mark. Small, but
/// never zero: russh asks again only after it has granted something.
const THROTTLED_WINDOW: u32 = 32 * 1024;

/// Client channel id to the pump that owns its outbound write half.
type Channels = Arc<Mutex<HashMap<ChannelId, UnboundedSender<Relayed>>>>;

/// Terminal geometry, as `pty-req` and `window-change` both carry it.
struct WindowSize {
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
}

struct PtyRequest {
    term: String,
    size: WindowSize,
    modes: Vec<(Pty, u32)>,
}

/// A request made on an open channel, authorized and queued as one unit.
enum RelayedRequest {
    Exec(Vec<u8>),
    Shell,
    Subsystem(String),
    Pty(PtyRequest),
    WindowChange(WindowSize),
    Signal(Sig),
}

impl RelayedRequest {
    fn audit(&self) -> audit::Allowed {
        match self {
            Self::Exec(command) => audit::Allowed {
                request: "exec",
                detail: Some(String::from_utf8_lossy(command).into_owned()),
                routine: false,
            },
            Self::Shell => audit::Allowed {
                request: "shell",
                detail: None,
                routine: false,
            },
            Self::Subsystem(name) => audit::Allowed {
                request: "subsystem",
                detail: Some(name.clone()),
                routine: false,
            },
            Self::Pty(pty) => audit::Allowed {
                request: "pty-req",
                detail: Some(pty.term.clone()),
                routine: false,
            },
            // A terminal being dragged sends these continuously, and a signal
            // is the client's own Ctrl-C arriving. Recorded, not announced.
            Self::WindowChange(_) => audit::Allowed {
                request: "window-change",
                detail: None,
                routine: true,
            },
            Self::Signal(_) => audit::Allowed {
                request: "signal",
                detail: None,
                routine: true,
            },
        }
    }

    /// Whether the remote owes an answer nono has to relay back.
    ///
    /// `window-change` and `signal` carry no reply by definition (RFC 4254),
    /// the rest are asked with `want_reply` set so that a refusal by the remote
    /// reaches the sandbox as a failed request rather than as a bare exit 255.
    fn wants_reply(&self) -> bool {
        match self {
            Self::Exec(_) | Self::Shell | Self::Subsystem(_) | Self::Pty(_) => true,
            Self::WindowChange(_) | Self::Signal(_) => false,
        }
    }
}

/// One item on a relayed channel's outbound queue.
enum Relayed {
    Data(Vec<u8>),
    ExtendedData { code: u32, data: Vec<u8> },
    Eof,
    Close,
    Request(RelayedRequest),
}

impl Relayed {
    /// What this item costs the parent while it waits for remote window.
    fn queued_bytes(&self) -> usize {
        match self {
            Self::Data(data) => data.len(),
            Self::ExtendedData { data, .. } => data.len(),
            Self::Eof | Self::Close | Self::Request(_) => 0,
        }
    }

    fn wants_reply(&self) -> bool {
        match self {
            Self::Request(request) => request.wants_reply(),
            Self::Data(_) | Self::ExtendedData { .. } | Self::Eof | Self::Close => false,
        }
    }
}

/// One mediated session: the outbound half plus the channels bound to it.
pub(crate) struct BastionSession {
    target: SessionTarget,
    outbound: Arc<Outbound>,
    /// Written by `channel_open_session`, read by every request that follows
    /// and retired by whichever pump sees the channel end.
    channels: Channels,
    /// Client bytes queued across all of this session's channels.
    backlog: Arc<AtomicUsize>,
    window_size: u32,
}

impl BastionSession {
    pub(crate) fn new(target: SessionTarget, outbound: Outbound, window_size: u32) -> Self {
        Self {
            target,
            outbound: Arc::new(outbound),
            channels: Arc::new(Mutex::new(HashMap::new())),
            backlog: Arc::new(AtomicUsize::new(0)),
            window_size,
        }
    }

    fn rule(&self) -> &EndpointRule {
        &self.target.rule
    }

    /// Hand one item to the channel's pump. False means there is no such
    /// channel, or its pump has gone.
    async fn queue(&self, id: ChannelId, item: Relayed) -> bool {
        let Some(pump) = self.channels.lock().await.get(&id).cloned() else {
            return false;
        };
        let bytes = item.queued_bytes();
        self.backlog.fetch_add(bytes, Ordering::Relaxed);
        if pump.send(item).is_err() {
            self.backlog.fetch_sub(bytes, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Authorize, record and queue one channel request.
    ///
    /// Every request kind goes through here so that the refusal text, the audit
    /// line and the reply cannot drift apart between them. Nothing is awaited
    /// on the remote: a success arrives later, from the pump.
    async fn relay(
        &self,
        channel: ChannelId,
        session: &mut Session,
        decision: ChannelDecision,
        request: RelayedRequest,
    ) {
        match decision {
            ChannelDecision::Refuse(refusal) => {
                send_refusal_text(session, channel, &refusal);
                self.refuse(channel, session, &refusal);
            }
            ChannelDecision::Allow => {
                audit::allowed(&self.target, request.audit());
                if !self.queue(channel, Relayed::Request(request)).await {
                    let _ = session.channel_failure(channel);
                }
            }
        }
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

    /// Hold the client's window back while its bytes are still queued here.
    fn adjust_window(&mut self, _channel: ChannelId, _current: u32) -> u32 {
        if self.backlog.load(Ordering::Relaxed) >= BACKLOG_HIGH_WATER {
            THROTTLED_WINDOW
        } else {
            self.window_size
        }
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

        let id = channel.id();
        let (queue, queued) = unbounded_channel();
        self.channels.lock().await.insert(id, queue);
        reply.accept().await;
        audit::allowed(
            &self.target,
            audit::Allowed {
                request: "session",
                detail: None,
                routine: false,
            },
        );
        spawn_relay(Relay {
            id,
            outbound: self.outbound.clone(),
            queued,
            handle: session.handle(),
            target: self.target.clone(),
            channels: self.channels.clone(),
            backlog: self.backlog.clone(),
        });
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
        self.queue(channel, Relayed::Data(data.to_vec())).await;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.queue(
            channel,
            Relayed::ExtendedData {
                code,
                data: data.to_vec(),
            },
        )
        .await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        self.queue(channel, Relayed::Eof).await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(pump) = self.channels.lock().await.remove(&channel) {
            let _ = pump.send(Relayed::Close);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let decision = super::policy::authorize_request(self.rule(), ChannelRequest::Exec(data));
        self.relay(
            channel,
            session,
            decision,
            RelayedRequest::Exec(data.to_vec()),
        )
        .await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let decision = super::policy::authorize_request(self.rule(), ChannelRequest::Shell);
        self.relay(channel, session, decision, RelayedRequest::Shell)
            .await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let decision =
            super::policy::authorize_request(self.rule(), ChannelRequest::Subsystem(name));
        self.relay(
            channel,
            session,
            decision,
            RelayedRequest::Subsystem(name.to_string()),
        )
        .await;
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
        let decision = super::policy::authorize_request(self.rule(), ChannelRequest::Pty);
        let request = RelayedRequest::Pty(PtyRequest {
            term: term.to_string(),
            size: WindowSize {
                col_width,
                row_height,
                pix_width,
                pix_height,
            },
            modes: modes.to_vec(),
        });
        self.relay(channel, session, decision, request).await;
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
        let decision = super::policy::authorize_request(self.rule(), ChannelRequest::WindowChange);
        let request = RelayedRequest::WindowChange(WindowSize {
            col_width,
            row_height,
            pix_width,
            pix_height,
        });
        self.relay(channel, session, decision, request).await;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        let decision = super::policy::authorize_request(self.rule(), ChannelRequest::Signal);
        self.relay(channel, session, decision, RelayedRequest::Signal(signal))
            .await;
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

/// One relayed channel, from the moment the client's half is accepted.
struct Relay {
    id: ChannelId,
    outbound: Arc<Outbound>,
    queued: UnboundedReceiver<Relayed>,
    handle: server::Handle,
    target: SessionTarget,
    channels: Channels,
    backlog: Arc<AtomicUsize>,
}

/// Open the outbound half, then pump both directions until the channel ends.
///
/// The open is a round trip with the remote, which is why it happens here and
/// not in the handler: the session loop that calls the handlers is also what
/// drains the return direction, so a round trip taken inside one waits on the
/// loop it is blocking.
fn spawn_relay(relay: Relay) {
    tokio::spawn(async move {
        let Relay {
            id,
            outbound,
            queued,
            handle,
            target,
            channels,
            backlog,
        } = relay;
        let remote = match outbound.handle.channel_open_session().await {
            Ok(remote) => remote,
            Err(err) => {
                tracing::warn!(
                    "ssh bastion could not open a session channel on {}: {err}",
                    target.describe()
                );
                let message = format!(
                    "nono: {} would not open a session channel: {err}\r\n",
                    target.describe()
                );
                let _ = handle.extended_data(id, 1, message.into_bytes()).await;
                channels.lock().await.remove(&id);
                let _ = handle.close(id).await;
                return;
            }
        };
        let (remote_read, remote_write) = remote.split();
        spawn_inbound_pump(id, remote_write, queued, handle.clone(), backlog);
        remote_pump(id, remote_read, handle, target, channels).await;
    });
}

/// Carry everything the client sends on to the remote.
///
/// Its own task because `data_bytes` parks until the remote grants window, and
/// the session loop that calls the handlers is also the loop that drains what
/// the return direction sends back: parking in a handler stops the only thing
/// that could deliver the window update.
fn spawn_inbound_pump(
    id: ChannelId,
    remote: ChannelWriteHalf<russh::client::Msg>,
    mut queued: UnboundedReceiver<Relayed>,
    handle: server::Handle,
    backlog: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        while let Some(item) = queued.recv().await {
            let bytes = item.queued_bytes();
            let wants_reply = item.wants_reply();
            let sent = forward(&remote, item).await;
            backlog.fetch_sub(bytes, Ordering::Relaxed);
            if let Err(err) = sent {
                tracing::debug!("ssh bastion could not reach the remote channel: {err}");
                if wants_reply {
                    let _ = handle.channel_failure(id).await;
                }
                break;
            }
        }
    });
}

async fn forward(
    remote: &ChannelWriteHalf<russh::client::Msg>,
    item: Relayed,
) -> std::result::Result<(), russh::Error> {
    match item {
        Relayed::Data(data) => remote.data_bytes(data).await,
        Relayed::ExtendedData { code, data } => remote.extended_data_bytes(code, data).await,
        Relayed::Eof => remote.eof().await,
        Relayed::Close => remote.close().await,
        Relayed::Request(request) => forward_request(remote, request).await,
    }
}

async fn forward_request(
    remote: &ChannelWriteHalf<russh::client::Msg>,
    request: RelayedRequest,
) -> std::result::Result<(), russh::Error> {
    match request {
        RelayedRequest::Exec(command) => remote.exec(true, command).await,
        RelayedRequest::Shell => remote.request_shell(true).await,
        RelayedRequest::Subsystem(name) => remote.request_subsystem(true, name).await,
        RelayedRequest::Pty(pty) => {
            remote
                .request_pty(
                    true,
                    &pty.term,
                    pty.size.col_width,
                    pty.size.row_height,
                    pty.size.pix_width,
                    pty.size.pix_height,
                    &pty.modes,
                )
                .await
        }
        RelayedRequest::WindowChange(size) => {
            remote
                .window_change(
                    size.col_width,
                    size.row_height,
                    size.pix_width,
                    size.pix_height,
                )
                .await
        }
        RelayedRequest::Signal(signal) => remote.signal(signal).await,
    }
}

/// Carry everything the remote sends back to the client.
///
/// Every send is best-effort: the client closing first is normal rather than
/// an error.
async fn remote_pump(
    id: ChannelId,
    mut remote: ChannelReadHalf,
    handle: server::Handle,
    target: SessionTarget,
    channels: Channels,
) {
    while let Some(msg) = remote.wait().await {
        if !relay_back(id, &handle, msg).await {
            break;
        }
    }
    // Retire the entry here rather than waiting for the client's close: until
    // it goes, every later request resolves to a pump with nothing on the
    // other end of it.
    channels.lock().await.remove(&id);
    let _ = handle.close(id).await;
    tracing::debug!(
        "ssh bastion session channel closed on {}",
        target.describe()
    );
}

/// Relay one message from the remote. False means the channel is over.
async fn relay_back(id: ChannelId, handle: &server::Handle, msg: ChannelMsg) -> bool {
    match msg {
        ChannelMsg::Data { data } => {
            let _ = handle.data(id, data).await;
        }
        ChannelMsg::ExtendedData { data, ext } => {
            let _ = handle.extended_data(id, ext, data).await;
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
        // The remote's answer to a request nono relayed with `want_reply` set.
        // Without it the sandbox is told its exec succeeded whatever the remote
        // decided about `command=`, `ForceCommand` or `PermitTTY no`.
        ChannelMsg::Success => {
            let _ = handle.channel_success(id).await;
        }
        ChannelMsg::Failure => {
            let _ = handle.channel_failure(id).await;
        }
        ChannelMsg::Close => return false,
        // Nothing to relay: flow control and channel setup belong to the leg
        // they happen on, and the rest are messages only a client sends, which
        // nono is on this leg.
        ChannelMsg::Open { .. }
        | ChannelMsg::OpenFailure(_)
        | ChannelMsg::WindowAdjusted { .. }
        | ChannelMsg::XonXoff { .. }
        | ChannelMsg::RequestPty { .. }
        | ChannelMsg::RequestShell { .. }
        | ChannelMsg::Exec { .. }
        | ChannelMsg::Signal { .. }
        | ChannelMsg::RequestSubsystem { .. }
        | ChannelMsg::RequestX11 { .. }
        | ChannelMsg::SetEnv { .. }
        | ChannelMsg::WindowChange { .. }
        | ChannelMsg::AgentForward { .. } => {}
        // `ChannelMsg` is `#[non_exhaustive]`, so this arm cannot be removed.
        // It says so out loud instead of dropping a new variant in silence.
        unknown => {
            tracing::warn!("ssh bastion received a channel message it does not know: {unknown:?}");
        }
    }
    true
}

/// Serve one already-authorized connection from the sandbox.
pub(crate) async fn serve(
    config: Arc<server::Config>,
    stream: tokio::net::UnixStream,
    target: SessionTarget,
    outbound: Outbound,
) -> Result<()> {
    let handler = BastionSession::new(target, outbound, config.window_size);
    let running = server::run_stream(config, stream, handler)
        .await
        .map_err(|err| {
            NonoError::Io(std::io::Error::other(format!(
                "ssh bastion session failed: {err}"
            )))
        })?;
    running.await.map_err(|err| {
        NonoError::Io(std::io::Error::other(format!(
            "ssh bastion session ended: {err}"
        )))
    })
}
