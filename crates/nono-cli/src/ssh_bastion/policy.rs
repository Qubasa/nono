//! The bastion's channel policy, as a pure function of the request.
//!
//! Nothing here touches a socket, so what the mediation permits is decided in
//! unit tests rather than against a remote host.
//!
//! There is no `_ =>` arm anywhere in this module, and that is the point of its
//! verbosity: every channel type and every request is classified by name, so
//! when a future `russh` exposes one nono has never seen, this module stops
//! compiling until somebody decides what it is. A wildcard arm would turn that
//! moment into a silent pass or a silent refusal, and only one of those is even
//! noticed.

use super::command::{self, CommandDecision};

/// What one allowance permits on its endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndpointRule {
    /// Default session policy: shell, exec, pty, subsystem all run.
    Session,
    /// Task endpoint: only these exact command lines may run, and a
    /// shell, pty or subsystem is refused outright.
    Commands(Vec<String>),
}

/// A channel type the client asked to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelKind {
    Session,
    X11,
    DirectTcpip,
    ForwardedTcpip,
    DirectStreamlocal,
}

/// A request made inside an already-open channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelRequest<'a> {
    Shell,
    Exec(&'a [u8]),
    Pty,
    WindowChange,
    Subsystem(&'a str),
    Signal,
    Env,
    X11,
    AgentForward,
}

/// A request made on the connection rather than on a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobalRequest {
    TcpipForward,
    CancelTcpipForward,
    StreamlocalForward,
    CancelStreamlocalForward,
}

/// Why a request was refused. `request` is the wire name, so the message
/// the client sees names the same thing the audit line does.
///
/// `routine` separates "a client asked for something it cannot have" from
/// "ordinary clients do this on every run". `git fetch` sends `env` for
/// LANG/LC_*, so warning on it would put a policy warning in the log of every
/// successful fetch and teach the reader to ignore the ones that matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusedRequest {
    pub(crate) request: &'static str,
    pub(crate) reason: String,
    pub(crate) routine: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChannelDecision {
    Allow,
    Refuse(RefusedRequest),
}

/// Authorize opening a channel.
///
/// The endpoint's rule plays no part here: a restricted endpoint still opens a
/// session channel, and the narrowing happens on the requests made inside it.
pub(crate) fn authorize_channel(_rule: &EndpointRule, kind: ChannelKind) -> ChannelDecision {
    match kind {
        ChannelKind::Session => ChannelDecision::Allow,
        ChannelKind::X11 => refuse(
            "x11",
            "x11 is refused: an X11 channel carries a connection back to a display, which turns the mediated session into a transport",
        ),
        ChannelKind::DirectTcpip => refuse(
            "direct-tcpip",
            "direct-tcpip is refused: it opens a forwarded connection to a third address, which turns the mediated session into a transport",
        ),
        ChannelKind::ForwardedTcpip => refuse(
            "forwarded-tcpip",
            "forwarded-tcpip is refused: it delivers a connection the remote host accepted for a listener nono never established, which turns the mediated session into a transport",
        ),
        ChannelKind::DirectStreamlocal => refuse(
            "direct-streamlocal@openssh.com",
            "direct-streamlocal@openssh.com is refused: it opens a forwarded connection to a unix socket on the remote host, which turns the mediated session into a transport",
        ),
    }
}

/// Authorize a request made inside a session channel.
pub(crate) fn authorize_request(
    rule: &EndpointRule,
    request: ChannelRequest<'_>,
) -> ChannelDecision {
    match rule {
        EndpointRule::Session => authorize_session_request(request),
        EndpointRule::Commands(commands) => authorize_restricted_request(commands, request),
    }
}

/// Authorize a request made on the connection itself.
pub(crate) fn authorize_global(request: GlobalRequest) -> ChannelDecision {
    match request {
        GlobalRequest::TcpipForward => refuse(
            "tcpip-forward",
            "tcpip-forward is refused: asking the remote host to listen on a port and hand the connections back turns the mediated session into a transport",
        ),
        GlobalRequest::CancelTcpipForward => refuse(
            "cancel-tcpip-forward",
            "cancel-tcpip-forward is refused: no remote listener exists to cancel, because tcpip-forward is refused",
        ),
        GlobalRequest::StreamlocalForward => refuse(
            "streamlocal-forward@openssh.com",
            "streamlocal-forward@openssh.com is refused: asking the remote host to listen on a unix socket and hand the connections back turns the mediated session into a transport",
        ),
        GlobalRequest::CancelStreamlocalForward => refuse(
            "cancel-streamlocal-forward@openssh.com",
            "cancel-streamlocal-forward@openssh.com is refused: no remote listener exists to cancel, because streamlocal-forward@openssh.com is refused",
        ),
    }
}

fn authorize_session_request(request: ChannelRequest<'_>) -> ChannelDecision {
    match request {
        ChannelRequest::Shell
        | ChannelRequest::Exec(_)
        | ChannelRequest::Pty
        | ChannelRequest::WindowChange
        | ChannelRequest::Subsystem(_)
        | ChannelRequest::Signal => ChannelDecision::Allow,
        ChannelRequest::Env => refuse_env(),
        ChannelRequest::X11 => refuse_x11(),
        ChannelRequest::AgentForward => refuse_agent_forward(),
    }
}

fn authorize_restricted_request(
    commands: &[String],
    request: ChannelRequest<'_>,
) -> ChannelDecision {
    match request {
        ChannelRequest::Exec(command_line) => {
            match command::command_matches(commands, command_line) {
                CommandDecision::Allowed => ChannelDecision::Allow,
                CommandDecision::Refused(reason) => refuse("exec", reason),
            }
        }
        ChannelRequest::Shell => refuse(
            "shell",
            format!(
                "shell is refused: this endpoint's allowance restricts it to the commands {}, and a shell runs whatever is typed into it",
                command::command_list(commands)
            ),
        ),
        ChannelRequest::Pty => refuse(
            "pty-req",
            format!(
                "pty-req is refused: this endpoint's allowance restricts it to the commands {}, and a pseudo-terminal only serves the interactive session that restriction denies",
                command::command_list(commands)
            ),
        ),
        ChannelRequest::Subsystem(name) => refuse(
            "subsystem",
            format!(
                "subsystem `{name}` is refused: this endpoint's allowance restricts it to the commands {}, and a subsystem reads and writes outside them",
                command::command_list(commands)
            ),
        ),
        // Meaningless without a pty, and harmless with one.
        ChannelRequest::WindowChange | ChannelRequest::Signal => ChannelDecision::Allow,
        ChannelRequest::Env => refuse_env(),
        ChannelRequest::X11 => refuse_x11(),
        ChannelRequest::AgentForward => refuse_agent_forward(),
    }
}

/// Refusing `env` is benign: the variable is dropped rather than forwarded,
/// most servers reject env requests anyway, and `TERM` travels inside `pty-req`
/// where it belongs.
fn refuse_env() -> ChannelDecision {
    refuse_routine(
        "env",
        "env is refused: the variable is dropped rather than forwarded, which costs nothing because TERM travels inside pty-req and most servers reject env requests anyway",
    )
}

fn refuse_x11() -> ChannelDecision {
    refuse(
        "x11-req",
        "x11-req is refused: X11 forwarding asks the remote host to open a channel back to a display, which turns the mediated session into a transport",
    )
}

fn refuse_agent_forward() -> ChannelDecision {
    refuse(
        "auth-agent-req@openssh.com",
        "auth-agent-req@openssh.com is refused: the credential nono authenticates with stays outside the sandbox, and forwarding the agent would offer it to the remote host as a signing oracle",
    )
}

fn refuse(request: &'static str, reason: impl Into<String>) -> ChannelDecision {
    ChannelDecision::Refuse(RefusedRequest {
        request,
        reason: reason.into(),
        routine: false,
    })
}

/// A refusal well-behaved clients trigger on their own. Same refusal, quieter
/// record.
fn refuse_routine(request: &'static str, reason: impl Into<String>) -> ChannelDecision {
    ChannelDecision::Refuse(RefusedRequest {
        request,
        reason: reason.into(),
        routine: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(decision: ChannelDecision) -> RefusedRequest {
        match decision {
            ChannelDecision::Refuse(refused) => refused,
            ChannelDecision::Allow => panic!("expected a refusal, got Allow"),
        }
    }

    fn restricted() -> EndpointRule {
        EndpointRule::Commands(vec!["git-upload-pack /srv/repo.git".to_string()])
    }

    #[test]
    fn session_channels_open_on_either_kind_of_endpoint() {
        assert_eq!(
            authorize_channel(&EndpointRule::Session, ChannelKind::Session),
            ChannelDecision::Allow
        );
        assert_eq!(
            authorize_channel(&restricted(), ChannelKind::Session),
            ChannelDecision::Allow
        );
    }

    #[test]
    fn x11_channel_is_refused() {
        let refused = refusal(authorize_channel(&EndpointRule::Session, ChannelKind::X11));
        assert_eq!(refused.request, "x11");
        assert!(refused.reason.contains("x11"), "{}", refused.reason);
    }

    #[test]
    fn direct_tcpip_channel_is_refused() {
        let refused = refusal(authorize_channel(
            &EndpointRule::Session,
            ChannelKind::DirectTcpip,
        ));
        assert_eq!(refused.request, "direct-tcpip");
        assert!(
            refused.reason.contains("direct-tcpip"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn forwarded_tcpip_channel_is_refused() {
        let refused = refusal(authorize_channel(
            &EndpointRule::Session,
            ChannelKind::ForwardedTcpip,
        ));
        assert_eq!(refused.request, "forwarded-tcpip");
        assert!(
            refused.reason.contains("forwarded-tcpip"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn direct_streamlocal_channel_is_refused() {
        let refused = refusal(authorize_channel(
            &EndpointRule::Session,
            ChannelKind::DirectStreamlocal,
        ));
        assert_eq!(refused.request, "direct-streamlocal@openssh.com");
        assert!(
            refused.reason.contains("direct-streamlocal@openssh.com"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn x11_request_is_refused() {
        let refused = refusal(authorize_request(
            &EndpointRule::Session,
            ChannelRequest::X11,
        ));
        assert_eq!(refused.request, "x11-req");
        assert!(refused.reason.contains("x11-req"), "{}", refused.reason);
    }

    #[test]
    fn agent_forwarding_request_is_refused() {
        let refused = refusal(authorize_request(
            &EndpointRule::Session,
            ChannelRequest::AgentForward,
        ));
        assert_eq!(refused.request, "auth-agent-req@openssh.com");
        assert!(
            refused.reason.contains("auth-agent-req@openssh.com"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn env_request_is_dropped_on_either_kind_of_endpoint() {
        for rule in [EndpointRule::Session, restricted()] {
            let refused = refusal(authorize_request(&rule, ChannelRequest::Env));
            assert_eq!(refused.request, "env");
            assert!(refused.reason.contains("dropped"), "{}", refused.reason);
        }
    }

    /// `git fetch` sends `env` on every run. If this refusal stops being
    /// routine, every successful fetch starts logging a policy warning and the
    /// warnings that mean something get lost among them.
    #[test]
    fn only_env_is_a_routine_refusal() {
        for rule in [EndpointRule::Session, restricted()] {
            assert!(
                refusal(authorize_request(&rule, ChannelRequest::Env)).routine,
                "env is what well-behaved clients send unprompted"
            );
        }

        for decision in [
            authorize_request(&EndpointRule::Session, ChannelRequest::X11),
            authorize_request(&EndpointRule::Session, ChannelRequest::AgentForward),
            authorize_global(GlobalRequest::TcpipForward),
            authorize_channel(&EndpointRule::Session, ChannelKind::DirectTcpip),
        ] {
            let refused = refusal(decision);
            assert!(
                !refused.routine,
                "{} asks for a capability the mediation exists to refuse",
                refused.request
            );
        }
    }

    #[test]
    fn tcpip_forward_is_refused() {
        let refused = refusal(authorize_global(GlobalRequest::TcpipForward));
        assert_eq!(refused.request, "tcpip-forward");
        assert!(
            refused.reason.contains("tcpip-forward"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn cancel_tcpip_forward_is_refused() {
        let refused = refusal(authorize_global(GlobalRequest::CancelTcpipForward));
        assert_eq!(refused.request, "cancel-tcpip-forward");
        assert!(
            refused.reason.contains("cancel-tcpip-forward"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn streamlocal_forward_is_refused() {
        let refused = refusal(authorize_global(GlobalRequest::StreamlocalForward));
        assert_eq!(refused.request, "streamlocal-forward@openssh.com");
        assert!(
            refused.reason.contains("streamlocal-forward@openssh.com"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn cancel_streamlocal_forward_is_refused() {
        let refused = refusal(authorize_global(GlobalRequest::CancelStreamlocalForward));
        assert_eq!(refused.request, "cancel-streamlocal-forward@openssh.com");
        assert!(
            refused
                .reason
                .contains("cancel-streamlocal-forward@openssh.com"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn an_unrestricted_endpoint_runs_work_on_the_remote_host() {
        let rule = EndpointRule::Session;
        for request in [
            ChannelRequest::Shell,
            ChannelRequest::Exec(b"uname -a"),
            ChannelRequest::Pty,
            ChannelRequest::WindowChange,
            ChannelRequest::Subsystem("sftp"),
            ChannelRequest::Signal,
        ] {
            assert_eq!(
                authorize_request(&rule, request),
                ChannelDecision::Allow,
                "{request:?}"
            );
        }
    }

    #[test]
    fn the_command_list_is_what_costs_a_restricted_endpoint_its_shell() {
        let restricted = restricted();
        let unrestricted = EndpointRule::Session;
        for (request, wire) in [
            (ChannelRequest::Shell, "shell"),
            (ChannelRequest::Pty, "pty-req"),
            (ChannelRequest::Subsystem("sftp"), "subsystem"),
        ] {
            let refused = refusal(authorize_request(&restricted, request));
            assert_eq!(refused.request, wire);
            assert!(
                refused.reason.contains("restricts it to the commands")
                    && refused.reason.contains("git-upload-pack /srv/repo.git"),
                "{}",
                refused.reason
            );
            assert_eq!(
                authorize_request(&unrestricted, request),
                ChannelDecision::Allow,
                "{request:?}"
            );
        }
    }

    #[test]
    fn a_restricted_endpoint_runs_the_named_command_only() {
        let rule = restricted();
        assert_eq!(
            authorize_request(
                &rule,
                ChannelRequest::Exec(b"git-upload-pack /srv/repo.git")
            ),
            ChannelDecision::Allow
        );
        let refused = refusal(authorize_request(
            &rule,
            ChannelRequest::Exec(b"git-receive-pack /srv/repo.git"),
        ));
        assert_eq!(refused.request, "exec");
        assert!(
            refused.reason.contains("git-receive-pack /srv/repo.git"),
            "{}",
            refused.reason
        );
    }

    #[test]
    fn a_restricted_endpoint_keeps_window_change_and_signal() {
        let rule = restricted();
        assert_eq!(
            authorize_request(&rule, ChannelRequest::WindowChange),
            ChannelDecision::Allow
        );
        assert_eq!(
            authorize_request(&rule, ChannelRequest::Signal),
            ChannelDecision::Allow
        );
    }
}
