## Context

See `proposal.md` - Why. What matters for the approach is where each piece runs
today:

| Piece | Process | File |
| --- | --- | --- |
| Proxy, filter, audit log | nono parent, outside the sandbox | `crates/nono-proxy/src/{server,filter,audit}.rs` |
| Port pins (`ssh_endpoints`) | same | `crates/nono-proxy/src/filter.rs` |
| Generated `ssh` config + wrapper, `0700` session dir | written by the parent, read by the sandbox | `crates/nono-cli/src/ssh_client.rs` |
| `nono ssh-tunnel` (CONNECT -> stdio) | **inside** the sandbox, as `ProxyCommand` | `crates/nono-cli/src/ssh_tunnel.rs` |
| Destination pin (`connect` to `127.0.0.1:<proxy_port>` only) | seccomp user-notification supervisor | `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:813` |

The last two rows set the shape of the solution. `ProxyCommand` runs inside the
sandbox, so the mediation cannot live there - it would hold the credential
inside the thing it is protecting against. The mediation must live in the
parent, and the in-sandbox side must be reduced to a dumb pipe that carries
bytes to it.

## Goals / Non-Goals

**Goals**

- One code path. After this change there is no configuration that yields a
  byte-transparent tunnel to an SSH port.
- The channel policy is a pure function of the request, so it is unit-testable
  without a network or a remote host.
- The hostile-input surface added to the parent process is bounded and named.

**Non-Goals**

- Pattern matching of any kind in the command allowlist. Rules are exact argument
  vectors; globs, prefixes and argument templating are the footgun this design
  refuses, because each of them turns "allow one command" into "allow a family
  of commands I have not enumerated".
- Configurability of the *channel* policy beyond the command allowlist. Which
  forwarding requests are refused is fixed here.
- Session recording beyond the audit line. No keystroke or output capture.
- Performance work. Two SSH sessions mean two handshakes and double symmetric
  crypto; on a `git fetch` this is noise next to the transfer.

## Decisions

### D1: Mediate in the parent, reach it over a unix socket

The `ProxyCommand` inside the sandbox becomes a relay that connects to a unix
socket in the existing session directory and copies stdio both ways. nono's SSH
server side binds that socket in the parent.

- **Why a unix socket, not a loopback port.** The session directory is already
  created `0700` and validated (non-symlink, owned by the euid, `mode & 0o077 ==
  0`) by `ensure_private_dir` / `validate_sessions_dir`. Filesystem permissions
  then carry the same weight the proxy's session token carries on loopback,
  without a token to leak into a config file the sandbox can read. It also means
  the mediation needs no entry in the seccomp destination pin: `AF_UNIX` to a
  granted path is a separate decision from `connect()` to an address.
- **Why not serve SSH over the `ProxyCommand`'s stdio directly.** That process
  runs inside the sandbox. It would have to hold the credential and the
  known-hosts decision there, which is the thing being fixed.
- **Alternative rejected:** reuse the HTTP proxy port with a new verb. It would
  put an SSH state machine behind a token the sandbox can read, and entangle two
  protocols in one listener for no gain.

### D2: `russh` 0.63, both halves, `ring` backend

`russh` is the only maintained pure-Rust SSH implementation with **both** a
client and a server (`Eugeny/russh`, 1.9k stars, ~2.9M recent downloads). Both
halves are needed: server for the sandbox-facing leg, client for the outbound
leg. Its `keys` module also speaks the agent protocol, which D4 needs.

Build it with `default-features = false, features = ["ring", ...]`. The default
feature set pulls `aws-lc-rs`; nono already links `ring` through rustls, and a
second crypto backend in one binary is a supply-chain and audit cost with no
benefit.

- **Alternative rejected:** shelling out to OpenSSH twice (a local `sshd -i` and
  an outbound `ssh`). It would keep the hardened parser but gives no channel
  visibility - `sshd` hands the session to a shell, it does not report channel
  requests - and requires a host `sshd` binary, a generated `sshd_config`, and
  privilege assumptions nono does not make.

### D3: Channel policy as a decision function

```
ChannelDecision::{Allow, Refuse(reason)}   <-  (channel_type, request)
```

Allowed: `session` channels; `shell`, `exec`, `pty-req`, `window-change`,
`subsystem`, `signal`, `exit-status`, `exit-signal`.
Refused: `direct-tcpip`, `forwarded-tcpip`, `tcpip-forward`,
`cancel-tcpip-forward`, `auth-agent-req@openssh.com`, `x11-req`, and any
unrecognised type. No wildcard arm - a new channel type added by a future
`russh` is a compile error, not a silent pass.

`subsystem` is allowed because it is work on the remote host, not a transport:
refusing it would break `sftp`, `scp` in its modern form, and `rsync -e ssh`.
The subsystem name is recorded in the audit line.

`env` requests are dropped rather than forwarded (most servers reject them
anyway), except that `TERM` travels inside `pty-req` where it belongs.

### D4: Credential resolution happens before the sandbox starts

Order: `--ssh-key FILE` if given, else the host's `SSH_AUTH_SOCK`. Both are
resolved, opened, and validated in the parent *before* the sandbox is built, so
"no usable credential" is a startup error next to the other `allow_ssh`
validations rather than a mid-session failure.

An encrypted key file fails with "add it to your agent" rather than prompting:
nono is often launched non-interactively, and a passphrase prompt racing a
sandbox startup is worse than a clear refusal. Hardware-backed (`sk-*`) keys and
certificates are agent-only for the same reason - `russh`'s direct file support
for them must be probed at startup and refused if absent.

Consequence for callers: the `--allow-unix-socket "$SSH_AUTH_SOCK"` grant that
wrappers like `cn` pass becomes unnecessary. It is not an error to pass it, but
nono warns, because it re-opens exactly the hole this change closes.

### D5: Two known-hosts stores, opposite directions

- **Outbound**: nono checks the endpoint against the user's `~/.ssh/known_hosts`
  itself. Unknown key -> refuse, never TOFU, never write. The sandbox has no say.
- **Inbound**: nono generates an ed25519 host key per session, writes a
  `known_hosts` naming it for `*`, and points the generated config at it with
  `StrictHostKeyChecking=yes` and `UserKnownHostsFile=<generated>`. The client
  then verifies nono, and a key stolen from one session is useless in the next.

Using `*` in the generated file is safe precisely because the `ProxyCommand`
delivers whatever endpoint nono authorizes: the name the client thinks it is
talking to is not a trust input on that leg.

### D6: The allowance check moves to the mediation, the pin stays

`%h %p` arrive as the relay's arguments, i.e. from inside the sandbox, so they
are untrusted. The parent re-checks them against the resolved `allow_ssh`
entries with the same port-exact matcher the filter uses before dialling out.

The filter's port pins stay as they are. They are now defence in depth rather
than the route: with `allow_ssh` no longer adding `host:port` to
`allowed_hosts`, `CONNECT host:22` is refused for every host, allowed or not.

### D7: Exact argv matching, on an object form of the allowance entry

`allow_ssh` becomes an untagged enum mirroring `AllowDomainEntry`
(`crates/nono-cli/src/profile/mod.rs:1768`), so the two allowlists stay the
same shape and `serde` handles the string/object split:

```rust
enum AllowSshEntry {
    Plain(String),
    WithCommands { endpoint: String, commands: Vec<String> },
}
```

Matching runs in three steps, all in the parent:

1. **Reject, then tokenise.** If the requested command contains any of
   `; | & $ \` ( ) < > { }` or a newline, refuse immediately. These are the
   characters that let one command become two, and nono cannot evaluate them -
   the remote shell does.
2. **Tokenise both sides identically.** Quote-aware POSIX word splitting with
   no expansion, applied to the rule and to the request. `git-upload-pack
   '/srv/repo.git'` and `git-upload-pack /srv/repo.git` are the same argv, and
   should match the same rule.
3. **Compare argument vectors element-wise.** No prefix, no glob, no "argv0
   matches so the rest is free".

Step 1 before step 2 matters: tokenising first and inspecting tokens afterwards
invites a rule that looks satisfied while the string still carries a separator
the shell will act on.

A restricted endpoint refuses `shell`, `pty-req` and `subsystem` outright -
D3's decision function takes the endpoint's rule as an input rather than
deciding on the request alone. Without that, the allowlist is theatre: `ssh
host` with no command opens a shell and types whatever it likes.

- **Alternative rejected: argv0 allowlisting.** One rule would cover every
  repository, which is the appeal and also the hole - `git-upload-pack` with a
  free path argument reaches every repository on the host, and
  `git-receive-pack` is a *different* argv0 that a user who wrote "allow git"
  would assume was covered.
- **Alternative rejected: forced commands** (OpenSSH's `command=`). Robust,
  since nothing is matched at all, but an endpoint can then run exactly one
  thing, and `git fetch` plus `git push` already needs two.
- **Not nono's to enforce:** what the allowed command then does on the far
  side. `git-upload-pack /srv/repo.git` is trusted to be `git-upload-pack`.
  A remote-side `authorized_keys` with `restrict` remains the stronger control
  and the two compose.

## Risks / Trade-offs

- **`russh` parses hostile remote bytes inside the parent process** → This is
  the central trade-off and it is accepted, not mitigated away. Bound it:
  `russh` is reached only after the endpoint passed the allowance check, the
  session task owns no capability beyond the credential and its two sockets, and
  the parent already parses attacker-influenced input (TLS, HTTP/2) from the
  same position. A panic in a session task must not take the proxy down -
  sessions run as supervised tasks whose failure ends that session only.
- **A command allowlist reads as stronger than it is** → It authorizes the
  *request*, not the effect. `git-receive-pack /srv/repo.git` is a push, and a
  push can run remote hooks. Document that the allowlist bounds which commands
  start, and that bounding what they then do is the remote host's job
  (`authorized_keys` `restrict`, `command=`).
- **Exact matching breaks on a client that quotes differently** → Tokenise
  before comparing rather than comparing strings, and test the real clients:
  OpenSSH's `git` integration quotes the repository path, plain `ssh host cmd`
  does not, and both must match the same rule.
- **Feature regressions surface as "ssh broke"** → The refusal path names the
  request type and points at the documentation, so `-L` fails as "port
  forwarding is refused by network.allow_ssh", not as a hang. The acceptance
  matrix in `tasks.md` enumerates what must keep working.
- **`russh` interop gaps against real servers** (KEX, ciphers, certificates,
  older OpenSSH) → Test against a real `sshd` in the integration suite, not a
  `russh` server talking to itself, which would test nothing about interop.
- **Double encryption cost** → Measured once on a `git fetch`; if it is not
  noise, that is a finding to report, not a reason to add a bypass.
- **The relay is a new in-sandbox binary path** → It connects to one unix socket
  and copies bytes; it holds no policy, so compromising it grants nothing the
  sandbox does not already have.

## Migration Plan

1. `add-allow-ssh-egress` is archived first, so `network/ssh-egress` exists as a
   main spec for this change's delta.
2. The bastion lands behind the existing `allow_ssh` key - there is no new
   profile key and no flag day. A profile that worked before works after, with
   the route swapped underneath it.
3. `nono ssh-tunnel` is deleted in the same change. Keeping it as a hidden
   fallback would leave the weaker path reachable by anything that can exec
   nono, which is the opposite of the point.
4. Rollback is `git revert` of the change: the profile key, the pins, and the
   generated-config plumbing all predate it.

## Resolved Questions

- **Certificates and `sk-*` keys through the agent.** `russh::keys::agent`
  yields an `AgentIdentity` that is either a plain `PublicKey` or a
  `Certificate`, and the client offers each in turn, so both work over the
  agent with no extra plumbing. Direct key *files* of either kind do not, and
  they fail differently. A hardware-backed key decodes and is then refused by
  the algorithm check at startup, naming `ssh-add` as the remedy, which is what
  D4 anticipated. A certificate never reaches that check: it is a separate
  artifact from the private key, so `decode_secret_key` refuses it as a parse
  failure and the user is told the file could not be parsed. Both are startup
  errors, but only the first says "agent".

## Measured

- **Latency of one `git fetch` over the mediated route** (task 8.4), against a
  real `sshd` on loopback with a new commit before each run so every fetch
  transfers objects: 6 runs, mean **0.56 s** (first run 0.66 s cold, steady
  state 0.52-0.53 s). The same fetch with no nono at all: 6 runs, mean
  **0.14 s**. So the route costs about **+0.42 s per fetch**, and that delta is
  `nono run` startup - sandbox construction, proxy, bastion bind - not the
  relay: a bare `nono run -- sh -c true` on the same profile lands in the same
  ballpark. There is no pre-change comparison because the old route no longer
  exists to measure; an `ssh-tunnel` number would time a different mechanism.

## Known Limits

- **The mediation does not contain an agent the sandbox can already reach.**
  It stops nono from handing a credential inward; it does not stop a sandboxed
  process from opening the host's `SSH_AUTH_SOCK` itself. That is decided by
  `linux.af_unix_mediation`, which is off by default in proxy-only mode
  (issue #1901). The specs and `docs/cli/features/networking.mdx` say so
  plainly rather than claim containment the sandbox does not have.
- **`ssh -L` is refused by Landlock's TCP-bind restriction, not by the channel
  policy.** Binding the local listener happens before any channel opens, so the
  `direct-tcpip` rule never sees it. The seccomp destination pin is a different
  control and governs `connect`/`sendto`; the `bind` refusal comes from
  `AccessNet::BindTcp` (`crates/nono/src/sandbox/linux.rs`). The channel rule
  is still reached, and tested, through `ssh -J`.

## Open Questions

None outstanding.
