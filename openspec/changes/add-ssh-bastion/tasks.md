## 1. Prerequisites

- [ ] 1.1 Archive `add-allow-ssh-egress` (`openspec archive add-allow-ssh-egress`)
      so `openspec/specs/network/ssh-egress/spec.md` exists; verify
      `openspec validate add-ssh-bastion --strict` no longer reports the
      modified capability as missing
- [ ] 1.2 Add `russh = { version = "0.63", default-features = false, features =
      ["ring", "rsa", "flate2"] }` to the workspace manifest and to the crate
      that will own the bastion; verify `cargo tree -p nono-cli -i aws-lc-rs`
      reports nothing, i.e. no second crypto backend entered the tree
- [ ] 1.3 Probe `russh`'s key loading for `sk-*` keys and certificates in a
      throwaway binary; record the answer in `design.md` Open Questions and let
      it decide whether 4.4 refuses those key types at startup

## 2. Channel policy

- [ ] 2.1 Add `ssh_bastion::policy` with `ChannelDecision::{Allow,
      Refuse(RefusedRequest)}` and one function mapping (channel type, request)
      to a decision, with no wildcard match arm; verify with unit tests that
      `session`+`exec`, `shell`, `pty-req`, `window-change`, `subsystem` and
      `signal` are allowed
- [ ] 2.2 Refuse `direct-tcpip`, `forwarded-tcpip`, `tcpip-forward`,
      `cancel-tcpip-forward`, `auth-agent-req@openssh.com` and `x11-req`, each
      with a reason naming the request; verify one unit test per refusal
      asserting the reason text names the request type
- [ ] 2.3 Verify by test that adding a new channel-request variant does not
      compile until it is classified (no `_ =>` arm anywhere in the module)

## 3. Sandbox-facing leg

- [ ] 3.1 Bind a `russh::server` on a unix socket under the existing session
      directory (`crates/nono-cli/src/ssh_client.rs` creates it `0700`); verify
      the socket path is inside the validated private dir and that the listener
      refuses to start if `validate_sessions_dir` rejects the directory
- [ ] 3.2 Generate a fresh ed25519 host key per session, write a `known_hosts`
      naming it for `*`, and emit the config with `StrictHostKeyChecking=yes`
      and `UserKnownHostsFile=<generated>`; verify two consecutive sessions
      present different keys and that the first session's key is rejected in the
      second
- [ ] 3.3 Accept the `none` authentication method on this leg only, and document
      in the module header that the boundary is the `0700` directory; verify a
      connection from a different uid is refused by the filesystem, not by SSH
- [ ] 3.4 Replace `nono ssh-tunnel` with a relay subcommand that connects to the
      session socket and copies stdio both ways, ending on server close (the
      existing tunnel's stdin-EOF bug is fixed this way - see
      `crates/nono-cli/src/ssh_tunnel.rs:70-84`); verify `ssh <allowed>` from
      inside the sandbox reaches the mediation
- [ ] 3.5 Regenerate the `ProxyCommand` line and the `ssh` wrapper to point at
      the relay (`ssh_client.rs:79`); verify the generated config no longer
      mentions `ssh-tunnel` and that `GIT_SSH_COMMAND` still resolves

## 4. Outbound leg

- [ ] 4.1 Re-check the requested `%h %p` against the resolved `allow_ssh`
      entries with the port-exact matcher before dialling; verify a session
      asking for an unlisted host is refused with the host named and no outbound
      socket opened (assert with a listener that must never accept)
- [ ] 4.2 Connect with `russh::client` and verify the remote host key against
      the user's `~/.ssh/known_hosts`, read in the parent; verify a known host
      connects, an unknown host is refused without writing to the store, and a
      changed key is refused with a message naming the endpoint
- [ ] 4.3 Authenticate via the host's `SSH_AUTH_SOCK` using `russh::keys`'
      agent client; verify against a real `ssh-agent` holding a test key that
      the session authenticates while no agent socket exists inside the sandbox
- [ ] 4.4 Support `--ssh-key FILE` by reading and parsing the key in the parent
      before sandbox setup; verify an encrypted key fails at startup with "add
      it to your agent", and that a key type 1.3 found unsupported fails at
      startup too
- [ ] 4.5 Resolve and validate the credential at the same point the other
      `allow_ssh` validations run, before the sandbox is built; verify that no
      usable credential is a startup error and not a mid-session failure

## 5. Relay and lifecycle

- [ ] 5.1 Wire the bastion into the proxy runtime beside the existing SSH client
      files (`crates/nono-cli/src/proxy_runtime.rs:3170-3182`), starting it when
      `allow_ssh` is non-empty and tearing it down with the session; verify the
      socket is gone after the run and the session directory is removed
- [ ] 5.2 Run each mediated session as its own supervised task so a panic ends
      that session only; verify with a test that forces a session task to panic
      and asserts the proxy still serves a subsequent request
- [ ] 5.3 Propagate exit status, `exit-signal`, and stream separation
      end-to-end; verify a remote command exiting 7 exits 7 locally, and that
      stderr arrives on stderr
- [ ] 5.4 Forward `pty-req` and `window-change` for interactive sessions; verify
      against a real `sshd` that `stty size` inside the session reports the
      local terminal size and follows a resize

## 6. Fail closed

- [ ] 6.1 Stop adding `host:port` to `allowed_hosts` for `allow_ssh`
      (`proxy_runtime.rs:2439-2449`), keeping the `ssh_endpoints` pins; verify
      `CONNECT <allowed-host>:22` is now refused and that the pin still refuses
      every other host on that port
- [ ] 6.2 Make a failure to start the mediation fail the session with an error
      naming the mediation; verify no environment variable or flag yields an
      unmediated tunnel (grep the tree for a remaining raw-tunnel path as part
      of the check)
- [ ] 6.3 Warn when the caller grants the agent socket into the sandbox
      (`--allow-unix-socket "$SSH_AUTH_SOCK"`) while `allow_ssh` is active;
      verify the warning names the flag and explains it is no longer needed
- [ ] 6.4 Keep the existing refusal when the destination pin cannot be installed
      (`crates/nono-cli/src/execution_runtime.rs`, keyed off
      `seccomp_proxy_fallback`); verify the existing test still passes

## 7. Audit and diagnostics

- [ ] 7.1 Record each decision in the existing audit log
      (`crates/nono-proxy/src/audit.rs`) with endpoint, channel type, request
      type, command line, and allowed/refused; verify an allowed `exec` and a
      refused `direct-tcpip` both appear with the command line present on the
      first
- [ ] 7.2 Distinguish a policy refusal from a transport failure in both the
      audit record and the user-visible error; verify the refusal text does not
      read as a network error (the `ConfigParse`-vs-`SshTunnel` mistake in
      `61b03406` is the precedent)
- [ ] 7.3 Report mediation state in `nono why --self`; verify the output names
      the mediated endpoints and the channel policy in force

## 8. Integration against a real sshd

- [ ] 8.1 Extend `crates/nono-cli/tests/ssh_egress_run.rs` to start a real
      `sshd` with a generated host key and test user key, not a banner server;
      verify the existing allowance tests still pass against it
- [ ] 8.2 Acceptance matrix, one test each: `ssh host cmd` runs; `ssh host`
      interactive runs; `git fetch` over SSH succeeds; `scp`/`sftp` succeed;
      `ssh -L` is refused; `ssh -R` is refused; `ssh -J` is refused;
      `ssh -A` is refused; a second host on the pinned port is refused
- [ ] 8.3 Verify no agent socket and no private key are reachable inside the
      sandbox during a successful session (assert on the capability set and on
      a read attempt from inside)
- [ ] 8.4 Measure the added latency of one `git fetch` against the pre-change
      route and record the number in the change; a regression worth reporting is
      a finding, not a reason for a bypass

## 9. Documentation and cleanup

- [ ] 9.1 Rewrite the Client Wiring and Rejected Combinations sections of
      `docs/cli/features/networking.mdx` for the mediated route, including what
      is refused and why; verify the doc no longer describes a raw tunnel
- [ ] 9.2 Document the credential change: the agent stays outside, the grant is
      no longer needed, `--ssh-key` is read by nono; verify `docs/cli/usage/flags.mdx`
      matches the implemented behavior
- [ ] 9.3 Delete `crates/nono-cli/src/ssh_tunnel.rs`, its CLI wiring, and the
      `SshTunnel` error variant if nothing else uses it; verify `cargo check -p
      nono-cli --all-targets` is clean and no doc references the subcommand
- [ ] 9.4 Run the full unit suite and the SSH integration suite; verify the
      failure set matches the recorded pre-existing baseline exactly
