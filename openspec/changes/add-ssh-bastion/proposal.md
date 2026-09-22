## Why

`network.allow_ssh` pins *where* a sandboxed process may speak SSH. It says
nothing about *what* it may do once it gets there, and it hands the sandbox the
credential that gets it in.

Both gaps are structural, not bugs:

| Gap | Where it comes from |
| --- | --- |
| One allowance grants a full interactive shell, plus `-L`/`-R`/`-D` forwards, plus `-J` onward hops | `handle_connect` relays bytes opaquely once the filter allows the authority (`crates/nono-proxy/src/connect.rs`), and `nono ssh-tunnel` is a 90-line CONNECT-to-stdio pipe (`crates/nono-cli/src/ssh_tunnel.rs:39`) |
| The agent signs for the sandbox, for any host, including hosts no allowance covers | The agent socket is bind-mounted *into* the sandbox; the pin refuses the connection, never the signature |
| The sandbox decides host-key trust | `Host *` in the generated config (`crates/nono-cli/src/ssh_client.rs:79`) leaves `known_hosts` to the client, inside the sandbox |

An `--allow-ssh build.example.com` intended for `git fetch` is, today, a shell
on the build box and a TCP forwarder to anything that box can reach. The port
pin cannot express the difference, because the difference is inside the
encrypted stream.

The only thing that can express it is a party that terminates SSH: it sees
channel requests (`exec`, `shell`, `direct-tcpip`, `auth-agent-req`), so it can
allow the first two and refuse the rest, keep the credential outside the
sandbox, and verify the remote host key itself.

## What Changes

- **New:** an SSH bastion inside nono. The sandboxed client speaks SSH to nono
  over a session-scoped unix socket; nono authenticates to the real endpoint
  itself and relays the session at the channel level.
- **New:** a channel policy. By default a `session` channel with `shell`,
  `exec`, `pty-req`, `window-change` and `subsystem` requests is allowed and
  audited. Every forwarding request - `direct-tcpip` (`-L`, `-D`, and `-J`),
  `tcpip-forward` (`-R`), `auth-agent-req@openssh.com`, `x11-req` - is refused,
  and the refusal names the request type.
- **New:** a per-endpoint command allowlist. An allowance may carry a list of
  exact command lines, and then only those commands run:

  ```json
  "allow_ssh": [
    { "endpoint": "git@build.example.com",
      "commands": ["git-upload-pack /srv/repo.git"] }
  ]
  ```

  The entry is an object form of the existing string entry, mirroring how
  `allow_domain` already carries optional endpoint rules
  (`AllowDomainEntry::{Plain, WithEndpoints}`, `crates/nono-cli/src/profile/mod.rs:1768`).
  Matching is exact on the tokenised argument vector; a command carrying shell
  metacharacters is refused before matching, because the string is interpreted
  by the remote shell and not by nono.
- **New:** an endpoint that carries a command allowlist becomes a task
  endpoint, not a login. `shell`, `pty-req` and `subsystem` are refused there,
  because an interactive shell would simply run the command the allowlist just
  refused. Endpoints without a list keep the default above.
- **New:** credentials leave the sandbox. nono uses the *host's* agent or a key
  file it reads itself; neither the agent socket nor the key file needs a grant
  inside the sandbox any more.
- **New:** host-key verification moves outside the sandbox. nono checks the
  endpoint against the user's `known_hosts` and refuses an unknown or changed
  key. The sandbox is handed a generated `known_hosts` naming only nono's own
  ephemeral per-session host key, so no in-sandbox process can accept a new key.
- **New:** every channel request is recorded in the existing audit log with the
  endpoint, request type, and command string.
- **BREAKING:** `nono ssh-tunnel` and the raw CONNECT route for SSH are
  removed. `allow_ssh` no longer adds `host:port` to the proxy allowlist, so
  `CONNECT host:22` is refused for every host including the allowed one. The
  subcommand is hidden and undocumented; a caller invoking it directly gets an
  unknown-subcommand error.
- **Unchanged:** the port pin (`ssh_endpoints`), the kernel-enforcement refusal
  (`allow_ssh` without the seccomp supervisor fails at startup), the
  `--block-net` and `no_proxy` conflicts, and the generated wrapper and
  `GIT_SSH_COMMAND` ergonomics. The `[user@]host[:port]` endpoint syntax is
  unchanged; it gains an object form that carries the command list.

Explicitly out of scope: session recording or replay beyond the audit line, and
multi-user access. Command allowlists are per endpoint and exact; patterns,
globs and argument templating are deliberately absent.

## Capabilities

### New Capabilities

- `network/ssh-session-mediation`: nono terminates the SSH session, authorizes
  it at the channel level and - where an allowance says so - at the command
  level, holds the credential outside the sandbox, and verifies the remote host
  key on the sandbox's behalf.

### Modified Capabilities

- `network/ssh-egress`: an SSH allowance now authorizes a *mediated SSH
  session* rather than a raw TCP tunnel to the endpoint, and may name the exact
  commands that session may run. Reachability, port exactness and the
  kernel-enforcement refusal are unchanged; the entry syntax gains an object
  form, the route and the failure text change, and the tunnel subcommand is
  removed.

## Dependencies

`network/ssh-egress` still lives in the unarchived change
`add-allow-ssh-egress`. That change MUST be archived before this one is
applied, so the modified-capability delta here has a main spec to modify.

## Impact

- New dependency: `russh` 0.63 (client + server), built against `ring` so the
  tree does not gain a second crypto backend beside rustls.
- New hostile-input surface: the remote server's bytes are parsed by `russh`
  inside the nono parent process, which is outside the sandbox. Today they are
  parsed by OpenSSH inside it. This is the central risk of the change and is
  argued in `design.md`.
- Compatibility: anything OpenSSH does that is not a `session` channel stops
  working, by design. `sftp`/`scp`/`rsync` keep working (they are `subsystem`
  and `exec`). FIDO (`sk-*`) keys and SSH certificates work only through the
  agent; a direct key file of those types must fail loudly at startup rather
  than mid-session.
- Platform: the bastion itself is platform-independent, but the existing
  refusal to run `allow_ssh` without a kernel-enforced destination pin stays,
  because a sandboxed process that can open arbitrary sockets does not need the
  bastion at all.
