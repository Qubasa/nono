## Why

nono can pin a sandboxed process to a single *host*, but not to a single
*service on that host*, and nothing makes a raw-TCP client such as `ssh` use
that pin. An agent that legitimately needs `ssh deploy@build.example.com`
today has exactly three options, all wrong:

| Option | What it actually grants |
| --- | --- |
| `network.connect_port: [22]` | TCP/22 to **every host on the internet**. Landlock's `AccessNet` carries a port and no address (`crates/nono/src/sandbox/linux.rs:1200-1210`), and the seccomp-notify supervisor is not even installed in this mode (`crates/nono-cli/src/exec_strategy.rs:248-250`). |
| `network.allow_domain: ["build.example.com:22"]` | The host on **every port**. `expand_proxy_allow` strips the `:port` suffix (`crates/nono-cli/src/network_policy.rs:397-401`) and `collect_allow_domain_port_warnings` prints a warning saying so. It also does nothing for `ssh`, which speaks no HTTP. |
| `network.block: false` / `--allow-net` | Everything. |

Measured on nono 0.78.0, NixOS, Landlock V6 kernel, profile
`{"network": {"allow_domain": ["github.com:22"]}}`, raw `CONNECT` probes from
inside the sandbox:

| Probe | Observed |
| --- | --- |
| `CONNECT github.com:22` | `HTTP/1.1 200 Connection Established` |
| `CONNECT github.com:443` | `HTTP/1.1 200 Connection Established` |
| `CONNECT github.com:80` | `HTTP/1.1 200 Connection Established` |
| `CONNECT gitlab.com:22` | `HTTP/1.1 403 Forbidden: host gitlab.com:22 is not in the allowlist` |
| `nc github.com 22` (direct, no proxy) | `connect to github.com (140.82.121.3) port 22 failed: Permission denied` |

The last row is the good news: the kernel-level pin already works. Proxy mode
forces a seccomp-notify supervisor unconditionally
(`crates/nono-cli/src/execution_runtime.rs:660-664`) and
`decide_network_notification` denies every `connect`/`sendto` whose sockaddr is
not `127.0.0.1:<proxy_port>`
(`crates/nono-cli/src/exec_strategy/supervisor_linux.rs:813`). Unsetting
`HTTPS_PROXY` yields `EACCES`, not escape.

The missing pieces are narrow: an allow entry whose port is honoured, and a way
to route `ssh` through the tunnel that already exists. `ProxyFilter` can
already match port-exact entries — `check_host_result` appends `:port` and
retries the allowlist (`crates/nono-proxy/src/filter.rs:128-153`, test
`test_proxy_filter_allows_host_port_entries` at :192) — and `handle_connect`
accepts any port and relays bytes opaquely
(`crates/nono-proxy/src/connect.rs:180-198`). The same probe run with a
`ProxyCommand` reached a real SSH handshake on the allowed host
(`Permission denied (publickey)` after host-key exchange) and `403` on the
denied one, with no nono changes at all. This change turns that hand-rolled
recipe into a supported, port-exact flag.

Naming `allow_domain` the fix is not an option: honouring ports there would
silently narrow every profile that already carries a `host:port` entry and has
been running host-wide.

## What Changes

- Add `network.allow_ssh` (profile) and `--allow-ssh` (CLI), taking
  `[user@]host[:port]` with port defaulting to 22 and the `user@` part accepted
  and ignored, so a copy-pasted SSH target works verbatim.
- Entries are **port-exact**: `--allow-ssh build.example.com` permits
  `build.example.com:22` and denies `build.example.com:443`, unlike
  `allow_domain`. Wildcard hosts are rejected — a flag that says "just this
  server" must not accept `*.example.com`.
- `allow_ssh` activates proxy mode on its own, so the seccomp-notify
  destination pin engages and direct TCP from the sandbox fails with `EACCES`.
  A profile needs no other network key to get a working, contained SSH path.
- Add a hidden `nono ssh-tunnel <host> <port>` subcommand: an HTTP `CONNECT`
  client for use as an OpenSSH `ProxyCommand`, so the feature does not depend
  on which `netcat` variant happens to be installed.
- Materialise a generated OpenSSH config that sets that `ProxyCommand`, grant
  the sandbox read access to it, and point `GIT_SSH_COMMAND` at it so
  `git clone ssh://…` works unmodified. Bare `ssh` picks it up through a
  PATH-injected wrapper.
- The wrapper and the generated config are **ergonomics, not enforcement**.
  Invoking `/usr/bin/ssh` directly bypasses them and fails closed with
  `EACCES`, because the kernel pin is what contains the process.
- Reject `--allow-ssh` when proxy enforcement cannot be kernel-backed
  (`linux.sandbox_policy` of `landlock` or `external`, or WSL2 without
  `wsl2_proxy_policy: "insecure_proxy"`), rather than granting an unenforced
  allowance.
- Surface `allow_ssh` in `nono profile show`, `nono profile diff`, the profile
  JSON output, and `nono why`.
- No change to `allow_domain`, `connect_port`, or any existing key. Nothing
  that works today stops working.

**Not in scope**: SSH key and agent policy. Granting a dedicated key is already
expressible with `filesystem.read_file`, and forwarding `$SSH_AUTH_SOCK` with
`credentials`/`filesystem.unix_socket` is already demonstrated by
`tool-sandbox-examples/git-ssh/`. This change documents the recommended
combination but adds no new mechanism for it.

## Capabilities

### New Capabilities

- `network/ssh-egress`: pinning a sandboxed process's SSH reachability to an
  explicit set of `host:port` endpoints, the port-exactness guarantee that
  distinguishes it from `allow_domain`, the fail-closed behaviour when the pin
  cannot be kernel-enforced, and the `ProxyCommand` plumbing that makes `ssh`
  and `git` use it.

### Modified Capabilities

<!-- None. openspec/specs/ is empty, so the capability above is new. -->

## Impact

- `crates/nono-cli/src/profile/mod.rs`: `NetworkConfig` gains `allow_ssh`;
  `merge_profiles` appends and dedups it; new validation rejects wildcards,
  empty hosts, and port 0.
- `crates/nono-cli/src/cli.rs`: `--allow-ssh` on `SandboxArgs`, `ProxyArgs`,
  and `WrapSandboxArgs`, plus the `--config` conflict list.
- `crates/nono-cli/src/proxy_runtime.rs`: `allow_ssh` joins the proxy
  activation condition and contributes port-exact entries to
  `ProxyConfig.allowed_hosts` without passing through `expand_proxy_allow`.
- `crates/nono-cli/src/sandbox_prepare.rs`, `profile_runtime.rs`: the new field
  threads through `PreparedProfileSettings` and `ProfilePreflight`.
- `crates/nono-cli/src/execution_runtime.rs`: the unenforceable-policy guard.
- New `nono ssh-tunnel` subcommand and the generated-config/PATH-wrapper
  materialisation, modelled on how the TLS-interception CA is already written
  out and granted.
- `crates/nono-cli/data/nono-profile.schema.json` and
  `crates/nono-cli/tests/schema_shape.rs`: schema entry and its pinned shape.
- Docs: `docs/cli/features/tool-sandbox.mdx:637-651` currently states that a
  raw TCP/22 rule requires Landlock and is not host-filtered; that guidance is
  replaced.
- No new dependencies. No breaking change.
