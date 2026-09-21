## Context

See `proposal.md` — Why. The relevant existing machinery, all verified against
nono 0.78.0 on a Landlock V6 kernel:

| Layer | Where | Granularity |
| --- | --- | --- |
| Landlock `AccessNet` | `crates/nono/src/sandbox/linux.rs:1200-1210` | TCP port, **no address** |
| Static seccomp on `socket()` | `linux.rs:2090-2250` (`TcpOnly`) | family/type/proto; kills UDP, so no in-sandbox DNS |
| seccomp-notify supervisor | `exec_strategy/supervisor_linux.rs:813` | `is_loopback && port == proxy_port` |
| nono-proxy host filter | `nono-proxy/src/filter.rs:128-153` | host, wildcard, **and `host:port`** |

Three facts shape the whole design:

1. The destination pin already exists and is already mandatory in proxy mode.
   `execution_runtime.rs:660-664` installs the supervisor whenever
   `NetworkMode::ProxyOnly` is set, with the comment that Landlock "filters by
   port only, never by destination address ... or the proxy's host allowlist is
   bypassable". So anything routed through the proxy is already contained.
2. `ProxyFilter::check_host_result` already tries the allowlist twice: bare
   host, then `host:port` (`filter.rs:147-152`). Port-exact entries are a
   supported input today; credential-route upstreams already use them
   (`proxy_runtime.rs:2442-2452`). The port only disappears because
   `expand_proxy_allow` strips it (`network_policy.rs:398-404`).
3. `handle_connect` relays bytes opaquely and accepts any port
   (`connect.rs:180-198`), so SSH-over-CONNECT needs no proxy changes at all.
   A probe run confirmed a full SSH handshake through it.

The gap is therefore *plumbing plus a client-side entry point*, not a new
enforcement mechanism.

Constraint that rules out the obvious shortcut: `network.block` is
`deny_unknown_fields`-strict and `allow_domain`'s port-stripping is
load-bearing. Several shipped profiles carry `host:port` entries in
`allow_domain` and currently get host-wide access; honouring the port there
would silently narrow them. A separate field is the only non-breaking route.

## Goals / Non-Goals

**Goals:**

- One flag that yields a port-exact, kernel-enforced SSH path.
- Zero change to the semantics of `allow_domain`, `connect_port`, `open_port`.
- `ssh` and `git` work unmodified inside the sandbox; the bypass failure mode is
  denial, never silent widening.
- Fail closed and loudly wherever the pin cannot be kernel-backed.

**Non-Goals:**

- A general raw-TCP host allowlist. That needs the seccomp-notify supervisor to
  retain destination IPs (`SockaddrInfo` currently discards them,
  `linux.rs:2774-2787`) and is a separate, larger change. Recorded in
  `Alternatives` below.
- SSH key or agent policy. Already expressible; see proposal scope note.
- Inspecting or constraining what flows *inside* the SSH session.
- Making the PATH wrapper tamper-proof. It is ergonomics; the kernel is the
  boundary.

## Decisions

### D1: A new `network.allow_ssh` field, not a change to `allow_domain`

Port-exactness is the whole point of the feature and the opposite of
`allow_domain`'s documented behaviour. Reusing `allow_domain` means either
breaking existing profiles or shipping a flag whose port is a lie.

A separate field is also strictly less invasive: `expand_proxy_allow` is
consumed by four call sites (`partition_allow_domain`, `why_runtime.rs:49`,
`why_runtime.rs:78`, `execution_runtime.rs:292`). Entries that skip it leave all
four untouched.

*Alternative rejected*: an `AllowDomainEntry::WithPort` variant. It puts two
contradictory port semantics inside one field, and every consumer would have to
branch on which kind it got.

### D2: Port-exact entries are appended to `plain_hosts` after partitioning

`build_proxy_config_from_flags` calls `partition_allow_domain`
(`proxy_runtime.rs:2392-2398`), which is where the strip happens. SSH entries
are formatted as `host:port` and appended to `plain_hosts` *after* that call,
exactly as credential upstreams already are (`proxy_runtime.rs:2442-2452`) —
minus the bare-host fallback those add, since that fallback is precisely what
would defeat port-exactness.

They must also be counted in `host_allowlist_active`
(`proxy_runtime.rs:2412-2417`), or an SSH-only run leaves the allowlist empty,
which `ProxyFilter` reads as allow-all (#1485).

The carrier is a new field on `DomainFilterIntent` (`launch_runtime.rs:79-89`)
rather than a smuggled string in `allow_domain`, so the "do not expand this"
property is visible in the type.

### D3: `allow_ssh` activates proxy mode by itself

Three gates currently decide whether a proxy starts, and an SSH-only
configuration fails all three:

- `SandboxArgs::has_proxy_flags` (`cli.rs:1417-1423`)
- `has_proxy_intent` (`sandbox_prepare.rs:871-875`)
- `has_domain_filter` / `would_activate` (`proxy_runtime.rs:1475-1478`), plus
  the `domain_filter` construction gate at `1505-1512`

All four get the new field OR'd in. Without the fourth, `DomainFilterIntent`
is `None` and the allowlist never reaches the proxy even though it started.

### D4: A hidden `nono ssh-tunnel <host> <port>` subcommand as `ProxyCommand`

`ssh` speaks no HTTP, so it needs a helper that performs the `CONNECT`
handshake and then splices stdio. The options were `nc -X connect` (works —
that is what the probe used — but `-X` is OpenBSD-netcat-only, absent from
GNU netcat and from most containers), `socat` (rarely installed), or nono
itself.

nono itself wins: the binary is necessarily present, and the CONNECT client
already exists as `nono_proxy::external::connect_via_proxy`
(`nono-proxy/src/external.rs:34`) — public, already a dependency of nono-cli,
already handling `Proxy-Authorization` and non-200 status. The subcommand
reads the proxy address from `HTTPS_PROXY` and the token from
`NONO_PROXY_TOKEN`, both already injected (`nono-proxy/src/server.rs:541`),
then `copy_bidirectional` between the tunnel and stdin/stdout.

It follows the existing hidden-helper pattern: a `#[command(hide = true)]`
variant on `Commands` (`cli.rs:664-670` has two precedents, `OpenUrlHelper` and
`PackUpdateHintHelper`) dispatched from `app_runtime.rs:145-146`, which
deliberately bypasses the update-check wrapper. The hidden-subcommand
completeness test already skips `is_hide_set()` entries (`cli.rs:4486`), so no
test-list edit is needed.

Module name: `ssh_tunnel.rs`. Not `connect_client.rs` — that name is taken by
the nono-console remote-attach client.

### D5: A generated SSH config plus a PATH wrapper, modelled on the TLS CA bundle

`ssh` has no environment variable for `ProxyCommand`, so the setting has to
reach it as a file. The precedent is exact: the TLS-interception trust bundle is
written to a session-scoped 0o700 directory (`prepare_intercept_ca_dir`,
`proxy_runtime.rs:3236`), created 0o400 with `create_new`
(`tls_intercept/bundle.rs:144`), granted with
`CapabilitySet::allow_file_mut(path, AccessMode::Read)`
(`capability.rs:1052`), advertised through env vars, and removed in
`impl Drop for ProxyHandle` (`server.rs:669`) forced by an explicit `drop`
(`execution_runtime.rs:810`). The SSH config follows the same lifecycle.

Contents:

```
Host *
  ProxyCommand <nono> ssh-tunnel %h %p
```

`Host *` is correct, not sloppy: a non-allowed host then fails with the proxy's
`403 ... is not in the allowlist` — the attributable error the spec requires —
instead of a confusing `EACCES` from a direct connect.

Reaching the two clients:

- **git**: `GIT_SSH_COMMAND="ssh -F <generated>"`, appended to
  `ActiveProxyRuntime.env_vars` in `start_proxy_runtime`
  (`proxy_runtime.rs:2944`), which is the same vector the CA vars use.
- **bare ssh**: a wrapper named `ssh` in a 0o500 session directory prepended to
  `PATH`. Precedent for both the materialisation and the PATH prepend is the
  tool-sandbox shim dir (`create_shim_dir` / `build_session_path`,
  `tool-sandbox/platform/linux.rs:3009` / `:2604`) and the browser shim PATH
  prepend (`exec_strategy.rs:732-741`). Tool-sandbox's own shim machinery is
  *not* reused: it is hard-gated on a non-empty `commands` policy
  (`is_active()`), and `--allow-ssh` must work without opting into command
  policy.

An injected env var always beats the inherited one —
`env_var_survives_filters` (`env_sanitization.rs:301`) drops any inherited var
already present in `config.env_vars` — so a host `GIT_SSH_COMMAND` cannot
shadow this.

*Explicitly accepted*: `/usr/bin/ssh` invoked by absolute path skips the
wrapper and fails with `EACCES`. That is the correct failure direction, and
making it impossible would require the tool-sandbox shim machinery this design
deliberately avoids.

### D6: Fail closed when the pin cannot be kernel-backed

`seccomp_proxy_fallback` (`execution_runtime.rs:619-668`) already has three
holes where proxy mode runs unenforced: `LinuxSandboxPolicy::Landlock`,
`LinuxSandboxPolicy::External`, and WSL2 with
`wsl2_proxy_policy: "insecure_proxy"`. Today those holes are opt-in and
documented for `allow_domain`.

A flag whose entire promise is "only this server" must not inherit them
silently. `allow_ssh` therefore errors on the first two, and on WSL2 defers to
the existing `wsl2_proxy_policy` — including its warning — rather than adding a
second, quieter opt-out. Same reasoning as the existing WSL2 error at
`execution_runtime.rs:638-648`.

### D7: Validation is load-time and reuses the existing host matcher

- Wildcards rejected. `nono::net_filter::validate_host_pattern` accepts `*.` and
  whole-label wildcards, which is right for `allow_domain` and wrong here, so
  the SSH validator runs the same matcher and then additionally rejects any
  entry containing `*`.
- Port must parse and be 1-65535.
- IPv6 literals must be bracketed to disambiguate the port separator, matching
  `check_host_result`'s own bracketing (`filter.rs:134-138`).
- Metadata and link-local addresses need no new code: `DENY_HOSTS`
  (`net_filter.rs:212-216`) and `proxy_metadata_filter_result`
  (`filter.rs:162-171`) are non-overridable and run before the allowlist.
- `no_proxy` overlap is rejected, extending
  `validate_no_proxy_allow_domain_conflicts` (`profile/mod.rs:1337`) and
  `validate_expanded_proxy_no_proxy_conflicts` (`proxy_runtime.rs:2718`). An SSH
  host in `no_proxy` would make the ProxyCommand bypass the very allowlist that
  authorises it.
- `--block-net` + `--allow-ssh` rejected, mirroring the existing
  `--block-net` + `--allow-domain` rejection (`sandbox_prepare.rs:939-940`).

### D8: `nono proxy` parity

`proxy_command.rs:199-280` is an independent second copy of the profile→proxy
merge. It gets the same treatment, because a standalone proxy that silently
ignored `allow_ssh` would be a trap.

## Alternatives considered

**Kernel destination allowlist (raw TCP).** Teach `SockaddrInfo` to keep the
destination IP (`linux.rs:2774-2787` parses and discards it), add a
`Vec<(IpAddr, u16)>` to `SupervisorConfig` (`exec_strategy.rs:377-385`), extend
`decide_network_notification` (`supervisor_linux.rs:813`), and install the
notify fd outside ProxyOnly (`exec_strategy.rs:248-250`).

Rejected for this change: Linux-only, and the DNS consequence is fatal to the
UX. The `TcpOnly` static filter denies UDP sockets whenever any restriction is
active (`linux.rs:2090-2250`), so the sandbox cannot resolve names; the host
would have to be an IP literal or an `/etc/hosts` entry, and pinned IPs go stale
when the server's address rotates. It also touches the most security-sensitive
function in the tree. The proxy path gets name resolution outside the sandbox
and resolved-IP pinning (`filter.rs:94-104`, `connect.rs:100-117`) for free.

Worth revisiting as a defence-in-depth layer *under* this design once the
supervisor keeps destination IPs; the two compose.

**Local TCP forwarder per endpoint.** nono listens on `127.0.0.1:<n>` and
forwards to the pinned server, so `ssh -p <n> 127.0.0.1` works. Rejected:
still requires rewriting the user's command, breaks host-key checking and
`known_hosts`, and needs one listener per endpoint.

## Risks / Trade-offs

- **The CONNECT tunnel is opaque; nothing verifies the bytes are SSH.** →
  Accepted and documented. The requirement is endpoint containment, and an SSH
  session to a server the user controls is already a full bidirectional channel.
  Port-exactness plus the host pin is the stated contract, not protocol
  validation.
- **PATH wrapper is bypassable by absolute path.** → Fail-closed by
  construction: bypassing it yields `EACCES`, never wider access. Documented as
  ergonomics, not enforcement.
- **`Host *` in the generated config routes every SSH target at the tunnel.** →
  Intended. Non-allowed hosts get an attributable `403` instead of a bare
  `EACCES`. The allowlist, not the config, decides.
- **17 exhaustive struct literals must be updated before anything compiles**
  (`PreparedSandbox` ×8, `EffectiveProxySettings` ×2, `DomainFilterIntent` ×2,
  `NetworkConfig` test literals ×2, `PreparedProfile` construction and
  destructuring, `From<WrapSandboxArgs>`). → Mechanical; `tasks.md` lists each
  with its line number. None derive `Default`, so the compiler finds any miss.
- **A second field that also configures host egress invites confusion with
  `allow_domain`.** → Mitigated by the error text, the docs table, and by
  `allow_ssh` refusing wildcards: the two are hard to confuse in use because one
  rejects what the other accepts.
- **`nono wrap` has no proxy support.** → `--allow-ssh` must be rejected there
  rather than accepted and ignored; `From<WrapSandboxArgs>` sets it empty
  (`cli.rs:1861` is the analogous `allow_proxy: Vec::new()`).
- **Generated config and wrapper leak on a hard kill.** → Same exposure as the
  existing CA bundle, and the same mitigation: session-scoped 0o700 directory,
  `Drop`-based removal, contents non-secret (a path and a port; the token stays
  in the environment).

## Migration Plan

Additive. No existing key changes meaning, no profile needs editing, and the
JSON schema gains one optional property. Rollback is removing the field; nothing
persists it outside profiles the user wrote.

The documentation claim at `docs/cli/features/tool-sandbox.mdx:637-651` ("a raw
TCP/22 rule currently requires Linux Landlock") becomes wrong on merge and is
replaced in the same change.
