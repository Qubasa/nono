## Purpose

SSH egress pinning lets a profile name the exact `host:port` endpoints a
sandboxed process may reach over SSH, guarantees that reachability is enforced
by the kernel rather than by client cooperation, and makes `ssh` and `git` use
that path without the operator hand-rolling proxy plumbing.

## ADDED Requirements

### Requirement: An SSH allowance names one endpoint and is port-exact

An SSH allowance MUST be expressed as `[user@]host[:port]`, where the port
defaults to 22 and any `user@` prefix is accepted and ignored, so an SSH target
copied from a shell command can be pasted verbatim. The allowance MUST permit
that host on that port only.

Unlike a domain allowance, an SSH allowance MUST NOT widen to other ports on
the same host, and MUST NOT emit the "port is ignored" warning that domain
allowances emit, because the port is not ignored.

#### Scenario: Default port

- **WHEN** a profile allows SSH to `build.example.com`
- **THEN** a TCP session to `build.example.com` port 22 is established, and a
  session to `build.example.com` port 443 is refused

#### Scenario: Explicit non-default port

- **WHEN** a profile allows SSH to `build.example.com:2222`
- **THEN** a session to port 2222 is established, and a session to port 22 on
  the same host is refused

#### Scenario: SSH target pasted with a user prefix

- **WHEN** a profile allows SSH to `deploy@build.example.com:2222`
- **THEN** the allowance is equivalent to `build.example.com:2222`, and the
  user name has no effect on which endpoints are reachable

#### Scenario: A second host is not reachable

- **WHEN** a profile allows SSH to `build.example.com` only
- **THEN** a session to any other host on port 22 is refused with a message
  naming the host and stating it is not in the allowlist

#### Scenario: No port-ignored warning

- **WHEN** a profile allows SSH to `build.example.com:2222`
- **THEN** no warning claiming that the port suffix is ignored is printed

### Requirement: Wildcard and malformed SSH endpoints are rejected at load time

An SSH allowance MUST name a single concrete host. A wildcard pattern, an empty
host, a port of 0, or a port outside 1-65535 MUST be rejected when the profile
or command line is loaded, before the sandbox starts, with an error naming the
offending entry.

#### Scenario: Wildcard host

- **WHEN** a profile allows SSH to `*.example.com`
- **THEN** loading fails with an error stating that SSH allowances must name a
  single host, and no sandbox is started

#### Scenario: Port zero

- **WHEN** a profile allows SSH to `build.example.com:0`
- **THEN** loading fails with an error naming the entry, and no sandbox is
  started

#### Scenario: Cloud metadata endpoint

- **WHEN** a profile allows SSH to a cloud metadata address such as
  `169.254.169.254`
- **THEN** the endpoint is refused, consistent with the non-overridable
  metadata denial that applies to every other egress path

### Requirement: SSH reachability is enforced below the client

An SSH allowance MUST be enforced such that a process in the sandbox cannot
reach any other endpoint by ignoring, unsetting, or overriding the configuration
that routes SSH traffic. Opening a socket directly to a non-allowed endpoint
MUST fail at the operating-system level.

#### Scenario: Direct socket to a non-allowed host

- **WHEN** a sandboxed process opens a TCP socket straight to a host that no
  allowance covers
- **THEN** the connection attempt fails with a permission error from the
  operating system, not from a client library

#### Scenario: Direct socket to the allowed host, bypassing the SSH path

- **WHEN** a sandboxed process opens a TCP socket straight to the allowed host
  and port without going through the mediated path
- **THEN** the connection attempt fails with a permission error, because the
  allowance grants a mediated route rather than raw reachability

#### Scenario: Proxy environment variables removed

- **WHEN** a sandboxed process clears every proxy-related environment variable
  and then attempts any outbound connection other than the mediated route
- **THEN** the attempt fails with a permission error

### Requirement: An SSH allowance is sufficient on its own

A profile or command line whose only network setting is an SSH allowance MUST
produce a working, contained SSH path: the mediated route is started, the
allowlist is active, and every endpoint outside the allowance is refused. No
additional network key SHALL be required, and the absence of other keys MUST
NOT be interpreted as "allow everything".

#### Scenario: SSH allowance as the only network setting

- **WHEN** a profile sets an SSH allowance and no other network key
- **THEN** SSH to the allowed endpoint succeeds and all other egress is refused

#### Scenario: Combined with a domain allowance

- **WHEN** a profile sets both an SSH allowance and a domain allowance
- **THEN** both are in effect, the domain allowance keeps its existing
  host-level behavior, and the SSH allowance stays port-exact

### Requirement: An SSH allowance that cannot be kernel-enforced is refused

When the platform or the configured sandbox policy cannot enforce the
destination pin in the kernel, an SSH allowance MUST fail at startup with an
error that names the reason and the setting responsible. Running with an
unenforced SSH allowance is not permitted unless the operator has already opted
into the documented degraded mode for proxy enforcement.

#### Scenario: Sandbox policy delegates network enforcement

- **WHEN** a profile sets an SSH allowance and also selects a sandbox policy
  that disables nono's own outbound enforcement
- **THEN** startup fails with an error naming both settings, rather than
  starting with an unenforced allowance

#### Scenario: Platform cannot enforce the destination pin

- **WHEN** an SSH allowance is used on a platform where the destination pin
  cannot be installed
- **THEN** startup fails with an error explaining that the process would be
  able to open arbitrary outbound connections, and pointing at the documented
  opt-in for degraded proxy mode

#### Scenario: Explicit degraded opt-in already present

- **WHEN** the operator has already opted into degraded proxy enforcement for
  that platform
- **THEN** the SSH allowance behaves as the existing degraded proxy mode does,
  including its warning, and does not introduce a second, quieter opt-out

### Requirement: An SSH allowance contradicts a full network block

An SSH allowance and a setting that blocks all network access MUST NOT be
accepted together. The combination MUST be reported as a configuration error
naming both settings, rather than silently resolving in favour of either.

#### Scenario: Block plus SSH allowance

- **WHEN** a command line or profile both blocks the network and allows SSH to
  a host
- **THEN** startup fails with an error naming both settings

### Requirement: SSH and Git use the allowed endpoint without manual configuration

When an SSH allowance is in effect, invoking `ssh` or a Git operation over SSH
from inside the sandbox MUST reach an allowed endpoint without the user editing
any SSH configuration file or passing extra options.

Reaching a non-allowed endpoint this way MUST fail with a message that names the
host and says it is not allowed, so the failure is attributable to policy rather
than to name resolution or connectivity.

#### Scenario: Plain ssh invocation

- **WHEN** a sandboxed process runs `ssh deploy@build.example.com` and
  `build.example.com` is allowed
- **THEN** the SSH protocol handshake with that server completes, and
  authentication proceeds according to the identities the sandbox grants

#### Scenario: Git clone over SSH

- **WHEN** a sandboxed process clones a repository over SSH from an allowed host
- **THEN** the clone proceeds, using the same mediated route

#### Scenario: ssh to a non-allowed host

- **WHEN** a sandboxed process runs `ssh` against a host no allowance covers
- **THEN** the command fails with a message naming that host as not allowed

#### Scenario: Name resolution is not required inside the sandbox

- **WHEN** the sandbox has no ability to perform DNS itself
- **THEN** an allowed host given by name still resolves and connects, because
  resolution happens outside the sandbox on the mediated route

### Requirement: SSH allowances are visible in policy output and merge predictably

Configured SSH allowances MUST appear in the commands that report effective
policy, in profile comparison output, and in machine-readable profile output.
When one profile extends another, SSH allowances MUST combine by appending and
de-duplicating, matching how other network list settings combine.

#### Scenario: Effective policy display

- **WHEN** a user inspects the effective profile
- **THEN** the configured SSH endpoints are listed

#### Scenario: Explaining a blocked host

- **WHEN** a user asks why a host is unreachable and that host is covered by an
  SSH allowance on a different port
- **THEN** the answer distinguishes the allowed endpoint from the requested one

#### Scenario: Profile inheritance

- **WHEN** a child profile extends a base profile and both declare SSH
  allowances
- **THEN** the effective profile contains both sets with duplicates removed

### Requirement: An SSH endpoint must not be configured to bypass the mediated route

A configuration that both allows an SSH endpoint and marks the same host for
direct, unmediated access MUST be rejected at load time, because the two
settings together would hand the sandbox a route the allowlist does not police.

#### Scenario: Host appears in both the SSH allowance and the bypass list

- **WHEN** a profile allows SSH to a host and also lists that host as a proxy
  bypass
- **THEN** loading fails with an error naming both entries
