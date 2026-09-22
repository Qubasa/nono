## MODIFIED Requirements

### Requirement: SSH reachability is enforced below the client

An SSH allowance MUST be enforced such that a process in the sandbox cannot
reach any other endpoint by ignoring, unsetting, or overriding the configuration
that routes SSH traffic. Opening a socket directly to a non-allowed endpoint
MUST fail at the operating-system level.

The allowance MUST NOT make the endpoint reachable as raw TCP by any route. The
only path to the endpoint is the mediated SSH session, and the endpoint's SSH
port MUST be refused to the sandbox even on the allowed host.

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

#### Scenario: Tunnelled socket to the allowed host

- **WHEN** a sandboxed process asks the proxy to tunnel a raw connection to the
  allowed host and port
- **THEN** the request is refused, because the allowance no longer places the
  endpoint in the proxy allowlist

#### Scenario: Proxy environment variables removed

- **WHEN** a sandboxed process clears every proxy-related environment variable
  and then attempts any outbound connection other than the mediated route
- **THEN** the attempt fails with a permission error

### Requirement: SSH and Git use the allowed endpoint without manual configuration

When an SSH allowance is in effect, invoking `ssh` or a Git operation over SSH
from inside the sandbox MUST reach an allowed endpoint without the user editing
any SSH configuration file or passing extra options. Authentication MUST succeed
without the sandbox holding a credential.

Reaching a non-allowed endpoint this way MUST fail with a message that names the
host and says it is not allowed, so the failure is attributable to policy rather
than to name resolution or connectivity.

#### Scenario: Plain ssh invocation

- **WHEN** a sandboxed process runs `ssh deploy@build.example.com` and
  `build.example.com` is allowed
- **THEN** the SSH protocol handshake completes, authentication is performed by
  nono outside the sandbox, and the remote session starts

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

#### Scenario: No credential grant is required

- **WHEN** an SSH allowance is in effect and the sandbox has no grant for an
  agent socket or a private key file
- **THEN** SSH to the allowed endpoint still authenticates

### Requirement: An SSH allowance is sufficient on its own

A profile or command line whose only network setting is an SSH allowance MUST
produce a working, contained SSH path: the mediated route is started, the port
named by the allowance is closed on every host the allowance does not name, and
the allowance never widens what the session can reach.

An SSH allowance MUST NOT narrow egress that is unrelated to the ports it names:
on a policy that allows all destinations, an SSH allowance MUST leave every
other port as reachable as it was.

#### Scenario: SSH allowance as the only network setting

- **WHEN** a profile sets an SSH allowance and no other network key
- **THEN** SSH to the allowed endpoint succeeds, and SSH to any other host on
  that port is refused

#### Scenario: Unrelated egress is unaffected

- **WHEN** a profile sets an SSH allowance and no other network key
- **THEN** destinations on other ports remain reachable, because the allowance
  pins a port rather than replacing the policy

#### Scenario: Combined with a domain allowance

- **WHEN** a profile sets both an SSH allowance and a domain allowance
- **THEN** both are in effect, the domain allowance keeps its existing
  host-level behavior, and the SSH allowance stays port-exact

## REMOVED Requirements

### Requirement: A raw tunnelling subcommand provides the SSH route

**Reason**: The route is now a mediated SSH session. A subcommand that turns an
allowed authority into a byte-transparent stream is exactly the capability this
change removes: it cannot distinguish `git fetch` from an interactive shell or a
port forward, and it is reachable by anything in the sandbox that can execute
the nono binary.

**Migration**: None required for users. The subcommand is hidden and is only
referenced by the SSH configuration nono generates, which is regenerated to
point at the mediated route. A caller invoking it directly now receives an
unknown-subcommand error.
