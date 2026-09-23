## MODIFIED Requirements

### Requirement: An SSH allowance names one endpoint and is port-exact

An SSH allowance MUST be expressed as `[user@]host[:port]`, where the port
defaults to 22, so an SSH target copied from a shell command can be pasted
verbatim. The allowance MUST permit that host on that port only.

The `user@` prefix MUST name the remote identity the allowance permits, and the
mediation MUST authenticate as exactly that identity. A sandboxed client asking
for a remote user that no allowance names on that endpoint MUST be refused
before anything is dialled, with a message naming the requested user and the
identities that are allowed there; the mediation MUST NOT substitute another
user. The user the client authenticates as on the sandbox-facing leg MUST be
the one it asked for. An allowance that names no user MUST stand for the user
nono itself runs as, matching what a bare `ssh host` would send.

Several allowances MAY name the same endpoint for different users, and each
MUST keep its own command policy. Two allowances resolving to the same user on
the same endpoint MUST be refused at load or startup.

An allowance MAY instead be written as an object naming the same endpoint plus
the exact commands that endpoint may run. Both forms MUST be accepted in the
same list, and the endpoint MUST be interpreted identically in either form.

Unlike a domain allowance, an SSH allowance MUST NOT widen to other ports on
the same host, and MUST NOT emit the "port is ignored" warning that domain
allowances emit, because the port is not ignored.

#### Scenario: Default port

- **WHEN** a profile allows SSH to `build.example.com`
- **THEN** a session to `build.example.com` port 22 is established, and a
  session to `build.example.com` port 443 is refused

#### Scenario: Explicit non-default port

- **WHEN** a profile allows SSH to `build.example.com:2222`
- **THEN** a session to port 2222 is established, and a session to port 22 on
  the same host is refused

#### Scenario: The allowance names the remote user

- **WHEN** a profile allows SSH to `deploy@build.example.com:2222`
- **THEN** the session on that endpoint authenticates as `deploy`

#### Scenario: The client asks for a different user

- **WHEN** a profile allows SSH to `deploy@build.example.com` and a sandboxed
  process runs `ssh root@build.example.com`
- **THEN** the session is refused with a message naming `root` as not allowed
  and `deploy@build.example.com:22` as the allowed identity, and no outbound
  connection is made

#### Scenario: Two users on one endpoint

- **WHEN** a profile allows SSH to `deploy@build.example.com` and to
  `git@build.example.com` restricted to `git-upload-pack /srv/repo.git`
- **THEN** `ssh deploy@build.example.com` runs with the default session
  policy, `ssh git@build.example.com` runs only the named command, and any
  other user is refused

#### Scenario: Allowance without a user

- **WHEN** a profile allows SSH to `build.example.com` with no user prefix
- **THEN** a session as the user nono runs as authenticates as that user, and a
  session asking for any other user is refused

#### Scenario: SSH target pasted with a user prefix

- **WHEN** a profile allows SSH to `deploy@build.example.com:2222`
- **THEN** the entry parses and pins `build.example.com:2222`, and the user
  prefix now selects the remote identity instead of being discarded

#### Scenario: A second host is not reachable

- **WHEN** a profile allows SSH to `build.example.com` only
- **THEN** a session to any other host on port 22 is refused with a message
  naming the host and stating it is not allowed

#### Scenario: No port-ignored warning

- **WHEN** a profile allows SSH to `build.example.com:2222`
- **THEN** no warning claiming that the port suffix is ignored is printed

#### Scenario: Object form with commands

- **WHEN** a profile allows SSH with an object naming `build.example.com` and a
  list of commands
- **THEN** the endpoint is reachable exactly as the string form would make it,
  and only the named commands may run

#### Scenario: Both forms in one list

- **WHEN** a profile's SSH allowances mix string entries and object entries
- **THEN** the profile loads and each entry keeps its own behavior

#### Scenario: Object form with an empty command list

- **WHEN** an object entry names an endpoint and an empty command list
- **THEN** loading fails with an error naming the entry, because an empty list
  would otherwise read as either "no restriction" or "nothing may run"

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
