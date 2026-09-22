## Purpose

SSH session mediation puts nono between a sandboxed SSH client and the remote
endpoint: nono terminates the client's SSH session, authorizes it one channel
request at a time, holds the authenticating credential outside the sandbox, and
verifies the remote host key on the sandbox's behalf, so an SSH allowance grants
a task rather than a shell.

## ADDED Requirements

### Requirement: SSH sessions are terminated and relayed by nono

When an SSH allowance is in effect, an SSH session started inside the sandbox
MUST terminate at nono, and nono MUST establish a separate SSH session to the
allowed endpoint. The two sessions MUST be distinct: the sandbox MUST NOT
receive a byte-transparent tunnel to the endpoint, and the endpoint MUST NOT
receive the sandbox's session keys.

The mediation point MUST live outside the sandbox, so that no process subject to
the sandbox policy can read the credential, the remote host key store, or the
plaintext of another session.

#### Scenario: A normal command still runs

- **WHEN** a sandboxed process runs a remote command over SSH against an allowed
  endpoint
- **THEN** the command runs on the remote host, its standard output and standard
  error reach the sandboxed process on their own streams, and its exit status is
  reported as the local command's exit status

#### Scenario: Interactive session

- **WHEN** a sandboxed process starts an interactive SSH session against an
  allowed endpoint from a terminal
- **THEN** a pseudo-terminal is allocated on the remote host, terminal resizes
  are carried through for the life of the session, and the session ends when
  either side closes

#### Scenario: Raw tunnel is not available

- **WHEN** a sandboxed process attempts a raw TCP connection to the allowed
  endpoint's SSH port by any route, including the proxy's tunnelling verb
- **THEN** the attempt is refused, because the allowance grants a mediated
  session and not reachability

### Requirement: Only session channels are authorized

Mediation MUST authorize each channel and each channel request individually. A
`session` channel MUST be permitted, and within it the requests that run work on
the remote host - starting a shell, executing a command, requesting a
pseudo-terminal, reporting a terminal resize, and starting a named subsystem -
MUST be permitted, unless the allowance for that endpoint restricts the commands
it may run, in which case the narrower rules of that requirement apply.

Every request that turns the session into a transport MUST be refused: opening a
forwarded connection to a third address, asking the remote host to listen on a
port, forwarding the authentication agent, and forwarding X11. A refusal MUST
name the request type, MUST be reported to the sandboxed client as a failed
channel request rather than as a broken connection, and MUST NOT terminate an
already-running session.

An unrecognised channel type or channel request MUST be refused rather than
passed through.

#### Scenario: Local port forward

- **WHEN** a sandboxed process asks for a local port forward over an allowed
  endpoint
- **THEN** the forward is refused with a message naming port forwarding, and any
  command or shell in the same session keeps running

#### Scenario: Remote port forward

- **WHEN** a sandboxed process asks the remote host to listen on a port
- **THEN** the request is refused with a message naming remote forwarding

#### Scenario: Onward hop

- **WHEN** a sandboxed process uses the allowed endpoint as a jump host to reach
  a second host
- **THEN** the attempt is refused, because reaching the second host requires a
  forwarded connection

#### Scenario: Agent forwarding

- **WHEN** a sandboxed process requests agent forwarding
- **THEN** the request is refused, and the session continues without an agent on
  the remote side

#### Scenario: File transfer keeps working

- **WHEN** a sandboxed process copies a file to or from an allowed endpoint
  using a file-transfer tool built on SSH
- **THEN** the transfer completes, because it is a subsystem or a remote command
  inside a session channel

#### Scenario: Unknown request type

- **WHEN** a client sends a channel request nono does not recognise
- **THEN** the request is refused rather than forwarded to the remote host

### Requirement: An allowance may restrict which remote commands run

An SSH allowance MAY name the exact commands its endpoint may run. When it
does, mediation MUST refuse every command the allowance does not name, and MUST
refuse every request that would let the session run work outside that list:
starting a shell, allocating a pseudo-terminal, and starting a subsystem. An
endpoint restricted this way is a task endpoint, not a login.

Matching MUST be exact on the command's argument vector after quote-aware
tokenisation, so that a rule naming one command cannot be satisfied by a
different command, by the same command with different arguments, or by
additional arguments.

Because the command string is interpreted by the remote host and not by nono, a
requested command that contains shell metacharacters - command separators,
pipes, redirections, command substitution, background operators, or newlines -
MUST be refused before matching is attempted, whether or not the allowance
would otherwise permit it.

A refusal MUST name the command that was refused and MUST be distinguishable
from the command failing on the remote host.

An allowance that names no commands MUST keep the default session behavior, so
adding the restriction is an opt-in narrowing and its absence never widens
anything.

#### Scenario: Allowed command

- **WHEN** an allowance names a command and a sandboxed process runs exactly
  that command against that endpoint
- **THEN** the command runs on the remote host and its output and exit status
  are returned

#### Scenario: Different command

- **WHEN** a sandboxed process runs a command the allowance does not name
- **THEN** the request is refused with the command named, no process is started
  on the remote host, and the refusal is not reported as a remote failure

#### Scenario: Same command, different arguments

- **WHEN** an allowance names a command with one argument and a sandboxed
  process runs the same command with a different or additional argument
- **THEN** the request is refused, because matching is exact on the whole
  argument vector

#### Scenario: Shell metacharacters

- **WHEN** a sandboxed process requests an allowed command with a command
  separator and a second command appended
- **THEN** the request is refused before matching, and neither command runs

#### Scenario: Interactive shell on a restricted endpoint

- **WHEN** a sandboxed process starts an interactive session against an endpoint
  whose allowance names commands
- **THEN** the session is refused, because a shell would run commands the
  allowance does not name

#### Scenario: Subsystem on a restricted endpoint

- **WHEN** a sandboxed process starts a file-transfer subsystem against an
  endpoint whose allowance names commands
- **THEN** the request is refused, because a file-transfer subsystem reads and
  writes outside the named commands

#### Scenario: Unrestricted endpoint is unaffected

- **WHEN** an allowance names no commands
- **THEN** commands, shells, pseudo-terminals and subsystems behave as the
  default session policy allows

#### Scenario: Restriction is recorded

- **WHEN** a command is refused by an allowance's command list
- **THEN** the audit trail records the endpoint, the requested command, and that
  the command list refused it

### Requirement: The authenticating credential stays outside the sandbox

nono MUST authenticate to the remote endpoint using a credential the sandbox
cannot reach: an authentication agent nono holds outside the sandbox, or a key
file nono reads itself before the sandbox starts.

The sandbox MUST NOT require a grant for the agent socket or the key file in
order for SSH to work. Key material MUST NOT be readable from inside the
sandbox, and nono MUST NOT itself place an agent socket there.

This bounds what nono hands over; it does not by itself bound what the sandbox
can already reach. Whether a sandboxed process can open the host's agent socket
on its own is decided by `AF_UNIX` mediation, not by this capability. When
`AF_UNIX` mediation is active, a sandboxed process MUST NOT be able to obtain a
signature for a host no allowance covers. When it is inactive - the default in
proxy-only mode - that guarantee does not hold, and documentation MUST say so
rather than claim containment the sandbox does not have.

When no usable credential is available, or the credential cannot be used without
interaction that is not possible at that point - an encrypted key file with no
passphrase source, a key type the mediation cannot use directly - startup MUST
fail with an error naming the credential and the reason. Failing mid-session
instead is not permitted.

#### Scenario: Agent-backed authentication

- **WHEN** an SSH allowance is used and the user has an authentication agent
- **THEN** SSH to the allowed endpoint authenticates, and nono places no agent
  socket inside the sandbox

#### Scenario: Signature for a non-allowed host

- **WHEN** a sandboxed process attempts to obtain a signature from the
  authentication agent for a host no allowance covers, and `AF_UNIX` mediation
  is active
- **THEN** it cannot reach the agent at all, so no signature is produced

#### Scenario: Agent reachable without AF_UNIX mediation

- **WHEN** an SSH allowance is in effect and `AF_UNIX` mediation is inactive
- **THEN** the mediated SSH route still works and still refuses non-allowed
  endpoints, and the documented behaviour states plainly that the host agent
  remains reachable by other means in that configuration

#### Scenario: Encrypted key file

- **WHEN** an SSH allowance names a key file that is encrypted and no passphrase
  source is available
- **THEN** startup fails with an error naming the key file and stating that it
  must be added to an agent, and no sandbox is started

#### Scenario: Key type the mediation cannot use

- **WHEN** an SSH allowance names a key file of a type the mediation cannot use
  directly, such as a hardware-backed key
- **THEN** startup fails with an error naming the key and directing the user to
  the agent, rather than starting and failing at connect time

### Requirement: Remote host keys are verified outside the sandbox

nono MUST verify the remote endpoint's host key against the user's known-hosts
store before relaying any session. An unknown host key MUST be refused: nono
MUST NOT trust a key on first use for a sandboxed session, and MUST NOT add an
entry to the user's store. A changed host key MUST be refused with an error that
names the endpoint and states that the key changed.

The client inside the sandbox MUST be given a known-hosts file naming only
nono's own per-session host key, and that key MUST be generated fresh for each
session, so that no process in the sandbox can make a trust decision about a
remote host or impersonate a later session.

#### Scenario: Known endpoint

- **WHEN** the allowed endpoint's host key is already in the user's known-hosts
  store
- **THEN** the session proceeds

#### Scenario: Unknown endpoint

- **WHEN** the allowed endpoint's host key is not in the user's known-hosts
  store
- **THEN** the session is refused with an error naming the endpoint and
  explaining that the key must be verified outside the sandbox first, and the
  store is left unchanged

#### Scenario: Changed host key

- **WHEN** the allowed endpoint presents a host key that differs from the stored
  one
- **THEN** the session is refused with an error naming the endpoint and stating
  that the key changed, and the store is left unchanged

#### Scenario: In-sandbox trust decisions are impossible

- **WHEN** a process inside the sandbox attempts to accept or record a new host
  key
- **THEN** it can only affect the generated per-session known-hosts file, which
  has no effect on which remote endpoints are reachable

#### Scenario: Per-session host key

- **WHEN** two sessions are started in turn
- **THEN** each is offered a different host key by nono, and a key captured from
  the first is not accepted in the second

### Requirement: The mediated endpoint is checked against the allowance

Before connecting outward, nono MUST check the endpoint the client asked for
against the configured SSH allowances, and MUST refuse any endpoint that no
allowance covers. The check MUST be made where the sandbox cannot influence it,
and MUST apply the same port-exact matching the allowance already defines.

#### Scenario: Endpoint outside the allowance

- **WHEN** a sandboxed client asks the mediation for a host no allowance covers
- **THEN** the connection is refused with a message naming the host, and no
  outbound connection is made

#### Scenario: Allowed host on a port the allowance does not name

- **WHEN** a sandboxed client asks for an allowed host on a port no allowance
  names
- **THEN** the connection is refused, consistent with the port exactness the
  allowance already guarantees

### Requirement: Channel activity is auditable

Every authorization decision the mediation makes MUST be recorded in the audit
trail nono already writes for network activity: the endpoint, the channel type,
the request type, the command line where one is present, and whether the request
was allowed or refused.

A refusal MUST be distinguishable from a transport failure in the record, so
that "the policy refused this" and "the connection broke" are not reported the
same way.

#### Scenario: Allowed command is recorded

- **WHEN** a sandboxed process runs a remote command over an allowed endpoint
- **THEN** the audit trail contains an entry naming the endpoint, the request
  type, and the command line

#### Scenario: Refusal is recorded

- **WHEN** a forwarding request is refused
- **THEN** the audit trail contains an entry naming the endpoint and the refused
  request type, marked as a policy refusal

### Requirement: The mediation fails closed

When the mediation cannot be started, cannot reach its configuration, or cannot
apply its channel policy, the session MUST fail. A degraded fallback to a
byte-transparent tunnel is not permitted, and the failure MUST name the
mediation as the cause rather than presenting as a network error.

#### Scenario: Mediation unavailable

- **WHEN** the mediation cannot be started for a session
- **THEN** SSH from the sandbox fails with an error naming the mediation, and no
  raw route to the endpoint becomes available as a result

#### Scenario: No silent downgrade

- **WHEN** any part of the mediated path is unavailable
- **THEN** no configuration, environment variable, or command-line flag causes
  the session to proceed as an unmediated tunnel
