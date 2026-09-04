## Purpose

Abstract-namespace and unnamed AF_UNIX sockets carry no filesystem path, so no
pathname capability can describe them. This capability fixes how nono contains
them, independently of whether pathname mediation is on.

## ADDED Requirements

### Requirement: Abstract sockets outside the sandbox are unreachable by default

With the default `security.ipc_mode`, a sandboxed process MUST NOT be able to
reach an abstract-namespace socket created outside its sandbox, while abstract
sockets created inside the sandbox MUST keep working. On kernels whose Landlock
ABI cannot scope abstract sockets, the scope MUST be reported as requested but
not enforced rather than silently assumed.

#### Scenario: Connect to a host abstract socket

- **WHEN** a listener is bound to an abstract name outside the sandbox and a
  sandboxed process connects to that name with `af_unix_mediation = "off"`
- **THEN** the connect fails with `EPERM` from Landlock scoping

#### Scenario: Abstract sockets inside the sandbox

- **WHEN** a sandboxed process binds its own abstract name and another process
  in the same sandbox connects to it
- **THEN** the bind and connect succeed, because scoping bounds the domain
  rather than banning the namespace

#### Scenario: Explicit opt-out

- **WHEN** the profile sets `security.ipc_mode = "full"`
- **THEN** abstract sockets outside the sandbox become reachable, and the
  session's capability report states that abstract socket scoping is not
  requested

#### Scenario: Kernel without abstract socket scoping

- **WHEN** the detected Landlock ABI predates abstract socket scoping
- **THEN** the session reports the scope as requested but unenforced, and does
  not claim abstract socket containment

### Requirement: Pathname mediation denies abstract and unnamed sockets with a record

Under `linux.af_unix_mediation = "pathname"`, abstract-namespace and unnamed
AF_UNIX operations MUST be denied with `EACCES` and reported as IPC denials that
name the socket kind, since no pathname capability can authorize them.

#### Scenario: Abstract bind and connect under mediation

- **WHEN** a sandboxed process binds or connects an abstract-namespace socket
  while pathname mediation is on
- **THEN** both calls fail with `EACCES`, and the session reports IPC denials
  identifying the socket as abstract and stating that pathname capabilities do
  not cover it

#### Scenario: Unnamed socket send under mediation

- **WHEN** a sandboxed process sends on an unnamed AF_UNIX socket while pathname
  mediation is on
- **THEN** the call fails with `EACCES` and the denial is recorded as unnamed,
  with no path claimed
