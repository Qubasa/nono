## Purpose

Pathname AF_UNIX mediation lets a profile decide which filesystem-backed Unix
sockets a sandboxed process may bind or talk to, and requires that every
decision the supervisor makes is both correct under load and visible in
diagnostics.

## ADDED Requirements

### Requirement: Allowed AF_UNIX operations are never denied by supervisor rate limiting

Under `linux.af_unix_mediation = "pathname"`, an AF_UNIX operation that the
profile's `filesystem.unix_socket*` capabilities permit MUST be allowed
regardless of how many AF_UNIX notifications preceded it. Supervisor rate
limiting MUST apply only to the approval-prompt path, whose purpose is bounding
human prompts.

#### Scenario: Burst of connects to a granted socket

- **WHEN** a sandboxed process performs 40 back-to-back `connect(2)` calls to a
  socket listed in `filesystem.unix_socket`
- **THEN** all 40 connects succeed, and no notification is denied for
  rate-limiting reasons

#### Scenario: Ambient AF_UNIX traffic does not consume a budget

- **WHEN** the workload also drives unrelated AF_UNIX traffic (name-service,
  logging, D-Bus) in the same session
- **THEN** the granted socket's operations still succeed, because allowed
  decisions are not charged against any shared budget

#### Scenario: Approval-prompt path keeps its rate limit

- **WHEN** a sandboxed process floods the supervisor with `openat(2)` requests
  that require approval
- **THEN** the excess requests are denied with a recorded rate-limited denial,
  and no approval prompt is emitted for them

### Requirement: Every AF_UNIX denial is recorded and classified as a policy denial

A supervisor-issued denial of an AF_UNIX operation MUST produce a denial record
that names the operation and, for pathname sockets, the requested path, and MUST
answer the child with `EACCES`. Denying with only a debug log, or with `EPERM`
where a policy denial is meant, is not permitted.

#### Scenario: Connect to an ungranted pathname socket

- **WHEN** a sandboxed process connects to a pathname socket no capability
  covers
- **THEN** the call fails with `EACCES`, and the session reports an IPC denial
  naming the operation and the socket path together with the grant flag that
  would allow it

#### Scenario: No silent denials remain

- **WHEN** the supervisor denies any AF_UNIX notification for any reason
- **THEN** a denial record exists for it, so the failure is attributable
  without tracing the child

### Requirement: A daemon may bind inside a granted subtree and serve its clients

A profile that grants a directory subtree for socket binding MUST allow a
sandboxed process to `bind(2)` and `listen(2)` a socket at a runtime-chosen path
inside that subtree, and MUST allow other sandboxed processes to `connect(2)` to
it, including when the socket's parent directories are created after the sandbox
starts.

#### Scenario: Broker binds a runtime path and a client connects

- **WHEN** `filesystem.unix_socket_subtree_bind` grants a directory, and a
  supervised background process binds `<dir>/<runtime-hash>/broker.sock` and
  listens
- **THEN** the bind and listen succeed, and a sibling process in the same
  sandbox connects to that socket successfully

#### Scenario: Bind outside the granted subtree

- **WHEN** the same process binds a socket at a path no capability covers
- **THEN** the bind fails with `EACCES` and the denial is recorded
