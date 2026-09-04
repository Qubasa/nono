## Why

`linux.af_unix_mediation = "pathname"` is the only mechanism nono has for
containing pathname AF_UNIX traffic, and it is currently unusable on real
workloads. The supervisor charges a shared token bucket
(`RateLimiter::new(10, 5)`, `crates/nono-cli/src/exec_strategy.rs:2959` on
`upstream/main`) on **every** AF_UNIX notification *before* the capability
lookup runs. An empty bucket answers `deny_notif` with a bare `EPERM`,
emitting only a `debug!` and no denial record
(`crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1108`).

Measured on nono 0.73.0, NixOS, Landlock V6 kernel, with a profile that
grants the target socket explicitly:

| run | result | rate-limit log lines |
| --- | --- | --- |
| 40 connects, no delay | `ok=5 EPERM=35` | 35 |
| 40 connects, 0.15 s apart | `ok=40 EPERM=0` | 0 |

`ok=5` is the burst capacity. The failures are timing-dependent, carry the
wrong errno (`EPERM`, where policy denials use `EACCES`), and leave no
diagnostic behind, so they are indistinguishable from a broken grant.

Consequences observed in the wild:

- An agent harness whose supervisor binds a per-project socket
  (`~/.omp/run/daemons/<hash>/broker.sock`) cannot start it at all. Every
  background-process feature is dead, and the surfaced error is a misleading
  `connect ENOENT`.
- Claude Code Agent View is broken the same way (#1715).
- Docker-socket test suites are "effectively impossible" with mediation on
  (#1420, reproduced by a second reporter on nono 0.70.0).

Because the failure looks like a grant problem and cannot be worked around
with any grant, users disable AF_UNIX mediation wholesale and lose all
pathname socket containment. That is the wrong trade to have to make.

Upstream state as of `upstream/main` d1d232ef (post-v0.75.0): #1420 and #1715
are open, unassigned, `triage` only, and no PR touches the network path. The
bucket and its pre-decision charge are still there. #1128/#1147 fixed
adjacent starvation (non-AF_UNIX passthrough), and #1399/#1401 fixed an
unrelated silent-`EPERM` cause (orphan ancestry), so neither covers this.

## What Changes

- Remove rate limiting from the AF_UNIX and proxy decision path. That path is
  a pure capability lookup that never prompts, so a token bought no
  containment: a child cannot provoke more supervisor work than its own
  syscall throughput allows. The bucket stays on the `openat` approval path,
  where prompt flooding is the real threat.
- Make every supervisor-issued AF_UNIX denial observable and correctly
  classified: `EACCES` for policy denials, plus a denial record, so no code
  path can deny an AF_UNIX syscall with nothing but a `debug!`.
- Pin the behaviour that lets a daemon bind inside a granted subtree and be
  connected to by its clients, which is the shape every broker-style workload
  needs.
- Pin the abstract-namespace behaviour that already holds, so a future change
  to the mediation path cannot silently regress it: abstract sockets created
  outside the sandbox stay unreachable via Landlock V6 scoping under the
  default `ipc_mode`, in-sandbox abstract sockets keep working, and
  `ipc_mode = "full"` remains the explicit opt-out.

## Capabilities

### New Capabilities

- `sandbox/af-unix-mediation`: pathname AF_UNIX mediation under
  `linux.af_unix_mediation`, its interaction with supervisor rate limiting,
  and the diagnostics every denial must leave behind.
- `sandbox/abstract-unix-sockets`: containment of abstract-namespace and
  unnamed AF_UNIX sockets, which no pathname capability can express.

### Modified Capabilities

<!-- None. openspec/specs/ is empty, so both capabilities above are new. -->

## Impact

- `crates/nono-cli/src/exec_strategy.rs`: drop the `rate_limiter` argument
  threaded into the network path (`run_supervisor_loop`,
  `drain_pending_network_notifications`).
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`:
  `handle_network_notification` loses its `RateLimiter` parameter and its
  pre-decision charge; denial reporting gains the missing record.
- `docs/cli/internals/security-model.mdx`: the "Rate limit exceeded" row must
  say the limit applies to the approval path only.
- No profile-schema or CLI-flag change. Existing profiles keep working, and
  `filesystem.unix_socket*` grants become effective under load rather than
  intermittently.
- Local commit 5dcbc83a ("disable rate limiting which breaks socket
  container") is the stopgap this change supersedes and upstreams with tests
  and diagnostics.
