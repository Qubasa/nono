## Context

The Linux supervisor multiplexes two seccomp-notify sources onto one loop:

- `openat` interception, which may consult an approval backend and therefore
  can prompt a human.
- network interception (`connect`, `bind`, `sendto`, `sendmsg`, `sendmmsg`),
  which under `af_unix_mediation = "pathname"` resolves `sockaddr_un.sun_path`
  and matches it against `filesystem.unix_socket*` capabilities.

Both share a single `RateLimiter` token bucket sized `(10, 5)`. The network
handler spends a token on entry, before `decide_network_notification` runs, so
allowed traffic competes with ambient AF_UNIX chatter (NSS/nscd, `/dev/log`,
D-Bus, the workload's own sockets) for the same 10/s budget.

Two asymmetries make the failure mode worse than the starvation itself:

- the `openat` path records `DenialReason::RateLimited`, the network path
  records nothing;
- policy denials answer `EACCES`, rate-limit denials answer `EPERM`, so the
  errno actively misdirects.

The BPF filter cannot pre-filter by address family, so in `AfUnixOnly` mode
TCP/UDP notifications also reach this handler. #1147 already exempted those
from the bucket, which is why `af_unix_mediation` no longer starves ordinary
network traffic and why only AF_UNIX traffic is affected today.

## Goals / Non-Goals

**Goals:**

- `af_unix_mediation = "pathname"` usable as a daily driver: granted sockets
  work under burst load, broker-style bind-then-connect workloads work.
- No supervisor denial without a record. Errno choice consistent with policy
  denials.
- Regression coverage that fails on the pre-change binary.

**Non-Goals:**

- Making the bucket tunable per profile. Nothing needs a budget once allowed
  decisions stop being charged, and a knob would only re-expose the failure.
- Removing rate limiting from the `openat` approval path. Prompt flooding is a
  genuine threat there and that path is unchanged.
- Granting the abstract namespace. Abstract sockets carry no filesystem path,
  so pathname capabilities cannot express them. Containment stays Landlock
  scoping plus default-deny under mediation.
- Relaxing the fail-closed denial for a socket path that cannot be
  canonicalized. A client binding into a granted subtree sees a few denied
  connects while the socket does not exist yet, and retries. Loosening that
  would decide policy on an unresolved path.

## Decisions

**Do not charge the bucket for network notifications at all, rather than
charging only on `Deny`.** Charging on deny still lets a workload with a
noisy, legitimately-denied socket exhaust the bucket and then have its
*allowed* sockets denied, which is the same bug one step removed. Containment
does not depend on the bucket either: every notification is driven by a real
syscall from the child, so the child's own throughput is the limit, and the
handler does no unbounded work per notification. The bucket's purpose is
bounding human prompts, and this path never prompts.

**Keep `RateLimiter` and its tests.** The `openat` approval path still needs
it. This change narrows where it applies, it does not delete the mechanism.

**Fix the diagnostics as part of the same change.** The silent `EPERM` is why
this cost users days: with a record and `EACCES`, the next regression in this
path is a one-line log read instead of an strace session. Requirement 2 is
therefore a spec requirement, not a follow-up.

## Risks / Trade-offs

- **Loss of a flood guard on the network path.** Accepted: an attacker-driven
  flood is bounded by the child's syscall rate, the handler allocates no
  unbounded state per notification, and the supervisor already survives
  notification storms on the `openat` path with a bucket that only suppresses
  prompts.
- **More audit volume.** Denials that were silent now produce records. This is
  the point, and the existing IPC-denial reporting already aggregates repeats
  ("... and N more").
- **Fork divergence.** This repo carries the change ahead of upstream. The
  tasks include filing the PR against #1420/#1715 so the fork can be dropped
  rather than maintained.
