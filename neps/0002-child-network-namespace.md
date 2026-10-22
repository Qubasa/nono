---
nep: 0002
title: Loopback-only network namespace for the sandboxed child
authors:
  - Qubasa
status: draft
created: 2026-10-22
superseded-by:
---

# NEP-0002: Loopback-only network namespace for the sandboxed child

## Summary

Add `linux.sandbox_policy = "namespace"`. The child runs in a user and
network namespace of its own that holds only loopback, while the supervisor,
its proxy and its SSH bastion stay outside. `pasta --splice-only` carries the
proxy port in and the child's listen ports back out.

## Motivation

Landlock's TCP rules match ports, not addresses. In proxy mode nono therefore
cannot let the child use loopback freely: a grant for "connect to 5432" is a
grant for every host on 5432, and a bind grant is per port. Today a dev server
needs its port declared up front, a test that starts `sshd` on an ephemeral
port cannot run inside the sandbox at all, and a browser automation stack
(daemon, Chromium's DevTools port, the app under test) has to have every
port it might pick listed in advance.

The seccomp destination check closes the address gap for the proxy port only.
It cannot express "loopback is free, everything else goes through the proxy",
because the proxy and the child share one network namespace and one uid, so
nothing in the kernel can tell their sockets apart.

Splitting the namespaces gives the kernel that distinction directly: the
child has no route anywhere, and the processes that need one are elsewhere.

### Goals

- Unrestricted loopback inside the sandbox, with egress still only through
  nono's proxy and SSH bastion.
- Declared listen ports reachable from the host's loopback, so a dev server
  opens in the user's browser.
- `allow_ssh` keeps working: the bastion dials out from the parent.

### Non-Goals

- Unrestricted networking (`AllowAll`) or direct `connect_port` egress inside
  the namespace. Both need a route out; the policy refuses them.
- macOS. Seatbelt already filters by destination.
- Replacing `auto` as the default.

## Proposal

CLI only (`nono-cli`); the `nono` library is unchanged.

1. `LinuxSandboxPolicy::Namespace` (`--sandbox-policy namespace`, profile
   `linux.sandbox_policy`). Its syscall surface is `external`'s: Landlock
   filesystem and process rules, no Landlock TCP rules, no static socket
   baseline, no seccomp destination check.
2. Before forking the child, the supervisor forks a holder. The holder calls
   `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, maps only the caller's uid and gid
   onto themselves (`setgroups` denied), brings `lo` up, reports success over
   a pipe and pauses. It uses raw syscalls only, since the supervisor is
   already multi-threaded. `PR_SET_PDEATHSIG` and `setsid` tie its life to the
   supervisor and keep terminal signals away from it.
3. The supervisor opens `/proc/<holder>/ns/{user,net}` and, when anything must
   cross, runs `pasta --splice-only -u none -U none` against the holder:
   - `-T <proxy port>`: the proxy at the same port inside, so the injected
     `HTTP(S)_PROXY` values are unchanged.
   - `-T <open ports>,auto`: an `open_port` service in the parent, forwarded
     in while it listens.
   - `-t 127.0.0.1/<listen and open ports>,auto`: forwarded out to the
     parent's loopback only while the child listens, minus the proxy port.
   pasta's launcher exits once the forwards are bound, which is the readiness
   signal; the daemon exits when the holder does.
4. Both spawn paths (`CLONE_FILES` bootstrap and legacy fork) call `setns`
   on the user then the network namespace first thing in the child, before
   the dumpable flag, the notify filters and Landlock.
5. `allow_ssh` is accepted under this policy without the seccomp supervisor:
   the missing route is the destination pin.
6. `nono wrap` (direct exec) refuses the policy: there is no parent left
   outside the namespace to hold the proxy or pasta.

Backward compatibility: a new enum value, no change to existing policies.

## Security Considerations

- **Least privilege.** The child gains free use of its own loopback and UDP
  on loopback, which it does not have under `auto` in proxy mode. It gains no
  reach beyond that: there is no interface but `lo`, and the child cannot add
  one. It runs as a non-root id in a namespace whose owner is the
  supervisor's user namespace, so its capabilities there are dropped at
  `execve`, and it has none over the parent's namespaces. A user namespace it
  creates itself owns nothing it can route through.
- **Outward forwards.** Bound on `127.0.0.1` only and only while the child
  listens on a declared port, so the child cannot squat arbitrary host ports.
  Undeclared listeners stay inside.
- **Fail-secure.** Any failure (no user namespaces, no pasta, pasta cannot
  bind) aborts before the child is forked. A child that cannot join exits
  with 126 before the sandbox is applied. If the holder dies, pasta exits and
  the child loses the proxy rather than gaining a route.
- **Trust in pasta.** pasta runs unsandboxed in the parent's namespace with
  the supervisor's privileges, the same position as the proxy, and is given
  only splice forwards.
- **Unix sockets.** Pathname sockets still cross, as before. Abstract sockets
  no longer do, which narrows rather than widens reach.
- **Credentials.** None introduced. The proxy token and phantom credentials
  reach the child exactly as under `auto`.
- **Library/CLI boundary.** Policy and namespace setup stay in `nono-cli`.

## Alternatives Considered

- **nftables in a shared namespace, matching the proxy's sockets by cgroup.**
  Needs nftables, a delegated cgroup subtree and a race-free cgroup move of
  the child; more moving parts for the same result.
- **Landlock port grants for every port.** Equivalent to no egress filter,
  since each grant applies to every destination.
- **seccomp notify on `connect` with an address check for loopback.** The
  supervisor already does this for the proxy port; extending it to all of
  loopback still cannot cover `bind`, and every loopback connection would
  pay a supervisor round trip.

## Open Questions

- Should `::1` listeners also be forwarded? Forwarding both families makes a
  `localhost` client that prefers `::1` reach pasta first and fail against an
  IPv4-only server, so the draft forwards `127.0.0.1` only.
- Should the policy become the default where unprivileged user namespaces and
  pasta are available?
