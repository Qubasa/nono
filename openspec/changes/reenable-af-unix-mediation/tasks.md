## 1. Remove rate limiting from the AF_UNIX decision path

- [x] 1.1 Drop the `rate_limiter: &mut RateLimiter` parameter from
      `supervisor_linux::handle_network_notification` and delete the
      `try_acquire`/`deny_notif` block, documenting on the function why this
      path is deliberately unlimited (commit 5dcbc83a)
- [x] 1.2 Stop threading `rate_limiter` through `run_supervisor_loop` and
      `drain_pending_network_notifications` in
      `crates/nono-cli/src/exec_strategy.rs` (commit 5dcbc83a)
- [x] 1.3 Keep `RateLimiter` and its unit tests for the `openat` approval path
      (commit 5dcbc83a)
- [x] 1.4 Confirm no remaining caller charges the bucket for a decision that
      cannot prompt: `rg 'try_acquire' crates/` reviewed against the approval
      path only

## 2. Close the diagnostics gap

- [x] 2.1 Emit a `DenialRecord`/`IpcDenialRecord` for every AF_UNIX denial the
      network handler issues, including the paths it cannot canonicalize
- [x] 2.2 Answer policy denials with `EACCES` and reserve `EPERM` for
      supervisor-side failures, so errno distinguishes the two
- [x] 2.3 Include the suggested grant flag in the denial record, matching the
      existing "Fix flags" output

## 3. Regression tests

- [x] 3.1 Integration test: 40 back-to-back connects to a socket granted via
      `filesystem.unix_socket` under `af_unix_mediation = "pathname"` all
      succeed. Must fail on a pre-change binary (measured `ok=5 EPERM=35`)
- [x] 3.2 Integration test: bind and listen at `<granted-subtree>/<runtime
      path>/x.sock` via `filesystem.unix_socket_subtree_bind`, then connect
      from a second process in the same sandbox
- [x] 3.3 Unit test: denying an AF_UNIX notification always yields a denial
      record, asserted over pathname, abstract, and unnamed kinds
- [x] 3.4 Unit test: `openat` approval flooding still produces
      `DenialReason::RateLimited`
- [x] 3.5 Integration test: with `af_unix_mediation = "off"` and default
      `ipc_mode`, connecting to an abstract socket bound outside the sandbox
      fails while an in-sandbox abstract bind and connect succeeds, and
      `ipc_mode = "full"` reverses the first result

## 4. Documentation

- [x] 4.1 `docs/cli/internals/security-model.mdx`: scope the "Rate limit
      exceeded" row to the approval path and state that AF_UNIX and proxy
      decisions are unlimited capability lookups (started in commit 5dcbc83a)
- [x] 4.2 Document in the profile reference that abstract sockets cannot be
      granted, are denied under pathname mediation, and are contained by
      `ipc_mode` scoping otherwise

## 5. Upstream and re-enable

- [ ] 5.1 Open a PR against `upstream/main` referencing #1420 and #1715, with
      the measured before/after numbers
- [ ] 5.2 After release, drop the fork carrying 5dcbc83a and pin the released
      version
- [x] 5.3 Restore `"af_unix_mediation": "pathname"` in
      `~/.config/nono/profiles/claude-code-local.json`, adding
      `filesystem.unix_socket_subtree_bind: ["~/.omp/run"]` for the agent
      harness broker socket, and verify a supervised background process starts
