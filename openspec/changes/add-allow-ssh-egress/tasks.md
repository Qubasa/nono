## 1. Config surface

- [x] 1.1 Add `allow_ssh: Vec<String>` with `#[serde(default)]` to
      `NetworkConfig` (`crates/nono-cli/src/profile/mod.rs:1769-1852`); verify a
      profile carrying the key parses instead of failing `deny_unknown_fields`
- [x] 1.2 Merge it in `merge_profiles` (`profile/mod.rs:3803-3856`) with
      `dedup_append` (`profile/mod.rs:3989`); verify with a unit test where a
      child and base each declare one endpoint and the effective profile has
      both, de-duplicated
- [x] 1.3 Add `parse_ssh_endpoint(&str) -> Result<(String, u16)>` accepting
      `[user@]host[:port]`, defaulting to 22, bracket-aware for IPv6; unit-test
      `deploy@h:2222`, `h`, `[::1]:22`, and the rejections in 1.4
- [x] 1.4 Reject wildcards (any `*`), empty host, non-numeric port, and port 0
      or >65535 at load time via a new validator called from
      `validate_profile_network` (`profile/mod.rs:1296`) so it also runs
      post-merge at `:3267`; verify each rejection names the offending entry
- [x] 1.5 Update the two exhaustive `NetworkConfig` literals at
      `profile/mod.rs:6960-6977` and `:7051-7067`; verify `cargo check -p
      nono-cli --tests` gets past them
- [x] 1.6 Add the `allow_ssh` property to `$defs/NetworkConfig`
      (`crates/nono-cli/data/nono-profile.schema.json:867-969`) and to the
      pinned key list in `tests/schema_shape.rs:65-81`; verify
      `test_schema_network_config_matches_rust_model` passes

## 2. CLI surface

- [x] 2.1 Add `--allow-ssh` (`Vec<String>`, `value_name = "SSH_TARGET"`,
      `env = "NONO_ALLOW_SSH"`, `help_heading = "NETWORK"`) to `SandboxArgs`
      (`cli.rs:1176-1184` is the `--allow-domain` model); verify
      `nono run --help` lists it under NETWORK
- [x] 2.2 Add `"allow_ssh"` to the `--allow-net` conflict list
      (`cli.rs:1147-1166`) and the `--config` conflict list (`cli.rs:1381-1390`);
      verify `nono run --allow-net --allow-ssh h -- true` fails to parse
- [x] 2.3 Add the field to `ProxyArgs` (`cli.rs:1496-1545`) and `WhyArgs`
      (`cli.rs:2157-2161`); verify both `--help` outputs list it
- [x] 2.4 Set `allow_ssh: Vec::new()` in `From<WrapSandboxArgs> for SandboxArgs`
      (`cli.rs:1839-1883`) and reject `--allow-ssh` under `nono wrap`, which has
      no proxy support; verify the wrap path errors rather than ignoring it
- [x] 2.5 Add `|| !self.allow_ssh.is_empty()` to `SandboxArgs::has_proxy_flags`
      (`cli.rs:1417-1423`); verify by unit test

## 3. Thread the field to the proxy

- [x] 3.1 Add `allow_ssh` to `PreparedProfile` (`profile_runtime.rs:8-62`) and
      populate it at the single construction site (`:834`, network block
      `:878-919`); verify `cargo check` passes
- [x] 3.2 Add it to the exhaustive `PreparedProfile` destructuring
      (`sandbox_prepare.rs:1552-1595`)
- [x] 3.3 Add it to `PreparedSandbox` (`sandbox_prepare.rs:506-578`) and all 8
      exhaustive literals: `sandbox_prepare.rs:1495`, `:1888`, `:2869`;
      `main.rs:277`, `:353`; `proxy_runtime.rs:3658`, `:3732`, `:3801`; verify
      `cargo check -p nono-cli --tests` compiles clean
- [x] 3.4 Add it to `EffectiveProxySettings` (`proxy_runtime.rs:43-50`) and both
      literals (`:1713` allow-net early return, `:1733`), merging CLI entries
      alongside the `allow_domain` merge at `:1725-1726`
- [x] 3.5 Add it to `DomainFilterIntent` (`launch_runtime.rs:79-89`) and both
      exhaustive literals (`proxy_runtime.rs:1508`, `proxy_command.rs:276`)
- [x] 3.6 Extend the preflight parity test
      (`profile_runtime.rs:1816`, fixture `:1838-1843`, asserts `:1869-1891`)
      with `allow_ssh`; verify it passes

## 4. Activation and port-exact enforcement

- [x] 4.1 OR `allow_ssh` into `has_proxy_intent` (`sandbox_prepare.rs:871-875`),
      `has_domain_filter` (`proxy_runtime.rs:1475-1476`), and the `domain_filter`
      construction gate (`proxy_runtime.rs:1505-1512`); verify a profile whose
      only network key is `allow_ssh` starts a proxy and sets
      `NetworkMode::ProxyOnly`
- [x] 4.2 In `build_proxy_config_from_flags`, append each endpoint as
      `host:port` to `plain_hosts` **after** the `partition_allow_domain` call
      (`proxy_runtime.rs:2392-2398`), with no bare-host fallback; verify by unit
      test that the resulting `ProxyConfig.allowed_hosts` contains `h:22` and
      not `h`
- [x] 4.3 Count SSH entries in `host_allowlist_active`
      (`proxy_runtime.rs:2412-2417`); verify an SSH-only run does not fall
      through to the empty-allowlist allow-all path (#1485)
- [x] 4.4 Exclude SSH entries from `collect_allow_domain_port_warnings`
      (`network_policy.rs:493`, printed via `sandbox_prepare.rs:30-38`); verify
      `--allow-ssh h:2222` prints no "port is ignored" warning while
      `--allow-domain h:2222` still does
- [x] 4.5 Mirror the merge in the standalone `nono proxy` path
      (`proxy_command.rs:199-280`); verify `nono proxy --allow-ssh h` produces
      the same allowlist as the sandboxed path

## 5. Fail-closed guards

- [x] 5.1 Reject `allow_ssh` with `LinuxSandboxPolicy::Landlock` or `External`
      in `execution_runtime.rs:619-668`, naming both settings; verify each
      combination errors before the sandbox starts
- [x] 5.2 On WSL2 without Landlock network support, route `allow_ssh` through
      the existing `wsl2_proxy_policy` error and warning
      (`execution_runtime.rs:631-659`) rather than adding a second opt-out;
      verify the error text matches the existing proxy-mode one
- [x] 5.3 Reject `--block-net` + `--allow-ssh` in `validate_block_net_conflicts`
      (`sandbox_prepare.rs:914-963`, model `has_allow_domain` at `:939-940`);
      verify the error names both flags
- [x] 5.4 Extend `validate_no_proxy_allow_domain_conflicts`
      (`profile/mod.rs:1337`, called from `:1296` and `proxy_runtime.rs:1739`)
      and `validate_expanded_proxy_no_proxy_conflicts`
      (`proxy_runtime.rs:2718`) to cover SSH endpoints; verify a profile with a
      host in both `allow_ssh` and `no_proxy` fails to load

## 6. ssh-tunnel subcommand

- [x] 6.1 Add `crates/nono-cli/src/ssh_tunnel.rs` (not `connect_client.rs`,
      which is the console attach client) implementing
      `run_ssh_tunnel(host, port)`: read `HTTPS_PROXY` and `NONO_PROXY_TOKEN`,
      call `nono_proxy::external::connect_via_proxy`
      (`nono-proxy/src/external.rs:34`), then `copy_bidirectional` with
      stdin/stdout; declare the module in `main.rs`
- [x] 6.2 Add `#[command(hide = true)] SshTunnel(SshTunnelArgs)` to `Commands`
      (`cli.rs:664-670` shows the two existing hidden helpers) and dispatch it
      from `app_runtime.rs:145-146`, bypassing the update-check wrapper; verify
      it is absent from `nono --help` and that `cli.rs:4484-4494` still passes
- [x] 6.3 Exit non-zero with a message naming the host when the proxy answers
      403; verify by pointing it at a running proxy with an empty allowlist
- [x] 6.4 Verify manually: with a proxy running, `nono ssh-tunnel <allowed> 22`
      emits the server's `SSH-2.0-` banner on stdout

## 7. Client wiring

- [x] 7.1 Materialise the generated SSH config in a session-scoped 0o700
      directory with 0o400 `create_new`, modelled on `prepare_intercept_ca_dir`
      (`proxy_runtime.rs:3236`) and `write_with_restrictive_perms`
      (`tls_intercept/bundle.rs:144`); content is `Host *` +
      `ProxyCommand <nono> ssh-tunnel %h %p`
- [x] 7.2 Grant read on it with `CapabilitySet::allow_file_mut`
      (`capability.rs:1052`) in `start_proxy_runtime` (`proxy_runtime.rs:2944`),
      next to the existing CA grant at `:3078-3101`
- [x] 7.3 Remove the directory on teardown alongside the CA bundle
      (`Drop for ProxyHandle`, `nono-proxy/src/server.rs:669`, forced by
      `execution_runtime.rs:810`); verify nothing is left in the session dir
      after a normal exit
- [x] 7.4 Append `GIT_SSH_COMMAND="ssh -F <path>"` to
      `ActiveProxyRuntime.env_vars` (`proxy_runtime.rs:3103-3117`); verify it
      overrides an inherited host value via `env_var_survives_filters`
      (`env_sanitization.rs:301`)
- [x] 7.5 Materialise an `ssh` wrapper in a 0o500 dir prepended to `PATH`,
      modelled on `build_session_path`
      (`tool-sandbox/platform/linux.rs:2604`) and the browser-shim prepend
      (`exec_strategy.rs:732-741`), execing the real `ssh` with `-F <path>`;
      verify tool-sandbox's `commands`-gated shim machinery is not required
- [x] 7.6 Verify `git clone ssh://<allowed>/repo` works inside the sandbox with
      no user-side SSH config

## 8. Policy visibility

- [x] 8.1 Print `allow_ssh` in `nono profile show`, including the `has_net` gate
      (`profile_cmd.rs:1039-1046`) and a display block next to `allow_domain`
      (`:1061-1077`); verify against a profile that sets only `allow_ssh`
- [x] 8.2 Add it to `nono profile show --json` (`profile_cmd.rs:1336-1344`) and
      the empty-network scaffold (`:286-290`)
- [x] 8.3 Add it to `nono profile diff` (`profile_cmd.rs:1588-1613`) and
      `diff --json` (`:2057-2142`); verify a diff between two profiles that
      differ only in `allow_ssh` reports it
- [x] 8.4 Make `nono why <host>` distinguish an allowed endpoint from a
      requested one on a different port (`why_runtime.rs:31-80`, `:205-249`);
      verify `nono why h:443` explains the port mismatch when `h:22` is allowed
- [x] 8.5 Include SSH endpoints in the sandbox-state allowlist so
      `nono why --self` matches runtime (`execution_runtime.rs:267-305`,
      `sandbox_state.rs:44-48`)

## 9. Integration verification

- [x] 9.1 Integration test: profile with `allow_ssh: ["<host>"]` — raw `CONNECT
      <host>:22` returns 200, `CONNECT <host>:443` returns 403, `CONNECT
      <other>:22` returns 403. This is the port-exactness contract and must fail
      on a pre-change binary, where all three returned 200
- [x] 9.2 Integration test: direct `connect()` from inside the sandbox to the
      allowed host:port fails with `EACCES`, proving the allowance grants a
      mediated route and not raw reachability
- [x] 9.3 Integration test: `ssh` with the proxy env cleared still cannot reach
      any endpoint
- [x] 9.4 End-to-end: `ssh -T <allowed>` inside the sandbox completes the SSH
      handshake (host key exchanged, authentication attempted) and
      `ssh -T <other>` fails naming the host as not allowed
- [x] 9.5 Confirm no regression in `allow_domain`: a profile with
      `allow_domain: ["h:22"]` still reaches `h` on every port, and still prints
      the port-ignored warning

## 10. Documentation

- [x] 10.1 `crates/nono-cli/data/profile-authoring-guide.md`: add `allow_ssh` to
      the append+dedup merge list (`:65`) and the `network.*` table (`:363-374`),
      stating the port-exactness difference from `allow_domain`
- [x] 10.2 `docs/cli/features/networking.mdx` and `docs/cli/usage/flags.mdx`:
      document the flag, its `NONO_ALLOW_SSH` env var, and that the generated
      SSH config and PATH wrapper are ergonomics while the kernel pin is the
      boundary
- [x] 10.3 Replace the now-wrong guidance at
      `docs/cli/features/tool-sandbox.mdx:637-651` ("a raw TCP/22 rule currently
      requires Linux Landlock")
- [x] 10.4 Document the recommended key posture next to the flag: a dedicated
      key via `filesystem.read_file` plus `IdentitiesOnly=yes`, and why
      forwarding `$SSH_AUTH_SOCK` weakens the guarantee
- [x] 10.5 `CHANGELOG.md` entry
