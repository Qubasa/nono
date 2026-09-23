# `network.allow_ssh` against a real NixOS client and a real sshd.
#
# The in-tree integration suite starts its own sshd but runs on whatever the
# developer's machine happens to look like. This one pins the environment that
# actually broke: a NixOS client, where `/etc/ssh/ssh_config` Includes a path
# in the Nix store. Inside nono's user namespace that path reports as
# `nobody:nogroup`, which OpenSSH calls "Bad owner or permissions" - fatal for
# `scp` and `sftp`, and enough to stop `ssh` reading the generated config.
#
# The tools tested here are the ones an agent actually reaches for. `ssh` alone
# passing proves nothing about `scp`, `sftp` and `rsync`: each finds its remote
# shell a different way, and only `git` was ever wired up.
{ self, pkgs }:

let
  privateKey = ''
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDkvjtXlmrZvXSZLpOGpMG5toAzOlB6zUN69kFJ+HrMowAAAJCdMNeWnTDX
    lgAAAAtzc2gtZWQyNTUxOQAAACDkvjtXlmrZvXSZLpOGpMG5toAzOlB6zUN69kFJ+HrMow
    AAAEC9I8BYEEbswHOnJQh13TWxo7i2rEqyLDRidf7Cv3TZv+S+O1eWatm9dJkuk4akwbm2
    gDM6UHrNQ3r2QUn4esyjAAAADG5vbm8tdm0tdGVzdAE=
    -----END OPENSSH PRIVATE KEY-----
  '';

  publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOS+O1eWatm9dJkuk4akwbm2gDM6UHrNQ3r2QUn4esyj nono-vm-test";

  # A store-resident drop-in, reproducing the libvirt/systemd Includes NixOS
  # puts at the top of every `ssh_config`. Owned by root and mode 0444 in the
  # store, which is the whole point: the sandbox cannot see root.
  sshDropIn = pkgs.writeTextDir "etc/ssh/ssh_config.d/30-nono-test.conf" ''
    # Deliberately inert. Being read at all is what matters.
    Host nono-test-drop-in-marker
      Compression no
  '';

  payload = "nono-mediated-payload-42";

  # On NixOS every binary's interpreter and libraries live in `/nix/store`,
  # which the stock `default` profile does not grant, so nothing execs at all
  # without `nix_runtime`. This is the profile a NixOS user actually needs.
  profile = builtins.toJSON {
    meta = {
      name = "ssh-vm-test";
      version = "1.0.0";
      description = "SSH mediation against a real sshd on NixOS";
    };
    extends = "default";
    groups.include = [ "nix_runtime" ];
    # Read-write, so the tests can check what the transfer actually landed.
    # `--allow-cwd` alone is read-only.
    filesystem.allow = [ "/home/agent/work" ];
    network.allow_ssh = [ "deploy@server:22" ];
  };
in
pkgs.testers.runNixOSTest {
  name = "nono-ssh-mediation";

  nodes = {
    server =
      { ... }:
      {
        services.openssh = {
          enable = true;
          settings = {
            PasswordAuthentication = false;
            PermitRootLogin = "no";
          };
        };
        users.users.deploy = {
          isNormalUser = true;
          openssh.authorizedKeys.keys = [ publicKey ];
        };
        environment.systemPackages = [
          pkgs.rsync
          pkgs.git
        ];
        environment.etc."nono-test/payload".text = payload;
      };

    client =
      { ... }:
      {
        environment.systemPackages = [
          self.packages.${pkgs.stdenv.hostPlatform.system}.nono
          pkgs.openssh
          pkgs.rsync
          pkgs.git
          pkgs.netcat
        ];

        # `extraConfig` is emitted before the generated `Host *` block, which
        # is exactly where libvirt's drop-in lands on a real machine.
        programs.ssh.extraConfig = ''
          Include ${sshDropIn}/etc/ssh/ssh_config.d/30-nono-test.conf
        '';

        users.users.agent = {
          isNormalUser = true;
          home = "/home/agent";
        };

        # nono needs unprivileged user namespaces for the sandbox and the
        # seccomp-notify supervisor.
        boot.kernel.sysctl."kernel.unprivileged_userns_clone" = 1;
        virtualisation.memorySize = 2048;

        # Spliced into the test script as a path, never as text: the driver
        # type-checks the Python, and a multi-line Nix string pasted into a
        # string literal does not survive that.
        environment.etc."nono-test/id_ed25519".text = privateKey;
        environment.etc."nono-test/profile.json".text = profile;
      };
  };

  testScript = ''
    import shlex

    start_all()
    server.wait_for_unit("sshd.service")
    server.wait_for_open_port(22)
    client.wait_for_unit("multi-user.target")

    server.succeed(
        "install -o deploy -g users -m 0644 /etc/nono-test/payload /tmp/payload"
    )

    # The bastion verifies the remote host key against the launching user's
    # known_hosts, in the parent. Populate it the way a human would.
    client.succeed("install -d -o agent -g users -m 0700 /home/agent/.ssh")
    client.succeed("install -d -o agent -g users -m 0755 /home/agent/work")
    client.succeed(
        "install -o agent -g users -m 0600 /etc/nono-test/id_ed25519 "
        "/home/agent/.ssh/id_ed25519"
    )
    client.succeed("su agent -c 'ssh-keyscan -T 20 server >> /home/agent/.ssh/known_hosts'")
    client.succeed("su agent -c 'test -s /home/agent/.ssh/known_hosts'")

    # The drop-in must really be in the chain, or every assertion below is
    # testing a machine that never had the problem.
    client.succeed("grep -q 'ssh_config.d/30-nono-test.conf' /etc/ssh/ssh_config")

    def agent_sh(script):
        return "su agent -c " + shlex.quote(script)

    def mediated(inner, extra_flags=""):
        """Run `inner` inside a nono sandbox whose only egress is the sshd.

        The two NONO_ variables are what keep this non-interactive: the save
        prompt reads /dev/tty directly, which the driver's console satisfies,
        and the update check would dial out through a sandbox that allows
        exactly one SSH endpoint and nothing else.
        """
        cmd = (
            "cd /home/agent/work && "
            "NONO_NO_SAVE_PROMPT=1 NONO_NO_UPDATE_CHECK=1 "
            "nono run --profile /etc/nono-test/profile.json --allow-cwd "
            "--ssh-key /home/agent/.ssh/id_ed25519 "
            f"{extra_flags}-- /bin/sh -c {shlex.quote(inner)}"
        )
        # A wedged mediation must fail the test, not stall the driver until
        # the CI job is killed with no diagnosis attached.
        return "timeout 120 " + agent_sh(cmd) + " </dev/null"

    with subtest("ssh reaches the endpoint and reads no hostile config"):
        out = client.succeed(mediated("ssh deploy@server 'echo SSH-OK; id -un'") + " 2>&1")
        assert "SSH-OK" in out, out
        assert "deploy" in out, out
        assert "Bad owner or permissions" not in out, out

    work = "/home/agent/work"

    with subtest("scp pulls a file"):
        out = client.succeed(
            mediated(f"scp deploy@server:/tmp/payload {work}/got && cat {work}/got") + " 2>&1"
        )
        assert "${payload}" in out, out
        assert "Bad owner or permissions" not in out, out

    with subtest("sftp pulls a file"):
        out = client.succeed(
            mediated(
                f"echo 'get /tmp/payload {work}/sftp-got' | sftp -b - deploy@server "
                f"&& cat {work}/sftp-got"
            )
            + " 2>&1"
        )
        assert "${payload}" in out, out
        assert "Bad owner or permissions" not in out, out

    with subtest("rsync pulls a file"):
        out = client.succeed(
            mediated(
                f"rsync deploy@server:/tmp/payload {work}/rsync-got && cat {work}/rsync-got"
            )
            + " 2>&1"
        )
        assert "${payload}" in out, out

    with subtest("rsync pushes a file"):
        client.succeed(
            mediated(
                f"echo pushed-by-rsync > {work}/up && rsync {work}/up deploy@server:/tmp/pushed"
            )
            + " 2>&1"
        )
        server.succeed("grep -q pushed-by-rsync /tmp/pushed")

    with subtest("git clones over the mediated route"):
        server.succeed(
            "su deploy -c '"
            "mkdir -p /tmp/repo && cd /tmp/repo && "
            "git init -q --bare'"
        )
        out = client.succeed(
            mediated("git ls-remote deploy@server:/tmp/repo >/dev/null && echo GIT-OK")
            + " 2>&1"
        )
        assert "GIT-OK" in out, out

    with subtest("a local forward is refused"):
        # `ExitOnForwardFailure` turns "the forward did not come up" into a
        # non-zero exit instead of a session that idles until the timeout.
        # The bind is a sandboxed operation of its own, so this one is usually
        # refused before any channel reaches the bastion.
        out = client.fail(
            mediated(
                "ssh -o ExitOnForwardFailure=yes -L 12345:server:22 deploy@server true"
            )
            + " 2>&1"
        )
        assert "SSH-OK" not in out, out

    with subtest("stdio forwarding is refused as direct-tcpip"):
        # `-W` is the `direct-tcpip` request on its own, in one process. `-J`
        # would reach the same rule but nests a second `ssh` whose stderr
        # OpenSSH discards, leaving nothing to assert on.
        out = client.fail(mediated("ssh -W server:22 deploy@server") + " 2>&1")
        assert "direct-tcpip" in out, out

    with subtest("the endpoint is not reachable as raw TCP"):
        out = client.fail(
            mediated("timeout 10 sh -c 'nc -w 5 server 22 </dev/null'") + " 2>&1"
        )
        assert "SSH-2.0" not in out, out

    with subtest("an unallowed host is refused by name"):
        out = client.fail(mediated("ssh other.invalid true") + " 2>&1")
        assert "not an allowed SSH endpoint" in out, out

    with subtest("a remote user the allowance does not name is refused"):
        # `agent` is the local user, which a bare `ssh server` would send.
        for target in ["root@server", "server"]:
            out = client.fail(mediated(f"ssh {target} 'echo SSH-OK'") + " 2>&1")
            assert "SSH-OK" not in out, out
            assert "is not an allowed remote user" in out, out
            assert "deploy@server:22" in out, out
  '';
}
