//! Runtime enforcement tests for `network.allow_ssh`.
//!
//! The contract being pinned: an SSH allowance opens exactly one `host:port`
//! through nono's own SSH bastion, and grants no raw reachability and no
//! proxy reachability at all. Everything the sandbox may do on that endpoint
//! is decided channel request by channel request in the parent.
//!
//! The mediated tests run against a real `sshd` started per test, because the
//! whole point of the bastion is that it terminates the session: a byte-pipe
//! stand-in cannot tell `exec` from a port forward, so it cannot show that
//! nono can. When no `sshd` is installed those tests skip rather than fail.
//!
//! Linux only: the destination pin is a seccomp user-notification supervisor.

#![cfg(target_os = "linux")]

use nono_test_support::{Argv, NonoTest, RunMode, Sandboxed, nono_test};
use std::fs;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BANNER: &[u8] = b"SSH-2.0-nono-test\r\n";

/// The shell used to launch everything inside the sandbox.
///
/// `nono run -- ssh …` resolves a bare `ssh` against the *host* `PATH` and so
/// execs the real binary, bypassing the generated wrapper. A shell inside the
/// sandbox resolves it against the child's `PATH`, where the wrapper dir is
/// prepended, which is the route a real agent takes.
const SHELL: &str = "/bin/sh";

/// A listener that answers every connection with an SSH-looking banner.
///
/// Not a stand-in for `sshd` any more: it is a plain reachability target for
/// the tests about the proxy allowlist and the destination pin, where what
/// matters is only whether bytes crossed.
struct BannerServer {
    port: u16,
    _thread: std::thread::JoinHandle<()>,
}

impl BannerServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = stream.write_all(BANNER);
                let _ = stream.flush();
            }
        });
        Self {
            port,
            _thread: thread,
        }
    }
}

fn nono_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nono"))
}

/// First executable named `name` on `PATH`, resolved through symlinks.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|cand| cand.is_file())
        .and_then(|cand| fs::canonicalize(cand).ok())
}

/// Record a missing prerequisite and let the caller return.
///
/// `NONO_TEST_REQUIRE_SSHD` turns every one of these into a failure. Without
/// it an image carrying no sshd package reports green for the entire subject
/// of this file.
fn skip(reason: &str) {
    assert!(
        std::env::var_os("NONO_TEST_REQUIRE_SSHD").is_none(),
        "NONO_TEST_REQUIRE_SSHD is set, so a missing prerequisite is a failure: {reason}"
    );
    eprintln!("skipping: {reason}");
}

/// A free loopback port. The listener is dropped before the caller binds, so
/// the port is only a suggestion: `spawn_sshd` waits for sshd's own pid file
/// rather than for the port to answer, because a sibling test winning the race
/// would make the port answer without sshd being there at all.
fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    listener.local_addr().expect("listener addr").port()
}

/// `$XDG_STATE_HOME` for a run that starts the bastion, as a short symlink.
///
/// The bastion's unix socket lives at
/// `$XDG_STATE_HOME/nono/sessions/ssh-<pid>-<nanos>/bastion.sock`, and
/// `NonoTest`'s state dir sits under `crates/nono-cli/target/test-artifacts/`,
/// which puts that socket path past `SUN_LEN` and fails the launch. Pointing
/// `$XDG_STATE_HOME` at a short symlink keeps the real state dir where the
/// harness wants it: `protected_state_roots()` canonicalizes, so the symlink
/// does not make `/tmp` look like the protected state root either.
struct ShortState {
    link: PathBuf,
}

impl ShortState {
    fn new(t: &NonoTest) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let link = PathBuf::from(format!("/tmp/nono-st-{}-{nanos:09}", std::process::id()));
        std::os::unix::fs::symlink(t.state(), &link).expect("a fresh name under /tmp");
        Self { link }
    }

    fn path(&self) -> &Path {
        &self.link
    }
}

impl Drop for ShortState {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.link);
    }
}

/// A short unix-socket path under `/tmp`, unique per call.
///
/// `SUN_LEN` is 108 bytes, and the harness's tempdir under
/// `crates/nono-cli/target/test-artifacts/` does not leave room for one.
fn short_socket_path(kind: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/nono-{kind}-{}-{seq}.sock",
        std::process::id()
    ))
}

/// A listening `AF_UNIX` socket that exists only to be something the sandbox
/// can try to connect to and fail.
///
/// Reading "unreachable" off a variable nobody set proves nothing: the probe
/// needs a socket that is genuinely there and genuinely out of reach.
struct DecoySocket {
    path: PathBuf,
    _listener: UnixListener,
}

impl DecoySocket {
    fn bind(kind: &str) -> Self {
        let path = short_socket_path(kind);
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("a fresh name under /tmp");
        Self {
            path,
            _listener: listener,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DecoySocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A real `ssh-agent`, optionally holding the fixture's client key.
///
/// With a key it is the default credential path, the one a user gets without
/// passing `--ssh-key`. Empty it is still useful: OpenSSH sends
/// `auth-agent-req@openssh.com` only when it has an agent to forward, so
/// without one `ssh -A` asks for nothing and a test of the refusal has nothing
/// to observe.
struct Agent {
    path: PathBuf,
    child: Child,
}

impl Agent {
    fn start(key: Option<&Path>) -> Option<Self> {
        let Some(agent) = which("ssh-agent") else {
            skip("no ssh-agent on PATH");
            return None;
        };

        let path = short_socket_path("agent");
        let _ = fs::remove_file(&path);
        let child = Command::new(agent)
            .arg("-D")
            .arg("-a")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("ssh-agent was just resolved on PATH");
        let server = Self { path, child };
        assert!(
            server.wait_for_socket(),
            "ssh-agent never bound {}",
            server.path.display()
        );

        let Some(key) = key else { return Some(server) };
        let Some(add) = which("ssh-add") else {
            skip("ssh-agent is installed but ssh-add is not");
            return None;
        };
        let status = Command::new(add)
            .arg(key)
            .env("SSH_AUTH_SOCK", &server.path)
            .env_remove("DISPLAY")
            .env_remove("SSH_ASKPASS")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("ssh-add was just resolved on PATH");
        assert!(status.success(), "ssh-add could not load the fixture key");
        Some(server)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn wait_for_socket(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.path);
    }
}

/// A real `sshd` on loopback, with generated host and client keys.
struct Sshd {
    port: u16,
    user: String,
    dir: PathBuf,
    keygen: PathBuf,
    client_key: PathBuf,
    child: Child,
}

impl Sshd {
    /// Start `sshd` and record its host key in `<home>/.ssh/known_hosts`.
    ///
    /// That file is what the bastion's outbound leg verifies against: it reads
    /// the user's own `known_hosts` and never trusts on first use, so without
    /// the entry the parent refuses to connect at all.
    fn start(t: &NonoTest) -> Option<Self> {
        let server = Self::start_untrusted(t)?;
        server.trust_host_key(t);
        Some(server)
    }

    /// The same server with nothing recorded in `known_hosts`, for the tests
    /// about a host the outbound leg has never seen.
    fn start_untrusted(t: &NonoTest) -> Option<Self> {
        let Some(sshd) = sshd_bin() else {
            skip("no sshd found on PATH, /usr/sbin or /run/current-system/sw/bin");
            return None;
        };
        let Some(keygen) = which("ssh-keygen") else {
            skip("sshd is installed but ssh-keygen is not");
            return None;
        };
        let Some(user) = remote_user() else {
            skip("neither USER nor LOGNAME is set, so no account to log in as");
            return None;
        };

        let dir = t.root().join("sshd");
        fs::create_dir_all(&dir).expect("test root is a fresh dir this test owns");
        let host_key = dir.join("host_key");
        let client_key = dir.join("client_key");
        generate_key(&keygen, &host_key);
        generate_key(&keygen, &client_key);

        let (child, port) = spawn_sshd(&sshd, &dir, &host_key);
        Some(Self {
            port,
            user,
            dir,
            keygen,
            client_key,
            child,
        })
    }

    /// Record this server's real host key for its endpoint.
    fn trust_host_key(&self, t: &NonoTest) {
        let pub_key = fs::read_to_string(self.dir.join("host_key.pub"))
            .expect("ssh-keygen wrote the public key");
        self.write_known_hosts(t, &pub_key);
    }

    /// Record a different key for this endpoint, which is what a client holds
    /// once the host it trusted has been replaced.
    fn trust_a_different_host_key(&self, t: &NonoTest) {
        let other = self.dir.join("other_host_key");
        generate_key(&self.keygen, &other);
        let pub_key = fs::read_to_string(self.dir.join("other_host_key.pub"))
            .expect("ssh-keygen wrote the public key");
        self.write_known_hosts(t, &pub_key);
    }

    fn write_known_hosts(&self, t: &NonoTest, pub_key: &str) {
        let ssh_home = t.home().join(".ssh");
        fs::create_dir_all(&ssh_home).expect("home is a fresh dir this test owns");
        fs::write(
            known_hosts_path(t),
            format!("[127.0.0.1]:{} {}\n", self.port, pub_key.trim()),
        )
        .expect("home is a fresh dir this test owns");
    }

    /// The endpoint as an allowance names it: the remote identity is nono's
    /// choice, not the client's, so it belongs in the profile.
    fn allowance(&self) -> String {
        format!("{}@127.0.0.1:{}", self.user, self.port)
    }

    /// What the sandboxed client types. It does carry a user, and that user is
    /// deliberately the same one the allowance names, so the mediated tests
    /// stay about what they are about. The substitution itself is exercised by
    /// `the_remote_identity_is_the_allowances_and_not_the_clients`.
    fn target(&self) -> String {
        format!("{}@127.0.0.1", self.user)
    }

    fn client_key(&self) -> &Path {
        &self.client_key
    }
}

/// Where the bastion's outbound leg looks for the endpoint's host key.
fn known_hosts_path(t: &NonoTest) -> PathBuf {
    t.home().join(".ssh").join("known_hosts")
}

fn generate_key(keygen: &Path, path: &Path) {
    let status = Command::new(keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "nono-test", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen was just resolved on PATH");
    assert!(status.success(), "ssh-keygen failed for {}", path.display());
}

/// How many ports to try before a failure to start stops being a lost race.
const SSHD_START_ATTEMPTS: usize = 3;

/// Start `sshd` on a free loopback port, retrying when the port was taken.
///
/// `free_port` drops its listener before sshd binds, the tests run in parallel,
/// and `BannerServer` draws from the same ephemeral range, so a sibling can
/// take the port in between. sshd then exits with "Cannot bind any address"
/// while the port still answers, to the sibling. Waiting for sshd's own pid
/// file is what separates "sshd is up" from "something is up".
fn spawn_sshd(sshd: &Path, dir: &Path, host_key: &Path) -> (Child, u16) {
    let log = dir.join("sshd.log");
    let pid_file = dir.join("sshd.pid");
    let mut attempts = String::new();
    for _ in 0..SSHD_START_ATTEMPTS {
        let port = free_port();
        let _ = fs::remove_file(&pid_file);
        let config = write_sshd_config(dir, port, host_key, &pid_file);
        let out = fs::File::create(&log).expect("sshd dir is a fresh dir this test owns");
        let err = out.try_clone().expect("a just-created file clones");
        let mut child = Command::new(sshd)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&config)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("sshd was just resolved to an existing file");
        if wait_for_sshd(&pid_file, port) {
            return (child, port);
        }
        let _ = child.kill();
        let _ = child.wait();
        attempts.push_str(&format!(
            "port {port}:\n{}\n",
            fs::read_to_string(&log).unwrap_or_default()
        ));
    }
    panic!(
        "sshd never wrote its pid file, so it never started \
         ({SSHD_START_ATTEMPTS} attempts):\n{attempts}"
    );
}

/// `StrictModes no` because the keys live under `target/`, and `UsePAM no`
/// because this sshd runs as an ordinary user. Forwarding is left enabled on
/// the server so that a refused forward is provably nono's decision and not
/// the remote's.
fn write_sshd_config(dir: &Path, port: u16, host_key: &Path, pid_file: &Path) -> PathBuf {
    let config = dir.join("sshd_config");
    fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             PidFile {pid}\n\
             StrictModes no\n\
             UsePAM no\n\
             PermitUserEnvironment no\n\
             AuthorizedKeysFile {authorized}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             AllowTcpForwarding yes\n\
             AllowAgentForwarding yes\n\
             PermitTTY yes\n\
             Subsystem sftp internal-sftp\n\
             PrintMotd no\n\
             LogLevel VERBOSE\n",
            host_key = host_key.display(),
            pid = pid_file.display(),
            authorized = dir.join("client_key.pub").display(),
        ),
    )
    .expect("sshd dir is a fresh dir this test owns");
    config
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sshd_bin() -> Option<PathBuf> {
    if let Some(path) = which("sshd") {
        return Some(path);
    }
    ["/usr/sbin/sshd", "/run/current-system/sw/bin/sshd"]
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .and_then(|path| fs::canonicalize(path).ok())
}

fn remote_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|user| !user.is_empty())
}

/// `sshd` is up when it has written its own pid file and its port answers.
fn wait_for_sshd(pid_file: &Path, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if pid_file.is_file() && port_answers(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn port_answers(port: u16) -> bool {
    let addr = (std::net::Ipv4Addr::LOCALHOST, port).into();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
        Ok(stream) => {
            let _ = stream.shutdown(Shutdown::Both);
            true
        }
        Err(_) => false,
    }
}

/// Everything the sandboxed child has to be able to exec: `nono` itself (the
/// `ProxyCommand`), the real `ssh` the generated wrapper hands off to, the
/// shell that resolves that wrapper, `python3` for the raw probes, and the
/// `git`/`sftp`/`scp` clients that ride the same mediated route.
fn read_paths() -> Vec<String> {
    let mut paths = vec![
        nono_bin()
            .parent()
            .expect("cargo bin lives in a directory")
            .to_path_buf(),
    ];
    for candidate in [
        which("ssh"),
        which("git"),
        which("sftp"),
        which("scp"),
        fs::canonicalize(SHELL).ok(),
        python3_bin().map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(dir) = candidate.parent() {
            paths.push(dir.to_path_buf());
        }
    }
    // `git` execs its subcommands out of its own libexec dir, which is not
    // where the `git` binary itself lives on most distributions.
    if let Some(exec_path) = git_exec_path() {
        paths.push(exec_path);
    }
    if Path::new("/etc/ssh").is_dir() {
        paths.push(PathBuf::from("/etc/ssh"));
    }
    let mut rendered: Vec<String> = paths
        .iter()
        .map(|path| format!("\"{}\"", path.to_string_lossy().replace('"', "\\\"")))
        .collect();
    rendered.sort();
    rendered.dedup();
    rendered
}

fn git_exec_path() -> Option<PathBuf> {
    let out = Command::new(which("git")?)
        .arg("--exec-path")
        .output()
        .ok()?;
    let path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    path.is_dir().then_some(path)
}

/// Profile granting read (and therefore execute) on everything the mediated
/// route needs to run.
fn profile_json(network: &str) -> String {
    profile_json_with("", network)
}

fn profile_json_with(linux: &str, network: &str) -> String {
    format!(
        concat!(
            r#"{{{groups}"meta":{{"name":"ssh-egress-test"}},{linux}"#,
            r#""workdir":{{"access":"readwrite"}},"#,
            r#""filesystem":{{"read":[{reads}]}},"network":{network}}}"#
        ),
        groups = nono_test_support::nix_runtime_groups(),
        linux = linux,
        reads = read_paths().join(","),
        network = network,
    )
}

/// Absolute path to a `python3` the sandbox can exec, for the raw probes.
fn python3_bin() -> Option<String> {
    let mut candidates: Vec<PathBuf> = ["/usr/bin/python3", "/bin/python3"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join("python3")));
    }
    for cand in candidates {
        let Ok(cand) = fs::canonicalize(&cand) else {
            continue;
        };
        if Command::new(&cand)
            .args(["-c", "import socket"])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return Some(cand.to_string_lossy().into_owned());
        }
    }
    None
}

/// A `nono run` that can start the bastion and authenticate with the fixture's
/// key. `--ssh-key` is read in the parent, so nothing about it is granted.
fn mediated<'t>(t: &'t NonoTest, state: &ShortState, sshd: &Sshd) -> Sandboxed<'t, RunMode> {
    t.run()
        .env("XDG_STATE_HOME", state.path())
        .env("NONO_SSH_KEY", sshd.client_key())
}

fn shell(cmdline: &str) -> Argv {
    Argv::new(SHELL).arg("-c").arg(cmdline)
}

/// Paired with an `allow_domain` entry, so the allowlist is closed and the
/// allowance is the only thing that could possibly grant the endpoint.
fn filtered_profile(endpoint: &str) -> String {
    profile_json(&format!(
        r#"{{"allow_domain":["example.invalid"],"allow_ssh":["{endpoint}"]}}"#
    ))
}

/// The same, restricted to an explicit command list.
fn restricted_profile(endpoint: &str, commands: &str) -> String {
    profile_json(&format!(
        r#"{{"allow_domain":["example.invalid"],"allow_ssh":[{{"endpoint":"{endpoint}","commands":[{commands}]}}]}}"#
    ))
}

/// No `allow_domain`: an open policy, where the port pin is the only thing
/// that can refuse anything.
fn open_profile(port: u16) -> String {
    profile_json(&format!(r#"{{"allow_ssh":["127.0.0.1:{port}"]}}"#))
}

/// Speak raw HTTP CONNECT to the proxy nono put in the child's environment.
fn connect_probe(host: &str, port: u16) -> String {
    const SCRIPT: &str = r#"
import base64, os, socket
from urllib.parse import urlsplit

proxy = (
    os.environ.get("HTTPS_PROXY")
    or os.environ.get("https_proxy")
    or os.environ.get("HTTP_PROXY")
    or os.environ.get("http_proxy")
)
url = urlsplit(proxy)
headers = b""
if url.username:
    token = base64.b64encode((url.username + ":" + (url.password or "")).encode()).decode()
    headers = ("Proxy-Authorization: Basic " + token + "\r\n").encode()
sock = socket.create_connection((url.hostname, url.port), timeout=10)
target = "@HOST@:@PORT@".encode()
sock.sendall(b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n" + headers + b"\r\n")
reply = sock.recv(512)
status = reply.split(b"\r\n")[0].decode("utf-8", "replace")
print("STATUS", status)
if " 200 " in status:
    # The tunnelled bytes can arrive in the same read as the CONNECT
    # response, so the payload starts at whatever followed the headers.
    body = reply.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in reply else b""
    sock.settimeout(10)
    while len(body) < len(b"SSH-2.0-nono-test"):
        try:
            chunk = sock.recv(64)
        except OSError:
            break
        if not chunk:
            break
        body += chunk
    print("PAYLOAD", body.decode("utf-8", "replace").strip())
"#;
    SCRIPT
        .replace("@HOST@", host)
        .replace("@PORT@", &port.to_string())
}

/// Open a socket directly, with every proxy variable removed first.
fn direct_socket_probe(host: &str, port: u16) -> String {
    const SCRIPT: &str = r#"
import os, socket

for name in list(os.environ):
    if "PROXY" in name.upper():
        del os.environ[name]
try:
    sock = socket.create_connection(("@HOST@", @PORT@), timeout=5)
    print("connected", sock.recv(32))
except PermissionError as err:
    print("denied", err)
"#;
    SCRIPT
        .replace("@HOST@", host)
        .replace("@PORT@", &port.to_string())
}

/// The hole this pin closes: on an open policy the allowance must still be an
/// allowance, not a decoration. `localhost` is the same machine on the same
/// pinned port, and is still refused, because the pin closes that port
/// everywhere.
#[test]
fn ssh_pin_refuses_another_host_on_an_open_policy() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-pin");
    let state = ShortState::new(&t);
    let profile = t.write_profile("ssh-pin", &open_profile(server.port));

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("localhost", server.port)),
        )
        .assert_stdout_contains("403")
        .assert_stdout_lacks("SSH-2.0-nono-test");
}

/// The other half of the same contract: the pin closes its port, not the box.
/// A second endpoint on an unpinned port stays reachable on an open policy.
#[test]
fn ssh_pin_leaves_other_ports_open_on_an_open_policy() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let other = BannerServer::start();
    let t = nono_test!("ssh-open");
    let state = ShortState::new(&t);
    let profile = t.write_profile("ssh-open", &open_profile(server.port));

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("127.0.0.1", other.port)),
        )
        .assert_stdout_contains("200")
        .assert_stdout_contains("SSH-2.0-nono-test");
}

/// The allowance is not a proxy allowlist entry any more. Reaching the
/// endpoint is the bastion's job, and a CONNECT for it is refused like any
/// other host the allowlist does not name.
#[test]
fn connect_to_the_allowed_endpoint_through_the_proxy_is_refused() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-connect");
    let state = ShortState::new(&t);
    let endpoint = format!("127.0.0.1:{}", server.port);
    let profile = t.write_profile("ssh-connect", &filtered_profile(&endpoint));

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("127.0.0.1", server.port)),
        )
        .assert_stdout_contains("403")
        .assert_stdout_lacks("SSH-2.0-nono-test");
}

/// The regression this suite previously could not see. The pin used to exempt
/// its own authority, so the endpoint stayed reachable as raw TCP wherever the
/// allowlist did not independently refuse it. On an open policy the allowlist
/// refuses nothing, so the allowance handed the sandbox exactly the
/// byte-transparent tunnel the bastion exists to take away. The pinned port
/// must be shut on the endpoint itself, not only on every other host.
#[test]
fn connect_to_the_allowed_endpoint_is_refused_on_an_open_policy() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-connect-open");
    let state = ShortState::new(&t);
    let profile = t.write_profile("ssh-connect-open", &open_profile(server.port));

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("127.0.0.1", server.port)),
        )
        .assert_stdout_contains("403")
        .assert_stdout_lacks("SSH-2.0-nono-test");
}

/// The same hole reached from the other side: an `allow_domain` entry naming
/// the endpoint's own host must not buy back the pinned port. The pin is
/// evaluated before the allowlist precisely so a domain allowance cannot
/// reopen it.
#[test]
fn an_allow_domain_for_the_endpoint_does_not_reopen_the_pinned_port() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-connect-domain");
    let state = ShortState::new(&t);
    let profile = t.write_profile(
        "ssh-connect-domain",
        &profile_json(&format!(
            r#"{{"allow_domain":["127.0.0.1"],"allow_ssh":["127.0.0.1:{}"]}}"#,
            server.port
        )),
    );

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("127.0.0.1", server.port)),
        )
        .assert_stdout_contains("403")
        .assert_stdout_lacks("SSH-2.0-nono-test");
}

/// The mediated route end to end: a real remote command runs on a real sshd
/// and its output comes back.
#[test]
fn ssh_allowance_reaches_the_allowed_endpoint_through_the_mediated_route() {
    let t = nono_test!("ssh-allow");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-allow", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo remote-command-ran'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("the allowed endpoint must be reachable through the mediation")
        .assert_stdout_contains("remote-command-ran");
}

/// The remote exit status is the local exit status, which is what makes the
/// mediation usable in a script at all.
#[test]
fn a_remote_command_exiting_seven_exits_seven_locally() {
    let t = nono_test!("ssh-exit");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-exit", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'exit 7'",
            sshd.port,
            sshd.target()
        )))
        .assert_exit_code(7, "a relayed exit status must arrive unchanged");
}

/// The two streams stay two streams: `extended_data` is relayed as
/// `extended_data`, not folded into the data channel.
#[test]
fn remote_stderr_arrives_on_stderr_and_not_on_stdout() {
    let t = nono_test!("ssh-streams");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-streams", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo out-marker; echo err-marker 1>&2'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("a command writing to both streams must still succeed")
        .assert_stdout_contains("out-marker")
        .assert_stdout_lacks("err-marker")
        .assert_stderr_contains("err-marker");
}

/// `-L` does not work from inside the sandbox.
///
/// The listener bind is refused by the destination pin before OpenSSH ever
/// asks for a channel, so this pins the outcome a user sees rather than the
/// bastion rule; the bastion's own `direct-tcpip` refusal is pinned by the
/// ProxyJump test, which reaches it deterministically.
#[test]
fn local_port_forwarding_is_refused() {
    let t = nono_test!("ssh-lfwd");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-lfwd", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -o ExitOnForwardFailure=yes -L 9999:127.0.0.1:1 -p {} {} 'echo forwarded'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a local forward must not be established from inside the sandbox")
        .assert_stdout_lacks("forwarded")
        .assert_stderr_contains("local forwarding");
}

/// `-R` asks the remote host to listen and hand connections back. The bastion
/// refuses the global request by name, and `ExitOnForwardFailure` turns that
/// into a non-zero exit instead of a warning.
#[test]
fn remote_port_forwarding_is_refused() {
    let t = nono_test!("ssh-rfwd");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-rfwd", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -o ExitOnForwardFailure=yes -R 9999:127.0.0.1:1 -p {} {} 'echo forwarded'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a remote forward must be refused")
        .assert_stdout_lacks("forwarded")
        .assert_stderr_contains("tcpip-forward");
}

/// `-J` turns the allowed endpoint into a transport to a second host. That is
/// a `direct-tcpip` channel, and the bastion refuses it by name.
#[test]
fn proxy_jump_through_the_allowed_endpoint_is_refused() {
    let t = nono_test!("ssh-jump");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-jump", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -J {target}:{port} -p {port} {user}@127.0.0.2 'echo jumped'",
            target = sshd.target(),
            port = sshd.port,
            user = sshd.user,
        )))
        .assert_failure("the allowed endpoint must not become a jump host")
        .assert_stdout_lacks("jumped")
        .assert_stderr_contains("direct-tcpip");
}

/// `-A` asks for the agent to be forwarded. It is refused, so the remote side
/// has no agent to use: the credential nono signs with never leaves the
/// parent, and offering it to the remote host would make it a signing oracle.
///
/// `agent=none` alone would not prove that. It is equally true when the client
/// never asked, which is in fact what a plain `ssh -A` does here: the
/// generated config sets `IdentityAgent none`, so OpenSSH decides it has no
/// agent to forward and sends nothing. A sandboxed process can override that
/// on its own command line, which is the case worth pinning, so the test does
/// exactly that and then asks the bastion to say no by name.
#[test]
fn agent_forwarding_leaves_no_agent_on_the_remote_side() {
    let t = nono_test!("ssh-agent");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let Some(agent) = Agent::start(None) else {
        return;
    };
    let profile = t.write_profile("ssh-agent", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .env("SSH_AUTH_SOCK", agent.path())
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -o IdentityAgent=\"$SSH_AUTH_SOCK\" -A -p {} {} \
             'echo agent=${{SSH_AUTH_SOCK:-none}}'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("refusing agent forwarding must not break the session")
        .assert_stderr_contains("auth-agent-req@openssh.com")
        .assert_stdout_contains("agent=none");
}

/// The pin names an authority. A second name for the same machine on the same
/// port is a different authority, and the relay refuses it before dialling.
#[test]
fn a_second_host_on_the_pinned_port_is_refused() {
    let t = nono_test!("ssh-host");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-host", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {}@localhost 'echo reached-second-host'",
            sshd.port, sshd.user
        )))
        .assert_failure("a second host on the pinned port must be refused")
        .assert_stdout_lacks("reached-second-host")
        .assert_stderr_contains("is not an allowed SSH endpoint");
}

/// An SSH allowance is port-exact: the same host on another port is a
/// different endpoint and no allowance covers it.
#[test]
fn ssh_allowance_refuses_another_port_on_the_same_host() {
    let other = BannerServer::start();
    let t = nono_test!("ssh-port");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-port", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo reached-other-port'",
            other.port,
            sshd.target()
        )))
        .assert_failure("an SSH allowance must not widen to another port")
        .assert_stdout_lacks("reached-other-port")
        .assert_stderr_contains(&format!("127.0.0.1:{}", other.port));
}

/// The allowance grants a mediated route, not raw reachability: a process that
/// ignores the generated config and opens its own socket is denied by the OS,
/// even for the endpoint it is allowed to reach.
#[test]
fn direct_socket_to_the_allowed_endpoint_is_denied_even_without_proxy_env() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let t = nono_test!("ssh-direct");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-direct", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(direct_socket_probe("127.0.0.1", sshd.port)),
        )
        .assert_stdout_lacks("connected")
        .assert_stdout_contains("denied");
}

/// `allow_domain` keeps its documented host-level behaviour: the `:port`
/// suffix is stripped, every port on that host stays reachable, and the
/// "port is ignored" warning still fires.
#[test]
fn allow_domain_port_suffix_still_widens_to_every_port() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-allow-domain");
    let profile = t.write_profile(
        "allow-domain-port",
        // Deliberately a different port from the one actually contacted.
        &profile_json(r#"{"allow_domain":["127.0.0.1:22"]}"#),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new(&py)
                .arg("-c")
                .arg(connect_probe("127.0.0.1", server.port)),
        )
        .assert_stdout_contains("200")
        .assert_stdout_contains("SSH-2.0-nono-test")
        .assert_stderr_contains("includes a :port suffix");
}

/// A restricted endpoint runs exactly what its allowance names.
#[test]
fn a_restricted_endpoint_runs_the_named_command() {
    let t = nono_test!("ssh-cmd-ok");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-cmd-ok",
        &restricted_profile(&sshd.allowance(), r#""echo allowed-command""#),
    );

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo allowed-command'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("the named command must run")
        .assert_stdout_contains("allowed-command");
}

/// A different command never reaches the remote host: the refusal is nono's,
/// so the command produces no output and the failure is not a remote status.
#[test]
fn a_restricted_endpoint_refuses_a_different_command() {
    let t = nono_test!("ssh-cmd-other");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-cmd-other",
        &restricted_profile(&sshd.allowance(), r#""echo allowed-command""#),
    );

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo a-different-command'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a command the allowance does not name must be refused")
        .assert_stdout_lacks("a-different-command")
        .assert_stderr_contains("network.allow_ssh refused the remote command");
}

/// Matching is whole-argv: an extra argument is a different command.
#[test]
fn a_restricted_endpoint_refuses_the_named_command_with_an_extra_argument() {
    let t = nono_test!("ssh-cmd-extra");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-cmd-extra",
        &restricted_profile(&sshd.allowance(), r#""echo allowed-command""#),
    );

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo allowed-command extra-argument'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("an extra argument makes it a different command")
        .assert_stdout_lacks("allowed-command extra-argument")
        .assert_stderr_contains("network.allow_ssh refused the remote command");
}

/// No command at all is a shell, which is precisely what a command list
/// excludes.
#[test]
fn a_restricted_endpoint_refuses_a_session_with_no_command() {
    let t = nono_test!("ssh-cmd-shell");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-cmd-shell",
        &restricted_profile(&sshd.allowance(), r#""echo allowed-command""#),
    );

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -T -p {} {} < /dev/null",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a restricted endpoint must not give out a shell")
        .assert_stderr_contains("shell is refused");
}

/// The credential stays outside. During a session that succeeds, the sandbox
/// can reach neither the host's agent nor the key file nono authenticated
/// with.
///
/// `af_unix_mediation` is on because AF_UNIX is unmediated by default in
/// proxy-only mode, so without it the agent socket is reachable for reasons
/// that have nothing to do with `allow_ssh`.
///
/// The agent socket is this test's own: a real listening `AF_UNIX` socket
/// named by `SSH_AUTH_SOCK`, so the probe has something to fail to connect to.
/// Reading `agent=unreachable` off an unset variable would pass whether or not
/// the mediation does anything at all, which is why a missing variable is a
/// failure here and not a pass.
#[test]
fn a_mediated_session_leaves_no_credential_reachable_in_the_sandbox() {
    let Some(py) = python3_bin() else {
        skip("no usable python3 available");
        return;
    };
    let t = nono_test!("ssh-contain");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let agent = DecoySocket::bind("agent");
    let profile = t.write_profile(
        "ssh-contain",
        &profile_json_with(
            r#""linux":{"af_unix_mediation":"pathname"},"#,
            &format!(
                r#"{{"allow_domain":["example.invalid"],"allow_ssh":["{}"]}}"#,
                sshd.allowance()
            ),
        ),
    );

    const PROBE: &str = r#"
import os, socket

agent = os.environ.get("SSH_AUTH_SOCK")
if not agent:
    print("agent=no-env")
else:
    try:
        socket.socket(socket.AF_UNIX).connect(agent)
        print("agent=reachable")
    except OSError:
        print("agent=unreachable")
try:
    open("@KEY@", "rb").read()
    print("key=readable")
except OSError:
    print("key=unreadable")
"#;
    let probe = PROBE.replace("@KEY@", &sshd.client_key().to_string_lossy());

    mediated(&t, &state, &sshd)
        .env("SSH_AUTH_SOCK", agent.path())
        .profile(&profile)
        .exec(shell(&format!(
            "{py} -c '{probe}' && ssh -p {port} {target} \"echo mediated-ok\"",
            port = sshd.port,
            target = sshd.target(),
        )))
        .assert_success("the session must still work with nothing granted")
        .assert_stdout_contains("mediated-ok")
        .assert_stdout_contains("agent=unreachable")
        .assert_stdout_lacks("agent=no-env")
        .assert_stdout_contains("key=unreadable");
}

/// The relay is only a client: without a bastion to speak to it must fail, and
/// say which variable was missing, not fall back to a direct connection.
#[test]
fn ssh_relay_without_a_bastion_fails_instead_of_connecting_directly() {
    let server = BannerServer::start();
    let output = Command::new(nono_bin())
        .arg("ssh-relay")
        .arg("127.0.0.1")
        .arg(server.port.to_string())
        .env_remove("NONO_SSH_BASTION")
        .output()
        .expect("run ssh-relay");

    assert!(
        !output.status.success(),
        "ssh-relay must fail with no bastion socket named"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("SSH-2.0"),
        "ssh-relay must not reach the server directly"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("NONO_SSH_BASTION"),
        "the failure must name the variable that was missing, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The remote identity is the allowance's and the sandbox cannot choose
/// another one. Every other mediated test names the same user on both sides,
/// where the substitution is unobservable, so this is the only place the
/// headline behaviour of the change is actually exercised.
#[test]
fn the_remote_identity_is_the_allowances_and_not_the_clients() {
    let t = nono_test!("ssh-user");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-user", &filtered_profile(&sshd.allowance()));

    let completed = mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} root@127.0.0.1 'id -un'",
            sshd.port
        )))
        .assert_success("asking for another remote user must not break the session")
        .assert_stdout_contains(&sshd.user);
    if sshd.user != "root" {
        completed.assert_stdout_lacks("root");
    }
}

/// The metacharacter refusal is covered as a pure function and never on the
/// wire, so a regression that ran `exec` before authorizing would pass the
/// whole unit suite. The spec's claim is that neither command runs, and only a
/// runtime test can make it: the marker is what the second command would
/// leave behind.
#[test]
fn a_command_carrying_a_metacharacter_runs_nothing_on_the_remote_host() {
    let t = nono_test!("ssh-meta");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-meta",
        &restricted_profile(&sshd.allowance(), r#""echo allowed-command""#),
    );
    let marker = t.root().join("metacharacter-marker");

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {port} {target} 'echo allowed-command; touch {marker}'",
            port = sshd.port,
            target = sshd.target(),
            marker = marker.display(),
        )))
        .assert_failure("a command carrying a separator must be refused")
        .assert_stdout_lacks("allowed-command")
        .assert_stderr_contains("shell metacharacter");

    assert!(
        !marker.exists(),
        "the command after the separator ran: {} exists",
        marker.display()
    );
}

/// OpenSSH's Git integration quotes the repository path and a plain
/// `ssh host cmd` does not. Tokenising both sides is what makes those the same
/// rule, and until now that only held for a pure function.
#[test]
fn a_quoted_argument_matches_the_unquoted_rule_on_the_wire() {
    let t = nono_test!("ssh-quote");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile(
        "ssh-quote",
        &restricted_profile(&sshd.allowance(), r#""echo /srv/repo.git""#),
    );

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {port} {target} \"echo '/srv/repo.git'\"",
            port = sshd.port,
            target = sshd.target(),
        )))
        .assert_success("a quoted argument is the same argument")
        .assert_stdout_contains("/srv/repo.git");
}

/// The outbound leg never trusts on first use, and never records a key on the
/// sandbox's behalf. Both refusal paths are otherwise dead to this suite,
/// because the fixture always writes `known_hosts`.
#[test]
fn an_unknown_host_key_is_refused_without_recording_it() {
    let t = nono_test!("ssh-unknown-key");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start_untrusted(&t) else {
        return;
    };
    let profile = t.write_profile("ssh-unknown-key", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo reached-unknown-host'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a host key nobody recorded must not be trusted on first use")
        .assert_stdout_lacks("reached-unknown-host")
        .assert_stderr_contains("does not trust a host key on first use");

    assert!(
        !known_hosts_path(&t).exists(),
        "the refusal must leave the store alone, but {} was written",
        known_hosts_path(&t).display()
    );
}

/// A host presenting a key other than the recorded one is the case the whole
/// check exists for, and the message has to say which endpoint changed.
#[test]
fn a_changed_host_key_is_refused_and_names_the_endpoint() {
    let t = nono_test!("ssh-changed-key");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start_untrusted(&t) else {
        return;
    };
    sshd.trust_a_different_host_key(&t);
    let recorded = fs::read_to_string(known_hosts_path(&t)).expect("the fixture just wrote it");
    let profile = t.write_profile("ssh-changed-key", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo reached-changed-host'",
            sshd.port,
            sshd.target()
        )))
        .assert_failure("a key that differs from the recorded one must be refused")
        .assert_stdout_lacks("reached-changed-host")
        .assert_stderr_contains(&format!("127.0.0.1:{}", sshd.port))
        .assert_stderr_contains("differs from the one recorded");

    assert_eq!(
        fs::read_to_string(known_hosts_path(&t)).expect("the store is still there"),
        recorded,
        "a refusal must not rewrite the store"
    );
}

/// The default credential path. Every other mediated test sets
/// `NONO_SSH_KEY`, so `authenticate_with_agent` has no coverage at all
/// otherwise, and it is the one a user gets without passing a flag.
#[test]
fn an_agent_backed_credential_authenticates_the_outbound_leg() {
    let t = nono_test!("ssh-agent-auth");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let Some(agent) = Agent::start(Some(sshd.client_key())) else {
        return;
    };
    let profile = t.write_profile("ssh-agent-auth", &filtered_profile(&sshd.allowance()));

    t.run()
        .env("XDG_STATE_HOME", state.path())
        .env("SSH_AUTH_SOCK", agent.path())
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -p {} {} 'echo agent-auth-ok'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("the host's agent must be able to authenticate the outbound leg")
        .assert_stdout_contains("agent-auth-ok");
}

/// `pty-req` and `window-change` are exercised nowhere outside the pure policy
/// function. A forced pty is the cheap half: `stty size` needs a terminal to
/// answer at all, so an unrelayed `pty-req` shows up as a failure here.
#[test]
fn an_interactive_pty_reports_a_terminal_size() {
    let t = nono_test!("ssh-pty");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-pty", &filtered_profile(&sshd.allowance()));

    let completed = mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "ssh -tt -p {} {} 'stty size'",
            sshd.port,
            sshd.target()
        )))
        .assert_success("a forced pty must be relayed to the remote host");

    let stdout = completed.stdout();
    assert!(
        stdout.lines().any(is_terminal_size),
        "stty size must report rows and columns, got: {stdout}"
    );
}

/// `stty size` prints exactly two integers, and under a pty the line ends CRLF.
fn is_terminal_size(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let rows = fields.next().and_then(|f| f.parse::<u32>().ok());
    let columns = fields.next().and_then(|f| f.parse::<u32>().ok());
    matches!((rows, columns, fields.next()), (Some(_), Some(_), None))
}

/// `sftp` is a `subsystem` request, which is the one thing in the default
/// policy that is neither a shell nor a command, and the networking page
/// promises users it keeps working.
#[test]
fn sftp_runs_as_a_subsystem_over_the_mediated_route() {
    let Some(sftp) = which("sftp") else {
        skip("no sftp client on PATH");
        return;
    };
    let t = nono_test!("ssh-sftp");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-sftp", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .profile(&profile)
        .exec(shell(&format!(
            "echo pwd | {sftp} -S \"$(command -v ssh)\" -b - -P {port} {target}",
            sftp = sftp.display(),
            port = sshd.port,
            target = sshd.target(),
        )))
        .assert_success("a file-transfer subsystem must run over the mediated route")
        .assert_stdout_contains("Remote working directory");
}

/// `scp` is the other client the networking page promises keeps working, and
/// it is the one that actually moves bytes rather than just listing.
#[test]
fn scp_copies_a_file_over_the_mediated_route() {
    let Some(scp) = which("scp") else {
        skip("no scp client on PATH");
        return;
    };
    let t = nono_test!("ssh-scp");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let profile = t.write_profile("ssh-scp", &filtered_profile(&sshd.allowance()));
    let source = t.root().join("scp-source.txt");
    fs::write(&source, "copied-content\n").expect("test root is a fresh dir this test owns");

    mediated(&t, &state, &sshd)
        .allow_cwd()
        .profile(&profile)
        .exec(shell(&format!(
            "{scp} -S \"$(command -v ssh)\" -P {port} {target}:{source} fetched.txt \
             && cat fetched.txt",
            scp = scp.display(),
            port = sshd.port,
            target = sshd.target(),
            source = source.display(),
        )))
        .assert_success("scp must move bytes over the mediated route")
        .assert_stdout_contains("copied-content");
}

/// A clone over SSH is the reason the mediation exists. It also proves the
/// generated `GIT_SSH_COMMAND` wiring end to end, which no other test does.
#[test]
fn git_clones_over_the_mediated_route() {
    let t = nono_test!("ssh-git");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let Some(origin) = bare_repo_with_a_commit(&t) else {
        return;
    };
    let profile = t.write_profile("ssh-git", &filtered_profile(&sshd.allowance()));

    mediated(&t, &state, &sshd)
        .allow_cwd()
        .profile(&profile)
        .exec(shell(&format!(
            "{env} git clone -q {url} cloned && cat cloned/file.txt",
            env = GIT_NO_CONFIG,
            url = ssh_url(&sshd, &origin),
        )))
        .assert_success("a clone over the mediated route must succeed")
        .assert_stdout_contains("committed-content");
}

/// The command allowlist's headline example. `git-upload-pack <path>` is the
/// one case where OpenSSH's quoting has to survive tokenisation on the wire,
/// and listing only it must leave `git push` refused.
#[test]
fn a_command_list_naming_upload_pack_allows_a_clone_and_refuses_a_push() {
    let t = nono_test!("ssh-git-acl");
    let state = ShortState::new(&t);
    let Some(sshd) = Sshd::start(&t) else { return };
    let Some(origin) = bare_repo_with_a_commit(&t) else {
        return;
    };
    let profile = t.write_profile(
        "ssh-git-acl",
        &restricted_profile(
            &sshd.allowance(),
            &format!(r#""git-upload-pack {}""#, origin.display()),
        ),
    );

    mediated(&t, &state, &sshd)
        .allow_cwd()
        .profile(&profile)
        .exec(shell(&format!(
            "{env} git clone -q {url} cloned && echo clone-ok && cd cloned && \
             {env} git -c user.email=nono@test -c user.name=nono commit -q --allow-empty \
             -m pushed && {env} git push -q origin HEAD:main",
            env = GIT_NO_CONFIG,
            url = ssh_url(&sshd, &origin),
        )))
        .assert_failure("a push runs git-receive-pack, which the list does not name")
        .assert_stdout_contains("clone-ok")
        .assert_stderr_contains("network.allow_ssh refused the remote command")
        .assert_stderr_contains("git-receive-pack");
}

/// Git reads `~/.gitconfig` and `/etc/gitconfig`, neither of which the test
/// profile grants. Pointing both at `/dev/null` keeps the test about SSH.
const GIT_NO_CONFIG: &str = "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null";

fn ssh_url(sshd: &Sshd, repo: &Path) -> String {
    format!(
        "ssh://{}@127.0.0.1:{}{}",
        sshd.user,
        sshd.port,
        repo.display()
    )
}

/// A bare repository with one commit, built outside the sandbox, for the
/// mediated clone to fetch.
fn bare_repo_with_a_commit(t: &NonoTest) -> Option<PathBuf> {
    let Some(git) = which("git") else {
        skip("no git on PATH");
        return None;
    };
    let work = t.root().join("origin-work");
    let repo = t.root().join("origin.git");
    fs::create_dir_all(&work).expect("test root is a fresh dir this test owns");
    run_git(&git, &work, &["init", "-q", "-b", "main"]);
    fs::write(work.join("file.txt"), "committed-content\n")
        .expect("the work tree is a fresh dir this test owns");
    run_git(&git, &work, &["add", "file.txt"]);
    run_git(
        &git,
        &work,
        &[
            "-c",
            "user.email=nono@test",
            "-c",
            "user.name=nono",
            "commit",
            "-q",
            "-m",
            "first",
        ],
    );
    run_git(
        &git,
        t.root(),
        &[
            "clone",
            "-q",
            "--bare",
            &work.to_string_lossy(),
            &repo.to_string_lossy(),
        ],
    );
    Some(repo)
}

fn run_git(git: &Path, cwd: &Path, args: &[&str]) {
    let status = Command::new(git)
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("git was just resolved on PATH");
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}
