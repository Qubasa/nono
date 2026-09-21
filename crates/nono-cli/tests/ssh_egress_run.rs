//! Runtime enforcement tests for `network.allow_ssh`.
//!
//! The contract being pinned: an SSH allowance opens exactly one `host:port`
//! through the mediated CONNECT route, and grants no raw reachability at all.
//! A pre-change binary fails these — `allow_domain: ["h:22"]` reached `h` on
//! every port, and there was no port-exact entry to begin with.
//!
//! Linux only: the destination pin is a seccomp user-notification supervisor.

#![cfg(target_os = "linux")]

use nono_test_support::{Argv, nono_test};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

const BANNER: &[u8] = b"SSH-2.0-nono-test\r\n";

/// A listener that answers every connection with an SSH-looking banner.
///
/// Stands in for a real sshd: the CONNECT tunnel is opaque, so the banner is
/// all the test needs to prove bytes crossed it.
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

/// A Nix-store-linked binary loads its interpreter and libc from `/nix/store`,
/// which the default system paths do not cover.
fn runtime_groups() -> &'static str {
    if Path::new("/nix/store").is_dir() {
        r#""groups":{"include":["nix_runtime"]},"#
    } else {
        ""
    }
}

/// Profile granting read (and therefore execute) on the `nono` binary's own
/// directory, so the sandboxed child can run `nono ssh-tunnel`.
fn profile_json(network: &str) -> String {
    let bin_dir = nono_bin()
        .parent()
        .expect("cargo bin lives in a directory")
        .to_string_lossy()
        .into_owned();
    format!(
        concat!(
            r#"{{{groups}"meta":{{"name":"ssh-egress-test"}},"#,
            r#""workdir":{{"access":"readwrite"}},"#,
            r#""filesystem":{{"read":["{bin_dir}"]}},"network":{network}}}"#
        ),
        groups = runtime_groups(),
        bin_dir = bin_dir,
        network = network,
    )
}

/// Absolute path to a `python3` the sandbox can exec, for the raw-socket probe.
fn python3_bin() -> Option<String> {
    let mut candidates: Vec<PathBuf> = ["/usr/bin/python3", "/bin/python3"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join("python3")));
    }
    for cand in candidates {
        let Ok(cand) = std::fs::canonicalize(&cand) else {
            continue;
        };
        if std::process::Command::new(&cand)
            .args(["-c", "import socket"])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return Some(cand.to_string_lossy().into_owned());
        }
    }
    None
}

#[test]
fn ssh_allowance_reaches_the_allowed_endpoint_through_the_mediated_route() {
    let server = BannerServer::start();
    let t = nono_test!("ssh-egress-allow");
    let profile = t.write_profile(
        "ssh-allow",
        &profile_json(&format!(r#"{{"allow_ssh":["127.0.0.1:{}"]}}"#, server.port)),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new(nono_bin())
                .arg("ssh-tunnel")
                .arg("127.0.0.1")
                .arg(server.port.to_string()),
        )
        .assert_success("the allowed endpoint must be reachable through the tunnel")
        .assert_stdout_contains("SSH-2.0-nono-test");
}

#[test]
fn ssh_allowance_refuses_another_port_on_the_same_host() {
    let server = BannerServer::start();
    let other = BannerServer::start();
    let t = nono_test!("ssh-egress-port");
    let profile = t.write_profile(
        "ssh-port",
        &profile_json(&format!(r#"{{"allow_ssh":["127.0.0.1:{}"]}}"#, server.port)),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new(nono_bin())
                .arg("ssh-tunnel")
                .arg("127.0.0.1")
                .arg(other.port.to_string()),
        )
        .assert_failure("an SSH allowance must not widen to another port")
        .assert_stdout_lacks("SSH-2.0-nono-test")
        .assert_stderr_contains("127.0.0.1");
}

/// The allowance grants a mediated route, not raw reachability: a process that
/// ignores the generated config and opens its own socket is denied by the OS,
/// even for the endpoint it is allowed to reach.
#[test]
fn direct_socket_to_the_allowed_endpoint_is_denied_even_without_proxy_env() {
    let Some(py) = python3_bin() else {
        eprintln!("skipping: no usable python3 available");
        return;
    };
    let server = BannerServer::start();
    let t = nono_test!("ssh-egress-direct");
    let profile = t.write_profile(
        "ssh-direct",
        &profile_json(&format!(r#"{{"allow_ssh":["127.0.0.1:{}"]}}"#, server.port)),
    );

    let script = format!(
        "import os, socket\n\
         for k in list(os.environ):\n\
         \x20   if 'PROXY' in k.upper(): del os.environ[k]\n\
         try:\n\
         \x20   socket.create_connection(('127.0.0.1', {port}), timeout=5)\n\
         \x20   print('connected')\n\
         except PermissionError as e:\n\
         \x20   print('denied', e)\n",
        port = server.port,
    );

    t.run()
        .profile(&profile)
        .exec(Argv::new(&py).arg("-c").arg(&script))
        .assert_stdout_lacks("connected")
        .assert_stdout_contains("denied");
}

/// `allow_domain` keeps its documented host-level behaviour: the `:port`
/// suffix is stripped, every port on that host stays reachable, and the
/// "port is ignored" warning still fires.
#[test]
fn allow_domain_port_suffix_still_widens_to_every_port() {
    let server = BannerServer::start();
    let t = nono_test!("ssh-egress-allow-domain");
    let profile = t.write_profile(
        "allow-domain-port",
        // Deliberately a different port from the one actually contacted.
        &profile_json(r#"{"allow_domain":["127.0.0.1:22"]}"#),
    );

    t.run()
        .profile(&profile)
        .exec(
            Argv::new(nono_bin())
                .arg("ssh-tunnel")
                .arg("127.0.0.1")
                .arg(server.port.to_string()),
        )
        .assert_success("allow_domain must keep granting the host on every port")
        .assert_stdout_contains("SSH-2.0-nono-test")
        .assert_stderr_contains("includes a :port suffix");
}

/// The tunnel is only a client: without a proxy to speak to it must fail, not
/// fall back to a direct connection.
#[test]
fn ssh_tunnel_without_a_proxy_fails_instead_of_connecting_directly() {
    let server = BannerServer::start();
    let output = std::process::Command::new(nono_bin())
        .arg("ssh-tunnel")
        .arg("127.0.0.1")
        .arg(server.port.to_string())
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .output()
        .expect("run ssh-tunnel");

    assert!(!output.status.success(), "ssh-tunnel must fail without a proxy");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("SSH-2.0"),
        "ssh-tunnel must not reach the server directly"
    );
}

