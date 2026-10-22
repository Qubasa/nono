//! `linux.sandbox_policy = "namespace"`: the child runs in a user and network
//! namespace of its own that holds nothing but loopback.
//!
//! The supervisor stays in the network namespace it was started in, so its
//! proxy and SSH bastion keep their outbound reach while the child has none.
//! A holder process owns the namespaces and the child joins them between fork
//! and exec. `pasta --splice-only` bridges the two loopbacks: the proxy port
//! into the child, and the ports the child may listen on back out to the
//! parent's `127.0.0.1`.

use crate::child_reaper::{self, OwnedPid};
use nix::libc;
use nono::{CapabilitySet, NetworkMode, NonoError, Result};
use std::ffi::CStr;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};

const PASTA: &str = "pasta";
const POLICY: &str = "linux.sandbox_policy = \"namespace\"";

/// What crosses between the child's loopback and the parent's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Forwards {
    /// The proxy the child reaches at the same port inside its namespace.
    proxy_port: Option<u16>,
    /// `open_port`: forwarded into the child while the parent listens there,
    /// and out of it while the child does.
    open: Vec<(u16, u16)>,
    /// `listen_port`: forwarded out while the child listens there.
    listen: Vec<(u16, u16)>,
}

impl Forwards {
    /// Derive the forwards from the session's final capabilities.
    ///
    /// Refuses grants that need a route out of the namespace, which it does
    /// not have: unrestricted networking and direct `connect_port` egress.
    pub(crate) fn from_caps(caps: &CapabilitySet) -> Result<Self> {
        let (proxy_port, mut listen) = match caps.network_mode() {
            NetworkMode::AllowAll => {
                return Err(NonoError::SandboxInit(format!(
                    "{POLICY} gives the child a loopback-only network, so it cannot grant \
                     unrestricted network access. Route traffic through the proxy \
                     (network.allow_domain or network.network_profile) or block the network."
                )));
            }
            NetworkMode::Blocked => (None, Vec::new()),
            NetworkMode::ProxyOnly { port, bind_ports } => (
                Some(*port),
                bind_ports.iter().map(|&p| (p, p)).collect::<Vec<_>>(),
            ),
        };
        if !caps.tcp_connect_ports().is_empty() {
            return Err(NonoError::SandboxInit(format!(
                "{POLICY} has no route out of the child's network, so connect_port and \
                 --allow-connect-port cannot be honored. Reach those services through the proxy."
            )));
        }
        listen.extend(caps.tcp_bind_ports().iter().map(|&p| (p, p)));
        let mut open: Vec<(u16, u16)> = caps.localhost_ports().iter().map(|&p| (p, p)).collect();
        open.extend_from_slice(caps.localhost_port_ranges());
        Ok(Self {
            proxy_port,
            open: without(&nono::capability::merge_port_ranges(&open), proxy_port),
            listen: without(&nono::capability::merge_port_ranges(&listen), proxy_port),
        })
    }

    fn is_empty(&self) -> bool {
        self.proxy_port.is_none() && self.open.is_empty() && self.listen.is_empty()
    }

    /// pasta's arguments for attaching to the holder's namespaces.
    ///
    /// Every outward forward is bound on `127.0.0.1` only and only while the
    /// child actually listens (`auto`), so the child never claims a port on
    /// the parent's side that it is not serving.
    fn pasta_args(&self, holder: libc::pid_t) -> Vec<String> {
        let mut args: Vec<String> = ["--quiet", "--splice-only", "-u", "none", "-U", "none"]
            .map(String::from)
            .to_vec();
        if let Some(port) = self.proxy_port {
            args.extend(["-T".to_string(), port.to_string()]);
        }
        if !self.open.is_empty() {
            args.extend(["-T".to_string(), format!("{},auto", spec(&self.open))]);
        }
        if self.proxy_port.is_none() && self.open.is_empty() {
            args.extend(["-T".to_string(), "none".to_string()]);
        }
        let mut outward = self.open.clone();
        outward.extend_from_slice(&self.listen);
        let outward = nono::capability::merge_port_ranges(&outward);
        args.push("-t".to_string());
        if outward.is_empty() {
            args.push("none".to_string());
        } else {
            args.push(format!("127.0.0.1/{},auto", spec(&outward)));
        }
        args.push(holder.to_string());
        args
    }
}

/// `ranges` with `port` cut out, so nothing is forwarded over the proxy.
fn without(ranges: &[(u16, u16)], port: Option<u16>) -> Vec<(u16, u16)> {
    let Some(port) = port else {
        return ranges.to_vec();
    };
    let mut kept = Vec::with_capacity(ranges.len() + 1);
    for &(start, end) in ranges {
        if port < start || port > end {
            kept.push((start, end));
            continue;
        }
        if start < port {
            kept.push((start, port - 1));
        }
        if port < end {
            kept.push((port + 1, end));
        }
    }
    kept
}

fn spec(ranges: &[(u16, u16)]) -> String {
    let mut parts = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        if start == end {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{end}"));
        }
    }
    parts.join(",")
}

/// The namespace descriptors a forked child joins before it execs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NetnsFds {
    user: RawFd,
    net: RawFd,
}

impl NetnsFds {
    /// Join the namespaces. Raw syscalls only: this runs in a forked child.
    ///
    /// The user namespace first, because joining it is what grants the
    /// capability the network namespace's owner demands. Both are dropped
    /// again at execve, since the child runs as a non-root id in there.
    pub(crate) fn join(self) -> bool {
        // SAFETY: scalar arguments, descriptors owned by the live ChildNetns.
        unsafe {
            libc::syscall(libc::SYS_setns, self.user, libc::CLONE_NEWUSER) == 0
                && libc::syscall(libc::SYS_setns, self.net, libc::CLONE_NEWNET) == 0
        }
    }
}

/// The holder process and the namespaces it keeps alive for the session.
///
/// Dropping it kills the holder, and pasta exits once the holder is gone.
pub(crate) struct ChildNetns {
    holder: libc::pid_t,
    _owned: OwnedPid,
    user: OwnedFd,
    net: OwnedFd,
}

impl ChildNetns {
    /// Create the namespaces and, when anything crosses, start pasta.
    ///
    /// Must run on the thread that outlives the session: the holder dies with
    /// the thread that created it.
    pub(crate) fn start(forwards: &Forwards) -> Result<Self> {
        let holder = spawn_holder()?;
        let netns = Self {
            holder: holder.0,
            _owned: holder.1,
            user: open_ns(holder.0, "user")?,
            net: open_ns(holder.0, "net")?,
        };
        if !forwards.is_empty() {
            run_pasta(&forwards.pasta_args(netns.holder))?;
        }
        Ok(netns)
    }

    pub(crate) fn fds(&self) -> NetnsFds {
        NetnsFds {
            user: self.user.as_raw_fd(),
            net: self.net.as_raw_fd(),
        }
    }
}

impl Drop for ChildNetns {
    fn drop(&mut self) {
        // SAFETY: the holder is our registered child, so the drain never
        // reaped it and the pid cannot have been reused.
        unsafe {
            libc::kill(self.holder, libc::SIGKILL);
            libc::waitpid(self.holder, std::ptr::null_mut(), 0);
        }
    }
}

fn open_ns(holder: libc::pid_t, kind: &str) -> Result<OwnedFd> {
    let path = format!("/proc/{holder}/ns/{kind}");
    std::fs::File::open(&path)
        .map(OwnedFd::from)
        .map_err(|err| NonoError::SandboxInit(format!("{POLICY}: cannot open {path}: {err}")))
}

fn run_pasta(args: &[String]) -> Result<()> {
    let mut command = Command::new(PASTA);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = child_reaper::spawn_owned(&mut command).map_err(|err| {
        NonoError::SandboxInit(format!(
            "{POLICY} needs {PASTA} (from the passt project) on PATH to forward the proxy port \
             into the child: {err}"
        ))
    })?;
    // pasta forks into the background once its forwards are in place, so its
    // launcher exiting is the readiness signal, and the daemon has already
    // pointed its stdio at /dev/null by then.
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let status = child.wait().map_err(NonoError::Io)?;
    if status.success() {
        return Ok(());
    }
    Err(NonoError::SandboxInit(format!(
        "{POLICY}: {PASTA} could not set up the child's forwards ({status}): {}",
        stderr.trim()
    )))
}

/// Holder setup steps, reported back through the readiness pipe.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Step {
    Ready = 0,
    Parent = 1,
    Unshare = 2,
    Maps = 3,
    Loopback = 4,
}

impl Step {
    const FAILED: [Step; 4] = [Step::Parent, Step::Unshare, Step::Maps, Step::Loopback];

    fn describe(byte: u8) -> &'static str {
        let step = Self::FAILED.into_iter().find(|step| *step as u8 == byte);
        match step {
            Some(Step::Parent) => "the holder lost its parent",
            Some(Step::Unshare) => {
                "unshare(CLONE_NEWUSER | CLONE_NEWNET) failed; unprivileged user \
                 namespaces may be disabled on this host"
            }
            Some(Step::Maps) => "writing the holder's uid_map/gid_map failed",
            Some(Step::Loopback) => "bringing up the namespace's loopback failed",
            Some(Step::Ready) | None => "the holder exited before reporting",
        }
    }
}

/// The id maps, rendered before the fork so the holder never allocates.
struct Maps {
    uid: Vec<u8>,
    gid: Vec<u8>,
}

fn spawn_holder() -> Result<(libc::pid_t, OwnedPid)> {
    // SAFETY: scalar getters, cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let maps = Maps {
        uid: format!("{uid} {uid} 1\n").into_bytes(),
        gid: format!("{gid} {gid} 1\n").into_bytes(),
    };
    let mut pipe = [0 as RawFd; 2];
    // SAFETY: valid two-element buffer.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(NonoError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: pipe2 returned two fresh descriptors that nothing else owns.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    // SAFETY: getpid takes no pointers and cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: a plain fork without libc's atfork handlers. The copy only makes
    // raw syscalls on memory prepared above, then never returns.
    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
    if pid == 0 {
        holder_main(write.as_raw_fd(), parent, &maps);
    }
    if pid < 0 {
        return Err(NonoError::Io(std::io::Error::last_os_error()));
    }
    let pid = pid as libc::pid_t;
    let owned = child_reaper::own(pid as u32);
    drop(write);
    let mut status = [u8::MAX];
    let _ = std::fs::File::from(read).read_exact(&mut status);
    if status[0] == Step::Ready as u8 {
        return Ok((pid, owned));
    }
    // SAFETY: our registered child, killed and reaped exactly once here.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    Err(NonoError::SandboxInit(format!(
        "{POLICY}: {}",
        Step::describe(status[0])
    )))
}

fn holder_main(ready: RawFd, parent: libc::pid_t, maps: &Maps) -> ! {
    let step = holder_setup(parent, maps);
    // SAFETY: one byte from a live stack slot to our pipe end.
    unsafe {
        libc::syscall(libc::SYS_write, ready, &(step as u8), 1_usize);
    }
    if !matches!(step, Step::Ready) {
        exit(1);
    }
    // SAFETY: the holder needs no descriptor at all. Holding none keeps it
    // from pinning the session's terminal or a caller's output pipe.
    unsafe {
        libc::syscall(libc::SYS_close_range, 0_u32, u32::MAX, 0_u32);
    }
    loop {
        // SAFETY: blocks until a signal; SIGKILL from ChildNetns ends it.
        unsafe {
            libc::syscall(libc::SYS_pause);
        }
    }
}

fn holder_setup(parent: libc::pid_t, maps: &Maps) -> Step {
    // SAFETY: scalar syscalls. A new session keeps terminal signals such as
    // Ctrl-C from killing the holder in the middle of the session.
    unsafe {
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        ) < 0
            || libc::syscall(libc::SYS_getppid) != parent as libc::c_long
            || libc::syscall(libc::SYS_setsid) < 0
        {
            return Step::Parent;
        }
        if libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER | libc::CLONE_NEWNET) < 0 {
            return Step::Unshare;
        }
    }
    if !write_file(c"/proc/self/setgroups", b"deny")
        || !write_file(c"/proc/self/uid_map", &maps.uid)
        || !write_file(c"/proc/self/gid_map", &maps.gid)
    {
        return Step::Maps;
    }
    if !loopback_up() {
        return Step::Loopback;
    }
    Step::Ready
}

fn write_file(path: &CStr, contents: &[u8]) -> bool {
    // SAFETY: NUL-terminated path and a live buffer; raw syscalls only.
    unsafe {
        let fd = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return false;
        }
        let written = libc::syscall(libc::SYS_write, fd, contents.as_ptr(), contents.len());
        libc::syscall(libc::SYS_close, fd);
        written == contents.len() as libc::c_long
    }
}

/// `ip link set lo up`, which a fresh network namespace leaves down.
fn loopback_up() -> bool {
    // SAFETY: zeroed ifreq is valid; the name fits IFNAMSIZ with its NUL.
    unsafe {
        let mut request: libc::ifreq = std::mem::zeroed();
        for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
            *slot = *byte as libc::c_char;
        }
        let sock = libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        );
        if sock < 0 {
            return false;
        }
        let ok = libc::syscall(libc::SYS_ioctl, sock, libc::SIOCGIFFLAGS, &mut request) == 0 && {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::syscall(libc::SYS_ioctl, sock, libc::SIOCSIFFLAGS, &request) == 0
        };
        libc::syscall(libc::SYS_close, sock);
        ok
    }
}

fn exit(status: i32) -> ! {
    // SAFETY: ends only this copied process, without destructors.
    unsafe {
        libc::syscall(libc::SYS_exit_group, status);
        libc::_exit(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxied(port: u16, bind_ports: Vec<u16>) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.set_network_mode_mut(NetworkMode::ProxyOnly { port, bind_ports });
        caps
    }

    fn args(forwards: &Forwards) -> String {
        forwards.pasta_args(42).join(" ")
    }

    #[test]
    fn unrestricted_network_is_refused() {
        let err = Forwards::from_caps(&CapabilitySet::new()).expect_err("AllowAll");
        assert!(err.to_string().contains("loopback-only"), "{err}");
    }

    #[test]
    fn direct_connect_ports_are_refused() {
        let mut caps = proxied(3128, Vec::new());
        caps.add_tcp_connect_port(5432);
        let err = Forwards::from_caps(&caps).expect_err("connect_port");
        assert!(err.to_string().contains("connect_port"), "{err}");
    }

    #[test]
    fn blocked_network_forwards_nothing() {
        let caps = CapabilitySet::new().block_network();
        let forwards = Forwards::from_caps(&caps).expect("blocked");
        assert!(forwards.is_empty());
    }

    #[test]
    fn proxy_port_is_forwarded_in_and_nothing_out() {
        let forwards = Forwards::from_caps(&proxied(3128, Vec::new())).expect("proxy");
        assert_eq!(
            args(&forwards),
            "--quiet --splice-only -u none -U none -T 3128 -t none 42"
        );
    }

    #[test]
    fn listen_ports_go_out_on_loopback_without_the_proxy_port() {
        let forwards =
            Forwards::from_caps(&proxied(3128, (3000..=4000).collect())).expect("listen");
        assert_eq!(
            args(&forwards),
            "--quiet --splice-only -u none -U none -T 3128 \
             -t 127.0.0.1/3000-3127,3129-4000,auto 42"
        );
    }

    #[test]
    fn open_ports_cross_both_ways_while_bound() {
        let mut caps = proxied(3128, vec![8080]);
        caps.add_localhost_port(5432);
        let forwards = Forwards::from_caps(&caps).expect("open");
        assert_eq!(
            args(&forwards),
            "--quiet --splice-only -u none -U none -T 3128 -T 5432,auto \
             -t 127.0.0.1/5432,8080,auto 42"
        );
    }
}
