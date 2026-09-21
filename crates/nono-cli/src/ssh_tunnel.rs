//! `nono ssh-tunnel <host> <port>` — an HTTP `CONNECT` client for use as an
//! OpenSSH `ProxyCommand`.
//!
//! `ssh` speaks no HTTP, so it cannot reach the session proxy on its own. This
//! helper performs the CONNECT handshake against the proxy named by
//! `HTTPS_PROXY`, authenticates with `NONO_PROXY_TOKEN`, and then splices the
//! tunnel onto stdin/stdout. The proxy's allowlist, not this command, decides
//! which endpoints are reachable: a denied host comes back as `403` and exits
//! non-zero with the host named.

use crate::cli::SshTunnelArgs;
use nono::{NonoError, Result};
use tokio::io::{AsyncWriteExt, copy};

/// Address (`host:port`) of the session proxy, parsed out of the proxy URL
/// nono injects into the sandbox environment.
fn proxy_address() -> Result<String> {
    let raw = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .ok_or_else(|| {
            NonoError::ConfigParse(
                "nono ssh-tunnel: HTTPS_PROXY is not set — this command only runs inside a \
                 nono sandbox with proxy mode active"
                    .to_string(),
            )
        })?;

    let url = url::Url::parse(&raw).map_err(|err| {
        NonoError::ConfigParse(format!("nono ssh-tunnel: HTTPS_PROXY is not a URL: {err}"))
    })?;
    let host = url.host_str().ok_or_else(|| {
        NonoError::ConfigParse("nono ssh-tunnel: HTTPS_PROXY has no host".to_string())
    })?;
    let port = url.port().unwrap_or(80);
    Ok(format!("{host}:{port}"))
}

pub(crate) fn run_ssh_tunnel(args: SshTunnelArgs) -> Result<()> {
    let proxy_addr = proxy_address()?;
    let auth = std::env::var("NONO_PROXY_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .map(|token| format!("Bearer {token}"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            NonoError::ConfigParse(format!("nono ssh-tunnel: could not start runtime: {err}"))
        })?;

    runtime.block_on(tunnel(&proxy_addr, &args.host, args.port, auth.as_deref()))
}

async fn tunnel(
    proxy_addr: &str,
    host: &str,
    port: u16,
    proxy_auth_header: Option<&str>,
) -> Result<()> {
    let stream = nono_proxy::external::connect_via_proxy(proxy_addr, host, port, proxy_auth_header)
        .await
        .map_err(|err| {
            NonoError::ConfigParse(format!(
                "nono ssh-tunnel: proxy refused a connection to {host}:{port}: {err}"
            ))
        })?;

    let (mut tunnel_read, mut tunnel_write) = stream.into_split();
    let mut stdout = tokio::io::stdout();

    // The server closing is what ends the session. A closed stdin only means
    // the client has nothing more to send, so half-close the tunnel and keep
    // draining the response instead of exiting on it.
    let upstream = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = copy(&mut stdin, &mut tunnel_write).await;
        let _ = tunnel_write.shutdown().await;
    });

    let result = async {
        copy(&mut tunnel_read, &mut stdout).await?;
        stdout.flush().await
    }
    .await;

    upstream.abort();
    result.map_err(NonoError::Io)
}
