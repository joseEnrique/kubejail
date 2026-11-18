//! Byte-level forwarding. TLS is never terminated here, so kubectl verifies
//! the real API server certificate and the server sees the real client cert.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to the first reachable address of the pinned endpoint.
pub async fn connect_pinned(targets: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::other("endpoint has no addresses");
    for addr in targets {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(err)) => last = err,
            Err(_) => last = std::io::ErrorKind::TimedOut.into(),
        }
    }
    Err(last)
}

/// Host side: every connection accepted on the session listener is piped to
/// the endpoint fixed at startup. Nothing the client sends is ever
/// interpreted, so the client has no way to name another destination.
pub async fn serve_host(listener: HostListener, targets: Arc<[SocketAddr]>) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let targets = targets.clone();
        tokio::spawn(async move {
            if let Ok(upstream) = connect_pinned(&targets).await {
                pipe(client, upstream).await;
            }
        });
    }
}

/// Linux jails reach the host through a private Unix socket; macOS sandboxes
/// through a loopback TCP port that the sandbox profile singles out.
#[cfg(target_os = "linux")]
pub type HostListener = tokio::net::UnixListener;
#[cfg(target_os = "macos")]
pub type HostListener = TcpListener;

/// Jail side (Linux): loopback TCP port -> the session's Unix socket.
#[cfg(target_os = "linux")]
pub async fn serve_jail(listener: TcpListener, socket: std::path::PathBuf) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let _ = client.set_nodelay(true);
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Ok(upstream) = tokio::net::UnixStream::connect(&socket).await {
                pipe(client, upstream).await;
            }
        });
    }
}

async fn pipe<A, B>(mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _ = copy_bidirectional(&mut a, &mut b).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(target_os = "linux")]
    /// A server that answers every connection with `tag` + what it received.
    async fn tagged_echo(tag: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    s.read_to_end(&mut buf).await.unwrap();
                    s.write_all(tag.as_bytes()).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                });
            }
        });
        addr
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn chain_reaches_only_the_pinned_endpoint() {
        let pinned = tagged_echo("pinned:").await;
        let other = tagged_echo("other:").await;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let host = HostListener::bind(&socket).unwrap();
        tokio::spawn(serve_host(host, Arc::from(vec![pinned])));
        let jail = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jail_addr = jail.local_addr().unwrap();
        tokio::spawn(serve_jail(jail, socket));

        // Even a payload that looks like a proxy request for the other
        // server is just bytes delivered to the pinned one.
        let request = format!("CONNECT {other} HTTP/1.1\r\n\r\n");
        let mut client = TcpStream::connect(jail_addr).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply, format!("pinned:{request}"));
    }

    #[tokio::test]
    async fn connect_pinned_reports_unreachable_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(connect_pinned(&[addr]).await.is_err());
    }
}
