//! Fake upstreams and a tiny client for the forwarder integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browserx_egress::Forwarder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub const STEP: Duration = Duration::from_secs(5);

/// What sits behind a tunnel once the fake upstream accepted it.
#[derive(Clone, Copy, Debug)]
pub enum Origin {
    /// Echo every byte back.
    Echo,
    /// Read one request head, record it, answer `hello-world`.
    Http,
    /// Read until the peer half-closes, then answer `got <n>`.
    CountThenReply,
}

pub type Log<T> = Arc<Mutex<Vec<T>>>;

pub async fn read_until_blank_line<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        out.push(byte[0]);
    }
    out
}

pub async fn run_origin<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    origin: Origin,
    requests: &Log<String>,
) {
    match origin {
        Origin::Echo => {
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
        Origin::Http => {
            let head = read_until_blank_line(&mut s).await;
            requests
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello-world")
                .await;
            let _ = s.shutdown().await;
        }
        Origin::CountThenReply => {
            let mut total = 0usize;
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
            }
            let _ = s.write_all(format!("got {total}").as_bytes()).await;
            let _ = s.shutdown().await;
        }
    }
}

/// A plain origin server on loopback (for direct-egress tests).
pub struct OriginServer {
    pub addr: SocketAddr,
    pub requests: Log<String>,
}

impl OriginServer {
    pub async fn start(origin: Origin) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Log<String> = Arc::default();
        let log = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move { run_origin(s, origin, &log).await });
            }
        });
        Self { addr, requests }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectSeen {
    pub target: String,
    pub proxy_authorization: Option<String>,
    pub head: String,
}

#[derive(Clone)]
pub struct ConnectOpts {
    pub expect_auth: Option<String>,
    pub reject_status: Option<u16>,
    pub origin: Origin,
    /// Bytes sent in the same write as the `200` head (server-first protocols).
    pub greeting: Vec<u8>,
    pub blackhole: bool,
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            expect_auth: None,
            reject_status: None,
            origin: Origin::Echo,
            greeting: Vec::new(),
            blackhole: false,
            tls: None,
        }
    }
}

/// Fake upstream HTTP CONNECT proxy.
pub struct ConnectProxy {
    pub addr: SocketAddr,
    pub seen: Log<ConnectSeen>,
    pub origin_requests: Log<String>,
}

impl ConnectProxy {
    pub async fn start(opts: ConnectOpts) -> Self {
        let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Log<ConnectSeen> = Arc::default();
        let origin_requests: Log<String> = Arc::default();
        let (seen2, reqs2) = (Arc::clone(&seen), Arc::clone(&origin_requests));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (opts, seen, reqs) = (opts.clone(), Arc::clone(&seen2), Arc::clone(&reqs2));
                tokio::spawn(async move {
                    if let Some(cfg) = opts.tls.clone() {
                        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serve_connect(tls, opts, seen, reqs).await;
                        }
                    } else {
                        serve_connect(tcp, opts, seen, reqs).await;
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            origin_requests,
        }
    }

    pub fn url(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.addr)
    }
}

async fn serve_connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    opts: ConnectOpts,
    seen: Log<ConnectSeen>,
    reqs: Log<String>,
) {
    let head = String::from_utf8_lossy(&read_until_blank_line(&mut s).await).into_owned();
    let target = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let auth = head
        .lines()
        .find_map(|l| l.strip_prefix("Proxy-Authorization: "))
        .map(str::to_owned);
    seen.lock().unwrap().push(ConnectSeen {
        target,
        proxy_authorization: auth.clone(),
        head,
    });
    if opts.blackhole {
        tokio::time::sleep(Duration::from_secs(60)).await;
        return;
    }
    if let Some(status) = opts.reject_status {
        let _ = s
            .write_all(format!("HTTP/1.1 {status} Nope\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await;
        return;
    }
    if let Some(expected) = &opts.expect_auth
        && auth.as_deref() != Some(expected.as_str())
    {
        let _ = s
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    let mut reply = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
    reply.extend_from_slice(&opts.greeting);
    if s.write_all(&reply).await.is_err() {
        return;
    }
    run_origin(s, opts.origin, &reqs).await;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksSeen {
    pub methods: Vec<u8>,
    pub creds: Option<(String, String)>,
    pub atyp: u8,
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct SocksOpts {
    pub require_auth: Option<(String, String)>,
    pub reply: u8,
    pub origin: Origin,
}

impl Default for SocksOpts {
    fn default() -> Self {
        Self {
            require_auth: None,
            reply: 0,
            origin: Origin::Echo,
        }
    }
}

/// Fake upstream SOCKS5 proxy.
pub struct SocksProxy {
    pub addr: SocketAddr,
    pub seen: Log<SocksSeen>,
}

impl SocksProxy {
    pub async fn start(opts: SocksOpts) -> Self {
        let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Log<SocksSeen> = Arc::default();
        let seen2 = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                let (opts, seen) = (opts.clone(), Arc::clone(&seen2));
                tokio::spawn(async move { serve_socks(s, opts, seen).await });
            }
        });
        Self { addr, seen }
    }

    pub fn url(&self, scheme: &str) -> String {
        format!("{scheme}://{}", self.addr)
    }
}

async fn serve_socks(mut s: TcpStream, opts: SocksOpts, seen: Log<SocksSeen>) {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 5);
    let mut methods = vec![0u8; usize::from(hdr[1])];
    s.read_exact(&mut methods).await.unwrap();
    let mut creds = None;
    match &opts.require_auth {
        Some((user, pass)) => {
            if !methods.contains(&2) {
                let _ = s.write_all(&[5, 0xff]).await;
                return;
            }
            s.write_all(&[5, 2]).await.unwrap();
            let mut v = [0u8; 2];
            s.read_exact(&mut v).await.unwrap();
            let mut u = vec![0u8; usize::from(v[1])];
            s.read_exact(&mut u).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; usize::from(plen[0])];
            s.read_exact(&mut p).await.unwrap();
            let got = (String::from_utf8(u).unwrap(), String::from_utf8(p).unwrap());
            let ok = got == (user.clone(), pass.clone());
            creds = Some(got);
            s.write_all(&[1, u8::from(!ok)]).await.unwrap();
            if !ok {
                return;
            }
        }
        None => s.write_all(&[5, 0]).await.unwrap(),
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await.unwrap();
    assert_eq!(&req[..3], &[5, 1, 0]);
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await.unwrap();
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await.unwrap();
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut n = vec![0u8; usize::from(l[0])];
            s.read_exact(&mut n).await.unwrap();
            String::from_utf8(n).unwrap()
        }
        other => panic!("bad atyp {other}"),
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await.unwrap();
    seen.lock().unwrap().push(SocksSeen {
        methods,
        creds,
        atyp: req[3],
        host,
        port: u16::from_be_bytes(port),
    });
    s.write_all(&[5, opts.reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    if opts.reply == 0 {
        run_origin(s, opts.origin, &Arc::default()).await;
    }
}

/// Reads one response head byte by byte so nothing past it is consumed.
pub async fn read_status<S: AsyncRead + Unpin>(s: &mut S) -> (u16, String) {
    let head = timeout(STEP, read_until_blank_line(s))
        .await
        .expect("response head in time");
    let text = String::from_utf8_lossy(&head).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, text)
}

/// Sends `CONNECT authority` through the forwarder.
pub async fn connect_via(fwd: &Forwarder, authority: &str) -> (u16, TcpStream) {
    let mut s = TcpStream::connect(fwd.local_addr()).await.unwrap();
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (status, _) = read_status(&mut s).await;
    (status, s)
}

/// Sends raw bytes and reads the reply until EOF.
pub async fn exchange(fwd: &Forwarder, request: &[u8]) -> String {
    let mut s = TcpStream::connect(fwd.local_addr()).await.unwrap();
    s.write_all(request).await.unwrap();
    let mut out = Vec::new();
    timeout(STEP, s.read_to_end(&mut out))
        .await
        .expect("reply in time")
        .ok();
    String::from_utf8_lossy(&out).into_owned()
}

/// Echo round trip through an established tunnel.
pub async fn echo_roundtrip(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    timeout(STEP, s.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(got, payload);
}

pub fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}
