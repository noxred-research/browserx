//! Establishing a byte tunnel to a destination: directly, through an upstream
//! HTTP(S) proxy with `CONNECT`, or through an upstream SOCKS5 proxy.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserx_core::{Error, ProxyRoute, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;
use zeroize::Zeroizing;

use crate::http::{HeadError, Host, parse_status, read_head};
use crate::policy::{CompiledPolicy, Verdict};

/// Any duplex byte stream.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;

/// A connected tunnel and any bytes the upstream sent right after the handshake.
pub(crate) struct Tunnel {
    pub(crate) io: BoxIo,
    pub(crate) leftover: Vec<u8>,
}

/// Why a tunnel could not be established.
#[derive(Debug)]
pub(crate) enum DialError {
    /// Blocked by the destination policy.
    Refused(String),
    /// The destination (or the upstream proxy) could not be reached.
    Unreachable(String),
    /// The upstream proxy answered but refused or broke the protocol.
    Upstream(String),
    /// The whole attempt exceeded its time budget.
    Timeout,
}

/// What a client is told when the upstream proxy cannot be used, whatever the cause.
const UPSTREAM_UNAVAILABLE: &str = "upstream proxy is unavailable";

enum Kind {
    Direct,
    Http {
        tls: Option<(TlsConnector, ServerName<'static>)>,
    },
    Socks5 {
        remote_dns: bool,
    },
}

/// The configured egress path with credentials rendered for this session.
pub(crate) struct Route {
    kind: Kind,
    proxy_host: String,
    proxy_port: u16,
    /// `Basic ...` header value for HTTP upstreams.
    basic: Option<Zeroizing<String>>,
    /// Username/password for SOCKS5 sub-negotiation.
    socks_auth: Option<(Zeroizing<String>, Zeroizing<String>)>,
    max_head: usize,
}

impl Route {
    pub(crate) fn direct(max_head: usize) -> Self {
        Self {
            kind: Kind::Direct,
            proxy_host: String::new(),
            proxy_port: 0,
            basic: None,
            socks_auth: None,
            max_head,
        }
    }

    pub(crate) fn from_proxy(
        route: &ProxyRoute,
        sticky_key: &str,
        generation: u64,
        extra_root_pem: Option<&str>,
        max_head: usize,
    ) -> Result<Self> {
        route.validate()?;
        let url = Url::parse(&route.url)
            .map_err(|e| Error::InvalidRequest(format!("invalid proxy url: {e}")))?;
        let host = url
            .host_str()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_owned())
            .filter(|h| !h.is_empty())
            .ok_or_else(|| Error::InvalidRequest("proxy url has no host".into()))?;
        let scheme = url.scheme().to_ascii_lowercase();
        let (port, kind) = match scheme.as_str() {
            "http" => (
                url.port_or_known_default().unwrap_or(80),
                Kind::Http { tls: None },
            ),
            "https" => {
                let name = ServerName::try_from(host.clone()).map_err(|_| {
                    Error::InvalidRequest("proxy host is not a valid TLS name".into())
                })?;
                let connector = tls_connector(extra_root_pem)?;
                (
                    url.port_or_known_default().unwrap_or(443),
                    Kind::Http {
                        tls: Some((connector, name)),
                    },
                )
            }
            "socks5" => (
                url.port().unwrap_or(1080),
                Kind::Socks5 { remote_dns: false },
            ),
            "socks5h" => (
                url.port().unwrap_or(1080),
                Kind::Socks5 { remote_dns: true },
            ),
            other => {
                return Err(Error::InvalidRequest(format!(
                    "unsupported proxy scheme {other}"
                )));
            }
        };
        let user = route.render_username(sticky_key, generation);
        let password = route
            .password
            .as_ref()
            .map(|p| Zeroizing::new(p.expose().to_owned()));
        if user.is_none() && password.is_some() {
            return Err(Error::InvalidRequest(
                "proxy password given without a username".into(),
            ));
        }
        let credentials = user.map(|u| {
            (
                Zeroizing::new(u),
                password.unwrap_or_else(|| Zeroizing::new(String::new())),
            )
        });
        if matches!(kind, Kind::Socks5 { .. })
            && credentials
                .as_ref()
                .is_some_and(|(u, p)| u.len() > 255 || p.len() > 255)
        {
            return Err(Error::InvalidRequest(
                "SOCKS5 username and password are limited to 255 bytes each".into(),
            ));
        }
        let basic = credentials
            .as_ref()
            .filter(|_| matches!(kind, Kind::Http { .. }))
            .map(|(u, p)| {
                let raw = Zeroizing::new(format!("{}:{}", u.as_str(), p.as_str()));
                let encoded = Zeroizing::new(STANDARD.encode(raw.as_bytes()));
                Zeroizing::new(format!("Basic {}", encoded.as_str()))
            });
        let socks_auth = credentials.filter(|_| matches!(kind, Kind::Socks5 { .. }));
        Ok(Self {
            kind,
            proxy_host: host,
            proxy_port: port,
            basic,
            socks_auth,
            max_head,
        })
    }

    /// Whether this route resolves destination names on the local machine.
    fn resolves_locally(&self) -> bool {
        matches!(self.kind, Kind::Direct | Kind::Socks5 { remote_dns: false })
    }

    /// Opens a tunnel to `host:port`, enforcing `policy` as far as the route allows.
    pub(crate) async fn dial(
        &self,
        host: &Host,
        port: u16,
        policy: &CompiledPolicy,
    ) -> std::result::Result<Tunnel, DialError> {
        if !self.resolves_locally() {
            precheck_literal(host, policy)?;
        }
        match &self.kind {
            Kind::Direct => {
                let addrs = allowed_addrs(host, port, policy).await?;
                let io = connect_any(&addrs).await?;
                Ok(Tunnel {
                    io: Box::new(io),
                    leftover: Vec::new(),
                })
            }
            Kind::Http { tls } => {
                let tcp = self.connect_proxy(policy).await?;
                let mut io: BoxIo = match tls {
                    Some((connector, name)) => {
                        let stream = connector.connect(name.clone(), tcp).await.map_err(|e| {
                            DialError::Unreachable(format!("TLS to upstream proxy failed: {e}"))
                        })?;
                        Box::new(stream)
                    }
                    None => Box::new(tcp),
                };
                let leftover = self.http_connect(&mut io, host, port).await?;
                Ok(Tunnel { io, leftover })
            }
            Kind::Socks5 { remote_dns } => {
                let target = if *remote_dns {
                    match host {
                        Host::Ip(ip) => SocksTarget::Ip(*ip),
                        Host::Name(n) => SocksTarget::Name(n),
                    }
                } else {
                    let addrs = allowed_addrs(host, port, policy).await?;
                    let first = addrs.first().ok_or_else(|| {
                        DialError::Unreachable("destination did not resolve".into())
                    })?;
                    SocksTarget::Ip(first.ip())
                };
                let mut io = self.connect_proxy(policy).await?;
                self.socks_handshake(&mut io, &target, port).await?;
                Ok(Tunnel {
                    io: Box::new(io),
                    leftover: Vec::new(),
                })
            }
        }
    }

    /// Connects to the upstream proxy itself.
    ///
    /// The proxy address is tenant-supplied, so it gets the same treatment as a
    /// destination: resolve it once, keep only addresses the policy permits and
    /// dial exactly those (never a second lookup, which could answer
    /// differently). Every failure here - resolution, policy, connection -
    /// collapses into one message, so a tenant cannot use the proxy URL to
    /// probe internal hosts and ports.
    async fn connect_proxy(
        &self,
        policy: &CompiledPolicy,
    ) -> std::result::Result<TcpStream, DialError> {
        let host = match self.proxy_host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(self.proxy_host.to_ascii_lowercase()),
        };
        let unavailable = |stage: &str, why: &DialError| {
            tracing::debug!(stage, reason = ?why, "upstream proxy unavailable");
            DialError::Unreachable(UPSTREAM_UNAVAILABLE.into())
        };
        let addrs = allowed_addrs(&host, self.proxy_port, policy)
            .await
            .map_err(|e| unavailable("resolve", &e))?;
        connect_any(&addrs)
            .await
            .map_err(|e| unavailable("connect", &e))
    }

    async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        host: &Host,
        port: u16,
    ) -> std::result::Result<Vec<u8>, DialError> {
        let authority = host.authority(port);
        let mut request = Zeroizing::new(format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        ));
        if let Some(basic) = &self.basic {
            request.push_str("Proxy-Authorization: ");
            request.push_str(basic.as_str());
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        io.write_all(request.as_bytes())
            .await
            .map_err(|_| DialError::Upstream("could not send CONNECT to upstream proxy".into()))?;
        let mut buf = Vec::with_capacity(512);
        let head_len = read_head(io, &mut buf, self.max_head)
            .await
            .map_err(|e| match e {
                HeadError::TooLarge => DialError::Upstream("upstream proxy reply too large".into()),
                _ => DialError::Upstream("upstream proxy closed the connection".into()),
            })?;
        match parse_status(&buf[..head_len]) {
            Some(200..=299) => Ok(buf.split_off(head_len)),
            Some(407) => Err(DialError::Upstream(
                "upstream proxy rejected the credentials".into(),
            )),
            Some(code) => Err(DialError::Upstream(format!(
                "upstream proxy refused the tunnel (status {code})"
            ))),
            None => Err(DialError::Upstream(
                "upstream proxy sent an invalid reply".into(),
            )),
        }
    }

    async fn socks_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        target: &SocksTarget<'_>,
        port: u16,
    ) -> std::result::Result<(), DialError> {
        let io_err = |_| DialError::Upstream("upstream SOCKS5 proxy closed the connection".into());
        let greeting: &[u8] = if self.socks_auth.is_some() {
            &[5, 2, 0x00, 0x02]
        } else {
            &[5, 1, 0x00]
        };
        io.write_all(greeting).await.map_err(io_err)?;
        let mut choice = [0u8; 2];
        io.read_exact(&mut choice).await.map_err(io_err)?;
        if choice[0] != 5 {
            return Err(DialError::Upstream("upstream is not a SOCKS5 proxy".into()));
        }
        match choice[1] {
            0x00 => {}
            0x02 => {
                let (user, pass) = self.socks_auth.as_ref().ok_or_else(|| {
                    DialError::Upstream("upstream SOCKS5 proxy demands credentials".into())
                })?;
                let mut msg = Zeroizing::new(Vec::with_capacity(3 + user.len() + pass.len()));
                msg.push(1);
                msg.push(u8::try_from(user.len()).unwrap_or(u8::MAX));
                msg.extend_from_slice(user.as_bytes());
                msg.push(u8::try_from(pass.len()).unwrap_or(u8::MAX));
                msg.extend_from_slice(pass.as_bytes());
                io.write_all(&msg).await.map_err(io_err)?;
                drop(msg);
                let mut reply = [0u8; 2];
                io.read_exact(&mut reply).await.map_err(io_err)?;
                if reply[1] != 0 {
                    return Err(DialError::Upstream(
                        "upstream SOCKS5 proxy rejected the credentials".into(),
                    ));
                }
            }
            0xff => {
                return Err(DialError::Upstream(
                    "upstream SOCKS5 proxy accepts none of the offered auth methods".into(),
                ));
            }
            _ => {
                return Err(DialError::Upstream(
                    "upstream SOCKS5 proxy chose an unsupported method".into(),
                ));
            }
        }

        let mut req = vec![5, 1, 0];
        match target {
            SocksTarget::Ip(IpAddr::V4(a)) => {
                req.push(1);
                req.extend_from_slice(&a.octets());
            }
            SocksTarget::Ip(IpAddr::V6(a)) => {
                req.push(4);
                req.extend_from_slice(&a.octets());
            }
            SocksTarget::Name(name) => {
                let len = u8::try_from(name.len()).map_err(|_| {
                    DialError::Unreachable("destination name too long for SOCKS5".into())
                })?;
                req.push(3);
                req.push(len);
                req.extend_from_slice(name.as_bytes());
            }
        }
        req.extend_from_slice(&port.to_be_bytes());
        io.write_all(&req).await.map_err(io_err)?;

        let mut head = [0u8; 4];
        io.read_exact(&mut head).await.map_err(io_err)?;
        if head[0] != 5 {
            return Err(DialError::Upstream(
                "upstream SOCKS5 reply is malformed".into(),
            ));
        }
        if head[1] != 0 {
            return Err(DialError::Upstream(socks_failure(head[1]).into()));
        }
        let addr_len = match head[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut len = [0u8; 1];
                io.read_exact(&mut len).await.map_err(io_err)?;
                usize::from(len[0])
            }
            _ => {
                return Err(DialError::Upstream(
                    "upstream SOCKS5 reply is malformed".into(),
                ));
            }
        };
        let mut skip = vec![0u8; addr_len + 2];
        io.read_exact(&mut skip).await.map_err(io_err)?;
        Ok(())
    }
}

enum SocksTarget<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

fn socks_failure(code: u8) -> &'static str {
    match code {
        1 => "upstream SOCKS5 proxy: general failure",
        2 => "upstream SOCKS5 proxy: connection not allowed by ruleset",
        3 => "upstream SOCKS5 proxy: network unreachable",
        4 => "upstream SOCKS5 proxy: host unreachable",
        5 => "upstream SOCKS5 proxy: connection refused by destination",
        6 => "upstream SOCKS5 proxy: TTL expired",
        7 => "upstream SOCKS5 proxy: command not supported",
        8 => "upstream SOCKS5 proxy: address type not supported",
        _ => "upstream SOCKS5 proxy: unknown failure",
    }
}

/// Checks what can be judged without resolving: IP literals and `localhost` names.
fn precheck_literal(host: &Host, policy: &CompiledPolicy) -> std::result::Result<(), DialError> {
    let ip = match host {
        Host::Ip(ip) => Some(*ip),
        h if h.is_localhost_name() => Some(IpAddr::from([127, 0, 0, 1])),
        Host::Name(_) => None,
    };
    match ip.map(|ip| policy.check_ip(ip)) {
        Some(Verdict::Refused(reason)) => {
            Err(DialError::Refused(format!("destination is a {reason}")))
        }
        _ => Ok(()),
    }
}

/// Resolves `host` locally and keeps only addresses the policy permits.
async fn allowed_addrs(
    host: &Host,
    port: u16,
    policy: &CompiledPolicy,
) -> std::result::Result<Vec<SocketAddr>, DialError> {
    let candidates: Vec<SocketAddr> = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Name(name) => tokio::net::lookup_host((name.as_str(), port))
            .await
            .map_err(|_| DialError::Unreachable("destination did not resolve".into()))?
            .collect(),
    };
    if candidates.is_empty() {
        return Err(DialError::Unreachable("destination did not resolve".into()));
    }
    let mut refusal: Option<&'static str> = None;
    let allowed: Vec<SocketAddr> = candidates
        .into_iter()
        .filter(|a| match policy.check_ip(a.ip()) {
            Verdict::Allowed => true,
            Verdict::Refused(reason) => {
                refusal.get_or_insert(reason);
                false
            }
        })
        .collect();
    match (allowed.is_empty(), refusal) {
        (true, Some(reason)) => Err(DialError::Refused(format!(
            "destination resolves to a {reason}"
        ))),
        _ => Ok(allowed),
    }
}

async fn connect_any(addrs: &[SocketAddr]) -> std::result::Result<TcpStream, DialError> {
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                // Best effort: latency matters more than coalescing here.
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last = Some(e.kind()),
        }
    }
    Err(DialError::Unreachable(match last {
        Some(kind) => format!("connection failed: {kind}"),
        None => "no address to connect to".into(),
    }))
}

fn tls_connector(extra_root_pem: Option<&str>) -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_root_pem {
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert =
                cert.map_err(|e| Error::InvalidRequest(format!("invalid extra root PEM: {e}")))?;
            roots.add(cert).map_err(|e| {
                Error::InvalidRequest(format!("invalid extra root certificate: {e}"))
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(Error::InvalidRequest(
                "extra root PEM contains no certificate".into(),
            ));
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Egress(format!("TLS configuration failed: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
