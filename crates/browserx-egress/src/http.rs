//! Minimal HTTP/1.1 proxy-request parsing: just enough to read `CONNECT` and
//! absolute-form requests from a browser, and to read an upstream proxy's reply.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Maximum number of header lines accepted.
const MAX_HEADERS: usize = 128;

/// A destination host as written by the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    Ip(IpAddr),
    /// Lowercased DNS name without a trailing dot.
    Name(String),
}

impl Host {
    /// `host:port` with IPv6 literals bracketed.
    pub(crate) fn authority(&self, port: u16) -> String {
        match self {
            Self::Ip(IpAddr::V6(a)) => format!("[{a}]:{port}"),
            Self::Ip(a) => format!("{a}:{port}"),
            Self::Name(n) => format!("{n}:{port}"),
        }
    }

    /// `localhost` and `*.localhost` always mean the local machine.
    pub(crate) fn is_localhost_name(&self) -> bool {
        matches!(self, Self::Name(n) if n == "localhost" || n.ends_with(".localhost"))
    }
}

/// Why a request was rejected before any upstream contact.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// The head exceeds the byte limit.
    TooLarge,
    /// The connection ended before a full head arrived.
    Closed,
    /// I/O failure while reading.
    Io,
    /// Syntactically invalid or unsupported.
    Bad(&'static str),
}

/// Reads until the blank line ending a message head. Returns the head length
/// (including the terminating CRLFCRLF); bytes past it stay in `buf`.
pub(crate) async fn read_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<usize, HeadError> {
    let mut scanned = 0usize;
    loop {
        if let Some(pos) = find_head_end(buf, scanned) {
            let len = pos + 4;
            return if len > max {
                Err(HeadError::TooLarge)
            } else {
                Ok(len)
            };
        }
        scanned = buf.len().saturating_sub(3);
        if buf.len() >= max {
            return Err(HeadError::TooLarge);
        }
        let want = (max - buf.len()).min(4096);
        let start = buf.len();
        buf.resize(start + want, 0);
        let read = reader.read(&mut buf[start..]).await;
        match read {
            Ok(0) => {
                buf.truncate(start);
                return Err(HeadError::Closed);
            }
            Ok(n) => buf.truncate(start + n),
            Err(_) => {
                buf.truncate(start);
                return Err(HeadError::Io);
            }
        }
    }
}

fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + from)
}

/// A parsed request line plus header fields.
#[derive(Debug)]
pub(crate) struct RawHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parses `head` (request line and headers, terminated by a blank line).
pub(crate) fn parse_head(head: &[u8]) -> Result<RawHead, HeadError> {
    let text = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or(HeadError::Bad("incomplete request"))?;
    let mut lines = text
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    // Splitting on bare LF would let a lone LF smuggle a header past strict
    // parsers; require CRLF everywhere.
    if text
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'\n' && (i == 0 || text[i - 1] != b'\r'))
    {
        return Err(HeadError::Bad("bare LF in request head"));
    }
    let request_line = lines.next().ok_or(HeadError::Bad("empty request"))?;
    let mut parts = request_line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HeadError::Bad("malformed request line"));
    };
    if method.is_empty() || !method.iter().copied().all(is_token_byte) {
        return Err(HeadError::Bad("invalid method"));
    }
    if target.is_empty() || target.iter().any(|b| *b <= 0x20 || *b == 0x7f) {
        return Err(HeadError::Bad("invalid request target"));
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(HeadError::Bad("unsupported HTTP version"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(HeadError::Bad("obsolete header folding"));
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(HeadError::Bad("malformed header"))?;
        let (name, value) = line.split_at(colon);
        if name.is_empty() || !name.iter().copied().all(is_token_byte) {
            return Err(HeadError::Bad("invalid header name"));
        }
        let value = trim_ows(&value[1..]);
        if value.iter().any(|b| *b == 0 || *b == b'\r') {
            return Err(HeadError::Bad("invalid header value"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(HeadError::Bad("too many headers"));
        }
        headers.push((String::from_utf8_lossy(name).into_owned(), value.to_vec()));
    }
    Ok(RawHead {
        // `method` and `target` were validated as ASCII above.
        method: String::from_utf8_lossy(method).into_owned(),
        target: String::from_utf8_lossy(target).into_owned(),
        headers,
    })
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if *first == b' ' || *first == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = v {
        if *last == b' ' || *last == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

/// Status code of an HTTP response head.
pub(crate) fn parse_status(head: &[u8]) -> Option<u16> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    status.parse().ok().filter(|code| *code >= 100)
}

/// Parses a host: IP literal (in WHATWG-style numeric forms too) or DNS name.
pub(crate) fn parse_host(raw: &str) -> Result<Host, &'static str> {
    if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return Ipv6Addr::from_str(inner)
            .map(|a| Host::Ip(IpAddr::V6(a)))
            .map_err(|_| "invalid IPv6 literal");
    }
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if name.is_empty() || name.len() > 253 {
        return Err("invalid host length");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err("invalid character in host");
    }
    if name.split('.').any(str::is_empty) {
        return Err("empty host label");
    }
    if let Ok(v4) = Ipv4Addr::from_str(name) {
        return Ok(Host::Ip(IpAddr::V4(v4)));
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    let numeric_tail = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if numeric_tail {
        // Resolvers (inet_aton and friends) read such names as IPv4 numbers in
        // decimal, octal or hex. Judge the address they would produce.
        return parse_legacy_ipv4(name)
            .map(|a| Host::Ip(IpAddr::V4(a)))
            .ok_or("invalid numeric host");
    }
    Ok(Host::Name(name.to_ascii_lowercase()))
}

fn parse_legacy_ipv4(name: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut numbers = parts
        .iter()
        .map(|p| legacy_number(p))
        .collect::<Option<Vec<u64>>>()?;
    let last = numbers.pop()?;
    if numbers.iter().any(|n| *n > 255) {
        return None;
    }
    let remaining_bits = 8 * (4 - numbers.len() as u32);
    if (remaining_bits < 32 && last >> remaining_bits != 0) || last > u64::from(u32::MAX) {
        return None;
    }
    let mut addr = last;
    for (i, n) in numbers.iter().enumerate() {
        addr |= n << (8 * (3 - i as u32));
    }
    u32::try_from(addr).ok().map(Ipv4Addr::from)
}

fn legacy_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (digits, radix) =
        if let Some(h) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (h, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Splits `host:port`. The port is mandatory (`CONNECT` authority form).
pub(crate) fn parse_connect_authority(authority: &str) -> Result<(Host, u16), &'static str> {
    let (host, port) = split_host_port(authority)?;
    let port = port.ok_or("missing port")?;
    Ok((parse_host(host)?, port))
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), &'static str> {
    if authority.contains('@') {
        return Err("userinfo is not allowed");
    }
    let (host, port_text) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or("unterminated IPv6 literal")?;
        let rest = &authority[end + 1..];
        match rest {
            "" => (&authority[..=end], None),
            _ => (
                &authority[..=end],
                Some(rest.strip_prefix(':').ok_or("malformed authority")?),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port_text {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            let n: u16 = p.parse().map_err(|_| "invalid port")?;
            if n == 0 {
                return Err("invalid port");
            }
            Some(n)
        }
        Some(_) => return Err("invalid port"),
    };
    Ok((host, port))
}

/// Result of splitting an absolute-form `http://` target.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AbsoluteTarget {
    pub(crate) host: Host,
    pub(crate) port: u16,
    /// Authority as it must appear in the `Host` header.
    pub(crate) host_header: String,
    /// Origin-form path and query, always starting with `/`.
    pub(crate) path: String,
}

/// Parses `http://authority/path?query`.
pub(crate) fn parse_absolute_http(target: &str) -> Result<AbsoluteTarget, &'static str> {
    let rest = match target.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("http://") => &target[7..],
        _ => {
            return if target.starts_with('/') {
                Err("this is a proxy: send absolute-form or CONNECT requests")
            } else {
                Err("only http:// absolute-form targets are supported; use CONNECT for TLS")
            };
        }
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.is_empty() {
        return Err("missing host");
    }
    let (host_text, port) = split_host_port(authority)?;
    let host = parse_host(host_text)?;
    let port = port.unwrap_or(80);
    // A fragment never goes on the wire, after a path or after a query.
    let tail = tail.split('#').next().unwrap_or_default();
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    let host_header = if port == 80 {
        host_text.to_ascii_lowercase()
    } else {
        authority.to_ascii_lowercase()
    };
    Ok(AbsoluteTarget {
        host,
        port,
        host_header,
        path,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_connect_request() {
        let head = parse_head(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Connection: Keep-Alive\r\n\r\n").unwrap();
        assert_eq!(head.method, "CONNECT");
        assert_eq!(head.target, "example.test:443");
        assert_eq!(head.headers.len(), 2);
        assert_eq!(head.headers[1].1, b"Keep-Alive");
    }

    #[test]
    fn rejects_malformed_heads() {
        for bad in [
            &b"GET /\r\n\r\n"[..],
            b"GET / HTTP/2\r\n\r\n",
            b"GET  / HTTP/1.1\r\n\r\n",
            b"GE T / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\nHost: a\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nbad header: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nno-colon\r\n\r\n",
            b"GET / HTTP/1.1\r\nx: a\0b\r\n\r\n",
        ] {
            assert!(
                parse_head(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn host_forms() {
        assert_eq!(
            parse_host("Example.TEST.").unwrap(),
            Host::Name("example.test".into())
        );
        assert_eq!(
            parse_host("10.0.0.1").unwrap(),
            Host::Ip("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            parse_host("[::1]").unwrap(),
            Host::Ip("::1".parse().unwrap())
        );
        // numeric spellings that resolvers read as 127.0.0.1
        for spelled in [
            "2130706433",
            "0x7f000001",
            "0x7f.1",
            "017700000001",
            "127.1",
            "0177.0.0.1",
        ] {
            assert_eq!(
                parse_host(spelled).unwrap(),
                Host::Ip("127.0.0.1".parse().unwrap()),
                "{spelled}"
            );
        }
        assert_eq!(
            parse_host("1.2.3.4").unwrap(),
            Host::Ip("1.2.3.4".parse().unwrap())
        );
        for bad in [
            "",
            "a..b",
            "a b",
            "a/b",
            "999.1.1.1",
            "1.2.3.4.5",
            "[::1",
            "ex@mple",
            "4294967296",
        ] {
            assert!(parse_host(bad).is_err(), "{bad}");
        }
        assert!(parse_host("a1").is_ok());
        assert!(parse_host("1a.test").is_ok());
    }

    #[test]
    fn connect_authority() {
        assert_eq!(
            parse_connect_authority("example.test:443").unwrap(),
            (Host::Name("example.test".into()), 443)
        );
        assert_eq!(
            parse_connect_authority("[2001:4860::1]:8443").unwrap(),
            (Host::Ip("2001:4860::1".parse().unwrap()), 8443)
        );
        for bad in [
            "example.test",
            "example.test:0",
            "example.test:70000",
            "example.test:",
            "u@example.test:1",
            "[::1]8080",
            ":443",
        ] {
            assert!(parse_connect_authority(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn absolute_targets() {
        let t = parse_absolute_http("http://Example.test/a/b?q=1").unwrap();
        assert_eq!(t.host, Host::Name("example.test".into()));
        assert_eq!(
            (t.port, t.host_header.as_str(), t.path.as_str()),
            (80, "example.test", "/a/b?q=1")
        );
        let t = parse_absolute_http("HTTP://example.test:8080").unwrap();
        assert_eq!(
            (t.port, t.host_header.as_str(), t.path.as_str()),
            (8080, "example.test:8080", "/")
        );
        let t = parse_absolute_http("http://[::1]:81?x").unwrap();
        assert_eq!(
            (t.host_header.as_str(), t.path.as_str()),
            ("[::1]:81", "/?x")
        );
        assert!(parse_absolute_http("/relative").is_err());
        assert!(parse_absolute_http("https://example.test/").is_err());
        assert!(parse_absolute_http("http:///x").is_err());
        assert!(parse_absolute_http("http://user@example.test/").is_err());
        let t = parse_absolute_http("http://example.test:8080?a=1#frag?b=2").unwrap();
        assert_eq!(t.path, "/?a=1");
        let t = parse_absolute_http("http://example.test/p?a=1#frag").unwrap();
        assert_eq!(t.path, "/p?a=1");
        let t = parse_absolute_http("http://example.test#frag").unwrap();
        assert_eq!(t.path, "/");
    }

    #[test]
    fn status_lines() {
        assert_eq!(
            parse_status(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            parse_status(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"),
            Some(407)
        );
        assert_eq!(parse_status(b"HTTP/1.1 200\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"ICY 200 OK\r\n\r\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 2000 OK\r\n\r\n"), None);
        // `u16::from_str` accepts a sign; a status code is three digits from 100.
        assert_eq!(parse_status(b"HTTP/1.1 +12 OK\r\n\r\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 000 OK\r\n\r\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 099 OK\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn read_head_keeps_trailing_bytes_and_enforces_limit() {
        let mut input: &[u8] = b"CONNECT a:1 HTTP/1.1\r\n\r\nEXTRA";
        let mut buf = Vec::new();
        let n = read_head(&mut input, &mut buf, 1024).await.unwrap();
        assert_eq!(&buf[n..], b"EXTRA");

        let big = vec![b'a'; 5000];
        let mut input: &[u8] = &big;
        let mut buf = Vec::new();
        assert_eq!(
            read_head(&mut input, &mut buf, 1024).await,
            Err(HeadError::TooLarge)
        );

        let mut input: &[u8] = b"GET / HTT";
        let mut buf = Vec::new();
        assert_eq!(
            read_head(&mut input, &mut buf, 1024).await,
            Err(HeadError::Closed)
        );
    }
}
