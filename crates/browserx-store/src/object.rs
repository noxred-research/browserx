//! S3-API object store: configuration and a small SigV4 client.
//!
//! The client speaks the part of the S3 protocol BrowserX needs (put, get, head, list, delete,
//! create bucket) over `reqwest` and signs requests itself, so there is no cloud SDK in the
//! dependency tree. It works with the original S3 service and with services that implement its
//! API (an edge object store, self-hosted servers). See `docs/design/backends.md`.
//!
//! Safety rules enforced here:
//!
//! * every key operation checks the key lies under the configured prefix;
//! * request bodies, response bodies, listings, retries and timeouts are bounded;
//! * credentials come from a file or the environment, are held in [`Secret`], and never reach
//!   `Debug`, logs or error text; error text never carries a URL or a signature.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use browserx_core::{Error, Result, Secret};
use rand::RngExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use url::{Host, Url};

use crate::MAX_SEALED_BYTES;

/// Environment variable holding the access key id when no credentials file is configured.
pub const ENV_ACCESS_KEY_ID: &str = "BROWSERX_OBJECT_STORE_ACCESS_KEY_ID";
/// Environment variable holding the secret access key when no credentials file is configured.
pub const ENV_SECRET_ACCESS_KEY: &str = "BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY";
/// Environment variable holding an optional session token.
pub const ENV_SESSION_TOKEN: &str = "BROWSERX_OBJECT_STORE_SESSION_TOKEN";

const SERVICE: &str = "s3";
const DEFAULT_PREFIX: &str = "browserx/";
const MAX_KEY_BYTES: usize = 1024;
const MAX_PREFIX_BYTES: usize = 512;
const MAX_CREDENTIALS_FILE_BYTES: u64 = 16 * 1024;
/// Largest XML response (a listing page or an error body) the client reads.
const MAX_XML_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_LIST_KEYS: usize = 100_000;
const LIST_PAGE_SIZE: usize = 1000;
const MAX_DELETE_MANY: usize = 1000;
const MAX_USER_METADATA_BYTES: usize = 1800;
const MAX_REQUEST_TIMEOUT_SECS: u64 = 600;
const MAX_RETRIES: u32 = 10;
const BACKOFF_BASE_MS: u64 = 100;
const BACKOFF_CAP_MS: u64 = 2_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Which kind of S3-API service the endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    /// The original S3 service. `region` is required; the endpoint is derived from it.
    #[serde(rename = "standard")]
    Standard,
    /// An edge object store with an S3 API. `endpoint` is required, `region` defaults to
    /// `auto` and addressing is path-style. KMS encryption is not available.
    #[serde(rename = "edge")]
    Edge,
    /// A self-hosted S3-compatible server (SeaweedFS, Garage, RustFS, MinIO). `endpoint` is
    /// required; plain `http://` needs `allow_http` unless the endpoint is loopback.
    #[serde(rename = "self-hosted")]
    SelfHosted,
    /// Any other S3-compatible service: `endpoint`, `region` and `path_style` are all explicit.
    #[serde(rename = "compatible")]
    Compatible,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Edge => "edge",
            Self::SelfHosted => "self-hosted",
            Self::Compatible => "compatible",
        }
    }
}

/// Server-side encryption requested for stored objects. Snapshots are already sealed before
/// they leave the process, so this is defence in depth, not a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sse {
    /// No server-side encryption header.
    None,
    /// Service-managed keys (`AES256`).
    Aes256,
    /// A key in the service's key management; needs `kms_key_id`.
    Kms,
}

fn default_prefix() -> String {
    DEFAULT_PREFIX.to_owned()
}

fn default_request_timeout_secs() -> u64 {
    60
}

fn default_max_retries() -> u32 {
    3
}

/// Configuration of an S3-API object store (the worker's `[object_store]` table).
///
/// Credentials are never part of the configuration: name a file in `credentials_file` or set
/// [`ENV_ACCESS_KEY_ID`] and [`ENV_SECRET_ACCESS_KEY`] (and optionally [`ENV_SESSION_TOKEN`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreConfig {
    /// Kind of service.
    pub profile: Profile,
    /// Service URL (`https://host[:port]`, no path). Required except for `standard`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Signing region. Required for `standard` and `compatible`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Bucket name (DNS-safe, 3 to 63 characters).
    pub bucket: String,
    /// Key prefix owned by this BrowserX deployment. Normalized to end with `/`.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Path-style (`host/bucket/key`) or virtual-host (`bucket.host/key`) addressing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_style: Option<bool>,
    /// File with `access_key_id`, `secret_access_key` and optional `session_token` lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_file: Option<PathBuf>,
    /// Server-side encryption of stored objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse: Option<Sse>,
    /// Key id for `sse = "kms"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    /// PEM file with extra certificate authorities for the service's certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<PathBuf>,
    /// Permit a plain-text `http://` endpoint that is not loopback.
    #[serde(default)]
    pub allow_http: bool,
    /// Whole-request timeout in seconds (1 to 600).
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Retries after a timeout, connection error, 429 or 5xx (0 to 10). 4xx is never retried.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

/// Everything `validate` derives from the configuration.
#[derive(Debug, Clone)]
struct Resolved {
    scheme: String,
    host: String,
    port: Option<u16>,
    region: String,
    path_style: bool,
    prefix: String,
    bucket: String,
    sse: SseMode,
    request_timeout: Duration,
    max_retries: u32,
}

#[derive(Debug, Clone)]
enum SseMode {
    None,
    Aes256,
    Kms(String),
}

fn bad(profile: Profile, msg: impl fmt::Display) -> Error {
    Error::InvalidRequest(format!("object_store ({}): {msg}", profile.name()))
}

impl ObjectStoreConfig {
    /// Checks the configuration without touching the network or any file. Refuses unsupported
    /// combinations with an error naming the setting.
    pub fn validate(&self) -> Result<()> {
        self.resolve().map(|_| ())
    }

    /// The prefix as used in keys: no leading `/`, ends with `/`.
    pub fn normalized_prefix(&self) -> Result<String> {
        normalize_prefix(self.profile, &self.prefix)
    }

    fn resolve(&self) -> Result<Resolved> {
        let profile = self.profile;
        check_bucket(profile, &self.bucket)?;
        let prefix = normalize_prefix(profile, &self.prefix)?;
        if !(1..=MAX_REQUEST_TIMEOUT_SECS).contains(&self.request_timeout_secs) {
            return Err(bad(
                profile,
                format!("request_timeout_secs must be 1 to {MAX_REQUEST_TIMEOUT_SECS}"),
            ));
        }
        if self.max_retries > MAX_RETRIES {
            return Err(bad(
                profile,
                format!("max_retries must be at most {MAX_RETRIES}"),
            ));
        }
        let region = match (profile, self.region.as_deref()) {
            (Profile::Standard | Profile::Compatible, None) => {
                return Err(bad(profile, "region is required"));
            }
            (Profile::Edge, None) => "auto".to_owned(),
            (Profile::SelfHosted, None) => "us-east-1".to_owned(),
            (_, Some(r)) => r.to_owned(),
        };
        check_region(profile, &region)?;
        let path_style = match (profile, self.path_style) {
            (Profile::Compatible, None) => {
                return Err(bad(profile, "path_style must be set explicitly"));
            }
            (Profile::Standard, None) => false,
            (Profile::Edge | Profile::SelfHosted, None) => true,
            (_, Some(v)) => v,
        };
        let endpoint = match (&self.endpoint, profile) {
            (Some(e), _) => e.clone(),
            (None, Profile::Standard) => format!("https://s3.{region}.amazonaws.com"),
            (None, _) => return Err(bad(profile, "endpoint is required")),
        };
        let url = Url::parse(&endpoint).map_err(|_| {
            bad(
                profile,
                "endpoint is not a valid URL (expected https://host[:port])",
            )
        })?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad(
                profile,
                "endpoint must not carry credentials; use credentials_file or the environment",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(bad(
                profile,
                "endpoint must be scheme, host and optional port only",
            ));
        }
        let host = url
            .host()
            .ok_or_else(|| bad(profile, "endpoint has no host"))?;
        let is_ip = !matches!(host, Host::Domain(_));
        let loopback = match &host {
            Host::Domain(d) => *d == "localhost" || d.ends_with(".localhost"),
            Host::Ipv4(ip) => ip.is_loopback(),
            Host::Ipv6(ip) => ip.is_loopback(),
        };
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http || loopback => {}
            "http" => {
                return Err(bad(
                    profile,
                    "an http:// endpoint needs allow_http = true unless it is loopback",
                ));
            }
            _ => return Err(bad(profile, "endpoint scheme must be https or http")),
        }
        if !path_style && is_ip {
            return Err(bad(
                profile,
                "virtual-host addressing needs a DNS name, not an IP address; set path_style = true",
            ));
        }
        if !path_style && self.bucket.contains('.') {
            return Err(bad(
                profile,
                "a bucket name with dots needs path_style = true",
            ));
        }
        let sse = match (self.sse, self.kms_key_id.as_deref()) {
            (None | Some(Sse::None), None) => SseMode::None,
            (Some(Sse::Aes256), None) => SseMode::Aes256,
            (Some(Sse::Kms), Some(id)) if !id.is_empty() && is_header_safe(id) => {
                SseMode::Kms(id.to_owned())
            }
            (Some(Sse::Kms), _) => {
                return Err(bad(
                    profile,
                    "sse = \"kms\" needs a non-empty printable kms_key_id",
                ));
            }
            (_, Some(_)) => {
                return Err(bad(profile, "kms_key_id is only valid with sse = \"kms\""));
            }
        };
        if matches!(sse, SseMode::Kms(_)) && profile == Profile::Edge {
            return Err(bad(
                profile,
                "sse = \"kms\" is not supported by this profile; use \"aes256\" or none",
            ));
        }
        Ok(Resolved {
            scheme: url.scheme().to_owned(),
            host: url.host_str().unwrap_or_default().to_owned(),
            port: url.port(),
            region,
            path_style,
            prefix,
            bucket: self.bucket.clone(),
            sse,
            request_timeout: Duration::from_secs(self.request_timeout_secs),
            max_retries: self.max_retries,
        })
    }
}

fn is_header_safe(s: &str) -> bool {
    s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn check_bucket(profile: Profile, bucket: &str) -> Result<()> {
    let ok_len = (3..=63).contains(&bucket.len());
    let ok_chars = bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let edge_ok = bucket
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bucket
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let no_dots = !bucket.contains("..") && !bucket.contains(".-") && !bucket.contains("-.");
    if !(ok_len && ok_chars && edge_ok && no_dots) || bucket.parse::<Ipv4Addr>().is_ok() {
        return Err(bad(
            profile,
            "bucket must be a DNS-safe name of 3 to 63 lowercase letters, digits, hyphens and dots",
        ));
    }
    Ok(())
}

fn check_region(profile: Profile, region: &str) -> Result<()> {
    let ok = !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(bad(
            profile,
            "region must be 1 to 32 lowercase letters, digits and hyphens",
        ))
    }
}

fn normalize_prefix(profile: Profile, prefix: &str) -> Result<String> {
    if prefix.is_empty() || prefix == "/" {
        return Err(bad(
            profile,
            "prefix must not be empty: BrowserX never owns a whole bucket",
        ));
    }
    if prefix.starts_with('/') {
        return Err(bad(profile, "prefix must not start with '/'"));
    }
    let mut out = prefix.to_owned();
    if !out.ends_with('/') {
        out.push('/');
    }
    if out.len() > MAX_PREFIX_BYTES {
        return Err(bad(profile, "prefix is too long"));
    }
    check_key_text(&out)
        .map_err(|()| bad(profile, "prefix has an invalid segment or character"))?;
    Ok(out)
}

/// Text shared by keys and prefixes: printable UTF-8 without control characters or backslashes,
/// no empty, `.` or `..` segment (a trailing empty segment of a prefix is allowed).
fn check_key_text(text: &str) -> std::result::Result<(), ()> {
    if text.chars().any(|c| c.is_control() || c == '\\') {
        return Err(());
    }
    let trimmed = text.strip_suffix('/').unwrap_or(text);
    if trimmed
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Failure of an object store operation. Never carries credentials, URLs or signatures.
#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    /// The configuration or credentials could not be loaded.
    #[error("object store configuration: {0}")]
    Config(String),
    /// A key or prefix is outside the configured prefix or malformed.
    #[error("object key is outside the configured prefix or malformed")]
    KeyOutsidePrefix,
    /// A body or metadata exceeds its limit.
    #[error("object store payload too large: {0}")]
    TooLarge(String),
    /// User metadata has a name or value S3 headers cannot carry.
    #[error("object metadata has an unsupported name or value")]
    InvalidMetadata,
    /// A listing has more entries than the client reads.
    #[error("object store listing has more than {MAX_LIST_KEYS} entries")]
    TooMany,
    /// The service rejected the credentials or the signature (HTTP 401 or 403).
    #[error("object store authentication failed (HTTP {status}{})", code_suffix(.code))]
    Auth {
        /// HTTP status.
        status: u16,
        /// Service error code, if any (for example `InvalidAccessKeyId`).
        code: String,
    },
    /// The bucket does not exist.
    #[error("object store bucket does not exist")]
    NoSuchBucket,
    /// The object does not exist.
    #[error("object not found")]
    NotFound,
    /// A conditional write lost: the object already exists.
    #[error("object already exists")]
    PreconditionFailed,
    /// The service does not support the request (for example a conditional create).
    #[error("object store does not support the request: {0}")]
    Unsupported(String),
    /// The service answered with an unexpected 4xx or 3xx status.
    #[error("object store request failed (HTTP {status}{})", code_suffix(.code))]
    Status {
        /// HTTP status.
        status: u16,
        /// Service error code, if any.
        code: String,
    },
    /// The service kept failing with 5xx after the retries.
    #[error("object store server error (HTTP {status}{})", code_suffix(.code))]
    Server {
        /// HTTP status.
        status: u16,
        /// Service error code, if any.
        code: String,
    },
    /// The service kept throttling (HTTP 429) after the retries.
    #[error("object store is throttling requests")]
    Throttled,
    /// The request timed out.
    #[error("object store request timed out")]
    Timeout,
    /// The connection failed or broke.
    #[error("object store connection failed ({0})")]
    Transport(&'static str),
    /// The response could not be understood.
    #[error("object store sent an unexpected response: {0}")]
    BadResponse(String),
    /// Signing failed (an internal error).
    #[error("object store request signing failed")]
    Signing,
}

fn code_suffix(code: &str) -> String {
    if code.is_empty() {
        String::new()
    } else {
        format!(", {code}")
    }
}

impl ObjectError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Server { .. } | Self::Throttled | Self::Timeout | Self::Transport(_)
        )
    }
}

impl From<ObjectError> for Error {
    fn from(e: ObjectError) -> Self {
        match e {
            ObjectError::Config(_)
            | ObjectError::KeyOutsidePrefix
            | ObjectError::InvalidMetadata => Error::InvalidRequest(e.to_string()),
            ObjectError::Timeout => Error::Timeout(e.to_string()),
            ObjectError::Signing => Error::Internal(e.to_string()),
            other => Error::Storage(other.to_string()),
        }
    }
}

type OResult<T> = std::result::Result<T, ObjectError>;

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Credentials {
    access_key_id: Secret,
    secret_access_key: Secret,
    session_token: Option<Secret>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &self.secret_access_key)
            .field("session_token", &self.session_token)
            .finish()
    }
}

fn credential_value_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 4096 && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn parse_credentials(text: &str) -> OResult<Credentials> {
    let mut id = None;
    let mut secret = None;
    let mut token = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            ObjectError::Config("credentials file: expected `name = \"value\"` lines".into())
        })?;
        let value = value.trim();
        let value = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(inner) => inner,
            None => value,
        };
        if !credential_value_ok(value) || value.contains('"') || value.contains('\\') {
            return Err(ObjectError::Config(
                "credentials file: a value is empty or has unsupported characters".into(),
            ));
        }
        let slot = match key.trim() {
            "access_key_id" => &mut id,
            "secret_access_key" => &mut secret,
            "session_token" => &mut token,
            other => {
                return Err(ObjectError::Config(format!(
                    "credentials file: unknown key `{}`",
                    other.chars().take(40).collect::<String>()
                )));
            }
        };
        if slot.replace(Secret::new(value)).is_some() {
            return Err(ObjectError::Config(
                "credentials file: a key appears twice".into(),
            ));
        }
    }
    match (id, secret) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Credentials {
            access_key_id,
            secret_access_key,
            session_token: token,
        }),
        _ => Err(ObjectError::Config(
            "credentials file: access_key_id and secret_access_key are required".into(),
        )),
    }
}

fn load_credentials(
    cfg: &ObjectStoreConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> OResult<Credentials> {
    if let Some(path) = &cfg.credentials_file {
        let mut text = String::new();
        let file = std::fs::File::open(path).map_err(|e| {
            ObjectError::Config(format!("cannot open credentials_file: {}", e.kind()))
        })?;
        file.take(MAX_CREDENTIALS_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| {
                ObjectError::Config(format!("cannot read credentials_file: {}", e.kind()))
            })?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CREDENTIALS_FILE_BYTES {
            return Err(ObjectError::Config("credentials_file is too large".into()));
        }
        return parse_credentials(&text);
    }
    let get = |name: &str| env(name).map(|v| v.trim().to_owned());
    let (Some(id), Some(secret)) = (get(ENV_ACCESS_KEY_ID), get(ENV_SECRET_ACCESS_KEY)) else {
        return Err(ObjectError::Config(format!(
            "no credentials: set credentials_file or {ENV_ACCESS_KEY_ID} and {ENV_SECRET_ACCESS_KEY}"
        )));
    };
    let token = get(ENV_SESSION_TOKEN).filter(|t| !t.is_empty());
    if !credential_value_ok(&id)
        || !credential_value_ok(&secret)
        || token.as_deref().is_some_and(|t| !credential_value_ok(t))
    {
        return Err(ObjectError::Config(
            "credentials in the environment are empty or have unsupported characters".into(),
        ));
    }
    Ok(Credentials {
        access_key_id: Secret::new(id),
        secret_access_key: Secret::new(secret),
        session_token: token.map(Secret::new),
    })
}

// ---------------------------------------------------------------------------------------------
// SigV4
// ---------------------------------------------------------------------------------------------

/// AWS Signature Version 4, header-signed. Public so its test vectors can run from `tests/`.
pub mod sigv4 {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    use super::{OResult, ObjectError};

    const ALGORITHM: &str = "AWS4-HMAC-SHA256";

    /// Percent-encodes `s` the way SigV4 requires: only `A-Z a-z 0-9 - _ . ~` stay; `/` stays
    /// when `keep_slash` is set (object paths) and is encoded otherwise (query components).
    #[must_use]
    pub fn uri_encode(s: &str, keep_slash: bool) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(char::from(b));
                }
                b'/' if keep_slash => out.push('/'),
                _ => {
                    out.push('%');
                    out.push(char::from(HEX[usize::from(b >> 4)]));
                    out.push(char::from(HEX[usize::from(b & 0x0f)]));
                }
            }
        }
        out
    }

    /// The canonical query string: names and values encoded, sorted, joined with `&`.
    #[must_use]
    pub fn canonical_query(query: &[(&str, &str)]) -> String {
        let mut pairs: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
            .collect();
        pairs.sort();
        let mut out = String::new();
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    }

    /// One request to sign.
    #[derive(Debug, Clone, Copy)]
    pub struct SigningRequest<'a> {
        /// HTTP method in upper case.
        pub method: &'a str,
        /// Absolute path, not yet encoded (for example `/bucket/some key`).
        pub path: &'a str,
        /// Query parameters, not yet encoded, in any order.
        pub query: &'a [(&'a str, &'a str)],
        /// Headers to sign (any case); must include `host`, and `x-amz-date` for S3.
        pub headers: &'a [(&'a str, &'a str)],
        /// Lower-case hex SHA-256 of the body (`x-amz-content-sha256`).
        pub payload_sha256: &'a str,
        /// `YYYYMMDD'T'HHMMSS'Z'`.
        pub amz_date: &'a str,
        /// Credential-scope region.
        pub region: &'a str,
        /// Credential-scope service (`s3`).
        pub service: &'a str,
    }

    /// The pieces of a computed signature.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Signed {
        /// The canonical request.
        pub canonical_request: String,
        /// The string to sign.
        pub string_to_sign: String,
        /// Lower-case hex signature.
        pub signature: String,
        /// Semicolon-joined signed header names.
        pub signed_headers: String,
        /// `YYYYMMDD/region/service/aws4_request`.
        pub credential_scope: String,
    }

    impl Signed {
        /// The `Authorization` header value.
        #[must_use]
        pub fn authorization(&self, access_key_id: &str) -> String {
            format!(
                "{ALGORITHM} Credential={access_key_id}/{}, SignedHeaders={}, Signature={}",
                self.credential_scope, self.signed_headers, self.signature
            )
        }
    }

    fn hmac(key: &[u8], data: &[u8]) -> OResult<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ObjectError::Signing)?;
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        if tag.len() != out.len() {
            return Err(ObjectError::Signing);
        }
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn canonical_header_value(v: &str) -> String {
        v.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Signs a request with a secret access key.
    pub fn sign(secret_access_key: &str, req: &SigningRequest<'_>) -> OResult<Signed> {
        let date = req.amz_date.get(..8).ok_or(ObjectError::Signing)?;
        let mut headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), canonical_header_value(v)))
            .collect();
        headers.sort();
        let mut canonical_headers = String::new();
        let mut signed_headers = String::new();
        for (i, (k, v)) in headers.iter().enumerate() {
            canonical_headers.push_str(k);
            canonical_headers.push(':');
            canonical_headers.push_str(v);
            canonical_headers.push('\n');
            if i > 0 {
                signed_headers.push(';');
            }
            signed_headers.push_str(k);
        }
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            req.method,
            uri_encode(req.path, true),
            canonical_query(req.query),
            canonical_headers,
            signed_headers,
            req.payload_sha256
        );
        let credential_scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);
        let string_to_sign = format!(
            "{ALGORITHM}\n{}\n{credential_scope}\n{}",
            req.amz_date,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let k_date = hmac(
            format!("AWS4{secret_access_key}").as_bytes(),
            date.as_bytes(),
        )?;
        let k_region = hmac(&k_date, req.region.as_bytes())?;
        let k_service = hmac(&k_region, req.service.as_bytes())?;
        let k_signing = hmac(&k_service, b"aws4_request")?;
        let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes())?);
        Ok(Signed {
            canonical_request,
            string_to_sign,
            signature,
            signed_headers,
            credential_scope,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

/// Size and user metadata of a stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHead {
    /// Size in bytes.
    pub size: u64,
    /// User metadata (`x-amz-meta-*`, names lower-cased, prefix removed).
    pub metadata: BTreeMap<String, String>,
}

struct Inner {
    http: Client,
    resolved: Resolved,
    credentials: Credentials,
    summary: String,
}

/// A client for one bucket and key prefix of an S3-API service. Cheap to clone.
#[derive(Clone)]
pub struct ObjectStore {
    inner: Arc<Inner>,
}

impl fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStore")
            .field("service", &self.inner.summary)
            .finish()
    }
}

struct Call<'a> {
    method: Method,
    /// Object key, or `None` for a bucket-level request.
    key: Option<&'a str>,
    query: Vec<(&'a str, String)>,
    headers: Vec<(String, String)>,
    body: &'a [u8],
}

struct Reply {
    headers: HeaderMap,
    body: Vec<u8>,
}

fn amz_date(now: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn backoff(attempt: u32) -> Duration {
    let base = BACKOFF_BASE_MS
        .saturating_mul(1u64 << attempt.min(10))
        .min(BACKOFF_CAP_MS);
    let jitter = rand::rng().random_range(0..=base / 4);
    Duration::from_millis(base + jitter)
}

fn error_code(body: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(body) else {
        return String::new();
    };
    find_tag(text, "Code", 0)
        .map(|(c, _)| c.trim())
        .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .map(str::to_owned)
        .unwrap_or_default()
}

fn classify(status: u16, code: String) -> ObjectError {
    match status {
        401 | 403 => ObjectError::Auth { status, code },
        404 if code == "NoSuchBucket" => ObjectError::NoSuchBucket,
        404 => ObjectError::NotFound,
        412 => ObjectError::PreconditionFailed,
        409 if code == "ConditionalRequestConflict" => ObjectError::PreconditionFailed,
        429 => ObjectError::Throttled,
        501 => ObjectError::Unsupported(code_or(code, "NotImplemented")),
        500..=599 => ObjectError::Server { status, code },
        _ => ObjectError::Status { status, code },
    }
}

fn code_or(code: String, fallback: &str) -> String {
    if code.is_empty() {
        fallback.to_owned()
    } else {
        code
    }
}

fn transport_error(e: &reqwest::Error) -> ObjectError {
    if e.is_timeout() {
        ObjectError::Timeout
    } else if e.is_connect() {
        ObjectError::Transport("connect")
    } else if e.is_body() || e.is_decode() {
        ObjectError::Transport("body")
    } else {
        ObjectError::Transport("request")
    }
}

fn user_metadata_ok(meta: &BTreeMap<String, String>) -> OResult<()> {
    let mut total = 0usize;
    for (k, v) in meta {
        let name_ok = !k.is_empty()
            && k.len() <= 64
            && k.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let value_ok = v.bytes().all(|b| (0x20..=0x7e).contains(&b)) && v.trim() == v.as_str();
        if !name_ok || !value_ok {
            return Err(ObjectError::InvalidMetadata);
        }
        total += k.len() + v.len();
    }
    if total > MAX_USER_METADATA_BYTES {
        return Err(ObjectError::TooLarge(format!(
            "object metadata is {total} bytes; the limit is {MAX_USER_METADATA_BYTES}"
        )));
    }
    Ok(())
}

fn metadata_of(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        if let Some(short) = name.as_str().strip_prefix("x-amz-meta-")
            && let Ok(v) = value.to_str()
        {
            out.insert(short.to_owned(), v.trim().to_owned());
        }
    }
    out
}

impl ObjectStore {
    /// Builds a client; credentials come from `credentials_file` or the environment.
    pub fn connect(cfg: &ObjectStoreConfig) -> Result<Self> {
        Self::connect_with_env(cfg, &|name| std::env::var(name).ok())
    }

    /// Like [`connect`](Self::connect) with an explicit environment lookup.
    pub fn connect_with_env(
        cfg: &ObjectStoreConfig,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let resolved = cfg.resolve()?;
        let credentials = load_credentials(cfg, env)?;
        let mut builder = Client::builder()
            .timeout(resolved.request_timeout)
            .connect_timeout(CONNECT_TIMEOUT.min(resolved.request_timeout))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(8)
            .user_agent(concat!("browserx-store/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &cfg.tls_ca_file {
            let pem = std::fs::read(path).map_err(|e| {
                bad(
                    cfg.profile,
                    format!("cannot read tls_ca_file: {}", e.kind()),
                )
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| bad(cfg.profile, "tls_ca_file holds no valid PEM certificate"))?;
            if certs.is_empty() {
                return Err(bad(cfg.profile, "tls_ca_file holds no certificate"));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|_| Error::Internal("object store HTTP client could not be built".into()))?;
        let summary = format!(
            "object store profile={} bucket={} prefix={} host={}{} region={} addressing={}",
            cfg.profile.name(),
            resolved.bucket,
            resolved.prefix,
            resolved.host,
            resolved.port.map(|p| format!(":{p}")).unwrap_or_default(),
            resolved.region,
            if resolved.path_style {
                "path"
            } else {
                "virtual-host"
            },
        );
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                resolved,
                credentials,
                summary,
            }),
        })
    }

    /// A one-line description for logs: profile, bucket, prefix, host. No credentials.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.inner.summary
    }

    /// The normalized key prefix this client is confined to.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.inner.resolved.prefix
    }

    fn check_key(&self, key: &str) -> OResult<()> {
        let prefix = self.prefix();
        if key.len() > MAX_KEY_BYTES
            || key.len() <= prefix.len()
            || !key.starts_with(prefix)
            || key.ends_with('/')
            || check_key_text(key).is_err()
        {
            return Err(ObjectError::KeyOutsidePrefix);
        }
        Ok(())
    }

    fn check_list_prefix(&self, list_prefix: &str) -> OResult<()> {
        if list_prefix.len() > MAX_KEY_BYTES
            || !list_prefix.starts_with(self.prefix())
            || list_prefix.chars().any(|c| c.is_control() || c == '\\')
            || list_prefix.contains("//")
            || list_prefix.split('/').any(|s| s == "." || s == "..")
        {
            return Err(ObjectError::KeyOutsidePrefix);
        }
        Ok(())
    }

    /// Host header value and the request path for a call.
    fn target(&self, key: Option<&str>) -> (String, String) {
        let r = &self.inner.resolved;
        let port = r.port.map(|p| format!(":{p}")).unwrap_or_default();
        if r.path_style {
            let path = match key {
                Some(k) => format!("/{}/{k}", r.bucket),
                None => format!("/{}", r.bucket),
            };
            (format!("{}{port}", r.host), path)
        } else {
            let path = key.map_or_else(|| "/".to_owned(), |k| format!("/{k}"));
            (format!("{}.{}{port}", r.bucket, r.host), path)
        }
    }

    async fn attempt(
        &self,
        call: &Call<'_>,
        payload_hash: &str,
        max_body: usize,
    ) -> OResult<Reply> {
        let inner = &*self.inner;
        let (host, path) = self.target(call.key);
        let date = amz_date(OffsetDateTime::now_utc());
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host.clone()),
            ("x-amz-content-sha256".into(), payload_hash.to_owned()),
            ("x-amz-date".into(), date.clone()),
        ];
        if let Some(token) = &inner.credentials.session_token {
            headers.push(("x-amz-security-token".into(), token.expose().to_owned()));
        }
        headers.extend(call.headers.iter().cloned());
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let query_refs: Vec<(&str, &str)> =
            call.query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let signed = sigv4::sign(
            inner.credentials.secret_access_key.expose(),
            &sigv4::SigningRequest {
                method: call.method.as_str(),
                path: &path,
                query: &query_refs,
                headers: &header_refs,
                payload_sha256: payload_hash,
                amz_date: &date,
                region: &inner.resolved.region,
                service: SERVICE,
            },
        )?;
        let authorization = signed.authorization(inner.credentials.access_key_id.expose());
        let mut url = format!(
            "{}://{host}{}",
            inner.resolved.scheme,
            sigv4::uri_encode(&path, true)
        );
        let query = sigv4::canonical_query(&query_refs);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query);
        }
        let mut req = inner.http.request(call.method.clone(), url);
        for (name, value) in &headers {
            if name == "host" {
                continue;
            }
            let (Ok(n), Ok(mut v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                return Err(ObjectError::Signing);
            };
            if name == "x-amz-security-token" {
                v.set_sensitive(true);
            }
            req = req.header(n, v);
        }
        let mut auth = HeaderValue::from_str(&authorization).map_err(|_| ObjectError::Signing)?;
        auth.set_sensitive(true);
        req = req.header(reqwest::header::AUTHORIZATION, auth);
        if call.method == Method::PUT || !call.body.is_empty() {
            req = req.body(call.body.to_vec());
        }
        let mut resp = req.send().await.map_err(|e| transport_error(&e))?;
        let status = resp.status().as_u16();
        let is_head = call.method == Method::HEAD;
        let ok = (200..300).contains(&status);
        let limit = if ok { max_body } else { MAX_ERROR_BODY_BYTES };
        if ok
            && let Some(len) = resp.content_length()
            && len > u64::try_from(limit).unwrap_or(u64::MAX)
            && !is_head
        {
            return Err(ObjectError::TooLarge(
                "the response is larger than the limit".into(),
            ));
        }
        let headers = resp.headers().clone();
        let mut body = Vec::new();
        if !is_head {
            while let Some(chunk) = resp.chunk().await.map_err(|e| transport_error(&e))? {
                if body.len() + chunk.len() > limit {
                    if ok {
                        return Err(ObjectError::TooLarge(
                            "the response is larger than the limit".into(),
                        ));
                    }
                    break;
                }
                body.extend_from_slice(&chunk);
            }
        }
        if ok {
            Ok(Reply { headers, body })
        } else {
            Err(classify(status, error_code(&body)))
        }
    }

    async fn execute(&self, call: &Call<'_>, max_body: usize) -> OResult<Reply> {
        let payload_hash = hex::encode(Sha256::digest(call.body));
        let mut attempt = 0u32;
        loop {
            match self.attempt(call, &payload_hash, max_body).await {
                Ok(reply) => return Ok(reply),
                Err(e) if e.retryable() && attempt < self.inner.resolved.max_retries => {
                    tracing::debug!(attempt, error = %e, "object store request retried");
                    tokio::time::sleep(backoff(attempt)).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Stores an object. With `if_none_match` the write only succeeds when the key does not
    /// exist (`If-None-Match: *`): [`ObjectError::PreconditionFailed`] if it does and
    /// [`ObjectError::Unsupported`] if the service does not support the header.
    pub async fn put(
        &self,
        key: &str,
        bytes: &[u8],
        user_metadata: &BTreeMap<String, String>,
        if_none_match: bool,
    ) -> OResult<()> {
        self.check_key(key)?;
        if bytes.len() > MAX_SEALED_BYTES {
            return Err(ObjectError::TooLarge(format!(
                "object is {} bytes; the limit is {MAX_SEALED_BYTES}",
                bytes.len()
            )));
        }
        user_metadata_ok(user_metadata)?;
        let mut headers = vec![(
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        )];
        for (k, v) in user_metadata {
            headers.push((format!("x-amz-meta-{k}"), v.clone()));
        }
        match &self.inner.resolved.sse {
            SseMode::None => {}
            SseMode::Aes256 => {
                headers.push(("x-amz-server-side-encryption".into(), "AES256".into()))
            }
            SseMode::Kms(id) => {
                headers.push(("x-amz-server-side-encryption".into(), "aws:kms".into()));
                headers.push((
                    "x-amz-server-side-encryption-aws-kms-key-id".into(),
                    id.clone(),
                ));
            }
        }
        if if_none_match {
            headers.push(("if-none-match".into(), "*".into()));
        }
        let call = Call {
            method: Method::PUT,
            key: Some(key),
            query: Vec::new(),
            headers,
            body: bytes,
        };
        match self.execute(&call, MAX_XML_BYTES).await {
            Ok(_) => Ok(()),
            Err(ObjectError::Status { status: 400, code }) if if_none_match => {
                Err(ObjectError::Unsupported(code_or(code, "InvalidArgument")))
            }
            Err(e) => Err(e),
        }
    }

    /// Reads an object and its user metadata; `None` when it does not exist.
    pub async fn get(&self, key: &str) -> OResult<Option<(Vec<u8>, BTreeMap<String, String>)>> {
        self.check_key(key)?;
        let call = Call {
            method: Method::GET,
            key: Some(key),
            query: Vec::new(),
            headers: Vec::new(),
            body: &[],
        };
        match self.execute(&call, MAX_SEALED_BYTES).await {
            Ok(reply) => Ok(Some((reply.body, metadata_of(&reply.headers)))),
            Err(ObjectError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Size and user metadata of an object; `None` when it does not exist.
    pub async fn head(&self, key: &str) -> OResult<Option<ObjectHead>> {
        self.check_key(key)?;
        let call = Call {
            method: Method::HEAD,
            key: Some(key),
            query: Vec::new(),
            headers: Vec::new(),
            body: &[],
        };
        match self.execute(&call, 0).await {
            Ok(reply) => {
                let size = reply
                    .headers
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(|| {
                        ObjectError::BadResponse("HEAD without a content length".into())
                    })?;
                Ok(Some(ObjectHead {
                    size,
                    metadata: metadata_of(&reply.headers),
                }))
            }
            Err(ObjectError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Lists `(key, size)` of every object whose key starts with `prefix` (which must itself
    /// start with the configured prefix). Follows continuation tokens page by page and fails
    /// with [`ObjectError::TooMany`] beyond 100 000 entries.
    pub async fn list(&self, prefix: &str) -> OResult<Vec<(String, u64)>> {
        self.check_list_prefix(prefix)?;
        let mut out: Vec<(String, u64)> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type", "2".to_owned()),
                ("max-keys", LIST_PAGE_SIZE.to_string()),
                ("prefix", prefix.to_owned()),
            ];
            if let Some(t) = token.take() {
                query.push(("continuation-token", t));
            }
            let call = Call {
                method: Method::GET,
                key: None,
                query,
                headers: Vec::new(),
                body: &[],
            };
            let reply = self.execute(&call, MAX_XML_BYTES).await?;
            let xml = std::str::from_utf8(&reply.body)
                .map_err(|_| ObjectError::BadResponse("listing is not UTF-8".into()))?;
            let page = parse_list(xml)?;
            for (key, size) in page.entries {
                if !key.starts_with(prefix) {
                    return Err(ObjectError::BadResponse(
                        "listing returned a key outside the requested prefix".into(),
                    ));
                }
                out.push((key, size));
            }
            if out.len() > MAX_LIST_KEYS {
                return Err(ObjectError::TooMany);
            }
            match page.next {
                Some(next) => token = Some(next),
                None => return Ok(out),
            }
        }
    }

    /// Deletes an object. Deleting a missing key succeeds.
    pub async fn delete(&self, key: &str) -> OResult<()> {
        self.check_key(key)?;
        let call = Call {
            method: Method::DELETE,
            key: Some(key),
            query: Vec::new(),
            headers: Vec::new(),
            body: &[],
        };
        match self.execute(&call, MAX_XML_BYTES).await {
            Ok(_) | Err(ObjectError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Deletes up to 1000 objects one request at a time (no multi-object delete, which needs a
    /// checksum header some services reject). Returns how many keys were processed. Every key
    /// is checked against the prefix before the first request is sent.
    pub async fn delete_many(&self, keys: &[String]) -> OResult<u64> {
        if keys.len() > MAX_DELETE_MANY {
            return Err(ObjectError::TooLarge(format!(
                "at most {MAX_DELETE_MANY} keys per delete_many"
            )));
        }
        for key in keys {
            self.check_key(key)?;
        }
        let mut done = 0u64;
        for key in keys {
            self.delete(key).await?;
            done += 1;
        }
        Ok(done)
    }

    /// Creates the bucket (used by tests and first-time setup). An existing bucket owned by
    /// the caller is not an error.
    pub async fn create_bucket(&self) -> OResult<()> {
        let region = &self.inner.resolved.region;
        let body = if region == "us-east-1" || region == "auto" {
            String::new()
        } else {
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>"
            )
        };
        let call = Call {
            method: Method::PUT,
            key: None,
            query: Vec::new(),
            headers: Vec::new(),
            body: body.as_bytes(),
        };
        match self.execute(&call, MAX_XML_BYTES).await {
            Ok(_) => Ok(()),
            Err(ObjectError::Status { status: 409, code }) if code == "BucketAlreadyOwnedByYou" => {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Checks the bucket, the credentials and the prefix with a one-entry listing.
    pub async fn ping(&self) -> OResult<()> {
        let call = Call {
            method: Method::GET,
            key: None,
            query: vec![
                ("list-type", "2".to_owned()),
                ("max-keys", "1".to_owned()),
                ("prefix", self.prefix().to_owned()),
            ],
            headers: Vec::new(),
            body: &[],
        };
        self.execute(&call, MAX_XML_BYTES).await.map(|_| ())
    }
}

// ---------------------------------------------------------------------------------------------
// Minimal XML
// ---------------------------------------------------------------------------------------------

/// Text between `<tag>` and `</tag>` at or after `from`, and the offset after the closing tag.
fn find_tag<'a>(xml: &'a str, tag: &str, from: usize) -> Option<(&'a str, usize)> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let rest = xml.get(from..)?;
    let start = from + rest.find(&open)? + open.len();
    let end = start + xml.get(start..)?.find(&close)?;
    Some((xml.get(start..end)?, end + close.len()))
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(semi) = rest.find(';').filter(|&j| j <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..semi];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

struct ListPage {
    entries: Vec<(String, u64)>,
    next: Option<String>,
}

fn parse_list(xml: &str) -> OResult<ListPage> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while let Some((block, next_pos)) = find_tag(xml, "Contents", pos) {
        pos = next_pos;
        let (key, _) = find_tag(block, "Key", 0)
            .ok_or_else(|| ObjectError::BadResponse("listing entry without a key".into()))?;
        let size = find_tag(block, "Size", 0)
            .and_then(|(s, _)| s.trim().parse::<u64>().ok())
            .ok_or_else(|| ObjectError::BadResponse("listing entry without a size".into()))?;
        entries.push((unescape(key), size));
        if entries.len() > LIST_PAGE_SIZE * 2 {
            return Err(ObjectError::BadResponse("listing page is too large".into()));
        }
    }
    let truncated = find_tag(xml, "IsTruncated", 0).is_some_and(|(v, _)| v.trim() == "true");
    let next = if truncated {
        let token = find_tag(xml, "NextContinuationToken", 0)
            .map(|(t, _)| unescape(t.trim()))
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                ObjectError::BadResponse("truncated listing without a continuation token".into())
            })?;
        Some(token)
    } else {
        None
    };
    Ok(ListPage { entries, next })
}
