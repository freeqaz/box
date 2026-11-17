//! A request-time credential source: the endpoint the gateway asks for one request's credential,
//! after policy has permitted that request.
//!
//! | Item | Is |
//! |---|---|
//! | [`CredentialSource`] | one operator-declared source: its endpoint, trust, and bounds |
//! | [`SourceClient`] | the source with its TLS configuration, ready to ask |
//! | [`Released`] | the value a source released for one request, and its send deadline |
//! | [`Withheld`] | why no credential was released, for the audit and for the workload |
//!
//! One exchange is one `POST` of a JSON document that describes the permitted request, and one JSON
//! reply that carries the credential or a refusal. There is no retry and no cache: every failure,
//! including a timeout, withholds the credential, and the request does not go upstream.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::boundary::HeaderMap;
use crate::error::{ProxyError, Result};

/// The wire format's version; a reply that names another is refused.
pub(crate) const WIRE_VERSION: u32 = 1;

/// The longest a source's reply may be.
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// The longest a refusal reason code may be.
const MAX_REASON_BYTES: usize = 64;

/// The request headers a source never receives: framing, hop-by-hop, and proxy headers, and `host`,
/// which the target already states.
const WITHHELD_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The default bound on one exchange with a source, from connect to the end of its reply.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The default bound on the request body a source receives.
pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Where a credential source listens.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    /// HTTP over a Unix domain socket at this absolute path; the request path is `/`.
    Unix(PathBuf),
    /// HTTPS to `host:port`, at `path`.
    Https {
        host: String,
        port: u16,
        path: String,
    },
}

/// One request-time credential source, as the operator declared it.
///
/// The gateway asks it for the credential of each request to a route that names it, after policy has
/// permitted the request and before the request goes upstream. The source answers with the
/// credential for that one request, or with a refusal; it never permits a request.
#[derive(Clone)]
pub struct CredentialSource {
    name: String,
    endpoint: Endpoint,
    ca_pems: Vec<String>,
    bearer: Option<Zeroizing<String>>,
    timeout: Duration,
    max_body_bytes: usize,
}

impl CredentialSource {
    /// A source named `name` at `endpoint`, which is `unix:///absolute/path` or
    /// `https://host[:port][/path]`. Refuses any other form.
    pub fn new(name: impl Into<String>, endpoint: &str) -> Result<Self> {
        let name = name.into();
        let endpoint = parse_endpoint(endpoint).map_err(|reason| {
            ProxyError::Config(format!("credential source {name:?}: {reason}"))
        })?;
        Ok(Self {
            name,
            endpoint,
            ca_pems: Vec::new(),
            bearer: None,
            timeout: DEFAULT_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Trust only the certificates in `pem` for an `https` endpoint, in place of the public roots.
    #[must_use]
    pub fn trusting(mut self, pem: String) -> Self {
        self.ca_pems.push(pem);
        self
    }

    /// Send `token` to the source as `Authorization: Bearer <token>`, so it can authenticate the box.
    #[must_use]
    pub fn bearer(mut self, token: impl Into<Zeroizing<String>>) -> Self {
        self.bearer = Some(token.into());

        self
    }

    /// Bound one exchange, from connect to the end of the reply, by `timeout`.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Withhold the credential of a request whose body is longer than `bytes`.
    #[must_use]
    pub fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    /// The name routes use to select this source.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Refuse a source whose `https` trust cannot be built, as the gateway's start would, so a
    /// caller can refuse it when its configuration loads.
    pub fn check(&self) -> Result<()> {
        SourceClient::new(self.clone()).map(|_| ())
    }

    /// Whether this source listens on `host:port`, so the gateway can refuse a workload request to it.
    pub(crate) fn listens_on(&self, host: &str, port: u16) -> bool {
        match &self.endpoint {
            Endpoint::Https {
                host: own,
                port: own_port,
                ..
            } => *own_port == port && super::connect::same_host(own, host),
            Endpoint::Unix(_) => false,
        }
    }
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSource")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("ca_pems", &self.ca_pems.len())
            .field("bearer", &self.bearer.as_ref().map(|_| "[REDACTED]"))
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

/// The endpoint `text` names, or why it names none.
fn parse_endpoint(text: &str) -> std::result::Result<Endpoint, String> {
    if let Some(path) = text.strip_prefix("unix://") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(format!(
                "the endpoint {text:?} names a relative socket path; write unix:///absolute/path"
            ));
        }
        return Ok(Endpoint::Unix(path));
    }
    let Some(rest) = text.strip_prefix("https://") else {
        return Err(format!(
            "the endpoint {text:?} is neither unix:///path nor https://host; the credential and \
             the box's own token must not travel in plain text"
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || path.contains(['?', '#']) {
        return Err(format!(
            "the endpoint {text:?} may name a host, a port, and a path, and nothing else"
        ));
    }
    // A bracketed IPv6 literal carries colons of its own, so the port follows the bracket.
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, rest)) => (host, Some(rest.strip_prefix(':').unwrap_or(rest))),
            None => ("", None),
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let port = match port {
        None => 443,
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("the endpoint {text:?} names an invalid port"))?,
    };
    if host.is_empty() || ServerName::try_from(host.to_string()).is_err() {
        return Err(format!("the endpoint {text:?} names no valid host"));
    }
    Ok(Endpoint::Https {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// A credential source with the TLS configuration its endpoint needs.
pub(crate) struct SourceClient {
    source: CredentialSource,
    tls: Option<Arc<ClientConfig>>,
}

/// The request the gateway asks a source about: the request policy permitted, as it will go
/// upstream, without its credential.
pub(crate) struct Ask<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) query: &'a str,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) body: &'a [u8],
}

/// The value a source released for one request, and when it may no longer be sent.
pub(crate) struct Released {
    pub(crate) value: Zeroizing<String>,
    pub(crate) send_by: SystemTime,
}

/// Why a source released no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Withheld {
    /// The non-secret reason, for the audit record.
    pub(crate) reason: String,
    /// The source's own reason code, when the source refused.
    pub(crate) code: Option<String>,
}

impl Withheld {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            code: None,
        }
    }

    /// The refusal body the workload receives: the source's reason code, or that the source gave
    /// none. Never a transport detail.
    pub(crate) fn workload_body(&self) -> Vec<u8> {
        match &self.code {
            Some(code) => format!("credential refused by its source: {code}").into_bytes(),
            None => b"credential source unavailable".to_vec(),
        }
    }
}

/// The JSON document a source receives.
#[derive(Serialize)]
struct SourceRequest<'a> {
    version: u32,
    request_id: &'a str,
    target: SourceTarget<'a>,
    headers: Vec<(String, &'a str)>,
    body: String,
}

/// The request's target, as policy judged it.
#[derive(Serialize)]
struct SourceTarget<'a> {
    scheme: &'static str,
    host: &'a str,
    port: u16,
    method: &'a str,
    path: &'a str,
    query: &'a str,
}

/// The JSON document a source replies with: a credential and its deadline, or a refusal.
#[derive(Deserialize)]
struct SourceReply {
    version: u32,
    request_id: String,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    send_by_unix_ms: Option<u64>,
    #[serde(default)]
    refusal: Option<String>,
}

impl SourceClient {
    /// The client for `source`, refusing an `https` endpoint whose trust cannot be built.
    pub(crate) fn new(source: CredentialSource) -> Result<Self> {
        let tls = match &source.endpoint {
            Endpoint::Unix(_) => None,
            Endpoint::Https { .. } => Some(Arc::new(
                super::tls::source_client_config(&source.ca_pems).map_err(|error| {
                    ProxyError::Config(format!("credential source {:?}: {error}", source.name))
                })?,
            )),
        };
        Ok(Self { source, tls })
    }

    /// The source's name.
    pub(crate) fn name(&self) -> &str {
        &self.source.name
    }

    /// The source's declaration.
    pub(crate) fn source(&self) -> &CredentialSource {
        &self.source
    }

    /// Ask the source for the credential of `ask`. Every failure withholds it.
    pub(crate) async fn release(&self, ask: &Ask<'_>) -> std::result::Result<Released, Withheld> {
        if ask.body.len() > self.source.max_body_bytes {
            return Err(Withheld::failed(format!(
                "the request body is {} bytes, more than credential source {:?} accepts ({} bytes)",
                ask.body.len(),
                self.source.name,
                self.source.max_body_bytes
            )));
        }
        let request_id = new_request_id()
            .map_err(|_| Withheld::failed("no random request identifier was available"))?;
        let document = request_document(&request_id, ask)
            .map_err(|error| Withheld::failed(format!("encoding the request: {error}")))?;
        let reply = tokio::time::timeout(self.source.timeout, self.exchange(document))
            .await
            .map_err(|_| {
                Withheld::failed(format!(
                    "credential source {:?} did not answer within {} ms",
                    self.source.name,
                    self.source.timeout.as_millis()
                ))
            })?
            .map_err(|reason| {
                Withheld::failed(format!(
                    "credential source {:?}: {reason}",
                    self.source.name
                ))
            })?;
        self.read_reply(&request_id, &reply)
    }

    /// One `POST` of `document` to the endpoint, returning the reply body of a `200`.
    async fn exchange(&self, document: Vec<u8>) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
        match &self.source.endpoint {
            Endpoint::Unix(path) => {
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|error| format!("connecting to {}: {error}", path.display()))?;
                self.round_trip(stream, "localhost", "/", document).await
            }
            Endpoint::Https { host, port, path } => {
                let tcp = tokio::net::TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|error| format!("connecting to {host}:{port}: {error}"))?;
                let _ = tcp.set_nodelay(true);
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| format!("{host} is not a TLS server name"))?;
                let tls = self
                    .tls
                    .clone()
                    .ok_or_else(|| "no TLS configuration for an https source".to_string())?;
                let stream = tokio_rustls::TlsConnector::from(tls)
                    .connect(name, tcp)
                    .await
                    .map_err(|error| format!("TLS handshake with {host}:{port}: {error}"))?;
                let authority = if *port == 443 {
                    host.clone()
                } else {
                    format!("{host}:{port}")
                };
                self.round_trip(stream, &authority, path, document).await
            }
        }
    }

    /// Send `document` over `stream` and read a bounded reply.
    async fn round_trip<S>(
        &self,
        stream: S,
        authority: &str,
        path: &str,
        document: Vec<u8>,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| format!("HTTP handshake: {error}"))?;
        // The connection task ends when the exchange below drops its sender.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut request = hyper::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", authority)
            .header("content-type", "application/json")
            .header("accept", "application/json");
        if let Some(token) = &self.source.bearer {
            let mut value = hyper::header::HeaderValue::from_str(&format!("Bearer {}", **token))
                .map_err(|_| "the source token is not a valid header value".to_string())?;
            value.set_sensitive(true);
            request = request.header("authorization", value);
        }
        let request = request
            .body(Full::new(Bytes::from(document)))
            .map_err(|error| format!("building the request: {error}"))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("sending the request: {error}"))?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), MAX_REPLY_BYTES)
            .collect()
            .await
            .map_err(|error| {
                format!("reading the reply (at most {MAX_REPLY_BYTES} bytes): {error}")
            })?
            .to_bytes();
        let body = Zeroizing::new(body.to_vec());
        if status != 200 {
            return Err(format!("the source answered status {status}"));
        }
        Ok(body)
    }

    /// The released credential `reply` carries for `request_id`, or why it carries none.
    fn read_reply(
        &self,
        request_id: &str,
        reply: &[u8],
    ) -> std::result::Result<Released, Withheld> {
        let name = &self.source.name;
        let reply: SourceReply = serde_json::from_slice(reply).map_err(|error| {
            Withheld::failed(format!(
                "credential source {name:?} sent a malformed reply: {}",
                reply_error_kind(&error)
            ))
        })?;
        let SourceReply {
            version,
            request_id: answered,
            credential,
            send_by_unix_ms,
            refusal,
        } = reply;
        let credential = credential.map(Zeroizing::new);
        if version != WIRE_VERSION {
            return Err(Withheld::failed(format!(
                "credential source {name:?} answered with version {version}, not {WIRE_VERSION}"
            )));
        }
        if answered != request_id {
            return Err(Withheld::failed(format!(
                "credential source {name:?} answered another request"
            )));
        }
        match (credential, refusal) {
            (None, Some(code)) => Err(Withheld {
                reason: format!("credential source {name:?} refused the request"),
                code: Some(reason_code(&code)),
            }),
            (Some(value), None) => {
                let send_by_unix_ms = send_by_unix_ms.ok_or_else(|| {
                    Withheld::failed(format!(
                        "credential source {name:?} released a credential with no send_by_unix_ms"
                    ))
                })?;
                let send_by = UNIX_EPOCH + Duration::from_millis(send_by_unix_ms);
                if send_by <= SystemTime::now() {
                    return Err(Withheld::failed(format!(
                        "credential source {name:?} released a credential whose deadline has passed"
                    )));
                }
                Ok(Released { value, send_by })
            }
            _ => Err(Withheld::failed(format!(
                "credential source {name:?} sent a reply with neither or both of credential and \
                 refusal"
            ))),
        }
    }
}

/// `code` when it is a short token, else `invalid`, so a source cannot write arbitrary text into the
/// workload's refusal or the audit.
fn reason_code(code: &str) -> String {
    let token = !code.is_empty()
        && code.len() <= MAX_REASON_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if token {
        code.to_string()
    } else {
        "invalid".to_string()
    }
}

/// A fresh 128-bit request identifier, as 32 lowercase hex digits.
fn new_request_id() -> std::result::Result<String, ring::error::Unspecified> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The JSON document that asks a source about `ask`.
fn request_document(request_id: &str, ask: &Ask<'_>) -> serde_json::Result<Vec<u8>> {
    let connection_options: Vec<String> = ask
        .headers
        .get("connection")
        .map(|value| {
            value
                .split(',')
                .map(|option| option.trim().to_ascii_lowercase())
                .filter(|option| !option.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let headers = ask
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .filter(|(name, _)| {
            !WITHHELD_HEADERS.contains(&name.as_str()) && !connection_options.contains(name)
        })
        .collect();
    serde_json::to_vec(&SourceRequest {
        version: WIRE_VERSION,
        request_id,
        target: SourceTarget {
            scheme: "https",
            host: ask.host,
            port: ask.port,
            method: ask.method,
            path: ask.path,
            query: ask.query,
        },
        headers,
        body: BASE64.encode(ask.body),
    })
}

/// The class of a reply's parse error. The error's own text can quote the reply, which may hold
/// the credential, so only the class is reported.
fn reply_error_kind(error: &serde_json::Error) -> &'static str {
    match error.classify() {
        serde_json::error::Category::Io => "an I/O error",
        serde_json::error::Category::Syntax => "not JSON",
        serde_json::error::Category::Data => "not the reply document",
        serde_json::error::Category::Eof => "cut short",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(name: &str) -> SourceClient {
        SourceClient::new(CredentialSource::new(name, "unix:///run/source.sock").unwrap()).unwrap()
    }

    fn reply(json: &str) -> std::result::Result<Released, Withheld> {
        client("cp").read_reply("abc", json.as_bytes())
    }

    fn later() -> u64 {
        (SystemTime::now() + Duration::from_secs(60))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn an_endpoint_is_a_unix_socket_or_https() {
        assert_eq!(
            parse_endpoint("unix:///run/cp.sock").unwrap(),
            Endpoint::Unix(PathBuf::from("/run/cp.sock"))
        );
        assert_eq!(
            parse_endpoint("https://cp.example.com").unwrap(),
            Endpoint::Https {
                host: "cp.example.com".into(),
                port: 443,
                path: "/".into()
            }
        );
        assert_eq!(
            parse_endpoint("https://cp.example.com:8443/v1/credential").unwrap(),
            Endpoint::Https {
                host: "cp.example.com".into(),
                port: 8443,
                path: "/v1/credential".into()
            }
        );
        assert_eq!(
            parse_endpoint("https://[::1]:8443").unwrap(),
            Endpoint::Https {
                host: "::1".into(),
                port: 8443,
                path: "/".into()
            }
        );
        for refused in [
            "https://[::1",
            "https://[::1]x",
            "http://cp.example.com",
            "unix://relative.sock",
            "https://",
            "https://user@cp.example.com",
            "https://cp.example.com/?x=1",
            "https://cp.example.com:0",
            "https://cp.example.com:http",
            "cp.example.com",
        ] {
            assert!(parse_endpoint(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_source_never_prints_its_token() {
        let source = CredentialSource::new("cp", "unix:///run/cp.sock")
            .unwrap()
            .bearer(Zeroizing::new("box-token-value".into()));
        let rendered = format!("{source:?}");
        assert!(!rendered.contains("box-token-value"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn a_credential_reply_releases_its_value() {
        let released = reply(&format!(
            r#"{{"version":1,"request_id":"abc","credential":"ghs_x","send_by_unix_ms":{}}}"#,
            later()
        ))
        .unwrap_or_else(|withheld| panic!("{withheld:?}"));
        assert_eq!(released.value.as_str(), "ghs_x");
        assert!(released.send_by > SystemTime::now());
    }

    #[test]
    fn a_refusal_carries_its_reason_code_and_nothing_else() {
        let withheld = reply(r#"{"version":1,"request_id":"abc","refusal":"access_withdrawn"}"#)
            .err()
            .unwrap();
        assert_eq!(withheld.code.as_deref(), Some("access_withdrawn"));
        assert_eq!(
            withheld.workload_body(),
            b"credential refused by its source: access_withdrawn"
        );
        let withheld = reply(r#"{"version":1,"request_id":"abc","refusal":"no\r\nx-forged: 1"}"#)
            .err()
            .unwrap();
        assert_eq!(withheld.code.as_deref(), Some("invalid"));
    }

    #[test]
    fn every_other_reply_withholds_the_credential() {
        let later = later();
        for json in [
            String::new(),
            "not json".to_string(),
            "{}".to_string(),
            format!(
                r#"{{"version":2,"request_id":"abc","credential":"x","send_by_unix_ms":{later}}}"#
            ),
            format!(
                r#"{{"version":1,"request_id":"other","credential":"x","send_by_unix_ms":{later}}}"#
            ),
            r#"{"version":1,"request_id":"abc","credential":"x"}"#.to_string(),
            r#"{"version":1,"request_id":"abc","credential":"x","send_by_unix_ms":1}"#.to_string(),
            format!(
                r#"{{"version":1,"request_id":"abc","credential":"x","refusal":"r","send_by_unix_ms":{later}}}"#
            ),
            r#"{"version":1,"request_id":"abc"}"#.to_string(),
        ] {
            let withheld = reply(&json)
                .err()
                .unwrap_or_else(|| panic!("{json:?} released"));
            assert_eq!(withheld.code, None, "{json:?}");
            assert_eq!(withheld.workload_body(), b"credential source unavailable");
            assert!(
                !withheld.reason.contains("\"x\""),
                "{json:?}: {}",
                withheld.reason
            );
        }
    }

    #[test]
    fn the_request_document_states_the_request_without_framing_or_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.append("Host", "api.example.com");
        headers.append("User-Agent", "gh/2.0");
        headers.append("Connection", "keep-alive, X-Hop");
        headers.append("X-Hop", "drop me");
        headers.append("Content-Length", "4");
        headers.append("Transfer-Encoding", "chunked");
        headers.append("Proxy-Authorization", "Basic x");
        headers.append("Accept", "application/json");
        let ask = Ask {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/graphql",
            query: "a=1",
            headers: &headers,
            body: b"\x00\xffok",
        };
        let document: serde_json::Value =
            serde_json::from_slice(&request_document("abc", &ask).unwrap()).unwrap();
        assert_eq!(
            document,
            serde_json::json!({
                "version": 1,
                "request_id": "abc",
                "target": {
                    "scheme": "https",
                    "host": "api.example.com",
                    "port": 443,
                    "method": "POST",
                    "path": "/graphql",
                    "query": "a=1"
                },
                "headers": [["user-agent", "gh/2.0"], ["accept", "application/json"]],
                "body": "AP9vaw=="
            })
        );
    }

    #[test]
    fn a_request_id_is_fresh_hex() {
        let first = new_request_id().unwrap();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, new_request_id().unwrap());
    }

    #[test]
    fn an_https_source_listens_on_its_own_authority_only() {
        let source = CredentialSource::new("cp", "https://cp.example.com:8443/x").unwrap();
        assert!(source.listens_on("cp.example.com", 8443));
        assert!(source.listens_on("CP.example.com.", 8443));
        assert!(!source.listens_on("cp.example.com", 443));
        assert!(!source.listens_on("other.example.com", 8443));
        let unix = CredentialSource::new("cp", "unix:///run/cp.sock").unwrap();
        assert!(!unix.listens_on("localhost", 443));
    }
}
