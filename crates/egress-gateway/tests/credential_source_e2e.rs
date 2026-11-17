//! A request-time credential source, end to end over real TLS.
//!
//! A route built with `RouteSpec::request_time` names a source. After policy permits a request on
//! that route, the gateway sends the request's target, headers, and body to the source, and attaches
//! the value the source releases at the route's own placement. The source can only release a value
//! or refuse: it never permits a request, and every failure withholds the credential.
//!
//! Each scenario runs a stub source on a Unix socket, a real `MitmInterceptor` that trusts a local
//! TLS upstream, and a real TLS workload client:
//!
//! - a released value reaches the upstream at the operator's placement, and the placeholder does not;
//! - a released value the upstream echoes is scrubbed from the response the workload reads;
//! - a refusal, a timeout, a body over the source's limit, a reply for another request, a malformed
//!   reply, and a send-by time that has passed each refuse the request with 403 before it leaves;
//! - a request policy denies never reaches the source;
//! - the workload cannot open a tunnel to the source's own `https` authority.
//!
//! Requires the default-on `tls-intercept` feature.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use credentials::{DestinationPattern, InjectMode, RouteSpec, Vault, VaultConfig};
use egress_gateway::{
    CapabilitySet, CredentialCapability, CredentialSource, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, MitmConfig, MitmInterceptor, StubEmitter,
};

use harness::{TlsUpstream, WorkloadClient, header_value};

/// The value the source releases, which only the upstream may see.
const RELEASED: &str = "ghs_released_e2e_3b8f";

/// The bearer token the gateway presents to the source.
const BEARER: &str = "source-bearer-e2e";

/// An upstream response that echoes [`RELEASED`] in a header and in its body.
const ECHO: &[u8] = b"HTTP/1.1 200 OK\r\nX-Echo: token ghs_released_e2e_3b8f\r\n\
Content-Length: 34\r\nConnection: close\r\n\r\n{\"seen\":\"ghs_released_e2e_3b8f\"}  ";

/// How the stub source answers.
#[derive(Clone, Copy)]
enum Reply {
    Release,
    Refuse(&'static str),
    Stall(Duration),
    WrongId,
    Malformed,
    Expired,
}

/// A stub source on a Unix socket, recording each request document and each bearer it was shown.
struct StubSource {
    directory: PathBuf,
    socket: PathBuf,
    asks: Arc<Mutex<Vec<serde_json::Value>>>,
    bearers: Arc<Mutex<Vec<String>>>,
}

impl StubSource {
    fn start(reply: Reply) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let directory = std::env::temp_dir().join(format!(
            "box-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).expect("source directory");
        let socket = directory.join("source.sock");
        let listener = UnixListener::bind(&socket).expect("bind source");
        let asks = Arc::new(Mutex::new(Vec::new()));
        let bearers = Arc::new(Mutex::new(Vec::new()));
        let (seen, shown) = (Arc::clone(&asks), Arc::clone(&bearers));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (seen, shown) = (Arc::clone(&seen), Arc::clone(&shown));
                std::thread::spawn(move || {
                    let _ = answer(stream, reply, &seen, &shown);
                });
            }
        });
        Self {
            directory,
            socket,
            asks,
            bearers,
        }
    }

    /// This source as the gateway is configured with it.
    fn declared(&self) -> CredentialSource {
        CredentialSource::new("stub", &format!("unix://{}", self.socket.display()))
            .expect("a valid endpoint")
            .bearer(BEARER.to_string())
            .timeout(Duration::from_millis(500))
    }

    fn asks(&self) -> Vec<serde_json::Value> {
        // A moment for the handler to record an ask that is in flight.
        std::thread::sleep(Duration::from_millis(50));
        self.asks.lock().expect("source lock").clone()
    }

    fn bearers(&self) -> Vec<String> {
        self.bearers.lock().expect("source lock").clone()
    }
}

impl Drop for StubSource {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn answer(
    mut stream: UnixStream,
    reply: Reply,
    asks: &Mutex<Vec<serde_json::Value>>,
    bearers: &Mutex<Vec<String>>,
) -> io::Result<()> {
    let head = harness::read_http_head(&mut stream);
    if let Some(bearer) = header_value(&head, "authorization") {
        bearers
            .lock()
            .expect("source lock")
            .push(bearer.to_string());
    }
    let length: usize = header_value(&head, "content-length")
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    let ask: serde_json::Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
    let id = ask["request_id"].as_str().unwrap_or_default().to_string();
    asks.lock().expect("source lock").push(ask);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    let release = |id: &str, send_by: u64| {
        serde_json::json!({
            "version": 1, "request_id": id, "credential": RELEASED, "send_by_unix_ms": send_by
        })
        .to_string()
    };
    let document = match reply {
        Reply::Release => release(&id, now + 60_000),
        Reply::Refuse(code) => {
            serde_json::json!({"version": 1, "request_id": id, "refusal": code}).to_string()
        }
        Reply::Stall(delay) => {
            std::thread::sleep(delay);
            release(&id, now + 60_000)
        }
        Reply::WrongId => release(&"0".repeat(32), now + 60_000),
        Reply::Malformed => format!("{{\"version\":1,\"credential\":\"{RELEASED}\""),
        Reply::Expired => release(&id, now.saturating_sub(1_000)),
    };
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{document}",
            document.len()
        )
        .as_bytes(),
    )?;
    stream.flush()
}

/// A stand-in for the policy decision point: it permits every connection, and permits an HTTP
/// request only when `requests` is set.
struct Policy {
    requests: bool,
}

impl EffectInterceptor for Policy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if !self.requests && matches!(attempt, EffectAttempt::HttpRequest { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test policy",
            ));
        }
        Ok(Box::new(NoopPermit))
    }
}

struct NoopPermit;

impl EffectPermit for NoopPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }
    fn mark_indeterminate(self: Box<Self>) {}
}

fn pat(host: &str, port: u16) -> DestinationPattern {
    DestinationPattern::parse(&format!("{host}:{port}")).unwrap()
}

/// A vault with one request-time route on `host:port` that names the source `stub`, attached as
/// `Authorization: token <value>`. Returns the vault and its phantom.
fn request_time_store(host: &str, port: u16) -> (Arc<Vault>, String) {
    let opened = Vault::open(
        VaultConfig::new(credentials::Backend::local(), "tenant").route(RouteSpec::request_time(
            pat(host, port),
            "stub",
            InjectMode::header("token {}".to_string(), None).expect("a header placement"),
        )),
    )
    .expect("a request-time route opens with no secret");
    let phantom = opened.phantoms()[0].token().to_string();
    (Arc::new(opened.into_vault()), phantom)
}

thread_local! {
    static RECORDS: StubEmitter = StubEmitter::new();
}

/// A gateway trusting `upstream`, with one request-time route on `host` and `sources` declared.
fn start_gateway(
    host: &str,
    upstream: &TlsUpstream,
    sources: Vec<CredentialSource>,
    requests: bool,
) -> (egress_gateway::MitmHandle, String) {
    let (store, phantom) = request_time_store(host, upstream.port());
    let controls = CapabilitySet::new(vec![CredentialCapability::new(
        pat(host, upstream.port()),
        store,
    )]);
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        credential_sources: sources,
        ..MitmConfig::default()
    };
    let records = Box::new(RECORDS.with(Clone::clone));
    let handle = MitmInterceptor::start_with(
        config,
        controls,
        Arc::new(Policy { requests }),
        records,
        None,
    )
    .expect("the gateway starts");
    (handle, phantom)
}

/// Send one POST with the phantom at the placement and `body`, and read the whole response.
fn send(
    handle: &egress_gateway::MitmHandle,
    host: &str,
    port: u16,
    phantom: &str,
    body: &[u8],
) -> String {
    let mut client = WorkloadClient::connect(handle.port().expect("TCP"), host, port);
    client.send_request(
        "POST",
        "/repos/o/r/pulls?state=open",
        &[
            ("Authorization", &format!("token {phantom}")),
            ("X-Request-Tag", "e2e"),
        ],
        body,
    );
    client.read_response()
}

fn assert_withheld(response: &str, reason: &str) {
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(
        header_value(response, "x-strands-box-egress").map(str::trim),
        Some("refused"),
        "{response}"
    );
    assert!(response.contains(reason), "{reason}: {response}");
    assert!(!response.contains(RELEASED), "{response}");
}

#[test]
fn a_released_value_reaches_the_upstream_at_the_operator_placement() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let source = StubSource::start(Reply::Release);
    let (handle, phantom) = start_gateway(host, &upstream, vec![source.declared()], true);

    let response = send(
        &handle,
        host,
        upstream.port(),
        &phantom,
        br#"{"title":"t"}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let seen = upstream.last_request();
    assert_eq!(
        seen.header("authorization").as_deref(),
        Some(format!("token {RELEASED}").as_str())
    );
    assert!(!seen.raw.contains(&phantom), "the placeholder never leaves");

    let asks = source.asks();
    assert_eq!(asks.len(), 1, "one request, one ask, no retry");
    let ask = &asks[0];
    assert_eq!(ask["version"], 1);
    assert_eq!(
        ask["target"],
        serde_json::json!({
            "scheme": "https", "host": host, "port": upstream.port(), "method": "POST",
            "path": "/repos/o/r/pulls", "query": "state=open"
        })
    );
    let headers = ask["headers"].as_array().expect("headers");
    assert!(
        headers.contains(&serde_json::json!(["x-request-tag", "e2e"])),
        "{headers:?}"
    );
    for pair in headers {
        let name = pair[0].as_str().expect("a name");
        assert_eq!(name, name.to_ascii_lowercase(), "names are lowercase");
        assert!(
            !["authorization", "host", "content-length", "connection"].contains(&name),
            "{name} reaches the source"
        );
    }
    assert!(
        !ask.to_string().contains(&phantom),
        "the placeholder never reaches the source"
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(ask["body"].as_str().expect("a body"))
            .expect("base64"),
        br#"{"title":"t"}"#
    );
    assert_eq!(source.bearers(), [format!("Bearer {BEARER}")]);
    for record in RECORDS.with(StubEmitter::records) {
        let text = format!("{record:?}");
        assert!(!text.contains(RELEASED) && !text.contains(BEARER), "{text}");
    }
}

#[test]
fn a_released_value_the_upstream_echoes_is_scrubbed() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start_with_response(host, ECHO);
    let source = StubSource::start(Reply::Release);
    let (handle, phantom) = start_gateway(host, &upstream, vec![source.declared()], true);

    let response = send(&handle, host, upstream.port(), &phantom, b"");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        !response.contains(RELEASED),
        "the released value is scrubbed from the response: {response}"
    );
    assert_eq!(
        upstream.last_request().header("authorization").as_deref(),
        Some(format!("token {RELEASED}").as_str())
    );
}

#[test]
fn every_source_failure_refuses_the_request_before_it_leaves() {
    let host = "api.github.test";
    for (reply, reason) in [
        (
            Reply::Refuse("installation_suspended"),
            "credential refused by its source: installation_suspended",
        ),
        (
            Reply::Refuse("bad code!"),
            "credential refused by its source: invalid",
        ),
        (
            Reply::Stall(Duration::from_secs(2)),
            "credential source unavailable",
        ),
        (Reply::WrongId, "credential source unavailable"),
        (Reply::Malformed, "credential source unavailable"),
        (Reply::Expired, "credential source unavailable"),
    ] {
        let upstream = TlsUpstream::start(host);
        let source = StubSource::start(reply);
        let (handle, phantom) = start_gateway(host, &upstream, vec![source.declared()], true);
        let response = send(&handle, host, upstream.port(), &phantom, b"{}");
        assert_withheld(&response, reason);
        assert_eq!(
            upstream.request_count(),
            0,
            "{reason}: the request never leaves"
        );
        assert_eq!(source.asks().len(), 1, "{reason}: one ask, no retry");
    }
}

#[test]
fn a_body_over_the_source_limit_is_refused_without_asking() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let source = StubSource::start(Reply::Release);
    let (handle, phantom) = start_gateway(
        host,
        &upstream,
        vec![source.declared().max_body_bytes(8)],
        true,
    );
    let response = send(&handle, host, upstream.port(), &phantom, &[b'x'; 64]);
    assert_withheld(&response, "credential source unavailable");
    assert_eq!(upstream.request_count(), 0);
    assert!(source.asks().is_empty(), "an oversize body is never sent");
}

#[test]
fn a_request_policy_denies_never_reaches_the_source() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let source = StubSource::start(Reply::Release);
    let (handle, phantom) = start_gateway(host, &upstream, vec![source.declared()], false);
    let response = send(&handle, host, upstream.port(), &phantom, b"{}");
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(
        source.asks().is_empty(),
        "policy decides before the source is asked"
    );
    assert_eq!(upstream.request_count(), 0);
}

#[test]
fn a_request_without_its_placeholder_never_reaches_the_source() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let source = StubSource::start(Reply::Release);
    let (handle, _) = start_gateway(host, &upstream, vec![source.declared()], true);
    let response = send(&handle, host, upstream.port(), "not-the-placeholder", b"{}");
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(source.asks().is_empty());
    assert_eq!(upstream.request_count(), 0);
}

#[test]
fn the_workload_cannot_tunnel_to_the_source_authority() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let declared = CredentialSource::new("stub", "https://source.internal.test:9443/release")
        .expect("a valid endpoint");
    let (handle, _) = start_gateway(host, &upstream, vec![declared], true);
    let mut client = WorkloadClient::connect_raw(handle.port().expect("TCP"));
    let reply = client.raw_connect("source.internal.test", 9443);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

#[test]
fn two_sources_with_one_name_are_refused_at_start() {
    let host = "api.github.test";
    let upstream = TlsUpstream::start(host);
    let source = StubSource::start(Reply::Release);
    let (store, _) = request_time_store(host, upstream.port());
    let config = MitmConfig {
        credential_sources: vec![source.declared(), source.declared()],
        ..MitmConfig::default()
    };
    let started = MitmInterceptor::start_with(
        config,
        CapabilitySet::new(vec![CredentialCapability::new(
            pat(host, upstream.port()),
            store,
        )]),
        Arc::new(Policy { requests: true }),
        Box::new(StubEmitter::new()),
        None,
    );
    assert!(started.is_err());
}
