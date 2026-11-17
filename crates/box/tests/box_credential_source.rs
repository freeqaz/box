//! `[gateway.credential_source.<name>]` and `secret.ref = "source://<name>"`, asserted end to end
//! through `strands-box run`.
//!
//! The gateway-level suite (`egress-gateway`'s `credential_source_e2e.rs`) proves the exchange with
//! a trusted upstream: the released value reaches the upstream and is scrubbed from the response.
//! These prove the path an operator takes. A stub source listens on a Unix socket outside every
//! workload grant, and the shipped binary runs the egress probe as the workload.
//!
//! - A source that refuses refuses the request, with the source's reason code, before it leaves.
//! - The source sees the request target, the request headers without the placeholder or the
//!   framing headers, the body, and the box's bearer token.
//! - A source that does not answer in time, or answers with a reply that is not for this request,
//!   withholds the credential.
//! - A released value lets the request go to the upstream.
//! - Policy decides first: a request policy denies, or one without its placeholder, never reaches
//!   the source.
//! - The workload cannot connect to the source's socket, and a grant on its directory is refused.
//! - A bearer variable that is not set stops the run before the workload starts.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "support/fixture.rs"]
mod fixture;

use base64::Engine as _;
use fixture::{Configured, Request};

/// The variable the workload's placeholder is placed in.
const PLACEHOLDER_VARIABLE: &str = "STRANDS_BOX_E2E_SOURCE_PLACEHOLDER";

/// The variable the box reads its bearer token for the source from.
const BEARER_VARIABLE: &str = "STRANDS_BOX_E2E_SOURCE_BEARER";

/// The bearer token the box presents to the source.
const BEARER: &str = "bearer-e2e-6f2a";

/// The value the source releases, which only the upstream may see.
const RELEASED: &str = "ghs_e2e_released_9d41";

/// How the stub source answers.
#[derive(Clone, Copy)]
enum Reply {
    /// Release [`RELEASED`] for this request.
    Release,
    /// Refuse with this reason code.
    Refuse(&'static str),
    /// Answer only after this long.
    Stall(Duration),
    /// Release a value for another request id.
    WrongId,
    /// Answer with a body that is not a reply.
    Malformed,
}

/// A stub credential source on a Unix socket, recording each request document and bearer.
struct StubSource {
    /// The socket's directory, outside every grant the fixture writes. Short, because a socket
    /// path must fit the platform's `AF_UNIX` limit.
    directory: tempfile::TempDir,
    socket: PathBuf,
    asks: Arc<Mutex<Vec<serde_json::Value>>>,
    bearers: Arc<Mutex<Vec<String>>>,
}

impl StubSource {
    fn start(reply: Reply) -> Self {
        let directory = fixture::short_temporary_home();
        let socket = directory.path().join("source.sock");
        let listener = UnixListener::bind(&socket).expect("bind the source socket");
        let asks = Arc::new(Mutex::new(Vec::new()));
        let bearers = Arc::new(Mutex::new(Vec::new()));
        let (seen, presented) = (Arc::clone(&asks), Arc::clone(&bearers));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (seen, presented) = (Arc::clone(&seen), Arc::clone(&presented));
                std::thread::spawn(move || {
                    let _ = answer(stream, reply, &seen, &presented);
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

    fn directory(&self) -> &Path {
        self.directory.path()
    }

    fn asks(&self) -> Vec<serde_json::Value> {
        self.asks.lock().expect("source lock").clone()
    }

    fn bearers(&self) -> Vec<String> {
        self.bearers.lock().expect("source lock").clone()
    }
}

fn answer(
    mut stream: std::os::unix::net::UnixStream,
    reply: Reply,
    asks: &Mutex<Vec<serde_json::Value>>,
    bearers: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let header = |name: &str| {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
    };
    if let Some(bearer) = header("authorization") {
        bearers.lock().expect("source lock").push(bearer);
    }
    let length: usize = header("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    let ask: serde_json::Value = serde_json::from_slice(&body).map_err(std::io::Error::other)?;
    let id = ask["request_id"].as_str().unwrap_or_default().to_string();
    asks.lock().expect("source lock").push(ask);
    let send_by = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        + 60_000;
    let document = match reply {
        Reply::Release => serde_json::json!({
            "version": 1, "request_id": id, "credential": RELEASED, "send_by_unix_ms": send_by
        })
        .to_string(),
        Reply::Refuse(code) => {
            serde_json::json!({"version": 1, "request_id": id, "refusal": code}).to_string()
        }
        Reply::Stall(delay) => {
            std::thread::sleep(delay);
            serde_json::json!({
                "version": 1, "request_id": id, "credential": RELEASED, "send_by_unix_ms": send_by
            })
            .to_string()
        }
        Reply::WrongId => serde_json::json!({
            "version": 1, "request_id": "0".repeat(32), "credential": RELEASED,
            "send_by_unix_ms": send_by
        })
        .to_string(),
        Reply::Malformed => "{\"version\":1,".to_string(),
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

/// A TCP upstream on localhost that counts the connections on which the gateway sent a byte. The
/// gateway opens the upstream connection when policy permits the `CONNECT`, before it reads the
/// request, and starts the upstream TLS handshake only when the request leaves. So a connection
/// that stays silent until the gateway closes it carried no request. The public roots do not vouch
/// for this upstream, so a request that leaves ends in a failed handshake.
struct CountingUpstream {
    port: u16,
    open: Arc<AtomicUsize>,
    spoken: Arc<AtomicUsize>,
}

impl CountingUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let port = listener.local_addr().expect("upstream addr").port();
        let (open, spoken) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (opened, spoke) = (Arc::clone(&open), Arc::clone(&spoken));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                opened.fetch_add(1, Ordering::SeqCst);
                let (opened, spoke) = (Arc::clone(&opened), Arc::clone(&spoke));
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut byte = [0_u8; 1];
                    if matches!(stream.read(&mut byte), Ok(1)) {
                        spoke.fetch_add(1, Ordering::SeqCst);
                    }
                    opened.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self { port, open, spoken }
    }

    /// The connections on which a request left, once every connection has spoken or closed.
    fn spoken(&self) -> usize {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while self.open.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        self.spoken.load(Ordering::SeqCst)
    }
}

/// A policy permitting the egress effects against `localhost:port`, with `http:request` only when
/// `http` is set.
fn permit_egress_to(port: u16, http: bool) -> String {
    let mut policy = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);

permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "localhost" && context.input.port == {port} }};
"#
    );
    if http {
        policy.push_str(&format!(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == "localhost" && context.input.port == {port} }};
"#
        ));
    }
    policy
}

/// The source table and one `[egress.a]` route on `localhost:port` that names it.
fn config_body(socket: &Path, port: u16) -> String {
    format!(
        "[gateway.credential_source.stub]\nendpoint = \"unix://{}\"\n\
         bearer = \"env://{BEARER_VARIABLE}\"\ntimeout_ms = 500\n\n\
         [egress.a]\ndestinations = [\"localhost:{port}\"]\n\
         secret.ref = \"source://stub\"\nsecret.env = \"{PLACEHOLDER_VARIABLE}\"\n",
        socket.display()
    )
}

/// The request for one box whose route names `source`, against `upstream`.
fn request_for(
    name: &str,
    upstream: &CountingUpstream,
    source: &StubSource,
    http: bool,
) -> Request {
    Request::with_config(
        name,
        &permit_egress_to(upstream.port, http),
        &config_body(&source.socket, upstream.port),
    )
}

/// One box, its stub source answering with `reply`, against `upstream`.
fn box_for(
    name: &str,
    upstream: &CountingUpstream,
    reply: Reply,
    http: bool,
) -> (Configured, Output, StubSource) {
    let source = StubSource::start(reply);
    let (box_, output) = request_for(name, upstream, &source, http)
        .env(BEARER_VARIABLE, BEARER)
        .attempt();
    (box_, output, source)
}

/// Send one POST through the gateway as the workload, with the placeholder at the operator's
/// placement when `with_placeholder` is set, and answer with the probe's JSON line.
fn send(box_: &Configured, port: u16, with_placeholder: bool) -> (String, String) {
    let mut request = serde_json::json!({
        "url": format!("https://localhost:{port}/repos/o/r/pulls?state=open"),
        "headers": {"x-request-tag": "e2e"},
        "body": {"title": "t"},
    });
    if with_placeholder {
        request["env_headers"] =
            serde_json::json!({"authorization": ["Bearer ", PLACEHOLDER_VARIABLE]});
    }
    let requests = serde_json::Value::Array(vec![request]).to_string();
    let output = box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        "trace-requests",
        requests.as_str(),
    ]);
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn created(output: &Output) {
    assert!(
        output.status.success(),
        "the creating run must succeed for this test to mean anything: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_refusing_source_refuses_the_request_before_it_leaves() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for(
        "src-refuse",
        &upstream,
        Reply::Refuse("installation_suspended"),
        true,
    );
    created(&output);

    let (out, err) = send(&box_, upstream.port, true);
    assert!(
        out.contains("\"status\":403")
            && out.contains("credential refused by its source: installation_suspended"),
        "the source's refusal refuses the request: stdout={out:?} stderr={err:?}"
    );
    assert_eq!(upstream.spoken(), 0, "a refused request never leaves");

    let asks = source.asks();
    assert_eq!(asks.len(), 1, "one request, one ask: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask["version"], 1);
    let id = ask["request_id"].as_str().expect("a request id");
    assert!(
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{id}"
    );
    assert_eq!(
        ask["target"],
        serde_json::json!({
            "scheme": "https", "host": "localhost", "port": upstream.port, "method": "POST",
            "path": "/repos/o/r/pulls", "query": "state=open"
        })
    );
    let headers = ask["headers"].as_array().expect("headers");
    let names: Vec<&str> = headers.iter().filter_map(|pair| pair[0].as_str()).collect();
    assert!(
        headers.contains(&serde_json::json!(["x-request-tag", "e2e"])),
        "{headers:?}"
    );
    for withheld in ["authorization", "host", "content-length", "connection"] {
        assert!(
            !names.contains(&withheld),
            "{withheld} reaches the source: {names:?}"
        );
    }
    let body = base64::engine::general_purpose::STANDARD
        .decode(ask["body"].as_str().expect("a body"))
        .expect("base64");
    assert_eq!(body, br#"{"title":"t"}"#);
    assert_eq!(source.bearers(), [format!("Bearer {BEARER}")]);
    assert!(!out.contains(BEARER) && !err.contains(BEARER));
}

#[test]
fn a_source_that_does_not_answer_in_time_withholds_the_credential() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for(
        "src-stall",
        &upstream,
        Reply::Stall(Duration::from_secs(3)),
        true,
    );
    created(&output);

    let (out, err) = send(&box_, upstream.port, true);
    assert!(
        out.contains("\"status\":403") && out.contains("credential source unavailable"),
        "a late source withholds the credential: stdout={out:?} stderr={err:?}"
    );
    assert_eq!(upstream.spoken(), 0);
    assert_eq!(source.asks().len(), 1, "no retry");
}

#[test]
fn a_reply_that_is_not_for_this_request_withholds_the_credential() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for (name, reply) in [
        ("src-wrong-id", Reply::WrongId),
        ("src-malformed", Reply::Malformed),
    ] {
        let upstream = CountingUpstream::start();
        let (box_, output, source) = box_for(name, &upstream, reply, true);
        created(&output);

        let (out, err) = send(&box_, upstream.port, true);
        assert!(
            out.contains("\"status\":403") && out.contains("credential source unavailable"),
            "{name}: stdout={out:?} stderr={err:?}"
        );
        assert!(!out.contains(RELEASED) && !err.contains(RELEASED), "{name}");
        assert_eq!(upstream.spoken(), 0, "{name}");
        assert_eq!(source.asks().len(), 1, "{name}");
    }
}

#[test]
fn a_released_credential_lets_the_request_go_upstream() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for("src-release", &upstream, Reply::Release, true);
    created(&output);

    let (out, err) = send(&box_, upstream.port, true);
    assert!(
        !out.contains("credential refused") && !out.contains("credential source unavailable"),
        "a released credential is not withheld: stdout={out:?} stderr={err:?}"
    );
    assert!(
        upstream.spoken() >= 1,
        "the request goes upstream: {out:?} {err:?}"
    );
    assert_eq!(source.asks().len(), 1);
    assert!(!out.contains(RELEASED) && !err.contains(RELEASED));
}

#[test]
fn policy_decides_before_the_source_is_asked() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for("src-policy", &upstream, Reply::Release, false);
    created(&output);
    let (out, err) = send(&box_, upstream.port, true);
    assert!(
        !out.contains("\"status\":200"),
        "policy denies the request: stdout={out:?} stderr={err:?}"
    );
    assert!(
        source.asks().is_empty(),
        "a denied request never reaches the source"
    );
    assert_eq!(upstream.spoken(), 0);

    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for("src-placeholder", &upstream, Reply::Release, true);
    created(&output);
    let (out, err) = send(&box_, upstream.port, false);
    assert!(
        out.contains("\"status\":403"),
        "a request without its placeholder is refused: stdout={out:?} stderr={err:?}"
    );
    assert!(
        source.asks().is_empty(),
        "a request without its placeholder never reaches the source"
    );
    assert_eq!(upstream.spoken(), 0);
}

#[test]
fn the_workload_cannot_reach_the_source() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let (box_, output, source) = box_for("src-reach", &upstream, Reply::Release, true);
    created(&output);
    let socket = source.socket.display().to_string();
    let run = box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        "connect-unix",
        socket.as_str(),
    ]);
    let out = String::from_utf8_lossy(&run.stdout).into_owned();
    assert!(
        out.contains("unix=refused"),
        "the workload must not connect to the source: {out:?} {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(source.asks().is_empty());

    // A grant on the socket's directory, or on a tree inside it, is refused before a box exists.
    let inside = source.directory().join("inside");
    std::fs::create_dir(&inside).expect("a directory inside the source directory");
    for (name, granted) in [
        ("src-grant", source.directory()),
        ("src-grant-in", inside.as_path()),
    ] {
        let (_, output) = request_for(name, &upstream, &source, true)
            .agent_read(&[granted])
            .env(BEARER_VARIABLE, BEARER)
            .attempt();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{name}: {stderr}");
        assert!(
            stderr.contains("holds a credential source's socket"),
            "{name}: the refusal names the reason: {stderr}"
        );
    }
}

#[test]
fn an_unset_bearer_stops_the_run_before_the_workload_starts() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = CountingUpstream::start();
    let source = StubSource::start(Reply::Release);
    let request = request_for("src-bearer", &upstream, &source, true);
    let (_, output) = request.attempt();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(BEARER_VARIABLE),
        "the refusal names the variable: {stderr}"
    );
    assert!(
        !stderr.contains("starting workload"),
        "the refusal comes before the workload is announced: {stderr}"
    );
}
