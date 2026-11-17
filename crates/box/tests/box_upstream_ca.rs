//! `[gateway] upstream_ca_file`, asserted end to end through `strands-box run`.
//!
//! The gateway-level suites (`egress-gateway`'s `interception_e2e.rs`) prove the additive trust
//! store with `MitmConfig::upstream_ca_pems`. These prove the path an operator takes: a file named in
//! `box.toml` is read, reaches the gateway that the workload's request goes through, and changes
//! exactly one thing, which roots vouch for an upstream server. Each case runs the shipped binary
//! against a real TLS upstream on localhost whose certificate a private CA signed.
//!
//! - Without the key, the private upstream is refused: the public roots do not vouch for it.
//! - With the key, the same upstream is reached, and the credential swap completes on the wire.
//! - With the key, a host signed by a different private CA is still refused, while the trusted CA's
//!   host is reached through the same box.
//! - A root whose name constraints exclude the host does not vouch for it, while a root constrained
//!   to the host's name in the same file does, which is how an operator narrows a gateway-wide root
//!   to the names it is meant for.
//! - A file the gateway could not use is refused before the workload starts.
//! - The public roots still verify a public host (network, so `#[ignore]`d by default).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Output;
use std::sync::{Arc, Mutex};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{Configured, Request};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
    NameConstraints,
};

/// The real secret, which only the upstream may see.
const REAL_SECRET: &str = "sk_live_e2e_upstream_ca_7c1d";

/// The environment variable the operator points the locator at.
const SECRET_VARIABLE: &str = "STRANDS_BOX_E2E_UPSTREAM_CA_TOKEN";

/// The CA file's name beside `box.toml`, so the case also proves the path resolves there.
const CA_FILE: &str = "upstream-ca.pem";

/// A private certificate authority.
struct PrivateCa {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl PrivateCa {
    /// A CA that may sign any name.
    fn new(name: &str) -> Self {
        Self::with_constraints(name, None)
    }

    /// A CA whose certificate permits only names under `permitted`.
    fn constrained_to(name: &str, permitted: &str) -> Self {
        Self::with_constraints(
            name,
            Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName(permitted.to_string())],
                excluded_subtrees: Vec::new(),
            }),
        )
    }

    fn with_constraints(name: &str, constraints: Option<NameConstraints>) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.name_constraints = constraints;
        let pem = params.self_signed(&key).expect("CA self-signs").pem();
        Self {
            pem,
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf for `localhost`, as the certificate chain and key an upstream presents.
    fn leaf(&self) -> (Vec<rustls::pki_types::CertificateDer<'static>>, Vec<u8>) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf");
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.is_ca = IsCa::NoCa;
        let leaf = params.signed_by(&key, &self.issuer).expect("the CA signs");
        (vec![leaf.der().clone()], key.serialize_der())
    }
}

/// A TLS upstream on localhost presenting a leaf a [`PrivateCa`] signed, recording the
/// `Authorization` of each request it completes.
struct PrivateUpstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl PrivateUpstream {
    fn start(ca: &PrivateCa) -> Self {
        let (chain, key) = ca.leaf();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()))
            .expect("server TLS config");
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let port = listener.local_addr().expect("upstream addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    let _ = serve_one(stream, config, recorded);
                });
            }
        });
        Self { port, seen }
    }

    /// Every `Authorization` value of a request that completed its handshake.
    fn authorizations(&self) -> Vec<String> {
        self.seen.lock().expect("upstream lock").clone()
    }

    fn url(&self) -> String {
        format!("https://localhost:{}/v1/charge", self.port)
    }
}

fn serve_one(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    recorded: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let connection = rustls::ServerConnection::new(config)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if tls.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let authorization = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_else(|| "<absent>".to_string());
    recorded.lock().expect("upstream lock").push(authorization);
    let body = br#"{"ok":true}"#;
    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    tls.write_all(body)?;
    tls.flush()
}

/// A policy permitting the egress effects against `host` on each of `ports`.
fn permit_egress_to(host: &str, ports: &[u16]) -> String {
    let mut policy = String::from(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#,
    );
    for port in ports {
        policy.push_str(&format!(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }};

permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }};
"#
        ));
    }
    policy
}

/// One `[egress.a]` binding the fixture secret to `localhost` on each of `ports`, and the
/// `[gateway]` table when the box trusts the CA file.
fn config_body(ports: &[u16], trusts_the_file: bool) -> String {
    let destinations = ports
        .iter()
        .map(|port| format!("\"localhost:{port}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!(
        "[egress.a]\ndestinations = [{destinations}]\nsecret.ref = \"env://{SECRET_VARIABLE}\"\n"
    );
    if trusts_the_file {
        body.push_str(&format!("\n[gateway]\nupstream_ca_file = \"{CA_FILE}\"\n"));
    }
    body
}

/// Place `pem` beside the `box.toml` the fixture is about to write.
fn place_ca_file(request: &Request, pem: &str) {
    let directory = request
        .operator_home()
        .join("workspace")
        .join(".strands-box");
    std::fs::create_dir_all(&directory).expect("the workspace's .strands-box directory");
    std::fs::write(directory.join(CA_FILE), pem).expect("write the CA file");
}

/// Configure a box against `upstreams`, trusting `ca_file` when it is given.
fn box_for(
    name: &str,
    upstreams: &[&PrivateUpstream],
    ca_file: Option<&str>,
) -> (Configured, Output) {
    let ports: Vec<u16> = upstreams.iter().map(|upstream| upstream.port).collect();
    let request = Request::with_config(
        name,
        &permit_egress_to("localhost", &ports),
        &config_body(&ports, ca_file.is_some()),
    )
    .env(SECRET_VARIABLE, REAL_SECRET);
    if let Some(pem) = ca_file {
        place_ca_file(&request, pem);
    }
    request.attempt()
}

/// Run the egress probe as the workload, sending the phantom the box provisioned.
fn probe(box_: &Configured, url: &str) -> (String, String) {
    let output = box_.run(&[env!("CARGO_BIN_EXE_box-egress-probe"), url, SECRET_VARIABLE]);
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

/// The public roots do not vouch for a private CA, so the gateway refuses the upstream leg.
#[test]
fn without_the_key_a_private_ca_upstream_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let ca = PrivateCa::new("Box e2e private CA");
    let upstream = PrivateUpstream::start(&ca);
    let (box_, output) = box_for("upca-none", &[&upstream], None);
    created(&output);

    let (out, err) = probe(&box_, &upstream.url());
    assert!(
        out.contains("status=") || err.contains("probe-error"),
        "the probe must reach the gateway: stdout={out:?} stderr={err:?}"
    );
    assert!(
        !out.contains("status=200"),
        "an upstream no trusted root signed must not answer: stdout={out:?} stderr={err:?}"
    );
    assert!(
        upstream.authorizations().is_empty(),
        "no request may complete against the private upstream: {:?}",
        upstream.authorizations()
    );
}

/// With the CA file, the same upstream is reached, and the upstream receives the real secret: the
/// credential swap, end to end through `run`, which no layer above the gateway could show before.
#[test]
fn with_the_key_a_private_ca_upstream_is_reached_and_receives_the_real_secret() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let ca = PrivateCa::new("Box e2e private CA");
    let upstream = PrivateUpstream::start(&ca);
    let (box_, output) = box_for("upca-trusted", &[&upstream], Some(&ca.pem));
    created(&output);
    let created_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        created_stderr.contains("the egress gateway also trusts the root sha256 ")
            && created_stderr.contains(CA_FILE),
        "run must disclose the root it trusts and the file it came from: {created_stderr}"
    );

    let (out, err) = probe(&box_, &upstream.url());
    assert!(
        out.contains("status=200"),
        "the private upstream must answer once its CA is trusted: stdout={out:?} stderr={err:?}"
    );
    assert_eq!(
        upstream.authorizations(),
        [format!("Bearer {REAL_SECRET}")],
        "the upstream receives the real secret, and only once"
    );
    assert!(
        !out.contains(REAL_SECRET) && !err.contains(REAL_SECRET),
        "the real secret never reaches the workload: {out:?} / {err:?}"
    );
}

/// Trust is in the named roots, not in "any private CA": another CA's host is still refused, while
/// the trusted CA's host answers through the same box, so the refusal is the root's doing.
#[test]
fn with_the_key_a_host_signed_by_another_private_ca_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let trusted = PrivateCa::new("Box e2e trusted CA");
    let other = PrivateCa::new("Box e2e other CA");
    let reached = PrivateUpstream::start(&trusted);
    let refused = PrivateUpstream::start(&other);
    let (box_, output) = box_for("upca-other", &[&reached, &refused], Some(&trusted.pem));
    created(&output);

    let (out, err) = probe(&box_, &reached.url());
    assert!(
        out.contains("status=200"),
        "the trusted CA's host must answer: stdout={out:?} stderr={err:?}"
    );
    let (out, err) = probe(&box_, &refused.url());
    assert!(
        !out.contains("status=200"),
        "a host the trusted root did not sign must not answer: stdout={out:?} stderr={err:?}"
    );
    assert!(refused.authorizations().is_empty());
}

/// A root's name constraints hold: with two roots in one file, the root permitted `localhost`
/// vouches for its `localhost` leaf, and the root permitted only `example.internal` does not vouch
/// for the `localhost` leaf it signed. This is the narrowing an operator can apply today to a root
/// the gateway trusts for every upstream.
#[test]
fn a_name_constrained_root_vouches_only_for_its_names() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let inside = PrivateCa::constrained_to("Box e2e CA for localhost", "localhost");
    let outside = PrivateCa::constrained_to("Box e2e CA for example.internal", "example.internal");
    let reached = PrivateUpstream::start(&inside);
    let refused = PrivateUpstream::start(&outside);
    let bundle = format!("{}{}", inside.pem, outside.pem);
    let (box_, output) = box_for("upca-constrained", &[&reached, &refused], Some(&bundle));
    created(&output);
    let created_stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        created_stderr
            .matches("the egress gateway also trusts the root sha256 ")
            .count(),
        2,
        "run names each root of the bundle: {created_stderr}"
    );

    let (out, err) = probe(&box_, &reached.url());
    assert!(
        out.contains("status=200"),
        "a leaf inside its root's permitted names must answer: stdout={out:?} stderr={err:?}"
    );
    let (out, err) = probe(&box_, &refused.url());
    assert!(
        !out.contains("status=200"),
        "a leaf outside the root's permitted names must not answer: stdout={out:?} stderr={err:?}"
    );
    assert!(refused.authorizations().is_empty());
}

/// A file the gateway could not use is refused by the creating run, naming the key and the reason,
/// and no workload runs.
#[test]
fn a_ca_file_holding_a_private_key_is_refused_before_the_workload_starts() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let ca = PrivateCa::new("Box e2e private CA");
    let upstream = PrivateUpstream::start(&ca);
    let key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
    let (box_, output) = box_for("upca-key", &[&upstream], Some(&format!("{}{key}", ca.pem)));
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the creating run must refuse: {stderr}"
    );
    for fragment in [
        "`[gateway] upstream_ca_file`",
        CA_FILE,
        "PrivateKey PEM block",
    ] {
        assert!(
            stderr.contains(fragment),
            "the refusal names {fragment:?}: {stderr}"
        );
    }
    assert!(
        !stderr.contains("starting workload"),
        "the refusal comes before the workload is announced: {stderr}"
    );
    let run = box_.run(&["/bin/bash", "-c", "printf 'NEVER\\n'"]);
    assert!(!String::from_utf8_lossy(&run.stdout).contains("NEVER"));
}

/// The roots are added, never substituted: a public host still verifies with the key set.
///
/// Reaches `example.com` over the network, so it runs only when asked:
/// `cargo test -p strands-box --all-features --test box_upstream_ca -- --ignored`.
#[test]
#[ignore = "reaches a public host over the network"]
fn with_the_key_a_public_host_still_verifies_against_the_public_roots() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let ca = PrivateCa::new("Box e2e private CA");
    let request = Request::with_config(
        "upca-public",
        &permit_egress_to("example.com", &[443]),
        &format!("[gateway]\nupstream_ca_file = \"{CA_FILE}\"\n"),
    )
    .agent_env("PROBE_TOKEN", "not-a-secret");
    place_ca_file(&request, &ca.pem);
    let (box_, output) = request.attempt();
    created(&output);

    let output = box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        "https://example.com/",
        "PROBE_TOKEN",
    ]);
    let out = String::from_utf8_lossy(&output.stdout).into_owned();
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        out.contains("status=") && !out.contains("status=502") && !out.contains("status=403"),
        "a public host must still verify against the public roots: stdout={out:?} stderr={err:?}"
    );
}
