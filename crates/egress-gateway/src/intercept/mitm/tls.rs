//! Selective TLS termination for the MITM adapter.

use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use super::ca::EphemeralCa;
use crate::error::{ProxyError, Result};

/// Build a rustls [`ServerConfig`] presenting the per-host leaf minted under `ca` for `host`.
/// This is the server side of interception: what the workload's client sees.
pub(crate) fn server_config_for_host(ca: &EphemeralCa, host: &str) -> Result<ServerConfig> {
    let leaf = ca.leaf_for(host)?;
    let cert_chain: Vec<CertificateDer<'static>> = leaf
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.to_vec()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| ProxyError::Intercept(format!("server TLS config for {host}: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Build the upstream (client) rustls [`ClientConfig`] with the additive trust bundle:
/// system roots (via `webpki-roots`) plus any PEM certs supplied in `extra_ca_pems` (e.g. a route's
/// custom CA). The upstream must present a cert the box legitimately trusts — a pin rejection here
/// surfaces as a handshake error the caller treats as a hard-fail drop.
pub(super) fn upstream_client_config(extra_ca_pems: &[String]) -> Result<ClientConfig> {
    Ok(ClientConfig::builder()
        .with_root_certificates(upstream_root_store(extra_ca_pems)?)
        .with_no_client_auth())
}

/// The upstream root store: the public roots, then every extra CA, added and never substituted.
fn upstream_root_store(extra_ca_pems: &[String]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    // System roots — the base of the additive bundle.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Additive: any extra CA PEMs (a route's custom CA bundle).
    for pem in extra_ca_pems {
        for cert in parse_pem_certs(pem)? {
            roots
                .add(cert)
                .map_err(|e| ProxyError::Intercept(format!("adding extra CA: {e}")))?;
        }
    }
    Ok(roots)
}

/// The certificates one operator PEM bundle adds to the upstream trust store, each as DER, or the
/// reason the bundle is refused.
///
/// Stricter than the gateway's own reading in `upstream_client_config`, never looser: every PEM
/// block must be a `CERTIFICATE`, at least one must be present, and each must be accepted as a
/// trust anchor exactly as the gateway's root store accepts it. A caller that checks a bundle here
/// before it starts the gateway therefore cannot hand the gateway a bundle it would refuse, and
/// learns which file is at fault before anything runs.
pub fn upstream_ca_certificates(pem: &str) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    for section in <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(pem.as_bytes()) {
        let (kind, der) = section.map_err(|error| format!("it is not valid PEM: {error}"))?;
        if kind != SectionKind::Certificate {
            return Err(format!(
                "it holds a {kind:?} PEM block, and only CERTIFICATE blocks are accepted"
            ));
        }
        let mut probe = RootCertStore::empty();
        probe
            .add(CertificateDer::from(der.as_slice()))
            .map_err(|error| {
                format!(
                    "certificate {} is not a usable trust anchor: {error}",
                    certificates.len() + 1
                )
            })?;
        certificates.push(der);
    }
    if certificates.is_empty() {
        return Err("it holds no PEM certificate".to_string());
    }
    Ok(certificates)
}

/// Parse PEM-encoded certificates into DER, for the additive trust bundle.
fn parse_pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| ProxyError::Intercept(format!("bad PEM certificate: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_presents_minted_leaf() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let config = server_config_for_host(&ca, "api.example.com");
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn upstream_config_builds_with_system_roots() {
        let config = upstream_client_config(&[]);
        assert!(config.is_ok());
    }

    #[test]
    fn an_operator_bundle_yields_each_certificate() {
        let first = EphemeralCa::generate(None, None).unwrap();
        let second = EphemeralCa::generate(None, None).unwrap();
        let bundle = format!("{}{}", first.ca_cert_pem(), second.ca_cert_pem());
        let certificates = upstream_ca_certificates(&bundle).expect("two CA certificates");
        assert_eq!(
            certificates,
            [first.ca_cert_der().to_vec(), second.ca_cert_der().to_vec()]
        );
        // What this accepts, the gateway accepts.
        assert!(upstream_client_config(&[bundle]).is_ok());
    }

    #[test]
    fn an_operator_bundle_the_gateway_would_misread_is_refused() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let key =
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
        for (bundle, reason) in [
            (String::new(), "holds no PEM certificate"),
            (
                "not a certificate\n".to_string(),
                "holds no PEM certificate",
            ),
            (
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_string(),
                "not a usable trust anchor",
            ),
            (
                "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_string(),
                "not valid PEM",
            ),
            (format!("{}{key}", ca.ca_cert_pem()), "PrivateKey PEM block"),
        ] {
            let refusal = upstream_ca_certificates(&bundle).expect_err(reason);
            assert!(refusal.contains(reason), "{bundle:?}: {refusal}");
        }
    }

    #[test]
    fn extra_roots_are_added_to_the_public_roots_and_never_replace_them() {
        let ca = EphemeralCa::generate(None, None).unwrap();
        let roots = upstream_root_store(&[ca.ca_cert_pem().to_string()]).unwrap();
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 1);
        for anchor in webpki_roots::TLS_SERVER_ROOTS {
            assert!(
                roots.roots.iter().any(|kept| kept.subject == anchor.subject
                    && kept.subject_public_key_info == anchor.subject_public_key_info),
                "a public root is missing once an extra root is added"
            );
        }
        assert_eq!(
            upstream_root_store(&[]).unwrap().len(),
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
    }

    #[test]
    fn upstream_config_accepts_extra_ca() {
        // The ephemeral CA's own public PEM is a valid extra CA to add.
        let ca = EphemeralCa::generate(None, None).unwrap();
        let config = upstream_client_config(&[ca.ca_cert_pem().to_string()]);
        assert!(config.is_ok());
    }
}
