//! `[gateway]`: settings that apply to every request through the box's egress gateway.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// The scheme of a `[gateway.credential_source.<name>]` endpoint on a Unix socket.
const UNIX_ENDPOINT: &str = "unix://";

/// The longest wait for a source's reply an operator may set, in milliseconds.
const MAX_TIMEOUT_MS: u64 = 60_000;

/// The largest request body an operator may let the gateway send to a source.
const MAX_BODY_BYTES: u64 = 16 * 1024 * 1024;

/// The longest name a credential source may have.
const MAX_SOURCE_NAME_LEN: usize = 64;

/// The box-wide egress gateway settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gateway {
    /// The hosts whose plain `http://` request to port 80 the gateway decides and sends as
    /// `https://` on port 443.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) upgrade_http: Vec<String>,

    /// A PEM file of CA certificates the gateway trusts, in addition to its built-in public roots,
    /// when it verifies an upstream server. Relative to the configuration file's directory unless
    /// absolute; the stored record keeps the canonical path that was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream_ca_file: Option<PathBuf>,
    /// The endpoints the gateway asks, per request, for the credential of a route whose
    /// `secret.ref` is `source://<name>`. Keyed by that name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) credential_source: BTreeMap<String, CredentialSource>,
}

/// One `[gateway.credential_source.<name>]`: an endpoint that releases one request's credential.
///
/// It is configuration, not policy. The gateway asks it only after policy permits the request,
/// and its reply can only give a value for the route's own placement or refuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialSource {
    /// Where the gateway sends the request: `unix:///absolute/path` or
    /// `https://host[:port][/path]`. The stored record keeps a Unix socket path canonical.
    pub(crate) endpoint: String,

    /// A PEM file of the CA certificates that sign an `https` endpoint's certificate, in place of
    /// the public roots. Relative to the configuration file's directory unless absolute; the stored
    /// record keeps the canonical path that was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ca_file: Option<PathBuf>,

    /// The token the gateway presents to the source as `Authorization: Bearer`, as `env://NAME`.
    /// The box reads the variable when it starts and never stores its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bearer: Option<String>,

    /// How long the gateway waits for the reply, in milliseconds. Defaults to 5000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) timeout_ms: Option<u64>,

    /// The largest request body the gateway sends to the source. A larger body is refused, not
    /// cut. Defaults to 1 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_body_bytes: Option<u64>,
}

impl CredentialSource {
    /// The socket path of a `unix://` endpoint, or `None` for an `https` endpoint.
    pub(crate) fn socket_path(&self) -> Option<&Path> {
        self.endpoint.strip_prefix(UNIX_ENDPOINT).map(Path::new)
    }

    /// The variable the bearer token is read from, or `None` when the source takes no token.
    pub(crate) fn bearer_variable(&self) -> Option<&str> {
        self.bearer.as_deref()?.strip_prefix("env://")
    }

    /// The CA file, resolved against the configuration file's directory.
    pub(super) fn ca_path(&self, config_path: &Path) -> Option<PathBuf> {
        let path = self.ca_file.as_ref()?;
        if path.is_absolute() {
            return Some(path.clone());
        }
        Some(
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path),
        )
    }

    /// Refuse a source this file may not express. `name` is its table key.
    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let refuse = |reason: String| {
            Err(ConfigError::Contract {
                reason: format!("`[gateway.credential_source.{name}]` {reason}"),
            })
        };
        if name.is_empty() || name.len() > MAX_SOURCE_NAME_LEN {
            return refuse(format!(
                "needs a name of 1 to {MAX_SOURCE_NAME_LEN} characters"
            ));
        }
        if let Some(bad) = name.chars().find(|c| !super::nameable(*c)) {
            return refuse(format!(
                "has a name that holds {bad:?}; a source name holds only letters, digits, '.', \
                 '_', and '-'"
            ));
        }
        // The gateway's own parser, so an endpoint accepted here cannot fail the gateway's start.
        if let Err(error) = egress_gateway::CredentialSource::new(name, &self.endpoint) {
            return refuse(format!("endpoint is refused: {error}"));
        }
        if self.ca_file.is_some() && self.socket_path().is_some() {
            return refuse(
                "sets ca_file on a unix:// endpoint; a CA file verifies only an https endpoint"
                    .to_string(),
            );
        }
        if let Some(bearer) = &self.bearer {
            match self.bearer_variable() {
                Some(variable) if super::env::valid_environment_name(variable) => {}
                _ => {
                    return refuse(format!(
                        "bearer {bearer:?} is not env://NAME; the box reads the token from the \
                         operator's environment when it starts"
                    ));
                }
            }
        }
        if let Some(timeout) = self.timeout_ms
            && !(1..=MAX_TIMEOUT_MS).contains(&timeout)
        {
            return refuse(format!(
                "timeout_ms {timeout} is not between 1 and {MAX_TIMEOUT_MS}"
            ));
        }
        if let Some(bytes) = self.max_body_bytes
            && bytes > MAX_BODY_BYTES
        {
            return refuse(format!(
                "max_body_bytes {bytes} is more than {MAX_BODY_BYTES}"
            ));
        }
        Ok(())
    }
}

impl Gateway {
    pub(super) fn is_default(&self) -> bool {
        self.upgrade_http.is_empty()
            && self.upstream_ca_file.is_none()
            && self.credential_source.is_empty()
    }

    /// The upstream CA file, resolved against the configuration file's directory.
    pub(super) fn upstream_ca_path(&self, config_path: &Path) -> Option<PathBuf> {
        let path = self.upstream_ca_file.as_ref()?;
        if path.is_absolute() {
            return Some(path.clone());
        }
        Some(
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path),
        )
    }

    /// Refuse an `upgrade_http` entry that is not one host name, and a credential source this file
    /// may not express.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for (name, source) in &self.credential_source {
            source.validate(name)?;
        }
        for entry in &self.upgrade_http {
            if let Some(reason) = not_a_host_name(entry) {
                return Err(ConfigError::Contract {
                    reason: format!(
                        "`[gateway] upgrade_http` entry {entry:?} is not a host name: {reason}; \
                         write a host name alone, such as \"static.rust-lang.org\""
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Why `entry` is not a host name the gateway can upgrade, or `None` when it is one.
fn not_a_host_name(entry: &str) -> Option<&'static str> {
    if entry.contains("://") {
        return Some("it names a scheme");
    }
    if entry.contains('*') {
        return Some("it is a wildcard");
    }
    let bare = entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(entry);
    if bare.parse::<IpAddr>().is_ok() {
        return Some("it is an IP address");
    }
    if entry.contains(':') {
        return Some("it names a port");
    }
    if entry.contains('/') {
        return Some("it names a path");
    }
    let host = egress_gateway::normalize_host(entry);
    if host.is_empty() {
        return Some("it is empty");
    }
    if !egress_gateway::is_bindable_host(&host) {
        return Some("it holds a character other than a letter, a digit, '.', '-', or '_'");
    }
    if host.split('.').any(str::is_empty) {
        return Some("it has an empty label");
    }
    if host.parse::<IpAddr>().is_ok()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Some("it is an IP address");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(entries: &[&str]) -> Gateway {
        Gateway {
            upgrade_http: entries.iter().map(|entry| entry.to_string()).collect(),
            upstream_ca_file: None,
            credential_source: BTreeMap::new(),
        }
    }

    /// A gateway that declares one credential source, `name`, as `table` spells it.
    fn source(name: &str, table: &str) -> Result<Gateway, String> {
        let gateway: Gateway = toml::from_str(&format!("[credential_source.{name}]\n{table}"))
            .map_err(|error| error.to_string())?;
        gateway.validate().map_err(|error| error.to_string())?;
        Ok(gateway)
    }

    #[test]
    fn a_credential_source_is_accepted() {
        let gateway = source(
            "github",
            "endpoint = \"unix:///run/source/source.sock\"\nbearer = \"env://SOURCE_TOKEN\"\n\
             timeout_ms = 2000\nmax_body_bytes = 0\n",
        )
        .expect("accepted");
        assert!(!gateway.is_default());
        let declared = &gateway.credential_source["github"];
        assert_eq!(
            declared.socket_path(),
            Some(Path::new("/run/source/source.sock"))
        );
        assert_eq!(declared.bearer_variable(), Some("SOURCE_TOKEN"));
        let https = source(
            "github",
            "endpoint = \"https://source.example.com:8443/release\"\nca_file = \"ca.pem\"\n",
        )
        .expect("accepted");
        assert_eq!(https.credential_source["github"].socket_path(), None);
        assert_eq!(
            https.credential_source["github"].ca_path(Path::new("/etc/box/box.toml")),
            Some(PathBuf::from("/etc/box/ca.pem"))
        );
    }

    #[test]
    fn a_credential_source_this_file_may_not_express_is_refused() {
        for (name, table, reason) in [
            (
                "github",
                "endpoint = \"http://source.example.com\"\n",
                "endpoint is refused",
            ),
            (
                "github",
                "endpoint = \"unix://run/source.sock\"\n",
                "relative socket path",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\nca_file = \"ca.pem\"\n",
                "verifies only an https endpoint",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\nbearer = \"SOURCE_TOKEN\"\n",
                "is not env://NAME",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\ntimeout_ms = 0\n",
                "timeout_ms 0",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\ntimeout_ms = 60001\n",
                "timeout_ms 60001",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\nmax_body_bytes = 16777217\n",
                "max_body_bytes",
            ),
            (
                "\"a b\"",
                "endpoint = \"unix:///run/source.sock\"\n",
                "has a name that holds",
            ),
            (
                "github",
                "endpoint = \"unix:///run/source.sock\"\nretry = 3\n",
                "unknown field",
            ),
        ] {
            let error = source(name, table).expect_err(reason);
            assert!(error.contains(reason), "{reason}: {error}");
        }
    }

    #[test]
    fn a_host_name_is_accepted() {
        for entry in [
            "static.rust-lang.org",
            "Static.Rust-Lang.Org",
            "static.rust-lang.org.",
            "localhost",
            "my_host.internal",
        ] {
            assert!(gateway(&[entry]).validate().is_ok(), "{entry:?}");
        }
        assert!(gateway(&[]).validate().is_ok());
        assert!(gateway(&[]).is_default());
    }

    #[test]
    fn an_entry_that_is_not_a_host_name_is_refused_with_its_reason() {
        for (entry, reason) in [
            ("http://static.rust-lang.org", "it names a scheme"),
            ("https://static.rust-lang.org", "it names a scheme"),
            ("static.rust-lang.org:80", "it names a port"),
            ("static.rust-lang.org:443", "it names a port"),
            ("*.rust-lang.org", "it is a wildcard"),
            ("*", "it is a wildcard"),
            ("127.0.0.1", "it is an IP address"),
            ("::1", "it is an IP address"),
            ("[::1]", "it is an IP address"),
            ("2001:db8::1", "it is an IP address"),
            ("10.0.0", "it is an IP address"),
            ("static.rust-lang.org/dist", "it names a path"),
            ("", "it is empty"),
            ("...", "it is empty"),
            ("static rust", "a character other than"),
            ("bücher.example", "a character other than"),
            ("static..rust-lang.org", "an empty label"),
        ] {
            let error = gateway(&["static.rust-lang.org", entry])
                .validate()
                .expect_err(entry)
                .to_string();
            assert!(error.contains(reason), "{entry:?}: {error}");
            assert!(error.contains("`[gateway] upgrade_http`"), "{error}");
        }
    }
}
