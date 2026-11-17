//! The [`mitm`] adapter: the egress gateway.

#[cfg(feature = "tls-intercept")]
pub(crate) mod mitm;

#[cfg(feature = "tls-intercept")]
pub use mitm::tls::upstream_ca_certificates;
#[cfg(feature = "tls-intercept")]
pub use mitm::{
    BackendDial, CredentialSource, MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits,
};
