// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use attest_data::{Attestation, Log, Nonce, NonceError};

#[cfg(feature = "ipcc")]
use libipcc::IpccError;
use thiserror::Error;
use x509_cert::PkiPath;

#[cfg(feature = "hiffy")]
pub mod hiffy;
#[cfg(feature = "hiffy")]
use hiffy::AttestHiffyError;

#[cfg(feature = "ipcc")]
pub mod ipcc;

#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "mock")]
pub use mock::AttestMock;

#[cfg(feature = "sled-agent")]
pub mod sled_agent;

/// `AttestError` describes the possible errors encountered while getting an
/// attestation from the RoT. Such errors range from those produced by the
/// transport used to communicate with the RoT to those related to parsing
/// or processing data produced by the RoT.
#[derive(Debug, Error)]
pub enum AttestError {
    #[error(transparent)]
    Certificate(#[from] der::Error),
    #[error(transparent)]
    Deserialize(hubpack::Error),
    #[cfg(feature = "hiffy")]
    #[error(transparent)]
    Hiffy(#[from] AttestHiffyError),
    #[error("failed to send ipcc message to RoT: {0}")]
    HostToRot(attest_data::messages::HostToRotError),
    #[cfg(feature = "ipcc")]
    #[error(transparent)]
    Ipcc(#[from] IpccError),
    #[error(transparent)]
    Serialize(hubpack::Error),
    #[error(transparent)]
    Nonce(#[from] NonceError),
    #[cfg(feature = "sled-agent")]
    #[error(transparent)]
    SledAgent(
        #[from] sled_agent_client::Error<sled_agent_client::types::Error>,
    ),
}

/// The `Attest` trait is implemented by types that provide access to the RoT
/// attestation API. These types are generally proxies that shuttle data over
/// some transport between the caller and the RoT.
#[async_trait::async_trait]
pub trait Attest {
    /// Get the measurement log from the attest task. The Log is transmitted
    /// with no integrity protection so its trustworthiness must be established
    /// by an external process (see `verify_attestation`).
    async fn get_measurement_log(&self) -> Result<Log, AttestError>;
    /// Get the certificate chain from the attest task. This cert chain is a
    /// PKI path (per RFC 6066) starting with the leaf cert for the attestation
    /// signer and terminating at the intermediate before the root. The
    /// trustworthiness of this certificate chain must be established through
    /// an external process (see `verify_cert_chain`).
    async fn get_certificates(&self) -> Result<PkiPath, AttestError>;
    /// Get an attestation from the attest task. An attestation is a signature
    /// over the (hubpack serialized) measurement Log and the provided Nonce.
    /// To prevent replay attacks each Nonce used must be unique and
    /// unpredictable. Generally the Nonce should be generated from the
    /// platform's random number generator (see `Nonce::from_platform_rng`).
    async fn attest(&self, nonce: &Nonce) -> Result<Attestation, AttestError>;
}
