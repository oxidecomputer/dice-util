// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use const_oid::db::rfc8410::ID_ED_25519;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;
use x509_cert::Certificate;

use crate::{CertVerifier, CertVerifierError};

/// Errors produced by the `Ed25519CertVerifier`.
#[derive(Debug, Error)]
pub enum Ed25519CertVerifierError {
    #[error("Spki public key type is not Ed25519")]
    WrongKeyType,
    #[error("Public key has params but Ed25519 keys have none")]
    UnexpectedParam,
    #[error("Malformed public key")]
    MalformedPublicKey,
    #[error("Failed to create verifier from bytes: {0}")]
    VerifyingKeyFromBytes(#[from] ed25519_dalek::SignatureError),
}

/// Errors produced when verifying ed25519 signatures over `Certificate`s by
/// the `Ed25519CertVerifier`.
pub(crate) struct Ed25519CertVerifier {
    verifying_key: VerifyingKey,
}

impl TryFrom<&Certificate> for Ed25519CertVerifier {
    type Error = Ed25519CertVerifierError;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_ED_25519 {
            return Err(Self::Error::WrongKeyType);
        }

        if spki.algorithm.parameters.is_some() {
            return Err(Self::Error::UnexpectedParam);
        }

        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Self::Error::MalformedPublicKey)?;
        let verifying_key = VerifyingKey::try_from(key_bytes)?;

        Ok(Self { verifying_key })
    }
}

impl CertVerifier for Ed25519CertVerifier {
    /// Verify the ed25519 signature on the `Certificate` provided
    fn verify(&self, cert: &Certificate) -> Result<(), CertVerifierError> {
        use ed25519_dalek::{Signature, Verifier};
        use x509_cert::der::Encode;

        let algorithm = &cert.signature_algorithm;
        if algorithm.oid != ID_ED_25519 {
            return Err(CertVerifierError::SignatureType);
        }

        if algorithm.parameters.is_some() {
            return Err(CertVerifierError::UnexpectedParams);
        }

        let signature = cert
            .signature
            .as_bytes()
            .ok_or(CertVerifierError::MalformedSignature)?;
        let signature = Signature::try_from(signature)
            .map_err(|e| CertVerifierError::SignatureConversion(Box::new(e)))?;

        let message = cert
            .tbs_certificate
            .to_der()
            .map_err(|e| CertVerifierError::Message(Box::new(e)))?;

        self.verifying_key
            .verify(&message, &signature)
            .map_err(|e| CertVerifierError::Signature(Box::new(e)))
    }
}
