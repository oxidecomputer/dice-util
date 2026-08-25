// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use rsa::{pkcs1v15::VerifyingKey, sha2::Sha384};
use thiserror::Error;
use x509_cert::{
    der::{asn1::ObjectIdentifier, Encode},
    Certificate,
};

use crate::{CertVerifier, CertVerifierError};

/// Errors produced when verifying P384 signatures over `Certificate`s by
/// the `RsaCertVerifier`.
#[derive(Debug, Error)]
pub enum RsaCertVerifierError {
    #[error("Signature from cert is not SHA_384_WITH_RSA_ENCRYPTION")]
    UnsupportedSignature(ObjectIdentifier),
    #[error("Failed to serialize SPKI to DER")]
    SpkiToDer(#[from] x509_cert::der::Error),
    #[error("Failed to parse RSA key from SPKI DER")]
    BadKey(#[from] x509_cert::spki::Error),
    #[error("Failed to get bytes from cert signature")]
    SignatureBytes,
}

/// CertVerifier for verifying p384 signatures on `Certificate`s.
pub(crate) struct RsaCertVerifier {
    verifying_key: VerifyingKey<Sha384>,
}

impl TryFrom<&Certificate> for RsaCertVerifier {
    type Error = RsaCertVerifierError;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
        use const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION;
        use x509_cert::der::referenced::OwnedToRef;

        if certificate.signature_algorithm.oid != SHA_384_WITH_RSA_ENCRYPTION {
            return Err(Self::Error::UnsupportedSignature(
                certificate.signature_algorithm.oid,
            ));
        }

        let spki = &certificate.tbs_certificate.subject_public_key_info;

        let verifying_key =
            VerifyingKey::<Sha384>::try_from(spki.owned_to_ref())?;

        Ok(Self { verifying_key })
    }
}

impl CertVerifier for RsaCertVerifier {
    /// Verify the RSA signature on the `Certificate` provided
    fn verify(&self, cert: &Certificate) -> Result<(), CertVerifierError> {
        use rsa::{pkcs1v15::Signature, signature::Verifier};

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
