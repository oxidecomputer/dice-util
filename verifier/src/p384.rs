// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use p384::ecdsa::VerifyingKey;
use thiserror::Error;
use x509_cert::Certificate;

use crate::{CertVerifier, CertVerifierError};

/// Errors produced when verifying P384 signatures over `Certificate`s by
/// the `P384CertVerifier`.
#[derive(Debug, Error)]
pub enum P384CertVerifierError {
    #[error("Key from cert is not ID_ECC_PUBLIC_KEY")]
    WrongKeyType,
    #[error("Missing expected key parameter: SECP_384_R_1")]
    MissingParam,
    #[error("Key parameter isn't an ObjectIdentifier")]
    ParamNotOid(#[from] x509_cert::der::Error),
    #[error("Key params are not SECP_384_R_1")]
    WrongKeyParam,
    #[error("Signature Error {0}")]
    VerifyingKeyFromSpki(#[from] x509_cert::spki::Error),
}

/// CertVerifier for verifying p384 signatures on `Certificate`s.
pub(crate) struct P384CertVerifier {
    verifying_key: VerifyingKey,
}

impl TryFrom<&Certificate> for P384CertVerifier {
    type Error = P384CertVerifierError;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
        use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_384_R_1};
        use x509_cert::{der::referenced::OwnedToRef, spki::ObjectIdentifier};

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(Self::Error::WrongKeyType);
        }

        let param = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or(Self::Error::MissingParam)?;
        let oid: ObjectIdentifier = param.decode_as()?;
        if oid != SECP_384_R_1 {
            return Err(Self::Error::WrongKeyParam);
        }

        let verifying_key = VerifyingKey::try_from(spki.owned_to_ref())?;

        Ok(Self { verifying_key })
    }
}

impl CertVerifier for P384CertVerifier {
    /// Verify the ed25519 signature on the `Certificate` provided
    fn verify(&self, cert: &Certificate) -> Result<(), CertVerifierError> {
        use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
        use p384::ecdsa::{signature::Verifier, Signature};
        use x509_cert::der::Encode;

        let algorithm = &cert.signature_algorithm;
        if algorithm.oid != ECDSA_WITH_SHA_384 {
            return Err(CertVerifierError::SignatureType);
        }

        if algorithm.parameters.is_some() {
            return Err(CertVerifierError::UnexpectedParams);
        }

        let signature = cert
            .signature
            .as_bytes()
            .ok_or(CertVerifierError::MalformedSignature)?;
        let signature = Signature::from_der(signature)
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
