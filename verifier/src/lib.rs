// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Attestation, Log, Nonce};
use const_oid::db::{rfc5912::ID_EC_PUBLIC_KEY, rfc8410::ID_ED_25519};
use hubpack::SerializedSize;
#[cfg(feature = "ipcc")]
use libipcc::IpccError;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use x509_cert::{
    der::{self, Encode},
    Certificate, PkiPath,
};

pub mod hiffy;
use hiffy::AttestHiffyError;

#[cfg(feature = "ipcc")]
pub mod ipcc;

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
    #[error(transparent)]
    Hiffy(#[from] AttestHiffyError),
    #[error("failed to send ipcc message to RoT: {0}")]
    HostToRot(attest_data::messages::HostToRotError),
    #[cfg(feature = "ipcc")]
    #[error(transparent)]
    Ipcc(#[from] IpccError),
    #[error(transparent)]
    Serialize(hubpack::Error),
}

/// The `Attest` trait is implemented by types that provide access to the RoT
/// attestation API. These types are generally proxies that shuttle data over
/// some transport between the caller and the RoT.
pub trait Attest {
    /// Get the measurement log from the attest task. The Log is transmitted
    /// with no integrity protection so its trustworthiness must be established
    /// by an external process (see `verify_attestation`).
    fn get_measurement_log(&self) -> Result<Log, AttestError>;
    /// Get the certificate chain from the attest task. This cert chain is a
    /// PKI path (per RFC 6066) starting with the leaf cert for the attestation
    /// signer and terminating at the intermediate before the root. The
    /// trustworthiness of this certificate chain must be established through
    /// an external process (see `verify_cert_chain`).
    fn get_certificates(&self) -> Result<PkiPath, AttestError>;
    /// Get an attestation from the attest task. An attestation is a signature
    /// over the (hubpack serialized) measurement Log and the provided Nonce.
    /// To prevent replay attacks each Nonce used must be unique and
    /// unpredictable. Generally the Nonce should be generated from the
    /// platform's random number generator (see `Nonce::from_platform_rng`).
    fn attest(&self, nonce: &Nonce) -> Result<Attestation, AttestError>;
}

/// Errors related to the creation of signature verifiers for certs in a
/// `PkiPath`.
#[derive(Debug, Error)]
pub enum CertSigVerifierFactoryError {
    #[error("Failed to create verifier from Ed25519 public key")]
    Ed25519CertVerifierError(#[from] Ed25519CertVerifierError),
    #[error("Failed to create verifier from P384 public key")]
    P384CertVerifierError(#[from] P384CertVerifierError),
    #[error("Cannot create verifier for unsupported algorithm")]
    UnsupportedAlgorithm,
}

/// Unit-like struct with a single non-member associated function. This
/// struct should never be instantiated. Just call the one associated
/// function.
struct CertSigVerifierFactory;

impl CertSigVerifierFactory {
    /// Get a CertVerifier suitable for verifying the signatures on
    /// `Certificates` from the certificate provided.
    fn get_verifier(
        cert: &Certificate,
    ) -> Result<Box<dyn CertVerifier>, CertSigVerifierFactoryError> {
        match cert.tbs_certificate.subject_public_key_info.algorithm.oid {
            ID_ED_25519 => Ok(Box::new(Ed25519CertVerifier::try_from(cert)?)),
            ID_EC_PUBLIC_KEY => Ok(Box::new(P384CertVerifier::try_from(cert)?)),
            _ => Err(CertSigVerifierFactoryError::UnsupportedAlgorithm),
        }
    }
}

/// Errors encountered while verifying aspects of a certificate.
#[derive(Debug, Error)]
pub enum CertVerifierError {
    #[error("Wrong signature type for veriying key")]
    SignatureType,
    #[error("Signature algorithm contains unexpected parameters")]
    UnexpectedParams,
    #[error("Signature is malformed")]
    MalformedSignature,
    #[error("Failed to convert bytes to Signature")]
    SignatureConversion(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("Message extraction failed")]
    Message(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("Signature verification failed")]
    Signature(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// This trait is intended to encapsulate arbitrary certificate verification
/// tasks.
trait CertVerifier {
    /// Verify some property of the `Certificate` provided.
    fn verify(&self, cert: &Certificate) -> Result<(), CertVerifierError>;
}

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
struct Ed25519CertVerifier {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl TryFrom<&Certificate> for Ed25519CertVerifier {
    type Error = Ed25519CertVerifierError;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
        use ed25519_dalek::VerifyingKey;

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
struct P384CertVerifier {
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl TryFrom<&Certificate> for P384CertVerifier {
    type Error = P384CertVerifierError;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self, Self::Error> {
        use const_oid::db::rfc5912::SECP_384_R_1;
        use p384::ecdsa::VerifyingKey;
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

/// Errors produced by the PkiPathSignatureVerifier
#[derive(Debug, Error)]
pub enum PkiPathSignatureVerifierError {
    #[error("Failed to get signature verifier for certificate: {0}")]
    Unsupported(#[from] CertSigVerifierFactoryError),
    #[error("The PkiPath provided must be length 2 or more")]
    PathTooShort,
    #[error("Signature verification failed: {0}")]
    VerifierFailed(#[from] CertVerifierError),
}

/// This struct encapsulates the signature verification process for a PkiPath.
#[derive(Debug)]
struct PkiPathSignatureVerifier<'a> {
    root_cert: Option<&'a Certificate>,
}

impl<'a> PkiPathSignatureVerifier<'a> {
    /// Create a new `PkiPathSignatureVerifier` with the provided
    /// `Certificate` acting as the root / trust anchor. If `None` is
    /// provided then the `PkiPath`s verified by this verifier must be self-
    /// signed.
    fn new(
        root_cert: Option<&'a Certificate>,
    ) -> Result<Self, PkiPathSignatureVerifierError> {
        if let Some(cert) = &root_cert {
            let verifier = CertSigVerifierFactory::get_verifier(cert)?;
            // verify root cert before using it
            verifier.verify(cert)?;
        }

        Ok(Self { root_cert })
    }

    /// Iterate over the provided PkiPath verifying the signature chain.
    /// NOTE: If `root` is `None` then the provided cert chain must terminate
    /// in a self-signed certificate.
    fn verify(
        &self,
        pki_path: &PkiPath,
    ) -> Result<(), PkiPathSignatureVerifierError> {
        if pki_path.len() >= 2 {
            self._verify(&pki_path[0], &pki_path[1..])
        } else {
            Err(PkiPathSignatureVerifierError::PathTooShort)
        }
    }

    /// This function is the work horse for verifying `PkiPath`s. It should
    /// only be called from the `PkiPathVerifier::verify` function.
    fn _verify(
        &self,
        certificate: &Certificate,
        pki_path: &[Certificate],
    ) -> Result<(), PkiPathSignatureVerifierError> {
        let verifier = if !pki_path.is_empty() {
            // common case: verify that the public key from `pki_path[0]`
            // can be use to verify the signature over `certificate`
            CertSigVerifierFactory::get_verifier(&pki_path[0])?
        } else {
            // terminal case: `pki_path` is empty, `certificate` is the last
            // Certificate from the PkiPath that needs verification. The
            // verifier we use depends on the value of `root`:
            match &self.root_cert {
                Some(root_cert) => {
                    // use `root_cert` to verify `certificate`
                    CertSigVerifierFactory::get_verifier(root_cert)?
                }
                None => {
                    // use `certificate to verify signature on `certificate`
                    CertSigVerifierFactory::get_verifier(certificate)?
                }
            }
        };
        verifier.verify(certificate)?;

        if !pki_path.is_empty() {
            // recurse verifying the signature on next cert
            self._verify(&pki_path[0], &pki_path[1..])
        } else {
            Ok(())
        }
    }
}

/// Errors produced by the `verify_attestation` function
#[derive(Debug, Error)]
pub enum VerifyAttestationError {
    #[error("Failed to hubpack the log: {0}")]
    Serialize(#[from] hubpack::error::Error),
    #[error("Alias public key is malformed: spki bit string has unused bits")]
    OddKey,
    #[error("Failed to construct VerifyingKey from alias public key")]
    KeyConversion(ed25519_dalek::ed25519::Error),
    #[error("Failed to construct VerifyingKey from alias public key")]
    VerificationFailed(ed25519_dalek::ed25519::Error),
}

/// The certificate chains produced by the RoT are PKI paths (RFC 6066) that
/// start with a leaf cert for the attestation signer and ends with the last
/// intermediate before the root. This function walks this PKI path verifying
/// the signatures over each certificate back to the provided root. Development
/// systems that have not been issued a platform identity certificate will
/// produce cert chains that terminate with a self-signed cert. To verify such
/// a cert chain the caller must pass `None` for the root to case the
/// verification function to accept the self-signed root.
pub fn verify_cert_chain(
    pki_path: &PkiPath,
    root: Option<&Certificate>,
) -> Result<(), PkiPathSignatureVerifierError> {
    PkiPathSignatureVerifier::new(root)?.verify(pki_path)
}

/// This function uses the provided artifacts to establish trust in the Log.
/// The trustworthiness of the alias certificate and the attestation / nonce
/// must be established independently (see
pub fn verify_attestation(
    alias: &Certificate,
    attestation: &Attestation,
    log: &Log,
    nonce: &Nonce,
) -> Result<(), VerifyAttestationError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // To verify an attestation we need to extract and construct a few
    // things before we can verify the attestation:
    // - signature: the attestation produced by the RoT when
    //   `alias_priv` is used to sign `message`
    let signature = match attestation {
        Attestation::Ed25519(s) => Signature::from_bytes(&s.0),
    };

    let mut buf = vec![0u8; Log::MAX_SIZE];
    hubpack::serialize(&mut buf, log)?;
    let log = buf;

    // - message: the data that's signed by the RoT to produce an
    //   attestation `sha3_256(log | nonce)`
    let mut message = Sha3_256::new();
    message.update(log);
    message.update(nonce);
    let message = message.finalize();

    let alias = alias
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyAttestationError::OddKey)?;
    let alias = VerifyingKey::try_from(alias)
        .map_err(VerifyAttestationError::KeyConversion)?;

    alias
        .verify(message.as_slice(), &signature)
        .map_err(VerifyAttestationError::VerificationFailed)
}
