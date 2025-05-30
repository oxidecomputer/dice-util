// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{
    AttestDataError, Attestation, DiceTcbInfo, Log, Measurement, Nonce,
    DICE_TCB_INFO,
};
use const_oid::db::{rfc5912::ID_EC_PUBLIC_KEY, rfc8410::ID_ED_25519};
use hubpack::SerializedSize;
#[cfg(feature = "ipcc")]
use libipcc::IpccError;
use rats_corim::Corim;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use thiserror::Error;
use x509_cert::{
    der::{self, Decode, DecodeValue, Encode, Header, SliceReader},
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
    #[error("The PkiPath provided cannot be empty")]
    EmptyPkiPath,
    #[error("Unable to verifiy cert chain with the available roots")]
    NoMatchingRoot,
    #[error("Signature verification failed: {0}")]
    VerifierFailed(#[from] CertVerifierError),
}

/// This struct encapsulates the signature verification process for a PkiPath.
#[derive(Debug)]
struct PkiPathSignatureVerifier<'a> {
    roots: Option<&'a [Certificate]>,
}

impl<'a> PkiPathSignatureVerifier<'a> {
    /// Create a new `PkiPathSignatureVerifier` with the provided
    /// `Certificate` acting as the root / trust anchor. If `None` is
    /// provided then the `PkiPath`s verified by this verifier must be self-
    /// signed.
    fn new(
        roots: Option<&'a [Certificate]>,
    ) -> Result<Self, PkiPathSignatureVerifierError> {
        if let Some(roots) = roots {
            // verify each root is self-signed: signature on root cert must
            // verify the public key from the same cert
            for root in roots {
                CertSigVerifierFactory::get_verifier(root)?.verify(root)?;
            }
        }

        Ok(Self { roots })
    }

    /// Iterate over the provided PkiPath verifying the signature chain.
    /// NOTE: If `root` is `None` then the provided cert chain must terminate
    /// in a self-signed certificate.
    fn verify(
        &self,
        pki_path: &'a [Certificate],
    ) -> Result<&'a Certificate, PkiPathSignatureVerifierError> {
        if pki_path.len() >= 2 {
            // recursive case: at least 2 certs in the PkiPath
            // verify pki_path[0] w/ public key from pki_path[1]
            let verifier = CertSigVerifierFactory::get_verifier(&pki_path[1])?;
            verifier.verify(&pki_path[0])?;
            // recurse
            self.verify(&pki_path[1..])
        } else if pki_path.len() == 1 {
            // terminal condition: pki path length is 1
            if let Some(roots) = self.roots {
                for root in roots {
                    let verifier = CertSigVerifierFactory::get_verifier(root)?;
                    match verifier.verify(&pki_path[0]) {
                        // if verification succeeds we return the root that it
                        // verified against
                        Ok(_) => return Ok(root),
                        // if verification fails we move on to the next root
                        Err(CertVerifierError::Signature(_)) => continue,
                        // if there's any other error return it
                        Err(e) => {
                            return Err(
                                PkiPathSignatureVerifierError::VerifierFailed(
                                    e,
                                ),
                            )
                        }
                    }
                }
                // if we get this far none of the roots were able to verify
                // the last cert
                Err(PkiPathSignatureVerifierError::NoMatchingRoot)
            } else {
                // if roots are None verify the final cert w/ itself
                let verifier =
                    CertSigVerifierFactory::get_verifier(&pki_path[0])?;
                verifier.verify(&pki_path[0])?;
                Ok(&pki_path[0])
            }
        } else {
            Err(PkiPathSignatureVerifierError::EmptyPkiPath)
        }
    }
}

/// Possible errors produced by the `MeasurmentSet` construction process.
#[derive(Debug, Error)]
pub enum MeasurementSetError {
    #[error("failed to create reader from extension value: {0}")]
    ExtensionDecode(der::Error),
    #[error("failed to decode extension header: {0}")]
    HeaderDecode(der::Error),
    #[error("failed to decode TcbInfo extension: {0}")]
    DiceTcbInfoDecode(der::Error),
    #[error("failed to create Measurement from DiceTcbInfo extension: {0}")]
    MeasurementConstruct(#[from] AttestDataError),
}

/// This is a collection to represent the measurements received from an
/// attestor. These measurements will come from the measurement log and the
/// DiceTcbInfo extension(s) in the attestation cert chain / pki path.
pub struct MeasurementSet(HashSet<Measurement>);

/// Construct a MeasurementSet from the provided artifacts. The
/// trustwirthiness of these artifacts must be established independently
/// (see `verify_cert_chain` and `verify_attestation`).
impl MeasurementSet {
    /// Construct a MeasurementSet from the provided artifacts. The
    /// trustwirthiness of these artifacts must be established independently
    /// (see `verify_cert_chain` and `verify_attestation`).
    pub fn from_artifacts(
        pki_path: &PkiPath,
        log: &Log,
    ) -> Result<Self, MeasurementSetError> {
        let mut measurements = HashSet::new();

        for cert in pki_path {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                for ext in extensions {
                    if ext.extn_id == DICE_TCB_INFO {
                        let mut reader =
                            SliceReader::new(ext.extn_value.as_bytes())
                                .map_err(
                                    MeasurementSetError::ExtensionDecode,
                                )?;
                        let header = Header::decode(&mut reader)
                            .map_err(MeasurementSetError::HeaderDecode)?;

                        let tcb_info =
                            DiceTcbInfo::decode_value(&mut reader, header)
                                .map_err(
                                    MeasurementSetError::DiceTcbInfoDecode,
                                )?;
                        if let Some(fwid_vec) = &tcb_info.fwids {
                            for fwid in fwid_vec {
                                let measurement = Measurement::try_from(fwid)?;
                                measurements.insert(measurement);
                            }
                        }
                    }
                }
            }
        }

        for measurement in log.iter() {
            measurements.insert(*measurement);
        }

        Ok(Self(measurements))
    }

    /// Thin wrapper over HashSet.is_subset w/ better type info
    pub fn is_subset(&self, corpus: &ReferenceMeasurements) -> bool {
        self.0.is_subset(&corpus.0)
    }
}

/// A collection of measurement values that is used as a source of truth when
/// appraising the set of measurements derived from an attestation.
pub struct ReferenceMeasurements(pub(crate) HashSet<Measurement>);

/// Possible errors produced by the `ReferenceMeasurements` construction
/// process.
#[derive(Debug, Error)]
pub enum ReferenceMeasurementsError {
    #[error("Digest is not the expected length")]
    BadDigest(#[from] AttestDataError),
}

impl TryFrom<Corim> for ReferenceMeasurements {
    type Error = ReferenceMeasurementsError;

    /// Construct a collection of `ReferenceMeasurements` from the provided
    /// `Corim` documents. The trustworthiness of these inputs must be
    /// established independently
    fn try_from(corim: Corim) -> Result<Self, Self::Error> {
        let mut set = HashSet::new();

        for d in corim.iter_digests() {
            set.insert(d.try_into()?);
        }

        Ok(Self(set))
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
pub fn verify_cert_chain<'a>(
    pki_path: &'a PkiPath,
    roots: Option<&'a [Certificate]>,
) -> Result<&'a Certificate, PkiPathSignatureVerifierError> {
    PkiPathSignatureVerifier::new(roots)?.verify(pki_path)
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

/// Possible errors produced by the measurement verification / appraisal
/// process.
#[derive(Debug, Error)]
pub enum VerifyMeasurementsError {
    #[error("Measurements are not a subset of reference measurements")]
    NotSubset,
}

/// This function implements the core of our attestation appraisal policy.
/// The trustworthiness of the parameters provided must be established
/// independently.
pub fn verify_measurements(
    measurements: &MeasurementSet,
    corpus: &ReferenceMeasurements,
) -> Result<(), VerifyMeasurementsError> {
    if measurements.is_subset(corpus) {
        Ok(())
    } else {
        Err(VerifyMeasurementsError::NotSubset)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use x509_cert::{der::DecodePem, Certificate};

    const ROOT_0_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtTCCAWegAwIBAgIBADAFBgMrZXAwWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxKTAnBgNVBAMMIDBYVjI6MDAwLTAwMDAw
MDA6MDAwOjAwMDAwMDAwMDAwMCAXDTI1MDUzMTE2MjU0MloYDzk5OTkxMjMxMjM1
OTU5WjBZMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29t
cGFueTEpMCcGA1UEAwwgMFhWMjowMDAtMDAwMDAwMDowMDA6MDAwMDAwMDAwMDAw
KjAFBgMrZXADIQBPGBgsC4CH7C+eKVxdZUwlH0b0B6EcS3XOwjvbkruJxqNSMFAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJ
BgdngQUFBGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQA0/VXdySYo
fli+6yShUCkuZDVwesR52N98P6vDyNFvln/RF+6G5jc5T/9JtyxVwpuRVmKIWOlK
yyVhSdKemygH
-----END CERTIFICATE-----
"#;
    const ROOT_BAD_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtTCCAWegAwIBAgIBADAFBgMrZXAwWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxKTAnBgNVBAMMIDBYVjI6MDAwLTAwMDAw
MDA6MDAwOjAwMDAwMDAwMDAwMCAXDTI1MDYwMTE2NTc0MVoYDzk5OTkxMjMxMjM1
OTU5WjBZMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29t
cGFueTEpMCcGA1UEAwwgMFhWMjowMDAtMDAwMDAwMDowMDA6MDAwMDAwMDAwMDAw
KjAFBgMrZXADIQBwLUhOMfbi14vhrb3JN9C/m+9ur6iQKzSYJz+wAfgboaNSMFAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJ
BgdngQUFBGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQDPqBoIOeJl
jdlBUvZJG9pJS+arSxKszMUX395vsP7YnugpyuwrHI/JMX37p40+A6TQToLmOvPE
x4pL7D1+t7cK
-----END CERTIFICATE-----
"#;
    const ALIAS_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBrDCCAV6gAwIBAgIBADAFBgMrZXAwQjELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxEjAQBgNVBAMMCWRldmljZS1pZDAgFw0y
NTA1MzExNjI1NDJaGA85OTk5MTIzMTIzNTk1OVowPjELMAkGA1UEBhMCVVMxHzAd
BgNVBAoMFk94aWRlIENvbXB1dGVyIENvbXBhbnkxDjAMBgNVBAMMBWFsaWFzMCow
BQYDK2VwAyEAij/G9qE5X/V5MKIq3MSy9n0NtZarYjYZRZ1X11ryLa6jezB5MAwG
A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBcGA1UdIAEB/wQNMAswCQYHZ4EF
BQRkCDBABgZngQUFBAEBAf8EMzAxpi8wLQYJYIZIAWUDBAIIBCCqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqjAFBgMrZXADQQC1BtAtcUmlHPoBgOqvvx4s
pAWhNNXiHLb1DoPg4CbmWnImT477NU3MB3APB+K7TowbMqlejZubsvm6BfwH98wA
-----END CERTIFICATE-----
"#;
    const DEVICE_ID_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkzCCAUWgAwIBAgIBADAFBgMrZXAwWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxKTAnBgNVBAMMIDBYVjI6MDAwLTAwMDAw
MDA6MDAwOjAwMDAwMDAwMDAwMCAXDTI1MDUzMTE2MjU0MloYDzk5OTkxMjMxMjM1
OTU5WjBCMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29t
cGFueTESMBAGA1UEAwwJZGV2aWNlLWlkMCowBQYDK2VwAyEAmjR8j+BKslllHrNp
EiqlaVXic78FKRrWXB2hnri0jZ6jRzBFMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgIEMCIGA1UdIAEB/wQYMBYwCQYHZ4EFBQRkCDAJBgdngQUFBGQMMAUG
AytlcANBAKPxOhjG/1pIzodhKzHUVJntVItYJlnwefDlUz16zyxjsysbVWBKOnN7
ezRrVF9+9OkCymi+xqWG8UN87sN/9Qk=
-----END CERTIFICATE-----
"#;
    // verify a valid cert chain against the matching root and ensure that
    // we get back a reference to the expected root
    #[test]
    fn verify_cert_chain_good() {
        let root = Certificate::from_pem(ROOT_0_PEM).unwrap();
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];

        let anchor =
            verify_cert_chain(&cert_chain, Some(std::slice::from_ref(&root)))
                .unwrap();

        assert_eq!(anchor, &root);
    }

    // Attempt to verify an invalid cert chain and ensure failure. The cert
    // chain is invalid because the leaf and intermediate are swapped so this
    // fails before the root is checked.
    #[test]
    fn verify_cert_chain_bad() {
        let cert_chain = vec![
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(ROOT_0_PEM).unwrap(),
        ];

        assert!(verify_cert_chain(&cert_chain, None).is_err());
    }

    // Verify a cert chain against the wrong root & ensure we get an error.
    #[test]
    fn verify_cert_chain_no_good_root() {
        let root = Certificate::from_pem(ROOT_BAD_PEM).unwrap();
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];

        let res =
            verify_cert_chain(&cert_chain, Some(std::slice::from_ref(&root)));

        assert!(res.is_err());
    }

    // Verify a valid, self-signed cert chain. We make the chain self-signed
    // by including the root in the correct position.
    #[test]
    fn verify_cert_chain_self() {
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
            Certificate::from_pem(ROOT_0_PEM).unwrap(),
        ];

        let anchor = verify_cert_chain(&cert_chain, None).unwrap();

        assert_eq!(anchor, &cert_chain[2]);
    }

    // Verify a valid cert chain against two roots: Only the second root can
    // validate the cert chain and we check that this is the one returned to
    // us.
    #[test]
    fn verify_cert_chain_second_root() {
        let roots = vec![
            Certificate::from_pem(ROOT_BAD_PEM).unwrap(),
            Certificate::from_pem(ROOT_0_PEM).unwrap(),
        ];
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];

        let anchor = verify_cert_chain(&cert_chain, Some(&roots)).unwrap();

        assert_eq!(anchor, &roots[1]);
    }

    // Attempt to verify a cert chain against a root that is not self-signed.
    #[test]
    fn verify_cert_chain_not_root() {
        let roots = vec![
            Certificate::from_pem(ROOT_0_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];

        let res = verify_cert_chain(&cert_chain, Some(&roots));

        assert!(res.is_err());
    }

    // Attempt to verify a cert chain that isn't self-signed as though it were
    // self-signed & ensure that we fail.
    #[test]
    fn verify_cert_chain_not_self_signed() {
        let cert_chain = vec![
            Certificate::from_pem(ALIAS_PEM).unwrap(),
            Certificate::from_pem(DEVICE_ID_PEM).unwrap(),
        ];

        let res = verify_cert_chain(&cert_chain, None);

        assert!(res.is_err());
    }
}
