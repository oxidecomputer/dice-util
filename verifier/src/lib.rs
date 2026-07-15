// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{AttestDataError, DiceTcbInfo, NonceError, DICE_TCB_INFO};
pub use attest_data::{Attestation, Log, Measurement, Nonce, Nonce32};
use const_oid::db::{rfc5912::ID_EC_PUBLIC_KEY, rfc8410::ID_ED_25519};
use hubpack::SerializedSize;
#[cfg(feature = "ipcc")]
use libipcc::IpccError;
pub use rats_corim::{Corim, Error as CorimError};
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

#[cfg(feature = "sled-agent")]
pub mod sled_agent;

#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "mock")]
pub use mock::AttestMock;

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
    async fn get_measurement_log(&mut self) -> Result<Log, AttestError>;
    /// Get the certificate chain from the attest task. This cert chain is a
    /// PKI path (per RFC 6066) starting with the leaf cert for the attestation
    /// signer and terminating at the intermediate before the root. The
    /// trustworthiness of this certificate chain must be established through
    /// an external process (see `verify_cert_chain`).
    async fn get_certificates(&mut self) -> Result<PkiPath, AttestError>;
    /// Get an attestation from the attest task. An attestation is a signature
    /// over the (hubpack serialized) measurement Log and the provided Nonce.
    /// To prevent replay attacks each Nonce used must be unique and
    /// unpredictable. Generally the Nonce should be generated from the
    /// platform's random number generator (see `Nonce::from_platform_rng`).
    async fn attest(
        &mut self,
        nonce: &Nonce,
    ) -> Result<Attestation, AttestError>;
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
    #[error("The chain is unexpectedly self-signed")]
    UnexpectedSelfSigned,
}

/// This struct encapsulates the signature verification process for a PkiPath.
#[derive(Debug)]
struct PkiPathSignatureVerifier<'a> {
    roots: Option<&'a [Certificate]>,
}

impl<'a> PkiPathSignatureVerifier<'a> {
    /// Create a new `PkiPathSignatureVerifier` permitting any `Certificate`
    /// in `roots` to be a root / trust anchor. If `None` is provided then the
    /// `PkiPath`s verified by this verifier must be self-signed.
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
                            // did we forget this was self-signed?
                            let verifier =
                                CertSigVerifierFactory::get_verifier(
                                    &pki_path[0],
                                )?;

                            if verifier.verify(&pki_path[0]).is_ok() {
                                return Err(PkiPathSignatureVerifierError::UnexpectedSelfSigned);
                            } else {
                                return Err(
                                PkiPathSignatureVerifierError::VerifierFailed(
                                    e,
                                ),
                            );
                            }
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
#[derive(Debug, PartialEq)]
pub struct MeasurementSet(HashSet<Measurement>);

/// Construct a MeasurementSet from the provided artifacts. The
/// trustworthiness of these artifacts must be established independently
/// (see `verify_cert_chain` and `verify_attestation`).
impl MeasurementSet {
    /// Construct a MeasurementSet from the provided artifacts. The
    /// trustworthiness of these artifacts must be established independently
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

    /// Return the actual differences from the corpus, useful for debugging
    pub fn difference(
        &self,
        corpus: &ReferenceMeasurements,
    ) -> Option<MeasurementSet> {
        if self.is_subset(corpus) {
            None
        } else {
            let mut measurements = HashSet::new();
            for measurement in self.0.difference(&corpus.0) {
                measurements.insert(*measurement);
            }
            Some(MeasurementSet(measurements))
        }
    }
}

impl std::iter::IntoIterator for MeasurementSet {
    type Item = Measurement;
    type IntoIter = <HashSet<Measurement> as std::iter::IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::fmt::Display for MeasurementSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "measurement set")?;
        for m in &self.0 {
            writeln!(f, " {}", m)?;
        }
        if self.0.is_empty() {
            writeln!(f, "(set is empty)")?;
        }
        Ok(())
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

impl TryFrom<&[Corim]> for ReferenceMeasurements {
    type Error = ReferenceMeasurementsError;

    /// Construct a collection of `ReferenceMeasurements` from the provided
    /// `Corim` documents. The trustworthiness of these inputs must be
    /// established independently
    fn try_from(corims: &[Corim]) -> Result<Self, Self::Error> {
        let mut set = HashSet::new();

        for corim in corims {
            for d in corim.iter_digests() {
                set.insert(d.try_into()?);
            }
        }

        Ok(Self(set))
    }
}

impl std::fmt::Display for ReferenceMeasurements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Reference measurements")?;
        for m in &self.0 {
            writeln!(f, " {}", m)?;
        }
        if self.0.is_empty() {
            writeln!(f, "(set is empty)")?;
        }
        Ok(())
    }
}

/// Errors produced by the `verify_attestation` function
#[derive(Debug, Error)]
pub enum VerifyAttestationError {
    #[error("Failed to hubpack the log: {0}")]
    Serialize(#[from] hubpack::error::Error),
    #[error(
        "Alias public key is malformed: \
        spki bit string does not end on octet boundary"
    )]
    OddKey,
    #[error("Failed to construct VerifyingKey from alias public key: {0}")]
    KeyConversion(ed25519_dalek::ed25519::Error),
    #[error("Failed to verify Attestation with alias public key: {0}")]
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
    #[error("Measurements are not a subset of reference measurements: {0}")]
    NotSubset(MeasurementSet),
}

/// This function implements the core of our attestation appraisal policy.
/// The trustworthiness of the parameters provided must be established
/// independently.
pub fn verify_measurements(
    measurements: &MeasurementSet,
    corpus: &ReferenceMeasurements,
) -> Result<(), VerifyMeasurementsError> {
    // This should be equivallent to measurements.subset(corpus) but
    // give us the entries that are not in the corpus for debugging
    // purposes
    if let Some(diff) = measurements.difference(corpus) {
        Err(VerifyMeasurementsError::NotSubset(diff))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use x509_cert::{der::DecodePem, Certificate};

    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    fn get_cert_from_file<P: AsRef<Path>>(p: P) -> Certificate {
        let p: &Path = p.as_ref();

        let pem_cert = fs::read(p).expect(&format!(
            "test root cert expected in file: {}",
            p.display()
        ));

        Certificate::from_pem(pem_cert).expect(&format!(
            "expected a PEM encoded cert from file: {}",
            p.display()
        ))
    }

    // Get Certificate instance for root cert generated by build.rs
    fn get_test_root() -> Certificate {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let root_file = out.join("root-a.cert.pem");
        get_cert_from_file(&root_file)
    }

    fn get_bad_test_root() -> Certificate {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let root_file = out.join("root-b.cert.pem");
        get_cert_from_file(&root_file)
    }

    fn get_cert_chain_from_file<P: AsRef<Path>>(p: P) -> Vec<Certificate> {
        let p: &Path = p.as_ref();

        let pem_chain = fs::read(p).expect(&format!(
            "test cert chain expected in file: {}",
            p.display()
        ));

        Certificate::load_pem_chain(&pem_chain).expect(&format!(
            "expected PEM cert chain in file: {}",
            p.display()
        ))
    }

    // Get cert chain for mock alias / attestation signer
    fn get_test_cert_chain() -> Vec<Certificate> {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let cert_chain_file = out.join("alias.certlist.pem");
        get_cert_chain_from_file(&cert_chain_file)
    }

    // verify a valid cert chain against the matching root and ensure that
    // we get back a reference to the expected root
    #[test]
    fn verify_cert_chain_good() {
        let root_cert = get_test_root();
        let cert_chain = get_test_cert_chain();

        let anchor = verify_cert_chain(
            &cert_chain,
            Some(std::slice::from_ref(&root_cert)),
        )
        .unwrap();

        assert_eq!(anchor, &root_cert);
    }

    // Attempt to verify an invalid cert chain and ensure failure. The cert
    // chain is invalid because the leaf and intermediate are swapped so this
    // fails before the root is checked.
    #[test]
    fn verify_cert_chain_bad() {
        let root_cert = get_test_root();
        let mut cert_chain = get_test_cert_chain();

        cert_chain.push(root_cert);
        cert_chain.swap(0, 2);

        assert!(verify_cert_chain(&cert_chain, None).is_err());
    }

    // Verify a cert chain against the wrong root & ensure we get an error.
    #[test]
    fn verify_cert_chain_no_good_root() {
        let root_cert = get_bad_test_root();
        let cert_chain = get_test_cert_chain();

        let res = verify_cert_chain(
            &cert_chain,
            Some(std::slice::from_ref(&root_cert)),
        );

        assert!(res.is_err());
    }

    // Verify a valid, self-signed cert chain. We make the chain self-signed
    // by including the root in the correct position.
    #[test]
    fn verify_cert_chain_self() {
        let root_cert = get_test_root();
        let mut cert_chain = get_test_cert_chain();
        cert_chain.push(root_cert);

        let anchor = verify_cert_chain(&cert_chain, None)
            .expect("the root cert that verifies the chain should be returned");
        let chain_last = cert_chain
            .last()
            .expect("the cert chain should not be empty");

        assert_eq!(anchor, chain_last);
    }

    // Verify a valid cert chain against two roots: Only the second root can
    // validate the cert chain and we check that this is the one returned to
    // us.
    #[test]
    fn verify_cert_chain_second_root() {
        let roots = vec![get_bad_test_root(), get_test_root()];
        let cert_chain = get_test_cert_chain();

        let anchor = verify_cert_chain(&cert_chain, Some(&roots)).unwrap();

        assert_eq!(anchor, &roots[1]);
    }

    // Attempt to verify a cert chain against a root that is not self-signed.
    #[test]
    fn verify_cert_chain_not_root() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let device_id_file = out.join("device-id.cert.pem");

        let roots = vec![get_test_root(), get_cert_from_file(&device_id_file)];
        let cert_chain = get_test_cert_chain();

        let res = verify_cert_chain(&cert_chain, Some(&roots));

        assert!(res.is_err());
    }

    // Attempt to verify a cert chain that isn't self-signed as though it were
    // self-signed & ensure that we fail.
    #[test]
    fn verify_cert_chain_not_self_signed() {
        let cert_chain = get_test_cert_chain();

        let res = verify_cert_chain(&cert_chain, None);

        assert!(res.is_err());
    }

    const MEASUREMENT_A: [u8; 32] = [0x1; 32];
    const MEASUREMENT_B: [u8; 32] = [0x2; 32];
    const MEASUREMENT_C: [u8; 32] = [0x3; 32];

    #[test]
    fn basic_measurement_set_tests() {
        let measurement_a = Measurement::fake(MEASUREMENT_A);
        let measurement_b = Measurement::fake(MEASUREMENT_B);
        let measurement_c = Measurement::fake(MEASUREMENT_C);

        let mut corpus = HashSet::new();

        corpus.insert(measurement_a);
        corpus.insert(measurement_b);
        corpus.insert(measurement_c);

        let corpus = ReferenceMeasurements(corpus);

        let mut set_a = HashSet::new();
        set_a.insert(measurement_a);
        let set_a = MeasurementSet(set_a);

        assert!(set_a.is_subset(&corpus));

        let mut set_b = HashSet::new();
        set_b.insert(measurement_b);
        let set_b = MeasurementSet(set_b);

        assert!(set_b.is_subset(&corpus));

        let mut set_c = HashSet::new();
        set_c.insert(measurement_c);
        let set_c = MeasurementSet(set_c);

        assert!(verify_measurements(&set_c, &corpus).is_ok());
    }

    #[test]
    fn missing_measurement_set_tests() {
        let measurement_a = Measurement::fake(MEASUREMENT_A);
        let measurement_b = Measurement::fake(MEASUREMENT_B);
        let measurement_c = Measurement::fake(MEASUREMENT_C);

        let mut corpus = HashSet::new();

        corpus.insert(measurement_a);
        corpus.insert(measurement_b);

        let corpus = ReferenceMeasurements(corpus);

        let mut set_c = HashSet::new();
        set_c.insert(measurement_c);
        let set_c = MeasurementSet(set_c);

        let mut other_c = HashSet::new();
        other_c.insert(measurement_c);
        let other_c = MeasurementSet(other_c);

        match verify_measurements(&set_c, &corpus) {
            Ok(()) => panic!("expected an error"),
            Err(e) => match e {
                VerifyMeasurementsError::NotSubset(set) => {
                    assert!(other_c == set)
                }
            },
        }
    }
}
