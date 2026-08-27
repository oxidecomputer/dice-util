// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use attest_data::{Attestation, Log, Measurement, Nonce, Nonce32};
use const_oid::{
    db::{
        rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION},
        rfc8410::ID_ED_25519,
    },
    ObjectIdentifier,
};
pub use rats_corim::{Corim, Error as CorimError};
use thiserror::Error;
use x509_cert::{Certificate, PkiPath};

mod p384;
use p384::{P384CertVerifier, P384CertVerifierError};

mod ed25519;
use ed25519::{Ed25519CertVerifier, Ed25519CertVerifierError};

pub mod helios_rot;
pub mod platform_rot;

mod rsa;
use rsa::{RsaCertVerifier, RsaCertVerifierError};

/// Errors related to the creation of signature verifiers for certs in a
/// `PkiPath`.
#[derive(Debug, Error)]
pub enum CertSigVerifierFactoryError {
    #[error("Failed to create verifier from Ed25519 public key")]
    Ed25519CertVerifierError(#[from] Ed25519CertVerifierError),
    #[error("Failed to create verifier from P384 public key")]
    P384CertVerifierError(#[from] P384CertVerifierError),
    #[error("Failed to create verifier from RSA certificate")]
    RsaCertVerifierError(#[from] RsaCertVerifierError),
    #[error("Cannot create verifier for unsupported algorithm")]
    UnsupportedAlgorithm(ObjectIdentifier),
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
            RSA_ENCRYPTION => Ok(Box::new(RsaCertVerifier::try_from(cert)?)),
            oid => Err(CertSigVerifierFactoryError::UnsupportedAlgorithm(oid)),
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

    #[test]
    fn helios_rot_amd_turin() {
        let mut out = PathBuf::from(env::var("OUT_DIR").unwrap());
        out.push("amd-root-ca-r4.cert.pem");
        let root_cert = get_cert_from_file(&out);
        out.pop();
        out.push("helios-rot.certlist.pem");
        let cert_chain = get_cert_chain_from_file(&out);

        let anchor = verify_cert_chain(
            &cert_chain,
            Some(std::slice::from_ref(&root_cert)),
        )
        .unwrap();

        assert_eq!(anchor, &root_cert);
    }
}
