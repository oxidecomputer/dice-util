// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use attest_data::{Attestation, Nonce};
use const_oid::db::{rfc5912::ID_EC_PUBLIC_KEY, rfc8410::ID_ED_25519};
use sha3::{Digest, Sha3_256};
use x509_cert::{der::Encode, Certificate, PkiPath};

/// Unit-like struct with a single non-member associated function. This
/// struct should never be instantiated. Just call the one associated
/// function.
struct CertSigVerifierFactory;

impl CertSigVerifierFactory {
    /// Get a CertVerifier suitable for verifying the signatures on
    /// `Certificates` from the certificate provided.
    fn get_verifier(cert: &Certificate) -> Result<Box<dyn CertVerifier>> {
        match cert.tbs_certificate.subject_public_key_info.algorithm.oid {
            ID_ED_25519 => Ok(Box::new(Ed25519CertVerifier::try_from(cert)?)),
            ID_EC_PUBLIC_KEY => Ok(Box::new(P384CertVerifier::try_from(cert)?)),
            _ => Err(anyhow!("UnsupportedAlgorithm")),
        }
    }
}

/// This trait is intended to encapsulate arbitrary certificate verification
/// tasks.
trait CertVerifier {
    /// Verify some property of the `Certificate` provided.
    fn verify(&self, cert: &Certificate) -> Result<()>;
}

/// CertVerifier for verifying ed25519 signatures on `Certificate`s.
struct Ed25519CertVerifier {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl TryFrom<&Certificate> for Ed25519CertVerifier {
    type Error = anyhow::Error;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self> {
        use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_ED_25519 {
            return Err(anyhow!("IncompatibleCertificate"));
        }

        if spki.algorithm.parameters.is_some() {
            return Err(anyhow!("UnexpectedParameters"));
        }

        let verifying_key: [u8; PUBLIC_KEY_LENGTH] = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow!("Invalid / unaligned public key"))?
            .try_into()?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key)?;

        Ok(Self { verifying_key })
    }
}

impl CertVerifier for Ed25519CertVerifier {
    /// Verify the ed25519 signature on the `Certificate` provided
    fn verify(&self, cert: &Certificate) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier, SIGNATURE_LENGTH};

        let algorithm = &cert.signature_algorithm;
        if algorithm.oid != ID_ED_25519 {
            return Err(anyhow!("Invalid signature algorithm for verifier"));
        }

        if algorithm.parameters.is_some() {
            return Err(anyhow!("UnexpectedParams"));
        }

        let signature: [u8; SIGNATURE_LENGTH] = cert
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("Invalid / unaligned signature"))?
            .try_into()?;
        let signature = Signature::from_bytes(&signature);

        let message = cert.tbs_certificate.to_der()?;

        self.verifying_key
            .verify(&message, &signature)
            .map_err(|e| anyhow!("signature verification failed: {}", e))
    }
}

/// CertVerifier for verifying p384 signatures on `Certificate`s.
struct P384CertVerifier {
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl TryFrom<&Certificate> for P384CertVerifier {
    type Error = anyhow::Error;

    /// Create a `CertVerifier` from the provided `Certificate`
    fn try_from(certificate: &Certificate) -> Result<Self> {
        use const_oid::db::rfc5912::SECP_384_R_1;
        use p384::ecdsa::VerifyingKey;
        use x509_cert::{
            der::{referenced::OwnedToRef, Tag, Tagged},
            spki::ObjectIdentifier,
        };

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(anyhow!("UnsupportedAlgorithm"));
        }

        let param = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| anyhow!("MissingParams"))?;
        if param.tag() != Tag::ObjectIdentifier {
            return Err(anyhow!("UnsupportedTag"));
        }

        let oid: ObjectIdentifier = param.decode_as()?;
        if oid != SECP_384_R_1 {
            return Err(anyhow!("UnsupportedParameter"));
        }

        let verifying_key = VerifyingKey::try_from(spki.owned_to_ref())?;

        Ok(Self { verifying_key })
    }
}

impl CertVerifier for P384CertVerifier {
    /// Verify the ed25519 signature on the `Certificate` provided
    fn verify(&self, cert: &Certificate) -> Result<()> {
        use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
        use p384::ecdsa::{signature::Verifier, Signature};

        let algorithm = &cert.signature_algorithm;
        if algorithm.oid != ECDSA_WITH_SHA_384 {
            return Err(anyhow!("Invalid signature algorithm for verifier"));
        }

        let signature: &[u8] = cert
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("Invalid / unaligned signature"))?;
        let signature = Signature::from_der(signature)?;

        let message = cert.tbs_certificate.to_der()?;

        self.verifying_key
            .verify(&message, &signature)
            .map_err(|e| anyhow!("signature verification failed: {}", e))
    }
}

/// This struct encapsulates the signature verification process for a PkiPath.
#[derive(Debug)]
pub struct PkiPathSignatureVerifier {
    root_cert: Option<Certificate>,
}

impl PkiPathSignatureVerifier {
    /// Create a new `PkiPathSignatureVerifier` with the provided
    /// `Certificate` acting as the root / trust anchor. If `None` is
    /// provided then the `PkiPath`s verified by this verifier must be self-
    /// signed.
    pub fn new(root_cert: Option<Certificate>) -> Result<Self> {
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
    pub fn verify(&self, pki_path: &PkiPath) -> Result<()> {
        if pki_path.is_empty() {
            return Err(anyhow!("EmptyPkiPath"));
        }

        self._verify(&pki_path[0], &pki_path[1..])
    }

    /// This function is the work horse for verifying `PkiPath`s. It should
    /// only be called from the `PkiPathVerifier::verify` function.
    fn _verify(
        &self,
        certificate: &Certificate,
        pki_path: &[Certificate],
    ) -> Result<()> {
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

pub fn verify_attestation(
    alias: &Certificate,
    attestation: &Attestation,
    log: &[u8],
    nonce: &Nonce,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // To verify an attestation we need to extract and construct a few
    // things before we can verify the attestation:
    // - signature: the attestation produced by the RoT when
    //   `alias_priv` is used to sign `message`
    let signature = match attestation {
        Attestation::Ed25519(s) => Signature::from_bytes(&s.0),
    };

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
        .ok_or_else(|| anyhow!("Invalid / unaligned public key"))?;

    let verifying_key = VerifyingKey::from_bytes(alias.try_into()?)?;
    Ok(verifying_key.verify(message.as_slice(), &signature)?)
}
