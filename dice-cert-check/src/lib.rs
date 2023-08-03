// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use const_oid::{
    db::rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1},
    ObjectIdentifier,
};
use hex::ToHex;
use log::{error, warn};
use sha2::Digest;
use std::fmt;
use std::result;
use x509_cert::{
    der::{
        self,
        asn1::{Any, BitString},
        Tag, Tagged,
    },
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

const ID_ED_25519: crate::ObjectIdentifier =
    crate::ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Signature is not octet aligned")]
    BadSignature,
    #[error("SPKI has parameters incompatible with Verifier.")]
    IncompatibleParams,
    #[error("Verifier is not compatible with provided signature")]
    IncompatibleSignature,
    #[error("Required parameters missing from SPKI.")]
    MissingParams,
    #[error("Failed to verify signature.")]
    P384VerificationFail {
        #[from]
        source: p384::ecdsa::Error,
    },
    #[error("Public key is not octet aligned")]
    UnalignedPublicKey,
    #[error("SPKI algorithm has parameters where none were expected")]
    UnexpectedParams,
    #[error("Algorithm not supported")]
    UnsupportedAlgorithm,
    #[error("Parameter not supported")]
    UnsupportedParameter,
    #[error("Signature not supported")]
    UnsupportedSignature,
    #[error("Parameters has unspported tag.")]
    UnsupportedTag,
    #[error("Unsupported OID in algorith parameter.")]
    UnsupportedOid {
        #[from]
        source: der::Error,
    },
    #[error("Wrong key type for verifier")]
    WrongAlgorithm,
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
pub enum AlgorithmType {
    EcPublicKey,
    Ed25519,
}

impl TryFrom<&ObjectIdentifier> for AlgorithmType {
    type Error = Error;

    fn try_from(oid: &ObjectIdentifier) -> result::Result<Self, Self::Error> {
        match *oid {
            ID_EC_PUBLIC_KEY => Ok(AlgorithmType::EcPublicKey),
            ID_ED_25519 => Ok(AlgorithmType::Ed25519),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ParameterType {
    P384,
}

impl TryFrom<&Any> for ParameterType {
    type Error = Error;

    fn try_from(param: &Any) -> result::Result<Self, Self::Error> {
        match param.tag() {
            Tag::ObjectIdentifier => {
                let oid = param.decode_as()?;
                match oid {
                    SECP_384_R_1 => Ok(ParameterType::P384),
                    _ => Err(Error::UnsupportedParameter),
                }
            }
            _ => Err(Error::UnsupportedTag),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SignatureType {
    EcdsaWithSha384,
    Ed25519,
}

impl TryFrom<&ObjectIdentifier> for SignatureType {
    type Error = Error;

    fn try_from(oid: &ObjectIdentifier) -> result::Result<Self, Self::Error> {
        match *oid {
            ECDSA_WITH_SHA_384 => Ok(SignatureType::EcdsaWithSha384),
            ID_ED_25519 => Ok(SignatureType::Ed25519),
            _ => {
                warn!("Unsupported signature w/ oid: {}", oid);
                Err(Error::UnsupportedSignature)
            }
        }
    }
}

pub struct Signature {
    pub bytes: Vec<u8>,
    pub kind: SignatureType,
    params: Option<ParameterType>,
}

impl Signature {
    pub fn new(
        algorithm: &AlgorithmIdentifierOwned,
        signature: &BitString,
    ) -> Result<Self> {
        let params = match &algorithm.parameters {
            Some(params) => Some(ParameterType::try_from(params)?),
            None => None,
        };

        let bytes = match signature.as_bytes() {
            // copy DER encoded signature
            Some(bytes) => bytes.to_vec(),
            // we get None back if the ANS.1 BIT STRING has unused bits
            None => Err(Error::BadSignature)?,
        };

        Ok(Self {
            bytes,
            kind: SignatureType::try_from(&algorithm.oid)?,
            params,
        })
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "kind: {:?}, params: {:?}, bytes: {}",
            self.kind,
            self.params,
            self.bytes.encode_hex::<String>(),
        )
    }
}

pub trait Verifier {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()>;
}

pub struct P384Verifier {
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl TryFrom<&SubjectPublicKeyInfoOwned> for P384Verifier {
    type Error = Error;

    fn try_from(
        spki: &SubjectPublicKeyInfoOwned,
    ) -> result::Result<Self, Self::Error> {
        let params = match &spki.algorithm.parameters {
            Some(params) => ParameterType::try_from(params)?,
            None => return Err(Error::MissingParams),
        };

        if params != ParameterType::P384 {
            warn!("P384Verifier: incompatible algorithm parameters");
            return Err(Error::IncompatibleParams);
        }

        use p384::ecdsa::VerifyingKey;
        use x509_cert::der::referenced::OwnedToRef;

        // do better error handling
        let verifying_key = VerifyingKey::try_from(spki.owned_to_ref())
            .expect("p384 VerifyingKey");
        Ok(Self { verifying_key })
    }
}

impl Verifier for P384Verifier {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        if sig.kind != SignatureType::EcdsaWithSha384 {
            warn!(
                "P384Verifier: incompatible signature algorithm: {:?}",
                sig.kind
            );
            return Err(Error::IncompatibleSignature);
        }

        let digest = sha2::Sha384::digest(msg);

        use p384::ecdsa::{self, signature::hazmat::PrehashVerifier};

        let signature = ecdsa::Signature::from_der(&sig.bytes)?;

        Ok(self.verifying_key.verify_prehash(&digest, &signature)?)
    }
}

pub struct Ed25519Verifier {
    verifying_key: ring_compat::signature::ed25519::VerifyingKey,
}

impl TryFrom<&SubjectPublicKeyInfoOwned> for Ed25519Verifier {
    type Error = Error;

    fn try_from(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let algorithm = AlgorithmType::try_from(&spki.algorithm.oid)?;
        if algorithm != AlgorithmType::Ed25519 {
            return Err(Error::WrongAlgorithm);
        }

        if spki.algorithm.parameters.is_some() {
            return Err(Error::UnexpectedParams);
        }

        use ring_compat::signature::ed25519::VerifyingKey;

        // The ring type behind the VerifyingKey expects the public key
        // as the raw bits, not the DER encoded SPKI like the rust crypto
        // ecc VerifyingKey. This requires dealing with the ASN.1 BIT
        // STRING type and the fact that it may not be byte aligned.
        let key_bytes = match spki.subject_public_key.as_bytes() {
            Some(b) => b,
            None => return Err(Error::UnalignedPublicKey),
        };

        let verifying_key = VerifyingKey::new(key_bytes)?;
        Ok(Self { verifying_key })
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        if sig.kind != SignatureType::Ed25519 {
            warn!("Ed25519Verifier: incompatible signature");
            return Err(Error::IncompatibleSignature);
        }

        use ring_compat::signature::ed25519::Signature;
        use ring_compat::signature::Verifier;

        let signature = Signature::from_slice(&sig.bytes)?;

        match self.verifying_key.verify(msg, &signature) {
            Ok(_) => Ok(()),
            Err(e) => {
                // not sure failed signature checks are worth
                // spamming the logs
                warn!("Signature verification failed: {}", e);
                Err(e.into())
            }
        }
    }
}

pub struct VerifierFactory;

impl VerifierFactory {
    pub fn get_verifier(
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<Box<dyn Verifier>> {
        match AlgorithmType::try_from(&spki.algorithm.oid)? {
            AlgorithmType::EcPublicKey => match &spki.algorithm.parameters {
                Some(params) => match ParameterType::try_from(params)? {
                    ParameterType::P384 => {
                        Ok(Box::new(P384Verifier::try_from(spki)?))
                    }
                },
                None => Err(Error::MissingParams),
            },
            AlgorithmType::Ed25519 => {
                Ok(Box::new(Ed25519Verifier::try_from(spki)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::asn1::Any;

    #[test]
    fn test_alg_type_ecpublickey() -> Result<()> {
        let alg_oid = ID_EC_PUBLIC_KEY;

        let alg = AlgorithmType::try_from(&alg_oid)?;
        assert_eq!(alg, AlgorithmType::EcPublicKey);

        Ok(())
    }

    #[test]
    fn test_alg_type_ed25519() -> Result<()> {
        let alg_oid = ID_ED_25519;

        let alg = AlgorithmType::try_from(&alg_oid)?;
        assert_eq!(alg, AlgorithmType::Ed25519);

        Ok(())
    }

    #[test]
    fn test_param_type() -> Result<()> {
        let param_oid = SECP_384_R_1;
        let param = Any::from(&param_oid);

        let param = ParameterType::try_from(&param)?;
        assert_eq!(param, ParameterType::P384);

        Ok(())
    }

    #[test]
    fn test_sig_type_ecdsa384() -> Result<()> {
        let sig_oid = ECDSA_WITH_SHA_384;
        let sig = SignatureType::try_from(&sig_oid)?;

        assert_eq!(sig, SignatureType::EcdsaWithSha384);

        Ok(())
    }

    #[test]
    fn test_sig_type_ed25519() -> Result<()> {
        let sig_oid = ID_ED_25519;
        let sig = SignatureType::try_from(&sig_oid)?;

        assert_eq!(sig, SignatureType::Ed25519);

        Ok(())
    }
}
