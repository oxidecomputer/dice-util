// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use p384::{
    ecdsa::{
        self, Signature, SigningKey,
        signature::{SignatureEncoding, Signer},
    },
    pkcs8::{self, DecodePrivateKey},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;
use x509_cert::{Certificate, PkiPath, der};

const SIGNATURE_SIZE: usize =
    core::mem::size_of::<<Signature as SignatureEncoding>::Repr>();

#[derive(Debug, Error)]
pub enum ArrayError {
    #[error("Slice is not 96 bytes")]
    TryFromSliceError,
}

#[serde_as]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Array<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Array<N> {
    pub const LENGTH: usize = N;
}

impl<const N: usize> AsRef<[u8]> for Array<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<const N: usize> TryFrom<&[u8]> for Array<N> {
    type Error = ArrayError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        let item: [u8; N] = item
            .try_into()
            .map_err(|_| Self::Error::TryFromSliceError)?;
        Ok(Array::<N>(item))
    }
}

pub type P384Signature = Array<SIGNATURE_SIZE>;

/// An attestation from the Illumos Rot
pub enum Attestation {
    P384(P384Signature),
}

#[derive(Debug, Error)]
pub enum NonceError {
    #[error("Only 48 byte Nonces are supported")]
    UnsupportedLength,
    #[error("Failed to pull 48 bytes from getrandom")]
    Rng(#[from] getrandom::Error),
}

pub type Nonce48 = Array<48>;

#[derive(
    Copy,
    Clone,
    Debug,
    Deserialize,
    PartialEq,
    // The current RoT Attest API takes the nonce bytes directly (i.e. a
    // `Nonce48`/`Array<48>`) rather than this more generic `Nonce` type.
    // To prevent accidentally accepting this type where it currently shouldn't
    // be accepted, we omit these for now until hubris#2375 is fixed.
    // Serialize, SerializedSize,
)]
pub enum Nonce {
    /// A 48-byte Nonce value.
    N48(Nonce48),
}

impl Nonce {
    pub fn from_platform_rng(len: usize) -> Result<Self, NonceError> {
        // We currently only support 32-byte Nonce's
        if len != Nonce48::LENGTH {
            return Err(NonceError::UnsupportedLength);
        }
        let mut nonce = Array([0u8; Nonce48::LENGTH]);
        getrandom::fill(nonce.0.as_mut_slice()).map_err(NonceError::Rng)?;
        Ok(Nonce::N48(nonce))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        match self {
            Nonce::N48(n) => n.as_ref(),
        }
    }
}

/// The `IllumosRot` trait is the interface to the roT in the Illumos kernel.
pub trait IllumosRot {
    type Error;

    fn get_certificates(&self) -> Result<PkiPath, Self::Error>;
    fn attest(&self, nonce: &Nonce) -> Result<Attestation, Self::Error>;
}

#[derive(Debug, Error)]
pub enum IllumosRotMockError {
    #[error("Failed to load certificate chain")]
    DerError(#[from] der::Error),
    #[error("Failed to load certificate chain from {}", path.display())]
    FileRead {
        path: PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("Failed to load p384 signing key from {}", path.display())]
    SigningKeyDecode {
        path: PathBuf,
        #[source]
        error: pkcs8::Error,
    },
    #[error("Signature isn't 96 bytes")]
    SignatureSize(#[from] ArrayError),
    #[error("Signature isn't 96 bytes")]
    SigningError(#[from] ecdsa::Error),
}

#[derive(Debug)]
pub struct IllumosRotMock {
    certs: PkiPath,
    alias_key: SigningKey,
}

impl IllumosRotMock {
    pub fn load<P: AsRef<Path>, A: AsRef<Path>>(
        certs: P,
        alias: A,
    ) -> Result<Self, IllumosRotMockError> {
        let certs = fs::read_to_string(&certs).map_err(|error| {
            IllumosRotMockError::FileRead {
                path: certs.as_ref().to_path_buf(),
                error,
            }
        })?;
        let certs = Certificate::load_pem_chain(certs.as_bytes())?;

        let alias_key = fs::read_to_string(&alias).map_err(|error| {
            IllumosRotMockError::FileRead {
                path: alias.as_ref().to_path_buf(),
                error,
            }
        })?;

        let alias_key =
            SigningKey::from_pkcs8_pem(&alias_key).map_err(|error| {
                IllumosRotMockError::SigningKeyDecode {
                    path: alias.as_ref().to_path_buf(),
                    error,
                }
            })?;

        Ok(Self { certs, alias_key })
    }
}

impl IllumosRot for IllumosRotMock {
    type Error = IllumosRotMockError;

    fn get_certificates(&self) -> Result<PkiPath, Self::Error> {
        Ok(self.certs.clone())
    }

    fn attest(&self, nonce: &Nonce) -> Result<Attestation, Self::Error> {
        let sig: Signature = self.alias_key.try_sign(nonce.as_ref())?;
        let sig = P384Signature::from(sig.to_bytes().as_slice().try_into()?);
        Ok(Attestation::P384(sig))
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::env;

    #[test]
    fn bad_path_to_key() {
        let res = IllumosRotMock::load("root.cert.pem", "foo");
        assert!(res.is_err());
    }

    #[test]
    fn bad_path_to_certs() {
        let res = IllumosRotMock::load("foo", "root.key.pem");
        assert!(res.is_err());
    }

    #[test]
    fn load_success() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let cert_chain = out.join("root.cert.pem");
        let key = out.join("root.key.pem");

        let res = IllumosRotMock::load(&cert_chain, &key);
        assert!(res.is_ok());
    }

    #[test]
    fn attest() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let signing_key = out.join("root.key.pem");

        let mock =
            IllumosRotMock::load(out.join("root.cert.pem"), &signing_key)
                .expect("load cert chain & key");

        let nonce = Nonce::from_platform_rng(48).expect("get Nonce from RNG");
        let attestation = mock.attest(&nonce).expect("attest to nonce");
        let signing_key = fs::read_to_string(&signing_key)
            .expect("Read signing key from file to string");
        let signing_key = SigningKey::from_pkcs8_pem(&signing_key)
            .expect("signing_key from pkcs8 string");

        use p384::ecdsa::signature::Verifier;
        let verifying_key = p384::ecdsa::VerifyingKey::from(signing_key);
        match attestation {
            Attestation::P384(a) => {
                let sig = Signature::from_slice(a.as_ref())
                    .expect("signature from Attestation::P384 bytes");
                let ret = verifying_key.verify(nonce.as_ref(), &sig);
                assert!(ret.is_ok());
            }
        }
    }
}
