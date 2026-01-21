// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "std")]
use const_oid::AssociatedOid;
#[cfg(feature = "std")]
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Sequence,
};
use hubpack::SerializedSize;
use salty::constants::SIGNATURE_SERIALIZED_LENGTH;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha3::{
    digest::{core_api::OutputSizeUser, typenum::Unsigned},
    Sha3_256Core,
};

#[cfg(feature = "std")]
use sha3::Sha3_256;

#[cfg(feature = "std")]
use std::{fmt, hash::Hash};

#[cfg(feature = "std")]
use thiserror::Error;

pub mod messages;

#[cfg_attr(feature = "std", derive(Debug, Error))]
#[derive(PartialEq)]
pub enum AttestDataError {
    #[cfg_attr(feature = "std", error("Deserialization failed"))]
    Deserialize,
    #[cfg_attr(
        feature = "std",
        error("Failed to get random Nonce from the platform")
    )]
    GetRandom,
    #[cfg_attr(feature = "std", error("Slice is the wrong length"))]
    TryFromSliceError,
    #[cfg_attr(
        feature = "std",
        error("Fwid provided contains unsupported digest value")
    )]
    UnsupportedDigest,
    #[cfg_attr(feature = "std", error("CoRIM Digest contained tagged value"))]
    TaggedDigest,
}

/// Array is the type we use as a base for types that are constant sized byte
/// buffers.
#[serde_as]
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    SerializedSize,
)]
pub struct Array<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Array<N> {
    pub const LENGTH: usize = N;
}

impl<const N: usize> Default for Array<N> {
    /// Create and initialize an `Array<N>` to 0's.
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for Array<N> {
    /// Create an Array from the provided array.
    fn from(item: [u8; N]) -> Self {
        Self(item)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Array<N> {
    type Error = AttestDataError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        let nonce: [u8; N] = item
            .try_into()
            .map_err(|_| Self::Error::TryFromSliceError)?;
        Ok(Array::<N>(nonce))
    }
}

#[cfg(feature = "std")]
impl<const N: usize> TryFrom<Vec<u8>> for Array<N> {
    type Error = AttestDataError;

    /// Attempt to create an `Array<N>` from the `Vec<u8>` provided.
    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        item[..].try_into()
    }
}

impl<const N: usize> AsRef<[u8]> for Array<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

const SHA3_256_DIGEST_SIZE: usize =
    <Sha3_256Core as OutputSizeUser>::OutputSize::USIZE;

const NONCE_SIZE: usize = SHA3_256_DIGEST_SIZE;

/// An array of bytes sized appropriately for a sha3-256 digest.
pub type Sha3_256Digest = Array<SHA3_256_DIGEST_SIZE>;

/// An array of bytes sized appropriately for a sha3-256 digest.
pub type Ed25519Signature = Array<SIGNATURE_SERIALIZED_LENGTH>;

/// Nonce is a newtype around an appropriately sized byte array.
pub type Nonce = Array<NONCE_SIZE>;

#[cfg(feature = "std")]
impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut out: Vec<String> = Vec::new();

        for byte in self.0 {
            out.push(format!("{byte}"));
        }
        let out = out.join(" ");

        write!(f, "[{out}]")
    }
}

impl Nonce {
    #[cfg(feature = "std")]
    pub fn from_platform_rng() -> Result<Self, AttestDataError> {
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce[..])
            .map_err(|_| AttestDataError::GetRandom)?;
        let nonce = nonce;

        Ok(Self(nonce))
    }
}

#[cfg(feature = "std")]
pub const DICE_TCB_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

// FWID from DICE Attestation Architecture §6.1.1:
#[cfg(feature = "std")]
#[derive(Debug, Sequence)]
pub struct Fwid {
    hash_algorithm: ObjectIdentifier,
    digest: OctetString,
}

// DiceTcbInfo from DICE Attestation Architecture §6.1.1:
#[cfg(feature = "std")]
#[derive(Debug, Sequence)]
pub struct DiceTcbInfo {
    // fwids [6] IMPLICIT FWIDLIST OPTIONAL,
    // where FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    pub fwids: Option<Vec<Fwid>>,
}

/// Measurement is an enum that can hold any of the hash algorithms that we support
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    Serialize,
    SerializedSize,
)]
pub enum Measurement {
    Sha3_256(Sha3_256Digest),
}

impl Measurement {
    // This is useful for unit tesitng purposes. The name here
    // intentional to indicate that this is unchecked and if you
    // are using it anywhere besides unit tests something has gone wrong!
    pub fn fake(bytes: [u8; 32]) -> Self {
        Measurement::Sha3_256(Sha3_256Digest::from(bytes))
    }
}

impl Default for Measurement {
    fn default() -> Self {
        Measurement::Sha3_256(Sha3_256Digest::default())
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Sha3_256(digest) => {
                write!(f, "sha3-256;{}", hex::encode(digest))
            }
        }
    }
}

#[cfg(feature = "std")]
impl TryFrom<&Fwid> for Measurement {
    type Error = AttestDataError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(fwid: &Fwid) -> Result<Self, Self::Error> {
        // map from fwid.hash_algorithm ObjectIdentifier to Measurement enum
        if fwid.hash_algorithm == Sha3_256::OID {
            // pull the associated data from fwid.digest OctetString
            let digest = fwid.digest.as_bytes();
            let digest = Sha3_256Digest::try_from(digest)?;

            Ok(Measurement::Sha3_256(digest))
        } else {
            Err(Self::Error::UnsupportedDigest)
        }
    }
}

#[cfg(feature = "std")]
impl TryFrom<rats_corim::Digest> for Measurement {
    type Error = AttestDataError;

    /// Attempt to create a Measurement from the `rats_corim::Digest` provided.
    fn try_from(digest: rats_corim::Digest) -> Result<Self, Self::Error> {
        match digest.alg {
            10 => {
                let bytes = match &digest.val {
                    rats_corim::TaggedBytes::Bytes(v) => v,
                    rats_corim::TaggedBytes::Tagged(_, _) => {
                        return Err(Self::Error::TaggedDigest)
                    }
                };
                Ok(Measurement::Sha3_256(bytes[..].try_into()?))
            }
            _ => Err(Self::Error::UnsupportedDigest),
        }
    }
}

/// Log is the collection of measurements recorded
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, SerializedSize)]
pub struct MeasurementLog<const N: usize> {
    index: u32,
    #[serde_as(as = "[_; N]")]
    measurements: [Measurement; N],
}

impl<const N: usize> MeasurementLog<N> {
    pub fn is_full(&self) -> bool {
        self.index as usize == N
    }

    pub fn is_empty(&self) -> bool {
        self.index == 0
    }

    pub fn len(&self) -> u32 {
        self.index
    }

    pub fn push(&mut self, measurement: Measurement) -> bool {
        if !self.is_full() {
            self.measurements[self.index as usize] = measurement;
            self.index += 1;
            true
        } else {
            false
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Measurement> {
        self.measurements.iter().enumerate().filter_map(|(i, e)| {
            if i < (self.index as usize) {
                Some(e)
            } else {
                None
            }
        })
    }
}

impl<const N: usize> core::ops::Index<u32> for MeasurementLog<N> {
    type Output = Measurement;
    fn index(&self, i: u32) -> &Self::Output {
        &self.measurements[i as usize]
    }
}

impl<const N: usize> Default for MeasurementLog<N> {
    fn default() -> Self {
        Self {
            index: 0,
            measurements: [Measurement::default(); N],
        }
    }
}

impl<const N: usize> TryFrom<&[u8]> for MeasurementLog<N> {
    type Error = AttestDataError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (log, _): (Self, _) = hubpack::deserialize(value)
            .map_err(|_| AttestDataError::Deserialize)?;
        Ok(log)
    }
}

const LOG_CAPACITY: usize = 16;

pub type Log = MeasurementLog<LOG_CAPACITY>;

#[derive(Debug, Deserialize, Serialize, SerializedSize)]
pub enum Attestation {
    Ed25519(Ed25519Signature),
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use super::*;

    #[cfg(feature = "std")]
    const SHA3_DIGEST: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[cfg(feature = "std")]
    const SHA3_DIGEST_BAD: &str = "AA";

    #[cfg(feature = "std")]
    #[test]
    fn measurement_from_fwid_good() {
        let bytes = hex::decode(SHA3_DIGEST).expect("decode digest hex");
        let fwid = Fwid {
            hash_algorithm: Sha3_256::OID,
            digest: OctetString::new(bytes.clone())
                .expect("OctetString from digest"),
        };

        let measurement =
            Measurement::try_from(&fwid).expect("Measurement from Fwid");

        let digest = Sha3_256Digest::try_from(bytes)
            .expect("Sha3_256Digest from digest");
        let expected = Measurement::Sha3_256(digest);

        assert_eq!(expected, measurement);
    }

    #[cfg(feature = "std")]
    #[test]
    fn measurement_from_fwid_bad_digest() {
        // create invalid digest for alg identified by OID
        let bytes = hex::decode(SHA3_DIGEST_BAD).expect("decode digest hex");
        let fwid = Fwid {
            hash_algorithm: Sha3_256::OID,
            digest: OctetString::new(bytes).expect("OctetString from digest"),
        };

        let measurement = Measurement::try_from(&fwid);
        assert_eq!(measurement, Err(AttestDataError::TryFromSliceError));
    }

    #[cfg(feature = "std")]
    #[test]
    fn measurement_from_fwid_bad_oid() {
        let bytes = hex::decode(SHA3_DIGEST).expect("decode digest hex");
        // create Fwid w/ invalid OID for digest
        let fwid = Fwid {
            hash_algorithm: DICE_TCB_INFO,
            digest: OctetString::new(bytes.clone())
                .expect("OctetString from digest"),
        };

        let measurement = Measurement::try_from(&fwid);
        assert_eq!(measurement, Err(AttestDataError::UnsupportedDigest));
    }

    #[cfg(feature = "std")]
    #[test]
    fn measurement_log_iter() {
        const THIRTY_TWO_BYTES_0: &str =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const THIRTY_TWO_BYTES_1: &str =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        let digest_0 =
            hex::decode(THIRTY_TWO_BYTES_0).expect("digest 0 decode");
        let digest_0: Array<32> =
            digest_0.try_into().expect("digest 0 try into");
        let digest_1 =
            hex::decode(THIRTY_TWO_BYTES_1).expect("digest 1 decode");
        let digest_1: Array<32> =
            digest_1.try_into().expect("digest 1 try into");

        // create 2 measurements for the log
        let measurements = [
            Measurement::Sha3_256(digest_0),
            Measurement::Sha3_256(digest_1),
        ];

        // this is the measurement we expect to get back from the iterator
        let measurement_0 = measurements[0].clone();

        // create a log for the two measurements above, set `index` to 1
        let log: MeasurementLog<2> = MeasurementLog {
            index: 1,
            measurements,
        };

        let mut count = 0;
        for measurement in log.iter() {
            count += 1;
            assert_eq!(measurement, &measurement_0);
        }
        assert_eq!(count, 1);
    }
}
