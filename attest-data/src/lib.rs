// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use hubpack::SerializedSize;
use salty::constants::SIGNATURE_SERIALIZED_LENGTH;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha3::{
    digest::{core_api::OutputSizeUser, typenum::Unsigned},
    Sha3_256Core,
};

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
use std::fmt::{self, Display, Formatter};

#[cfg_attr(feature = "std", derive(Debug, Error))]
pub enum AttestDataError {
    #[cfg_attr(feature = "std", error("Deserialization failed"))]
    Deserialize,
    #[cfg_attr(feature = "std", error("Slice is the wrong length"))]
    TryFromSliceError,
}

/// Array is the type we use as a base for types that are constant sized byte
/// buffers.
#[serde_as]
#[derive(
    Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize,
)]
pub struct Array<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Array<N> {
    pub const LENGTH: usize = N;
}

impl<const N: usize> Default for Array<N> {
    /// Create and initialize an Array<N> to 0's.
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

    /// Attempt to create an Array<N> from the slice provided.
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

    /// Attempt to create an Array<N> from the Vec<u8> provided.
    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        item.try_into()
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
impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut out: Vec<String> = Vec::new();

        for byte in self.0 {
            out.push(format!("{}", byte));
        }
        let out = out.join(" ");

        write!(f, "[{}]", out)
    }
}

/// Measurement is an enum that can hold any of the hash algorithms that we support
#[derive(
    Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize,
)]
pub enum Measurement {
    Sha3_256(Sha3_256Digest),
}

impl Default for Measurement {
    fn default() -> Self {
        Measurement::Sha3_256(Sha3_256Digest::default())
    }
}

/// Log is the collection of measurements recorded
#[serde_as]
#[derive(Deserialize, Serialize, SerializedSize)]
pub struct MeasurementLog<const N: usize> {
    index: u32,
    #[serde_as(as = "[_; N]")]
    measurements: [Measurement; N],
}

impl<const N: usize> MeasurementLog<N> {
    pub fn is_full(&self) -> bool {
        self.index as usize == N
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

#[derive(Deserialize, Serialize, SerializedSize)]
pub enum Attestation {
    Ed25519(Ed25519Signature),
}
