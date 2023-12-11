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
use std::fmt::{self, Display, Formatter};

/// ArrayBuf is the type we use as a base for types that are constant sized
/// byte buffers.
#[serde_as]
#[derive(
    Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize,
)]
pub struct ArrayBuf<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Default for ArrayBuf<N> {
    /// Create and initialize an ArrayBuf<N> to 0's.
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for ArrayBuf<N> {
    /// Create an ArrayBuf from the provided array.
    fn from(item: [u8; N]) -> Self {
        Self(item)
    }
}

impl<const N: usize> TryFrom<&[u8]> for ArrayBuf<N> {
    type Error = core::array::TryFromSliceError;

    /// Attempt to create an ArrayBuf of a given size from the slice provided.
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        let nonce: [u8; N] = item.try_into()?;
        Ok(ArrayBuf::<N>(nonce))
    }
}

pub const SHA3_256_DIGEST_SIZE: usize =
    <Sha3_256Core as OutputSizeUser>::OutputSize::USIZE;

pub const NONCE_SIZE: usize = SHA3_256_DIGEST_SIZE;

/// An array of bytes sized appropriately for a sha3-256 digest.
pub type Sha3_256Digest = ArrayBuf<SHA3_256_DIGEST_SIZE>;

/// An array of bytes sized appropriately for a sha3-256 digest.
pub type Ed25519Signature = ArrayBuf<SIGNATURE_SERIALIZED_LENGTH>;

/// Nonce is a newtype around an appropriately sized byte array.
pub type Nonce = ArrayBuf<NONCE_SIZE>;

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
#[derive(Serialize, SerializedSize)]
pub struct Log<const N: usize> {
    index: u32,
    #[serde_as(as = "[_; N]")]
    measurements: [Measurement; N],
}

impl<const N: usize> Log<N> {
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

impl<const N: usize> Default for Log<N> {
    fn default() -> Self {
        Self {
            index: 0,
            measurements: [Measurement::default(); N],
        }
    }
}

#[derive(Deserialize, Serialize, SerializedSize)]
pub enum Attestation {
    Ed25519(Ed25519Signature),
}
