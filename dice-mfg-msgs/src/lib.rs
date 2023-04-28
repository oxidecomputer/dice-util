// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(test), no_std)]

use core::convert::{From, TryFrom};
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zerocopy::AsBytes;

const BLOB_SIZE: usize = 768;

#[derive(Clone, Debug, Deserialize, Serialize, SerializedSize)]
pub struct Blob(#[serde(with = "BigArray")] [u8; BLOB_SIZE]);

impl TryFrom<&[u8]> for Blob {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        if s.len() > BLOB_SIZE {
            return Err(Self::Error::SliceTooBig);
        }
        let mut buf = [0u8; BLOB_SIZE];
        buf[..s.len()].copy_from_slice(s);

        Ok(Self(buf))
    }
}

impl Default for Blob {
    fn default() -> Self {
        Self([0u8; BLOB_SIZE])
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, SerializedSize)]
pub struct SizedBlob {
    pub size: u16,
    pub data: Blob,
}

impl TryFrom<&[u8]> for SizedBlob {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            // this is a lossy conversion but if s.len() > u16::MAX then the
            // following try_from will produce an error
            size: s.len() as u16,
            data: Blob::try_from(s)?,
        })
    }
}

impl SizedBlob {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data.0[..]
    }
}

// see RFD 219
const SN_LENGTH: usize = 11;

#[repr(C)]
#[derive(
    AsBytes, Clone, Copy, Debug, Deserialize, Serialize, SerializedSize,
)]
pub struct SerialNumber([u8; SN_LENGTH]);

#[derive(Clone, Copy, Debug)]
pub enum SNError {
    BadSize,
    Invalid,
}

impl TryFrom<&str> for SerialNumber {
    type Error = SNError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() {
                return Err(SNError::Invalid);
            }
        }

        Ok(Self(s.as_bytes().try_into().map_err(|_| SNError::BadSize)?))
    }
}

impl From<&[u8; SN_LENGTH]> for SerialNumber {
    fn from(sn: &[u8; SN_LENGTH]) -> Self {
        Self::new(sn)
    }
}

impl SerialNumber {
    pub fn new(sn: &[u8; SN_LENGTH]) -> Self {
        Self(*sn)
    }
}

// Code39 alphabet https://en.wikipedia.org/wiki/Code_39
const CODE39_LEN: usize = 43;
const CODE39_ALPHABET: [char; CODE39_LEN] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
    'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', '-', '.', ' ', '$', '/', '+', '%',
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PRNError {
    PartSeparatorMissing,
    SeparatorMissing,
    BadSize,
    Invalid { i: usize, c: char },
}

const PRN_LENGTH: usize = 15;

#[repr(C)]
#[derive(
    AsBytes, Clone, Copy, Debug, Deserialize, Serialize, SerializedSize,
)]
pub struct PartRevisionNumber([u8; PRN_LENGTH]);

impl TryFrom<&str> for PartRevisionNumber {
    type Error = PRNError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        for (i, c) in s.chars().enumerate() {
            // see RFD 308
            match i {
                3 => {
                    if c != '-' {
                        return Err(PRNError::PartSeparatorMissing);
                    }
                }
                11 => {
                    if c != ':' {
                        return Err(PRNError::SeparatorMissing);
                    }
                }
                _ => {
                    if !CODE39_ALPHABET.contains(&c) {
                        return Err(PRNError::Invalid { i, c });
                    }
                }
            }
        }

        Ok(Self(
            s.as_bytes().try_into().map_err(|_| PRNError::BadSize)?,
        ))
    }
}

// large variants in enum is intentional: this is how we do serialization
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize, SerializedSize)]
pub enum MfgMessage {
    Ack,
    Break,
    Csr(SizedBlob),
    CsrPlz,
    IdentityCert(SizedBlob),
    IntermediateCert(SizedBlob),
    Nak,
    Ping,
    SerialNumber(SerialNumber),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Decode,
    Deserialize,
    Serialize,
    SliceTooBig,
}

impl MfgMessage {
    pub const MAX_ENCODED_SIZE: usize =
        corncobs::max_encoded_len(Self::MAX_SIZE);

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut buf = [0u8; Self::MAX_SIZE];

        let size =
            corncobs::decode_buf(data, &mut buf).map_err(|_| Error::Decode)?;
        let (msg, _) = hubpack::deserialize::<Self>(&buf[..size])
            .map_err(|_| Error::Deserialize)?;

        Ok(msg)
    }

    pub fn encode(
        &self,
        dst: &mut [u8; Self::MAX_ENCODED_SIZE],
    ) -> Result<usize, Error> {
        let mut buf = [0xFFu8; Self::MAX_ENCODED_SIZE];

        let size =
            hubpack::serialize(&mut buf, self).map_err(|_| Error::Serialize)?;

        Ok(corncobs::encode_buf(&buf[..size], dst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error, result};

    type Result = result::Result<(), Box<dyn error::Error>>;

    #[test]
    fn prn_check() -> Result {
        let prn = "PPP-PPPPPPP:RRR";
        let res = PartRevisionNumber::try_from(prn);

        assert!(!res.is_err());
        Ok(())
    }

    #[test]
    fn prn_check_bad_part() -> Result {
        let prn = "pPP-PPPPPPP:RRR";
        let prn = PartRevisionNumber::try_from(prn);

        assert_eq!(prn.err(), Some(PRNError::Invalid { i: 0, c: 'p' }));
        Ok(())
    }

    #[test]
    fn prn_check_bad_revision() -> Result {
        let prn = "PPP-PPPPPPP:RrR";
        let prn = PartRevisionNumber::try_from(prn);

        assert_eq!(prn.err(), Some(PRNError::Invalid { i: 13, c: 'r' }));
        Ok(())
    }

    #[test]
    fn prn_check_bad_part_sep() -> Result {
        let prn = "PPPHPPPPPPP:RRR";
        let prn = PartRevisionNumber::try_from(prn);

        assert_eq!(prn.err(), Some(PRNError::PartSeparatorMissing));
        Ok(())
    }

    #[test]
    fn prn_check_bad_sep() -> Result {
        let prn = "PPP-PPPPPPPRRRR";
        let prn = PartRevisionNumber::try_from(prn);

        assert_eq!(prn.err(), Some(PRNError::SeparatorMissing));
        Ok(())
    }
}
