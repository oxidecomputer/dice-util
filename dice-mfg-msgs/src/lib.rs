// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use core::fmt;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub type MessageHash = [u8; 32];
pub const NULL_HASH: MessageHash = [0u8; 32];

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

// Code39 alphabet https://en.wikipedia.org/wiki/Code_39
const CODE39_LEN: usize = 43;
const CODE39_ALPHABET: [char; CODE39_LEN] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
    'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', '-', '.', ' ', '$', '/', '+', '%',
];

#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PlatformIdError {
    #[cfg_attr(
        any(test, feature = "std"),
        error("PID string length not supported")
    )]
    BadSize,
    #[cfg_attr(
        any(test, feature = "std"),
        error("invalid char '{c:?}' at offset {i:?}")
    )]
    Invalid { i: usize, c: char },
    #[cfg_attr(
        any(test, feature = "std"),
        error("PID string has invalid prefix")
    )]
    InvalidPrefix,
    #[cfg_attr(any(test, feature = "std"), error("PID string is malformed"))]
    Malformed,
}

// see RFD 308 § 4.3.1
// 0XV2:PPP-PPPPPPP:RRR:LLLWWYYSSSS
const PREFIX_LEN: usize = 4;
const RFD308_V2_LEN: usize = 32;
const RFD308_V2_PREFIX: &str = "0XV2";

// RFD 303 §4.6
const PLATFORM_ID_V1_LEN: usize = 32;
const PLATFORM_ID_V1_PREFIX: &str = "PDV1";
const PLATFORM_ID_V2_LEN: usize = 32;
const PLATFORM_ID_V2_PREFIX: &str = "PDV2";
pub const PLATFORM_ID_MAX_LEN: usize = PLATFORM_ID_V1_LEN;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
#[repr(C)]
pub struct PlatformId([u8; PLATFORM_ID_MAX_LEN]);

fn validate_0xv2(s: &str) -> Result<(), PlatformIdError> {
    if s.len() != RFD308_V2_LEN {
        return Err(PlatformIdError::BadSize);
    }
    if !s.starts_with(RFD308_V2_PREFIX) {
        return Err(PlatformIdError::InvalidPrefix);
    }
    validate_0xv2_noprefix(s)
}

fn validate_0xv2_noprefix(s: &str) -> Result<(), PlatformIdError> {
    for (i, c) in s.chars().enumerate() {
        match i {
            8 => {
                if c != '-' {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
            4 | 16 | 20 => {
                if c != ':' {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
            _ => {
                if c == 'O' || c == 'I' || !CODE39_ALPHABET.contains(&c) {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
        }
    }
    Ok(())
}

fn validate_pdv1(s: &str) -> Result<(), PlatformIdError> {
    if s.len() != PLATFORM_ID_V1_LEN {
        return Err(PlatformIdError::BadSize);
    }
    if !s.starts_with(PLATFORM_ID_V1_PREFIX) {
        return Err(PlatformIdError::InvalidPrefix);
    }
    // the only difference between the `0XV2` and `PDV1` formats are their
    // prefix
    validate_0xv2_noprefix(s)
}

fn validate_pdv2(s: &str) -> Result<(), PlatformIdError> {
    if s.len() != PLATFORM_ID_V2_LEN {
        return Err(PlatformIdError::BadSize);
    }
    if !s.starts_with(PLATFORM_ID_V2_PREFIX) {
        return Err(PlatformIdError::InvalidPrefix);
    }

    for (i, c) in s.chars().enumerate() {
        match i {
            8 => {
                if c != '-' {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
            4 | 16 | 20 => {
                if c != ':' {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
            17..=19 => {
                if c != 'R' {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
            _ => {
                if c == 'O' || c == 'I' || !CODE39_ALPHABET.contains(&c) {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
        }
    }
    Ok(())
}

// 0XV2 strings are converted to the most recent version of the PlatformId
// string.
fn platform_id_from_0xv2(s: &str) -> Result<PlatformId, PlatformIdError> {
    validate_0xv2(s)?;
    let s = s.as_bytes();
    let mut bytes = [0u8; PLATFORM_ID_MAX_LEN];

    // set PDV2 prefix
    bytes[..PLATFORM_ID_V2_PREFIX.len()]
        .copy_from_slice(PLATFORM_ID_V2_PREFIX.as_bytes());

    // copy ':PN'
    bytes[PLATFORM_ID_V1_PREFIX.len()..16]
        .copy_from_slice(&s[PLATFORM_ID_V2_PREFIX.len()..16]);

    bytes[16..20].copy_from_slice(b":RRR");
    // copy ':SN'
    bytes[20..32].copy_from_slice(&s[20..32]);

    Ok(PlatformId(bytes))
}

// PDV1 strings are copied verbatim. This is to support systems already mfg'd
// with certs containing PDV1 strings in the subject CN. We must be able to
// set the issuer field to the same value in it's descendants.
fn platform_id_from_pdv1(s: &str) -> Result<PlatformId, PlatformIdError> {
    validate_pdv1(s)?;
    Ok(PlatformId(
        s.as_bytes()
            .try_into()
            .map_err(|_| PlatformIdError::BadSize)?,
    ))
}

fn platform_id_from_pdv2(s: &str) -> Result<PlatformId, PlatformIdError> {
    validate_pdv2(s)?;

    const LEN: usize = PLATFORM_ID_MAX_LEN;
    let mut bytes = [0u8; LEN];
    bytes[..PLATFORM_ID_V2_LEN].copy_from_slice(s.as_bytes());

    Ok(PlatformId(bytes))
}

impl TryFrom<&str> for PlatformId {
    type Error = PlatformIdError;

    /// Construct a PlatformId enum variant appropriate for the supplied &str.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match &s[..PREFIX_LEN] {
            RFD308_V2_PREFIX => platform_id_from_0xv2(s),
            PLATFORM_ID_V1_PREFIX => platform_id_from_pdv1(s),
            PLATFORM_ID_V2_PREFIX => platform_id_from_pdv2(s),
            _ => Err(PlatformIdError::InvalidPrefix),
        }
    }
}

impl TryFrom<&[u8]> for PlatformId {
    type Error = PlatformIdError;

    /// Construct a PlatformId enum variant appropriate for the supplied &str.
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let pid =
            core::str::from_utf8(b).map_err(|_| PlatformIdError::Malformed)?;
        let pid = pid.trim_end_matches('\0');

        Self::try_from(pid)
    }
}

impl PlatformId {
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0[..PREFIX_LEN] {
            [b'P', b'D', b'V', b'1'] => &self.0[..PLATFORM_ID_V1_LEN],
            [b'P', b'D', b'V', b'2'] => &self.0[..PLATFORM_ID_V2_LEN],
            _ => panic!("invalid prefix in constructed PlatformId"),
        }
    }

    pub fn as_str(&self) -> Result<&str, PlatformIdError> {
        Ok(core::str::from_utf8(self.as_bytes())
            .map_err(|_| PlatformIdError::Malformed)?
            .trim_end_matches('\0'))
    }
}

#[derive(Debug, Deserialize, Serialize, SerializedSize)]
pub enum KeySlotStatus {
    Invalid,
    Enabled,
    Revoked,
}

#[cfg_attr(any(test, feature = "std"), derive(thiserror::Error))]
#[derive(Debug, PartialEq)]
pub enum Error {
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to decode corncobs message")
    )]
    Decode,
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to deserialize hubpack message")
    )]
    Deserialize,
    #[cfg_attr(
        any(test, feature = "std"),
        error("Failed to serialize hubpack message")
    )]
    Serialize,
    #[cfg_attr(
        any(test, feature = "std"),
        error("Slice too large for SizedBuf")
    )]
    SliceTooBig,
}

// large variants in enum is intentional: this is how we do serialization
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize, SerializedSize)]
pub enum MfgMessage {
    Ack(MessageHash),
    Break,
    Csr(SizedBlob),
    CsrPlz,
    IdentityCert(SizedBlob),
    IntermediateCert(SizedBlob),
    Nak,
    Ping,
    PlatformId(PlatformId),
    YouLockedBro,
    LockStatus {
        cmpa_locked: bool,
        syscon_locked: bool,
    },
    GetKeySlotStatus,
    KeySlotStatus {
        slots: [KeySlotStatus; 4],
    },
}

impl fmt::Display for MfgMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MfgMessage::Ack(hash) => write!(f, "MfgMessage::Ack: {:?}", hash),
            MfgMessage::Break => write!(f, "MfgMessage::Break"),
            MfgMessage::Csr(_) => write!(f, "MfgMessage::Csr"),
            MfgMessage::CsrPlz => write!(f, "MfgMessage::CsrPlz"),
            MfgMessage::IdentityCert(_) => {
                write!(f, "MfgMessage::IdentityCert")
            }
            MfgMessage::IntermediateCert(_) => {
                write!(f, "MfgMessage::IntermediateCert")
            }
            MfgMessage::Nak => write!(f, "MfgMessage::Nack"),
            MfgMessage::Ping => write!(f, "MfgMessage::Ping"),
            MfgMessage::PlatformId(_) => write!(f, "MfgMessage::PlatformId"),
            MfgMessage::YouLockedBro => f.write_str("MfgMessage::YouLockedBro"),
            MfgMessage::LockStatus { .. } => {
                f.write_str("MfgMessage::LockStatus")
            }
            MfgMessage::GetKeySlotStatus => {
                f.write_str("MfgMessage::GetKeySlotStatus")
            }
            MfgMessage::KeySlotStatus { .. } => {
                f.write_str("MfgMessage::KeySlotStatus")
            }
        }
    }
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

    type Result = std::result::Result<(), PlatformIdError>;

    const RFD308_V2_GOOD: &str = "0XV2:PPP-PPPPPPP:RRR:SSSSSSSSSSS";
    const PID_V1_GOOD: &str = "PDV1:PPP-PPPPPPP:000:SSSSSSSSSSS";
    const PID_V2_GOOD: &str = "PDV2:PPP-PPPPPPP:RRR:SSSSSSSSSSS";

    #[test]
    fn rfd308_v2_good() -> Result {
        assert!(!validate_0xv2(RFD308_V2_GOOD).is_err());

        Ok(())
    }

    #[test]
    fn pid_v1_good() -> Result {
        assert!(!validate_pdv1(PID_V1_GOOD).is_err());

        Ok(())
    }

    #[test]
    fn pid_v2_good() -> Result {
        assert!(validate_pdv2(PID_V2_GOOD).is_ok());

        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_length() -> Result {
        // missing an 'S'
        let pid = "0XV2:PPP-PPPPPPP:RRR:SSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::BadSize));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_prefix_part_sep() -> Result {
        let pid = "0XV2SPPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 4, c: 'S' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_part_rev_sep() -> Result {
        let pid = "0XV2:PPP-PPPPPPPERRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 16, c: 'E' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_rev_sn_sep() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:RRRPSSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 20, c: 'P' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_part() -> Result {
        let pid = "0XV2:pPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 5, c: 'p' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_revision() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:rRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 17, c: 'r' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_bad_serial() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:RRR:sSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 21, c: 's' }));
        Ok(())
    }
    // malformed UTF-8 from:
    // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
    #[test]
    fn rfd308_v2_malformed() -> Result {
        let mut bytes = [0u8; RFD308_V2_LEN];
        bytes[0] = 0xed;
        bytes[1] = 0xa0;
        bytes[2] = 0x80;
        let res = PlatformId::try_from(&bytes[..]);

        assert_eq!(res.err(), Some(PlatformIdError::Malformed));

        Ok(())
    }

    #[test]
    fn pid_v1_bad_length() -> Result {
        // missing an 'S'
        let pid = "PDV1:PPP-PPPPPPP:RRR:SSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::BadSize));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_prefix_part_sep() -> Result {
        let pid = "PDV1SPPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 4, c: 'S' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_part_rev_sep() -> Result {
        let pid = "PDV1:PPP-PPPPPPPERRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 16, c: 'E' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_rev_sn_sep() -> Result {
        let pid = "PDV1:PPP-PPPPPPP:RRRPSSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 20, c: 'P' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_part() -> Result {
        let pid = "PDV1:pPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 5, c: 'p' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_revision() -> Result {
        let pid = "PDV1:PPP-PPPPPPP:rRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 17, c: 'r' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_serial() -> Result {
        let pid = "PDV1:PPP-PPPPPPP:RRR:sSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 21, c: 's' }));
        Ok(())
    }

    #[test]
    fn rfd308_v2_copy_to_template() -> Result {
        let pid = RFD308_V2_GOOD;
        let pid = PlatformId::try_from(pid)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        assert_eq!(pid.as_str()?.len(), PLATFORM_ID_V2_LEN);
        dest[..pid.as_str()?.len()].copy_from_slice(pid.as_str()?.as_bytes());

        assert_eq!(&dest[..PREFIX_LEN], PLATFORM_ID_V2_PREFIX.as_bytes());
        assert_eq!(&pid.as_bytes()[4..16], &dest[4..16]);
        assert_eq!(&pid.as_bytes()[16..28], &dest[16..28]);
        Ok(())
    }

    #[test]
    fn pid_v1_from_template() -> Result {
        let pid = PlatformId::try_from(PID_V1_GOOD)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str()?.len()].copy_from_slice(pid.as_str()?.as_bytes());
        // mut no more
        let dest = dest;

        assert_eq!(pid.as_bytes(), &dest[..pid.as_str()?.len()]);

        let pid = PlatformId::try_from(&dest[..])?;
        assert_eq!(pid.as_str()?, PID_V1_GOOD);

        Ok(())
    }

    #[test]
    fn pid_v2_from_template() -> Result {
        let pid = PlatformId::try_from(RFD308_V2_GOOD)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str()?.len()].copy_from_slice(pid.as_str()?.as_bytes());
        // mut no more
        let dest = dest;

        assert_eq!(pid.as_bytes(), &dest[..pid.as_str()?.len()]);

        let pid = PlatformId::try_from(&dest[..])?;
        assert_eq!(pid.as_str()?, PID_V2_GOOD);

        Ok(())
    }
}
