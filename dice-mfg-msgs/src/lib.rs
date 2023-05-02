// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(test), no_std)]

use core::convert::TryFrom;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PlatformIdError {
    BadSize,
    Invalid { i: usize, c: char },
    InvalidPrefix,
    Malformed,
}

// see RFD 308 § 4.3.1
// 0XV1:PPPPPPPPPP:RRR:LLLWWYYSSSS
// 0XV2:PPP-PPPPPPP:RRR:LLLWWYYSSSS
const PLATFORM_ID_V1_LEN: usize = 31;
const PLATFORM_ID_V1_PREFIX: &str = "0XV1";
const PLATFORM_ID_V2_LEN: usize = 32;
const PLATFORM_ID_V2_PREFIX: &str = "0XV2";
pub const PLATFORM_ID_MAX_LEN: usize = PLATFORM_ID_V2_LEN;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, SerializedSize)]
#[repr(C)]
pub enum PlatformId {
    V1([u8; PLATFORM_ID_V1_LEN]),
    V2([u8; PLATFORM_ID_V2_LEN]),
}

fn new_platform_id_v1(s: &str) -> Result<PlatformId, PlatformIdError> {
    if !s.starts_with(PLATFORM_ID_V1_PREFIX) {
        return Err(PlatformIdError::InvalidPrefix);
    }
    for (i, c) in s.chars().enumerate() {
        match i {
            4 | 15 | 19 => {
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

    Ok(PlatformId::V1(
        s.as_bytes()
            .try_into()
            .map_err(|_| PlatformIdError::BadSize)?,
    ))
}

fn new_platform_id_v2(s: &str) -> Result<PlatformId, PlatformIdError> {
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
            _ => {
                if c == 'O' || c == 'I' || !CODE39_ALPHABET.contains(&c) {
                    return Err(PlatformIdError::Invalid { i, c });
                }
            }
        }
    }

    Ok(PlatformId::V2(
        s.as_bytes()
            .try_into()
            .map_err(|_| PlatformIdError::BadSize)?,
    ))
}

impl TryFrom<&str> for PlatformId {
    type Error = PlatformIdError;

    /// Construct a PlatformId enum variant appropriate for the supplied &str.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.len() {
            PLATFORM_ID_V1_LEN => new_platform_id_v1(s),
            PLATFORM_ID_V2_LEN => new_platform_id_v2(s),
            _ => Err(PlatformIdError::BadSize),
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

        match pid.len() {
            PLATFORM_ID_V1_LEN => new_platform_id_v1(pid),
            PLATFORM_ID_V2_LEN => new_platform_id_v2(pid),
            _ => Err(PlatformIdError::BadSize),
        }
    }
}

impl PlatformId {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PlatformId::V1(b) => &b[..],
            PlatformId::V2(b) => &b[..],
        }
    }

    pub fn as_str(&self) -> Result<&str, PlatformIdError> {
        match self {
            PlatformId::V1(b) => core::str::from_utf8(&b[..])
                .map_err(|_| PlatformIdError::Malformed),
            PlatformId::V2(b) => core::str::from_utf8(&b[..])
                .map_err(|_| PlatformIdError::Malformed),
        }
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
    PlatformId(PlatformId),
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

    type Result = std::result::Result<(), PlatformIdError>;

    const PID_V1_GOOD: &str = "0XV1:PPPPPPPPPP:RRR:SSSSSSSSSSS";
    const PID_V2_GOOD: &str = "0XV2:PPP-PPPPPPP:RRR:SSSSSSSSSSS";

    #[test]
    fn pid_v1_good() -> Result {
        let res = new_platform_id_v1(PID_V1_GOOD);

        assert!(!res.is_err());
        assert_eq!(res.unwrap().as_str().unwrap(), PID_V1_GOOD);

        Ok(())
    }

    // malformed UTF-8 from:
    // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
    #[test]
    fn pid_v1_malformed() -> Result {
        let mut bytes = [0u8; PLATFORM_ID_V1_LEN];
        bytes[0] = 0xed;
        bytes[1] = 0xa0;
        bytes[2] = 0x80;
        let pid = PlatformId::V1(bytes);
        let res = pid.as_str();

        assert_eq!(res.err(), Some(PlatformIdError::Malformed));

        Ok(())
    }

    #[test]
    fn pid_v1_bad_length() -> Result {
        // missing an 'S'
        let pid = "0XV1:PPPPPPPPPP:RRR:SSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::BadSize));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_prefix_part_sep() -> Result {
        let pid = "0XV1SPPPPPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 4, c: 'S' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_part_rev_sep() -> Result {
        let pid = "0XV1:PPPPPPPPPPERRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 15, c: 'E' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_rev_sn_sep() -> Result {
        let pid = "0XV1:PPPPPPPPPP:RRRPSSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 19, c: 'P' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_part() -> Result {
        let pid = "0XV1:pPPPPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 5, c: 'p' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_revision() -> Result {
        let pid = "0XV1:PPPPPPPPPP:rRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 16, c: 'r' }));
        Ok(())
    }

    #[test]
    fn pid_v1_bad_serial() -> Result {
        let pid = "0XV1:PPPPPPPPPP:RRR:sSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 20, c: 's' }));
        Ok(())
    }

    #[test]
    fn pid_v2_good() -> Result {
        let res = new_platform_id_v2(PID_V2_GOOD);

        assert!(!res.is_err());
        assert_eq!(res.unwrap().as_str().unwrap(), PID_V2_GOOD);

        Ok(())
    }

    #[test]
    fn pid_v2_bad_length() -> Result {
        // missing an 'S'
        let pid = "0XV2:PPP-PPPPPPP:RRR:SSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::BadSize));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_prefix_part_sep() -> Result {
        let pid = "0XV2SPPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 4, c: 'S' }));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_part_rev_sep() -> Result {
        let pid = "0XV2:PPP-PPPPPPPERRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 16, c: 'E' }));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_rev_sn_sep() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:RRRPSSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 20, c: 'P' }));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_part() -> Result {
        let pid = "0XV2:pPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 5, c: 'p' }));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_revision() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:rRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 17, c: 'r' }));
        Ok(())
    }

    #[test]
    fn pid_v2_bad_serial() -> Result {
        let pid = "0XV2:PPP-PPPPPPP:RRR:sSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(pid.err(), Some(PlatformIdError::Invalid { i: 21, c: 's' }));
        Ok(())
    }

    #[test]
    fn pid_v1_copy_to_template() -> Result {
        let pid = "0XV1:PPPPPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str()?.len()].copy_from_slice(pid.as_str()?.as_bytes());

        assert_eq!(pid.as_bytes(), &dest[..pid.as_str()?.len()]);
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
        let pid = PlatformId::try_from(PID_V2_GOOD)?;
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
