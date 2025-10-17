// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use const_oid::db::rfc4519::COMMON_NAME;
use core::{fmt, str::Utf8Error};
use dice_util_barcode::{
    Barcode, BarcodeError, Prefix, PREFIX_PDV1, PREFIX_PDV2, SEPARATOR,
};
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
#[cfg(feature = "std")]
use x509_cert::{
    der::{asn1::Utf8StringRef, Error as DerError},
    PkiPath,
};

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

/// A type representing all possible errors that can be encountered while
/// parsing a serial number string.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlatformIdError {
    #[error("The input string has an invalid prefix")]
    InvalidPrefix,
    #[error("Failed to construct Barcode from the provided string: {0}")]
    Barcode(#[from] BarcodeError),
    #[error("TheThe input string has no delimiters")]
    Encoding(#[from] Utf8Error),
    #[error("The input string has no delimiters")]
    NoDelim,
}

pub const PLATFORM_ID_MAX_LEN: usize = 32;
/// A type representing a platform identity string. It must fit in a 32 byte
/// region of memory.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
#[serde(try_from = "[u8; PLATFORM_ID_MAX_LEN]")]
pub struct PlatformId([u8; PLATFORM_ID_MAX_LEN]);

impl PlatformId {
    /// Get the platform identity string as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the platform identity as a &str
    /// NOTE: This function will panic if any of the bytes in the PlatformId
    /// aren't valid UTF8.
    pub fn as_str(&self) -> &str {
        str::from_utf8(&self.0)
            .expect("malformed platform id string")
            .trim_end_matches('\0')
    }
}

impl fmt::Display for PlatformId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for PlatformId {
    type Error = PlatformIdError;

    /// Attempt to construct a `PlatformId` instance from a string
    fn try_from(s: &str) -> Result<PlatformId, Self::Error> {
        let barcode = Barcode::try_from(s)?;

        // memory to collect parts of the barcode that make up the PlatformId
        // & indexes for copying data into it
        let mut pdv2 = [0u8; PLATFORM_ID_MAX_LEN];

        // offsets used copy bytes into `pdv2`
        let mut start = 0;
        let bytes = match barcode.prefix {
            // preserve the format / prefix of PDV1
            Prefix::PDV1 => PREFIX_PDV1.as_bytes(),
            // preserve the prefix for PDV2 & convert 0XV1 & 2 to PDV2
            Prefix::ZeroXV1 | Prefix::ZeroXV2 | Prefix::PDV2 => {
                PREFIX_PDV2.as_bytes()
            }
        };
        let mut end = bytes.len();
        pdv2[start..end].copy_from_slice(bytes);

        // set up a byte slice w/ the SEPARATOR char that we'll reuse
        let sep = SEPARATOR.as_bytes();

        // write separator
        start = end;
        end += 1;
        pdv2[start..end].copy_from_slice(sep);

        // write part number
        start = end;
        let part = barcode.part.as_str();
        // NOTE: how we update `start` depends on the type of the prefix so we
        // return `end` / the new `start`
        start = match barcode.prefix {
            // 0XV1 part number strings are v1 & must have a hyphen added to
            // become PDV2
            Prefix::ZeroXV1 => {
                // write first 3 bytes of the part number
                let bytes = &part.as_bytes()[..3];
                end += bytes.len();
                pdv2[start..end].copy_from_slice(bytes);

                // set up byte slice w/ ASCII for hyphen char '-'
                let hyphen = b"-";

                // write the hyphen missing from v1 part numbers
                start = end;
                end += hyphen.len();
                pdv2[start..end].copy_from_slice(hyphen);

                // write the last 7 bytes of the part number
                let bytes = &part.as_bytes()[3..];
                start = end;
                end += bytes.len();
                pdv2[start..end].copy_from_slice(bytes);

                end
            }
            // 0XV2, PDV1 & 2 already have v2 part numbers
            Prefix::ZeroXV2 | Prefix::PDV1 | Prefix::PDV2 => {
                let bytes = part.as_bytes();
                end += bytes.len();
                pdv2[start..end].copy_from_slice(bytes);

                end
            }
        };

        // write separator: `start` was updated above
        end += sep.len();
        pdv2[start..end].copy_from_slice(sep);

        // write revision
        start = end;

        // preserve the revision number for PDV1, all others will become PDV2
        let bytes = match barcode.prefix {
            Prefix::PDV1 => barcode.revision.as_bytes(),
            Prefix::ZeroXV1 | Prefix::ZeroXV2 | Prefix::PDV2 => b"RRR",
        };
        end += bytes.len();
        pdv2[start..end].copy_from_slice(bytes);

        // write separator
        start = end;
        end += sep.len();
        pdv2[start..end].copy_from_slice(sep);

        // write serial number
        start = end;
        let bytes = barcode.serial.as_bytes();
        end += bytes.len();
        pdv2[start..end].copy_from_slice(bytes);

        Ok(Self(pdv2))
    }
}

impl TryFrom<[u8; PLATFORM_ID_MAX_LEN]> for PlatformId {
    type Error = PlatformIdError;

    fn try_from(b: [u8; PLATFORM_ID_MAX_LEN]) -> Result<Self, Self::Error> {
        Self::try_from(&b[..])
    }
}

impl TryFrom<&[u8]> for PlatformId {
    type Error = PlatformIdError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let pid = str::from_utf8(b).map_err(PlatformIdError::Encoding)?;
        let pid = pid.trim_end_matches('\0');

        Self::try_from(pid)
    }
}

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlatformIdPkiPathError {
    #[error("Failed to decode CountryName")]
    CountryNameDecode(DerError),
    #[error("Expected CountryName \"US\", got {0}")]
    InvalidCountryName(String),
    #[error("Failed to decode OrganizationName")]
    OrganizationNameDecode(DerError),
    #[error("Expected CountryName \"US\", got {0}")]
    InvalidOrganizationName(String),
    #[error("Failed to decode OrganizationName")]
    CommonNameDecode(DerError),
    #[error("More than one PlatformId found in PkiPath")]
    MultiplePlatformIds,
    #[error("No PlatformId found in PkiPath")]
    NoPlatformId,
}

#[cfg(feature = "std")]
impl TryFrom<&PkiPath> for PlatformId {
    type Error = PlatformIdPkiPathError;
    // Find the PlatformId in the provided cert chain. This value is stored
    // in cert's `Subject` field. The PlatformId string is stored in the
    // Subject CN / commonName. A PkiPath with more than one PlatformId in
    // it produces an error.
    fn try_from(pki_path: &PkiPath) -> Result<Self, Self::Error> {
        let mut platform_id: Option<PlatformId> = None;
        for cert in pki_path {
            for elm in &cert.tbs_certificate.subject.0 {
                for atav in elm.0.iter() {
                    if atav.oid == COMMON_NAME {
                        let common = Utf8StringRef::try_from(&atav.value)
                            .map_err(Self::Error::CommonNameDecode)?;
                        let common: &str = common.as_ref();
                        // our common name is a fixed 32 bytes, but trailing
                        // characters may be NUL so we trim
                        let common = common.trim_end_matches('\0');
                        if let Ok(id) = PlatformId::try_from(common) {
                            if platform_id.is_none() {
                                platform_id = Some(id);
                            } else {
                                return Err(Self::Error::MultiplePlatformIds);
                            }
                        }
                    }
                }
            }
        }

        platform_id.ok_or(Self::Error::NoPlatformId)
    }
}

#[derive(Debug, Deserialize, Serialize, SerializedSize)]
pub enum KeySlotStatus {
    Invalid,
    Enabled,
    Revoked,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("Failed to decode corncobs message")]
    Decode,
    #[error("Failed to deserialize hubpack message")]
    Deserialize,
    #[error("Failed to serialize hubpack message")]
    Serialize,
    #[error("Slice too large for SizedBuf")]
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
            MfgMessage::Ack(hash) => write!(f, "MfgMessage::Ack: {hash:?}"),
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

    #[cfg(feature = "std")]
    use anyhow::Context;
    use dice_util_barcode::{
        InvalidChar, PartError, PartV2Error, PrefixError, RevisionError,
        SerialError, SerialV1Error,
    };
    #[cfg(feature = "std")]
    use x509_cert::{Certificate, PkiPath};

    #[test]
    fn rfd308_v2_bad_prefix_part_sep() -> Result<(), PlatformIdError> {
        let pid = "0XV2SPPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Prefix(
                PrefixError::Invalid
            )))
        );
        Ok(())
    }

    // malformed UTF-8 from:
    // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
    #[test]
    fn rfd308_v2_malformed() -> Result<(), PlatformIdError> {
        let mut bytes = [0u8; PLATFORM_ID_MAX_LEN];
        bytes[0] = 0xed;
        bytes[1] = 0xa0;
        bytes[2] = 0x80;
        let res = PlatformId::try_from(&bytes[..]);

        // NOTE: how to construct Utf8Error to enable comparison?
        assert!(res.is_err());

        Ok(())
    }

    #[test]
    fn pid_v1_bad_length() -> Result<(), PlatformIdError> {
        // missing an 'S'
        let pid = "PDV1:PPP-PPPPPPP:RRR:SSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        // NOTE: this is going to fail for a different reason than intended /
        // expected by this test: there's an 'S' missing from the SN as
        // indicated above, but the parser will reject the PN (invalid
        // characters) before it gets to the SN (I think)
        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Part(
                PartError::PartV2(PartV2Error::InvalidChar(InvalidChar {
                    index: 0,
                    character: 'P'
                }))
            )))
        );
        Ok(())
    }

    #[test]
    fn pid_v1_bad_prefix_part_sep() -> Result<(), PlatformIdError> {
        let pid = "PDV1SPPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Prefix(
                PrefixError::Invalid
            )))
        );
        Ok(())
    }

    #[test]
    fn pid_v1_bad_part() -> Result<(), PlatformIdError> {
        let pid = "PDV1:pPP-PPPPPPP:RRR:SSSSSSSSSSS";
        let pid = PlatformId::try_from(pid);

        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Part(
                PartError::PartV2(PartV2Error::InvalidChar(InvalidChar {
                    index: 0,
                    character: 'p'
                }))
            )))
        );
        Ok(())
    }

    #[test]
    fn pid_v1_bad_revision() -> Result<(), PlatformIdError> {
        let pid = "PDV1:913-0000019:R14:BRM03250020";
        let pid = PlatformId::try_from(pid);

        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Revision(
                RevisionError::InvalidChar(InvalidChar {
                    index: 0,
                    character: 'R'
                })
            )))
        );
        Ok(())
    }

    #[test]
    fn pid_v1_bad_serial() -> Result<(), PlatformIdError> {
        let pid = "PDV1:913-0000019:014:BRM54250020";
        let pid = PlatformId::try_from(pid);

        assert_eq!(
            pid.err(),
            Some(PlatformIdError::Barcode(BarcodeError::Serial(
                SerialError::SerialV1(SerialV1Error::InvalidWeek)
            )))
        );
        Ok(())
    }

    #[test]
    fn rfd308_v2_copy_to_template() -> Result<(), PlatformIdError> {
        let pid = PDV2_GOOD;
        let pid = PlatformId::try_from(pid)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str().len()].copy_from_slice(pid.as_bytes());

        let pdv2_bytes = PREFIX_PDV2.as_bytes();
        assert_eq!(&dest[..pdv2_bytes.len()], pdv2_bytes);
        assert_eq!(&pid.as_bytes()[4..16], &dest[4..16]);
        assert_eq!(&pid.as_bytes()[16..28], &dest[16..28]);
        Ok(())
    }

    const PDV1_GOOD: &str = "PDV1:913-0000019:000:BRM03250020";
    #[test]
    fn pid_v1_from_template() -> Result<(), PlatformIdError> {
        let pid = PlatformId::try_from(PDV1_GOOD)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str().len()].copy_from_slice(pid.as_bytes());
        // mut no more
        let dest = dest;

        assert_eq!(pid.as_bytes(), &dest[..pid.as_str().len()]);

        let pid = PlatformId::try_from(&dest[..])?;
        assert_eq!(pid.as_str(), PDV1_GOOD);

        Ok(())
    }

    const PDV2_GOOD: &str = "PDV2:913-0000019:RRR:BRM01010001";
    #[test]
    fn pid_v2_from_template() -> Result<(), PlatformIdError> {
        let pid = PlatformId::try_from(OXV2_GOOD)?;
        let mut dest = [0u8; PLATFORM_ID_MAX_LEN];

        dest[..pid.as_str().len()].copy_from_slice(pid.as_bytes());
        // mut no more
        let dest = dest;

        assert_eq!(pid.as_bytes(), &dest[..pid.as_str().len()]);

        let pid = PlatformId::try_from(&dest[..])?;
        assert_eq!(pid.as_str(), PDV2_GOOD);

        Ok(())
    }

    const OXV2_GOOD: &str = "0XV2:913-0000019:014:BRM01010001";
    const OXV2_GOOD_SERIALIZED: [u8; 32] = [
        b'P', b'D', b'V', b'2', b':', b'9', b'1', b'3', b'-', b'0', b'0', b'0',
        b'0', b'0', b'1', b'9', b':', b'R', b'R', b'R', b':', b'B', b'R', b'M',
        b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'1',
    ];

    #[test]
    fn pid_serialize() -> Result<(), PlatformIdError> {
        let mut buf = [0u8; PlatformId::MAX_SIZE];

        let pid = PlatformId::try_from(OXV2_GOOD)?;
        let _ = hubpack::serialize(&mut buf, &pid).unwrap();

        assert_eq!(buf, OXV2_GOOD_SERIALIZED);
        Ok(())
    }

    #[test]
    fn pid_deserialize_good() -> Result<(), PlatformIdError> {
        let (pid, _) =
            hubpack::deserialize::<PlatformId>(&OXV2_GOOD_SERIALIZED)
                .expect("deserialization failed for \"good\" test data");
        let pid_expected = PlatformId::try_from(OXV2_GOOD)
            .expect("failed to create PlatformId from \"good\" test data");

        assert_eq!(pid, pid_expected);
        Ok(())
    }

    #[test]
    fn pid_deserialize_bad() -> Result<(), PlatformIdError> {
        // make a local copy of the good serialized value
        let mut pid = OXV2_GOOD_SERIALIZED;
        // set one character to an invalid value
        pid[22] = b's';

        let res = hubpack::deserialize::<PlatformId>(&pid);
        assert_eq!(res, Err(hubpack::error::Error::Custom));

        Ok(())
    }

    // a self signed cert with a platform id string in the the Subject
    // commonName
    #[cfg(feature = "std")]
    const PLATFORM_ID_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtTCCAWegAwIBAgIBADAFBgMrZXAwWTELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxKTAnBgNVBAMMIFBEVjI6OTEzLTAwMDAw
MTk6UlJSOkJSTTAxMjVTU1NTMCAXDTI1MTAwNTIwMjUzNVoYDzk5OTkxMjMxMjM1
OTU5WjBZMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29t
cGFueTEpMCcGA1UEAwwgUERWMjo5MTMtMDAwMDAxOTpSUlI6QlJNMDEyNVNTU1Mw
KjAFBgMrZXADIQBMG83tJtwLBZUEWEvqdmArDurS99oWBzqRuwGWVOwygqNSMFAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJ
BgdngQUFBGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQDct3PXbNNr
580BdDFF0xijkWVPuNwTcmPtbweFwHyjKmrMnsPoH0SGdXPnNPBQaxIQRRUBlsll
I1Dpq9liDQgB
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path() -> anyhow::Result<()> {
        let bytes = PLATFORM_ID_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from PLATFORM_ID_PEM")?;

        let platform_id = PlatformId::try_from(&cert_chain)
            .context("PlatformId from cert chain")?;

        Ok(assert_eq!(
            platform_id.as_str(),
            "PDV2:913-0000019:RRR:BRM0125SSSS"
        ))
    }

    #[cfg(feature = "std")]
    const PLATFORM_ID_V2_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBrzCCAWGgAwIBAgIBADAFBgMrZXAwVjELMAkGA1UEBhMCVVMxHzAdBgNVBAoM
Fk94aWRlIENvbXB1dGVyIENvbXBhbnkxJjAkBgNVBAMMHVBEVjI6OTEzLTAwMDAw
MTk6UlJSOjIwMDAwMDAxMCAXDTI1MTAwNTIwNDAxNVoYDzk5OTkxMjMxMjM1OTU5
WjBWMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWT3hpZGUgQ29tcHV0ZXIgQ29tcGFu
eTEmMCQGA1UEAwwdUERWMjo5MTMtMDAwMDAxOTpSUlI6MjAwMDAwMDEwKjAFBgMr
ZXADIQAGu+YOb+jCK2ym7VbkqLFow84N63eGReFvUjFjFY4hDqNSMFAwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwLQYDVR0gAQH/BCMwITAJBgdngQUF
BGQGMAkGB2eBBQUEZAgwCQYHZ4EFBQRkDDAFBgMrZXADQQAZl2L55J+mR16GvdJ3
RbTFWQP529efGPuONazpoynDoFBadsoB+9h2COjtba45BogaXG1mfc+gThY/byGN
pngE
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_v2() -> anyhow::Result<()> {
        let bytes = PLATFORM_ID_V2_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from PLATFORM_ID_PEM")?;

        let platform_id = PlatformId::try_from(&cert_chain)
            .context("PlatformId from cert chain")?;

        Ok(assert_eq!(
            platform_id.as_str(),
            "PDV2:913-0000019:RRR:20000001"
        ))
    }

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_multiple() -> anyhow::Result<()> {
        // Create a cert chain w/ multiple PlatformIds. This chain is invalid
        // but it's useful for testing and a good example of why we need to
        // verify the signatures through the chain before pulling out data
        // like the PlatformId.
        let mut certs: String = PLATFORM_ID_PEM.to_owned();
        certs.push_str(PLATFORM_ID_PEM);

        let cert_chain: PkiPath = Certificate::load_pem_chain(certs.as_bytes())
            .context("Certificate from two istances of PLATFORM_ID_PEM")?;

        let platform_id = PlatformId::try_from(&cert_chain);

        Ok(assert_eq!(
            platform_id,
            Err(PlatformIdPkiPathError::MultiplePlatformIds)
        ))
    }

    #[cfg(feature = "std")]
    const NO_PLATFORM_ID_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBADCBs6ADAgECAgEAMAUGAytlcDApMQswCQYDVQQGEwJVUzEMMAoGA1UECgwD
Zm9vMQwwCgYDVQQDDANiYXIwIBcNMjUwNDI5MDUyMzE5WhgPOTk5OTEyMzEyMzU5
NTlaMCkxCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANmb28xDDAKBgNVBAMMA2JhcjAq
MAUGAytlcAMhALcL3kNks3jo9ExtQYeCZ+BoCy1Or5ybLPqSsi9XZXiSMAUGAytl
cANBAFleiVB2JzLpysPIJkia4DYodkTc0KuelpNqV0ycemgQqD30O085W7xZ+c/X
+AqBlWPcwiy+hq3aaWCa586hUQ8=
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "std")]
    #[test]
    fn pid_from_pki_path_none() -> anyhow::Result<()> {
        let bytes = NO_PLATFORM_ID_PEM.as_bytes();
        let cert_chain: PkiPath = Certificate::load_pem_chain(bytes)
            .context("Certificate from NO_PLATFORM_ID_PEM")?;

        let platform_id = PlatformId::try_from(&cert_chain);

        Ok(assert_eq!(
            platform_id,
            Err(PlatformIdPkiPathError::NoPlatformId)
        ))
    }
}
