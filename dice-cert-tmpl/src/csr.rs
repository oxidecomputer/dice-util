// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{MissingFieldError, SIGNATURE_LEN, SUBJECT_CN_LEN, SUBJECT_SN_LEN};
use anyhow::{anyhow, Context, Result};
use std::{fmt, ops::Range};
use x509_cert::der::{Decode, Header, Reader, SliceReader, Tag};

// Type to expose parsing operations on CSR in underlying slice
pub struct Csr<'a>(&'a mut [u8]);

impl fmt::Display for Csr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::arrayfmt(self.as_bytes(), f)
    }
}

impl<'a> Csr<'a> {
    pub fn from_slice(csr: &'a mut [u8]) -> Self {
        Self(csr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    pub fn clear_range(&mut self, start: usize, end: usize) {
        self.0[start..end].fill(0)
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().len() == 0
    }

    pub fn get_pub_offsets(&self) -> Result<Range<usize>> {
        let mut reader =
            SliceReader::new(self.0).context("SliceReader from cert DER")?;

        // RFC 5280 Certificate is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode Certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // certificateRequestInfo is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode tbsCertificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `version` is a constructed, context specific type numbered 0
        let header =
            Header::decode(&mut reader).context("decode version header")?;
        if header.tag != Tag::Integer {
            return Err(anyhow!(
                "Expected version INTEGER, got {:?}",
                header.tag
            ));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past version")?;

        // `subject` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode subject header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past subject")?;

        // `subjectPKInfo` is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode subjectPublicKeyInfo header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // algorithm is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode subjectPublicKeyInfo header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        // TODO: ensure the subjectPublicKey is an ed25519
        let _ = reader
            .read_slice(header.length)
            .context("read past subjectPublicKeyInfo")?;

        // `subjectPublicKey` is a `BIT STRING`
        let header = Header::decode(&mut reader)
            .context("decode subjectPublicKey header")?;
        if header.tag != Tag::BitString {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // there are no partial bytes in the signature algorithms used
        let unused = reader
            .read_byte()
            .context("read past byte with unused bits")?;
        if unused != 0 {
            return Err(anyhow!("signature BIT STRING has unused bits"));
        }

        let start = u32::from(reader.offset());
        let end = start + u32::from(header.length) - 1;

        Ok(Range {
            start: start.try_into().context("start offset to usize")?,
            end: end.try_into().context("end offset to usize")?,
        })
    }

    pub fn get_pub(&self) -> Result<&[u8]> {
        Ok(&self.0[self.get_pub_offsets()?])
    }

    // SET, SEQUENCE, OID (2.5.4.3 / commonName)
    const SUBJECT_CN_PATTERN: [u8; 11] = [
        0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20,
    ];
    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_cn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SUBJECT_CN_PATTERN, SUBJECT_CN_LEN)
            .ok_or(MissingFieldError::SubjectCn.into())
    }

    // ASN.1 TLVs & OID for serialNumber (x.520 DN component)
    #[rustfmt::skip]
    const SUBJECT_SN_PATTERN: [u8; 11] = [
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
        0x05, 0x13, 0x0B,
    ];

    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_sn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SUBJECT_SN_PATTERN, SUBJECT_SN_LEN)
            .ok_or(MissingFieldError::SubjectSn.into())
    }

    #[rustfmt::skip]
    const SIG_PATTERN: [u8; 10] = [
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03,
        0x41, 0x00,
    ];
    pub fn get_sig_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SIG_PATTERN, SIGNATURE_LEN)
            .ok_or(MissingFieldError::Signature.into())
    }

    pub fn get_sig(&self) -> Result<&[u8]> {
        let (start, end) = self.get_sig_offsets()?;

        Ok(&self.0[start..end])
    }

    #[rustfmt::skip]
    const SIGNDATA_PATTERN: [u8; 7] = [
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    ];

    pub fn get_signdata_offsets(&self) -> Result<(usize, usize)> {
        // CSR data to sign is the CertificationRequestInfo field in the
        // CertificationRequest structure (RFC 2986).
        let start = match self.as_bytes()[1] {
            0x81 => 3,
            0x82 => 4,
            _ => return Err(MissingFieldError::SignData.into()),
        };

        let end = crate::get_pattern_roffset(self.0, &Self::SIGNDATA_PATTERN)
            .ok_or(MissingFieldError::SignData)?;

        Ok((start, end))
    }

    pub fn get_signdata(&self) -> Result<&[u8]> {
        let (start, end) = self.get_signdata_offsets()?;

        Ok(&self.0[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: include_bytes! from file
    #[rustfmt::skip]
    const CSR: [u8; 224] = [
        0x30, 0x81, 0xdd, 0x30, 0x81, 0x90, 0x02, 0x01,
        0x00, 0x30, 0x5d, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42,
        0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x0c, 0x07, 0x45, 0x6e, 0x67, 0x6c, 0x61,
        0x6e, 0x64, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
        0x55, 0x04, 0x0a, 0x0c, 0x09, 0x41, 0x6c, 0x69,
        0x63, 0x65, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c,
        0x0f, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c,
        0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x61, 0x73,
        0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73,
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00, 0x27, 0xfb, 0x87, 0x77,
        0x77, 0x36, 0x54, 0xfb, 0x78, 0xb3, 0x46, 0x6b,
        0x95, 0x0e, 0x15, 0x2b, 0x8b, 0xcd, 0x0c, 0x9b,
        0x8a, 0x08, 0xfc, 0x7a, 0xef, 0x68, 0x97, 0x1e,
        0xab, 0xa0, 0x87, 0x70, 0xa0, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00,
        0xf5, 0xf5, 0xcf, 0xde, 0x58, 0x87, 0x6a, 0x0e,
        0xa6, 0xb3, 0x3f, 0x23, 0x98, 0xd6, 0x97, 0x0c,
        0x3a, 0xaa, 0xb2, 0xdf, 0xa0, 0x6e, 0x5b, 0xf7,
        0xd2, 0x2b, 0x86, 0x2e, 0x05, 0xd9, 0xa4, 0x5f,
        0xe6, 0x49, 0xfc, 0xf0, 0x09, 0x66, 0x85, 0x87,
        0x6b, 0x42, 0xe6, 0xea, 0x77, 0x74, 0x55, 0x64,
        0xf8, 0x86, 0x12, 0xeb, 0x4d, 0x8d, 0xcc, 0x22,
        0xd6, 0x13, 0x5d, 0x2f, 0x47, 0xf3, 0x99, 0x03,
    ];

    #[rustfmt::skip]
    const PUB: &[u8] = &[
        0x27, 0xfb, 0x87, 0x77, 0x77, 0x36, 0x54, 0xfb,
        0x78, 0xb3, 0x46, 0x6b, 0x95, 0x0e, 0x15, 0x2b,
        0x8b, 0xcd, 0x0c, 0x9b, 0x8a, 0x08, 0xfc, 0x7a,
        0xef, 0x68, 0x97, 0x1e, 0xab, 0xa0, 0x87, 0x70,
    ];

    #[rustfmt::skip]
    const SIG: &[u8] = &[
        0xf5, 0xf5, 0xcf, 0xde, 0x58, 0x87, 0x6a, 0x0e,
        0xa6, 0xb3, 0x3f, 0x23, 0x98, 0xd6, 0x97, 0x0c,
        0x3a, 0xaa, 0xb2, 0xdf, 0xa0, 0x6e, 0x5b, 0xf7,
        0xd2, 0x2b, 0x86, 0x2e, 0x05, 0xd9, 0xa4, 0x5f,
        0xe6, 0x49, 0xfc, 0xf0, 0x09, 0x66, 0x85, 0x87,
        0x6b, 0x42, 0xe6, 0xea, 0x77, 0x74, 0x55, 0x64,
        0xf8, 0x86, 0x12, 0xeb, 0x4d, 0x8d, 0xcc, 0x22,
        0xd6, 0x13, 0x5d, 0x2f, 0x47, 0xf3, 0x99, 0x03,
    ];

    #[rustfmt::skip]
    const SIGNDATA: &[u8] = &[
        0x30, 0x81, 0x90, 0x02, 0x01, 0x00, 0x30, 0x5d,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x10, 0x30,
        0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07,
        0x45, 0x6e, 0x67, 0x6c, 0x61, 0x6e, 0x64, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x09, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x20,
        0x4c, 0x74, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06,
        0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x41, 0x6c,
        0x69, 0x63, 0x65, 0x20, 0x4c, 0x74, 0x64, 0x20,
        0x61, 0x6c, 0x69, 0x61, 0x73, 0x31, 0x0e, 0x30,
        0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05,
        0x61, 0x6c, 0x69, 0x61, 0x73, 0x30, 0x2a, 0x30,
        0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
        0x00, 0x27, 0xfb, 0x87, 0x77, 0x77, 0x36, 0x54,
        0xfb, 0x78, 0xb3, 0x46, 0x6b, 0x95, 0x0e, 0x15,
        0x2b, 0x8b, 0xcd, 0x0c, 0x9b, 0x8a, 0x08, 0xfc,
        0x7a, 0xef, 0x68, 0x97, 0x1e, 0xab, 0xa0, 0x87,
        0x70, 0xa0, 0x00,
    ];

    #[test]
    fn get_pub_offsets() -> Result<()> {
        let mut csr = CSR;
        let csr = Csr::from_slice(&mut csr);
        let range = csr.get_pub_offsets()?;
        assert_eq!(&csr.as_bytes()[range], PUB);
        Ok(())
    }

    #[test]
    fn get_sig_offsets() -> Result<()> {
        let mut csr = CSR;
        let csr = Csr::from_slice(&mut csr);
        let (start, end) = csr.get_sig_offsets()?;
        assert_eq!(&csr.as_bytes()[start..end], SIG);
        Ok(())
    }

    #[test]
    fn get_signdata_offsets() -> Result<()> {
        let mut csr = CSR;
        let csr = Csr::from_slice(&mut csr);
        let (start, end) = csr.get_signdata_offsets()?;
        assert_eq!(&csr.as_bytes()[start..end], SIGNDATA);
        Ok(())
    }

    #[test]
    fn get_signdata_offsets_bad() {
        let mut csr = [0u8; 10];
        let csr = Csr::from_slice(&mut csr);
        assert!(csr.get_signdata_offsets().is_err());
    }
}
