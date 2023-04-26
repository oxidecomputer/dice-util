// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    MissingFieldError, PUBLIC_KEY_LEN, SIGNATURE_LEN, SIGNDATA_BEGIN,
    SUBJECT_CN_LEN, SUBJECT_SN_LEN,
};
use std::{fmt, result};

type Result<T> = result::Result<T, MissingFieldError>;

// Type to expose parsing operations on CSR in underlying slice
pub struct Csr<'a>(&'a mut [u8]);

impl<'a> fmt::Display for Csr<'a> {
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

    #[rustfmt::skip]
    const PUB_PATTERN: [u8; 12] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
        0x70, 0x03, 0x21, 0x00,
    ];
    pub fn get_pub_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::PUB_PATTERN, PUBLIC_KEY_LEN)
            .ok_or(MissingFieldError::PublicKey)
    }

    pub fn get_pub(&self) -> Result<&[u8]> {
        let (start, end) = self.get_pub_offsets()?;
        Ok(&self.0[start..end])
    }

    // SET, SEQUENCE, OID (2.5.4.3 / commonName)
    const SUBJECT_CN_PATTERN: [u8; 11] = [
        0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F,
    ];
    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_cn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SUBJECT_CN_PATTERN, SUBJECT_CN_LEN)
            .ok_or(MissingFieldError::SubjectCn)
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
            .ok_or(MissingFieldError::SubjectSn)
    }

    #[rustfmt::skip]
    const SIG_PATTERN: [u8; 10] = [
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03,
        0x41, 0x00,
    ];
    pub fn get_sig_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SIG_PATTERN, SIGNATURE_LEN)
            .ok_or(MissingFieldError::Signature)
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
        // CSR data to sign is between offset SIGNDATA_BEGIN & beginning of this
        // pattern in the CSR. This is the end of the certificationRequestInfo
        // field in the CSR.
        let pattern_offset =
            crate::get_pattern_roffset(self.0, &Self::SIGNDATA_PATTERN)
                .ok_or(MissingFieldError::SignData)?;

        Ok((SIGNDATA_BEGIN, pattern_offset))
    }

    pub fn get_signdata(&self) -> Result<&[u8]> {
        let (start, end) = self.get_signdata_offsets()?;

        Ok(&self.0[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error, result};

    type Result = result::Result<(), Box<dyn error::Error>>;

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
    const PUB: &'static [u8] = &[
        0x27, 0xfb, 0x87, 0x77, 0x77, 0x36, 0x54, 0xfb,
        0x78, 0xb3, 0x46, 0x6b, 0x95, 0x0e, 0x15, 0x2b,
        0x8b, 0xcd, 0x0c, 0x9b, 0x8a, 0x08, 0xfc, 0x7a,
        0xef, 0x68, 0x97, 0x1e, 0xab, 0xa0, 0x87, 0x70,
    ];

    #[rustfmt::skip]
    const SIG: &'static [u8] = &[
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
    const SIGNDATA: &'static [u8] = &[
        0x81, 0x90, 0x02, 0x01, 0x00, 0x30, 0x5d, 0x31,
        0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
        0x13, 0x02, 0x47, 0x42, 0x31, 0x10, 0x30, 0x0e,
        0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x45,
        0x6e, 0x67, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x12,
        0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x09, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x20, 0x4c,
        0x74, 0x64, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
        0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x41, 0x6c, 0x69,
        0x63, 0x65, 0x20, 0x4c, 0x74, 0x64, 0x20, 0x61,
        0x6c, 0x69, 0x61, 0x73, 0x31, 0x0e, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05, 0x61,
        0x6c, 0x69, 0x61, 0x73, 0x30, 0x2a, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        0x27, 0xfb, 0x87, 0x77, 0x77, 0x36, 0x54, 0xfb,
        0x78, 0xb3, 0x46, 0x6b, 0x95, 0x0e, 0x15, 0x2b,
        0x8b, 0xcd, 0x0c, 0x9b, 0x8a, 0x08, 0xfc, 0x7a,
        0xef, 0x68, 0x97, 0x1e, 0xab, 0xa0, 0x87, 0x70,
        0xa0, 0x00,
    ];

    #[test]
    fn get_pub_offsets() -> Result {
        let mut csr = CSR.clone();
        let csr = Csr::from_slice(&mut csr);
        let (start, end) = csr.get_pub_offsets()?;
        assert_eq!(&csr.as_bytes()[start..end], PUB);
        Ok(())
    }

    #[test]
    fn get_sig_offsets() -> Result {
        let mut csr = CSR.clone();
        let csr = Csr::from_slice(&mut csr);
        let (start, end) = csr.get_sig_offsets()?;
        assert_eq!(&csr.as_bytes()[start..end], SIG);
        Ok(())
    }

    #[test]
    fn get_signdata_offsets() -> Result {
        let mut csr = CSR.clone();
        let csr = Csr::from_slice(&mut csr);
        let (start, end) = csr.get_signdata_offsets()?;
        assert_eq!(&csr.as_bytes()[start..end], SIGNDATA);
        Ok(())
    }

    #[test]
    fn get_signdata_offsets_bad() {
        let mut csr = [0u8; 10];
        let csr = Csr::from_slice(&mut csr);
        assert_eq!(
            csr.get_signdata_offsets(),
            Err(MissingFieldError::SignData)
        );
    }
}
