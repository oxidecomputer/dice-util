// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    MissingFieldError, FWID_LEN, ISSUER_CN_LEN, ISSUER_SN_LEN, NOTBEFORE_LEN,
    PUBLIC_KEY_LEN, SERIAL_NUMBER_LEN, SIGNATURE_LEN, SUBJECT_CN_LEN,
    SUBJECT_SN_LEN,
};
use anyhow::{anyhow, Context, Result};
use std::{fmt, ops::Range};
use x509_cert::der::{Decode, Header, Reader, SliceReader, Tag};

pub struct Cert<'a>(pub &'a mut [u8]);

impl fmt::Display for Cert<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::arrayfmt(self.as_bytes(), f)
    }
}

impl<'a> Cert<'a> {
    pub fn from_slice(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn clear_range(&mut self, start: usize, end: usize) {
        self.0[start..end].fill(0)
    }

    pub fn set_range(&mut self, start: usize, data: &[u8]) {
        let end = start + data.len();
        self.0[start..end].copy_from_slice(data)
    }

    const SERIAL_NUMBER_PATTERN: [u8; 7] =
        [0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01];
    // the SN can be up to 20 bytes (per rfd5280), but we only mint a few certs
    // so a single byte is plenty
    pub fn get_serial_number_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(
            self.0,
            &Self::SERIAL_NUMBER_PATTERN,
            SERIAL_NUMBER_LEN,
        )
        .ok_or(MissingFieldError::SerialNumber.into())
    }

    pub fn get_serial_number(&self) -> Result<u8> {
        let sn = self.get_bytes(self.get_serial_number_offsets()?);
        Ok(sn[0])
    }

    // SET, SEQUENCE, OID (2.5.4.3 / commonName)
    const ISSUER_CN_PATTERN: [u8; 11] = [
        0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20,
    ];
    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_issuer_cn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::ISSUER_CN_PATTERN, ISSUER_CN_LEN)
            .ok_or(MissingFieldError::IssuerCn.into())
    }

    pub fn get_issuer_cn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_issuer_cn_offsets()?))
    }

    // ANS.1 TLVs & OID for serialNumber (x.520 DN component)
    const ISSUER_SN_PATTERN: [u8; 11] = [
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0B,
    ];

    pub fn get_issuer_sn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::ISSUER_SN_PATTERN, ISSUER_SN_LEN)
            .ok_or(MissingFieldError::IssuerSn.into())
    }

    pub fn get_issuer_sn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_issuer_sn_offsets()?))
    }

    // ASN.1 TLVs & for Sequence & UTCTime
    const NOTBEFORE_PATTERN: [u8; 4] = [0x30, 0x20, 0x17, 0x0D];

    pub fn get_notbefore_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::NOTBEFORE_PATTERN, NOTBEFORE_LEN)
            .ok_or(MissingFieldError::NotBefore.into())
    }

    pub fn get_notbefore(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_notbefore_offsets()?))
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

    pub fn get_subject_cn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_subject_cn_offsets()?))
    }

    // ASN.1 TLVs & OID for serialNumber (x.520 DN component)
    const SUBJECT_SN_PATTERN: [u8; 11] = [
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0B,
    ];

    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_sn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SUBJECT_SN_PATTERN, SUBJECT_SN_LEN)
            .ok_or(MissingFieldError::SubjectSn.into())
    }

    pub fn get_subject_sn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_subject_sn_offsets()?))
    }

    const PUBLIC_KEY_PATTERN: [u8; 12] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    pub fn get_pub_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::PUBLIC_KEY_PATTERN, PUBLIC_KEY_LEN)
            .ok_or(MissingFieldError::PublicKey.into())
    }

    pub fn get_pub(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_pub_offsets()?))
    }

    const SIGNDATA_PATTERN: [u8; 10] =
        [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00];
    pub fn get_signdata_offsets(&self) -> Result<Range<usize>> {
        let mut reader = SliceReader::new(self.0)?;

        // advance the reader past the outer Certificate / `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // tbsCertificate is a `SEQUENCE`
        // the full DER encoding of tbsCertificate is signed so we get the
        // starting offset before reading the header
        let start = u32::from(reader.offset());
        let header = Header::decode(&mut reader)?;

        let end = start
            + u32::from(header.length)
            + (u32::from(reader.offset()) - start);

        Ok(Range {
            start: start.try_into()?,
            end: end.try_into()?,
        })
    }

    pub fn get_signdata(&self) -> Result<&[u8]> {
        Ok(&self.as_bytes()[self.get_signdata_offsets()?])
    }

    pub fn get_sig_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SIGNDATA_PATTERN, SIGNATURE_LEN)
            .ok_or(MissingFieldError::Signature.into())
    }

    pub fn get_sig(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_sig_offsets()?))
    }

    pub fn get_bytes(&self, (start, end): (usize, usize)) -> &[u8] {
        &self.as_bytes()[start..end]
    }

    //06 06 67 81 05 05 04 01 01 01 FF 04 33 30 31
    //A6 2F 30 2D 06 09 60 86 48 01 65 03 04 02 08
    //04 20
    // SHA3_256 length
    const FWID_PATTERN: [u8; 32] = [
        0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x01, 0x01, 0xFF, 0x04,
        0x33, 0x30, 0x31, 0xA6, 0x2F, 0x30, 0x2D, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x04, 0x20,
    ];
    pub fn get_fwid_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::FWID_PATTERN, FWID_LEN)
            .ok_or(MissingFieldError::Fwid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Changes to the file included for each test will break these tests
    // because expected results are hard coded here.
    const TEST_DER: &[u8] = include_bytes!("../test/ca.cert.der");
    fn init() -> [u8; TEST_DER.len()] {
        let mut buf = [0u8; TEST_DER.len()];
        buf.copy_from_slice(TEST_DER);

        buf
    }

    const SERIAL_NUMBER_EXPECTED: u8 = 0x10;
    #[test]
    fn cert_get_serial_number_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_serial_number_offsets()?;
        assert_eq!(
            &cert.as_bytes()[start..end],
            // SN appears to be big endian?
            SERIAL_NUMBER_EXPECTED.to_be_bytes()
        );
        Ok(())
    }

    const SN_EXPECTED: &str = "00000000000";
    #[test]
    fn cert_get_issuer_sn_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_issuer_sn_offsets()?;
        assert_eq!(&cert.as_bytes()[start..end], SN_EXPECTED.as_bytes());
        Ok(())
    }

    const NOTBEFORE_EXPECTED: [u8; 13] = [
        0x32, 0x33, 0x30, 0x31, 0x30, 0x34, 0x32, 0x33, 0x34, 0x38, 0x34, 0x36,
        0x5a,
    ];
    #[test]
    fn cert_get_notbefore_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_notbefore_offsets()?;
        assert_eq!(&cert.as_bytes()[start..end], NOTBEFORE_EXPECTED);
        Ok(())
    }

    #[test]
    fn cert_get_subject_sn_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_subject_sn_offsets()?;
        assert_eq!(&cert.as_bytes()[start..end], SN_EXPECTED.as_bytes());
        Ok(())
    }

    // sed -E "s/(\S)(\s|$)/\1,  /g;s/(\s|^)(\S)/0x\2/g"
    const PUB_EXPECTED: [u8; 32] = [
        0x0b, 0x83, 0x26, 0x6b, 0xa0, 0x96, 0x6d, 0x30, 0x2d, 0x96, 0x6b, 0x2f,
        0xf6, 0x1b, 0xb9, 0xf8, 0xfc, 0x16, 0xcd, 0xde, 0xe2, 0x35, 0xb3, 0x79,
        0x68, 0xfc, 0xd8, 0xe6, 0x34, 0x98, 0xdc, 0xee,
    ];

    #[test]
    fn cert_get_pub_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_pub_offsets()?;
        assert_eq!(&cert.as_bytes()[start..end], &PUB_EXPECTED);
        Ok(())
    }

    const SIGNDATA_EXPECTED: [u8; 398] = [
        0x30, 0x82, 0x01, 0x8a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x10,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x81, 0x81, 0x31, 0x0b,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61,
        0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0a, 0x45, 0x6d, 0x65, 0x72, 0x79,
        0x76, 0x69, 0x6c, 0x6c, 0x65, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x16, 0x4f, 0x78, 0x69, 0x64, 0x65, 0x20, 0x43, 0x6f,
        0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61,
        0x6e, 0x79, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x08, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x31, 0x14, 0x30,
        0x12, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0b, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x17, 0x0d, 0x32,
        0x33, 0x30, 0x31, 0x30, 0x34, 0x32, 0x33, 0x34, 0x38, 0x34, 0x36, 0x5a,
        0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
        0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x81, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69,
        0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x07, 0x0c, 0x0a, 0x45, 0x6d, 0x65, 0x72, 0x79, 0x76, 0x69,
        0x6c, 0x6c, 0x65, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x16, 0x4f, 0x78, 0x69, 0x64, 0x65, 0x20, 0x43, 0x6f, 0x6d, 0x70,
        0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79,
        0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x69,
        0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x31, 0x14, 0x30, 0x12, 0x06,
        0x03, 0x55, 0x04, 0x05, 0x13, 0x0b, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b,
        0x65, 0x70, 0x03, 0x21, 0x00, 0x0b, 0x83, 0x26, 0x6b, 0xa0, 0x96, 0x6d,
        0x30, 0x2d, 0x96, 0x6b, 0x2f, 0xf6, 0x1b, 0xb9, 0xf8, 0xfc, 0x16, 0xcd,
        0xde, 0xe2, 0x35, 0xb3, 0x79, 0x68, 0xfc, 0xd8, 0xe6, 0x34, 0x98, 0xdc,
        0xee, 0xa3, 0x23, 0x30, 0x21, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
        0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e,
        0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
        0x02, 0x04,
    ];

    #[test]
    fn cert_get_signdata_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let range = cert.get_signdata_offsets()?;
        assert_eq!(&cert.as_bytes()[range], &SIGNDATA_EXPECTED);
        Ok(())
    }
    const SIG_EXPECTED: [u8; 64] = [
        0xcc, 0x1b, 0x10, 0x1f, 0x4f, 0x67, 0x67, 0x87, 0xf1, 0xd0, 0x69, 0x74,
        0xbc, 0xdc, 0x1a, 0x1e, 0x32, 0x72, 0x9f, 0x08, 0x1e, 0x81, 0xeb, 0x8f,
        0xf7, 0xeb, 0x80, 0x2f, 0x2a, 0x90, 0x8e, 0xb3, 0x0e, 0x29, 0x4c, 0x18,
        0x99, 0xe1, 0x13, 0x0b, 0x3f, 0xaa, 0x43, 0xa5, 0x0a, 0x3e, 0x12, 0x34,
        0x10, 0x04, 0xa2, 0x7e, 0xfa, 0x1f, 0xfb, 0x01, 0xff, 0xf1, 0x2b, 0x36,
        0xa3, 0xe2, 0x08, 0x0f,
    ];

    #[test]
    fn cert_get_sig_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        // I'm not convinced this is better than just an 'unwrap()'
        // All it gets us is the error string instead of the enum variant
        let (start, end) =
            cert.get_sig_offsets().map_err(|e| panic!("{}", e)).unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &SIG_EXPECTED);
        Ok(())
    }

    const FWID_EXPECTED: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // this test is specific to the alias / leaf cert
    #[test]
    fn cert_get_fwid_offsets() -> Result<()> {
        const TEST_DER: &[u8] = include_bytes!("../test/alias.cert.der");
        let mut der = [0u8; TEST_DER.len()];
        der.copy_from_slice(TEST_DER);

        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_fwid_offsets().unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &FWID_EXPECTED);
        Ok(())
    }

    use salty::signature::{PublicKey, Signature};
    #[test]
    fn cert_sig_check() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let msg_range = cert.get_signdata_offsets()?;
        let (start_sig, end_sig) = cert.get_sig_offsets()?;
        let (start_pub, end_pub) = cert.get_pub_offsets()?;
        let pubkey: &[u8; PUBLIC_KEY_LEN] =
            &cert.as_bytes()[start_pub..end_pub].try_into()?;

        // none of the salty error simplement Error trait
        let pubkey = PublicKey::try_from(pubkey).expect("pubkey");

        // massage bytes from Cert slice representation of sig into sized array
        let sig: &[u8; SIGNATURE_LEN] =
            cert.as_bytes()[start_sig..end_sig].try_into()?;

        let sig = Signature::from(sig);
        let res = pubkey.verify(&cert.as_bytes()[msg_range], &sig);
        assert!(res.is_ok());
        Ok(())
    }
}
