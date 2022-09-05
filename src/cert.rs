// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{ED25519_PUB_LEN, ED25519_SIG_LEN, SN_LEN};
use std::{error, fmt, result};

// Clippy hates this type name. But renaming it to CertMissingFieldError like
// we did in the Csr module causes the compiler to panic.
#[derive(Debug, PartialEq)]
pub enum CertError {
    NoAuthorityKeyId,
    NoFwid,
    NoIssuerSn,
    NoNotBefore,
    NoPub,
    NoSerialNumber,
    NoSig,
    NoSignData,
    NoSubjectSn,
    NoSubjectKeyId,
}

impl error::Error for CertError {}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertError::NoAuthorityKeyId => {
                write!(f, "authorityKeyId not found")
            }
            CertError::NoIssuerSn => write!(f, "No issuer SN found."),
            CertError::NoFwid => write!(f, "No FWID found."),
            CertError::NoNotBefore => write!(f, "No not before found."),
            CertError::NoPub => write!(f, "No public key found."),
            CertError::NoSerialNumber => write!(f, "No serial number found."),
            CertError::NoSig => write!(f, "No signature found."),
            CertError::NoSignData => write!(f, "No signdata found."),
            CertError::NoSubjectKeyId => write!(f, "No subject key ID found."),
            CertError::NoSubjectSn => write!(f, "No subject SN found."),
        }
    }
}

type Result<T> = result::Result<T, CertError>;

pub struct Cert<'a>(pub &'a mut [u8]);

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

    const SERIAL_NUMBER_PATTERN: [u8; 7] = [0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01];
    // the SN can be up to 20 bytes (per rfd5280), but we only mint a few certs
    // so a single byte is plenty
    const SERIAL_NUMBER_LEN: usize = 1;
    pub fn get_serial_number_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(
            self.0,
            &Self::SERIAL_NUMBER_PATTERN,
            Self::SERIAL_NUMBER_LEN,
        )
        .ok_or(CertError::NoSerialNumber)
    }

    pub fn get_serial_number(&self) -> Result<u8> {
        let sn = self.get_bytes(self.get_serial_number_offsets()?);
        Ok(sn[0])
    }

    // ANS.1 TLVs & OID for commonName (x.520 DN component)
    const SELFCERT_ISSUER_SN_PATTERN: [u8; 11] = [
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0C,
    ];
    const SELFCERT_ISSUER_SN_LEN: usize = SN_LEN;

    pub fn get_issuer_sn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(
            self.0,
            &Self::SELFCERT_ISSUER_SN_PATTERN,
            Self::SELFCERT_ISSUER_SN_LEN,
        )
        .ok_or(CertError::NoIssuerSn)
    }

    pub fn get_issuer_sn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_issuer_sn_offsets()?))
    }

    // ASN.1 TLVs & for Sequence & UTCTime
    const NOTBEFORE_PATTERN: [u8; 4] = [0x30, 0x20, 0x17, 0x0D];
    const NOTBEFORE_LEN: usize = 13;

    pub fn get_notbefore_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::NOTBEFORE_PATTERN, Self::NOTBEFORE_LEN)
            .ok_or(CertError::NoNotBefore)
    }

    pub fn get_notbefore(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_issuer_sn_offsets()?))
    }

    // ASN.1 TLVs & OID for commonName (x.520 DN component)
    const SELFCERT_SUBJECT_SN_PATTERN: [u8; 11] = [
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0C,
    ];
    const SELFCERT_SUBJECT_SN_LEN: usize = SN_LEN;

    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_sn_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(
            self.0,
            &Self::SELFCERT_SUBJECT_SN_PATTERN,
            Self::SELFCERT_SUBJECT_SN_LEN,
        )
        .ok_or(CertError::NoSubjectSn)
    }

    pub fn get_subject_sn(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_subject_sn_offsets()?))
    }

    const SELFCERT_PUB_PATTERN: [u8; 12] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    const SELFCERT_PUB_LEN: usize = ED25519_PUB_LEN;
    pub fn get_pub_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::SELFCERT_PUB_PATTERN, Self::SELFCERT_PUB_LEN)
            .ok_or(CertError::NoPub)
    }

    pub fn get_pub(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_pub_offsets()?))
    }

    const SIGN_BEGIN: usize = 0x4;
    const SIGNDATA_PATTERN: [u8; 10] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00];

    pub fn get_signdata_offsets(&self) -> Result<(usize, usize)> {
        // Data to sign is between offset SIGN_BEGIN & beginning of this
        // pattern. This is the end of the certificationRequestInfo field.
        let offset = crate::get_pattern_roffset(self.0, &Self::SIGNDATA_PATTERN)
            .ok_or(CertError::NoSignData)?;

        Ok((Self::SIGN_BEGIN, offset))
    }

    pub fn get_signdata(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_signdata_offsets()?))
    }

    pub fn get_sig_offsets(&self) -> Result<(usize, usize)> {
        crate::get_roffsets(self.0, &Self::SIGNDATA_PATTERN, ED25519_SIG_LEN)
            .ok_or(CertError::NoSig)
    }

    pub fn get_sig(&self) -> Result<&[u8]> {
        Ok(self.get_bytes(self.get_sig_offsets()?))
    }

    pub fn get_bytes(&self, (start, end): (usize, usize)) -> &[u8] {
        &self.as_bytes()[start..end]
    }

    const FWID_BEGIN: [u8; 31] = [
        0x06, 0x05, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x01, 0xFF, 0x04, 0x33, 0x30, 0x31, 0xA6,
        0x2F, 0x30, 0x2D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x04,
        0x20,
    ];
    // SHA3_256 length
    const FWID_LEN: usize = 32;
    pub fn get_fwid_offsets(&self) -> Result<(usize, usize)> {
        crate::get_offsets(self.0, &Self::FWID_BEGIN, Self::FWID_LEN).ok_or(CertError::NoFwid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Changes to the file included for each test will break these tests
    // because expected results are harded coded here.
    const TEST_DER: &[u8] = include_bytes!("../data/deviceid-selfcert-tmpl.der");
    fn init() -> [u8; TEST_DER.len()] {
        let mut buf = [0u8; TEST_DER.len()];
        buf.copy_from_slice(TEST_DER);

        buf
    }

    const SERIAL_NUMBER_EXPECTED: u8 = 0x10;
    #[test]
    fn cert_get_serial_number_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert
            .get_serial_number_offsets()
            .map_err(|e| panic!("{}", e))
            .unwrap();
        assert_eq!(
            &cert.as_bytes()[start..end],
            // SN appears to be big endian?
            SERIAL_NUMBER_EXPECTED.to_be_bytes()
        );
    }

    const SN_EXPECTED: &str = "000000000000";
    #[test]
    fn cert_get_issuer_sn_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert
            .get_issuer_sn_offsets()
            .map_err(|e| panic!("{}", e))
            .unwrap();
        assert_eq!(&cert.as_bytes()[start..end], SN_EXPECTED.as_bytes());
    }

    const NOTBEFORE_EXPECTED: [u8; 13] = [
        0x32, 0x32, 0x30, 0x37, 0x31, 0x32, 0x32, 0x33, 0x32, 0x37, 0x31, 0x39, 0x5A,
    ];
    #[test]
    fn cert_get_notbefore_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert
            .get_notbefore_offsets()
            .map_err(|e| panic!("{}", e))
            .unwrap();
        assert_eq!(&cert.as_bytes()[start..end], NOTBEFORE_EXPECTED);
    }

    #[test]
    fn cert_get_subject_sn_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert
            .get_subject_sn_offsets()
            .map_err(|e| panic!("{}", e))
            .unwrap();
        assert_eq!(&cert.as_bytes()[start..end], SN_EXPECTED.as_bytes());
    }

    // sed -E "s/(\S)(\s|$)/\1,  /g;s/(\s|^)(\S)/0x\2/g"
    const PUB_EXPECTED: [u8; 32] = [
        0x73, 0x8D, 0x79, 0x75, 0x3B, 0x14, 0x57, 0xC4, 0xA2, 0x74, 0xA7, 0xFF, 0x9D, 0x66, 0xFB,
        0xED, 0xBF, 0x7A, 0x0F, 0xC1, 0xA8, 0xAF, 0x4B, 0x58, 0xB6, 0x45, 0x04, 0xD8, 0xB2, 0x2C,
        0x2C, 0x03,
    ];

    #[test]
    fn cert_get_pub_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_pub_offsets().map_err(|e| panic!("{}", e)).unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &PUB_EXPECTED);
    }

    const SIGNDATA_EXPECTED: [u8; 453] = [
        0x30, 0x82, 0x01, 0xC1, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x10, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x70, 0x30, 0x81, 0x9B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
        0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0A, 0x45, 0x6D, 0x65, 0x72, 0x79, 0x76, 0x69, 0x6C,
        0x6C, 0x65, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x16, 0x4F, 0x78,
        0x69, 0x64, 0x65, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x6F,
        0x6D, 0x70, 0x61, 0x6E, 0x79, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C,
        0x0D, 0x4D, 0x61, 0x6E, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x69, 0x6E, 0x67, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x09, 0x64, 0x65, 0x76, 0x69, 0x63,
        0x65, 0x2D, 0x69, 0x64, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0C,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x20, 0x17,
        0x0D, 0x32, 0x32, 0x30, 0x37, 0x31, 0x32, 0x32, 0x33, 0x32, 0x37, 0x31, 0x39, 0x5A, 0x18,
        0x0F, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
        0x5A, 0x30, 0x81, 0x9B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61,
        0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x07, 0x0C, 0x0A, 0x45, 0x6D, 0x65, 0x72, 0x79, 0x76, 0x69, 0x6C, 0x6C, 0x65, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x16, 0x4F, 0x78, 0x69, 0x64, 0x65,
        0x20, 0x43, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x6F, 0x6D, 0x70, 0x61,
        0x6E, 0x79, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0D, 0x4D, 0x61,
        0x6E, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x69, 0x6E, 0x67, 0x31, 0x12, 0x30, 0x10,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x09, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2D, 0x69,
        0x64, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0C, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03,
        0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x73, 0x8D, 0x79, 0x75, 0x3B, 0x14, 0x57, 0xC4, 0xA2,
        0x74, 0xA7, 0xFF, 0x9D, 0x66, 0xFB, 0xED, 0xBF, 0x7A, 0x0F, 0xC1, 0xA8, 0xAF, 0x4B, 0x58,
        0xB6, 0x45, 0x04, 0xD8, 0xB2, 0x2C, 0x2C, 0x03, 0xA3, 0x26, 0x30, 0x24, 0x30, 0x12, 0x06,
        0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02,
        0x01, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03,
        0x02, 0x01, 0x86,
    ];

    #[test]
    fn cert_get_signdata_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert
            .get_signdata_offsets()
            .map_err(|e| panic!("{}", e))
            .unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &SIGNDATA_EXPECTED);
    }
    const SIG_EXPECTED: [u8; 64] = [
        0x0A, 0x71, 0xA8, 0xF6, 0x02, 0xEB, 0xDC, 0xC3, 0x5F, 0xC5, 0xF1, 0xE0, 0x75, 0x4A, 0xDC,
        0xFC, 0x45, 0x94, 0x37, 0x0E, 0x85, 0x8E, 0xCB, 0xFC, 0x50, 0x45, 0x21, 0xCC, 0xF6, 0x6A,
        0x7C, 0x08, 0xB7, 0x31, 0xB1, 0x4D, 0xA6, 0x48, 0xCE, 0xE6, 0x17, 0x02, 0x1E, 0x05, 0x12,
        0x40, 0x49, 0x8D, 0x4B, 0xB2, 0x22, 0xE3, 0x3E, 0x39, 0x98, 0x1D, 0xE9, 0xF5, 0x36, 0xCC,
        0xC5, 0x5D, 0x44, 0x0C,
    ];

    #[test]
    fn cert_get_sig_offsets() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        // I'm not convinced this is better than just an 'unwrap()'
        // All it gets us is the error string instead of the enum variant
        let (start, end) = cert.get_sig_offsets().map_err(|e| panic!("{}", e)).unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &SIG_EXPECTED);
    }

    const FWID_EXPECTED: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    // this test is specific to the alias / leaf cert
    #[test]
    fn cert_get_fwid_offsets() {
        const TEST_DER: &[u8] = include_bytes!("../data/alias-cert-tmpl.der");
        let mut der = [0u8; TEST_DER.len()];
        der.copy_from_slice(TEST_DER);

        let cert = Cert::from_slice(&mut der);
        let (start, end) = cert.get_fwid_offsets().unwrap();
        assert_eq!(&cert.as_bytes()[start..end], &FWID_EXPECTED);
    }

    use salty::signature::{PublicKey, Signature};
    #[test]
    fn cert_sig_check() {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let (start_msg, end_msg) = cert.get_signdata_offsets().expect("signdata");
        let (start_sig, end_sig) = cert.get_sig_offsets().map_err(|e| panic!("{}", e)).unwrap();
        let (start_pub, end_pub) = cert.get_pub_offsets().map_err(|e| panic!("{}", e)).unwrap();
        let pubkey: &[u8; ED25519_PUB_LEN] = &cert.as_bytes()[start_pub..end_pub]
            .try_into()
            .expect("pubkey try_into");
        let pubkey = PublicKey::try_from(pubkey).expect("pubkey");

        // massage bytes from Cert slice representation of sig into sized array
        let sig: &[u8; ED25519_SIG_LEN] = cert.as_bytes()[start_sig..end_sig]
            .try_into()
            .expect("bad sig size");

        let sig = Signature::from(sig);
        let res = pubkey.verify(&cert.as_bytes()[start_msg..end_msg], &sig);
        assert!(res.is_ok());
    }
}
