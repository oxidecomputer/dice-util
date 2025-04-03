// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    MissingFieldError, ISSUER_SN_LEN, NOTBEFORE_LEN, SERIAL_NUMBER_LEN,
    SIGNATURE_LEN, SUBJECT_SN_LEN,
};
use anyhow::{anyhow, Context, Result};
use const_oid::db::rfc4519::COMMON_NAME;
use std::{fmt, ops::Range};
use x509_cert::der::{
    asn1::ObjectIdentifier, Decode, Header, Reader, SliceReader, Tag, TagNumber,
};

pub const DICE_TCB_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

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

    // Parse the cert & find the start and end offsets of the Issuer
    // commonName. If the Issuer SEQUENCE doesn't contain a
    // RelativeDistinguishedName with the commonName AttributeType (2.5.4.3)
    // it will return None.
    pub fn get_issuer_cn_offsets(&self) -> Result<Option<Range<usize>>> {
        let mut reader =
            SliceReader::new(self.0).context("SliceReader from cert DER")?;

        // RFC 5280 Certificate is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode Certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // tbsCertificate is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode tbsCertificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `version` is a constructed, context specific type numbered 0
        let header =
            Header::decode(&mut reader).context("decode version header")?;
        if header.tag
            != (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            })
        {
            return Err(anyhow!(
                "Expected constructed, context specific tag [0], got {:?}",
                header.tag
            ));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past version")?;

        // `serialNumber` is an `INTEGER`
        let header = Header::decode(&mut reader)
            .context("decode serialNumber header")?;
        if header.tag != Tag::Integer {
            return Err(anyhow!("Expected INTEGER, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past serialNumber")?;

        // `signature` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode signature header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past signature")?;

        // `issuer` is a `SEQUENCE`
        // that we will iterate over
        let header =
            Header::decode(&mut reader).context("decode issuer header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        // iterating over the issuer `SEQUENCE` ends when the reader has advanced
        // header.length bytes from the current position
        let end = (reader.offset() + header.length)
            .context("calculate end of issuer SEQUENCE")?;

        loop {
            if end == reader.offset() {
                break;
            }
            if end < reader.offset() {
                return Err(anyhow!("read past end of issuer SEQUENCE"));
            }

            // the outer RelativeDistinguishedName `SET`
            let header = Header::decode(&mut reader)
                .context("decode RelativeDistinguishedName header")?;
            if header.tag != Tag::Set {
                return Err(anyhow!("Expected SET, got {:?}", header.tag));
            }

            // the outer AttributeTypeAndValue `SEQUENCE`
            let header = Header::decode(&mut reader)
                .context("decode AttributeTypeAndValue header")?;
            if header.tag != Tag::Sequence {
                return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
            }

            // get the `AttributeType` oid
            let oid = ObjectIdentifier::decode(&mut reader)
                .context("decode AttributeType OID")?;

            let header = Header::decode(&mut reader)
                .context("decode AttributeValue header")?;
            if oid != COMMON_NAME {
                // if the AttributeType isn't `COMMON_NAME` advance the reader
                // to the end of the value & iterate again
                let _ = reader
                    .read_slice(header.length)
                    .context("read past AttributeValue")?;
            } else {
                let start = u32::from(reader.offset());
                let end = start + u32::from(header.length);

                return Ok(Some(Range {
                    start: start.try_into().context("start offset to usize")?,
                    end: end.try_into().context("end offset to usize")?,
                }));
            }
        }

        Ok(None)
    }

    pub fn get_issuer_cn(&self) -> Result<Option<&[u8]>> {
        match self.get_issuer_cn_offsets()? {
            Some(range) => Ok(Some(&self.as_bytes()[range])),
            None => Ok(None),
        }
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

    // when issuer and subject SN are the same length their identifying
    // patterns are the same. This function searches backward for the pattern
    // since issuer comes before subject in the structure
    pub fn get_subject_cn_offsets(&self) -> Result<Option<Range<usize>>> {
        let mut reader =
            SliceReader::new(self.0).context("SliceReader from cert DER")?;

        // RFC 5280 Certificate is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode Certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // tbsCertificate is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode tbsCertificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `version` is a constructed, context specific type numbered 0
        let header =
            Header::decode(&mut reader).context("decode version header")?;
        if header.tag
            != (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            })
        {
            return Err(anyhow!(
                "Expected constructed, context specific tag [0], got {:?}",
                header.tag
            ));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past version")?;

        // `serialNumber` is an `INTEGER`
        let header = Header::decode(&mut reader)
            .context("decode serialNumber header")?;
        if header.tag != Tag::Integer {
            return Err(anyhow!("Expected INTEGER, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past serialNumber")?;

        // `signature` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode signature header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past signature")?;

        // `issuer` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode issuer header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past issuer")?;

        // `validity` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode validity header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past validity")?;

        // `subject` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode issuer header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // iterating over the subject `SEQUENCE` ends when the reader has advanced
        // header.length bytes from the current position
        let end = (reader.offset() + header.length)
            .context("calculate end of issuer SEQUENCE")?;

        loop {
            if end == reader.offset() {
                break;
            }
            if end < reader.offset() {
                return Err(anyhow!("read past end of issuer SEQUENCE"));
            }

            // the outer RelativeDistinguishedName `SET`
            let header = Header::decode(&mut reader)
                .context("decode RelativeDistinguishedName header")?;
            if header.tag != Tag::Set {
                return Err(anyhow!("Expected SET, got {:?}", header.tag));
            }

            // the outer AttributeTypeAndValue `SEQUENCE`
            let header = Header::decode(&mut reader)
                .context("decode AttributeTypeAndValue header")?;
            if header.tag != Tag::Sequence {
                return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
            }

            // get the `AttributeType` oid
            let oid = ObjectIdentifier::decode(&mut reader)
                .context("decode AttributeType OID")?;

            let header = Header::decode(&mut reader)
                .context("decode AttributeValue header")?;
            if oid != COMMON_NAME {
                // if the AttributeType isn't `COMMON_NAME` advance the reader
                // to the end of the value & iterate again
                let _ = reader
                    .read_slice(header.length)
                    .context("read past AttributeValue")?;
            } else {
                let start = u32::from(reader.offset());
                let end = start + u32::from(header.length);

                return Ok(Some(Range {
                    start: start.try_into().context("start offset to usize")?,
                    end: end.try_into().context("end offset to usize")?,
                }));
            }
        }

        Ok(None)
    }

    pub fn get_subject_cn(&self) -> Result<Option<&[u8]>> {
        match self.get_subject_cn_offsets()? {
            Some(range) => Ok(Some(&self.as_bytes()[range])),
            None => Ok(None),
        }
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

    pub fn get_pub_offsets(&self) -> Result<Range<usize>> {
        let mut reader = SliceReader::new(self.0)?;

        // RFC 5280 Certificate is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode Certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // tbsCertificate is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode tbsCertificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `version` is a constructed, context specific type numbered 0
        let header =
            Header::decode(&mut reader).context("decode version header")?;
        if header.tag
            != (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            })
        {
            return Err(anyhow!(
                "Expected constructed, context specific tag [0], got {:?}",
                header.tag
            ));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past version")?;

        // `serialNumber` is an `INTEGER`
        let header = Header::decode(&mut reader)
            .context("decode serialNumber header")?;
        if header.tag != Tag::Integer {
            return Err(anyhow!("Expected INTEGER, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past serialNumber")?;

        // `signature` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode signature header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past signature")?;

        // `issuer` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode issuer header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past issuer")?;

        // `validity` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode validity header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past validity")?;

        // `subject` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode subject header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past subject")?;

        // `subjectPublicKeyInfo` is a `SEQUENCE`
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
        Ok(&self.as_bytes()[self.get_pub_offsets()?])
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

    pub fn get_fwids_offsets(&self) -> Result<Vec<Range<usize>>> {
        let mut reader =
            SliceReader::new(self.0).context("SliceReader from cert DER")?;

        // RFC 5280 Certificate is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode Certificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // tbsCertificate is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode tbsCertificate header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `version` is a constructed, context specific type numbered 0
        let header =
            Header::decode(&mut reader).context("decode version header")?;
        if header.tag
            != (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            })
        {
            return Err(anyhow!(
                "Expected constructed, context specific tag [0], got {:?}",
                header.tag
            ));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past version")?;

        // `serialNumber` is an `INTEGER`
        let header = Header::decode(&mut reader)
            .context("decode serialNumber header")?;
        if header.tag != Tag::Integer {
            return Err(anyhow!("Expected INTEGER, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past serialNumber")?;

        // `signature` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode signature header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past signature")?;

        // `issuer` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode issuer header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past issuer")?;

        // `validity` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode validity header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past validity")?;

        // `subject` is a `SEQUENCE`
        let header =
            Header::decode(&mut reader).context("decode subject header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past subject")?;

        // `subjectPublicKeyInfo` is a `SEQUENCE`
        let header = Header::decode(&mut reader)
            .context("decode subjectPublicKeyInfo header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }
        let _ = reader
            .read_slice(header.length)
            .context("read past subjectPublicKeyInfo")?;

        // `extensions` is a constructed, context specific type with tag [3]
        let header =
            Header::decode(&mut reader).context("decode extensions header")?;
        if header.tag
            != (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N3,
            })
        {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        // `extensions.Extensions` is a `SEQUENCE`
        // we've descended into
        let header =
            Header::decode(&mut reader).context("decode Extensions header")?;
        if header.tag != Tag::Sequence {
            return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
        }

        let end = (reader.offset() + header.length)
            .context("Offset + length of Extensions SEQUENCE")?;

        // Now we loop over the extensions till we find the DiceTcbInfoExtension
        let mut fwid_ranges: Vec<Range<usize>> = Vec::new();
        loop {
            if end == reader.offset() {
                break;
            }
            if end < reader.offset() {
                return Err(anyhow!("read past end of Extensions SEQUENCE"));
            }

            // This is the outer sequence for the extension
            let header = Header::decode(&mut reader)
                .context("decode Extension header")?;
            if header.tag != Tag::Sequence {
                return Err(anyhow!("Expected SEQUENCE, got {:?}", header.tag));
            }

            // `extnId` is an `OBJECT IDENTIFIER`
            let oid = ObjectIdentifier::decode(&mut reader)
                .context("Decode ObjectIdentifier")?;

            // skip the rest of the extension
            // skipping critical or extnValue if critical is not present
            let header = Header::decode(&mut reader)
                .context("decode next header, critical or extnValue?")?;
            let _ = reader
                .read_slice(header.length)
                .context("read past Extension critical")?;

            let header = if header.tag == Tag::Boolean {
                // if the critical field is present we have to advance the
                // reader past the associated extnValue
                Header::decode(&mut reader)
                    .context("decode extnValue header")?
            } else {
                header
            };
            if header.tag != Tag::OctetString {
                return Err(anyhow!(
                    "Expected OCTET STRING, got {:?}",
                    header.tag
                ));
            }

            if oid != DICE_TCB_INFO {
                let _ = reader
                    .read_slice(header.length)
                    .context("read past Extension critical")?;
            } else {
                // descend into the FWIDLIST SEQUENCE
                let header = Header::decode(&mut reader)
                    .context("decode Fwids header")?;
                if header.tag != Tag::Sequence {
                    return Err(anyhow!(
                        "Expected SEQUENCE, got {:?}",
                        header.tag
                    ));
                }
                // get end point for our future iteration over the FWIDLIST
                let end = (reader.offset() + header.length)
                    .context("Offset + length of FWIDS SEQUENCE")?;

                let header = Header::decode(&mut reader)
                    .context("decode Fwids TAG[6] header")?;
                if header.tag
                    != (Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber::N6,
                    })
                {
                    return Err(anyhow!(
                        "Expected constructed, context specific tag [6], got {:?}",
                        header.tag
                    ));
                }
                loop {
                    if end == reader.offset() {
                        break;
                    }
                    if end < reader.offset() {
                        return Err(anyhow!("read past end of FWIDs SEQUENCE"));
                    }

                    // descend into the FWID SEQUENCE
                    let header = Header::decode(&mut reader)
                        .context("decode FWID header")?;
                    if header.tag != Tag::Sequence {
                        return Err(anyhow!(
                            "Expected SEQUENCE, got {:?}",
                            header.tag
                        ));
                    }

                    // get the OID for the digest
                    let _ = ObjectIdentifier::decode(&mut reader)
                        .context("Decode ObjectIdentifier")?;

                    // get the header for the OctetString
                    let header = Header::decode(&mut reader)
                        .context("decode FWID header")?;
                    if header.tag != Tag::OctetString {
                        return Err(anyhow!(
                            "Expected SEQUENCE, got {:?}",
                            header.tag
                        ));
                    }

                    let start = u32::from(reader.offset());
                    let end = start + u32::from(header.length);
                    let range = Range {
                        start: start
                            .try_into()
                            .context("fwid start offset to usize")?,
                        end: end
                            .try_into()
                            .context("fwid end offset to usize")?,
                    };
                    fwid_ranges.push(range);

                    // advance the reader past the FWID value
                    let _ = reader
                        .read_slice(header.length)
                        .context("Read FWID value")?;
                }
            }
        }

        Ok(fwid_ranges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

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

    const ISSUER_CN_EXPECTED: &str = "identity";
    #[test]
    fn cert_get_issuer_cn_offsets() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let range = cert
            .get_issuer_cn_offsets()?
            .ok_or(anyhow!("No Issuer commonName in cert"))?;
        assert_eq!(&cert.as_bytes()[range], ISSUER_CN_EXPECTED.as_bytes());
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
        let range = cert.get_pub_offsets()?;
        assert_eq!(&cert.as_bytes()[range], &PUB_EXPECTED);
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
    fn cert_get_fwids_offsets() -> Result<()> {
        const TEST_DER: &[u8] = include_bytes!("../test/alias.cert.der");
        let mut der = [0u8; TEST_DER.len()];
        der.copy_from_slice(TEST_DER);

        let cert = Cert::from_slice(&mut der);
        let offsets = cert.get_fwids_offsets()?;
        assert_eq!(offsets.len(), 1);
        assert_eq!(&cert.as_bytes()[offsets[0].clone()], &FWID_EXPECTED);
        Ok(())
    }

    use salty::{
        constants::PUBLICKEY_SERIALIZED_LENGTH,
        signature::{PublicKey, Signature},
    };
    #[test]
    fn cert_sig_check() -> Result<()> {
        let mut der = init();
        let cert = Cert::from_slice(&mut der);
        let msg_range = cert.get_signdata_offsets()?;
        let (start_sig, end_sig) = cert.get_sig_offsets()?;
        let pub_range = cert.get_pub_offsets()?;
        assert_eq!(pub_range.len(), PUBLICKEY_SERIALIZED_LENGTH);
        let pubkey: [u8; PUBLICKEY_SERIALIZED_LENGTH] =
            cert.as_bytes()[pub_range].try_into()?;

        // none of the salty error simplement Error trait
        let pubkey = PublicKey::try_from(&pubkey).expect("pubkey");

        // massage bytes from Cert slice representation of sig into sized array
        let sig: &[u8; SIGNATURE_LEN] =
            cert.as_bytes()[start_sig..end_sig].try_into()?;

        let sig = Signature::from(sig);
        let res = pubkey.verify(&cert.as_bytes()[msg_range], &sig);
        assert!(res.is_ok());
        Ok(())
    }
}
