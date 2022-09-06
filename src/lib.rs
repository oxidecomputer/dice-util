// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
pub mod cert;
pub mod csr;
pub mod encoding;

pub use crate::cert::{Cert, CertError};
pub use crate::csr::{Csr, MissingFieldError};
pub use crate::encoding::{Encoding, EncodingError};

use salty::constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH};

use std::{error::Error, fmt, io::Write, path::Path, process::Command};

// csr / cert field sizes
// get this from sha3 crate as a const requires const generics
const FWID_LEN: usize = 32;
const ISSUER_SN_LEN: usize = 12;
const NOTBEFORE_LEN: usize = 13;
const PUBLIC_KEY_LEN: usize = PUBLICKEY_SERIALIZED_LENGTH;
const SERIAL_NUMBER_LEN: usize = 1;
const SIGNATURE_LEN: usize = SIGNATURE_SERIALIZED_LENGTH;
// TODO: This is brittle. Size of the ASN.1 structure will effect this offset.
const SIGNDATA_BEGIN: usize = 0x4;
const SUBJECT_SN_LEN: usize = ISSUER_SN_LEN;

/// Get the offset of a given pattern within the provided buffer.
fn get_pattern_offset(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

/// Get the start and end offset of length bytes starting at the end of a
/// given pattern. This convenience function is intended to make it easy to
/// get a slice of the data between these two offsets.
fn get_offsets(data: &[u8], pattern: &[u8], length: usize) -> Option<(usize, usize)> {
    let offset = get_pattern_offset(data, pattern)?;

    let start = offset + pattern.len();
    let end = start + length;

    if end <= data.len() {
        Some((start, end))
    } else {
        None
    }
}

/// Get the offset of a given pattern within the provided buffer. This
/// variation performs a reverse search of the buffer.
fn get_pattern_roffset(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).rposition(|w| w == pattern)
}

/// Get the start and end offset of length bytes starting at the end of a
/// given pattern in the given data slice by reverse search. This convenience
/// function is intended to make it easy to get a slice of the data between
/// these two offsets.
fn get_roffsets(data: &[u8], pattern: &[u8], length: usize) -> Option<(usize, usize)> {
    let offset = get_pattern_roffset(data, pattern)?;

    let start = offset + pattern.len();
    let end = start + length;

    if end <= data.len() {
        Some((start, end))
    } else {
        None
    }
}

/// Format the given file using 'rustfmt' in place.
/// This was shamelessly borrowed from hubris call_rustfmt.
pub fn rustfmt(path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    let which_out = Command::new("rustup").args(["which", "rustfmt"]).output()?;

    if !which_out.status.success() {
        return Err(format!("rustup which returned status {}", which_out.status).into());
    }

    let out_str = std::str::from_utf8(&which_out.stdout)?.trim();

    let fmt_status = Command::new(out_str).arg(path.as_ref()).status()?;
    if !fmt_status.success() {
        return Err(format!("rustfmt returned status {}", fmt_status).into());
    }
    Ok(())
}

/// Format a slice for use on the right hand side of an assignment. This is
/// used for generating const arrays for templates.
pub fn arrayfmt(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[ ")?;
    for &byte in data {
        write!(f, "{:#04x}, ", byte)?;
    }
    write!(f, "]")?;

    Ok(())
}

/// Given a type implementing 'Write', a string prefix and the start & end
/// offsets this function writes const values for the length, start and end.
pub fn write_offsets<T: Write>(
    f: &mut T,
    prefix: &str,
    start: usize,
    end: usize,
) -> Result<(), Box<dyn Error>> {
    writeln!(f, "const {}_START: usize = {};", prefix, start)?;
    writeln!(f, "const {}_LENGTH: usize = {};", prefix, end - start)?;
    writeln!(
        f,
        "const {}_END: usize = {}_START + {}_LENGTH;",
        prefix, prefix, prefix
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &'static [u8] = &[0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe];

    #[test]
    fn get_pattern_offset_none() {
        let pattern = &[0xde, 0xad];
        let offset = get_pattern_offset(DATA, pattern);
        assert_eq!(offset, None);
    }

    #[test]
    fn get_pattern_offset_some() {
        let pattern = &DATA[0..2];
        let offset = get_pattern_offset(DATA, pattern);
        assert_eq!(offset, Some(0));
    }

    #[test]
    fn get_pattern_roffset_none() {
        let pattern = &[0xde, 0xad];
        let offset = get_pattern_roffset(DATA, pattern);
        assert_eq!(offset, None);
    }

    #[test]
    fn get_pattern_roffset_some() {
        let pattern = &DATA[0..2];
        let offset = get_pattern_roffset(DATA, pattern);
        assert_eq!(offset, Some(4));
    }
}
