// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
pub mod csr;
pub mod encoding;

pub use crate::csr::{Csr, MissingFieldError};
pub use crate::encoding::{Encoding, EncodingError};

use salty::constants::{
    PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
};

pub const ED25519_PUB_LEN: usize = PUBLICKEY_SERIALIZED_LENGTH;
pub const ED25519_SIG_LEN: usize = SIGNATURE_SERIALIZED_LENGTH;
// TODO: get this programatically from the cert / csr
pub const SN_LEN: usize = 12;
pub const CN_LEN: usize = SN_LEN;

fn get_pattern_offset(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

fn get_offsets(
    data: &[u8],
    pattern: &[u8],
    length: usize,
) -> Option<(usize, usize)> {
    let offset = get_pattern_offset(data, pattern)?;

    let start = offset + pattern.len();
    let end = start + length;

    if end <= data.len() {
        Some((start, end))
    } else {
        None
    }
}

fn get_pattern_roffset(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).rposition(|w| w == pattern)
}

fn get_roffsets(
    data: &[u8],
    pattern: &[u8],
    length: usize,
) -> Option<(usize, usize)> {
    let offset = get_pattern_roffset(data, pattern)?;

    let start = offset + pattern.len();
    let end = start + length;

    if end <= data.len() {
        Some((start, end))
    } else {
        None
    }
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
