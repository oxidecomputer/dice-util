// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{error::Error, fmt, fs, io::Write, path::PathBuf, str::FromStr};

pub const PRIV_KEY_TAG: &str = "PRIVATE KEY";
pub const PEM_CERT_TAG: &str = "CERTIFICATE";
pub const PEM_CSR_TAG: &str = "CERTIFICATE REQUEST";

/// Enum to represent possible encodings.
#[derive(Clone, Debug, PartialEq)]
pub enum Encoding {
    DER,
    PEM,
    RAW,
}

#[derive(Debug)]
pub enum EncodingError {
    BadTag,
    InvalidEncoding,
}

impl Error for EncodingError {}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncodingError::BadTag => write!(f, "PEM has unexpected tag."),
            EncodingError::InvalidEncoding => write!(f, "Invalid encoding."),
        }
    }
}

/// FromStr implementation useful in parsing command line options.
impl FromStr for Encoding {
    type Err = EncodingError;

    fn from_str(input: &str) -> Result<Encoding, Self::Err> {
        match input {
            "der" => Ok(Encoding::DER),
            "pem" => Ok(Encoding::PEM),
            "raw" => Ok(Encoding::RAW),
            _ => Err(EncodingError::InvalidEncoding),
        }
    }
}

pub fn decode_cert(
    path: &PathBuf,
    encoding: &Encoding,
) -> Result<Vec<u8>, Box<dyn Error>> {
    decode_obj(path, encoding, PEM_CERT_TAG)
}

pub fn decode_csr(
    path: &PathBuf,
    encoding: &Encoding,
) -> Result<Vec<u8>, Box<dyn Error>> {
    decode_obj(path, encoding, PEM_CSR_TAG)
}

fn decode_obj(
    path: &PathBuf,
    encoding: &Encoding,
    tag: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match encoding {
        Encoding::PEM => {
            let obj = fs::read(path)?;
            let (label, obj) = pem_rfc7468::decode_vec(&obj)?;

            if label != tag {
                return Err(Box::new(EncodingError::BadTag));
            }

            Ok(obj)
        }
        Encoding::DER => Ok(fs::read(path)?),
        Encoding::RAW => Err(Box::new(EncodingError::InvalidEncoding)),
    }
}

/// Decode the key file at `path` based on provided encoding.
///
/// This code doesn't parse the DER, and doesn't validate the key type.
/// We assume it's an Ed25519 key & use known offsets that we think will work.
/// Or not.
pub fn decode_key(
    path: &PathBuf,
    encoding: &Encoding,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match encoding {
        Encoding::PEM => {
            let key = fs::read(path)?;
            let (label, key) = pem_rfc7468::decode_vec(&key)?;

            if label != PRIV_KEY_TAG {
                return Err(Box::new(EncodingError::BadTag));
            }

            if key.len() != 0x30 {
                return Err(Box::new(EncodingError::InvalidEncoding));
            }
            Ok(key[0x10..].to_vec())
        }
        Encoding::DER => {
            let key_der = fs::read(path)?;

            if key_der.len() != 0x30 {
                return Err(Box::new(EncodingError::InvalidEncoding));
            }
            Ok(key_der[0x10..].to_vec())
        }
        Encoding::RAW => {
            let key_raw = fs::read(path)?;
            if key_raw.len() != 0x20 {
                return Err(Box::new(EncodingError::InvalidEncoding));
            }
            Ok(key_raw)
        }
    }
}

pub fn buf_out_fmt<F: Write>(
    out: &mut F,
    name: &str,
    slice: &[u8],
) -> Result<(), Box<dyn Error>> {
    writeln!(out, "\nconst {}: [u8; {}] = [", name, slice.len())?;
    for (i, elm) in slice.iter().enumerate() {
        if i.is_multiple_of(8) {
            write!(out, "    {elm:#04x}, ")?;
        } else if i % 8 == 7 {
            #[allow(clippy::write_with_newline)]
            write!(out, "{elm:#04x},\n")?;
        } else {
            write!(out, "{elm:#04x}, ")?;
        }
    }
    if !slice.len().is_multiple_of(8) {
        #[allow(clippy::write_with_newline)]
        write!(out, "\n")?;
    }
    writeln!(out, "];")?;
    Ok(())
}

pub fn write_csr<T: Write>(
    mut f: T,
    csr: &[u8],
    encoding: Encoding,
) -> Result<(), Box<dyn Error>> {
    match encoding {
        Encoding::PEM => {
            let csr_pem = pem_rfc7468::encode_string(
                PEM_CSR_TAG,
                pem_rfc7468::LineEnding::LF,
                csr,
            )?;
            f.write_all(csr_pem.as_bytes())?;
        }
        Encoding::DER => {
            f.write_all(csr)?;
        }
        _ => return Err(Box::new(EncodingError::InvalidEncoding)),
    };
    Ok(())
}
