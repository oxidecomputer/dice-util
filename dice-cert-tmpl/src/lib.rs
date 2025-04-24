// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cert;
pub mod csr;
pub mod encoding;

pub use crate::cert::Cert;
pub use crate::csr::Csr;
pub use crate::encoding::{Encoding, EncodingError};

use std::{error, fmt, io::Write, path::Path, process::Command};

/// Format the given file using 'rustfmt' in place.
/// This was shamelessly borrowed from hubris call_rustfmt.
pub fn rustfmt(path: impl AsRef<Path>) -> Result<(), Box<dyn error::Error>> {
    let which_out =
        Command::new("rustup").args(["which", "rustfmt"]).output()?;

    if !which_out.status.success() {
        return Err(format!(
            "rustup which returned status {}",
            which_out.status
        )
        .into());
    }

    let out_str = std::str::from_utf8(&which_out.stdout)?.trim();

    let fmt_status = Command::new(out_str).arg(path.as_ref()).status()?;
    if !fmt_status.success() {
        return Err(format!("rustfmt returned status {fmt_status}").into());
    }
    Ok(())
}

/// Format a slice for use on the right hand side of an assignment. This is
/// used for generating const arrays for templates.
pub fn arrayfmt(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[ ")?;
    for &byte in data {
        write!(f, "{byte:#04x}, ")?;
    }
    write!(f, "]")?;

    Ok(())
}

/// Given a type implementing 'Write', a string prefix and the start & end
/// offsets this function writes const values for the length, start and end.
pub fn write_range<T: Write>(
    f: &mut T,
    prefix: &str,
    start: usize,
    end: usize,
) -> Result<(), Box<dyn error::Error>> {
    writeln!(
        f,
        "pub const {prefix}_RANGE: Range<usize> = {start}..{end};"
    )?;
    Ok(())
}
