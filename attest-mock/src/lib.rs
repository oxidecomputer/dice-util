// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fs;
use std::path::{Path, PathBuf};

pub mod corim;
pub use corim::{MockCorim, MockCorimError};

pub mod log;
pub use log::{MockLog, MockLogError};

#[derive(Debug, thiserror::Error)]
pub enum MockError {
    #[error("Failed to parse the provided config: {0}")]
    InvalidConfig(#[from] knus::errors::Error),

    #[error("Failed to read file: {}", path.display())]
    Load {
        path: PathBuf,

        #[source]
        err: std::io::Error,
    },
}

pub trait MockData {
    type Error;

    /// Load the KDL representation of the mock data
    fn load<T: AsRef<Path>>(path: T) -> Result<Self, MockError>
    where
        Self: Sized,
    {
        let path_str = path.as_ref().to_string_lossy();
        let kdl = fs::read_to_string(path_str.as_ref()).map_err(|e| {
            MockError::Load {
                path: PathBuf::from(path.as_ref()),
                err: e,
            }
        })?;

        Self::parse(&path_str, &kdl)
    }

    /// Parse the KDL in from string `kdl`
    ///
    /// NOTE: The `name` param should be the name of the file that the `kdl`
    /// string was read from. This will show up in error reporting.
    fn parse(name: &str, kdl: &str) -> Result<Self, MockError>
    where
        Self: Sized;

    /// Produce a serialized byte stream representing the mock data
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error>;
}
