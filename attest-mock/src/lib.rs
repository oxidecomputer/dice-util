// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::Path;

pub mod corim;
pub use corim::{MockCorim, MockCorimError};

pub mod log;
pub use log::{MockLog, MockLogError};

pub trait MockData {
    type Error: std::error::Error + Send + Sync + 'static;
    type Inner;

    /// Load the KDL representation of the mock data
    fn load<T: AsRef<Path>>(path: T) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Parse the KDL in from string `kdl`
    ///
    /// The `name` param should be the name of the file that the `kdl` string
    /// was read from. This will show up in error reporting.
    fn parse(name: &str, kdl: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Produce a serialized representation of the mock data
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    /// Consume the instance and return ownership of Self::Inner
    fn into_inner(self) -> Self::Inner;
}
