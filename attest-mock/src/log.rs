// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Log, Sha3_256Digest};
use hubpack::SerializedSize;
use slog_error_chain::SlogInlineError;
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::MockData;

#[derive(knus::Decode, Debug)]
pub struct Document {
    #[knus(children)]
    pub measurements: Vec<Measurement>,
}

#[derive(knus::Decode, Debug)]
pub struct Measurement {
    #[knus(child, unwrap(argument))]
    pub algorithm: String,

    #[knus(child, unwrap(argument))]
    pub digest: String,
}

pub struct MockLog(Log);

#[derive(Debug, SlogInlineError, thiserror::Error)]
pub enum MockLogError {
    #[error("Unexpected algorithm string from config: {0}")]
    BadAlgorithm(String),

    #[error("Failed to convert digest from config to Sha3_256Digest")]
    BadDigest(#[from] attest_data::AttestDataError),

    #[error("Failed to decode hex from config: {hex_str}")]
    HexDecode {
        hex_str: String,

        #[source]
        err: hex::FromHexError,
    },

    #[error("Failed to serialize mock log to hubpack form")]
    HubpackFail(#[from] hubpack::Error),

    #[error("Failed to parse the provided config")]
    InvalidConfig(#[from] knus::errors::Error),

    #[error("Failed to read file: {}", path.display())]
    Load {
        path: PathBuf,

        #[source]
        err: std::io::Error,
    },
}

impl MockData for MockLog {
    type Error = MockLogError;
    type Inner = Log;

    /// Parse the contents of the provided file as a KDL document describing
    /// a platform RoT Log
    fn load<T: AsRef<Path>>(path: T) -> Result<Self, Self::Error> {
        let path_str = path.as_ref().to_string_lossy();
        let kdl = fs::read_to_string(path_str.as_ref()).map_err(|e| {
            MockLogError::Load {
                path: PathBuf::from(path.as_ref()),
                err: e,
            }
        })?;

        Self::parse(&path_str, &kdl)
    }

    /// Transform the provided KDL to a platform RoT Log
    fn parse(name: &str, kdl: &str) -> Result<Self, Self::Error> {
        let doc: Document = knus::parse(name, kdl)?;

        let mut log = Log::default();
        for measurement in &doc.measurements {
            let measurement = if measurement.algorithm == "sha3-256" {
                let digest = hex::decode(&measurement.digest).map_err(|e| {
                    Self::Error::HexDecode {
                        hex_str: measurement.digest.clone(),
                        err: e,
                    }
                })?;
                let digest = Sha3_256Digest::try_from(digest)?;
                attest_data::Measurement::Sha3_256(digest)
            } else {
                return Err(Self::Error::BadAlgorithm(
                    measurement.algorithm.clone(),
                ));
            };

            log.push(measurement);
        }

        Ok(Self(log))
    }

    /// Serialize the Log with hubpack to a vec of bytes
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; Log::MAX_SIZE];
        let size = hubpack::serialize(&mut out, &self.0)?;
        out.resize(size, 0);

        Ok(out)
    }

    /// Consume the instance and return ownership of the inner platform RoT Log
    /// to the caller
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}
