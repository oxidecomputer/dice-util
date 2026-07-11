// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Log, Sha3_256Digest};
use hubpack::SerializedSize;

use crate::{MockData, MockError};

#[derive(knus::Decode, Debug)]
pub struct MockLog {
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

#[derive(Debug, thiserror::Error)]
pub enum MockLogError {
    #[error("Unexpected algorithm string from config: {0}")]
    BadAlgorithm(String),

    #[error("Failed to convert digest from config to Sha3_256Digest: {0}")]
    BadDigest(#[from] attest_data::AttestDataError),

    #[error("Failed to decode hex from config: {hex_str}")]
    HexDecode {
        hex_str: String,
        #[source]
        err: hex::FromHexError,
    },

    #[error("Failed to serialize mock log to hubpack form: {0}")]
    HubpackFail(#[from] hubpack::Error),
}

impl MockData for MockLog {
    type Error = MockLogError;

    fn parse(name: &str, kdl: &str) -> Result<Self, MockError> {
        Ok(knus::parse(name, kdl)?)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let mut log = Log::default();
        for measurement in &self.measurements {
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

        let mut out = vec![0u8; Log::MAX_SIZE];
        let size = hubpack::serialize(&mut out, &log)?;
        out.resize(size, 0);

        Ok(out)
    }
}
