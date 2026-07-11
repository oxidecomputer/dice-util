// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use rats_corim::CorimBuilder;

use crate::{MockData, MockError};

#[derive(knus::Decode, Debug)]
pub struct Measurement {
    #[knus(child, unwrap(argument))]
    pub mkey: String,

    #[knus(child, unwrap(argument))]
    pub algorithm: usize,

    #[knus(child, unwrap(argument))]
    pub digest: String,
}

#[derive(knus::Decode, Debug)]
pub struct MockCorim {
    #[knus(child, unwrap(argument))]
    pub vendor: String,

    #[knus(child, unwrap(argument))]
    pub tag_id: String,

    #[knus(child, unwrap(argument))]
    pub id: String,

    #[knus(children)]
    pub measurements: Vec<Measurement>,
}

#[derive(Debug, thiserror::Error)]
pub enum MockCorimError {
    #[error("Failed to decode hex from config: {hex_str}")]
    HexDecode {
        hex_str: String,
        #[source]
        err: hex::FromHexError,
    },

    #[error("CorimBuilder failed: {0}")]
    CorimBuild(#[from] rats_corim::Error),
}

impl MockData for MockCorim {
    type Error = MockCorimError;

    fn parse(name: &str, kdl: &str) -> Result<Self, MockError> {
        Ok(knus::parse(name, kdl)?)
    }

    /// Produce a CoRIM document (serialized CBOR) from a `MockCorim` instance
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        let mut corim_builder = CorimBuilder::new();
        corim_builder.vendor(self.vendor.clone());
        corim_builder.tag_id(self.tag_id.clone());
        corim_builder.id(self.id.clone());

        for measurement in &self.measurements {
            let digest = hex::decode(&measurement.digest).map_err(|e| {
                Self::Error::HexDecode {
                    hex_str: measurement.digest.clone(),
                    err: e,
                }
            })?;
            corim_builder.add_hash(
                measurement.mkey.clone(),
                measurement.algorithm,
                digest,
            )
        }

        let corim = corim_builder.build()?;
        Ok(corim.to_vec()?)
    }
}
