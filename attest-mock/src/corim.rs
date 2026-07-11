// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use rats_corim::{Corim, CorimBuilder};
use slog_error_chain::SlogInlineError;
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::MockData;

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
pub struct Document {
    #[knus(child, unwrap(argument))]
    pub vendor: String,

    #[knus(child, unwrap(argument))]
    pub tag_id: String,

    #[knus(child, unwrap(argument))]
    pub id: String,

    #[knus(children)]
    pub measurements: Vec<Measurement>,
}

pub struct MockCorim(Corim);

#[derive(Debug, SlogInlineError, thiserror::Error)]
pub enum MockCorimError {
    #[error("CorimBuilder failed")]
    CorimBuild(#[from] rats_corim::Error),

    #[error("Failed to decode hex from config: {hex_str}")]
    HexDecode {
        hex_str: String,

        #[source]
        err: hex::FromHexError,
    },

    #[error("Failed to parse the provided config")]
    InvalidConfig(#[from] knus::errors::Error),

    #[error("Failed to read file: {}", path.display())]
    Load {
        path: PathBuf,

        #[source]
        err: std::io::Error,
    },
}

impl MockData for MockCorim {
    type Error = MockCorimError;
    type Inner = Corim;

    /// Parse the contents of the provided file as a KDL document describing
    /// a CoRIM document
    fn load<T: AsRef<Path>>(path: T) -> Result<Self, Self::Error> {
        let path_str = path.as_ref().to_string_lossy();
        let kdl = fs::read_to_string(path_str.as_ref()).map_err(|e| {
            MockCorimError::Load {
                path: PathBuf::from(path.as_ref()),
                err: e,
            }
        })?;

        Self::parse(&path_str, &kdl)
    }

    /// Transform the provided KDL to a CoRIM document
    fn parse(name: &str, kdl: &str) -> Result<Self, Self::Error> {
        let doc: Document = knus::parse(name, kdl)?;

        let mut corim_builder = CorimBuilder::new();
        corim_builder.vendor(doc.vendor.clone());
        corim_builder.tag_id(doc.tag_id.clone());
        corim_builder.id(doc.id.clone());

        for measurement in &doc.measurements {
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

        Ok(Self(corim_builder.build()?))
    }

    /// Serialize the CoRIM document to a vec of bytes
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.0.to_vec()?)
    }

    /// Pass ownership of the inner CoRIM instance to the caller
    fn into_inner(self) -> Self::Inner {
        self.0
    }
}
