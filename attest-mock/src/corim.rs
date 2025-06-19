// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use miette::{IntoDiagnostic, Result, miette};
use rats_corim::CorimBuilder;

#[derive(knuffel::Decode, Debug)]
struct Measurement {
    #[knuffel(child, unwrap(argument))]
    pub mkey: String,

    #[knuffel(child, unwrap(argument))]
    pub algorithm: usize,

    #[knuffel(child, unwrap(argument))]
    pub digest: String,
}

#[derive(knuffel::Decode, Debug)]
struct Document {
    #[knuffel(child, unwrap(argument))]
    pub vendor: String,

    #[knuffel(child, unwrap(argument))]
    pub tag_id: String,

    #[knuffel(child, unwrap(argument))]
    pub id: String,

    #[knuffel(children)]
    pub measurements: Vec<Measurement>,
}

/// Parse the KDL in from string `kdl`, convert it to an `rats_corim::Corim`
/// instance. NOTE: The `name` param should be the name of the file that the
/// `kdl` string was read from. This is used in error reporting.
pub fn mock(name: &str, kdl: &str) -> Result<Vec<u8>> {
    let doc: Document = knuffel::parse(name, kdl)?;

    let mut corim_builder = CorimBuilder::new();
    corim_builder.vendor(doc.vendor);
    corim_builder.tag_id(doc.tag_id);
    corim_builder.id(doc.id);

    for measurement in doc.measurements {
        let digest = hex::decode(measurement.digest)
            .into_diagnostic()
            .map_err(|e| miette!("decode digest hex: {e}"))?;
        corim_builder.add_hash(measurement.mkey, measurement.algorithm, digest)
    }

    let corim = corim_builder
        .build()
        .into_diagnostic()
        .map_err(|e| miette!("building CoRIM from config: {e}"))?;

    corim
        .to_vec()
        .into_diagnostic()
        .map_err(|e| miette!("CoRIM to bytes: {e}"))
}
