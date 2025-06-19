// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Log, Sha3_256Digest};
use hubpack::SerializedSize;
use miette::{IntoDiagnostic, Result, miette};

#[derive(knuffel::Decode, Debug)]
struct Document {
    #[knuffel(children)]
    pub measurements: Vec<Measurement>,
}

#[derive(knuffel::Decode, Debug)]
struct Measurement {
    #[knuffel(child, unwrap(argument))]
    pub algorithm: String,

    #[knuffel(child, unwrap(argument))]
    pub digest: String,
}

/// Parse the KDL in from string `kdl`, convert it to an `attest_data::Log`
/// instance. NOTE: The `name` param should be the name of the file that the
/// `kdl` string was read from. This is used in error reporting.
pub fn mock(name: &str, kdl: &str) -> Result<Vec<u8>> {
    let doc: Document = knuffel::parse(name, kdl)?;

    let mut log = Log::default();
    for measurement in doc.measurements {
        let measurement = if measurement.algorithm == "sha3-256" {
            let digest = hex::decode(measurement.digest)
                .into_diagnostic()
                .map_err(|e| miette!("decode digest hex: {e}"))?;
            let digest =
                Sha3_256Digest::try_from(digest).into_diagnostic().map_err(
                    |e| miette!("decoded digest to Sha3_256Digest: {e}"),
                )?;
            attest_data::Measurement::Sha3_256(digest)
        } else {
            return Err(miette!(
                "unsupported digest algorithm: {}",
                measurement.algorithm
            ));
        };

        log.push(measurement);
    }

    let mut out = vec![0u8; Log::MAX_SIZE];
    let size = hubpack::serialize(&mut out, &log)
        .into_diagnostic()
        .map_err(|e| miette!("hubpack attest_data::Log: {e}"))?;
    out.resize(size, 0);

    Ok(out)
}
